"""Deterministic stub research agent.

Reasons only from the code graph and source text — never from benchmark ground
truth — so it is safe to use inside benchmarks. It re-checks the path's
invariants, collects concrete source evidence, and can propose follow-on paths
(other sinks reachable from functions on the investigated path).
"""

from __future__ import annotations

import itertools
from pathlib import Path

from ..models import (
    AttackPath,
    EdgeType,
    EvidenceItem,
    InvestigationReport,
    InvestigationStatus,
    NewPathSpec,
    NodeType,
    SourceLocation,
)
from ..graph.code_graph import CodeGraph
from ..graph.invariants import InvariantChecker, SINK_INVARIANTS, AUTHZ_SINK_KINDS
from .base import InvestigationTask, ResearchAgent

_counter = itertools.count(1)

# sanitizer call names that genuinely neutralize the sink kinds listed
_EFFECTIVE_SANITIZERS: dict[str, set[str]] = {
    "shlex.quote": {"command_execution"},
    "html.escape": {"template_injection"},
    "os.path.basename": {"file_access", "file_delete"},
    "int": {"raw_query", "file_access", "command_execution"},
    "float": {"raw_query"},
}


class StubAgent(ResearchAgent):
    """Rule-based investigator used for offline runs and benchmark baselines."""

    name = "stub"

    def __init__(self, repo_root: str):
        self.repo_root = Path(repo_root)

    def investigate(self, task: InvestigationTask, graph: CodeGraph) -> InvestigationReport:
        path = task.path
        checker = InvariantChecker(graph)
        sink = graph.nodes.get(path.nodes[-1]) if path.nodes else None
        evidence: list[EvidenceItem] = []
        locs = graph.path_locations(path.nodes)

        def ev(kind: str, summary: str, loc: SourceLocation | None = None, detail: str = "") -> None:
            evidence.append(EvidenceItem(
                id=f"ev-{next(_counter)}", path_id=path.id, kind=kind,
                summary=summary, locations=[loc] if loc else [], detail=detail,
            ))

        if sink is None:
            return InvestigationReport(hypothesis=task.hypothesis,
                                       status=InvestigationStatus.UNCERTAIN,
                                       agent=self.name)

        vuln = sink.attrs.get("vuln", "")
        san_nodes = checker.sanitizer_nodes_on(path)
        sanitized = bool(san_nodes)
        has_authz = checker.path_has_authz(path)
        has_authn = checker.path_has_authn(path)

        # Does an observed sanitizer actually address this sink kind?
        effective_san = False
        for n in san_nodes:
            call = n.attrs.get("call", "")
            kinds = _EFFECTIVE_SANITIZERS.get(call, set())
            if vuln in kinds or self._validator_looks_real(graph, call):
                effective_san = True
            ev("sanitizer_seen", f"{call} present on path", n.location)

        status = InvestigationStatus.UNCERTAIN
        hypothesis = task.hypothesis

        if sink.attrs.get("parameterized"):
            status = InvestigationStatus.FALSIFIED
            ev("guard_found", "Query is parameterized (constant SQL + bound args)",
               sink.location)
        elif vuln in SINK_INVARIANTS:
            if effective_san:
                status = InvestigationStatus.FALSIFIED
                ev("guard_found", f"Effective sanitizer for {vuln} present", sink.location)
            elif sanitized:
                # a sanitizer exists but does not address this sink kind
                status = InvestigationStatus.CONFIRMED
                ev("missing_guard",
                   f"Sanitizer present but does not neutralize {vuln}",
                   sink.location)
            else:
                status = InvestigationStatus.CONFIRMED
                ev("missing_guard", f"No sanitizing transform before {sink.label}",
                   sink.location)

        if status != InvestigationStatus.FALSIFIED:
            if vuln in AUTHZ_SINK_KINDS and not has_authz:
                status = InvestigationStatus.CONFIRMED
                ev("authz_missing",
                   f"No authorization check between entry and {sink.label}",
                   sink.location)
            elif vuln in AUTHZ_SINK_KINDS and has_authz:
                ev("authz_found", "Authorization check present on path")

        if status == InvestigationStatus.CONFIRMED:
            ev("reachability", "Attacker-controlled input reaches sink",
               locs[0] if locs else None)

        new_paths = self._suggest_new_paths(path, graph)

        return InvestigationReport(
            hypothesis=hypothesis,
            status=status,
            evidence=evidence,
            source_locations=locs,
            new_paths=new_paths,
            next_questions=[] if status != InvestigationStatus.UNCERTAIN else [
                "Does an upstream caller constrain the input before this path runs?"
            ],
            agent=self.name,
        )

    def _validator_looks_real(self, graph: CodeGraph, call: str) -> bool:
        """Heuristic: an in-repo validator counts as effective when its body
        contains a membership/allowlist comparison, a prefix/suffix host check,
        or a raise/early-return that rejects bad input."""
        short = call.split(".")[-1]
        fn = next(
            (n for n in graph.nodes.values()
             if n.id.startswith("fn:") and n.attrs.get("qualname", "").endswith(short)),
            None,
        )
        if not fn:
            return False
        try:
            src = (self.repo_root / fn.location.file).read_text(errors="replace").splitlines()
            body = "\n".join(src[fn.location.line_start - 1: fn.location.line_end])
        except OSError:
            return False
        checks = (" in (", " in [", " in {", ".startswith(", ".endswith(",
                  "raise ", "return False", "return True", "ALLOWED", "allow")
        return any(c in body for c in checks)

    def _suggest_new_paths(self, path: AttackPath, graph: CodeGraph) -> list[NewPathSpec]:
        """Propose sibling sinks reachable from functions on this path — the
        'alternate path' discovery behavior the loop depends on."""
        specs: list[NewPathSpec] = []
        path_set = set(path.nodes)
        for nid in path.nodes:
            n = graph.nodes.get(nid)
            if not n or n.type not in (NodeType.FUNCTION, NodeType.HTTP_ENTRY, NodeType.CLI_ENTRY):
                continue
            for e in graph.out_edges(nid, EdgeType.REACHES, EdgeType.DATA_FLOWS_INTO):
                dst = graph.nodes.get(e.dst)
                if dst and dst.attrs.get("vuln") and e.dst not in path_set:
                    entry = graph.nodes.get(path.nodes[0])
                    specs.append(NewPathSpec(
                        description=f"Alternate sink {dst.label} reachable via {n.label}",
                        node_labels=[entry.label if entry else "", n.label, dst.label],
                    ))
        return specs[:4]

"""Static proof validator: re-checks every hop of a confirmed path against the
actual source. Verifies that (a) each claimed source read, call, and sink exists
at its recorded location, and (b) no effective guard sits between the source and
the sink. Produces citable evidence, not a re-exploitation.
"""

from __future__ import annotations

import re
from pathlib import Path

from ..models import AttackPath, InvestigationReport, NodeType
from ..graph.code_graph import CodeGraph
from ..graph.invariants import AUTHZ_SINK_KINDS, InvariantChecker
from .base import ValidationResult, Validator


class StaticProofValidator(Validator):
    name = "static-proof"

    def __init__(self, repo_root: str):
        self.repo_root = Path(repo_root)

    def validate(
        self,
        path: AttackPath,
        report: InvestigationReport,
        graph: CodeGraph,
    ) -> ValidationResult:
        checker = InvariantChecker(graph)
        evidence: list[str] = []
        ok = True

        sink = graph.nodes.get(path.nodes[-1]) if path.nodes else None
        if not sink or not sink.attrs.get("vuln"):
            return ValidationResult(False, self.name, detail="path has no typed sink")

        # 1. every hop exists at its claimed location
        for nid in path.nodes:
            n = graph.nodes.get(nid)
            if not n:
                ok = False
                evidence.append(f"missing node {nid}")
                continue
            try:
                text = (self.repo_root / n.location.file).read_text(errors="replace")
            except OSError:
                ok = False
                evidence.append(f"unreadable file {n.location.file}")
                continue
            lines = text.splitlines()
            lo = max(1, n.location.line_start - 2)
            hi = min(len(lines), n.location.line_end + 2)
            window = "\n".join(lines[lo - 1: hi])
            call = n.attrs.get("call", "")
            if n.type == NodeType.USER_INPUT:
                kind = n.attrs.get("source_kind", "")
                var = n.attrs.get("var", "")
                # source_kind may be synthesized ("http.request"); accept the
                # literal kind text or the tainted variable name
                if kind and kind in window:
                    continue
                if var and var in window:
                    continue
                ok = False
                evidence.append(
                    f"source read '{kind or var}' not found near {n.location.short()}")
            elif call:
                needle = call.split(".")[-1]
                if needle not in window:
                    ok = False
                    evidence.append(
                        f"call '{call}' not found near {n.location.short()}")
            else:
                evidence.append(f"hop {n.label} at {n.location.short()} confirmed")

        # 2. no effective guard between source and sink
        vuln = sink.attrs["vuln"]
        if sink.attrs.get("parameterized"):
            ok = False
            evidence.append("query is parameterized (bound arguments)")
        san_nodes = checker.sanitizer_nodes_on(path)
        if san_nodes:
            effective = any(
                self._sanitizer_covers(n.attrs.get("call", ""), vuln, graph)
                for n in san_nodes
            )
            if effective:
                ok = False
                evidence.append(f"effective sanitizer present for {vuln}")
            else:
                evidence.append(f"sanitizer present but does not neutralize {vuln}")
        if vuln in AUTHZ_SINK_KINDS and checker.path_has_authz(path):
            ok = False
            evidence.append("authorization check present on path")

        repro = self._repro_hint(path, graph)
        return ValidationResult(
            verified=ok,
            method=self.name,
            reproduction=repro,
            evidence=evidence,
            detail="static proof: all hops confirmed, no effective guard" if ok
            else "static proof failed",
        )

    def _sanitizer_covers(self, call: str, vuln: str, graph: CodeGraph) -> bool:
        covers = {
            "shlex.quote": {"command_execution"},
            "html.escape": {"template_injection"},
            "os.path.basename": {"file_access", "file_delete"},
            "int": {"raw_query", "file_access", "command_execution"},
            "float": {"raw_query"},
        }
        if vuln in covers.get(call, set()):
            return True
        # in-repo validators: membership/prefix checks or a raise in the body
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
        return any(c in body for c in (
            " in (", " in [", " in {", ".startswith(", ".endswith(",
            "raise ", "return False", "ALLOWED",
        ))

    def _repro_hint(self, path: AttackPath, graph: CodeGraph) -> str:
        parts = []
        src = graph.nodes.get(path.nodes[0]) if path.nodes else None
        sink = graph.nodes.get(path.nodes[-1]) if path.nodes else None
        if src:
            parts.append(f"entry={src.label} ({src.location.short()})")
        if sink:
            parts.append(f"sink={sink.label} ({sink.location.short()})")
        return "reproduce: " + " -> ".join(parts)

"""DecisionModel abstraction: the pluggable probabilistic scorer that ranks
attack paths. Jev implements this interface; so do the ablation models
(static heuristic, random, baseline) used by the benchmark harness.
"""

from __future__ import annotations

import re
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Any

from ..models import AttackPath, EdgeType, NodeType, PathScores, RunStats
from ..graph.code_graph import CodeGraph
from ..graph.invariants import InvariantChecker


def _boundary(target: str) -> "re.Pattern[str]":
    pat = re.escape(target)
    if target[0].isalnum() or target[0] == "_":
        pat = r"\b" + pat
    if target[-1].isalnum() or target[-1] == "_":
        pat += r"\b"
    return re.compile(pat)


_ASSIGN = re.compile(r"\s*([\w.\[\]'\"]+?)\s*=[^=]")


def _post_sink_lines(root: Path, sink_hop: dict, graph: CodeGraph,
                     src: list[str] | None = None,
                     max_lines: int = 16) -> str:
    """Lines in the sink's enclosing function that consume the sink call's
    return value: where the fetched/decoded result actually goes.

    The sink question asks about consequence, so the state must show the
    consequence: ``self.content = r.text`` can sit dozens of lines after
    ``r = session.request(...)``, outside the hop excerpt window.
    """
    fn = min(
        (f for f in graph.nodes_of_type(
            NodeType.FUNCTION, NodeType.HTTP_ENTRY, NodeType.CLI_ENTRY,
            NodeType.EVENT_CONSUMER)
         if f.location.file == sink_hop["file"]
         and f.location.line_start <= sink_hop["line"]
         <= (f.location.line_end or f.location.line_start)),
        key=lambda f: (f.location.line_end or f.location.line_start)
                      - f.location.line_start,
        default=None)
    if fn is None:
        return ""
    if src is None:
        try:
            src = (root / fn.location.file).read_text(
                errors="replace").splitlines()
        except OSError:
            return ""
    call_line = src[sink_hop["line"] - 1] \
        if 0 < sink_hop["line"] <= len(src) else ""
    m = _ASSIGN.match(call_line)
    if not m:
        return ""
    tracked = {m.group(1): _boundary(m.group(1))}
    out = []
    last = min(fn.location.line_end or sink_hop["line"], len(src))
    for lineno in range(sink_hop["line"] + 1, last + 1):
        line = src[lineno - 1]
        if not any(p.search(line) for p in tracked.values()):
            continue
        # propagate through assignments: `res = r.json()` also tracks `res`
        am = _ASSIGN.match(line)
        if am and am.group(1) not in tracked and any(
                p.search(line[am.end(1):]) for p in tracked.values()):
            tracked[am.group(1)] = _boundary(am.group(1))
        out.append(f"{lineno}: {line.rstrip()}")
        if len(out) >= max_lines:
            break
    return "\n".join(out)


def path_state(path: AttackPath, graph: CodeGraph, checker: InvariantChecker,
               max_hops: int = 12, excerpt_lines: int = 4) -> dict[str, Any]:
    """Build the shared state object handed to a decision model.

    Compact but concrete: every hop carries its node type, label, source
    location, and a few lines of real code so the model judges code, not labels.
    """
    feats = checker.features(path)
    hops = []
    root = Path(graph.root)
    file_cache: dict[str, list[str] | None] = {}

    def read_lines(rel: str) -> list[str] | None:
        if rel not in file_cache:
            try:
                file_cache[rel] = (root / rel).read_text(
                    errors="replace").splitlines()
            except OSError:
                file_cache[rel] = None
        return file_cache[rel]

    node_ids = path.nodes[:max_hops]
    n_hops = len(feats["hops"])
    for i, h in enumerate(feats["hops"][:max_hops]):
        excerpt = ""
        src = read_lines(h["file"])
        if src:
            lo = max(0, h["line"] - 2)
            hi = min(len(src), h["line"] + excerpt_lines)
            excerpt = "\n".join(f"{i+1}: {src[i]}" for i in range(lo, hi))
        hop = {**h, "code": excerpt}
        # Include the call-site line for the next hop so the model can see
        # which argument carried taint across the edge (e.g. send(base_url=q)
        # vs send(base_url=FIXED, query=q)).
        if i + 1 < len(node_ids):
            for e in graph.out_edges(node_ids[i], EdgeType.CALLS):
                if e.dst == node_ids[i + 1]:
                    csrc = read_lines(e.location.file)
                    ln = e.location.line_start - 1
                    if csrc and 0 <= ln < len(csrc):
                        hop["call_site"] = (
                            f"{e.location.file}:{e.location.line_start}: "
                            f"{csrc[ln].strip()}")
                    break
        hops.append(hop)
    funcs = {
        n.attrs.get("qualname", n.label.rstrip("()")): n
        for n in graph.nodes_of_type(NodeType.FUNCTION)
    }
    guards = []
    seen_guard_locs = set()
    for g in checker.sanitizer_nodes_on(path) + checker.authz_nodes_on(path):
        loc = (g.location.file, g.location.line_start)
        if loc in seen_guard_locs:
            continue
        seen_guard_locs.add(loc)
        excerpt = ""
        gsrc = read_lines(g.location.file)
        if gsrc:
            lo = max(0, g.location.line_start - 2)
            hi = min(len(gsrc), g.location.line_start + excerpt_lines)
            excerpt = "\n".join(f"{i+1}: {gsrc[i]}" for i in range(lo, hi))
        guard = {
            "call": g.attrs.get("call", g.label),
            "file": g.location.file,
            "line": g.location.line_start,
            "code": excerpt,
        }
        # Resolve the guard call to its in-repo definition so the model judges
        # the actual check, not just the call site. Includes module-level
        # constants the body references (allowlists, blocklists).
        fn = funcs.get(guard["call"])
        fsrc = read_lines(fn.location.file) if fn is not None else None
        if fsrc:
            body = fsrc[fn.location.line_start - 1:fn.location.line_end]
            guard["definition"] = {
                "file": fn.location.file,
                "line": fn.location.line_start,
                "code": "\n".join(
                    f"{fn.location.line_start + i}: {l}"
                    for i, l in enumerate(body)),
            }
            body_names = set(re.findall(r"[A-Za-z_][A-Za-z0-9_]*",
                                        "\n".join(body)))
            consts = [
                f"{i+1}: {l}" for i, l in enumerate(fsrc)
                if l and not l[0].isspace()
                and re.match(r"[A-Za-z_][A-Za-z0-9_]*\s*=", l)
                and l.split("=")[0].strip() in body_names
            ]
            if consts:
                guard["definition"]["module_constants"] = "\n".join(consts)
        guards.append(guard)
    post_sink = ""
    if feats["hops"]:
        sink_hop = feats["hops"][-1]
        post_sink = _post_sink_lines(
            root, sink_hop, graph, read_lines(sink_hop["file"]))
    if n_hops <= max_hops and hops:
        hops[-1]["post_sink"] = post_sink
    state = {
        "path_id": path.id,
        "hypothesis": path.hypothesis,
        "prior_investigations": path.iterations_investigated,
        "evidence_notes": path.history[-4:] if path.history else [],
        "summary": {
            "length": feats["length"],
            "entry": feats["entry_label"],
            "sink": f'{feats["sink_call"]} ({feats["sink_vuln"]})',
            "user_input_present": feats["has_user_input"],
            "sanitizer_present": feats["has_sanitizer"],
            "authn_present": feats["has_authn"],
            "authz_present": feats["has_authz"],
            "invariants_plausibly_violated": feats["violated_invariants"],
        },
        "hops": hops,
        "guards": guards,
    }
    if n_hops > max_hops:
        state["post_sink"] = post_sink
    return state


class DecisionModel(ABC):
    name: str = "abstract"

    @abstractmethod
    def score_path(
        self,
        path: AttackPath,
        graph: CodeGraph,
        checker: InvariantChecker,
        stats: RunStats,
    ) -> PathScores:
        """Return structured probability scores for one candidate path."""

    def score_paths(
        self,
        paths: list[AttackPath],
        graph: CodeGraph,
        checker: InvariantChecker,
        stats: RunStats,
    ) -> None:
        for p in paths:
            p.scores = self.score_path(p, graph, checker, stats)

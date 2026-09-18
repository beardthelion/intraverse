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


def _post_sink_lines(root: Path, sink_hop: dict, graph: CodeGraph,
                     max_lines: int = 16) -> str:
    """Lines in the sink's enclosing function that consume the sink call's
    return value: where the fetched/decoded result actually goes.

    The sink question asks about consequence, so the state must show the
    consequence: ``self.content = r.text`` can sit dozens of lines after
    ``r = session.request(...)``, outside the hop excerpt window.
    """
    fn = None
    for t in (NodeType.FUNCTION, NodeType.HTTP_ENTRY, NodeType.CLI_ENTRY,
              NodeType.EVENT_CONSUMER):
        for f in graph.nodes_of_type(t):
            loc = f.location
            end = loc.line_end or loc.line_start
            if loc.file == sink_hop["file"] \
                    and loc.line_start <= sink_hop["line"] <= end:
                if fn is None or end - loc.line_start < \
                        (fn.location.line_end or fn.location.line_start) \
                        - fn.location.line_start:
                    fn = f
    if fn is None:
        return ""
    try:
        src = (root / fn.location.file).read_text(
            errors="replace").splitlines()
    except OSError:
        return ""
    call_line = src[sink_hop["line"] - 1] \
        if 0 < sink_hop["line"] <= len(src) else ""
    m = re.match(r"\s*(\w+)\s*=[^=]", call_line)
    if not m:
        return ""
    tracked = {m.group(1)}
    out = []
    last = min(fn.location.line_end or sink_hop["line"], len(src))
    for lineno in range(sink_hop["line"] + 1, last + 1):
        line = src[lineno - 1]
        if not any(re.search(rf"\b{v}\b", line) for v in tracked):
            continue
        # one level of propagation: `res = r.json()` also tracks `res`
        am = re.match(r"\s*(\w+)\s*=[^=]", line)
        if am and re.search(
                rf"\b{'|'.join(re.escape(v) for v in tracked)}\b",
                line.split("=", 1)[1]):
            tracked.add(am.group(1))
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
    node_ids = path.nodes[:max_hops]
    n_hops = len(feats["hops"])
    for i, h in enumerate(feats["hops"][:max_hops]):
        excerpt = ""
        try:
            src = (root / h["file"]).read_text(errors="replace").splitlines()
            lo = max(0, h["line"] - 2)
            hi = min(len(src), h["line"] + excerpt_lines)
            excerpt = "\n".join(f"{i+1}: {src[i]}" for i in range(lo, hi))
        except OSError:
            pass
        hop = {**h, "code": excerpt}
        # Include the call-site line for the next hop so the model can see
        # which argument carried taint across the edge (e.g. send(base_url=q)
        # vs send(base_url=FIXED, query=q)).
        if i + 1 < len(node_ids):
            for e in graph.out_edges(node_ids[i], EdgeType.CALLS):
                if e.dst == node_ids[i + 1]:
                    try:
                        csrc = (root / e.location.file).read_text(
                            errors="replace").splitlines()
                        ln = e.location.line_start - 1
                        hop["call_site"] = (
                            f"{e.location.file}:{e.location.line_start}: "
                            f"{csrc[ln].strip()}")
                    except (OSError, IndexError):
                        pass
                    break
        if i == n_hops - 1:
            hop["post_sink"] = _post_sink_lines(root, h, graph)
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
        try:
            src = (root / g.location.file).read_text(errors="replace").splitlines()
            lo = max(0, g.location.line_start - 2)
            hi = min(len(src), g.location.line_start + excerpt_lines)
            excerpt = "\n".join(f"{i+1}: {src[i]}" for i in range(lo, hi))
        except OSError:
            pass
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
        if fn is not None:
            try:
                fsrc = (root / fn.location.file).read_text(
                    errors="replace").splitlines()
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
            except OSError:
                pass
        guards.append(guard)
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
    if n_hops > max_hops and feats["hops"]:
        state["post_sink"] = _post_sink_lines(
            root, feats["hops"][-1], graph)
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

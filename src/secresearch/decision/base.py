"""DecisionModel abstraction: the pluggable probabilistic scorer that ranks
attack paths. Jev implements this interface; so do the ablation models
(static heuristic, random, baseline) used by the benchmark harness.
"""

from __future__ import annotations

import re
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Any

from ..models import AttackPath, NodeType, PathScores, RunStats
from ..graph.code_graph import CodeGraph
from ..graph.invariants import InvariantChecker


def path_state(path: AttackPath, graph: CodeGraph, checker: InvariantChecker,
               max_hops: int = 12, excerpt_lines: int = 4) -> dict[str, Any]:
    """Build the shared state object handed to a decision model.

    Compact but concrete: every hop carries its node type, label, source
    location, and a few lines of real code so the model judges code, not labels.
    """
    feats = checker.features(path)
    hops = []
    root = Path(graph.root)
    for h in feats["hops"][:max_hops]:
        excerpt = ""
        try:
            src = (root / h["file"]).read_text(errors="replace").splitlines()
            lo = max(0, h["line"] - 2)
            hi = min(len(src), h["line"] + excerpt_lines)
            excerpt = "\n".join(f"{i+1}: {src[i]}" for i in range(lo, hi))
        except OSError:
            pass
        hops.append({**h, "code": excerpt})
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
    return {
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

"""DecisionModel abstraction: the pluggable probabilistic scorer that ranks
attack paths. Jev implements this interface; so do the ablation models
(static heuristic, random, baseline) used by the benchmark harness.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from pathlib import Path
from typing import Any

from ..models import AttackPath, PathScores, RunStats
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

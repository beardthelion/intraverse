"""Ablation decision models.

- ``BaselineModel``: flat scores; the orchestrator's path order degenerates to
  discovery order. Represents "frontier agent alone, no search signal".
- ``RandomModel``: seeded uniform scores; the random-path-selection ablation.
- ``StaticHeuristicModel``: deterministic scoring from graph features only;
  represents "static analysis + frontier agent" without Jev.
"""

from __future__ import annotations

import random

from ..models import AttackPath, PathScores, RunStats
from ..graph.code_graph import CodeGraph
from ..graph.invariants import InvariantChecker
from .base import DecisionModel


class BaselineModel(DecisionModel):
    name = "baseline"

    def score_path(self, path, graph, checker, stats) -> PathScores:
        return PathScores(
            attacker_control=0.5,
            trust_boundary_crossing=0.5,
            authz_boundary_crossing=0.5,
            sensitive_sink=0.5,
            insufficient_validation=0.5,
            invariant_violation=0.5,
            research_value=0.5,
            estimated_cost=1.0,
            continue_exploration=0.5,
        )


class RandomModel(DecisionModel):
    name = "random"

    def __init__(self, seed: int = 0):
        self.rng = random.Random(seed)

    def score_path(self, path, graph, checker, stats) -> PathScores:
        r = self.rng.random
        return PathScores(
            attacker_control=r(),
            trust_boundary_crossing=r(),
            authz_boundary_crossing=r(),
            sensitive_sink=r(),
            insufficient_validation=r(),
            invariant_violation=r(),
            research_value=r(),
            estimated_cost=0.2 + 0.8 * r(),
            continue_exploration=r(),
        )


# Sinks ranked by how security-interesting they are to a static heuristic.
_SINK_VALUE = {
    "command_execution": 0.9,
    "code_execution": 0.9,
    "unsafe_deserialization": 0.85,
    "outbound_request": 0.8,
    "template_injection": 0.8,
    "open_redirect": 0.6,
    "file_access": 0.7,
    "file_delete": 0.75,
    "raw_query": 0.8,
}


class StaticHeuristicModel(DecisionModel):
    name = "static"

    def score_path(
        self,
        path: AttackPath,
        graph: CodeGraph,
        checker: InvariantChecker,
        stats: RunStats,
    ) -> PathScores:
        f = checker.features(path)
        attacker = 0.9 if f["has_user_input"] or f["entry_type"] in ("http_entry", "cli_entry") else 0.3
        sink_val = _SINK_VALUE.get(f["sink_vuln"], 0.4)
        validated = f["has_sanitizer"]
        authz = f["has_authz"]
        n_viol = f["n_violated"]
        insufficient = 0.15 if validated else 0.8
        invariant = min(1.0, 0.3 + 0.25 * n_viol)
        research = max(0.05, min(0.95, attacker * 0.4 + sink_val * 0.4 + insufficient * 0.2))
        cost = min(1.0, 0.2 + 0.1 * f["length"])
        return PathScores(
            attacker_control=attacker,
            trust_boundary_crossing=attacker * sink_val,
            authz_boundary_crossing=0.8 if (f["sink_vuln"] in ("raw_query", "file_access") and not authz) else 0.2,
            sensitive_sink=sink_val,
            insufficient_validation=insufficient,
            invariant_violation=invariant,
            research_value=research,
            estimated_cost=cost,
            continue_exploration=research,
        )

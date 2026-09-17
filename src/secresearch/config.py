"""Run configuration: strategy selection, scoring weights, budgets, backends."""

from __future__ import annotations

import json
from dataclasses import dataclass, field, asdict
from pathlib import Path


DEFAULT_WEIGHTS = {
    "research_value": 0.30,
    "invariant_violation": 0.20,
    "attacker_control": 0.15,
    "sensitive_sink": 0.12,
    "trust_boundary_crossing": 0.08,
    "authz_boundary_crossing": 0.07,
    "insufficient_validation": 0.06,
    "state_manipulation": 0.02,
}


@dataclass
class ScanConfig:
    strategy: str = "jev"  # jev | static | random | baseline
    agent: str = "stub"  # stub | devin
    language: str = "python"
    max_iterations: int = 40
    select_per_iteration: int = 1
    max_paths: int = 500
    max_path_depth: int = 10
    budget_jev_calls: int = 2000
    budget_agent_calls: int = 60
    budget_seconds: float = 3600.0
    rescore_after_evidence: bool = True
    dead_end_threshold: int = 3
    weights: dict[str, float] = field(default_factory=lambda: dict(DEFAULT_WEIGHTS))
    cost_exponent: float = 1.0  # priority = value / cost ** cost_exponent
    devin_model: str | None = None
    devin_timeout: float = 600.0
    random_seed: int = 0
    output_dir: str = "runs"
    verbose: bool = False

    def priority(self, scores) -> float:
        value = sum(
            getattr(scores, k) * w for k, w in self.weights.items()
        )
        cost = max(0.05, scores.estimated_cost) ** self.cost_exponent
        return value / cost

    def to_dict(self) -> dict:
        return asdict(self)

    @staticmethod
    def from_file(path: str) -> "ScanConfig":
        d = json.loads(Path(path).read_text())
        cfg = ScanConfig()
        for k, v in d.items():
            if hasattr(cfg, k):
                setattr(cfg, k, v)
        return cfg

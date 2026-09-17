"""Benchmark harness: run each strategy over a fixture dataset and score the
result against ground truth the search system never sees.

Dataset layout::

    <dataset>/fixtures/<name>/        # source the system indexes
    <dataset>/ground_truth/<name>.json

Ground truth files are read only by this harness, after the scan completes.
"""

from __future__ import annotations

import json
import time
from pathlib import Path

from ..config import ScanConfig
from ..findings import FindingStore
from ..models import InvestigationStatus, PathStatus
from .metrics import compute_metrics


class BenchmarkReport:
    def __init__(self):
        self.rows: list[dict] = []

    def add(self, row: dict) -> None:
        self.rows.append(row)

    def to_dict(self) -> dict:
        return {"rows": self.rows}

    def render(self) -> str:
        cols = ["fixture", "strategy", "TP", "FP", "missed", "paths_explored",
                "agent_calls", "jev_calls", "wall_s", "jev_$"]
        lines = [" | ".join(cols), "-|-".join("---" for _ in cols)]
        for r in self.rows:
            m = r["metrics"]
            lines.append(" | ".join([
                r["fixture"], r["strategy"],
                str(m["true_positives"]), str(m["false_positives"]),
                str(m["missed"]), str(m["paths_explored"]),
                str(m["agent_calls"]), str(m["jev_calls"]),
                str(m["wall_seconds"]), str(m["estimated_jev_cost_usd"]),
            ]))
        return "\n".join(lines)


def run_benchmark(
    dataset_dir: str,
    strategies: list[str],
    agent: str = "stub",
    max_iterations: int = 40,
    budget_seconds: float = 3600.0,
    output_dir: str = "runs/benchmark",
    verbose: bool = False,
    seed: int = 0,
) -> BenchmarkReport:
    from ..cli import _build_stack

    dataset = Path(dataset_dir)
    fixtures_dir = dataset / "fixtures"
    truth_dir = dataset / "ground_truth"
    report = BenchmarkReport()

    for fixture in sorted(p for p in fixtures_dir.iterdir() if p.is_dir()):
        truth_path = truth_dir / f"{fixture.name}.json"
        ground_truth = json.loads(truth_path.read_text()) if truth_path.exists() else []
        for strategy in strategies:
            out = Path(output_dir) / fixture.name / strategy
            out.mkdir(parents=True, exist_ok=True)
            cfg = ScanConfig(
                strategy=strategy, agent=agent,
                max_iterations=max_iterations,
                budget_seconds=budget_seconds,
                output_dir=str(out), verbose=verbose,
                random_seed=seed,
            )
            orch, graph = _build_stack(cfg, str(fixture), str(out))
            t0 = time.monotonic()
            result = orch.run()
            elapsed = time.monotonic() - t0
            discovery_times = dict(orch.discovery_times)
            metrics = compute_metrics(
                result.findings, ground_truth, result.stats, elapsed,
                discovery_times,
            )
            report.add({"fixture": fixture.name, "strategy": strategy,
                        "metrics": metrics})
            orch.tracer.close()
    return report

"""Dense-corpus experiment driver.

Phases:
  stub   - jev x10, random x10 (seeds 0-9), static x3, baseline x3; stub agent;
           14 picks out of 58 candidates so ranking decides the outcome.
  devin  - jev x2, static x2 with the devin-cli agent (agent ablation).

Writes runs/dense/summary.json with one row per run.
"""

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "src"))

ROOT = Path(__file__).resolve().parent
OUT = Path(__file__).resolve().parents[2] / "runs" / "dense"
SUMMARY = OUT / "summary.json"


def done(phase: str, strategy: str, rep: int) -> bool:
    if not SUMMARY.exists():
        return False
    return any(
        r["strategy"] == strategy and r["rep"] == rep
        and r.get("agent", "stub") == ("devin" if phase == "devin" else "stub")
        for r in json.loads(SUMMARY.read_text())
    )


def run(phase: str, strategy: str, agent: str, iters: int, seed: int, rep: int) -> dict:
    from secresearch.benchmark.harness import run_benchmark
    rep_dir = OUT / phase / f"rep{rep:02d}"
    report = run_benchmark(str(ROOT), strategies=[strategy], agent=agent,
                           max_iterations=iters, output_dir=str(rep_dir),
                           seed=seed)
    row = dict(report.rows[0])
    row["rep"] = rep
    row["agent"] = agent
    return row


def append(row: dict) -> None:
    SUMMARY.parent.mkdir(parents=True, exist_ok=True)
    rows = json.loads(SUMMARY.read_text()) if SUMMARY.exists() else []
    rows.append(row)
    SUMMARY.write_text(json.dumps(rows, indent=2))


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("phase", choices=["stub", "devin"])
    args = ap.parse_args()

    def go(phase, strategy, agent, iters, seed, rep, tag):
        if done(phase, strategy, rep):
            print(f"{tag} rep{rep}: already recorded, skipping", flush=True)
            return
        row = run(phase, strategy, agent, iters, seed, rep)
        append(row)
        m = row["metrics"]
        print(f"{tag} rep{rep}: TP={m['true_positives']} "
              f"FP={m['false_positives']} missed={m['missed']} "
              f"explored={m['paths_explored']} "
              f"jev_fail={m.get('jev_failures', 0)}", flush=True)

    if args.phase == "stub":
        for i in range(10):
            for strategy, seed in (("jev", 0), ("random", i)):
                go("stub", strategy, "stub", 14, seed, i, strategy)
        for i in range(3):
            for strategy in ("static", "baseline"):
                go("stub", strategy, "stub", 14, 0, i, strategy)
    else:
        for i in range(2):
            for strategy in ("jev", "static"):
                go("devin", strategy, "devin", 12, 0, i, f"devin+{strategy}")


if __name__ == "__main__":
    main()

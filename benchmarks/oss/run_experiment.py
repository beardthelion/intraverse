"""OSS benchmark driver: whoogle (11 paths, budget 6) and alerta
(62 paths, budget 12), repeated trials per strategy.

Usage: python3 benchmarks/oss/run_experiment.py [stub|devin]
Writes runs/oss/summary.json with one row per run.
"""

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "src"))

ROOT = Path(__file__).resolve().parent
OUT = Path(__file__).resolve().parents[2] / "runs" / "oss"
SUMMARY = OUT / "summary.json"


def done(phase: str, fixture: str, strategy: str, rep: int) -> bool:
    if not SUMMARY.exists():
        return False
    return any(
        r["strategy"] == strategy and r["rep"] == rep
        and r.get("phase", "stub") == phase and r["fixture"] == fixture
        for r in json.loads(SUMMARY.read_text())
    )


def run(phase, fixture, strategy, agent, iters, seed, rep) -> dict:
    from secresearch.benchmark.harness import run_benchmark
    rep_dir = OUT / phase / f"rep{rep:02d}"
    report = run_benchmark(str(ROOT), strategies=[strategy], agent=agent,
                           max_iterations=iters, output_dir=str(rep_dir),
                           fixture_filter=fixture)
    row = dict(report.rows[0])
    row["rep"] = rep
    row["agent"] = agent
    row["phase"] = phase
    return row


def append(row: dict) -> None:
    SUMMARY.parent.mkdir(parents=True, exist_ok=True)
    rows = json.loads(SUMMARY.read_text()) if SUMMARY.exists() else []
    rows.append(row)
    SUMMARY.write_text(json.dumps(rows, indent=2))


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("phase", choices=["stub", "devin", "stub-uu", "stub2"])
    args = ap.parse_args()

    # per-fixture budgets: paths must outnumber picks for ranking to matter
    budgets = {"whoogle-ssrf": 6, "alerta-sqli": 12, "cdio-lfr": 12}

    def go(fixture, strategy, agent, seed, rep):
        if done(args.phase, fixture, strategy, rep):
            print(f"{fixture} {strategy} rep{rep}: skip", flush=True)
            return
        row = run(args.phase, fixture, strategy, agent,
                  budgets[fixture], seed, rep)
        append(row)
        m = row["metrics"]
        print(f"{fixture} {strategy} rep{rep}: TP={m['true_positives']} "
              f"FP={m['false_positives']} missed={m['missed']} "
              f"jev_fail={m.get('jev_failures', 0)}", flush=True)

    if args.phase == "stub2":
        # post-stored-taint analyzer: cdio is new; alerta grew 62->78 paths
        # after the enumeration-cap fix so its old rows are stale. whoogle
        # and corpus-a are unchanged (no classes/stores, under old cap).
        for rep in range(5):
            go("cdio-lfr", "jev", "stub", 0, rep)
        for rep in range(3):
            go("cdio-lfr", "random", "stub", rep, rep)
        for rep in range(2):
            go("cdio-lfr", "static", "stub", 0, rep)
            go("cdio-lfr", "baseline", "stub", 0, rep)
        for rep in range(3):
            go("alerta-sqli", "jev", "stub", 0, rep)
        for rep in range(2):
            go("alerta-sqli", "random", "stub", rep, rep)
            go("alerta-sqli", "static", "stub", 0, rep)
    elif args.phase == "stub-uu":
        # unintended_use dimension only affects jev scoring; heuristics are
        # identical to the stub phase and need no rerun
        for rep in range(5):
            go("whoogle-ssrf", "jev", "stub", 0, rep)
        for rep in range(3):
            go("alerta-sqli", "jev", "stub", 0, rep)
    elif args.phase == "stub":
        for rep in range(5):
            go("whoogle-ssrf", "jev", "stub", 0, rep)
        for rep in range(3):
            go("whoogle-ssrf", "random", "stub", rep, rep)
        for rep in range(2):
            go("whoogle-ssrf", "static", "stub", 0, rep)
            go("whoogle-ssrf", "baseline", "stub", 0, rep)
        for rep in range(3):
            go("alerta-sqli", "jev", "stub", 0, rep)
        for rep in range(2):
            go("alerta-sqli", "random", "stub", rep, rep)
            go("alerta-sqli", "static", "stub", 0, rep)
    else:
        for rep in range(2):
            go("whoogle-ssrf", "jev", "devin", 0, rep)
            go("alerta-sqli", "jev", "devin", 0, rep)


if __name__ == "__main__":
    main()

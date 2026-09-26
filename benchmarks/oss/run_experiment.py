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
                           fixture_filter=fixture, seed=seed)
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
    ap.add_argument("phase", choices=["stub", "devin", "stub-uu", "stub2", "stub3", "stub4", "stub5", "stub6", "stub7", "stub8", "devin2"])
    args = ap.parse_args()

    # per-fixture budgets: paths must outnumber picks for ranking to matter
    budgets = {"whoogle-ssrf": 6, "alerta-sqli": 12, "cdio-lfr": 12,
               "calweb-ssrf": 10}

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

    if args.phase == "stub8":
        # contract_gap at weight 0.30: the counterfactual sweep put
        # whoogle's window on the pick line at >=0.30 and both CVE paths
        # inside at >=0.50. The dimension's output is near-binary and
        # neutral-positive on cdio/calweb, so this sweep measures whether
        # the weighting policy stabilizes the element/window picks.
        for rep in range(5):
            go("whoogle-ssrf", "jev", "stub", 0, rep)
        for rep in range(3):
            go("cdio-lfr", "jev", "stub", 0, rep)
        for rep in range(2):
            go("calweb-ssrf", "jev", "stub", 0, rep)
    elif args.phase == "stub7":
        # contract_gap dimension (weight 0.15): asks whether enforcement
        # depends on the attacker opting in (optional verify/decrypt
        # branch forwarding the raw value, env- or config-gated checks).
        # Probes put whoogle's element/window at 0.70-0.85 vs the crowd's
        # 0.09-0.39, the first dimension to rank them above the config
        # family. whoogle x5 is the primary measurement (window sits at
        # the 6-pick line); cdio x3 and calweb x2 check for regressions.
        for rep in range(5):
            go("whoogle-ssrf", "jev", "stub", 0, rep)
        for rep in range(3):
            go("cdio-lfr", "jev", "stub", 0, rep)
        for rep in range(2):
            go("calweb-ssrf", "jev", "stub", 0, rep)
    elif args.phase == "devin2":
        # devin ablation on the OSS fixtures: does a real investigator
        # confirm what jev selects? calweb is the clean win under stub
        # (5/5 picks); cdio straddles the line; whoogle is the crowded
        # pool where the SSRF stays unpicked. 2 reps each.
        for rep in range(2):
            go("calweb-ssrf", "jev", "devin", 0, rep)
        for rep in range(2):
            go("cdio-lfr", "jev", "devin", 0, rep)
        for rep in range(2):
            go("whoogle-ssrf", "jev", "devin", 0, rep)
    elif args.phase == "stub6":
        # calweb-ssrf (calibre-web 0.6.16, 67 paths, budget 10): tests
        # whether the holistic dimensions under-score the subtle shape:
        # a feature-intended cover fetch behind a bypassable '127.'
        # getaddrinfo denylist. jev x5 primary; static/baseline x1 each
        # as heuristic reference.
        for rep in range(5):
            go("calweb-ssrf", "jev", "stub", 0, rep)
        for rep in range(1):
            go("calweb-ssrf", "static", "stub", 0, rep)
            go("calweb-ssrf", "baseline", "stub", 0, rep)
    elif args.phase == "stub5":
        # sink_input reach semantics: call-site-aware scheme_control splits
        # attacker-named fetch targets (expression, sc=true) from pinned
        # ones (prefix_expr/literal, sc=false). cdio jev x5 primary;
        # whoogle jev x5 checks whether element/window CVE picks recover
        # now that their base_url= call sites read sc=true while the
        # search/autocomplete fetches read sc=false; alerta x3 regression.
        for rep in range(5):
            go("cdio-lfr", "jev", "stub", 0, rep)
        for rep in range(5):
            go("whoogle-ssrf", "jev", "stub", 0, rep)
        for rep in range(3):
            go("alerta-sqli", "jev", "stub", 0, rep)
    elif args.phase == "stub4":
        # sink_reach dimension (weight 0.15, post-sink lines in path_state):
        # asks what the sink reaches or returns when the shown checks fail
        # and where the result goes. cdio jev x5 is the primary measurement;
        # static/baseline get one rep each as heuristic reference; whoogle
        # and alerta jev x3 check for regressions.
        for rep in range(5):
            go("cdio-lfr", "jev", "stub", 0, rep)
        for rep in range(1):
            go("cdio-lfr", "static", "stub", 0, rep)
            go("cdio-lfr", "baseline", "stub", 0, rep)
        for rep in range(3):
            go("alerta-sqli", "jev", "stub", 0, rep)
            go("whoogle-ssrf", "jev", "stub", 0, rep)
    elif args.phase == "stub3":
        # post-provenance analyzer: user-stored:* labels on store reads whose
        # backing root received tainted writes; ast.Dict taint added paths to
        # every fixture (cdio 110->118, alerta 78->87, whoogle 11->14).
        for rep in range(5):
            go("cdio-lfr", "jev", "stub", 0, rep)
        for rep in range(2):
            go("cdio-lfr", "static", "stub", 0, rep)
            go("cdio-lfr", "baseline", "stub", 0, rep)
        for rep in range(3):
            go("alerta-sqli", "jev", "stub", 0, rep)
            go("whoogle-ssrf", "jev", "stub", 0, rep)
    elif args.phase == "stub2":
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

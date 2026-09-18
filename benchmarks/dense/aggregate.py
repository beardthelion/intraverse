"""Aggregate dense-corpus experiment results.

Two views per (agent, strategy):
  findings   - verified findings matched against ground truth (system-level)
  selection  - of the paths the strategy chose to investigate, how many were
               real vulns (ranker quality, independent of agent verdicts)

Selection data comes from trace 'selected' events: each label ends with
"@file:line" and carries the vuln class in [brackets].
"""

import json
import re
import statistics
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
OUT = HERE.parents[1] / "runs" / "dense"
LABEL_RE = re.compile(r"\[(\w+)\]\s*@([\w./-]+):(\d+)")


def match(cls: str, f: str, line: int, truth: list[dict]) -> bool:
    for t in truth:
        if t["class"] == cls and t["sink_file"] == f \
                and abs(t["sink_line"] - line) <= 1:
            return True
    return False


def selection_stats(run_dir: Path, truth: list[dict]) -> tuple[int, int]:
    """(real_vuln_picks, total_picks) from a run's trace."""
    traces = list(run_dir.glob("trace-*.jsonl"))
    if not traces:
        return 0, 0
    tp = tot = 0
    for line in traces[0].read_text().splitlines():
        e = json.loads(line)
        if e.get("kind") != "selected":
            continue
        m = LABEL_RE.search(e.get("label", ""))
        if not m:
            continue
        tot += 1
        if match(m.group(1), m.group(2), int(m.group(3)), truth):
            tp += 1
    return tp, tot


def main() -> None:
    summary = json.loads((OUT / "summary.json").read_text())
    truth = json.loads((HERE / "ground_truth" / "corpus-a.json").read_text())

    groups: dict[tuple[str, str, str], list[dict]] = {}
    for row in summary:
        phase = row.get("phase") or ("devin" if row.get("agent") == "devin" else "stub")
        groups.setdefault((row.get("agent", "stub"), row["strategy"], phase), []).append(row)

    print(f"{'agent':6} {'strategy':9} {'phase':8} {'n':>2} {'TP':>12} {'FP':>9} "
          f"{'missed':>10} {'sel_prec':>9} {'sel_vulns':>9} {'explored':>8}")
    for (agent, strat, phase), rows in sorted(groups.items()):
        tps = [r["metrics"]["true_positives"] for r in rows]
        fps = [r["metrics"]["false_positives"] for r in rows]
        missed = [r["metrics"]["missed"] for r in rows]
        expl = [r["metrics"]["paths_explored"] for r in rows]
        sel_precs, sel_hits = [], []
        for r in rows:
            run_dir = OUT / phase / f"rep{r['rep']:02d}" / r["fixture"] / strat
            tp, tot = selection_stats(run_dir, truth)
            if tot:
                sel_precs.append(tp / tot)
                sel_hits.append(tp)
        fmt = lambda xs: f"{statistics.mean(xs):.1f}[{min(xs)}-{max(xs)}]"
        print(f"{agent:6} {strat:9} {phase:8} {len(rows):>2} {fmt(tps):>12} "
              f"{fmt(fps):>9} {fmt(missed):>10} "
              f"{statistics.mean(sel_precs):>8.0%} "
              f"{fmt(sel_hits):>9} {fmt(expl):>8}")


if __name__ == "__main__":
    main()

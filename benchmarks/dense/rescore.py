"""Recompute TP/FP/missed for completed runs using the current match_finding.

Findings persist under runs/dense/<phase>/repNN/<fixture>/<strategy>/findings/.
Scoring them again with the fixed matcher avoids re-running scans when only the
metric window changed. Rewrites those fields inside runs/dense/summary.json.
"""

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "src"))

from secresearch.findings import FindingStore
from secresearch.benchmark.metrics import match_finding

HERE = Path(__file__).resolve().parent
OUT = HERE.parents[1] / "runs" / "dense"


def rescore_dir(run_dir: Path, truth: list[dict]) -> tuple[int, int, int]:
    t = [dict(x) for x in truth]
    tp = fp = 0
    for f in FindingStore(str(run_dir / "findings")).all():
        if match_finding(f, t):
            tp += 1
        else:
            fp += 1
    missed = sum(1 for x in t if not x.get("matched"))
    return tp, fp, missed


def main() -> None:
    truth = json.loads((HERE / "ground_truth" / "corpus-a.json").read_text())
    summary_path = OUT / "summary.json"
    rows = json.loads(summary_path.read_text())
    for row in rows:
        phase = row.get("phase") or ("devin" if row.get("agent") == "devin" else "stub")
        run_dir = OUT / phase / f"rep{row['rep']:02d}" / row["fixture"] / row["strategy"]
        if not (run_dir / "findings").exists():
            print("missing:", run_dir)
            continue
        tp, fp, missed = rescore_dir(run_dir, truth)
        row["metrics"]["true_positives"] = tp
        row["metrics"]["false_positives"] = fp
        row["metrics"]["missed"] = missed
    summary_path.write_text(json.dumps(rows, indent=2))
    print(f"rescored {len(rows)} rows")


if __name__ == "__main__":
    main()

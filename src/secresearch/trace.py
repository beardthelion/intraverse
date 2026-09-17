"""Structured run tracing: JSONL event log plus console observability."""

from __future__ import annotations

import json
import sys
import time
from pathlib import Path
from typing import Any


class Tracer:
    def __init__(self, out_dir: str | None = None, verbose: bool = False):
        self.verbose = verbose
        self.events: list[dict] = []
        self.path: Path | None = None
        self._fh = None
        if out_dir:
            p = Path(out_dir)
            p.mkdir(parents=True, exist_ok=True)
            self.path = p / f"trace-{int(time.time())}.jsonl"
            self._fh = self.path.open("w")

    def emit(self, kind: str, **data: Any) -> None:
        ev = {"t": round(time.time(), 3), "kind": kind, **data}
        self.events.append(ev)
        if self._fh:
            self._fh.write(json.dumps(ev, default=str) + "\n")
            self._fh.flush()
        if self.verbose:
            self._console(ev)

    def _console(self, ev: dict) -> None:
        k = ev["kind"]
        if k == "iteration":
            print(f"\n=== Iteration {ev['iteration']} "
                  f"(unexplored={ev['unexplored']} promising={ev['promising']} "
                  f"verified={ev['verified']} discarded={ev['discarded']}) ===")
        elif k == "scores":
            print(f"  Scored {ev['count']} candidate paths with {ev['model']}")
            for row in ev.get("top", []):
                print(f"    #{row['id']}  score {row['priority']:.2f}  {row['label']}")
        elif k == "selected":
            print(f"  Selected: #{ev['path_id']}  {ev['label']}")
        elif k == "investigation":
            print(f"  Agent [{ev['agent']}] -> {ev['status']} "
                  f"({ev['wall_seconds']:.1f}s, {ev['n_evidence']} evidence items)")
            for q in ev.get("next_questions", []):
                print(f"    next question: {q}")
        elif k == "new_paths":
            for p in ev["paths"]:
                print(f"  New candidate: #{p['id']}  {p['label']}")
        elif k == "rescore":
            print(f"  Re-scored {ev['count']} paths with new evidence "
                  f"(#{ev['path_id']} now {ev['priority']:.2f})")
        elif k == "finding":
            print(f"  FINDING {ev['finding_id']}: {ev['title']} [{ev['status']}]")
        elif k == "path_status":
            print(f"  #{ev['path_id']} -> {ev['status']}")
        elif k == "warning":
            print(f"  ! {ev['message']}", file=sys.stderr)

    def close(self) -> None:
        if self._fh:
            self._fh.close()

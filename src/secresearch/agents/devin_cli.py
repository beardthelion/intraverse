"""Devin CLI research agent: shells out to ``devin -p`` for the expensive
per-path investigation. The prompt constrains the agent to a single hypothesis
and demands a structured JSON report as its last output.
"""

from __future__ import annotations

import json
import re
import subprocess
import tempfile
import time
from pathlib import Path

from ..models import (
    EvidenceItem,
    InvestigationReport,
    InvestigationStatus,
    NewPathSpec,
    SecurityInvariant,
    SourceLocation,
)
from ..graph.code_graph import CodeGraph
from .base import InvestigationTask, ResearchAgent

_JSON_RE = re.compile(r"\{.*\}", re.DOTALL)

REPORT_SCHEMA = """{
  "hypothesis": "the hypothesis you investigated",
  "status": "confirmed | falsified | uncertain",
  "evidence": [
    {"kind": "code_observation|missing_guard|authz_found|sanitizer_seen|counterexample|reachability",
     "summary": "one sentence",
     "file": "relative/path.py", "line_start": 1, "line_end": 5, "detail": "optional"}
  ],
  "source_locations": [{"file": "...", "function": "...", "line_start": 0, "line_end": 0}],
  "new_paths": [
    {"description": "...", "node_labels": ["entry label", "fn label", "sink label"],
     "source_hint": "", "sink_hint": ""}
  ],
  "new_invariants": [{"kind": "...", "statement": "...", "params": {}}],
  "next_questions": ["..."]
}"""


def build_prompt(task: InvestigationTask, graph: CodeGraph) -> str:
    lines = [
        "You are a security research agent investigating ONE specific hypothesis in the",
        f"repository rooted at {task.repo_root}. Do not audit the whole repository.",
        "",
        "ATTACK PATH UNDER INVESTIGATION:",
        task.path.label,
        "",
        f"HYPOTHESIS: {task.hypothesis}",
        "",
    ]
    if task.invariants:
        lines.append("CANDIDATE INVARIANTS THAT MAY BE VIOLATED:")
        for inv in task.invariants:
            lines.append(f"- [{inv.kind}] {inv.statement}")
        lines.append("")
    if task.code_excerpts:
        lines.append("CODE ON THE PATH (excerpts; read the real files for full context):")
        for ex in task.code_excerpts:
            lines.append(f"--- {ex.get('file')}:{ex.get('line')} ({ex.get('label')}) ---")
            lines.append(ex.get("code", ""))
        lines.append("")
    lines += [
        "INSTRUCTIONS:",
        "1. Trace the path concretely in the source files. Check every hop.",
        "2. Look for validation, sanitization, authorization, and authentication",
        "   checks on or around the path. A check that exists but is bypassable",
        "   does not falsify the hypothesis; explain the bypass as evidence.",
        "3. If the hypothesis is wrong, say so explicitly (status=falsified) and",
        "   name the code that defeats it.",
        "4. Report alternate reachable paths to the same or related sinks as",
        "   new_paths when you find them.",
        "5. Do not modify any files. Do not run destructive commands.",
        "",
        "Respond with prose analysis first, then END your reply with exactly one",
        "JSON object matching this schema (no trailing text after it):",
        REPORT_SCHEMA,
    ]
    return "\n".join(lines)


def parse_report(text: str, task: InvestigationTask, wall: float) -> InvestigationReport:
    """Extract the trailing JSON report from agent output."""
    match = None
    for m in _JSON_RE.finditer(text):
        match = m
    if not match:
        return InvestigationReport(
            hypothesis=task.hypothesis, status=InvestigationStatus.UNCERTAIN,
            agent="devin-cli", wall_seconds=wall, raw=text[-4000:],
        )
    try:
        d = json.loads(match.group(0))
    except json.JSONDecodeError:
        return InvestigationReport(
            hypothesis=task.hypothesis, status=InvestigationStatus.UNCERTAIN,
            agent="devin-cli", wall_seconds=wall, raw=text[-4000:],
        )
    status_map = {
        "confirmed": InvestigationStatus.CONFIRMED,
        "falsified": InvestigationStatus.FALSIFIED,
        "uncertain": InvestigationStatus.UNCERTAIN,
    }
    evidence = []
    for i, e in enumerate(d.get("evidence", [])):
        loc = SourceLocation(
            file=e.get("file", ""), line_start=int(e.get("line_start", 0)),
            line_end=int(e.get("line_end", 0)),
        )
        evidence.append(EvidenceItem(
            id=f"devin-ev-{i}", path_id=task.path.id,
            kind=e.get("kind", "code_observation"),
            summary=e.get("summary", ""),
            locations=[loc] if loc.file else [],
            detail=e.get("detail", ""),
        ))
    locs = [
        SourceLocation(
            file=l.get("file", ""), function=l.get("function", ""),
            line_start=int(l.get("line_start", 0)), line_end=int(l.get("line_end", 0)),
        )
        for l in d.get("source_locations", [])
    ]
    new_paths = [NewPathSpec.from_dict(p) for p in d.get("new_paths", [])]
    new_invs = [
        SecurityInvariant(id=f"agent-inv-{i}", kind=x.get("kind", "agent"),
                          statement=x.get("statement", ""),
                          params=x.get("params", {}), source="agent")
        for i, x in enumerate(d.get("new_invariants", []))
    ]
    return InvestigationReport(
        hypothesis=d.get("hypothesis", task.hypothesis),
        status=status_map.get(str(d.get("status", "uncertain")).lower(),
                              InvestigationStatus.UNCERTAIN),
        evidence=evidence,
        source_locations=locs,
        new_paths=new_paths,
        new_invariants=new_invs,
        next_questions=list(d.get("next_questions", [])),
        agent="devin-cli",
        wall_seconds=wall,
        raw=text[-8000:],
    )


class DevinCliAgent(ResearchAgent):
    name = "devin-cli"

    def __init__(self, repo_root: str, timeout: float = 600.0, model: str | None = None):
        self.repo_root = repo_root
        self.timeout = timeout
        self.model = model

    def investigate(self, task: InvestigationTask, graph: CodeGraph) -> InvestigationReport:
        task.repo_root = task.repo_root or self.repo_root
        prompt = build_prompt(task, graph)
        cmd = ["devin", "-p", "--respect-workspace-trust", "false"]
        if self.model:
            cmd += ["--model", self.model]
        t0 = time.monotonic()
        try:
            with tempfile.NamedTemporaryFile(
                "w", suffix=".md", prefix="secresearch-", delete=False
            ) as f:
                f.write(prompt)
                prompt_file = f.name
            cmd += ["--prompt-file", prompt_file]
            proc = subprocess.run(
                cmd,
                cwd=self.repo_root,
                capture_output=True,
                text=True,
                timeout=self.timeout,
            )
            out = proc.stdout + "\n" + proc.stderr
        except subprocess.TimeoutExpired:
            return InvestigationReport(
                hypothesis=task.hypothesis, status=InvestigationStatus.UNCERTAIN,
                agent=self.name, wall_seconds=time.monotonic() - t0,
                raw="devin CLI timed out",
            )
        except FileNotFoundError:
            return InvestigationReport(
                hypothesis=task.hypothesis, status=InvestigationStatus.UNCERTAIN,
                agent=self.name, wall_seconds=time.monotonic() - t0,
                raw="devin CLI not found on PATH",
            )
        finally:
            try:
                Path(prompt_file).unlink(missing_ok=True)  # type: ignore[possibly-undefined]
            except Exception:
                pass
        return parse_report(out, task, time.monotonic() - t0)

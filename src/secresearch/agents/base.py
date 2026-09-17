"""ResearchAgent abstraction: the expensive reasoning agent that investigates a
single prioritized attack path and returns structured evidence.

The task handed to the agent is deliberately narrow: confirm or falsify one
hypothesis about one path. ``FALSIFIED`` is a first-class result — the loop
depends on it to stop wasting budget on dead ends.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field

from ..models import AttackPath, InvestigationReport, SecurityInvariant
from ..graph.code_graph import CodeGraph


@dataclass
class InvestigationTask:
    path: AttackPath
    hypothesis: str
    invariants: list[SecurityInvariant]
    # Code excerpts for each hop, pre-collected by the orchestrator so the
    # agent starts from concrete source, not a directory listing.
    code_excerpts: list[dict] = field(default_factory=list)
    repo_root: str = ""


class ResearchAgent(ABC):
    name: str = "abstract"

    @abstractmethod
    def investigate(self, task: InvestigationTask, graph: CodeGraph) -> InvestigationReport:
        ...

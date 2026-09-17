"""Validator abstraction: turns a confirmed hypothesis into independently
inspectable evidence. A finding may not reach ``verified`` on the strength of
an LLM's or stub's say-so; a validator must produce concrete artifacts.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field

from ..models import AttackPath, Finding, InvestigationReport
from ..graph.code_graph import CodeGraph


@dataclass
class ValidationResult:
    verified: bool
    method: str
    reproduction: str = ""
    evidence: list[str] = field(default_factory=list)
    detail: str = ""


class Validator(ABC):
    name: str = "abstract"

    @abstractmethod
    def validate(
        self,
        path: AttackPath,
        report: InvestigationReport,
        graph: CodeGraph,
    ) -> ValidationResult:
        ...

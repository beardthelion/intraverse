"""Core data model shared by every layer of the research loop.

Everything here is a plain dataclass with ``to_dict``/``from_dict`` so the whole
search trace is inspectable and serializable to JSON.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Any, Optional


class NodeType(str, Enum):
    HTTP_ENTRY = "http_entry"
    CLI_ENTRY = "cli_entry"
    EVENT_CONSUMER = "event_consumer"
    USER_INPUT = "user_input"
    AUTH_BOUNDARY = "auth_boundary"
    AUTHZ_CHECK = "authz_check"
    TRUST_BOUNDARY = "trust_boundary"
    TRANSFORM = "transform"
    DB_OP = "db_op"
    FS_OP = "fs_op"
    NET_OP = "net_op"
    PROCESS_EXEC = "process_exec"
    DESERIALIZATION = "deserialization"
    TEMPLATE_RENDER = "template_render"
    REDIRECT = "redirect"
    SECRET = "secret"
    PRIVILEGED_OP = "privileged_op"
    SENSITIVE_RESOURCE = "sensitive_resource"
    STATE_TRANSITION = "state_transition"
    EXTERNAL_SERVICE = "external_service"
    FUNCTION = "function"


class EdgeType(str, Enum):
    CALLS = "calls"
    DATA_FLOWS_INTO = "data_flows_into"
    CONTROLS = "controls"
    AUTHENTICATES = "authenticates"
    AUTHORIZES = "authorizes"
    TRANSFORMS = "transforms"
    READS = "reads"
    WRITES = "writes"
    REACHES = "reaches"
    CROSSES_TRUST_BOUNDARY = "crosses_trust_boundary"
    CREATES = "creates"
    MODIFIES = "modifies"
    DELETES = "deletes"
    INVOKES = "invokes"
    REDIRECTS = "redirects"
    SERIALIZES = "serializes"


class PathStatus(str, Enum):
    UNEXPLORED = "unexplored"
    EXPLORING = "exploring"
    PROMISING = "promising"
    DISCARDED = "discarded"
    VERIFIED = "verified"


class InvestigationStatus(str, Enum):
    CONFIRMED = "confirmed"
    FALSIFIED = "falsified"
    UNCERTAIN = "uncertain"


class ValidationStatus(str, Enum):
    UNVERIFIED = "unverified"
    VERIFIED = "verified"
    FALSIFIED = "falsified"


@dataclass
class SourceLocation:
    """Provenance: a concrete location in the target repository."""

    file: str
    function: str = ""
    line_start: int = 0
    line_end: int = 0

    def short(self) -> str:
        fn = f" in {self.function}()" if self.function else ""
        return f"{self.file}:{self.line_start}-{self.line_end}{fn}"

    def to_dict(self) -> dict:
        return asdict(self)

    @staticmethod
    def from_dict(d: dict) -> "SourceLocation":
        return SourceLocation(**d)


@dataclass
class GraphNode:
    id: str
    type: NodeType
    label: str
    location: SourceLocation
    # Free-form attributes produced by analyzers: tainted param names, sink kind,
    # callee names, route path, decorator names, etc.
    attrs: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "type": self.type.value,
            "label": self.label,
            "location": self.location.to_dict(),
            "attrs": self.attrs,
        }

    @staticmethod
    def from_dict(d: dict) -> "GraphNode":
        return GraphNode(
            id=d["id"],
            type=NodeType(d["type"]),
            label=d["label"],
            location=SourceLocation.from_dict(d["location"]),
            attrs=d.get("attrs", {}),
        )


@dataclass
class GraphEdge:
    id: str
    type: EdgeType
    src: str  # node id
    dst: str  # node id
    location: Optional[SourceLocation] = None
    attrs: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "type": self.type.value,
            "src": self.src,
            "dst": self.dst,
            "location": self.location.to_dict() if self.location else None,
            "attrs": self.attrs,
        }

    @staticmethod
    def from_dict(d: dict) -> "GraphEdge":
        return GraphEdge(
            id=d["id"],
            type=EdgeType(d["type"]),
            src=d["src"],
            dst=d["dst"],
            location=SourceLocation.from_dict(d["location"]) if d.get("location") else None,
            attrs=d.get("attrs", {}),
        )


@dataclass
class SecurityInvariant:
    """A candidate security invariant inferred from code structure.

    ``kind`` names the rule family; ``params`` carries rule-specific data such as
    the protected resource or the required privilege.
    """

    id: str
    kind: str
    statement: str
    params: dict[str, Any] = field(default_factory=dict)
    source: str = "inferred"  # inferred | agent | operator

    def to_dict(self) -> dict:
        return asdict(self)

    @staticmethod
    def from_dict(d: dict) -> "SecurityInvariant":
        return SecurityInvariant(**d)


@dataclass
class PathScores:
    """Structured decision output for one attack path.

    Probabilities in [0, 1]. ``priority`` is computed by the orchestrator from the
    score dimensions and the configured weights; ``estimated_cost`` is the
    decision model's estimate of investigation effort (arbitrary units, lower is
    cheaper).
    """

    attacker_control: float = 0.0
    trust_boundary_crossing: float = 0.0
    authz_boundary_crossing: float = 0.0
    sensitive_sink: float = 0.0
    state_manipulation: float = 0.0
    invariant_violation: float = 0.0
    insufficient_validation: float = 0.0
    research_value: float = 0.0
    guard_bypassable: float = 0.0  # P(guard on this path can be bypassed)
    # P(input controls something the feature does not need: which host to
    # fetch, which file to open, which query to run, vs. content the
    # feature exists to pass through)
    unintended_use: float = 0.0
    # P(the sink, past the shown checks, reaches or returns something the
    # feature does not intend: file contents into attacker-visible state,
    # an arbitrary scheme or internal host fetched, code execution)
    sink_reach: float = 0.0
    # P(enforcement on this path depends on the attacker opting in: an
    # optional verify/decrypt branch whose else-case forwards the raw
    # value, an env- or config-gated check that may be unset)
    contract_gap: float = 0.0
    estimated_cost: float = 1.0
    continue_exploration: float = 0.5
    raw: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict:
        return asdict(self)

    @staticmethod
    def from_dict(d: dict) -> "PathScores":
        return PathScores(**d)


@dataclass
class AttackPath:
    """A candidate attack path through the graph: an ordered chain of node ids
    with full provenance back to source locations."""

    id: str
    nodes: list[str]  # node ids, source -> ... -> sink
    label: str = ""
    status: PathStatus = PathStatus.UNEXPLORED
    scores: Optional[PathScores] = None
    priority: float = 0.0
    hypothesis: str = ""
    iterations_investigated: int = 0
    dead_end_strikes: int = 0
    derived_from: Optional[str] = None  # parent path id when expanded by an agent
    evidence_ids: list[str] = field(default_factory=list)
    finding_id: Optional[str] = None
    history: list[dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> dict:
        d = asdict(self)
        d["status"] = self.status.value
        d["scores"] = self.scores.to_dict() if self.scores else None
        return d

    @staticmethod
    def from_dict(d: dict) -> "AttackPath":
        d = dict(d)
        d["status"] = PathStatus(d["status"])
        d["scores"] = PathScores.from_dict(d["scores"]) if d.get("scores") else None
        return AttackPath(**d)


@dataclass
class EvidenceItem:
    id: str
    path_id: str
    kind: str  # code_observation | authz_found | missing_guard | repro | counterexample | ...
    summary: str
    locations: list[SourceLocation] = field(default_factory=list)
    detail: str = ""

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "path_id": self.path_id,
            "kind": self.kind,
            "summary": self.summary,
            "locations": [l.to_dict() for l in self.locations],
            "detail": self.detail,
        }

    @staticmethod
    def from_dict(d: dict) -> "EvidenceItem":
        d = dict(d)
        d["locations"] = [SourceLocation.from_dict(l) for l in d.get("locations", [])]
        return EvidenceItem(**d)


@dataclass
class NewPathSpec:
    """A path the research agent asks the orchestrator to add to the graph."""

    description: str
    node_labels: list[str] = field(default_factory=list)
    source_hint: str = ""
    sink_hint: str = ""

    def to_dict(self) -> dict:
        return asdict(self)

    @staticmethod
    def from_dict(d: dict) -> "NewPathSpec":
        return NewPathSpec(**d)


@dataclass
class InvestigationReport:
    """Structured evidence returned by a ResearchAgent for one task."""

    hypothesis: str
    status: InvestigationStatus
    evidence: list[EvidenceItem] = field(default_factory=list)
    source_locations: list[SourceLocation] = field(default_factory=list)
    new_paths: list[NewPathSpec] = field(default_factory=list)
    new_invariants: list[SecurityInvariant] = field(default_factory=list)
    next_questions: list[str] = field(default_factory=list)
    agent: str = ""
    wall_seconds: float = 0.0
    raw: str = ""

    def to_dict(self) -> dict:
        return {
            "hypothesis": self.hypothesis,
            "status": self.status.value,
            "evidence": [e.to_dict() for e in self.evidence],
            "source_locations": [l.to_dict() for l in self.source_locations],
            "new_paths": [p.to_dict() for p in self.new_paths],
            "new_invariants": [i.to_dict() for i in self.new_invariants],
            "next_questions": self.next_questions,
            "agent": self.agent,
            "wall_seconds": self.wall_seconds,
        }


@dataclass
class Finding:
    id: str
    title: str
    vuln_class: str
    severity: str
    confidence: float
    affected_components: list[str]
    attack_path: list[str]  # node ids
    root_cause: str
    security_invariant: str
    evidence: list[EvidenceItem]
    reproduction: str
    source_locations: list[SourceLocation]
    validation_status: ValidationStatus = ValidationStatus.UNVERIFIED
    path_id: str = ""

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "title": self.title,
            "class": self.vuln_class,
            "severity": self.severity,
            "confidence": self.confidence,
            "affected_components": self.affected_components,
            "attack_path": self.attack_path,
            "root_cause": self.root_cause,
            "security_invariant": self.security_invariant,
            "evidence": [e.to_dict() for e in self.evidence],
            "reproduction": self.reproduction,
            "source_locations": [l.to_dict() for l in self.source_locations],
            "validation_status": self.validation_status.value,
            "path_id": self.path_id,
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2)


@dataclass
class RunStats:
    jev_calls: int = 0
    jev_input_tokens: int = 0
    jev_failures: int = 0
    agent_calls: int = 0
    agent_wall_seconds: float = 0.0
    paths_scored: int = 0
    paths_explored: int = 0
    paths_discarded: int = 0
    paths_verified: int = 0
    iterations: int = 0
    wall_seconds: float = 0.0

    def to_dict(self) -> dict:
        return asdict(self)

    @staticmethod
    def from_dict(d: dict) -> "RunStats":
        return RunStats(**d)

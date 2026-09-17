"""The search loop: generate candidate attack paths, score them with the
configured DecisionModel, send the best to the ResearchAgent, integrate the
evidence, expand the graph, re-score, and repeat under budget limits.
"""

from __future__ import annotations

import time
from pathlib import Path

from .agents.base import InvestigationTask, ResearchAgent
from .config import ScanConfig
from .decision.base import DecisionModel, path_state
from .findings import FindingStore
from .graph.code_graph import CodeGraph
from .graph.invariants import InvariantChecker, infer_invariants
from .graph.path_generator import AttackPathGenerator
from .models import (
    AttackPath,
    EvidenceItem,
    Finding,
    InvestigationStatus,
    PathStatus,
    RunStats,
    SecurityInvariant,
    ValidationStatus,
)
from .trace import Tracer
from .validation.base import Validator


class Orchestrator:
    def __init__(
        self,
        config: ScanConfig,
        graph: CodeGraph,
        generator: AttackPathGenerator,
        decision: DecisionModel,
        agent: ResearchAgent,
        validators: list[Validator],
        store: FindingStore,
        tracer: Tracer,
    ):
        self.config = config
        self.graph = graph
        self.generator = generator
        self.decision = decision
        self.agent = agent
        self.validators = validators
        self.store = store
        self.tracer = tracer
        self.checker = InvariantChecker(graph)
        self.invariants: list[SecurityInvariant] = infer_invariants(graph)
        self.paths: dict[str, AttackPath] = {}
        self.stats = RunStats()
        self._scored_history_len: dict[str, int] = {}
        self._finding_n = 0
        self.discovery_times: dict[str, float] = {}
        self._t0 = 0.0

    # ------------------------------------------------------------------ loop

    def run(self) -> "ScanResult":
        t0 = time.monotonic()
        self._t0 = t0
        for p in self.generator.generate(self.graph):
            self.paths[p.id] = p
        self.tracer.emit("generated", count=len(self.paths))

        while not self._budget_exceeded(t0):
            self.stats.iterations += 1
            it = self.stats.iterations
            self.tracer.emit("iteration", iteration=it, **self._status_counts())

            self._score_unexplored()
            selected = self._select()
            if not selected:
                self.tracer.emit("warning", message="no selectable paths remain")
                break

            for path in selected:
                if self._agent_budget_exceeded():
                    break
                self._investigate(path)

            if not self._has_candidates():
                break

        self.stats.wall_seconds = time.monotonic() - t0
        return ScanResult(
            findings=self.store.all(),
            paths=list(self.paths.values()),
            stats=self.stats,
            invariants=self.invariants,
        )

    # ------------------------------------------------------------------ steps

    def _score_unexplored(self) -> None:
        todo = [
            p for p in self.paths.values()
            if p.status in (PathStatus.UNEXPLORED, PathStatus.PROMISING)
            and (
                p.scores is None
                or (
                    self.config.rescore_after_evidence
                    and len(p.history) > self._scored_history_len.get(p.id, -1)
                )
            )
        ]
        if not todo:
            return
        self.decision.score_paths(todo, self.graph, self.checker, self.stats)
        for p in todo:
            p.priority = self._priority(p)
            self._scored_history_len[p.id] = len(p.history)
            self.stats.paths_scored += 1
        top = sorted(
            (p for p in self.paths.values()
             if p.status in (PathStatus.UNEXPLORED, PathStatus.PROMISING) and p.scores),
            key=lambda p: -p.priority,
        )[:5]
        self.tracer.emit("scores", count=len(todo), model=self.decision.name, top=[
            {"id": p.id, "priority": p.priority, "label": p.label} for p in top
        ])

    def _priority(self, path: AttackPath) -> float:
        if not path.scores:
            return 0.0
        base = self.config.priority(path.scores)
        # penalize repeatedly investigated dead ends
        base *= 0.85 ** path.iterations_investigated
        base *= 0.7 ** path.dead_end_strikes
        return base

    def _select(self) -> list[AttackPath]:
        cands = [
            p for p in self.paths.values()
            if p.status in (PathStatus.UNEXPLORED, PathStatus.PROMISING)
            and p.scores is not None
            and p.iterations_investigated < self.config.dead_end_threshold
        ]
        cands.sort(key=lambda p: (-p.priority, p.id))
        return cands[: self.config.select_per_iteration]

    def _investigate(self, path: AttackPath) -> None:
        path.status = PathStatus.EXPLORING
        path.iterations_investigated += 1
        self.stats.paths_explored += 1
        self.tracer.emit("selected", path_id=path.id, label=path.label)

        if not path.hypothesis:
            path.hypothesis = self._hypothesis(path)
        violated = self.checker.violated_invariants(path)
        task = InvestigationTask(
            path=path,
            hypothesis=path.hypothesis,
            invariants=violated,
            code_excerpts=path_state(path, self.graph, self.checker)["hops"],
            repo_root=self.graph.root,
        )
        report = self.agent.investigate(task, self.graph)
        self.stats.agent_calls += 1
        self.stats.agent_wall_seconds += report.wall_seconds
        self.tracer.emit(
            "investigation", path_id=path.id, agent=report.agent,
            status=report.status.value, wall_seconds=report.wall_seconds,
            n_evidence=len(report.evidence),
            next_questions=report.next_questions,
        )
        self._integrate(path, report)

    def _integrate(self, path: AttackPath, report) -> None:
        path.history.append({
            "iteration": self.stats.iterations,
            "status": report.status.value,
            "hypothesis": report.hypothesis,
            "evidence": [e.summary for e in report.evidence],
        })
        for e in report.evidence:
            e.path_id = path.id
            path.evidence_ids.append(e.id)
        self.invariants.extend(report.new_invariants)

        # expand the graph with agent-discovered paths
        new_paths: list[AttackPath] = []
        for spec in report.new_paths:
            for np in self.generator.expand(self.graph, spec, path):
                self.paths[np.id] = np
                new_paths.append(np)
        if new_paths:
            self.tracer.emit("new_paths", paths=[
                {"id": p.id, "label": p.label} for p in new_paths
            ])

        if report.status == InvestigationStatus.CONFIRMED:
            self._validate(path, report)
        elif report.status == InvestigationStatus.FALSIFIED:
            path.status = PathStatus.DISCARDED
            path.dead_end_strikes += 1
            self.stats.paths_discarded += 1
            self.tracer.emit("path_status", path_id=path.id, status="discarded")
            self._propagate_falsification(path, report)
        else:
            path.dead_end_strikes += 1
            path.status = (
                PathStatus.DISCARDED
                if path.dead_end_strikes >= self.config.dead_end_threshold
                else PathStatus.PROMISING
            )
            self.tracer.emit("path_status", path_id=path.id, status=path.status.value)

    def _validate(self, path: AttackPath, report) -> None:
        best = None
        for v in self.validators:
            res = v.validate(path, report, self.graph)
            path.history.append({
                "iteration": self.stats.iterations,
                "validator": v.name,
                "verified": res.verified,
                "detail": res.detail,
            })
            if res.verified:
                best = res
                break
            if best is None:
                best = res
        if best and best.verified:
            path.status = PathStatus.VERIFIED
            self.stats.paths_verified += 1
            self.discovery_times[path.id] = time.monotonic() - self._t0
            self._finding_n += 1
            sink = self.graph.nodes.get(path.nodes[-1])
            vuln = sink.attrs.get("vuln", "unknown") if sink else "unknown"
            finding = Finding(
                id=f"finding-{self._finding_n}",
                title=f"{vuln} via {self.graph.nodes[path.nodes[0]].label}",
                vuln_class=vuln,
                severity=self._severity(vuln),
                confidence=path.scores.research_value if path.scores else 0.0,
                affected_components=sorted({n.location.file for n in
                                            (self.graph.nodes[i] for i in path.nodes)
                                            if n}),
                attack_path=list(path.nodes),
                root_cause=report.hypothesis,
                security_invariant="; ".join(
                    i.statement for i in self.checker.violated_invariants(path)),
                evidence=report.evidence + [
                    EvidenceItem(id=f"val-{self._finding_n}", path_id=path.id,
                                 kind="repro", summary=best.detail,
                                 detail=best.reproduction),
                ],
                reproduction=best.reproduction,
                source_locations=self.graph.path_locations(path.nodes),
                validation_status=ValidationStatus.VERIFIED,
                path_id=path.id,
            )
            path.finding_id = finding.id
            self.store.add(finding)
            self.tracer.emit("finding", finding_id=finding.id,
                             title=finding.title, status="verified")
        else:
            # confirmed by agent but unproven: keep it promising unless stuck
            path.dead_end_strikes += 1
            path.status = (
                PathStatus.DISCARDED
                if path.dead_end_strikes >= self.config.dead_end_threshold
                else PathStatus.PROMISING
            )
            self.tracer.emit("path_status", path_id=path.id, status=path.status.value)

    def _propagate_falsification(self, path: AttackPath, report) -> None:
        """Attach falsification evidence to sibling paths sharing the sink, so a
        re-scoring model sees the counterevidence instead of re-ranking a dead
        hypothesis."""
        if not path.nodes:
            return
        sink_id = path.nodes[-1]
        note = (f"related path {path.id} falsified: "
                + "; ".join(e.summary for e in report.evidence[:3]))
        for other in self.paths.values():
            if other.id != path.id and other.nodes and other.nodes[-1] == sink_id:
                other.history.append({"iteration": self.stats.iterations,
                                      "note": note})

    # ------------------------------------------------------------------ util

    def _hypothesis(self, path: AttackPath) -> str:
        violated = self.checker.violated_invariants(path)
        sink = self.graph.nodes.get(path.nodes[-1])
        base = f"Attacker-controlled input reaches {sink.label if sink else 'sink'}"
        if violated:
            base += "; plausibly violates: " + "; ".join(i.statement for i in violated)
        return base

    @staticmethod
    def _severity(vuln: str) -> str:
        return {
            "command_execution": "critical",
            "code_execution": "critical",
            "unsafe_deserialization": "high",
            "outbound_request": "high",
            "raw_query": "high",
            "file_access": "medium",
            "file_delete": "high",
            "template_injection": "high",
            "open_redirect": "medium",
        }.get(vuln, "medium")

    def _status_counts(self) -> dict:
        c = {"unexplored": 0, "promising": 0, "verified": 0, "discarded": 0,
             "exploring": 0}
        for p in self.paths.values():
            c[p.status.value] = c.get(p.status.value, 0) + 1
        return c

    def _has_candidates(self) -> bool:
        return any(
            p.status in (PathStatus.UNEXPLORED, PathStatus.PROMISING)
            and p.iterations_investigated < self.config.dead_end_threshold
            for p in self.paths.values()
        )

    def _budget_exceeded(self, t0: float) -> bool:
        return (
            self.stats.iterations >= self.config.max_iterations
            or self.stats.jev_calls >= self.config.budget_jev_calls
            or time.monotonic() - t0 >= self.config.budget_seconds
        )

    def _agent_budget_exceeded(self) -> bool:
        return self.stats.agent_calls >= self.config.budget_agent_calls


class ScanResult:
    def __init__(self, findings, paths, stats, invariants):
        self.findings = findings
        self.paths = paths
        self.stats = stats
        self.invariants = invariants

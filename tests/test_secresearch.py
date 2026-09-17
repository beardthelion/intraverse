"""Unit tests for secresearch. Run with: PYTHONPATH=src python3 -m unittest discover -s tests -v
"""

import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from secresearch.agents.stub import StubAgent
from secresearch.agents.base import InvestigationTask
from secresearch.config import ScanConfig
from secresearch.decision.heuristics import (
    BaselineModel, RandomModel, StaticHeuristicModel,
)
from secresearch.findings import FindingStore
from secresearch.graph.invariants import InvariantChecker
from secresearch.graph.path_generator import GraphPathGenerator
from secresearch.graph.python_analyzer import PythonAnalyzer
from secresearch.graph.code_graph import CodeGraph
from secresearch.models import (
    AttackPath, GraphNode, InvestigationStatus, NodeType, PathStatus,
    SourceLocation,
)
from secresearch.orchestrator import Orchestrator
from secresearch.trace import Tracer
from secresearch.validation.static_proof import StaticProofValidator
from secresearch.benchmark.metrics import match_finding

FIXTURES = Path(__file__).resolve().parent.parent / "benchmarks" / "fixtures"


def analyze(fixture: str):
    graph = PythonAnalyzer().build(str(FIXTURES / fixture))
    paths = GraphPathGenerator().generate(graph)
    return graph, paths


def sink_line(graph, path):
    return graph.nodes[path.nodes[-1]].location.line_start


class TestAnalyzer(unittest.TestCase):
    def test_detects_entries(self):
        graph, _ = analyze("vuln-fetch")
        entries = graph.nodes_of_type(NodeType.HTTP_ENTRY)
        self.assertTrue(any("do_GET" in n.attrs.get("qualname", "") for n in entries))

    def test_detects_sinks_by_class(self):
        graph, paths = analyze("vuln-exec")
        vulns = {graph.nodes[p.nodes[-1]].attrs.get("vuln") for p in paths}
        self.assertIn("command_execution", vulns)

    def test_fstring_taint(self):
        # f-string interpolation must carry taint to the sink
        graph, paths = analyze("vuln-files")
        sinks = [graph.nodes[p.nodes[-1]] for p in paths]
        lines = sorted(s.location.line_start for s in sinks)
        self.assertIn(55, lines)  # open(f"files/{name}")
        self.assertIn(66, lines)  # conn.execute(f"... {account_id}")

    def test_parameterized_flag(self):
        graph, paths = analyze("vuln-files")
        flagged = [
            graph.nodes[p.nodes[-1]] for p in paths
            if graph.nodes[p.nodes[-1]].attrs.get("parameterized")
        ]
        self.assertTrue(flagged, "parameterized execute() should be flagged")

    def test_multi_hop_path(self):
        # taint through a helper: do_GET -> check_account_owner -> execute
        graph, paths = analyze("vuln-files")
        self.assertTrue(any(len(p.nodes) >= 3 for p in paths))


class TestGuards(unittest.TestCase):
    def test_same_line_sanitizer_dominates(self):
        graph, paths = analyze("clean-app")
        checker = InvariantChecker(graph)
        cmd = [p for p in paths
               if graph.nodes[p.nodes[-1]].attrs.get("vuln") == "command_execution"]
        self.assertTrue(cmd)
        self.assertTrue(checker.path_has_sanitizer(cmd[0]))

    def test_guard_does_not_leak_across_branches(self):
        # the sanitizer in /fetch-safe must not guard the /fetch sink
        graph, paths = analyze("vuln-fetch")
        checker = InvariantChecker(graph)
        unsafe = [p for p in paths if sink_line(graph, p) == 32]
        safe = [p for p in paths if sink_line(graph, p) == 42]
        self.assertFalse(checker.path_has_sanitizer(unsafe[0]))
        self.assertTrue(checker.path_has_sanitizer(safe[0]))


class TestStubAgent(unittest.TestCase):
    def _investigate(self, fixture, want_line):
        graph, paths = analyze(fixture)
        stub = StubAgent(str(FIXTURES / fixture))
        target = next(p for p in paths if sink_line(graph, p) == want_line)
        task = InvestigationTask(path=target, hypothesis="h", invariants=[])
        return stub.investigate(task, graph)

    def test_confirms_real_vuln(self):
        rep = self._investigate("vuln-fetch", 32)
        self.assertEqual(rep.status, InvestigationStatus.CONFIRMED)

    def test_falsifies_guarded(self):
        rep = self._investigate("vuln-fetch", 42)
        self.assertEqual(rep.status, InvestigationStatus.FALSIFIED)

    def test_falsifies_parameterized(self):
        rep = self._investigate("vuln-files", 79)
        self.assertEqual(rep.status, InvestigationStatus.FALSIFIED)


class TestStrategies(unittest.TestCase):
    def _score(self, model):
        graph, paths = analyze("vuln-fetch")
        checker = InvariantChecker(graph)
        from secresearch.models import RunStats
        stats = RunStats()
        for p in paths:
            p.scores = model.score_path(p, graph, checker, stats)
        return paths

    def test_static_ranks_unguarded_first(self):
        paths = self._score(StaticHeuristicModel())
        cfg = ScanConfig()
        ranked = sorted(paths, key=lambda p: -cfg.priority(p.scores))
        self.assertEqual(sink_line_for(ranked[0]), 32)

    def test_random_is_seeded(self):
        a = RandomModel(7)
        b = RandomModel(7)
        pa = self._score(a)
        pb = self._score(b)
        self.assertEqual(
            [p.scores.research_value for p in pa],
            [p.scores.research_value for p in pb],
        )

    def test_baseline_is_flat(self):
        paths = self._score(BaselineModel())
        self.assertTrue(all(p.scores.research_value == 0.5 for p in paths))


def sink_line_for(path):
    # sink line lookup needs the graph; rebuild cheaply
    graph = PythonAnalyzer().build(str(FIXTURES / "vuln-fetch"))
    return graph.nodes[path.nodes[-1]].location.line_start


class TestOrchestrator(unittest.TestCase):
    def _run(self, fixture, strategy="static"):
        cfg = ScanConfig(strategy=strategy, agent="stub", max_iterations=20)
        with tempfile.TemporaryDirectory() as td:
            graph = PythonAnalyzer().build(str(FIXTURES / fixture))
            store = FindingStore(str(Path(td) / "findings"))
            tracer = Tracer(None)
            orch = Orchestrator(
                cfg, graph, GraphPathGenerator(),
                StaticHeuristicModel() if strategy == "static" else BaselineModel(),
                StubAgent(str(FIXTURES / fixture)),
                [StaticProofValidator(str(FIXTURES / fixture))],
                store, tracer,
            )
            return orch.run(), orch

    def test_finds_and_verifies(self):
        result, _ = self._run("vuln-exec")
        self.assertEqual(len(result.findings), 1)
        self.assertEqual(result.findings[0].vuln_class, "command_execution")

    def test_falsified_paths_preserved(self):
        result, orch = self._run("clean-app")
        discarded = [p for p in result.paths if p.status == PathStatus.DISCARDED]
        self.assertTrue(discarded)
        self.assertTrue(all(p.history for p in discarded))
        self.assertEqual(len(result.findings), 0)

    def test_terminates_within_limits(self):
        result, _ = self._run("vuln-files")
        self.assertLessEqual(result.stats.iterations, 20)


class TestMetrics(unittest.TestCase):
    def test_match_by_class_file_line(self):
        from secresearch.models import Finding, ValidationStatus
        f = Finding(
            id="f1", title="t", vuln_class="outbound_request", severity="high",
            confidence=0.9, affected_components=["app.py"], attack_path=["a", "b"],
            root_cause="", security_invariant="", evidence=[], reproduction="",
            source_locations=[
                SourceLocation("app.py", "Handler.do_GET", 26, 47),
                SourceLocation("app.py", "Handler.do_GET", 32, 32),
            ],
            validation_status=ValidationStatus.VERIFIED,
        )
        truth = [{"class": "outbound_request", "sink_file": "app.py",
                  "sink_function": "do_GET", "sink_line": 32}]
        self.assertIsNotNone(match_finding(f, truth))
        # wrong line -> no match
        truth2 = [{"class": "outbound_request", "sink_file": "app.py",
                   "sink_function": "do_GET", "sink_line": 42}]
        self.assertIsNone(match_finding(f, truth2))


if __name__ == "__main__":
    unittest.main()

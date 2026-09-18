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


class TestJevParsing(unittest.TestCase):
    def test_score_normalized_by_rungs(self):
        # the API returns interpolated scores on a 0-indexed 0..4 rung scale;
        # a raw score of 1.0 is rung 1 of 4, not probability 1.0
        from secresearch.decision.jev import _score01
        self.assertAlmostEqual(_score01({"score": 4.0}), 1.0)
        self.assertAlmostEqual(_score01({"score": 2.0}), 0.5)
        self.assertAlmostEqual(_score01({"score": 1.04}), 0.26)
        self.assertAlmostEqual(_score01({"score": 0.0}), 0.0)

    def test_score_distribution_fallback(self):
        from secresearch.decision.jev import _score01
        dist = {"distribution": {"a": 0.0, "b": 0.0, "c": 0.0, "d": 0.0, "e": 1.0}}
        self.assertAlmostEqual(_score01(dist), 1.0)

    def test_noul_defaults_to_half(self):
        from secresearch.decision.jev import _noul
        self.assertEqual(_noul({}), 0.5)
        self.assertEqual(_noul({"noul": 0.9}), 0.9)

    def test_guard_bypassable_only_when_guarded(self):
        # bypassability must be zeroed on unguarded paths so its weight
        # cannot inflate them
        from secresearch.decision.jev import JevDecisionModel
        from secresearch.models import RunStats

        class FakeClient:
            def evaluate(self, state, questions=None):
                return {"answers": {"guard_bypassable": {"noul": 0.95}},
                        "usage": {}}

        graph, paths = analyze("vuln-fetch")
        checker = InvariantChecker(graph)
        model = JevDecisionModel(client=FakeClient())
        stats = RunStats()
        guarded = next(p for p in paths if sink_line(graph, p) == 42)
        unguarded = next(p for p in paths if sink_line(graph, p) == 32)
        self.assertEqual(
            model.score_path(guarded, graph, checker, stats).guard_bypassable,
            0.95)
        self.assertEqual(
            model.score_path(unguarded, graph, checker, stats).guard_bypassable,
            0.0)

    def test_state_includes_guard_code(self):
        from secresearch.decision.base import path_state
        graph, paths = analyze("vuln-fetch")
        checker = InvariantChecker(graph)
        guarded = next(p for p in paths if sink_line(graph, p) == 42)
        state = path_state(guarded, graph, checker)
        self.assertTrue(state["guards"])
        self.assertTrue(any("is_allowed" in g["call"] for g in state["guards"]))

    def test_state_resolves_guard_definition(self):
        # guard judgments need the check's body, not just its call site
        from secresearch.decision.base import path_state
        graph, paths = analyze("vuln-fetch")
        checker = InvariantChecker(graph)
        guarded = next(p for p in paths if sink_line(graph, p) == 42)
        guard = next(g for g in path_state(guarded, graph, checker)["guards"]
                     if "is_allowed" in g["call"])
        self.assertIn("definition", guard)
        self.assertIn("ALLOWED", guard["definition"]["code"]
                      + guard["definition"].get("module_constants", ""))


class TestDevinReportParsing(unittest.TestCase):
    def _task(self):
        graph, paths = analyze("vuln-fetch")
        return InvestigationTask(path=paths[0], hypothesis="h", invariants=[])

    def test_parses_trailing_json(self):
        from secresearch.agents.devin_cli import parse_report
        text = ('prose analysis first\n{"hypothesis": "h", "status": "confirmed",'
                ' "evidence": [{"kind": "reachability", "summary": "reaches sink",'
                ' "file": "app.py", "line_start": 32, "line_end": 32}],'
                ' "new_paths": [{"description": "alt", "node_labels": ["a","b"],'
                ' "source_hint": "", "sink_hint": ""}],'
                ' "next_questions": ["q1"]}')
        rep = parse_report(text, self._task(), 1.0)
        self.assertEqual(rep.status, InvestigationStatus.CONFIRMED)
        self.assertEqual(len(rep.evidence), 1)
        self.assertEqual(len(rep.new_paths), 1)
        self.assertEqual(rep.next_questions, ["q1"])

    def test_uses_last_json_object(self):
        from secresearch.agents.devin_cli import parse_report
        text = ('{"status": "uncertain"} more prose '
                '{"hypothesis": "h", "status": "falsified", "evidence": []}')
        rep = parse_report(text, self._task(), 1.0)
        self.assertEqual(rep.status, InvestigationStatus.FALSIFIED)

    def test_no_json_is_uncertain(self):
        from secresearch.agents.devin_cli import parse_report
        rep = parse_report("no structured output here", self._task(), 1.0)
        self.assertEqual(rep.status, InvestigationStatus.UNCERTAIN)


class TestHttpSandbox(unittest.TestCase):
    def test_localhost_allowlist_bypass_verified(self):
        # /fetch-safe allowlists "localhost"; a loopback canary URL must still
        # produce a server-side fetch, proving the guard is bypassable
        from secresearch.validation.http_sandbox import HttpSandboxValidator
        from secresearch.models import InvestigationReport
        graph, paths = analyze("vuln-fetch")
        target = next(p for p in paths if sink_line(graph, p) == 42)
        rep = InvestigationReport(
            hypothesis="h", status=InvestigationStatus.CONFIRMED, agent="t")
        v = HttpSandboxValidator(str(FIXTURES / "vuln-fetch"))
        res = v.validate(target, rep, graph)
        self.assertTrue(res.verified, res.detail)

    def test_no_vuln_means_unverified(self):
        from secresearch.validation.http_sandbox import HttpSandboxValidator
        from secresearch.models import InvestigationReport
        graph, paths = analyze("clean-app")
        target = next(
            p for p in paths
            if graph.nodes[p.nodes[-1]].attrs.get("vuln") == "command_execution")
        rep = InvestigationReport(
            hypothesis="h", status=InvestigationStatus.CONFIRMED, agent="t")
        v = HttpSandboxValidator(str(FIXTURES / "clean-app"))
        res = v.validate(target, rep, graph)
        self.assertFalse(res.verified)


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

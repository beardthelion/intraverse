"""security-research CLI.

    security-research graph ./repo
    security-research paths ./repo
    security-research scan ./repo --strategy=jev --max-iterations=40
    security-research finding <id> --findings-dir runs/.../findings
    security-research benchmark benchmarks/ --strategies jev,baseline
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .config import ScanConfig


def _build_stack(cfg: ScanConfig, repo: str, output_dir: str):
    """Wire analyzer, generator, decision model, agent, validators, store."""
    from .agents.stub import StubAgent
    from .decision.base import DecisionModel
    from .decision.heuristics import BaselineModel, RandomModel, StaticHeuristicModel
    from .findings import FindingStore
    from .graph.path_generator import GraphPathGenerator
    from .graph.python_analyzer import PythonAnalyzer
    from .orchestrator import Orchestrator
    from .trace import Tracer
    from .validation.static_proof import StaticProofValidator

    analyzer = PythonAnalyzer()
    graph = analyzer.build(repo)
    generator = GraphPathGenerator(cfg.max_path_depth, cfg.max_paths)

    if cfg.strategy == "jev":
        from .decision.jev import JevDecisionModel
        decision: DecisionModel = JevDecisionModel()
    elif cfg.strategy == "static":
        decision = StaticHeuristicModel()
    elif cfg.strategy == "random":
        decision = RandomModel(seed=cfg.random_seed)
    else:
        decision = BaselineModel()

    if cfg.agent == "devin":
        from .agents.devin_cli import DevinCliAgent
        agent = DevinCliAgent(repo, timeout=cfg.devin_timeout, model=cfg.devin_model)
    else:
        agent = StubAgent(repo)

    validators = [StaticProofValidator(repo)]
    try:
        from .validation.http_sandbox import HttpSandboxValidator
        validators.insert(0, HttpSandboxValidator(repo))
    except Exception:
        pass

    store = FindingStore(str(Path(output_dir) / "findings"))
    tracer = Tracer(output_dir, verbose=cfg.verbose)
    orch = Orchestrator(cfg, graph, generator, decision, agent, validators, store, tracer)
    return orch, graph


def cmd_graph(args) -> int:
    from .graph.python_analyzer import PythonAnalyzer
    graph = PythonAnalyzer().build(args.repo)
    if args.output:
        Path(args.output).write_text(json.dumps(graph.to_dict(), indent=2))
        print(f"wrote {args.output}: {len(graph.nodes)} nodes, {len(graph.edges)} edges")
    else:
        for n in graph.nodes.values():
            print(f"{n.id:24} {n.type.value:16} {n.label:50} {n.location.short()}")
        print(f"\n{len(graph.nodes)} nodes, {len(graph.edges)} edges")
    return 0


def cmd_paths(args) -> int:
    from .graph.path_generator import GraphPathGenerator
    from .graph.python_analyzer import PythonAnalyzer
    graph = PythonAnalyzer().build(args.repo)
    gen = GraphPathGenerator()
    paths = gen.generate(graph)
    for p in paths:
        print(f"{p.id}  {p.label}")
    print(f"\n{len(paths)} candidate paths")
    return 0


def cmd_scan(args) -> int:
    if args.config:
        cfg = ScanConfig.from_file(args.config)
    else:
        cfg = ScanConfig()
    # CLI flags always override the config file
    cfg.strategy = args.strategy
    cfg.agent = args.agent
    cfg.language = args.language
    cfg.max_iterations = args.max_iterations
    cfg.budget_seconds = args.budget_seconds
    cfg.output_dir = args.output or cfg.output_dir
    cfg.verbose = args.verbose
    cfg.random_seed = args.seed
    cfg.devin_model = args.devin_model or cfg.devin_model
    out = Path(cfg.output_dir)
    out.mkdir(parents=True, exist_ok=True)
    orch, graph = _build_stack(cfg, args.repo, str(out))
    result = orch.run()
    orch.tracer.close()

    summary = {
        "repo": args.repo,
        "strategy": cfg.strategy,
        "stats": result.stats.to_dict(),
        "findings": [f.to_dict() for f in result.findings],
        "paths": {p.id: {"status": p.status.value, "priority": p.priority,
                          "label": p.label} for p in result.paths},
    }
    (out / "scan-result.json").write_text(json.dumps(summary, indent=2))
    print(f"\nscan complete: {len(result.findings)} findings, "
          f"{result.stats.iterations} iterations, "
          f"{result.stats.jev_calls} jev calls, "
          f"{result.stats.agent_calls} agent calls")
    for f in result.findings:
        print(f"  {f.id} [{f.validation_status.value}] {f.title}")
    print(f"output: {out}")
    return 0


def cmd_finding(args) -> int:
    from .findings import FindingStore
    store = FindingStore(args.findings_dir)
    f = store.get(args.finding_id)
    if not f:
        print(f"finding {args.finding_id} not found in {args.findings_dir}")
        return 1
    print(f.to_json())
    return 0


def cmd_benchmark(args) -> int:
    from .benchmark.harness import run_benchmark
    strategies = args.strategies.split(",") if args.strategies else ["jev", "baseline"]
    report = run_benchmark(
        dataset_dir=args.dataset,
        strategies=strategies,
        agent=args.agent,
        max_iterations=args.max_iterations,
        budget_seconds=args.budget_seconds,
        output_dir=args.output or "runs/benchmark",
        verbose=args.verbose,
        seed=args.seed,
    )
    print(report.render())
    out = Path(args.output or "runs/benchmark")
    out.mkdir(parents=True, exist_ok=True)
    (out / "benchmark-report.json").write_text(json.dumps(report.to_dict(), indent=2))
    print(f"\nwrote {out / 'benchmark-report.json'}")
    return 0


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="security-research")
    sub = ap.add_subparsers(dest="cmd", required=True)

    def common(p):
        p.add_argument("repo", nargs="?", default=".")
        p.add_argument("--strategy", default="jev",
                       choices=["jev", "static", "random", "baseline"])
        p.add_argument("--agent", default="stub", choices=["stub", "devin"])
        p.add_argument("--language", default="python")
        p.add_argument("--max-iterations", type=int, default=40)
        p.add_argument("--budget-seconds", type=float, default=3600.0)
        p.add_argument("--output", default=None)
        p.add_argument("--verbose", action="store_true")
        p.add_argument("--seed", type=int, default=0)
        p.add_argument("--devin-model", default=None)
        p.add_argument("--config", default=None)

    for name, fn in (("graph", cmd_graph), ("paths", cmd_paths), ("scan", cmd_scan)):
        p = sub.add_parser(name)
        common(p)
        p.set_defaults(fn=fn)

    p = sub.add_parser("finding")
    p.add_argument("finding_id")
    p.add_argument("--findings-dir", required=True)
    p.set_defaults(fn=cmd_finding)

    p = sub.add_parser("benchmark")
    p.add_argument("dataset")
    p.add_argument("--strategies", default="jev,baseline")
    p.add_argument("--agent", default="stub", choices=["stub", "devin"])
    p.add_argument("--max-iterations", type=int, default=40)
    p.add_argument("--budget-seconds", type=float, default=3600.0)
    p.add_argument("--output", default=None)
    p.add_argument("--verbose", action="store_true")
    p.add_argument("--seed", type=int, default=0)
    p.set_defaults(fn=cmd_benchmark)

    args = ap.parse_args(argv)
    return args.fn(args)


if __name__ == "__main__":
    sys.exit(main())

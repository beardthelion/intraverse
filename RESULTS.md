# Results

Benchmarks run against `benchmarks/fixtures/` (six synthetic apps with planted
vulnerabilities; ground truth in `benchmarks/ground_truth/`). Strategy
comparison used the deterministic `stub` research agent so every strategy saw
the same investigator. A separate smoke run used the real `devin` agent.

Report: `runs/bench-final/benchmark-report.json` (max-iterations=6 per run).

## Strategy comparison (stub agent, all fixtures)

```
fixture    | strategy | TP | FP | missed | explored | agent | jev | wall_s | jev_$
-----------|----------|----|----|--------|----------|-------|-----|--------|------
clean-app  | jev      | 0  | 0  | 0      | 3        | 3     | 3   | 1.0    | .00014
clean-app  | static   | 0  | 0  | 0      | 3        | 3     | 0   | 0.0    | 0
clean-app  | random   | 0  | 0  | 0      | 3        | 3     | 0   | 0.0    | 0
clean-app  | baseline | 0  | 0  | 0      | 3        | 3     | 0   | 0.0    | 0
vuln-exec  | all four | 1  | 0  | 0      | 2        | 2     | *   | ~0.5-1 | ~.0001
vuln-fetch | all four | 1  | 0  | 1      | 2        | 2     | *   | ~0.7-1 | ~.0001
vuln-files | all four | 2  | 0  | 0      | 4        | 4     | *   | ~1-2   | ~.0002
vuln-mixed | all four | 2  | 0  | 0      | 3        | 3     | *   | ~1-2   | ~.0001
vuln-heap  | jev      | 3  | 0  | 1      | 6        | 6     | 11  | 5.6    | .00050
vuln-heap  | static   | 4  | 0  | 0      | 6        | 6     | 0   | 2.3    | 0
vuln-heap  | random   | 2  | 0  | 2      | 6        | 6     | 0   | 1.2    | 0
vuln-heap  | baseline | 2  | 0  | 2      | 6        | 6     | 0   | 1.2    | 0
```

`vuln-heap` is the only fixture dense enough for ranking to matter (11
candidate paths, 4 real vulns among guarded decoys, budget 6 picks).
Repetitions of the jev row: TP 4, 4, 3 across three runs; the SSRF path
scores near the decoys and its rank varies run to run.

`vuln-fetch` missed=1 for every strategy because the stub agent falsifies the
`/fetch-safe` allowlist bypass (the guard exists but admits `localhost`
targets). Search surfaced the path; the cheap investigator could not reason
through the bypass.

## Real agent run (devin-cli + jev, vuln-fetch)

```
=== Iteration 1 ===
  #path-1  score 3.25  http.request -> HTTP GET -> urlopen() [outbound_request] @app.py:32
  #path-2  score 2.50  http.request -> HTTP GET -> urlopen() [outbound_request] @app.py:42
  Agent [devin-cli] -> confirmed (28.5s, 6 evidence items)
  FINDING finding-1: outbound_request [verified]
=== Iteration 2 ===
  Agent [devin-cli] -> uncertain (89.2s)   # path-2 stays PROMISING
=== Iteration 3 ===
  #path-2  re-scored 1.60, re-selected
  Agent [devin-cli] -> confirmed (33.7s)
  FINDING finding-2: outbound_request [verified]   # localhost allowlist bypass
scan complete: 2 findings, 3 iterations, 3 jev calls, 3 agent calls
```

Both vulns verified, including the allowlist bypass the stub falsified. The
sandbox proved it by fetching `http://localhost:<canary>/hit` through
`/fetch-safe` and observing the canary hit. Iteration 2 -> 3 shows the
evidence loop working: uncertain evidence kept the path alive, Jev re-scored
it, and a second investigation confirmed it.

## Adapter bug found and fixed during benchmarking

Jev returns `score` answers on a 0-indexed rung scale (0..4). The original
normalizer treated values <= 1.0 as already-normalized probabilities, which
crushed a "trivial" investigation cost of 1.04 to 0.01 while "cheap" 0.5
stayed 0.5, inverting the cost ratio and ranking a decoy first. Pre-fix
vuln-heap: jev TP=1 vs static TP=4. Post-fix: TP=3-4. The headline numbers
above are post-fix; the bug itself is a data point: adapter semantics matter
more than model quality at this scale, and the benchmark caught it.

## Conclusions

1. **Did Jev improve path selection?** Over random and flat baselines, yes:
   3-4/4 vulns under a 6-pick budget vs 2/4. Against the static heuristic it
   roughly tied (3-4 vs 4). The fixtures are small; on corpora where most
   paths fit under budget, ranking barely matters. The discriminating signal
   was real where measured: real SQLi scored insufficient_validation 0.98 vs
   0.35 for the parameterized decoy.

2. **Did it reduce expensive agent investigation?** Directionally. Jev calls
   cost ~1s and ~$0.0001 per fixture; a devin-cli investigation costs 30-90s.
   On vuln-heap Jev spent 5-6 agent calls on mostly-real paths while random
   wasted picks on decoys. Whether that advantage compounds on real
   repositories with thousands of candidate paths is untested.

3. **Did it discover vulnerabilities the baseline missed?** On vuln-heap, yes:
   random and baseline each missed 2 of 4, Jev missed 0-1. No fixture gave
   Jev a vuln that static missed in the same run.

4. **Where did Jev make incorrect predictions?** Marginal cases. The SSRF
   path on vuln-heap scored 1.9-3.1 across runs, straddling the budget cut;
   it was found twice and missed once. It also ranked a guarded `open()`
   decoy (path-3, 1.91) above two real vulns in the bench-final run. The
   earlier catastrophic miss was the normalization bug, not the model.

5. **What is the biggest bottleneck?** The research agent, not the search.
   Agent calls dominate wall time ~100:1 over everything else, and agent
   depth is where findings are lost: the stub falsified a genuinely
   vulnerable path it could not reason through. Search only has to nominate
   paths; the investigator decides them.

6. **What experiment should run next?** Two things. (a) A decoy-dense,
   multi-file corpus: real authorized OSS projects with known CVEs or a
   larger synthetic suite, at n>=10 runs per strategy, to measure Jev
   variance and whether it separates from the static heuristic once
   candidate counts exceed budget by orders of magnitude. (b) An agent
   ablation on the same strategy (stub vs devin-cli) to isolate how much
   recall is lost at the investigator layer rather than the ranker.

## Limitations

- Python-only analyzer; heuristic AST taint, no real interprocedural dataflow
  engine.
- Fixtures are small and single-file; planted vulns and decoys are adjacent.
- The stub agent is deterministic and much weaker than a real coding agent,
  so strategy rows share its blind spots (e.g. the vuln-fetch miss).
- Jev scoring is stochastic; single-run numbers have visible variance.
- Jev requires network + `TYPESAFE_API_KEY`; devin-cli requires the Devin CLI.
- Sandbox validation covers runnable stdlib HTTP fixtures only; other repos
  fall back to static proof.

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

## Dense-corpus experiment (the real test)

`benchmarks/dense/` holds a generated multi-file app (`corpus-a`): 58
candidate paths, 16 planted vulns (10 unguarded, 6 behind bypassable guards
like a `localhost`-permitting allowlist or a `|`-only blacklist), 30 guarded
decoys, and 12 soundness traps (authz-guarded dead ends, `isalnum()`/`len()`/
`sha256` paths that are tainted but safe). Budget: 14 investigations per run.

Stub-agent sweep (n=10 jev, n=10 random seeds, n=3 static/baseline):

```
strategy   TP           FP           missed       sel_prec  sel_vulns
jev        6.2 [6-7]    7.8 [7-8]    9.8 [9-10]   44%       6.2 [6-7]
static     4.0          4.0          12.0         29%       4.0
random     3.2 [1-5]    2.9 [0-5]    12.8 [11-15] 35%       4.9 [2-6]
baseline   3.0          0.0          13.0         64%*      9.0
```

*baseline is flat-priority and resolves ties by lexicographic path id; the
generator happens to place vulns early, inflating its raw numbers. Treat it
as a floor, not a competitor.

The interesting part is what Jev picked: its 14 selections were almost all
paths with *no visible guard* — the 10 unguarded vulns plus the invisible-
guard/bounded traps. It skipped every parameterized query, `shlex.quote`,
`basename`, and real-allowlist decoy. Its high FP count is a validator
artifact: stub+static-proof cannot see `isalnum()`/`len()`/`sha256()` as
guards, so those paths "verify". The ranker did its job; the soundness traps
separated at the investigator layer, which is what they are for.

Agent ablation (devin-cli, 12 picks/run, 2 reps per strategy):

```
strategy   TP             FP         sel_prec
jev        4.5 [3-6]      0.5 [0-1]  63%
static     2.0 [2-2]      4.5 [3-6]  42%
```

With a real investigator the ranking gap widens: Jev-guided selection gave
devin 2x the verified TPs and ~9x fewer FPs than static. Devin falsified the
bounded-transform traps correctly (FP collapse vs stub's 7.8) and expanded
the graph with agent-suggested paths — rep1's finding-5 (pickle.loads, r010)
was reached only through such an expansion. Its weakness: `uncertain` on
several unambiguous vulns (it reasons about deployment context, e.g. whether
loopback binding matters), stalling paths under a fixed budget.

The six bypassable-guard vulns were picked 35 times across all 30 runs
(mostly random/baseline ordering) and the stub falsified every one; under
devin neither ranker put them in the top 12. "Guard present" dominates both
scorers even when the guard is bypassable — the systematic blind spot this
experiment exposed.

## Conclusions

1. **Did Jev improve path selection?** Yes, measurably, once candidates
   outnumbered budget. On corpus-a (58 paths, 14 picks): Jev selected 6.2
   real-vuln paths/run vs static 4.0 and random 4.9, and skipped the entire
   falsifiable-decoy pool. Under devin-cli the gap widened: 4.5 vs 2.0
   verified TPs and 0.5 vs 4.5 FPs. On the small corpus it only tied static;
   ranking quality is invisible when everything fits under budget.

2. **Did it reduce expensive agent investigation?** Yes where it counts.
   Jev calls cost ~1s and ~$0.0001/fixture vs 30-150s per devin-cli call.
   Under the same investigation budget, Jev's picks converted to findings at
   ~44% (stub) / 63% (devin) vs static's ~29%/42% — roughly half the wasted
   agent calls per verified vuln.

3. **Did it discover vulnerabilities the baseline missed?** Partly. It found
   ~1.5-2.5x more real vulns than static/random under budget. It did NOT find
   the bypassable-guard class: "guard present" suppresses its score even when
   the guard is fake, the same blind spot the static heuristic has.

4. **Where did Jev make incorrect predictions?** (a) It cannot distinguish
   "tainted but bounded" (len/sha256/isalnum traps) from unguarded — it ranked
   all six traps high. Defensible: the graph shows no guard, so they ARE
   suspicious; the investigator layer is where they should die. (b) SSRF on
   vuln-heap straddled the budget cut across runs. (c) The earlier catastrophic
   miss was an adapter normalization bug, not the model.

5. **What is the biggest bottleneck?** Still the investigator, but now
   precisely characterized: stub falsifies real vulns it cannot reason
   through (all 6 bypassable-guard vulns); devin reasons correctly but burns
   30-150s/call and stalls on epistemic caution ("uncertain" on unambiguous
   injections). Second bottleneck: validator soundness — static proof
   verifies paths whose guards it cannot see, turning ranker noise into FPs.

6. **What experiment should run next?** (a) Guard-quality scoring: ask Jev
   specifically "is this guard bypassable?" on guarded paths rather than
   letting guard presence suppress the score — the 6 hard vulns are the
   discriminating class. (b) Point the pipeline at a real authorized OSS
   repo with known CVEs to see if candidate counts reach the regime where
   ranking dominates. (c) Larger devin ablation (n>=5) once per-run cost is
   tolerable; two reps is a hint, not a measurement.

## Limitations

- Python-only analyzer; heuristic AST taint, no real interprocedural dataflow
  engine.
- Original fixtures are small and single-file; corpus-a is multi-file but
  still synthetic, with planted vulns and decoys drawn from a small pattern
  set.
- The stub agent is deterministic and much weaker than a real coding agent,
  so strategy rows share its blind spots (e.g. the vuln-fetch miss).
- Jev scoring is stochastic; single-run numbers have visible variance (on
  corpus-a it was stable, TP 6-7; on vuln-heap it swung a marginal path).
- The generated corpus places easy vulns on early routes, which inflates the
  flat-ordering baseline's apparent precision; treat baseline as a floor.
- Static proof cannot verify that a *dynamic* guard is effective, and cannot
  see guards that are not sanitizer-named calls — both produce verified FPs.
- Two validator/adapter bugs were found and fixed during this experiment
  (greedy JSON report regex, weak raw_query sandbox check, 503 retry); the
  earlier `jev score` rung-normalization fix is described above.
- Jev requires network + `TYPESAFE_API_KEY`; devin-cli requires the Devin CLI.
- Sandbox validation covers runnable stdlib HTTP fixtures only; other repos
  fall back to static proof.

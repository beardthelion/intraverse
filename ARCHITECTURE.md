# Architecture

secresearch is a research MVP for autonomous vulnerability discovery. The
central hypothesis under test: a cheap probabilistic decision model (Jev,
TypeSafe AI's System One model) can rank attack paths well enough that an
expensive reasoning agent spends its budget only on the paths most likely to
be real vulnerabilities.

## Data flow

```
repository
   |  PythonAnalyzer (stdlib ast)
   v
CodeGraph            typed nodes/edges with file:function:line provenance
   |  GraphPathGenerator
   v
AttackPath[]         candidate source -> transform -> boundary -> sink chains
   |  DecisionModel.score_path()
   v
PathScores           calibrated probabilities per path dimension
   |  priority = weighted value / estimated cost
   v
ResearchAgent        narrow investigation task -> InvestigationReport
   |  evidence, falsifications, new paths, new invariants
   v
orchestrator         updates path states, expands graph, re-scores
   |  confirmed hypotheses
   v
Validator            static proof or localhost sandbox reproduction
   v
Finding              verified, with the full reasoning chain attached
```

## Layers and interfaces

Every layer is an interface so components can be swapped and compared:

- `CodeGraphProvider` (`graph/code_graph.py`): language analyzers. Today:
  `PythonAnalyzer`, a stdlib-ast pass that detects http.server/Flask-style
  entries, user-input sources, typed sinks (exec, deserialization, net, fs,
  db, template, redirect), auth calls/decorators, and sanitizer calls, then
  runs intra- and inter-procedural taint to wire `data_flows_into`, `calls`,
  `authorizes`, `transforms` edges.
- `AttackPathGenerator` (`graph/path_generator.py`): enumerates deduplicated
  entry->sink paths and expands the graph when agents report new paths.
- `SecurityInvariant` + `InvariantChecker` (`graph/invariants.py`): rules like
  "attacker-controlled input must not reach process execution without a
  sanitizing transform," evaluated against each path with dominance-aware
  guard checks (a guard only counts if it textually dominates the sink within
  the same branch).
- `DecisionModel` (`decision/`): `JevDecisionModel` posts the path state
  (hops, code excerpts, prior evidence notes) to `api.typesafe.ai/v1/systemone`
  with noul/score questions and gets calibrated probabilities back. Ablations:
  `StaticHeuristicModel`, `RandomModel` (seeded), `BaselineModel` (flat).
- `ResearchAgent` (`agents/`): `StubAgent` (deterministic invariant re-checker,
  for offline runs and baselines) and `DevinCliAgent` (`devin -p` subprocess;
  prompt pins one hypothesis, demands a structured JSON report ending in
  confirmed | falsified | uncertain plus new_paths/new_invariants).
- `Validator` (`validation/`): `StaticProofValidator` re-checks every hop and
  guard claim against source; `HttpSandboxValidator` launches runnable fixture
  apps on 127.0.0.1 and sends a vuln-class-appropriate exploit request
  (canary listener for SSRF, marker echo for command injection, traversal,
  redirect Location checks). Nothing leaves localhost.
- `FindingStore` (`findings.py`): one JSON per finding + index.
- `Orchestrator` (`orchestrator.py`): the search loop and anti-tunnel-vision
  machinery (dead-end decay, falsification propagation to sibling paths,
  verified-requires-validator gate).
- `benchmark/` harness: fixtures under `benchmarks/fixtures/`, ground truth in
  `benchmarks/ground_truth/` — outside the indexed tree so the searcher never
  sees it.

## Search loop

Per iteration: score all UNEXPLORED/PROMISING paths with new evidence ->
priority = Sigma(w_i * p_i) / cost^alpha (weights in ScanConfig) -> select top
K -> investigate -> integrate evidence -> expand graph -> rescore. Paths move
through UNEXPLORED -> EXPLORING -> PROMISING -> VERIFIED | DISCARDED. Budgets
cap iterations, Jev calls, agent calls, and wall time.

## Anti-confirmation-bias mechanisms

- FALSIFIED is a first-class agent result; falsified paths are retained with
  their counter-evidence, not deleted.
- Falsification propagates to sibling paths sharing the sink as evidence
  notes, which Jev sees on re-score.
- Repeatedly investigated dead ends decay (`0.85^investigated`,
  `0.7^strikes`) and discard at a threshold.
- Jev probabilities are search signals only: VERIFIED requires a validator's
  concrete evidence. An agent's "confirmed" without proof keeps the path
  PROMISING.
- Agents may emit `new_paths`/`new_invariants`, which expand the candidate
  graph mid-search.

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
paths with *no visible guard*, the 10 unguarded vulns plus the invisible-
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
the graph with agent-suggested paths, rep1's finding-5 (pickle.loads, r010)
was reached only through such an expansion. Its weakness: `uncertain` on
several unambiguous vulns (it reasons about deployment context, e.g. whether
loopback binding matters), stalling paths under a fixed budget.

The six bypassable-guard vulns were picked 35 times across all 30 runs
(mostly random/baseline ordering) and the stub falsified every one; under
devin neither ranker put them in the top 12. "Guard present" dominates both
scorers even when the guard is bypassable, the systematic blind spot this
experiment exposed.

## Guard-bypass scoring experiment

Follow-up to close that blind spot. Three changes: `path_state` now resolves
each guard call to its function definition (plus referenced module constants
like allowlist contents, not just the call site), a `guard_bypassable`
score dimension (weight 0.15, zeroed on unguarded paths) asks Jev whether a
concrete attacker input defeats the shown guard, and the question requires
naming a concrete bypass.

Effect on ranking (single scoring pass over all 58 paths): the six hard
vulns moved from ranks ~21-51 (all outside the 14-pick budget) to ranks
2, 3, 6, 7, 10, 29, five inside budget. Bypass scores on hards ran
0.80-0.93 vs 0.0 on parameterized decoys. Residual noise: `os.path.basename`
decoys still score 0.77-0.84 (Jev stays suspicious of basename), costing a
few picks.

Measured reruns:

```
agent  strategy       n   TP           FP          sel_prec  note
stub   jev (old)     10   6.2 [6-7]    7.8 [7-8]   44%       0 hard picks
stub   jev+gb        10   1.9 [1-3]    1.8 [0-3]   51%       53 hard picks,
                                                           all falsified
devin  jev (old)      2   4.5 [3-6]    0.5 [0-1]   63%       0 hard picks
devin  jev+gb         2   7.5 [7-8]    0.0 [0-0]   76%       hards confirmed:
                                                           r011,12,14,15,16
```

Read the stub and devin rows together. The ranker now sends the bypassable-
guard vulns to the investigator (53 hard selections across 10 stub reps, up
from 0) and selection precision rose in both settings. Under the stub,
verified TP *drops* (1.9 vs 6.2): the stub falsifies every guarded path it
is handed, so better ranking just spends more budget on paths the stub
cannot judge. Under devin the same selections convert: TP 4.5 -> 7.5 with
zero FPs, devin confirmed 5 of the 6 bypassable-guard vulns per rep,
including the `localhost`-allowlist SSRF, the `|`-only command blacklist,
and the quote-stripping SQLi.

## Real-OSS experiment (benchmarks/oss)

Two real repos at pre-fix commits, vendored into `benchmarks/oss/fixtures/`:

- **whoogle-search** @ `3a2e0b2~1` (CVE-2024-22205, SSRF in `element`/`window`
  endpoints): 11 candidate paths, ~6 real vulns (2 SSRF + traversal/deser/
  redirect in the config endpoints), budget 6 picks.
- **alerta** v9.0.0 (CVE-2026-34400, SQLi via the `q=` query param parsed into
  a raw `WHERE` fragment): 62 candidate paths, ~28 endpoints sharing the
  vulnerable `qb.*.from_params(request.args)` flow, budget 12 picks.

**Analyzer fixes real code required.** Three gaps only real repos exposed:
`x or default` (BoolOp) dropped taint, keyword args (`send(base_url=q)`)
were never propagated into callee params, and test suites were being
scanned as attack surface. All three are fixed; the CVE chains enumerate
on both repos.

**Scoring caveat found on real code.** Sink-line truth matching is unsound
when many flows share a helper: 5 whoogle paths converge on
`requests.get` @request.py:339 and every alerta query funnels through the
same `cursor.execute` helpers. Naive matching scored static alerta TP=2 , 
route-aware scoring (`benchmarks/oss/score.py`, a finding counts only if
its *entry* is a genuinely vulnerable endpoint) revises that to TP=0.

Route-aware results (stub agent):

```
fixture       strategy   n   TP         FP         picks-on-vuln-routes
alerta-sqli   jev        3   4.0        8.0        4/12
alerta-sqli   random     2   4.0        8.0        4/12
alerta-sqli   static     2   0.0        12.0       0/12
whoogle-ssrf  jev        5   3.4 [3-4]  2.6 [2-3]  CVE paths: 0
whoogle-ssrf  static     2   3.0        3.0        CVE paths: 0
whoogle-ssrf  random     3   2.0        4.0        CVE paths: 0
whoogle-ssrf  baseline   2   3.0        3.0        CVE paths: 0
```

**What it means.** On alerta, Jev put the real CVE flows (`/_bulk/alerts`,
`/keys`) in the top 12 every rep while static actively anti-selected them
(0/12), but random matched Jev because ~40% of alerta's paths are vuln
routes, so density does the work for chance. On whoogle, no ranker found
the actual CVE: element/window ranked 7-8 of 11, just under the 6-pick
budget. Adding call-site excerpts to the state (so the model sees
`send(base_url=src_url)` vs `send(base_url=FIXED, query=q)`) moved them
up one rank but not across the line. Devin confirmed the element SSRF in
91s when handed the path directly, the miss is ranker-side.

The limiting signal is semantic: "user input reaches a fetch" scores high
whether the fetch is intended (autocomplete, rank 3) or arbitrary
(element SSRF, rank 7). Distinguishing intended from unintended use is the
frontier, the imgres endpoint, whose *purpose* is redirecting, ranked #1
of 11 as open_redirect.

### unintended_use dimension (phase stub-uu)

A fourth score, `unintended_use` (weight 0.15), asks whether the
attacker-controlled value determines *which* resource the operation acts
on beyond what the feature's design needs, high for "input picks the
target" or "input can exceed the expected grammar", low for "input fills
a slot in a fixed target" or "passthrough is the feature's purpose".

Scores on whoogle: element/window SSRF 0.82-0.83, autocomplete 0.13,
search 0.26, imgres 0.90 (defensible: it IS an open redirect). On
alerta's vuln routes it scored only 0.16-0.48, `q=` is a designed input
slot, so the dimension does not boost them and the added weight slightly
dilutes the other signals.

Measured effect (route-aware, stub agent, jev only):

```
fixture       phase    n   TP         FP         CVE paths picked
whoogle-ssrf  stub     5   3.4        2.6        0/5
whoogle-ssrf  stub-uu  5   3.8        2.4        4/5 (element x3, window x1)
alerta-sqli   stub     3   4.0        8.0        n/a (vuln-dense)
alerta-sqli   stub-uu  3   3.7        8.3        n/a
```

The experiment succeeded on its target: the CVE-2024-22205 path crossed
the budget line in 4 of 5 reps and the stub confirmed it. Cost: a small
regression on alerta (4.0 -> 3.7), where the vuln lives behind a
designed input so the new dimension is correctly neutral but its weight
still dilutes. Net effect is positive but the dimension is really a
designed-vs-arbitrary-input probe: it helps exactly the fixture class
it was built for.

### cdio-lfr fixture + stored-taint analyzer work (phase stub2)

Third fixture: **changedetection.io** @ 0.48.04 (GHSA-j5vv-6wjg-cfr8,
LFR via bypassable `file:` URI check on the stored watch URL): 110
candidate paths, ONE sparse CVE, budget 12, the sparsest test yet.

Getting the CVE to enumerate required real analyzer work, each piece
necessary on real code:

- **Stored (second-order) taint**: the vulnerable value is
  `self.watch.link`, user input persisted in the datastore and read
  back later by an async worker. `self.<attr>` reads are now sources
  when the attr was assigned from a store-backed expression
  (`self.x = f(self.datastore...)`, plus always-on datastore/db/store/
  cache/backend attr names).
- **Qualname collision bug**: `Class.method` qualnames have no module
  path, so four `fetcher.run` implementations silently overwrote each
  other, on a 131-file repo many functions were simply absent.
  Collisions now get `@filestem` suffixes.
- **Polymorphic dispatch**: `self.fetcher.run` resolves via the declared
  type (`self.fetcher = Fetcher()`) to ALL concrete subclass impls
  (abstract bases excluded); same-class implementations across files
  (alerta's swappable mongo/postgres backends) also fan out.
- **Validation-call guards**: `re.search(p, tainted)` /
  `x.startswith(...)` checks register as guards, and guard dominance
  now crosses files (a check in the caller guards a sink in the callee
  when it precedes the outgoing call edge). The `guard_bypassable`
  machinery engages on the real-world guard shape.
- **Enumeration cap**: `max_paths=500` silently truncated alerta (62 of
  78 real paths) and hid every stored-source path on cdio. Raised to
  20000 in the generator default, but see the stub4 section: the
  `ScanConfig.max_paths=500` override kept truncating every benchmark
  run until it was fixed there.
- **Propagation fix**: `_expr_taint_in` only saw tainted `Name` nodes,
  so `f(url=self.watch.link)` never propagated; attribute/stored reads
  in call args now carry taint.

Route-aware results (stub agent, 12 picks; runs generated 73 paths,
see the stub4 correction):

```
fixture    strategy   n   TP   FP    note
cdio-lfr   jev        5   0    12    /start variant in pool, never picked
cdio-lfr   random     3   0    10
cdio-lfr   static     2   0    12
cdio-lfr   baseline   2   1    11    /start variant early in enum order
alerta     jev        3   2    10    was 4 under the 62-path analyzer
alerta     random     2   4    8     density still does the work
alerta     static     2   0    12
```

Sobering on two axes. On cdio, no ranker found the CVE by ranking:
Jev never picked the `/<string:uuid>/start -> ... -> session.request`
variant that WAS in the pool (the `self.watch` stored-source variant
was truncated away, see stub4), and the flat baseline found it only
because it sits early in enumeration order. And on alerta, the analyzer
improvements HURT jev (4 -> 2 route-
aware TPs): the 16 newly-enumerated paths (mongo-backend siblings, more
stored sources) are plausible-looking and pushed vuln routes out of the
top 12. Coverage and ranking pull in opposite directions: every path the
analyzer recovers is one more competitor for the budget.

### Store-write provenance (phase stub3)

The stub2 read blamed missing *state*, not scoring: "the stored URL is
user-written" was invisible to Jev. This round adds provenance tracking:

- Tainted writes into store-rooted objects (`self.__data[uuid] =
  new_watch`, `datastore.add_watch(url=...)`, `s.update(tainted)`)
  mark the root user-written. Stored reads of that root, or of attrs
  assigned from it (`self.watch = self.datastore...`), emit
  `user-stored:self.x` labels, so the path's source reads as
  attacker-written, not feature-internal.
- Container-shaped writes (`self.x[k] = v`, `self.x.update(v)` on
  store-named attrs) mark the attr stored even without a store-shaped
  RHS; `ast.Dict` now carries taint (`row = {'url': self.path}`).

Path counts grew everywhere (cdio 110->118, alerta 78->87, whoogle
11->14; the Dict fix alone added paths). On cdio the CVE path now
enumerates as `user-stored:self.watch -> call_browser() -> ... ->
session.request()` with the guard's source visible in state.

```
fixture     strategy   n   TP   FP    route-aware note
cdio-lfr    jev        5   0    12    self.watch variant absent from pool
cdio-lfr    baseline   2   1    11    enum-order luck again
cdio-lfr    static     2   0    12
alerta      jev        3   2    10    87-path pool keeps diluting
whoogle     jev        3   3    3
```

Two honest reads:

1. **Provenance moved the label, not the ordering.** In a manual
   full-pool pass (118 paths) the CVE variant scored ~19-20, still
   short of budget. In the actual runs the `self.watch` variant never
   enumerated at all, `ScanConfig.max_paths=500` overrode the
   generator's raised cap, so the run pool had 73 paths and the
   self.watch source never reached it (see stub4 for the fix and the
   measured effect). Provenance lifted the *entire stored class*: the
   top 12 was dominated by `user-stored:` paths like `add_watch ->
   requests.request` (the URL-validation fetch, itself a suspicious
   user-controlled fetch). Within-class discrimination was still
   missing.

2. **The miss is ranker-side, confirmed.** Handed the path directly,
   devin-cli timed out at 600s (uncertain) then CONFIRMED on retry
   (~600s), correctly identifying the bypass: `re.search(r'^file:/')`
   misses `file:path` (no slash) and `file:\path` (backslash), and
   browser fetchers navigate the URL with no scheme check at all. The
   investigator can verify this path; it just costs ~10min on a
   313-file repo. Budget spent on 12 wrong picks means the CVE never
   reaches the investigator.

### sink_reach dimension + post-sink state (phase stub4)

The stub3 read blamed missing within-class discrimination: the CVE
path scores like its stored-fetch siblings because "fetch a stored
URL" is the feature. The `sink_reach` dimension (weight 0.15) asks a
different question: what does the sink's return value let the
attacker reach, once the shown checks fail? To make the question
answerable, `path_state` now appends `post_sink` lines: the later
lines in the enclosing body that consume the sink's result. On the
CVE path this surfaces `self.content = r.text` and
`self.raw_content = r.content` ~40 lines past the sink, previously
invisible.

**Direct probe** (CVE path vs its top-3 stored-class siblings,
scored twice):

```
rep 0:  CVE 0.78 | add_watch 0.69 | snapshot-open 0.67 | add_watch2 0.64
rep 1:  CVE 0.78 | add_watch 0.73 | snapshot-open 0.71 | add_watch2 0.65
```

Consistent direction but a 0.05-0.13 margin, under the 0.2 bar for
clean separation. Per the plan's decision rule an ambiguous gap goes
to the sweep.

**A measurement bug surfaced first.** The stub4 sweep initially ran
the same miss as stub3 (0/5), and a full-pool rank pass put the CVE
at rank 6 of 118, a contradiction that exposed it: benchmark runs
generated 73 paths, not 118. `ScanConfig.max_paths=500` overrode the
generator's raised cap, so every run since stub2 truncated the pool
and the `self.watch` variant never enumerated in ANY run. The
"rank ~14/19-20" figures in earlier sections were manual passes on
a pool the runs never saw. Fixed the config default and re-ran the
whole phase.

Route-aware results (stub agent, 12 picks/118 paths, jev_fail=0):

```
fixture    strategy   n   TP   FP    note
cdio-lfr   jev        5   1    11    CVE picked 5/5, positions 10-12 of 12
cdio-lfr   static     1   0    12
cdio-lfr   baseline   1   1    8     stored-source sibling by enum order
alerta     jev        3   1    11    87-path pool; was 2 under stub3's 75
whoogle    jev        3   2-3  3-4   element/window still 0/3 picked
```

Three honest reads:

1. **The win is mostly coverage, not the new dimension.** An ablation
   scoring the same 118-path pool with the `sink_reach` weight zeroed
   ranks the CVE 9-13 across three draws, vs 6-11 with it active.
   The dimension contributes a small consistent nudge (matching the
   probe's direction) but the path straddles the budget line either
   way; the 0/5 -> 5/5 reversal comes from the path entering the
   pool at all. In-run it lands at positions 10-12, the boundary.

2. **It found the real path, not a shortcut.** Picks are the
   canonical `user-stored:self.watch -> call_browser() -> ... ->
   session.request` chain, and the stub confirmed all five. The
   baseline's TP is a legitimate stored-source sibling early in
   enumeration order, not a scoring success.

3. **Regressions.** Whoogle element/window picks stayed 0/3 (TP
   stayed 2-3 via other real vulns, so the TP count hides the pick-
   level miss, exactly the confound the plan flagged). Alerta fell
   to 1 TP/run, but its pool grew 75 -> 87 under the same cap fix,
   so dilution, not the dimension, is the likelier cause.

Net: Jev now surfaces the cdio CVE inside budget every rep, but the
credit splits between finally enumerating the path and a marginal
scoring nudge. Within-class discrimination is still the open
problem: `sink_reach` separates the CVE from siblings by ~0.05, not
the ~0.2+ a robust pick would need.

### Guard-content check objects (post-stub4 lever)

Within-class discrimination needs the check's *content*, not just its
presence: `re.search(r'^file:/', url)` is a denylist whose pattern
misses `file:path` and `file:\path` spellings, and the model could not
see that structure from a raw excerpt alone. Guards now carry a
`check` object extracted from the enclosing conditional's AST:
`subject`, `pattern`, `negated`, `env` gates, and `kind`
(denylist/allowlist/gate). The CVE path's guard reads
`{pattern: '^file:/', subject: 'url.strip()', kind: 'denylist',
env: ['ALLOW_FILE_URI']}`.

Measured effect (manual full-pool rank passes, 118 paths):

| signal | before | after |
|--------|--------|-------|
| CVE guard_bypassable | ~0.62 | 0.73-0.74 |
| CVE rank (2 passes) | 6-11 | 12, 12 |

The check object lifted the bypass score ~0.11 and stabilized the
rank at the 12-pick boundary, but the separation problem is
unchanged in kind: the 11 paths ahead are all plausible stored or
form-controlled fetches (add_watch's pinned share endpoint, clone),
and the strongest sibling still outranks the CVE (2.15-2.22 vs
1.98-2.05). Guard content sharpened the signal; it did not produce
robust within-class separation. The residual gap is reach semantics
the model cannot see without evaluating which URI schemes or hosts
a fetched attacker value can actually name.

### Reach semantics: sink_input constraint extraction (post-stub4 lever)

Within-class discrimination on the cdio pool reduces to one
question: which URI schemes and hosts can the fetched value name
given the checks that passed. `path_state` now emits `sink_input`:
the sink call's target argument classified as `unconstrained` (a
bare variable; the attacker names the whole URI), `prefix`/`literal`
(a fixed leading part from an f-string, concat, or module
constant), or `urljoin` (a base that an absolute URI still
overrides); plus `pinned`, the patterns of allowlist checks and
same-subject gates whose true-branch contains the sink; and
`scheme_control`, whether the attacker can still choose the URI
scheme after those pins. A gate pins even when its `kind` reads
denylist: a sink inside the check's true-branch sees only values
satisfying the pattern, so `gates_sink` overrides polarity (a
negated gate excludes rather than pins).

On the fixture this splits the outbound_request sinks into the
classes that matter:

| path | sink_input |
|------|-----------|
| CVE: `session.request(url)` after the `^file:/` denylist | `unconstrained`, scheme_control=true, no pins |
| add_watch: `requests.request(url)` inside `url.startswith('https://changedetection.io/share/')` | `pinned: ['https://changedetection.io/share/']`, scheme_control=false |
| literal-URL calls | `literal`, scheme_control=false |

Measured effect (direct probe, 2 reps, then one full-pool pass):

| signal | before | after |
|--------|--------|-------|
| CVE sink_reach | ~0.78 | 0.80-0.81 |
| pinned siblings' sink_reach | 0.76-0.80 | 0.46-0.55 |
| CVE rank (full pool) | 12, 12 | 9 |

The question needed one sharpening: phrased as a soft conditional
("answer low when scheme_control is false AND the pin caps at a
safe target"), siblings still scored 0.76-0.80, the model judged
the pinned endpoint's JSON-merge outcome as concrete anyway.
Restated as a rule (scheme_control=false confines the URI to the
pinned prefix; answer low even if the response is stored or
parsed), the dimension separated >0.3, above the 0.2 bar, the
first within-class separation on this fixture.

The composite still does not flip pairwise: sink_reach carries
weight 0.15, so the 0.3 dimension gap contributes ~0.05 of value
and the pinned siblings' other dimensions (gb 0.71-0.78, uu
0.60-0.75, ac ~0.80) keep them at 2.23-2.40 vs the CVE's 2.10.
What changed in the full-pool ranking is the *composition* above
the cut: the paths now ahead of the CVE are stored-name `open()`
file reads (sc=true, sr 0.71-0.80, a genuinely reach-dangerous
class), not its safe pinned-fetch twins. The rank moved from the
budget boundary (12) inside it with margin (9). The state now
carries the discriminating fact, the model scores it, and the
remaining dilution is aggregation: whether a sharper ranker needs
a bigger weight on reach or fewer confounded dimensions is a
weighting question, not a perception one.

### Call-site-aware reach (whoogle generalization check)

The first version of `sink_input` classified only the sink's local
argument expression, and on whoogle that expression is the same
for every caller: `requests.get((base_url or self.search_url) +
query)` inside `Request.send`. Whether the attacker names the
scheme depends on *which parameter the path's taint enters*:
`send(base_url=src_url)` on `/element` puts the attacker value at
string position 0 (the SSRF), while `send(query=full_query)` and
`send(base_url=AUTOCOMPLETE_URL, ...)` leave it in the tail.

`sink_input` now derives per-path tainted params from the path's
last CALLS-edge call site (parsed with paren balancing so
multi-line calls stay readable; non-fixed values mark the param,
module constants and literals do not), falling back to the
callee's merged `tainted_params` when no call site exists. The arg
expression is then decomposed at the leading segment:
position 0 attacker-influenced means `expression`/`unconstrained`
with scheme_control true; a literal, module constant, or
non-tainted leading expression (`prefix_expr`) means
scheme_control false.

Measured on whoogle's five outbound_request paths:

| path | call site | sink_input |
|------|-----------|------------|
| `/element` CVE (`request.args.get`) | `send(base_url=src_url)` | expression, sc=true |
| `/window` CVE (`request.args.get`) | `send(base_url=target_url)` | expression, sc=true |
| `/search` (`HTTP search`) | `send(query=full_query, ...)` | prefix_expr, sc=false |
| autocomplete (`http.request`) | `send(base_url=AUTOCOMPLETE_URL, ...)` | prefix_expr, sc=false |
| env config (`os.environ`) | n/a | expression, sc=true |

Jev probe (2 reps): `sink_reach` 0.80 on `/element` vs 0.44-0.48
(`/search`) and 0.48-0.51 (autocomplete), the same ~0.3
separation as cdio, via the same mechanism, on a different code
shape. The composite again does not flip pairwise (autocomplete
2.14-2.17 vs CVE 1.94-1.98 on other dimensions), but the
dimension now carries a true, load-bearing fact on two fixtures.
On alerta the raw_query sinks read `unconstrained`, honest for
SQL, where there is no scheme to pin.

### stub5 sweep (harness confirmation)

| fixture | n | TP | pick detail |
|---------|---|----|-------------|
| cdio-lfr jev | 5 | 3 | CVE-variant picked at positions 8/10/11 of 12 in the hits; the picked shape is `self.watch -> call_browser() -> run@requests`, the browser-fetcher route to the same requests.py sink |
| whoogle-ssrf jev | 5 | 4,4,4,3,3 | picks are the /config vuln family (open/redirect/deser, all in truth); element/window SSRF never picked, composite ~1.95 sits below the config family's ~2.0+ despite sr=0.80 |
| alerta-sqli jev | 3 | 2,1,1 | unchanged from prior phases |

Reading: the dimension-level separation measured in the probes is
real, and on cdio it translates to picks inside budget in 3 of 5
draws (the CVE straddles the line). On whoogle it does not
translate: the /config family is genuinely vulnerable *and*
scores high on the other dimensions, so the SSRF paths' composite
stays under the cut even though `sink_reach` correctly separates
them from the pinned fetches. The honest summary after three
levers: `sink_reach` now carries true discriminating facts
(provenance, check content, reach) and the model scores them
correctly, what still fails is that one dimension at weight
0.15 cannot outvote several confounded ones at the pick line.

### Weight sensitivity: does aggregation lose what the dimension finds?

Counterfactual ranking over stored per-dimension scores (one
scoring pass per fixture, priorities recomputed at varying
`sink_reach` weights):

| fixture | w=0 | w=0.15 | w=0.3 | w=0.6 | w=1.0 |
|---------|-----|--------|-------|-------|-------|
| cdio CVE rank (budget 12) | 16 | 13 | 11 | 9 | 7 |
| whoogle element/window rank (budget 6) | 11-13 | 10-12 | 10-11 | 9-11 | 9-10 |

Three findings, none flattering to a simple fix:

1. **cdio responds to weight but never orders cleanly.** ~0.3
   puts the CVE inside budget, yet the pinned siblings stay
   ahead at every weight, their `sink_reach` is mid (0.5-0.6),
   not low, so the dimension separates "dangerous" from
   "plausible" without producing "dangerous above safe".

2. **whoogle does not respond at all.** The element/window paths
   sit at rank 9-13 at every weight because the paths ahead
   score HIGHER on `sink_reach` (0.65-0.83): `open()` and
   `redirect()` on attacker input are legitimately high-reach
   too, and 3-4 of them are real vulns in the truth file. The
   CVE loses not on weight but on crowding by other
   genuinely-dangerous flows.

3. **The residual is a holistic-judgment gap, not aggregation.**
   The whoogle SSRF paths score `research_value` 0.55-0.60 and
   `invariant_violation` 0.63 while the config family scores
   0.69-0.85 / 0.81-0.93, the model's broad "is this a real
   vuln" answer prefers obvious file-access and deserialization
   sinks over the subtler gated-SSRF shape, which reads as
   "the feature fetching a URL behind a check". `sink_reach`
   answers its narrow question correctly; the wide-angle
   dimensions answer theirs plausibly-wrongly on exactly the
   subtle vuln.

So the aggregation story needs amending: on cdio, weight is the
binding constraint and a modest increase suffices; on whoogle,
no weight on the discriminating dimension helps because the
crowd above is also correctly scored on it, the miss lives in
`research_value`/`invariant_violation`, which reward the obvious
vuln shape over the subtle one.

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
   ~44% (stub) / 63% (devin) vs static's ~29%/42%, roughly half the wasted
   agent calls per verified vuln.

3. **Did it discover vulnerabilities the baseline missed?** After the
   guard-bypass change, yes, including a class no ranker found before. With
   guard definitions in the state and a `guard_bypassable` score, Jev put 5
   of the 6 bypassable-guard vulns inside the 14-pick budget (previously 0),
   and devin+gb verified TP 7.5/run with FP 0, the best result in the
   benchmark. The prerequisite was showing Jev the guard's *body*: scored on
   call sites alone it ranked the hards no better than before.

4. **Where did Jev make incorrect predictions?** (a) It cannot distinguish
   "tainted but bounded" (len/sha256/isalnum traps) from unguarded, it ranked
   all six traps high. Defensible: the graph shows no guard, so they ARE
   suspicious; the investigator layer is where they should die. (b) SSRF on
   vuln-heap straddled the budget cut across runs. (c) The earlier catastrophic
   miss was an adapter normalization bug, not the model. (d) On cdio the
   CVE path was not even in the run pool until stub4 (the max_paths
   override bug); once enumerable it ranks ~6-13 of 118, straddling the
   pick line, and was picked 5/5. The weak `^file:/` check registers
   (gb=0.62) but the residual problem is that its stored-fetch siblings
   score within ~0.05 of it.

5. **What is the biggest bottleneck?** Still the investigator, but now
   precisely characterized: stub falsifies real vulns it cannot reason
   through (all 6 bypassable-guard vulns); devin reasons correctly but burns
   30-150s/call and stalls on epistemic caution ("uncertain" on unambiguous
   injections). Second bottleneck: validator soundness, static proof
   verifies paths whose guards it cannot see, turning ranker noise into FPs.

6. **What experiment should run next?** (a) Done: intended-use scoring
   moved the whoogle CVE inside budget (4/5 reps) at a small cost on
   alerta. (b) Done: a mid-size sparse-CVE repo (cdio) showed the analyzer
   was the bottleneck, then showed the ranker is too, stored-intended-
   fetch vulns are the hardest class and NO ranker found it. (c) Done:
   store-write provenance made the source label truthful
   (`user-stored:self.watch`) and lifted the whole stored class, but the
   CVE path still scored ~19/118 in manual passes (and, it turned out,
   was absent from run pools entirely), the missing capability is now
   discrimination *within* a uniformly-plausible class, not source
   identification. Devin confirmed the path when handed it (~10min on
   313 files), so the residual gap is ranking, not investigation.
   (d) Done: `sink_reach` plus post-sink state asked what the sink's
   result lets the attacker reach. The CVE now gets picked 5/5, but
   mostly because a max_paths override bug had kept it out of every
   run pool; zeroing the dimension's weight still ranks it ~9-13, so
   the new signal is a nudge, not the separation the class needs.
   The plan's stop condition holds: record and stop, no further
   dimension iteration in this change. (e) Done: guard-content check
   objects gave `guard_bypassable` the check's structure (subject,
   pattern, polarity, env gates). The CVE's bypass score rose ~0.11
   and its rank stabilized at 12/118, but the top of the pool is
   still uniformly-plausible stored fetches, the lever sharpened
   the signal without producing robust separation. (f) Done: reach
   semantics, `sink_input` classifies the sink's target argument
   and folds in same-subject allowlist/gate pins into a
   `scheme_control` verdict. It produced the first clean
   within-class separation (sink_reach 0.80 vs 0.46-0.55 on pinned
   siblings) and moved the CVE rank from 12 to 9 of 118, inside
   budget with margin; the paths still ahead are a legitimately
   reach-dangerous `open()` class, not the safe pinned fetches.
   (g) Done: call-site-aware reach generalized `scheme_control` to
   whoogle's shared-sink shape, `send(base_url=src_url)` reads
   sc=true where `send(query=...)` and `send(base_url=CONST)`
   read sc=false, and the stub5 sweep confirmed the harness sees
   it too: cdio picked a CVE variant in 3/5 draws at positions
   8-11 of 12, whoogle's /config family took 4-5 of 6 picks (all
   true positives) while element/window stayed unpicked because
   their composite, not their sink_reach, trails. The persistent
   pattern across levers: the separating signal exists at the
   dimension level and loses at the composite level. (h) Done:
   weight sensitivity over stored dimension
   scores. On cdio ~0.3 weight puts the CVE inside budget but no
   weight orders pinned-siblings below it; on whoogle no weight
   helps at all, the paths ahead score higher on the
   discriminating dimension itself, and the miss lives in
   `research_value`/`invariant_violation` preferring obvious vuln
   shapes. Aggregation was the story on cdio; holistic judgment
   is the story on whoogle. (i) Next levers: the n-rep question
   for whoogle's earlier 4/5 -> 0/3 flip (now largely explained , 
   pool crowding plus holistic-score drift), a third fixture to
   test whether subtle-shape under-scoring is general, and a
   larger devin ablation once per-run cost is tolerable.

7. **Methodological note.** "Verified TP" confounds ranker and investigator
   quality: the gb reruns have identical Jev picks under stub and devin, but
   opposite TP movement (6.2 -> 1.9 vs 4.5 -> 7.5). Selection precision
   (fraction of *picks* that are real vulns) is the ranker-quality metric;
   verified TP measures the pipeline end to end.

## Limitations

- Python-only analyzer; heuristic AST taint, no real interprocedural dataflow
  engine.
- Original fixtures are small and single-file; corpus-a is multi-file but
  still synthetic, with planted vulns and decoys drawn from a small pattern
  set.
- The stub agent is deterministic and much weaker than a real coding agent,
  so strategy rows share its blind spots (e.g. the vuln-fetch miss).
- Jev scoring is stochastic; single-run numbers have visible variance (on
  corpus-a it was stable, TP 6-7; on vuln-heap it swung a marginal path;
  on cdio the CVE draws at ranks 6-13, straddling the 12-pick line, so
  its 5/5 pick rate is a boundary result, not a robust margin).
- Every benchmark run before stub4 silently used `max_paths=500`
  (ScanConfig overrode the generator's raised cap), so stored-source
  paths, including the cdio CVE variant, were absent from those pools.
  Rank claims in the stub2/stub3 sections were measured manually on the
  full pool; in-run comparisons across phases now mix pool sizes
  (cdio 73 -> 118, alerta 75 -> 87).
- Random-strategy reps written before the seed-forwarding fix all ran
  seed=0 regardless of rep number, so each random rep group is n=1
  distinct draws repeated, not independent samples.
- Jev reps send identical local inputs each rep; rep independence rests
  entirely on remote API nondeterminism. A deterministic or cached
  upstream would silently collapse the rep count to n=1.
- The generated corpus places easy vulns on early routes, which inflates the
  flat-ordering baseline's apparent precision; treat baseline as a floor.
- Static proof cannot verify that a *dynamic* guard is effective, and cannot
  see guards that are not sanitizer-named calls, both produce verified FPs.
- Two validator/adapter bugs were found and fixed during this experiment
  (greedy JSON report regex, weak raw_query sandbox check, 503 retry); the
  earlier `jev score` rung-normalization fix is described above.
- Jev requires network + `TYPESAFE_API_KEY`; devin-cli requires the Devin CLI.
- Sandbox validation covers runnable stdlib HTTP fixtures only; other repos
  fall back to static proof.
- Sources are only emitted for tainted *variables*: a bare tainted call arg
  (`open(request.args['f'])` with no assignment) produces a sink site but
  no source node, so no path. Stored-taint covers `self.<attr>` reads but
  not module-level store handles (e.g. `cache.get(k)`).
- Store-shape detection is name-based: attrs matching
  `datastore|store|db|cache|backend|*data` count as stores, so a
  `self.metadata` field assigned non-store data still marks the class
  stored. The user-written upgrade requires a *tainted* write, which
  limits false upgrades, but the base stored label can still over-fire.
- The `request` short-name sink matches any `x.request(...)`; plausible
  FPs on non-HTTP receivers.
- Baseline's flat ordering is enumeration order, which is roughly source
  order, early-file vulns flatter it (cdio: baseline TP=1 by position).

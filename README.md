# secresearch

Research MVP: autonomous codebase security research driven by attack-path
search, where Jev (TypeSafe AI's System One decision model) probabilistically
prioritizes which paths an expensive coding agent should investigate.

See `ARCHITECTURE.md` for the design and `RESULTS.md` for benchmark outcomes.

## Install / run

Zero dependencies; Python 3.10+.

```bash
pip install -e .            # provides the security-research CLI
# or run in place:
PYTHONPATH=src python3 -m secresearch ...
```

Jev scoring needs `TYPESAFE_API_KEY`. The `devin` agent backend needs the
Devin CLI on PATH.

## Commands

```bash
security-research graph ./repo                  # dump the code graph
security-research paths ./repo                  # list candidate attack paths
security-research scan ./repo \
    --strategy=jev --agent=stub --max-iterations=40 --output runs/x --verbose
security-research finding finding-1 --findings-dir runs/x/findings
security-research benchmark benchmarks \
    --strategies jev,static,random,baseline --max-iterations=5
```

Strategies: `jev` | `static` | `random` | `baseline`. Agents: `stub` |
`devin`. Scoring weights, cost exponent, and budgets live in `ScanConfig`
(`--config file.json`).

## Benchmark dataset

`benchmarks/fixtures/*` are small stdlib-only HTTP apps with planted
vulnerabilities; `benchmarks/ground_truth/<name>.json` holds the expected
findings outside the indexed tree.

## Tests

```bash
PYTHONPATH=src python3 -m unittest discover -s tests -v
```

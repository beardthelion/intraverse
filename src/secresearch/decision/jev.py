"""Jev decision model: TypeSafe System One API adapter.

``POST https://api.typesafe.ai/v1/systemone`` accepts one ``state`` plus typed
``questions`` and returns calibrated probabilities in a single call. Jev is used
as a search heuristic here: it scores each candidate attack path on the
dimensions the orchestrator combines into an exploration priority.
"""

from __future__ import annotations

import json
import os
import time
import urllib.request
import urllib.error

from ..models import AttackPath, PathScores, RunStats
from ..graph.code_graph import CodeGraph
from ..graph.invariants import InvariantChecker
from .base import DecisionModel, path_state

JEV_ENDPOINT = "https://api.typesafe.ai/v1/systemone"
JEV_MODEL = "jev-latest"

QUESTIONS: dict[str, dict] = {
    "attacker_control": {
        "type": "noul",
        "instructions": "Is the data reaching the end of this path controlled by an external attacker or untrusted user?",
    },
    "trust_boundary_crossing": {
        "type": "noul",
        "instructions": "Does this path carry data across a trust boundary (from untrusted input into privileged/internal operations)?",
    },
    "authz_boundary_concern": {
        "type": "noul",
        "instructions": "Does this path reach a resource or operation that should require an authorization check it may be missing?",
    },
    "sensitive_sink": {
        "type": "noul",
        "instructions": "Does this path end at a security-sensitive sink (command execution, deserialization, network request, file/db/template operation, redirect)?",
    },
    "insufficient_validation": {
        "type": "noul",
        "instructions": "Is the input on this path missing validation or sanitization appropriate for the sink it reaches?",
    },
    "guard_bypassable": {
        "type": "noul",
        "instructions": (
            "If a validation, sanitization, or authorization check guards this "
            "path, can a crafted attacker input bypass it? The guard's call "
            "site and its function definition (when resolvable, with module "
            "constants like allowlists) are shown. Answer high only if you can "
            "name a concrete bypass input (an allowed-but-dangerous value, a "
            "blocklist gap, a normalization trick, a logic flaw). Answer low "
            "if the shown definition actually blocks dangerous inputs, and "
            "lowest if no guard is present."
        ),
    },
    "invariant_violation": {
        "type": "noul",
        "instructions": "Does this path plausibly violate a security invariant (untrusted input reaching a privileged sink, missing authorization, secret exposure)?",
    },
    "unintended_use": {
        "type": "noul",
        "instructions": (
            "Does the attacker-controlled value determine WHICH resource this "
            "operation acts on (which host to fetch, which file to open, which "
            "query fragment to run, which page to redirect to) beyond what the "
            "feature's design needs? Answer high when the input picks the "
            "target itself and the feature does not require accepting an "
            "arbitrary target (e.g. a fetch that only ever needs search-result "
            "icon URLs but accepts any URL). Answer high also when the input "
            "can exceed the shape or grammar the feature expects (a filter "
            "parameter that accepts raw query syntax). Answer low when the "
            "input merely fills a slot in a fixed target (a query appended "
            "to a fixed search URL), or when passing the input straight "
            "through IS the feature's documented purpose."
        ),
    },
    "research_value": {
        "type": "score",
        "instructions": "How likely is deep investigation of this path to produce a real, exploitable vulnerability?",
        "criteria": ["noise", "unlikely", "possible", "likely", "very likely"],
    },
    "investigation_cost": {
        "type": "score",
        "instructions": "How much effort would a strong coding agent need to confirm or falsify this path?",
        "criteria": ["trivial", "cheap", "moderate", "expensive", "very expensive"],
    },
    "continue_exploration": {
        "type": "noul",
        "instructions": "Given the path and any prior evidence, is further investigation of this path likely to produce useful security evidence?",
    },
}


class JevClient:
    """Thin stdlib HTTP client for the TypeSafe System One API."""

    def __init__(self, api_key: str | None = None, endpoint: str = JEV_ENDPOINT,
                 model: str = JEV_MODEL, timeout: float = 30.0):
        self.api_key = api_key or os.environ.get("TYPESAFE_API_KEY", "")
        self.endpoint = endpoint
        self.model = model
        self.timeout = timeout
        if not self.api_key:
            raise RuntimeError("TYPESAFE_API_KEY is not set")

    def evaluate(self, state: dict | str, questions: dict | None = None,
                 retries: int = 3) -> dict:
        body = json.dumps({
            "state": state,
            "model": self.model,
            "questions": questions or QUESTIONS,
        }).encode()
        delay = 2.0
        last: Exception | None = None
        for attempt in range(retries + 1):
            req = urllib.request.Request(
                self.endpoint,
                data=body,
                headers={
                    "Authorization": f"Bearer {self.api_key}",
                    "Content-Type": "application/json",
                },
                method="POST",
            )
            try:
                with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                    return json.loads(resp.read())
            except urllib.error.HTTPError as e:
                payload = e.read()[:500]
                last = RuntimeError(f"Jev API error {e.code}: {payload!r}")
                if e.code < 500 and e.code != 429:
                    raise last from e  # 4xx (except 429) will not heal on retry
            except (urllib.error.URLError, TimeoutError, OSError) as e:
                last = RuntimeError(f"Jev request failed: {e}")
            if attempt < retries:
                time.sleep(delay)
                delay *= 4
        raise last


def _noul(answer: dict) -> float:
    for key in ("noul", "probability", "p", "value"):
        if key in answer and isinstance(answer[key], (int, float)):
            return float(answer[key])
    return 0.5


def _score01(answer: dict, n_rungs: int = 5) -> float:
    """Normalize a score answer to [0, 1]. The API returns an interpolated
    score on a 0-indexed rung scale (0 .. n_rungs-1); a probability
    distribution over rungs is also accepted."""
    if "score" in answer and isinstance(answer["score"], (int, float)):
        s = float(answer["score"])
        return max(0.0, min(1.0, s / (n_rungs - 1)))
    dist = answer.get("distribution") or answer.get("probabilities")
    if isinstance(dist, dict):
        rungs = list(dist.values())
        if rungs and all(isinstance(x, (int, float)) for x in rungs):
            return sum(i * float(p) for i, p in enumerate(rungs)) / max(1, len(rungs) - 1)
    return 0.5


class JevDecisionModel(DecisionModel):
    name = "jev"

    def __init__(self, client: JevClient | None = None):
        self.client = client or JevClient()

    def score_path(
        self,
        path: AttackPath,
        graph: CodeGraph,
        checker: InvariantChecker,
        stats: RunStats,
    ) -> PathScores:
        state = path_state(path, graph, checker)
        try:
            resp = self.client.evaluate(state)
        except RuntimeError as e:
            # degrade to a neutral score rather than aborting the run; the
            # failure counter keeps it visible in metrics
            stats.jev_failures += 1
            return PathScores(
                attacker_control=0.5, trust_boundary_crossing=0.5,
                authz_boundary_crossing=0.5, sensitive_sink=0.5,
                insufficient_validation=0.5, invariant_violation=0.5,
                research_value=0.5, estimated_cost=0.6,
                continue_exploration=0.5,
                raw={"error": str(e)},
            )
        stats.jev_calls += 1
        usage = resp.get("usage") or {}
        stats.jev_input_tokens += int(usage.get("input_tokens", 0))
        answers = resp.get("answers", {})
        # bypassability is only meaningful when a guard exists; zero it out on
        # unguarded paths so the weight cannot inflate them
        guarded = checker.path_has_sanitizer(path) or checker.path_has_authz(path)
        bypass = _noul(answers.get("guard_bypassable", {})) if guarded else 0.0
        return PathScores(
            attacker_control=_noul(answers.get("attacker_control", {})),
            trust_boundary_crossing=_noul(answers.get("trust_boundary_crossing", {})),
            authz_boundary_crossing=_noul(answers.get("authz_boundary_concern", {})),
            sensitive_sink=_noul(answers.get("sensitive_sink", {})),
            insufficient_validation=_noul(answers.get("insufficient_validation", {})),
            invariant_violation=_noul(answers.get("invariant_violation", {})),
            research_value=_score01(answers.get("research_value", {})),
            guard_bypassable=bypass,
            unintended_use=_noul(answers.get("unintended_use", {})),
            estimated_cost=0.2 + 0.8 * _score01(answers.get("investigation_cost", {})),
            continue_exploration=_noul(answers.get("continue_exploration", {})),
            raw={"answers": answers, "model": resp.get("model")},
        )

"""Benchmark metrics: match verified findings against hidden ground truth."""

from __future__ import annotations

from ..models import Finding, RunStats


def match_finding(f: Finding, truth: list[dict]) -> dict | None:
    """A finding matches a ground-truth entry when the vulnerability class
    matches and the sink lands in the expected file/function/line region.
    ``sink_line`` disambiguates two same-class sinks in one function."""
    sink_loc = f.source_locations[-1] if f.source_locations else None
    for t in truth:
        if t.get("matched"):
            continue
        if t.get("class") != f.vuln_class:
            continue
        tfile = t.get("sink_file", "")
        tfunc = t.get("sink_function", "")
        tline = t.get("sink_line")
        hit_file = bool(sink_loc) and sink_loc.file == tfile
        hit_func = not tfunc or bool(
            sink_loc and (sink_loc.function.endswith(tfunc) or tfunc in sink_loc.function)
        )
        hit_line = tline is None or bool(
            sink_loc and abs(sink_loc.line_start - int(tline)) <= 4
        )
        if hit_file and hit_func and hit_line:
            t["matched"] = True
            return t
    return None


def compute_metrics(
    findings: list[Finding],
    ground_truth: list[dict],
    stats: RunStats,
    elapsed: float,
    discovery_times: dict[str, float],
) -> dict:
    truth = [dict(t) for t in ground_truth]
    tp = 0
    matched_ids = []
    times = []
    for f in findings:
        m = match_finding(f, truth)
        if m:
            tp += 1
            matched_ids.append(f.id)
            if f.path_id in discovery_times:
                times.append(discovery_times[f.path_id])
    fp = len(findings) - tp
    missed = [t for t in truth if not t.get("matched")]
    return {
        "vulnerabilities_in_corpus": len(ground_truth),
        "findings": len(findings),
        "true_positives": tp,
        "false_positives": fp,
        "missed": len(missed),
        "missed_classes": [t.get("class") for t in missed],
        "matched_finding_ids": matched_ids,
        "mean_time_to_discovery_s": round(sum(times) / len(times), 2) if times else None,
        "jev_calls": stats.jev_calls,
        "jev_input_tokens": stats.jev_input_tokens,
        "agent_calls": stats.agent_calls,
        "agent_wall_seconds": round(stats.agent_wall_seconds, 1),
        "paths_scored": stats.paths_scored,
        "paths_explored": stats.paths_explored,
        "paths_discarded": stats.paths_discarded,
        "paths_verified": stats.paths_verified,
        "iterations": stats.iterations,
        "wall_seconds": round(elapsed, 1),
        # $0.042 / 1M input tokens, per TypeSafe's published Jev pricing
        "estimated_jev_cost_usd": round(stats.jev_input_tokens * 0.042 / 1e6, 6),
    }

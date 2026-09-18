"""Route-aware scoring for the OSS benchmark.

Shared sinks (a helper like Request.send or Backend._fetchall called from many
endpoints) make sink-line-only truth matching unsound on real code: a verified
finding on a safe flow can land on the same execute() line as the CVE flow.
This scorer resolves each finding to its path's entry endpoint and counts a
hit only when that entry is a genuinely vulnerable route.

Usage: python3 benchmarks/oss/score.py runs/oss-stub-6
"""

import json
import re
import sys
from pathlib import Path

# Endpoint names (as they appear in path labels) that are actually vulnerable.
# whoogle: only element/window send attacker-controlled URLs to requests.get;
# autocomplete/search/environ reach the same sink via fixed base URLs.
WHOOgle_VULN_ENTRIES = {"element", "window"}
WHOOgle_TRUTH = {
    # class -> (sink file suffix, sink line, allowed entry names)
    "outbound_request": ("app/request.py", 339, WHOOgle_VULN_ENTRIES),
    "unsafe_deserialization": ("app/routes.py", 430, {"config"}),
    "file_access": ("app/routes.py", None, {"config"}),
    "open_redirect": ("app/routes.py", 450, {"config"}),
}

# alerta: q= SQLi exists on every view calling qb.*.from_params(request.args)
ALERTA_VULN_ROUTES = {
    "/alerts", "/alerts/history", "/alerts/count",
    "/alerts/topn/count", "/alerts/topn/flapping", "/alerts/topn/standing",
    "/alerts/top10/count", "/alerts/top10/flapping", "/alerts/top10/standing",
    "/environments", "/services", "/alerts/groups", "/alerts/tags",
    "/blackouts", "/customers", "/groups", "/heartbeats", "/keys",
    "/perms", "/users", "/oembed", "/oembed.<format>",
    "/user/<user_id>/groups",
    "/_bulk/alerts", "/_bulk/alerts/status", "/_bulk/alerts/action",
    "/_bulk/alerts/tag", "/_bulk/alerts/untag", "/_bulk/alerts/attributes",
}
ALERTA_EXECUTE_LINES = {1583, 1593, 1605, 1614, 1624, 1640, 1650}

LOC = re.compile(r"@(\S+):(\d+)")


def entry_of(label: str) -> str:
    """Entry endpoint name from a path label ('HTTP element' -> 'element',
    'HTTP /_bulk/alerts' -> '/_bulk/alerts')."""
    for hop in label.split("->"):
        hop = hop.strip()
        if hop.startswith("HTTP "):
            return hop[5:].split(" ")[0]
    return label.split("->")[0].strip()


def sink_of(label: str):
    m = LOC.search(label)
    return (m.group(1), int(m.group(2))) if m else ("", 0)


def load_run(run_dir: Path):
    labels, statuses, findings = {}, {}, []
    for tf in run_dir.glob("*.jsonl"):
        for line in open(tf):
            e = json.loads(line)
            if e.get("kind") == "selected":
                labels[e["path_id"]] = e["label"]
            elif e.get("kind") == "investigation":
                statuses[e["path_id"]] = e["status"]
    for f in sorted((run_dir / "findings").glob("finding-*.json")):
        findings.append(json.loads(open(f).read()))
    return labels, statuses, findings


def score_fixture(fixture: str, run_dir: Path):
    labels, statuses, findings = load_run(run_dir)
    tp = fp = 0
    hits, misses = [], []
    for d in findings:
        label = labels.get(d.get("path_id"), "")
        entry = entry_of(label)
        sfile, sline = sink_of(label)
        cls = d.get("class")
        ok = False
        if fixture == "whoogle-ssrf":
            spec = WHOOgle_TRUTH.get(cls)
            if spec:
                tfile, tline, entries = spec
                ok = (sfile.endswith(tfile)
                      and (tline is None or abs(sline - tline) <= 1)
                      and entry in entries)
        elif fixture == "alerta-sqli":
            ok = (cls == "raw_query" and sline in ALERTA_EXECUTE_LINES
                  and entry in ALERTA_VULN_ROUTES)
        if ok:
            tp += 1
            hits.append(f"{cls} via {entry}")
        else:
            fp += 1
            misses.append(f"{cls} via {entry} @{sfile}:{sline}")
    return tp, fp, hits, misses


def main():
    root = Path(sys.argv[1] if len(sys.argv) > 1 else "runs/oss")
    groups: dict[tuple, list] = {}
    for fdir in sorted(root.rglob("findings")):
        run_dir = fdir.parent
        fixture, strat = run_dir.parent.name, run_dir.name
        phase_rep = run_dir.parent.parent.name + "/" + run_dir.parent.name
        tp, fp, hits, misses = score_fixture(fixture, run_dir)
        groups.setdefault((phase_rep, fixture, strat), []).append((tp, fp, hits, misses))
    for (phase_rep, fixture, strat), rows in sorted(groups.items()):
        for tp, fp, hits, misses in rows:
            print(f"{phase_rep:16} {fixture:14} {strat:8} TP={tp} FP={fp}")
            for h in hits:
                print(f"      TP: {h}")
            for m in misses:
                print(f"      FP: {m}")


if __name__ == "__main__":
    main()

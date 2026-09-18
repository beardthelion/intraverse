"""DecisionModel abstraction: the pluggable probabilistic scorer that ranks
attack paths. Jev implements this interface; so do the ablation models
(static heuristic, random, baseline) used by the benchmark harness.
"""

from __future__ import annotations

import ast
import re
import textwrap
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Any

from ..models import AttackPath, EdgeType, NodeType, PathScores, RunStats
from ..graph.code_graph import CodeGraph
from ..graph.invariants import InvariantChecker


def _dotted(node: ast.AST) -> str:
    parts = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        parts.append(node.id)
    return ".".join(reversed(parts))


def _target_names(t: ast.AST, subscript_binds: bool) -> list[str]:
    """Names bound by an assignment target. When subscript_binds, a
    subscript store binds the container (`d[k] = v` marks `d`); otherwise
    it is excluded since it mutates rather than rebinds."""
    if isinstance(t, (ast.Tuple, ast.List)):
        return [n for e in t.elts for n in _target_names(e, subscript_binds)]
    if isinstance(t, ast.Starred):
        return _target_names(t.value, subscript_binds)
    if isinstance(t, ast.Subscript):
        if not subscript_binds:
            return []
        return _target_names(t.value, subscript_binds)
    if isinstance(t, (ast.Name, ast.Attribute)):
        return [_dotted(t)]
    return []


def _bound_names(stmt: ast.stmt, subscript_binds: bool) -> list[str]:
    targets: list[ast.AST] = []
    if isinstance(stmt, ast.Assign):
        targets = list(stmt.targets)
    elif isinstance(stmt, (ast.AnnAssign, ast.AugAssign)):
        targets = [stmt.target]
    elif isinstance(stmt, (ast.For, ast.AsyncFor)):
        targets = [stmt.target]
    elif isinstance(stmt, (ast.With, ast.AsyncWith)):
        targets = [i.optional_vars for i in stmt.items if i.optional_vars]
    names = [n for t in targets for n in _target_names(t, subscript_binds)]
    names += [_dotted(w.target) for w in ast.walk(stmt)
              if isinstance(w, ast.NamedExpr)]
    return names


def _load_names(stmt: ast.stmt) -> list[tuple[int, str]]:
    out = []
    for n in ast.walk(stmt):
        if isinstance(n, (ast.Name, ast.Attribute)) \
                and isinstance(n.ctx, ast.Load):
            d = _dotted(n)
            if d:
                out.append((n.lineno, d))
    return out


def _fn_tree(graph: CodeGraph, file: str, line: int,
             src: list[str] | None):
    """(tree, line offset) of the parsed segment of the innermost function
    containing ``file:line``, or (None, 0)."""
    fn = min(
        (f for f in graph.nodes_of_type(
            NodeType.FUNCTION, NodeType.HTTP_ENTRY, NodeType.CLI_ENTRY,
            NodeType.EVENT_CONSUMER)
         if f.location.file == file
         and f.location.line_start <= line
         <= (f.location.line_end or f.location.line_start)),
        key=lambda f: (f.location.line_end or f.location.line_start)
                      - f.location.line_start,
        default=None)
    if fn is None or not src:
        return None, 0
    end = min(fn.location.line_end or line, len(src))
    try:
        tree = ast.parse(textwrap.dedent(
            "\n".join(src[fn.location.line_start - 1:end])))
    except SyntaxError:
        return None, 0
    return tree, fn.location.line_start - 1


def _guard_check(guard, graph: CodeGraph,
                 src: list[str] | None) -> dict | None:
    """Structural reading of the check around a guard call: what is tested
    against what pattern, under which env gates, and whether a match
    denies the flow (denylist), a non-match denies it (allowlist), or the
    check only gates a branch. The bypass question is blind without the
    check's content, not just the call site."""
    tree, off = _fn_tree(graph, guard.location.file,
                         guard.location.line_start, src)
    if tree is None:
        return None
    rel = guard.location.line_start - off
    cond = min(
        (n for n in ast.walk(tree)
         if isinstance(n, (ast.If, ast.While, ast.Assert))
         and n.test.lineno <= rel <= (n.test.end_lineno or n.test.lineno)),
        key=lambda n: (n.end_lineno or n.lineno) - n.lineno,
        default=None)
    if cond is None:
        return None
    check: dict[str, Any] = {}
    calls = [c for c in ast.walk(cond.test)
             if isinstance(c, ast.Call) and c.lineno == rel]
    call = calls[0] if calls else None
    if call is not None:
        full = _dotted(call.func)
        check["call"] = full
        name = full.rsplit(".", 1)[-1]
        args = [ast.unparse(a) for a in call.args]
        if name in {"search", "match", "fullmatch", "findall",
                    "finditer"} and len(args) >= 2:
            check["pattern"], check["subject"] = args[0], args[1]
        elif name in {"startswith", "endswith"}:
            check["subject"] = (
                _dotted(call.func.value)
                if isinstance(call.func, ast.Attribute) else None)
            check["pattern"] = args[0] if args else None
        elif args:
            check["args"] = args[:3]
    env = sorted({
        c.args[0].value if c.args and isinstance(c.args[0], ast.Constant)
        else None
        for c in ast.walk(cond)
        if isinstance(c, ast.Call)
        and _dotted(c.func).endswith(("getenv", "environ.get"))})
    env = [e for e in env if e]
    if env:
        check["env"] = env
    negated = call is not None and any(
        isinstance(n, ast.UnaryOp) and isinstance(n.op, ast.Not)
        and any(x is call for x in ast.walk(n.operand))
        for n in ast.walk(cond.test))
    if isinstance(cond, ast.Assert):
        # `assert check` denies when the check fails: an allow-list
        negated, on_true = not negated, "deny"
    else:
        denies = any(isinstance(n, (ast.Raise, ast.Return))
                     for s in cond.body for n in ast.walk(s))
        on_true = "deny" if denies else "pass"
    if call is not None:
        check["negated"] = negated
    check["on_true"] = on_true
    check["kind"] = ("denylist" if on_true == "deny" and not negated
                     else "allowlist" if on_true == "deny"
                     else "gate")
    return check or None


def _post_sink_lines(sink_hop: dict, graph: CodeGraph,
                     src: list[str] | None,
                     max_lines: int = 16) -> str:
    """Lines in the sink's enclosing function that consume the sink call's
    return value: where the fetched/decoded result actually goes.

    The sink question asks about consequence, so the state must show the
    consequence: ``self.content = r.text`` can sit dozens of lines after
    ``r = session.request(...)``, outside the hop excerpt window.
    """
    tree, off = _fn_tree(graph, sink_hop["file"], sink_hop["line"], src)
    if tree is None:
        return ""
    rel = sink_hop["line"] - off
    stmts = [n for n in ast.walk(tree)
             if isinstance(n, ast.stmt)
             and n.lineno <= rel <= (n.end_lineno or n.lineno)]
    if not stmts:
        return ""
    stmt = min(stmts, key=lambda n: (n.end_lineno or n.lineno) - n.lineno)
    seed = _bound_names(stmt, subscript_binds=True)
    if not seed:
        # no binding: the statement itself is the disposition (a result
        # that is returned, passed to another call, or used as a check)
        calls = sum(1 for n in ast.walk(stmt) if isinstance(n, ast.Call))
        if isinstance(stmt, ast.Expr) and calls == 1:
            return ""  # bare call: result discarded
        line = src[stmt.lineno + off - 1]
        return f"{stmt.lineno + off}: {line.rstrip()}"
    tracked = set(seed)
    out: list[str] = []
    seen: set[int] = set()

    def emit(lineno: int) -> None:
        if lineno not in seen and 0 < lineno <= len(src) \
                and len(out) < max_lines:
            seen.add(lineno)
            out.append(f"{lineno}: {src[lineno - 1].rstrip()}")

    later = sorted(
        (n for n in ast.walk(tree)
         if isinstance(n, ast.stmt) and n.lineno > stmt.lineno),
        key=lambda n: n.lineno)
    for s2 in later:
        hits = sorted({ln for ln, name in _load_names(s2) if any(
            name == t or name.startswith(t + ".") for t in tracked)})
        if hits:
            tracked.update(_bound_names(s2, subscript_binds=True))
            for ln in hits:
                emit(ln + off)
            continue
        kill = [b for b in _bound_names(s2, subscript_binds=False)
                if b in tracked]
        if kill:
            # `r = other()` ends r's consumer chain; show the reassignment
            # so the model sees where tracking stopped
            emit(s2.lineno + off)
            tracked.difference_update(kill)
    return "\n".join(out)


def path_state(path: AttackPath, graph: CodeGraph, checker: InvariantChecker,
               max_hops: int = 12, excerpt_lines: int = 4) -> dict[str, Any]:
    """Build the shared state object handed to a decision model.

    Compact but concrete: every hop carries its node type, label, source
    location, and a few lines of real code so the model judges code, not labels.
    """
    feats = checker.features(path)
    hops = []
    root = Path(graph.root)
    file_cache: dict[str, list[str] | None] = {}

    def read_lines(rel: str) -> list[str] | None:
        if rel not in file_cache:
            try:
                file_cache[rel] = (root / rel).read_text(
                    errors="replace").splitlines()
            except OSError:
                file_cache[rel] = None
        return file_cache[rel]

    node_ids = path.nodes[:max_hops]
    for i, h in enumerate(feats["hops"][:max_hops]):
        excerpt = ""
        src = read_lines(h["file"])
        if src:
            lo = max(0, h["line"] - 2)
            hi = min(len(src), h["line"] + excerpt_lines)
            excerpt = "\n".join(f"{i+1}: {src[i]}" for i in range(lo, hi))
        hop = {**h, "code": excerpt}
        # Include the call-site line for the next hop so the model can see
        # which argument carried taint across the edge (e.g. send(base_url=q)
        # vs send(base_url=FIXED, query=q)).
        if i + 1 < len(node_ids):
            for e in graph.out_edges(node_ids[i], EdgeType.CALLS):
                if e.dst == node_ids[i + 1]:
                    csrc = read_lines(e.location.file)
                    ln = e.location.line_start - 1
                    if csrc and 0 <= ln < len(csrc):
                        hop["call_site"] = (
                            f"{e.location.file}:{e.location.line_start}: "
                            f"{csrc[ln].strip()}")
                    break
        hops.append(hop)
    funcs = {
        n.attrs.get("qualname", n.label.rstrip("()")): n
        for n in graph.nodes_of_type(NodeType.FUNCTION)
    }
    guards = []
    seen_guard_locs = set()
    for g in checker.sanitizer_nodes_on(path) + checker.authz_nodes_on(path):
        loc = (g.location.file, g.location.line_start)
        if loc in seen_guard_locs:
            continue
        seen_guard_locs.add(loc)
        excerpt = ""
        gsrc = read_lines(g.location.file)
        if gsrc:
            lo = max(0, g.location.line_start - 2)
            hi = min(len(gsrc), g.location.line_start + excerpt_lines)
            excerpt = "\n".join(f"{i+1}: {gsrc[i]}" for i in range(lo, hi))
        guard = {
            "call": g.attrs.get("call", g.label),
            "file": g.location.file,
            "line": g.location.line_start,
            "code": excerpt,
        }
        check = _guard_check(g, graph, gsrc)
        if check:
            guard["check"] = check
        # Resolve the guard call to its in-repo definition so the model judges
        # the actual check, not just the call site. Includes module-level
        # constants the body references (allowlists, blocklists).
        fn = funcs.get(guard["call"])
        fsrc = read_lines(fn.location.file) if fn is not None else None
        if fsrc:
            body = fsrc[fn.location.line_start - 1:fn.location.line_end]
            guard["definition"] = {
                "file": fn.location.file,
                "line": fn.location.line_start,
                "code": "\n".join(
                    f"{fn.location.line_start + i}: {l}"
                    for i, l in enumerate(body)),
            }
            body_names = set(re.findall(r"[A-Za-z_][A-Za-z0-9_]*",
                                        "\n".join(body)))
            consts = [
                f"{i+1}: {l}" for i, l in enumerate(fsrc)
                if l and not l[0].isspace()
                and re.match(r"[A-Za-z_][A-Za-z0-9_]*\s*=", l)
                and l.split("=")[0].strip() in body_names
            ]
            if consts:
                guard["definition"]["module_constants"] = "\n".join(consts)
        guards.append(guard)
    post_sink = ""
    if feats["hops"]:
        sink_hop = feats["hops"][-1]
        post_sink = _post_sink_lines(
            sink_hop, graph, read_lines(sink_hop["file"]))
    state = {
        "path_id": path.id,
        "hypothesis": path.hypothesis,
        "prior_investigations": path.iterations_investigated,
        "evidence_notes": path.history[-4:] if path.history else [],
        "summary": {
            "length": feats["length"],
            "entry": feats["entry_label"],
            "sink": f'{feats["sink_call"]} ({feats["sink_vuln"]})',
            "user_input_present": feats["has_user_input"],
            "sanitizer_present": feats["has_sanitizer"],
            "authn_present": feats["has_authn"],
            "authz_present": feats["has_authz"],
            "invariants_plausibly_violated": feats["violated_invariants"],
        },
        "hops": hops,
        "guards": guards,
        "post_sink": post_sink,
    }
    return state


class DecisionModel(ABC):
    name: str = "abstract"

    @abstractmethod
    def score_path(
        self,
        path: AttackPath,
        graph: CodeGraph,
        checker: InvariantChecker,
        stats: RunStats,
    ) -> PathScores:
        """Return structured probability scores for one candidate path."""

    def score_paths(
        self,
        paths: list[AttackPath],
        graph: CodeGraph,
        checker: InvariantChecker,
        stats: RunStats,
    ) -> None:
        for p in paths:
            p.scores = self.score_path(p, graph, checker, stats)

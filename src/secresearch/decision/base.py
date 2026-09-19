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


def _fn_node(graph: CodeGraph, file: str, line: int):
    """Innermost function-ish node containing ``file:line``, or None."""
    return min(
        (f for f in graph.nodes_of_type(
            NodeType.FUNCTION, NodeType.HTTP_ENTRY, NodeType.CLI_ENTRY,
            NodeType.EVENT_CONSUMER)
         if f.location.file == file
         and f.location.line_start <= line
         <= (f.location.line_end or f.location.line_start)),
        key=lambda f: (f.location.line_end or f.location.line_start)
                      - f.location.line_start,
        default=None)


def _fn_tree(graph: CodeGraph, file: str, line: int,
             src: list[str] | None):
    """(tree, line offset) of the parsed segment of the innermost function
    containing ``file:line``, or (None, 0)."""
    fn = _fn_node(graph, file, line)
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
                 src: list[str] | None,
                 sink_file: str | None = None,
                 sink_line: int | None = None) -> dict | None:
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
    gate_sink = (
        sink_file == guard.location.file and sink_line is not None
        and any(s.lineno <= sink_line - off <= (s.end_lineno or s.lineno)
                for s in getattr(cond, "body", [])))
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
    if gate_sink:
        check["gates_sink"] = True
    return check or None


def _subject_root(expr_src: str | None) -> str | None:
    """Reduce a check subject or sink arg to the name it roots in:
    ``url.strip()`` -> ``url``, ``str(url)`` -> ``url``,
    ``self.a['k']`` -> ``self.a``. Returns None for literals."""
    if not expr_src:
        return None
    try:
        node = ast.parse(expr_src, mode="eval").body
    except SyntaxError:
        return None
    while True:
        if isinstance(node, ast.Call):
            node = (node.func.value
                    if isinstance(node.func, ast.Attribute)
                    else node.args[0] if node.args else node.func)
        elif isinstance(node, ast.Subscript):
            node = node.value
        else:
            break
    return _dotted(node) or None


def _literal_prefix(node: ast.AST,
                    consts: dict[str, str]) -> str | None:
    """Leading literal text of an argument expression: the part of an
    f-string or +-concatenation that is fixed at the call site. A Name
    operand resolves through module-level ``NAME = 'lit'`` constants."""
    if isinstance(node, ast.Constant):
        return node.value if isinstance(node.value, str) else ""
    if isinstance(node, ast.JoinedStr):
        v0 = node.values[0] if node.values else None
        return v0.value if isinstance(v0, ast.Constant) else None
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        left = _literal_prefix(node.left, consts)
        return left if left is not None else _literal_prefix(
            node.right, consts)
    if isinstance(node, ast.Name):
        return consts.get(node.id)
    if isinstance(node, ast.Call):
        if isinstance(node.func, ast.Attribute) and \
                node.func.attr in {"format", "join"}:
            return _literal_prefix(node.func.value, consts)
        if _dotted(node.func).endswith("urljoin") and node.args:
            return _literal_prefix(node.args[0], consts)
    return None


_TARGET_KWARGS = {"url", "uri", "path", "file", "filename", "target",
                  "host", "addr", "address", "dest", "endpoint"}


def _leading_segment(node: ast.AST) -> ast.AST | None:
    """Leftmost operand of a concat chain or f-string: the part of the
    result string that determines position 0, hence the URI scheme."""
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        return _leading_segment(node.left)
    if isinstance(node, ast.JoinedStr):
        return node.values[0] if node.values else None
    if isinstance(node, ast.Call):
        f = node.func
        if isinstance(f, ast.Attribute) and f.attr == "format":
            return _leading_segment(f.value)
    return node


def _seg_tainted(node: ast.AST, tainted: set[str], params: set[str],
                 consts: dict[str, str], stored: set[str]) -> bool:
    """True when a name in the segment could carry the attacker value:
    a param tainted at this call site, a stored attr the analyzer marked
    user-written, or a local nothing proves fixed. Module constants,
    untainted params, and plain attributes count as fixed."""
    for n in ast.walk(node):
        if isinstance(n, ast.Name):
            if n.id in consts:
                continue
            if n.id in params and n.id not in tainted:
                continue
            return True
        if isinstance(n, ast.Attribute) and _dotted(n) in stored:
            return True
    return False


def _callsite_tainted(code: str, fn_short: str, params: list[str],
                      caller_consts: dict[str, str]) -> set[str] | None:
    """Callee params that received a non-fixed value at this call site:
    `send(base_url=u)` marks base_url; `send(base_url=CONST, query=q)`
    marks only query. None when the call cannot be found."""
    try:
        tree = ast.parse(code)
    except SyntaxError:
        return None
    call = next(
        (c for c in ast.walk(tree)
         if isinstance(c, ast.Call)
         and _dotted(c.func).rsplit(".", 1)[-1] == fn_short),
        None)
    if call is None:
        return None
    bound: dict[str, ast.expr] = {}
    plist = [p for p in params if p != "self"]
    for i, a in enumerate(call.args):
        if i < len(plist):
            bound[plist[i]] = a
    for kw in call.keywords:
        if kw.arg:
            bound[kw.arg] = kw.value
    return {p for p, v in bound.items()
            if not isinstance(v, ast.Constant)
            and not (isinstance(v, ast.Name) and v.id in caller_consts)}


def _module_consts(src: list[str] | None) -> dict[str, str]:
    consts = {}
    for l in src or []:
        if l and not l[0].isspace():
            m = re.match(
                r"([A-Za-z_][A-Za-z0-9_]*)\s*=\s*\(?\s*(['\"][^'\"]*['\"])",
                l)
            if m:
                consts[m.group(1)] = m.group(2).strip("'\"")
    return consts


def _sink_input(sink_hop: dict, call_name: str, graph: CodeGraph,
                src: list[str] | None, guards: list[dict],
                call_site: str | None = None,
                call_site_src: list[str] | None = None,
                sink_node=None) -> dict | None:
    """What the sink's target argument can name. The resource is attacker-
    chosen only when a tainted value reaches string position 0: a bare
    tainted name, or the leading segment of a concat/f-string. A literal
    or non-tainted leading segment pins it; allowlist and sink-gating
    checks on the same subject pin further; urljoin keeps scheme_control
    true because an absolute URI overrides the base."""
    tree, off = _fn_tree(graph, sink_hop["file"], sink_hop["line"], src)
    if tree is None:
        return None
    rel = sink_hop["line"] - off
    short = call_name.rstrip("()").rsplit(".", 1)[-1]
    calls = [c for c in ast.walk(tree)
             if isinstance(c, ast.Call) and c.lineno == rel]
    call = next(
        (c for c in calls
         if _dotted(c.func).rsplit(".", 1)[-1] == short),
        calls[-1] if calls else None)
    if call is None:
        return None
    kw = next((k for k in call.keywords if k.arg in _TARGET_KWARGS), None)
    arg = kw.value if kw else (call.args[0] if call.args else None)
    if arg is None:
        return None
    consts = _module_consts(src)
    fn = _fn_node(graph, sink_hop["file"], sink_hop["line"])
    params = list(fn.attrs.get("params", [])) if fn else []
    tainted = set(fn.attrs.get("tainted_params", [])) if fn else set()
    if call_site and fn:
        code = call_site.split(": ", 1)[-1]
        per_path = _callsite_tainted(
            code, fn.label.rstrip("()").rsplit(".", 1)[-1],
            params, _module_consts(call_site_src))
        if per_path is not None:
            tainted = per_path
    stored = {l.split(":", 1)[1] for l in
              (sink_node.attrs.get("tainted_labels", []) if sink_node
               else [])
              if l.startswith("user-stored:")}
    pset = set(params)
    out: dict[str, Any] = {
        "arg": kw.arg if kw else "arg0",
        "expr": ast.unparse(arg)}
    if isinstance(arg, ast.Constant):
        out["constraint"] = "literal"
    elif isinstance(arg, ast.Call) and _dotted(arg.func).endswith(
            "urljoin"):
        out["constraint"] = "urljoin"
        base = _literal_prefix(arg.args[0], consts) if arg.args else None
        if base:
            out["base"] = base
    elif isinstance(arg, (ast.Name, ast.Attribute, ast.Subscript)):
        out["constraint"] = (
            "unconstrained" if _seg_tainted(
                arg, tainted, pset, consts, stored) else "fixed")
    else:
        leading = _leading_segment(arg)
        if isinstance(leading, ast.Constant) and leading.value:
            out["constraint"], out["prefix"] = (
                "prefix", str(leading.value))
        elif isinstance(leading, ast.Name) and leading.id in consts:
            out["constraint"], out["prefix"] = (
                "prefix", consts[leading.id])
        elif leading is not None and _seg_tainted(
                leading, tainted, pset, consts, stored):
            out["constraint"] = "expression"
        else:
            out["constraint"] = "prefix_expr"
            if leading is not None:
                out["prefix_expr"] = ast.unparse(leading)
    root = _subject_root(out["expr"])
    # A check pins the argument when it is an allowlist on the same
    # subject, or when the sink sits in the check's true-branch: either
    # way the value at sink time satisfies the pattern. A negated gate
    # excludes the pattern instead of pinning it.
    pinned = [chk["pattern"] for g in guards
              if (chk := g.get("check"))
              and chk.get("pattern")
              and (chk.get("kind") == "allowlist"
                   or (chk.get("gates_sink")
                       and not chk.get("negated")))
              and _subject_root(chk.get("subject")) == root]
    if pinned:
        out["pinned"] = pinned
    if out["constraint"] == "literal":
        out["scheme_control"] = False
    elif pinned:
        out["scheme_control"] = ":" not in pinned[0]
    else:
        out["scheme_control"] = out["constraint"] in {
            "unconstrained", "expression", "urljoin"}
    return out


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
        # Include the call-site lines for the next hop so the model can
        # see which argument carried taint across the edge (e.g.
        # send(base_url=q) vs send(base_url=FIXED, query=q)). Reads ahead
        # until parentheses balance so multi-line calls stay parseable.
        if i + 1 < len(node_ids):
            for e in graph.out_edges(node_ids[i], EdgeType.CALLS):
                if e.dst == node_ids[i + 1]:
                    csrc = read_lines(e.location.file)
                    ln = e.location.line_start - 1
                    if csrc and 0 <= ln < len(csrc):
                        code = csrc[ln].strip()
                        depth = code.count("(") - code.count(")")
                        j = ln + 1
                        while depth > 0 and j < len(csrc) and j < ln + 8:
                            code += " " + csrc[j].strip()
                            depth = code.count("(") - code.count(")")
                            j += 1
                        hop["call_site"] = (
                            f"{e.location.file}:{e.location.line_start}: "
                            f"{code}")
                    break
        hops.append(hop)
    funcs = {
        n.attrs.get("qualname", n.label.rstrip("()")): n
        for n in graph.nodes_of_type(NodeType.FUNCTION)
    }
    guards = []
    seen_guard_locs = set()
    sink_hop = feats["hops"][-1] if feats["hops"] else None
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
        check = _guard_check(
            g, graph, gsrc,
            sink_file=sink_hop["file"] if sink_hop else None,
            sink_line=sink_hop["line"] if sink_hop else None)
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
    sink_input = None
    if sink_hop:
        post_sink = _post_sink_lines(
            sink_hop, graph, read_lines(sink_hop["file"]))
        call_site = next(
            (h["call_site"] for h in reversed(hops)
             if h.get("call_site")), None)
        cs_file = (call_site.split(": ", 1)[0].rsplit(":", 1)[0]
                   if call_site else None)
        sink_input = _sink_input(
            sink_hop, feats["sink_call"], graph,
            read_lines(sink_hop["file"]), guards,
            call_site=call_site,
            call_site_src=read_lines(cs_file) if cs_file else None,
            sink_node=checker.sink_node(path))
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
        "sink_input": sink_input,
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

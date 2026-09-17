"""Python code-graph provider built on the stdlib ``ast`` module.

Detects entry points (``http.server`` handler methods, Flask/FastAPI-style route
decorators, CLI entry points), user-controlled sources, security-sensitive sinks,
auth checks and sanitizers, then wires them into a ``CodeGraph`` using
intra-procedural taint tracking plus inter-procedural propagation through the
call graph.
"""

from __future__ import annotations

import ast
import re
from pathlib import Path

from ..models import EdgeType, GraphNode, NodeType, SourceLocation
from .code_graph import CodeGraph, CodeGraphProvider

ROUTE_DECORATORS = {
    "route", "get", "post", "put", "delete", "patch", "head", "options",
    "websocket", "add_url_rule",
}
AUTHN_DECORATORS = {"login_required", "auth_required", "requires_auth", "authenticated"}
AUTHZ_DECORATORS = {
    "permission_required", "requires_permission", "admin_required",
    "requires_role", "authorize", "check_permission",
}
AUTH_CALL_RE = re.compile(
    r"^(check_|verify_|require_|ensure_|is_|has_).*(auth|perm|admin|owner|access|role|right|privilege|login|session|token)",
    re.IGNORECASE,
)
SANITIZER_NAME_RE = re.compile(
    r"(sanitize|validat|escape|allowlist|whitelist|is_safe|is_allowed|normalize_path|check_url)",
    re.IGNORECASE,
)
SECRET_RE = re.compile(
    r"(password|passwd|secret|api_?key|private_?key|access_?token|auth_?token|session_?key|credential)",
    re.IGNORECASE,
)

SOURCE_ATTRS = {
    "request": {"args", "form", "json", "data", "headers", "cookies", "files", "values", "query", "body", "GET", "POST"},
}
SOURCE_CALLS = {"input"}
SOURCE_NAMES = {"argv"}

SINK_SPECS: dict[str, tuple[NodeType, str]] = {
    "os.system": (NodeType.PROCESS_EXEC, "command_execution"),
    "os.popen": (NodeType.PROCESS_EXEC, "command_execution"),
    "subprocess.call": (NodeType.PROCESS_EXEC, "command_execution"),
    "subprocess.run": (NodeType.PROCESS_EXEC, "command_execution"),
    "subprocess.Popen": (NodeType.PROCESS_EXEC, "command_execution"),
    "subprocess.check_output": (NodeType.PROCESS_EXEC, "command_execution"),
    "eval": (NodeType.PROCESS_EXEC, "code_execution"),
    "exec": (NodeType.PROCESS_EXEC, "code_execution"),
    "pickle.loads": (NodeType.DESERIALIZATION, "unsafe_deserialization"),
    "pickle.load": (NodeType.DESERIALIZATION, "unsafe_deserialization"),
    "marshal.loads": (NodeType.DESERIALIZATION, "unsafe_deserialization"),
    "yaml.load": (NodeType.DESERIALIZATION, "unsafe_deserialization"),
    "urllib.request.urlopen": (NodeType.NET_OP, "outbound_request"),
    "urlopen": (NodeType.NET_OP, "outbound_request"),
    "requests.get": (NodeType.NET_OP, "outbound_request"),
    "requests.post": (NodeType.NET_OP, "outbound_request"),
    "requests.put": (NodeType.NET_OP, "outbound_request"),
    "requests.delete": (NodeType.NET_OP, "outbound_request"),
    "requests.request": (NodeType.NET_OP, "outbound_request"),
    "httpx.get": (NodeType.NET_OP, "outbound_request"),
    "httpx.post": (NodeType.NET_OP, "outbound_request"),
    "socket.connect": (NodeType.NET_OP, "outbound_request"),
    "open": (NodeType.FS_OP, "file_access"),
    "os.remove": (NodeType.FS_OP, "file_delete"),
    "os.unlink": (NodeType.FS_OP, "file_delete"),
    "shutil.copy": (NodeType.FS_OP, "file_access"),
    "shutil.move": (NodeType.FS_OP, "file_access"),
    "send_file": (NodeType.FS_OP, "file_access"),
    "execute": (NodeType.DB_OP, "raw_query"),
    "executemany": (NodeType.DB_OP, "raw_query"),
    "cursor.execute": (NodeType.DB_OP, "raw_query"),
    "render_template_string": (NodeType.TEMPLATE_RENDER, "template_injection"),
    "Template": (NodeType.TEMPLATE_RENDER, "template_injection"),
    "redirect": (NodeType.REDIRECT, "open_redirect"),
    "send_redirect": (NodeType.REDIRECT, "open_redirect"),
}

KNOWN_SANITIZERS = {
    "shlex.quote": "shell_escape",
    "html.escape": "html_escape",
    "os.path.basename": "basename",
    "int": "type_cast",
    "float": "type_cast",
}

TRUSTED_BUT_UNSAFE = {"json.loads", "ast.literal_eval"}

HTTP_HANDLER_METHODS = {"do_GET", "do_POST", "do_PUT", "do_DELETE", "do_PATCH", "do_HEAD"}
HTTP_SELF_SOURCES = {"path", "headers", "rfile", "wfile"}


def _dotted(node: ast.expr) -> str:
    """Resolve a Name/Attribute chain to a dotted string."""
    parts = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        parts.append(node.id)
    return ".".join(reversed(parts))


def _call_name(node: ast.Call) -> str:
    return _dotted(node.func)


def _decorator_name(dec: ast.expr) -> str:
    if isinstance(dec, ast.Call):
        return _dotted(dec.func).split(".")[-1]
    return _dotted(dec).split(".")[-1]


def _decorator_route(dec: ast.expr) -> str:
    if isinstance(dec, ast.Call) and dec.args and isinstance(dec.args[0], ast.Constant):
        return str(dec.args[0].value)
    return ""


def _loc(rel: str, qualname: str, node: ast.AST) -> SourceLocation:
    return SourceLocation(
        file=rel,
        function=qualname,
        line_start=getattr(node, "lineno", 0),
        line_end=getattr(node, "end_lineno", getattr(node, "lineno", 0)),
    )


class _FunctionInfo:
    """Per-function analysis record."""

    def __init__(self, qualname: str, rel_file: str, node: ast.FunctionDef):
        self.qualname = qualname
        self.rel_file = rel_file
        self.node = node
        args = getattr(node, "args", None)
        self.params = (
            [a.arg for a in args.args] + [a.arg for a in args.kwonlyargs]
            if args else []
        )
        self.is_method = "." in qualname
        self.entry: str | None = None  # "http" | "cli" | None
        self.route: str = ""
        self.authn = False
        self.authz = False
        self.authn_decorator = False
        self.authz_decorator = False
        self.tainted_params: set[str] = set()
        self.taint_sources: dict[str, set[str]] = {}  # name -> set of source labels
        self.sink_sites: list[tuple[ast.Call, str, str, list[str], dict]] = []  # (call, kind, vuln, tainted args, flags)
        self.calls: list[tuple[ast.Call, str]] = []  # (call node, dotted callee)
        self.returns_taint = False
        self.auth_calls: list[ast.Call] = []
        self.sanitizer_calls: list[ast.Call] = []
        self.secret_names: set[str] = set()


class PythonAnalyzer(CodeGraphProvider):
    """AST-based Python code graph builder."""

    def language(self) -> str:
        return "python"

    def supports(self, repo_root: str) -> bool:
        return any(Path(repo_root).rglob("*.py"))

    def build(self, repo_root: str) -> CodeGraph:
        graph = CodeGraph(repo_root)
        root = Path(repo_root).resolve()
        functions: dict[str, _FunctionInfo] = {}
        methods_by_name: dict[str, list[str]] = {}
        for py in sorted(root.rglob("*.py")):
            rel = str(py.relative_to(root))
            try:
                tree = ast.parse(py.read_text(errors="replace"))
            except SyntaxError:
                continue
            self._collect_functions(tree, rel, functions, methods_by_name)
        self._methods_by_name = methods_by_name
        for info in functions.values():
            self._analyze_function(info, functions, methods_by_name)
        self._propagate_taint(functions)
        # Re-analyze callees whose params received taint during propagation so
        # their sink sites and downstream flows are captured.
        for info in functions.values():
            if info.tainted_params:
                self._analyze_function(info, functions, methods_by_name)
        self._propagate_taint(functions)
        self._emit_graph(graph, functions)
        return graph

    # ------------------------------------------------------------------ pass 1

    def _collect_functions(
        self,
        tree: ast.Module,
        rel: str,
        functions: dict[str, _FunctionInfo],
        methods_by_name: dict[str, list[str]],
    ) -> None:
        def visit_body(body: list[ast.stmt], prefix: str) -> None:
            for stmt in body:
                if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    qualname = f"{prefix}{stmt.name}"
                    info = _FunctionInfo(qualname, rel, stmt)
                    functions[qualname] = info
                    methods_by_name.setdefault(stmt.name, []).append(qualname)
                    for dec in stmt.decorator_list:
                        name = _decorator_name(dec)
                        if name in ROUTE_DECORATORS:
                            info.entry = "http"
                            info.route = _decorator_route(dec)
                        if name in AUTHN_DECORATORS:
                            info.authn = True
                            info.authn_decorator = True
                        if name in AUTHZ_DECORATORS:
                            info.authz = True
                            info.authz_decorator = True
                    if stmt.name in HTTP_HANDLER_METHODS:
                        info.entry = "http"
                        info.route = stmt.name[3:]
                    visit_body(stmt.body, qualname + ".")
                elif isinstance(stmt, ast.ClassDef):
                    visit_body(stmt.body, f"{prefix}{stmt.name}.")
                elif isinstance(stmt, ast.If):
                    # `if __name__ == "__main__":` -> CLI entry
                    if self._is_main_guard(stmt.test):
                        info = _FunctionInfo(f"{prefix}<main>", rel, stmt)  # type: ignore[arg-type]
                        info.entry = "cli"
                        functions[info.qualname] = info
                        visit_body(stmt.body, prefix)
                    else:
                        visit_body(stmt.body, prefix)
                        visit_body(stmt.orelse, prefix)

        visit_body(tree.body, "")

    @staticmethod
    def _is_main_guard(test: ast.expr) -> bool:
        if not isinstance(test, ast.Compare) or len(test.comparators) != 1:
            return False
        left, right = test.left, test.comparators[0]
        names = (
            isinstance(left, ast.Name) and left.id == "__name__"
            and isinstance(right, ast.Constant) and right.value == "__main__"
        ) or (
            isinstance(right, ast.Name) and right.id == "__name__"
            and isinstance(left, ast.Constant) and left.value == "__main__"
        )
        return bool(names)

    # ------------------------------------------------------------------ pass 2

    def _analyze_function(
        self,
        info: _FunctionInfo,
        functions: dict[str, _FunctionInfo],
        methods_by_name: dict[str, list[str]],
    ) -> None:
        # Reset so the pass is idempotent (re-run after param taint arrives).
        info.calls = []
        info.sink_sites = []
        info.auth_calls = []
        info.sanitizer_calls = []
        info.returns_taint = False
        tainted: dict[str, set[str]] = {
            p: {"param"} for p in info.tainted_params
        }

        def expr_taint(e: ast.expr) -> set[str]:
            """Return source labels flowing through this expression."""
            if isinstance(e, ast.Name):
                return tainted.get(e.id, set())
            if isinstance(e, ast.Attribute):
                base = _dotted(e)
                # request.args / self.path style reads
                root, _, attr = base.partition(".")
                if root in SOURCE_ATTRS and attr.split(".")[0] in SOURCE_ATTRS[root]:
                    return {f"{root}.{attr}"}
                if root == "self" and attr.split(".")[0] in HTTP_SELF_SOURCES:
                    return {f"self.{attr}"}
                if root == "sys" and attr.split(".")[0] in SOURCE_NAMES:
                    return {"sys.argv"}
                if root == "os" and attr.split(".")[0] == "environ":
                    return {"os.environ"}
                return expr_taint(e.value)
            if isinstance(e, ast.Call):
                name = _call_name(e)
                if name.split(".")[-1] in SOURCE_CALLS:
                    return {name}
                labels: set[str] = set()
                # receiver taint: qs.get("k"), self.rfile.read(n), data.decode()
                labels |= expr_taint(e.func)
                for a in e.args:
                    labels |= expr_taint(a)
                for kw in e.keywords:
                    labels |= expr_taint(kw.value)
                if name.split(".")[-1] in ("parse_qs", "parse_qsl", "urlparse") or "parse" in name:
                    labels |= {"http.request"}
                callee = self._resolve_callee(name, info, functions, methods_by_name)
                if callee and functions[callee].returns_taint:
                    labels |= {"call:" + callee}
                return labels
            if isinstance(e, ast.JoinedStr):
                labels = set()
                for v in e.values:
                    labels |= expr_taint(v)
                return labels
            if isinstance(e, ast.FormattedValue):
                return expr_taint(e.value)
            if isinstance(e, ast.BinOp):
                return expr_taint(e.left) | expr_taint(e.right)
            if isinstance(e, (ast.Tuple, ast.List)):
                labels = set()
                for x in e.elts:
                    labels |= expr_taint(x)
                return labels
            if isinstance(e, ast.Subscript):
                return expr_taint(e.value)
            if isinstance(e, ast.IfExp):
                return expr_taint(e.body) | expr_taint(e.orelse)
            if isinstance(e, ast.Await):
                return expr_taint(e.value)
            return set()

        def visit(stmt: ast.stmt) -> None:
            # Exclude bodies of nested defs/classes: they are analyzed as their
            # own _FunctionInfo records.
            nested: set[int] = set()
            for s in ast.walk(stmt):
                if s is not stmt and isinstance(s, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                    nested.update(id(n) for n in ast.walk(s))
            for child in ast.walk(stmt):
                if id(child) in nested:
                    continue
                if isinstance(child, ast.Call):
                    cname = _call_name(child)
                    short = cname.split(".")[-1]
                    info.calls.append((child, cname))
                    taint_labels: set[str] = set()
                    for a in child.args:
                        taint_labels |= expr_taint(a)
                    for kw in child.keywords:
                        taint_labels |= expr_taint(kw.value)
                    if taint_labels:
                        sink_key = self._sink_key(cname, short)
                        if sink_key:
                            ntype, vuln = SINK_SPECS[sink_key]
                            flags = {}
                            # parameterized query shape: execute("...?", (params,))
                            if vuln == "raw_query" and len(child.args) >= 2 and isinstance(
                                child.args[0], ast.Constant
                            ) and isinstance(child.args[0].value, str):
                                flags["parameterized"] = True
                            info.sink_sites.append(
                                (child, ntype.value, vuln, sorted(taint_labels), flags)
                            )
                        elif cname in KNOWN_SANITIZERS or short in KNOWN_SANITIZERS \
                                or SANITIZER_NAME_RE.search(short):
                            info.sanitizer_calls.append(child)
                        elif self._resolve_callee(cname, info, functions, methods_by_name):
                            pass  # inter-proc propagation handled in pass 3
                    if AUTH_CALL_RE.match(short):
                        info.auth_calls.append(child)
                        if "perm" in short or "authz" in short or "owner" in short or "access" in short or "admin" in short or "role" in short:
                            info.authz = True
                        else:
                            info.authn = True
                elif isinstance(child, ast.Assign):
                    labels: set[str] = set()
                    for t in child.targets:
                        if isinstance(t, ast.Name) and SECRET_RE.search(t.id):
                            info.secret_names.add(t.id)
                    labels |= expr_taint(child.value)
                    if labels:
                        for t in child.targets:
                            if isinstance(t, ast.Name):
                                tainted.setdefault(t.id, set()).update(labels)
                            elif isinstance(t, ast.Attribute):
                                tainted.setdefault(_dotted(t), set()).update(labels)
                elif isinstance(child, ast.AnnAssign) and child.value:
                    labels = expr_taint(child.value)
                    if labels and isinstance(child.target, ast.Name):
                        tainted.setdefault(child.target.id, set()).update(labels)
                elif isinstance(child, ast.AugAssign):
                    labels = expr_taint(child.value)
                    if labels and isinstance(child.target, ast.Name):
                        tainted.setdefault(child.target.id, set()).update(labels)
                elif isinstance(child, ast.Return) and child.value:
                    if expr_taint(child.value):
                        info.returns_taint = True
            if isinstance(stmt, ast.Return) and stmt.value and expr_taint(stmt.value):
                info.returns_taint = True

        for stmt in info.node.body:  # type: ignore[union-attr]
            visit(stmt)
        info.taint_sources = tainted

    def _sink_key(self, cname: str, short: str) -> str | None:
        if cname in SINK_SPECS:
            return cname
        if short in SINK_SPECS:
            return short
        # method-style sinks: x.execute(q), conn.execute(...)
        if "." in cname and short in SINK_SPECS:
            return short
        return None

    def _resolve_callee(
        self,
        cname: str,
        caller: _FunctionInfo,
        functions: dict[str, _FunctionInfo],
        methods_by_name: dict[str, list[str]],
    ) -> str | None:
        short = cname.split(".")[-1]
        if cname in functions:
            return cname
        if short in functions:
            return short
        if cname.startswith("self."):
            cls = caller.qualname.rsplit(".", 1)[0] if "." in caller.qualname else ""
            cand = f"{cls}.{short}"
            if cand in functions:
                return cand
        cands = methods_by_name.get(short, [])
        if len(cands) == 1:
            return cands[0]
        for c in cands:
            if c.rsplit(".", 1)[0] and caller.rel_file == functions[c].rel_file:
                return c
        return cands[0] if cands else None

    # ------------------------------------------------------------------ pass 3

    def _propagate_taint(self, functions: dict[str, _FunctionInfo]) -> None:
        """Push taint through call arguments into callee parameters (bounded)."""
        worklist = list(functions.keys())
        rounds = 0
        while worklist and rounds < 4:
            rounds += 1
            next_round: list[str] = []
            for qualname in worklist:
                info = functions[qualname]
                for call, cname in info.calls:
                    callee = self._resolve_callee(cname, info, functions, getattr(self, "_methods_by_name", {}))
                    if not callee or callee == qualname:
                        continue
                    target = functions[callee]
                    args = call.args
                    for i, a in enumerate(args):
                        if i >= len(target.params):
                            break
                        labels = self._expr_taint_in(info, a)
                        if labels:
                            pname = target.params[i]
                            if pname not in target.tainted_params:
                                target.tainted_params.add(pname)
                                next_round.append(callee)
            worklist = next_round

    def _expr_taint_in(self, info: _FunctionInfo, e: ast.expr) -> set[str]:
        srcs = info.taint_sources
        found: set[str] = set()

        def walk(n: ast.expr) -> None:
            if isinstance(n, ast.Name) and (n.id in srcs or n.id in info.tainted_params):
                found.update(srcs.get(n.id, {"param"}))
            for c in ast.iter_child_nodes(n):
                if isinstance(c, ast.expr):
                    walk(c)

        walk(e)
        return found

    # ------------------------------------------------------------------ emit

    def _emit_graph(self, graph: CodeGraph, functions: dict[str, _FunctionInfo]) -> None:
        fn_node_ids: dict[str, str] = {}
        for qualname, info in functions.items():
            ntype = NodeType.FUNCTION
            label = qualname.split(".")[-1] + "()"
            if info.entry == "http":
                ntype = NodeType.HTTP_ENTRY
                label = f"HTTP {info.route or qualname}"
            elif info.entry == "cli":
                ntype = NodeType.CLI_ENTRY
                label = f"CLI {qualname}"
            node = graph.add_node(
                ntype,
                label,
                _loc(info.rel_file, qualname, info.node),
                node_id=f"fn:{qualname}",
                qualname=qualname,
                file=info.rel_file,
                authn=info.authn,
                authz=info.authz,
                authn_decorator=info.authn_decorator,
                authz_decorator=info.authz_decorator,
                params=info.params,
                tainted_params=sorted(info.tainted_params),
            )
            fn_node_ids[qualname] = node.id

        # call edges
        for qualname, info in functions.items():
            for call, cname in info.calls:
                callee = self._resolve_callee(cname, info, functions, getattr(self, "_methods_by_name", {}))
                if callee and callee in fn_node_ids and callee != qualname:
                    graph.add_edge(
                        EdgeType.CALLS,
                        fn_node_ids[qualname],
                        fn_node_ids[callee],
                        location=_loc(info.rel_file, qualname, call),
                        callee=cname,
                    )

        # source, sink, authz, sanitizer, secret nodes
        for qualname, info in functions.items():
            fnode = fn_node_ids[qualname]

            # user-input sources
            for name, labels in info.taint_sources.items():
                for label in labels:
                    if label.startswith("call:") or label == "param":
                        continue
                    src = graph.add_node(
                        NodeType.USER_INPUT,
                        label,
                        _loc(info.rel_file, qualname, info.node),
                        source_kind=label,
                        var=name,
                    )
                    graph.add_edge(EdgeType.DATA_FLOWS_INTO, src.id, fnode, var=name)

            # call-site auth markers (decorator authn/authz is carried on the
            # function node's authn_decorator/authz_decorator attrs)
            for call in info.auth_calls:
                short = _call_name(call).split(".")[-1]
                is_authz = bool(
                    re.search(r"perm|authz|owner|access|admin|role|privilege", short, re.I)
                )
                zn = graph.add_node(
                    NodeType.AUTHZ_CHECK if is_authz else NodeType.AUTH_BOUNDARY,
                    _call_name(call) + "()",
                    _loc(info.rel_file, qualname, call),
                    call=_call_name(call),
                )
                graph.add_edge(
                    EdgeType.AUTHORIZES if is_authz else EdgeType.AUTHENTICATES,
                    fnode, zn.id,
                )

            # sanitizers / validators
            for call in info.sanitizer_calls:
                cname = _call_name(call)
                tn = graph.add_node(
                    NodeType.TRANSFORM,
                    cname + "()",
                    _loc(info.rel_file, qualname, call),
                    call=cname,
                    sanitizer=True,
                )
                graph.add_edge(EdgeType.TRANSFORMS, fnode, tn.id)

            # sinks reached with tainted args
            for call, ntype, vuln, labels, flags in info.sink_sites:
                cname = _call_name(call)
                sn = graph.add_node(
                    NodeType(ntype),
                    f"{cname}() [{vuln}]",
                    _loc(info.rel_file, qualname, call),
                    call=cname,
                    vuln=vuln,
                    tainted_labels=labels,
                    **flags,
                )
                graph.add_edge(EdgeType.DATA_FLOWS_INTO, fnode, sn.id, labels=labels)
                graph.add_edge(EdgeType.REACHES, fnode, sn.id)

            # secrets
            for name in info.secret_names:
                sn = graph.add_node(
                    NodeType.SECRET,
                    name,
                    _loc(info.rel_file, qualname, info.node),
                    var=name,
                )
                graph.add_edge(EdgeType.READS, fnode, sn.id)

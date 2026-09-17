"""Security invariants inferred from the code graph, and the checks that decide
whether a concrete attack path plausibly violates one.

Invariants are rule-shaped, not signature-shaped: the analyzer does not look for
known CVE patterns. Each invariant states a property ("attacker-controlled input
must not reach process execution without a sanitizing transform") and the check
evaluates whether the observed path has the required guard.
"""

from __future__ import annotations

import itertools
import re
from pathlib import Path as _Path

from ..models import AttackPath, EdgeType, GraphNode, NodeType, SecurityInvariant
from .code_graph import CodeGraph

_counter = itertools.count(1)

# sink vuln kind -> invariant statement
SINK_INVARIANTS: dict[str, tuple[str, str]] = {
    "command_execution": (
        "no_unvalidated_exec",
        "Attacker-controlled input must not reach process/command execution without a sanitizing transform.",
    ),
    "code_execution": (
        "no_unvalidated_exec",
        "Attacker-controlled input must not reach eval/exec without a sanitizing transform.",
    ),
    "unsafe_deserialization": (
        "no_untrusted_deserialization",
        "Attacker-controlled data must not reach unsafe deserialization.",
    ),
    "outbound_request": (
        "no_unvalidated_request",
        "An attacker must not be able to cause an unintended network request (SSRF).",
    ),
    "file_access": (
        "no_unvalidated_fs",
        "Attacker-controlled input must not reach filesystem reads without path validation.",
    ),
    "file_delete": (
        "no_unvalidated_fs",
        "Attacker-controlled input must not reach filesystem deletes without path validation.",
    ),
    "raw_query": (
        "no_unvalidated_query",
        "Attacker-controlled input must not reach raw database queries without parameterization.",
    ),
    "template_injection": (
        "no_unvalidated_template",
        "Attacker-controlled input must not reach template rendering without escaping.",
    ),
    "open_redirect": (
        "no_unvalidated_redirect",
        "Attacker-controlled input must not control a redirect target.",
    ),
}

# Sink kinds that additionally require an authorization boundary when the
# operation touches a user-identified resource.
AUTHZ_SINK_KINDS = {"raw_query", "file_access", "file_delete"}


def _inv_id() -> str:
    return f"inv-{next(_counter)}"


def infer_invariants(graph: CodeGraph) -> list[SecurityInvariant]:
    """Infer candidate invariants from graph structure."""
    invs: list[SecurityInvariant] = []
    seen: set[str] = set()
    for node in graph.nodes.values():
        vuln = node.attrs.get("vuln")
        if vuln in SINK_INVARIANTS and vuln not in seen:
            kind, statement = SINK_INVARIANTS[vuln]
            invs.append(SecurityInvariant(id=_inv_id(), kind=kind, statement=statement,
                                          params={"vuln": vuln}))
            seen.add(vuln)
        if node.type == NodeType.DB_OP:
            if "requires_authorization" not in seen:
                invs.append(SecurityInvariant(
                    id=_inv_id(),
                    kind="requires_authorization",
                    statement="Data access identified by attacker-supplied identifiers must pass an authorization check.",
                    params={"sink_type": "db_op"},
                ))
                seen.add("requires_authorization")
        if node.type == NodeType.SECRET and "secret_not_observable" not in seen:
            invs.append(SecurityInvariant(
                id=_inv_id(),
                kind="secret_not_observable",
                statement="Secrets must not become attacker-controlled or externally observable.",
                params={},
            ))
            seen.add("secret_not_observable")
    return invs


class InvariantChecker:
    """Evaluates whether an AttackPath plausibly violates known invariants."""

    def __init__(self, graph: CodeGraph):
        self.graph = graph

    def _guard_dominates(self, guard: GraphNode, sink: GraphNode) -> bool:
        """A guard call dominates a sink when it sits earlier in the same file
        and no dedented branch keyword (elif/else/except/def) intervenes."""
        if guard.location.file != sink.location.file:
            return False
        gl, sl = guard.location.line_start, sink.location.line_start
        if gl == sl:
            # sanitizer inside the sink expression itself, e.g.
            # os.system(f"...{shlex.quote(x)}")
            return True
        if gl > sl:
            return False
        try:
            lines = (_Path(self.graph.root) / guard.location.file).read_text(
                errors="replace"
            ).splitlines()
        except OSError:
            return False
        g_indent = len(lines[gl - 1]) - len(lines[gl - 1].lstrip()) if gl - 1 < len(lines) else 0
        for i in range(gl, sl - 1):
            if i >= len(lines):
                break
            text = lines[i].strip()
            indent = len(lines[i]) - len(lines[i].lstrip())
            if indent <= g_indent and re.match(
                r"^(elif |else:|except|finally:|def |class |case )", text
            ):
                return False
        return True

    def sanitizer_nodes_on(self, path: AttackPath) -> list[GraphNode]:
        """Sanitizer transforms that dominate the path's sink."""
        sink = self.sink_node(path)
        if not sink:
            return []
        out = []
        for nid in path.nodes:
            n = self.graph.nodes.get(nid)
            if not n:
                continue
            if n.type == NodeType.TRANSFORM and n.attrs.get("sanitizer"):
                out.append(n)
            for e in self.graph.out_edges(nid, EdgeType.TRANSFORMS):
                t = self.graph.nodes.get(e.dst)
                if t and t.attrs.get("sanitizer") and self._guard_dominates(t, sink):
                    out.append(t)
        return out

    def path_has_sanitizer(self, path: AttackPath) -> bool:
        return bool(self.sanitizer_nodes_on(path))

    def authz_nodes_on(self, path: AttackPath) -> list[GraphNode]:
        sink = self.sink_node(path)
        out = []
        for nid in path.nodes:
            n = self.graph.nodes.get(nid)
            if not n:
                continue
            if n.type == NodeType.AUTHZ_CHECK:
                out.append(n)
            # decorator-level authz guards the whole function
            if n.attrs.get("authz_decorator") and n.type in (
                NodeType.FUNCTION, NodeType.HTTP_ENTRY, NodeType.CLI_ENTRY,
            ):
                out.append(n)
            for e in self.graph.out_edges(nid, EdgeType.AUTHORIZES):
                z = self.graph.nodes.get(e.dst)
                if z and sink and self._guard_dominates(z, sink):
                    out.append(z)
        return out

    def path_has_authz(self, path: AttackPath) -> bool:
        return bool(self.authz_nodes_on(path))

    def path_has_authn(self, path: AttackPath) -> bool:
        sink = self.sink_node(path)
        for nid in path.nodes:
            n = self.graph.nodes.get(nid)
            if not n:
                continue
            if n.type == NodeType.AUTH_BOUNDARY or n.attrs.get("authn_decorator"):
                return True
            for e in self.graph.out_edges(nid, EdgeType.AUTHENTICATES):
                z = self.graph.nodes.get(e.dst)
                if z and sink and self._guard_dominates(z, sink):
                    return True
        return False

    def sink_node(self, path: AttackPath) -> GraphNode | None:
        if not path.nodes:
            return None
        return self.graph.nodes.get(path.nodes[-1])

    def violated_invariants(self, path: AttackPath) -> list[SecurityInvariant]:
        """Return the invariants this path plausibly violates."""
        out: list[SecurityInvariant] = []
        sink = self.sink_node(path)
        if not sink:
            return out
        vuln = sink.attrs.get("vuln")
        if vuln in SINK_INVARIANTS and not sink.attrs.get("parameterized") \
                and not self.path_has_sanitizer(path):
            kind, statement = SINK_INVARIANTS[vuln]
            out.append(SecurityInvariant(
                id=_inv_id(), kind=kind, statement=statement,
                params={"vuln": vuln, "sink": sink.label}, source="inferred",
            ))
        if vuln in AUTHZ_SINK_KINDS and not self.path_has_authz(path):
            out.append(SecurityInvariant(
                id=_inv_id(),
                kind="requires_authorization",
                statement="Data access identified by attacker-supplied identifiers must pass an authorization check.",
                params={"sink": sink.label},
                source="inferred",
            ))
        if not self.path_has_authn(path) and vuln:
            out.append(SecurityInvariant(
                id=_inv_id(),
                kind="reachable_without_authn",
                statement="A security-sensitive sink must not be reachable without authentication.",
                params={"sink": sink.label},
                source="inferred",
            ))
        return out

    def features(self, path: AttackPath) -> dict:
        """Deterministic structural features used by every decision model."""
        sink = self.sink_node(path)
        first = self.graph.nodes.get(path.nodes[0]) if path.nodes else None
        hops = [self.graph.nodes.get(nid) for nid in path.nodes]
        hops = [h for h in hops if h]
        return {
            "length": len(path.nodes),
            "entry_type": first.type.value if first else "",
            "entry_label": first.label if first else "",
            "sink_type": sink.type.value if sink else "",
            "sink_vuln": sink.attrs.get("vuln", "") if sink else "",
            "sink_call": sink.attrs.get("call", "") if sink else "",
            "has_user_input": any(h.type == NodeType.USER_INPUT for h in hops),
            "has_sanitizer": self.path_has_sanitizer(path),
            "has_authz": self.path_has_authz(path),
            "has_authn": self.path_has_authn(path),
            "crosses_authz_boundary": self.path_has_authz(path),
            "violated_invariants": [i.kind for i in self.violated_invariants(path)],
            "n_violated": len(self.violated_invariants(path)),
            "hops": [
                {
                    "label": h.label,
                    "type": h.type.value,
                    "file": h.location.file,
                    "line": h.location.line_start,
                }
                for h in hops
            ],
        }

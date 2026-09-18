"""Attack-path generation: enumerate candidate source->sink paths over the code
graph and expand the candidate set when agents surface new relationships.
"""

from __future__ import annotations

import itertools
from abc import ABC, abstractmethod

from ..models import AttackPath, EdgeType, GraphNode, NodeType, PathStatus, NewPathSpec
from .code_graph import CodeGraph

ENTRY_TYPES = {NodeType.HTTP_ENTRY, NodeType.CLI_ENTRY, NodeType.EVENT_CONSUMER}
SINK_TYPES = {
    NodeType.DB_OP,
    NodeType.FS_OP,
    NodeType.NET_OP,
    NodeType.PROCESS_EXEC,
    NodeType.DESERIALIZATION,
    NodeType.TEMPLATE_RENDER,
    NodeType.REDIRECT,
    NodeType.PRIVILEGED_OP,
    NodeType.SENSITIVE_RESOURCE,
}


class AttackPathGenerator(ABC):
    """Pluggable candidate-path generator."""

    @abstractmethod
    def generate(self, graph: CodeGraph) -> list[AttackPath]: ...

    @abstractmethod
    def expand(self, graph: CodeGraph, spec: NewPathSpec, parent: AttackPath | None) -> list[AttackPath]:
        ...


class GraphPathGenerator(AttackPathGenerator):
    """Enumerates entry -> user-input -> ... -> sink chains in the CodeGraph."""

    def __init__(self, max_depth: int = 10, max_paths: int = 20000):
        self.max_depth = max_depth
        self.max_paths = max_paths
        self._counter = itertools.count(1)
        self._seen: set[tuple[str, ...]] = set()

    def generate(self, graph: CodeGraph) -> list[AttackPath]:
        entries = [n.id for n in graph.nodes_of_type(*ENTRY_TYPES)]
        sources = [n.id for n in graph.nodes_of_type(NodeType.USER_INPUT)]
        sinks = [n.id for n in graph.nodes_of_type(*SINK_TYPES)]
        starts = entries + [s for s in sources if s not in entries]
        raw = graph.enumerate_paths(starts, sinks, self.max_depth, self.max_paths)
        # One candidate per (entry function, sink): several tainted variables may
        # feed the same sink; keep the path that shows the user-input hop.
        by_key: dict[tuple[str, str], list[str]] = {}
        for node_ids in raw:
            first = graph.nodes.get(node_ids[0])
            start = (
                node_ids[0]
                if first and first.type in ENTRY_TYPES
                else node_ids[1]
            )
            key = (start, node_ids[-1])
            has_input = any(
                (n := graph.nodes.get(i)) and n.type == NodeType.USER_INPUT
                for i in node_ids
            )
            if key not in by_key or (has_input and not self._has_input(by_key[key], graph)):
                by_key[key] = node_ids
        paths = []
        for node_ids in by_key.values():
            path = self._make_path(graph, node_ids)
            if path:
                paths.append(path)
        return paths

    @staticmethod
    def _has_input(node_ids: list[str], graph: CodeGraph) -> bool:
        return any(
            (n := graph.nodes.get(i)) and n.type == NodeType.USER_INPUT
            for i in node_ids
        )

    def expand(
        self, graph: CodeGraph, spec: NewPathSpec, parent: AttackPath | None
    ) -> list[AttackPath]:
        """Turn an agent-reported path hint into concrete graph paths.

        Match the spec's node labels against graph nodes, then find a reachable
        chain between the matched nodes.
        """
        matched: list[GraphNode] = []
        for label in spec.node_labels:
            for n in graph.nodes.values():
                if label in n.label or label == n.attrs.get("qualname") or label == n.attrs.get("call"):
                    matched.append(n)
                    break
        if len(matched) < 2:
            return []
        chain: list[str] = []
        for i in range(len(matched) - 1):
            seg = graph.find_reachable(matched[i].id, matched[i + 1].id)
            if not seg:
                return []
            chain.extend(seg if not chain else seg[1:])
        path = self._make_path(graph, chain)
        if path:
            path.derived_from = parent.id if parent else None
            path.hypothesis = spec.description
            return [path]
        return []

    def _make_path(self, graph: CodeGraph, node_ids: list[str]) -> AttackPath | None:
        key = tuple(node_ids)
        if key in self._seen:
            return None
        self._seen.add(key)
        pid = f"path-{next(self._counter)}"
        return AttackPath(id=pid, nodes=list(node_ids), label=graph.describe_path(node_ids))

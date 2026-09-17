"""Code graph: typed nodes and edges with source provenance.

``CodeGraphProvider`` is the pluggable analyzer interface. Providers turn a
repository into a ``CodeGraph``; additional languages plug in here.
"""

from __future__ import annotations

import itertools
from abc import ABC, abstractmethod
from pathlib import Path

from ..models import EdgeType, GraphEdge, GraphNode, NodeType, SourceLocation


class CodeGraph:
    def __init__(self, root: str):
        self.root = str(Path(root).resolve())
        self.nodes: dict[str, GraphNode] = {}
        self.edges: dict[str, GraphEdge] = {}
        self._out: dict[str, list[str]] = {}  # node id -> edge ids
        self._in: dict[str, list[str]] = {}
        self._counter = itertools.count(1)

    def _next_id(self, prefix: str) -> str:
        return f"{prefix}-{next(self._counter)}"

    def add_node(
        self,
        type: NodeType,
        label: str,
        location: SourceLocation,
        node_id: str | None = None,
        **attrs,
    ) -> GraphNode:
        nid = node_id or self._next_id("n")
        if nid in self.nodes:
            node = self.nodes[nid]
            node.attrs.update(attrs)
            return node
        node = GraphNode(id=nid, type=type, label=label, location=location, attrs=attrs)
        self.nodes[nid] = node
        return node

    def add_edge(
        self,
        type: EdgeType,
        src: str,
        dst: str,
        location: SourceLocation | None = None,
        edge_id: str | None = None,
        **attrs,
    ) -> GraphEdge | None:
        if src not in self.nodes or dst not in self.nodes:
            return None
        for eid in self._out.get(src, []):
            e = self.edges[eid]
            if e.dst == dst and e.type == type:
                return e
        eid = edge_id or self._next_id("e")
        edge = GraphEdge(id=eid, type=type, src=src, dst=dst, location=location, attrs=attrs)
        self.edges[eid] = edge
        self._out.setdefault(src, []).append(eid)
        self._in.setdefault(dst, []).append(eid)
        return edge

    def out_edges(self, node_id: str, *types: EdgeType) -> list[GraphEdge]:
        return [self.edges[e] for e in self._out.get(node_id, []) if not types or self.edges[e].type in types]

    def in_edges(self, node_id: str, *types: EdgeType) -> list[GraphEdge]:
        return [self.edges[e] for e in self._in.get(node_id, []) if not types or self.edges[e].type in types]

    def successors(self, node_id: str, *types: EdgeType) -> list[str]:
        return [e.dst for e in self.out_edges(node_id, *types)]

    def predecessors(self, node_id: str, *types: EdgeType) -> list[str]:
        return [e.src for e in self.in_edges(node_id, *types)]

    def nodes_of_type(self, *types: NodeType) -> list[GraphNode]:
        return [n for n in self.nodes.values() if n.type in types]

    def find_reachable(self, src: str, dst: str, max_depth: int = 12) -> list[str] | None:
        """BFS shortest path of node ids from src to dst, or None."""
        if src == dst:
            return [src]
        seen = {src}
        frontier = [(src, [src])]
        while frontier:
            node, path = frontier.pop(0)
            if len(path) > max_depth:
                continue
            for nxt in self.successors(node):
                if nxt == dst:
                    return path + [nxt]
                if nxt not in seen:
                    seen.add(nxt)
                    frontier.append((nxt, path + [nxt]))
        return None

    def enumerate_paths(
        self,
        sources: list[str],
        sinks: list[str],
        max_depth: int = 10,
        max_paths: int = 500,
    ) -> list[list[str]]:
        """Enumerate simple source->sink paths (DFS, bounded)."""
        sink_set = set(sinks)
        results: list[list[str]] = []

        def dfs(node: str, path: list[str], visited: set[str]) -> None:
            if len(results) >= max_paths:
                return
            if node in sink_set and len(path) > 1:
                results.append(list(path))
                return
            if len(path) >= max_depth:
                return
            for nxt in self.successors(node):
                if nxt not in visited:
                    visited.add(nxt)
                    path.append(nxt)
                    dfs(nxt, path, visited)
                    path.pop()
                    visited.discard(nxt)

        for s in sources:
            dfs(s, [s], {s})
        return results

    def to_dict(self) -> dict:
        return {
            "root": self.root,
            "nodes": [n.to_dict() for n in self.nodes.values()],
            "edges": [e.to_dict() for e in self.edges.values()],
        }

    def describe_path(self, node_ids: list[str]) -> str:
        """Human-readable chain like ``POST /import -> ImportService.process -> fetch()``."""
        parts = []
        for nid in node_ids:
            n = self.nodes.get(nid)
            parts.append(n.label if n else nid)
        sink = self.nodes.get(node_ids[-1]) if node_ids else None
        suffix = f" @{sink.location.file}:{sink.location.line_start}" if sink else ""
        return " -> ".join(parts) + suffix

    def path_locations(self, node_ids: list[str]) -> list[SourceLocation]:
        return [self.nodes[nid].location for nid in node_ids if nid in self.nodes]


class CodeGraphProvider(ABC):
    """Builds a CodeGraph from a repository. One implementation per language."""

    @abstractmethod
    def language(self) -> str: ...

    @abstractmethod
    def supports(self, repo_root: str) -> bool: ...

    @abstractmethod
    def build(self, repo_root: str) -> CodeGraph: ...

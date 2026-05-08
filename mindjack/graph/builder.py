"""Build a directed trust graph from RunContext artifacts and surfaces."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any

from mindjack.core.constants import ScopeLevel
from mindjack.core.models import DiscoveredArtifact, RunContext, TrustSurface


# ---------------------------------------------------------------------------
# Node / Edge value objects
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class GraphNode:
    """A node in the trust graph."""

    id: str
    type: str  # tool, artifact, trust_surface, scope, project
    label: str
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class GraphEdge:
    """A directed edge in the trust graph."""

    source: str
    target: str
    relation: str  # influences, overrides, belongs_to, executes, persists_across, shared_by, reachable_from
    metadata: dict[str, Any] = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Node / Edge type literals (kept as constants for programmatic use)
# ---------------------------------------------------------------------------

NODE_TOOL = "tool"
NODE_ARTIFACT = "artifact"
NODE_TRUST_SURFACE = "trust_surface"
NODE_SCOPE = "scope"
NODE_PROJECT = "project"

EDGE_INFLUENCES = "influences"
EDGE_OVERRIDES = "overrides"
EDGE_BELONGS_TO = "belongs_to"
EDGE_EXECUTES = "executes"
EDGE_PERSISTS_ACROSS = "persists_across"
EDGE_SHARED_BY = "shared_by"
EDGE_REACHABLE_FROM = "reachable_from"


# ---------------------------------------------------------------------------
# TrustGraph — adjacency-list directed graph (stdlib only)
# ---------------------------------------------------------------------------

class TrustGraph:
    """Directed graph built from a RunContext's artifacts and surfaces.

    Uses a simple adjacency-list representation — no external dependencies.
    """

    def __init__(self) -> None:
        self._nodes: dict[str, GraphNode] = {}
        self._adj: dict[str, list[GraphEdge]] = {}  # outgoing edges by source

    # -- mutation helpers (private) -----------------------------------------

    def _add_node(self, node: GraphNode) -> None:
        self._nodes[node.id] = node
        self._adj.setdefault(node.id, [])

    def _add_edge(self, edge: GraphEdge) -> None:
        self._adj.setdefault(edge.source, []).append(edge)
        # ensure target appears in adjacency list even with no outgoing edges
        self._adj.setdefault(edge.target, [])

    # -- public API ---------------------------------------------------------

    def build(self, ctx: RunContext) -> TrustGraph:
        """Populate the graph from *ctx* and return ``self`` for chaining."""
        # Lookup helpers
        artifact_by_id: dict[str, DiscoveredArtifact] = {
            a.artifact_id: a for a in ctx.artifacts
        }
        tools_seen: set[str] = set()
        scopes_seen: set[str] = set()
        projects_seen: set[str] = set()

        # --- 1. Artifact + Tool + Scope nodes ------------------------------
        for art in ctx.artifacts:
            # artifact node
            self._add_node(GraphNode(
                id=art.artifact_id,
                type=NODE_ARTIFACT,
                label=str(art.path),
                metadata={
                    "tool_slug": art.tool_slug,
                    "surface_type": art.surface_type.value,
                    "scope": art.scope.value,
                    "exists": art.exists,
                    "state": art.state.value,
                    "precedence_rank": art.precedence_rank,
                },
            ))

            # tool node (deduplicated)
            tool_id = f"tool:{art.tool_slug}"
            if tool_id not in tools_seen:
                tools_seen.add(tool_id)
                self._add_node(GraphNode(
                    id=tool_id,
                    type=NODE_TOOL,
                    label=art.tool_slug,
                ))
            # artifact -> belongs_to -> tool
            self._add_edge(GraphEdge(
                source=art.artifact_id,
                target=tool_id,
                relation=EDGE_BELONGS_TO,
            ))

            # scope node (deduplicated)
            scope_id = f"scope:{art.scope.value}"
            if scope_id not in scopes_seen:
                scopes_seen.add(scope_id)
                self._add_node(GraphNode(
                    id=scope_id,
                    type=NODE_SCOPE,
                    label=art.scope.value,
                ))
            # artifact -> persists_across -> scope
            self._add_edge(GraphEdge(
                source=art.artifact_id,
                target=scope_id,
                relation=EDGE_PERSISTS_ACROSS,
            ))

            # project node for project-scope artifacts
            if art.scope == ScopeLevel.PROJECT:
                for sp in ctx.scope_paths:
                    proj_id = f"project:{sp}"
                    if proj_id not in projects_seen:
                        projects_seen.add(proj_id)
                        self._add_node(GraphNode(
                            id=proj_id,
                            type=NODE_PROJECT,
                            label=str(sp),
                        ))
                    self._add_edge(GraphEdge(
                        source=art.artifact_id,
                        target=proj_id,
                        relation=EDGE_BELONGS_TO,
                    ))

        # --- 2. Trust-surface nodes ----------------------------------------
        for surf in ctx.surfaces:
            self._add_node(GraphNode(
                id=surf.surface_id,
                type=NODE_TRUST_SURFACE,
                label=surf.influence_type.value,
                metadata={
                    "execution_capability": surf.execution_capability,
                    "persistence": surf.persistence,
                    "cross_tool_reach": surf.cross_tool_reach,
                    "severity": surf.risk_dimensions.get("_severity", "unknown"),
                    "composite": surf.risk_dimensions.get("_composite", 0),
                },
            ))

            # surface -> influences -> tool (via artifact)
            art = artifact_by_id.get(surf.artifact_id)
            if art is not None:
                tool_id = f"tool:{art.tool_slug}"
                self._add_edge(GraphEdge(
                    source=surf.surface_id,
                    target=tool_id,
                    relation=EDGE_INFLUENCES,
                    metadata={"via_artifact": surf.artifact_id},
                ))
                # surface -> reachable_from -> artifact
                self._add_edge(GraphEdge(
                    source=surf.surface_id,
                    target=surf.artifact_id,
                    relation=EDGE_REACHABLE_FROM,
                ))

            # cross-tool surfaces -> executes edges to all tools
            if surf.cross_tool_reach:
                for tid in tools_seen:
                    self._add_edge(GraphEdge(
                        source=surf.surface_id,
                        target=tid,
                        relation=EDGE_EXECUTES,
                        metadata={"cross_tool": True},
                    ))

        # --- 3. Shared-path edges ------------------------------------------
        path_to_artifacts: dict[str, list[str]] = {}
        for art in ctx.artifacts:
            path_to_artifacts.setdefault(str(art.path), []).append(art.artifact_id)
        for path, art_ids in path_to_artifacts.items():
            if len(art_ids) > 1:
                for i, a_id in enumerate(art_ids):
                    for b_id in art_ids[i + 1:]:
                        self._add_edge(GraphEdge(
                            source=a_id,
                            target=b_id,
                            relation=EDGE_SHARED_BY,
                            metadata={"shared_path": path},
                        ))

        # --- 4. Precedence edges (if already resolved) ---------------------
        for pedge in getattr(ctx, "precedence_edges", []):
            self._add_edge(GraphEdge(
                source=pedge.source_id,
                target=pedge.target_id,
                relation=EDGE_OVERRIDES,
                metadata={"precedence_relation": pedge.relation, "reason": pedge.reason},
            ))

        return self

    # -- query API ----------------------------------------------------------

    def nodes(self) -> list[GraphNode]:
        """Return all nodes."""
        return list(self._nodes.values())

    def edges(self) -> list[GraphEdge]:
        """Return all edges."""
        all_edges: list[GraphEdge] = []
        for edge_list in self._adj.values():
            all_edges.extend(edge_list)
        return all_edges

    def neighbors(self, node_id: str) -> list[GraphEdge]:
        """Return outgoing edges from *node_id*."""
        return list(self._adj.get(node_id, []))

    def subgraph_for_tool(self, slug: str) -> TrustGraph:
        """Return a new TrustGraph containing only nodes/edges related to *slug*."""
        tool_id = f"tool:{slug}"
        # Collect relevant node ids via BFS on reverse direction
        relevant: set[str] = set()
        relevant.add(tool_id)

        # Gather artifact ids belonging to this tool
        for node in self._nodes.values():
            if node.type == NODE_ARTIFACT and node.metadata.get("tool_slug") == slug:
                relevant.add(node.id)

        # Gather surfaces that reference these artifacts
        for edge_list in self._adj.values():
            for e in edge_list:
                if e.target in relevant or e.source in relevant:
                    relevant.add(e.source)
                    relevant.add(e.target)

        sub = TrustGraph()
        for nid in relevant:
            if nid in self._nodes:
                sub._add_node(self._nodes[nid])
        for edge_list in self._adj.values():
            for e in edge_list:
                if e.source in relevant and e.target in relevant:
                    sub._add_edge(e)
        return sub

    def to_dict(self) -> dict[str, Any]:
        """Serialise the graph to a plain dict (JSON-safe)."""
        def _node_dict(n: GraphNode) -> dict[str, Any]:
            return {"id": n.id, "type": n.type, "label": n.label, "metadata": dict(n.metadata)}

        def _edge_dict(e: GraphEdge) -> dict[str, Any]:
            return {"source": e.source, "target": e.target, "relation": e.relation, "metadata": dict(e.metadata)}

        return {
            "nodes": [_node_dict(n) for n in self.nodes()],
            "edges": [_edge_dict(e) for e in self.edges()],
        }

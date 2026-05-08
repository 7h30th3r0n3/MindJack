"""Precedence resolution engine for overlapping artifacts."""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
from typing import Any

from mindjack.core.constants import PrecedenceRelation, ScopeLevel
from mindjack.core.models import DiscoveredArtifact


# ---------------------------------------------------------------------------
# PrecedenceEdge — emitted by the engine
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class PrecedenceEdge:
    """A resolved precedence relationship between two artifacts."""

    source_id: str
    target_id: str
    relation: str  # value from PrecedenceRelation
    reason: str


# ---------------------------------------------------------------------------
# Scope ordering (narrower = higher priority number → lower wins)
# ---------------------------------------------------------------------------

_SCOPE_PRIORITY: dict[ScopeLevel, int] = {
    ScopeLevel.GLOBAL_SYSTEM: 0,
    ScopeLevel.ENTERPRISE: 1,
    ScopeLevel.TEAM: 2,
    ScopeLevel.USER: 3,
    ScopeLevel.WORKSPACE: 4,
    ScopeLevel.PROJECT: 5,
}


def _is_override_file(art: DiscoveredArtifact) -> bool:
    """Return True if the artifact looks like an override variant."""
    name = art.path.name.lower()
    return "override" in name or ".override." in name


# ---------------------------------------------------------------------------
# PrecedenceEngine
# ---------------------------------------------------------------------------

class PrecedenceEngine:
    """Resolve precedence relationships among discovered artifacts.

    Rules
    -----
    1. Lower ``precedence_rank`` = higher priority.
    2. USER scope dominates PROJECT scope for the same tool when both exist.
    3. Override files (e.g. ``AGENTS.override.md``) dominate their base file.
    4. Within the same scope + tool, ``precedence_rank`` is the tiebreaker.
    """

    def resolve(self, artifacts: list[DiscoveredArtifact]) -> list[PrecedenceEdge]:
        """Resolve precedence for a list of artifacts (typically all from one run)."""
        # Group by tool_slug
        by_tool: dict[str, list[DiscoveredArtifact]] = defaultdict(list)
        for art in artifacts:
            by_tool[art.tool_slug].append(art)

        edges: list[PrecedenceEdge] = []
        for _slug, group in by_tool.items():
            edges.extend(self._resolve_group(group))
        return edges

    # -- internal -----------------------------------------------------------

    def _resolve_group(self, group: list[DiscoveredArtifact]) -> list[PrecedenceEdge]:
        """Resolve precedence within a single tool's artifact group."""
        if len(group) < 2:
            return []

        edges: list[PrecedenceEdge] = []

        # Sort by effective priority (lower = higher priority)
        ranked = sorted(group, key=lambda a: (a.precedence_rank or 99, _SCOPE_PRIORITY.get(a.scope, 99)))

        for i, higher in enumerate(ranked):
            for lower in ranked[i + 1:]:
                edge = self._compare(higher, lower)
                if edge is not None:
                    edges.append(edge)

        return edges

    def _compare(
        self,
        a: DiscoveredArtifact,
        b: DiscoveredArtifact,
    ) -> PrecedenceEdge | None:
        """Compare two artifacts and return a PrecedenceEdge (or None)."""

        # Rule 3: override files dominate base files
        a_override = _is_override_file(a)
        b_override = _is_override_file(b)
        if a_override and not b_override and a.tool_slug == b.tool_slug:
            return PrecedenceEdge(
                source_id=a.artifact_id,
                target_id=b.artifact_id,
                relation=PrecedenceRelation.OVERRIDES.value,
                reason=f"Override file {a.path.name} overrides base {b.path.name}",
            )
        if b_override and not a_override and a.tool_slug == b.tool_slug:
            return PrecedenceEdge(
                source_id=b.artifact_id,
                target_id=a.artifact_id,
                relation=PrecedenceRelation.OVERRIDES.value,
                reason=f"Override file {b.path.name} overrides base {a.path.name}",
            )

        # Rule 2: USER scope dominates PROJECT scope
        if a.scope == ScopeLevel.USER and b.scope == ScopeLevel.PROJECT:
            return PrecedenceEdge(
                source_id=a.artifact_id,
                target_id=b.artifact_id,
                relation=PrecedenceRelation.DOMINATES.value,
                reason=f"User-scope artifact dominates project-scope artifact",
            )
        if b.scope == ScopeLevel.USER and a.scope == ScopeLevel.PROJECT:
            return PrecedenceEdge(
                source_id=b.artifact_id,
                target_id=a.artifact_id,
                relation=PrecedenceRelation.DOMINATES.value,
                reason=f"User-scope artifact dominates project-scope artifact",
            )

        # Rule 1: lower precedence_rank wins
        a_rank = a.precedence_rank if a.precedence_rank is not None else 99
        b_rank = b.precedence_rank if b.precedence_rank is not None else 99
        if a_rank < b_rank:
            return PrecedenceEdge(
                source_id=a.artifact_id,
                target_id=b.artifact_id,
                relation=PrecedenceRelation.SHADOWED_BY.value,
                reason=f"Artifact rank {a_rank} shadows rank {b_rank}",
            )
        if b_rank < a_rank:
            return PrecedenceEdge(
                source_id=b.artifact_id,
                target_id=a.artifact_id,
                relation=PrecedenceRelation.SHADOWED_BY.value,
                reason=f"Artifact rank {b_rank} shadows rank {a_rank}",
            )

        # Same scope + same rank → parallel scope
        if a.scope == b.scope:
            return PrecedenceEdge(
                source_id=a.artifact_id,
                target_id=b.artifact_id,
                relation=PrecedenceRelation.PARALLEL_SCOPE.value,
                reason=f"Both artifacts share scope {a.scope.value} with equal rank",
            )

        # Different scopes, same rank → inherits_from (broader inherits from narrower)
        a_prio = _SCOPE_PRIORITY.get(a.scope, 99)
        b_prio = _SCOPE_PRIORITY.get(b.scope, 99)
        if a_prio < b_prio:
            return PrecedenceEdge(
                source_id=b.artifact_id,
                target_id=a.artifact_id,
                relation=PrecedenceRelation.INHERITS_FROM.value,
                reason=f"Narrower scope {b.scope.value} inherits from broader {a.scope.value}",
            )
        if b_prio < a_prio:
            return PrecedenceEdge(
                source_id=a.artifact_id,
                target_id=b.artifact_id,
                relation=PrecedenceRelation.INHERITS_FROM.value,
                reason=f"Narrower scope {a.scope.value} inherits from broader {b.scope.value}",
            )

        return None

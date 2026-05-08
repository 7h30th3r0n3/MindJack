"""Cross-tool correlation engine."""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any

from mindjack.core.models import DiscoveredArtifact, RunContext, TrustSurface


# ---------------------------------------------------------------------------
# Correlation value object
# ---------------------------------------------------------------------------

@dataclass
class Correlation:
    """A detected cross-tool or cross-artifact correlation."""

    paths: list[str]
    tools: list[str]
    surface_types: list[str]
    risk_multiplier: float
    description: str


# ---------------------------------------------------------------------------
# CorrelationEngine
# ---------------------------------------------------------------------------

class CorrelationEngine:
    """Detect cross-tool correlations in a RunContext.

    Two detection strategies:

    1. **Shared-path artifacts** — the same filesystem path is referenced by
       multiple tool slugs (or has tags referencing multiple tools).
    2. **Overlapping surfaces** — the same artifact path has trust surfaces
       that influence multiple tools.
    """

    def correlate(self, ctx: RunContext) -> list[Correlation]:
        """Return all detected correlations."""
        results: list[Correlation] = []
        results.extend(self._shared_path_artifacts(ctx))
        results.extend(self._overlapping_surfaces(ctx))
        results.extend(self._tag_cross_references(ctx))
        return results

    # -- strategy 1: shared-path artifacts ----------------------------------

    def _shared_path_artifacts(self, ctx: RunContext) -> list[Correlation]:
        """Detect artifacts where the same path is claimed by multiple tools."""
        path_to_arts: dict[str, list[DiscoveredArtifact]] = defaultdict(list)
        for art in ctx.artifacts:
            path_to_arts[str(art.path)].append(art)

        correlations: list[Correlation] = []
        for path, arts in path_to_arts.items():
            slugs = sorted({a.tool_slug for a in arts})
            if len(slugs) < 2:
                continue
            surface_types = sorted({a.surface_type.value for a in arts})
            correlations.append(Correlation(
                paths=[path],
                tools=slugs,
                surface_types=surface_types,
                risk_multiplier=1.0 + 0.5 * (len(slugs) - 1),
                description=(
                    f"Path {path} is shared across tools: {', '.join(slugs)}. "
                    f"A single modification could affect multiple assistants."
                ),
            ))
        return correlations

    # -- strategy 2: overlapping surfaces -----------------------------------

    def _overlapping_surfaces(self, ctx: RunContext) -> list[Correlation]:
        """Detect paths whose trust surfaces influence multiple tools."""
        artifact_by_id: dict[str, DiscoveredArtifact] = {
            a.artifact_id: a for a in ctx.artifacts
        }

        # Map path -> set of tools that have surfaces reachable from that path
        path_tool_surfaces: dict[str, dict[str, list[str]]] = defaultdict(lambda: defaultdict(list))
        for surf in ctx.surfaces:
            art = artifact_by_id.get(surf.artifact_id)
            if art is None:
                continue
            path_tool_surfaces[str(art.path)][art.tool_slug].append(surf.influence_type.value)

        # Also account for cross_tool_reach surfaces
        cross_tool_paths: dict[str, list[str]] = defaultdict(list)
        for surf in ctx.surfaces:
            if not surf.cross_tool_reach:
                continue
            art = artifact_by_id.get(surf.artifact_id)
            if art is None:
                continue
            cross_tool_paths[str(art.path)].append(surf.influence_type.value)

        correlations: list[Correlation] = []

        # Multi-tool surface paths
        for path, tool_map in path_tool_surfaces.items():
            if len(tool_map) < 2:
                continue
            tools = sorted(tool_map.keys())
            all_surfaces = sorted({s for slist in tool_map.values() for s in slist})
            correlations.append(Correlation(
                paths=[path],
                tools=tools,
                surface_types=all_surfaces,
                risk_multiplier=1.0 + 0.3 * (len(tools) - 1),
                description=(
                    f"Surfaces at {path} influence multiple tools: {', '.join(tools)}. "
                    f"Surface types: {', '.join(all_surfaces)}."
                ),
            ))

        # Cross-tool-reach surfaces
        for path, influence_types in cross_tool_paths.items():
            art_match = next(
                (a for a in ctx.artifacts if str(a.path) == path), None
            )
            if art_match is None:
                continue
            all_tools = sorted({a.tool_slug for a in ctx.artifacts})
            correlations.append(Correlation(
                paths=[path],
                tools=all_tools,
                surface_types=sorted(set(influence_types)),
                risk_multiplier=2.0,
                description=(
                    f"Cross-tool surface at {path} (tool: {art_match.tool_slug}) "
                    f"can reach all detected tools: {', '.join(all_tools)}."
                ),
            ))

        return correlations

    # -- strategy 3: tag cross-references -----------------------------------

    def _tag_cross_references(self, ctx: RunContext) -> list[Correlation]:
        """Detect artifacts whose tags reference other tool slugs."""
        all_slugs = {a.tool_slug for a in ctx.artifacts}

        correlations: list[Correlation] = []
        for art in ctx.artifacts:
            referenced = {t for t in art.tags if t in all_slugs and t != art.tool_slug}
            if not referenced:
                continue
            tools = sorted({art.tool_slug} | referenced)
            correlations.append(Correlation(
                paths=[str(art.path)],
                tools=tools,
                surface_types=[art.surface_type.value],
                risk_multiplier=1.0 + 0.4 * len(referenced),
                description=(
                    f"Artifact {art.path} (tool: {art.tool_slug}) has tags "
                    f"referencing other tools: {', '.join(sorted(referenced))}."
                ),
            ))
        return correlations

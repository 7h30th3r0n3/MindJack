"""Estimate the blast radius of a patch plan."""

from __future__ import annotations

from dataclasses import dataclass, field

from mindjack.core.constants import PatchEngine
from mindjack.core.models import PatchPlan, RunContext


@dataclass
class BlastRadius:
    """Result of blast-radius analysis for a patch plan."""

    affected_tools: list[str] = field(default_factory=list)
    affected_scopes: list[str] = field(default_factory=list)
    cross_tool: bool = False
    persistence_level: str = "session"
    reversible: bool = True
    risk_score: float = 0.0
    description: str = ""


# Operations that produce content which persists beyond a session.
_PERSISTENT_OPS: set[str] = {
    PatchEngine.CREATE_NEW,
    PatchEngine.JSON_MERGE,
    PatchEngine.TOML_UPDATE,
    PatchEngine.YAML_UPDATE,
    PatchEngine.PREPEND_FRONTMATTER,
}


class BlastRadiusAnalyzer:
    """Cross-references a patch plan against known surfaces."""

    def analyze(self, plan: PatchPlan, ctx: RunContext) -> BlastRadius:
        """Analyze which tools and scopes a patch would affect."""
        affected_tools: list[str] = []
        affected_scopes: list[str] = []

        # Find the artifact being patched
        target_artifact = None
        for art in ctx.artifacts:
            if art.artifact_id == plan.artifact_id:
                target_artifact = art
                break

        if target_artifact is not None:
            affected_tools.append(target_artifact.tool_slug)
            affected_scopes.append(target_artifact.scope.value)

        # Check if other artifacts share the same path or tool
        for art in ctx.artifacts:
            if art.artifact_id == plan.artifact_id:
                continue
            # Same path means the same file is consumed by multiple tools
            if plan.target_path and art.path == plan.target_path:
                if art.tool_slug not in affected_tools:
                    affected_tools.append(art.tool_slug)
                if art.scope.value not in affected_scopes:
                    affected_scopes.append(art.scope.value)

        # Check surfaces linked to the target artifact
        for surface in ctx.surfaces:
            if surface.artifact_id == plan.artifact_id:
                if surface.cross_tool_reach:
                    # Mark any tools that could be affected via cross-tool reach
                    for art in ctx.artifacts:
                        if art.tool_slug not in affected_tools:
                            affected_tools.append(art.tool_slug)

        cross_tool = len(affected_tools) > 1

        # Persistence
        persistence_level = "session"
        if plan.patch_engine in _PERSISTENT_OPS:
            persistence_level = "persistent"
        if plan.operation == PatchEngine.APPEND_TEXT:
            persistence_level = "persistent"

        # Reversibility — create_new on a path that doesn't exist is less
        # reversible (no original to restore).
        reversible = True
        if plan.operation == PatchEngine.CREATE_NEW:
            if target_artifact and not target_artifact.exists:
                reversible = True  # can just delete the new file

        # Risk score heuristic (0.0 – 1.0)
        risk = 0.1
        if cross_tool:
            risk += 0.3
        if persistence_level == "persistent":
            risk += 0.2
        if len(affected_scopes) > 1:
            risk += 0.1
        # High-influence surfaces
        for surface in ctx.surfaces:
            if surface.artifact_id == plan.artifact_id:
                composite = surface.risk_dimensions.get("_composite", 0.0)
                risk += min(composite * 0.3, 0.3)
        risk = min(risk, 1.0)

        parts: list[str] = []
        parts.append(f"Affects {len(affected_tools)} tool(s)")
        if cross_tool:
            parts.append("cross-tool impact")
        parts.append(f"persistence={persistence_level}")
        description = "; ".join(parts)

        return BlastRadius(
            affected_tools=affected_tools,
            affected_scopes=affected_scopes,
            cross_tool=cross_tool,
            persistence_level=persistence_level,
            reversible=reversible,
            risk_score=round(risk, 2),
            description=description,
        )

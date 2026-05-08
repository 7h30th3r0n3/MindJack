"""Discovery plugin for cross-tool shared artifacts."""

from __future__ import annotations

from mindjack.core.constants import InfluenceType, ParserType, ScopeLevel, SurfaceType
from mindjack.core.models import DiscoveredArtifact, Indicator, ToolDescriptor, TrustSurface
from mindjack.core.scope import Scope

from .base import artifact_if_accessible, find_project_dirs

SLUG = "cross-tool"

DESCRIPTOR = ToolDescriptor(
    slug=SLUG,
    display_name="Cross-Tool Shared",
    category="shared",
    indicators=(),
    supported_surfaces=(SurfaceType.INSTRUCTIONS,),
    parser_hints={"instructions": "markdown"},
)


class CrossToolPlugin:
    slug = SLUG
    descriptor = DESCRIPTOR

    def detect(self, scope: Scope) -> list[DiscoveredArtifact]:
        artifacts: list[DiscoveredArtifact] = []
        for proj in find_project_dirs(scope):
            # AGENTS.md — read by Codex CLI, Cursor, Windsurf, Cline, Copilot
            a = artifact_if_accessible(
                tool_slug=SLUG, surface_type=SurfaceType.INSTRUCTIONS,
                scope_level=ScopeLevel.PROJECT, path=proj / "AGENTS.md",
                parser_type=ParserType.MARKDOWN, precedence_rank=10,
                description="AGENTS.md — read by 5+ tools simultaneously",
                tags=["codex-cli", "cursor", "windsurf", "cline", "copilot"],
            )
            if a and scope.contains(a.path):
                artifacts.append(a)
        return artifacts

    def classify(self, artifact: DiscoveredArtifact) -> list[TrustSurface]:
        return [TrustSurface(
            artifact_id=artifact.artifact_id,
            influence_type=InfluenceType.PROMPT_INJECTION,
            execution_capability="indirect",
            persistence="session",
            cross_tool_reach=True,
            risk_dimensions={"cross_tool_reach": 10.0},
        )]


def create_plugin() -> CrossToolPlugin:
    return CrossToolPlugin()

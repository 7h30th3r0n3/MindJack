"""Discovery plugin for Amazon Q Developer."""

from __future__ import annotations

from mindjack.core.constants import InfluenceType, ParserType, ScopeLevel, SurfaceType
from mindjack.core.models import DiscoveredArtifact, Indicator, ToolDescriptor, TrustSurface
from mindjack.core.scope import Scope

from .base import HOME, artifact_if_accessible, find_project_dirs

SLUG = "amazon-q"

DESCRIPTOR = ToolDescriptor(
    slug=SLUG,
    display_name="Amazon Q Developer",
    category="ai-assistant",
    indicators=(
        Indicator(kind="directory", value="~/.aws/amazonq"),
    ),
    supported_surfaces=(
        SurfaceType.MCP,
        SurfaceType.RULES,
    ),
    parser_hints={"mcp": "json", "rules": "markdown"},
)


class AmazonQPlugin:
    slug = SLUG
    descriptor = DESCRIPTOR

    def detect(self, scope: Scope) -> list[DiscoveredArtifact]:
        artifacts: list[DiscoveredArtifact] = []

        _add(artifacts, scope,
             path=HOME / ".aws" / "amazonq" / "mcp.json",
             surface=SurfaceType.MCP, scope_level=ScopeLevel.USER,
             parser=ParserType.JSON, precedence=5,
             desc="Global MCP server definitions for Amazon Q")

        for proj in find_project_dirs(scope):
            rules_dir = proj / ".amazonq" / "rules"
            if rules_dir.exists():
                for f in rules_dir.rglob("*.md"):
                    a = artifact_if_accessible(
                        tool_slug=SLUG, surface_type=SurfaceType.RULES,
                        scope_level=ScopeLevel.PROJECT, path=f,
                        parser_type=ParserType.MARKDOWN, precedence_rank=20,
                        description=f"Q rule: {f.name} ({proj.name})",
                    )
                    if a:
                        artifacts.append(a)

        return artifacts

    def classify(self, artifact: DiscoveredArtifact) -> list[TrustSurface]:
        surfaces = []
        if artifact.surface_type == SurfaceType.MCP:
            surfaces.append(TrustSurface(
                artifact_id=artifact.artifact_id,
                influence_type=InfluenceType.TOOL_CONTROL,
                execution_capability="arbitrary_process",
                persistence="persistent",
                cross_tool_reach=True,
            ))
        elif artifact.surface_type == SurfaceType.RULES:
            surfaces.append(TrustSurface(
                artifact_id=artifact.artifact_id,
                influence_type=InfluenceType.PROMPT_INJECTION,
                execution_capability="indirect",
                persistence="session",
                cross_tool_reach=False,
            ))
        return surfaces


def _add(artifacts, scope, *, path, surface, scope_level, parser, precedence, desc):
    if not scope.contains(path):
        return
    a = artifact_if_accessible(
        tool_slug=SLUG, surface_type=surface, scope_level=scope_level,
        path=path, parser_type=parser, precedence_rank=precedence, description=desc,
    )
    if a:
        artifacts.append(a)


def create_plugin() -> AmazonQPlugin:
    return AmazonQPlugin()

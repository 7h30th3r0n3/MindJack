"""Discovery plugin for Cursor IDE."""

from __future__ import annotations

from mindjack.core.constants import InfluenceType, ParserType, ScopeLevel, SurfaceType
from mindjack.core.models import DiscoveredArtifact, Indicator, ToolDescriptor, TrustSurface
from mindjack.core.scope import Scope

from .base import HOME, artifact_if_accessible, find_project_dirs

SLUG = "cursor"

DESCRIPTOR = ToolDescriptor(
    slug=SLUG,
    display_name="Cursor IDE",
    category="ai-assistant",
    indicators=(
        Indicator(kind="directory", value="~/.cursor"),
        Indicator(kind="file", value=".cursorrules"),
    ),
    supported_surfaces=(
        SurfaceType.INSTRUCTIONS,
        SurfaceType.RULES,
        SurfaceType.MCP,
    ),
    parser_hints={"instructions": "markdown", "mcp": "json"},
)


class CursorPlugin:
    slug = SLUG
    descriptor = DESCRIPTOR

    def detect(self, scope: Scope) -> list[DiscoveredArtifact]:
        artifacts: list[DiscoveredArtifact] = []

        # MCP config
        _add(artifacts, scope, path=HOME / ".cursor" / "mcp.json",
             surface=SurfaceType.MCP, scope_level=ScopeLevel.USER,
             parser=ParserType.JSON, precedence=5,
             desc="Cursor MCP config — CVE-2025-54135 RCE vector")

        for proj in find_project_dirs(scope):
            _add(artifacts, scope, path=proj / ".cursorrules",
                 surface=SurfaceType.INSTRUCTIONS, scope_level=ScopeLevel.PROJECT,
                 parser=ParserType.MARKDOWN, precedence=20,
                 desc=f".cursorrules for {proj.name}")

            _add(artifacts, scope, path=proj / ".cursor" / "mcp.json",
                 surface=SurfaceType.MCP, scope_level=ScopeLevel.PROJECT,
                 parser=ParserType.JSON, precedence=15,
                 desc=f"Project MCP config for {proj.name}")

            rules_dir = proj / ".cursor" / "rules"
            if rules_dir.exists():
                for f in rules_dir.rglob("*.md"):
                    a = artifact_if_accessible(
                        tool_slug=SLUG, surface_type=SurfaceType.RULES,
                        scope_level=ScopeLevel.PROJECT, path=f,
                        parser_type=ParserType.MARKDOWN, precedence_rank=25,
                        description=f"Scoped rule: {f.name}",
                    )
                    if a:
                        artifacts.append(a)

        return artifacts

    def classify(self, artifact: DiscoveredArtifact) -> list[TrustSurface]:
        surfaces = []
        if artifact.surface_type in (SurfaceType.INSTRUCTIONS, SurfaceType.RULES):
            surfaces.append(TrustSurface(
                artifact_id=artifact.artifact_id,
                influence_type=InfluenceType.PROMPT_INJECTION,
                execution_capability="indirect",
                persistence="session",
                cross_tool_reach=False,
            ))
        elif artifact.surface_type == SurfaceType.MCP:
            surfaces.append(TrustSurface(
                artifact_id=artifact.artifact_id,
                influence_type=InfluenceType.TOOL_CONTROL,
                execution_capability="arbitrary_process",
                persistence="persistent",
                cross_tool_reach=True,
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


def create_plugin() -> CursorPlugin:
    return CursorPlugin()

"""Discovery plugin for Continue.dev."""

from __future__ import annotations

from mindjack.core.constants import InfluenceType, ParserType, ScopeLevel, SurfaceType
from mindjack.core.models import DiscoveredArtifact, Indicator, ToolDescriptor, TrustSurface
from mindjack.core.scope import Scope

from .base import HOME, artifact_if_accessible, find_project_dirs

SLUG = "continue-dev"

DESCRIPTOR = ToolDescriptor(
    slug=SLUG,
    display_name="Continue.dev",
    category="ai-assistant",
    indicators=(
        Indicator(kind="directory", value="~/.continue"),
        Indicator(kind="file", value="~/.continue/config.yaml"),
    ),
    supported_surfaces=(
        SurfaceType.SETTINGS,
        SurfaceType.RULES,
        SurfaceType.INSTRUCTIONS,
    ),
    parser_hints={"settings": "yaml", "rules": "markdown"},
)


class ContinueDevPlugin:
    slug = SLUG
    descriptor = DESCRIPTOR

    def detect(self, scope: Scope) -> list[DiscoveredArtifact]:
        artifacts: list[DiscoveredArtifact] = []
        base = HOME / ".continue"

        _add(artifacts, scope, path=base / "config.yaml",
             surface=SurfaceType.SETTINGS, scope_level=ScopeLevel.USER,
             parser=ParserType.YAML, precedence=10,
             desc="Controls models, MCP servers, tools, context providers")

        rules_dir = base / "rules"
        if rules_dir.exists():
            for f in rules_dir.rglob("*.md"):
                a = artifact_if_accessible(
                    tool_slug=SLUG, surface_type=SurfaceType.RULES,
                    scope_level=ScopeLevel.USER, path=f,
                    parser_type=ParserType.MARKDOWN, precedence_rank=15,
                    description=f"Global rule: {f.name}",
                )
                if a:
                    artifacts.append(a)

        for proj in find_project_dirs(scope):
            _add(artifacts, scope, path=proj / ".continuerc.json",
                 surface=SurfaceType.SETTINGS, scope_level=ScopeLevel.PROJECT,
                 parser=ParserType.JSON, precedence=20,
                 desc=f"Project config override for {proj.name}")

        return artifacts

    def classify(self, artifact: DiscoveredArtifact) -> list[TrustSurface]:
        surfaces = []
        if artifact.surface_type == SurfaceType.SETTINGS:
            surfaces.append(TrustSurface(
                artifact_id=artifact.artifact_id,
                influence_type=InfluenceType.CONFIG_OVERRIDE,
                execution_capability="mcp_and_tools",
                persistence="persistent",
                cross_tool_reach=False,
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


def create_plugin() -> ContinueDevPlugin:
    return ContinueDevPlugin()

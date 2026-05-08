"""Discovery plugin for Windsurf / Codeium."""

from __future__ import annotations

from mindjack.core.constants import InfluenceType, ParserType, ScopeLevel, SurfaceType
from mindjack.core.models import DiscoveredArtifact, Indicator, ToolDescriptor, TrustSurface
from mindjack.core.scope import Scope

from .base import HOME, artifact_if_accessible, find_project_dirs

SLUG = "windsurf"

DESCRIPTOR = ToolDescriptor(
    slug=SLUG,
    display_name="Windsurf",
    category="ai-assistant",
    indicators=(
        Indicator(kind="directory", value="~/.codeium/windsurf"),
    ),
    supported_surfaces=(
        SurfaceType.INSTRUCTIONS,
        SurfaceType.MEMORY,
    ),
    parser_hints={"instructions": "markdown", "memory": "markdown"},
)


class WindsurfPlugin:
    slug = SLUG
    descriptor = DESCRIPTOR

    def detect(self, scope: Scope) -> list[DiscoveredArtifact]:
        artifacts: list[DiscoveredArtifact] = []
        base = HOME / ".codeium" / "windsurf"

        if base.exists():
            _add(artifacts, scope,
                 path=base / "memories" / "global_rules.md",
                 surface=SurfaceType.INSTRUCTIONS, scope_level=ScopeLevel.USER,
                 parser=ParserType.MARKDOWN, precedence=5,
                 desc="Always-on global instructions for all workspaces")

            memories_dir = base / "memories"
            if memories_dir.exists():
                for f in memories_dir.rglob("*.md"):
                    if f.name == "global_rules.md":
                        continue
                    a = artifact_if_accessible(
                        tool_slug=SLUG, surface_type=SurfaceType.MEMORY,
                        scope_level=ScopeLevel.USER, path=f,
                        parser_type=ParserType.MARKDOWN, precedence_rank=30,
                        description=f"Windsurf memory: {f.name}",
                    )
                    if a:
                        artifacts.append(a)

        for proj in find_project_dirs(scope):
            _add(artifacts, scope, path=proj / ".windsurfrules",
                 surface=SurfaceType.INSTRUCTIONS, scope_level=ScopeLevel.PROJECT,
                 parser=ParserType.MARKDOWN, precedence=20,
                 desc=f".windsurfrules for {proj.name}")

        return artifacts

    def classify(self, artifact: DiscoveredArtifact) -> list[TrustSurface]:
        surfaces = []
        if artifact.surface_type == SurfaceType.INSTRUCTIONS:
            surfaces.append(TrustSurface(
                artifact_id=artifact.artifact_id,
                influence_type=InfluenceType.PROMPT_INJECTION,
                execution_capability="indirect",
                persistence="session",
                cross_tool_reach=False,
            ))
        elif artifact.surface_type == SurfaceType.MEMORY:
            surfaces.append(TrustSurface(
                artifact_id=artifact.artifact_id,
                influence_type=InfluenceType.CONTEXT_POISONING,
                execution_capability="indirect",
                persistence="cross_session",
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


def create_plugin() -> WindsurfPlugin:
    return WindsurfPlugin()

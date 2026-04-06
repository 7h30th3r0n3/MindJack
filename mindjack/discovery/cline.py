"""Discovery plugin for Cline."""

from __future__ import annotations

from mindjack.core.constants import InfluenceType, ParserType, ScopeLevel, SurfaceType
from mindjack.core.models import DiscoveredArtifact, Indicator, ToolDescriptor, TrustSurface
from mindjack.core.scope import Scope

from .base import artifact_if_accessible, find_project_dirs

SLUG = "cline"

DESCRIPTOR = ToolDescriptor(
    slug=SLUG,
    display_name="Cline",
    category="ai-assistant",
    indicators=(
        Indicator(kind="file", value=".clinerules"),
    ),
    supported_surfaces=(
        SurfaceType.INSTRUCTIONS,
        SurfaceType.MEMORY,
    ),
    parser_hints={"instructions": "markdown", "memory": "markdown"},
)


class ClinePlugin:
    slug = SLUG
    descriptor = DESCRIPTOR

    def detect(self, scope: Scope) -> list[DiscoveredArtifact]:
        artifacts: list[DiscoveredArtifact] = []
        for proj in find_project_dirs(scope):
            _add(artifacts, scope, path=proj / ".clinerules",
                 surface=SurfaceType.INSTRUCTIONS, scope_level=ScopeLevel.PROJECT,
                 parser=ParserType.MARKDOWN, precedence=20,
                 desc=f".clinerules for {proj.name}")

            mem_bank = proj / "memory-bank"
            if mem_bank.exists():
                for f in mem_bank.rglob("*.md"):
                    a = artifact_if_accessible(
                        tool_slug=SLUG, surface_type=SurfaceType.MEMORY,
                        scope_level=ScopeLevel.PROJECT, path=f,
                        parser_type=ParserType.MARKDOWN, precedence_rank=30,
                        description=f"Memory bank: {f.name}",
                    )
                    if a:
                        artifacts.append(a)
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


def create_plugin() -> ClinePlugin:
    return ClinePlugin()

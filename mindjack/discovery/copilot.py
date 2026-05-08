"""Discovery plugin for GitHub Copilot."""

from __future__ import annotations

from mindjack.core.constants import InfluenceType, ParserType, ScopeLevel, SurfaceType
from mindjack.core.models import DiscoveredArtifact, Indicator, ToolDescriptor, TrustSurface
from mindjack.core.scope import Scope

from .base import artifact_if_accessible, find_project_dirs

SLUG = "copilot"

DESCRIPTOR = ToolDescriptor(
    slug=SLUG,
    display_name="GitHub Copilot",
    category="ai-assistant",
    indicators=(
        Indicator(kind="file", value=".github/copilot-instructions.md"),
    ),
    supported_surfaces=(SurfaceType.INSTRUCTIONS,),
    parser_hints={"instructions": "markdown"},
)


class CopilotPlugin:
    slug = SLUG
    descriptor = DESCRIPTOR

    def detect(self, scope: Scope) -> list[DiscoveredArtifact]:
        artifacts: list[DiscoveredArtifact] = []
        for proj in find_project_dirs(scope):
            _add(artifacts, scope,
                 path=proj / ".github" / "copilot-instructions.md",
                 surface=SurfaceType.INSTRUCTIONS, scope_level=ScopeLevel.PROJECT,
                 parser=ParserType.MARKDOWN, precedence=20,
                 desc=f"Copilot instructions for {proj.name}")

            instructions_dir = proj / ".github" / "instructions"
            if instructions_dir.exists():
                for f in instructions_dir.glob("*.instructions.md"):
                    a = artifact_if_accessible(
                        tool_slug=SLUG, surface_type=SurfaceType.INSTRUCTIONS,
                        scope_level=ScopeLevel.PROJECT, path=f,
                        parser_type=ParserType.MARKDOWN, precedence_rank=25,
                        description=f"Scoped instruction: {f.name}",
                    )
                    if a:
                        artifacts.append(a)
        return artifacts

    def classify(self, artifact: DiscoveredArtifact) -> list[TrustSurface]:
        return [TrustSurface(
            artifact_id=artifact.artifact_id,
            influence_type=InfluenceType.PROMPT_INJECTION,
            execution_capability="indirect",
            persistence="session",
            cross_tool_reach=False,
        )]


def _add(artifacts, scope, *, path, surface, scope_level, parser, precedence, desc):
    if not scope.contains(path):
        return
    a = artifact_if_accessible(
        tool_slug=SLUG, surface_type=surface, scope_level=scope_level,
        path=path, parser_type=parser, precedence_rank=precedence, description=desc,
    )
    if a:
        artifacts.append(a)


def create_plugin() -> CopilotPlugin:
    return CopilotPlugin()

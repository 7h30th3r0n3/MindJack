"""Discovery plugin for Roo Code."""

from __future__ import annotations

from mindjack.core.constants import InfluenceType, ParserType, ScopeLevel, SurfaceType
from mindjack.core.models import DiscoveredArtifact, Indicator, ToolDescriptor, TrustSurface
from mindjack.core.scope import Scope

from .base import HOME, artifact_if_accessible, find_project_dirs

SLUG = "roo-code"

DESCRIPTOR = ToolDescriptor(
    slug=SLUG,
    display_name="Roo Code",
    category="ai-assistant",
    indicators=(
        Indicator(kind="directory", value="~/.roo"),
        Indicator(kind="file", value=".roo/rules"),
    ),
    supported_surfaces=(SurfaceType.RULES,),
    parser_hints={"rules": "markdown"},
)


class RooCodePlugin:
    slug = SLUG
    descriptor = DESCRIPTOR

    def detect(self, scope: Scope) -> list[DiscoveredArtifact]:
        artifacts: list[DiscoveredArtifact] = []

        # Global rules
        global_rules = HOME / ".roo" / "rules"
        if global_rules.exists():
            for f in global_rules.rglob("*.md"):
                a = artifact_if_accessible(
                    tool_slug=SLUG, surface_type=SurfaceType.RULES,
                    scope_level=ScopeLevel.USER, path=f,
                    parser_type=ParserType.MARKDOWN, precedence_rank=10,
                    description=f"Global Roo rule: {f.name}",
                )
                if a:
                    artifacts.append(a)

        for proj in find_project_dirs(scope):
            roo_rules = proj / ".roo" / "rules"
            if roo_rules.exists():
                for f in roo_rules.rglob("*.md"):
                    a = artifact_if_accessible(
                        tool_slug=SLUG, surface_type=SurfaceType.RULES,
                        scope_level=ScopeLevel.PROJECT, path=f,
                        parser_type=ParserType.MARKDOWN, precedence_rank=20,
                        description=f"Project rule: {f.name} ({proj.name})",
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


def create_plugin() -> RooCodePlugin:
    return RooCodePlugin()

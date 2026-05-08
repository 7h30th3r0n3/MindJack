"""Discovery plugin for OpenAI Codex CLI."""

from __future__ import annotations

import os
from pathlib import Path

from mindjack.core.constants import InfluenceType, ParserType, ScopeLevel, SurfaceType
from mindjack.core.models import DiscoveredArtifact, Indicator, ToolDescriptor, TrustSurface
from mindjack.core.scope import Scope

from .base import HOME, artifact_if_accessible, find_project_dirs

SLUG = "codex-cli"

DESCRIPTOR = ToolDescriptor(
    slug=SLUG,
    display_name="Codex CLI",
    category="ai-assistant",
    indicators=(
        Indicator(kind="directory", value="~/.codex"),
        Indicator(kind="file", value="~/.codex/config.toml"),
    ),
    supported_surfaces=(
        SurfaceType.INSTRUCTIONS,
        SurfaceType.SETTINGS,
    ),
    parser_hints={"settings": "toml", "instructions": "markdown"},
)


class CodexCliPlugin:
    slug = SLUG
    descriptor = DESCRIPTOR

    def detect(self, scope: Scope) -> list[DiscoveredArtifact]:
        artifacts: list[DiscoveredArtifact] = []
        base = Path(os.environ.get("CODEX_HOME", str(HOME / ".codex")))

        _add(artifacts, scope, path=base / "AGENTS.md",
             surface=SurfaceType.INSTRUCTIONS, scope_level=ScopeLevel.USER,
             parser=ParserType.MARKDOWN, precedence=10,
             desc="Global AGENTS.md for all Codex sessions")

        _add(artifacts, scope, path=base / "AGENTS.override.md",
             surface=SurfaceType.INSTRUCTIONS, scope_level=ScopeLevel.USER,
             parser=ParserType.MARKDOWN, precedence=5,
             desc="Highest-priority override for AGENTS.md")

        _add(artifacts, scope, path=base / "config.toml",
             surface=SurfaceType.SETTINGS, scope_level=ScopeLevel.USER,
             parser=ParserType.TOML, precedence=10,
             desc="Controls sandbox_mode, approval_policy, model, MCP servers")

        for proj in find_project_dirs(scope):
            _add(artifacts, scope, path=proj / "AGENTS.md",
                 surface=SurfaceType.INSTRUCTIONS, scope_level=ScopeLevel.PROJECT,
                 parser=ParserType.MARKDOWN, precedence=20,
                 desc=f"Project AGENTS.md for {proj.name}")
            _add(artifacts, scope, path=proj / "AGENTS.override.md",
                 surface=SurfaceType.INSTRUCTIONS, scope_level=ScopeLevel.PROJECT,
                 parser=ParserType.MARKDOWN, precedence=15,
                 desc=f"Project override for {proj.name}")

        return artifacts

    def classify(self, artifact: DiscoveredArtifact) -> list[TrustSurface]:
        surfaces = []
        if artifact.surface_type == SurfaceType.INSTRUCTIONS:
            surfaces.append(TrustSurface(
                artifact_id=artifact.artifact_id,
                influence_type=InfluenceType.PROMPT_INJECTION,
                execution_capability="indirect",
                persistence="session",
                cross_tool_reach=True,  # AGENTS.md read by multiple tools
            ))
        elif artifact.surface_type == SurfaceType.SETTINGS:
            surfaces.append(TrustSurface(
                artifact_id=artifact.artifact_id,
                influence_type=InfluenceType.CONFIG_OVERRIDE,
                execution_capability="sandbox_control",
                persistence="persistent",
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


def create_plugin() -> CodexCliPlugin:
    return CodexCliPlugin()

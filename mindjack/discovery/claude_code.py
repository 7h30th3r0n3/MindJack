"""Discovery plugin for Claude Code."""

from __future__ import annotations

from mindjack.core.constants import (
    InfluenceType,
    ParserType,
    ScopeLevel,
    SurfaceType,
)
from mindjack.core.models import DiscoveredArtifact, Indicator, ToolDescriptor, TrustSurface
from mindjack.core.scope import Scope

from .base import HOME, artifact_if_accessible, find_project_dirs, safe_iterdir

SLUG = "claude-code"

DESCRIPTOR = ToolDescriptor(
    slug=SLUG,
    display_name="Claude Code",
    category="ai-assistant",
    indicators=(
        Indicator(kind="directory", value="~/.claude"),
        Indicator(kind="file", value="~/.claude/settings.json"),
    ),
    supported_surfaces=(
        SurfaceType.INSTRUCTIONS,
        SurfaceType.SETTINGS,
        SurfaceType.MCP,
        SurfaceType.HOOKS,
        SurfaceType.MEMORY,
        SurfaceType.RULES,
    ),
    parser_hints={
        "settings": "json",
        "instructions": "markdown",
        "memory": "markdown",
    },
    precedence_model="claude-code-v1",
)


class ClaudeCodePlugin:
    slug = SLUG
    descriptor = DESCRIPTOR

    def detect(self, scope: Scope) -> list[DiscoveredArtifact]:
        artifacts: list[DiscoveredArtifact] = []
        base = HOME / ".claude"

        # Global CLAUDE.md (in $HOME)
        _add(artifacts, scope,
             path=HOME / "CLAUDE.md",
             surface=SurfaceType.INSTRUCTIONS,
             scope_level=ScopeLevel.USER,
             parser=ParserType.MARKDOWN,
             precedence=10,
             desc="Instructions loaded for ALL projects in home directory")

        # User CLAUDE.md (in ~/.claude/)
        _add(artifacts, scope,
             path=base / "CLAUDE.md",
             surface=SurfaceType.INSTRUCTIONS,
             scope_level=ScopeLevel.USER,
             parser=ParserType.MARKDOWN,
             precedence=20,
             desc="Personal default instructions for all sessions")

        # Project-level CLAUDE.md
        for proj in find_project_dirs(scope):
            _add(artifacts, scope,
                 path=proj / "CLAUDE.md",
                 surface=SurfaceType.INSTRUCTIONS,
                 scope_level=ScopeLevel.PROJECT,
                 parser=ParserType.MARKDOWN,
                 precedence=30,
                 desc=f"Project instructions for {proj.name}")
            _add(artifacts, scope,
                 path=proj / ".claude" / "CLAUDE.md",
                 surface=SurfaceType.INSTRUCTIONS,
                 scope_level=ScopeLevel.PROJECT,
                 parser=ParserType.MARKDOWN,
                 precedence=30,
                 desc=f"Project instructions (nested) for {proj.name}")

        # Rules directory
        rules_dir = base / "rules"
        if rules_dir.exists():
            for f in rules_dir.rglob("*.md"):
                _add(artifacts, scope,
                     path=f,
                     surface=SurfaceType.RULES,
                     scope_level=ScopeLevel.USER,
                     parser=ParserType.MARKDOWN,
                     precedence=25,
                     desc=f"Auto-loaded rule: {f.name}")

        # Settings files
        for settings_path, desc in [
            (base / "settings.json", "Global settings (allowedTools, MCP, permissions)"),
            (base / "settings.local.json", "Local settings override"),
        ]:
            _add(artifacts, scope,
                 path=settings_path,
                 surface=SurfaceType.SETTINGS,
                 scope_level=ScopeLevel.USER,
                 parser=ParserType.JSON,
                 precedence=5,
                 desc=desc)

        # Project-level settings
        for proj in find_project_dirs(scope):
            _add(artifacts, scope,
                 path=proj / ".claude" / "settings.json",
                 surface=SurfaceType.SETTINGS,
                 scope_level=ScopeLevel.PROJECT,
                 parser=ParserType.JSON,
                 precedence=15,
                 desc=f"Project settings for {proj.name}")
            _add(artifacts, scope,
                 path=proj / ".claude" / "settings.local.json",
                 surface=SurfaceType.SETTINGS,
                 scope_level=ScopeLevel.PROJECT,
                 parser=ParserType.JSON,
                 precedence=16,
                 desc=f"Project local settings for {proj.name}")

        # MCP config
        _add(artifacts, scope,
             path=HOME / ".mcp.json",
             surface=SurfaceType.MCP,
             scope_level=ScopeLevel.USER,
             parser=ParserType.JSON,
             precedence=5,
             desc="Global MCP server definitions — can spawn arbitrary processes")

        for proj in find_project_dirs(scope):
            _add(artifacts, scope,
                 path=proj / ".mcp.json",
                 surface=SurfaceType.MCP,
                 scope_level=ScopeLevel.PROJECT,
                 parser=ParserType.JSON,
                 precedence=15,
                 desc=f"Project MCP config for {proj.name}")

        # Memory files
        for mem_dir in base.rglob("memory"):
            if not mem_dir.is_dir():
                continue
            for mem_file in mem_dir.glob("*.md"):
                if mem_file.name == "MEMORY.md":
                    continue
                _add(artifacts, scope,
                     path=mem_file,
                     surface=SurfaceType.MEMORY,
                     scope_level=ScopeLevel.USER,
                     parser=ParserType.MARKDOWN,
                     precedence=40,
                     desc=f"Persistent memory: {mem_file.stem}")

        return artifacts

    def classify(self, artifact: DiscoveredArtifact) -> list[TrustSurface]:
        surfaces: list[TrustSurface] = []
        st = artifact.surface_type

        if st == SurfaceType.INSTRUCTIONS or st == SurfaceType.RULES:
            surfaces.append(TrustSurface(
                artifact_id=artifact.artifact_id,
                influence_type=InfluenceType.PROMPT_INJECTION,
                execution_capability="indirect",
                persistence="session",
                cross_tool_reach=False,
            ))
        elif st == SurfaceType.SETTINGS:
            surfaces.append(TrustSurface(
                artifact_id=artifact.artifact_id,
                influence_type=InfluenceType.PERMISSION_ESCALATION,
                execution_capability="direct",
                persistence="persistent",
                cross_tool_reach=False,
            ))
            # Settings also contain hooks
            surfaces.append(TrustSurface(
                artifact_id=artifact.artifact_id,
                influence_type=InfluenceType.EXECUTION_HOOK,
                execution_capability="direct_shell",
                persistence="persistent",
                cross_tool_reach=False,
            ))
        elif st == SurfaceType.MCP:
            surfaces.append(TrustSurface(
                artifact_id=artifact.artifact_id,
                influence_type=InfluenceType.TOOL_CONTROL,
                execution_capability="arbitrary_process",
                persistence="persistent",
                cross_tool_reach=True,
            ))
        elif st == SurfaceType.MEMORY:
            surfaces.append(TrustSurface(
                artifact_id=artifact.artifact_id,
                influence_type=InfluenceType.CONTEXT_POISONING,
                execution_capability="indirect",
                persistence="cross_session",
                cross_tool_reach=False,
            ))

        return surfaces


def _add(
    artifacts: list[DiscoveredArtifact],
    scope: Scope,
    *,
    path,
    surface,
    scope_level,
    parser,
    precedence,
    desc,
):
    if not scope.contains(path):
        return
    a = artifact_if_accessible(
        tool_slug=SLUG,
        surface_type=surface,
        scope_level=scope_level,
        path=path,
        parser_type=parser,
        precedence_rank=precedence,
        description=desc,
    )
    if a:
        artifacts.append(a)


def create_plugin() -> ClaudeCodePlugin:
    return ClaudeCodePlugin()

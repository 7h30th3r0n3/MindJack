"""Enumerations and constants for MindJack v2."""

from __future__ import annotations

from enum import Enum


class SurfaceType(str, Enum):
    """Types of trust surfaces an artifact can expose."""

    INSTRUCTIONS = "instructions"
    SETTINGS = "settings"
    MCP = "mcp"
    HOOKS = "hooks"
    MEMORY = "memory"
    RULES = "rules"
    CONFIG = "config"
    STATE = "state"


class ArtifactState(str, Enum):
    """Lifecycle state of a discovered artifact."""

    ACTIVE = "active"
    LIKELY_ACTIVE = "likely_active"
    STALE = "stale"
    ARTIFACT_ONLY = "artifact_only"
    UNSUPPORTED = "unsupported"


class ScopeLevel(str, Enum):
    """Where an artifact's influence reaches."""

    USER = "user"
    PROJECT = "project"
    WORKSPACE = "workspace"
    TEAM = "team"
    ENTERPRISE = "enterprise"
    GLOBAL_SYSTEM = "global_system"


class InfluenceType(str, Enum):
    """How a trust surface influences assistant behavior."""

    PROMPT_INJECTION = "prompt_injection"
    CONFIG_OVERRIDE = "config_override"
    TOOL_CONTROL = "tool_control"
    EXECUTION_HOOK = "execution_hook"
    CONTEXT_POISONING = "context_poisoning"
    PERMISSION_ESCALATION = "permission_escalation"


class ParserType(str, Enum):
    """Supported parser backends."""

    JSON = "json"
    TOML = "toml"
    YAML = "yaml"
    MARKDOWN = "markdown"
    SQLITE = "sqlite"
    RAW_TEXT = "raw_text"


class PrecedenceRelation(str, Enum):
    """How two artifacts relate in terms of priority."""

    DOMINATES = "dominates"
    SHADOWED_BY = "shadowed_by"
    OVERRIDES = "overrides"
    INHERITS_FROM = "inherits_from"
    PARALLEL_SCOPE = "parallel_scope"


class Mode(str, Enum):
    """Operating mode for the framework."""

    ASSESSMENT = "assessment"
    SIMULATION = "simulation"
    LAB_APPLY = "lab-apply"
    RESTORE = "restore"


class PatchEngine(str, Enum):
    """Supported patch engine types."""

    APPEND_TEXT = "append_text"
    INSERT_SECTION = "insert_section"
    JSON_MERGE = "json_merge"
    TOML_UPDATE = "toml_update"
    YAML_UPDATE = "yaml_update"
    CREATE_NEW = "create_new"
    REPLACE_SCALAR = "replace_scalar"
    PREPEND_FRONTMATTER = "prepend_frontmatter"


# Tool category slugs
TOOL_CATEGORIES = (
    "claude-code",
    "codex-cli",
    "cursor",
    "copilot",
    "aider",
    "continue-dev",
    "cline",
    "roo-code",
    "amazon-q",
    "windsurf",
    "cross-tool",
)

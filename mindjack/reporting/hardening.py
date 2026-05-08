"""Defender-oriented hardening report generation."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from mindjack.core.constants import ScopeLevel, SurfaceType
from mindjack.core.models import DiscoveredArtifact, RunContext, TrustSurface


# ---------------------------------------------------------------------------
# HardeningItem — a single actionable recommendation
# ---------------------------------------------------------------------------

@dataclass
class HardeningItem:
    """A single hardening recommendation."""

    tool: str
    category: str  # e.g. "file_permissions", "config_review", "monitoring"
    priority: str  # "critical", "high", "medium", "low"
    recommendation: str
    effort: str  # "minimal", "moderate", "significant"
    impact: str  # "high", "medium", "low"


# ---------------------------------------------------------------------------
# Built-in recommendation database
# ---------------------------------------------------------------------------

# Keyed by (tool_slug_pattern, surface_type) → partial HardeningItem fields.
# tool_slug_pattern of "*" matches any tool.
_RECOMMENDATION_DB: list[tuple[str, SurfaceType, dict[str, str]]] = [
    # -- Instructions surfaces --
    ("*", SurfaceType.INSTRUCTIONS, {
        "category": "config_review",
        "priority": "high",
        "recommendation": "Audit instruction files for injected directives. Pin file contents with checksums and review diffs on every commit.",
        "effort": "minimal",
        "impact": "high",
    }),
    # -- MCP surfaces --
    ("*", SurfaceType.MCP, {
        "category": "access_control",
        "priority": "critical",
        "recommendation": "Review MCP server configurations. Restrict allowed tools/servers to a known allowlist. Disable dynamic MCP discovery if not needed.",
        "effort": "moderate",
        "impact": "high",
    }),
    # -- Hooks surfaces --
    ("*", SurfaceType.HOOKS, {
        "category": "execution_control",
        "priority": "critical",
        "recommendation": "Audit all hook scripts for command injection. Restrict hook execution to signed scripts or disable hooks in shared environments.",
        "effort": "moderate",
        "impact": "high",
    }),
    # -- Settings surfaces --
    ("*", SurfaceType.SETTINGS, {
        "category": "config_review",
        "priority": "high",
        "recommendation": "Review settings files for dangerous permission grants (e.g. allowedTools, exec permissions). Use the most restrictive settings possible.",
        "effort": "minimal",
        "impact": "high",
    }),
    # -- Memory surfaces --
    ("*", SurfaceType.MEMORY, {
        "category": "data_hygiene",
        "priority": "medium",
        "recommendation": "Periodically review and prune memory/context files. Watch for injected memories that alter assistant behavior.",
        "effort": "minimal",
        "impact": "medium",
    }),
    # -- Rules surfaces --
    ("*", SurfaceType.RULES, {
        "category": "config_review",
        "priority": "high",
        "recommendation": "Treat rule files as security-critical. Add them to version control and require review for all changes.",
        "effort": "minimal",
        "impact": "high",
    }),
    # -- Config surfaces --
    ("*", SurfaceType.CONFIG, {
        "category": "config_review",
        "priority": "medium",
        "recommendation": "Review configuration files for overly permissive settings. Ensure sensitive values are not stored in plaintext.",
        "effort": "minimal",
        "impact": "medium",
    }),
    # -- State surfaces --
    ("*", SurfaceType.STATE, {
        "category": "monitoring",
        "priority": "low",
        "recommendation": "Monitor state/database files for unexpected growth or modification. Consider integrity checks on state files.",
        "effort": "moderate",
        "impact": "low",
    }),
    # -- Tool-specific: claude-code --
    ("claude-code", SurfaceType.SETTINGS, {
        "category": "access_control",
        "priority": "critical",
        "recommendation": "Review .claude/settings.json for allowedTools entries. Restrict to minimum required tools. Disable Bash and computer-use if not needed.",
        "effort": "minimal",
        "impact": "high",
    }),
    ("claude-code", SurfaceType.INSTRUCTIONS, {
        "category": "supply_chain",
        "priority": "high",
        "recommendation": "Pin CLAUDE.md / AGENTS.md contents. Check for override files (AGENTS.override.md) that may shadow project instructions.",
        "effort": "minimal",
        "impact": "high",
    }),
    # -- Tool-specific: cursor --
    ("cursor", SurfaceType.RULES, {
        "category": "config_review",
        "priority": "high",
        "recommendation": "Audit .cursor/rules/ and .cursorrules for injected instructions. These files directly control Cursor agent behavior.",
        "effort": "minimal",
        "impact": "high",
    }),
    # -- Tool-specific: copilot --
    ("copilot", SurfaceType.INSTRUCTIONS, {
        "category": "config_review",
        "priority": "high",
        "recommendation": "Review .github/copilot-instructions.md. Ensure it does not contain prompt injection payloads from untrusted contributors.",
        "effort": "minimal",
        "impact": "high",
    }),
    # -- Cross-tool general --
    ("*", SurfaceType.INSTRUCTIONS, {
        "category": "file_permissions",
        "priority": "medium",
        "recommendation": "Restrict write permissions on instruction files to project maintainers only. Use CODEOWNERS or branch protection to gate changes.",
        "effort": "moderate",
        "impact": "medium",
    }),
]

# Scope-level recommendations (not tied to a specific surface)
_SCOPE_RECOMMENDATIONS: list[tuple[ScopeLevel, dict[str, str]]] = [
    (ScopeLevel.USER, {
        "category": "access_control",
        "priority": "high",
        "recommendation": "User-scope artifacts persist across all projects. Ensure user-level configs are not writable by project-level automation.",
        "effort": "minimal",
        "impact": "high",
    }),
    (ScopeLevel.PROJECT, {
        "category": "supply_chain",
        "priority": "medium",
        "recommendation": "Project-scope artifacts may be introduced via pull requests. Require review for all changes to AI assistant config files.",
        "effort": "moderate",
        "impact": "medium",
    }),
]


# ---------------------------------------------------------------------------
# HardeningReport
# ---------------------------------------------------------------------------

class HardeningReport:
    """Generate defender-oriented hardening recommendations."""

    def generate(self, ctx: RunContext) -> list[HardeningItem]:
        """Generate hardening items from the current RunContext."""
        items: list[HardeningItem] = []
        seen: set[tuple[str, str, str]] = set()  # dedup key: (tool, category, recommendation_prefix)

        artifact_by_id: dict[str, DiscoveredArtifact] = {
            a.artifact_id: a for a in ctx.artifacts
        }

        # Surface-based recommendations
        for surf in ctx.surfaces:
            art = artifact_by_id.get(surf.artifact_id)
            if art is None:
                continue
            for slug_pattern, stype, rec in _RECOMMENDATION_DB:
                if art.surface_type != stype:
                    continue
                if slug_pattern != "*" and slug_pattern != art.tool_slug:
                    continue
                dedup_key = (art.tool_slug, rec["category"], rec["recommendation"][:60])
                if dedup_key in seen:
                    continue
                seen.add(dedup_key)
                items.append(HardeningItem(
                    tool=art.tool_slug,
                    category=rec["category"],
                    priority=rec["priority"],
                    recommendation=rec["recommendation"],
                    effort=rec["effort"],
                    impact=rec["impact"],
                ))

        # Scope-level recommendations
        scopes_seen: set[ScopeLevel] = {a.scope for a in ctx.artifacts if a.exists}
        for scope_level, rec in _SCOPE_RECOMMENDATIONS:
            if scope_level not in scopes_seen:
                continue
            tools_in_scope = sorted({
                a.tool_slug for a in ctx.artifacts
                if a.scope == scope_level and a.exists
            })
            for tool in tools_in_scope:
                dedup_key = (tool, rec["category"], rec["recommendation"][:60])
                if dedup_key in seen:
                    continue
                seen.add(dedup_key)
                items.append(HardeningItem(
                    tool=tool,
                    category=rec["category"],
                    priority=rec["priority"],
                    recommendation=rec["recommendation"],
                    effort=rec["effort"],
                    impact=rec["impact"],
                ))

        # Cross-tool correlation recommendations
        correlations = getattr(ctx, "correlations", [])
        for corr in correlations:
            if corr.risk_multiplier >= 1.5:
                for tool in corr.tools:
                    dedup_key = (tool, "cross_tool", corr.description[:60])
                    if dedup_key in seen:
                        continue
                    seen.add(dedup_key)
                    items.append(HardeningItem(
                        tool=tool,
                        category="cross_tool",
                        priority="high",
                        recommendation=f"Cross-tool risk: {corr.description} Review shared paths and restrict write access.",
                        effort="moderate",
                        impact="high",
                    ))

        # Sort by priority
        priority_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        items.sort(key=lambda i: (priority_order.get(i.priority, 99), i.tool))
        return items

    def generate_markdown(
        self,
        items: list[HardeningItem],
        output_dir: Path,
    ) -> Path:
        """Write a hardening checklist as Markdown and return the file path."""
        output_dir.mkdir(parents=True, exist_ok=True)

        lines = [
            "# MindJack v2 — Hardening Checklist",
            "",
            f"**Generated:** {datetime.now(timezone.utc).isoformat()}",
            "",
            "---",
            "",
        ]

        if not items:
            lines.append("No hardening recommendations generated (no surfaces detected).")
            lines.append("")
        else:
            # Summary counts
            by_priority: dict[str, int] = {}
            for item in items:
                by_priority[item.priority] = by_priority.get(item.priority, 0) + 1

            lines.append("## Summary")
            lines.append("")
            lines.append("| Priority | Count |")
            lines.append("|----------|------:|")
            for prio in ("critical", "high", "medium", "low"):
                if prio in by_priority:
                    lines.append(f"| {prio.upper()} | {by_priority[prio]} |")
            lines.append("")

            # Group by tool
            by_tool: dict[str, list[HardeningItem]] = {}
            for item in items:
                by_tool.setdefault(item.tool, []).append(item)

            lines.append("---")
            lines.append("")

            for tool in sorted(by_tool):
                lines.append(f"## {tool}")
                lines.append("")
                for item in by_tool[tool]:
                    prio_badge = item.priority.upper()
                    lines.append(f"- [ ] **[{prio_badge}]** ({item.category}) {item.recommendation}")
                    lines.append(f"  - Effort: {item.effort} | Impact: {item.impact}")
                lines.append("")

        report_path = output_dir / "hardening.md"
        report_path.write_text("\n".join(lines))
        return report_path

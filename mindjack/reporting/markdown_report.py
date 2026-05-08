"""Markdown report generation."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

from mindjack.core.models import DiscoveredArtifact, RunContext, TrustSurface


def generate_markdown_report(ctx: RunContext, output_dir: Path) -> Path:
    """Generate human-readable Markdown assessment report."""
    output_dir.mkdir(parents=True, exist_ok=True)

    existing = [a for a in ctx.artifacts if a.exists]
    creatable = [a for a in ctx.artifacts if not a.exists]

    # Build surface lookup
    surf_by_artifact: dict[str, list[TrustSurface]] = {}
    for s in ctx.surfaces:
        surf_by_artifact.setdefault(s.artifact_id, []).append(s)

    lines = [
        "# MindJack v2 — Assessment Report",
        "",
        f"**Run ID:** `{ctx.run_id}`",
        f"**Mode:** {ctx.mode}",
        f"**Generated:** {datetime.now(timezone.utc).isoformat()}",
        f"**Scope:** {', '.join(str(p) for p in ctx.scope_paths) or '(all)'}",
        "",
        "---",
        "",
        "## Summary",
        "",
        f"| Metric | Count |",
        f"|--------|------:|",
        f"| Artifacts discovered | {len(ctx.artifacts)} |",
        f"| Existing (active) | {len(existing)} |",
        f"| Creatable (parent exists) | {len(creatable)} |",
        f"| Trust surfaces | {len(ctx.surfaces)} |",
        "",
    ]

    # By tool
    by_tool: dict[str, list[DiscoveredArtifact]] = {}
    for a in ctx.artifacts:
        by_tool.setdefault(a.tool_slug, []).append(a)

    lines.append("### By Tool")
    lines.append("")
    lines.append("| Tool | Artifacts | Existing | Surfaces |")
    lines.append("|------|----------:|---------:|---------:|")
    for tool in sorted(by_tool):
        arts = by_tool[tool]
        exist_count = sum(1 for a in arts if a.exists)
        surf_count = sum(
            len(surf_by_artifact.get(a.artifact_id, []))
            for a in arts
        )
        lines.append(f"| {tool} | {len(arts)} | {exist_count} | {surf_count} |")
    lines.append("")

    # By severity
    sev_counts: dict[str, int] = {}
    for s in ctx.surfaces:
        sev = s.risk_dimensions.get("_severity", "unknown")
        sev_counts[sev] = sev_counts.get(sev, 0) + 1

    if sev_counts:
        lines.append("### By Severity")
        lines.append("")
        lines.append("| Severity | Count |")
        lines.append("|----------|------:|")
        for sev in ("critical", "high", "medium", "low", "info", "unknown"):
            if sev in sev_counts:
                lines.append(f"| {sev.upper()} | {sev_counts[sev]} |")
        lines.append("")

    lines.append("---")
    lines.append("")

    # Detailed findings per tool
    lines.append("## Findings")
    lines.append("")

    for tool in sorted(by_tool):
        arts = by_tool[tool]
        lines.append(f"### {tool}")
        lines.append("")

        for a in sorted(arts, key=lambda x: (x.precedence_rank or 99, str(x.path))):
            status = "EXISTS" if a.exists else "CREATABLE"
            lines.append(f"#### `{a.path}`")
            lines.append("")
            lines.append(f"- **Status:** {status} | **Surface:** {a.surface_type.value} | **Scope:** {a.scope.value}")
            lines.append(f"- **Confidence:** {a.confidence:.0%} | **Precedence:** {a.precedence_rank or 'n/a'}")
            lines.append(f"- **Description:** {a.description}")

            surfs = surf_by_artifact.get(a.artifact_id, [])
            if surfs:
                for s in surfs:
                    sev = s.risk_dimensions.get("_severity", "?")
                    score = s.risk_dimensions.get("_composite", 0)
                    lines.append(
                        f"- **Surface:** {s.influence_type.value} | "
                        f"exec={s.execution_capability} | "
                        f"persist={s.persistence} | "
                        f"cross-tool={'yes' if s.cross_tool_reach else 'no'} | "
                        f"severity={sev} ({score:.1f})"
                    )
            lines.append("")

    # Precedence relationships
    precedence_edges = getattr(ctx, "precedence_edges", [])
    if precedence_edges:
        lines.append("---")
        lines.append("")
        lines.append("## Precedence Relationships")
        lines.append("")
        lines.append("| Source | Target | Relation | Reason |")
        lines.append("|--------|--------|----------|--------|")

        # Build artifact id -> path lookup
        art_path_map: dict[str, str] = {a.artifact_id: str(a.path) for a in ctx.artifacts}
        for pedge in precedence_edges:
            src_label = art_path_map.get(pedge.source_id, pedge.source_id)
            tgt_label = art_path_map.get(pedge.target_id, pedge.target_id)
            lines.append(
                f"| `{src_label}` | `{tgt_label}` | {pedge.relation} | {pedge.reason} |"
            )
        lines.append("")

    # Cross-tool correlations
    correlations = getattr(ctx, "correlations", [])
    if correlations:
        lines.append("---")
        lines.append("")
        lines.append("## Cross-Tool Correlations")
        lines.append("")
        for i, corr in enumerate(correlations, 1):
            lines.append(f"### Correlation {i}")
            lines.append("")
            lines.append(f"- **Tools:** {', '.join(corr.tools)}")
            lines.append(f"- **Paths:** {', '.join(f'`{p}`' for p in corr.paths)}")
            lines.append(f"- **Surface types:** {', '.join(corr.surface_types)}")
            lines.append(f"- **Risk multiplier:** {corr.risk_multiplier:.1f}x")
            lines.append(f"- **Description:** {corr.description}")
            lines.append("")

    # Hardening reference
    lines.append("---")
    lines.append("")
    lines.append("## Hardening")
    lines.append("")
    lines.append("See [`hardening.md`](hardening.md) for a defender-oriented checklist of recommended actions.")
    lines.append("")

    # Evidence summary
    lines.append("---")
    lines.append("")
    lines.append(f"## Evidence")
    lines.append("")
    lines.append(f"Total events logged: {len(ctx.evidence)}")
    lines.append("")
    lines.append("See `events.jsonl` for full evidence chain.")
    lines.append("")

    report_path = output_dir / "report.md"
    report_path.write_text("\n".join(lines))
    return report_path

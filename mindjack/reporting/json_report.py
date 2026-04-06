"""JSON report generation."""

from __future__ import annotations

import json
from pathlib import Path

from mindjack.core.models import RunContext


def generate_json_report(ctx: RunContext, output_dir: Path) -> Path:
    """Write structured JSON report."""
    output_dir.mkdir(parents=True, exist_ok=True)

    # Artifacts
    artifacts_data = []
    for a in ctx.artifacts:
        artifacts_data.append({
            "artifact_id": a.artifact_id,
            "tool_slug": a.tool_slug,
            "surface_type": a.surface_type.value,
            "scope": a.scope.value,
            "path": str(a.path),
            "exists": a.exists,
            "state": a.state.value,
            "parser_type": a.parser_type.value,
            "confidence": a.confidence,
            "precedence_rank": a.precedence_rank,
            "description": a.description,
            "tags": a.tags,
            "sha256": a.sha256,
        })

    # Surfaces
    surfaces_data = []
    for s in ctx.surfaces:
        surfaces_data.append({
            "surface_id": s.surface_id,
            "artifact_id": s.artifact_id,
            "influence_type": s.influence_type.value,
            "execution_capability": s.execution_capability,
            "persistence": s.persistence,
            "cross_tool_reach": s.cross_tool_reach,
            "risk_dimensions": s.risk_dimensions,
        })

    report = {
        "run_id": ctx.run_id,
        "mode": ctx.mode,
        "started_at": ctx.started_at,
        "scope_paths": [str(p) for p in ctx.scope_paths],
        "summary": {
            "total_artifacts": len(ctx.artifacts),
            "existing_artifacts": sum(1 for a in ctx.artifacts if a.exists),
            "total_surfaces": len(ctx.surfaces),
            "by_tool": _count_by(ctx.artifacts, lambda a: a.tool_slug),
            "by_surface_type": _count_by(ctx.artifacts, lambda a: a.surface_type.value),
            "by_severity": _count_by_severity(ctx.surfaces),
        },
        "artifacts": artifacts_data,
        "surfaces": surfaces_data,
    }

    report_path = output_dir / "report.json"
    report_path.write_text(json.dumps(report, indent=2, ensure_ascii=False))

    # Also write artifacts.jsonl for streaming consumption
    jsonl_path = output_dir / "artifacts.jsonl"
    with jsonl_path.open("w") as f:
        for a in artifacts_data:
            f.write(json.dumps(a) + "\n")

    return report_path


def _count_by(items, key_fn) -> dict[str, int]:
    counts: dict[str, int] = {}
    for item in items:
        k = key_fn(item)
        counts[k] = counts.get(k, 0) + 1
    return counts


def _count_by_severity(surfaces) -> dict[str, int]:
    counts: dict[str, int] = {}
    for s in surfaces:
        sev = s.risk_dimensions.get("_severity", "unknown")
        counts[sev] = counts.get(sev, 0) + 1
    return counts

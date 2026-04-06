"""Scan orchestration — the core discover + assess pipeline."""

from __future__ import annotations

from pathlib import Path

from mindjack.core.evidence import EvidenceLogger
from mindjack.core.models import RunContext
from mindjack.core.registry import PluginRegistry, get_registry, load_default_plugins
from mindjack.core.risk import RiskScore, score_surface
from mindjack.core.scope import Scope
from mindjack.graph.builder import TrustGraph
from mindjack.graph.correlation import CorrelationEngine
from mindjack.graph.precedence import PrecedenceEngine
from mindjack.parsers.base import parse_artifact


def run_discover(
    scope: Scope,
    *,
    registry: PluginRegistry | None = None,
    tool_filter: list[str] | None = None,
) -> RunContext:
    """Run read-only discovery across all registered plugins."""
    if registry is None:
        registry = load_default_plugins()

    ctx = RunContext(
        mode="assessment",
        scope_paths=list(scope.paths),
    )
    evidence = EvidenceLogger(ctx)
    evidence.log("discovery_started", metadata={"scope": [str(p) for p in scope.paths]})

    plugins = registry.all_plugins()
    if tool_filter:
        plugins = [p for p in plugins if p.slug in tool_filter]

    for plugin in plugins:
        try:
            artifacts = plugin.detect(scope)
        except Exception as exc:
            evidence.log("discovery_error", metadata={
                "plugin": plugin.slug, "error": str(exc),
            })
            continue

        for artifact in artifacts:
            ctx.artifacts.append(artifact)
            evidence.log(
                "artifact_detected",
                path=artifact.path,
                sha256_before=artifact.sha256,
                metadata={
                    "tool": artifact.tool_slug,
                    "surface_type": artifact.surface_type.value,
                    "scope": artifact.scope.value,
                    "exists": artifact.exists,
                    "state": artifact.state.value,
                    "confidence": artifact.confidence,
                },
            )

            # Parse the artifact
            parsed = parse_artifact(artifact)
            evidence.log(
                "artifact_parsed",
                path=artifact.path,
                metadata={"parser_status": parsed.get("_status", "unknown")},
            )

            # Classify trust surfaces
            try:
                surfaces = plugin.classify(artifact)
            except Exception:
                surfaces = []

            for surface in surfaces:
                ctx.surfaces.append(surface)
                risk = score_surface(artifact, surface)
                surface.risk_dimensions["_composite"] = risk.composite
                surface.risk_dimensions["_severity"] = risk.severity
                evidence.log(
                    "surface_classified",
                    path=artifact.path,
                    metadata={
                        "surface_id": surface.surface_id,
                        "influence_type": surface.influence_type.value,
                        "severity": risk.severity,
                        "composite_score": risk.composite,
                    },
                )

    # --- Phase 2: Precedence resolution ---
    prec_engine = PrecedenceEngine()
    ctx.precedence_edges = prec_engine.resolve(ctx.artifacts)
    evidence.log("precedence_resolved", metadata={
        "edge_count": len(ctx.precedence_edges),
    })

    # --- Phase 2: Cross-tool correlation ---
    corr_engine = CorrelationEngine()
    ctx.correlations = corr_engine.correlate(ctx)
    evidence.log("correlations_detected", metadata={
        "correlation_count": len(ctx.correlations),
    })

    # --- Phase 2: Build trust graph ---
    graph = TrustGraph().build(ctx)
    evidence.log("graph_built", metadata={
        "node_count": len(graph.nodes()),
        "edge_count": len(graph.edges()),
    })

    evidence.log("discovery_completed", metadata={
        "artifact_count": len(ctx.artifacts),
        "surface_count": len(ctx.surfaces),
        "precedence_edges": len(ctx.precedence_edges),
        "correlations": len(ctx.correlations),
    })

    return ctx

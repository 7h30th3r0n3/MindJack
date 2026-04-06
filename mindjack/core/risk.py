"""Multidimensional risk scoring."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from .constants import InfluenceType, SurfaceType
from .models import DiscoveredArtifact, TrustSurface


@dataclass
class RiskScore:
    """Multidimensional risk assessment for a trust surface."""

    impact: float = 0.0
    exploitability: float = 0.0
    persistence: float = 0.0
    stealth: float = 0.0
    required_privilege: float = 0.0
    cross_tool_reach: float = 0.0
    execution_potential: float = 0.0
    recovery_complexity: float = 0.0
    confidence: float = 0.0

    @property
    def severity(self) -> str:
        s = self.composite
        if s >= 8.0:
            return "critical"
        if s >= 6.0:
            return "high"
        if s >= 4.0:
            return "medium"
        if s >= 2.0:
            return "low"
        return "info"

    @property
    def composite(self) -> float:
        """Weighted composite score (0-10)."""
        weights = {
            "impact": 0.20,
            "exploitability": 0.20,
            "execution_potential": 0.15,
            "persistence": 0.10,
            "cross_tool_reach": 0.10,
            "stealth": 0.08,
            "recovery_complexity": 0.07,
            "required_privilege": 0.05,
            "confidence": 0.05,
        }
        total = sum(
            getattr(self, dim) * w for dim, w in weights.items()
        )
        return round(min(10.0, total), 2)

    def to_dict(self) -> dict[str, Any]:
        return {
            "impact": self.impact,
            "exploitability": self.exploitability,
            "persistence": self.persistence,
            "stealth": self.stealth,
            "required_privilege": self.required_privilege,
            "cross_tool_reach": self.cross_tool_reach,
            "execution_potential": self.execution_potential,
            "recovery_complexity": self.recovery_complexity,
            "confidence": self.confidence,
            "composite": self.composite,
            "severity": self.severity,
        }


# ---------------------------------------------------------------------------
# Default scoring heuristics by surface type
# ---------------------------------------------------------------------------

_SURFACE_DEFAULTS: dict[SurfaceType, dict[str, float]] = {
    SurfaceType.INSTRUCTIONS: {
        "impact": 8.0, "exploitability": 9.0, "persistence": 7.0,
        "stealth": 7.0, "required_privilege": 9.0, "execution_potential": 6.0,
        "recovery_complexity": 3.0, "confidence": 8.0,
    },
    SurfaceType.SETTINGS: {
        "impact": 9.0, "exploitability": 7.0, "persistence": 8.0,
        "stealth": 5.0, "required_privilege": 8.0, "execution_potential": 8.0,
        "recovery_complexity": 4.0, "confidence": 8.0,
    },
    SurfaceType.MCP: {
        "impact": 10.0, "exploitability": 7.0, "persistence": 9.0,
        "stealth": 6.0, "required_privilege": 7.0, "execution_potential": 10.0,
        "recovery_complexity": 5.0, "confidence": 8.0,
    },
    SurfaceType.HOOKS: {
        "impact": 10.0, "exploitability": 6.0, "persistence": 8.0,
        "stealth": 4.0, "required_privilege": 7.0, "execution_potential": 10.0,
        "recovery_complexity": 4.0, "confidence": 9.0,
    },
    SurfaceType.MEMORY: {
        "impact": 6.0, "exploitability": 8.0, "persistence": 9.0,
        "stealth": 8.0, "required_privilege": 9.0, "execution_potential": 4.0,
        "recovery_complexity": 5.0, "confidence": 7.0,
    },
    SurfaceType.RULES: {
        "impact": 8.0, "exploitability": 8.0, "persistence": 7.0,
        "stealth": 7.0, "required_privilege": 9.0, "execution_potential": 6.0,
        "recovery_complexity": 3.0, "confidence": 8.0,
    },
    SurfaceType.CONFIG: {
        "impact": 7.0, "exploitability": 6.0, "persistence": 7.0,
        "stealth": 5.0, "required_privilege": 8.0, "execution_potential": 5.0,
        "recovery_complexity": 3.0, "confidence": 7.0,
    },
}


def score_surface(
    artifact: DiscoveredArtifact,
    surface: TrustSurface,
) -> RiskScore:
    """Score a trust surface using heuristics based on type and attributes."""
    defaults = _SURFACE_DEFAULTS.get(artifact.surface_type, {})
    dims = {**defaults, **surface.risk_dimensions}

    score = RiskScore(
        impact=dims.get("impact", 5.0),
        exploitability=dims.get("exploitability", 5.0),
        persistence=dims.get("persistence", 5.0),
        stealth=dims.get("stealth", 5.0),
        required_privilege=dims.get("required_privilege", 5.0),
        cross_tool_reach=8.0 if surface.cross_tool_reach else dims.get("cross_tool_reach", 2.0),
        execution_potential=dims.get("execution_potential", 5.0),
        recovery_complexity=dims.get("recovery_complexity", 5.0),
        confidence=artifact.confidence * 10,
    )
    return score

"""Findings model for pentest-style reporting."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class Finding:
    """A single assessment finding suitable for pentest reports."""

    title: str
    description: str
    evidence: list[str] = field(default_factory=list)
    likelihood: str = "medium"
    impact: str = "medium"
    severity: str = "medium"
    affected_scope: str = ""
    trust_surface_type: str = ""
    abuse_scenario: str = ""
    operator_notes: str = ""
    remediation_quick_wins: list[str] = field(default_factory=list)
    remediation_strategic: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "title": self.title,
            "description": self.description,
            "evidence": self.evidence,
            "likelihood": self.likelihood,
            "impact": self.impact,
            "severity": self.severity,
            "affected_scope": self.affected_scope,
            "trust_surface_type": self.trust_surface_type,
            "abuse_scenario": self.abuse_scenario,
            "operator_notes": self.operator_notes,
            "remediation_quick_wins": self.remediation_quick_wins,
            "remediation_strategic": self.remediation_strategic,
        }

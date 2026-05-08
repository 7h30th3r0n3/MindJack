"""Canonical data models for MindJack v2."""

from __future__ import annotations

import hashlib
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .constants import (
    ArtifactState,
    InfluenceType,
    ParserType,
    ScopeLevel,
    SurfaceType,
)


# ---------------------------------------------------------------------------
# Indicator — what signals the presence of a tool
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Indicator:
    """A filesystem or environment signal that indicates tool presence."""

    kind: str  # "directory", "file", "env_var", "process"
    value: str  # path pattern or env var name
    weight: float = 1.0


# ---------------------------------------------------------------------------
# ToolDescriptor — registry entry for a supported tool
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ToolDescriptor:
    """Metadata describing a supported AI coding tool."""

    slug: str
    display_name: str
    category: str
    indicators: tuple[Indicator, ...] = ()
    supported_surfaces: tuple[SurfaceType, ...] = ()
    parser_hints: dict[str, str] = field(default_factory=dict)
    precedence_model: str | None = None
    version_detection: bool = True


# ---------------------------------------------------------------------------
# DiscoveredArtifact — a file/resource found during discovery
# ---------------------------------------------------------------------------


def _new_id() -> str:
    return uuid.uuid4().hex[:12]


@dataclass
class DiscoveredArtifact:
    """A concrete file or resource found on the system."""

    tool_slug: str
    surface_type: SurfaceType
    scope: ScopeLevel
    path: Path
    exists: bool
    parser_type: ParserType
    confidence: float = 0.0
    precedence_rank: int | None = None
    supports_safe_patch: bool = False
    rollback_strategy: str = "backup_copy"
    tags: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)
    artifact_id: str = field(default_factory=_new_id)
    state: ArtifactState = ArtifactState.ACTIVE
    description: str = ""

    @property
    def sha256(self) -> str | None:
        """Compute SHA-256 of the file if it exists."""
        if not self.exists or not self.path.is_file():
            return None
        try:
            return hashlib.sha256(self.path.read_bytes()).hexdigest()
        except OSError:
            return None


# ---------------------------------------------------------------------------
# TrustSurface — security-relevant influence a artifact exposes
# ---------------------------------------------------------------------------


@dataclass
class TrustSurface:
    """A security-relevant influence exposed by an artifact."""

    artifact_id: str
    influence_type: InfluenceType
    execution_capability: str = "none"
    persistence: str = "session"
    cross_tool_reach: bool = False
    risk_dimensions: dict[str, float] = field(default_factory=dict)
    surface_id: str = field(default_factory=_new_id)


# ---------------------------------------------------------------------------
# EvidenceRecord — audit log entry
# ---------------------------------------------------------------------------


@dataclass
class EvidenceRecord:
    """A single timestamped event in an evidence chain."""

    run_id: str
    event_type: str
    path: str | None = None
    sha256_before: str | None = None
    sha256_after: str | None = None
    diff_path: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)
    event_time: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )


# ---------------------------------------------------------------------------
# PatchPlan — planned mutation (Phase 3, stub for now)
# ---------------------------------------------------------------------------


@dataclass
class PatchPlan:
    """A planned mutation to an artifact (Phase 3)."""

    plan_id: str
    run_id: str
    artifact_id: str
    operation: str
    mode: str
    patch_engine: str
    payload: str = ""
    target_path: Path | None = None
    validation_required: bool = True
    rollback_required: bool = True
    expected_effects: list[str] = field(default_factory=list)
    blast_radius: dict[str, Any] = field(default_factory=dict)


# ---------------------------------------------------------------------------
# RunContext — ties a single invocation together
# ---------------------------------------------------------------------------


@dataclass
class RunContext:
    """Top-level context for a single MindJack invocation."""

    run_id: str = field(default_factory=lambda: f"MJ-{datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S')}-{uuid.uuid4().hex[:6]}")
    mode: str = "assessment"
    scope_paths: list[Path] = field(default_factory=list)
    started_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    artifacts: list[DiscoveredArtifact] = field(default_factory=list)
    surfaces: list[TrustSurface] = field(default_factory=list)
    evidence: list[EvidenceRecord] = field(default_factory=list)
    precedence_edges: list = field(default_factory=list)
    correlations: list = field(default_factory=list)

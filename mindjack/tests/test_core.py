"""Tests for core models, scope, evidence, risk, and registry."""

from __future__ import annotations

import json
import tempfile
from pathlib import Path

from mindjack.core.constants import (
    ArtifactState,
    InfluenceType,
    Mode,
    ParserType,
    ScopeLevel,
    SurfaceType,
)
from mindjack.core.evidence import EvidenceLogger
from mindjack.core.models import (
    DiscoveredArtifact,
    EvidenceRecord,
    RunContext,
    ToolDescriptor,
    TrustSurface,
)
from mindjack.core.registry import PluginRegistry
from mindjack.core.risk import RiskScore, score_surface
from mindjack.core.scope import Scope


def test_artifact_creation():
    a = DiscoveredArtifact(
        tool_slug="claude-code",
        surface_type=SurfaceType.INSTRUCTIONS,
        scope=ScopeLevel.PROJECT,
        path=Path("/tmp/nonexistent/CLAUDE.md"),
        exists=False,
        parser_type=ParserType.MARKDOWN,
        confidence=0.5,
    )
    assert a.tool_slug == "claude-code"
    assert a.state == ArtifactState.ACTIVE
    assert a.sha256 is None
    assert len(a.artifact_id) == 12


def test_risk_score():
    score = RiskScore(
        impact=8.0,
        exploitability=9.0,
        persistence=7.0,
        execution_potential=6.0,
        confidence=8.0,
    )
    assert score.severity in ("critical", "high", "medium", "low", "info")
    assert 0 <= score.composite <= 10


def test_score_surface():
    artifact = DiscoveredArtifact(
        tool_slug="claude-code",
        surface_type=SurfaceType.MCP,
        scope=ScopeLevel.USER,
        path=Path("/tmp/.mcp.json"),
        exists=True,
        parser_type=ParserType.JSON,
        confidence=0.9,
    )
    surface = TrustSurface(
        artifact_id=artifact.artifact_id,
        influence_type=InfluenceType.TOOL_CONTROL,
        execution_capability="arbitrary_process",
        persistence="persistent",
        cross_tool_reach=True,
    )
    risk = score_surface(artifact, surface)
    assert risk.severity in ("critical", "high")
    assert risk.composite > 5.0


def test_evidence_logger():
    ctx = RunContext()
    logger = EvidenceLogger(ctx)
    logger.log("test_event", path="/tmp/test", metadata={"key": "value"})
    assert len(ctx.evidence) == 1
    assert ctx.evidence[0].event_type == "test_event"

    with tempfile.TemporaryDirectory() as td:
        p = logger.write(Path(td))
        assert p.exists()
        run_json = Path(td) / "run.json"
        assert run_json.exists()
        data = json.loads(run_json.read_text())
        assert data["run_id"] == ctx.run_id
        assert data["event_count"] == 1


def test_registry():
    from mindjack.core.registry import load_default_plugins
    reg = load_default_plugins()
    slugs = reg.all_slugs()
    assert "claude-code" in slugs
    assert "codex-cli" in slugs
    assert len(slugs) >= 10


def test_scope_contains():
    scope = Scope(paths=[Path("/tmp/project")])
    assert scope.contains(Path("/tmp/project/CLAUDE.md"))


def test_run_context():
    ctx = RunContext()
    assert ctx.run_id.startswith("MJ-")
    assert ctx.mode == "assessment"


if __name__ == "__main__":
    import sys
    failures = 0
    for name, fn in list(globals().items()):
        if name.startswith("test_") and callable(fn):
            try:
                fn()
                print(f"  PASS  {name}")
            except Exception as exc:
                print(f"  FAIL  {name}: {exc}")
                failures += 1
    sys.exit(1 if failures else 0)

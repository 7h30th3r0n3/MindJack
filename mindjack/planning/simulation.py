"""Dry-run simulation — generate diffs without writing to disk."""

from __future__ import annotations

from dataclasses import dataclass, field

from mindjack.core.constants import PatchEngine
from mindjack.core.models import PatchPlan, RunContext
from mindjack.parsers.base import safe_read
from mindjack.patching.diffing import generate_diff
from mindjack.patching.patch_engines import get_engine
from mindjack.planning.blast_radius import BlastRadius, BlastRadiusAnalyzer


@dataclass
class SimulationResult:
    """Result of a simulated (dry-run) patch application."""

    plan_id: str = ""
    artifact_path: str = ""
    diff_preview: str = ""
    original_content: str | None = None
    new_content: str = ""
    blast_radius: BlastRadius | None = None
    warnings: list[str] = field(default_factory=list)


class Simulator:
    """Simulates a patch plan in memory, producing diffs without disk writes."""

    def simulate(
        self,
        plan: PatchPlan,
        payload: str,
        *,
        ctx: RunContext | None = None,
    ) -> SimulationResult:
        """Run a dry-run simulation of *plan*.

        Parameters
        ----------
        plan:
            The patch plan to simulate.
        payload:
            The content payload for the patch engine.
        ctx:
            Optional RunContext for blast-radius analysis.
        """
        warnings: list[str] = []
        original_content: str | None = None
        artifact_path = str(plan.target_path) if plan.target_path else ""

        # Read original content (unless create_new)
        if plan.operation != PatchEngine.CREATE_NEW and plan.target_path:
            original_content = safe_read(plan.target_path)
            if original_content is None:
                warnings.append(
                    f"Could not read {plan.target_path}; "
                    "simulating as if file is empty"
                )
                original_content = ""

        # Apply engine in memory
        engine_fn = get_engine(plan.patch_engine)
        metadata: dict = {}
        if plan.target_path:
            metadata["path"] = str(plan.target_path)

        try:
            new_content = engine_fn(original_content, payload, metadata)
        except Exception as exc:
            warnings.append(f"Engine error: {exc}")
            new_content = original_content or ""

        # Generate diff
        diff_preview = generate_diff(original_content, new_content, artifact_path)

        # Blast-radius analysis
        blast_radius: BlastRadius | None = None
        if ctx is not None:
            analyzer = BlastRadiusAnalyzer()
            blast_radius = analyzer.analyze(plan, ctx)

        return SimulationResult(
            plan_id=plan.plan_id,
            artifact_path=artifact_path,
            diff_preview=diff_preview,
            original_content=original_content,
            new_content=new_content,
            blast_radius=blast_radius,
            warnings=warnings,
        )

"""Simulation execution command — read-only diff preview."""

from __future__ import annotations

from mindjack.core.models import DiscoveredArtifact, RunContext
from mindjack.core.scope import Scope
from mindjack.planning.patch_planner import PatchPlanner
from mindjack.planning.simulation import SimulationResult, Simulator


def run_simulate(
    scope: Scope,
    technique: str,
    ctx_or_artifacts: RunContext | list[DiscoveredArtifact],
    payload: str,
) -> list[SimulationResult]:
    """Orchestrate: select targets -> plan patches -> simulate -> return diffs.

    This function is purely read-only and never writes to disk.

    Parameters
    ----------
    scope:
        The scope to constrain target selection.
    technique:
        The patch engine / operation name (e.g. "append_text").
    ctx_or_artifacts:
        Either a RunContext (from a prior discover run) or a list of
        DiscoveredArtifact objects to target.
    payload:
        The content to apply.

    Returns
    -------
    A list of SimulationResult objects, one per targeted artifact.
    """
    planner = PatchPlanner()
    simulator = Simulator()

    # Resolve artifacts and context
    if isinstance(ctx_or_artifacts, RunContext):
        ctx = ctx_or_artifacts
        artifacts = ctx.artifacts
    else:
        artifacts = ctx_or_artifacts
        ctx = None

    # Filter artifacts to those within scope
    targets = [a for a in artifacts if scope.contains(a.path)]

    results: list[SimulationResult] = []
    for artifact in targets:
        try:
            plan = planner.plan(
                artifact,
                operation=technique,
                payload=payload,
                mode="simulation",
                run_id=ctx.run_id if ctx else None,
            )
        except Exception:
            # Operation incompatible with this artifact — skip
            continue

        result = simulator.simulate(plan, payload, ctx=ctx)
        results.append(result)

    return results

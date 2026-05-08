"""Lab-mode apply execution — write patches with rollback."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from pathlib import Path

from mindjack.core.constants import Mode
from mindjack.core.errors import ModeError
from mindjack.core.evidence import EvidenceLogger
from mindjack.core.models import DiscoveredArtifact, PatchPlan, RunContext
from mindjack.patching.atomic_write import atomic_write
from mindjack.patching.patch_engines import get_engine
from mindjack.patching.rollback import RollbackEntry, RollbackManager
from mindjack.patching.validators import validate_post_write, validate_pre_write
from mindjack.parsers.base import safe_read


@dataclass
class ApplyResult:
    """Result of a lab-mode apply operation."""

    run_id: str = ""
    applied: list[str] = field(default_factory=list)
    failed: list[dict] = field(default_factory=list)
    rollback_manifest_path: str = ""


def _sha256(content: str) -> str:
    return hashlib.sha256(content.encode("utf-8")).hexdigest()


def run_apply(
    plan_path_or_plans: Path | list[PatchPlan],
    scope_paths: list[Path],
    run_id: str,
    *,
    artifacts: list[DiscoveredArtifact] | None = None,
    output_dir: Path | None = None,
) -> ApplyResult:
    """Execute patch plans in lab-apply mode.

    Parameters
    ----------
    plan_path_or_plans:
        Either a Path to a plan JSON file, or a list of PatchPlan objects.
    scope_paths:
        Paths that define the operation scope.
    run_id:
        The run identifier.
    artifacts:
        Optional list of DiscoveredArtifact objects (needed for rollback
        preparation when plans are passed directly).
    output_dir:
        Directory for rollback manifests and evidence.

    Raises
    ------
    ModeError
        If the mode is not "lab-apply".
    """
    output_dir = output_dir or Path("mindjack_output")
    result = ApplyResult(run_id=run_id)

    # Resolve plans
    if isinstance(plan_path_or_plans, Path):
        plans = _load_plans(plan_path_or_plans)
    else:
        plans = plan_path_or_plans

    # MUST check mode
    for plan in plans:
        if plan.mode != Mode.LAB_APPLY:
            raise ModeError(
                f"Plan {plan.plan_id} has mode {plan.mode!r}; "
                f"only {Mode.LAB_APPLY!r} is allowed for apply. "
                "Pass --lab-mode explicitly."
            )

    # Build artifact lookup
    artifact_map: dict[str, DiscoveredArtifact] = {}
    if artifacts:
        for art in artifacts:
            artifact_map[art.artifact_id] = art

    # Set up evidence and rollback
    ctx = RunContext(run_id=run_id, mode=Mode.LAB_APPLY, scope_paths=scope_paths)
    evidence = EvidenceLogger(ctx)
    rollback_mgr = RollbackManager(backup_dir=output_dir / "backups")
    rollback_entries: list[RollbackEntry] = []

    evidence.log("apply_started", metadata={
        "plan_count": len(plans),
        "scope": [str(p) for p in scope_paths],
    })

    for plan in plans:
        plan_target = plan.target_path
        if plan_target is None:
            result.failed.append({
                "plan_id": plan.plan_id,
                "error": "No target_path in plan",
            })
            continue

        try:
            # Read original
            original_content = safe_read(plan_target) if plan_target.exists() else None

            # Apply engine
            engine_fn = get_engine(plan.patch_engine)
            metadata: dict = {"path": str(plan_target)}
            new_content = engine_fn(original_content, plan.payload, metadata)

            # Pre-write validation
            if plan.validation_required:
                pre_msgs = validate_pre_write(plan, original_content, new_content)
                errors = [m for m in pre_msgs if m.level == "error"]
                if errors:
                    result.failed.append({
                        "plan_id": plan.plan_id,
                        "error": "; ".join(m.message for m in errors),
                    })
                    evidence.log("apply_pre_validation_failed", path=plan_target, metadata={
                        "plan_id": plan.plan_id,
                        "errors": [m.message for m in errors],
                    })
                    continue

            # Prepare rollback
            if plan.rollback_required:
                art = artifact_map.get(plan.artifact_id)
                if art is not None:
                    entry = rollback_mgr.prepare(art, run_id)
                    entry.patch_engine = plan.patch_engine
                    rollback_entries.append(entry)

            sha_before = _sha256(original_content) if original_content else ""

            # Atomic write
            atomic_write(plan_target, new_content)

            sha_after = _sha256(new_content)

            # Update mutation_hash on rollback entry
            if rollback_entries:
                rollback_entries[-1].mutation_hash = sha_after

            # Post-write validation
            if plan.validation_required:
                post_msgs = validate_post_write(plan, plan_target)
                post_errors = [m for m in post_msgs if m.level == "error"]
                if post_errors:
                    # Log but don't fail — the write already happened
                    evidence.log("apply_post_validation_warning", path=plan_target, metadata={
                        "plan_id": plan.plan_id,
                        "errors": [m.message for m in post_errors],
                    })

            # Log evidence
            evidence.log(
                "artifact_mutated",
                path=plan_target,
                sha256_before=sha_before,
                sha256_after=sha_after,
                metadata={
                    "plan_id": plan.plan_id,
                    "patch_engine": plan.patch_engine,
                    "operation": plan.operation,
                },
            )

            result.applied.append(plan.plan_id)

        except Exception as exc:
            result.failed.append({
                "plan_id": plan.plan_id,
                "error": str(exc),
            })
            evidence.log("apply_error", path=plan_target, metadata={
                "plan_id": plan.plan_id,
                "error": str(exc),
            })

    # Write rollback manifest
    if rollback_entries:
        manifest_path = rollback_mgr.write_manifest(rollback_entries, output_dir)
        result.rollback_manifest_path = str(manifest_path)
        evidence.log("rollback_manifest_written", metadata={
            "path": str(manifest_path),
            "entry_count": len(rollback_entries),
        })

    # Write evidence
    evidence.write(output_dir)

    evidence.log("apply_completed", metadata={
        "applied": len(result.applied),
        "failed": len(result.failed),
    })

    return result


def _load_plans(path: Path) -> list[PatchPlan]:
    """Load PatchPlan objects from a JSON file."""
    try:
        data = json.loads(path.read_text())
    except (OSError, json.JSONDecodeError) as exc:
        raise ModeError(f"Cannot load plan file: {exc}")

    plans_data = data if isinstance(data, list) else data.get("plans", [data])
    plans: list[PatchPlan] = []
    for item in plans_data:
        plans.append(PatchPlan(
            plan_id=item["plan_id"],
            run_id=item["run_id"],
            artifact_id=item["artifact_id"],
            operation=item["operation"],
            mode=item["mode"],
            patch_engine=item["patch_engine"],
            payload=item.get("payload", ""),
            target_path=Path(item["target_path"]) if item.get("target_path") else None,
            validation_required=item.get("validation_required", True),
            rollback_required=item.get("rollback_required", True),
            expected_effects=item.get("expected_effects", []),
            blast_radius=item.get("blast_radius", {}),
        ))
    return plans

"""Restore from a rollback manifest."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from mindjack.core.evidence import EvidenceLogger
from mindjack.core.models import RunContext
from mindjack.patching.rollback import RollbackManager


@dataclass
class RestoreResult:
    """Result of a restore operation."""

    run_id: str = ""
    restored: list[str] = field(default_factory=list)
    failed: list[dict] = field(default_factory=list)


def run_restore(
    manifest_path_or_run_id: Path | str,
    output_dir: Path | None = None,
) -> RestoreResult:
    """Restore all changes from a rollback manifest.

    Parameters
    ----------
    manifest_path_or_run_id:
        Either a Path to a rollback_manifest.json, or a run ID string.
        When a run ID is provided, looks for the manifest in the default
        output directory.
    output_dir:
        Base directory for mindjack output (used when resolving by run ID
        and for evidence logging).
    """
    output_dir = output_dir or Path("mindjack_output")
    rollback_mgr = RollbackManager(backup_dir=output_dir / "backups")

    # Resolve manifest path
    if isinstance(manifest_path_or_run_id, Path):
        manifest_path = manifest_path_or_run_id
    else:
        # Treat as run_id — look in default location
        manifest_path = output_dir / "rollback_manifest.json"
        if not manifest_path.exists():
            # Also try a run-id-specific subdirectory
            manifest_path = output_dir / manifest_path_or_run_id / "rollback_manifest.json"

    entries = rollback_mgr.load_manifest(manifest_path)

    if not entries:
        return RestoreResult(run_id="", restored=[], failed=[])

    run_id = entries[0].run_id
    result = RestoreResult(run_id=run_id)

    # Set up evidence logging
    ctx = RunContext(run_id=run_id, mode="restore", scope_paths=[])
    evidence = EvidenceLogger(ctx)
    evidence.log("restore_started", metadata={
        "manifest_path": str(manifest_path),
        "entry_count": len(entries),
    })

    for entry in entries:
        try:
            rollback_mgr.restore(entry)
            result.restored.append(entry.artifact_id)
            evidence.log(
                "artifact_restored",
                path=entry.original_path,
                metadata={
                    "artifact_id": entry.artifact_id,
                    "backup_path": entry.backup_path,
                },
            )
        except Exception as exc:
            result.failed.append({
                "artifact_id": entry.artifact_id,
                "error": str(exc),
            })
            evidence.log("restore_error", metadata={
                "artifact_id": entry.artifact_id,
                "error": str(exc),
            })

    evidence.log("restore_completed", metadata={
        "restored": len(result.restored),
        "failed": len(result.failed),
    })

    # Write evidence
    restore_evidence_dir = output_dir / "restore_evidence"
    evidence.write(restore_evidence_dir)

    return result

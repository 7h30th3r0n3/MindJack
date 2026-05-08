"""Rollback manifest management."""

from __future__ import annotations

import hashlib
import json
import shutil
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from mindjack.core.errors import MindJackError
from mindjack.core.models import DiscoveredArtifact


class RollbackError(MindJackError):
    """Raised when a rollback operation fails."""


@dataclass
class RollbackEntry:
    """A single entry in the rollback manifest."""

    run_id: str
    artifact_id: str
    original_path: str
    backup_path: str
    original_hash: str
    mutation_hash: str = ""
    patch_engine: str = ""
    timestamp: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )


def _hash_file(path: Path) -> str:
    """Compute SHA-256 of a file, or empty string if not readable."""
    try:
        return hashlib.sha256(path.read_bytes()).hexdigest()
    except OSError:
        return ""


class RollbackManager:
    """Manages backup copies and rollback manifests."""

    def __init__(self, backup_dir: Path | None = None) -> None:
        self._backup_dir = backup_dir or Path("mindjack_output") / "backups"

    def prepare(
        self,
        artifact: DiscoveredArtifact,
        run_id: str,
    ) -> RollbackEntry:
        """Create a backup copy of the artifact and return a RollbackEntry."""
        self._backup_dir.mkdir(parents=True, exist_ok=True)

        original_hash = ""
        backup_path_str = ""

        if artifact.exists and artifact.path.is_file():
            original_hash = _hash_file(artifact.path)
            # Backup filename includes artifact id to avoid collisions
            backup_name = f"{run_id}_{artifact.artifact_id}_{artifact.path.name}"
            backup_path = self._backup_dir / backup_name
            shutil.copy2(artifact.path, backup_path)
            backup_path_str = str(backup_path)
        else:
            # File doesn't exist yet — rollback means deletion
            backup_path_str = ""

        return RollbackEntry(
            run_id=run_id,
            artifact_id=artifact.artifact_id,
            original_path=str(artifact.path),
            backup_path=backup_path_str,
            original_hash=original_hash,
        )

    def restore(self, entry: RollbackEntry) -> None:
        """Restore a single artifact from its backup."""
        target = Path(entry.original_path)

        if not entry.backup_path:
            # No backup means the file was created fresh — remove it
            if target.exists():
                target.unlink()
            return

        backup = Path(entry.backup_path)
        if not backup.exists():
            raise RollbackError(
                f"Backup file not found: {backup} "
                f"(artifact {entry.artifact_id})"
            )

        # Verify backup integrity
        backup_hash = _hash_file(backup)
        if entry.original_hash and backup_hash != entry.original_hash:
            raise RollbackError(
                f"Backup integrity check failed for {entry.artifact_id}: "
                f"expected {entry.original_hash}, got {backup_hash}"
            )

        shutil.copy2(backup, target)

    def write_manifest(
        self,
        entries: list[RollbackEntry],
        output_dir: Path,
    ) -> Path:
        """Write the rollback manifest as JSON."""
        output_dir.mkdir(parents=True, exist_ok=True)
        manifest_path = output_dir / "rollback_manifest.json"
        data = {
            "version": 1,
            "entries": [asdict(e) for e in entries],
        }
        manifest_path.write_text(
            json.dumps(data, indent=2, ensure_ascii=False) + "\n"
        )
        return manifest_path

    def load_manifest(self, path: Path) -> list[RollbackEntry]:
        """Load a rollback manifest from JSON."""
        try:
            data = json.loads(path.read_text())
        except (OSError, json.JSONDecodeError) as exc:
            raise RollbackError(f"Cannot read rollback manifest: {exc}")

        entries_data = data.get("entries", [])
        entries: list[RollbackEntry] = []
        for item in entries_data:
            entries.append(RollbackEntry(
                run_id=item["run_id"],
                artifact_id=item["artifact_id"],
                original_path=item["original_path"],
                backup_path=item["backup_path"],
                original_hash=item["original_hash"],
                mutation_hash=item.get("mutation_hash", ""),
                patch_engine=item.get("patch_engine", ""),
                timestamp=item.get("timestamp", ""),
            ))
        return entries

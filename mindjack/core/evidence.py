"""Evidence logging for audit trails."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .models import EvidenceRecord, RunContext


class EvidenceLogger:
    """Collects and persists evidence records for a run."""

    def __init__(self, ctx: RunContext) -> None:
        self._ctx = ctx

    def log(
        self,
        event_type: str,
        *,
        path: str | Path | None = None,
        sha256_before: str | None = None,
        sha256_after: str | None = None,
        diff_path: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> EvidenceRecord:
        record = EvidenceRecord(
            run_id=self._ctx.run_id,
            event_type=event_type,
            path=str(path) if path else None,
            sha256_before=sha256_before,
            sha256_after=sha256_after,
            diff_path=diff_path,
            metadata=metadata or {},
        )
        self._ctx.evidence.append(record)
        return record

    def write(self, output_dir: Path) -> Path:
        """Write all evidence records to a JSONL file."""
        output_dir.mkdir(parents=True, exist_ok=True)
        events_path = output_dir / "events.jsonl"
        with events_path.open("w") as f:
            for rec in self._ctx.evidence:
                f.write(json.dumps({
                    "run_id": rec.run_id,
                    "event_time": rec.event_time,
                    "event_type": rec.event_type,
                    "path": rec.path,
                    "sha256_before": rec.sha256_before,
                    "sha256_after": rec.sha256_after,
                    "diff_path": rec.diff_path,
                    "metadata": rec.metadata,
                }) + "\n")

        # Also write the run manifest
        run_path = output_dir / "run.json"
        run_path.write_text(json.dumps({
            "run_id": self._ctx.run_id,
            "mode": self._ctx.mode,
            "scope_paths": [str(p) for p in self._ctx.scope_paths],
            "started_at": self._ctx.started_at,
            "artifact_count": len(self._ctx.artifacts),
            "surface_count": len(self._ctx.surfaces),
            "event_count": len(self._ctx.evidence),
        }, indent=2))

        return events_path

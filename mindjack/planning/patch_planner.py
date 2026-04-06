"""Generate PatchPlan objects from discovered artifacts."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

from mindjack.core.constants import Mode, PatchEngine, ParserType
from mindjack.core.errors import MindJackError
from mindjack.core.models import DiscoveredArtifact, PatchPlan

# Which operations are compatible with which parser types.
_OPERATION_COMPAT: dict[str, set[str]] = {
    PatchEngine.APPEND_TEXT: {
        ParserType.RAW_TEXT, ParserType.MARKDOWN, ParserType.JSON,
        ParserType.TOML, ParserType.YAML,
    },
    PatchEngine.INSERT_SECTION: {ParserType.MARKDOWN},
    PatchEngine.JSON_MERGE: {ParserType.JSON},
    PatchEngine.TOML_UPDATE: {ParserType.TOML},
    PatchEngine.YAML_UPDATE: {ParserType.YAML},
    PatchEngine.CREATE_NEW: {
        ParserType.RAW_TEXT, ParserType.MARKDOWN, ParserType.JSON,
        ParserType.TOML, ParserType.YAML,
    },
    PatchEngine.REPLACE_SCALAR: {
        ParserType.RAW_TEXT, ParserType.MARKDOWN, ParserType.JSON,
        ParserType.TOML, ParserType.YAML,
    },
    PatchEngine.PREPEND_FRONTMATTER: {ParserType.MARKDOWN},
}


class PlanningError(MindJackError):
    """Raised when a patch plan cannot be created."""


class PatchPlanner:
    """Generates PatchPlan objects from artifacts."""

    def plan(
        self,
        artifact: DiscoveredArtifact,
        operation: str,
        payload: str,
        mode: str,
        *,
        run_id: str | None = None,
    ) -> PatchPlan:
        """Create a PatchPlan for the given artifact and operation.

        Parameters
        ----------
        artifact:
            The target artifact to patch.
        operation:
            One of the PatchEngine values (e.g. "append_text").
        payload:
            The content to apply via the patch engine.
        mode:
            Operating mode ("assessment", "simulation", "lab-apply", "restore").
        run_id:
            Optional run identifier; auto-generated if omitted.
        """
        # Validate operation
        try:
            engine = PatchEngine(operation)
        except ValueError:
            valid = ", ".join(e.value for e in PatchEngine)
            raise PlanningError(
                f"Unknown operation {operation!r}. Valid: {valid}"
            )

        # Validate compatibility
        compat = _OPERATION_COMPAT.get(engine, set())
        if artifact.parser_type not in compat:
            raise PlanningError(
                f"Operation {operation!r} is not compatible with "
                f"parser type {artifact.parser_type.value!r} "
                f"(artifact {artifact.artifact_id})"
            )

        if run_id is None:
            run_id = (
                f"MJ-{datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S')}"
                f"-{uuid.uuid4().hex[:6]}"
            )

        plan_id = f"PP-{uuid.uuid4().hex[:10]}"

        # Determine flags based on mode
        validation_required = True
        rollback_required = mode == Mode.LAB_APPLY

        return PatchPlan(
            plan_id=plan_id,
            run_id=run_id,
            artifact_id=artifact.artifact_id,
            operation=operation,
            mode=mode,
            patch_engine=engine.value,
            payload=payload,
            target_path=artifact.path,
            validation_required=validation_required,
            rollback_required=rollback_required,
        )

"""Pre-write and post-write validation for patch operations."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

from mindjack.core.constants import PatchEngine
from mindjack.core.models import PatchPlan


@dataclass
class ValidationMessage:
    """A single validation warning or error."""

    level: str  # "warning" or "error"
    message: str


MAX_REASONABLE_SIZE = 10 * 1024 * 1024  # 10 MB
MIN_CONTENT_LENGTH = 0  # empty is valid for some engines
TRUNCATION_RATIO = 0.5  # warn if new content is < 50% of original


def validate_pre_write(
    plan: PatchPlan,
    original_content: str | None,
    new_content: str,
) -> list[ValidationMessage]:
    """Validate content before writing to disk."""
    messages: list[ValidationMessage] = []

    # Check content is not empty (unless create_new with empty payload)
    if not new_content and plan.operation != PatchEngine.CREATE_NEW:
        messages.append(ValidationMessage("error", "New content is empty"))

    # Check for accidental truncation
    if original_content and new_content:
        if len(new_content) < len(original_content) * TRUNCATION_RATIO:
            messages.append(ValidationMessage(
                "warning",
                f"New content ({len(new_content)} bytes) is significantly "
                f"smaller than original ({len(original_content)} bytes) — "
                "possible accidental truncation",
            ))

    # Check reasonable size
    if len(new_content) > MAX_REASONABLE_SIZE:
        messages.append(ValidationMessage(
            "warning",
            f"New content is very large ({len(new_content)} bytes)",
        ))

    # Format-specific validity checks
    if plan.patch_engine in (PatchEngine.JSON_MERGE,):
        try:
            json.loads(new_content)
        except json.JSONDecodeError as exc:
            messages.append(ValidationMessage(
                "error", f"Result is not valid JSON: {exc}"
            ))

    if plan.patch_engine in (PatchEngine.TOML_UPDATE,):
        try:
            import tomllib
        except ImportError:
            try:
                import tomli as tomllib  # type: ignore[no-redef]
            except ImportError:
                tomllib = None  # type: ignore[assignment]
        if tomllib is not None:
            try:
                tomllib.loads(new_content)
            except Exception as exc:
                messages.append(ValidationMessage(
                    "error", f"Result is not valid TOML: {exc}"
                ))

    if plan.patch_engine in (PatchEngine.YAML_UPDATE,):
        try:
            import yaml
            yaml.safe_load(new_content)
        except ImportError:
            pass
        except Exception as exc:
            messages.append(ValidationMessage(
                "error", f"Result is not valid YAML: {exc}"
            ))

    return messages


def validate_post_write(
    plan: PatchPlan,
    path: Path,
) -> list[ValidationMessage]:
    """Validate after writing to disk."""
    messages: list[ValidationMessage] = []

    if not path.exists():
        messages.append(ValidationMessage("error", f"File not found after write: {path}"))
        return messages

    try:
        content = path.read_text(errors="replace")
    except OSError as exc:
        messages.append(ValidationMessage("error", f"Cannot read written file: {exc}"))
        return messages

    if not content and plan.operation != PatchEngine.CREATE_NEW:
        messages.append(ValidationMessage("error", "Written file is empty"))

    # Re-check format validity
    if plan.patch_engine == PatchEngine.JSON_MERGE:
        try:
            json.loads(content)
        except json.JSONDecodeError as exc:
            messages.append(ValidationMessage(
                "error", f"Written file is not valid JSON: {exc}"
            ))

    return messages

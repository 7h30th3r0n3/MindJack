"""Concrete patch engines for MindJack v2.

Each engine is a function:
    (original_content: str | None, payload: str, metadata: dict) -> str
returning the new file content.
"""

from __future__ import annotations

import json
from typing import Any, Callable

from mindjack.core.constants import PatchEngine
from mindjack.core.errors import MindJackError


class PatchEngineError(MindJackError):
    """Raised when a patch engine encounters an error."""


# ---------------------------------------------------------------------------
# Engine registry
# ---------------------------------------------------------------------------

_ENGINE_REGISTRY: dict[str, Callable[[str | None, str, dict], str]] = {}


def _register(name: str):
    """Decorator to register a patch engine function."""
    def decorator(fn: Callable[[str | None, str, dict], str]):
        _ENGINE_REGISTRY[name] = fn
        return fn
    return decorator


def get_engine(name: str) -> Callable[[str | None, str, dict], str]:
    """Look up a patch engine by name."""
    fn = _ENGINE_REGISTRY.get(name)
    if fn is None:
        raise PatchEngineError(f"Unknown patch engine: {name!r}")
    return fn


# ---------------------------------------------------------------------------
# append_text
# ---------------------------------------------------------------------------

@_register(PatchEngine.APPEND_TEXT)
def append_text(original: str | None, payload: str, metadata: dict) -> str:
    """Append payload to the end of the file with a separator marker."""
    base = original or ""
    separator = metadata.get("separator", "\n# --- MindJack appended ---\n")
    if base and not base.endswith("\n"):
        base += "\n"
    return base + separator + payload + "\n"


# ---------------------------------------------------------------------------
# insert_section
# ---------------------------------------------------------------------------

@_register(PatchEngine.INSERT_SECTION)
def insert_section(original: str | None, payload: str, metadata: dict) -> str:
    """Insert payload under a markdown heading.

    metadata["heading"] specifies the heading to insert after.
    If heading is not found, appends as a new section.
    """
    base = original or ""
    heading = metadata.get("heading", "")

    if heading and heading in base:
        # Find the line with the heading, insert payload after it
        lines = base.split("\n")
        result: list[str] = []
        inserted = False
        for line in lines:
            result.append(line)
            if not inserted and heading in line and line.strip().startswith("#"):
                # Insert payload after this heading line
                result.append("")
                result.append(payload)
                inserted = True
        if not inserted:
            result.append("")
            result.append(payload)
        return "\n".join(result)

    # Heading not found — append as new section
    if base and not base.endswith("\n"):
        base += "\n"
    section_heading = heading if heading else "## MindJack Injected Section"
    return base + f"\n{section_heading}\n\n{payload}\n"


# ---------------------------------------------------------------------------
# json_deep_merge
# ---------------------------------------------------------------------------

def _deep_merge(base: dict, overlay: dict) -> dict:
    """Recursively merge *overlay* into *base*, returning a new dict."""
    merged = dict(base)
    for key, value in overlay.items():
        if (
            key in merged
            and isinstance(merged[key], dict)
            and isinstance(value, dict)
        ):
            merged[key] = _deep_merge(merged[key], value)
        else:
            merged[key] = value
    return merged


@_register(PatchEngine.JSON_MERGE)
def json_deep_merge(original: str | None, payload: str, metadata: dict) -> str:
    """Parse original as JSON, deep-merge payload (also JSON), serialize back."""
    try:
        base_data = json.loads(original) if original else {}
    except json.JSONDecodeError as exc:
        raise PatchEngineError(f"Original content is not valid JSON: {exc}")

    try:
        overlay_data = json.loads(payload)
    except json.JSONDecodeError as exc:
        raise PatchEngineError(f"Payload is not valid JSON: {exc}")

    if isinstance(base_data, dict) and isinstance(overlay_data, dict):
        merged = _deep_merge(base_data, overlay_data)
    else:
        # If either isn't a dict, payload replaces original
        merged = overlay_data

    indent = metadata.get("indent", 2)
    return json.dumps(merged, indent=indent, ensure_ascii=False) + "\n"


# ---------------------------------------------------------------------------
# toml_update
# ---------------------------------------------------------------------------

def _simple_toml_serialize(data: dict, prefix: str = "") -> str:
    """Minimal TOML serializer (stdlib tomllib is read-only)."""
    lines: list[str] = []
    tables: list[tuple[str, dict]] = []

    for key, value in data.items():
        full_key = f"{prefix}.{key}" if prefix else key
        if isinstance(value, dict):
            tables.append((full_key, value))
        elif isinstance(value, bool):
            lines.append(f"{key} = {'true' if value else 'false'}")
        elif isinstance(value, int):
            lines.append(f"{key} = {value}")
        elif isinstance(value, float):
            lines.append(f"{key} = {value}")
        elif isinstance(value, str):
            escaped = value.replace("\\", "\\\\").replace('"', '\\"')
            lines.append(f'{key} = "{escaped}"')
        elif isinstance(value, list):
            items = json.dumps(value)
            lines.append(f"{key} = {items}")
        else:
            lines.append(f'{key} = "{value}"')

    result = "\n".join(lines)

    for table_key, table_data in tables:
        section = f"\n[{table_key}]\n" + _simple_toml_serialize(
            table_data, prefix=table_key
        )
        result += section

    return result


@_register(PatchEngine.TOML_UPDATE)
def toml_update(original: str | None, payload: str, metadata: dict) -> str:
    """Parse original as TOML, update keys from payload, serialize back."""
    try:
        import tomllib
    except ImportError:
        try:
            import tomli as tomllib  # type: ignore[no-redef]
        except ImportError:
            raise PatchEngineError(
                "tomllib (Python 3.11+) or tomli is required for TOML updates"
            )

    try:
        base_data = tomllib.loads(original) if original else {}
    except Exception as exc:
        raise PatchEngineError(f"Original content is not valid TOML: {exc}")

    # Payload is TOML text
    try:
        overlay_data = tomllib.loads(payload)
    except Exception as exc:
        raise PatchEngineError(f"Payload is not valid TOML: {exc}")

    merged = _deep_merge(base_data, overlay_data)
    return _simple_toml_serialize(merged) + "\n"


# ---------------------------------------------------------------------------
# yaml_update
# ---------------------------------------------------------------------------

@_register(PatchEngine.YAML_UPDATE)
def yaml_update(original: str | None, payload: str, metadata: dict) -> str:
    """Parse original as YAML, merge payload, serialize back."""
    try:
        import yaml
    except ImportError:
        raise PatchEngineError(
            "PyYAML is required for YAML updates (pip install pyyaml)"
        )

    try:
        base_data = yaml.safe_load(original) if original else {}
        if base_data is None:
            base_data = {}
    except Exception as exc:
        raise PatchEngineError(f"Original content is not valid YAML: {exc}")

    try:
        overlay_data = yaml.safe_load(payload)
        if overlay_data is None:
            overlay_data = {}
    except Exception as exc:
        raise PatchEngineError(f"Payload is not valid YAML: {exc}")

    if isinstance(base_data, dict) and isinstance(overlay_data, dict):
        merged = _deep_merge(base_data, overlay_data)
    else:
        merged = overlay_data

    return yaml.dump(merged, default_flow_style=False, allow_unicode=True)


# ---------------------------------------------------------------------------
# create_new
# ---------------------------------------------------------------------------

@_register(PatchEngine.CREATE_NEW)
def create_new(original: str | None, payload: str, metadata: dict) -> str:
    """Return payload as the full file content."""
    return payload


# ---------------------------------------------------------------------------
# replace_scalar
# ---------------------------------------------------------------------------

@_register(PatchEngine.REPLACE_SCALAR)
def replace_scalar(original: str | None, payload: str, metadata: dict) -> str:
    """Find and replace a specific value in the content.

    metadata["find"] — the string to find.
    payload — the replacement string.
    """
    base = original or ""
    find = metadata.get("find", "")
    if not find:
        raise PatchEngineError(
            "replace_scalar requires metadata['find'] to specify what to replace"
        )
    if find not in base:
        raise PatchEngineError(
            f"Value {find!r} not found in original content"
        )
    return base.replace(find, payload)


# ---------------------------------------------------------------------------
# prepend_frontmatter
# ---------------------------------------------------------------------------

@_register(PatchEngine.PREPEND_FRONTMATTER)
def prepend_frontmatter(original: str | None, payload: str, metadata: dict) -> str:
    """Add or update YAML frontmatter block at the top of a markdown file.

    payload is a YAML string that will be placed between --- delimiters.
    If frontmatter already exists, it is merged.
    """
    base = original or ""

    # Try merging with existing frontmatter
    if base.startswith("---"):
        parts = base.split("---", 2)
        if len(parts) >= 3:
            existing_fm = parts[1]
            body = parts[2]
            try:
                import yaml
                existing_data = yaml.safe_load(existing_fm) or {}
                new_data = yaml.safe_load(payload) or {}
                if isinstance(existing_data, dict) and isinstance(new_data, dict):
                    merged = _deep_merge(existing_data, new_data)
                    fm_text = yaml.dump(
                        merged, default_flow_style=False, allow_unicode=True
                    ).strip()
                    return f"---\n{fm_text}\n---{body}"
            except ImportError:
                pass
            except Exception:
                pass
            # Fallback: replace frontmatter entirely
            return f"---\n{payload.strip()}\n---{body}"

    # No existing frontmatter — prepend
    return f"---\n{payload.strip()}\n---\n\n{base}"

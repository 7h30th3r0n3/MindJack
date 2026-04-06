"""Base parser interface and dispatcher."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Protocol, runtime_checkable

from mindjack.core.constants import ParserType
from mindjack.core.errors import ParserError
from mindjack.core.models import DiscoveredArtifact


MAX_FILE_BYTES = 50 * 1024 * 1024  # 50 MB safety limit


@runtime_checkable
class ArtifactParser(Protocol):
    """Interface for artifact content parsers."""

    def can_parse(self, artifact: DiscoveredArtifact) -> bool: ...
    def parse(self, artifact: DiscoveredArtifact) -> dict[str, Any]: ...


def safe_read(path: Path) -> str | None:
    """Read a file with size limit."""
    try:
        if path.stat().st_size > MAX_FILE_BYTES:
            return None
        return path.read_text(errors="replace")
    except (OSError, PermissionError):
        return None


def parse_artifact(artifact: DiscoveredArtifact) -> dict[str, Any]:
    """Dispatch to the appropriate parser based on artifact type."""
    if not artifact.exists:
        return {"_status": "not_found", "path": str(artifact.path)}

    content = safe_read(artifact.path)
    if content is None:
        return {"_status": "unreadable", "path": str(artifact.path)}

    parser_map: dict[ParserType, _ParserFn] = {
        ParserType.JSON: _parse_json,
        ParserType.TOML: _parse_toml,
        ParserType.YAML: _parse_yaml,
        ParserType.MARKDOWN: _parse_markdown,
        ParserType.RAW_TEXT: _parse_raw,
    }

    fn = parser_map.get(artifact.parser_type, _parse_raw)
    try:
        return fn(content, artifact)
    except Exception as exc:
        return {"_status": "parse_error", "error": str(exc), "path": str(artifact.path)}


# Type alias for parser functions
type _ParserFn = Any  # Callable[[str, DiscoveredArtifact], dict[str, Any]]


def _parse_json(content: str, artifact: DiscoveredArtifact) -> dict[str, Any]:
    import json
    try:
        data = json.loads(content)
    except json.JSONDecodeError as exc:
        raise ParserError(f"Invalid JSON in {artifact.path}: {exc}") from exc
    return {
        "_status": "ok",
        "_parser": "json",
        "path": str(artifact.path),
        "data": data,
        "size_bytes": len(content),
    }


def _parse_toml(content: str, artifact: DiscoveredArtifact) -> dict[str, Any]:
    try:
        import tomllib
    except ImportError:
        import tomli as tomllib  # type: ignore[no-redef]
    try:
        data = tomllib.loads(content)
    except Exception as exc:
        raise ParserError(f"Invalid TOML in {artifact.path}: {exc}") from exc
    return {
        "_status": "ok",
        "_parser": "toml",
        "path": str(artifact.path),
        "data": data,
        "size_bytes": len(content),
    }


def _parse_yaml(content: str, artifact: DiscoveredArtifact) -> dict[str, Any]:
    # Use safe loading; yaml is stdlib-adjacent via PyYAML
    # Fall back to raw text if PyYAML not available
    try:
        import yaml
        data = yaml.safe_load(content)
    except ImportError:
        return _parse_raw(content, artifact)
    except Exception as exc:
        raise ParserError(f"Invalid YAML in {artifact.path}: {exc}") from exc
    return {
        "_status": "ok",
        "_parser": "yaml",
        "path": str(artifact.path),
        "data": data,
        "size_bytes": len(content),
    }


def _parse_markdown(content: str, artifact: DiscoveredArtifact) -> dict[str, Any]:
    """Parse markdown — extract frontmatter and section structure."""
    frontmatter: dict[str, Any] = {}
    body = content

    # Simple frontmatter extraction (YAML between --- delimiters)
    if content.startswith("---"):
        parts = content.split("---", 2)
        if len(parts) >= 3:
            try:
                import yaml
                frontmatter = yaml.safe_load(parts[1]) or {}
            except Exception:
                pass
            body = parts[2]

    # Extract headings as section structure
    sections = []
    for line in body.splitlines():
        stripped = line.strip()
        if stripped.startswith("#"):
            level = len(stripped) - len(stripped.lstrip("#"))
            title = stripped.lstrip("#").strip()
            sections.append({"level": level, "title": title})

    return {
        "_status": "ok",
        "_parser": "markdown",
        "path": str(artifact.path),
        "frontmatter": frontmatter,
        "sections": sections,
        "line_count": content.count("\n") + 1,
        "size_bytes": len(content),
    }


def _parse_raw(content: str, artifact: DiscoveredArtifact) -> dict[str, Any]:
    return {
        "_status": "ok",
        "_parser": "raw_text",
        "path": str(artifact.path),
        "line_count": content.count("\n") + 1,
        "size_bytes": len(content),
    }

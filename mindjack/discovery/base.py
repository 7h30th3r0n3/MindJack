"""Base protocol and helpers for tool discovery plugins."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Protocol, runtime_checkable

from mindjack.core.constants import ArtifactState, ParserType, ScopeLevel, SurfaceType
from mindjack.core.models import DiscoveredArtifact, ToolDescriptor, TrustSurface
from mindjack.core.scope import Scope


@runtime_checkable
class ToolPlugin(Protocol):
    """Interface every discovery plugin must implement."""

    slug: str
    descriptor: ToolDescriptor

    def detect(self, scope: Scope) -> list[DiscoveredArtifact]: ...

    def classify(self, artifact: DiscoveredArtifact) -> list[TrustSurface]: ...


# ---------------------------------------------------------------------------
# Shared helpers for plugin implementations
# ---------------------------------------------------------------------------

HOME = Path.home()

_PROJECT_DIRS_CACHE: list[Path] | None = None


def find_project_dirs(scope: Scope) -> list[Path]:
    """Find directories that look like code projects within scope."""
    global _PROJECT_DIRS_CACHE
    if _PROJECT_DIRS_CACHE is not None:
        return _PROJECT_DIRS_CACHE

    dirs: set[Path] = set()
    search_roots = scope.paths if scope.paths else [HOME]
    markers = {".git", "package.json", "pyproject.toml", "Cargo.toml", "go.mod", "pom.xml"}
    skip_dirs = {
        "node_modules", "__pycache__", ".git", "venv", ".venv",
        "AppData", "Windows", "Program Files", ".cache", ".local",
        ".codex", ".claude", ".continue", ".cursor", ".codeium",
    }

    max_depth = 3
    for root in search_roots:
        if not root.exists():
            continue
        root_depth = len(root.resolve().parts)
        for dirpath, dirnames, filenames in os.walk(root):
            current_depth = len(Path(dirpath).resolve().parts) - root_depth
            if current_depth >= max_depth:
                dirnames.clear()
                continue
            if markers & set(filenames + dirnames):
                p = Path(dirpath)
                if scope.contains(p):
                    dirs.add(p)
            dirnames[:] = [
                d for d in dirnames
                if d not in skip_dirs and not d.startswith(".")
            ]

    _PROJECT_DIRS_CACHE = sorted(dirs)
    return _PROJECT_DIRS_CACHE


def reset_project_cache() -> None:
    """Clear the cached project dirs (useful for testing)."""
    global _PROJECT_DIRS_CACHE
    _PROJECT_DIRS_CACHE = None


def artifact_if_accessible(
    *,
    tool_slug: str,
    surface_type: SurfaceType,
    scope_level: ScopeLevel,
    path: Path,
    parser_type: ParserType,
    confidence: float = 0.9,
    precedence_rank: int | None = None,
    description: str = "",
    tags: list[str] | None = None,
    metadata: dict | None = None,
) -> DiscoveredArtifact | None:
    """Create a DiscoveredArtifact if the file or its parent exists."""
    exists = path.exists()
    parent_exists = path.parent.exists()
    if not exists and not parent_exists:
        return None

    state = ArtifactState.ACTIVE if exists else ArtifactState.ARTIFACT_ONLY

    return DiscoveredArtifact(
        tool_slug=tool_slug,
        surface_type=surface_type,
        scope=scope_level,
        path=path,
        exists=exists,
        parser_type=parser_type,
        confidence=confidence if exists else confidence * 0.5,
        precedence_rank=precedence_rank,
        state=state,
        description=description,
        tags=tags or [],
        metadata=metadata or {},
    )


def safe_iterdir(path: Path):
    """iterdir() that silently skips permission errors."""
    try:
        yield from path.iterdir()
    except PermissionError:
        pass

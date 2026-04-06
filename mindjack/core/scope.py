"""Scope validation and resolution."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from .constants import ScopeLevel
from .errors import ScopeError

HOME = Path.home()


@dataclass
class Scope:
    """Defines the boundary for a MindJack operation."""

    paths: list[Path] = field(default_factory=list)
    allow_home: bool = False
    allow_user_scope: bool = True
    allow_project_scope: bool = True

    def __post_init__(self) -> None:
        resolved = []
        for p in self.paths:
            rp = p.resolve()
            if rp == HOME and not self.allow_home:
                raise ScopeError(
                    f"Scope includes $HOME ({HOME}). "
                    "Pass --allow-home-scope to permit this."
                )
            resolved.append(rp)
        self.paths = resolved

    def contains(self, path: Path) -> bool:
        """Check if a path falls within any scoped directory."""
        rp = path.resolve()
        # User-level artifacts are always in scope if allow_user_scope
        if self.allow_user_scope and _is_user_config(rp):
            return True
        if not self.paths:
            return True  # no explicit scope = everything
        return any(
            rp == sp or sp in rp.parents
            for sp in self.paths
        )

    def classify(self, path: Path) -> ScopeLevel:
        """Classify a path into a scope level."""
        rp = path.resolve()
        if _is_user_config(rp):
            return ScopeLevel.USER
        # If inside a scoped project path, it's project scope
        for sp in self.paths:
            if rp == sp or sp in rp.parents:
                return ScopeLevel.PROJECT
        # Fallback heuristics
        if _is_user_config(rp):
            return ScopeLevel.USER
        return ScopeLevel.PROJECT


def _is_user_config(path: Path) -> bool:
    """Return True if path looks like a user-level config directory."""
    user_dirs = (
        HOME / ".claude",
        HOME / ".codex",
        HOME / ".cursor",
        HOME / ".continue",
        HOME / ".codeium",
        HOME / ".aws" / "amazonq",
        HOME / ".roo",
        HOME / ".config" / "Code",
    )
    return any(
        path == d or d in path.parents
        for d in user_dirs
    )

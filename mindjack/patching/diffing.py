"""Diff generation using stdlib difflib."""

from __future__ import annotations

import difflib


def generate_diff(
    original: str | None,
    new: str,
    path: str,
) -> str:
    """Generate a unified diff string.

    Parameters
    ----------
    original:
        The original file content, or None for new files.
    new:
        The new file content.
    path:
        The file path (used in diff headers).

    Returns
    -------
    A unified-diff formatted string.
    """
    original_lines = (original or "").splitlines(keepends=True)
    new_lines = new.splitlines(keepends=True)

    from_label = f"a/{path}" if original is not None else "/dev/null"
    to_label = f"b/{path}"

    diff = difflib.unified_diff(
        original_lines,
        new_lines,
        fromfile=from_label,
        tofile=to_label,
        lineterm="",
    )

    return "".join(line if line.endswith("\n") else line + "\n" for line in diff)

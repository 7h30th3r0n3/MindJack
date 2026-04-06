"""Safe atomic file writing."""

from __future__ import annotations

import os
import tempfile
from pathlib import Path

from mindjack.core.errors import MindJackError


class AtomicWriteError(MindJackError):
    """Raised when an atomic write fails."""


def atomic_write(path: Path, content: str) -> None:
    """Write *content* to *path* atomically.

    Writes to a temporary file in the same directory, then uses
    ``os.replace()`` to swap it in.  This ensures that partial writes
    never corrupt the original file.
    """
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)

    fd = None
    tmp_path = None
    try:
        fd, tmp_path = tempfile.mkstemp(
            dir=str(target.parent),
            prefix=f".mindjack_{target.name}_",
            suffix=".tmp",
        )
        os.write(fd, content.encode("utf-8"))
        os.fsync(fd)
        os.close(fd)
        fd = None

        # Preserve original permissions if the file already exists
        if target.exists():
            stat = target.stat()
            os.chmod(tmp_path, stat.st_mode)

        os.replace(tmp_path, str(target))
        tmp_path = None  # successfully replaced, no cleanup needed
    except OSError as exc:
        raise AtomicWriteError(
            f"Atomic write failed for {path}: {exc}"
        ) from exc
    finally:
        if fd is not None:
            try:
                os.close(fd)
            except OSError:
                pass
        if tmp_path is not None:
            try:
                os.unlink(tmp_path)
            except OSError:
                pass

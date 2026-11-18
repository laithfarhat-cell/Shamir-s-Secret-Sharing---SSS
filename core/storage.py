"""Private-by-default filesystem helpers.

Secret material must never be world-readable, and half-written share files must
never be mistaken for complete ones.  Every write in this toolkit therefore goes
through :func:`atomic_write_bytes`, which

1. creates directories with mode ``0700``,
2. writes the payload to a ``0600`` temporary file in the *same* directory,
3. ``fsync``s it, and
4. atomically ``os.replace``s it into place.

A crash or a full disk can therefore leave a stray temporary file, but never a
truncated share or a corrupted vault.
"""

from __future__ import annotations

import os
import stat
import tempfile
from pathlib import Path
from typing import Union

from core.errors import OutputError

__all__ = [
    "secure_makedirs",
    "atomic_write_bytes",
    "atomic_write_text",
    "secure_read_bytes",
    "wipe",
    "PRIVATE_FILE_MODE",
    "PRIVATE_DIR_MODE",
]

PRIVATE_FILE_MODE = 0o600
PRIVATE_DIR_MODE = 0o700

PathLike = Union[str, os.PathLike]


def secure_makedirs(path: PathLike) -> Path:
    """Create ``path`` (and any missing ancestors) with ``0700`` permissions.

    ``mkdir(parents=True)`` only applies the requested mode to the final
    component, so every newly created ancestor is tightened afterwards.  Paths
    that already existed are never touched -- a caller's pre-existing directory
    keeps its own policy.
    """
    target = Path(path)
    if target.exists():
        if not target.is_dir():
            raise OutputError(f"{target} exists and is not a directory")
        return target

    missing = []
    current = target
    while not current.exists():
        missing.append(current)
        if current.parent == current:  # pragma: no cover - filesystem root
            break
        current = current.parent
    try:
        target.mkdir(mode=PRIVATE_DIR_MODE, parents=True, exist_ok=True)
    except OSError as exc:
        raise OutputError(f"cannot create directory {target}: {exc}") from exc
    for created in missing:
        _restrict(created, PRIVATE_DIR_MODE)
    return target


def atomic_write_bytes(
    path: PathLike,
    data: bytes,
    *,
    mode: int = PRIVATE_FILE_MODE,
    force: bool = True,
) -> Path:
    """Atomically write ``data`` to ``path`` with restrictive permissions."""
    target = Path(path)
    parent = target.parent if str(target.parent) else Path(".")
    if parent and not parent.exists():
        secure_makedirs(parent)
    if target.exists() and not force:
        raise OutputError(f"refusing to overwrite existing file {target} (use --force)")
    if target.is_dir():
        raise OutputError(f"{target} is a directory")

    file_descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{target.name}.", suffix=".tmp", dir=str(parent)
    )
    temporary = Path(temporary_name)
    try:
        if hasattr(os, "fchmod"):  # not available on Windows
            os.fchmod(file_descriptor, mode)
        with os.fdopen(file_descriptor, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, target)
        _restrict(target, mode)
    except OSError as exc:
        try:
            temporary.unlink(missing_ok=True)
        except OSError:  # pragma: no cover - best effort cleanup
            pass
        raise OutputError(f"cannot write {target}: {exc}") from exc
    return target


def atomic_write_text(
    path: PathLike,
    text: str,
    *,
    mode: int = PRIVATE_FILE_MODE,
    force: bool = True,
    newline: str = "\n",
) -> Path:
    """Atomically write UTF-8 text, normalising line endings to ``newline``."""
    normalised = text.replace("\r\n", "\n").replace("\r", "\n")
    if newline != "\n":
        normalised = normalised.replace("\n", newline)
    return atomic_write_bytes(path, normalised.encode("utf-8"), mode=mode, force=force)


def secure_read_bytes(path: PathLike, *, max_bytes: int = 64 * 1024 * 1024) -> bytes:
    """Read a file defensively, refusing directories and absurd sizes."""
    target = Path(path)
    try:
        info = target.stat()
    except OSError as exc:
        raise OutputError(f"cannot read {target}: {exc}") from exc
    if not stat.S_ISREG(info.st_mode):
        raise OutputError(f"{target} is not a regular file")
    if info.st_size > max_bytes:
        raise OutputError(
            f"{target} is {info.st_size} bytes, above the {max_bytes}-byte safety limit"
        )
    try:
        return target.read_bytes()
    except OSError as exc:
        raise OutputError(f"cannot read {target}: {exc}") from exc


def _restrict(path: Path, mode: int) -> None:
    """Best-effort permission tightening (no-op on platforms without POSIX modes)."""
    try:
        os.chmod(path, mode)
    except OSError:  # pragma: no cover - Windows / exotic filesystems
        pass


def wipe(buffer: bytearray) -> None:
    """Overwrite a :class:`bytearray` in place as a best-effort zeroisation.

    Python ``bytes`` objects are immutable and may be copied by the runtime, so
    this is *not* a guarantee that no copy of the secret survives in memory.
    It does, however, remove the long-lived working buffers this library
    controls.  See ``THEORY.md`` ("Threat model and side channels").
    """
    if isinstance(buffer, bytearray):
        for index in range(len(buffer)):
            buffer[index] = 0

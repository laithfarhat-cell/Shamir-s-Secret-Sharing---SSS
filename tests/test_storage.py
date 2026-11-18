"""Tests for the private-file helpers in :mod:`core.storage`."""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from core.errors import OutputError
from core.storage import (
    atomic_write_bytes,
    atomic_write_text,
    secure_makedirs,
    secure_read_bytes,
    wipe,
)

posix_only = pytest.mark.skipif(os.name != "posix", reason="POSIX permission bits required")


def test_atomic_write_creates_private_file(tmp_path):
    path = tmp_path / "secret.bin"
    atomic_write_bytes(path, b"payload")
    assert path.read_bytes() == b"payload"
    assert not list(tmp_path.glob("*.tmp"))


@posix_only
def test_atomic_write_modes(tmp_path):
    path = atomic_write_bytes(tmp_path / "file", b"x")
    assert path.stat().st_mode & 0o777 == 0o600
    assert oct(tmp_path.stat().st_mode & 0o777) == "0o700"


def test_atomic_write_refuses_overwrite(tmp_path):
    path = tmp_path / "file"
    atomic_write_bytes(path, b"first")
    with pytest.raises(OutputError, match="refusing to overwrite"):
        atomic_write_bytes(path, b"second", force=False)
    assert path.read_bytes() == b"first"
    atomic_write_bytes(path, b"third", force=True)
    assert path.read_bytes() == b"third"


def test_atomic_write_rejects_directory_target(tmp_path):
    with pytest.raises(OutputError, match="directory"):
        atomic_write_bytes(tmp_path, b"x")


@posix_only
def test_nested_directories_are_private(tmp_path):
    target = tmp_path / "a" / "b" / "c" / "file.txt"
    atomic_write_text(target, "hello")
    assert target.read_text() == "hello"
    for directory in (tmp_path / "a", tmp_path / "a" / "b", tmp_path / "a" / "b" / "c"):
        assert directory.stat().st_mode & 0o777 == 0o700, directory


def test_atomic_write_text_normalises_newlines(tmp_path):
    path = tmp_path / "text"
    atomic_write_text(path, "a\r\nb\rc\n", newline="\n")
    assert path.read_bytes() == b"a\nb\nc\n"
    atomic_write_text(path, "a\nb\n", newline="\r\n", force=True)
    assert path.read_bytes() == b"a\r\nb\r\n"


def test_secure_makedirs_is_idempotent(tmp_path):
    created = secure_makedirs(tmp_path / "shares")
    assert created.is_dir()
    assert secure_makedirs(created) == created


def test_secure_makedirs_rejects_file(tmp_path):
    file_path = tmp_path / "file"
    file_path.write_text("x")
    with pytest.raises(OutputError, match="not a directory"):
        secure_makedirs(file_path)


def test_secure_read_bytes(tmp_path):
    path = tmp_path / "data"
    path.write_bytes(b"abc")
    assert secure_read_bytes(path) == b"abc"
    with pytest.raises(OutputError, match="not a regular file"):
        secure_read_bytes(tmp_path)
    with pytest.raises(OutputError, match="safety limit"):
        secure_read_bytes(path, max_bytes=2)
    with pytest.raises(OutputError, match="cannot read"):
        secure_read_bytes(tmp_path / "missing")


def test_wipe_zeroes_bytearray():
    buffer = bytearray(b"super secret")
    wipe(buffer)
    assert buffer == bytearray(len(buffer))
    # Non-bytearray input is a no-op rather than an error.
    wipe(b"immutable")  # type: ignore[arg-type]


def test_paths_accept_strings(tmp_path):
    path = atomic_write_bytes(str(tmp_path / "str-path"), b"x")
    assert isinstance(path, Path)
    assert str(path).endswith("str-path")

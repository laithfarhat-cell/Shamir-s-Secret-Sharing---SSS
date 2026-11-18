"""Tests for the hybrid AES-256-GCM + Shamir file vault."""

from __future__ import annotations

import hashlib
import json
import secrets
from pathlib import Path

import pytest

pytest.importorskip("cryptography", reason="vault mode requires the cryptography package")

from core.errors import (
    ChecksumError,
    CommitmentError,
    OutputError,
    ShareConsistencyError,
    ThresholdError,
    VaultError,
)
from core.shamir import combine
from core.vault import (
    DEK_BYTES,
    MAGIC,
    VaultHeader,
    _safe_filename,
    lock_file,
    parse_envelope,
    read_vault_header,
    unlock_file,
)


@pytest.fixture
def source_file(tmp_path: Path) -> Path:
    path = tmp_path / "payload.bin"
    path.write_bytes(b"top secret archive\n" + secrets.token_bytes(4096))
    return path


@pytest.fixture
def locked(tmp_path: Path, source_file: Path):
    out_dir = tmp_path / "vault"
    result = lock_file(source_file, threshold=3, total=5, out_dir=out_dir)
    return result


def _text_shares(result) -> list[Path]:
    return [path for path in result.share_paths if path.suffix == ".txt"]


# ---------------------------------------------------------------------------
# Round trip
# ---------------------------------------------------------------------------
def test_lock_unlock_roundtrip(tmp_path, source_file, locked):
    output = tmp_path / "restored.bin"
    result = unlock_file(locked.vault_path, _text_shares(locked)[:3], out_path=output)
    assert output.read_bytes() == source_file.read_bytes()
    assert result.plaintext_size == source_file.stat().st_size
    assert result.shares_used == 3
    assert result.commitment_verified is True
    assert result.header.threshold == 3 and result.header.total == 5
    assert oct(output.stat().st_mode & 0o777) == "0o600"


def test_unlock_accepts_share_objects_and_strings(tmp_path, locked):
    output = tmp_path / "restored2.bin"
    shares = locked.shares[:3]
    result = unlock_file(
        locked.vault_path,
        [shares[0], shares[1].to_armored(), shares[2].to_dict()],
        out_path=output,
    )
    assert output.exists() and result.shares_used == 3


def test_unlock_with_all_shares(tmp_path, locked):
    output = tmp_path / "restored3.bin"
    result = unlock_file(locked.vault_path, _text_shares(locked), out_path=output)
    assert result.shares_used == 5


def test_vault_files_are_private(locked):
    assert oct(locked.vault_path.stat().st_mode & 0o777) == "0o600"
    assert oct(locked.vault_path.parent.stat().st_mode & 0o777) == "0o700"
    for path in locked.share_paths:
        assert oct(path.stat().st_mode & 0o777) == "0o600"


def test_header_metadata(locked, source_file):
    header, size = read_vault_header(locked.vault_path)
    assert header.cipher == "AES-256-GCM"
    assert header.field == "m521"
    assert header.secret_bytes == DEK_BYTES
    assert header.original_name == source_file.name
    assert header.original_size == source_file.stat().st_size
    assert header.plaintext_sha256 == hashlib.sha256(source_file.read_bytes()).hexdigest()
    assert header.created_at.endswith("Z")
    assert size == locked.vault_path.stat().st_size


def test_dek_commitment_matches_shares(locked):
    header, _ = read_vault_header(locked.vault_path)
    combined = combine(locked.shares[:3])
    assert hashlib.sha256(combined.secret).hexdigest() == header.dek_commitment
    assert all(share.commitment == header.dek_commitment for share in locked.shares)
    assert locked.split.secret_length == DEK_BYTES


def test_envelope_structure(locked):
    data = locked.vault_path.read_bytes()
    assert data.startswith(MAGIC)
    header, header_bytes, ciphertext = parse_envelope(data)
    assert header.threshold == 3
    assert header_bytes == json.dumps(
        header.to_dict(), sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode()
    assert len(ciphertext) == header.original_size + 16  # GCM tag


def test_large_file_roundtrip(tmp_path):
    source = tmp_path / "large.dat"
    source.write_bytes(secrets.token_bytes(1024 * 1024))
    result = lock_file(source, threshold=2, total=3, out_dir=tmp_path / "v")
    output = tmp_path / "restored.dat"
    unlock_file(result.vault_path, _text_shares(result)[:2], out_path=output)
    assert output.read_bytes() == source.read_bytes()


@pytest.mark.parametrize("fmt", ["armored", "json", "both"])
def test_share_formats(tmp_path, source_file, fmt):
    result = lock_file(source_file, threshold=2, total=4, out_dir=tmp_path / fmt, fmt=fmt)
    shares = [path for path in result.share_paths if path.suffix in (".txt", ".json")]
    expected = 4 * (1 if fmt == "armored" else 2 if fmt == "both" else 1)
    assert len(shares) == expected
    quorum = [path for path in shares if path.suffix == ".txt"][:2] if fmt == "both" else shares[:2]
    output = tmp_path / f"out-{fmt}.bin"
    unlock_file(result.vault_path, quorum, out_path=output)
    assert output.read_bytes() == source_file.read_bytes()


def test_labels_flow_into_share_files(tmp_path, source_file):
    result = lock_file(
        source_file,
        threshold=2,
        total=3,
        out_dir=tmp_path / "labels",
        labels=["Alice", "Bob", "Carol"],
    )
    labels = [json.loads(path.read_text()).get("label") for path in result.share_paths if path.suffix == ".json"]
    assert labels == ["Alice", "Bob", "Carol"]


def test_unlock_default_output_name(tmp_path, source_file, locked, monkeypatch):
    workdir = tmp_path / "cwd"
    workdir.mkdir()
    monkeypatch.chdir(workdir)
    result = unlock_file(locked.vault_path, _text_shares(locked)[:3])
    assert result.output_path.name == source_file.name
    assert result.output_path.read_bytes() == source_file.read_bytes()


def test_unlock_refuses_to_overwrite(tmp_path, source_file, locked):
    output = tmp_path / "existing.bin"
    output.write_bytes(b"do not clobber me")
    with pytest.raises(OutputError):
        unlock_file(locked.vault_path, _text_shares(locked)[:3], out_path=output)
    assert output.read_bytes() == b"do not clobber me"
    unlock_file(locked.vault_path, _text_shares(locked)[:3], out_path=output, force=True)
    assert output.read_bytes() == source_file.read_bytes()


def test_unlock_into_directory_uses_original_name(tmp_path, source_file, locked):
    target_dir = tmp_path / "restore"
    target_dir.mkdir()
    result = unlock_file(locked.vault_path, _text_shares(locked)[:3], out_path=target_dir)
    assert result.output_path == target_dir / source_file.name


# ---------------------------------------------------------------------------
# Failure modes
# ---------------------------------------------------------------------------
def test_insufficient_shares(tmp_path, locked):
    with pytest.raises(ThresholdError):
        unlock_file(locked.vault_path, _text_shares(locked)[:2], out_path=tmp_path / "x")


def test_duplicate_shares(tmp_path, locked):
    shares = _text_shares(locked)
    with pytest.raises(ShareConsistencyError):
        unlock_file(locked.vault_path, [shares[0], shares[0], shares[1]], out_path=tmp_path / "x")


def test_tampered_ciphertext(tmp_path, locked):
    raw = bytearray(locked.vault_path.read_bytes())
    raw[-20] ^= 0x01
    tampered = tmp_path / "tampered.vault"
    tampered.write_bytes(raw)
    with pytest.raises(VaultError, match="authentication failed"):
        unlock_file(tampered, _text_shares(locked)[:3], out_path=tmp_path / "x")


def test_tampered_header_is_rejected(tmp_path, locked):
    header, _ = read_vault_header(locked.vault_path)
    raw = locked.vault_path.read_bytes()
    # Flip one hex digit of the plaintext digest: still valid JSON, still 64 chars.
    original = header.plaintext_sha256.encode()
    replacement = (b"0" if original[:1] != b"0" else b"1") + original[1:]
    tampered_bytes = raw.replace(original, replacement, 1)
    assert tampered_bytes != raw
    tampered = tmp_path / "header.vault"
    tampered.write_bytes(tampered_bytes)
    with pytest.raises(VaultError, match="authentication failed"):
        unlock_file(tampered, _text_shares(locked)[:3], out_path=tmp_path / "x")


def test_tampered_magic(tmp_path, locked):
    raw = bytearray(locked.vault_path.read_bytes())
    raw[0] ^= 0xFF
    tampered = tmp_path / "magic.vault"
    tampered.write_bytes(raw)
    with pytest.raises(VaultError, match="magic"):
        read_vault_header(tampered)


def test_truncated_vault(tmp_path, locked):
    raw = locked.vault_path.read_bytes()
    truncated = tmp_path / "truncated.vault"
    truncated.write_bytes(raw[: len(MAGIC) + 2])
    with pytest.raises(VaultError, match="truncated"):
        read_vault_header(truncated)
    truncated.write_bytes(raw[: len(MAGIC) + 4 + 4])
    with pytest.raises(VaultError):
        read_vault_header(truncated)


def test_invalid_header_json(tmp_path):
    header = b"{}"
    blob = MAGIC + len(header).to_bytes(4, "big") + header + b"\x00" * 32
    path = tmp_path / "bad.vault"
    path.write_bytes(blob)
    with pytest.raises(VaultError):
        read_vault_header(path)


def test_wrong_vault_shares_are_rejected(tmp_path, source_file, locked):
    other_source = tmp_path / "other.bin"
    other_source.write_bytes(b"another payload")
    other = lock_file(other_source, threshold=3, total=5, out_dir=tmp_path / "other")
    with pytest.raises((CommitmentError, VaultError)):
        unlock_file(locked.vault_path, _text_shares(other)[:3], out_path=tmp_path / "x")


def test_header_cipher_validation():
    with pytest.raises(VaultError):
        VaultHeader.from_dict({"version": 1})

    base = {
        "version": 1,
        "cipher": "CHACHA20",
        "nonce": "AAAAAAAAAAAAAAAA",
        "dek_commitment": "00" * 32,
        "secret_bytes": 32,
        "threshold": 2,
        "total": 3,
        "field": "m521",
        "original_name": "x",
        "original_size": 1,
        "plaintext_sha256": "00" * 32,
        "created_at": "now",
    }
    with pytest.raises(VaultError, match="cipher"):
        VaultHeader.from_dict(base)
    base["cipher"] = "AES-256-GCM"
    base["threshold"] = 9
    with pytest.raises(VaultError, match="invalid"):
        VaultHeader.from_dict(base)
    base["threshold"] = 2
    base["secret_bytes"] = 16
    with pytest.raises(VaultError, match="DEK"):
        VaultHeader.from_dict(base)


def test_empty_file_rejected(tmp_path):
    source = tmp_path / "empty"
    source.write_bytes(b"")
    with pytest.raises(VaultError, match="empty"):
        lock_file(source, threshold=2, total=3, out_dir=tmp_path)


def test_missing_file_rejected(tmp_path):
    with pytest.raises(VaultError):
        lock_file(tmp_path / "nope.bin", threshold=2, total=3, out_dir=tmp_path)


def test_lock_refuses_overwrite(tmp_path, source_file):
    lock_file(source_file, threshold=2, total=3, out_dir=tmp_path)
    with pytest.raises(OutputError):
        lock_file(source_file, threshold=2, total=3, out_dir=tmp_path)
    lock_file(source_file, threshold=2, total=3, out_dir=tmp_path, force=True)


@pytest.mark.parametrize("name", ["../evil", "/etc/passwd", "..", "", "."])
def test_safe_filename_blocks_traversal(name):
    assert "/" not in _safe_filename(name)
    assert _safe_filename(name) not in ("", ".", "..")


def test_vault_share_commitment_is_not_the_plaintext_hash(locked, source_file):
    header, _ = read_vault_header(locked.vault_path)
    assert header.dek_commitment != header.plaintext_sha256
    assert header.dek_commitment == locked.split.commitment


def test_intermediate_dek_never_appears_in_share_files(locked):
    combined = combine(locked.shares[:3])
    dek_hex = combined.secret.hex()
    for path in locked.share_paths:
        assert dek_hex not in path.read_text()


def test_lock_result_repr_is_safe(locked):
    assert "VaultLockResult" in repr(locked)
    assert "redacted" not in repr(locked).lower()


# ---------------------------------------------------------------------------
# Header and envelope hardening
# ---------------------------------------------------------------------------
def _base_header_dict():
    return {
        "version": 1,
        "cipher": "AES-256-GCM",
        "nonce": "AAAAAAAAAAAAAAAA",
        "dek_commitment": "00" * 32,
        "secret_bytes": 32,
        "threshold": 2,
        "total": 3,
        "field": "m521",
        "original_name": "x.bin",
        "original_size": 1,
        "plaintext_sha256": "11" * 32,
        "created_at": "2026-01-01T00:00:00Z",
    }


@pytest.mark.parametrize(
    "key",
    [
        "version",
        "cipher",
        "nonce",
        "dek_commitment",
        "secret_bytes",
        "threshold",
        "total",
        "field",
        "original_name",
        "original_size",
        "plaintext_sha256",
        "created_at",
    ],
)
def test_header_requires_every_key(key):
    data = _base_header_dict()
    del data[key]
    with pytest.raises(VaultError, match="missing"):
        VaultHeader.from_dict(data)


def test_header_field_validation():
    cases = [
        ({"version": 2}, "version"),
        ({"nonce": "AAAA"}, "nonce"),
        ({"dek_commitment": "zz" * 32}, "dek_commitment"),
        ({"plaintext_sha256": "nothex"}, "plaintext_sha256"),
        ({"original_size": -1}, "original_size"),
        ({"original_name": 5}, "original_name"),
        ({"field": 5}, "field"),
        ({"threshold": "2"}, "threshold"),
        ({"total": 999}, "invalid"),
    ]
    for patch, message in cases:
        data = _base_header_dict()
        data.update(patch)
        with pytest.raises(VaultError, match=message):
            VaultHeader.from_dict(data)


def test_envelope_rejects_bad_header_lengths(tmp_path):
    for header_length in (0, 10**6):
        blob = MAGIC + header_length.to_bytes(4, "big") + b"{}" + b"\x00" * 32
        path = tmp_path / "bad-length.vault"
        path.write_bytes(blob)
        with pytest.raises(VaultError):
            parse_envelope(path.read_bytes())


def test_envelope_requires_gcm_tag():
    header = json.dumps(_base_header_dict(), sort_keys=True, separators=(",", ":")).encode()
    blob = MAGIC + len(header).to_bytes(4, "big") + header + b"\x00" * 8
    with pytest.raises(VaultError, match="truncated"):
        parse_envelope(blob)


def test_unlock_rejects_corrupt_share_file(tmp_path, locked):
    shares = _text_shares(locked)
    path = shares[0]
    text = path.read_text()
    lines = text.splitlines()
    armored = lines[-1]
    parts = armored.split("-")
    payload = list(parts[7])
    # Flip a low-order bit so the value stays a canonical field element and the
    # checksum (not the range check) is what catches the corruption.
    payload[-3] = "B" if payload[-3] != "B" else "C"
    parts[7] = "".join(payload)
    path.write_text("\n".join(lines[:-1] + ["-".join(parts)]) + "\n")
    with pytest.raises(ChecksumError):
        unlock_file(locked.vault_path, shares[:3], out_path=tmp_path / "x")


def test_lock_file_rejects_unknown_field(tmp_path, source_file):
    from core.errors import FieldError

    with pytest.raises(FieldError):
        lock_file(source_file, threshold=2, total=3, out_dir=tmp_path / "f", field="m1024")


def test_lock_file_validates_parameters(tmp_path, source_file):
    from core.errors import ShareFormatError

    with pytest.raises(ShareFormatError):
        lock_file(source_file, threshold=1, total=3, out_dir=tmp_path / "p")
    with pytest.raises(ShareFormatError):
        lock_file(source_file, threshold=4, total=3, out_dir=tmp_path / "p")


def test_vault_mode_requires_cryptography(tmp_path, source_file, monkeypatch):
    import sys

    from core.errors import DependencyError

    for module in (
        "cryptography",
        "cryptography.exceptions",
        "cryptography.hazmat",
        "cryptography.hazmat.primitives",
        "cryptography.hazmat.primitives.ciphers",
        "cryptography.hazmat.primitives.ciphers.aead",
    ):
        monkeypatch.setitem(sys.modules, module, None)
    with pytest.raises(DependencyError, match="cryptography"):
        lock_file(source_file, threshold=2, total=3, out_dir=tmp_path / "dep")

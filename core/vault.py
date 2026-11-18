"""Hybrid file vault: AES-256-GCM envelope encryption + Shamir-protected DEK.

Splitting a whole file with Shamir directly would be both slow and wasteful:
every share would be as large as the file.  Instead this module uses *envelope
encryption*:

1. draw a fresh 256-bit Data Encryption Key (``DEK``) from the OS CSPRNG,
2. encrypt the file with AES-256-GCM under that DEK and a 96-bit random nonce,
3. split **only the 32-byte DEK** into ``n`` Shamir shares with threshold ``k``,
4. store the ciphertext next to an authenticated header inside a single
   ``.vault`` file.

Recovery is the mirror image: ``k`` shares rebuild the DEK, the DEK verifies
against the commitment written into the authenticated header, and GCM's tag
proves that the file (and header) are byte-for-byte intact.

Envelope layout (binary, big-endian)::

    +----------------+----------------+---------------------+------------------+
    | magic (8)      | header_len (4) | header JSON (utf-8) | ciphertext||tag  |
    | "SSSVLT01"     | uint32         | canonical JSON      | AES-256-GCM      |
    +----------------+----------------+---------------------+------------------+

The magic, length prefix and header are fed to GCM as *associated data*, so any
modification of the metadata (threshold, nonce, original filename, commitment)
is detected before decryption is attempted.

Security notes
--------------
* The nonce is random per lock; a DEK is used exactly once, so nonce reuse
  across messages under the same key cannot occur.
* The DEK commitment ``SHA-256(DEK)`` is safe to publish: the DEK has 256 bits
  of entropy, so the hash is not a guessing oracle.
* The vault file is created with mode ``0600``; shares likewise.
* Files are held in memory while being locked/unlocked (see README limits).
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import json
import secrets
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple, Union

from core.errors import DependencyError, OutputError, VaultError
from core.shamir import (
    CombineResult,
    Share,
    SplitResult,
    combine,
    load_share_inputs,
    split,
    write_share_files,
)
from core.storage import atomic_write_bytes, secure_makedirs, secure_read_bytes, wipe

__all__ = [
    "MAGIC",
    "DEK_BYTES",
    "NONCE_BYTES",
    "VaultHeader",
    "VaultLockResult",
    "VaultUnlockResult",
    "lock_file",
    "unlock_file",
    "read_vault_header",
    "VAULT_SUFFIX",
]

MAGIC = b"SSSVLT01"
VAULT_SUFFIX = ".vault"
DEK_BYTES = 32
NONCE_BYTES = 12
MAX_HEADER_BYTES = 64 * 1024
MAX_VAULT_BYTES = 2 * 1024 * 1024 * 1024  # 2 GiB, memory-bound by design
CIPHER_NAME = "AES-256-GCM"
HEADER_VERSION = 1


def _load_aesgcm():
    """Import ``cryptography`` lazily so the rest of the toolkit works without it."""
    try:
        from cryptography.exceptions import InvalidTag
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    except ImportError as exc:  # pragma: no cover - depends on environment
        raise DependencyError(
            "vault mode requires the 'cryptography' package; install it with "
            "`pip install cryptography` (or `pip install 'shamir-sss[vault]'`)"
        ) from exc
    return AESGCM, InvalidTag


def _b64e(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def _b64d(text: str, what: str) -> bytes:
    try:
        return base64.b64decode(text.encode("ascii"), validate=True)
    except (binascii.Error, ValueError, UnicodeEncodeError) as exc:
        raise VaultError(f"vault header field {what!r} is not valid base64") from exc


def _utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _is_hex64(value: Any) -> bool:
    return isinstance(value, str) and len(value) == 64 and set(value) <= set("0123456789abcdef")


def _safe_filename(name: str) -> str:
    """Reduce a header-supplied name to a plain basename (no traversal)."""
    candidate = Path(str(name)).name.strip()
    if candidate in ("", ".", ".."):
        return "recovered.bin"
    return candidate


@dataclass(frozen=True)
class VaultHeader:
    """Authenticated metadata stored at the head of a ``.vault`` file."""

    version: int
    cipher: str
    nonce: bytes
    dek_commitment: str
    threshold: int
    total: int
    field: str
    secret_bytes: int
    original_name: str
    original_size: int
    plaintext_sha256: str
    created_at: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "version": self.version,
            "cipher": self.cipher,
            "nonce": _b64e(self.nonce),
            "dek_commitment": self.dek_commitment,
            "secret_bytes": self.secret_bytes,
            "threshold": self.threshold,
            "total": self.total,
            "field": self.field,
            "original_name": self.original_name,
            "original_size": self.original_size,
            "plaintext_sha256": self.plaintext_sha256,
            "created_at": self.created_at,
        }

    def to_json_bytes(self) -> bytes:
        return json.dumps(
            self.to_dict(), sort_keys=True, separators=(",", ":"), ensure_ascii=True
        ).encode("utf-8")

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "VaultHeader":
        if not isinstance(data, dict):
            raise VaultError("vault header must be a JSON object")

        def require(key: str) -> Any:
            if key not in data:
                raise VaultError(f"vault header is missing {key!r}")
            return data[key]

        version = require("version")
        if version != HEADER_VERSION:
            raise VaultError(
                f"unsupported vault version {version!r}; this build understands version "
                f"{HEADER_VERSION}"
            )
        cipher = require("cipher")
        if cipher != CIPHER_NAME:
            raise VaultError(f"unsupported cipher {cipher!r}; expected {CIPHER_NAME}")
        nonce = _b64d(str(require("nonce")), "nonce")
        if len(nonce) != NONCE_BYTES:
            raise VaultError(f"vault nonce must be {NONCE_BYTES} bytes, got {len(nonce)}")
        dek_commitment = require("dek_commitment")
        if not _is_hex64(dek_commitment):
            raise VaultError("vault header dek_commitment must be 64 hex characters")
        threshold = require("threshold")
        total = require("total")
        if not isinstance(threshold, int) or not isinstance(total, int):
            raise VaultError("vault header threshold/total must be integers")
        if not 2 <= threshold <= total <= 255:
            raise VaultError(f"vault header has invalid (k, n) = ({threshold}, {total})")
        secret_bytes = require("secret_bytes")
        if secret_bytes != DEK_BYTES:
            raise VaultError(f"vault DEK must be {DEK_BYTES} bytes, header says {secret_bytes}")
        original_size = require("original_size")
        if not isinstance(original_size, int) or original_size < 0:
            raise VaultError("vault header original_size must be a non-negative integer")
        plaintext_sha256 = require("plaintext_sha256")
        if not _is_hex64(plaintext_sha256):
            raise VaultError("vault header plaintext_sha256 must be 64 hex characters")
        original_name = require("original_name")
        if not isinstance(original_name, str):
            raise VaultError("vault header original_name must be a string")
        created_at = require("created_at")
        if not isinstance(created_at, str):
            raise VaultError("vault header created_at must be a string")
        field_name = require("field")
        if not isinstance(field_name, str):
            raise VaultError("vault header field must be a string")
        return cls(
            version=version,
            cipher=cipher,
            nonce=nonce,
            dek_commitment=dek_commitment,
            threshold=threshold,
            total=total,
            field=field_name,
            secret_bytes=secret_bytes,
            original_name=original_name,
            original_size=original_size,
            plaintext_sha256=plaintext_sha256,
            created_at=created_at,
        )


@dataclass(frozen=True)
class VaultLockResult:
    """Outcome of :func:`lock_file`."""

    vault_path: Path
    share_paths: Tuple[Path, ...]
    split: SplitResult
    header: VaultHeader
    plaintext_size: int

    @property
    def shares(self) -> Tuple[Share, ...]:
        return self.split.shares

    def __repr__(self) -> str:  # pragma: no cover - cosmetic
        return (
            f"VaultLockResult(vault={self.vault_path}, k={self.split.threshold}, "
            f"n={self.split.total}, plaintext_size={self.plaintext_size})"
        )


@dataclass(frozen=True)
class VaultUnlockResult:
    """Outcome of :func:`unlock_file`."""

    output_path: Path
    plaintext_size: int
    shares_used: int
    commitment_verified: bool
    combination: CombineResult
    header: VaultHeader

    def __repr__(self) -> str:  # pragma: no cover - cosmetic
        return (
            f"VaultUnlockResult(output={self.output_path}, size={self.plaintext_size}, "
            f"shares_used={self.shares_used}, commitment_verified={self.commitment_verified})"
        )


def _build_header(
    *,
    nonce: bytes,
    dek: bytes,
    threshold: int,
    total: int,
    field_name: str,
    original_name: str,
    plaintext: bytes,
    created_at: Optional[str] = None,
) -> VaultHeader:
    return VaultHeader(
        version=HEADER_VERSION,
        cipher=CIPHER_NAME,
        nonce=nonce,
        dek_commitment=hashlib.sha256(dek).hexdigest(),
        threshold=threshold,
        total=total,
        field=field_name,
        secret_bytes=len(dek),
        original_name=original_name,
        original_size=len(plaintext),
        plaintext_sha256=hashlib.sha256(plaintext).hexdigest(),
        created_at=created_at or _utc_now(),
    )


def _aad(header_bytes: bytes) -> bytes:
    return MAGIC + len(header_bytes).to_bytes(4, "big") + header_bytes


def lock_file(
    source: Union[str, Path],
    *,
    threshold: int,
    total: int,
    out_dir: Union[str, Path] = ".",
    field: Union[str, int] = "m521",
    labels: Optional[Sequence[Optional[str]]] = None,
    fmt: str = "both",
    force: bool = False,
) -> VaultLockResult:
    """Encrypt ``source`` with AES-256-GCM and Shamir-split its DEK.

    The vault is written as ``<out_dir>/<name>.vault`` and shares as
    ``<out_dir>/<name>-share-XX-of-YY.{json,txt}``.
    """
    AESGCM, _ = _load_aesgcm()
    path = Path(source)
    if not path.is_file():
        raise VaultError(f"{path} is not a regular file")
    plaintext_buffer = bytearray(secure_read_bytes(path, max_bytes=MAX_VAULT_BYTES))
    if not plaintext_buffer:
        raise VaultError(f"{path} is empty; nothing to lock")
    plaintext = bytes(plaintext_buffer)
    wipe(plaintext_buffer)

    dek_buffer = bytearray(secrets.token_bytes(DEK_BYTES))
    nonce = secrets.token_bytes(NONCE_BYTES)
    try:
        split_result = split(
            bytes(dek_buffer),
            threshold,
            total,
            field=field,
            commitment=True,  # committing a full-entropy DEK is always safe
            labels=labels,
        )
        header = _build_header(
            nonce=nonce,
            dek=bytes(dek_buffer),
            threshold=threshold,
            total=total,
            field_name=split_result.field.name,
            original_name=_safe_filename(path.name),
            plaintext=plaintext,
        )
        if not hmac.compare_digest(header.dek_commitment, split_result.commitment or ""):
            raise VaultError("internal error: DEK commitment mismatch while locking")
        header_bytes = header.to_json_bytes()
        if len(header_bytes) > MAX_HEADER_BYTES:  # pragma: no cover - defensive
            raise VaultError("vault header is implausibly large")
        aad = _aad(header_bytes)
        ciphertext = AESGCM(bytes(dek_buffer)).encrypt(nonce, plaintext, aad)
    finally:
        wipe(dek_buffer)

    directory = secure_makedirs(out_dir)
    vault_path = directory / f"{path.name}{VAULT_SUFFIX}"
    atomic_write_bytes(vault_path, aad + ciphertext, force=force)
    share_paths = write_share_files(
        split_result.shares,
        directory,
        fmt=fmt,
        prefix=f"{path.name}-share",
        force=force,
    )
    return VaultLockResult(
        vault_path=vault_path,
        share_paths=tuple(share_paths),
        split=split_result,
        header=header,
        plaintext_size=len(plaintext),
    )


def parse_envelope(data: bytes) -> Tuple[VaultHeader, bytes, bytes]:
    """Split raw vault bytes into ``(header, header_bytes, ciphertext)``."""
    if len(data) < len(MAGIC) + 4 + 2 + 16:
        raise VaultError("vault file is truncated (too short to contain a header and tag)")
    if data[: len(MAGIC)] != MAGIC:
        raise VaultError(
            "not a Shamir vault file: magic bytes are missing or the file is corrupted"
        )
    offset = len(MAGIC)
    header_length = int.from_bytes(data[offset : offset + 4], "big")
    offset += 4
    if header_length == 0 or header_length > MAX_HEADER_BYTES:
        raise VaultError(f"vault header length {header_length} is invalid")
    header_end = offset + header_length
    if header_end > len(data):
        raise VaultError("vault file is truncated inside its header")
    header_bytes = data[offset:header_end]
    try:
        header_data = json.loads(header_bytes.decode("utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise VaultError(f"vault header is not valid UTF-8 JSON: {exc}") from exc
    header = VaultHeader.from_dict(header_data)
    ciphertext = data[header_end:]
    if len(ciphertext) < 16:
        raise VaultError("vault file is truncated: ciphertext is shorter than a GCM tag")
    return header, header_bytes, ciphertext


def read_vault_header(path: Union[str, Path]) -> Tuple[VaultHeader, int]:
    """Read only the authenticated header (plus total envelope size)."""
    data = secure_read_bytes(path, max_bytes=MAX_VAULT_BYTES)
    header, _header_bytes, _ciphertext = parse_envelope(data)
    return header, len(data)


def _materialise_shares(
    share_inputs: Sequence[Union[Share, str, Path, Dict[str, Any]]],
) -> List[Union[Share, str, Dict[str, Any]]]:
    """Turn file paths in ``share_inputs`` into parsed shares, keep the rest."""
    direct: List[Union[Share, str, Dict[str, Any]]] = []
    paths: List[str] = []
    for item in share_inputs:
        if isinstance(item, Path) or (
            isinstance(item, str) and not item.strip().startswith(("{", "SSS", "sss"))
        ):
            paths.append(str(item))
        else:
            direct.append(item)
    if paths:
        direct.extend(load_share_inputs(paths))
    return direct


def unlock_file(
    vault_path: Union[str, Path],
    share_inputs: Sequence[Union[Share, str, Path, Dict[str, Any]]],
    *,
    out_path: Optional[Union[str, Path]] = None,
    force: bool = False,
) -> VaultUnlockResult:
    """Rebuild the DEK from shares, authenticate and decrypt the vault."""
    AESGCM, InvalidTag = _load_aesgcm()
    path = Path(vault_path)
    data = secure_read_bytes(path, max_bytes=MAX_VAULT_BYTES)
    header, header_bytes, ciphertext = parse_envelope(data)
    aad = _aad(header_bytes)

    combination = combine(
        _materialise_shares(share_inputs), expected_commitment=header.dek_commitment
    )
    dek_buffer = bytearray(combination.secret)
    try:
        if len(dek_buffer) != DEK_BYTES:  # pragma: no cover - combine enforces length
            raise VaultError(f"reconstructed DEK has {len(dek_buffer)} bytes, expected {DEK_BYTES}")
        try:
            plaintext = AESGCM(bytes(dek_buffer)).decrypt(header.nonce, ciphertext, aad)
        except InvalidTag as exc:
            raise VaultError(
                "AES-256-GCM authentication failed: the vault file, its header or the "
                "reconstructed key material has been modified"
            ) from exc
    finally:
        wipe(dek_buffer)

    if len(plaintext) != header.original_size:
        raise VaultError(
            f"decrypted size {len(plaintext)} does not match the authenticated header "
            f"({header.original_size}); refusing to write output"
        )
    digest = hashlib.sha256(plaintext).hexdigest()
    if not hmac.compare_digest(digest, header.plaintext_sha256):
        raise VaultError("decrypted content does not match the authenticated plaintext digest")

    target = Path(out_path) if out_path is not None else Path(_safe_filename(header.original_name))
    if target.is_dir():
        target = target / _safe_filename(header.original_name)
    try:
        atomic_write_bytes(target, plaintext, force=force)
    except OutputError:
        raise
    return VaultUnlockResult(
        output_path=target,
        plaintext_size=len(plaintext),
        shares_used=combination.shares_used,
        commitment_verified=combination.commitment_verified,
        combination=combination,
        header=header,
    )

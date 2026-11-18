"""Threshold secret sharing: splitter, reconstructor and share serialisation.

This module implements Shamir's ``(k, n)`` threshold scheme over the prime
fields defined in :mod:`core.finite_field`.

A secret is interpreted as a big-endian integer ``S``.  A random polynomial of
degree exactly ``k - 1`` is drawn with constant term ``a_0 = S``:

.. math::

    f(x) = S + a_1 x + a_2 x^2 + \\dots + a_{k-1} x^{k-1} \\pmod p

Shares are the pairs :math:`(x_i, f(x_i))` for :math:`x_i \\in \\{1, \\dots, n\\}`.
Any ``k`` of them determine ``f`` uniquely (and hence ``S = f(0)``); any
``k - 1`` leave ``S`` information-theoretically undetermined.

Payloads longer than the field capacity are split into fixed-width chunks, each
protected by an independent random polynomial of the same degree and evaluated
at the same x-coordinates.  Chunking is standard practice and preserves both
correctness and perfect secrecy (see ``THEORY.md`` §6).

Share format
------------
Human-copyable armoured string (whitespace is ignored, ASCII only, QR-safe)::

    SSS-V1-<field>-<k>-<n>-<index>-<secret_len>-<b64_y>-<checksum>[-<commitment>]

``<field>``      registered field name (``m521`` / ``m2281``)
``<k>``          reconstruction threshold
``<n>``          total number of shares
``<index>``      x-coordinate, ``1 <= index <= n`` (0 is never a valid share)
``<secret_len>`` exact byte length of the original secret (preserves leading zeros)
``<b64_y>``      standard base64, unpadded, of the fixed-width payload block(s)
``<checksum>``   first 64 bits of ``SHA-256`` over the canonical header+payload,
                 standard base64 without padding (11 characters)
``<commitment>`` optional ``SHA-256(secret)`` in hex

The structured JSON form carries the same information plus optional
``label``/``created_at`` metadata.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import json
import secrets
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple, Union

from core.errors import (
    ChecksumError,
    CommitmentError,
    ShareConsistencyError,
    ShareFormatError,
    SSSError,
    ThresholdError,
)
from core.finite_field import PrimeField, get_field, resolve_field
from core.storage import atomic_write_text, secure_makedirs

__all__ = [
    "Share",
    "SplitResult",
    "CombineResult",
    "ShareEntry",
    "ShareSetAnalysis",
    "split",
    "combine",
    "parse_armored",
    "parse_hex_secret",
    "analyze_shares",
    "load_share_inputs",
    "load_share_inputs_detailed",
    "write_share_files",
    "shares_to_json_bundle",
    "MAX_SHARES",
    "MIN_THRESHOLD",
    "CHECKSUM_BYTES",
    "ARMOR_PREFIX",
]

#: Hard ceiling on ``n``.  Keeps x-coordinates one byte wide and share files
#: human-checkable; 255 custodians is far beyond any realistic deployment.
MAX_SHARES = 255

#: A threshold of 1 would expose the secret itself as the "share".
MIN_THRESHOLD = 2

#: Truncated SHA-256 integrity tag length in bytes (64-bit collision resistance).
CHECKSUM_BYTES = 8

ARMOR_PREFIX = "SSS-V1"
JSON_FORMAT = "sss-share"
JSON_VERSION = 1

_HEX_DIGITS = set("0123456789abcdef")


# ---------------------------------------------------------------------------
# Small encoding helpers
# ---------------------------------------------------------------------------
def _b64e(data: bytes) -> str:
    """Standard base64, padding stripped (safe inside a dash-delimited token)."""
    return base64.b64encode(data).decode("ascii").rstrip("=")


def _b64d(text: str, what: str = "base64 field") -> bytes:
    if not isinstance(text, str) or not text:
        raise ShareFormatError(f"{what} must be a non-empty base64 string")
    padded = text + "=" * (-len(text) % 4)
    try:
        return base64.b64decode(padded, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise ShareFormatError(f"{what} is not valid base64: {exc}") from exc


def _utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _normalise_commitment(value: Any) -> Optional[str]:
    if value is None:
        return None
    if not isinstance(value, str):
        raise ShareFormatError("commitment must be a hex string or null")
    token = value.strip().lower()
    if token in ("", "-", "null", "none"):
        return None
    if len(token) != 64 or not set(token) <= _HEX_DIGITS:
        raise ShareFormatError("commitment must be 64 lowercase hexadecimal characters (SHA-256)")
    return token


def _parse_uint(token: str, name: str, *, minimum: int, maximum: int) -> int:
    text = token.strip()
    if not text:
        raise ShareFormatError(f"missing {name} in share")
    if not text.isdigit():
        raise ShareFormatError(f"{name} must be a decimal integer, got {token!r}")
    value = int(text)
    if not minimum <= value <= maximum:
        raise ShareFormatError(f"{name} must satisfy {minimum} <= {name} <= {maximum}, got {value}")
    return value


# ---------------------------------------------------------------------------
# The Share object
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class Share:
    """A single point ``(index, f(index))`` plus the metadata needed to combine."""

    field: PrimeField
    threshold: int
    total: int
    index: int
    secret_length: int
    y: bytes
    checksum: str
    commitment: Optional[str] = None
    label: Optional[str] = None
    created_at: Optional[str] = None

    # -- construction -----------------------------------------------------
    def __post_init__(self) -> None:
        if not isinstance(self.field, PrimeField):
            object.__setattr__(self, "field", get_field(self.field))
        if not isinstance(self.y, (bytes, bytearray)):
            raise ShareFormatError("share payload y must be bytes")
        object.__setattr__(self, "y", bytes(self.y))
        object.__setattr__(self, "commitment", _normalise_commitment(self.commitment))
        _validate_share_metadata(
            self.field,
            self.threshold,
            self.total,
            self.index,
            self.secret_length,
            self.y,
        )

    @classmethod
    def build(
        cls,
        *,
        field: PrimeField,
        threshold: int,
        total: int,
        index: int,
        secret_length: int,
        y: bytes,
        commitment: Optional[str] = None,
        label: Optional[str] = None,
        created_at: Optional[str] = None,
    ) -> "Share":
        """Create a share and compute its integrity checksum."""
        checksum = cls.compute_checksum(
            field.name, threshold, total, index, secret_length, _b64e(bytes(y)), commitment
        )
        return cls(
            field=field,
            threshold=threshold,
            total=total,
            index=index,
            secret_length=secret_length,
            y=bytes(y),
            checksum=checksum,
            commitment=commitment,
            label=label,
            created_at=created_at,
        )

    # -- integrity --------------------------------------------------------
    @staticmethod
    def canonical_payload(
        field_name: str,
        threshold: int,
        total: int,
        index: int,
        secret_length: int,
        y_b64: str,
        commitment: Optional[str],
    ) -> str:
        """Byte-exact string covered by the checksum (never change this)."""
        return "|".join(
            [
                "SSS",
                "V1",
                field_name,
                str(int(threshold)),
                str(int(total)),
                str(int(index)),
                str(int(secret_length)),
                y_b64,
                commitment or "",
            ]
        )

    @classmethod
    def compute_checksum(
        cls,
        field_name: str,
        threshold: int,
        total: int,
        index: int,
        secret_length: int,
        y_b64: str,
        commitment: Optional[str],
    ) -> str:
        canonical = cls.canonical_payload(
            field_name, threshold, total, index, secret_length, y_b64, commitment
        )
        digest = hashlib.sha256(canonical.encode("ascii")).digest()
        return _b64e(digest[:CHECKSUM_BYTES])

    def verify_checksum(self, *, raise_on_error: bool = True) -> bool:
        """Recompute the truncated SHA-256 and compare in constant time."""
        expected = self.compute_checksum(
            self.field.name,
            self.threshold,
            self.total,
            self.index,
            self.secret_length,
            self.y_b64,
            self.commitment,
        )
        valid = hmac.compare_digest(expected, self.checksum)
        if not valid and raise_on_error:
            raise ChecksumError(
                f"checksum mismatch for share x={self.index}: expected {expected}, tag reads "
                f"{self.checksum}. The share was mistyped, truncated or modified in transit."
            )
        return valid

    # -- derived properties ----------------------------------------------
    @property
    def chunk_count(self) -> int:
        return len(self.y) // self.field.element_bytes

    @property
    def y_b64(self) -> str:
        return _b64e(self.y)

    @property
    def chunk_values(self) -> Tuple[int, ...]:
        width = self.field.element_bytes
        return tuple(
            self.field.decode(self.y[offset : offset + width], f"share x={self.index}")
            for offset in range(0, len(self.y), width)
        )

    # -- serialisation ----------------------------------------------------
    def to_armored(self) -> str:
        """Return the portable single-line armoured representation."""
        tokens = [
            "SSS",
            "V1",
            self.field.name,
            str(self.threshold),
            str(self.total),
            str(self.index),
            str(self.secret_length),
            self.y_b64,
            self.checksum,
        ]
        if self.commitment:
            tokens.append(self.commitment)
        return "-".join(tokens)

    def to_dict(self) -> Dict[str, Any]:
        data: Dict[str, Any] = {
            "format": JSON_FORMAT,
            "version": JSON_VERSION,
            "field": self.field.name,
            "threshold": self.threshold,
            "total": self.total,
            "index": self.index,
            "secret_bytes": self.secret_length,
            "y": self.y_b64,
            "checksum": self.checksum,
            "commitment": self.commitment,
        }
        if self.label is not None:
            data["label"] = self.label
        if self.created_at is not None:
            data["created_at"] = self.created_at
        return data

    def to_json(self, *, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent, sort_keys=False) + "\n"

    def describe(self) -> Dict[str, Any]:
        return {
            "index": self.index,
            "label": self.label or f"share {self.index}",
            "field": self.field.name,
            "threshold": self.threshold,
            "total": self.total,
            "secret_bytes": self.secret_length,
            "chunks": self.chunk_count,
            "payload_bytes": len(self.y),
            "checksum": self.checksum,
            "commitment": self.commitment,
            "created_at": self.created_at,
        }

    # -- parsing ----------------------------------------------------------
    @classmethod
    def from_armored(cls, text: str) -> "Share":
        if not isinstance(text, str):
            raise ShareFormatError("armoured share must be a string")
        # Whitespace is ignored so that wrapped / QR-scanned shares still parse.
        compact = "".join(text.split())
        if not compact:
            raise ShareFormatError("empty share string")
        parts = compact.split("-")
        if len(parts) < 2 or parts[0].upper() != "SSS":
            raise ShareFormatError("unrecognised share prefix; expected 'SSS-V1-...'")
        if parts[1].upper() != "V1":
            raise ShareFormatError(
                f"unsupported share version {parts[1]!r}; this build understands V1 only"
            )
        fields = parts[2:]
        if len(fields) not in (7, 8):
            raise ShareFormatError(
                "malformed share: expected 7 or 8 dash-separated fields after 'SSS-V1-' "
                "(field, k, n, index, secret_len, y, checksum[, commitment]); "
                f"got {len(fields)}. Check for stray dashes or a truncated paste."
            )
        field_token, k_token, n_token, index_token, length_token, y_token, checksum = fields[:7]
        commitment = fields[7] if len(fields) == 8 else None
        if commitment is not None and commitment.strip() in ("", "-"):
            commitment = None

        prime_field = get_field(field_token)
        threshold = _parse_uint(k_token, "threshold k", minimum=MIN_THRESHOLD, maximum=MAX_SHARES)
        total = _parse_uint(n_token, "total n", minimum=MIN_THRESHOLD, maximum=MAX_SHARES)
        index = _parse_uint(index_token, "share index", minimum=1, maximum=MAX_SHARES)
        secret_length = _parse_uint(
            length_token, "secret length", minimum=1, maximum=2**31 - 1
        )
        if threshold > total:
            raise ShareFormatError(f"threshold k={threshold} exceeds total n={total}")
        if index > total:
            raise ShareFormatError(f"share index {index} exceeds total n={total}")
        y = _b64d(y_token, "share payload")
        share = cls(
            field=prime_field,
            threshold=threshold,
            total=total,
            index=index,
            secret_length=secret_length,
            y=y,
            checksum=checksum,
            commitment=_normalise_commitment(commitment),
        )
        share.verify_checksum()
        return share

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Share":
        if not isinstance(data, dict):
            raise ShareFormatError("share JSON must be an object")
        fmt = data.get("format", JSON_FORMAT)
        if fmt != JSON_FORMAT:
            raise ShareFormatError(f"unexpected JSON format {fmt!r}; expected {JSON_FORMAT!r}")
        version = data.get("version", JSON_VERSION)
        if version != JSON_VERSION:
            raise ShareFormatError(f"unsupported share JSON version {version!r}")
        try:
            field_token = data["field"]
            threshold = data["threshold"]
            total = data["total"]
            index = data["index"]
            secret_length = data.get("secret_bytes", data.get("secret_length"))
            y_token = data["y"]
            checksum = data["checksum"]
        except KeyError as exc:
            raise ShareFormatError(f"share JSON is missing required key {exc.args[0]!r}") from exc
        for name, value in (
            ("threshold", threshold),
            ("total", total),
            ("index", index),
            ("secret_bytes", secret_length),
        ):
            if isinstance(value, bool) or not isinstance(value, int):
                raise ShareFormatError(f"share JSON key {name!r} must be an integer")
        if not isinstance(y_token, str) or not isinstance(checksum, str):
            raise ShareFormatError("share JSON keys 'y' and 'checksum' must be strings")
        label = data.get("label")
        if label is not None and not isinstance(label, str):
            raise ShareFormatError("share JSON key 'label' must be a string")
        created_at = data.get("created_at")
        if created_at is not None and not isinstance(created_at, str):
            raise ShareFormatError("share JSON key 'created_at' must be a string")
        share = cls(
            field=get_field(field_token),
            threshold=threshold,
            total=total,
            index=index,
            secret_length=secret_length,
            y=_b64d(y_token, "share payload"),
            checksum=checksum.strip(),
            commitment=_normalise_commitment(data.get("commitment")),
            label=label.strip() if label else None,
            created_at=created_at,
        )
        share.verify_checksum()
        return share


def _validate_share_metadata(
    prime_field: PrimeField,
    threshold: int,
    total: int,
    index: int,
    secret_length: int,
    y: bytes,
) -> None:
    for name, value in (("threshold", threshold), ("total", total), ("index", index)):
        if isinstance(value, bool) or not isinstance(value, int):
            raise ShareFormatError(f"{name} must be an integer")
    if not MIN_THRESHOLD <= threshold <= total <= MAX_SHARES:
        raise ShareFormatError(
            f"invalid (k, n) = ({threshold}, {total}); require "
            f"{MIN_THRESHOLD} <= k <= n <= {MAX_SHARES}"
        )
    if not 1 <= index <= total:
        raise ShareFormatError(f"share index {index} is outside 1..{total}")
    if isinstance(secret_length, bool) or not isinstance(secret_length, int) or secret_length < 1:
        raise ShareFormatError("secret length must be a positive integer")
    width = prime_field.element_bytes
    if len(y) == 0 or len(y) % width != 0:
        raise ShareFormatError(
            f"share payload is {len(y)} bytes, not a positive multiple of the "
            f"{width}-byte encoding width for {prime_field.label}"
        )
    expected_chunks = (secret_length + prime_field.secret_capacity - 1) // prime_field.secret_capacity
    if len(y) // width != expected_chunks:
        raise ShareFormatError(
            f"share payload holds {len(y) // width} chunk(s) but a {secret_length}-byte "
            f"secret requires exactly {expected_chunks} in {prime_field.label}"
        )
    if secret_length > (1 << 31) - 1:  # pragma: no cover - defensive
        raise ShareFormatError("secret length is implausibly large")
    for offset in range(0, len(y), width):
        if int.from_bytes(y[offset : offset + width], "big") >= prime_field.p:
            raise ShareFormatError(
                f"share payload chunk {offset // width} is not a canonical element of "
                f"{prime_field.label}; the share is corrupt or uses the wrong field"
            )


#: Public factory kept for symmetry with :func:`split`.
parse_armored = Share.from_armored


# ---------------------------------------------------------------------------
# Result containers
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class SplitResult:
    """Outcome of :func:`split`."""

    shares: Tuple[Share, ...]
    field: PrimeField
    threshold: int
    total: int
    secret_length: int
    commitment: Optional[str]
    chunk_count: int
    created_at: str

    def armored(self) -> List[str]:
        return [share.to_armored() for share in self.shares]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "format": "sss-split",
            "version": 1,
            "field": self.field.name,
            "threshold": self.threshold,
            "total": self.total,
            "secret_bytes": self.secret_length,
            "chunks": self.chunk_count,
            "commitment": self.commitment,
            "created_at": self.created_at,
            "shares": [share.to_dict() for share in self.shares],
        }

    def __repr__(self) -> str:  # pragma: no cover - cosmetic
        return (
            f"SplitResult(k={self.threshold}, n={self.total}, field={self.field.name}, "
            f"secret_bytes={self.secret_length}, chunks={self.chunk_count})"
        )


@dataclass(frozen=True)
class CombineResult:
    """Outcome of :func:`combine`.

    ``__repr__`` deliberately omits the recovered secret so that a stray log
    line or debugger frame does not leak it.
    """

    secret: bytes
    field: PrimeField
    threshold: int
    total: int
    shares_used: int
    commitment: Optional[str]
    commitment_verified: bool
    chunk_count: int

    @property
    def secret_hex(self) -> str:
        return self.secret.hex()

    def __repr__(self) -> str:  # pragma: no cover - cosmetic
        return (
            f"CombineResult(k={self.threshold}, n={self.total}, shares_used={self.shares_used}, "
            f"field={self.field.name}, secret=<redacted {len(self.secret)} bytes>, "
            f"commitment_verified={self.commitment_verified})"
        )


@dataclass(frozen=True)
class ShareEntry:
    """One row in a verification report."""

    position: int
    source: str
    share: Optional[Share] = None
    error: Optional[str] = None

    @property
    def ok(self) -> bool:
        return self.share is not None and self.error is None


@dataclass(frozen=True)
class ShareSetAnalysis:
    """Result of :func:`analyze_shares` -- never reconstructs the secret."""

    entries: Tuple[ShareEntry, ...]
    problems: Tuple[str, ...]
    warnings: Tuple[str, ...]
    shares: Tuple[Share, ...]
    threshold: Optional[int]
    total: Optional[int]
    field: Optional[PrimeField]
    commitment: Optional[str]
    secret_length: Optional[int]
    chunk_count: Optional[int]
    unique_indices: Tuple[int, ...]
    sufficient: bool
    consistent: bool

    @property
    def ok(self) -> bool:
        return self.consistent and self.sufficient

    @property
    def missing(self) -> Optional[int]:
        if self.threshold is None:
            return None
        return max(0, self.threshold - len(self.shares))

    @property
    def verdict(self) -> str:
        if not self.consistent:
            return "invalid"
        if not self.sufficient:
            return "insufficient"
        return "valid"


# ---------------------------------------------------------------------------
# Split
# ---------------------------------------------------------------------------
def _validate_parameters(threshold: int, total: int) -> None:
    for name, value in (("threshold", threshold), ("shares", total)):
        if isinstance(value, bool) or not isinstance(value, int):
            raise ShareFormatError(f"{name} must be an integer")
    if threshold < MIN_THRESHOLD:
        raise ShareFormatError(
            f"threshold k must be at least {MIN_THRESHOLD}; a 1-of-n split would publish the secret"
        )
    if total > MAX_SHARES:
        raise ShareFormatError(f"total n must be at most {MAX_SHARES}")
    if threshold > total:
        raise ShareFormatError(f"threshold k={threshold} cannot exceed total n={total}")


def _int_chunks(secret: bytes, width: int) -> List[int]:
    """Split a big-endian byte string into fixed-width field elements.

    The first (most significant) chunk is zero-padded on the left, which is why
    the exact secret length must travel with every share.
    """
    if not secret:
        raise ShareFormatError("secret must contain at least one byte")
    chunk_count = (len(secret) + width - 1) // width
    padding = chunk_count * width - len(secret)
    padded = b"\x00" * padding + secret
    return [int.from_bytes(padded[i * width : (i + 1) * width], "big") for i in range(chunk_count)]


def _join_chunks(
    values: Sequence[int], element_width: int, secret_capacity: int, secret_length: int
) -> bytes:
    """Inverse of :func:`_int_chunks`, with canonical-padding validation."""
    width = secret_capacity
    expected_chunks = (secret_length + width - 1) // width
    if len(values) != expected_chunks:
        raise ShareConsistencyError(
            f"reconstructed {len(values)} chunk(s) where {expected_chunks} were expected"
        )
    accumulator = 0
    limit = 1 << (8 * width)
    for value in values:
        if not 0 <= value < limit:
            raise ShareConsistencyError(
                "reconstructed chunk is not a canonical "
                f"{width}-byte value; the supplied shares are inconsistent"
            )
        accumulator = (accumulator << (8 * width)) | value
    raw = accumulator.to_bytes(len(values) * width, "big")
    padding = len(raw) - secret_length
    if raw[:padding] != b"\x00" * padding:
        raise ShareConsistencyError(
            "reconstructed payload has non-zero high-order padding: the supplied shares are "
            "mutually inconsistent (mixed splits, tampering, or a corrupted share that still "
            "passed its checksum)"
        )
    return raw[padding:]


def split(
    secret: Union[bytes, bytearray, memoryview, str],
    threshold: int,
    total: int,
    *,
    field: Union[str, int, PrimeField, None] = None,
    commitment: bool = False,
    labels: Optional[Sequence[Optional[str]]] = None,
    require_exact_degree: bool = True,
    rng: Any = secrets,
    created_at: Optional[str] = None,
) -> SplitResult:
    """Split ``secret`` into ``total`` shares, any ``threshold`` of which recover it.

    Parameters
    ----------
    secret:
        Raw secret bytes (``str`` is UTF-8 encoded for convenience).
    threshold, total:
        ``k`` and ``n`` with ``2 <= k <= n <= 255``.
    field:
        ``None``/``"auto"`` selects the smallest field that holds the payload;
        explicit ``"m521"``/``"m2281"`` override, and longer payloads are chunked.
    commitment:
        When true, every share carries ``SHA-256(secret)`` so ``combine`` can
        detect a consistent-but-wrong reconstruction.  **Off by default**: a
        commitment on a low-entropy secret hands an attacker holding ``k - 1``
        shares an offline verification oracle.  Vault mode commits the 256-bit
        DEK instead, which is always safe.
    labels:
        Optional custodian labels, one per share (JSON output only).
    require_exact_degree:
        Keep the polynomial degree exactly ``k - 1`` by sampling every
        coefficient from ``GF(p)^*``.  Disabling this samples from all of
        ``GF(p)`` (see ``THEORY.md`` §4.3 for the negligible difference).
    """
    if isinstance(secret, str):
        secret_bytes = secret.encode("utf-8")
    elif isinstance(secret, (bytes, bytearray, memoryview)):
        secret_bytes = bytes(secret)
    else:
        raise ShareFormatError("secret must be bytes, bytearray or str")
    if not secret_bytes:
        raise ShareFormatError("secret must contain at least one byte")

    _validate_parameters(threshold, total)

    normalised_labels: Optional[List[Optional[str]]] = None
    if labels is not None:
        normalised_labels = []
        if len(labels) != total:
            raise ShareFormatError(
                f"expected {total} labels (one per share), got {len(labels)}"
            )
        for label in labels:
            if label is None:
                normalised_labels.append(None)
                continue
            if not isinstance(label, str):
                raise ShareFormatError("labels must be strings or None")
            text = label.strip()
            if len(text) > 64:
                raise ShareFormatError("labels must be at most 64 characters")
            if text and not text.isprintable():
                raise ShareFormatError("labels must be printable text (no control characters)")
            normalised_labels.append(text or None)

    prime_field = resolve_field(field, len(secret_bytes))
    chunk_values = _int_chunks(secret_bytes, prime_field.secret_capacity)
    commitment_hex = hashlib.sha256(secret_bytes).hexdigest() if commitment else None
    timestamp = created_at or _utc_now()

    xs = list(range(1, total + 1))
    payloads: List[List[int]] = [[] for _ in range(total)]
    for constant_term in chunk_values:
        coefficients = [prime_field.check(constant_term, "secret chunk")]
        if require_exact_degree:
            # a_1 .. a_{k-1} uniform over GF(p)^*, which forces deg(f) == k - 1.
            coefficients.extend(
                prime_field.random_nonzero(rng) for _ in range(threshold - 1)
            )
        else:
            coefficients.extend(
                prime_field.random_element(rng) for _ in range(threshold - 1)
            )
        for position, x in enumerate(xs):
            payloads[position].append(prime_field.horner(coefficients, x))

    shares: List[Share] = []
    for position, x in enumerate(xs):
        y = b"".join(prime_field.encode(value) for value in payloads[position])
        shares.append(
            Share.build(
                field=prime_field,
                threshold=threshold,
                total=total,
                index=x,
                secret_length=len(secret_bytes),
                y=y,
                commitment=commitment_hex,
                label=normalised_labels[position] if normalised_labels else None,
                created_at=timestamp,
            )
        )

    chunk_count = len(chunk_values)
    # Drop references to intermediate field elements as soon as possible.
    payloads.clear()
    chunk_values.clear()

    return SplitResult(
        shares=tuple(shares),
        field=prime_field,
        threshold=threshold,
        total=total,
        secret_length=len(secret_bytes),
        commitment=commitment_hex,
        chunk_count=chunk_count,
        created_at=timestamp,
    )


# ---------------------------------------------------------------------------
# Combine
# ---------------------------------------------------------------------------
def _coerce_share(item: Union[Share, str, Dict[str, Any], bytes]) -> Share:
    if isinstance(item, Share):
        return item
    if isinstance(item, dict):
        if "shares" in item and "field" not in item:
            raise ShareFormatError(
                "this is a share bundle, not a single share; pass the bundle file instead"
            )
        return Share.from_dict(item)
    if isinstance(item, (bytes, bytearray)):
        try:
            item = bytes(item).decode("utf-8")
        except UnicodeDecodeError as exc:
            raise ShareFormatError("share bytes are not valid UTF-8") from exc
    if isinstance(item, str):
        text = item.strip()
        if not text:
            raise ShareFormatError("empty share")
        if text.startswith("{"):
            try:
                data = json.loads(text)
            except json.JSONDecodeError as exc:
                raise ShareFormatError(f"share JSON is malformed: {exc.msg}") from exc
            if isinstance(data, dict) and "shares" in data:
                raise ShareFormatError(
                    "this is a share bundle, not a single share; pass the bundle file instead"
                )
            return Share.from_dict(data)
        return Share.from_armored(text)
    raise ShareFormatError(f"cannot interpret {type(item).__name__} as a share")


def _require_same_group(shares: Sequence[Share], reference: Share) -> None:
    for share in shares:
        if share.field.name != reference.field.name:
            raise ShareConsistencyError(
                f"shares use different fields ({reference.field.name} vs {share.field.name})"
            )
        if share.threshold != reference.threshold or share.total != reference.total:
            raise ShareConsistencyError(
                "shares belong to different splits: "
                f"(k={share.threshold}, n={share.total}) vs "
                f"(k={reference.threshold}, n={reference.total})"
            )
        if share.secret_length != reference.secret_length:
            raise ShareConsistencyError(
                "shares disagree about the secret length "
                f"({share.secret_length} vs {reference.secret_length} bytes)"
            )
        if len(share.y) != len(reference.y):
            raise ShareConsistencyError("shares carry payloads of different sizes")
        if share.commitment != reference.commitment:
            raise ShareConsistencyError(
                "shares carry different commitments; they were produced by different splits "
                "or the commitment field was modified"
            )


def _share_chunk_value(share: Share, chunk_index: int, prime_field: PrimeField) -> int:
    width = prime_field.element_bytes
    start = chunk_index * width
    block = share.y[start : start + width]
    if len(block) != width:
        raise ShareConsistencyError(f"share x={share.index} is missing chunk {chunk_index}")
    return prime_field.decode(block, f"share x={share.index} chunk {chunk_index}")


def _verify_superset(
    shares: Sequence[Share],
    threshold: int,
    prime_field: PrimeField,
    chunk_count: int,
) -> None:
    """Check that shares beyond the threshold lie on the same polynomials.

    With more than ``k`` shares the system is over-determined; a single
    tampered share would silently corrupt naive interpolation.  We therefore
    fit the first ``k`` points, then require every extra share to evaluate
    identically -- turning redundancy into tamper detection.
    """
    base = shares[:threshold]
    extras = shares[threshold:]
    bad: List[int] = []
    for chunk_index in range(chunk_count):
        points = [
            (share.index, _share_chunk_value(share, chunk_index, prime_field)) for share in base
        ]
        coefficients = prime_field.interpolate(points)
        for extra in extras:
            expected = prime_field.horner(coefficients, extra.index)
            actual = _share_chunk_value(extra, chunk_index, prime_field)
            if expected != actual and extra.index not in bad:
                bad.append(extra.index)
    if bad:
        raise ShareConsistencyError(
            "shares at x="
            + ", ".join(str(index) for index in sorted(bad))
            + " are inconsistent with the quorum subset: at least one supplied share is "
            "corrupted or forged. Re-run `sss verify` and drop the failing share."
        )


def _check_commitment(expected_hex: str, secret: bytes, what: str) -> None:
    actual = hashlib.sha256(secret).hexdigest()
    if not hmac.compare_digest(actual, expected_hex.lower()):
        raise CommitmentError(
            f"{what} does not match the reconstructed secret "
            f"(expected {expected_hex.lower()}, got {actual}). The shares are internally "
            "consistent but do not belong to the secret they claim to protect."
        )


def combine(
    shares: Sequence[Union[Share, str, Dict[str, Any]]],
    *,
    expected_commitment: Optional[str] = None,
) -> CombineResult:
    """Reconstruct the secret from ``k`` or more shares.

    Validation performed before any interpolation:

    * every share parses and its truncated SHA-256 checksum matches,
    * all shares agree on field, ``k``, ``n``, secret length and commitment,
    * x-indices are unique and within ``1..n``,
    * at least ``k`` shares are present,
    * if more than ``k`` are supplied, the surplus shares are required to lie on
      the same polynomial (tamper detection).
    """
    parsed = [_coerce_share(item) for item in shares]
    if not parsed:
        raise ThresholdError("at least one share is required")

    for share in parsed:
        share.verify_checksum()

    reference = parsed[0]
    _require_same_group(parsed, reference)

    indices = [share.index for share in parsed]
    duplicates = sorted({index for index in indices if indices.count(index) > 1})
    if duplicates:
        raise ShareConsistencyError(
            "duplicate share indices "
            + ", ".join(str(index) for index in duplicates)
            + ": each x-coordinate may be used only once (did you pass the same share twice?)"
        )

    if len(parsed) < reference.threshold:
        raise ThresholdError(
            f"need at least {reference.threshold} shares to reconstruct this secret, "
            f"got {len(parsed)} (k={reference.threshold}, n={reference.total})"
        )

    ordered = sorted(parsed, key=lambda share: share.index)
    prime_field = reference.field
    chunk_count = reference.chunk_count
    if len(ordered) > reference.threshold:
        _verify_superset(ordered, reference.threshold, prime_field, chunk_count)

    chunk_values: List[int] = []
    for chunk_index in range(chunk_count):
        points = [
            (share.index, _share_chunk_value(share, chunk_index, prime_field))
            for share in ordered[: reference.threshold]
        ]
        chunk_values.append(prime_field.lagrange_at_zero(points))

    try:
        secret = _join_chunks(
            chunk_values,
            prime_field.element_bytes,
            prime_field.secret_capacity,
            reference.secret_length,
        )
    finally:
        # Best-effort scrub of the intermediate chunk integers.
        chunk_values.clear()

    commitment_verified = False
    if expected_commitment is not None:
        _check_commitment(expected_commitment, secret, "expected commitment")
        commitment_verified = True
    if reference.commitment is not None:
        _check_commitment(reference.commitment, secret, "share commitment")
        commitment_verified = True

    return CombineResult(
        secret=secret,
        field=prime_field,
        threshold=reference.threshold,
        total=reference.total,
        shares_used=len(ordered),
        commitment=reference.commitment,
        commitment_verified=commitment_verified,
        chunk_count=chunk_count,
    )


# ---------------------------------------------------------------------------
# Verification (never reconstructs)
# ---------------------------------------------------------------------------
def analyze_shares(
    items: Sequence[Union[Share, str, Dict[str, Any]]],
    *,
    sources: Optional[Sequence[str]] = None,
    failures: Sequence[Tuple[str, str]] = (),
    expected_commitment: Optional[str] = None,
) -> ShareSetAnalysis:
    """Validate a share set without interpolating anything.

    ``failures`` lets a caller inject already-known load errors (for example a
    file that failed to parse) so they appear in the same report.
    """
    entries: List[ShareEntry] = []
    position = 0
    for source, message in failures:
        entries.append(ShareEntry(position=position, source=source, error=message))
        position += 1
    for offset, item in enumerate(items):
        source = (
            sources[offset]
            if sources is not None and offset < len(sources)
            else f"input #{offset + 1}"
        )
        try:
            share = _coerce_share(item)
            share.verify_checksum()
            entries.append(ShareEntry(position=position, source=source, share=share))
        except SSSError as exc:
            entries.append(ShareEntry(position=position, source=source, error=str(exc)))
        position += 1

    problems: List[str] = []
    warnings: List[str] = []
    valid = tuple(entry.share for entry in entries if entry.share is not None)

    for entry in entries:
        if entry.error:
            problems.append(f"{entry.source}: {entry.error}")

    threshold: Optional[int] = None
    total: Optional[int] = None
    analysis_field: Optional[PrimeField] = None
    commitment: Optional[str] = None
    secret_length: Optional[int] = None
    chunk_count: Optional[int] = None
    unique_indices: Tuple[int, ...] = ()
    sufficient = False
    consistent = bool(valid) and not failures

    if valid:
        reference = valid[0]
        threshold = reference.threshold
        total = reference.total
        analysis_field = reference.field
        commitment = reference.commitment
        secret_length = reference.secret_length
        chunk_count = reference.chunk_count
        indices = [share.index for share in valid]
        unique_indices = tuple(sorted(set(indices)))
        duplicates = sorted({index for index in indices if indices.count(index) > 1})
        if duplicates:
            consistent = False
            problems.append(
                "duplicate share indices: " + ", ".join(str(index) for index in duplicates)
            )
        for share in valid[1:]:
            if share.field.name != reference.field.name:
                consistent = False
                problems.append(
                    f"field mismatch: {share.field.name} vs {reference.field.name}"
                )
            if (share.threshold, share.total) != (reference.threshold, reference.total):
                consistent = False
                problems.append(
                    f"parameter mismatch: (k={share.threshold}, n={share.total}) vs "
                    f"(k={reference.threshold}, n={reference.total})"
                )
            if share.secret_length != reference.secret_length:
                consistent = False
                problems.append(
                    f"secret-length mismatch: {share.secret_length} vs {reference.secret_length}"
                )
            if share.commitment != reference.commitment:
                consistent = False
                problems.append("commitment mismatch between shares")
        sufficient = len(valid) >= reference.threshold
        if not sufficient:
            problems.append(
                f"insufficient shares: {len(valid)} of the required {reference.threshold} present"
            )
        if commitment is None:
            warnings.append(
                "no secret commitment is attached: typos are still caught by per-share "
                "checksums, but a consistent set of forged shares would not be"
            )
        elif expected_commitment is not None and not hmac.compare_digest(
            commitment, expected_commitment.lower()
        ):
            consistent = False
            problems.append("shares do not match the expected commitment")
        if len(valid) > reference.threshold:
            warnings.append(
                f"{len(valid)} shares supplied; {len(valid) - reference.threshold} more than "
                "the threshold. Surplus shares are cross-checked for consistency."
            )
        if len({share.label for share in valid if share.label}) < len(valid) and any(
            share.label for share in valid
        ):
            warnings.append("some shares have no custodian label")
        if len(unique_indices) < len(valid):
            consistent = False

    elif not entries:
        problems.append("no shares supplied")

    return ShareSetAnalysis(
        entries=tuple(entries),
        problems=tuple(dict.fromkeys(problems)),
        warnings=tuple(dict.fromkeys(warnings)),
        shares=valid,
        threshold=threshold,
        total=total,
        field=analysis_field,
        commitment=commitment,
        secret_length=secret_length,
        chunk_count=chunk_count,
        unique_indices=unique_indices,
        sufficient=sufficient,
        consistent=consistent,
    )


# ---------------------------------------------------------------------------
# Input/output helpers
# ---------------------------------------------------------------------------
def _parse_share_document(text: str, origin: str) -> List[Share]:
    """Parse a file that holds one or many shares (JSON or armoured)."""
    cleaned = text.replace("\ufeff", "").strip()
    if not cleaned:
        raise ShareFormatError(f"{origin} is empty")
    if cleaned.startswith("{") or cleaned.startswith("["):
        try:
            data = json.loads(cleaned)
        except json.JSONDecodeError as exc:
            raise ShareFormatError(
                f"{origin} looks like JSON but does not parse ({exc.msg} at line {exc.lineno})"
            ) from exc
        if isinstance(data, list):
            return [Share.from_dict(item) for item in data]
        if isinstance(data, dict) and "shares" in data:
            payload = data["shares"]
            if not isinstance(payload, list):
                raise ShareFormatError(f"{origin}: 'shares' must be a list")
            return [Share.from_dict(item) for item in payload]
        if isinstance(data, dict):
            return [Share.from_dict(data)]
        raise ShareFormatError(f"{origin} does not contain a share object")
    tokens = [token for token in cleaned.split() if token.upper().startswith("SSS")]
    if not tokens:
        raise ShareFormatError(
            f"{origin} contains no armoured share (expected a token starting with 'SSS-V1-')"
        )
    return [Share.from_armored(token) for token in tokens]


def load_share_inputs(
    specs: Iterable[str],
    *,
    stdin_text: Optional[str] = None,
) -> List[Share]:
    """Resolve CLI share arguments: file paths, ``-`` (stdin), or inline strings."""
    shares: List[Share] = []
    for spec in specs:
        if spec == "-":
            text = stdin_text if stdin_text is not None else sys.stdin.read()
            shares.extend(_parse_share_document(text, "stdin"))
            continue
        candidate = Path(spec)
        try:
            is_file = candidate.is_file()
        except OSError:
            is_file = False
        if is_file:
            try:
                text = candidate.read_text(encoding="utf-8")
            except UnicodeDecodeError:
                try:
                    text = candidate.read_text(encoding="latin-1")
                except OSError as exc:
                    raise ShareFormatError(f"cannot read {candidate}: {exc}") from exc
            except OSError as exc:
                raise ShareFormatError(f"cannot read {candidate}: {exc}") from exc
            shares.extend(_parse_share_document(text, str(candidate)))
        elif spec.strip().startswith(("{", "[", "SSS", "sss")):
            shares.extend(_parse_share_document(spec, "inline share"))
        else:
            raise ShareFormatError(
                f"{spec!r} is neither an existing file nor an armoured share string"
            )
    return shares


def load_share_inputs_detailed(
    specs: Iterable[str],
    *,
    stdin_text: Optional[str] = None,
) -> Tuple[List[Share], List[Tuple[str, str]]]:
    """Like :func:`load_share_inputs` but collects per-source failures."""
    shares: List[Share] = []
    failures: List[Tuple[str, str]] = []
    for spec in specs:
        label = "stdin" if spec == "-" else spec
        try:
            shares.extend(load_share_inputs([spec], stdin_text=stdin_text))
        except SSSError as exc:
            failures.append((label, str(exc)))
    return shares, failures


def write_share_files(
    shares: Sequence[Share],
    out_dir: Union[str, Path],
    *,
    fmt: str = "both",
    prefix: str = "share",
    force: bool = False,
) -> List[Path]:
    """Write share files (``0600``) into a private directory (``0700``)."""
    if fmt not in ("armored", "json", "both"):
        raise ShareFormatError("format must be one of: armored, json, both")
    prefix = str(prefix).strip()
    if not prefix or prefix in (".", "..") or Path(prefix).name != prefix or ".." in prefix:
        raise ShareFormatError("share file prefix must be a plain file-name fragment")
    directory = secure_makedirs(out_dir)
    written: List[Path] = []
    for share in shares:
        stem = f"{prefix}-{share.index:02d}-of-{share.total:02d}"
        if fmt in ("json", "both"):
            path = directory / f"{stem}.json"
            atomic_write_text(path, share.to_json(), force=force)
            written.append(path)
        if fmt in ("armored", "both"):
            path = directory / f"{stem}.txt"
            header = (
                f"# Shamir secret share {share.index} of {share.total} "
                f"(threshold {share.threshold}, {share.field.label})\n"
                f"# checksum {share.checksum}"
                + (f", custodian {share.label}\n" if share.label else "\n")
                + "# Keep this file offline. Never store k shares together.\n"
            )
            atomic_write_text(path, header + share.to_armored() + "\n", force=force)
            written.append(path)
    return written


def shares_to_json_bundle(shares: Sequence[Share]) -> str:
    """Serialise several shares into one JSON document (convenient for archives)."""
    bundle = {
        "format": "sss-share-bundle",
        "version": 1,
        "shares": [share.to_dict() for share in shares],
    }
    return json.dumps(bundle, indent=2) + "\n"


def parse_hex_secret(text: str) -> bytes:
    """Decode a hex secret, tolerating ``0x``, spaces, colons and dashes."""
    if not isinstance(text, str):
        raise ShareFormatError("hex secret must be a string")
    cleaned = text.strip().lower()
    if cleaned.startswith("0x"):
        cleaned = cleaned[2:]
    for separator in (" ", ":", "-", "_"):
        cleaned = cleaned.replace(separator, "")
    if not cleaned:
        raise ShareFormatError("hex secret is empty")
    if len(cleaned) % 2:
        raise ShareFormatError("hex secret must have an even number of digits")
    try:
        return bytes.fromhex(cleaned)
    except ValueError as exc:
        raise ShareFormatError(f"hex secret contains non-hex characters: {exc}") from exc

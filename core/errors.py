"""Typed exception hierarchy shared by every module in the toolkit.

Every failure that a user can meaningfully act on derives from :class:`SSSError`
and carries ``exit_code = 2`` so the CLI can map cryptographic / validation
failures onto a distinct process status without leaking tracebacks.
"""

from __future__ import annotations

__all__ = [
    "SSSError",
    "FieldError",
    "ShareFormatError",
    "ChecksumError",
    "ThresholdError",
    "ShareConsistencyError",
    "CommitmentError",
    "OutputError",
    "VaultError",
    "DependencyError",
]


class SSSError(Exception):
    """Base class for all expected, user-actionable errors."""

    exit_code = 2


class FieldError(SSSError):
    """Raised when a value, modulus or polynomial operation is invalid in GF(p)."""


class ShareFormatError(SSSError):
    """Raised when a share cannot be parsed or violates the format grammar."""


class ChecksumError(ShareFormatError):
    """Raised when a share's truncated SHA-256 integrity tag does not match."""


class ThresholdError(SSSError):
    """Raised when there are too few shares to reconstruct the secret."""


class ShareConsistencyError(SSSError):
    """Raised when shares disagree about parameters, x-indices or their payload."""


class CommitmentError(SSSError):
    """Raised when the reconstructed secret does not match the commitment hash."""


class OutputError(SSSError):
    """Raised when an output path is unsafe, unwritable or would be clobbered."""


class VaultError(SSSError):
    """Raised for envelope-encryption failures (authentication, I/O, envelope)."""


class DependencyError(SSSError):
    """Raised when an optional dependency is required but missing."""

"""Shamir's Secret Sharing toolkit -- exact threshold cryptography over GF(p).

Public surface
--------------
* :class:`core.finite_field.PrimeField` -- modular arithmetic, Horner
  evaluation and Lagrange interpolation.
* :func:`core.shamir.split` / :func:`core.shamir.combine` -- the ``(k, n)``
  threshold scheme with checksummed, human-copyable shares.
* :func:`core.vault.lock_file` / :func:`core.vault.unlock_file` --
  AES-256-GCM envelope encryption with a Shamir-protected DEK.
"""

from __future__ import annotations

__version__ = "1.0.0"

__all__ = ["__version__"]

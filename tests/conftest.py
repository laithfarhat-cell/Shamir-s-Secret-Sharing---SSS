"""Shared pytest fixtures and helpers for the Shamir SSS test-suite."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:  # allows `pytest` from any working directory
    sys.path.insert(0, str(ROOT))

from core.shamir import Share, split  # noqa: E402


@pytest.fixture
def field():
    from core.finite_field import get_field

    return get_field("m521")


@pytest.fixture
def secret() -> bytes:
    return b"correct horse battery staple"


@pytest.fixture
def split_3_of_5(secret: bytes):
    return split(secret, 3, 5)


@pytest.fixture
def armored_shares(split_3_of_5) -> list[str]:
    return [share.to_armored() for share in split_3_of_5.shares]


def make_share_with_payload(share: Share, y: bytes) -> Share:
    """Rebuild a share with a modified payload and a *valid* checksum.

    Models an attacker who understands the format: per-share checksums alone
    cannot stop them, which is exactly why commitments and superset checks exist.
    """
    return Share.build(
        field=share.field,
        threshold=share.threshold,
        total=share.total,
        index=share.index,
        secret_length=share.secret_length,
        y=y,
        commitment=share.commitment,
        label=share.label,
        created_at=share.created_at,
    )

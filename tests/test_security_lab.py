"""Tests for the k-1 zero-leakage demonstration."""

from __future__ import annotations

import secrets

import pytest

from cli.interface import UI
from core.errors import SSSError, ThresholdError
from core.finite_field import horner_eval, polynomial_degree
from core.shamir import combine, split
from simulation.security_lab import (
    CandidateResult,
    LabReport,
    _analyse_candidate,
    _default_candidates,
    _normalise_candidate,
    main as lab_main,
    run_lab,
)


@pytest.fixture
def quiet_ui():
    return UI(quiet=True)


def _quorum(secret: bytes, k: int = 3, n: int = 5):
    result = split(secret, k, n)
    quorum = result.shares[: k - 1]
    held = result.shares[k - 1 :]
    quorum_points = [(share.index, share.chunk_values[0]) for share in quorum]
    held_points = [(share.index, share.chunk_values[0]) for share in held]
    return result, quorum_points, held_points


# ---------------------------------------------------------------------------
# The mathematical core
# ---------------------------------------------------------------------------
def test_every_candidate_polynomial_fits_the_quorum():
    secret = b"the one true secret"
    result, quorum_points, held_points = _quorum(secret)
    field = result.field
    candidates = [
        ("true", secret),
        ("zeros", b"\x00" * len(secret)),
        ("ones", b"\xff" * len(secret)),
        ("random", secrets.token_bytes(len(secret))),
    ]
    results = [
        _analyse_candidate(label, candidate, field, quorum_points, held_points)
        for label, candidate in candidates
    ]
    assert all(candidate.consistent_with_quorum for candidate in results)
    assert [candidate.label for candidate in results if candidate.matches_held_out] == ["true"]
    for candidate in results:
        assert len(candidate.polynomial) == 3
        assert polynomial_degree(candidate.polynomial) == 2
        assert candidate.polynomial[0] == int.from_bytes(candidate.secret, "big")
        for x, y in quorum_points:
            assert horner_eval(candidate.polynomial, x, field.p) == y


def test_candidate_polynomials_are_distinct():
    secret = b"distinct polynomials"
    result, quorum_points, held = _quorum(secret)
    first = _analyse_candidate("a", b"\x00" * len(secret), result.field, quorum_points, held)
    second = _analyse_candidate("b", b"\x01" * len(secret), result.field, quorum_points, held)
    assert first.polynomial != second.polynomial
    assert first.consistent_with_quorum and second.consistent_with_quorum


def test_held_out_share_pins_the_secret_uniquely():
    secret = secrets.token_bytes(24)
    result, quorum_points, held_points = _quorum(secret)
    candidates = [("true", secret), ("zeros", b"\x00" * len(secret))]
    matches = [
        label
        for label, candidate in candidates
        if _analyse_candidate(label, candidate, result.field, quorum_points, held_points).matches_held_out
    ]
    assert matches == ["true"]
    assert combine(result.shares[:3]).secret == secret


def test_k_two_leaks_nothing_with_one_share():
    secret = b"two of n"
    result, quorum_points, held_points = _quorum(secret, k=2, n=4)
    assert len(quorum_points) == 1
    for candidate in (b"aaaaaaa", b"bbbbbbb", secrets.token_bytes(len(secret))):
        analysis = _analyse_candidate("c", candidate, result.field, quorum_points, held_points)
        assert analysis.consistent_with_quorum
        assert not analysis.matches_held_out


# ---------------------------------------------------------------------------
# The lab runner
# ---------------------------------------------------------------------------
def test_default_lab_run_is_verified(quiet_ui):
    report = run_lab(k=3, n=5, ui=quiet_ui)
    assert isinstance(report, LabReport)
    assert report.verified is True
    assert report.all_candidates_consistent
    assert report.threshold == 3 and report.total == 5
    assert report.field.name == "m521"
    assert report.quorum_indices == (1, 2)
    assert len(report.held_out_indices) == 3
    assert len(report.candidates) >= 4
    assert len(report.matching_candidates) == 1
    assert report.matching_candidates[0].label == "true secret"
    assert report.recovered_secret == report.true_secret


def test_lab_with_custom_secret_and_candidates(quiet_ui):
    secret = b"custom demo secret!!"
    report = run_lab(
        k=4,
        n=7,
        secret=secret,
        candidates=[b"guess number one!!!", b"\x00" * len(secret)],
        ui=quiet_ui,
    )
    assert report.verified
    assert report.threshold == 4
    assert report.quorum_indices == (1, 2, 3)
    labels = {candidate.label for candidate in report.candidates}
    assert len(labels) == 2
    assert all(label.startswith("user candidate") for label in labels)
    assert all(candidate.consistent_with_quorum for candidate in report.candidates)
    assert not any(candidate.matches_held_out for candidate in report.candidates)


def test_lab_report_candidate_fields(quiet_ui):
    report = run_lab(k=3, n=5, ui=quiet_ui)
    for candidate in report.candidates:
        assert isinstance(candidate, CandidateResult)
        assert len(candidate.secret) == report.secret_length
        assert len(candidate.polynomial) == 3
        assert candidate.short_hex()
        assert candidate.leading_hex()
        assert 0 <= candidate.degree <= 2


def test_lab_with_real_shares(quiet_ui):
    secret = b"real shares"
    result = split(secret, 3, 5)
    report = run_lab(shares=result.shares[:4], ui=quiet_ui)
    assert report.verified
    assert report.threshold == 3
    # A quorum was supplied, so the lab can state the ground truth it recovered.
    assert report.true_secret == secret
    assert report.recovered_secret == secret
    assert report.matching_candidates[0].label == "true secret"
    assert report.quorum_indices == (1, 2)
    assert report.held_out_indices == (3, 4)


def test_lab_with_exactly_k_minus_one_real_shares(quiet_ui):
    result = split(b"bare quorum", 3, 5)
    report = run_lab(shares=result.shares[:2], ui=quiet_ui)
    assert report.verified
    assert report.held_out_indices == ()
    assert report.matching_candidates == ()
    assert report.recovered_secret is None


def test_lab_with_too_few_shares(quiet_ui):
    result = split(b"too few", 4, 6)
    with pytest.raises(ThresholdError):
        run_lab(shares=result.shares[:1], ui=quiet_ui)


def test_lab_rejects_invalid_parameters(quiet_ui):
    for k, n in ((1, 3), (4, 3), (0, 0)):
        with pytest.raises(SSSError):
            run_lab(k=k, n=n, ui=quiet_ui)


def test_lab_rejects_multi_chunk_secret(quiet_ui):
    with pytest.raises(SSSError, match="single-chunk"):
        run_lab(k=3, n=5, secret=secrets.token_bytes(2000), ui=quiet_ui)


def test_candidate_normalisation():
    padded, note = _normalise_candidate(b"abc", 5)
    assert padded == b"abc\x00\x00" and "padded" in note
    truncated, note = _normalise_candidate(b"abcdef", 3)
    assert truncated == b"abc" and "truncated" in note
    same, note = _normalise_candidate(b"abc", 3)
    assert same == b"abc" and note == ""


def test_short_candidate_is_zero_padded_and_labelled(quiet_ui):
    report = run_lab(k=3, n=5, candidates=[b"short"], ui=quiet_ui)
    assert report.candidates[0].label.endswith("(zero-padded)")
    assert report.candidates[0].consistent_with_quorum


def test_default_candidates_include_boundaries():
    candidates = _default_candidates(b"secret", 6)
    labels = [label for label, _ in candidates]
    assert "true secret" in labels
    assert "all 0x00" in labels
    assert "all 0xFF" in labels
    assert "random guess" in labels

    without_truth = _default_candidates(None, 6)
    assert [label for label, _ in without_truth] == ["all 0x00", "all 0xFF", "random guess"]


def test_lab_interactive_mode(quiet_ui, monkeypatch):
    answers = iter(["my guess", "another guess", "q"])
    prompts: list[str] = []

    def fake_input(prompt=""):
        prompts.append(prompt)
        return next(answers)

    monkeypatch.setattr("builtins.input", fake_input)
    report = run_lab(k=3, n=5, interactive=True, ui=quiet_ui)
    assert report.verified
    assert len(prompts) == 3
    assert all("candidate secret" in prompt for prompt in prompts)


def test_lab_interactive_eof(quiet_ui, monkeypatch):
    def raise_eof(prompt=""):
        raise EOFError

    monkeypatch.setattr("builtins.input", raise_eof)
    assert run_lab(k=3, n=5, interactive=True, ui=quiet_ui).verified


def test_lab_module_entrypoint():
    assert lab_main(["-k", "3", "-n", "5", "--quiet"]) == 0
    assert lab_main(["-k", "1", "-n", "5", "--quiet"]) == 2


def test_lab_prints_ground_truth_and_verdict(capsys):
    ui = UI()
    report = run_lab(k=3, n=5, ui=ui)
    out = capsys.readouterr().out
    assert report.verified
    assert "Ground truth" in out
    assert "Verdict" in out
    assert "2^-521" in out
    assert "Shamir's Secret Sharing" in out

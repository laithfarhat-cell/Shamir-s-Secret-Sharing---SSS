"""End-to-end tests for the Shamir splitter, reconstructor and share format.

Coverage highlights
-------------------
* exact ``k``-of-``n`` recovery for every subset, ``> k`` recovery, ``< k`` failure
* duplicate share rejection, bit-flip tamper detection, forged-share detection
* boundary parameters ``k = n = 2`` and ``k = n = 20``
* leading-zero preservation and multi-chunk payloads
* armoured/JSON round-trips, checksums, commitments and input validation
* information-theoretic behaviour: every candidate secret fits ``k - 1`` shares
"""

from __future__ import annotations

import itertools
import json
import secrets

import pytest

from core.errors import (
    ChecksumError,
    CommitmentError,
    OutputError,
    ShareConsistencyError,
    ShareFormatError,
    SSSError,
    ThresholdError,
)
from core.finite_field import horner_eval, interpolate_coefficients, polynomial_degree
from core.shamir import (
    MAX_SHARES,
    Share,
    analyze_shares,
    combine,
    load_share_inputs,
    load_share_inputs_detailed,
    parse_armored,
    parse_hex_secret,
    shares_to_json_bundle,
    split,
    write_share_files,
)

from tests.conftest import make_share_with_payload


# ---------------------------------------------------------------------------
# Correctness of the threshold scheme
# ---------------------------------------------------------------------------
def test_exact_threshold_recovers_secret(split_3_of_5, secret):
    result = combine(split_3_of_5.shares[:3])
    assert result.secret == secret
    assert result.shares_used == 3
    assert result.threshold == 3 and result.total == 5
    assert result.field.name == "m521"


def test_every_k_subset_recovers_secret(split_3_of_5, secret):
    for subset in itertools.combinations(split_3_of_5.shares, 3):
        assert combine(subset).secret == secret


def test_more_than_threshold_recovers_secret(split_3_of_5, secret):
    assert combine(split_3_of_5.shares).secret == secret
    assert combine(split_3_of_5.shares).shares_used == 5


def test_fewer_than_threshold_is_rejected(split_3_of_5):
    with pytest.raises(ThresholdError, match="need at least 3"):
        combine(split_3_of_5.shares[:2])
    with pytest.raises(ThresholdError):
        combine([])


def test_duplicate_shares_are_rejected(split_3_of_5):
    share = split_3_of_5.shares[0]
    with pytest.raises(ShareConsistencyError, match="duplicate share indices"):
        combine([share, share, split_3_of_5.shares[1]])


def test_indices_cover_one_to_n(split_3_of_5):
    assert [share.index for share in split_3_of_5.shares] == [1, 2, 3, 4, 5]


def test_x_zero_is_never_a_share(split_3_of_5):
    assert 0 not in [share.index for share in split_3_of_5.shares]


@pytest.mark.parametrize("k,n", [(2, 2), (2, 3), (3, 3), (5, 9), (20, 20)])
def test_boundary_parameters(k, n):
    secret = secrets.token_bytes(32)
    result = split(secret, k, n)
    assert len(result.shares) == n
    assert combine(result.shares[:k]).secret == secret
    assert combine(list(reversed(result.shares))[:k]).secret == secret
    if n > k:
        assert combine(result.shares).secret == secret


def test_k_equals_n_twenty_all_shares_required():
    secret = b"twenty custodians, no single point of failure"
    result = split(secret, 20, 20)
    with pytest.raises(ThresholdError):
        combine(result.shares[:19])
    assert combine(result.shares).secret == secret


def test_all_zeros_and_leading_zero_secret():
    secret = b"\x00\x00\x00\x01" + b"\x00" * 10
    result = split(secret, 3, 5)
    assert combine(result.shares[:3]).secret == secret


def test_random_binary_secrets_roundtrip():
    for length in (1, 2, 16, 31, 32, 64, 65, 100, 300):
        secret = secrets.token_bytes(length)
        result = split(secret, 3, 5)
        assert combine(result.shares[1:4]).secret == secret


def test_secret_is_recovered_from_a_different_subset_each_time(split_3_of_5, secret):
    for subset in ([0, 1, 4], [0, 2, 3], [1, 3, 4], [2, 3, 4]):
        shares = [split_3_of_5.shares[index] for index in subset]
        assert combine(shares).secret == secret


# ---------------------------------------------------------------------------
# Polynomial properties
# ---------------------------------------------------------------------------
def test_polynomial_degree_is_exactly_k_minus_one(split_3_of_5, field):
    points = [(share.index, share.chunk_values[0]) for share in split_3_of_5.shares[:3]]
    coefficients = interpolate_coefficients(points, field.p)
    assert polynomial_degree(coefficients) == 2
    assert coefficients[0] == int.from_bytes(b"correct horse battery staple", "big")
    # Every share lies on that polynomial.
    for share in split_3_of_5.shares:
        assert horner_eval(coefficients, share.index, field.p) == share.chunk_values[0]


def test_polynomial_degree_can_be_relaxed(field):
    secret = b"relaxed degree"
    result = split(secret, 4, 6, require_exact_degree=False)
    points = [(share.index, share.chunk_values[0]) for share in result.shares[:4]]
    coefficients = interpolate_coefficients(points, field.p)
    assert len(coefficients) == 4
    assert polynomial_degree(coefficients) <= 3
    assert combine(result.shares[:4]).secret == secret


def test_two_splits_of_the_same_secret_differ(secret):
    first = split(secret, 3, 5)
    second = split(secret, 3, 5)
    assert [share.y for share in first.shares] != [share.y for share in second.shares]
    assert first.shares[0].y != second.shares[0].y


def test_shares_are_full_width(field):
    result = split(b"short", 2, 3)
    for share in result.shares:
        assert len(share.y) == field.element_bytes * result.chunk_count
        assert all(value < field.p for value in share.chunk_values)


def test_every_candidate_secret_fits_k_minus_one_shares(field, split_3_of_5):
    """The core perfect-secrecy property, checked by construction."""
    quorum = split_3_of_5.shares[:2]
    quorum_points = [(share.index, share.chunk_values[0]) for share in quorum]
    length = split_3_of_5.secret_length
    candidates = [
        b"\x00" * length,
        b"\xff" * length,
        secrets.token_bytes(length),
        b"another plausible secret!!!!",
    ]
    for candidate in candidates:
        coefficients = field.interpolate([(0, int.from_bytes(candidate, "big")), *quorum_points])
        assert polynomial_degree(coefficients) <= 2
        assert coefficients[0] == int.from_bytes(candidate, "big")
        for x, y in quorum_points:
            assert horner_eval(coefficients, x, field.p) == y


# ---------------------------------------------------------------------------
# Length, chunking and field selection
# ---------------------------------------------------------------------------
def test_auto_field_selection_by_length():
    assert split(b"x" * 65, 2, 3).field.name == "m521"
    assert split(b"x" * 66, 2, 3).field.name == "m2281"


def test_chunking_for_long_payloads(field):
    secret = secrets.token_bytes(300)
    result = split(secret, 3, 5, field="m521")
    assert result.chunk_count == 5  # 5 × 65 = 325 bytes
    assert len(result.shares[0].y) == 5 * field.element_bytes
    assert combine(result.shares[:3]).secret == secret


def test_m2281_field_for_large_payloads():
    secret = secrets.token_bytes(600)
    result = split(secret, 2, 3, field="m2281")
    assert result.field.name == "m2281"
    assert result.chunk_count == 3  # 3 × 285 = 855 bytes
    assert combine(result.shares[:2]).secret == secret


def test_large_payload_auto_chunking():
    secret = secrets.token_bytes(2000)
    result = split(secret, 3, 5)
    assert result.field.name == "m2281"
    assert combine(result.shares[2:5]).secret == secret


def test_secret_length_is_preserved_with_leading_zeros():
    for padding in (1, 5, 65):
        secret = b"\x00" * padding + secrets.token_bytes(20)
        result = split(secret, 2, 3, field="m521")
        recovered = combine(result.shares[:2]).secret
        assert recovered == secret
        assert len(recovered) == len(secret)


def test_inconsistent_padding_is_detected(field):
    result = split(b"padding check", 2, 3)
    # Forge a share whose y decodes to a value with a non-zero "pad" region.
    share = result.shares[0]
    forged_y = (field.p - 1).to_bytes(field.element_bytes, "big")
    forged = make_share_with_payload(share, forged_y)
    with pytest.raises((ShareConsistencyError, CommitmentError)):
        combine([forged, result.shares[1], result.shares[2]])


# ---------------------------------------------------------------------------
# Armoured and JSON serialisation
# ---------------------------------------------------------------------------
def test_armored_roundtrip(split_3_of_5):
    share = split_3_of_5.shares[2]
    armored = share.to_armored()
    assert armored.startswith("SSS-V1-m521-3-5-3-")
    assert " " not in armored and "\n" not in armored
    parsed = parse_armored(armored)
    for key in ("index", "threshold", "total", "secret_length", "y", "checksum", "commitment"):
        assert getattr(parsed, key) == getattr(share, key)


def test_armored_ignores_whitespace_and_case(split_3_of_5):
    armored = split_3_of_5.shares[0].to_armored()
    wrapped = "\n".join(armored[i : i + 37] for i in range(0, len(armored), 37))
    assert combine([wrapped, split_3_of_5.shares[1].to_armored(), split_3_of_5.shares[2].to_armored()]).secret == (
        b"correct horse battery staple"
    )
    lowered = "sss-v1" + armored[len("SSS-V1") :]
    assert parse_armored(lowered).index == 1


def test_armored_contains_commitment_when_present():
    result = split(b"committed secret", 2, 3, commitment=True)
    armored = result.shares[0].to_armored()
    assert armored.count("-") >= 8
    parsed = parse_armored(armored)
    assert parsed.commitment == result.commitment
    assert len(parsed.commitment) == 64


def test_json_roundtrip(split_3_of_5):
    share = split_3_of_5.shares[3]
    restored = Share.from_dict(json.loads(share.to_json()))
    assert restored.describe() == share.describe()
    assert restored.to_armored() == share.to_armored()


def test_json_share_accepts_unknown_keys(split_3_of_5):
    data = split_3_of_5.shares[0].to_dict()
    data["future_field"] = {"anything": 1}
    assert Share.from_dict(data).index == 1


def test_combine_accepts_mixed_input_types(split_3_of_5, secret):
    share_objects = list(split_3_of_5.shares[:3])
    mixed = [share_objects[0].to_armored(), share_objects[1].to_dict(), json.dumps(share_objects[2].to_dict())]
    assert combine(mixed).secret == secret
    assert combine([share.to_armored().encode() for share in share_objects]).secret == secret


def test_json_bundle_roundtrip(tmp_path, split_3_of_5, secret):
    bundle = tmp_path / "bundle.json"
    bundle.write_text(shares_to_json_bundle(split_3_of_5.shares))
    assert combine(load_share_inputs([str(bundle)])).secret == secret


def test_share_file_with_comments_is_parsed(tmp_path, split_3_of_5, secret):
    path = tmp_path / "share.txt"
    path.write_text("# custodian Alice\n\n" + split_3_of_5.shares[0].to_armored() + "\n")
    loaded = load_share_inputs([str(path)])
    assert len(loaded) == 1
    assert combine([loaded[0], *split_3_of_5.shares[1:3]]).secret == secret


def test_stdin_share_input(split_3_of_5, secret):
    text = "\n".join(share.to_armored() for share in split_3_of_5.shares[:3])
    loaded = load_share_inputs(["-"], stdin_text=text)
    assert combine(loaded).secret == secret


def test_detailed_loader_collects_failures(tmp_path, split_3_of_5):
    good = write_share_files(split_3_of_5.shares[:1], tmp_path, fmt="armored")[0]
    shares, failures = load_share_inputs_detailed([str(good), "not-a-share", str(tmp_path / "missing.json")])
    assert len(shares) == 1
    assert len(failures) == 2


# ---------------------------------------------------------------------------
# Integrity: checksums, tampering and commitments
# ---------------------------------------------------------------------------
def test_armored_bit_flip_is_detected(split_3_of_5):
    armored = split_3_of_5.shares[0].to_armored()
    # Flip one base64 character inside the payload token.
    parts = armored.split("-")
    payload = parts[7]
    flipped = list(payload)
    flipped[3] = "A" if flipped[3] != "A" else "B"
    parts[7] = "".join(flipped)
    with pytest.raises(ChecksumError):
        parse_armored("-".join(parts))


def test_metadata_tamper_is_detected(split_3_of_5):
    armored = split_3_of_5.shares[0].to_armored()
    # Change the declared secret length: the checksum no longer matches.
    tampered = armored.replace("-3-5-1-28-", "-3-5-1-29-")
    assert tampered != armored
    with pytest.raises(ChecksumError):
        parse_armored(tampered)


def test_checksum_field_tamper_is_detected(split_3_of_5):
    armored = split_3_of_5.shares[0].to_armored()
    with pytest.raises(ChecksumError):
        parse_armored(armored[:-3] + "AAA")


def test_programmatic_share_with_bad_checksum_is_rejected(split_3_of_5):
    share = split_3_of_5.shares[0]
    bad = Share(
        field=share.field,
        threshold=share.threshold,
        total=share.total,
        index=share.index,
        secret_length=share.secret_length,
        y=share.y,
        checksum="AAAAAAAAAAA",
    )
    with pytest.raises(ChecksumError):
        combine([bad, split_3_of_5.shares[1], split_3_of_5.shares[2]])


def test_forged_surplus_share_is_detected(split_3_of_5, secret):
    shares = list(split_3_of_5.shares)
    original = shares[4]
    flipped = bytearray(original.y)
    flipped[3] ^= 0x01
    shares[4] = make_share_with_payload(original, bytes(flipped))
    shares[4].verify_checksum()  # the forgery carries a valid checksum
    with pytest.raises(ShareConsistencyError, match="inconsistent"):
        combine(shares)


def test_forged_share_detected_in_chunked_payload(field):
    secret = secrets.token_bytes(200)
    result = split(secret, 2, 3, field="m521")
    forged_y = bytearray(result.shares[2].y)
    forged_y[-1] ^= 0x01
    forged = make_share_with_payload(result.shares[2], bytes(forged_y))
    with pytest.raises(ShareConsistencyError):
        combine([result.shares[0], result.shares[1], forged])


def test_commitment_verification_success(secret):
    result = split(secret, 3, 5, commitment=True)
    outcome = combine(result.shares[:3])
    assert outcome.commitment_verified is True
    assert outcome.commitment == result.commitment


def test_commitment_mismatch_is_detected(secret):
    result = split(secret, 3, 5, commitment=True)
    share = result.shares[0]
    forged = Share.build(
        field=share.field,
        threshold=share.threshold,
        total=share.total,
        index=share.index,
        secret_length=share.secret_length,
        y=share.y,
        commitment="00" * 32,
    )
    with pytest.raises(ShareConsistencyError, match="commitment"):
        combine([forged, result.shares[1], result.shares[2]])


def test_expected_commitment_argument(secret):
    result = split(secret, 2, 3, commitment=True)
    assert combine(result.shares[:2], expected_commitment=result.commitment).commitment_verified
    with pytest.raises(CommitmentError):
        combine(result.shares[:2], expected_commitment="ff" * 32)


def test_expected_commitment_without_share_commitment(secret):
    result = split(secret, 2, 3)
    with pytest.raises(CommitmentError):
        combine(result.shares[:2], expected_commitment="00" * 32)


def test_commitment_detects_consistent_but_wrong_secret(secret):
    """A forged quorum that agrees internally but not with SHA-256(secret)."""
    genuine = split(secret, 2, 3, commitment=True)
    other = split(b"a different secret entirely!", 2, 3)
    forged = Share.build(
        field=other.shares[0].field,
        threshold=2,
        total=3,
        index=1,
        secret_length=other.shares[0].secret_length,
        y=other.shares[0].y,
        commitment=genuine.commitment,
    )
    with pytest.raises(CommitmentError):
        combine([forged, forged.__class__.build(
            field=other.shares[1].field,
            threshold=2,
            total=3,
            index=2,
            secret_length=other.shares[1].secret_length,
            y=other.shares[1].y,
            commitment=genuine.commitment,
        )])


# ---------------------------------------------------------------------------
# Cross-split consistency
# ---------------------------------------------------------------------------
def test_shares_from_different_parameters_are_rejected():
    first = split(b"secret one", 2, 3)
    second = split(b"secret two", 3, 5)
    with pytest.raises(ShareConsistencyError, match="different splits|different commitments"):
        combine([first.shares[0], second.shares[0], second.shares[1]])


def test_shares_with_different_fields_are_rejected():
    first = split(b"field test", 2, 3, field="m521")
    second = split(b"field test", 2, 3, field="m2281")
    with pytest.raises(ShareConsistencyError, match="different fields"):
        combine([first.shares[0], second.shares[0]])


def test_shares_with_different_secret_lengths_are_rejected():
    first = split(b"abc", 2, 3)
    second = split(b"abcd", 2, 3)
    with pytest.raises(ShareConsistencyError, match="secret length"):
        combine([first.shares[0], second.shares[0]])


# ---------------------------------------------------------------------------
# Input validation
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("k,n", [(1, 3), (0, 3), (4, 3), (3, 256), (-1, 3)])
def test_invalid_parameters_rejected(k, n):
    with pytest.raises(ShareFormatError):
        split(b"secret", k, n)


@pytest.mark.parametrize("k,n", [("3", 5), (3.0, 5), (True, 5)])
def test_non_integer_parameters_rejected(k, n):
    with pytest.raises(ShareFormatError):
        split(b"secret", k, n)


def test_max_shares_constant_is_documented():
    assert MAX_SHARES == 255


@pytest.mark.parametrize("secret", [b"", bytearray(), memoryview(b"")])
def test_empty_secret_rejected(secret):
    with pytest.raises(ShareFormatError):
        split(secret, 2, 3)


@pytest.mark.parametrize("secret", [123, None, ["a"], 3.5])
def test_invalid_secret_types_rejected(secret):
    with pytest.raises(ShareFormatError):
        split(secret, 2, 3)


def test_string_secret_is_utf8_encoded():
    result = split("pässword ✓", 2, 3)
    assert combine(result.shares[:2]).secret == "pässword ✓".encode("utf-8")


def test_labels_are_validated_and_serialised():
    result = split(b"labelled", 2, 3, labels=["Alice", "Bob", None])
    assert [share.label for share in result.shares] == ["Alice", "Bob", None]
    assert result.shares[0].to_dict()["label"] == "Alice"
    assert "label" not in result.shares[2].to_dict()
    with pytest.raises(ShareFormatError):
        split(b"labelled", 2, 3, labels=["only-one"])
    with pytest.raises(ShareFormatError):
        split(b"labelled", 2, 3, labels=["a" * 65, None, None])


def test_armored_malformed_inputs():
    good = split(b"malformed check", 2, 3).shares[0].to_armored()
    assert parse_armored(good).index == 1

    bad_inputs = [
        "",
        "   ",
        "SSS-V1",
        "NOT-A-SHARE",
        "SSS-V2-m521-2-3-1-20-AAAA-BBBB",
        "SSS-V1-m999-2-3-1-20-AAAA-BBBB",
        "SSS-V1-m521-1-3-1-20-AAAA-BBBB",
        "SSS-V1-m521-4-3-1-20-AAAA-BBBB",
        "SSS-V1-m521-2-3-0-20-AAAA-BBBB",
        "SSS-V1-m521-2-3-4-20-AAAA-BBBB",
        "SSS-V1-m521-2-3-1-0-AAAA-BBBB",
        "SSS-V1-m521-2-3-1-20-!!!!-BBBB",
        "SSS-V1-m521-2-3-1-20",
        good + "-extra-field",
        good.replace("-2-3-1-15-", "-2-3-1-16-"),
    ]
    for text in bad_inputs:
        with pytest.raises(SSSError):
            parse_armored(text)


def test_armored_wrong_version_message_is_specific():
    with pytest.raises(ShareFormatError, match="version"):
        parse_armored("SSS-V9-m521-2-3-1-20-AAAA-BBBB")


def test_invalid_commitment_format_rejected():
    result = split(b"commitment format", 2, 3)
    data = result.shares[0].to_dict()
    data["commitment"] = "xyz"
    with pytest.raises(ShareFormatError):
        Share.from_dict(data)


def test_json_validation_errors():
    result = split(b"json validation", 2, 3)
    data = result.shares[0].to_dict()
    for key in ("field", "threshold", "total", "index", "y", "checksum"):
        broken = dict(data)
        del broken[key]
        with pytest.raises(ShareFormatError):
            Share.from_dict(broken)
    broken = dict(data)
    broken["format"] = "something-else"
    with pytest.raises(ShareFormatError):
        Share.from_dict(broken)
    broken = dict(data)
    broken["version"] = 99
    with pytest.raises(ShareFormatError):
        Share.from_dict(broken)
    broken = dict(data)
    broken["threshold"] = "3"
    with pytest.raises(ShareFormatError):
        Share.from_dict(broken)


def test_parse_hex_secret_variants():
    assert parse_hex_secret("00ff") == b"\x00\xff"
    assert parse_hex_secret("0x00FF") == b"\x00\xff"
    assert parse_hex_secret("00:11:22") == b"\x00\x11\x22"
    assert parse_hex_secret("00 11 22") == b"\x00\x11\x22"
    assert parse_hex_secret("00-11-22") == b"\x00\x11\x22"
    for bad in ("", "0x", "abc", "zz"):
        with pytest.raises(ShareFormatError):
            parse_hex_secret(bad)


def test_hex_secret_roundtrip_via_cli_helper():
    secret = secrets.token_bytes(32)
    result = split(parse_hex_secret(secret.hex()), 2, 3)
    assert combine(result.shares[:2]).secret == secret


# ---------------------------------------------------------------------------
# Verification reports (no reconstruction)
# ---------------------------------------------------------------------------
def test_analyze_valid_set(split_3_of_5):
    analysis = analyze_shares(split_3_of_5.shares)
    assert analysis.ok and analysis.consistent and analysis.sufficient
    assert analysis.verdict == "valid"
    assert analysis.threshold == 3 and analysis.total == 5
    assert analysis.unique_indices == (1, 2, 3, 4, 5)
    assert analysis.problems == ()
    assert not hasattr(analysis, "secret")


def test_analyze_insufficient_set(split_3_of_5):
    analysis = analyze_shares(split_3_of_5.shares[:2])
    assert analysis.consistent
    assert not analysis.sufficient
    assert analysis.verdict == "insufficient"
    assert analysis.missing == 1
    assert any("insufficient" in problem for problem in analysis.problems)


def test_analyze_duplicate_indices(split_3_of_5):
    analysis = analyze_shares([split_3_of_5.shares[0], split_3_of_5.shares[0]])
    assert not analysis.consistent
    assert any("duplicate" in problem for problem in analysis.problems)


def test_analyze_records_parse_failures(split_3_of_5):
    analysis = analyze_shares(
        split_3_of_5.shares[:2],
        failures=[("bad.txt", "checksum mismatch")],
    )
    assert not analysis.consistent
    assert analysis.entries[0].error == "checksum mismatch"
    assert any("bad.txt" in problem for problem in analysis.problems)


def test_analyze_mixed_parameters():
    first = split(b"aaa", 2, 3)
    second = split(b"bbb", 3, 5)
    analysis = analyze_shares([first.shares[0], second.shares[0]])
    assert not analysis.consistent
    assert any("parameter mismatch" in problem for problem in analysis.problems)


def test_analyze_commitment_expectation(secret):
    result = split(secret, 2, 3, commitment=True)
    good = analyze_shares(result.shares, expected_commitment=result.commitment)
    assert good.ok
    bad = analyze_shares(result.shares, expected_commitment="00" * 32)
    assert not bad.consistent


def test_analyze_warns_without_commitment(split_3_of_5):
    analysis = analyze_shares(split_3_of_5.shares)
    assert any("commitment" in warning for warning in analysis.warnings)


def test_analyze_empty_input():
    analysis = analyze_shares([])
    assert not analysis.ok
    assert analysis.problems


# ---------------------------------------------------------------------------
# File output
# ---------------------------------------------------------------------------
def test_write_share_files_layout_and_permissions(tmp_path, split_3_of_5):
    directory = tmp_path / "shares"
    paths = write_share_files(split_3_of_5.shares, directory, fmt="both")
    assert len(paths) == 10
    for path in paths:
        assert path.exists()
        assert oct(path.stat().st_mode & 0o777) == "0o600"
        assert path.read_text()
    assert oct(directory.stat().st_mode & 0o777) == "0o700"
    json_path = directory / "share-03-of-05.json"
    text_path = directory / "share-03-of-05.txt"
    assert json.loads(json_path.read_text())["index"] == 3
    assert text_path.read_text().splitlines()[-1].startswith("SSS-V1-")


def test_write_share_files_refuses_overwrite(tmp_path, split_3_of_5):
    write_share_files(split_3_of_5.shares[:1], tmp_path, fmt="json")
    with pytest.raises(OutputError):
        write_share_files(split_3_of_5.shares[:1], tmp_path, fmt="json")
    write_share_files(split_3_of_5.shares[:1], tmp_path, fmt="json", force=True)


def test_write_share_files_custom_prefix_and_armored_only(tmp_path, split_3_of_5):
    paths = write_share_files(split_3_of_5.shares[:2], tmp_path, fmt="armored", prefix="vault-share")
    assert [path.name for path in paths] == [
        "vault-share-01-of-05.txt",
        "vault-share-02-of-05.txt",
    ]


def test_load_share_inputs_rejects_unknown(tmp_path):
    with pytest.raises(ShareFormatError):
        load_share_inputs([str(tmp_path / "nothing.json")])


# ---------------------------------------------------------------------------
# Structural sanity of the share format
# ---------------------------------------------------------------------------
def test_share_checksum_covers_every_metadata_field(secret):
    result = split(secret, 3, 5)
    share = result.shares[0]
    baseline = share.compute_checksum(
        share.field.name,
        share.threshold,
        share.total,
        share.index,
        share.secret_length,
        share.y_b64,
        share.commitment,
    )
    assert baseline == share.checksum
    variants = [
        ("m2281", share.threshold, share.total, share.index, share.secret_length),
        (share.field.name, 4, share.total, share.index, share.secret_length),
        (share.field.name, share.threshold, 6, share.index, share.secret_length),
        (share.field.name, share.threshold, share.total, 4, share.secret_length),
        (share.field.name, share.threshold, share.total, share.index, share.secret_length + 1),
    ]
    for field_name, k, n, index, length in variants:
        assert (
            share.compute_checksum(field_name, k, n, index, length, share.y_b64, share.commitment)
            != baseline
        )


def test_share_checksums_are_stable_across_processes(secret):
    """No timestamps or randomness may enter the checksum."""
    first = split(secret, 2, 3, created_at="2020-01-01T00:00:00Z")
    second = split(secret, 2, 3, created_at="2030-01-01T00:00:00Z")
    # Same metadata and payload -> same checksum; y differs because coefficients differ.
    assert first.shares[0].compute_checksum(
        "m521", 2, 3, 1, first.secret_length, first.shares[0].y_b64, None
    ) == first.shares[0].checksum
    assert first.shares[0].created_at == "2020-01-01T00:00:00Z"
    assert second.shares[0].created_at == "2030-01-01T00:00:00Z"


def test_combine_result_repr_hides_secret(secret):
    result = combine(split(secret, 2, 3).shares[:2])
    text = repr(result)
    assert "redacted" in text
    assert secret.decode() not in text


def test_split_result_repr_is_informative(secret):
    result = split(secret, 3, 5)
    assert "k=3" in repr(result) and "n=5" in repr(result)
    assert result.to_dict()["format"] == "sss-split"
    assert len(result.armored()) == 5


def test_timestamps_are_iso8601_utc(secret):
    result = split(secret, 2, 3)
    assert result.created_at.endswith("Z")
    assert all(share.created_at == result.created_at for share in result.shares)


def test_secret_bytes_are_never_stored_in_share_metadata(secret):
    result = split(secret, 2, 3)
    payload = json.dumps([share.to_dict() for share in result.shares])
    assert secret.hex() not in payload
    assert "correct horse" not in payload


def test_share_set_uses_one_file_per_share(tmp_path, split_3_of_5):
    paths = write_share_files(split_3_of_5.shares, tmp_path, fmt="armored")
    loaded = load_share_inputs([str(path) for path in paths[:3]])
    assert len(loaded) == 3
    assert len({share.index for share in loaded}) == 3


# ---------------------------------------------------------------------------
# Additional structural validation
# ---------------------------------------------------------------------------
def test_write_share_files_rejects_unsafe_prefix(tmp_path, split_3_of_5):
    for prefix in ("../evil", "sub/dir", "..", "", "   "):
        with pytest.raises(ShareFormatError):
            write_share_files(split_3_of_5.shares[:1], tmp_path, prefix=prefix)
    with pytest.raises(ShareFormatError):
        write_share_files(split_3_of_5.shares[:1], tmp_path, fmt="yaml")


def test_labels_reject_control_characters():
    with pytest.raises(ShareFormatError, match="printable"):
        split(b"x", 2, 3, labels=["bad\nlabel", None, None])


def test_share_json_rejects_wrong_types(split_3_of_5):
    base = split_3_of_5.shares[0].to_dict()
    cases = [
        ("y", 123),
        ("checksum", None),
        ("label", 5),
        ("created_at", []),
        ("commitment", 42),
    ]
    for key, value in cases:
        data = dict(base)
        data[key] = value
        with pytest.raises(ShareFormatError):
            Share.from_dict(data)
    with pytest.raises(ShareFormatError, match="object"):
        Share.from_dict(["not", "an", "object"])  # type: ignore[arg-type]


def test_share_payload_length_must_match_chunk_count(field):
    share = split(b"chunk check", 2, 3).shares[0]
    with pytest.raises(ShareFormatError, match="multiple"):
        Share.build(
            field=field,
            threshold=2,
            total=3,
            index=1,
            secret_length=share.secret_length,
            y=b"\x00" * (field.element_bytes - 1),
        )
    with pytest.raises(ShareFormatError, match="chunk"):
        Share.build(
            field=field,
            threshold=2,
            total=3,
            index=1,
            secret_length=share.secret_length,
            y=b"\x00" * (2 * field.element_bytes),
        )


def test_share_chunk_must_be_below_p(field):
    with pytest.raises(ShareFormatError, match="canonical"):
        Share.build(
            field=field,
            threshold=2,
            total=3,
            index=1,
            secret_length=field.secret_capacity,
            y=field.p.to_bytes(field.element_bytes, "big"),
        )


def test_share_requires_bytes_payload(field):
    with pytest.raises(ShareFormatError, match="bytes"):
        Share(
            field=field,
            threshold=2,
            total=3,
            index=1,
            secret_length=1,
            y="not-bytes",  # type: ignore[arg-type]
            checksum="AAAAAAAAAAA",
        )


@pytest.mark.parametrize(
    "threshold,total,index,secret_length",
    [
        (1, 3, 1, 64),
        (4, 3, 1, 64),
        (2, 3, 0, 64),
        (2, 3, 4, 64),
        (2, 3, 1, 0),
        (2, 3, 1, -5),
        (2, 300, 1, 64),
    ],
)
def test_share_metadata_validation(field, threshold, total, index, secret_length):
    with pytest.raises(ShareFormatError):
        Share.build(
            field=field,
            threshold=threshold,
            total=total,
            index=index,
            secret_length=secret_length,
            y=b"\x00" * field.element_bytes,
        )


def test_load_share_inputs_rejects_directory(tmp_path):
    with pytest.raises(ShareFormatError, match="neither an existing file"):
        load_share_inputs([str(tmp_path)])


def test_parse_share_document_errors(tmp_path):
    bad_json = tmp_path / "bad.json"
    bad_json.write_text("{ this is not json")
    with pytest.raises(ShareFormatError, match="does not parse"):
        load_share_inputs([str(bad_json)])

    empty = tmp_path / "empty.txt"
    empty.write_text("   \n")
    with pytest.raises(ShareFormatError, match="is empty"):
        load_share_inputs([str(empty)])

    nothing = tmp_path / "nothing.txt"
    nothing.write_text("# just a comment\n")
    with pytest.raises(ShareFormatError, match="no armoured share"):
        load_share_inputs([str(nothing)])

    bundle = tmp_path / "bundle.json"
    bundle.write_text(json.dumps({"format": "sss-share-bundle", "shares": "nope"}))
    with pytest.raises(ShareFormatError, match="list"):
        load_share_inputs([str(bundle)])


def test_load_json_list_document(tmp_path, split_3_of_5):
    path = tmp_path / "list.json"
    path.write_text(json.dumps([share.to_dict() for share in split_3_of_5.shares[:3]]))
    loaded = load_share_inputs([str(path)])
    assert len(loaded) == 3
    assert combine(loaded).secret == b"correct horse battery staple"


def test_combine_rejects_bundle_dict():
    share = split(b"bundle rejection", 2, 3).shares[0]
    with pytest.raises(ShareFormatError, match="bundle"):
        combine([{"shares": [share.to_dict()]}])


def test_analyze_invalid_inline_share():
    analysis = analyze_shares(["SSS-V1-m521-9-9-1-1-AAAA-BBBB"])
    assert not analysis.ok
    assert analysis.entries[0].error
    assert not analysis.shares

"""Arithmetic and interpolation tests for :mod:`core.finite_field`."""

from __future__ import annotations

import random
import secrets
from dataclasses import FrozenInstanceError

import pytest

from core.errors import FieldError
from core.finite_field import (
    MERSENNE_EXPONENTS,
    PrimeField,
    available_fields,
    batch_invert,
    field_for_length,
    get_field,
    horner_eval,
    interpolate_coefficients,
    lagrange_coefficients,
    lagrange_interpolate_at_zero,
    lucas_lehmer,
    mod_add,
    mod_inv,
    mod_mul,
    mod_neg,
    mod_sub,
    polynomial_degree,
    resolve_field,
)


# ---------------------------------------------------------------------------
# Field parameters
# ---------------------------------------------------------------------------
def test_registered_fields_are_the_documented_mersenne_primes():
    fields = available_fields()
    assert [prime.exponent for prime in fields] == sorted(MERSENNE_EXPONENTS)
    for prime_field in fields:
        assert prime_field.p == (1 << prime_field.exponent) - 1
        assert prime_field.verify_primality()


@pytest.mark.parametrize("exponent", [521, 2281])
def test_field_capacities(exponent):
    prime_field = get_field(exponent)
    assert prime_field.name == f"m{exponent}"
    # Every secret_capacity-byte integer must be a valid field element.
    assert (1 << (8 * prime_field.secret_capacity)) <= prime_field.p
    assert prime_field.secret_capacity == (exponent - 1) // 8
    # Field elements themselves need the extra byte(s).
    assert prime_field.element_bytes == (exponent + 7) // 8
    assert prime_field.p - 1 < (1 << (8 * prime_field.element_bytes))
    assert len(prime_field.encode(prime_field.p - 1)) == prime_field.element_bytes


def test_get_field_accepts_name_exponent_and_object():
    assert get_field("m521") is get_field(521) is get_field(get_field("m521"))
    assert get_field("M521") is get_field("521") is get_field("2^521")


@pytest.mark.parametrize("bad", ["m1024", "foo", 127, 3.5, None])
def test_get_field_rejects_unknown(bad):
    with pytest.raises(FieldError):
        get_field(bad)


def test_field_for_length_boundaries():
    assert field_for_length(1).name == "m521"
    assert field_for_length(65).name == "m521"
    assert field_for_length(66).name == "m2281"
    assert field_for_length(285).name == "m2281"
    with pytest.raises(FieldError):
        field_for_length(286)
    with pytest.raises(FieldError):
        field_for_length(0)


def test_resolve_field_auto_and_chunking_fallback():
    assert resolve_field("auto", 32).name == "m521"
    assert resolve_field("auto", 100).name == "m2281"
    # Beyond the largest capacity the caller chunks with the largest field.
    assert resolve_field("auto", 1000).name == "m2281"
    assert resolve_field("m521", 1000).name == "m521"


def test_lucas_lehmer_known_values():
    for exponent in (2, 3, 5, 7, 13, 17, 19, 31, 61, 521):
        assert lucas_lehmer(exponent), exponent
    for exponent in (0, 1, 4, 9, 11, 23, 29, 6, 15):
        assert not lucas_lehmer(exponent), exponent


def test_prime_field_is_frozen():
    prime_field = get_field("m521")
    with pytest.raises(FrozenInstanceError):
        prime_field.exponent = 3  # type: ignore[misc]


# ---------------------------------------------------------------------------
# Scalar arithmetic
# ---------------------------------------------------------------------------
def test_modular_operations_are_canonical(field):
    p = field.p
    rng = random.Random(1234)
    for _ in range(200):
        a = rng.randrange(-2 * p, 2 * p)
        b = rng.randrange(1, p)
        assert 0 <= mod_add(a, b, p) < p
        assert 0 <= mod_sub(a, b, p) < p
        assert 0 <= mod_mul(a, b, p) < p
        assert 0 <= mod_neg(a, p) < p
        assert (mod_add(a, b, p) + mod_sub(a, b, p)) % p == (2 * a) % p


def test_inverse_roundtrip(field):
    p = field.p
    for value in [1, 2, 3, p - 1, p // 2, secrets.randbelow(p - 1) + 1]:
        inverse = mod_inv(value, p)
        assert (value * inverse) % p == 1
        assert field.inverse(value) == inverse
        assert field.divide(value, value) == 1


def test_inverse_of_zero_raises(field):
    with pytest.raises(FieldError):
        mod_inv(0, field.p)
    with pytest.raises(FieldError):
        field.inverse(0)


def test_fermat_little_theorem(field):
    a = secrets.randbelow(field.p - 1) + 1
    assert pow(a, field.p - 1, field.p) == 1
    assert field.power(a, field.p - 1) == 1


def test_batch_invert_matches_individual(field):
    p = field.p
    values = [secrets.randbelow(p - 1) + 1 for _ in range(17)]
    batched = batch_invert(values, p)
    assert batched == [mod_inv(value, p) for value in values]
    assert batch_invert([], p) == []
    with pytest.raises(FieldError):
        batch_invert([1, 0, 2], p)


def test_field_contains_and_check(field):
    assert field.contains(0) and field.contains(field.p - 1)
    assert not field.contains(field.p)
    assert not field.contains(-1)
    with pytest.raises(FieldError):
        field.check(field.p)
    with pytest.raises(FieldError):
        field.check("3")
    with pytest.raises(FieldError):
        field.check(True)


def test_encode_decode_roundtrip(field):
    for value in (0, 1, 255, 256, field.p - 1):
        encoded = field.encode(value)
        assert len(encoded) == field.element_bytes
        assert field.decode(encoded) == value
    with pytest.raises(FieldError):
        field.encode(field.p)
    with pytest.raises(FieldError):
        field.decode(field.encode(field.p - 1) + b"\x00")


# ---------------------------------------------------------------------------
# Horner evaluation
# ---------------------------------------------------------------------------
def _naive_eval(coefficients, x, p):
    total = 0
    for index, coefficient in enumerate(coefficients):
        total = (total + coefficient * pow(x, index, p)) % p
    return total


def test_horner_matches_naive_definition(field):
    p = field.p
    for _ in range(50):
        degree = random.randrange(0, 12)
        coefficients = [random.randrange(p) for _ in range(degree + 1)]
        x = random.randrange(p)
        assert horner_eval(coefficients, x, p) == _naive_eval(coefficients, x, p)


def test_horner_edge_cases(field):
    p = field.p
    assert horner_eval([], 5, p) == 0
    assert horner_eval([7], 12345, p) == 7
    assert horner_eval([0, 0, 0], 9, p) == 0
    assert horner_eval([5, 3], 0, p) == 5
    assert polynomial_degree([1, 0, 0]) == 0
    assert polynomial_degree([0, 0]) == -1
    assert polynomial_degree([0, 2, 3]) == 2


def test_horner_known_value(field):
    # f(x) = 2 + 3x + 4x^2 ; f(5) = 2 + 15 + 100 = 117
    assert horner_eval([2, 3, 4], 5, field.p) == 117


# ---------------------------------------------------------------------------
# Lagrange interpolation
# ---------------------------------------------------------------------------
def test_lagrange_weights_sum_to_one(field):
    xs = [1, 2, 3, 4, 5]
    weights = lagrange_coefficients(xs, 0, field.p)
    assert sum(weights) % field.p == 1


def test_lagrange_recovers_constant_term(field):
    p = field.p
    coefficients = [secrets.randbelow(p) for _ in range(6)]
    xs = [1, 2, 3, 4, 5, 6]
    points = [(x, horner_eval(coefficients, x, p)) for x in xs]
    assert lagrange_interpolate_at_zero(points, p) == coefficients[0]


def test_lagrange_at_arbitrary_target_matches_horner(field):
    p = field.p
    coefficients = [secrets.randbelow(p) for _ in range(5)]
    xs = [2, 5, 9, 11, 17]
    points = [(x, horner_eval(coefficients, x, p)) for x in xs]
    weights = lagrange_coefficients(xs, 12345, p)
    reconstructed = sum(
        weight * y for weight, (_, y) in zip(weights, points, strict=True)
    ) % p
    assert reconstructed == horner_eval(coefficients, 12345, p)


def test_interpolate_coefficients_roundtrip(field):
    p = field.p
    for _ in range(20):
        degree = random.randrange(0, 8)
        coefficients = [secrets.randbelow(p) for _ in range(degree + 1)]
        xs = random.sample(range(1, 400), degree + 1)
        points = [(x, horner_eval(coefficients, x, p)) for x in xs]
        recovered = interpolate_coefficients(points, p)
        assert recovered[: degree + 1] == coefficients
        assert all(horner_eval(recovered, x, p) == y for x, y in points)


def test_interpolation_matches_lagrange_at_zero(field):
    p = field.p
    xs = [3, 8, 13, 21, 34]
    coefficients = [secrets.randbelow(p) for _ in range(5)]
    points = [(x, horner_eval(coefficients, x, p)) for x in xs]
    assert interpolate_coefficients(points, p)[0] == lagrange_interpolate_at_zero(points, p)


def test_duplicate_x_rejected(field):
    with pytest.raises(FieldError):
        lagrange_coefficients([1, 2, 2], 0, field.p)
    with pytest.raises(FieldError):
        interpolate_coefficients([(1, 5), (1, 6)], field.p)
    with pytest.raises(FieldError):
        lagrange_interpolate_at_zero([], field.p)


def test_single_point_interpolation(field):
    assert lagrange_interpolate_at_zero([(7, 42)], field.p) == 42
    assert interpolate_coefficients([(0, 42)], field.p) == [42]


def test_points_are_reduced_modulo_p(field):
    p = field.p
    coefficients = [3, 5, 7]
    xs = [11, 12, 13]
    points = [
        (x, horner_eval(coefficients, x, p) + (p if index == 0 else 0))
        for index, x in enumerate(xs)
    ]
    # y-values congruent modulo p must interpolate identically.
    assert lagrange_interpolate_at_zero(points, p) == 3
    # A target of p is the same field element as 0.
    assert lagrange_coefficients([1, 2, 3], p, p) == lagrange_coefficients([1, 2, 3], 0, p)


def test_prime_field_helpers_delegate(field):
    coefficients = [4, 2, 9]
    assert field.horner(coefficients, 3) == horner_eval(coefficients, 3, field.p)
    points = [(1, 31), (2, 51), (3, 79)]
    assert field.lagrange_at_zero(points) == lagrange_interpolate_at_zero(points, field.p)
    assert field.interpolate(points) == interpolate_coefficients(points, field.p)


def test_random_sampling_is_in_range(field):
    rng = random.Random(7)
    for _ in range(100):
        assert 0 <= field.random_element(rng) < field.p
        assert 1 <= field.random_nonzero(rng) < field.p


def test_prime_field_construction_rejects_bad_exponent():
    with pytest.raises(FieldError):
        PrimeField(exponent=1)
    with pytest.raises(FieldError):
        PrimeField(exponent="521")  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# Defensive branches
# ---------------------------------------------------------------------------
def test_encode_width_validation(field):
    with pytest.raises(FieldError):
        field.encode(1, width=0)
    with pytest.raises(FieldError):
        field.encode(field.p - 1, width=2)


def test_decode_requires_bytes(field):
    with pytest.raises(FieldError):
        field.decode("not bytes")  # type: ignore[arg-type]


def test_random_element_with_randrange_only(field):
    class RandrangeOnly:
        def randrange(self, bound):
            return bound - 1

    rng = RandrangeOnly()
    assert field.random_element(rng) == field.p - 1
    assert field.random_nonzero(rng) == field.p - 1


def test_verify_primality_is_cached(field):
    assert field.verify_primality() is True
    assert field.verify_primality() is True


def test_field_labels(field):
    assert field.label == "GF(2^521 - 1)"
    assert field.name == "m521"
    assert str(field) == field.label


def test_resolve_field_unknown_raises():
    with pytest.raises(FieldError):
        resolve_field("m1024", 10)


def test_lagrange_requires_points(field):
    with pytest.raises(FieldError):
        lagrange_coefficients([], 0, field.p)


def test_field_for_length_rejects_non_integer():
    with pytest.raises(FieldError):
        field_for_length("65")  # type: ignore[arg-type]

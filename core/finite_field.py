"""Exact arithmetic in the prime field :math:`\\mathbb{F}_p = GF(p)`.

Everything in this module is built from Python's arbitrary-precision integers:
there is no floating point anywhere in the code-path, so polynomial
interpolation is *exact* for every value representable in the field.

Contents
--------
* :class:`PrimeField` -- an immutable prime-field descriptor with the full
  arithmetic API (add / sub / mul / neg / inverse / divide / power), byte
  encoding helpers and cryptographically secure sampling.
* Module level functions (:func:`horner_eval`,
  :func:`lagrange_coefficients`, :func:`lagrange_interpolate_at_zero`,
  :func:`interpolate_coefficients`) that operate on plain ``int`` values plus a
  modulus, for callers that prefer a functional style.
* A registry of the Mersenne prime fields used for secret sharing
  (:math:`p = 2^{521} - 1`, :math:`p = 2^{2281} - 1`).

Why Mersenne primes?
--------------------
``p = 2^e - 1`` has an extremely dense representation (all 521 or 2281 bits are
one-bits), is a documented, standardised modulus, and -- most importantly -- is
large enough that a 32-byte AES key, a BIP-39 seed or a 64-byte master key maps
to an integer strictly below ``p``.  Deterministic primality for these moduli is
established with the Lucas-Lehmer test (:func:`lucas_lehmer`), which is a
*proof* of primality rather than a probabilistic claim.
"""

from __future__ import annotations

import secrets
from dataclasses import dataclass
from dataclasses import field as dataclass_field
from typing import List, Optional, Sequence, Tuple, Union

from core.errors import FieldError

__all__ = [
    "PrimeField",
    "get_field",
    "available_fields",
    "field_for_length",
    "resolve_field",
    "mod_add",
    "mod_sub",
    "mod_mul",
    "mod_neg",
    "mod_inv",
    "batch_invert",
    "horner_eval",
    "lagrange_coefficients",
    "lagrange_interpolate_at_zero",
    "interpolate_coefficients",
    "polynomial_degree",
    "lucas_lehmer",
    "is_mersenne_prime",
    "DEFAULT_EXPONENT",
    "MERSENNE_EXPONENTS",
]

#: Mersenne exponents registered for secret sharing, smallest first.
MERSENNE_EXPONENTS: Tuple[int, ...] = (521, 2281)

#: Field used by default for short secrets (keys, seeds, passwords).
DEFAULT_EXPONENT = 521


# ---------------------------------------------------------------------------
# Scalar arithmetic
# ---------------------------------------------------------------------------
def mod_add(a: int, b: int, p: int) -> int:
    """Return ``(a + b) mod p`` with ``0 <= result < p``."""
    return (a + b) % p


def mod_sub(a: int, b: int, p: int) -> int:
    """Return ``(a - b) mod p`` with ``0 <= result < p``."""
    return (a - b) % p


def mod_mul(a: int, b: int, p: int) -> int:
    """Return ``(a * b) mod p``."""
    return (a * b) % p


def mod_neg(a: int, p: int) -> int:
    """Return the additive inverse ``-a mod p``."""
    return (-a) % p


def mod_inv(a: int, p: int) -> int:
    """Return the multiplicative inverse of ``a`` modulo the prime ``p``.

    Uses the extended Euclidean algorithm through :func:`pow` (Python >= 3.8),
    with Fermat's little theorem ``a^(p-2) mod p`` as a belt-and-braces
    fallback.  ``a`` must not be congruent to ``0``.
    """
    a %= p
    if a == 0:
        raise FieldError("0 has no multiplicative inverse in GF(p)")
    try:
        return pow(a, -1, p)
    except (ValueError, TypeError):  # pragma: no cover - very old interpreters
        return pow(a, p - 2, p)


def batch_invert(values: Sequence[int], p: int) -> List[int]:
    """Invert several non-zero field elements with a single modular inversion.

    Montgomery's batched-inversion trick: build the prefix products, invert the
    total product once, then walk backwards recovering each inverse with one
    multiplication.  ``n`` inversions become ``3n`` multiplications plus one
    exponentiation -- a meaningful speed-up when ``k`` grows.
    """
    n = len(values)
    if n == 0:
        return []
    normalised = [v % p for v in values]
    prefix: List[int] = [1] * n
    accumulator = 1
    for i, value in enumerate(normalised):
        if value == 0:
            raise FieldError("cannot invert 0 in GF(p)")
        prefix[i] = accumulator
        accumulator = (accumulator * value) % p
    inverse_total = mod_inv(accumulator, p)
    inverses: List[int] = [0] * n
    for i in range(n - 1, -1, -1):
        inverses[i] = (inverse_total * prefix[i]) % p
        inverse_total = (inverse_total * normalised[i]) % p
    return inverses


# ---------------------------------------------------------------------------
# Polynomial evaluation: Horner's method
# ---------------------------------------------------------------------------
def horner_eval(coefficients: Sequence[int], x: int, p: int) -> int:
    """Evaluate ``sum(a_i * x^i)`` by Horner's rule in ``O(k)`` field operations.

    ``coefficients`` is ordered low-to-high: ``[a_0, a_1, ..., a_{k-1}]``.

        f(x) = a_0 + x * (a_1 + x * (a_2 + ... + x * a_{k-1}))

    This performs exactly ``k - 1`` multiplications and ``k - 1`` additions and
    never materialises ``x**i``, so it is both faster and numerically safer than
    the naive power-sum form (there is no intermediate blow-up before the final
    reduction modulo ``p``).
    """
    if not coefficients:
        return 0 % p
    if not isinstance(x, int):  # pragma: no cover - defensive
        raise FieldError("the evaluation point x must be an integer")
    x %= p
    result = coefficients[-1] % p
    for coefficient in reversed(coefficients[:-1]):
        result = (result * x + coefficient) % p
    return result


def polynomial_degree(coefficients: Sequence[int]) -> int:
    """Return the degree of the polynomial, or ``-1`` for the zero polynomial."""
    for index in range(len(coefficients) - 1, -1, -1):
        if coefficients[index]:
            return index
    return -1


# ---------------------------------------------------------------------------
# Lagrange interpolation
# ---------------------------------------------------------------------------
def _check_distinct(xs: Sequence[int], p: int) -> None:
    seen = set()
    for x in xs:
        value = x % p
        if value in seen:
            raise FieldError(f"interpolation points must have distinct x-values; {value} is repeated")
        seen.add(value)


def lagrange_coefficients(xs: Sequence[int], x_target: int, p: int) -> List[int]:
    """Return the Lagrange basis weights ``c_i`` such that ``f(x_target) = sum c_i y_i``.

    For nodes :math:`x_1, \\dots, x_k`:

    .. math::

        c_i = \\prod_{j \\neq i} \\frac{x_{target} - x_j}{x_i - x_j} \\pmod p

    The numerators and denominators are accumulated separately and all
    denominators are inverted in one batch, giving ``O(k^2)`` field
    multiplications and a single modular inversion.
    """
    k = len(xs)
    if k == 0:
        raise FieldError("at least one interpolation point is required")
    xs = [x % p for x in xs]
    _check_distinct(xs, p)
    target = x_target % p

    numerators: List[int] = []
    denominators: List[int] = []
    for i, xi in enumerate(xs):
        numerator = 1
        denominator = 1
        for j, xj in enumerate(xs):
            if i == j:
                continue
            numerator = (numerator * ((target - xj) % p)) % p
            denominator = (denominator * ((xi - xj) % p)) % p
        numerators.append(numerator)
        denominators.append(denominator)

    inverses = batch_invert(denominators, p) if k > 1 else [1]
    return [(numerators[i] * inverses[i]) % p for i in range(k)]


def lagrange_interpolate_at_zero(points: Sequence[Tuple[int, int]], p: int) -> int:
    """Recover ``f(0)`` -- i.e. the constant term / secret -- from share points.

    .. math::

        S = f(0) = \\sum_{i=1}^{k} y_i \\prod_{j \\neq i} \\frac{-x_j}{x_i - x_j}
                 \\pmod p

    The x-values must be distinct; the y-values are reduced modulo ``p``.
    """
    if not points:
        raise FieldError("at least one share point is required")
    xs = [x for x, _ in points]
    ys = [y for _, y in points]
    weights = lagrange_coefficients(xs, 0, p)
    total = 0
    for weight, y in zip(weights, ys, strict=True):
        total = (total + weight * y) % p
    return total


def _poly_mul_linear(coefficients: Sequence[int], root: int, p: int) -> List[int]:
    """Multiply a polynomial by ``(x - root)`` in ``O(deg)``."""
    out = [0] * (len(coefficients) + 1)
    for i, coefficient in enumerate(coefficients):
        c = coefficient % p
        out[i] = (out[i] - c * root) % p
        out[i + 1] = (out[i + 1] + c) % p
    return out


def interpolate_coefficients(points: Sequence[Tuple[int, int]], p: int) -> List[int]:
    """Return the unique polynomial through ``points`` in the standard basis.

    The result is ``[a_0, a_1, ..., a_{k-1}]`` (low-to-high), with ``a_i < p``.
    Newton's divided-difference form is used internally and then expanded with
    Horner synthetics, so the whole interpolation costs ``O(k^2)`` field
    operations and one batched inversion per difference level.

    Existence and uniqueness follow from the Vandermonde matrix being
    invertible whenever the ``x_i`` are pairwise distinct in a field.
    """
    k = len(points)
    if k == 0:
        raise FieldError("at least one interpolation point is required")
    xs = [x % p for x, _ in points]
    ys = [y % p for _, y in points]
    _check_distinct(xs, p)

    # Newton divided differences, computed in place.
    divided = list(ys)
    for level in range(1, k):
        denominators = [((xs[i] - xs[i - level]) % p) for i in range(level, k)]
        inverses = batch_invert(denominators, p)
        for i in range(k - 1, level - 1, -1):
            divided[i] = ((divided[i] - divided[i - 1]) % p) * inverses[i - level] % p

    # Expand the Newton form into the monomial basis.
    coefficients = [divided[k - 1] % p]
    for i in range(k - 2, -1, -1):
        coefficients = _poly_mul_linear(coefficients, xs[i], p)
        coefficients[0] = (coefficients[0] + divided[i]) % p
    return coefficients


# ---------------------------------------------------------------------------
# Primality certification for Mersenne numbers
# ---------------------------------------------------------------------------
def _is_small_prime(n: int) -> bool:
    if n < 2:
        return False
    if n % 2 == 0:
        return n == 2
    divisor = 3
    while divisor * divisor <= n:
        if n % divisor == 0:
            return False
        divisor += 2
    return True


def lucas_lehmer(exponent: int) -> bool:
    """Deterministic Lucas-Lehmer primality test for :math:`M_e = 2^e - 1`.

    ``M_e`` is prime iff ``e`` is prime and the Lucas-Lehmer sequence
    ``s_0 = 4``, ``s_{n+1} = s_n^2 - 2 mod M_e`` satisfies
    ``s_{e-2} == 0``.  This is a proof, not a probabilistic screen.
    """
    if exponent < 2:
        return False
    if exponent == 2:
        return True
    if exponent % 2 == 0 or not _is_small_prime(exponent):
        return False
    modulus = (1 << exponent) - 1
    state = 4
    for _ in range(exponent - 2):
        state = (state * state - 2) % modulus
    return state == 0


def is_mersenne_prime(exponent: int) -> bool:
    """Alias of :func:`lucas_lehmer` with a descriptive name."""
    return lucas_lehmer(exponent)


# ---------------------------------------------------------------------------
# The field object
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class PrimeField:
    """An immutable prime field ``GF(p)`` with ``p = 2^exponent - 1``.

    Two widths matter and are kept distinct to avoid off-by-one bugs:

    ``secret_capacity`` (65 / 285 bytes)
        Whole input bytes that are *always* below ``p``.
    ``element_bytes`` (66 / 286 bytes)
        Fixed-width encoding for arbitrary field elements, since a share value
        can use the full 521- or 2281-bit range.
    """

    exponent: int
    p: int = dataclass_field(init=False)
    _primality_checked: bool = dataclass_field(default=False, init=False, repr=False, compare=False)

    def __post_init__(self) -> None:
        if not isinstance(self.exponent, int) or self.exponent < 2:
            raise FieldError(f"invalid field exponent: {self.exponent!r}")
        modulus = (1 << self.exponent) - 1
        object.__setattr__(self, "p", modulus)

    # -- descriptive properties ------------------------------------------
    @property
    def name(self) -> str:
        """Compact identifier used in shares: ``m521``, ``m2281``."""
        return f"m{self.exponent}"

    @property
    def bit_length(self) -> int:
        return self.exponent

    @property
    def secret_capacity(self) -> int:
        """Whole input bytes guaranteed to be strictly below ``p``.

        ``2^(8c) <= p`` is required for *any* ``c``-byte big-endian integer to be
        a valid field element, hence ``c = (exponent - 1) // 8``: 65 bytes for
        ``m521`` and 285 bytes for ``m2281``.
        """
        return (self.exponent - 1) // 8

    @property
    def element_bytes(self) -> int:
        """Fixed width used to encode *any* field element, including ``p - 1``.

        A share value may use the full 521 (or 2281) bits, so the encoded block
        is ``ceil(exponent / 8)`` bytes: 66 for ``m521``, 286 for ``m2281``.
        """
        return (self.exponent + 7) // 8

    #: Historical alias retained for readability in older notes.
    max_secret_bytes = secret_capacity

    @property
    def label(self) -> str:
        return f"GF(2^{self.exponent} - 1)"

    def __str__(self) -> str:  # pragma: no cover - cosmetic
        return self.label

    # -- validation -------------------------------------------------------
    def contains(self, value: int) -> bool:
        return isinstance(value, int) and 0 <= value < self.p

    def check(self, value: int, what: str = "value") -> int:
        """Validate that ``value`` is a canonical field element and return it."""
        if not isinstance(value, int) or isinstance(value, bool):
            raise FieldError(f"{what} must be an integer, got {type(value).__name__}")
        if not 0 <= value < self.p:
            raise FieldError(f"{what} is outside {self.label}: 0 <= {what} < p required")
        return value

    def verify_primality(self) -> bool:
        """Prove (Lucas-Lehmer) that the modulus is prime. Result is cached."""
        if not self._primality_checked:
            if not lucas_lehmer(self.exponent):
                raise FieldError(f"2^{self.exponent} - 1 is not a Mersenne prime")
            object.__setattr__(self, "_primality_checked", True)
        return True

    # -- arithmetic -------------------------------------------------------
    def add(self, a: int, b: int) -> int:
        return (a + b) % self.p

    def sub(self, a: int, b: int) -> int:
        return (a - b) % self.p

    def mul(self, a: int, b: int) -> int:
        return (a * b) % self.p

    def neg(self, a: int) -> int:
        return (-a) % self.p

    def inverse(self, a: int) -> int:
        return mod_inv(a, self.p)

    inv = inverse

    def divide(self, a: int, b: int) -> int:
        return (a * mod_inv(b, self.p)) % self.p

    def power(self, a: int, e: int) -> int:
        return pow(a % self.p, e, self.p)

    def batch_inverse(self, values: Sequence[int]) -> List[int]:
        return batch_invert(values, self.p)

    # -- encoding ---------------------------------------------------------
    def encode(self, value: int, width: Optional[int] = None) -> bytes:
        """Big-endian encode a field element, padded to ``width`` bytes.

        Defaults to :attr:`element_bytes`, which makes every encoded share a
        fixed-size block and therefore keeps concatenated chunk payloads
        unambiguous.
        """
        self.check(value)
        width = self.element_bytes if width is None else width
        if width < 1:
            raise FieldError("encoding width must be positive")
        if value.bit_length() > 8 * width:
            raise FieldError(f"value does not fit in {width} byte(s)")
        return value.to_bytes(width, "big")

    def decode(self, data: bytes, what: str = "field element") -> int:
        if not isinstance(data, (bytes, bytearray, memoryview)):
            raise FieldError(f"{what} must be bytes")
        value = int.from_bytes(bytes(data), "big")
        return self.check(value, what)

    # -- sampling ---------------------------------------------------------
    @staticmethod
    def _randbelow(rng, bound: int) -> int:
        try:
            return rng.randbelow(bound)
        except AttributeError:  # pragma: no cover - exotic RNGs
            return rng.randrange(bound)

    def random_element(self, rng=secrets) -> int:
        """Uniform element of ``GF(p)`` drawn from a CSPRNG (``secrets``)."""
        return self._randbelow(rng, self.p)

    def random_nonzero(self, rng=secrets) -> int:
        """Uniform element of ``GF(p)^*`` -- i.e. ``[1, p - 1]``."""
        return self._randbelow(rng, self.p - 1) + 1

    # -- polynomials ------------------------------------------------------
    def horner(self, coefficients: Sequence[int], x: int) -> int:
        return horner_eval(coefficients, x, self.p)

    evaluate = horner

    def lagrange_weights(self, xs: Sequence[int], x_target: int = 0) -> List[int]:
        return lagrange_coefficients(xs, x_target, self.p)

    def lagrange_at_zero(self, points: Sequence[Tuple[int, int]]) -> int:
        return lagrange_interpolate_at_zero(points, self.p)

    def interpolate(self, points: Sequence[Tuple[int, int]]) -> List[int]:
        return interpolate_coefficients(points, self.p)


# ---------------------------------------------------------------------------
# Registry helpers
# ---------------------------------------------------------------------------
_FIELD_CACHE = {}


def get_field(spec: Union[str, int, PrimeField]) -> PrimeField:
    """Look up a registered field by name (``"m521"``), exponent (``521``).

    Registered fields are exactly the Mersenne primes in
    :data:`MERSENNE_EXPONENTS`.  Unknown names raise :class:`FieldError`
    listing what is available.
    """
    if isinstance(spec, PrimeField):
        return spec
    if isinstance(spec, str):
        token = spec.strip().lower()
        if token.startswith("m"):
            token = token[1:]
        if token.startswith("2^"):
            token = token[2:]
        if not token.isdigit():
            raise FieldError(
                f"unknown field {spec!r}; expected one of "
                + ", ".join(f"m{e}" for e in MERSENNE_EXPONENTS)
            )
        exponent = int(token)
    elif isinstance(spec, int) and not isinstance(spec, bool):
        exponent = spec
    else:
        raise FieldError(f"cannot interpret {spec!r} as a prime field")
    if exponent not in MERSENNE_EXPONENTS:
        raise FieldError(
            f"field m{exponent} is not registered; available: "
            + ", ".join(f"m{e}" for e in MERSENNE_EXPONENTS)
        )
    if exponent not in _FIELD_CACHE:
        _FIELD_CACHE[exponent] = PrimeField(exponent=exponent)
    return _FIELD_CACHE[exponent]


def available_fields() -> Tuple[PrimeField, ...]:
    """All registered fields, smallest (fastest) first."""
    return tuple(get_field(e) for e in sorted(MERSENNE_EXPONENTS))


def field_for_length(nbytes: int) -> PrimeField:
    """Smallest registered field able to hold an ``nbytes`` big-endian integer."""
    if not isinstance(nbytes, int) or nbytes < 1:
        raise FieldError("secret length must be a positive number of bytes")
    for prime_field in available_fields():
        if nbytes <= prime_field.secret_capacity:
            return prime_field
    raise FieldError(
        f"{nbytes} bytes exceed the largest registered field capacity "
        f"({available_fields()[-1].secret_capacity} bytes for m{MERSENNE_EXPONENTS[-1]}); "
        "use vault mode for large payloads"
    )


def resolve_field(spec: Union[str, int, PrimeField, None], nbytes: int) -> PrimeField:
    """Resolve a user-supplied field request.

    ``None`` / ``"auto"`` picks the smallest field that holds the whole secret,
    falling back to the largest registered field (which triggers transparent
    chunking in :mod:`core.shamir`) for payloads beyond 285 bytes.
    """
    if spec is None or (isinstance(spec, str) and spec.strip().lower() == "auto"):
        try:
            return field_for_length(nbytes)
        except FieldError:
            return available_fields()[-1]
    return get_field(spec)

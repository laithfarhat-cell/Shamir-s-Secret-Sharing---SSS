"""Information-theoretic security lab: why ``k - 1`` shares leak *nothing*.

The demonstration
-----------------
Fix ``k - 1`` shares ``(x_1, y_1), ..., (x_{k-1}, y_{k-1})`` of a ``(k, n)``
Shamir split.  For **any** candidate secret :math:`S'`, the ``k`` points

.. math::

    (0, S'), (x_1, y_1), \\dots, (x_{k-1}, y_{k-1})

have pairwise distinct x-coordinates, so by the uniqueness of polynomial
interpolation there is *exactly one* polynomial of degree ``<= k - 1`` passing
through all of them.  It automatically reproduces every one of the ``k - 1``
shares, for **every** choice of :math:`S' \\in GF(p)`.

Consequently the map ``S' -> coefficients`` is a bijection between the ``p``
possible secrets and the ``p`` polynomials consistent with the observed shares.
The shares therefore carry zero bits of information about ``S``: the posterior
distribution over secrets is uniform, no matter what the prior was.

This script makes that concrete: it interpolates the unique polynomial for
several arbitrary candidates (including the true secret) and shows that all of
them are equally consistent with the reduced share set.  Adding one more share
collapses the ambiguity to a single polynomial -- the threshold effect.

Run interactively::

    python -m simulation.security_lab --interactive
    sss lab --k 4 --n 7 --candidate "my guess"

or import :func:`run_lab` and inspect the structured :class:`LabReport`.
"""

from __future__ import annotations

import argparse
import math
import secrets
import sys
from dataclasses import dataclass
from typing import Any, List, Optional, Sequence, Tuple

from core.errors import SSSError, ThresholdError
from core.finite_field import PrimeField, polynomial_degree
from core.shamir import Share, combine, split

__all__ = ["CandidateResult", "LabReport", "run_lab", "main", "DEMO_SECRET"]

#: A deliberately guessable, human-readable demo secret.
DEMO_SECRET = b"correct horse battery staple"


@dataclass(frozen=True)
class CandidateResult:
    """One hypothetical secret and the polynomial it implies."""

    label: str
    secret: bytes
    polynomial: Tuple[int, ...]
    consistent_with_quorum: bool
    matches_held_out: bool

    @property
    def degree(self) -> int:
        return polynomial_degree(self.polynomial)

    def short_hex(self, limit: int = 6) -> str:
        head = self.secret[:limit].hex()
        return head + ("…" if len(self.secret) > limit else "")

    def leading_hex(self, digits: int = 16) -> str:
        text = f"{self.polynomial[-1]:x}"
        return (text[:digits] + "…") if len(text) > digits else text


@dataclass
class LabReport:
    """Structured result of a lab run (handy for tests and CI)."""

    field: PrimeField
    threshold: int
    total: int
    quorum_indices: Tuple[int, ...]
    held_out_indices: Tuple[int, ...]
    candidates: Tuple[CandidateResult, ...]
    secret_length: int
    true_secret: Optional[bytes]
    recovered_secret: Optional[bytes]
    verified: bool

    @property
    def all_candidates_consistent(self) -> bool:
        return all(candidate.consistent_with_quorum for candidate in self.candidates)

    @property
    def matching_candidates(self) -> Tuple[CandidateResult, ...]:
        return tuple(candidate for candidate in self.candidates if candidate.matches_held_out)


def _normalise_candidate(data: bytes, length: int) -> Tuple[bytes, str]:
    """Pad/truncate a candidate to the secret length (right-hand zero padding)."""
    if len(data) == length:
        return data, ""
    if len(data) < length:
        return data + b"\x00" * (length - len(data)), " (zero-padded)"
    return data[:length], " (truncated)"


def _analyse_candidate(
    label: str,
    candidate: bytes,
    field: PrimeField,
    quorum_points: Sequence[Tuple[int, int]],
    held_out_points: Sequence[Tuple[int, int]],
) -> CandidateResult:
    secret_int = int.from_bytes(candidate, "big")
    if secret_int >= field.p:
        raise SSSError(
            f"candidate {label!r} is not a valid field element; use a shorter candidate"
        )
    polynomial = tuple(field.interpolate([(0, secret_int), *quorum_points]))
    consistent = all(field.horner(polynomial, x) == y for x, y in quorum_points)
    matches = bool(held_out_points) and all(
        field.horner(polynomial, x) == y for x, y in held_out_points
    )
    return CandidateResult(
        label=label,
        secret=candidate,
        polynomial=polynomial,
        consistent_with_quorum=consistent,
        matches_held_out=matches,
    )


def _default_candidates(true_secret: Optional[bytes], length: int) -> List[Tuple[str, bytes]]:
    """Boundary candidates plus the real secret when it is known."""
    candidates: List[Tuple[str, bytes]] = []
    if true_secret is not None:
        candidates.append(("true secret", true_secret))
    candidates.extend(
        [
            ("all 0x00", b"\x00" * length),
            ("all 0xFF", b"\xff" * length),
            ("random guess", secrets.token_bytes(length)),
        ]
    )
    return candidates


def run_lab(
    *,
    k: int = 3,
    n: int = 5,
    secret: Optional[bytes] = None,
    candidates: Optional[Sequence[bytes]] = None,
    interactive: bool = False,
    shares: Optional[Sequence[Share]] = None,
    ui: Optional[Any] = None,
    field: Any = None,
    stream: Optional[Any] = None,
) -> LabReport:
    """Run the zero-leakage demonstration and print a human-readable report."""
    if ui is None:
        from cli.interface import UI

        ui = UI(stream=stream)

    if shares:
        share_list = sorted(shares, key=lambda share: share.index)
        reference = share_list[0]
        field_obj = reference.field
        k = reference.threshold
        n = reference.total
        if len(share_list) < k - 1:
            raise ThresholdError(
                f"the lab needs at least k-1 = {k - 1} shares; got {len(share_list)}"
            )
        if reference.chunk_count != 1:
            raise SSSError(
                "the lab supports single-chunk secrets only; use a shorter secret "
                "or an explicit field with enough capacity"
            )
        quorum = share_list[: k - 1]
        held_out = share_list[k - 1 :]
        secret_length = reference.secret_length
        recovered: Optional[bytes] = None
        if len(share_list) >= k:
            recovered = combine(share_list[:k]).secret
        # When a quorum is available the lab can reveal the ground truth;
        # with only k-1 shares nothing is known and no "true secret" is offered.
        true_secret = recovered
    else:
        if not 2 <= k <= n:
            raise SSSError(f"invalid parameters: require 2 <= k <= n, got k={k}, n={n}")
        secret_bytes = bytes(secret) if secret is not None else DEMO_SECRET
        if not secret_bytes:
            raise SSSError("the demo secret must not be empty")
        split_result = split(secret_bytes, k, n, field=field)
        if split_result.chunk_count != 1:
            raise SSSError(
                "the lab supports single-chunk secrets only; choose a larger field explicitly"
            )
        field_obj = split_result.field
        share_list = list(split_result.shares)
        quorum = share_list[: k - 1]
        held_out = share_list[k - 1 :]
        secret_length = len(secret_bytes)
        true_secret = secret_bytes
        recovered = secret_bytes

    quorum_points = [(share.index, share.chunk_values[0]) for share in quorum]
    held_out_points = [(share.index, share.chunk_values[0]) for share in held_out]

    ui.banner()
    ui.section("Zero-knowledge demonstration")
    ui.kv(
        "Experiment",
        [
            ("field", f"{field_obj.label}  ({field_obj.name})"),
            ("scheme", f"{k}-of-{n} threshold"),
            ("secret", f"{secret_length} bytes (value withheld during the experiment)"),
            ("quorum shown", f"k-1 = {len(quorum)} share(s) at x = {', '.join(str(s.index) for s in quorum)}"),
            (
                "held out",
                f"{len(held_out)} share(s) at x = {', '.join(str(s.index) for s in held_out)}"
                if held_out
                else "none supplied",
            ),
        ],
    )

    ui.panel(
        "Why this works",
        [
            "Every candidate secret S' fixes the point (0, S'). Together with the",
            f"{len(quorum)} observed share(s) that is {len(quorum) + 1} points with distinct",
            f"x-coordinates, and a degree-≤{k - 1} polynomial through them is unique:",
            f"k coefficients minus {len(quorum)} constraints leaves exactly one free",
            "parameter — the secret itself. So the map S' ↦ polynomial is a bijection",
            f"between the {field_obj.bit_length}-bit field and the polynomials consistent",
            "with the shares you hold. No candidate is preferred.",
        ],
        border="cyan",
    )

    candidate_pairs: List[Tuple[str, bytes]] = []
    seen: set = set()
    if candidates:
        for index, candidate in enumerate(candidates, start=1):
            normalised, note = _normalise_candidate(bytes(candidate), secret_length)
            label = f"user candidate {index}{note}"
            if normalised not in seen:
                candidate_pairs.append((label, normalised))
                seen.add(normalised)
    else:
        for label, candidate in _default_candidates(true_secret, secret_length):
            if candidate not in seen:
                candidate_pairs.append((label, candidate))
                seen.add(candidate)

    results: List[CandidateResult] = [
        _analyse_candidate(label, candidate, field_obj, quorum_points, held_out_points)
        for label, candidate in candidate_pairs
    ]

    def render(results: Sequence[CandidateResult], title: str) -> None:
        rows = []
        for candidate in results:
            rows.append(
                [
                    candidate.label,
                    candidate.short_hex(),
                    str(candidate.degree),
                    "yes" if candidate.consistent_with_quorum else "NO",
                    ("yes" if candidate.matches_held_out else "no") if held_out_points else "n/a",
                ]
            )
        ui.table(
            [
                "candidate secret",
                "first bytes",
                "deg",
                f"fits {len(quorum)} share(s)",
                "fits k-th share",
            ],
            rows,
            title=title,
        )

    ui.section("Interpolation results")
    render(results, "Each candidate implies a different, equally valid polynomial")

    all_consistent = all(candidate.consistent_with_quorum for candidate in results)
    if all_consistent:
        ui.success(
            f"All {len(results)} candidates reproduce the {len(quorum)} observed share(s) "
            "exactly — the shares cannot tell them apart."
        )
    else:  # pragma: no cover - would indicate an implementation bug
        ui.error("At least one candidate failed to reproduce the shares: regression detected.")

    unique_matches = [candidate for candidate in results if candidate.matches_held_out]
    if held_out_points:
        if len(unique_matches) == 1:
            ui.success(
                f"Adding share x={held_out[0].index} leaves exactly one surviving candidate "
                f"({unique_matches[0].label}): the threshold is now met."
            )
        elif not unique_matches:
            ui.info(
                "None of the sampled candidates matches the k-th share — expected, since the "
                "true secret was not among them. The k-th share still determines the secret "
                "uniquely among all p possibilities."
            )
        else:  # pragma: no cover - distinct secrets cannot share a polynomial
            ui.error("More than one candidate matched the held-out share: regression detected.")

    entropy_bits = field_obj.bit_length
    probability = 2.0 ** (-entropy_bits)
    ui.panel(
        "Quantifying the leak",
        [
            f"Candidate space            : |GF(p)| = 2^{entropy_bits} - 1 secrets",
            "Consistent with k-1 shares : every candidate (bijection)",
            f"Shannon entropy of S given k-1 shares : log2(p) ≈ {math.log2(field_obj.p):.2f} bits",
            f"Best possible guess probability      : 1/p = 2^-{entropy_bits} "
            f"≈ 10^{math.log10(probability):.1f}",
            "",
            "Holding k-1 shares is therefore equivalent to holding no shares at all:",
            "the mutual information I(S; shares) is exactly 0 bits.",
        ],
        border="green",
    )

    if true_secret is not None:
        ui.panel(
            "Ground truth (revealed only for the demo)",
            [
                f"the real secret was : {true_secret.hex()}",
                f"as text             : {true_secret.decode('utf-8', 'replace')!r}",
            ],
            border="dim",
        )
    if recovered is not None and true_secret is not None and recovered != true_secret:
        ui.error("Recovered secret does not match the demo secret: regression detected.")

    if interactive:
        ui.section("Try it yourself")
        ui.info("Type any candidate secret; every one will fit the k-1 shares. 'q' quits.")
        extra: List[CandidateResult] = []
        while True:
            try:
                answer = input("candidate secret > ").strip()
            except (EOFError, KeyboardInterrupt):
                print()
                break
            if answer.lower() in ("q", "quit", "exit"):
                break
            if not answer:
                continue
            normalised, note = _normalise_candidate(answer.encode("utf-8"), secret_length)
            candidate = _analyse_candidate(
                f"interactive {len(extra) + 1}{note}",
                normalised,
                field_obj,
                quorum_points,
                held_out_points,
            )
            extra.append(candidate)
            render([candidate], "Interactive candidate")
            if candidate.consistent_with_quorum:
                ui.success("Fits every visible share — indistinguishable from the truth.")
            else:  # pragma: no cover - defensive
                ui.error("Did not fit the shares (this should be impossible).")
        if extra:
            ui.info(f"Analysed {len(extra)} interactive candidate(s); none was preferred.")

    verified = all_consistent and (not held_out_points or len(unique_matches) <= 1)
    if verified:
        ui.panel(
            "Verdict",
            [
                f"With {len(quorum)} share(s) every secret is equally likely (0 bits leaked);",
                f"with {len(quorum) + 1} share(s) exactly one polynomial remains.",
                "This is perfect secrecy in the information-theoretic sense.",
            ],
            border="green",
        )
    else:  # pragma: no cover - defensive
        ui.error("The demonstration did not hold; please report this as a bug.")

    return LabReport(
        field=field_obj,
        threshold=k,
        total=n,
        quorum_indices=tuple(share.index for share in quorum),
        held_out_indices=tuple(share.index for share in held_out),
        candidates=tuple(results),
        secret_length=secret_length,
        true_secret=true_secret,
        recovered_secret=recovered,
        verified=verified,
    )


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m simulation.security_lab",
        description="Demonstrate that k-1 Shamir shares leak zero information.",
    )
    parser.add_argument("-k", "--threshold", type=int, default=3)
    parser.add_argument("-n", "--total", type=int, default=5)
    parser.add_argument("--candidate", action="append", help="extra candidate secret (repeatable)")
    parser.add_argument("--interactive", action="store_true", help="prompt for candidates")
    parser.add_argument("--secret", help="demo secret to split (UTF-8 text)")
    parser.add_argument("--shares", nargs="+", help="analyse real shares instead of a demo")
    parser.add_argument("--quiet", action="store_true")
    parser.add_argument("--no-color", action="store_true")
    args = parser.parse_args(list(argv) if argv is not None else None)

    from cli.interface import UI

    ui = UI(quiet=args.quiet, color=not args.no_color)
    shares = None
    if args.shares:
        from core.shamir import load_share_inputs

        shares = load_share_inputs(args.shares)
    try:
        report = run_lab(
            k=args.threshold,
            n=args.total,
            secret=args.secret.encode("utf-8") if args.secret else None,
            candidates=[text.encode("utf-8") for text in args.candidate] if args.candidate else None,
            interactive=args.interactive,
            shares=shares,
            ui=ui,
        )
    except SSSError as exc:
        ui.error(str(exc))
        return exc.exit_code
    return 0 if report.verified else 2


if __name__ == "__main__":  # pragma: no cover - manual execution
    sys.exit(main())

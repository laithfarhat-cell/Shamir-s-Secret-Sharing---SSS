"""Interactive terminal interface for the Shamir Secret Sharing toolkit.

The CLI is a thin, defensive layer over :mod:`core`: it parses arguments,
resolves secrets from text/hex/stdin/files, renders share cards with ``rich``
(falling back to plain text when rich is unavailable) and maps every
:class:`SSSError` onto a clean message plus exit code ``2``.

Subcommands
-----------
``split``          split a secret into ``n`` shares (threshold ``k``)
``combine``        reconstruct a secret from share strings or files
``verify``         validate share syntax/checksums/consistency without combining
``vault-lock``     AES-256-GCM encrypt a file and Shamir-split its DEK
``vault-unlock``   rebuild the DEK and decrypt a vault
``vault-info``     inspect an authenticated vault header (no shares needed)
``lab``            run the k-1 zero-leakage demonstration
``fields``         list the registered prime fields and their capacity
"""

from __future__ import annotations

import argparse
import base64
import json
import os
import shutil
import sys
import textwrap
from pathlib import Path
from typing import Any, List, Optional, Sequence, Tuple

from core import __version__
from core.errors import SSSError
from core.finite_field import available_fields, lucas_lehmer
from core.shamir import (
    MAX_SHARES,
    Share,
    analyze_shares,
    combine,
    load_share_inputs,
    load_share_inputs_detailed,
    parse_hex_secret,
    split,
    write_share_files,
)
from core.storage import atomic_write_bytes, secure_read_bytes
from core.vault import lock_file, read_vault_header, unlock_file

try:  # pragma: no cover - exercised implicitly by both paths
    from rich import box as rich_box
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table
    from rich.text import Text

    RICH_AVAILABLE = True
except Exception:  # pragma: no cover - rich is a declared dependency
    RICH_AVAILABLE = False

MAX_SECRET_FILE_BYTES = 64 * 1024 * 1024


# ---------------------------------------------------------------------------
# Terminal UI
# ---------------------------------------------------------------------------
class UI:
    """Small presentation layer with a graceful plain-text fallback."""

    def __init__(
        self,
        *,
        quiet: bool = False,
        color: bool = True,
        stream: Optional[Any] = None,
        error_stream: Optional[Any] = None,
    ) -> None:
        self.quiet = quiet
        self.color = color and os.environ.get("NO_COLOR") is None
        self._stream = stream or sys.stdout
        self._error_stream = error_stream or sys.stderr
        self._console = None
        self._error_console = None
        if RICH_AVAILABLE:
            self._console = Console(
                highlight=False,
                no_color=not self.color,
                file=self._stream,
                soft_wrap=False,
            )
            self._error_console = Console(
                highlight=False,
                no_color=not self.color,
                file=self._error_stream,
                soft_wrap=False,
            )

    # -- low level --------------------------------------------------------
    @property
    def width(self) -> int:
        columns = shutil.get_terminal_size((84, 24)).columns
        return max(60, min(100, columns))

    def _emit(self, message: str = "") -> None:
        if self._console is not None:
            self._console.print(message)
        else:
            print(message, file=self._stream)

    def _emit_error(self, message: str) -> None:
        if self._error_console is not None:
            self._error_console.print(message)
        else:
            print(message, file=self._error_stream)

    def raw(self, text: str) -> None:
        if self._console is not None:
            self._console.print(text, markup=False, highlight=False)
        else:
            print(text, file=self._stream)

    # -- decorative -------------------------------------------------------
    def banner(self) -> None:
        if self.quiet:
            return
        subtitle = f"exact k-of-n threshold cryptography over GF(p)  ·  v{__version__}"
        if self._console is not None:
            self._console.print()
            self._console.print(
                Panel.fit(
                    Text.assemble(
                        ("Shamir's Secret Sharing\n", "bold white"),
                        (subtitle, "dim"),
                    ),
                    border_style="cyan",
                    padding=(0, 4),
                )
            )
            self._console.print()
        else:
            self.raw("=" * self.width)
            self.raw("  Shamir's Secret Sharing")
            self.raw(f"  {subtitle}")
            self.raw("=" * self.width)

    def section(self, title: str) -> None:
        if self.quiet:
            return
        if self._console is not None:
            self._console.rule(Text(title, style="bold cyan"), style="cyan")
        else:
            self.raw(f"-- {title} " + "-" * max(0, self.width - len(title) - 4))

    def info(self, message: str) -> None:
        if self.quiet:
            return
        if self._console is not None:
            self._console.print(Text("  " + message, style="white"))
        else:
            self.raw(f"  {message}")

    def success(self, message: str) -> None:
        if self.quiet:
            return
        if self._console is not None:
            self._console.print(Text("  " + message, style="bold green"))
        else:
            self.raw(f"[ok] {message}")

    def warning(self, message: str) -> None:
        if self.quiet:
            return
        if self._console is not None:
            self._console.print(Text("  " + message, style="bold yellow"))
        else:
            self.raw(f"[!] {message}")

    def error(self, message: str) -> None:
        if self._error_console is not None:
            self._error_console.print(Text("  " + message, style="bold red"))
        else:
            print(f"[x] {message}", file=self._error_stream)

    # -- structured -------------------------------------------------------
    def panel(self, title: str, lines: Sequence[str], *, border: str = "cyan") -> None:
        if self.quiet:
            return
        body = "\n".join(lines)
        if self._console is not None:
            self._console.print(
                Panel(
                    Text(body),
                    title=Text(title, style="bold"),
                    border_style=border,
                    padding=(0, 2),
                )
            )
        else:
            self._plain_box(title, lines)

    def kv(self, title: str, pairs: Sequence[Tuple[str, Any]], *, border: str = "cyan") -> None:
        if self.quiet:
            return
        if self._console is not None:
            grid = Table.grid(padding=(0, 2))
            grid.add_column(style="dim", justify="right", no_wrap=True)
            grid.add_column(overflow="fold")
            for key, value in pairs:
                grid.add_row(str(key), Text(str(value)))
            self._console.print(
                Panel(grid, title=Text(title, style="bold"), border_style=border, padding=(0, 2))
            )
        else:
            lines = [f"{key}: {value}" for key, value in pairs]
            self._plain_box(title, lines)

    def table(
        self,
        headers: Sequence[str],
        rows: Sequence[Sequence[Any]],
        *,
        title: Optional[str] = None,
        justify: Optional[Sequence[str]] = None,
    ) -> None:
        if self.quiet:
            return
        if self._console is not None:
            table = Table(
                title=Text(title, style="bold") if title else None,
                box=rich_box.SIMPLE_HEAD,
                header_style="bold cyan",
                pad_edge=False,
                show_edge=False,
            )
            for index, header in enumerate(headers):
                align = justify[index] if justify and index < len(justify) else "left"
                table.add_column(header, justify=align, overflow="fold")
            for row in rows:
                table.add_row(*[Text(str(cell)) for cell in row])
            self._console.print(table)
        else:
            if title:
                self.raw(title)
            self._plain_table(headers, rows)

    def _plain_table(self, headers: Sequence[str], rows: Sequence[Sequence[Any]]) -> None:
        cells = [[str(cell) for cell in row] for row in rows]
        widths = [len(header) for header in headers]
        for row in cells:
            for index, cell in enumerate(row):
                widths[index] = max(widths[index], len(cell))
        header_line = "  ".join(header.ljust(widths[index]) for index, header in enumerate(headers))
        self.raw(header_line)
        self.raw("  ".join("-" * width for width in widths))
        for row in cells:
            self.raw("  ".join(cell.ljust(widths[index]) for index, cell in enumerate(row)))

    def _plain_box(self, title: str, lines: Sequence[str]) -> None:
        width = self.width
        label = f" {title} " if title else ""
        self.raw("+" + label + "-" * max(0, width - len(label) - 2) + "+")
        for line in lines:
            for wrapped in textwrap.wrap(str(line), width - 4) or [""]:
                self.raw("| " + wrapped.ljust(width - 4) + " |")
        self.raw("+" + "-" * (width - 2) + "+")

    # -- domain specific ---------------------------------------------------
    def share_card(self, share: Share) -> None:
        if self.quiet:
            return
        label = f" · {share.label}" if share.label else ""
        title = f"Share {share.index} of {share.total}{label}"
        armored = share.to_armored()
        wrapped = textwrap.wrap(armored, 72) or [armored]
        lines = [
            f"threshold k={share.threshold}   field {share.field.label}   x = {share.index}",
            f"secret {share.secret_length} B   payload {len(share.y)} B   chunks {share.chunk_count}",
            f"checksum {share.checksum}"
            + (f"   commitment {share.commitment[:16]}…" if share.commitment else ""),
            "",
            *wrapped,
            "",
            "ASCII only (whitespace ignored) — safe for paper backups, QR codes, SMS.",
        ]
        self.panel(title, lines, border="green")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def _read_stdin_bytes() -> bytes:
    buffer = getattr(sys.stdin, "buffer", None)
    try:
        if buffer is not None:
            return buffer.read()
        return sys.stdin.read().encode("utf-8")
    except (AttributeError, OSError, ValueError) as exc:
        raise SSSError(f"cannot read the secret from stdin: {exc}") from exc


def _strip_single_newline(data: bytes) -> bytes:
    if data.endswith(b"\r\n"):
        return data[:-2]
    if data.endswith(b"\n"):
        return data[:-1]
    return data


def _secret_from_args(args: argparse.Namespace) -> Tuple[bytes, str]:
    if getattr(args, "secret", None) is not None:
        return args.secret.encode("utf-8"), "command-line string"
    if getattr(args, "hex_secret", None) is not None:
        return parse_hex_secret(args.hex_secret), "hex string"
    if getattr(args, "secret_file", None):
        data = secure_read_bytes(args.secret_file, max_bytes=MAX_SECRET_FILE_BYTES)
        return data, f"file {args.secret_file}"
    if getattr(args, "stdin", False) or not sys.stdin.isatty():
        data = _read_stdin_bytes()
        if not getattr(args, "no_strip", False):
            data = _strip_single_newline(data)
        return data, "stdin"
    raise SSSError(
        "no secret supplied; use --secret, --hex, --secret-file or --stdin "
        "(or pipe the secret into the command)"
    )


def _parse_labels(raw: Optional[str], total: int) -> Optional[List[Optional[str]]]:
    if not raw:
        return None
    labels: List[Optional[str]] = []
    for token in raw.split(","):
        text = token.strip()
        labels.append(text or None)
    if len(labels) != total:
        raise SSSError(f"--labels expects {total} comma-separated names, got {len(labels)}")
    return labels


def _looks_textual(data: bytes) -> bool:
    if not data:
        return False
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        return False
    return all(character.isprintable() or character in "\n\r\t" for character in text)


def _hex_block(data: bytes, width: int = 64) -> List[str]:
    digest = data.hex()
    return [digest[i : i + width] for i in range(0, len(digest), width)] or [""]


def _security_notice(ui: UI, *, vault: bool = False) -> None:
    lines = [
        "• Any k shares reconstruct the secret — any k-1 reveal nothing.",
        "• Keep each share on separate, offline media (paper, HSM, smart card).",
        "• Never store k shares in one place: that is the secret, in pieces.",
        "• Share files here are written with mode 0600 in a 0700 directory.",
        "• Terminal scrollback and shell history are not secure storage.",
    ]
    if vault:
        lines.insert(1, "• The vault holds ciphertext only; shares hold the key.")
        lines.append("• Verify the restored file before destroying the original.")
    ui.panel("Operational security checklist", lines, border="yellow")


def _field_choices() -> List[str]:
    return ["auto"] + [prime_field.name for prime_field in available_fields()]


# ---------------------------------------------------------------------------
# Handlers
# ---------------------------------------------------------------------------
def _cmd_split(args: argparse.Namespace, ui: UI) -> int:
    secret, origin = _secret_from_args(args)
    if not secret:
        raise SSSError("the secret is empty; refusing to split nothing")

    fmt = args.fmt
    if fmt is None:
        fmt = "both" if args.out_dir else "armored"
    if fmt in ("json", "both") and not args.out_dir:
        raise SSSError("--format json/both writes files and therefore requires --out-dir")

    labels = _parse_labels(args.labels, args.shares)
    result = split(
        secret,
        args.threshold,
        args.shares,
        field=args.field,
        commitment=args.commitment,
        labels=labels,
        require_exact_degree=not args.allow_degenerate_degree,
    )

    ui.banner()
    ui.section("Split")
    ui.kv(
        "Share set",
        [
            ("secret", f"{len(secret)} bytes from {origin}"),
            ("scheme", f"{result.threshold}-of-{result.total} Shamir threshold"),
            ("field", f"{result.field.label}  ({result.field.name})"),
            ("chunks", f"{result.chunk_count} × {result.field.secret_capacity} B"),
            ("commitment", result.commitment or "none (recommended default)"),
            ("created", result.created_at),
        ],
    )

    if args.out_dir:
        paths = write_share_files(
            result.shares,
            args.out_dir,
            fmt=fmt,
            prefix=args.prefix,
            force=args.force,
        )
        ui.success(f"Wrote {len(paths)} file(s) to {Path(args.out_dir).resolve()} (0600)")
        if fmt in ("json", "both"):
            ui.info("JSON shares include custodian labels and timestamps.")

    if not args.no_print_shares:
        ui.section("Distribution cards")
        for share in result.shares:
            ui.share_card(share)

    ui.section("Warnings")
    if origin == "command-line string":
        ui.warning("The secret was passed on the command line and is in your shell history.")
    if origin == "stdin":
        ui.warning("Piped secrets may persist in terminal scrollback; clear it if needed.")
    if args.out_dir:
        ui.warning("All shares are currently in one directory — distribute them now.")
    ui.warning("Use `vault-lock` for files; it encrypts with AES-256-GCM and splits only the key.")
    _security_notice(ui)
    return 0


def _cmd_combine(args: argparse.Namespace, ui: UI) -> int:
    shares = load_share_inputs(args.shares)
    if not shares:
        raise SSSError("no shares were found in the supplied inputs")
    result = combine(shares, expected_commitment=args.expected_commitment)

    written: Optional[Path] = None
    if args.out:
        written = atomic_write_bytes(args.out, result.secret, force=args.force)
        if not args.print_secret and not args.print_hex and not args.print_base64:
            pass  # do not echo a secret that the operator asked to keep in a file

    ui.banner()
    ui.section("Reconstruction")
    ui.kv(
        "Recovered secret",
        [
            ("shares used", f"{result.shares_used} of {result.total} (threshold {result.threshold})"),
            ("field", f"{result.field.label}  ({result.field.name})"),
            ("size", f"{len(result.secret)} bytes"),
            ("commitment", "verified" if result.commitment_verified else "not present"),
            ("output file", str(written) if written else "not written"),
        ],
    )

    if ui.quiet:
        # Script-friendly mode: emit only the payload on stdout.
        if written is None:
            if _looks_textual(result.secret) and not args.print_hex:
                sys.stdout.write(result.secret.decode("utf-8"))
                if not result.secret.endswith(b"\n"):
                    sys.stdout.write("\n")
            else:
                sys.stdout.write(result.secret.hex() + "\n")
        return 0

    show_payload = (
        written is None or args.print_secret or args.print_hex or args.print_base64
    )
    if show_payload:
        if args.print_hex:
            ui.panel(
                "Secret (hex)",
                _hex_block(result.secret),
                border="green",
            )
        elif args.print_base64:
            ui.panel(
                "Secret (base64)",
                textwrap.wrap(base64.b64encode(result.secret).decode("ascii"), 72),
                border="green",
            )
        elif args.print_secret or _looks_textual(result.secret):
            try:
                text = result.secret.decode("utf-8")
                ui.panel("Secret (UTF-8 text)", text.splitlines() or [""], border="green")
            except UnicodeDecodeError:  # pragma: no cover - guarded by _looks_textual
                ui.panel("Secret (hex)", _hex_block(result.secret), border="green")
        else:
            ui.panel("Secret (hex)", _hex_block(result.secret), border="green")

    if written is not None:
        ui.success(f"Secret written to {written} (mode 0600)")
    if result.commitment_verified:
        ui.success("SHA-256 commitment verified: the shares belong to this secret.")
    elif not args.quiet:
        ui.info(
            "No commitment was attached; correctness relies on per-share checksums. "
            "Use `sss verify` before combining if any share travelled by hand."
        )
    ui.section("Warnings")
    if written is None:
        ui.warning("The secret is now in your terminal scrollback. Consider --out instead.")
    ui.warning("Recombining on a networked machine exposes the secret to that machine.")
    return 0


def _cmd_verify(args: argparse.Namespace, ui: UI) -> int:
    shares, failures = load_share_inputs_detailed(args.shares)
    analysis = analyze_shares(
        shares,
        sources=[f"share x={share.index}" for share in shares],
        failures=failures,
        expected_commitment=args.expected_commitment,
    )

    if args.json_out:
        payload = {
            "verdict": analysis.verdict,
            "ok": analysis.ok,
            "consistent": analysis.consistent,
            "sufficient": analysis.sufficient,
            "threshold": analysis.threshold,
            "total": analysis.total,
            "field": analysis.field.name if analysis.field else None,
            "commitment": analysis.commitment,
            "secret_bytes": analysis.secret_length,
            "unique_indices": list(analysis.unique_indices),
            "problems": list(analysis.problems),
            "warnings": list(analysis.warnings),
            "entries": [
                {
                    "source": entry.source,
                    "index": entry.share.index if entry.share else None,
                    "checksum": entry.share.checksum if entry.share else None,
                    "valid": entry.ok,
                    "error": entry.error,
                }
                for entry in analysis.entries
            ],
        }
        print(json.dumps(payload, indent=2))
        return 0 if analysis.ok else 2

    ui.banner()
    ui.section("Share verification (no secret is reconstructed)")
    rows: List[List[str]] = []
    for entry in analysis.entries:
        if entry.share is not None:
            share = entry.share
            rows.append(
                [
                    "valid" if entry.ok else "INVALID",
                    entry.source,
                    str(share.index),
                    f"{share.threshold}/{share.total}",
                    share.field.name,
                    str(share.secret_length),
                    share.checksum,
                ]
            )
        else:
            rows.append(["INVALID", entry.source, "-", "-", "-", "-", (entry.error or "")[:60]])
    ui.table(
        ["status", "source", "x", "k/n", "field", "secret B", "checksum"],
        rows,
        title="Individual shares",
    )

    if analysis.threshold is not None:
        ui.kv(
            "Share set",
            [
                ("field", analysis.field.label if analysis.field else "-"),
                ("scheme", f"{analysis.threshold}-of-{analysis.total}"),
                ("valid shares", f"{len(analysis.shares)} (distinct x: {len(analysis.unique_indices)})"),
                ("sufficient to combine", "yes" if analysis.sufficient else "no"),
                (
                    "missing shares",
                    "0" if analysis.sufficient else str(analysis.missing or 0),
                ),
                ("commitment", (analysis.commitment or "none")[:32]),
                (
                    "verdict",
                    "VALID" if analysis.ok else ("INSUFFICIENT" if analysis.consistent else "INVALID"),
                ),
            ],
        )

    for problem in analysis.problems:
        if analysis.consistent:
            ui.warning(problem)
        else:
            ui.error(problem)
    for warning in analysis.warnings:
        ui.warning(warning)

    if analysis.ok:
        ui.success("Every share is well-formed and the set can reconstruct the secret.")
    elif analysis.consistent and not analysis.sufficient:
        ui.info(
            f"Fewer than {analysis.threshold} shares were supplied. This is expected when "
            "checking individual custodians; no information about the secret was revealed."
        )
    return 0 if analysis.ok else 2


def _format_size(size: int) -> str:
    for unit in ("B", "KiB", "MiB", "GiB"):
        if size < 1024 or unit == "GiB":
            return f"{size} {unit}" if unit == "B" else f"{size:.1f} {unit}"
        size /= 1024.0
    return f"{size} B"  # pragma: no cover - unreachable


def _cmd_vault_lock(args: argparse.Namespace, ui: UI) -> int:
    labels = _parse_labels(args.labels, args.shares)
    result = lock_file(
        args.file,
        threshold=args.threshold,
        total=args.shares,
        out_dir=args.out_dir,
        field=args.field,
        labels=labels,
        fmt=args.fmt,
        force=args.force,
    )
    ui.banner()
    ui.section("Vault locked")
    ui.kv(
        "Envelope",
        [
            ("vault file", str(result.vault_path)),
            ("plaintext", f"{result.header.original_name} · {_format_size(result.plaintext_size)}"),
            ("cipher", "AES-256-GCM (256-bit DEK, 96-bit nonce, header as AAD)"),
            ("shamir", f"{result.split.threshold}-of-{result.split.total} over {result.split.field.label}"),
            ("DEK commitment", result.header.dek_commitment),
            ("plaintext SHA-256", result.header.plaintext_sha256),
            ("share files", f"{len(result.share_paths)} written to {Path(args.out_dir).resolve()}"),
        ],
    )
    if not args.no_print_shares:
        ui.section("Distribution cards")
        for share in result.split.shares:
            ui.share_card(share)
    ui.section("Warnings")
    ui.warning("Move every share to separate offline media before you need them.")
    ui.warning("Sharing the vault and all shares on one machine defeats the threshold.")
    ui.info("Recover with: sss vault-unlock <vault> --shares <k share files or strings>")
    _security_notice(ui, vault=True)
    return 0


def _cmd_vault_unlock(args: argparse.Namespace, ui: UI) -> int:
    result = unlock_file(
        args.vault,
        args.shares,
        out_path=args.out,
        force=args.force,
    )
    ui.banner()
    ui.section("Vault unlocked")
    ui.kv(
        "Restored file",
        [
            ("output", str(result.output_path)),
            ("size", _format_size(result.plaintext_size)),
            ("shares used", f"{result.shares_used} (threshold {result.header.threshold})"),
            ("GCM tag", "verified — ciphertext and header are authentic"),
            ("DEK commitment", "verified" if result.commitment_verified else "not verified"),
            ("plaintext SHA-256", result.header.plaintext_sha256),
        ],
    )
    ui.success(f"Decrypted {result.output_path} successfully.")
    ui.warning("The plaintext exists on disk now; re-lock or destroy it when finished.")
    return 0


def _cmd_vault_info(args: argparse.Namespace, ui: UI) -> int:
    header, size = read_vault_header(args.vault)
    ui.banner()
    ui.section("Vault header")
    ui.kv(
        "Authenticated metadata",
        [
            ("file", str(args.vault)),
            ("envelope size", _format_size(size)),
            ("version", header.version),
            ("cipher", header.cipher),
            ("threshold", f"{header.threshold}-of-{header.total}"),
            ("field", header.field),
            ("DEK length", f"{header.secret_bytes} bytes"),
            ("DEK commitment", header.dek_commitment),
            ("original name", header.original_name),
            ("original size", _format_size(header.original_size)),
            ("plaintext SHA-256", header.plaintext_sha256),
            ("created", header.created_at),
        ],
    )
    ui.info("The header is authenticated by GCM: any modification is detected on unlock.")
    return 0


def _cmd_lab(args: argparse.Namespace, ui: UI) -> int:
    from simulation.security_lab import run_lab

    shares = None
    if args.shares:
        shares = load_share_inputs(args.shares)
    report = run_lab(
        k=args.threshold,
        n=args.total,
        candidates=[text.encode("utf-8") for text in (args.candidate or [])] or None,
        interactive=args.interactive,
        shares=shares,
        ui=ui,
    )
    return 0 if report.verified else 2


def _cmd_fields(args: argparse.Namespace, ui: UI) -> int:
    rows: List[List[str]] = []
    for prime_field in available_fields():
        rows.append(
            [
                prime_field.name,
                str(prime_field.bit_length),
                str(prime_field.secret_capacity),
                str(prime_field.element_bytes),
                f"{prime_field.bit_length} bits ≈ {prime_field.bit_length * 0.30103:.0f} decimal digits",
                "proved" if lucas_lehmer(prime_field.exponent) else "NOT PRIME",
            ]
        )
    ui.banner()
    ui.section("Registered prime fields")
    ui.table(
        ["name", "bits", "secret B", "share B", "entropy", "Lucas-Lehmer"],
        rows,
        justify=["left", "right", "right", "right", "left", "left"],
    )
    ui.info(
        "Secrets longer than 'secret B' are split into multiple chunks, each with its own "
        "degree-(k-1) polynomial evaluated at the same x-coordinates."
    )
    return 0


# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------
def _add_common(parser: argparse.ArgumentParser, *, suppress: bool = False) -> None:
    default = argparse.SUPPRESS if suppress else False
    parser.add_argument(
        "--quiet",
        "-q",
        action="store_true",
        default=default,
        help="suppress decoration and share cards (errors still print)",
    )
    parser.add_argument(
        "--no-color",
        action="store_true",
        default=default,
        help="disable ANSI colour (also honours NO_COLOR)",
    )
    parser.add_argument(
        "--debug",
        action="store_true",
        default=default,
        help="show tracebacks for unexpected errors",
    )


def build_parser() -> argparse.ArgumentParser:
    common = argparse.ArgumentParser(add_help=False)
    _add_common(common, suppress=True)

    parser = argparse.ArgumentParser(
        prog="sss",
        description=(
            "Shamir's Secret Sharing over GF(p): split a secret into n shares where any k "
            "reconstruct it and any k-1 reveal nothing."
        ),
        epilog=(
            "examples:\n"
            "  sss split --secret 'master password' -k 3 -n 5 --out-dir ./shares\n"
            "  sss split --hex 00112233... -k 2 -n 3 --format armored\n"
            "  sss combine --shares shares/share-01-of-05.json shares/share-03-of-05.json \\\n"
            "                          shares/share-05-of-05.json --out secret.bin\n"
            "  sss verify --shares share-01.txt share-02.txt\n"
            "  sss vault-lock backup.tar.gz -k 3 -n 5 --out-dir ./vault\n"
            "  sss vault-unlock backup.tar.gz.vault --shares vault/*.txt --out restored.tar.gz\n"
            "  sss lab --k 3 --n 5 --interactive\n"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--version", action="version", version=f"sss {__version__}")
    _add_common(parser)
    subparsers = parser.add_subparsers(dest="command", metavar="<command>")

    # -- split ---------------------------------------------------------
    split_parser = subparsers.add_parser(
        "split",
        parents=[common],
        help="split a secret into n shares (any k reconstruct)",
        description="Split a text, hex, file or stdin secret into a k-of-n share set.",
    )
    source = split_parser.add_mutually_exclusive_group()
    source.add_argument("--secret", "-s", metavar="TEXT", help="secret as UTF-8 text")
    source.add_argument(
        "--hex", "-x", dest="hex_secret", metavar="HEX", help="secret as hex (0x/spaces/colons ok)"
    )
    source.add_argument(
        "--secret-file", metavar="PATH", help="read raw secret bytes from a (small) file"
    )
    source.add_argument("--stdin", action="store_true", help="read the secret from stdin")
    split_parser.add_argument(
        "-k", "--threshold", type=int, required=True, metavar="K", help="shares required (k >= 2)"
    )
    split_parser.add_argument(
        "-n", "--shares", type=int, required=True, metavar="N", help=f"shares to create (n <= {MAX_SHARES})"
    )
    split_parser.add_argument(
        "--field",
        choices=_field_choices(),
        default="auto",
        help="prime field (auto = smallest that fits; larger secrets are chunked)",
    )
    split_parser.add_argument(
        "--format",
        dest="fmt",
        choices=["armored", "json", "both"],
        default=None,
        help="output file format (default: armored, or both when --out-dir is given)",
    )
    split_parser.add_argument(
        "--out-dir", type=Path, metavar="DIR", help="write share files here (mode 0700)"
    )
    split_parser.add_argument(
        "--prefix", default="share", help="share file prefix (default: share)"
    )
    split_parser.add_argument(
        "--commitment",
        action="store_true",
        help="attach SHA-256(secret) to every share (see THEORY.md §7 on the trade-off)",
    )
    split_parser.add_argument(
        "--labels", metavar="A,B,C", help="comma-separated custodian labels, one per share"
    )
    split_parser.add_argument(
        "--allow-degenerate-degree",
        action="store_true",
        help="sample all coefficients from GF(p) (allows degree < k-1)",
    )
    split_parser.add_argument(
        "--no-print-shares", action="store_true", help="do not print distribution cards"
    )
    split_parser.add_argument(
        "--no-strip", action="store_true", help="keep a trailing newline when reading stdin"
    )
    split_parser.add_argument(
        "--force", action="store_true", help="overwrite existing share files"
    )
    split_parser.set_defaults(handler=_cmd_split)

    # -- combine -------------------------------------------------------
    combine_parser = subparsers.add_parser(
        "combine",
        parents=[common],
        help="reconstruct a secret from k or more shares",
        description="Reconstruct a secret from armoured strings, JSON shares or share files.",
    )
    combine_parser.add_argument(
        "--shares",
        nargs="+",
        required=True,
        metavar="SHARE",
        help="share strings, share files, bundles, or '-' for stdin",
    )
    combine_parser.add_argument(
        "--out", "-o", type=Path, metavar="FILE", help="write the secret to FILE (mode 0600)"
    )
    combine_parser.add_argument(
        "--print-secret", action="store_true", help="print the secret even when --out is used"
    )
    combine_parser.add_argument("--print-hex", action="store_true", help="print the secret as hex")
    combine_parser.add_argument(
        "--print-base64", action="store_true", help="print the secret as base64"
    )
    combine_parser.add_argument(
        "--expected-commitment",
        metavar="HEX",
        help="require SHA-256(secret) to equal this value",
    )
    combine_parser.add_argument("--force", action="store_true", help="overwrite --out")
    combine_parser.set_defaults(handler=_cmd_combine)

    # -- verify --------------------------------------------------------
    verify_parser = subparsers.add_parser(
        "verify",
        parents=[common],
        help="validate shares without reconstructing the secret",
        description=(
            "Parse shares, check truncated SHA-256 checksums, duplicate x-indices and "
            "cross-share metadata consistency. The secret is never interpolated."
        ),
    )
    verify_parser.add_argument(
        "--shares", nargs="+", required=True, metavar="SHARE", help="share strings or files"
    )
    verify_parser.add_argument(
        "--expected-commitment", metavar="HEX", help="require matching commitment"
    )
    verify_parser.add_argument(
        "--json", dest="json_out", action="store_true", help="machine-readable report"
    )
    verify_parser.set_defaults(handler=_cmd_verify)

    # -- vault-lock ----------------------------------------------------
    lock_parser = subparsers.add_parser(
        "vault-lock",
        parents=[common],
        help="encrypt a file with AES-256-GCM and split its DEK",
        description=(
            "Envelope-encrypt a file (AES-256-GCM) and Shamir-split the 256-bit DEK. "
            "Any k shares rebuild the key; k-1 reveal nothing."
        ),
    )
    lock_parser.add_argument("file", type=Path, help="file to encrypt")
    lock_parser.add_argument("-k", "--threshold", type=int, required=True, metavar="K")
    lock_parser.add_argument("-n", "--shares", type=int, required=True, metavar="N")
    lock_parser.add_argument(
        "--out-dir", type=Path, default=Path("."), metavar="DIR", help="output directory"
    )
    lock_parser.add_argument(
        "--field", choices=["m521", "m2281"], default="m521", help="field for the 32-byte DEK"
    )
    lock_parser.add_argument(
        "--format",
        dest="fmt",
        choices=["armored", "json", "both"],
        default="both",
        help="share file format (default: both)",
    )
    lock_parser.add_argument(
        "--labels", metavar="A,B,C", help="comma-separated custodian labels, one per share"
    )
    lock_parser.add_argument(
        "--no-print-shares", action="store_true", help="do not print distribution cards"
    )
    lock_parser.add_argument("--force", action="store_true", help="overwrite existing outputs")
    lock_parser.set_defaults(handler=_cmd_vault_lock)

    # -- vault-unlock --------------------------------------------------
    unlock_parser = subparsers.add_parser(
        "vault-unlock",
        parents=[common],
        help="reconstruct a vault DEK from shares and decrypt the file",
        description="Rebuild the DEK from k shares, verify the commitment and authenticate the file.",
    )
    unlock_parser.add_argument("vault", type=Path, help=".vault file to decrypt")
    unlock_parser.add_argument(
        "--shares", nargs="+", required=True, metavar="SHARE", help="share strings or files"
    )
    unlock_parser.add_argument(
        "--out", "-o", type=Path, metavar="FILE", help="output path (default: original name)"
    )
    unlock_parser.add_argument("--force", action="store_true", help="overwrite the output file")
    unlock_parser.set_defaults(handler=_cmd_vault_unlock)

    # -- vault-info ----------------------------------------------------
    info_parser = subparsers.add_parser(
        "vault-info",
        parents=[common],
        help="inspect a vault header without shares",
        description="Show authenticated vault metadata. No secret material is required.",
    )
    info_parser.add_argument("vault", type=Path, help=".vault file")
    info_parser.set_defaults(handler=_cmd_vault_info)

    # -- lab -----------------------------------------------------------
    lab_parser = subparsers.add_parser(
        "lab",
        parents=[common],
        help="demonstrate that k-1 shares leak zero information",
        description=(
            "Interpolate the unique degree-(k-1) polynomial through k-1 shares plus an "
            "arbitrary candidate secret: every candidate is equally consistent."
        ),
    )
    lab_parser.add_argument("-k", "--threshold", type=int, default=3, metavar="K")
    lab_parser.add_argument("-n", "--total", type=int, default=5, metavar="N")
    lab_parser.add_argument(
        "--candidate", action="append", metavar="TEXT", help="extra candidate secret (repeatable)"
    )
    lab_parser.add_argument(
        "--interactive", action="store_true", help="prompt for candidate secrets"
    )
    lab_parser.add_argument(
        "--shares", nargs="+", metavar="SHARE", help="analyse real shares instead of a demo"
    )
    lab_parser.set_defaults(handler=_cmd_lab)

    # -- fields --------------------------------------------------------
    fields_parser = subparsers.add_parser(
        "fields",
        parents=[common],
        help="list registered prime fields",
        description="Show Mersenne prime fields, capacities and primality certificates.",
    )
    fields_parser.set_defaults(handler=_cmd_fields)

    return parser


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------
def run(argv: Optional[Sequence[str]] = None) -> int:
    """Execute the CLI and return a process exit code (never raises SSSError)."""
    parser = build_parser()
    args = parser.parse_args(list(argv) if argv is not None else None)
    if not getattr(args, "command", None):
        parser.print_help()
        return 1

    ui = UI(
        quiet=getattr(args, "quiet", False),
        color=not getattr(args, "no_color", False),
    )
    debug = getattr(args, "debug", False)
    try:
        return int(args.handler(args, ui) or 0)
    except SSSError as exc:
        ui.error(str(exc))
        if not ui.quiet:
            ui.info(f"hint: run `sss {args.command} --help` for usage")
        return exc.exit_code
    except BrokenPipeError:  # pragma: no cover - piping into head
        return 0
    except KeyboardInterrupt:  # pragma: no cover - interactive abort
        ui.error("interrupted")
        return 130
    except Exception as exc:  # pragma: no cover - genuine bug
        if debug:
            raise
        ui.error(f"unexpected error: {type(exc).__name__}: {exc}")
        ui.info("re-run with --debug for a traceback")
        return 1


def main(argv: Optional[Sequence[str]] = None) -> int:
    """Console-script entry point."""
    return run(argv)

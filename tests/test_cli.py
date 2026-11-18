"""CLI integration tests: argument handling, exit codes, files and output modes."""

from __future__ import annotations

import io
import json
import os
import sys
from pathlib import Path

import pytest

from cli import interface
from cli.interface import run
from core.shamir import combine, load_share_inputs


class FakeStdin:
    """Minimal stdin stand-in with a binary buffer, like a real pipe."""

    def __init__(self, data: bytes) -> None:
        self.buffer = io.BytesIO(data)

    def read(self) -> str:  # pragma: no cover - buffer path is used
        return self.buffer.read().decode()

    def isatty(self) -> bool:
        return False


def _split_files(tmp_path: Path, secret: bytes = b"cli integration", k: int = 3, n: int = 5):
    directory = tmp_path / "shares"
    code = run(
        [
            "--quiet",
            "split",
            "--secret",
            secret.decode("utf-8"),
            "-k",
            str(k),
            "-n",
            str(n),
            "--out-dir",
            str(directory),
            "--no-print-shares",
        ]
    )
    assert code == 0
    return directory


# ---------------------------------------------------------------------------
# Basic invocation
# ---------------------------------------------------------------------------
def test_version_flag(capsys):
    with pytest.raises(SystemExit) as excinfo:
        run(["--version"])
    assert excinfo.value.code == 0
    assert "sss 1.0.0" in capsys.readouterr().out


def test_help_lists_subcommands(capsys):
    with pytest.raises(SystemExit) as excinfo:
        run(["--help"])
    assert excinfo.value.code == 0
    out = capsys.readouterr().out
    for command in ("split", "combine", "verify", "vault-lock", "vault-unlock", "lab", "fields"):
        assert command in out


def test_no_command_prints_help(capsys):
    assert run([]) == 1
    assert "usage:" in capsys.readouterr().out


def test_unknown_option_exits_two():
    with pytest.raises(SystemExit) as excinfo:
        run(["split", "--secret", "x", "-k", "2", "-n", "3", "--nonexistent"])
    assert excinfo.value.code == 2


def test_unknown_field_choice_rejected():
    with pytest.raises(SystemExit):
        run(["split", "--secret", "x", "-k", "2", "-n", "3", "--field", "m1024"])


# ---------------------------------------------------------------------------
# split
# ---------------------------------------------------------------------------
def test_split_prints_armored_cards(capsys):
    code = run(["split", "--secret", "hello world", "-k", "2", "-n", "3"])
    out = capsys.readouterr().out
    assert code == 0
    assert "Shamir's Secret Sharing" in out
    assert "SSS-V1-m521-2-3-" in out
    assert "Share 1 of 3" in out


def test_split_writes_both_formats(tmp_path, capsys):
    directory = _split_files(tmp_path, b"file based secret")
    files = sorted(path.name for path in directory.iterdir())
    assert files == [
        "share-01-of-05.json",
        "share-01-of-05.txt",
        "share-02-of-05.json",
        "share-02-of-05.txt",
        "share-03-of-05.json",
        "share-03-of-05.txt",
        "share-04-of-05.json",
        "share-04-of-05.txt",
        "share-05-of-05.json",
        "share-05-of-05.txt",
    ]
    assert all(os.stat(path).st_mode & 0o777 == 0o600 for path in directory.iterdir())


def test_split_json_requires_out_dir(capsys):
    code = run(["split", "--secret", "x", "-k", "2", "-n", "3", "--format", "json"])
    assert code == 2
    assert "--out-dir" in capsys.readouterr().err


def test_split_rejects_bad_parameters(tmp_path, capsys):
    for params in (["-k", "1", "-n", "3"], ["-k", "4", "-n", "3"], ["-k", "2", "-n", "256"]):
        code = run(["split", "--secret", "x", *params, "--out-dir", str(tmp_path / "x")])
        assert code == 2
        assert capsys.readouterr().err


def test_split_quiet_produces_no_output(tmp_path, capsys):
    code = run(
        [
            "--quiet",
            "split",
            "--secret",
            "x",
            "-k",
            "2",
            "-n",
            "3",
            "--out-dir",
            str(tmp_path / "q"),
        ]
    )
    assert code == 0
    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err == ""


def test_split_labels_mismatch(tmp_path, capsys):
    code = run(
        [
            "split",
            "--secret",
            "x",
            "-k",
            "2",
            "-n",
            "3",
            "--out-dir",
            str(tmp_path / "l"),
            "--labels",
            "Alice,Bob",
        ]
    )
    assert code == 2
    assert "labels" in capsys.readouterr().err


def test_split_hex_input(tmp_path):
    secret_hex = "deadbeef00ff"
    directory = tmp_path / "hex"
    assert (
        run(
            [
                "split",
                "--hex",
                "de:ad:be:ef:00:ff",
                "-k",
                "2",
                "-n",
                "3",
                "--out-dir",
                str(directory),
                "--no-print-shares",
            ]
        )
        == 0
    )
    shares = load_share_inputs([str(path) for path in sorted(directory.glob("*.json"))[:2]])
    assert combine(shares).secret.hex() == secret_hex


def test_split_stdin_input(tmp_path, monkeypatch):
    monkeypatch.setattr(sys, "stdin", FakeStdin(b"secret from stdin\n"))
    directory = tmp_path / "stdin"
    assert (
        run(
            ["split", "--stdin", "-k", "2", "-n", "3", "--out-dir", str(directory), "--no-print-shares"]
        )
        == 0
    )
    shares = load_share_inputs([str(path) for path in sorted(directory.glob("*.txt"))[:2]])
    assert combine(shares).secret == b"secret from stdin"


def test_split_secret_file_input(tmp_path):
    source = tmp_path / "key.bin"
    source.write_bytes(b"\x00\x01\x02binary\xff")
    directory = tmp_path / "fromfile"
    assert (
        run(
            [
                "split",
                "--secret-file",
                str(source),
                "-k",
                "2",
                "-n",
                "2",
                "--out-dir",
                str(directory),
            ]
        )
        == 0
    )
    shares = load_share_inputs([str(path) for path in sorted(directory.glob("*.json"))])
    assert combine(shares).secret == source.read_bytes()


def test_split_empty_secret_rejected(capsys):
    code = run(["split", "--secret", "", "-k", "2", "-n", "3"])
    assert code == 2
    assert "empty" in capsys.readouterr().err.lower()


def test_missing_secret_argument_is_a_usage_error(capsys):
    code = run(["split", "-k", "2", "-n", "3"])
    assert code == 2
    assert capsys.readouterr().err


# ---------------------------------------------------------------------------
# combine
# ---------------------------------------------------------------------------
def test_combine_from_files_and_write_output(tmp_path, capsys):
    secret = b"combine me from files"
    directory = _split_files(tmp_path, secret)
    output = tmp_path / "restored.bin"
    code = run(
        [
            "combine",
            "--shares",
            str(directory / "share-01-of-05.json"),
            str(directory / "share-03-of-05.txt"),
            str(directory / "share-05-of-05.json"),
            "--out",
            str(output),
        ]
    )
    assert code == 0
    assert output.read_bytes() == secret
    assert oct(output.stat().st_mode & 0o777) == "0o600"
    out = capsys.readouterr().out
    assert secret.decode() not in out  # secret stays out of stdout when --out is used
    assert "Reconstruction" in out


def test_combine_quiet_prints_only_secret(tmp_path, capsys):
    secret = b"quiet mode secret"
    directory = _split_files(tmp_path, secret)
    code = run(
        [
            "combine",
            "--shares",
            *(str(path) for path in sorted(directory.glob("*.txt"))[:3]),
            "--quiet",
        ]
    )
    assert code == 0
    assert capsys.readouterr().out == "quiet mode secret\n"


def test_combine_print_hex(tmp_path, capsys):
    secret = b"\x00\x01\x02"
    directory = tmp_path / "hexout"
    run(
        [
            "split",
            "--hex",
            "000102",
            "-k",
            "2",
            "-n",
            "3",
            "--out-dir",
            str(directory),
            "--no-print-shares",
        ]
    )
    code = run(
        [
            "combine",
            "--shares",
            *(str(path) for path in sorted(directory.glob("*.json"))[:2]),
            "--print-hex",
        ]
    )
    assert code == 0
    assert "000102" in capsys.readouterr().out
    assert secret.hex() == "000102"


def test_combine_insufficient_shares(tmp_path, capsys):
    directory = _split_files(tmp_path)
    code = run(
        ["combine", "--shares", str(directory / "share-01-of-05.json"), str(directory / "share-02-of-05.txt")]
    )
    assert code == 2
    assert "need at least 3" in capsys.readouterr().err


def test_combine_duplicate_share(tmp_path, capsys):
    directory = _split_files(tmp_path)
    share = str(directory / "share-01-of-05.json")
    code = run(["combine", "--shares", share, share, str(directory / "share-02-of-05.json")])
    assert code == 2
    assert "duplicate" in capsys.readouterr().err.lower()


def test_combine_missing_file(tmp_path, capsys):
    code = run(["combine", "--shares", str(tmp_path / "ghost.json")])
    assert code == 2
    assert "neither an existing file" in capsys.readouterr().err


def test_combine_refuses_overwrite_without_force(tmp_path, capsys):
    secret = b"overwrite protection"
    directory = _split_files(tmp_path, secret)
    output = tmp_path / "existing.bin"
    output.write_bytes(b"keep me")
    args = [
        "combine",
        "--shares",
        *(str(path) for path in sorted(directory.glob("*.json"))[:3]),
        "--out",
        str(output),
    ]
    assert run(args) == 2
    assert output.read_bytes() == b"keep me"
    assert capsys.readouterr().err
    assert run([*args, "--force"]) == 0
    assert output.read_bytes() == secret


def test_combine_expected_commitment_mismatch(tmp_path, capsys):
    directory = tmp_path / "committed"
    run(
        [
            "split",
            "--secret",
            "commitment cli",
            "-k",
            "2",
            "-n",
            "3",
            "--out-dir",
            str(directory),
            "--commitment",
            "--no-print-shares",
        ]
    )
    code = run(
        [
            "combine",
            "--shares",
            *(str(path) for path in sorted(directory.glob("*.json"))[:2]),
            "--expected-commitment",
            "ff" * 32,
        ]
    )
    assert code == 2
    assert "commitment" in capsys.readouterr().err.lower()


def test_combine_stdin_shares(tmp_path, monkeypatch, capsys):
    secret = b"stdin share pipe"
    directory = _split_files(tmp_path, secret)
    text = "\n".join(
        path.read_text() for path in sorted(directory.glob("*.txt"))[:3]
    )
    monkeypatch.setattr(sys, "stdin", FakeStdin(text.encode()))
    assert run(["combine", "--shares", "-"]) == 0
    assert secret.decode() in capsys.readouterr().out


# ---------------------------------------------------------------------------
# verify
# ---------------------------------------------------------------------------
def test_verify_valid_exit_zero(tmp_path, capsys):
    directory = _split_files(tmp_path)
    code = run(["verify", "--shares", *(str(path) for path in sorted(directory.glob("*.json"))[:3])])
    out = capsys.readouterr().out
    assert code == 0
    assert "VALID" in out
    assert "no secret is reconstructed" in out


def test_verify_insufficient_exit_two(tmp_path, capsys):
    directory = _split_files(tmp_path)
    code = run(["verify", "--shares", str(directory / "share-01-of-05.json")])
    captured = capsys.readouterr()
    assert code == 2
    assert "insufficient" in (captured.out + captured.err).lower()


def test_verify_tampered_share(tmp_path, capsys):
    directory = _split_files(tmp_path, b"cli integration secret")
    path = directory / "share-02-of-05.txt"
    lines = path.read_text().splitlines()
    armored = lines[-1]
    parts = armored.split("-")
    payload = list(parts[7])
    payload[2] = "A" if payload[2] != "A" else "B"
    parts[7] = "".join(payload)
    path.write_text("\n".join(lines[:-1] + ["-".join(parts)]) + "\n")
    code = run(["verify", "--shares", str(path)])
    captured = capsys.readouterr()
    assert code == 2
    assert "INVALID" in captured.out


def test_verify_json_report(tmp_path, capsys):
    directory = _split_files(tmp_path)
    code = run(
        [
            "verify",
            "--shares",
            *(str(path) for path in sorted(directory.glob("*.txt"))[:3]),
            "--json",
        ]
    )
    payload = json.loads(capsys.readouterr().out)
    assert code == 0
    assert payload["verdict"] == "valid"
    assert payload["threshold"] == 3
    assert payload["total"] == 5
    assert payload["field"] == "m521"
    assert len(payload["entries"]) == 3
    assert all(entry["valid"] for entry in payload["entries"])


def test_verify_json_insufficient(tmp_path, capsys):
    directory = _split_files(tmp_path)
    code = run(["verify", "--shares", str(directory / "share-01-of-05.json"), "--json"])
    payload = json.loads(capsys.readouterr().out)
    assert code == 2
    assert payload["verdict"] == "insufficient"


# ---------------------------------------------------------------------------
# vault commands
# ---------------------------------------------------------------------------
def test_vault_lock_unlock_roundtrip(tmp_path, capsys):
    source = tmp_path / "archive.bin"
    source.write_bytes(b"vault payload " + bytes(range(64)))
    vault_dir = tmp_path / "vault"
    code = run(
        [
            "vault-lock",
            str(source),
            "-k",
            "2",
            "-n",
            "4",
            "--out-dir",
            str(vault_dir),
            "--no-print-shares",
        ]
    )
    assert code == 0
    vault_path = vault_dir / "archive.bin.vault"
    assert vault_path.exists()

    info_code = run(["vault-info", str(vault_path)])
    info = capsys.readouterr().out
    assert info_code == 0
    assert "AES-256-GCM" in info
    assert "2-of-4" in info

    output = tmp_path / "restored.bin"
    share_files = sorted(vault_dir.glob("*.txt"))[:2]
    assert (
        run(
            [
                "vault-unlock",
                str(vault_path),
                "--shares",
                *(str(path) for path in share_files),
                "--out",
                str(output),
            ]
        )
        == 0
    )
    assert output.read_bytes() == source.read_bytes()
    assert "GCM tag" in capsys.readouterr().out


def test_vault_unlock_insufficient(tmp_path, capsys):
    source = tmp_path / "small.txt"
    source.write_text("hello")
    vault_dir = tmp_path / "v"
    run(["vault-lock", str(source), "-k", "3", "-n", "5", "--out-dir", str(vault_dir)])
    vault_path = vault_dir / "small.txt.vault"
    share_files = sorted(vault_dir.glob("*.txt"))[:2]
    code = run(
        ["vault-unlock", str(vault_path), "--shares", *(str(p) for p in share_files)]
    )
    assert code == 2
    assert "need at least 3" in capsys.readouterr().err


def test_vault_lock_missing_file(tmp_path, capsys):
    code = run(["vault-lock", str(tmp_path / "missing.bin"), "-k", "2", "-n", "3"])
    assert code == 2
    assert capsys.readouterr().err


# ---------------------------------------------------------------------------
# Informational commands
# ---------------------------------------------------------------------------
def test_fields_command(capsys):
    code = run(["fields"])
    out = capsys.readouterr().out
    assert code == 0
    assert "m521" in out and "m2281" in out
    assert "proved" in out
    assert "65" in out and "285" in out


def test_lab_command(capsys):
    code = run(["lab", "-k", "3", "-n", "5"])
    out = capsys.readouterr().out
    assert code == 0
    assert "bijection" in out.lower()
    assert "Verdict" in out


def test_lab_command_rejects_bad_parameters(capsys):
    code = run(["lab", "-k", "1", "-n", "3"])
    assert code == 2
    assert capsys.readouterr().err


# ---------------------------------------------------------------------------
# Presentation fallbacks
# ---------------------------------------------------------------------------
def test_plain_text_fallback_without_rich(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(interface, "RICH_AVAILABLE", False)
    directory = tmp_path / "plain"
    code = run(
        [
            "split",
            "--secret",
            "no rich here",
            "-k",
            "2",
            "-n",
            "3",
            "--out-dir",
            str(directory),
        ]
    )
    out = capsys.readouterr().out
    assert code == 0
    assert "Shamir's Secret Sharing" in out
    assert "SSS-V1-" in out
    assert "Share 1 of 3" in out
    assert (
        run(["verify", "--shares", *(str(p) for p in sorted(directory.glob("*.json"))[:2])]) == 0
    )
    assert "valid" in capsys.readouterr().out
    assert run(["fields"]) == 0
    assert "m521" in capsys.readouterr().out


def test_no_color_flag_smoke(capsys):
    assert run(["--no-color", "split", "--secret", "x", "-k", "2", "-n", "3"]) == 0
    assert "SSS-V1-" in capsys.readouterr().out


# ---------------------------------------------------------------------------
# Additional error paths
# ---------------------------------------------------------------------------
def test_split_rejects_unsafe_prefix(tmp_path, capsys):
    code = run(
        [
            "split",
            "--secret",
            "x",
            "-k",
            "2",
            "-n",
            "3",
            "--out-dir",
            str(tmp_path / "p"),
            "--prefix",
            "../escape",
        ]
    )
    assert code == 2
    assert "prefix" in capsys.readouterr().err


def test_combine_corrupt_share_file(tmp_path, capsys):
    directory = _split_files(tmp_path)
    path = directory / "share-01-of-05.txt"
    text = path.read_text()
    path.write_text(text.replace("SSS-V1-m521-3-5-1-15-", "SSS-V1-m521-3-5-1-16-"))
    code = run(
        [
            "combine",
            "--shares",
            str(path),
            str(directory / "share-02-of-05.txt"),
            str(directory / "share-03-of-05.txt"),
        ]
    )
    assert code == 2
    assert "checksum" in capsys.readouterr().err.lower()


def test_vault_info_missing_file(tmp_path, capsys):
    code = run(["vault-info", str(tmp_path / "ghost.vault")])
    assert code == 2
    assert capsys.readouterr().err


def test_combine_print_base64(tmp_path, capsys):
    import base64

    directory = _split_files(tmp_path, b"base64 output")
    code = run(
        [
            "combine",
            "--shares",
            *(str(p) for p in sorted(directory.glob("*.json"))[:3]),
            "--print-base64",
        ]
    )
    out = capsys.readouterr().out
    assert code == 0
    assert base64.b64encode(b"base64 output").decode().rstrip("=") in out.replace("\n", "")


def test_split_stdin_no_strip(tmp_path, monkeypatch):
    monkeypatch.setattr(sys, "stdin", FakeStdin(b"keep-newline\n"))
    directory = tmp_path / "nostrip"
    assert (
        run(
            [
                "split",
                "--stdin",
                "--no-strip",
                "-k",
                "2",
                "-n",
                "2",
                "--out-dir",
                str(directory),
                "--quiet",
            ]
        )
        == 0
    )
    shares = load_share_inputs([str(path) for path in sorted(directory.glob("*.json"))])
    assert combine(shares).secret == b"keep-newline\n"


def test_verify_expected_commitment(tmp_path, capsys):
    directory = tmp_path / "committed-verify"
    run(
        [
            "split",
            "--secret",
            "verify commitment",
            "-k",
            "2",
            "-n",
            "3",
            "--out-dir",
            str(directory),
            "--commitment",
            "--quiet",
        ]
    )
    shares = sorted(directory.glob("*.json"))[:2]
    commitment = json.loads(shares[0].read_text())["commitment"]
    assert (
        run(
            [
                "verify",
                "--shares",
                *(str(path) for path in shares),
                "--expected-commitment",
                commitment,
                "--quiet",
            ]
        )
        == 0
    )
    assert (
        run(
            [
                "verify",
                "--shares",
                *(str(path) for path in shares),
                "--expected-commitment",
                "00" * 32,
                "--quiet",
            ]
        )
        == 2
    )


def test_vault_lock_with_json_only(tmp_path, capsys):
    source = tmp_path / "j.bin"
    source.write_bytes(b"json only")
    vault_dir = tmp_path / "jv"
    code = run(
        [
            "vault-lock",
            str(source),
            "-k",
            "2",
            "-n",
            "3",
            "--out-dir",
            str(vault_dir),
            "--format",
            "json",
            "--quiet",
        ]
    )
    assert code == 0
    assert list(vault_dir.glob("*.txt")) == []
    output = tmp_path / "out.bin"
    assert (
        run(
            [
                "vault-unlock",
                str(vault_dir / "j.bin.vault"),
                "--shares",
                *(str(p) for p in sorted(vault_dir.glob("*.json"))[:2]),
                "--out",
                str(output),
                "--quiet",
            ]
        )
        == 0
    )
    assert output.read_bytes() == b"json only"


def test_vault_commands_explain_missing_dependency(tmp_path, capsys, monkeypatch):
    for module in (
        "cryptography",
        "cryptography.exceptions",
        "cryptography.hazmat",
        "cryptography.hazmat.primitives",
        "cryptography.hazmat.primitives.ciphers",
        "cryptography.hazmat.primitives.ciphers.aead",
    ):
        monkeypatch.setitem(sys.modules, module, None)
    source = tmp_path / "f.bin"
    source.write_bytes(b"payload")
    code = run(["vault-lock", str(source), "-k", "2", "-n", "3", "--out-dir", str(tmp_path / "v")])
    assert code == 2
    assert "cryptography" in capsys.readouterr().err

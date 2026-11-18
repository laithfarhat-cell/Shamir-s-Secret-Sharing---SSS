# Shamir's Secret Sharing — threshold cryptography you can audit

[![Python](https://img.shields.io/badge/python-3.10%20%7C%203.11%20%7C%203.12-blue.svg)](https://www.python.org/)
[![Tests](https://img.shields.io/badge/tests-284%20passed-brightgreen.svg)](#testing)
[![Coverage](https://img.shields.io/badge/branch%20coverage-93%25-brightgreen.svg)](#testing)
[![Security](https://img.shields.io/badge/security-information--theoretic-blueviolet.svg)](THEORY.md#4-perfect-secrecy-why-k-1-shares-leak-zero-bits)
[![Field](https://img.shields.io/badge/field-GF%282%5E521%E2%88%921%29-purple.svg)](THEORY.md#12-registered-fields)
[![Vault](https://img.shields.io/badge/vault-AES--256--GCM-green.svg)](THEORY.md#73-hybrid-file-vault-envelope-encryption)
[![License](https://img.shields.io/badge/license-MIT-yellow.svg)](LICENSE)
[![Style](https://img.shields.io/badge/code%20style-ruff-000000.svg)](https://github.com/astral-sh/ruff)
[![Docker](https://img.shields.io/badge/docker-ready-2496ED.svg)](#docker)

Split a master key, seed phrase, root password or file key into `n` shares so that
**any `k` reconstruct it and any `k−1` reveal mathematically zero information**.
Polynomial arithmetic is implemented from scratch over
`GF(2^521 − 1)` / `GF(2^2281 − 1)` with Python's arbitrary-precision integers —
no floating point, no rounding, no silent data loss.

```
                 ★ 3-of-5 threshold  ·  exact finite-field arithmetic  ·  auditable  ★
```

---

## Contents

- [Why this implementation](#why-this-implementation)
- [Install](#install)
- [60-second quick start](#60-second-quick-start)
- [How it works](#how-it-works)
- [CLI reference](#cli-reference)
- [Share formats](#share-formats)
- [Hybrid file vault](#hybrid-file-vault)
- [Security lab: watch the secrecy happen](#security-lab-watch-the-secrecy-happen)
- [Python API](#python-api)
- [Security best practices](#security-best-practices)
- [Threat model & limitations](#threat-model--limitations)
- [Performance](#performance)
- [Testing](#testing)
- [Docker](#docker)
- [Project structure](#project-structure)
- [FAQ](#faq)
- [Further reading](#further-reading)

---

## Why this implementation

* **Information-theoretic secrecy, not "computational".** With `k−1` shares, every
  possible secret remains equally likely — even for an adversary with unlimited
  computing power. The proof is in [`THEORY.md` §4](THEORY.md#4-perfect-secrecy-why-k-1-shares-leak-zero-bits);
  the `sss lab` command demonstrates it by interpolation.
* **Exact arithmetic by construction.** Shares are elements of a prime field
  `GF(p)` with `p = 2^521−1` or `2^2281−1`. Floating point cannot represent those
  values, cannot invert modulo `p`, and silently returns wrong secrets —
  [`THEORY.md` §5](THEORY.md#5-why-floating-point-destroys-threshold-cryptography)
  quantifies the failure.
* **Operational safety.** Human-copyable armoured shares with truncated SHA-256
  checksums, optional commitments, duplicate/mixed-split detection, `0600` files in
  `0700` directories, atomic writes, and a `verify` command that never touches the
  secret.
* **Files handled properly.** `vault-lock` encrypts with AES-256-GCM and shares only
  the 32-byte DEK, so a 4 GiB archive does not become five 4 GiB shares.
* **Auditable.** ≈1 850 executable statements (≈4 100 lines with docstrings), 284 tests, 93 % branch coverage,
  no clever dependencies: `secrets`, `hashlib`, `json`, `base64`, `rich`, and
  `cryptography` for AES-GCM only.

---

## Install

```bash
# from source (recommended while the project is young)
git clone https://github.com/laithfarhat-cell/Shamir-s-Secret-Sharing---SSS
cd Shamir-s-Secret-Sharing---SSS
python -m venv .venv && source .venv/bin/activate
pip install -e ".[vault]"

# or, once published
pip install "shamir-sss[vault]"
```

`cryptography` is only needed for `vault-lock` / `vault-unlock`; everything else
works with `rich` alone (`pip install shamir-sss`). If the vault commands are used
without it, the CLI prints an actionable install hint instead of a traceback.

Requires Python 3.10+. No network access, no telemetry, no configuration files.

---

## 60-second quick start

Split a secret 3-of-5, distributing one card per custodian:

```console
$ sss split --secret "correct horse battery staple" -k 3 -n 5 \
            --out-dir ./shares --labels Alice,Bob,Carol,Dave,Erin
```

```text
╭──────────────────────────── Share 1 of 5 · Alice ────────────────────────────╮
│  threshold k=3   field GF(2^521 - 1)   x = 1                                 │
│  secret 28 B   payload 66 B   chunks 1                                       │
│  checksum 3f9aQ2m1x0A                                                        │
│                                                                              │
│  SSS-V1-m521-3-5-1-28-AKa7ZFLYbLCLhAwNwlRl3/kswVFnEJzN7jiHHfvNBQg+prW93Bc/   │
│  e/4HDOvm7NwZx0OsLy/5eQmFQI2yUg19c817-Ubq8hLkfFEo                              │
│                                                                              │
│  ASCII only (whitespace ignored) — safe for paper backups, QR codes, SMS.    │
╰──────────────────────────────────────────────────────────────────────────────╯
```

Reconstruct from any three shares — files, armoured strings, or a mix:

```console
$ sss combine --shares shares/share-01-of-05.txt \
                        shares/share-03-of-05.json \
                        shares/share-05-of-05.txt
```

Verify a share set without reconstructing (safe to run on a custodian's laptop):

```console
$ sss verify --shares shares/*.json
```

Protect a file instead of a short secret:

```console
$ sss vault-lock backup.tar.gz -k 3 -n 5 --out-dir ./vault
$ sss vault-unlock vault/backup.tar.gz.vault \
      --shares vault/backup.tar.gz-share-0{1,3,5}-of-05.txt --out restored.tar.gz
```

Watch the information-theoretic guarantee for yourself:

```console
$ sss lab -k 3 -n 5 --interactive
```

---

## How it works

### Splitting

```
   SECRET  S = 0x636f7272…61706c65           (28 bytes → one GF(2^521−1) element)
      │
      │  a₀ = S ;  a₁, a₂ ←$ GF(p) \ {0}
      ▼
   f(x) = a₀ + a₁x + a₂x²  (mod p)            degree exactly k−1 = 2
      │
      │  Horner: f(x) = a₀ + x·(a₁ + x·a₂)
      │
      ├── x=1 → ▣ Share 1   (Alice)
      ├── x=2 → ▣ Share 2   (Bob)
      ├── x=3 → ▣ Share 3   (Carol)
      ├── x=4 → ▣ Share 4   (Dave)
      └── x=5 → ▣ Share 5   (Erin)
```

### Reconstruction

```
        y
        │            ● (x₃, y₃)
        │          ╱   ╲
        │        ╱       ● (x₅, y₅)          any k = 3 points determine
        │      ● (x₁,y₁)     ╲               exactly one parabola
        │    ╱                 ╲
   S ●────┘                   ╲
        └───┬────┬────┬────┬────┬────▶ x
            1    2    3    4    5

                 k
        S = f(0) = Σ  yᵢ · Π  (−xⱼ)/(xᵢ − xⱼ)   (mod p)
                i=1      j≠i
```

Everything is exact integer arithmetic modulo a Mersenne prime. The full
derivation, the uniqueness lemma, the perfect-secrecy proof and the floating-point
post-mortem live in [`THEORY.md`](THEORY.md).

---

## CLI reference

```
sss <command> [options]
```

| Command | Purpose |
| --- | --- |
| `split` | split a text / hex / file / stdin secret into `n` shares |
| `combine` | reconstruct a secret from `k` or more shares |
| `verify` | validate syntax, checksums, duplicates, consistency — never reconstructs |
| `vault-lock` | AES-256-GCM encrypt a file and Shamir-split its DEK |
| `vault-unlock` | rebuild the DEK from shares and decrypt the file |
| `vault-info` | show a vault's authenticated header (needs no shares) |
| `lab` | run the `k−1` zero-leakage demonstration |
| `fields` | list registered prime fields and their capacities |

Global options: `--quiet/-q`, `--no-color` (also honours `NO_COLOR`), `--debug`,
`--version`. Exit codes: `0` success, `2` validation / cryptographic failure,
`1` unexpected error, `130` interrupted.

### `sss split`

```console
sss split --secret TEXT -k K -n N [--out-dir DIR] [--format armored|json|both]
sss split --hex 0011aaff -k K -n N
sss split --secret-file master.key -k K -n N
printf 'secret' | sss split --stdin -k K -n N
```

| Option | Meaning |
| --- | --- |
| `-k, --threshold K` | shares required to reconstruct (`2 ≤ k ≤ n`) |
| `-n, --shares N` | shares to create (`n ≤ 255`) |
| `--field auto\|m521\|m2281` | prime field; `auto` picks the smallest that fits |
| `--format` | `armored` (default without `--out-dir`), `json`, `both` (default with it) |
| `--out-dir DIR` | write share files (`0700` dir, `0600` files) |
| `--prefix NAME` | share file prefix (default `share`) |
| `--commitment` | attach `SHA-256(secret)` to every share — read [the caveat](THEORY.md#45-what-about-commitments) first |
| `--labels A,B,C` | custodian labels, one per share (JSON + cards) |
| `--allow-degenerate-degree` | sample coefficients over all of `GF(p)` (see [§4.3](THEORY.md#43-note-on-degree-exactly-k-1)) |
| `--no-print-shares` | suppress the distribution cards |
| `--no-strip` | keep a trailing newline read from stdin |
| `--force` | overwrite existing share files |

File names are `share-01-of-05.json` / `.txt`; vault shares are prefixed with the
source filename.

### `sss combine`

```console
sss combine --shares S1 S2 S3 [--out FILE] [--print-hex|--print-base64|--print-secret]
```

`--shares` accepts armoured strings, JSON share files, JSON bundles, `-` for stdin,
or any mixture. Extra shares beyond `k` are cross-checked against the quorum
polynomial, so a forged surplus share is rejected. `--out` writes the raw secret
(`0600`) and *does not* echo it; add `--print-secret` if you want both.
`--expected-commitment HEX` adds an out-of-band commitment check.

### `sss verify`

```console
sss verify --shares S1 S2 [--json] [--expected-commitment HEX]
```

Reports per-share validity plus set-level consistency: field, `k`, `n`, secret
length, duplicate x-indices, commitment agreement, and whether enough shares are
present. **No interpolation is performed** — the secret cannot leak. Exit code `0`
only when the set is valid *and* sufficient. `--json` emits a machine-readable
report for monitoring.

### `sss vault-lock` / `vault-unlock` / `vault-info`

```console
sss vault-lock archive.tar.gz -k 3 -n 5 --out-dir ./vault [--format both]
sss vault-info vault/archive.tar.gz.vault
sss vault-unlock vault/archive.tar.gz.vault \
    --shares vault/archive.tar.gz-share-01-of-05.txt \
             vault/archive.tar.gz-share-03-of-05.txt \
             vault/archive.tar.gz-share-05-of-05.txt \
    --out restored.tar.gz
```

`vault-info` prints parameters, the DEK commitment, the plaintext digest and the
original name without needing any share.

### `sss lab`

```console
sss lab -k 3 -n 5 [--candidate TEXT ...] [--interactive] [--shares ...]
```

Interpolates the unique polynomial through `k−1` shares plus an arbitrary candidate
secret, for several candidates, and shows that all of them fit equally well. Adding
the `k`-th share collapses the ambiguity to one polynomial.

### `sss fields`

Shows the registered Mersenne fields, their secret capacity, share encoding width
and Lucas–Lehmer primality certificate.

---

## Share formats

### Armoured string (human copyable, QR-safe, whitespace-insensitive)

```
SSS-V1-<field>-<k>-<n>-<index>-<secret_len>-<b64_y>-<checksum>[-<commitment>]
```

| Field | Meaning |
| --- | --- |
| `SSS-V1` | format tag and version |
| `<field>` | `m521` or `m2281` |
| `<k>`, `<n>` | threshold and total |
| `<index>` | x-coordinate, `1 ≤ index ≤ n` (0 is never a share) |
| `<secret_len>` | exact secret length in bytes (preserves leading zeros) |
| `<b64_y>` | unpadded standard base64 of the fixed-width payload block(s) |
| `<checksum>` | first 64 bits of SHA-256 over all fields, 11 base64 characters |
| `<commitment>` | optional `SHA-256(secret)`, 64 hex characters |

Parsing ignores whitespace (wrapped lines and QR scans are fine), accepts a
lowercase `sss-v1` prefix, and rejects any metadata change via the checksum.

### JSON share

```json
{
  "format": "sss-share",
  "version": 1,
  "field": "m521",
  "threshold": 3,
  "total": 5,
  "index": 2,
  "secret_bytes": 32,
  "y": "AKa7ZFLYbLCLhAwNwlRl3/kswVFnEJzN7jiHHfvNBQg+prW93Bc/e/4HDOvm7NwZx0OsLy/5eQmFQI2yUg19c817",
  "checksum": "Ubq8hLkfFEo",
  "commitment": null,
  "label": "Bob",
  "created_at": "2026-11-18T16:21:32Z"
}
```

The checksum covers everything except `label` and `created_at`, which are
presentation-only. JSON files may also contain a list of shares or a
`{"format": "sss-share-bundle", "shares": [...]}` document.

### Field capacities

| Field | Secret bytes per chunk | Share bytes per chunk | Entropy |
| --- | --- | --- | --- |
| `m521` = `GF(2^521−1)` | 65 | 66 | 521 bits |
| `m2281` = `GF(2^2281−1)` | 285 | 286 | 2281 bits |

Longer secrets are chunked transparently: each chunk gets an independent random
polynomial of degree `k−1`, all evaluated at the same x-coordinates.

---

## Hybrid file vault

```text
 file ──AES-256-GCM(DEK, nonce)──▶ ciphertext ─┐
                                                ├──▶ <name>.vault
 DEK ← secrets.token_bytes(32) ──Shamir(k,n)──▶ shares (32 bytes each)
```

Envelope layout (big-endian, all metadata authenticated as GCM associated data):

```
┌────────────┬──────────────┬──────────────────────┬──────────────────────────┐
│ magic (8)  │ header_len(4)│ header JSON (utf-8)  │ ciphertext ‖ GCM tag(16) │
│ "SSSVLT01" │ uint32       │ canonical, sorted    │ AES-256-GCM              │
└────────────┴──────────────┴──────────────────────┴──────────────────────────┘
```

* 256-bit DEK, 96-bit random nonce per file, single use.
* Header carries the DEK commitment, plaintext SHA-256, original name/size and
  parameters; any modification breaks the GCM tag before decryption.
* Output is written atomically with mode `0600`; the original is never modified or
  deleted.
* Wrong shares, wrong vault, insufficient shares and tampering all fail closed with
  a specific error message.

---

## Security lab: watch the secrecy happen

```console
$ sss lab -k 3 -n 5 --interactive
```

```text
candidate secret   first bytes     deg   fits 2 share(s)   fits k-th share
──────────────────────────────────────────────────────────────────────────
true secret        636f72726563…   2     yes               yes
all 0x00           000000000000…   2     yes               no
all 0xFF           ffffffffffff…   2     yes               no
random guess       087f4f2b1d2b…   2     yes               no
  All 4 candidates reproduce the 2 observed share(s) exactly — the shares cannot
  tell them apart.
  Adding share x=3 leaves exactly one surviving candidate (true secret).
```

Each candidate `S'` fixes the point `(0, S')`; together with `k−1` shares that is
`k` points with distinct x-coordinates, hence exactly one polynomial of degree
`k−1` — and it reproduces every visible share. The map `S' ↦ polynomial` is a
bijection, so the posterior over secrets is uniform: **0 bits leaked**. See
[`THEORY.md` §4](THEORY.md#4-perfect-secrecy-why-k-1-shares-leak-zero-bits).

The lab also runs against your own shares (`--shares ...`) and supports typed
candidates in interactive mode.

---

## Python API

```python
from core.shamir import split, combine, analyze_shares
from core.vault import lock_file, unlock_file

# --- threshold secret sharing -------------------------------------------
result = split(b"master key material", threshold=3, total=5)
assert len(result.shares) == 5

recovered = combine(result.shares[:3]).secret
assert recovered == b"master key material"

# export / import in either format
armored = result.shares[0].to_armored()
payload = result.shares[1].to_dict()
assert combine([armored, payload, result.shares[2].to_armored()]).secret == recovered

# validate without reconstructing
report = analyze_shares(result.shares[:2])
assert report.verdict == "insufficient"
assert not hasattr(report, "secret")

# --- hybrid file vault ---------------------------------------------------
locked = lock_file("archive.tar.gz", threshold=3, total=5, out_dir="vault")
restored = unlock_file(locked.vault_path, locked.shares[:3], out_path="restored.tar.gz")
assert restored.plaintext_size == locked.plaintext_size
```

Lower-level primitives are public too:

```python
from core.finite_field import get_field, horner_eval, lagrange_interpolate_at_zero

p = get_field("m521").p
coefficients = [42, 7, 123456789]              # f(x) = 42 + 7x + 123456789x²
points = [(x, horner_eval(coefficients, x, p)) for x in (1, 2, 3)]
assert lagrange_interpolate_at_zero(points, p) == 42
```

---

## Security best practices

- [ ] **Choose `k` for collusion, `n−k` for loss.** `k ≥ 3`, `n ≥ k+2` is a
      sensible default; `k=1` is meaningless (the share *is* the secret).
- [ ] **Separate the shares physically.** Different safes, sites, jurisdictions,
      HSMs, smart cards or paper. Never store `k` shares in one backup, one
      password manager, one cloud account or one repository.
- [ ] **Encrypt the storage medium too.** Shamir protects against *fewer than `k`*
      shares; full-disk encryption protects the machine that holds one.
- [ ] **Verify before you need it.** Run `sss verify` periodically, and rehearse a
      full reconstruction with a test secret once a year.
- [ ] **Prefer `--out` to printing.** Terminal scrollback, shell history, `script`
      logs and screenshots are all plaintext.
- [ ] **Prefer `vault-lock` for files.** It keeps share size constant and adds
      AES-256-GCM authenticity.
- [ ] **Treat a commitment as public information.** `--commitment` exposes
      `SHA-256(secret)` to every custodian; fine for random keys, dangerous for
      passwords. The vault commits only to a 256-bit DEK.
- [ ] **Do not renumber shares by hand.** Re-split with a new `(k, n)` instead;
      mixing splits is detected but cannot be repaired.
- [ ] **Retire a split by destroying all shares**, not by deleting some of them.

---

## Threat model & limitations

**Defended:** compromise of `< k` shares at rest or in transit; typos, truncation,
bit rot; mixed share sets; modified vault ciphertext or header; world-readable
files; a cloud provider reading the vault.

**Not defended:** `≥ k` colluding custodians; malware, keyloggers, debuggers or
memory dumps on the machine performing the operation; a subverted OS CSPRNG; timing
/ power side channels (CPython big integers are not constant-time); loss of
`≥ n−k+1` shares; a low-entropy secret protected only by a commitment.

**Practical limits.** Files are held in memory while locking/unlocking (2 GiB
safety cap), so keep the machine's RAM in mind for very large archives. `split`
supports arbitrary payloads, but share size grows linearly with the payload —
use the vault for files. Python cannot guarantee zeroisation of immutable `bytes`;
buffers the library owns are wiped on a best-effort basis.

---

## Performance

Measured on CPython 3.11 (median of 20 runs, 32-byte secret):

| Operation | Time |
| --- | --- |
| `split` 3-of-5 | **0.07 ms** |
| `combine` 3-of-5 | **0.04 ms** |
| `split` 20-of-20 | **0.28 ms** |
| `combine` 20-of-20 | **0.66 ms** |
| `split` 3-of-5, 2 KiB payload (chunked) | **0.26 ms** |
| `vault-lock` 10 MiB | ~0.34 s |
| `vault-unlock` 10 MiB | ~0.03 s |

Cost is dominated by big-integer multiplications (521 or 2281 bits) and, for the
vault, by AES-GCM throughput.

---

## Testing

```bash
pip install -e ".[dev]"
pytest -q                                  # 284 tests
pytest --cov=core --cov=cli --cov=simulation --cov-report=term-missing
ruff check .
```

The suite covers every `k`-subset recovery, `>k` and `<k` behaviour, boundaries
`k=n=2` and `k=n=20`, leading zeros, chunked payloads, both fields, checksum and
commitment tampering (including forgeries with recomputed valid checksums),
cross-split rejection, vault ciphertext/header tampering, file permissions, CLI
exit codes, JSON output, stdin/hex inputs, the plain-text fallback and the
perfect-secrecy property itself. Details in
[`THEORY.md` §11](THEORY.md#11-what-the-test-suite-proves).

---

## Docker

```bash
docker build -t sss .

docker run --rm -it -v "$PWD:/data" sss split \
    --secret "hello" -k 3 -n 5 --out-dir /data/shares

docker run --rm -it -v "$PWD:/data" sss combine \
    --shares /data/shares/share-01-of-05.json \
             /data/shares/share-03-of-05.json \
             /data/shares/share-05-of-05.json

# run the test-suite inside the image
docker build --target test -t sss-test .
docker run --rm sss-test
```

The runtime image runs as UID 10001 with no shell, installs only `rich` and
`cryptography`, and writes nothing outside the mounted working directory.

---

## Project structure

```
.
├── main.py                  # entry point: `python main.py ...` / `sss ...`
├── core/
│   ├── finite_field.py      # GF(p) arithmetic, Horner, Lagrange, Lucas–Lehmer
│   ├── shamir.py            # split/combine, share format, checksums, validation
│   ├── vault.py             # AES-256-GCM envelope + Shamir-protected DEK
│   ├── storage.py           # 0700/0600 atomic private file I/O
│   └── errors.py            # typed exception hierarchy
├── cli/
│   └── interface.py         # argparse + rich UI (plain-text fallback)
├── simulation/
│   └── security_lab.py      # k−1 zero-leakage demonstration
├── tests/
│   ├── test_finite_field.py
│   ├── test_shamir.py       # main suite: thresholds, tampering, boundaries
│   ├── test_vault.py
│   ├── test_cli.py
│   ├── test_security_lab.py
│   └── test_storage.py
├── THEORY.md                # derivations, proofs, floating-point post-mortem
├── pyproject.toml
├── requirements.txt
├── Dockerfile
└── .gitignore
```

---

## FAQ

**What happens if a custodian loses a share?**
As long as at least `k` shares survive, reconstruction still works. With `k` shares
there is no redundancy left — which is why `n > k` matters.

**Can I add a custodian later, or change `k`?**
No. Shamir shares are bound to `(k, n)` and a specific polynomial. Reconstruct the
secret in a secure environment and split it again with the new parameters.

**Can the shares themselves be encrypted or stored in the cloud?**
Yes — a share is a random-looking field element. Adding a password-based wrapper is
orthogonal and can only help. Never store `k` shares in the same account.

**How is this different from a password manager or "split a file into pieces"?**
Cutting a file into parts gives partial information: `k−1` pieces reveal `k−1` of
the bytes. Shamir's shares are individually uniform — `k−1` of them are exactly as
informative as none.

**What if two shares disagree?**
`combine` refuses to interpolate (duplicate index, parameter mismatch, or
inconsistency with the surplus-share check). `verify` tells you exactly which input
failed and why.

**Is the secret ever written to disk by `verify`?**
No. `verify` only parses, checksums and compares metadata; it never interpolates.

**Why is the armoured string so long?**
It contains a 66-byte field element (~88 base64 chars) plus authenticated metadata
and a checksum. A 521-bit field is what makes the secrecy information-theoretic at
that size. For compactness use JSON files or the vault.

**Which field should I choose?**
Leave `--field auto`. Up to 65 bytes you get the fast `m521`; 66–285 bytes use
`m2281`; longer payloads are chunked with `m2281`.

---

## Further reading

* [`THEORY.md`](THEORY.md) — finite fields, Horner, Lagrange interpolation,
  uniqueness, the perfect-secrecy proof, degree-exactness analysis, chunking, the
  floating-point failure modes, integrity layers and threat model.
* A. Shamir, *How to share a secret*, CACM 22(11), 1979.
* G. R. Blakley, *Safeguarding cryptographic keys*, AFIPS NCC, 1979.
* NIST SP 800-38D — GCM; FIPS 197 — AES.

---

## Contributing

Issues and pull requests are welcome. Please run `ruff check .` and `pytest -q`
before submitting; cryptographic changes must come with a proof sketch in
`THEORY.md` and tests that demonstrate the new property (positive *and* negative
cases).

## License

MIT — see [LICENSE](LICENSE). Provided as-is; review the threat model before
protecting anything you cannot afford to lose.

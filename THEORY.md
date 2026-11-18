# Shamir's Secret Sharing over Prime Fields

**Theory, security analysis and implementation notes**

This document derives every result the toolkit relies on, states the precise
security guarantee, and explains — with numbers — why threshold cryptography must
never be implemented with floating-point arithmetic.

---

## 0. Notation

| Symbol | Meaning |
| --- | --- |
| $p$ | a prime modulus; the toolkit uses Mersenne primes $2^{521}-1$ and $2^{2281}-1$ |
| $\mathbb{F}_p = GF(p)$ | the field of integers $\{0, 1, \dots, p-1\}$ under addition and multiplication modulo $p$ |
| $\mathbb{F}_p^{*}$ | the multiplicative group $\mathbb{F}_p \setminus \{0\}$, of order $p-1$ |
| $S$ | the secret, interpreted as a big-endian integer with $0 \le S < p$ |
| $k$ | threshold: number of shares required |
| $n$ | total number of shares issued |
| $f(x)$ | the random degree-$(k-1)$ polynomial whose constant term is $S$ |
| $(x_i, y_i)$ | a share: field element $x_i$ (the index) and $y_i = f(x_i)$ |
| $\lVert L \rVert$ | byte length of the secret |

---

## 1. The finite field $\mathbb{F}_p$

### 1.1 Why a field, and why a *prime* field

A field is a set with addition, subtraction, multiplication and division (except
by zero) satisfying the usual axioms. Interpolation requires division by
non-zero differences $x_i - x_j$, and the uniqueness proof requires that a
product of non-zero elements is non-zero. Both hold in $\mathbb{Z}/p\mathbb{Z}$
exactly when $p$ is prime.

If $p$ is composite, $\mathbb{Z}/p\mathbb{Z}$ is only a ring: it has zero
divisors ($2 \cdot 3 \equiv 0 \pmod 6$), some elements have no inverse, and a
non-zero polynomial can vanish on more points than its degree. Interpolation then
loses uniqueness, and the secrecy proof collapses. This is why
"Shamir over 64-bit integers" is not Shamir's scheme at all.

### 1.2 Registered fields

| name | modulus | secret capacity | share encoding | $\log_2 p$ (bits) |
| --- | --- | --- | --- | --- |
| `m521` | $2^{521}-1$ | 65 bytes | 66 bytes per chunk | 521 |
| `m2281` | $2^{2281}-1$ | 285 bytes | 286 bytes per chunk | 2281 |

Two widths are deliberately distinguished:

* **secret capacity** $c = \lfloor (e-1)/8 \rfloor$: every $c$-byte big-endian
  integer satisfies $2^{8c} \le p$, so it is always a field element.
* **element encoding width** $w = \lceil e/8 \rceil$: an arbitrary field element
  (including $p-1$, which has $e$ bits) needs $w$ bytes.

For $e = 521$: $c = 65$, $w = 66$. For $e = 2281$: $c = 285$, $w = 286$.
Conflating these two numbers is a classic off-by-one source of corrupt shares.

### 1.3 Primality is *proved*, not assumed

Both moduli are Mersenne numbers $M_e = 2^e - 1$ with prime exponent. The
Lucas–Lehmer test decides primality of $M_e$ deterministically:

$$
s_0 = 4, \qquad s_{j+1} = s_j^2 - 2 \bmod M_e, \qquad
M_e \text{ is prime} \iff s_{e-2} = 0 .
$$

The test is implemented in `core.finite_field.lucas_lehmer` and exercised by the
test-suite for both registered primes (`verify_primality()`); no probabilistic
Miller–Rabin assumption is involved.

### 1.4 Arithmetic

All operations are performed on Python integers, which have arbitrary precision,
and are reduced modulo $p$ immediately:

$$
a + b \equiv (a+b) \bmod p, \quad
a - b \equiv (a-b) \bmod p, \quad
a \cdot b \equiv (a b) \bmod p, \quad
-a \equiv (p-a) \bmod p .
$$

The multiplicative inverse is computed with the extended Euclidean algorithm
(`pow(a, -1, p)`), with Fermat's little theorem as a fallback:

$$
a^{-1} \equiv a^{p-2} \pmod p \qquad (a \not\equiv 0).
$$

Because $p$ is prime, every non-zero element is invertible and the inverse is
unique.

**Batched inversion (Montgomery's trick).** Lagrange interpolation needs $k$
inversions. Instead of $k$ exponentiations, the implementation computes prefix
products $\pi_i = a_1 \cdots a_{i-1}$, inverts the total product once, and walks
backwards:

$$
a_i^{-1} = \bigl(a_1 \cdots a_k\bigr)^{-1} \cdot \pi_i \cdot (a_{i+1}\cdots a_k).
$$

Cost: $3k$ multiplications plus one inversion instead of $k$ inversions.

### 1.5 Encoding and the leading-zero problem

A big-endian byte string maps to an integer in the obvious way. Two subtleties:

1. `int.from_bytes(b"\x00\x01")` and `int.from_bytes(b"\x01")` are both `1`.
   Reconstruction would therefore silently strip leading zero bytes. Every share
   therefore carries the exact `secret_len`, which is covered by the integrity
   checksum, and reconstruction converts back with an explicit width.
2. Payloads longer than the field capacity are **chunked** (§6). Each chunk is
   encoded at the fixed width $w$, so a share payload is always an exact multiple
   of $w$ and the chunk boundaries are unambiguous.

---

## 2. Splitting: the polynomial

### 2.1 Construction

Given $S \in \mathbb{F}_p$ and parameters $2 \le k \le n$, draw

$$
a_1, \dots, a_{k-1} \;\stackrel{\$}{\leftarrow}\; \mathbb{F}_p^{*}
$$

independently and uniformly (via `secrets.randbelow(p-1) + 1`), and define

$$
f(x) = a_0 + a_1 x + a_2 x^2 + \cdots + a_{k-1} x^{k-1},
\qquad a_0 = S .
$$

Shares are $(x_i, y_i)$ for $x_i = i$, $i = 1,\dots,n$. Since $a_{k-1} \ne 0$,
$\deg f = k-1$ exactly.

**Why $x_i \ne 0$?** $f(0) = S$: a share at $x = 0$ would *be* the secret. Indices
start at 1 and the parser rejects index 0.

**Why distinct $x_i$?** Duplicate abscissae make the interpolation problem
singular (two values for one point). The implementation uses $1..n$ and rejects
duplicate indices on reconstruction.

### 2.2 Horner's method

Evaluating $f$ by first forming powers costs $O(k^2)$ multiplications. Horner's
rule reorganises the same polynomial:

$$
f(x) = a_0 + x\bigl(a_1 + x(a_2 + \cdots + x\,a_{k-1})\bigr),
$$

which uses exactly $k-1$ multiplications and $k-1$ additions:

```
result = a[k-1]
for i = k-2 down to 0:
    result = result * x + a[i]     (mod p)
```

`core.finite_field.horner_eval` implements this. It never materialises $x^i$, and
every intermediate value is reduced modulo $p$, so no precision is lost and no
intermediate blows up. The test-suite checks it against the literal definition
for random polynomials.

---

## 3. Reconstruction: Lagrange interpolation at $x = 0$

### 3.1 Lagrange basis polynomials

For distinct nodes $x_1,\dots,x_k \in \mathbb{F}_p$, define

$$
L_i(x) \;=\; \prod_{\substack{j=1\\ j \ne i}}^{k} \frac{x - x_j}{x_i - x_j}
\;\in\; \mathbb{F}_p[x].
$$

Each $L_i$ has degree $k-1$ and satisfies the Kronecker property

$$
L_i(x_j) = \delta_{ij} =
\begin{cases} 1 & i = j,\\ 0 & i \ne j .\end{cases}
$$

Therefore

$$
P(x) = \sum_{i=1}^{k} y_i \, L_i(x)
$$

has degree $\le k-1$ and $P(x_i) = y_i$ for every $i$.

### 3.2 Uniqueness

**Lemma.** *Let $f, g \in \mathbb{F}_p[x]$ have degree $\le k-1$ and agree at $k$
distinct points. Then $f = g$.*

*Proof.* $h = f - g$ has degree $\le k-1$ and $k$ distinct roots. A non-zero
polynomial of degree $d$ over a field has at most $d$ roots, so $h = 0$. $\square$

Consequently $P$ above is *the* interpolating polynomial, and $S = P(0)$ is
determined by any $k$ shares.

### 3.3 The reconstruction formula

Setting $x = 0$ in the basis polynomials gives the implementation's formula:

$$
\boxed{\;S = f(0) = \sum_{i=1}^{k} y_i \prod_{\substack{j=1\\ j \ne i}}^{k}
\frac{-x_j}{x_i - x_j} \pmod p\;}
$$

All arithmetic is in $\mathbb{F}_p$: the differences are reduced modulo $p$, the
products are accumulated modulo $p$, and the denominators are inverted with
`batch_invert`. Evaluation costs $O(k^2)$ field multiplications, which for
$k \le 255$ is microseconds.

### 3.4 Worked example ($p = 101$, $k = 2$)

Secret $S = 42$, coefficient $a_1 = 7$, so $f(x) = 42 + 7x$:

| $x$ | $f(x) \bmod 101$ |
| --- | --- |
| 1 | 49 |
| 2 | 56 |
| 3 | 63 |

Reconstruct from shares $(1,49)$ and $(3,63)$:

$$
L_1(0) = \frac{0-3}{1-3} = \frac{-3}{-2} = \frac{3}{2} = 3\cdot 51 = 52,
\qquad
L_3(0) = \frac{0-1}{3-1} = \frac{-1}{2} = (-1)\cdot 51 = 50,
$$

$$
S = 52\cdot 49 + 50\cdot 63 = 2548 + 3150 = 5698 \equiv 42 \pmod{101}. \checkmark
$$

(The inverse of 2 modulo 101 is 51 because $2 \cdot 51 = 102 \equiv 1$.)

### 3.5 Recovering the whole polynomial

`interpolate_coefficients` returns $[a_0, \dots, a_{k-1}]$ using Newton's divided
differences followed by synthetic expansion:

$$
f[x_1,\dots,x_j] = \frac{f[x_2,\dots,x_j] - f[x_1,\dots,x_{j-1}]}{x_j - x_1},
\qquad
f(x) = \sum_{j=1}^{k} f[x_1,\dots,x_j] \prod_{i<j}(x - x_i).
$$

The lab uses this to exhibit the unique polynomial implied by each candidate
secret. Reconstruction of $S$ does **not** need it — evaluating at $x = 0$ via
the Lagrange weights is cheaper and equally exact.

---

## 4. Perfect secrecy: why $k-1$ shares leak zero bits

### 4.1 Statement

**Theorem (Shamir, 1979).** Let shares be generated as in §2 with
$a_1,\dots,a_{k-1}$ i.i.d. uniform over $\mathbb{F}_p$ (or over
$\mathbb{F}_p^{*}$, see §4.3). Then for any secret distribution on
$\mathbb{F}_p$,

$$
\Pr[\,S = s \mid (x_i,y_i)_{i=1}^{k-1}\,] \;=\; \Pr[\,S = s\,]
\qquad \text{for all } s,
$$

i.e. the $k-1$ shares are *statistically independent* of the secret. Equivalently,
the mutual information is $I(S;\,Y_1,\dots,Y_{k-1}) = 0$ and
$H(S \mid Y_1,\dots,Y_{k-1}) = H(S)$.

### 4.2 Proof by bijection

Fix the observed share points $(x_1,y_1),\dots,(x_{k-1},y_{k-1})$ and any candidate
secret $s' \in \mathbb{F}_p$. Consider the $k$ points

$$
(0, s'),\ (x_1,y_1),\ \dots,\ (x_{k-1},y_{k-1}).
$$

Their $x$-coordinates are distinct, so by the lemma of §3.2 there is **exactly
one** polynomial $f_{s'}$ of degree $\le k-1$ through them, and it reproduces
every observed share by construction.

Now count coefficient vectors. Write $f_{s'}(x) = a_0 + a_1 x + \cdots + a_{k-1}
x^{k-1}$ with $a_0 = s'$. The share equations are

$$
\underbrace{\begin{pmatrix}
x_1 & x_1^2 & \cdots & x_1^{k-1}\\
x_2 & x_2^2 & \cdots & x_2^{k-1}\\
\vdots & & & \vdots\\
x_{k-1} & x_{k-1}^2 & \cdots & x_{k-1}^{k-1}
\end{pmatrix}}_{V}
\begin{pmatrix} a_1 \\ a_2 \\ \vdots \\ a_{k-1}\end{pmatrix}
=
\begin{pmatrix} y_1 - s' \\ y_2 - s' \\ \vdots \\ y_{k-1} - s'\end{pmatrix}.
$$

$V$ is a Vandermonde matrix with distinct, non-zero $x_i$, hence invertible over
$\mathbb{F}_p$. Therefore, for **each** $s'$, the equation has exactly one solution
$(a_1,\dots,a_{k-1})$, and the map

$$
\varphi:\ \mathbb{F}_p \;\longrightarrow\; \mathbb{F}_p^{\,k-1},\qquad
s' \mapsto (a_1,\dots,a_{k-1})
$$

is a bijection. Under the uniform sampling of §2, every coefficient vector is
equally likely, so **every candidate secret is equally likely**:

$$
\Pr[\,S = s' \mid \text{shares}\,] = \frac{1}{p}
\qquad \text{for all } s' \in \mathbb{F}_p .
$$

No amount of computation can improve on a blind guess: the uncertainty is exactly
$\log_2 p$ bits ($\approx 521$ or $2281$ bits). This is *information-theoretic*
security — it holds against adversaries with unbounded computing power, because
the share distribution simply does not depend on the secret.

### 4.3 Note on "degree exactly $k-1$"

The specification (and this implementation, by default) forces every coefficient
into $\mathbb{F}_p^{*}$, which guarantees $\deg f = k-1$ and hence that *any* $k$
shares have a unique interpolant of the advertised degree. This costs an
information-theoretic $\varepsilon$ that is worth stating precisely:

Given $k-1$ shares, for each candidate $s'$ the interpolated coefficient
$c_j(s')$ is an affine function of $s'$, $c_j(s') = \alpha_j s' + \beta_j$ with
$\alpha_j = [x^j]\,L_0(x)$. The candidate is *excluded* only if some $c_j(s') = 0$.
Each such equation has at most one solution, so at most $k-1$ of the $p$ candidate
secrets are excluded. The posterior is therefore uniform over at least $p-(k-1)$
values, and the statistical distance from uniform is at most

$$
\varepsilon \;\le\; \frac{k-1}{p} \;\le\; \frac{254}{2^{521}-1} \;\approx\; 2^{-513}.
$$

This is far below any operational threshold (it is smaller than the probability of
a cosmic-ray bit flip), and it is not exploitable. For an exactly uniform
coefficient distribution, pass `--allow-degenerate-degree` (`require_exact_degree=
False` in the API): then $\deg f < k-1$ with probability $\approx (k-1)/p$, and the
shares are *exactly* uniform over $\mathbb{F}_p^{k-1}$ for every secret.

### 4.4 Why $k$ shares are enough, and $k-1$ are useless

* $k$ shares: the interpolating polynomial is unique (§3.2), so $S = f(0)$ is
  determined; `combine` computes it in $O(k^2)$.
* $k-1$ shares: there are exactly $p$ polynomials consistent with them, one per
  candidate secret (§4.2); nothing is determined.

The transition is sharp: entropy drops from $\log_2 p$ bits to $0$ bits at the
$k$-th share. This is why the scheme is called *threshold* rather than
*computational*.

### 4.5 What about commitments?

If shares carry $H = \mathrm{SHA\text{-}256}(S)$, an attacker holding $k-1$
shares can test guesses offline: compute $H(s')$ for a guess and compare. For a
high-entropy secret this is infeasible; for a human-memorable password it is a
serious weakness that destroys the information-theoretic guarantee. The toolkit
therefore makes commitments **opt-in on `split`** and documents the trade-off. The
vault always commits, but only to a fresh 256-bit DEK (§7.3), which is safe.

---

## 5. Why floating point destroys threshold cryptography

Floating-point arithmetic is *approximate real* arithmetic. Shamir's scheme needs
*exact finite-field* arithmetic. The gap is not a small numerical error — it is a
category error. Five independent failure modes:

### 5.1 Representability

IEEE-754 binary64 has a 53-bit significand and therefore represents integers
exactly only up to $2^{53} = 9{,}007{,}199{,}254{,}740{,}992$. A share in
$\mathbb{F}_{2^{521}-1}$ is a 521-bit integer. The moment a share is converted to
a float, it is rounded — before any arithmetic happens.

Concrete example ($p = 2^{61}-1$, so the numbers fit in a double without overflow,
which makes the failure *purely* one of precision):

| quantity | exact integer | stored as `float` | error |
| --- | --- | --- | --- |
| $y_1 = 2140575826594513642$ | …513642 | …513664 | $+22$ |
| $y_2 = 822387139368474012$ | …474012 | …473984 | $-28$ |

Interpolating $S = 2 y_1 - y_2$ (the $k=2$, $x \in \{1,2\}$ case) in floats returns
`3.458764513820553e+18` instead of `1152921504606859321` — an error of
$2.3 \times 10^{18}$.

For `m521`, share values around $10^{157}$ are still representable as doubles but
carry only 53 bits of them; products of two shares ($\sim 10^{314}$) overflow to
`inf`, and for `m2281` the share values themselves ($\sim 10^{686}$) already
overflow binary64's maximum of $\approx 1.8 \times 10^{308}$.

### 5.2 Modular reduction has no floating-point analogue

"$a^{-1} \bmod p$" is not "$1/a$". For $p = 101$, $2^{-1} = 51$, not $0.5$. Floating
point cannot express the reduction operation at all: `%` on floats in Python is a
*real* remainder (`fmod`), not a modular inverse or a field reduction. Any attempt
to emulate it accumulates error and eventually returns a value outside $[0,p)$.

### 5.3 The Lagrange identity breaks

Exactness of reconstruction relies on $\sum_i L_i(0) = 1$ and $L_i(x_j) = \delta_{ij}$
*identically* in the field. In floating point these become approximate:
interpolation is ill-conditioned — the Lebesgue constant grows with the nodes and
degree, and cancellations such as $2y_1 - y_2$ above destroy leading digits. The
reconstructed value is typically not even an integer:

```
>>> float interpolation of 3 shares mod 2^61-1
5.764607523034247e+18      # instead of 1152921504606859321
```

### 5.4 Non-associativity and irreproducibility

Floating-point addition and multiplication are not associative. Different
summation orders (or vectorised/parallel reductions, or FMA contraction) give
different results, so the same shares can reconstruct to different secrets on
different CPUs or with different optimisation flags. There is no canonical answer
to reproduce.

### 5.5 Silent security failure

Rounding is deterministic given the shares, so a "float Shamir" implementation
leaks information about the secret through the low-order rounding pattern, and its
shares are not uniform. More importantly, reconstruction silently returns a wrong
secret — a *data-loss* bug in a backup system that surfaces only when the
custodians are already assembled and the original is gone.

### 5.6 Fixed-width integers fail too

Replacing floats with `uint64_t` is not the fix. Arithmetic wraps modulo $2^{64}$,
not modulo $p$; $2 \cdot 2^{63} \equiv 0 \pmod{2^{64}}$ makes the ring have zero
divisors, so interpolation is no longer unique and secrets are lost. Using a
machine-word prime (e.g. $2^{61}-1$) works *if* all multiplications are widened
(128-bit) and reduced with Montgomery/Barrett arithmetic — which is exactly the
kind of constant-time, side-channel-aware engineering a production C implementation
needs. This toolkit sidesteps the class of bug entirely by using Python's
arbitrary-precision integers: exact by construction, at a performance cost that is
irrelevant for key-sized secrets (see §10).

---

## 6. Chunking long secrets

A field element holds at most $c = 65$ bytes (`m521`) or $285$ bytes (`m2281`).
Longer payloads are split into

$$
m = \left\lceil \frac{\lVert L \rVert}{c} \right\rceil
$$

chunks, most-significant first. The secret integer is

$$
S = S_1 \cdot 2^{8c(m-1)} + S_2 \cdot 2^{8c(m-2)} + \cdots + S_m ,
$$

and each chunk $S_j$ gets its **own independent** polynomial $f_j$ of degree
$k-1$ with constant term $S_j$; all polynomials are evaluated at the same
$x_1,\dots,x_n$. A share is the concatenation of the $w$-byte encodings of
$f_1(x_i), \dots, f_m(x_i)$.

**Security.** The coefficient vectors of the chunks are drawn independently.
Conditioned on $k-1$ shares, each chunk's coefficient vector is uniform (§4.2), and
independence across chunks means the joint distribution of
$(S_1,\dots,S_m)$ — hence of $S$ — is uniform over $\mathbb{F}_p^m$. Chunking
therefore neither weakens secrecy nor couples chunks.

**Correctness.** Reconstruction interpolates each chunk independently, rebuilds
the big integer, converts to the recorded `secret_len` bytes, and verifies that the
high-order padding region is all zeros. Non-zero padding means the shares were
mixed across splits or tampered with, and is rejected.

**Cost.** Shares grow linearly with the payload: a 1 MiB file split 3-of-5 produces
five ~1 MiB shares (plus base64 expansion). For files, use `vault-lock`: it encrypts
once with AES-256-GCM and shares only the 32-byte key (§7.3).

---

## 7. Integrity, commitments and the vault

Shamir's scheme provides **confidentiality, not authenticity**. Any $k$ shares
interpolate to *some* secret; a forged share yields a plausible-looking but wrong
secret. Three layers address this.

### 7.1 Per-share integrity checksum

Every share carries a 64-bit tag

$$
\tau = \mathrm{SHA\text{-}256}\bigl(\texttt{"SSS|V1|}\mathit{field}\texttt{|}k\texttt{|}n
\texttt{|}i\texttt{|}\ell\texttt{|}y_{\text{b64}}\texttt{|}\mathit{commitment}\bigr)[0..7],
$$

encoded as 11 base64 characters. It covers *all* metadata (field, $k$, $n$, index,
secret length, payload, commitment), so changing any of them is detected before
interpolation. A random typo or bit flip evades detection with probability
$2^{-64}$ — well below hardware error rates.

The tag is **not a MAC**: anyone can recompute it. It detects accidents, not a
determined attacker. This is stated explicitly in the threat model (§9).

### 7.2 Optional commitment to the secret

`split --commitment` stores $H(S) = \mathrm{SHA\text{-}256}(S)$ in every share. On
`combine`, the reconstructed secret must hash to $H$, which catches internally
consistent forgeries and wrong-share mix-ups. The trade-off is §4.5: with $k-1$
shares and a commitment, low-entropy secrets become offline-guessable. The
commitment is therefore **off by default**; use it when the secret is a
high-entropy key or when you control the distribution risk.

### 7.3 Hybrid file vault (envelope encryption)

```text
file ──AES-256-GCM(DEK, nonce)──▶ ciphertext ─┐
                                              ├──▶ .vault = magic | len | header | ciphertext‖tag
DEK (32 random bytes) ──Shamir(k,n)──▶ shares ┘        header is GCM associated data
```

* A fresh 32-byte DEK is drawn per file from `secrets.token_bytes`.
* AES-256-GCM with a 96-bit random nonce; the 128-bit tag authenticates the
  ciphertext **and** the header, because the header bytes are supplied as AAD.
* Only the DEK is Shamir-split, so share size is independent of file size.
* The header stores `SHA-256(DEK)` (a safe commitment: 256 bits of entropy), the
  plaintext digest, the original name/size and the parameters.
* Nonce reuse cannot occur: each DEK is used for exactly one message.

Security: violating the GCM tag requires breaking AES-256; recovering the DEK from
$k-1$ shares requires breaking the perfect secrecy of §4. Both are out of reach.
What remains is the operational problem of keeping shares apart (and the vault file
itself can be stored anywhere, including with an untrusted cloud provider).

| Layer | Protects against | Secret/public? |
| --- | --- | --- |
| Truncated SHA-256 checksum | typos, truncation, bit rot, mixed metadata | public, forgeable |
| SHA-256 commitment | consistent forgery, wrong split (low-entropy caveat) | public, offline-testable |
| AES-256-GCM tag | ciphertext/header modification, wrong key | public, unforgeable |

---

## 8. Side channels and implementation notes

* **Not constant time.** CPython's big-integer arithmetic and `pow` are not
  constant-time. The scheme is information-theoretically secure, but an attacker
  who can time or power-analyse the implementation may learn about coefficients.
  This toolkit targets offline splitting/reconstruction on a trusted machine, not
  an interactive oracle. Do not expose `combine` as a network service.
* **CSPRNG.** Coefficients come from `secrets.randbelow`, which uses the OS
  CSPRNG and rejection sampling (no modulo bias).
* **Memory hygiene.** `core.storage.wipe` zeroes the bytearray buffers the library
  controls, but Python `bytes` are immutable and may be copied by the interpreter,
  the garbage collector or `str` conversions. Python cannot guarantee
  zeroisation; use full-disk encryption and a trusted, single-purpose host.
* **Filesystem.** Share files are written `0600` inside `0700` directories,
  atomically (temp file + `fsync` + `os.replace`), so a crash cannot leave a
  half-written share. Existing files are never overwritten without `--force`.
* **No telemetry, no network I/O.** The tool never phones home and makes no
  network calls; `cryptography` is used purely for AES-GCM.

---

## 9. Threat model

**In scope (defended):**

* Theft or compromise of fewer than $k$ shares, at rest or in transit, including
  a full disk image of a custodian's machine.
* Typos, truncation, bit rot, mixed-up share files (checksums, commitments).
* Cross-split mixing of shares with different parameters (consistency checks).
* Vault ciphertext or header modification (AES-GCM AAD).
* Accidental leakage through world-readable files (permissions, atomic writes).
* A cloud provider reading the vault file (it is AES-256-GCM ciphertext).

**Out of scope (cannot be defended by the scheme):**

* $\ge k$ colluding custodians: they legitimately reconstruct the secret.
* A compromised endpoint: malware, a keylogger, a debugger or a memory dump that
  observes the secret or $\ge k$ shares while they are in use.
* A subverted OS CSPRNG or a malicious Python interpreter.
* Side-channel attacks against the process (timing, power, cache).
* Loss of $\ge n-k+1$ shares (no recovery is mathematically possible).
* A low-entropy secret protected only by a commitment (§4.5).

**Operational guidance.**

* Choose $k$ so that collusion is implausible and $n-k$ so that loss is survivable:
  $k \ge 3$, $n \ge k+2$ for most organisations.
* Distribute shares over independent channels: paper in separate safes, HSMs, smart
  cards, different jurisdictions. Never store $k$ shares in one place, one backup,
  or one password manager.
* Label shares by custodian and split id (supported via `--labels`), never by
  secret content.
* Run `sss verify` before combining; it validates checksums and consistency without
  ever reconstructing the secret.
* For files, prefer `vault-lock`; verify the restored file (the tool does, via the
  plaintext digest and GCM tag) before destroying the original.
* Clear terminal scrollback after handling secrets; prefer `--out` to printing.

---

## 10. Complexity and measured performance

| Operation | Time complexity | Measured (median, CPython 3.11) |
| --- | --- | --- |
| Split $(k,n)$ | $O(nk)$ field mults + $n$ checksums | 3-of-5, 32 B: **0.07 ms** |
| Combine $k$ shares | $O(k^2)$ field mults | 3-of-5: **0.04 ms** |
| Combine 20 shares | $O(k^2)$ | 20-of-20: **0.66 ms** |
| Interpolate coefficients | $O(k^2)$ | $k=20$: < 1 ms |
| Vault lock (AES-GCM) | $O(\text{file})$ | 10 MiB: **~0.34 s** |
| Vault unlock | $O(\text{file})$ | 10 MiB: **~0.03 s** (plus key rebuild) |

Field multiplications are on 521- or 2281-bit integers; Python's Karatsuba
multiplication makes them a few hundred nanoseconds. Chunked payload splitting is
linear in payload size.

---

## 11. What the test-suite proves

`tests/` contains 284 tests covering:

* Horner evaluation against the literal polynomial definition, for random degrees.
* Lagrange interpolation against direct evaluation at arbitrary targets.
* Newton coefficient recovery reproducing the original coefficients.
* Exact $k$-of-$n$ recovery for **every** $k$-subset; $>k$ recovery; $<k$ rejection.
* Boundaries $k=n=2$ and $k=n=20$, leading zeros, 1-byte to multi-kilobyte secrets,
  both fields and multi-chunk payloads.
* Duplicate-index, checksum, metadata, commitment, cross-split and forged-share
  detection (including forgeries with recomputed valid checksums).
* Armoured/JSON/bundle round-trips and malformed-input rejection.
* Vault tampering of ciphertext, header, magic and truncation; wrong shares;
  overwrite protection; permission bits.
* The perfect-secrecy property: for arbitrary candidate secrets, the implied
  polynomial reproduces every one of the $k-1$ shares.
* CLI exit codes, JSON output, quiet mode, stdin/hex/file inputs and the plain-text
  fallback.

Run them with `pytest -q` (or `docker build --target test .`).

---

## 12. References

1. A. Shamir, *How to share a secret*, Communications of the ACM 22(11), 1979,
   pp. 612–613.
2. G. R. Blakley, *Safeguarding cryptographic keys*, AFIPS National Computer
   Conference, 1979.
3. R. J. McEliece, D. V. Sarwate, *On sharing secrets and Reed–Solomon codes*,
   Communications of the ACM 24(9), 1981.
4. D. E. Knuth, *The Art of Computer Programming, Vol. 2*, §4.6.1 (Horner's rule)
   and §4.6.4 (polynomial arithmetic).
5. NIST, *SP 800-38D: Recommendation for Block Cipher Modes of Operation:
   Galois/Counter Mode (GCM) and GMAC*, 2007.
6. NIST, *FIPS 197: Advanced Encryption Standard (AES)*, 2001.
7. D. H. Lehmer, *Lucas's test for the primality of Mersenne's numbers*, 1930;
   see also H. Riesel, *Prime Numbers and Computer Methods for Factorization*.
8. W. Trappe, L. C. Washington, *Introduction to Cryptography with Coding Theory*,
   chapters on secret sharing and finite fields.

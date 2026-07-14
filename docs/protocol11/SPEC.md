# Code-based dePCS protocol11 executable specification

Status: executable G0 specification for the `protocol11` implementation.

## Source

- Historical paper path: `Doc/papers/pq_dSNARK.pdf`
- Git blob: `af3aad2a0fa618e6324bd48d03d586b281315299`
- Normative protocol range: Protocols 6 through 11, including the security and
  complexity discussion on PDF pages 28 through 31.
- Encoding references: [Brakedown, IACR ePrint 2021/1043](https://eprint.iacr.org/2021/1043.pdf)
  and [BrakingBase, IACR ePrint 2024/1825](https://eprint.iacr.org/2024/1825.pdf).

This repository instantiates every polynomial commitment with DeepFold,
including `H_u`. The protocol paper and this executable specification use the
same backend; the artifact does not contain a BaseFold compatibility mode.

## Parameters and layout

Let `N` be the polynomial evaluation-vector length and `M` the worker count.
Both are powers of two and `1 <= M < N`.

```
n  = log2(N)
m  = log2(M)
b  = next_power_of_two(n - m)
B  = M * b
C  = N / B
c  = 2
```

`B` and `C` must divide `N` and be powers of two. The paper matrix is
`M_f in F^(B x C)`. Worker `i` owns rows `[i*b, (i+1)*b)`. Each row is encoded
systematically from `C` to `c*C` elements.

The paper-visible layout is row-major. `bin(i)` is MSB-first. The public
evaluation point is `s = s1 || s2`, with `|s1| = log2(B)` and
`|s2| = log2(C)`. Any low-bit-first representation required by a PCS backend is
confined to its adapter.

Brakedown's native systematic codeword order is `[message | parity]`. Before a
codeword becomes the paper polynomial `E`, a fixed permutation maps it to the
MSB-first `(column_bits, expansion_bit)` table. Thus the systematic slots are
exactly `E(u',0)`, while the encoder API itself retains a systematic prefix.
The inverse bit-order permutation needed by DeepFold is confined to the same
adapter boundary.

For worker `i` and local row `k`,

```
beta^(i)[k] = eq(s1, bin(i*b + k)).
```

## Transparent setup

`setup_seed` is public. Setup expands it with SHA-256 domain separation into
the systematic Brakedown encoder parameters and binds the seed, layout,
field, hashes, security profile, and protocol version into `params_digest`.

The encoder follows Brakedown Algorithm 1 with `r=2`, `alpha=1/4`, and a
target `beta=1/10`: `Enc_n(x)=(x,z,v)`, `y=x*A(n)`,
`z=Enc_(n/4)(y)`, and `v=z*B(n)`. The finite-domain implementation uses
SHA-256-derived matrices from the paper's `M_(n,m,d)` distribution. Every
recursive level derives the `A(n)` and `B(n)` row weights from Equations
(7)--(8), with one conservative extra edge after the entropy-expression
ceiling. The degree is capped by the target dimension only when the resulting
row is dense. The diagonal systematic base code for `n<4` has non-zero
diagonal coefficients and relative distance at least `1/3`.

The encoder exposes its systematic parity-check relation `H=[-P|I]`. For
every valid row `F`, `E=Enc(F)` satisfies `H*E=0`; `H_u` is evaluated by the
transpose of the recursive encoder without materializing a dense matrix.

## Protocol 11 message order

1. Bind `(version, params_digest, commitment, s, v)`.
2. Verifier samples `a in F^B`.
3. Workers send PC commitments to `E1`, `F1`, `E2`, `F2` and Merkle roots for
   `E1`, `E2`.
4. Verifier samples a distinct column-index set `I`.
5. Workers send original encoded-column openings, `E1/E2` Merkle openings,
   `F2(s2)` openings, and the aggregate values `y1`, `y2`.
6. Run Protocol 10 for `E1 = Enc(F1)`.
7. Run Protocol 10 for `E2 = Enc(F2)`.
8. Bind the final transcript digest.

Protocol 10 samples `u`, runs a round-by-round sumcheck for
`sum_b E(b) * H_u(b) = 0`, opens `H_u(r)` and `E(r)`, then samples `u'` and
checks `E(u', 0^log(c)) = F(u')`.

The interactive implementation is normative. Fiat-Shamir replays the same
state machine and derives each verifier message only after absorbing every
preceding prover message. A proof contains prover messages; the public `s` and
`v` are supplied independently to verification.

## Security profiles

- `Paper100`: at least 100 bits of classical soundness in the classical random
  oracle model. DeepFold runs at rate `1/2` in the proven unique-decoding
  regime `Delta=1/4`; setup derives the PCS and column query counts and rejects
  configurations whose exact probability ledger exceeds `2^-100`.
- `TestOnly(q)`: permits reduced queries for tests and carries no security
  claim. CLI use requires an explicit insecure-test flag.

The release field is the 255-bit prime field `Ft255`. SHA-256 is used for
transcript challenges and hash-to-field; BLAKE3 is used by Merkle/DeepFold.
Field sampling uses canonical 32-byte encodings and rejection sampling. Query
indices are sampled without replacement.

## Non-goals

protocol11 is not zero knowledge or hiding, does not provide public-network
authentication/TLS, and has no large-scale performance guarantee. Vendored
DeepFold has no confirmed license file, so public redistribution is blocked.

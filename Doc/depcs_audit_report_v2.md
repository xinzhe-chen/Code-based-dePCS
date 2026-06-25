# dePCS Implementation Status

Scope: current `crates/pq-pcs`, `crates/pq-sumcheck`,
`crates/pq-core/matrix.rs`, `crates/pq-core/mle.rs`, and
`crates/pq-transcript`, checked against Chapter 4 of `Doc/pq_dSNARK.pdf`
including Protocols 6, 8, 9, 10, and 11.

## Verdict

The implementation has been rewritten from the older full-vector direct
prototype into a Chapter 4 dePCS implementation path:

- transparent PC interface plus a BaseFold-semantics Merkle folding backend,
- Brakedown-style systematic linear-time code with a matching sparse
  parity-check matrix,
- Protocol 8/9 distributed PC commitments and evaluation openings,
- Protocol 10 product-sumcheck encoding proof using `H_u`,
- Protocol 11 distributed Brakedown flow with Merkle column sampling and two
  Protocol 10 relation proofs.
- lazy verifier-side checks for sampled `H_u[j]` leaves, avoiding the older
  full `eq(u)`/`eq(r)` materialization in Protocol 10 verification.
- O(1) verifier-side Protocol 10 parity-shape binding through
  `BrakedownParityShape`; the verifier no longer builds the materialized sparse
  `H` matrix. The current shape is `rows = 4n`, `cols = 4n`, `nnz = 14n`,
  matching the implemented `5n + 5n + 4n` constraints.

Verifier-facing proof objects no longer carry full `row`, `encoded_row`,
`f1/e1/f2/e2`, `f`, or `e` vectors. The Fiat-Shamir challenges `a` and `beta`
are also recomputed by the verifier rather than stored in the proof.

## Remaining Boundary

The BaseFold backend is implemented in-repository as a transparent Merkle
folding evaluation-opening protocol. It follows the required PC interface and
succinct-opening shape, but it is not a line-for-line port of an external
production BaseFold implementation.

The default security budget is `lambda=128` through query count. The base field
is still Goldilocks, so documentation and benchmark reports must avoid claiming
that one field element alone gives 128-bit algebraic soundness.

The main remaining theoretical gap is a formal distance proof for the concrete
deterministic sparse code used here. The implementation proves and tests that
the code and parity-check matrix are consistent, but it does not yet establish
the Brakedown paper's constant-relative-distance assumption for this exact
graph family.

## Complexity Status

| Dimension | Current status |
| --- | --- |
| Prover work per worker | linear in local matrix rows/codewords |
| Verifier work | commitments, sumcheck rounds, lazy `H_u[j]` column checks, and sampled PC/Merkle openings |
| Proof size | no full witness/codeword vectors and no stored `a/beta`; dominated by PC openings, Merkle paths, and sumcheck rounds |
| Encoding proof | verifier-sampled `u`, `H_u`, product sumcheck, PC openings for `E`, `F`, and `H_u` |
| Underlying PC | transparent Merkle folding backend with BaseFold-style interface |
| Code | systematic Brakedown-style linear-time code with sparse parity-check matrix |

## Benchmark Interpretation

New benchmark directories should be interpreted as measuring:

- `commit_ms`: Protocol 11 commit runtime,
- `commitment_kib`: commitment object size,
- `proof_kib`: Protocol 11 opening proof size,
- `communication_kib`: measured bytes sent plus bytes received. The current
  dePCS benchmark uses local TCP worker processes, so this value is measured
  from framed socket traffic rather than inferred from proof size.

The older directory
`results/depcs-ligesis-full-nv10-16-workers1-16-parity` is a pre-BaseFold
direct-prototype result and should not be mixed with the new proof-size charts.

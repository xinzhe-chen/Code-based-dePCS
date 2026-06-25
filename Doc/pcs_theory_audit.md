# PCS Theory Audit

This repository is scoped to the Chapter 4 distributed transparent PCS path in
`Doc/pq_dSNARK.pdf`.

## Current Protocol Surface

- `pq-pcs::DistributedBrakedown::commit` implements the Protocol 11 commit
  phase over a row-wise distributed matrix. Each worker commits to hashes of
  encoded columns, matching the distributed Merkle commitment role in the
  paper.
- `pq-pcs::DistributedBrakedown::open` implements the Protocol 11 evaluation
  phase: verifier challenge vector `a`, `beta = eq(s1, row)`, per-worker
  commitments to `E1/F1/E2/F2`, Merkle column sampling over the encoded domain,
  `F2(s2)` aggregation, and two Protocol 10 encoding proofs.
- Protocols 8 and 9 are represented by per-worker transparent PC commitments
  and evaluation openings for `E1/E2/F1/F2`; verifier-side checks aggregate
  local claimed values into the global claim.
- Protocol 10 now follows the paper shape: the verifier samples `u`, the prover
  forms `H_u`, proves `sum_b E(b) * H_u(b) = 0` with product sumcheck, opens
  `H_u(r)` and distributed `E(r)` through the transparent PC, then checks the
  systematic relation `E(u', 0, 0) = F(u')`.
- The `H_u` verifier path no longer materializes full `eq(u)` and `eq(r)`
  tables to recompute `H_u(r)`. Instead, the BaseFold verifier checks sampled
  original-layer `H_u[j]` leaves lazily from the sparse parity-check column,
  using only the O(1)-sized column support of the in-repo code.
- Protocol 10 verification also no longer constructs the full sparse
  parity-check matrix just to bind dimensions. The transcript absorbs an O(1)
  `BrakedownParityShape` derived from the code spec: `rows = 4n`,
  `cols = 4n`, and `nnz = 14n` for the current in-repo constraint system
  (`5n + 5n + 4n` nonzero entries).

## Implementation Boundary

The default transparent PC backend is an in-repository BaseFold-semantics
Merkle folding commitment: it commits to MLE evaluations, folds by the claimed
evaluation point, and verifies sampled folding paths through Merkle openings.
This replaces the older full-vector verifier path; verifier-facing Protocol 10
and Protocol 11 proofs no longer carry full witness rows or full codewords.

The field remains the 64-bit Goldilocks field. The default `lambda=128` is
implemented as a query-budget parameter for proximity/folding checks; this is
not a claim that a single Goldilocks field element provides 128 bits of
algebraic security by itself.

The remaining proof-level caveat is code distance: the current deterministic
constant-degree expander-style code is sparse and systematic, and its matching
`H` is tested, but the repository does not yet include a formal constant
relative-distance proof for that concrete graph family.

## Benchmark Contract

`pq-experiments pcs-benchmark` measures only the `protocol11` dePCS path. CSV
outputs separate verifier-facing proof payload fields from `communication_bytes`,
which is reserved for measured bytes sent plus bytes received. The dePCS local
TCP runner records `network_commit_bytes`, `network_open_bytes`, and
`network_bytes` from actual framed socket traffic.

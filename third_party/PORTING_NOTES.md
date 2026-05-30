# Porting Notes

This file tracks how the pinned third-party sources are used by the local
prototype. The current implementation keeps local, dependency-light Rust crates
as the executable path and uses vendored sources as reference material until a
symbol-level port is completed.

## Spartan2

- Pin: `third_party/Spartan2` at
  `0d4f1409e8f30536b8b25ed3f81bc446ed717e61`.
- License: MIT.
- Referenced structure:
  - `src/r1cs/*` for R1CS shape and sparse-matrix organization.
  - `src/sumcheck.rs` and `src/polys/*` for Spartan-style MLE/sumcheck flow.
  - `src/traits/*` for PCS-generic API boundaries.
- Current local mapping:
  - `crates/pq-core` owns the small Goldilocks-field R1CS and sparse matrix
    types.
  - `crates/pq-sumcheck` owns the executable sumcheck and
    equality-polynomial weighted zerocheck prototype.
  - `crates/pq-piop-r1cs` owns the distributed Spartan-style adapter and
    Spark-like multiset checks.
- Source-level ports completed:
  - `third_party/Spartan2/src/r1cs/sparse.rs::PrecomputedSparseMatrix`
    coefficient bucketing has been ported to
    `crates/pq-core/src/matrix.rs::PrecomputedSparseMatrix`. The local version
    keeps the same semantic buckets (`+1`, `-1`, signed small coefficients
    `2..=7`, and general coefficients) over the Goldilocks field and is now on
    the executable `SparseMatrix::mul_vec` path used by R1CS constraint
    evaluation. Differential tests compare precomputed and naive
    multiplication and assert the bucket counts.
- Not ported yet:
  - Curve/IPA/Hyrax commitment backends are intentionally excluded from the
    final PCS path.
  - Spartan2 does not implement the Spark optimization noted in its README, so
    the current distributed multiset check remains local code.

## HyperPlonk

- Pin: `third_party/hyperplonk` at
  `2a3b55c97ad8a5d6627108a2e7def2aeccb7f3b9`.
- License: MIT.
- Referenced structure:
  - `hyperplonk/src/custom_gate.rs`, `selectors.rs`, `structs.rs`, and
    `witness.rs` for Plonkish gate/witness shape.
  - `subroutines/src/poly_iop/*` for sumcheck, zero-check, permutation-check,
    and product-check organization.
- Current local mapping:
  - `crates/pq-core` has row-oriented Plonkish arithmetic gates and a separate
    gate/permutation witness model.
  - `crates/pq-piop-plonkish` has the executable gate plus permutation PIOP
    adapter used by the experiment CLI.
- Source-level ports completed:
  - `third_party/hyperplonk/hyperplonk/src/custom_gate.rs::CustomizedGates`
    vanilla Plonk gate representation has been ported to
    `crates/pq-core/src/plonkish.rs::CustomizedGate`. The local executable
    path now evaluates row constraints through the ported monomial evaluator,
    following `third_party/hyperplonk/hyperplonk/src/utils.rs::eval_f`.
    Tests check the vanilla gate degree, selector/witness counts, monomial
    count, and equality with direct Plonk row evaluation.
  - `third_party/hyperplonk/hyperplonk/src/utils.rs::eval_perm_gate` product
    factors `w + beta * id + gamma` and `w + beta * perm + gamma` have been
    ported to `crates/pq-piop-plonkish/src/lib.rs` as
    `hyperplonk_permutation_products`. The current accumulator proof uses this
    product-factor helper for numerator and denominator transitions. A
    `cfg(test)` conformance helper mirrors the full `eval_perm_gate` formula
    and checks a constructed zero subclaim.
- Not ported yet:
  - Lookup arguments and complex custom gates are out of scope for the current
    prototype.
  - The current accumulator proof does not yet replace the whole HyperPlonk
    permutation-check protocol; it ports and uses the product-factor/evaluator
    algebra while retaining the local committed running-product accumulator.
  - HyperPlonk KZG PCS code is reference-only and is not used as the final
    post-quantum PCS.

## Next Porting Milestone

- Extend this source-level mapping to the Spartan2 sumcheck round-polynomial
  routines and HyperPlonk product/permutation subroutines.
- Replace any local helper whose behavior should exactly match upstream with a
  directly ported implementation plus differential tests.
- Keep `pq-pcs` independent from KZG/IPA/Ristretto commitments; only transparent
  hash/Merkle and distributed Brakedown-style code may be on the final path.

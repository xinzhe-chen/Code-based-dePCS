# Implementation Scope

This project implements a correctness-focused transparent, post-quantum
distributed SNARK stack with explicit protocol composition, transcript binding,
distributed execution, and benchmark evidence.

## Shared Structure

- The field backend is a small Goldilocks-field implementation.
- Commitments are transparent SHA-256/Merkle commitments.
- R1CS and Plonkish routes both pass through Fiat-Shamir, equality-weighted
  zerocheck, and the distributed PCS module.
- Benchmark rows are positive end-to-end prove-and-verify jobs. Negative and
  tampered cases are covered by tests and explicit proof-experiment commands,
  keeping performance rows focused on measured proving and verification paths.

## PCS Implementation

The PCS crate follows the Brakedown/BaseFold protocol shape with explicit,
auditable checks for encoding, composition, distributed opening, and sampled
fold consistency.

Current PCS checks include systematic, adjacent-parity, stride-parity, and
blend-parity encoding checks; combined-codeword composition checks; and MLE
folding evaluation proofs for the row-weighted combined column and composed
codeword. Distributed openings also carry Fiat-Shamir sampled folding and
consistency openings against Merkle commitments.

The default local PCS opening uses the compact distributed-opening path for
the final R1CS PCS claims and the Plonkish constraint-residual claim. Hook-based
and compatibility tests can still exercise the original full-opening path.
Network R1CS and Plonkish runners use the compact worker-provider path for
their final PCS openings.

## R1CS Implementation

The R1CS route avoids carrying the full witness in the proof. It uses:

- a Spartan-style outer cubic sumcheck over the R1CS residual;
- distributed PCS openings for the final `Az`, `Bz`, and `Cz` claims;
- an inner product sumcheck for a random linear combination of public matrix
  projections against the committed witness MLE;
- witness and linearization commitments;
- transcript-sampled row-consistency openings;
- transcript-bound distributed sparse-matrix fingerprints;
- Spark-style per-matrix sparse evaluation claims for `A`, `B`, and `C`.

The Spark-style matrix checks include row, column, and value
memory-consistency reductions with per-worker product digests, Merkle
commitments, and Fiat-Shamir sampled openings. The current verifier uses small
public sparse traces to keep these matrix checks directly auditable at the
experiment sizes exercised by the repository.

## Plonkish Implementation

The Plonkish route uses committed `A`, `B`, `C`, selector, gate-residual, and
permutation-residual oracle columns. Gate evaluation is bound through a
Fiat-Shamir random-point virtual subclaim and sampled MLE folding openings
rather than full gate-column vectors.

The permutation route includes a Fiat-Shamir `beta/gamma` running-product
accumulator committed by Merkle PCS. It precommits shifted `next` traces and
transition-residual commitments before deriving the random point, binds column
evaluations with sampled MLE folding openings, and uses numerator and
denominator cubic zerocheck sumchecks for the recurrence relation.

Accumulator boundary openings are verified with Merkle paths and absorbed
before downstream accumulator challenges. Gate, copy, and accumulator index
consistency openings are transcript sampled, keeping the permutation path
compact while preserving explicit verifier checks.

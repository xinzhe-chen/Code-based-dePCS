# PCS Batch Backend Soundness Notes

## Implemented Encoded BaseFold Batch Path

The active BaseFold backend is batch-only and commits to an encoded RS codeword
with rate inverse 4. A distributed opening no longer carries one full folding
proof per worker. The prover first sums the worker-local evaluation vectors
into one combined vector, commits to the combined raw vector and its rate-1/4
RS codeword, and proves one encoded folding opening for the combined
commitment.

Completeness follows from linearity of multilinear evaluation: the combined
vector evaluates to the sum of worker-local evaluations at the same point.  The
verifier checks the combined encoded BaseFold opening, then checks level-0
RS-codeword consistency against every original worker commitment at every leaf
sampled by the combined folding proof. Both siblings used by each first-round
fold query are checked; the implementation does not use the simplified
beta-prime consistency shortcut seen in the vendored LigeSIS artifact.

Soundness relies on the distance of the rate-1/4 encoded codeword plus the
sampling argument of the folding check for the combined vector. The consistency
check binds sampled combined codeword leaves to the original worker codeword
roots. The transcript binds the backend kind, rate inverse, security bits,
batch label, all original commitments, the opening point, and the combined
commitment before BaseFold fold-query challenges are sampled.

## Implemented DeepFold Rate 1/4 Batch Path

`PcsBackendKind::DeepFold` is a separate batch proof variant with rate inverse
4. The backend uses the local `pq_pcs::deepfold` RS-domain/FFT core.  The
prover converts Boolean-hypercube evaluations to coefficient form, evaluates
the polynomial over a Goldilocks RS domain of length `4 * base_len`, commits to
the RS codeword with the repository Merkle tree, and proves a DeepFold folding
argument with linear-polynomial consistency checks and beta/conjugate Merkle
queries.

The verifier checks:

- batch claim transcript binding,
- Protocol 10 sumcheck reduction from the requested claims to the final
  combined claim,
- DeepFold linear-polynomial folding consistency,
- final folded RS value consistency,
- Fiat-Shamir beta query recomputation,
- Merkle authentication for every beta and conjugate opening at every folded
  layer, and
- level-0 RS-codeword consistency against every worker's DeepFold commitment
  for all sampled beta/conjugate positions.

The backend query policy is rate-derived:

- BaseFold rate inverse 4 uses `ceil(security_bits / log2(4))`, so the default
  query count is 64 for a 128-bit query budget.
- DeepFold rate inverse 4 uses `ceil(security_bits / log2(4))`, so the default
  query count is 64 for a 128-bit query budget.
- Protocol 11 column checks use the outer Brakedown rate inverse 4 policy.

The implementation currently samples Fiat-Shamir algebraic challenges in the
Goldilocks base field. The CSV metadata therefore separates
`query_security_bits = 128` from `algebraic_security_bits = 64`; it does not
claim 128-bit algebraic security from one Goldilocks challenge field element.

The proof declares its query count, but the verifier recomputes the expected
count from the backend config and base length, caps it by the RS codeword
length, and rejects mismatches. Beta queries are sampled in one
transcript-derived batch without replacement when the query count does not
exceed the codeword length. Proof-carried beta indices are checked against the
replayed transcript output and are not trusted.

The current negative tests cover tampered DeepFold value/fold state, beta
challenge, opening point, original commitment root, RS codeword root, backend
tag, Merkle path, rate inverse, and proof-declared query count metadata.

## Backend-Aware Commitment And Advice Shape

Protocol 10/11 evaluation commitments and distributed opening commitments now
use `PcCommitment::{BaseFold, DeepFold}` and
`PcCommitmentAdvice::{BaseFold, DeepFold}` instead of exposing only the raw
Merkle `Commitment` and `BaseFoldCommitmentAdvice` in the protocol proof
shape. The verifier checks that every enum variant matches the selected
backend, and the transcript absorbs the backend tag plus backend-specific
commitment metadata before sampling challenges.

Both backends carry backend-aware commitments. BaseFold carries the original
raw-vector Merkle commitment plus a rate-1/4 RS codeword commitment; DeepFold
carries the original raw-vector Merkle commitment plus a rate-1/4 RS codeword
commitment. Distributed batch consistency uses the backend RS codeword
commitment for both BaseFold and DeepFold. The raw-vector commitment remains a
separate component for Protocol 11 column proof compatibility.

## DeepFold Core Port Status

The local `pq_pcs::deepfold` module now defines an Arkworks-compatible
Goldilocks field type and canonical bridge helpers between `FieldElement` and
`FGoldilocks`. The bridge is tested for canonical roundtrip and arithmetic
agreement.

The same module implements the local audited subset of the DeepFold core:
RS-domain FFT commitment, DeepFold opening, verifier-side folding checks,
Fiat-Shamir alpha/r/beta replay, final value check, and Merkle verification for
sampled beta/conjugate positions.  The implementation does not import the
vendored LigeSIS crate, network layer, or verifier shortcuts.

## Protocol 10/11 Batch Shape

Protocol 11 carries a single `Protocol10EncodingBatchProof` rather than two
top-level `encoding_e1` and `encoding_e2` proofs. The batch proof binds the
relation count, relation order, commitments, and transcript-derived
`rho_j` challenges before verifying each relation's opening batch.

The e1/e2 encoding relation now uses one degree-2 multi-product sumcheck for

```text
sum_j rho_j * E_j(X) * H_j(X) = 0.
```

The prover samples one common sumcheck point `r` for the product relation and,
inside each Protocol 10 relation, proves a single `Protocol10OpeningBatchProof`
for the four logical opening claims:

- `H_u(r)`,
- `E(r)`,
- `F_pad(u', 0, 0)`, and
- `E(u', 0, 0)`.

`F_pad(X, a, b) = F(X) * eq_00(a, b)` lifts the message-domain `F` vector into
the encoded Protocol 10 domain, so the four claims have the same arity. The
opening batch absorbs every claim label, relation index, claim kind,
commitment list, point, claimed value, backend tag, rate inverse, and security
metadata before sampling its random weights.

Different-point claims are not combined by a bare random linear combination.
The batch reduction proves

```text
sum_x sum_i gamma_i * f_i(x) * eq_{z_i}(x) = sum_i gamma_i * y_i
```

with one degree-2 eq-product sumcheck. Its verifier-side random point `zeta`
defines weights `gamma_i * eq_{z_i}(zeta)`. The prover then opens exactly one
weighted combined polynomial at `zeta` through `WeightedSourceBatchOpening`.
That opening carries sampled level-0 consistency for every original source
commitment, including the local `H_u` source and all worker `E`/`F_pad`
sources. The verifier recomputes the weights, verifies the single backend PCS
opening, checks the combined opening value equals the reduction final
evaluation, and checks the sampled source leaves recombine to the combined
leaf values.

The verifier also checks `sum_j rho_j * E_j(r) * H_j(r)` against the outer
multi-product sumcheck final claim and checks `F_pad(u',0,0) == E(u',0,0)` for
each relation. The legacy CSV proof-size columns remain as logical splits for
compatibility; `protocol10_*_opening_batch_*` fields carry the real single
opening-batch timing and byte counts.

## Experiment Contract

`depcs-basefold-batch` rows are valid benchmark rows only when
`verified = true`.  `depcs-deepfold-batch` rows are valid benchmark rows only
when the DeepFold verifier succeeds. Legacy `depcs-deepfold-rho1over2-batch`
or `deepfold:2` artifacts are old rate-1/2 runs and should not be mixed with
the default rate-1/4 series. The comparison script treats a DeepFold backend
failure as a failed experiment rather than silently continuing with a missing
DeepFold row.

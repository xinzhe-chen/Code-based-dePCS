# Protocol compliance matrix

| Paper component | Protocol 11 implementation | Status |
| --- | --- | --- |
| Protocol 6 commit | row encoding, column hashes, Merkle commitment | implemented |
| Protocol 6 eval | `a`, four polynomials, column openings, `y1/y2`, `F2(s2)` | implemented |
| Protocol 7 | separate per-worker `E1/E2` Merkle roots and openings | implemented |
| Protocol 8 | separate per-worker `E1/E2` PC commitments and proofs | implemented |
| Protocol 9 | separate per-worker `F1/F2` PC commitments and proofs | implemented |
| Protocol 10 | real `H_u`, sumcheck rounds, openings, systematic check | implemented |
| Protocol 11 | statement-bound transcript order and individual checks | implemented |
| Interactive protocol | typed prover/verifier ordered session | implemented |
| Fiat-Shamir | same session order, challenges after prior messages | implemented |
| Brakedown algorithm | recursive `x,z,v` Algorithm 1 structure | implemented |
| Brakedown finite parameters | paper Equations (7)--(8), per-level certified degrees | implemented |
| Concrete `H_u` PCS | DeepFold, matching the revised protocol specification | implemented |
| Classical security profile | exact ledger, `Ft255`, unique-decoding DeepFold | implemented |
| Zero knowledge | not supplied by the PCS construction | non-goal |
| DeepFold redistribution | upstream license unavailable | release blocker |

The public artifact marker is `fidelity=protocol11-deepfold`, with
`security_model=classical-rom`, `soundness_regime=deepfold-unique-decoding`,
and `field=Ft255`.
Unmeasured timings are `-1`; a zero is reserved for an operation that is
actually absent and is never presented as measured work.

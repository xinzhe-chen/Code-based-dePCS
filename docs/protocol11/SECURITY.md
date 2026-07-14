# protocol11 security statement

The `Paper100` claim is at least 100 bits of classical soundness in the
classical random-oracle model, under the binding/evaluation soundness of
DeepFold in its unique-decoding regime and the collision resistance of
SHA-256/BLAKE3.

The implementation does **not** claim zero knowledge, hiding, post-quantum
100-bit security, or audited production security. The missing upstream
DeepFold license remains a redistribution blocker.

The budget is computed with arbitrary-precision rational arithmetic. It sums:

- the Brakedown setup bound `2^-110` after deriving every finite matrix degree
  from Equations (7)--(8);
- `(19/20)^q` for the distinct Brakedown column tests;
- `(7M+2)*(3/4)^s` for all actual DeepFold openings at rate `1/2` and
  unique-decoding distance `Delta=1/4`;
- finite-field terms for every transcript/DeepFold challenge and both
  degree-2 Protocol 10 sumchecks over `Ft255`;
- a conservative classical collision term for the bounded SHA-256/BLAKE3
  invocations.

Setup selects the smallest PCS and column query counts whose individual query
terms are at most `2^-110`, computes the full sum, and rejects the configuration
unless the resulting effective bits are at least 100. Both query sets are
sampled without replacement and must fit their smallest domains. `TestOnly`
is explicitly insecure and reports no effective security claim.

The list-decoding speedup from the DeepFold paper is deliberately not used by
`Paper100`, because its finite concrete bound depends on an RS list-size
conjecture with unspecified constants. A future explicitly named fast profile
may use that regime, but it must not inherit the `Paper100` claim.

The verifier receives `(public parameters, commitment, point, claimed value,
proof)` independently. A point or value embedded in untrusted proof bytes is
never treated as the statement to be verified.

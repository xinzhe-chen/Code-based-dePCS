# PCS Theory Audit

This audit is scoped to the distributed Brakedown PCS path used by the new
`pq-experiments pcs-benchmark` workflow. It is not a proof that the repository
implements every optimization in the paper; it separates measured prototype
behavior from the PCS target in `Doc/pq_dSNARK.pdf`.

## Scope

- Paper: `Doc/pq_dSNARK.pdf` pages 22-31, covering Section 4, Protocols 8-11,
  and the distributed Brakedown complexity discussion.
- Current implementation: `pq-pcs` distributed commit/open/verify, compact
  opening, encoding check, byte accounting, and network worker integration.
- Reference implementation: `C:\Projects\deSpartan2` files
  `crates/deSpartan2/src/provider/pcs/di_brakedown.rs`,
  `distributed_encoding.rs`, `provider/pcs/brakedown.rs`,
  `linear_code/brakedown.rs`, and the distributed Brakedown example scripts.

## Matches

- Distributed commit shape: `pq-pcs` keeps the Protocol 8/9 split between
  per-worker shard commitments and a master-level distributed commitment.
- Open/verify API shape: both full and compact opening variants are available
  for distributed openings, and the benchmark records open time, verify time,
  proof bytes, communication bytes, and network bytes separately.
- Fiat-Shamir transcript separation: the current PCS code absorbs the
  distributed commitment before deriving opening challenges, matching the
  paper's transcript-driven protocol flow at the PCS layer.
- Byte accounting: `pq-pcs` exposes commitment size, full proof size, compact
  proof size, and communication-byte helpers. The PCS verifier checks local rows
  have zero network bytes and network rows have positive network bytes.
- Benchmark grid: the PCS-only workflow measures `N`, `M`, `T=N/M`, and the
  paper target `B=M log(N/M)` for every runner/opening/trial row.

## Partial

- Protocol 10 encoding proof: `pq-pcs` has an encoding check path, but the
  current benchmark treats it as part of PCS correctness/prototype validation
  rather than a separately parameterized Protocol 10 sub-benchmark.
- Protocol 11 distributed Brakedown composition: the code exercises distributed
  commit/open/verify and compact openings, but it does not yet expose every
  paper-level subphase as a first-class benchmark column.
- Master aggregation timing: local mode splits partition, worker commit, and
  master aggregation timing. Network mode records end-to-end network commit
  timing and byte counts, but worker and master timing cannot be fully separated
  without adding server-side phase telemetry.
- Paper parameter `B`: the report records the target `B=M log(N/M)` but the
  current implementation does not force every internal code parameter to equal
  the paper's asymptotic tuning.
- deSpartan2 comparison: deSpartan2 has a more mature distributed Brakedown
  implementation and distributed encoding organization. The current repo uses
  it as a reference for module boundaries and expected protocol phases, not as
  a source-compatible implementation.

## Missing

- Dedicated Protocol 10 benchmark columns for encoding proof prover time,
  verifier time, and bytes.
- Server-side network phase telemetry for partition, per-worker commit, master
  aggregation, open construction, and worker response serialization.
- A full paper-quality complexity validator that asserts observed scaling
  against `O(N/M)` prover work and `O(M log^2(N/M))` proof/verifier targets.
- A direct artifact diff against deSpartan2 proof objects or transcript states.

## Intentionally Prototype

- The PCS benchmark is correctness-first: every row must verify, and verifier
  failure is surfaced as `failure_reason`. It is not presented as an optimized
  production benchmark.
- Compact and full openings are both measured because the repository exposes
  both paths. The compact path is the more report-relevant communication target,
  while full openings remain useful for regression checks.
- Network byte accounting is measured at the client/worker exchange boundary.
  It is sufficient for runner comparison, but it should not be treated as a
  full transport stack profile.

## Benchmark Contract

`pq-experiments pcs-benchmark` writes `results/pcs-bench-YYYYMMDD-HHMMSS/` with:

- `metadata.json`
- `result_manifest.json`
- `source.csv` and `source.json`
- `summary_stats.csv`
- `summary.txt`
- `overview.html`
- phase timing artifacts
- commit/open/verify/proof-byte/network-byte/scaling SVG and PGFPlots charts

`pq-experiments verify-pcs-results --dir <run>` validates the PCS artifact
schema, manifest hashes, non-negative timings, verified rows, local/network byte
rules, and compact/full proof-byte accounting.

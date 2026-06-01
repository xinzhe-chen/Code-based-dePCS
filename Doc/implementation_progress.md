# pq_dSNARK Implementation Progress

## 2026-05-31

- Created the implementation plan from `Doc/pq_dSNARK.pdf`.
- Started a Rust 2024 Cargo workspace with crates for core algebra, transcript,
  sumcheck, PCS, R1CS PIOP, Plonkish PIOP, network runtime, and experiments.
- Fixed first-version scope as a correctness prototype with TCP master/worker
  runtime and internal tests before end-to-end integration.
- Third-party reuse policy: pin/fork Spartan and HyperPlonk-family code before
  importing; never replace the post-quantum distributed PCS with KZG, IPA, or
  Ristretto commitments.

## Current Acceptance Target

- `cargo test --workspace` passes.
- R1CS and Plonkish example experiments produce valid proofs for honest inputs
  and verification failures for tampered inputs.
- Experiment output includes worker count, size, prove/verify timings, proof
  bytes, communication bytes, verification result, and failure reason when
  verification fails.

## 2026-05-31 Implementation Checkpoint

- Implemented module crates for `pq-core`, `pq-transcript`, `pq-sumcheck`,
  `pq-pcs`, `pq-piop-r1cs`, `pq-piop-plonkish`, `pq-net`, and
  `pq-experiments`.
- Integrated both R1CS and Plonkish routes with Fiat-Shamir transcript,
  sumcheck, and the `pq-pcs` distributed Brakedown correctness prototype.
- Added TCP loopback worker tests for the network runtime.
- Hardened verifier binding after review:
  - rational sumcheck and multiset equality verification now bind public
    statement vectors instead of accepting proof-internal vectors;
  - Merkle path verification binds path direction and depth to the opened
    index;
  - distributed PCS verification checks worker ranges before copying data.
- Verification commands run successfully:
  - `cargo test --workspace`
  - `cargo fmt --check`
  - `cargo clippy --workspace --all-targets -- -D warnings`
  - `cargo run -p pq-experiments -- r1cs --workers 1 --size 8 --format json --case both`
  - `cargo run -p pq-experiments -- plonkish --workers 2 --size 4 --format csv --case both`
  - `cargo run -p pq-experiments -- r1cs --workers 1 --size 16 --pcs-queries 3 --format json --case both`
  - `cargo run -p pq-experiments -- plonkish --workers 2 --size 16 --pcs-queries 3 --format csv --case both`
  - `cargo run -p pq-experiments -- net-demo --workers 2 --format json`
  - multi-process `worker`/`master --shutdown` TCP smoke on
    `127.0.0.1:19101,127.0.0.1:19102`
- Latest CLI smoke results:
  - R1CS positive verified `true`, negative verified `false`,
    `proof_bytes=11536`, `communication_bytes=3776`.
  - Plonkish positive verified `true`, negative verified `false`,
    `proof_bytes=13424`, `communication_bytes=7432`.
  - Custom PCS query parameter smoke:
    - R1CS `--size 16 --pcs-queries 3`: positive `true`, negative `false`,
      `proof_bytes=11517`, `communication_bytes=1885`.
  - Plonkish `--size 16 --pcs-queries 3`: positive `true`, negative
      `false`, `proof_bytes=26076`, `communication_bytes=4308`.
  - TCP `net-demo` and multi-process master/worker both returned `ok=true`;
    worker ports were closed after `master --shutdown`.
- Post-review hardening completed after subagent read-only audits:
  - `pq-core` now rejects oversized allocating MLE constructors through a
    fallible path, fixes the gate/permutation sample to use a true bijection,
    and prevents row-only satisfaction checks from silently accepting
    gate/permutation circuits.
  - `pq-sumcheck` now absorbs polynomial evaluations into the sumcheck
    transcript, binds multiset equality challenges to all public multiset
    values, and exposes a tamperable Fiat-Shamir zerocheck proof/verifier based
    on a random equality-polynomial weighted quadratic sumcheck.
  - `pq-pcs` now hashes worker id, range, encoded length, and worker Merkle root
    into the distributed commitment root and Fiat-Shamir transcript.
  - `pq-piop-r1cs` and `pq-piop-plonkish` now explicitly bind proof worker
    counts to PCS commitment shape; both routes check the PCS opening point and
    opened residual value against the zerocheck challenges/final evaluation.
  - `pq-net` now has Ping/Pong, stateful registration before rounds, lossless
    escaped payload round-trips, and a loopback worker startup path without the
    previous bind/drop/rebind port race.
  - `pq-experiments` now exposes `worker`, `master`, and `net-demo` network
    experiment entries; `scripts/run_experiments.sh` includes the loopback TCP
    smoke in its default Linux path.
- Distributed PCS query security is now explicit:
  - `DistributedPcsParams` carries requested query count, defaulting to `32`;
  - opening and verification absorb requested/effective query counts into the
    Fiat-Shamir transcript and reject mismatched proof parameters;
  - R1CS, Plonkish, and `pq-experiments` expose the same parameter through
    `--pcs-queries`, and experiment output records `pcs_queries`.
- Plonkish route moved closer to the PIOP/oracle structure:
  - proof now carries commitments to `A/B/C`, gate residual, and permutation
    residual oracle columns instead of relying on verifier-side full residual
    recomputation from witness values;
  - verifier absorbs circuit selectors and permutation map as public statement
    data, then checks exhaustive gate and copy-constraint openings against the
    committed columns and distributed residual PCS;
  - Plonkish negative experiments now tamper proof openings rather than changing
    private witness values inside the local sample instance.
- Plonkish permutation argument no longer has a zero-valued placeholder:
  - prover derives Fiat-Shamir `beta/gamma` after oracle commitments, builds
    numerator and denominator running-product traces for
    `value + beta * position + gamma`, and commits both traces with Merkle PCS;
  - verifier checks accumulator boundary openings (`Z_num(0)=Z_den(0)=1` and
    matching terminal products), then checks exhaustive recurrence openings
    against the committed witness cell oracle and public permutation map;
  - accumulator challenge and boundary tampering are covered by unit tests, and
    the CLI negative Plonkish case now tampers an accumulator recurrence
    opening.
- R1CS route moved closer to an oracle/PCS PIOP:
  - `R1csPiopProof` no longer carries the full witness vector.
  - prover commits to witness, `Az`, `Bz`, and `Cz` with Merkle PCS and commits
    to the residual vector with distributed Brakedown PCS before deriving the
    random equality point and zerocheck challenges.
  - verifier checks the equality-weighted residual zerocheck using the PCS
    opening at the final challenge and validates exhaustive row-consistency
    queries by opening witness coordinates, `Az/Bz/Cz`, and distributed
    residual indices.
  - `pq-pcs` now exposes detached distributed commitments plus verified
    distributed index openings for these row-consistency checks.
- Added Linux experiment entrypoint:
  - `bash scripts/run_experiments.sh`
  - `bash scripts/run_experiments.sh interactive`
  - `bash scripts/run_experiments.sh r1cs --workers 1 --size 8 --format json --case negative`
- Linux entrypoint status: script is checked in, but this Windows host cannot
  execute it because `bash` resolves to the WSL launcher and no Linux
  distribution is installed. The same Rust CLI path was validated directly with
  `cargo run` on Windows.
- Latest post-accumulator validation commands run successfully:
  - `cargo fmt --check`
  - `cargo test --workspace`
  - `cargo clippy --workspace --all-targets -- -D warnings`
  - `cargo run -p pq-experiments -- plonkish --workers 2 --size 16 --pcs-queries 3 --format csv --case both`
  - `cargo run -p pq-experiments -- r1cs --workers 2 --size 8 --pcs-queries 3 --format json --case both`
  - `cargo run -p pq-experiments -- net-demo --workers 2 --format json`
- Subagent audit follow-up hardening:
  - `pq-pcs` now validates the distributed commitment root in
    `verify_index`, requires canonical worker ids/ranges/codeword lengths, and
    separates public split APIs that absorb the commitment from explicit
    `after_commitment` internal APIs;
  - R1CS and Plonkish verifiers now reject oracle/PCS commitment lengths that
    do not match the canonical instance domains before deriving verifier
    challenges;
  - `pq-experiments` now emits structured `failure_reason` in JSON/CSV output
    and has parser/output-format unit tests.
- Latest smoke outputs include failure reasons:
  - R1CS `--workers 2 --size 8 --pcs-queries 3`: positive `true` with
    `failure_reason=null`, negative `false` with `failure_reason="Pcs"`.
  - Plonkish `--workers 2 --size 16 --pcs-queries 3`: positive `true`,
    negative `false` with `failure_reason=InvalidProof`.
- Network-backed PCS proof path added:
  - `pq-net` workers now execute structured `PcsCommit` and `PcsOpen` tasks
    over TCP instead of only echoing generic round payloads;
  - `pq-pcs` exposes a worker-provider opening path so R1CS and Plonkish PIOPs
    can use network-returned partition commitments and Merkle openings while
    preserving the same Fiat-Shamir transcript order;
  - `pq-experiments master --protocol <r1cs|plonkish>` runs positive/negative
    proof cases through those network PCS worker tasks and reports
    `network_bytes` in addition to proof `communication_bytes`;
  - `pq-experiments` now has a loopback unit test that runs both R1CS and
    Plonkish network proof paths with positive and negative records;
  - worker robustness test now covers malformed/half-open TCP connections so a
    bad probe does not kill the worker.
- Network-backed proof smoke results on Windows:
  - `master --protocol r1cs --size 8 --pcs-queries 3 --case both`: positive
    `true`, negative `false`, `network_bytes=2470`.
  - `master --protocol plonkish --size 8 --pcs-queries 3 --case both`:
    positive `true`, negative `false`, `network_bytes=4042`.
- Linux experiment entrypoint now includes:
  - `bash scripts/run_experiments.sh interactive`
  - `bash scripts/run_experiments.sh net-proof r1cs --size 8 --pcs-queries 3 --format json --case both`
  - `bash scripts/run_experiments.sh net-proof plonkish --size 8 --pcs-queries 3 --format csv --case both`
- Interactive experiment CLI added:
  - `cargo run -p pq-experiments -- interactive` prompts for runner
    (`local`, `net-proof`, or `net-demo`), output format, worker count,
    protocol, size, PCS query count, and positive/negative case selection;
  - `local` executes the same R1CS/Plonkish prover/verifier paths as the
    scripted CLI, `net-proof` starts loopback TCP workers and runs the network
    PCS proof path, and `net-demo` runs the TCP worker round-trip smoke;
  - parser tests cover default local R1CS settings and explicit network
    Plonkish selection.
- Benchmark runner added:
  - `cargo run -p pq-experiments -- benchmark` runs local R1CS and Plonkish
    positive/negative cases for a size grid and worker-count grid, treating
    `workers=1` as the non-distributed baseline;
  - each run writes `results/bench-<timestamp>/source.csv`,
    `source.json`, `summary.txt`, `prove_time_by_size.svg`,
    `verify_time_by_size.svg`, `proof_bytes_by_size.svg`, and
    `worker_scaling_max_size.svg`;
  - `summary.txt` records the theoretical expectation that ideal distributed
    proving speedup is bounded by worker count, then compares measured speedup
    and efficiency against the `workers=1` baseline and flags suspicious
    superlinear/slowdown cases.
- Benchmark script entrypoints added:
  - Linux: `bash scripts/run_benchmarks.sh --sizes 4,8,16 --workers 1,2,4 --pcs-queries 3 --out results`
  - Windows: `powershell -ExecutionPolicy Bypass -File .\scripts\run_benchmarks.ps1 -Sizes 4,8,16 -Workers 1,2,4 -PcsQueries 3 -OutDir results`
  - Windows experiment helper: `scripts/run_experiments.ps1 interactive`
  - interactive script paths check that `cargo` exists and run
    `cargo build -p pq-experiments` before launching the Rust target.
- Spartan2 source-level porting started:
  - ported the coefficient-bucketed sparse-matrix accelerator from
    `third_party/Spartan2/src/r1cs/sparse.rs::PrecomputedSparseMatrix` into
    `crates/pq-core/src/matrix.rs::PrecomputedSparseMatrix`;
  - `SparseMatrix::mul_vec` now executes through the precomputed bucket path
    (`+1`, `-1`, signed small `2..=7`, general coefficients), while
    `mul_vec_naive` remains for differential tests;
  - `pq-core` tests now check precomputed-vs-naive multiplication and Spartan2
    bucket classification counts.
- HyperPlonk source-level porting started:
  - ported the vanilla customized gate representation from
    `third_party/hyperplonk/hyperplonk/src/custom_gate.rs::CustomizedGates` to
    `crates/pq-core/src/plonkish.rs::CustomizedGate`;
  - `PlonkishRow::evaluate` and the Plonkish PIOP gate verifier now
    evaluate through this ported monomial evaluator, matching HyperPlonk
    `utils.rs::eval_f` semantics over selector and witness evaluations;
  - `pq-core` tests check vanilla gate degree, selector count, witness count,
    monomial count, and equality with direct Plonk row evaluation.
- HyperPlonk permutation/product algebra porting started:
  - ported the product-factor loops from HyperPlonk
    `third_party/hyperplonk/hyperplonk/src/utils.rs::eval_perm_gate` into
    `crates/pq-piop-plonkish`;
  - the current committed permutation accumulator now computes numerator and
    denominator transition factors through the ported
    `w + beta * id + gamma` / `w + beta * perm + gamma` helper;
  - tests cover both factor semantics and a `cfg(test)` conformance helper for
    a constructed zero subclaim under the full `eval_perm_gate` expression.
- Vendored third-party reference sources and recorded pins in
  `third_party/PINS.md`:
  - Spartan2 `0d4f1409e8f30536b8b25ed3f81bc446ed717e61`
  - HyperPlonk `2a3b55c97ad8a5d6627108a2e7def2aeccb7f3b9`
- Added `third_party/PORTING_NOTES.md` to record the current local mapping,
  excluded commitment backends, and the next source-level porting milestone.
- Strengthened `pq-pcs` from full worker message/codeword openings to a
  Brakedown-style query proof:
  - prover sends the row-weighted combined column vector;
  - verifier derives query indices from Fiat-Shamir;
  - each worker originally opened systematic, next-systematic, and parity
    codeword entries through Merkle paths;
  - verifier checks sampled encoding relations and combined-column consistency.
- Zerocheck soundness hardening:
  - replaced residual-sum and squared-residual sum checks in the executable
    R1CS and Plonkish paths with the shared `pq-sumcheck` equality-polynomial
    weighted quadratic zerocheck;
  - R1CS and Plonkish now commit to residual vectors directly for the
    distributed PCS zerocheck opening, and row/gate/permutation consistency
    queries bind residual indices back to their local oracle columns;
  - regression tests cover plain-sum cancellation, so vectors like `[1, -1]`
    cannot pass merely because their unweighted sum is zero.
- PIOP oracle-consistency hardening:
  - R1CS row-consistency openings now cover every constraint row instead of a
    capped Fiat-Shamir sample;
  - Plonkish gate openings, copy-constraint residual openings, and permutation
    accumulator recurrence openings now cover their full domains;
  - regression tests assert exact domain coverage for R1CS row queries and
    Plonkish gate/permutation/accumulator queries.
- Latest exhaustive-consistency validation:
  - `cargo fmt --check`
  - `cargo test --workspace`
  - `cargo clippy --workspace --all-targets -- -D warnings`
  - R1CS local CLI `--workers 2 --size 8 --pcs-queries 3 --case both`:
    positive `true`, negative `false`, `proof_bytes=9790`,
    `communication_bytes=2278`
  - Plonkish local CLI `--workers 2 --size 8 --pcs-queries 3 --case both`:
    positive `true`, negative `false`, `proof_bytes=44854`,
    `communication_bytes=3578`
  - hidden multi-process TCP proof path still passes for both protocols:
    R1CS `network_bytes=2470`, Plonkish `network_bytes=4042`; worker ports
    `19411`, `19412`, `19421`, and `19422` were checked closed after cleanup.
- Latest interactive validation:
  - `cargo test -p pq-experiments`
  - `cargo test --workspace`
  - `cargo clippy --workspace --all-targets -- -D warnings`
  - piped `interactive` local R1CS run: positive `true`, negative `false`,
    `proof_bytes=4052`, `communication_bytes=1152`
  - piped `interactive` loopback network Plonkish run: positive `true`,
    negative `false`, `network_bytes=3192`
  - piped `interactive` net-demo run returned `ok=true` for two loopback
    workers.
- Latest lightweight benchmark validation:
  - command:
    `powershell -ExecutionPolicy Bypass -File .\scripts\run_benchmarks.ps1 -Sizes 4,8 -Workers 1,2 -PcsQueries 2 -OutDir results`
  - output directory: `results/bench-1780169639`
  - generated files: `source.csv`, `source.json`, `summary.txt`,
    `prove_time_by_size.svg`, `verify_time_by_size.svg`,
    `proof_bytes_by_size.svg`, `worker_scaling_max_size.svg`
  - source data contains 16 rows: 2 protocols * 2 sizes * 2 worker counts *
    positive/negative cases; all 8 positive cases verified and all 8 negative
    cases were rejected.
  - measured scaling at size 8: R1CS `workers=2` speedup `1.144` and
    Plonkish `workers=2` speedup `1.290` versus the `workers=1`
    non-distributed baseline. These are sublinear, which is plausible for this
    correctness prototype because transcript work, exhaustive consistency
    openings, and verification remain largely serial. No suspicious
    superlinear result was observed, so this benchmark did not indicate an
    implementation error requiring correction.
- Proof-size metric hardening:
  - `pq-pcs` now exposes canonical byte accounting helpers for commitments,
    Merkle openings, distributed commitments, distributed openings, and
    distributed index openings;
  - R1CS and Plonkish `proof_size_bytes` now count commitments, vector length
    prefixes, zerocheck rounds, PCS openings, consistency openings, worker
    counts, and R1CS Spark / Plonkish accumulator proof fields;
  - tests assert representative accounting invariants, including PCS Merkle
    opening size, R1CS Spark multiset inclusion, and Plonkish accumulator
    recurrence-query inclusion.
- Latest proof-size accounting validation:
  - `cargo fmt --check`
  - `cargo test --workspace`
  - `cargo clippy --workspace --all-targets -- -D warnings`
  - R1CS local CLI `--workers 2 --size 8 --pcs-queries 3 --case both`:
    positive `true`, negative `false`, `proof_bytes=11398`,
    `communication_bytes=2550`
  - Plonkish local CLI `--workers 2 --size 8 --pcs-queries 3 --case both`:
    positive `true`, negative `false`, `proof_bytes=48214`,
    `communication_bytes=3850`
  - hidden multi-process TCP proof path still passes for both protocols:
    R1CS `network_bytes=2470`, Plonkish `network_bytes=4042`; worker ports
    `19511`, `19512`, `19521`, and `19522` were checked closed after cleanup.
- Latest zerocheck hardening validation:
  - `cargo fmt --check`
  - `cargo test --workspace`
  - `cargo clippy --workspace --all-targets -- -D warnings`
  - `cargo run -p pq-experiments -- r1cs --workers 2 --size 8 --pcs-queries 3 --format json --case both`
  - `cargo run -p pq-experiments -- plonkish --workers 2 --size 8 --pcs-queries 3 --format csv --case both`
  - `cargo run -p pq-experiments -- net-demo --workers 2 --format json`
  - hidden multi-process TCP workers plus
    `master --protocol r1cs --size 8 --pcs-queries 3 --case both`: positive
    `true`, negative `false`, `network_bytes=2470`
  - hidden multi-process TCP workers plus
    `master --protocol plonkish --size 8 --pcs-queries 3 --case both`:
    positive `true`, negative `false`, `network_bytes=4042`
  - worker ports `19311`, `19312`, `19321`, and `19322` were checked closed
    after shutdown/cleanup.
- Distributed PCS multi-relation hardening:
  - `encode_systematic` now emits a `4 * local_len` codeword containing the
    systematic message, adjacent parity `m[i] + m[i+1]`, stride parity
    `m[i] + m[i+local_len/2]`, and a blend parity equal to adjacent plus
    stride parity;
  - each PCS query now opens systematic, next-systematic, stride-systematic,
    adjacent-parity, stride-parity, and blend-parity leaves through Merkle
    paths;
  - the verifier checks all three parity equations and binds the
    row-weighted combined column at the queried, next, and stride positions;
  - `pq-net` worker PCS open messages and codecs were updated to carry the
    enlarged opening, and proof/communication byte accounting now includes all
    added Merkle paths.
- Benchmark size and figure update:
  - benchmark sizes can now be selected by direct `--sizes`, exponent lists
    `--nv-powers` / `--n-values`, or inclusive exponent ranges
    `--nv-range` / `--n-range`, where `nv=2^n`;
  - `scripts/run_benchmarks.sh` and `scripts/run_benchmarks.ps1` expose those
    entries while preserving the previous direct-size path;
  - source data now includes `nv_power`, and SVG generation was rewritten for
    paper-oriented vector output with clean axes, measured markers, legends,
    colorblind-safe colors, and an ideal-linear reference only on the worker
    scaling plot.
- Script readability and progress output update:
  - Windows and Linux experiment scripts now print explicit `[experiment]`
    stages for workspace selection, target build, local runs, network worker
    startup, and completion;
  - Windows and Linux benchmark scripts now print `[benchmark]` stages for
    workspace selection, target build, size-mode selection, run start, and
    completion;
  - the Rust benchmark runner prints per-job progress of the form
    `protocol / n / nv / workers / pcs_queries`, plus positive/negative
    verification counts for each completed job, while keeping source CSV/JSON
    generation in `results/bench-*` clean.
- Latest progress-enabled validation:
  - `cargo fmt --check`
  - `cargo test --workspace`
  - `cargo clippy --workspace --all-targets -- -D warnings`
  - `powershell -ExecutionPolicy Bypass -File .\scripts\run_experiments.ps1 r1cs --workers 2 --size 4 --pcs-queries 2 --format json --case both`
  - `powershell -ExecutionPolicy Bypass -File .\scripts\run_benchmarks.ps1 -NvRange "2..3" -Workers "1,2" -PcsQueries 2 -OutDir results`
  - latest output directory: `results/bench-1780170559`;
  - generated files: `source.csv`, `source.json`, `summary.txt`,
    `prove_time_by_size.svg`, `verify_time_by_size.svg`,
    `proof_bytes_by_size.svg`, and `worker_scaling_max_size.svg`;
  - source data contains `nv_power` and `size` columns, with 16 rows covering
    2 protocols * 2 exponent values * 2 worker counts * positive/negative
    cases; all 8 positive cases verified and all 8 negative cases were
    rejected;
  - measured scaling at `n=3` / `nv=8`: R1CS `workers=2` speedup `1.182`
    with efficiency `0.591`, and Plonkish `workers=2` speedup `1.419` with
    efficiency `0.710`; both are below the ideal linear upper bound and marked
    `plausible-prototype-overhead`, consistent with serial transcript,
    exhaustive consistency, and verification work in this correctness
    prototype.
- R1CS Spartan/Spark hardening:
  - added `pq-sumcheck` degree-3 zerocheck support for the Spartan outer
    relation `sum_x eq_tau(x) * (A(x)B(x)-C(x)) = 0`, including cubic round
    polynomials, Fiat-Shamir challenges, final-claim verification, and tamper
    tests;
  - `pq-piop-r1cs` now commits `Az`, `Bz`, and `Cz` through distributed PCS in
    addition to the Merkle row-consistency oracles, runs the outer cubic
    sumcheck, opens `Az/Bz/Cz` at the sumcheck final point, and checks the
    final claim against the opened PCS values;
  - replaced the earlier proof-carried public row/column Spark multisets with
    transcript-bound distributed sparse-entry fingerprints over worker row
    partitions, including per-worker linear/product fingerprints and total
    entry count;
  - added R1CS tests for outer sumcheck round tampering, final opening point
    tampering, final opened value tampering, Spark fingerprint tampering,
    partition/challenge binding, and updated proof-size accounting.
- Latest R1CS outer-sumcheck validation:
  - `cargo fmt --check`
  - `cargo test --workspace`
  - `cargo clippy --workspace --all-targets -- -D warnings`
  - `cargo run -p pq-experiments -- r1cs --workers 2 --size 4 --pcs-queries 2 --format json --case both`
  - `cargo run -p pq-experiments -- plonkish --workers 2 --size 4 --pcs-queries 2 --format csv --case both`
  - `cargo test -p pq-experiments loopback_network_proof_paths_produce_positive_and_negative_records`
  - `powershell -ExecutionPolicy Bypass -File .\scripts\run_benchmarks.ps1 -NvRange "2..3" -Workers "1,2" -PcsQueries 2 -OutDir results`
  - latest output directory: `results/bench-1780171366`;
  - source data contains 16 rows, all 8 positive cases verified, and all 8
    negative cases were rejected;
  - R1CS `workers=2`, `n=2` smoke after outer sumcheck: positive verified
    `true`, negative verified `false`, `proof_bytes=17216`,
    positive `communication_bytes=12960`;
  - measured scaling at `n=3` / `nv=8`: R1CS `workers=2` speedup `1.098`
    with efficiency `0.549`, and Plonkish `workers=2` speedup `1.350` with
    efficiency `0.675`; these remain below the ideal linear upper bound and
    match the expected overhead of the added outer PCS openings plus serial
    transcript and exhaustive consistency checks.
- PCS folding proof hardening:
  - `pq-pcs::DistributedOpening` now carries an `MleFoldingProof` for the
    row-weighted `combined_column`;
  - the prover commits to the combined input vector and every deterministic
    MLE fold layer, records each fold challenge and layer commitment, and
    carries the final folded scalar;
  - the verifier checks every fold relation from `combined_column` to the final
    scalar and checks that the folding final value equals the claimed PCS
    evaluation before verifying worker query consistency;
  - folding proof commitments are absorbed into the Fiat-Shamir transcript
    before deriving distributed PCS query indices, so the query schedule is
    bound to the folding evaluation proof;
  - tests cover honest folding, layer-value tampering, layer-commitment
    tampering, challenge tampering, and distributed opening final-value
    tampering.
- Latest PCS folding validation:
  - `cargo fmt --check`
  - `cargo test --workspace`
  - `cargo clippy --workspace --all-targets -- -D warnings`
  - `cargo run -p pq-experiments -- r1cs --workers 2 --size 4 --pcs-queries 2 --format json --case both`
  - `cargo run -p pq-experiments -- plonkish --workers 2 --size 4 --pcs-queries 2 --format csv --case both`
  - `powershell -ExecutionPolicy Bypass -File .\scripts\run_benchmarks.ps1 -NvRange "2..3" -Workers "1,2" -PcsQueries 2 -OutDir results`
  - latest output directory: `results/bench-1780171632`;
  - source data contains 16 rows, all 8 positive cases verified, and all 8
    negative cases were rejected;
  - R1CS `workers=2`, `n=2` smoke after PCS folding: positive verified
    `true`, negative verified `false`, `proof_bytes=17696`,
    positive `communication_bytes=13440`;
  - Plonkish `workers=2`, `n=2` smoke after PCS folding: positive verified
    `true`, negative verified `false`, `proof_bytes=24200`,
    `communication_bytes=5168`;
  - measured scaling at `n=3` / `nv=8`: R1CS `workers=2` speedup `1.131`
    with efficiency `0.565`, and Plonkish `workers=2` speedup `1.331` with
    efficiency `0.666`; both remain below the ideal distributed upper bound,
    consistent with the added full folding layers plus existing serial
    transcript and exhaustive consistency work.
- Plonkish random-point gate subclaim and figure-quality chart update:
  - `pq-piop-plonkish` now commits the five vanilla Plonk selector columns
    `q_l/q_r/q_o/q_m/q_c` alongside `A/B/C`, gate residual, and permutation
    residual columns;
  - after absorbing oracle commitments, the prover samples a Fiat-Shamir
    random row-domain point and carries MLE folding proofs for `A/B/C`,
    selector columns, and the gate-residual column at that point;
  - the verifier recomputes the HyperPlonk-style virtual gate evaluation
    `q_l(r)A(r)+q_r(r)B(r)+q_o(r)C(r)+q_m(r)A(r)B(r)+q_c(r)` from those folded
    oracle evaluations and checks it against the proof-carried virtual gate
    value. It does not incorrectly require this virtual polynomial to vanish
    at the random field point; Boolean-row correctness remains enforced by the
    residual zerocheck and exhaustive consistency path in this prototype;
  - selector commitments and the gate subclaim proof are absorbed into the
    transcript before the permutation accumulator challenge and are included in
    `proof_size_bytes`;
  - tests now reject tampering with gate subclaim values, folding final values,
    the virtual gate value, and selector commitments;
  - benchmark SVG generation now uses fixed protocol colors, worker-specific
    line dashes and marker shapes, legend boxes, clean vector axes, and the
    ideal-linear reference only on the worker-scaling figure.
- Latest Plonkish/chart validation:
  - `cargo fmt --check`
  - `cargo test -p pq-piop-plonkish`
  - `cargo test -p pq-experiments`
  - `cargo test --workspace`
  - `cargo clippy --workspace --all-targets -- -D warnings`
  - `cargo run -p pq-experiments -- r1cs --workers 2 --size 4 --pcs-queries 2 --format json --case both`
  - `cargo run -p pq-experiments -- plonkish --workers 2 --size 4 --pcs-queries 2 --format csv --case both`
  - `powershell -ExecutionPolicy Bypass -File .\scripts\run_benchmarks.ps1 -NvRange "2..3" -Workers "1,2" -PcsQueries 2 -OutDir results`
  - latest output directory: `results/bench-1780172387`;
  - generated files: `source.csv`, `source.json`, `summary.txt`,
    `prove_time_by_size.svg`, `verify_time_by_size.svg`,
    `proof_bytes_by_size.svg`, and `worker_scaling_max_size.svg`;
  - source data contains 16 rows, all 8 positive cases verified, and all 8
    negative cases were rejected;
  - R1CS `workers=2`, `n=2` smoke: positive verified `true`, negative verified
    `false`, `proof_bytes=17696`, positive `communication_bytes=13440`;
  - Plonkish `workers=2`, `n=2` smoke after selector/gate-subclaim update:
    positive verified `true`, negative verified `false`,
    `proof_bytes=26520`, positive `communication_bytes=5168`;
  - measured scaling at `n=3` / `nv=8`: R1CS `workers=2` speedup `1.067`
    with efficiency `0.533`, and Plonkish `workers=2` speedup `1.179` with
    efficiency `0.590`; both are below the ideal linear upper bound and marked
    `plausible-prototype-overhead`, so this lightweight run does not show a
    suspicious superlinear artifact.
- R1CS Spartan inner linearization hardening:
  - added `pq-sumcheck::ProductSumcheckProof`, a quadratic product-sumcheck
    for claims of the form `sum_x L(x)R(x)=c`, with verifier-side round checks
    that defer the final opening check to the caller;
  - `pq-piop-r1cs` now derives Fiat-Shamir challenges for a random linear
    combination of `A/B/C`, projects the public sparse matrices at the outer
    row point, and proves that this projected matrix MLE has the claimed inner
    product with the committed witness MLE;
  - the witness is additionally committed through the distributed PCS for this
    inner path, and the prover opens the witness MLE at the product-sumcheck
    final point. The verifier checks the distributed PCS opening and verifies
    that `projected_matrix(r) * witness(r)` matches the product-sumcheck final
    value;
  - this is the core Spartan inner/eval-W consistency shape for the current
    correctness prototype. It is not yet a full production Spark memory-check
    implementation.
- Latest R1CS inner validation:
  - `cargo test -p pq-sumcheck -p pq-piop-r1cs`
  - `cargo test --workspace`
  - `cargo clippy --workspace --all-targets -- -D warnings`
  - `cargo run -p pq-experiments -- r1cs --workers 2 --size 4 --pcs-queries 2 --format json --case both`
  - `cargo run -p pq-experiments -- plonkish --workers 2 --size 4 --pcs-queries 2 --format csv --case both`
  - `cargo test -p pq-experiments loopback_network_proof_paths_produce_positive_and_negative_records`
  - `powershell -ExecutionPolicy Bypass -File .\scripts\run_benchmarks.ps1 -NvRange "2..3" -Workers "1,2" -PcsQueries 2 -OutDir results`
  - latest output directory: `results/bench-1780172820`;
  - source data contains 16 rows, all 8 positive cases verified, and all 8
    negative cases were rejected;
  - R1CS `workers=2`, `n=2` smoke after inner product-sumcheck: positive
    verified `true`, negative verified `false`, `proof_bytes=22208`, positive
    `communication_bytes=17688`;
  - measured scaling at `n=3` / `nv=8`: R1CS `workers=2` speedup `0.988`
    with efficiency `0.494`, and Plonkish `workers=2` speedup `1.265` with
    efficiency `0.633`; the R1CS slowdown is expected for this lightweight run
    because the new inner witness PCS opening and product-sumcheck add
    fixed-cost correctness work at small sizes. No suspicious superlinear
    behavior was observed.
- Plonkish permutation accumulator random recurrence subclaim:
  - added a Fiat-Shamir random-point subclaim after accumulator boundary
    openings and before deriving exhaustive recurrence query indices;
  - the proof carries folded columns for flattened witness values, public
    source ids, public permutation target ids, numerator/denominator current
    traces, and shifted next traces;
  - the verifier reconstructs public id columns, binds flattened values back to
    the committed `A/B/C` oracle columns, binds current traces to the committed
    numerator/denominator accumulators, checks shifted-next consistency, and
    folds the pointwise numerator/denominator recurrence residual vectors to
    zero;
  - the recurrence residual is explicitly restricted to the real cell domain
    `0..permutation_check_count`; terminal accumulator values and padding are
    not incorrectly treated as recurrence rows;
  - tests reject tampering with shifted next values, residual folding final
    values, flattened witness values, and the random subclaim point. Proof-size
    accounting now includes the accumulator subclaim columns and folding
    proofs.
- Latest Plonkish accumulator subclaim validation:
  - `cargo test -p pq-piop-plonkish`
  - `cargo test --workspace`
  - `cargo clippy --workspace --all-targets -- -D warnings`
  - `cargo run -p pq-experiments -- r1cs --workers 2 --size 4 --pcs-queries 2 --format json --case both`
  - `cargo run -p pq-experiments -- plonkish --workers 2 --size 4 --pcs-queries 2 --format csv --case both`
  - `cargo test -p pq-experiments loopback_network_proof_paths_produce_positive_and_negative_records`
  - `powershell -ExecutionPolicy Bypass -File .\scripts\run_benchmarks.ps1 -NvRange "2..3" -Workers "1,2" -PcsQueries 2 -OutDir results`
  - latest output directory: `results/bench-1780173229`;
  - source data contains 16 rows, all 8 positive cases verified, and all 8
    negative cases were rejected;
  - Plonkish `workers=2`, `n=2` smoke after accumulator subclaim: positive
    verified `true`, negative verified `false`, `proof_bytes=31112`, positive
    `communication_bytes=5168`;
  - measured scaling at `n=3` / `nv=8`: R1CS `workers=2` speedup `1.045`
    with efficiency `0.522`, and Plonkish `workers=2` speedup `1.191` with
    efficiency `0.596`; Plonkish proof bytes rose to `62132` at workers=2,
    n=3 because the new random recurrence subclaim carries folded accumulator
    columns and residual folding proofs. The scaling remains below the ideal
    linear upper bound and was marked `plausible-prototype-overhead`.
- PCS combined-codeword composition hardening:
  - `pq-pcs::DistributedOpening` now carries `combined_codeword`, the
    systematic/adjacent-parity/stride-parity/blend-parity encoding of the
    row-weighted `combined_column`;
  - the verifier checks the full `combined_codeword == encode_systematic(
    combined_column )` relation, derives a Fiat-Shamir composition folding
    point, verifies an MLE folding proof for the combined codeword, and then
    checks every sampled worker codeword opening linearly combines to the
    corresponding combined-codeword positions;
  - sampled PCS checks now bind not only systematic, next, and stride message
    positions, but also the adjacent-parity, stride-parity, and blend-parity
    positions of the composed codeword;
  - tests reject tampering with `combined_codeword`, composition folding final
    values, worker parity leaves, query indices, combined columns, and folding
    layers. This remains a transparent correctness prototype, but is closer to
    Brakedown proof composition than only checking local worker parity leaves.
- Latest PCS composition validation:
  - `cargo test -p pq-pcs`
  - `cargo test --workspace`
  - `cargo clippy --workspace --all-targets -- -D warnings`
  - `cargo run -p pq-experiments -- r1cs --workers 2 --size 4 --pcs-queries 2 --format json --case both`
  - `cargo run -p pq-experiments -- plonkish --workers 2 --size 4 --pcs-queries 2 --format csv --case both`
  - `cargo test -p pq-experiments loopback_network_proof_paths_produce_positive_and_negative_records`
  - `powershell -ExecutionPolicy Bypass -File .\scripts\run_benchmarks.ps1 -NvRange "2..3" -Workers "1,2" -PcsQueries 2 -OutDir results`
  - latest output directory: `results/bench-1780173481`;
  - source data contains 16 rows, all 8 positive cases verified, and all 8
    negative cases were rejected;
  - R1CS `workers=2`, `n=2` smoke after PCS composition: positive verified
    `true`, negative verified `false`, `proof_bytes=24152`, positive
    `communication_bytes=19632`;
  - Plonkish `workers=2`, `n=2` smoke after PCS composition: positive verified
    `true`, negative verified `false`, `proof_bytes=31960`, positive
    `communication_bytes=6016`;
  - measured scaling at `n=3` / `nv=8`: R1CS `workers=2` speedup `1.348`
    with efficiency `0.674`, and Plonkish `workers=2` speedup `1.213` with
    efficiency `0.606`; both remain below the ideal distributed upper bound
    and were marked `plausible-prototype-overhead`. The increased proof bytes
    and verification time are expected because every distributed opening now
    carries and verifies the composed codeword layer.
- Windows experiment entrypoint and publication-figure export audit:
  - `scripts/run_experiments.ps1` now mirrors the Linux experiment entrypoint;
    with no arguments it runs `cargo test --workspace`, builds
    `pq-experiments`, runs local R1CS and Plonkish positive/negative proof
    smokes, runs the TCP `net-demo`, and then runs network-backed R1CS and
    Plonkish proof smokes through hidden loopback worker processes;
  - added `scripts/run_experiments.ps1 net-proof <r1cs|plonkish> ...`; the
    wrapper chooses free local TCP ports, forwards `--size`, `--pcs-queries`,
    `--format`, and `--case` to the master command, appends `--shutdown`, and
    force-cleans workers in a `finally` block if any remain;
  - benchmark chart generation now writes PGFPlots/TikZ `.tex` figures next
    to each SVG: `prove_time_by_size.tex`, `verify_time_by_size.tex`,
    `proof_bytes_by_size.tex`, and `worker_scaling_max_size.tex`; each file
    references `source.csv/source.json`, uses fixed protocol colors, line and
    marker encodings, PGFPlots grid/legend styling, and can be included in a
    LaTeX paper with `\usepackage{pgfplots}` and
    `\pgfplotsset{compat=1.18}`;
  - `scripts/run_benchmarks.ps1` now checks native process exit codes after
    `cargo build` and after the Rust benchmark runner, so script failures are
    surfaced instead of being masked by PowerShell's default native-command
    behavior;
  - fixed a Windows wrapper bug found during validation where positional array
    forwarding caused `net-proof` to fall back to default `size=8` and
    `pcs_queries=32`; reruns confirmed `--size 4 --pcs-queries 2` reaches the
    master for both protocols.
- Latest script/figure validation:
  - `powershell -ExecutionPolicy Bypass -File .\scripts\run_experiments.ps1 --help`
  - `cargo test -p pq-experiments`
  - `powershell -ExecutionPolicy Bypass -File .\scripts\run_experiments.ps1 net-proof r1cs --size 4 --pcs-queries 2 --format json --case both`
  - `powershell -ExecutionPolicy Bypass -File .\scripts\run_experiments.ps1 net-proof plonkish --size 4 --pcs-queries 2 --format csv --case both`
  - `powershell -ExecutionPolicy Bypass -File .\scripts\run_experiments.ps1`
  - `cargo fmt --check`
  - `cargo clippy --workspace --all-targets -- -D warnings`
  - no residual `pq-experiments` worker processes were present after the
    Windows `net-proof` and no-argument script runs;
  - benchmark command:
    `powershell -ExecutionPolicy Bypass -File .\scripts\run_benchmarks.ps1 -NvRange "2..3" -Workers "1,2" -PcsQueries 2 -OutDir results`
  - latest output directory: `results/bench-1780173998`;
  - generated files: `source.csv`, `source.json`, `summary.txt`,
    `prove_time_by_size.svg`, `prove_time_by_size.tex`,
    `verify_time_by_size.svg`, `verify_time_by_size.tex`,
    `proof_bytes_by_size.svg`, `proof_bytes_by_size.tex`,
    `worker_scaling_max_size.svg`, and `worker_scaling_max_size.tex`;
  - source data contains 16 rows, all 8 positive cases verified, and all 8
    negative cases were rejected;
  - network-backed Windows smoke at `n=2`: R1CS `workers=2` positive verified
    `true`, negative verified `false`, `pcs_queries=2`, `proof_bytes=24152`,
    positive `network_bytes=6984`; Plonkish `workers=2` positive verified
    `true`, negative verified `false`, `pcs_queries=2`,
    `proof_bytes=31960`, positive `network_bytes=4840`;
  - latest measured scaling at `n=3` / `nv=8`: R1CS `workers=2` speedup
    `1.313` with efficiency `0.656`, and Plonkish `workers=2` speedup
    `1.216` with efficiency `0.608`; both remain below the ideal distributed
    upper bound and were marked `plausible-prototype-overhead`.
  - post-hardening minimal Windows benchmark sanity:
    `powershell -ExecutionPolicy Bypass -File .\scripts\run_benchmarks.ps1 -NvRange "2..2" -Workers "1" -PcsQueries 2 -OutDir results`
    generated `results/bench-1780174121` with `source.csv`, `source.json`,
    `summary.txt`, all four SVGs, and all four PGFPlots/TikZ `.tex` figures.
- Linux experiment entrypoint hardening:
  - `scripts/run_experiments.sh net-proof` now chooses free loopback TCP ports
    instead of fixed `19211/19212`, validates the protocol name before
    launching workers, waits for each worker TCP listener before starting the
    master, and cleans worker processes through an EXIT trap on both success
    and failure;
  - when `python3` is present, the Linux helper asks the OS for a free port;
    otherwise it probes random high ports through Bash `/dev/tcp` before
    falling back to the old fixed ports;
  - the script now resolves `target/debug/pq-experiments.exe` as a fallback
    when it is executed under Git Bash on Windows, while keeping the Linux
    `target/debug/pq-experiments` path first.
- Latest Linux-entry validation:
  - native `bash` on this Windows host still maps to WSL and failed because no
    WSL distro is installed; validation therefore used Git Bash login mode:
    `& 'C:\Program Files\Git\bin\bash.exe' --login -c 'cd /c/Projects/pq_dSNARK && ...'`;
  - `scripts/run_experiments.sh --help` displayed the expected usage;
  - `bash -n scripts/run_experiments.sh` passed;
  - `scripts/run_experiments.sh net-proof r1cs --size 4 --pcs-queries 2 --format json --case both`
    produced a positive R1CS proof with `verified=true`, a negative proof with
    `verified=false`, `size=4`, `pcs_queries=2`, and non-zero `network_bytes`;
  - `scripts/run_experiments.sh net-proof plonkish --size 4 --pcs-queries 2 --format csv --case both`
    used dynamically chosen ports `34564` and `24650`, produced a positive
    Plonkish proof with `verified=true`, a negative proof with
    `verified=false`, `size=4`, `pcs_queries=2`, and non-zero `network_bytes`;
  - full default Linux entrypoint smoke, run through Git Bash login mode,
    completed successfully:
    `scripts/run_experiments.sh`;
  - the default run executed `cargo test --workspace`, local R1CS and Plonkish
    positive/negative smokes, TCP `net-demo`, network-backed R1CS proof smoke
    on dynamic ports `41506` and `38652`, and network-backed Plonkish proof
    smoke on dynamic ports `37784` and `50578`;
  - no residual `pq-experiments` worker processes were present after the Git
    Bash network proof and default script runs.
- Distributed PCS worker/master API split:
  - `pq-pcs::DistributedPcs` now exposes explicit `worker_commit`,
    `worker_open`, and `master_commit` methods in addition to `partition`,
    `commit`, `open_at`, and `verify`;
  - `DistributedBrakedown::commit` is now assembled from the same
    `partition -> worker_commit -> master_commit` stages used by networked
    execution, and `commit_detached` reuses the worker-level API before
    validating the master commitment;
  - `DistributedBrakedown::worker_open` constructs the systematic, next,
    stride, adjacent-parity, stride-parity, and blend-parity Merkle openings
    for each queried local row; the local opening provider now reuses this API
    after checking the worker commitment root;
  - `pq-net` worker `PcsCommit` and `PcsOpen` handlers now call
    `DistributedBrakedown::worker_commit` and `DistributedBrakedown::worker_open`
    instead of duplicating PCS code in the network crate.
- Latest PCS worker/master validation:
  - `cargo test -p pq-pcs -p pq-net`
  - `cargo test --workspace`
  - `cargo fmt --check`
  - `cargo clippy --workspace --all-targets -- -D warnings`
  - `powershell -ExecutionPolicy Bypass -File .\scripts\run_experiments.ps1 net-proof r1cs --size 4 --pcs-queries 2 --format json --case both`
  - `powershell -ExecutionPolicy Bypass -File .\scripts\run_experiments.ps1 net-proof plonkish --size 4 --pcs-queries 2 --format csv --case both`
  - new PCS unit tests check that split worker/master commitments match the
    convenience `commit`, that reordered or malformed worker metadata is
    rejected by the master, and that worker local openings contain all
    systematic and parity layers;
  - network-backed smoke after the API split: R1CS `workers=2`, `n=2`
    positive verified `true`, negative verified `false`, `pcs_queries=2`,
    positive `network_bytes=6984`; Plonkish `workers=2`, `n=2` positive
    verified `true`, negative verified `false`, `pcs_queries=2`, positive
    `network_bytes=4840`;
  - no residual `pq-experiments` worker processes were present after the
    Windows network proof smoke.
- Base PCS setup and batch-opening interface:
  - `pq-pcs::PolynomialCommitment` now exposes `setup`, `commit_with_setup`,
    `open_with_setup`, `batch_open`, `batch_open_with_setup`, and
    `batch_verify` in addition to the existing single `commit/open/verify`
    operations;
  - `PcsSetup` records the transparent maximum supported vector length and
    rejects commitments/openings whose power-of-two evaluation length exceeds
    that setup bound;
  - `BatchOpeningProof` carries the ordered Merkle openings returned for a
    caller-specified index list. The default batch verifier checks every
    included opening against the same commitment and rejects empty batches.
- Latest base PCS API validation:
  - `cargo test -p pq-pcs`
  - `cargo test --workspace`
  - `cargo clippy --workspace --all-targets -- -D warnings`
  - new PCS unit test verifies setup-bound commit/open, ordered batch opening,
    batch verification, tampered batch rejection, empty batch rejection, and
    setup max-length rejection.
- Unified PIOP trait and paper-ready benchmark figures:
  - added `crates/pq-piop` with a protocol-agnostic `Piop` trait carrying
    statement, witness, proof, metrics, error, `DistributedPcsParams`, and a
    generic `Transcript` implementation through `prove_interactive` and
    `verify_interactive`;
  - added `R1csPiop` and `PlonkishPiop` marker adapters so the R1CS and
    Plonkish routes can be driven through the same trait while still using
    their real PCS and Fiat-Shamir paths;
  - Plonkish transcript plumbing is now generic over `pq_transcript::Transcript`
    instead of hard-coding `HashTranscript` in internal helper signatures;
  - benchmark chart generation now writes paper-oriented PGFPlots/TikZ outputs:
    individual `.tex` charts plus a 2x2 `paper_figures.tex` groupplot and a
    `paper_figures_standalone.tex` wrapper that can be compiled from the result
    directory; the grouped figure uses shared legend entries, fixed protocol
    colors, worker line/marker encodings, and an explicit ideal-linear baseline
    in the worker-scaling panel;
  - README now documents the shared `pq-piop` crate and the `paper_figures.tex`
    inclusion requirements (`pgfplots`, `groupplots`, `compat=1.18`).
- Latest unified PIOP and figure validation:
  - `cargo test -p pq-piop-r1cs -p pq-piop-plonkish -p pq-experiments`
  - `cargo test --workspace`
  - `cargo fmt --check`
  - `cargo clippy --workspace --all-targets -- -D warnings`
  - benchmark sanity command:
    `powershell -ExecutionPolicy Bypass -File .\scripts\run_benchmarks.ps1 -NvRange "2..2" -Workers "1" -PcsQueries 2 -OutDir results`
  - latest output directory: `results/bench-1780175470`;
  - generated files include `source.csv`, `source.json`, `summary.txt`, all
    four SVGs, all four individual PGFPlots/TikZ `.tex` figures,
    `paper_figures.tex`, and `paper_figures_standalone.tex`;
  - latest minimal benchmark source rows: R1CS positive verified `true`, R1CS
    negative verified `false` with failure `Pcs`, Plonkish positive verified
    `true`, and Plonkish negative verified `false` with failure
    `InvalidProof`;
  - at `n=2` / `nv=4` / `workers=1`, measured baseline prover times were R1CS
    `64.342 ms` and Plonkish `91.501 ms`; with only the baseline worker count
    enabled, speedup is correctly `1.000` for both routes and marked
    `plausible-prototype-overhead`.
- Benchmark reliability hardening after subagent audit:
  - `pq-experiments benchmark` now rejects worker sets that do not contain
    `workers=1`, because the worker-scaling plot and theory comparison require
    an explicit non-distributed baseline instead of an implicit fallback;
  - each benchmark result directory now includes `metadata.json` with schema
    version, run id, host OS/architecture, command line, build profile,
    selected `nv_powers`, sizes, workers, PCS query count, positive/negative
    counts, and the complete artifact list;
  - `summary.txt` also records the benchmark binary profile (`debug` or
    `release`) and the full artifact list;
  - `scripts/run_benchmarks.ps1` accepts `-Release`, and
    `scripts/run_benchmarks.sh` accepts `--release`, then builds and runs the
    matching `target/release/pq-experiments` binary;
  - `scripts/run_experiments.ps1 net-proof` now waits for each hidden worker
    TCP listener before launching the master, matching the Linux helper's
    explicit readiness check instead of relying on a fixed sleep.
- Latest hardening validation:
  - `cargo test -p pq-experiments`
  - `cargo test --workspace`
  - `cargo clippy --workspace --all-targets -- -D warnings`
  - `cargo fmt --check`
  - Linux script syntax checks used Git Bash explicitly because default
    `bash` on this Windows host maps to WSL without an installed distro:
    `& 'C:\Program Files\Git\bin\bash.exe' -n scripts/run_benchmarks.sh`
    and
    `& 'C:\Program Files\Git\bin\bash.exe' -n scripts/run_experiments.sh`
  - Windows network proof smoke:
    `powershell -ExecutionPolicy Bypass -File .\scripts\run_experiments.ps1 net-proof r1cs --size 4 --pcs-queries 2 --format json --case both`
  - release benchmark sanity:
    `powershell -ExecutionPolicy Bypass -File .\scripts\run_benchmarks.ps1 -Release -NvRange "2..2" -Workers "1" -PcsQueries 2 -OutDir results`
  - latest release output directory: `results/bench-1780175986`;
  - generated artifacts include `metadata.json`, source CSV/JSON, summary, all
    SVGs, all individual PGFPlots/TikZ figures, `paper_figures.tex`, and
    `paper_figures_standalone.tex`;
  - `summary.txt` and `metadata.json` both recorded `build_profile=release`;
  - latest release source rows: R1CS positive verified `true`, R1CS negative
    verified `false` with failure `Pcs`, Plonkish positive verified `true`,
    and Plonkish negative verified `false` with failure `InvalidProof`;
  - at `n=2` / `nv=4` / `workers=1`, release prover times were R1CS
    `6.595 ms` and Plonkish `9.050 ms`; speedup is `1.000` for both routes
    because this sanity run intentionally used only the baseline worker count.
- Distributed PCS malicious-worker rejection evidence:
  - added a PCS unit test that assembles an opening through the public
    worker-provider hook with an honest worker response and then with one
    worker returning a tampered local systematic opening; the honest proof
    verifies, while the tampered worker response is rejected by the master-side
    verifier against the worker Merkle commitment;
  - this does not claim malicious-worker fault tolerance, but it gives a
    concrete regression test for the network/distributed PCS trust boundary:
    malformed worker local openings cannot be silently accepted into a valid
    distributed opening.
- Linux benchmark script progress hardening:
  - `scripts/run_benchmarks.sh` now prints the selected size mode, matching the
    Windows script and README claim (`direct sizes`, explicit `nv` powers, or
    inclusive `nv` range);
  - Git Bash validation command:
    `& 'C:\Program Files\Git\bin\bash.exe' --login -c 'cd /c/Projects/pq_dSNARK && scripts/run_benchmarks.sh --nv-range 2..2 --workers 1 --pcs-queries 2 --out results'`
    printed `size selection: nv=2^n for n in 2..2`.
- Latest PCS/script validation:
  - `cargo test -p pq-pcs distributed_opening_rejects_malicious_worker_response`
  - `& 'C:\Program Files\Git\bin\bash.exe' -n scripts/run_benchmarks.sh`
  - `cargo test --workspace`
  - `cargo fmt --check`
  - `cargo clippy --workspace --all-targets -- -D warnings`
  - latest Git Bash benchmark output directory: `results/bench-1780176187`;
    its `metadata.json` recorded `build_profile=debug`, source rows again
    showed R1CS/Plonkish positives verified `true`, and negatives verified
    `false`.
- Sampled MLE folding proof component:
  - added `SampledMleFoldingProof`, `SampledFoldRoundProof`, and
    `SampledFoldCheck` to `pq-pcs`;
  - added `prove_sampled_mle_folding` and `verify_sampled_mle_folding`, which
    bind an input Merkle commitment, the evaluation point, query count, each
    folded-layer commitment, Fiat-Shamir sampled fold indices, Merkle openings
    for the left/right/folded values, and the final singleton opening;
  - verifier checks sampled fold equations
    `folded = left * (1 - challenge) + right * challenge` against Merkle
    openings without requiring the full original vector as verifier input;
  - this is not yet wired as a replacement for the integrated distributed PCS
    opening, which still carries full `combined_column` and
    `combined_codeword`; it is an explicitly tested component moving the PCS
    crate toward a Brakedown/BaseFold-style sampled proximity path.
- Latest sampled-folding validation:
  - `cargo test -p pq-pcs sampled_mle_folding_proof_verifies_and_rejects_tampering`
  - `cargo test --workspace`
  - `cargo fmt --check`
  - `cargo clippy --workspace --all-targets -- -D warnings`
  - the new sampled-folding test checks a valid proof against the committed
    input vector, then rejects tampered sampled values, sampled indices, and
    final values.
- Integrated sampled folding into distributed PCS opening:
  - `DistributedOpening` now carries `sampled_folding_proof` for the
    row-weighted combined column and `sampled_composition_proof` for the
    composed codeword;
  - prover and verifier absorb both sampled proofs into the same
    Fiat-Shamir transcript before deriving Brakedown query indices, so query
    sampling is bound to the sampled fold-consistency checks;
  - verifier checks sampled final values against the full folding proof claims
    and rejects tampered sampled folded openings or final sampled values;
  - `proof_size_bytes` now accounts for sampled folding commitments,
    sampled Merkle openings, final singleton openings, and sampled transcript
    states;
  - the full folding proofs remain in this correctness prototype, so this is
    an integrated soundness-hardening step rather than a replacement by a
    production Brakedown/BaseFold proximity proof.
- Paper-ready benchmark figure pass:
  - benchmark output now emits source data, SVG previews, individual
    PGFPlots/TikZ `.tex` files, `paper_figures.tex`, and
    `paper_figures_standalone.tex`;
  - PGFPlots figures use measured records only, with an Okabe-Ito
    color-blind-friendly palette, white background, restrained grid/axis
    styling, consistent line widths/markers, and a grouped 2x2 figure layout
    suitable for direct LaTeX inclusion;
  - each result directory still includes `metadata.json`, `source.csv`,
    `source.json`, and `summary.txt`, and benchmark validation requires
    `workers=1` for a real non-distributed baseline.
- Plonkish sampled gate subclaim pass:
  - `PlonkishGateSubclaimProof` no longer carries full `values:
    Vec<FieldElement>` for the nine gate-subclaim oracle columns
    `A/B/C/q_l/q_r/q_o/q_m/q_c/gate_residual`;
  - those random-point gate evaluations are now bound to the existing Merkle
    oracle commitments with `SampledMleFoldingProof`, using the same PCS query
    count parameter and the same Fiat-Shamir transcript;
  - the verifier checks each sampled proof against the corresponding oracle
    commitment before evaluating the virtual Plonkish gate subclaim, and
    tampered sampled folded openings are rejected;
  - this was the first targeted gate subclaim compactness step; the later
    accumulator recurrence pass below removes the full accumulator-column
    vectors from that subclaim as well.
- Benchmark script alias pass:
  - `scripts/run_benchmarks.ps1` now accepts `-NValues` and `-NRange` aliases
    in addition to `-NvPowers` and `-NvRange`, matching the Rust CLI and Linux
    wrapper `--n-values` / `--n-range` aliases.
- Compact distributed PCS opening prototype:
  - added `CompactDistributedOpening` and `CompactQueryOpening` as a parallel
    PCS opening path that does not carry full `combined_column` or
    `combined_codeword` vectors in the proof;
  - the compact path commits to the row-weighted combined column and its
    systematic/parity codeword, verifies sampled MLE folding proofs against
    those commitments, then checks Fiat-Shamir selected combined openings
    against row-weighted worker Merkle openings and local codeword parity
    relations;
  - `compact_proof_size_bytes` and `compact_communication_bytes` account for
    the compact proof separately from the original full-vector
    `DistributedOpening`;
  - a PCS regression test verifies a valid compact opening, checks that it is
    smaller than the full opening on a 256-entry sample, and rejects tampered
    combined openings, worker openings, sampled folding final values, and
    query-index order;
  - this path is still not wired into the Plonkish proof struct, and the
    original full correctness opening remains available for hook/network
    compatibility; the R1CS integration below is the first PIOP route using
    the compact opening by default.
- R1CS compact PCS integration:
  - introduced `R1csPcsOpening::{Full, Compact}` so R1CS verification can
    accept either the original full distributed PCS opening or the new compact
    PCS opening with a single code path for point/value/size accounting;
  - the default local `prove_r1cs_with_pcs_params` path now uses
    `DistributedBrakedown::open_compact_at_after_commitment_with_params` for
    outer `Az/Bz/Cz`, inner witness, and residual PCS openings;
  - `prove_r1cs_with_pcs_hooks` remains compatible with hook/network
    experiments by wrapping hook-returned `DistributedOpening` values as
    `R1csPcsOpening::Full`;
  - outer `Az/Bz/Cz` commitments and openings now also route through the
    provided commit/open hooks, so the networked R1CS prover path exercises
    worker PCS rounds for those linearization columns instead of only for
    witness/residual openings;
  - added a regression test that the default R1CS proof uses compact openings
    and a hook-path proof still verifies with full openings.
- Sampled PIOP consistency query pass:
  - R1CS `row_queries` are now selected with Fiat-Shamir
    `challenge_indices` using `DistributedPcsParams::query_count`; when the
    query count is at least the number of constraints the path still checks
    every row, but benchmark settings such as `--pcs-queries 2` now produce a
    sampled row-consistency proof instead of an exhaustive row proof;
  - Plonkish gate, copy/permutation, and accumulator recurrence consistency
    queries now use the same transcript-derived sampled-index pattern and
    query-count parameter, while preserving full-domain checks when the query
    count covers the domain;
  - added regression tests that full-domain mode still covers every R1CS row
    and every Plonkish gate/copy/accumulator domain, plus sampled-mode tests
    that prove/verify with two distinct transcript-selected queries.
- R1CS compact network and interactive preflight pass:
  - introduced `prove_r1cs_with_pcs_opening_hooks`, which lets hook users
    return `R1csPcsOpening::{Full, Compact}` directly instead of forcing
    hook-produced openings into the full-vector variant;
  - the R1CS network experiment path now calls
    `NetworkPcsClient::open_compact` and wraps worker-provider openings as
    `R1csPcsOpening::Compact`, so both R1CS and Plonkish multi-process proof
    paths exercise compact distributed PCS openings;
  - Windows and Linux `interactive` script entry points now run
    `cargo check -p pq-experiments` before building and launching the
    interactive CLI, giving the requested minimal Rust target check without
    running the full workspace test suite.
- Plonkish compact PCS integration:
  - introduced `PlonkishPcsOpening::{Full, Compact}` so the Plonkish verifier
    can check either the original full distributed PCS opening or the compact
    distributed PCS opening through the same point/value/size accounting path;
  - the default local `prove_plonkish_with_pcs_params` path now opens the final
    constraint-residual claim with
    `DistributedBrakedown::open_compact_at_after_commitment_with_params`;
  - `prove_plonkish_with_pcs_hooks` remains compatible with network
    experiments by letting hook users wrap a `DistributedOpening` as
    `PlonkishPcsOpening::Full`;
  - `pq-pcs` now exposes
    `open_compact_at_after_commitment_with_worker_provider`, and the Plonkish
    network experiment hook uses it so multi-process Plonkish proofs also
    exercise compact constraint openings;
  - `pq-experiments` fallback metric accounting now reads Plonkish opening
    communication bytes through the opening enum, so failed negative cases are
    accounted consistently for compact and full hook paths;
  - added a regression test that the default Plonkish proof uses compact
    constraint openings, a hook-path proof still verifies with full openings,
    compact-opening tampering is rejected, and opening size/communication
    accounting distinguishes compact from full openings.
- Plonkish accumulator recurrence sumcheck pass:
  - `PlonkishPermutationAccumulatorSubclaimProof` no longer carries full
    accumulator column vectors for `value/source_id/target_id/current/next`
    or transition residuals;
  - the prover now computes and absorbs shifted `next` commitments and
    numerator/denominator transition-residual commitments before deriving the
    accumulator random subclaim point, so the residual zero checks are not
    committed after seeing that point;
  - random-point column evaluations in the accumulator subclaim are bound with
    sampled MLE folding openings against Merkle commitments, matching the gate
    subclaim approach;
  - added `PlonkishAccumulatorRecurrenceProof` for numerator and denominator:
    each proof runs a cubic zerocheck sumcheck for
    `current * (value + beta * id + gamma * active) = next - residual`;
  - the verifier checks the cubic sumcheck rounds, then verifies committed
    sampled openings for `current/value/id/active/next/residual` at the
    sumcheck challenge point and recomputes the final evaluation from those
    openings;
  - sampled index queries remain as an additional local Merkle consistency
    layer, but recurrence soundness is no longer only sampled-index binding;
  - regression coverage now rejects tampering with shift queries, residual
    Merkle queries, sampled folding checks, next commitments, recurrence
    sumcheck round polynomials, recurrence sampled openings, and the random
    point.
- Latest integrated validation:
  - `cargo test -p pq-piop-plonkish`
  - `cargo fmt --check`
  - `cargo test --workspace`
  - `cargo clippy --workspace --all-targets -- -D warnings`
  - subagent proof audit re-check reported no remaining P1/P2 issue for the
    accumulator recurrence binding after the cubic sumcheck pass;
  - earlier script syntax checks remain valid:
    `& 'C:\Program Files\Git\bin\bash.exe' -n scripts/run_experiments.sh`
    and
    `& 'C:\Program Files\Git\bin\bash.exe' -n scripts/run_benchmarks.sh`;
  - Windows interactive preflight smoke:
    piped `scripts\run_experiments.ps1 interactive` with local R1CS positive
    input; it printed `checking pq-experiments before interactive run`, built
    `pq-experiments`, and verified the R1CS proof;
  - Windows network R1CS compact smoke:
    `powershell -ExecutionPolicy Bypass -File .\scripts\run_experiments.ps1 net-proof r1cs --size 4 --pcs-queries 2 --format json --case both`
    produced positive `verified=true`, negative `verified=false`, and
    `proof_bytes=41414` with nonzero `network_bytes=16176`;
  - Windows alias smoke:
    `powershell -ExecutionPolicy Bypass -File .\scripts\run_benchmarks.ps1 -NRange "2..2" -Workers "1" -PcsQueries 2 -OutDir results`
    generated `results/bench-1780177403`;
  - release benchmark command:
    `powershell -ExecutionPolicy Bypass -File .\scripts\run_benchmarks.ps1 -Release -NRange "2..2" -Workers "1,2" -PcsQueries 2 -OutDir results`
  - latest output directory: `results/bench-1780181530`;
  - latest source rows: R1CS positive verified `true`, R1CS negative verified
    `false` with failure `Pcs`, Plonkish positive verified `true`, and
    Plonkish negative verified `false` with failure `InvalidProof`;
  - measured scaling at `n=2` / `nv=4`: R1CS `workers=2` speedup was
    `1.751x` versus the `workers=1` baseline; Plonkish `workers=2` speedup was
    `0.904x`, below the ideal bound because the new accumulator recurrence
    sumchecks add serial work on this tiny circuit. These `nv=4` timings are
    smoke data, not an asymptotic performance claim;
  - with compact PCS openings, sampled consistency queries, and accumulator
    recurrence sumchecks enabled, latest tiny `nv=4` proof bytes were R1CS
    `45962` bytes for `workers=1` and `41414` bytes for `workers=2`, and
    Plonkish `86796` bytes for `workers=1` and `85758` bytes for `workers=2`.
    The Plonkish increase relative to the previous compact-opening run comes
    from the newly added numerator/denominator cubic recurrence sumchecks and
    their committed sampled openings;
  - generated figure artifacts include `prove_time_by_size.svg/.tex`,
    `verify_time_by_size.svg/.tex`, `proof_bytes_by_size.svg/.tex`,
    `worker_scaling_max_size.svg/.tex`, `paper_figures.tex`, and
    `paper_figures_standalone.tex`;
  - local PDF rendering of `paper_figures_standalone.tex` was not attempted
    because `pdflatex` is not installed in this Windows environment; the
    generated LaTeX source is syntax-level checked by Rust unit tests and
    retained beside the measured source data.

- R1CS Spark matrix-evaluation and memory-check integration:
  - `DistributedSparkProof` now carries per-matrix sparse evaluation proofs
    for `A`, `B`, and `C`, plus a combined matrix evaluation under the
    verifier-sampled inner matrix challenges;
  - each matrix evaluation proof partitions sparse entries by worker range and
    records worker local evaluation sums at the outer-row and inner-column
    challenge points;
  - row and column memory checks now build Init/Read/Write/Audit traces and
    reduce `Init + Write = Audit + Read` to a transcript-bound product
    multiset-equality protocol under a transcript-derived Spark memory hash
    challenge;
  - the R1CS inner linearization verifier no longer recomputes the public
    matrix projection for its final product check. It verifies the PCS-bound
    witness opening and then checks
    `spark.combined_evaluation * witness_opening == inner_final_evaluation`,
    so the Spark matrix-evaluation path is now on the main verification path;
  - proof-size accounting now includes the Spark combined value, per-worker
    matrix evaluations, row/column memory worker digests, and compact memory
    product-check fields;
  - added regression coverage for tampered Spark matrix evaluations, combined
    evaluations, worker digests, memory product checks, memory hash challenges,
    proof-size accounting, and the direct inner/Spark link.
- R1CS Spark validation:
  - `cargo fmt --check`
  - `cargo test -p pq-piop-r1cs`
  - `cargo clippy -p pq-piop-r1cs --all-targets -- -D warnings`
  - `cargo test --workspace`
  - `cargo clippy --workspace --all-targets -- -D warnings`
  - subagent R1CS/Spark audit re-check accepted the main soundness-path fix:
    the inner verifier now depends on `proof.spark.combined_evaluation`
    instead of bypassing Spark with direct matrix recomputation.
- Latest release benchmark after the Spark integration:
  - command:
    `powershell -ExecutionPolicy Bypass -File .\scripts\run_benchmarks.ps1 -Release -NRange "2..2" -Workers "1,2" -PcsQueries 2 -OutDir results`
  - latest output directory: `results/bench-1780182548`;
  - source rows cover `n=2` / `nv=4`, protocols `r1cs` and `plonkish`,
    workers `1` and `2`, with both positive and negative cases;
  - all positive rows verified and all negative rows were rejected. R1CS
    negative cases failed in the PCS path, while Plonkish negative cases failed
    with `InvalidProof`;
  - measured R1CS proving time was `44.876 ms` for `workers=1` and
    `25.005 ms` for `workers=2`, a `1.795x` speedup on this tiny smoke case;
  - measured Plonkish proving time was `235.697 ms` for `workers=1` and
    `266.744 ms` for `workers=2`, so this tiny circuit remains dominated by
    serial accumulator and opening work rather than showing worker speedup;
  - latest proof bytes were R1CS `47946` (`workers=1`) and `43806`
    (`workers=2`), and Plonkish `86796` (`workers=1`) and `85758`
    (`workers=2`);
  - generated paper-oriented figure artifacts include `prove_time_by_size.tex`,
    `verify_time_by_size.tex`, `proof_bytes_by_size.tex`,
    `worker_scaling_max_size.tex`, `paper_figures.tex`, and
    `paper_figures_standalone.tex`, alongside SVG previews and the measured
    `source.csv` / `source.json`.
- R1CS Spark compact memory-product proof pass:
  - added `pq-sumcheck::ProductMultisetEqualityProof`, which binds four public
    multiset segments to the transcript and carries only lengths plus the
    verifier-challenge products, not the full left/right vectors;
  - R1CS Spark row/column memory checks now use this compact product proof for
    `Init + Write = Audit + Read`;
  - the verifier still reconstructs the current public matrix memory trace,
    but proof bytes no longer scale by carrying the explicit trace vectors
    inside `SparkMemoryCheckProof`;
  - regression coverage now checks compact product proof tampering, forged
    public inputs, R1CS Spark memory-product tampering, and updated R1CS memory
    proof-size accounting.
- Latest validation after compact memory-product proof:
  - `cargo test -p pq-sumcheck`
  - `cargo test -p pq-piop-r1cs`
  - `cargo test --workspace`
  - `cargo clippy --workspace --all-targets -- -D warnings`
  - release benchmark command:
    `powershell -ExecutionPolicy Bypass -File .\scripts\run_benchmarks.ps1 -Release -NRange "2..2" -Workers "1,2" -PcsQueries 2 -OutDir results`
  - latest output directory: `results/bench-1780182986`;
  - all 4 positive rows verified and all 4 negative rows were rejected;
  - R1CS proof bytes at `n=2` / `nv=4` decreased to `46986`
    (`workers=1`) and `42846` (`workers=2`) after removing carried memory
    vectors from the Spark memory check;
  - measured R1CS proving time was `44.727 ms` for `workers=1` and
    `28.020 ms` for `workers=2`, a `1.596x` speedup on this tiny smoke case;
  - measured Plonkish proving time was `244.216 ms` for `workers=1` and
    `268.272 ms` for `workers=2`; Plonkish proof bytes remained `86796` and
    `85758` because this change only touched the R1CS Spark memory path;
  - generated artifacts again include measured `source.csv` / `source.json`,
    SVG previews, individual PGFPlots/TikZ figures, `paper_figures.tex`, and
    `paper_figures_standalone.tex`.
- R1CS Spark worker memory digest pass:
  - replaced the old Spark memory `worker_sums` records with
    `SparkMemoryWorkerDigest`;
  - each worker digest now binds both the sparse-entry shard range and the
    memory-domain shard range, and carries products for Init, Read, Write, and
    Audit contributions instead of only Read/Write additive sums;
  - row and column memory checks absorb these worker digests before proving the
    compact product multiset equality, so the distributed worker evidence now
    matches the product-check proof shape;
  - R1CS tamper tests now reject modified worker memory products, and proof
    size accounting uses the explicit worker digest size rather than the old
    worker-sum record size;
  - the Spark memory tamper test now also covers worker digest metadata,
    `domain_len`, `access_count`, row/column memory swaps, product-check
    `gamma`, and product-check segment lengths.
- Latest validation after worker memory digests:
  - `cargo test -p pq-piop-r1cs`
  - `cargo test --workspace`
  - `cargo clippy --workspace --all-targets -- -D warnings`
  - after adding the additional memory tamper cases, `cargo test -p
    pq-piop-r1cs` and `cargo clippy --workspace --all-targets -- -D warnings`
    were rerun successfully;
  - release benchmark command:
    `powershell -ExecutionPolicy Bypass -File .\scripts\run_benchmarks.ps1 -Release -NRange "2..2" -Workers "1,2" -PcsQueries 2 -OutDir results`
  - latest output directory: `results/bench-1780183354`;
  - all 4 positive rows verified and all 4 negative rows were rejected;
  - R1CS proof bytes at `n=2` / `nv=4` are now `47178` (`workers=1`) and
    `43230` (`workers=2`). This is slightly larger than the immediately
    preceding compact-product run because the proof now records Init/Read/
    Write/Audit worker product digests instead of only Read/Write additive
    sums;
  - measured R1CS proving time was `44.216 ms` for `workers=1` and
    `26.594 ms` for `workers=2`, a `1.663x` speedup on this tiny smoke case;
  - measured Plonkish proving time was `241.582 ms` for `workers=1` and
    `264.079 ms` for `workers=2`; Plonkish proof bytes stayed at `86796` and
    `85758` because the digest change only affects the R1CS Spark path;
  - generated artifacts include `source.csv`, `source.json`, `summary.txt`,
    all SVG previews, all individual PGFPlots/TikZ figures,
    `paper_figures.tex`, and `paper_figures_standalone.tex`.
- R1CS benchmark fallback metric correction:
  - fixed `pq-experiments` R1CS fallback communication accounting for rejected
    negative cases. It now sums the same five PCS opening components as the
    verifier metrics: outer `Az/Bz/Cz`, inner witness, and residual openings;
  - added `r1cs_fallback_metrics_include_all_pcs_openings`, which compares
    fallback metrics against successful verifier metrics and checks that
    fallback communication is larger than the residual opening alone;
  - validation:
    `cargo test -p pq-experiments r1cs_fallback_metrics_include_all_pcs_openings`,
    `cargo test -p pq-experiments`, and
    `cargo clippy --workspace --all-targets -- -D warnings`;
  - release benchmark command:
    `powershell -ExecutionPolicy Bypass -File .\scripts\run_benchmarks.ps1 -Release -NRange "2..2" -Workers "1,2" -PcsQueries 2 -OutDir results`
  - latest output directory: `results/bench-1780183560`;
  - all 4 positive rows verified and all 4 negative rows were rejected;
  - R1CS negative `communication_bytes` now matches the corresponding
    positive case at the same worker count: `43188` for `workers=1` and
    `38498` for `workers=2`, rather than undercounting only the residual
    opening;
  - latest R1CS proof bytes remain `47178` (`workers=1`) and `43230`
    (`workers=2`); latest Plonkish proof bytes remain `86796` and `85758`.
- Benchmark wrapper help and syntax validation:
  - fixed `scripts/run_benchmarks.ps1 -Help` so it prints usage and exits
    before building or launching the default benchmark suite;
  - removed the empty `results/bench-1780183679` directory left by the earlier
    interrupted accidental help run after verifying it was empty and inside the
    workspace;
  - validation:
    `powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\run_benchmarks.ps1 -Help`,
    `& 'C:\Program Files\Git\bin\bash.exe' -n scripts/run_benchmarks.sh`,
    `& 'C:\Program Files\Git\bin\bash.exe' -n scripts/run_experiments.sh`,
    `cargo test --workspace`, and `cargo fmt --check`.
- R1CS Spark matrix statement binding:
  - `absorb_spark_matrix_evaluation_statement` now absorbs every sparse entry's
    entry index, row, column, and value, in addition to matrix id, shape, nnz,
    and the row/column evaluation points;
  - this makes the per-matrix Spark evaluation statement transcript-bound to
    the concrete public sparse matrix, instead of relying only on outer
    instance-shape absorption plus later verifier recomputation;
  - added `spark_matrix_statement_absorbs_sparse_entries`, which checks that
    same-shape/same-nnz value changes and entry reordering both change the
    transcript challenge derived from the Spark matrix statement;
  - validation:
    `cargo test -p pq-piop-r1cs spark_matrix_statement_absorbs_sparse_entries`,
    `cargo test -p pq-piop-r1cs`, `cargo test --workspace`,
    `cargo clippy --workspace --all-targets -- -D warnings`, and
    `cargo fmt --check`;
  - release benchmark command:
    `powershell -ExecutionPolicy Bypass -File .\scripts\run_benchmarks.ps1 -Release -NRange "2..2" -Workers "1,2" -PcsQueries 2 -OutDir results`
  - latest output directory: `results/bench-1780202907`;
  - all 4 positive rows verified and all 4 negative rows were rejected;
  - latest R1CS proof bytes remain `47178` (`workers=1`) and `43230`
    (`workers=2`), as expected because this change strengthens transcript
    binding but does not add proof fields; latest Plonkish proof bytes remain
    `86796` and `85758`;
  - latest tiny-case scaling: R1CS `workers=2` speedup was `1.681x`; Plonkish
    `workers=2` speedup was `0.974x`, still marked
    `plausible-prototype-overhead`.
- R1CS network compact-opening proof-path regression:
  - added `r1cs_network_hook_produces_compact_pcs_openings` in
    `pq-experiments`;
  - the test starts two loopback TCP workers, proves an R1CS instance through
    the network PCS hook, asserts that outer `Az/Bz/Cz`, inner witness, and
    residual PCS openings are all `R1csPcsOpening::Compact`, verifies the proof,
    and checks that network bytes are nonzero;
  - this gives a direct white-box regression for the R1CS network path, rather
    than relying only on positive/negative metric rows to infer compact PCS use;
  - validation:
    `cargo test -p pq-experiments r1cs_network_hook_produces_compact_pcs_openings`,
    `cargo test -p pq-experiments`,
    `cargo clippy --workspace --all-targets -- -D warnings`, and
    `cargo test --workspace`.
- Sumcheck full-vector proof-surface cleanup:
  - `RationalSumcheckProof` no longer carries the full numerator and
    denominator vectors. It now carries the claimed sum, input length, a real
    `SumcheckProof` over the zero-padded rational-evaluation MLE, and a
    Fiat-Shamir binding challenge; the verifier rebuilds the rational
    evaluation vector from the public numerator and denominator slices and
    verifies the embedded sumcheck rounds before accepting;
  - added transcript-aware
    `prove_rational_sumcheck_with_transcript` /
    `verify_rational_sumcheck_with_transcript`; the existing
    `prove_rational_sumcheck` / `verify_rational_sumcheck` helpers remain
    available and route through a fixed rational-sumcheck transcript domain;
  - `MultisetEqualityProof` no longer carries the concatenated left/right
    multiset vectors. It now carries the Fiat-Shamir challenge, four segment
    lengths, and the log-derivative left/right sums; the verifier recomputes
    those sums from the public statement vectors;
  - tests now cover forged public inputs, length tampering, aggregate value
    tampering, rational binding-challenge tampering, rational sumcheck-round
    tampering, prover/verifier transcript state equality, and public-input
    changes altering the transcript-bound challenge for these non-default
    helper proofs;
  - this removes the remaining full-input-vector proof surface from the public
    `pq-sumcheck` helper APIs. The default R1CS Spark path already uses
    `ProductMultisetEqualityProof`;
  - validation:
    `cargo test -p pq-sumcheck rational`, `cargo test -p pq-sumcheck`,
    `cargo test --workspace`,
    `cargo clippy --workspace --all-targets -- -D warnings`, and
    `cargo fmt --check`;
  - post-change benchmark smoke:
    `powershell -ExecutionPolicy Bypass -File .\scripts\run_benchmarks.ps1 -Runner both -NRange "2..2" -Workers "1" -PcsQueries 1 -Repeats 1 -OutDir results`;
    output directory `results/bench-1780213744`; all 4 positive rows verified,
    all 4 negative rows were rejected, and independent result verification
    reported `files_checked=19` and `bytes_checked=45976`. The Linux shell
    verification entry was also exercised through Git Bash with
    `scripts/verify_results.sh results/bench-1780213744 --format csv`; a bare
    `bash` on this Windows host resolves to WSL and reports that no Linux
    distribution is installed, so the explicit Git Bash path was used to
    distinguish host environment absence from script failure.
- Plonkish network compact-opening proof-path regression:
  - added `plonkish_network_hook_produces_compact_pcs_opening` in
    `pq-experiments`;
  - the test starts two loopback TCP workers, proves a Plonkish instance
    through the network PCS hook, asserts that the constraint PCS opening is
    `PlonkishPcsOpening::Compact`, verifies the proof, and checks that network
    bytes are nonzero;
  - this mirrors the R1CS network compact-opening regression and gives direct
    white-box coverage that both PIOP routes use compact PCS openings in their
    network experiment paths;
  - validation:
    `cargo test -p pq-experiments plonkish_network_hook_produces_compact_pcs_opening`,
    `cargo test -p pq-experiments`,
    `cargo clippy --workspace --all-targets -- -D warnings`, and
    `cargo test --workspace`.
- R1CS Spark value-memory and paper-figure pass:
  - `SparkMatrixEvaluationProof` now carries a third compact memory check for
    the sparse matrix value vector, in addition to the existing row and column
    address-memory checks;
  - the row, column, and value checks share the same transcript-derived
    memory hash, product multiset equality proof shape, and per-worker
    Init/Read/Write/Audit product digest verification;
  - added regressions that reject tampered value-memory worker digests,
    multiset products, and memory hash challenges, and extended proof-size
    accounting to include value-memory digests;
  - `paper_figures.tex` now uses a more publication-oriented PGFPlots group
    style: color-blind-friendly protocol colors, conservative major/minor
    grids, shared bottom legend, y-axes starting at zero, and a KiB proof-size
    panel. SVGs remain preview artifacts; the `.tex` outputs are the intended
    paper-facing figures;
  - validation:
    `cargo test -p pq-piop-r1cs`, `cargo test --workspace`,
    `cargo clippy --workspace --all-targets -- -D warnings`, and
    `cargo fmt --check`;
  - release benchmark command:
    `powershell -ExecutionPolicy Bypass -File .\scripts\run_benchmarks.ps1 -Release -NRange "2..2" -Workers "1,2" -PcsQueries 2 -OutDir results`
  - latest output directory: `results/bench-1780204261`;
  - all 4 positive rows verified and all 4 negative rows were rejected;
  - latest R1CS proof bytes are `47682` (`workers=1`) and `43974`
    (`workers=2`), increasing as expected because three per-matrix
    value-memory product checks were added; latest Plonkish proof bytes remain
    `86796` and `85758`;
  - latest tiny-case scaling: R1CS `workers=2` speedup was `1.670x`;
    Plonkish `workers=2` speedup was `0.917x`; both are marked
    `plausible-prototype-overhead`. The Plonkish small-case slowdown remains
    consistent with prototype overhead because commitment, transcript, and
    verification work are still largely serial at `nv=4`.
- Benchmark repeated-trial statistics pass:
  - `pq-experiments benchmark` now accepts `--repeats N`; the Windows wrapper
    exposes `-Repeats N`, and the Linux wrapper documents and forwards
    `--repeats N`;
  - raw `source.csv` and `source.json` now include a `trial` field for every
    measured positive/negative run; `metadata.json` records `repeats` and bumps
    `schema_version` to `2`;
  - each benchmark result now writes `summary_stats.csv` with per
    protocol/case/size/worker means and sample standard deviations for prove
    time, verify time, proof bytes, communication bytes, and network bytes;
  - `summary.txt` scaling analysis now uses aggregated positive-run
    `prove_ms_mean` and reports sample count plus `prove_ms_stddev`, rather
    than selecting a single raw row;
  - SVG preview charts and individual PGFPlots figures use aggregated means;
    the paper grouped PGFPlots figure uses means plus explicit y error bars for
    proving time, verification time, and proof-size panels. Worker scaling
    remains a mean-speedup panel against the `workers=1` baseline;
  - validation:
    `cargo test -p pq-experiments`, `cargo test --workspace`,
    `cargo clippy --workspace --all-targets -- -D warnings`,
    `powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\run_benchmarks.ps1 -Help`,
    and `& 'C:\Program Files\Git\bin\bash.exe' -n scripts/run_benchmarks.sh`;
  - repeated-trial release benchmark command:
    `powershell -ExecutionPolicy Bypass -File .\scripts\run_benchmarks.ps1 -Release -NRange "2..2" -Workers "1,2" -PcsQueries 2 -Repeats 2 -OutDir results`
  - latest repeated-trial output directory: `results/bench-1780205018`;
  - all 8 positive rows verified and all 8 negative rows were rejected;
  - latest aggregated R1CS proof bytes remain `47682` (`workers=1`) and
    `43974` (`workers=2`); latest Plonkish proof bytes remain `86796` and
    `85758`;
  - latest mean tiny-case scaling: R1CS `workers=2` speedup was `1.668x`;
    Plonkish `workers=2` speedup was `0.900x`; both are marked
    `plausible-prototype-overhead` under the small correctness-prototype
    benchmark model.
- Fresh-machine bootstrap and optional figure-compilation pass:
  - added `scripts/bootstrap.ps1` for Windows and `scripts/bootstrap.sh` for
    Linux fresh-device setup;
  - bootstrap scripts default to dependency detection and use `-Install` /
    `--install` for one-command installation of missing required tools. The
    Windows script uses `winget` or Chocolatey for Git, Rustup, and Visual
    Studio C++ build tools; the Linux script uses the detected package manager
    plus `rustup`;
  - Windows and Linux bootstrap now handle the fresh-device edge case where
    `rustup` exists but the repository-pinned Rust toolchain, `cargo`, or
    `rustc` is missing: both scripts read `rust-toolchain.toml`, run
    `rustup toolchain install <channel>`, install `rustfmt` and `clippy` for
    that channel, refresh the Cargo PATH, and fail with a concrete PATH hint if
    `cargo`/`rustc` are still unavailable;
  - `-WithFigures` / `--with-figures` additionally checks or installs a LaTeX
    figure compiler path, using `tectonic` through Cargo when no compiler is
    present;
  - benchmark figure compilation is now optional via `--compile-figures`;
    Windows exposes `-CompileFigures`, Linux forwards `--compile-figures`, and
    `--figure-compiler` / `-FigureCompiler` can force `auto`, `pdflatex`, or
    `tectonic`;
  - if figure compilation is requested but the compiler is missing, the
    benchmark fails explicitly after leaving `source.csv`, `source.json`,
    `summary_stats.csv`, `summary.txt`, and all `.tex` figure sources in the
    result directory. `metadata.json` records the requested compiler and
    whether figure compilation succeeded;
  - validation:
    `cargo test -p pq-experiments`, `cargo clippy --workspace --all-targets -- -D warnings`,
    `powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\run_benchmarks.ps1 -Help`,
    and `& 'C:\Program Files\Git\bin\bash.exe' -n scripts/run_benchmarks.sh`;
  - latest fresh-machine bootstrap smoke validation:
    `powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\bootstrap.ps1`
    reported `all required tools are present` on the current Windows host;
    `powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\bootstrap.ps1 -Help`
    displayed the expected usage; `& 'C:\Program Files\Git\bin\bash.exe'
    --login -c 'cd /c/Projects/pq_dSNARK && bash -n scripts/bootstrap.sh'`
    passed; `& 'C:\Program Files\Git\bin\bash.exe' --login -c 'cd
    /c/Projects/pq_dSNARK && scripts/bootstrap.sh --help'` displayed the
    expected Linux usage;
    `& 'C:\Program Files\Git\bin\bash.exe' --login -c 'cd /c/Projects/pq_dSNARK && scripts/bootstrap.sh'`
    reported missing `c-compiler pkg-config` and suggested `--install`, which
    exercises the Linux missing-dependency detection path from this Windows
    Git Bash environment;
  - missing-compiler failure-path check:
    `powershell -ExecutionPolicy Bypass -File .\scripts\run_benchmarks.ps1 -NRange "2..2" -Workers "1" -PcsQueries 1 -Repeats 1 -CompileFigures -FigureCompiler pdflatex -OutDir results`
    generated `results/bench-1780205578`, failed with a clear
    `pdflatex ... not found on PATH` message, and preserved metadata with
    `compile_figures_requested=true` and `compile_figures_succeeded=false`;
  - latest successful release benchmark command:
    `powershell -ExecutionPolicy Bypass -File .\scripts\run_benchmarks.ps1 -Release -NRange "2..2" -Workers "1,2" -PcsQueries 2 -Repeats 2 -OutDir results`
  - latest successful output directory: `results/bench-1780205602`;
  - all 8 positive rows verified and all 8 negative rows were rejected;
  - latest mean tiny-case scaling: R1CS `workers=2` speedup was `1.772x`;
    Plonkish `workers=2` speedup was `0.957x`; both are marked
    `plausible-prototype-overhead`.
- Paper benchmark preset pass:
  - `pq-experiments benchmark` now accepts `--paper-preset`, selecting the
    paper-facing default grid `n=2..6`, `workers=1,2,4`, `pcs_queries=3`, and
    `repeats=5`;
  - explicit `--sizes` / `--nv-range` / `--n-range`, `--workers`,
    `--pcs-queries`, and `--repeats` flags still override the preset defaults,
    so quick smoke tests can use the same preset path without running the full
    paper grid;
  - Windows exposes `-PaperPreset` and automatically builds/runs the release
    target for preset runs. Linux `scripts/run_benchmarks.sh --paper-preset`
    likewise switches to release mode while forwarding the preset flag to the
    Rust benchmark runner;
  - metadata and summaries now record `paper_preset=true/false`, so result
    directories can be traced back to the intended experiment profile;
  - validation:
    `cargo test -p pq-experiments`,
    `powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\run_benchmarks.ps1 -Help`,
    and `& 'C:\Program Files\Git\bin\bash.exe' -n scripts/run_benchmarks.sh`;
  - light preset override command:
    `powershell -ExecutionPolicy Bypass -File .\scripts\run_benchmarks.ps1 -PaperPreset -NRange "2..2" -Workers "1" -PcsQueries 1 -Repeats 1 -OutDir results`
  - output directory: `results/bench-1780206151`;
  - all 2 positive rows verified and all 2 negative rows were rejected, with
    `paper_preset=true` recorded in `metadata.json` and `summary.txt`.
- Benchmark acceptance hardening pass:
  - added a per-job benchmark acceptance check requiring exactly one verified
    positive proof and exactly one rejected tampered negative proof before a
    benchmark job can contribute source rows or figure data;
  - this prevents `source.csv`, `summary_stats.csv`, and paper figures from
    silently filtering out a failed positive verification or accepting a
    negative proof that should have been rejected;
  - changed `--figure-compiler auto` to prefer `tectonic` over `pdflatex` when
    both are present, because `tectonic` is the less interactive path for CI
    and fresh-machine script runs;
  - tightened Windows bootstrap detection so missing Visual Studio C++ Build
    Tools are reported as a missing dependency with a non-zero check-only exit
    status, rather than a successful warning-only path;
  - Linux bootstrap now tries a system `tectonic` package first for
    `--with-figures` and falls back to `cargo install tectonic --locked` when
    the package is unavailable;
  - individual PGFPlots metric charts now use the raw trial records through
    `summary_stats.csv`-equivalent aggregation and emit explicit y error bars,
    matching the grouped paper figure rather than plotting mean-only lines;
  - validation:
    `cargo test -p pq-experiments`,
    `powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\bootstrap.ps1`,
    `powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\bootstrap.ps1 -Help`,
    and `& 'C:\Program Files\Git\bin\bash.exe' -n scripts/bootstrap.sh`;
  - light benchmark revalidation command:
    `powershell -ExecutionPolicy Bypass -File .\scripts\run_benchmarks.ps1 -PaperPreset -NRange "2..2" -Workers "1" -PcsQueries 1 -Repeats 1 -OutDir results`
  - output directory: `results/bench-1780206932`;
  - all 2 positive rows verified and all 2 negative rows were rejected under
    the new hard acceptance gate, and the individual PGFPlots metric figures
    contain explicit y error bars.
- Network benchmark runner pass:
  - `pq-experiments benchmark` now accepts `--runner local|network|both`; local
    is the default, `network` runs each benchmark job through loopback TCP PCS
    workers and the same network-backed proof hooks used by the interactive
    `net-proof` path, and `both` records local and network rows in one result
    directory for direct figure comparison;
  - raw source rows and `summary_stats.csv` now include a `runner` column so
    local and network-backed measurements cannot be accidentally aggregated
    into the same statistical group;
  - `metadata.json` and `summary.txt` record `runner=...`; paper/SVG/PGFPlots
    chart series include the runner when it is not local and use distinct
    network colors (`pqGreen`/`pqPurple`) for R1CS/Plonkish network series;
  - benchmark metadata schema is bumped to `schema_version=3` because the raw
    and summary CSV schemas now include the `runner` dimension;
  - Windows exposes `-Runner local|network|both`, and the Linux benchmark
    wrapper documents/pass-throughs `--runner local|network|both`;
  - network benchmark smoke command:
    `powershell -ExecutionPolicy Bypass -File .\scripts\run_benchmarks.ps1 -Runner network -NRange "2..2" -Workers "1" -PcsQueries 1 -Repeats 1 -OutDir results`
  - output directory: `results/bench-1780207441`;
  - all 2 positive rows verified and all 2 negative rows were rejected; source
    rows recorded non-zero `network_bytes` (`5542` for R1CS rows, `1644` for
    Plonkish rows).
- Combined local/network benchmark validation:
  - command:
    `powershell -ExecutionPolicy Bypass -File .\scripts\run_benchmarks.ps1 -Runner both -NRange "2..2" -Workers "1" -PcsQueries 1 -Repeats 1 -OutDir results`
  - output directory: `results/bench-1780207948`;
  - source rows include local and network runner rows in the same
    `source.csv`; 4 positive rows verified and 4 tampered negative rows were
    rejected;
  - local rows have `network_bytes=0`, while network rows have non-zero
    `network_bytes` (`5542` for R1CS rows, `1644` for Plonkish rows);
  - `prove_time_by_size.tex` contains separate `R1CS`, `Plonkish`,
    `R1CS network`, and `Plonkish network` legend entries.
- Network-cost and runner-overhead figure pass:
  - benchmark result artifacts now include `network_bytes_by_size.svg/.tex`
    and `runner_overhead_by_size.svg/.tex`;
  - `network_bytes_by_size` plots the measured `network_bytes` field by
    circuit exponent, using the same raw-source/summary-statistics pipeline as
    the time and proof-size figures;
  - `runner_overhead_by_size` computes network-runner prover time divided by
    local-runner prover time for matching protocol, worker count, circuit size,
    and PCS query count, and includes a parity baseline at `1.0`;
  - added unit coverage for overhead-point construction and both SVG/PGFPlots
    overhead figure outputs.
  - validation command:
    `powershell -ExecutionPolicy Bypass -File .\scripts\run_benchmarks.ps1 -Runner both -NRange "2..2" -Workers "1" -PcsQueries 1 -Repeats 1 -OutDir results`
  - output directory: `results/bench-1780208305`;
  - metadata artifact list includes the new network-cost and overhead figures,
    with `schema_version=3`, `record_count=8`, `positive_verified=4`, and
    `negative_rejected=4`.
- R1CS Spark memory trace commitment pass:
  - each row/column/value Spark memory check now commits the Init, Read,
    Write, and Audit trace columns with Merkle PCS before deriving
    Fiat-Shamir sampled trace openings;
  - the sampled trace-opening count is controlled by the same
    `DistributedPcsParams`/`--pcs-queries` setting used by PCS sampling, with
    access traces capped to the real access count and padded only for Merkle
    commitment shape;
  - verification checks trace commitments, sampled Merkle openings, expected
    query indices, per-worker Init/Read/Write/Audit product digests, and the
    product multiset equality in one transcript order;
  - added R1CS tamper coverage for trace commitment roots, sampled domain
    openings, sampled access openings, memory metadata, worker digests, and
    product checks, plus helper-level Merkle path tampering, transcript-order
    binding checks, and a zero-nnz matrix case where access traces are padded
    for commitment shape but produce no access samples;
  - validation:
    `cargo test -p pq-piop-r1cs`,
    `cargo test --workspace`,
    `cargo clippy --workspace --all-targets -- -D warnings`,
    and `cargo fmt --check`;
  - light local/network benchmark revalidation:
    `powershell -ExecutionPolicy Bypass -File .\scripts\run_benchmarks.ps1 -Runner both -NRange "2..2" -Workers "1" -PcsQueries 1 -Repeats 1 -OutDir results`;
  - output directory: `results/bench-1780209283`; metadata reports
    `record_count=8`, `positive_verified=4`, `negative_rejected=4`, and all
    paper/SVG/PGFPlots artifacts, including network-cost and runner-overhead
    figures; source rows show the new R1CS proof size `33417` bytes under
    both local and network runners.
- Plonkish accumulator boundary transcript binding pass:
  - accumulator boundary openings now absorb the complete Merkle opening
    summaries, including path siblings and side bits, before downstream
    permutation accumulator subclaim and recurrence challenges are derived;
  - the previous boundary transcript material included only the boundary
    indices and values, while Merkle paths were verified but not part of the
    challenge stream;
  - top-level sampled accumulator recurrence queries are now absorbed into the
    Fiat-Shamir transcript after opening generation/verification, matching the
    existing treatment of accumulator residual and shift queries before the
    protocol moves on to the constraint-residual zerocheck;
  - added tests that reject a tampered boundary Merkle path and show the
    post-boundary transcript challenge changes when the path changes; the same
    test now also rejects a tampered recurrence query and checks that changing
    a recurrence-query Merkle path changes the transcript state;
  - validation:
    `cargo test -p pq-piop-plonkish permutation_accumulator_tampering_fails_verification -- --nocapture`
    and `cargo test -p pq-piop-plonkish`;
  - full regression after this pass:
    `cargo test --workspace`, `cargo clippy --workspace --all-targets -- -D warnings`,
    and `cargo fmt --check`;
  - light local/network benchmark revalidation:
    `powershell -ExecutionPolicy Bypass -File .\scripts\run_benchmarks.ps1 -Runner both -NRange "2..2" -Workers "1" -PcsQueries 1 -Repeats 1 -OutDir results`;
  - output directory: `results/bench-1780209918`; metadata reports
    `record_count=8`, `positive_verified=4`, and `negative_rejected=4`.
- Benchmark result manifest/checksum pass:
  - every benchmark result directory now includes `result_manifest.json`;
  - the manifest records `schema_version=1`, the run id, and SHA-256/byte-size
    entries for every generated artifact except the manifest itself, including
    `metadata.json`, source CSV/JSON, summary statistics, SVG previews,
    PGFPlots/TikZ figures, and the compiled PDF when figure compilation
    succeeds;
  - benchmark `metadata.json` now lists `result_manifest.json` and bumps its
    schema version to `4` so consumers can distinguish checksum-capable result
    directories from earlier benchmark outputs;
  - unit coverage creates a temporary synthetic result directory, writes all
    expected artifacts, checks manifest JSON shape, verifies checksums are
    emitted, and confirms the manifest does not recursively hash itself;
  - validation:
    `cargo test -p pq-experiments`, `cargo test --workspace`,
    `cargo clippy --workspace --all-targets -- -D warnings`, and
    `cargo fmt --check`;
  - added `pq-experiments verify-results --dir <result-dir> [--format json|csv]`;
    it parses `result_manifest.json`, rejects recursive manifest entries,
    recomputes SHA-256 and byte sizes for every listed artifact, and returns a
    machine-readable checked-file/checked-byte report;
  - `pq-experiments benchmark` now self-verifies the just-written manifest
    before reporting completion, and also verifies the partial no-PDF artifact
    set before returning a requested figure-compilation error;
  - added Windows and Linux helper entrypoints
    `scripts/verify_results.ps1` and `scripts/verify_results.sh`; both check
    for `cargo`, build `pq-experiments` in debug or release mode, and then run
    the verifier against the chosen result directory;
  - verification command on the latest manifest-bearing result:
    `cargo run -p pq-experiments -- verify-results --dir results\bench-1780213308 --format json`;
    output: `ok=true`, `run_id=1780213308`, `files_checked=19`,
    `bytes_checked=46118`;
  - script validation:
    `powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\verify_results.ps1 -Help`,
    `powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\verify_results.ps1 results\bench-1780213308 -Format json`,
    `& 'C:\Program Files\Git\bin\bash.exe' -n scripts/verify_results.sh`, and
    `& 'C:\Program Files\Git\bin\bash.exe' --login -c 'cd /c/Projects/pq_dSNARK && scripts/verify_results.sh results/bench-1780213308 --format csv'`;
  - light local/network benchmark revalidation:
    `powershell -ExecutionPolicy Bypass -File .\scripts\run_benchmarks.ps1 -Runner both -NRange "2..2" -Workers "1" -PcsQueries 1 -Repeats 1 -OutDir results`;
  - output directory: `results/bench-1780213308`; the benchmark runner printed
    `[benchmark] manifest verified: files=19 bytes=46118` before completion;
    `metadata.json` reports
    `schema_version=4`, `record_count=8`, `positive_verified=4`, and
    `negative_rejected=4`; `result_manifest.json` reports 19 hashed artifacts.
- Distributed PCS query-material transcript-binding pass:
  - full `DistributedOpening` and compact `CompactDistributedOpening` now absorb
    all sampled worker `QueryOpening` Merkle proofs into the Fiat-Shamir
    transcript before recording `transcript_state`;
  - compact openings also absorb every sampled combined-column/codeword
    `CompactQueryOpening`, including Merkle paths for the systematic,
    adjacent-parity, stride-parity, and blend-parity openings;
  - verification recomputes the same transcript binding before comparing
    `transcript_state`, so downstream protocol challenges cannot ignore or
    reorder sampled PCS query material;
  - regression coverage checks valid full/compact openings end with verifier
    transcript state equal to the proof state, query-opening path tampering
    changes the absorbed state, and direct `transcript_state` tampering is
    rejected;
  - validation:
    `cargo test -p pq-pcs opening_verifies`, `cargo test -p pq-pcs`,
    `cargo test --workspace`,
    `cargo clippy --workspace --all-targets -- -D warnings`,
    `cargo fmt --check`, and
    `powershell -ExecutionPolicy Bypass -File .\scripts\run_benchmarks.ps1 -Runner both -NRange "2..2" -Workers "1" -PcsQueries 1 -Repeats 1 -OutDir results`;
  - post-change benchmark output directory: `results/bench-1780211966`;
    all 4 positive rows verified, all 4 negative rows were rejected, and
    independent result verification reported `files_checked=19` and
    `bytes_checked=46105`.
- R1CS row-consistency query transcript-binding pass:
  - sampled row-consistency openings are now absorbed into the R1CS
    Fiat-Shamir transcript before the distributed Spark protocol derives its
    worker/matrix/row/column/value challenges;
  - the absorbed material includes every sampled row id, witness Merkle
    opening, `Az/Bz/Cz` opening, and distributed residual index opening;
  - verifier flow first checks each sampled row query against the committed
    witness/vector/residual commitments, then absorbs the same query material
    before `verify_distributed_spark`, keeping prover/verifier challenge order
    symmetric;
  - the Merkle-opening transcript helper was generalized from the Spark memory
    label to `r1cs-merkle-opening-proof-v1`, because it now binds both Spark
    memory trace openings and row-consistency openings;
  - regression coverage checks that tampering a row-query opening changes the
    transcript state and the subsequent Spark challenges while the untampered
    proof still verifies;
  - validation:
    `cargo test -p pq-piop-r1cs row_consistency_query_openings_bind_spark_challenges`,
    `cargo test -p pq-piop-r1cs`, `cargo test --workspace`,
    `cargo clippy --workspace --all-targets -- -D warnings`,
    `cargo fmt --check`, and
    `powershell -ExecutionPolicy Bypass -File .\scripts\run_benchmarks.ps1 -Runner both -NRange "2..2" -Workers "1" -PcsQueries 1 -Repeats 1 -OutDir results`;
  - post-change benchmark output directory: `results/bench-1780212396`;
    all 4 positive rows verified, all 4 negative rows were rejected, and
    independent result verification reported `files_checked=19` and
    `bytes_checked=46119`.
- Plonkish final consistency-query transcript-binding pass:
  - sampled gate and permutation consistency query openings are now absorbed
    into the Plonkish Fiat-Shamir transcript after they are generated by the
    prover and after they are verified by the verifier;
  - the absorbed material includes sampled gate row ids, `a/b/c` Merkle
    openings, gate residual openings, sampled permutation source/target ids,
    source/target value openings, permutation residual openings, and the
    distributed constraint-residual index openings;
  - this makes the final prover/verifier transcript states depend on the
    query-opening material, which matters when a caller composes this PIOP with
    later Fiat-Shamir challenges;
  - regression coverage checks prover and verifier transcript states match at
    the end of a valid proof, gate-query path tampering and permutation-query
    value tampering change the post-query challenge, and a tampered gate-query
    path is rejected by verification;
  - validation:
    `cargo test -p pq-piop-plonkish consistency_query_openings_bind_final_transcript_state`,
    `cargo test -p pq-piop-plonkish`, `cargo test --workspace`,
    `cargo clippy --workspace --all-targets -- -D warnings`,
    `cargo fmt --check`, and
    `powershell -ExecutionPolicy Bypass -File .\scripts\run_benchmarks.ps1 -Runner both -NRange "2..2" -Workers "1" -PcsQueries 1 -Repeats 1 -OutDir results`;
  - post-change benchmark output directory: `results/bench-1780212905`;
    all 4 positive rows verified, all 4 negative rows were rejected, and
    independent result verification reported `files_checked=19` and
    `bytes_checked=45827`.
- R1CS Spark product-multiset log-derivative hardening:
  - `pq-sumcheck::ProductMultisetEqualityProof` still keeps the compact random
    product check, but now also carries left/right rational log-derivative
    sumcheck proofs;
  - the prover derives the same product-multiset Fiat-Shamir challenge
    `gamma`, forms denominators `gamma + value` for the concatenated
    `Init || Write` and `Audit || Read` multisets, and proves the two
    log-derivative sums with `RationalSumcheckProof`;
  - the verifier reruns both embedded rational sumchecks and requires the two
    log-derivative claimed sums to match in addition to the existing product
    equality. This keeps the public-vector prototype path but gives the Spark
    memory equality check a real sumcheck subproof instead of only two product
    scalars;
  - R1CS proof-size accounting now measures the embedded rational sumcheck
    rounds dynamically for each Spark row/column/value memory check;
  - regression coverage rejects direct product tampering, rational
    log-derivative round tampering inside the R1CS Spark proof, changed
    public inputs, length tampering, and mismatched Fiat-Shamir challenges;
  - validation:
    `cargo test -p pq-sumcheck product_multiset`,
    `cargo test -p pq-piop-r1cs spark_memory`,
    `cargo test -p pq-piop-r1cs spark_memory_and_matrix_evaluation_tampering_fails`,
    `cargo test --workspace`,
    `cargo clippy --workspace --all-targets -- -D warnings`, and
    `cargo fmt --check`;
  - post-change benchmark smoke:
    `powershell -ExecutionPolicy Bypass -File .\scripts\run_benchmarks.ps1 -Runner both -NRange "2..2" -Workers "1" -PcsQueries 1 -Repeats 1 -OutDir results`;
    output directory `results/bench-1780214367`; all 4 positive rows verified,
    all 4 negative rows were rejected, and independent result verification
    reported `files_checked=19` and `bytes_checked=46133`;
  - at `n=2`, `workers=1`, `pcs_queries=1`, the measured proof bytes were
    R1CS `35865` and Plonkish `52530`. The R1CS increase is expected because
    the Spark row/column/value memory checks now include rational sumcheck
    subproofs; the Plonkish route was unaffected by this change.
- R1CS witness commitment consistency pass:
  - the R1CS proof now carries sampled consistency queries between the local
    Merkle witness commitment used by row-consistency checks and the
    distributed PCS witness commitment used by the Spartan-style inner
    product-sumcheck;
  - challenge derivation absorbs the local witness commitment, the distributed
    witness commitment, the witness domain length, the requested PCS query
    count, and the effective sampled query count. The resulting sampled
    witness indices are opened in both commitments and absorbed into the
    transcript before the residual commitment and all later R1CS/Spark
    challenges;
  - verification checks every sampled index, verifies the local Merkle opening,
    verifies the distributed index opening, and requires both opened witness
    values to match. This closes the previous prototype gap where the two
    witness commitments were shape-checked but not commitment-consistency
    sampled;
  - proof-size accounting now includes the sampled local witness openings and
    distributed witness index openings;
  - regression coverage checks valid prover/verifier transcript state
    equality, sampled query count, and rejection of tampered local witness
    opening values, tampered distributed witness opening values, and tampered
    sampled indices;
  - validation:
    `cargo test -p pq-piop-r1cs witness_consistency`,
    `cargo test -p pq-piop-r1cs inner_sumcheck_binds_witness_opening_and_matrix_projection`,
    `cargo test --workspace`,
    `cargo clippy --workspace --all-targets -- -D warnings`, and
    `cargo fmt --check`;
  - post-change benchmark smoke:
    `powershell -ExecutionPolicy Bypass -File .\scripts\run_benchmarks.ps1 -Runner both -NRange "2..2" -Workers "1" -PcsQueries 1 -Repeats 1 -OutDir results`;
    output directory `results/bench-1780214852`; all 4 positive rows verified,
    all 4 negative rows were rejected, and independent result verification
    reported `files_checked=19` and `bytes_checked=45995`;
  - at `n=2`, `workers=1`, `pcs_queries=1`, measured proof bytes were R1CS
    `36217` and Plonkish `52530`. The R1CS increase is expected because the
    proof now includes sampled witness consistency openings; the Plonkish route
    was unaffected.

- R1CS/Plonkish communication-byte accounting hardening:
  - added a public PCS helper for distributed index-opening communication
    bytes and routed both PIOP verifiers through crate-level
    `proof_communication_bytes` helpers;
  - R1CS `communication_bytes` now includes top-level distributed PCS
    openings plus sampled distributed witness-consistency index openings and
    sampled row residual index openings. Plonkish `communication_bytes` now
    includes the constraint-residual opening plus sampled gate and permutation
    distributed index openings;
  - experiment fallback metrics for rejected negative proofs now reuse the
    same R1CS and Plonkish communication helpers as successful verification,
    preventing source CSV/JSON undercounting on failure rows;
  - regression coverage:
    `cargo test -p pq-piop-r1cs communication_accounting_includes_sampled_distributed_index_openings`,
    `cargo test -p pq-piop-plonkish plonkish_opening_accounting_distinguishes_full_and_compact`,
    and `cargo test -p pq-experiments fallback_metrics_include`;
  - validation:
    `cargo fmt --check`,
    `cargo test --workspace`,
    `cargo clippy --workspace --all-targets -- -D warnings`,
    `powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\bootstrap.ps1 -Help`,
    Git Bash syntax checks for `scripts/bootstrap.sh`,
    `scripts/run_benchmarks.sh`, and `scripts/verify_results.sh`;
  - post-change benchmark smoke:
    `powershell -ExecutionPolicy Bypass -File .\scripts\run_benchmarks.ps1 -Runner both -NRange "2..2" -Workers "1" -PcsQueries 1 -Repeats 1 -OutDir results`;
    output directory `results/bench-1780215514`; all 4 positive rows verified,
    all 4 negative rows were rejected, and result verification reported
    `files_checked=19` and `bytes_checked=46135`;
  - at `n=2`, `workers=1`, `pcs_queries=1`, measured communication bytes are
    now R1CS `24985` and Plonkish `8339`, reflecting the sampled distributed
    index openings that were previously omitted from the benchmark accounting.

- Network PCS worker-resident opening hardening:
  - subagent audit flagged that the TCP PCS worker `PcsOpen` request was
    resending the full row back to the worker, so the opening path was not
    genuinely worker-resident after `PcsCommit`;
  - changed `pq-net::Message::PcsOpen` and `pcs_worker_open` to carry only the
    PCS session, worker id, shard start, and query indices. The worker now
    stores `WorkerShard { start, values, commitment }` when it accepts
    `PcsCommit`, and later opens from that stored shard;
  - duplicate PCS commit sessions are rejected through `HashMap::entry`
    without replacing the original shard. Regression coverage reopens the
    original shard after a rejected duplicate commit to check that the stored
    values were not overwritten;
  - updated `NetworkPcsClient` to remember distributed commitment roots mapped
    to the commit session, then use that session for compact opening worker
    callbacks. Network opening byte accounting no longer includes a resent row
    during opening, because row transfer occurs only at commit time in this
    prototype;
  - replaced remaining hand-written `network_bytes` formulas for PCS commit and
    open with `pq-net` wire-byte helpers that call the actual text codec and add
    the 4-byte frame prefix for both requests and responses;
  - deliberately did not add the proposed Plonkish equality
    `virtual_gate_value == gate_residual.folding.final_value`: for an MLE of
    row-wise gate residuals, the random-point evaluation is not generally equal
    to evaluating the gate expression on independently opened witness MLEs
    except in special multilinear-compatible cases. Adding that check would
    reject valid instances rather than strengthen the protocol;
  - targeted validation:
    `cargo test -p pq-net worker_stores_committed_pcs_shard_and_opens_by_session`,
    `cargo test -p pq-net codec_round_trips_escaped_payloads`,
    `cargo test -p pq-experiments r1cs_network_hook_produces_compact_pcs_openings`,
    and `cargo test -p pq-experiments plonkish_network_hook_produces_compact_pcs_opening`;
  - package/workspace validation:
    `cargo test -p pq-net -p pq-experiments`,
    `cargo test --workspace`,
    `cargo clippy --workspace --all-targets -- -D warnings`, and
    `cargo fmt --check`;
  - post-change benchmark smoke:
    `powershell -ExecutionPolicy Bypass -File .\scripts\run_benchmarks.ps1 -Runner both -NRange "2..2" -Workers "1" -PcsQueries 1 -Repeats 1 -OutDir results`;
    output directory `results/bench-1780219239`; all 4 positive rows verified,
    all 4 negative rows were rejected, and independent result verification
    reported `files_checked=19` and `bytes_checked=46981`;
  - at `n=2`, `workers=1`, `pcs_queries=1`, measured network bytes are now
    R1CS `9554` and Plonkish `2650` for network rows. These values are larger
    than the earlier hand estimate because they now include actual encoded frame
    lengths for both request and response payloads.

- Plonkish benchmark negative coverage hardening:
  - subagent audit flagged that Plonkish benchmark negatives only exercised one
    accumulator-query mutation. The negative Plonkish case now verifies five
    tampered proof variants and fails the run if any variant verifies:
    accumulator recurrence, gate query, permutation query, gate subclaim, and
    constraint PCS opening;
  - the CSV/JSON schema remains one `case=negative` row per benchmark job, but
    `failure_reason` records the rejection reason for each tamper variant. This
    keeps scaling aggregation stable while broadening negative correctness
    coverage;
  - regression coverage:
    `cargo test -p pq-experiments plonkish_negative_variants_cover_multiple_failure_surfaces`,
    `cargo test -p pq-experiments plonkish_rejected_fallback_metrics_include_sampled_index_openings`,
    and `cargo test -p pq-experiments loopback_network_proof_paths_produce_positive_and_negative_records`;
  - validation also reran:
    `cargo test -p pq-experiments`,
    `cargo test --workspace`,
    `cargo clippy --workspace --all-targets -- -D warnings`, and
    `cargo fmt --check`;
  - the final smoke benchmark in `results/bench-1780219239` records Plonkish
    negative failure reasons as
    `accumulator-recurrence:InvalidProof;gate-query:InvalidProof;permutation-query:InvalidProof;gate-subclaim:InvalidProof;constraint-pcs-opening:InvalidProof`
    for both local and network runners.

- Fresh-device Rust toolchain pin hardening:
  - fixed a bootstrap mismatch: the workspace pins Rust through
    `rust-toolchain.toml` (`1.95.0` with `rustfmt` and `clippy`), while the
    fresh-machine bootstrap scripts previously installed/check-reported only
    `stable`;
  - `scripts/bootstrap.ps1` and `scripts/bootstrap.sh` now parse the pinned
    channel from `rust-toolchain.toml`, detect missing pinned toolchains and
    missing `rustfmt`/`clippy` components even when some other `cargo`/`rustc`
    is already on PATH, and install the pinned channel/components in
    `-Install` / `--install` mode;
  - validation:
    `powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\bootstrap.ps1`,
    `powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\bootstrap.ps1 -Help`,
    `& 'C:\Program Files\Git\bin\bash.exe' -n scripts/bootstrap.sh`,
    `& 'C:\Program Files\Git\bin\bash.exe' --login -c 'cd /c/Projects/pq_dSNARK && scripts/bootstrap.sh --help'`,
    and a Git Bash no-install detection run that exited through the expected
    missing-dependency path for `c-compiler pkg-config` on this Windows host.

- R1CS Spark worker-provider/network task and benchmark result strictness:
  - added `R1csProverHooks` and
    `prove_r1cs_with_pcs_and_spark_hooks`, so the R1CS prover can now source
    Spark shard fingerprints and matrix-evaluation claims through a worker
    provider instead of hard-wiring all Spark shard work inside the master
    path. The default local route uses an in-process provider, and the network
    R1CS route now uses a `pq-net` Spark claim request per partition;
  - `pq-net` now exposes `R1csSparkClaim`, `R1csSparkClaimResult`, and
    `r1cs_spark_worker_claim`. Each worker reconstructs its partition-local
    sparse R1CS shard, computes `compute_spark_worker_shard_claim` in the
    worker process, and returns the real Spark fingerprint plus per-matrix
    evaluation claims. The experiment network byte counter includes the encoded
    Spark request and response frames;
  - added regression coverage that confirms the prover calls one Spark provider
    per partition, carries two worker matrix-evaluation claims per matrix in a
    two-worker sample, verifies the resulting proof, and rejects malformed
    worker claim ranges before accepting a proof. Network tests additionally
    check that a TCP worker's Spark claim matches the local reference claim and
    that the network R1CS proof path carries two worker Spark evaluations per
    matrix in a two-worker sample;
  - benchmark result directories now use nanosecond run ids and `create_dir`
    for the final `bench-<run-id>` path, so a stale or partially reused
    directory is rejected instead of silently reused. `verify-results` now also
    rejects extra top-level artifacts and subdirectories, not just missing or
    tampered manifest entries;
  - README examples now include explicit Linux and Windows paper-facing commands
    with `runner=both` and figure compilation, and clarify that the grouped
    `paper_figures.tex` covers prove time, verify time, proof size, and worker
    scaling while network bytes and runner overhead remain separate paper-facing
    figures;
  - validation:
    `cargo test -p pq-piop-r1cs r1cs_spark_worker_provider`,
    `cargo test -p pq-net worker_computes_r1cs_spark_claim_for_partition`,
    `cargo test -p pq-experiments r1cs_network_hook_produces_compact_pcs_openings`,
    `cargo test -p pq-net`,
    `cargo test -p pq-piop-r1cs`,
    `cargo test -p pq-experiments benchmark_charts_are_svg_and_pgfplots_with_real_series`,
    `cargo test -p pq-experiments`,
    `cargo clippy --workspace --all-targets -- -D warnings`,
    `cargo test --workspace`, and `cargo fmt --check`;
  - post-change benchmark smoke:
    `powershell -ExecutionPolicy Bypass -File .\scripts\run_benchmarks.ps1 -Runner both -NRange "2..2" -Workers "1" -PcsQueries 1 -Repeats 1 -OutDir results`;
    output directory `results/bench-1780221020012397100`; all 4 positive rows
    verified, all 4 negative rows were rejected, and independent
    `verify_results.ps1` reported `files_checked=19`, `bytes_checked=46718`,
    and `run_id=1780221020012397100`;
  - measured debug smoke metrics at `n=2`, `workers=1`, `pcs_queries=1`:
    local R1CS positive prove/verify `1460.459/1498.464 ms`, local Plonkish
    positive prove/verify `1478.338/1418.062 ms`, network R1CS positive
    `network_bytes=10043`, network Plonkish positive `network_bytes=2650`.
    The R1CS network byte count is higher than the previous PCS-only network
    path because it now includes real Spark claim request/response frames.
    Since this smoke uses only `workers=1`, speedup versus the baseline is
    correctly `1.000`; it is a correctness/output-integrity check rather than
    a scaling claim.

- Benchmark provenance metadata:
  - benchmark `metadata.json` schema is now `5` and includes a `provenance`
    block for reproducibility: current working directory, `RUSTFLAGS`,
    `CARGO_TARGET_DIR`, git commit/branch/dirty state, SHA-256 of the git
    status text, full `rustc --version --verbose`, full
    `cargo --version --verbose`, `Cargo.lock` SHA-256,
    `rust-toolchain.toml` SHA-256, and pinned third-party Spartan2/HyperPlonk
    commit ids when those repositories exist;
  - third-party commit capture uses a command-local
    `git -c safe.directory=<repo>` invocation so Windows sandbox ownership
    checks do not require modifying global git configuration;
  - `summary.txt` now repeats the high-signal provenance fields in single-line
    key/value form while keeping the complete multi-line version strings in
    `metadata.json`;
  - validation:
    `cargo test -p pq-experiments benchmark_charts_are_svg_and_pgfplots_with_real_series`,
    `cargo test -p pq-experiments`,
    `cargo test --workspace`,
    `cargo clippy --workspace --all-targets -- -D warnings`,
    `cargo clippy -p pq-experiments --all-targets -- -D warnings`, and
    `cargo fmt --check`;
  - post-change benchmark smoke:
    `powershell -ExecutionPolicy Bypass -File .\scripts\run_benchmarks.ps1 -Runner both -NRange "2..2" -Workers "1" -PcsQueries 1 -Repeats 1 -OutDir results`;
    output directory `results/bench-1780221621152427000`; all 4 positive rows
    verified, all 4 negative rows were rejected, and independent
    `verify_results.ps1` reported `files_checked=19`, `bytes_checked=48340`,
    and `run_id=1780221621152427000`;
  - latest provenance evidence in that result:
    `schema_version=5`,
    `git_commit=54bb96c23e85a58d0c29045c69b4e1b8f5d8b0ab`,
    `git_dirty=true`,
    `rustc 1.95.0 (59807616e 2026-04-14)`,
    `cargo 1.95.0 (f2d3ce0bd 2026-03-21)`,
    `Cargo.lock` hash
    `b2b0488bfce55e6d967530c436dbf47da4f8ac05dd83b7e1bfb7f12d1ca368c2`,
    `rust-toolchain.toml` hash
    `d96b583acf5afe7ef70ee89e2c5ed92a188611fd8f2d49f8e180480264ca1b8c`,
    Spartan2 commit `0d4f1409e8f30536b8b25ed3f81bc446ed717e61`, and
    HyperPlonk commit `2a3b55c97ad8a5d6627108a2e7def2aeccb7f3b9`;
  - measured debug smoke metrics at `n=2`, `workers=1`, `pcs_queries=1`:
    local R1CS positive prove/verify `1488.944/1440.243 ms`, local Plonkish
    positive prove/verify `1335.727/1300.052 ms`, network R1CS positive
    `network_bytes=10043`, network Plonkish positive `network_bytes=2650`.
    With only one worker, the scaling section correctly reports speedup
    `1.000`, so this run is used as a provenance/output-integrity check rather
    than a speedup claim.

- Fresh-device bootstrap hardening for figure-capable experiments:
  - Linux bootstrap now fails with a concrete message when system package
    installation needs `sudo` but neither root nor `sudo` is available. The
    package-manager paths remain non-interactive: apt uses
    `DEBIAN_FRONTEND=noninteractive`, pacman uses `--noconfirm`, and zypper
    uses `--non-interactive`;
  - `--with-figures` / `-WithFigures` now checks whether `pdflatex` can
    actually find `pgfplots.sty`, `tikz.sty`, and `standalone.cls`; otherwise
    the scripts install/use `tectonic`. This avoids accepting a partial TeX
    install that cannot compile `paper_figures_standalone.tex`;
  - Linux `install_tectonic` now bootstraps Rust, ensures the pinned toolchain,
    and checks Cargo availability before running `cargo install tectonic
    --locked`;
  - README now documents that figure bootstrap requires a figure-capable
    compiler path, not just any `pdflatex` executable;
  - validation:
    `powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\bootstrap.ps1 -Help`,
    `& 'C:\Program Files\Git\bin\bash.exe' -n scripts/bootstrap.sh`,
    `& 'C:\Program Files\Git\bin\bash.exe' --login -c 'cd /c/Projects/pq_dSNARK && scripts/bootstrap.sh --help'`,
    a Windows no-install `-WithFigures` check that reported
    `pdflatex-or-tectonic` as missing and exited through the expected path,
    a Git Bash/Linux `--with-figures` no-install check that reported
    `c-compiler pkg-config pdflatex-or-tectonic`, and a Git Bash/Linux
    required-tool check that reported `c-compiler pkg-config`;
  - Rust quality validation after the script changes:
    `cargo fmt --check`, `cargo clippy --workspace --all-targets -- -D warnings`,
    and `cargo test --workspace`;
  - post-change benchmark smoke:
    `powershell -ExecutionPolicy Bypass -File .\scripts\run_benchmarks.ps1 -Runner both -NRange "2..2" -Workers "1" -PcsQueries 1 -Repeats 1 -OutDir results`;
    output directory `results/bench-1780221902715962200`; all 4 positive rows
    verified, all 4 negative rows were rejected, and independent
    `verify_results.ps1` reported `files_checked=19`, `bytes_checked=48058`,
    and `run_id=1780221902715962200`;
  - measured debug smoke metrics at `n=2`, `workers=1`, `pcs_queries=1`:
    local R1CS positive prove/verify `1498.516/1457.365 ms`, local Plonkish
    positive prove/verify `1358.304/1372.289 ms`, network R1CS positive
    `network_bytes=10043`, and network Plonkish positive `network_bytes=2650`.
    The one-worker scaling baseline remains `1.000`, so this is a script and
    output-integrity check rather than a distributed speedup claim.

- Unified experiment entrypoint and fixed per-worker core allocation:
  - public experiment execution is now documented through exactly one Linux
    entrypoint, `scripts/run_experiments.sh`, and one Windows entrypoint,
    `scripts\run_experiments.ps1`. Both expose `bootstrap`, `benchmark`,
    `verify-results`, `interactive`, direct local protocol runs, `net-demo`,
    manual `worker`/`master`, and `net-proof` modes. The older helper scripts
    remain implementation wrappers but are no longer the documented user
    surface;
  - benchmark runs with `runner=network` or `runner=both` and multiple worker
    counts now compute a strict core allocation before launching distributed
    subexperiments: `cores_per_worker = floor(host_logical_cores /
    max(workers))`. Every worker in every distributed subexperiment receives
    that fixed core count, so lower-worker runs use fewer total cores instead
    of silently consuming the whole host;
  - Linux uses `taskset -c <core-list>` for affinity-controlled worker
    processes. Windows uses hidden PowerShell child processes and
    `ProcessorAffinity` masks; the prototype fails clearly if the requested
    Windows logical-core ids exceed the supported mask range;
  - Rust benchmark metadata advanced to `schema_version=6` and records
    `core_allocation` with `host_logical_cores`, `max_workers`,
    `cores_per_worker`, `affinity_mode`, and each worker's logical core ids.
    `source.csv` and `source.json` also include `host_logical_cores`,
    `cores_per_worker`, and `core_affinity` per row;
  - validation:
    `cargo check -p pq-experiments`,
    `powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\run_experiments.ps1 -Help`,
    `powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\run_benchmarks.ps1 -Help`,
    `& 'C:\Program Files\Git\bin\bash.exe' -n scripts/run_experiments.sh`,
    `& 'C:\Program Files\Git\bin\bash.exe' -n scripts/run_benchmarks.sh`, and
    `& 'C:\Program Files\Git\bin\bash.exe' --login -c 'cd /c/Projects/pq_dSNARK && scripts/run_experiments.sh --help'`;
  - end-to-end Windows unified-entry benchmark:
    `powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\run_experiments.ps1 benchmark -Runner network -NRange "2..2" -Workers "1,2" -PcsQueries 1 -Repeats 1 -OutDir results`;
    output directory `results/bench-1780222617840798600`; all 4 positive rows
    verified, all 4 negative rows were rejected, and unified
    `run_experiments.ps1 verify-results results\bench-1780222617840798600 -Format json`
    reported `files_checked=19`, `bytes_checked=49232`, and
    `run_id=1780222617840798600`;
  - measured core allocation evidence in that run:
    `host_logical_cores=20`, `max_workers=2`, `cores_per_worker=10`,
    `affinity_mode=windows-powershell-processor-affinity`, and
    `worker_core_ids=[[0,1,2,3,4,5,6,7,8,9],[10,11,12,13,14,15,16,17,18,19]]`.

- HTML experiment overview artifact:
  - every benchmark result directory now includes `overview.html` as a
    manifest-checked artifact alongside raw `source.csv`/`source.json`,
    `summary_stats.csv`, SVG previews, PGFPlots/TikZ figures, metadata, and
    the manifest;
  - the overview is a static, self-contained dashboard with no external CDN
    dependency. It summarizes run id, correctness counts, selected runner,
    `nv` powers, worker counts, PCS query count, build profile, optional
    figure-PDF state, fixed core allocation, chart previews, scaling assessment
    against the `workers=1` baseline, summary statistics, and links to all
    generated artifacts;
  - the scaling assessment stays conservative: it reports ideal-linear
    comparison and labels high prototype overhead or suspicious superlinear
    results, but it never fabricates speedup when only `workers=1` is present;
  - targeted validation:
    `cargo check -p pq-experiments` and
    `cargo test -p pq-experiments benchmark_charts_are_svg_and_pgfplots_with_real_series`;
  - end-to-end unified-entry benchmark after adding the HTML overview:
    `powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\run_experiments.ps1 benchmark -Runner network -NRange "2..2" -Workers "1,2" -PcsQueries 1 -Repeats 1 -OutDir results`;
    output directory `results/bench-1780223261809512000`; the manifest now
    verifies 20 artifacts and includes `overview.html`; unified
    `run_experiments.ps1 verify-results results\bench-1780223261809512000 -Format json`
    reported `files_checked=20`, `bytes_checked=60037`, and
    `run_id=1780223261809512000`;
  - actual debug smoke results: all 4 positive rows verified and all 4
    negative rows were rejected. The fixed Windows allocation was
    `host_logical_cores=20`, `max_workers=2`, `cores_per_worker=10`.
    At `n=2`, R1CS network `workers=2` speedup was `1.084` with efficiency
    `0.542`; Plonkish network `workers=2` speedup was `1.019` with efficiency
    `0.510`. Both are below the ideal linear bound and match expected
    correctness-prototype overhead rather than indicating a protocol shortcut
    or suspicious fitted speedup.

- Repository hygiene for clone-and-run use:
  - added a root `.gitignore` that excludes Rust build output and generated
    `results/bench-*` directories while keeping `results/README.md` and the
    curated `results/release_results/` tree;
  - added `results/README.md` documenting the contents and validation command
    for self-contained benchmark outputs;
  - added `results/release_results/README.md`; this is the explicit location
    for manually copying benchmark result directories that should be published
    with the GitHub repository, while scratch runs remain ignored;
  - README now has a short fresh-clone fast path for Windows and Linux using
    the unified `run_experiments` entrypoints, including a minimal benchmark
    command and the expected `overview.html` inspection step;
  - verified `.gitignore` behavior: `results/bench-1780223261809512000`
    scratch artifacts are ignored, while `results/release_results/` remains
    visible for curated publication results.

- GitHub release-readiness metadata:
  - added root `LICENSE-MIT` and `LICENSE-APACHE` to match the workspace
    `MIT OR Apache-2.0` license declaration;
  - added `.github/workflows/ci.yml` with Linux and Windows jobs covering
    `cargo fmt --check`, `cargo clippy --workspace --all-targets -- -D warnings`,
    `cargo test --workspace`, OS-specific script help checks, Linux shell syntax
    checks, and a lightweight Linux benchmark smoke that verifies both
    `overview.html` and `result_manifest.json`;
  - README now explicitly states that `run_experiments` is the integrated
    user-facing surface while `run_benchmarks.sh` and `run_benchmarks.ps1`
    remain the two OS-specific benchmark script entrypoints used underneath and
    available for advanced/CI usage.

- HTML overview render validation:
  - Node REPL and bundled Node Playwright paths were not usable in this
    Windows sandbox (`node_repl` failed with a sandbox spawn error, and bundled
    Node had a `playwright` package without `playwright-core`);
  - used installed Microsoft Edge headless mode with a dedicated temporary
    profile under `target/` and `--no-sandbox` to render
    `results/bench-1780223261809512000/overview.html`;
  - screenshot output `target/overview-render-check.png` was produced
    successfully. Visual inspection showed the dashboard hero, correctness
    cards, configuration/core-allocation panel, and SVG figure previews render
    coherently without visible overlap at `1440x1400`.

- Benchmark trust gate hardening:
  - added `verify-results --paper-quality` in `pq-experiments` and forwarded it
    through both `scripts/run_experiments.sh verify-results` and
    `scripts\run_experiments.ps1 verify-results`;
  - the ordinary verifier still recomputes the `result_manifest.json`
    SHA-256/byte-size checks and rejects missing, modified, extra, or
    non-file artifacts;
  - the paper-quality verifier now additionally parses `metadata.json` and
    requires `schema_version=6`, `build_profile=release`, `runner=both`, the
    full `n=2..6` paper preset grid, workers `[1,2,4]`, at least the paper
    repeat/query counts, compiled `paper_figures_standalone.pdf`, and exact
    positive/negative record counts;
  - documented that `--release` / `-Release` only chooses the verifier binary
    build profile, while `--paper-quality` / `-PaperQuality` is the actual
    publication-quality result gate;
  - investigated a proposed Plonkish random-point residual equality check and
    rejected it after a smoke benchmark showed it incorrectly rejects valid
    proofs: the virtual gate polynomial formed from individual column MLEs is
    not equal away from Boolean rows to the MLE of the row residual column;
    the implementation keeps row-level binding through sampled gate queries
    against the committed residual columns and records this invariant in code;
  - validation run: ordinary verification still accepts
    `results/bench-1780223261809512000` (`files_checked=20`,
    `bytes_checked=60037`), while the same debug/lightweight run is rejected by
    `-PaperQuality` with `build_profile expected release`;
  - after rejecting the invalid Plonkish random-point residual equality check,
    reran a current smoke benchmark:
    `scripts\run_experiments.ps1 benchmark -Runner local -NRange "2..2" -Workers "1" -PcsQueries 1 -Repeats 1 -OutDir results`;
    it produced `results/bench-1780224312262312900` with 4 records, 2 verified
    positive cases, 2 rejected negative cases, `overview.html`, and a verified
    manifest (`files_checked=20`, `bytes_checked=49190`). The same run is
    intentionally rejected by `-PaperQuality` because it is debug/local/smoke
    evidence rather than a release/full-grid benchmark;
  - ran a release benchmark with both local and network runners:
    `scripts\run_experiments.ps1 benchmark -Release -Runner both -NRange "2..2" -Workers "1,2" -PcsQueries 1 -Repeats 1 -OutDir results`;
    it produced `results/bench-1780224426296880800` with 16 source rows,
    8/8 positive cases verified, 8/8 negative cases rejected, release
    provenance, `overview.html`, SVG/TikZ figure artifacts, and a verified
    manifest (`files_checked=20`, `bytes_checked=80699`);
  - the release smoke recorded fixed-core network scaling metadata:
    `host_logical_cores=20`, `max_workers=2`, `cores_per_worker=10`, and
    `windows-powershell-processor-affinity`, so workers=1 and workers=2
    network rows use the same per-worker core budget;
  - release smoke scaling matched the expected prototype regime rather than a
    suspicious superlinear result: local R1CS workers=2 speedup `1.107`,
    local Plonkish `1.036`, network R1CS `1.039`, and network Plonkish `1.052`.
    The summary classifies these as plausible prototype overhead because the
    circuit is tiny and transcript/verification/oracle consistency costs remain
    mostly serial;
  - verified that the release smoke does not pass the publication gate:
    `-PaperQuality` rejects it with `paper_preset expected true`, as intended
    for a short release smoke that is not the full paper preset with compiled
    figures;
  - rendered `results/bench-1780224426296880800/overview.html` with Microsoft
    Edge headless to `target/overview-release-smoke-1780224484532.png`; visual
    inspection showed the benchmark dashboard, correctness cards, core
    allocation panel, and paper figure previews render coherently without blank
    charts or overlapping text at `1440x1400`;
  - README and the two `results/` README files now distinguish smoke/release
    commands from the full paper-quality command:
    `benchmark --paper-preset --runner both --compile-figures --figure-compiler auto`.
  - targeted tests and checks passed:
    `cargo test -p pq-piop-plonkish gate_random_point_subclaim_tampering_fails_verification`,
    `cargo test -p pq-experiments verify_results`,
    `cargo test -p pq-experiments benchmark_charts_are_svg_and_pgfplots_with_real_series`,
    `cargo clippy -p pq-experiments --all-targets -- -D warnings`,
    `cargo clippy -p pq-piop-plonkish --all-targets -- -D warnings`, and
    `cargo fmt --check`.

- Benchmark semantics correction and wall-clock accounting:
  - corrected `pq-experiments benchmark` to be a performance benchmark rather
    than a mixed correctness/performance run. Each atomic benchmark row is now
    exactly one positive end-to-end `prove` plus `verify` for one circuit
    configuration. Negative/tampered checks remain in unit tests, integration
    tests, and ordinary experiment commands with `--case negative|both`; they
    are no longer emitted into benchmark `source.csv`;
  - `--repeats` is now compatibility-parsed but rejected unless it is `1`.
    The Windows/Linux benchmark wrappers no longer expose repeat flags, and
    `-MediumPreset` / `--medium-preset` means release, `runner=both`,
    `n=2..5`, workers `1,2,4`, `pcs_queries=3`, one positive prove+verify per
    configuration;
  - benchmark metadata advanced to `schema_version=7`. Result directories now
    include `phase_timing.csv` and `phase_timing.json`, and the manifest checks
    both. These files record setup, reusable network worker-pool lifecycle,
    each benchmark job's wall time, recorded prove/verify spans, inferred
    overhead, artifact generation, manifest writing, and total binary wall
    clock;
  - network benchmark worker processes are now pooled per worker count inside a
    benchmark run instead of being respawned for every circuit. Long-lived
    worker reuse initially exposed a real PCS session collision; network PCS
    session prefixes now include `size`, `workers`, and `pcs_queries` to avoid
    cross-circuit state collisions when workers are reused;
  - the previous medium run `results/bench-1780229021324851700` was diagnosed
    as the wrong benchmark shape: it had 192 rows because it included 96
    positive and 96 negative rows, with `repeats=2`. Its recorded protocol time
    was `386.4s` (`prove=153.8s`, `verify=232.6s`), plus roughly `62s` of
    build/wrapper/artifact overhead. That explains the long wall clock despite
    `n=2..5`: it was running correctness negative paths and repeats, not just
    performance rows;
  - after the correction, the current medium PC benchmark is
    `results/bench-1780230517432549800`. It uses `n=2..5`, workers `1,2,4`,
    `runner=both`, `pcs_queries=3`, release build, fixed Windows core
    allocation `host_logical_cores=20`, `max_workers=4`, `cores_per_worker=5`,
    and `windows-powershell-processor-affinity`;
  - current medium result summary: `records=48`, `positive_verified=48`,
    `negative_rejected=0`, manifest `files_checked=22`,
    `bytes_checked=181139`. `phase_timing.csv` reports binary wall clock
    `81.763s`, jobs `77.534s`, recorded prove `39.197s`, recorded verify
    `38.327s`, job overhead `0.010s`, reusable network worker-pool lifecycle
    `3.747s`, and setup/artifact/manifest work `0.480s`. The outer PowerShell
    command took about `89.1s`, including a `5.58s` release rebuild and wrapper
    overhead;
  - current medium per-route measured protocol time from `source.csv`:
    local R1CS `17.350s`, local Plonkish `21.388s`, network R1CS `17.450s`,
    and network Plonkish `21.336s`;
  - ordinary result verification passed:
    `powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\run_experiments.ps1 verify-results results\bench-1780230517432549800 -Release -Format json`.
    The stricter `-PaperQuality` gate deliberately rejects this medium PC run
    with `paper_preset expected true`, because it is not the full paper preset
    with compiled figures;
  - validation after the benchmark changes:
    `cargo fmt --check`,
    `cargo clippy -p pq-experiments --all-targets -- -D warnings`,
    `cargo test -p pq-experiments`,
    `& 'C:\Program Files\Git\bin\bash.exe' -n scripts/run_benchmarks.sh scripts/run_experiments.sh scripts/verify_results.sh scripts/bootstrap.sh`,
    `powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\run_benchmarks.ps1 -Help`,
    and
    `powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\run_experiments.ps1 -Help`.

- Worker-scaling interpretation update:
  - the screenshot based on `results/bench-1780229021324851700` should not be
    used as performance-scaling evidence because that run mixed positive and
    negative correctness paths and used `repeats=2`;
  - the corrected performance-only medium run
    `results/bench-1780230517432549800` still shows near-flat speedup at the
    largest tested circuit (`n=5`, `nv=32`): network R1CS speedup is `1.081x`
    at two workers and `1.015x` at four workers, while network Plonkish is
    `1.020x` and `1.059x`. This is therefore not just a plotting bug;
  - the dashed worker-scaling reference in future figures is now described as a
    perfect-linear upper bound rather than a predicted scaling curve. The
    current correctness prototype keeps substantial work on the master side,
    including transcript, verification, consistency checks, and PCS
    orchestration. The TCP PCS client also dispatches worker commit/open calls
    sequentially, so the current implementation is expected to sit far below
    the perfect-linear ceiling on small PC-scale circuits;
  - updated generated report text, SVG legend text, and PGFPlots legend text to
    use `Perfect upper bound` for this line.

- Network worker dispatch parallelization:
  - `pq-net::TcpWorkerRuntime::dispatch_round` now sends public-coin round
    payloads to all configured worker addresses concurrently and then returns
    replies in the original address order. This preserves caller-visible
    transcript order while removing a purely transport-layer serial loop;
  - `pq-net::TcpWorkerRuntime::shutdown` now sends worker shutdown requests
    concurrently so multi-worker benchmark teardown is not artificially
    serialized;
  - `pq-experiments::NetworkPcsClient::commit` now dispatches PCS shard
    commitments concurrently across worker partitions, aggregates byte counts,
    and then reorders commitments by worker id before calling
    `DistributedBrakedown::commit_from_worker_commitments`. This keeps the
    distributed commitment deterministic and does not change PCS transcript
    semantics;
  - added a `pq-net` regression test that starts three loopback workers and
    checks that parallel round dispatch still preserves address/worker order;
  - targeted validation after this change:
    `cargo fmt --check`,
    `cargo test -p pq-net tcp_worker_parallel_round_preserves_address_order`,
    `cargo test -p pq-experiments r1cs_network_hook_produces_compact_pcs_openings`,
    and
    `cargo test -p pq-experiments plonkish_network_hook_produces_compact_pcs_opening`;
  - post-change lightweight network release benchmark:
    `powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\run_experiments.ps1 benchmark -Runner network -NRange "2..3" -Workers "1,2,4" -PcsQueries 2 -OutDir results -Release`;
    output directory `results/bench-1780236398908666500`; all `12`
    performance rows verified, manifest verification passed with
    `files_checked=22` and `bytes_checked=87082`;
  - the light benchmark recorded binary wall clock `11.702s` after the release
    build, with recorded prove `3.785s`, recorded verify `3.680s`, reusable
    network worker-pool lifecycle `3.759s`, and source/chart/final artifact
    work `0.475s`;
  - at the largest tested size in that light run (`n=3`, `nv=8`), network R1CS
    speedup improved modestly from the one-worker baseline to `1.104x` at two
    workers and `1.107x` at four workers. Network Plonkish was `1.069x` at two
    workers and `0.924x` at four workers, showing that parallel PCS commit
    alone is not enough to overcome remaining serial prototype overhead on
    tiny circuits;
  - ordinary result verification command:
    `powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\run_experiments.ps1 verify-results results\bench-1780236398908666500 -Release -Format json`;
  - remaining known scaling limitation: compact PCS worker openings and the
    R1CS Spark worker provider are still invoked through single-worker
    callbacks, so fully parallel open/Spark execution requires a wider batch
    provider API rather than only transport-layer threading.

- Compact PCS opening batch-provider parallelization:
  - added `pq-pcs::WorkerOpeningRequest` and
    `DistributedBrakedown::open_compact_at_after_commitment_with_batch_worker_provider`,
    allowing the compact distributed PCS opening phase to request all worker
    openings in one batch after Fiat-Shamir query indices have been fixed;
  - the existing single-worker provider API now delegates to the batch API, so
    old callers keep the same behavior and transcript order;
  - the batch path validates that the provider returns exactly one opening for
    each requested worker in the original worker order before absorbing worker
    openings into the transcript;
  - `pq-experiments::NetworkPcsClient::open_compact` now uses the batch API
    and fan-outs `PcsOpen` TCP requests concurrently across workers, then
    aggregates byte counts and reorders openings by request index. This
    parallelizes the PCS open transport path without changing the proof
    transcript schedule;
  - added a `pq-pcs` regression test proving that the batch worker provider
    produces the exact same compact opening and transcript state as the
    sequential provider;
  - targeted validation:
    `cargo test -p pq-pcs compact_batch_worker_provider_matches_sequential_provider`,
    `cargo test -p pq-experiments r1cs_network_hook_produces_compact_pcs_openings`,
    `cargo test -p pq-experiments plonkish_network_hook_produces_compact_pcs_opening`,
    and
    `cargo clippy -p pq-pcs -p pq-net -p pq-experiments --all-targets -- -D warnings`;
  - post-change lightweight network release benchmark:
    `powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\run_experiments.ps1 benchmark -Runner network -NRange "2..3" -Workers "1,2,4" -PcsQueries 2 -OutDir results -Release`;
    output directory `results/bench-1780236684518605300`; all `12`
    performance rows verified and manifest verification passed with
    `files_checked=22`, `bytes_checked=87075`;
  - at `n=3` / `nv=8`, network R1CS speedup was `1.139x` at two workers and
    `1.141x` at four workers. Network Plonkish was `1.047x` at two workers and
    `0.910x` at four workers. The result confirms correctness of the new
    parallel open path but also confirms that remaining serial prototype work
    still dominates at tiny sizes;
  - remaining high-priority scaling limitation after this change: R1CS Spark
    worker claims still use the older single-partition callback shape, and
    local PCS commit/open still simulate distributed workers mostly in a single
    process.

- R1CS Spark worker-claim batch-provider parallelization:
  - added `pq_piop_r1cs::SparkWorkerClaimRequest`,
    `R1csBatchProverHooks`, and
    `prove_r1cs_with_pcs_and_spark_batch_hooks`;
  - the existing single-worker Spark provider API now delegates to the batch
    provider API, preserving old caller behavior while enabling network callers
    to fan out all partition-local Spark claim requests together;
  - added `prove_distributed_spark_with_batch_worker_provider`; it derives the
    Spark Fiat-Shamir challenges once, constructs all per-partition requests,
    accepts the returned worker claims in request order, and then reuses the
    existing claim validation and matrix-evaluation proof path;
  - `pq-experiments` network R1CS proving now uses the batch Spark hook.
    `NetworkPcsClient::r1cs_spark_claims` builds all partition-local sparse
    matrix request payloads, sends `R1csSparkClaim` TCP messages concurrently,
    aggregates network bytes, and restores request order before returning to
    the PIOP;
  - added a `pq-piop-r1cs` regression test that checks the batch provider sees
    worker partitions `[0, 1]` in one batch and still produces a proof accepted
    by the verifier;
  - targeted validation:
    `cargo test -p pq-piop-r1cs r1cs_spark_batch_worker_provider_matches_shard_claim_order`,
    `cargo test -p pq-experiments r1cs_network_hook_produces_compact_pcs_openings`,
    and
    `cargo clippy -p pq-piop-r1cs -p pq-experiments --all-targets -- -D warnings`.
  - post-change light benchmark:
    `powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\run_experiments.ps1 benchmark -Runner network -NRange "2..3" -Workers "1,2,4" -PcsQueries 2 -OutDir results -Release`;
    output directory `results/bench-1780237207208211700`; all `12`
    performance rows verified and manifest verification passed with
    `files_checked=22`, `bytes_checked=86701`;
  - in that full light run, at `n=3` / `nv=8`, network R1CS speedup was
    `2.012x` at two workers and `2.029x` at four workers, while network
    Plonkish remained near flat (`1.026x` at two workers and `0.981x` at four
    workers). Because the single-sample Windows run also showed higher
    baseline times than the previous run, this should be read as evidence that
    the R1CS fan-out path is now real, not as a stable paper-quality scaling
    number;
  - sanity rerun limited to `n=3`:
    `powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\run_experiments.ps1 benchmark -Runner network -NRange "3..3" -Workers "1,2,4" -PcsQueries 2 -OutDir results -Release`;
    output directory `results/bench-1780237258532564200`; all `6`
    performance rows verified, manifest verification passed with
    `files_checked=22`, `bytes_checked=71763`, and R1CS speedup was `1.175x`
    at two workers but `0.667x` at four workers. This confirms correctness and
    shows the PC-scale single-run timings are noisy; future paper-quality runs
    should use larger circuits on the Linux server before interpreting the
    worker-scaling slope.

- Local distributed PCS worker parallelization:
  - `DistributedBrakedown::commit_detached` and the `DistributedPcs::commit`
    implementation now build worker commitments through scoped threads and
    restore the canonical worker order before master aggregation. This removes
    a local-runner-only serial loop without changing the distributed root;
  - full and compact local openings now use the same batch worker-opening path
    as network callers. The default local provider fans out worker openings
    with scoped threads and validates that returned openings match the original
    worker order before absorbing them into the Fiat-Shamir transcript;
  - `DistributedBrakedown::worker_open` now builds each worker codeword Merkle
    tree once and derives all requested systematic/parity openings from cached
    Merkle layers, instead of rebuilding the tree for every opened leaf;
  - the public single-worker provider APIs are kept for compatibility and now
    delegate to the batch path, so existing tests and callers preserve their
    original transcript order;
  - targeted validation:
    `cargo test -p pq-pcs`,
    `cargo clippy -p pq-pcs --all-targets -- -D warnings`,
    `cargo test -p pq-pcs compact_batch_worker_provider_matches_sequential_provider`,
    and
    `cargo test -p pq-pcs distributed_opening_binds_combined_column_and_queries`.

- Fresh-clone repository hygiene and full validation:
  - removed the Rust `target/` build cache from Git tracking and kept
    `/target/` ignored. This prevents fresh clones from receiving local build
    artifacts while preserving reproducible source-level validation through
    Cargo;
  - removed nested `.git` directories from `third_party/Spartan2` and
    `third_party/hyperplonk` and staged the vendored files as ordinary source
    files. `git ls-files -s third_party/Spartan2 third_party/hyperplonk`
    now reports normal file modes rather than gitlink mode `160000`;
  - restored a valid workspace `repository` URL in `Cargo.toml` because
    `pq-core` and `pq-transcript` inherit `repository.workspace = true`.
    Without this, `cargo metadata` and `cargo fmt` failed before any tests
    could run;
  - Linux bootstrap now checks for `taskset` through `util-linux`, matching
    the worker-affinity requirement used by multi-worker network/both
    benchmarks. Windows bootstrap verifies Rust, clippy/rustfmt, MSVC build
    tools, and optional figure tooling;
  - validation run on Windows:
    `cargo fmt --check`,
    `cargo test --workspace`,
    and `cargo clippy --workspace --all-targets -- -D warnings` all passed;
  - script validation run:
    `powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\run_experiments.ps1 bootstrap`
    passed. `bash -n scripts/bootstrap.sh scripts/run_benchmarks.sh scripts/run_experiments.sh scripts/verify_results.sh`
    passed under Git for Windows bash. A Git Bash bootstrap dry-run correctly
    reported missing Linux-only tools (`c-compiler`, `pkg-config`, `taskset`);
    this is expected on this Windows PC and is covered by `bootstrap.sh
    --install` on a real Linux host;
  - post-validation light benchmark:
    `powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\run_benchmarks.ps1 -Release -Runner both -NRange "2..2" -Workers "1,2" -PcsQueries 1 -OutDir results`;
    output directory `results/bench-1780239470104973000`; all `8`
    performance rows were positive end-to-end prove+verify runs and all
    verified. The result verifier command
    `powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\verify_results.ps1 results\bench-1780239470104973000 -Format json -Release`
    returned `ok=true`, `files_checked=22`, `bytes_checked=81156`;
  - this light benchmark confirmed the fixed-core allocation path on Windows:
    `host_logical_cores=20`, `max_workers=2`, `cores_per_worker=10`,
    `affinity_mode=windows-powershell-processor-affinity`;
  - the latest light benchmark is intentionally a smoke/performance-path
    validation, not scaling evidence: `n=2`/`nv=4` is too small, and the
    summary labels the dashed worker line as a perfect-linear upper bound
    rather than an expected curve for the current prototype.

- Benchmark provenance overhead reduction:
  - root cause for the previously large small-benchmark finalization cost was
    `git status --porcelain` over a large vendored and staged worktree. On this
    Windows PC it measured about `5.5s` per call, and benchmark summary plus
    metadata generation could capture provenance repeatedly;
  - replaced the full porcelain status call with a faster reproducibility
    fingerprint over `git diff --name-status`, `git diff --cached
    --name-status`, and `git ls-files -o --exclude-standard`, excluding
    ignored scratch result directories and `target/`. This preserves a stable
    dirty-state fingerprint for benchmark metadata without scanning the full
    ignored build cache path;
  - benchmark summary and metadata now share one captured `BenchmarkProvenance`
    instance during final artifact generation instead of re-running Git/Rust
    version commands multiple times;
  - after converting `third_party/` from nested Git repos to ordinary vendored
    files, third-party commit provenance now comes from
    `third_party/PINS.md`. The fallback `git -C` path is used only when the
    third-party directory itself still has a `.git` directory/file, preventing
    accidental recording of the parent project HEAD as a Spartan2/HyperPlonk
    pin;
  - validation:
    `cargo fmt --check`,
    `cargo test -p pq-experiments benchmark_charts_are_svg_and_pgfplots_with_real_series`,
    and
    `cargo clippy -p pq-experiments --all-targets -- -D warnings` passed;
  - reran the same light benchmark command:
    `powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\run_benchmarks.ps1 -Release -Runner both -NRange "2..2" -Workers "1,2" -PcsQueries 1 -OutDir results`;
    output directory `results/bench-1780239964291976300`; all `8`
    performance rows verified and `verify_results.ps1` returned `ok=true`,
    `files_checked=22`, `bytes_checked=81001`;
  - the measured `final_result_artifacts` phase fell from about `8185ms` in
    `results/bench-1780239470104973000` to about `308ms` in
    `results/bench-1780239964291976300`. The new metadata records the correct
    pins: Spartan2
    `0d4f1409e8f30536b8b25ed3f81bc446ed717e61` and HyperPlonk
    `2a3b55c97ad8a5d6627108a2e7def2aeccb7f3b9`.

- Paper-quality result verifier semantic checks:
  - strengthened `pq-experiments verify-results --paper-quality` beyond
    metadata checks. It now parses `source.csv` and requires the full
    paper-grid Cartesian product: local/network runners, R1CS/Plonkish
    protocols, `n=2..6`, workers `1,2,4`, one trial, positive-only rows,
    successful verification, positive timing/proof/communication metrics,
    zero `network_bytes` for local rows, and nonzero `network_bytes` for
    network rows;
  - fixed the paper-quality expected record formula to include both runners:
    `n_count * worker_count * protocol_count * runner_count * repeats`, i.e.
    `5 * 3 * 2 * 2 * 1 = 60` rows for the current preset. The previous
    metadata-only verifier undercounted `runner=both` as `30`;
  - paper-quality verification now also checks `phase_timing.csv` for every
    job row plus `source_and_chart_artifacts`, `final_result_artifacts`, and
    `total`, and checks `overview.html`, `paper_figures.tex`, all SVG preview
    charts, and `paper_figures_standalone.pdf` for expected structural
    markers;
  - added regression coverage that constructs a synthetic paper-quality result
    directory, verifies it, then mutates the metadata and `source.csv` to
    confirm the stricter gate rejects bad publication evidence;
  - validation:
    `cargo fmt --check`,
    `cargo test -p pq-experiments benchmark_charts_are_svg_and_pgfplots_with_real_series`,
    and
    `cargo clippy -p pq-experiments --all-targets -- -D warnings` passed.

- Vendored reference hygiene:
  - audited `third_party/` for large/generated artifacts before repository
    publication. HyperPlonk's upstream `hyperplonk/srs.params` KZG SRS binary
    was about `6.3MB` and is not part of the PIOP source reuse path; upstream
    `bench_results/plot_*` files are generated plotting scratch files rather
    than implementation source;
  - removed those HyperPlonk benchmark-result files and the KZG SRS binary
    from Git tracking while leaving the local files ignored. This keeps the
    fixed source reference available for local inspection if present, but a
    fresh GitHub clone will not publish non-PQ commitment parameters or
    upstream generated benchmark artifacts;
  - added explicit ignore rules for
    `third_party/hyperplonk/bench_results/` and
    `third_party/hyperplonk/hyperplonk/srs.params`, and documented the policy
    in `third_party/README.md` and `third_party/PORTING_NOTES.md`;
  - verification:
    `git ls-files third_party | Select-String -Pattern "srs\\.params|bench_results"`
    produced no tracked matches, while
    `git status --ignored --short third_party/hyperplonk/bench_results third_party/hyperplonk/hyperplonk/srs.params`
    shows both paths ignored.

- Benchmark scaling interpretation hardening:
  - audited the worker-scaling plot after a light Windows run showed near-1x
    speedup at `n=5` while the dashed reference reached `4x`. The measured
    path is end-to-end prove/verify for a very small correctness prototype:
    worker PCS/Spark requests are real, but master orchestration, transcript
    sequencing, verifier-facing proof assembly, consistency checks, and network
    process scheduling dominate at this size;
  - clarified the plot/HTML/summary language so the dashed line is described as
    a perfect-linear upper bound, not as the expected performance prediction for
    the prototype;
  - added an Amdahl-style `serial+overhead` diagnostic to the HTML overview and
    text summary. This is derived from the observed speedup only and is not used
    to fit or synthesize benchmark data;
  - made `worker_scaling_max_size.svg/.tex` aggregate verified positive repeats
    before plotting even when the chart function is called with raw source
    records, matching the summary statistics path;
  - verification:
    `cargo fmt --check`,
    `cargo test -p pq-experiments benchmark_charts_are_svg_and_pgfplots_with_real_series`,
    and `cargo clippy -p pq-experiments --all-targets -- -D warnings` passed.

- Protocol-hardening follow-up after subagent review:
  - Plonkish gate checking now includes a cubic zerocheck over committed derived
    columns for `(q_m * a) * b = -(q_l*a + q_r*b + q_o*c + q_c)`. The proof
    also opens selector columns and derived columns at sampled points so the
    verifier checks that the gate residual is tied to committed witness and
    selector data rather than only to a precomputed residual vector;
  - distributed PCS worker openings now require canonical per-worker query
    order before any transcript absorption in both full and compact opening
    verification paths. Reordered query payloads are rejected instead of being
    accepted as an alternative proof encoding;
  - R1CS outer row-domain commitments, residual commitments, and Spark row
    partitions are now checked against the same padded power-of-two row domain
    derived from the instance. A proof whose row-domain commitments use a
    different worker partition than `proof.workers` is rejected;
  - verification:
    `cargo test -p pq-piop-plonkish gate_cubic`,
    `cargo test -p pq-pcs`,
    `cargo test -p pq-piop-r1cs r1cs_row_domain_partitions_are_canonical_for_outer_spark_and_residual`,
    `cargo clippy -p pq-pcs --all-targets -- -D warnings`,
    `cargo clippy -p pq-piop-r1cs --all-targets -- -D warnings`,
    `cargo clippy -p pq-piop-plonkish --all-targets -- -D warnings`,
    `cargo test -p pq-experiments loopback_network_proof_paths_produce_positive_and_negative_records`,
    and `cargo clippy -p pq-experiments --all-targets -- -D warnings` passed.

- Latest light Windows performance run after the hardening changes:
  - command:
    `powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\run_benchmarks.ps1 -Release -Runner both -NRange "2..2" -Workers "1,2" -PcsQueries 1 -OutDir results`;
  - output directory:
    `results/bench-1780242530848427700`;
  - result verifier:
    `.\target\release\pq-experiments.exe verify-results --dir results\bench-1780242530848427700 --format json`
    returned `{"ok":true,...}`;
  - all 8 positive end-to-end prove/verify rows verified. This run contains no
    negative correctness rows because the benchmark path is now performance-only;
  - worker scaling at this tiny size is intentionally reported against the
    workers=1 baseline and the dashed line is labeled as a perfect-linear upper
    bound, not an expected prototype prediction. In the latest `source.csv`,
    local R1CS improves from `154.372 ms` at one worker to `135.198 ms` at two
    workers, local Plonkish improves from `154.055 ms` to `150.359 ms`, network
    R1CS slows from `152.458 ms` to `250.264 ms`, and network Plonkish improves
    from `262.682 ms` to `250.941 ms`. The gap to the upper-bound line is
    therefore dominated by serial master/transcript/verification/PCS orchestration
    and loopback worker overhead at small `n`, not by an ideal-line prediction
    failure.

- Full workspace and script-level validation after the protocol hardening:
  - `cargo test --workspace` passed on Windows. The run covered all workspace
    crates and included core, transcript, sumcheck, PCS, R1CS PIOP, Plonkish
    PIOP, TCP runtime, experiment CLI, and doctests;
  - `cargo clippy --workspace --all-targets -- -D warnings` passed;
  - Windows entrypoint help checks passed:
    `powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\run_experiments.ps1 -Help`
    and
    `powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\run_benchmarks.ps1 -Help`;
  - Linux script syntax checks passed through Git Bash on Windows:
    `bash -n scripts/run_experiments.sh`,
    `bash -n scripts/run_benchmarks.sh`,
    and `bash -n scripts/bootstrap.sh`;
  - latest benchmark manifest verification passed through the documented
    Windows entrypoint:
    `powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\verify_results.ps1 results\bench-1780242530848427700 -Format json`.

- Plonkish permutation/transcript binding hardening:
  - sampled permutation-accumulator recurrence queries now open the public
    `source_id` and `target_id` columns under their Merkle commitments. The
    verifier checks those openings, checks they match the sampled source and
    configured permutation target, and uses the opened id values in the
    HyperPlonk-style product-factor check instead of only recomputing ids
    locally;
  - accumulator query transcript absorption now includes those id openings, so
    the final Fiat-Shamir state is bound to the same id material verified by
    the recurrence query;
  - superseded by the later public-witness separation pass: the Plonkish
    statement transcript no longer absorbs raw `a/b/c` wire values before
    oracle commitments. The accumulator subclaim now carries public
    active/value/source-id/target-id commitments, and the verifier binds
    recurrence queries to proof-carried public value openings instead of
    recomputing witness-bearing vectors from `PlonkishInstance`;
  - verification:
    `cargo test -p pq-piop-plonkish permutation_accumulator_recurrence_queries_bind_public_values_and_ids`,
    `cargo test -p pq-piop-plonkish plonkish_statement_excludes_wire_values_until_oracle_commitments`,
    `cargo test -p pq-piop-plonkish`,
    `cargo clippy -p pq-piop-plonkish --all-targets -- -D warnings`,
    `cargo test -p pq-experiments loopback_network_proof_paths_produce_positive_and_negative_records`,
    and `cargo clippy -p pq-experiments --all-targets -- -D warnings` passed.

- R1CS Spark memory access preimage binding:
  - sampled Spark memory access queries now carry the accessed memory address,
    memory value, read timestamp, and write timestamp in addition to the
    Merkle openings of the read/write hash leaves;
  - the verifier checks those preimage fields against the recomputed trace and
    re-evaluates the read/write hash at each sampled access. This makes the
    sampled memory check bind the visible Init/Read/Write/Audit leaves to the
    actual address/value/timestamp transition, instead of only checking leaf
    equality against a recomputed trace vector;
  - the new preimage fields are absorbed into the Spark memory trace transcript
    and included in proof-size accounting;
  - verification:
    `cargo test -p pq-piop-r1cs spark_memory_trace_sampling_binds_commitments_and_openings`,
    `cargo test -p pq-piop-r1cs spark_memory_and_matrix_evaluation_tampering_fails`,
    `cargo test -p pq-piop-r1cs`,
    `cargo clippy -p pq-piop-r1cs --all-targets -- -D warnings`,
    `cargo test -p pq-experiments loopback_network_proof_paths_produce_positive_and_negative_records`,
    and `cargo clippy -p pq-experiments --all-targets -- -D warnings` passed.

- Compact PCS composition-query hardening:
  - `CompactDistributedOpening` now carries a second Fiat-Shamir sampled query
    set, `composition_query_indices`/`composition_queries`, derived immediately
    after the sampled codeword-composition folding proof and before the worker
    consistency query schedule;
  - these composition queries open the combined-column commitment and the
    composed codeword commitment at systematic, adjacent, strided, and parity
    positions. The verifier checks Merkle paths and the systematic encoding
    relation independently from the row-weighted worker consistency queries;
  - the new query material is absorbed under a separate transcript domain and
    included in compact proof-size accounting, so reordering or tampering with
    either composition-query values or query indices changes verification;
  - verification:
    `cargo test -p pq-pcs compact_distributed_opening_verifies_and_rejects_tamper`,
    `cargo test -p pq-pcs`,
    `cargo clippy -p pq-pcs --all-targets -- -D warnings`,
    `cargo test -p pq-experiments r1cs_network_hook_produces_compact_pcs_openings`,
    `cargo test -p pq-experiments plonkish_network_hook_produces_compact_pcs_opening`,
    `cargo test -p pq-experiments loopback_network_proof_paths_produce_positive_and_negative_records`,
    and `cargo clippy -p pq-experiments --all-targets -- -D warnings` passed.

- Worker-scaling figure interpretation and benchmark-entry hardening:
  - `worker_scaling_max_size.svg`, `worker_scaling_max_size.tex`, and the
    grouped `paper_figures.tex` panel now draw measured speedup as solid
    series, retain the perfect-linear line only as an explicit upper bound, and
    add a dotted `Serial+overhead diagnostic` curve for each measured series;
  - the dotted curve is not substitute data: it is derived from each series'
    largest-worker measured speedup via the same Amdahl-style
    `serial+overhead` diagnostic already reported in `summary.txt`, and it is
    labelled as a diagnostic rather than a prediction;
  - Windows and Linux benchmark entry scripts now build the release binary by
    default for performance runs. `-Debug` / `--debug` remains available only
    for script-development smoke checks, while paper and medium presets still
    force release mode;
  - generated verification run:
    `powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\run_benchmarks.ps1 -NRange 2..2 -Workers 1,2 -PcsQueries 1 -Runner both -OutDir results`
    produced `results\bench-1780294987111319300`;
  - that release smoke recorded `build_profile=release`, `records=8`,
    `positive_verified=8`, and `negative_rejected=0`. Its source rows are
    performance-only positive end-to-end prove/verify jobs, with fixed
    Windows core allocation `host_logical_cores=20`, `max_workers=2`,
    `cores_per_worker=10`;
  - manifest verification passed:
    `powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\verify_results.ps1 results\bench-1780294987111319300 -Format json`
    returned `ok=true`, `files_checked=22`, and `bytes_checked=83717`;
  - verification:
    `cargo test -p pq-experiments benchmark_charts_are_svg_and_pgfplots_with_real_series`,
    `cargo clippy -p pq-experiments --all-targets -- -D warnings`,
    Windows benchmark/experiment help checks, and Git Bash syntax checks for
    `scripts/run_benchmarks.sh` and `scripts/run_experiments.sh` passed.

- Plonkish PIOP witness-parameter binding:
  - replaced the empty `PlonkishWitness` marker with explicit per-row
    witness-wire values `a/b/c`, plus `PlonkishWitness::from_instance` for the
    current public-row prototype model;
  - `PlonkishPiop::prove_interactive` now validates that the supplied witness
    shape and wire values match the statement before any proof work starts, so
    the unified PIOP trait no longer ignores its witness parameter;
  - the compatibility `prove_plonkish*` helpers still derive this witness from
    `PlonkishInstance`, matching the current statement model where wire values
    are public. Separating hidden witness assignment from public selectors and
    permutation metadata remains future frontend work;
  - verification:
    `cargo test -p pq-piop-plonkish unified_piop_trait_drives_plonkish_route`,
    `cargo test -p pq-piop-plonkish plonkish_piop_trait_rejects_mismatched_witness`,
    `cargo test -p pq-piop-plonkish plonkish_piop_trait_rejects_wrong_witness_shape`,
    `cargo test -p pq-piop-plonkish`,
    `cargo clippy -p pq-piop-plonkish --all-targets -- -D warnings`,
    and
    `cargo test -p pq-experiments plonkish_network_hook_produces_compact_pcs_opening`,
    and `cargo clippy -p pq-experiments --all-targets -- -D warnings` passed.

- Plonkish public statement boundary regression:
  - added an end-to-end verifier regression confirming that raw `a/b/c` wire
    changes in `PlonkishInstance` do not alter verification once the proof's
    oracle commitments/openings are fixed, while selector changes with the same
    shape and permutation still fail verification. This is stronger than the
    earlier transcript-only check because it exercises the full
    `verify_plonkish` path;
  - this locks in the intended boundary for the current research prototype:
    selectors, row count, worker count, and permutation are public statement
    data; witness-wire values are bound after oracle commitments and sampled
    openings;
  - verification:
    `cargo test -p pq-piop-plonkish plonkish_verifier_binds_selectors_but_not_statement_wire_values`,
    `cargo test -p pq-piop-plonkish plonkish_statement_excludes_wire_values_until_oracle_commitments`,
    `cargo test -p pq-piop-plonkish`,
    `cargo clippy -p pq-piop-plonkish --all-targets -- -D warnings`,
    `cargo test -p pq-experiments plonkish_network_hook_produces_compact_pcs_opening`,
    `cargo test -p pq-experiments benchmark_charts_are_svg_and_pgfplots_with_real_series`,
    `cargo test -p pq-experiments loopback_network_proof_paths_produce_positive_and_negative_records`,
    and `cargo clippy -p pq-experiments --all-targets -- -D warnings` passed.

- R1CS Spark worker-claim matrix-id binding:
  - `SparkWorkerEvaluation` now carries an explicit `matrix_id`, and the
    prover-side worker-claim validator checks that each worker's A/B/C
    evaluation claim is in the expected matrix slot before assembling the
    matrix-evaluation proof;
  - the verifier recomputed expected worker evaluations with the same matrix
    id, and worker evaluation transcript absorption now includes
    `spark-worker-matrix-id`. This makes the distributed worker claim wire
    format self-describing instead of relying only on `Vec` position for the
    A/B/C route;
  - `pq-net` Spark claim encoding/decoding now includes the matrix id in each
    encoded worker evaluation, and the R1CS tamper test now rejects a proof
    whose worker evaluation is relabelled to a different matrix;
  - verification:
    `cargo test -p pq-piop-r1cs spark_memory_and_matrix_evaluation_tampering_fails`,
    `cargo test -p pq-net worker_computes_r1cs_spark_claim_for_partition`,
    `cargo test -p pq-experiments r1cs_network_hook_produces_compact_pcs_openings`,
    `cargo test -p pq-piop-r1cs`,
    `cargo clippy -p pq-piop-r1cs --all-targets -- -D warnings`,
    `cargo clippy -p pq-net --all-targets -- -D warnings`,
    `cargo test -p pq-net`,
    `cargo clippy -p pq-experiments --all-targets -- -D warnings`,
    and `cargo test --workspace` passed.

- Interactive script entrypoint consolidation:
  - removed the old split script surface (`bootstrap`, `run_experiments`,
    `run_benchmarks`, and `verify_results` variants) and kept exactly three
    script entrypoints under `scripts/`:
    `interactive-linux.sh`, `interactive-macos.sh`, and
    `interactive-powershell.ps1`;
  - all three entries now open a menu instead of running predetermined
    experiments on launch. The menu covers dependency preflight/installation,
    proof experiment wizard, performance benchmark wizard, and result
    verification;
  - the PowerShell entry keeps the console open by default after completion or
    failure, with `-NoPause` reserved for CI/scripted smoke checks. This fixes
    the Windows "open and immediately closes" failure mode;
  - the benchmark wizard explicitly reports that each atomic benchmark is one
    real end-to-end prove+verify run and relies on the Rust benchmark runner's
    completed-job progress bar. It also prints the derived scaling core plan
    before network scaling runs;
  - `.github/workflows/ci.yml` now smoke-checks the menu entrypoints and uses
    direct `cargo run -p pq-experiments -- ...` commands for non-interactive
    benchmark/verification automation, keeping scripts interactive-only;
  - verification:
    PowerShell parser check for `scripts/interactive-powershell.ps1` passed;
    piped PowerShell menu exit and preflight checks passed;
    Git for Windows Bash syntax checks for `scripts/interactive-linux.sh` and
    `scripts/interactive-macos.sh` passed; piped Linux/macOS menu exit checks
    passed.

- Interactive entrypoint revalidation:
  - `scripts/` currently contains only `interactive-linux.sh`,
    `interactive-macos.sh`, and `interactive-powershell.ps1`;
  - PowerShell double-click behavior was rechecked by running the menu without
    `-NoPause`: selecting exit prints `Press Enter to exit...`, so a normal
    Windows launch does not immediately close on success or error;
  - PowerShell preflight was rechecked through the interactive menu and reports
    `git`, `rustc`, `cargo`, `rustup`, and MSVC C++ build tools as present;
  - PowerShell benchmark wizard was rechecked with menu input
    `runner=local`, `n-range=2..2`, `workers=1`, `pcs_queries=1`, and
    `repeats=1`; the run created
    `results/bench-1780299366059533400` and printed exactly
    `[benchmark 1/2]` and `[benchmark 2/2]` for the two actual
    end-to-end prove+verify jobs (`R1CS`, `Plonkish`);
  - PowerShell verify-results wizard was rechecked through the menu against
    `results/bench-1780299366059533400`; it returned `ok=true`,
    `files_checked=22`, and `bytes_checked=52167`;
  - Git for Windows `bash.exe` rechecked `bash -n` and piped menu exit for
    both Linux and macOS entrypoints. The unqualified Windows `bash` command on
    this machine resolves to the WSL launcher, but WSL is not installed, so
    Git Bash was used only as a local syntax/menu compatibility validator.
- Formatting and lint revalidation:
  - `cargo fmt --check` passed;
  - `cargo clippy --workspace --all-targets -- -D warnings` passed.

- Result verifier semantic gate:
  - ordinary `pq-experiments verify-results` now performs a second validation
    layer after manifest checksum verification. It cross-checks
    `metadata.json`, `source.csv`, `source.json`, `summary_stats.csv`,
    `phase_timing.csv`, and `overview.html`;
  - the semantic gate enforces `schema_version=7`, matching manifest/metadata
    run ids, `repeats=1`, performance-only positive rows, exact coverage of
    the configured runner/protocol/worker/`n` grid, valid `size=2^n`, matching
    PCS query counts, no local network bytes, required network affinity fields,
    summary row consistency, and a phase-timing job row for every benchmark
    row;
  - ordinary verification now also checks that `overview.html` contains the
    expected dashboard links/markers, every SVG preview is a structurally
    complete SVG with the generated chart style/title markers, every
    individual PGFPlots/TikZ file contains the generated-source preamble,
    TikZ/axis structure, and source-data marker, and
    `paper_figures.tex` / `paper_figures_standalone.tex` contain the expected
    groupplot/standalone markers. If a compiled PDF is present, it must start
    with `%PDF`;
  - `verify-results` JSON/CSV output now includes `source_rows_checked`,
    `phase_rows_checked`, and `summary_rows_checked`;
  - added regression coverage for a manifest-consistent but semantically
    invalid result directory, so recomputing `result_manifest.json` after a bad
    `source.csv` edit or broken SVG replacement is still rejected;
  - revalidated `results/bench-1780299366059533400`:
    `files_checked=22`, `bytes_checked=52167`,
    `source_rows_checked=2`, `phase_rows_checked=6`,
    `summary_rows_checked=2`;
  - re-ran the PowerShell verify-results wizard through the interactive menu
    against the same directory; it returned the new semantic row-count fields
    without breaking the menu flow;
  - updated `results/README.md` and `results/release_results/README.md` to use
    the current interactive entrypoints or direct `cargo run` commands instead
    of the removed `run_experiments.*` wrappers.
- CI result-verifier coverage:
  - `.github/workflows/ci.yml` now captures `verify-results --format json` in
    both Windows and Linux benchmark smoke jobs and asserts the semantic row
    counters. For the CI smoke grid (`runner=network`, `n=2`, workers `1,2`),
    it expects `source_rows_checked=4`, `phase_rows_checked=11`, and
    `summary_rows_checked=4`; the phase count includes setup, two reusable
    network worker-pool startup phases, four job phases, worker-pool shutdown,
    source/chart generation, final artifact generation, and total wall-clock
    accounting;
  - local PowerShell assertion against `results/bench-1780299366059533400`
    passed with `source_rows_checked=2`, `phase_rows_checked=6`, and
    `summary_rows_checked=2`.
- macOS interactive preflight hardening:
  - `scripts/interactive-macos.sh` still delegates to the shared Bash menu, but
    the shared script now detects Xcode Command Line Tools explicitly via
    `xcode-select -p` plus `clang`;
  - macOS preflight reports `Xcode command line tools ok/missing`, and the
    install action invokes `xcode-select --install` when they are missing,
    then asks the user to complete the Apple installer and rerun the menu;
  - README documents this macOS first-run behavior so a fresh clone does not
    fail later at Rust link/build time without a clear dependency diagnosis;
  - validation on this Windows PC with Git Bash: `bash -n` passed for
    `interactive-linux.sh` and `interactive-macos.sh`; piped Linux menu exit
    passed; piped macOS preflight displayed `Xcode command line tools missing`
    as expected in the non-macOS compatibility shell; PowerShell parser check
    for `interactive-powershell.ps1` passed.
- Interactive script and benchmark progress hardening:
  - kept the root `scripts/` directory limited to exactly
    `interactive-linux.sh`, `interactive-macos.sh`, and
    `interactive-powershell.ps1`;
  - added a `pq-experiments` regression test that fails if any other root
    script entrypoint is added, so legacy predetermined wrapper scripts cannot
    reappear silently;
  - changed benchmark status output from plain `[benchmark i/total]` messages
    to an explicit completed-jobs progress bar. The denominator is computed
    from the actual protocol/runner/size/worker/trial Cartesian product, and
    the numerator advances only after a real end-to-end prove+verify benchmark
    job finishes;
  - updated the Linux/macOS/PowerShell interactive benchmark menus and README
    wording to describe the real completed-job progress semantics;
  - strengthened CI smoke checks so piping `0` into the PowerShell, Linux, or
    macOS entrypoint must render the menu and exit without entering proof or
    benchmark wizards. This directly guards against the previous pseudo-
    interactive/default-action regression.
- Fresh-clone reproducibility and lightweight benchmark assessment:
  - added `Doc/reproducibility_runbook.md` with the Windows/Linux/macOS
    interactive entrypoints, new-machine validation order, core `cargo`
    quality gates, and direct automation commands;
  - recorded the local lightweight sanity benchmark
    `results\bench-1780301737355633500`, including the exact command,
    verifier output, raw R1CS/Plonkish timing rows, phase timing, and a
    conservative interpretation: it proves benchmark plumbing and real
    positive prove/verify execution, but it is a debug local-only workers=1
    run and therefore cannot support distributed scaling claims;
  - linked the runbook from README and updated the results README to include
    the macOS interactive entrypoint.
- Completion audit:
  - added `Doc/completion_audit.md`, mapping the active goal to current
    repository evidence. It marks the modular workspace, supported R1CS and
    Plonkish PIOP surfaces, distributed PCS, Fiat-Shamir transcript, scripts,
    benchmark artifacts, HTML overview, result verifier, and quality gates as
    proven where current code/tests/artifacts directly support them;
  - the audit deliberately leaves the overall goal active because several
    protocol boundaries remain documented as research-prototype scope rather
    than production-complete Spartan/Spark, HyperPlonk, or Brakedown/BaseFold
    implementations.
- Results publishing surface cleanup:
  - removed already-tracked local scratch `results/bench-*` directories from
    the Git index with `git rm -r --cached results/bench-*`, leaving the files
    on disk but preventing them from being published in the repository;
  - verified `git ls-files results` now lists only `results/README.md` and
    `results/release_results/README.md`;
  - verified `.gitignore` ignores scratch benchmark outputs via
    `/results/bench-*/`, while `results/release_results/` remains the explicit
    curated publication location.

## Current Limitations

- This is not a production SNARK and does not claim zero knowledge or optimized
  proof size. The R1CS route no longer sends the full witness and now includes
  a Spartan-style outer cubic sumcheck and a Spartan-style inner
  product-sumcheck tying random `Az/Bz/Cz` openings to the committed witness
  MLE. The local Merkle witness commitment and distributed PCS witness
  commitment are now sampled for equality before the residual and Spark
  challenges. The Spark route now contributes verifier-checked sparse matrix
  evaluation claims plus row/column/value memory product-multiset and
  log-derivative rational-sumcheck checks to the inner final verification
  equation. Sampled row-consistency openings are
  transcript-bound before Spark derives its challenges. In network R1CS
  experiments, Spark worker fingerprints and matrix-evaluation claims are now
  computed by TCP workers from partition-local sparse entries rather than by a
  master-only helper. The Spark memory checks now commit the Init/Read/Write/Audit trace columns and verify Fiat-Shamir
  sampled Merkle openings under the configured PCS query count. Sampled access
  openings also expose and verify the address/value/timestamp preimage of the
  read/write hash transition. Its default local PCS opening path uses compact
  distributed openings, but the production Spark memory-check protocol is still
  not complete: the current matrix-evaluation verifier recomputes small public
  sparse traces and values remain public-entry bound, so this is a
  commitment-bound prototype trace check rather than a production-succinct Spark
  memory proof. The Plonkish route now includes selector commitments,
  random-point virtual gate evaluation subclaims whose gate-column evaluations
  are bound by sampled MLE folding proofs, a committed permutation
  running-product accumulator, precommitted transition-residual columns, and
  numerator/denominator cubic recurrence sumchecks whose final evaluations are
  tied to committed sampled openings at the sumcheck challenge point. Final
  sampled gate/permutation consistency openings are transcript-bound before the
  Plonkish transcript is returned to a caller. Its default local
  constraint-residual PCS opening now uses compact distributed openings.
  Gate/copy/accumulator index consistency checks are sampled by the configured
  query count; accumulator recurrence queries now also open the public
  source/target id columns and use those opened ids in the product-factor
  check. The statement transcript now excludes raw `a/b/c` witness-wire values
  before oracle commitments, and accumulator public value/source/target columns
  are bound through proof-carried commitments and sampled openings. The unified
  Plonkish PIOP trait still validates compatibility witnesses against the
  current demo `PlonkishInstance` rows, so separating a full hidden-witness
  frontend from public selectors and permutation metadata remains future work.
  These checks remain prototype Merkle-opening
  checks, and this is still not a full HyperPlonk production argument.
- The distributed Brakedown module performs explicit small-scale systematic
  encoding checks and now includes full-relation MLE folding proofs for the
  combined-column evaluation and composed codeword layer in the main
  `DistributedOpening`. It now also integrates sampled MLE folding proofs into
  that opening, checking Fiat-Shamir selected fold consistency openings
  against Merkle commitments. Full and compact distributed openings now bind
  sampled worker/query Merkle opening material into the final PCS transcript
  state. A parallel `CompactDistributedOpening` no longer carries the full
  combined vectors and instead checks commitment-bound sampled fold proofs,
  a dedicated sampled composition-query set for combined-column/codeword
  encoding consistency, plus sampled row-weighted worker/codeword consistency.
  The
  compact path is now the default for local final R1CS openings, the local
  Plonkish constraint-residual opening, and the R1CS/Plonkish network
  experiment paths, while explicit full-opening hook paths can still produce
  full openings for compatibility tests. Replacing the full
  correctness proof everywhere with a fully optimized Brakedown/BaseFold proof
  composition and proximity/folding soundness parameters remains a next
  milestone.
- Spartan2 and HyperPlonk are vendored and pinned. Spartan2 sparse-matrix
  coefficient bucketing and HyperPlonk vanilla custom-gate evaluation have been
  source-level ported. HyperPlonk permutation/product factor algebra has also
  been ported into the current accumulator path, but the complete HyperPlonk
  permutation-check protocol remains a next milestone alongside Spartan2 inner
  sumcheck, `eval_W`, and full Spark memory-check ports.

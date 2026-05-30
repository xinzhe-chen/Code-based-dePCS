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

## Current Limitations

- This is not a production SNARK and does not claim zero knowledge or optimized
  proof size. The R1CS route no longer sends the full witness and now includes
  a Spartan-style outer cubic sumcheck and a Spartan-style inner
  product-sumcheck tying random `Az/Bz/Cz` openings to the committed witness
  MLE. The production Spark memory-check protocol is still not complete, and
  the current row-consistency layer remains exhaustive for the prototype. The
  Plonkish route now includes selector commitments,
  random-point virtual gate evaluation subclaims, exhaustive
  gate/copy/accumulator consistency checks, and a committed permutation
  running-product accumulator, but it is still not a full HyperPlonk
  production argument.
- The distributed Brakedown module performs explicit small-scale systematic
  encoding checks and now includes a full-relation MLE folding proof for the
  combined-column evaluation. Replacing this with a fully optimized
  Brakedown/BaseFold proof composition with proximity/folding soundness
  parameters remains a next milestone.
- Spartan2 and HyperPlonk are vendored and pinned. Spartan2 sparse-matrix
  coefficient bucketing and HyperPlonk vanilla custom-gate evaluation have been
  source-level ported. HyperPlonk permutation/product factor algebra has also
  been ported into the current accumulator path, but the complete HyperPlonk
  permutation-check protocol remains a next milestone alongside Spartan2 inner
  sumcheck, `eval_W`, and full Spark memory-check ports.

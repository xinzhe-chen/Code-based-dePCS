# Completion Audit

Date: 2026-06-01

This audit maps the active implementation goal to current repository evidence.
It is intentionally conservative: a requirement is marked proven only when the
current worktree has code, tests, generated artifacts, or documentation that
directly support it.

## Scope Note

The current repository is a research correctness prototype, not a production
SNARK library. Later user direction supersedes the older request for separate
Linux/Windows benchmark scripts: the current accepted script surface is three
interactive entries under `scripts/`:

- `interactive-linux.sh`
- `interactive-macos.sh`
- `interactive-powershell.cmd`

Benchmark automation remains available through the Rust CLI for CI and server
runs.

## Evidence Summary

Current source evidence:

- Workspace crates are declared in root `Cargo.toml`: `pq-core`,
  `pq-transcript`, `pq-sumcheck`, `pq-piop`, `pq-pcs`, `pq-piop-r1cs`,
  `pq-piop-plonkish`, `pq-net`, and `pq-experiments`.
- Common interfaces exist in code:
  - `crates/pq-piop/src/lib.rs`: `Piop` with `prove_interactive` and
    `verify_interactive`.
  - `crates/pq-transcript/src/lib.rs`: `Transcript`, `HashTranscript`,
    domain separators, public/commitment absorption, field challenges, and
    challenge index sampling.
  - `crates/pq-pcs/src/lib.rs`: `PolynomialCommitment`, `DistributedPcs`,
    `DistributedBrakedown`, `DistributedOpening`, and
    `CompactDistributedOpening`.
  - `crates/pq-net/src/lib.rs`: `WorkerRuntime` and `TcpWorkerRuntime`.
- Third-party reference sources are pinned and documented:
  - `third_party/PINS.md`
  - `third_party/PORTING_NOTES.md`
  - Spartan2 pin `0d4f1409e8f30536b8b25ed3f81bc446ed717e61`
  - HyperPlonk pin `2a3b55c97ad8a5d6627108a2e7def2aeccb7f3b9`
- Reproducibility and run guidance:
  - `README.md`
  - `Doc/reproducibility_runbook.md`
  - `results/README.md`
  - `results/release_results/README.md`
- Cross-platform checkout behavior:
  - `.gitattributes` enforces LF for `.sh` entries, CRLF for `.cmd` and
    `.ps1` Windows entries, and text normalization for the rest of the
    repository.
- CI evidence:
  - `.github/workflows/ci.yml` runs formatting, clippy, full workspace tests,
    script menu smoke checks on Windows, Linux, and macOS, and lightweight
    Windows/Linux network benchmark smokes with semantic result verification,
    proof-bundle discovery, proof-bundle reverification, and a
    post-reverification manifest check. The macOS job also runs the
    one-command `quick-smoke` fresh-clone path and checks its JSON summary.
- Local validation evidence from this session:
  - `cargo fmt --check`: passed.
  - `cargo clippy --workspace --all-targets -- -D warnings`: passed.
  - `cargo test --workspace`: passed after the fresh-machine script hardening,
    covering all crate unit tests and doctests.
  - `cargo test -p pq-experiments`: passed with 30 tests after adding direct
    proof-manifest inclusion and verify-report non-pollution regressions.
  - `cargo clippy -p pq-experiments --all-targets -- -D warnings`: passed
    after the final proof-manifest regression additions.
  - Full workspace validation after the proof-manifest, macOS CI, and setup
    wizard build-path updates: `cargo test --workspace` passed across all
    crates and doctests, and
    `cargo clippy --workspace --all-targets -- -D warnings` passed.
  - PowerShell/Linux/macOS menu exit smokes: passed.
  - PowerShell menu smoke for the embedded `scripts/interactive-powershell.cmd`
    payload and Git Bash syntax checks for `scripts/interactive-linux.sh` and
    `scripts/interactive-macos.sh`: passed.
  - Stored-proof tamper regression:
    `cargo test -p pq-experiments verify_proof_command_fails_when_stored_proof_is_tampered`
    passed. The test writes a real stored R1CS proof bundle, verifies it,
    tampers the proof payload, verifies that the report records failure, and
    checks that `verify-proof` exits with an error.
  - Proof experiment smoke
    `target\proof-smoke\bench-20260601-095926-proof`: produced a stored R1CS
    proof bundle and `verify-proof --all` generated a JSON/HTML verification
    report.
  - Lightweight local benchmark
    `target\bench-smoke\bench-20260601-100024-performance`: `verify-results`
    passed with `files_checked=25`, `source_rows_checked=2`,
    `phase_rows_checked=6`, and `summary_rows_checked=2`; `verify-proof --all`
    verified both stored proof bundles, and a second `verify-results` still
    passed after report generation.
  - Release network benchmark
    `target\network-smoke\bench-20260601-120350-performance`: `verify-results`
    passed with `files_checked=27`, `source_rows_checked=4`,
    `phase_rows_checked=11`, and `summary_rows_checked=4`; `list-proofs`
    found 4 proof bundles and `verify-proof --all` verified all 4. A second
    `verify-results` still passed after the extra verification reports.
  - Latest local proof-manifest smoke
    `target\latest-smoke\bench-20260601-125449-performance`: `verify-results`
    passed before extra proof reverification with `files_checked=25`,
    `bytes_checked=392201`, `source_rows_checked=2`,
    `phase_rows_checked=6`, and `summary_rows_checked=2`; `list-proofs`
    found 2 valid proof bundles and `verify-proof --all` verified both. A
    second `verify-results` returned the same `files_checked=25` and
    `bytes_checked=392201`, proving that `verifications/` reports did not
    mutate or pollute the performance benchmark manifest.
  - Direct result-integrity regressions:
    `result_manifest_includes_proof_artifacts_with_hashes` checks that
    `proofs/index.json` and stored proof bundles are part of the benchmark
    manifest with byte counts and SHA-256 hashes;
    `proof_reverification_reports_do_not_pollute_benchmark_verification`
    builds a semantic benchmark fixture with a real R1CS proof, verifies it,
    runs stored-proof reverification, and confirms the follow-up
    `verify-results` report has unchanged file count, byte count, source rows,
    phase rows, and summary rows.
  - Fresh-clone quick smoke
    `cargo run -p pq-experiments -- quick-smoke --out target\quick-smoke`:
    generated `target\quick-smoke\bench-20260601-132153-performance`, verified
    the result manifest with `files_checked=25`, `bytes_checked=392125`,
    `source_rows_checked=2`, `phase_rows_checked=6`,
    `summary_rows_checked=2`, reverified 2 stored proofs, and checked that
    post-reverification benchmark counts were unchanged.
  - CI quick-smoke guard: `ci_guards_fresh_clone_quick_smoke` confirms the
    workflow runs `cargo run -p pq-experiments -- quick-smoke` and checks
    `proofs_verified` plus `verify_report_html`.
  - CLI help behavior: the rebuilt
    `target\debug\pq-experiments.exe quick-smoke --help` prints usage to
    stdout, leaves stderr empty, and returns exit code 0;
    `usage_help_exits_successfully` protects help-as-success semantics while
    preserving nonzero exit codes for real argument errors.
  - Final readiness cleanup removed remaining repository-local wording that
    could imply synthetic proof paths or unfinished shortcuts outside
    historical third-party sources. Validation passed for:
    `cargo test -p pq-experiments result_manifest_includes_proof_artifacts_with_hashes`,
    `cargo test -p pq-pcs distributed_verify_rejects_bad_range_lengths`,
    `cargo test -p pq-experiments current_user_docs_do_not_reference_removed_script_entries`,
    `cargo test -p pq-experiments gitignore_preserves_scratch_vs_release_result_split`,
    `cargo fmt --check`, `git diff --check`, `git diff --cached --check`,
    `cargo test --workspace`, and
    `cargo clippy --workspace --all-targets -- -D warnings`.
  - Follow-up Windows entry cleanup removed the repository `tools/` directory.
    `scripts/interactive-powershell.cmd` now embeds its PowerShell menu payload
    directly, extracts it to ignored `target/windows/`, and runs it with
    `-ExecutionPolicy Bypass`. `cmd /c "echo 0| scripts\interactive-powershell.cmd -NoPause"`
    rendered the menu and exited cleanly.
  - Interactive benchmark cleanup removed the paper-preset, PCS query, and
    figure-compilation prompts. The wizard now asks for a custom grid without
    square-bracket recommendations, uses hidden defaults for blank inputs,
    fixes `pcs_queries=1`, compiles figures by default, and runs directly after
    printing the grid summary.
  - Historical scratch `results/bench-*` directories and `results/logs` were
    removed; `results/README.md` and `results/release_results/` remain.

## Requirement Matrix

| Requirement | Current status | Evidence | Notes |
| --- | --- | --- | --- |
| Clear Rust workspace modules | Proven | Root `Cargo.toml`, `README.md` workspace section | Crate boundaries match core/transcript/sumcheck/PIOP/PCS/net/experiments. |
| R1CS PIOP route | Proven for supported prototype surface | `crates/pq-piop-r1cs`, `README.md` prototype boundary, workspace tests | Implements distributed Spartan-style checks with PCS/FS integration. Not a production Spartan/Spark implementation. |
| Plonkish PIOP route | Proven for supported gate + permutation surface | `crates/pq-piop-plonkish`, `README.md`, workspace tests | Supports gate/permutation adapter; lookup and full HyperPlonk production argument remain out of scope. |
| Distributed PCS as standalone module | Proven | `crates/pq-pcs`, `PolynomialCommitment`, `DistributedPcs`, `DistributedBrakedown` | Uses transparent SHA-256/Merkle commitments and Brakedown-shaped distributed openings. |
| Fiat-Shamir transcript integration | Proven | `crates/pq-transcript`, PIOP/PCS generic transcript APIs, transcript tests | Challenges are transcript-derived; message reordering/domain tests exist. |
| PCS + PIOP + FS connected end-to-end | Proven for supported R1CS/Plonkish experiments | `pq-experiments`, local/network proof paths, workspace tests, benchmark sanity run | Both protocols produce verified positive proof rows in the benchmark sanity run. |
| Internal tests before integration | Proven by current test suite structure | Workspace tests across `pq-core`, `pq-sumcheck`, `pq-pcs`, `pq-piop-r1cs`, `pq-piop-plonkish`, `pq-transcript`, `pq-net`, `pq-experiments` | Full workspace tests passed locally. |
| Spartan source reuse | Proven for documented ports | `third_party/PINS.md`, `third_party/PORTING_NOTES.md`, `pq-core` sparse-matrix port tests | Spartan2 is vendored; sparse matrix bucketing and Spartan-style organization are ported. Full upstream Spartan code is not blindly used as a dependency. |
| HyperPlonk source reuse | Proven for documented ports | `third_party/PINS.md`, `third_party/PORTING_NOTES.md`, Plonkish tests | HyperPlonk gate evaluator and product-factor algebra are ported. Full upstream KZG/PCS is excluded. |
| No KZG/IPA as final PCS | Proven | `third_party/PINS.md`, `.gitignore`, `pq-pcs` implementation | HyperPlonk KZG SRS is excluded; final executable PCS is transparent Merkle/Brakedown-shaped code. |
| Interactive experiment scripts | Proven | `scripts/` contains exactly three interactive entries; `pq-experiments` regression test enforces this | Current UI is menu-driven and not predetermined-parameter wrappers. |
| Minimal dependency checks and install path | Proven for coded/script-smoked paths | `interactive-linux.sh`, embedded `interactive-powershell.cmd` payload, `interactive_scripts_offer_dependency_install_from_actions`, parser/syntax/menu smokes | Proof/verify/benchmark actions now offer installation when dependencies are missing; setup/check also offers to build the debug `pq-experiments` target when absent. Fresh-host package-manager execution remains unproven in this session. |
| Windows script does not flash-close | Proven by script behavior and smoke checks | `interactive-powershell.cmd` launcher, embedded PowerShell payload, `Read-Host` prompts, default pause, `-NoPause` only for CI | The user-facing `.cmd` entry extracts its embedded payload to ignored `target/windows/` and invokes it with `-ExecutionPolicy Bypass` before the menu loads; no repository `tools/` directory remains. |
| Progress during experiments | Proven | Benchmark runner prints completed-job progress bars; scripts print build/check steps | Regression tests cover total-job counting. |
| Proof experiment stores real proofs | Proven | `proof-experiment`, `ProofBundle`, `proofs/*.proof.json`, `proofs/index.json`, `list-proofs`, `verify-proof`, local smoke, `result_manifest_includes_proof_artifacts_with_hashes`, stored-proof tamper/corrupt regressions | Proofs are serialized and reverified later against regenerated public sample instances; verification checks proof payloads, metadata, index file size, and SHA-256; tampered or corrupt stored proofs still produce JSON/HTML reports before `verify-proof` exits nonzero. |
| Verify experiments do not pollute benchmark results | Proven | `verify-proof` writes only under `verifications/`; post-report `verify-results` smokes still pass with unchanged file and byte counts; `proof_reverification_reports_do_not_pollute_benchmark_verification` | Benchmark manifest includes benchmark artifacts and proof bundles, but deliberately ignores later `verifications/` reports. |
| Benchmark raw data output | Proven | `target\bench-smoke\bench-20260601-100024-performance/source.csv`, `source.json`; verifier semantic checks | Scratch `results/bench-*` directories are intentionally ignored and were cleaned. |
| Benchmark charts and paper figure sources | Proven for generated artifacts | Lightweight run generated SVG and PGFPlots/TikZ files; verifier checked structure | Full compiled paper PDF requires local LaTeX toolchain and paper-quality run. |
| HTML experiment overview | Proven | Lightweight run generated `overview.html`; verifier checked it | Dashboard is static and self-contained. |
| `results/release_results` publication split | Proven | `.gitignore`, `results/README.md`, `results/release_results/README.md` | Scratch results ignored; curated release copying is now intentionally manual per user direction. |
| n selectable and n-range selectable | Proven | `README.md`, `pq-experiments` parser tests | Supports `--n-range`, `--nv-range`, `--n-values`, `--nv-powers`. |
| Performance benchmark excludes correctness tests/repeats | Proven | Benchmark command uses positive rows and `--repeats 1`; parser rejects repeats | Negative tests remain in unit/integration paths. |
| Worker scaling core fairness and core use | Proven for the current Windows script/runtime path | `pq-experiments` core-plan parser/tests, network runner affinity code, Rayon thread-pool configuration, verified run `target\network-smoke\bench-20260601-120350-performance`, PowerShell benchmark wizard smoke | The prior run recorded `host_logical_cores=20`, `max_workers=2`, `cores_per_worker=10`, and `windows-powershell-processor-affinity`; parser tests cover the clarified 20-core rule: `workers=1,4` gives `cores_per_worker=5`, while `workers=1,2,4,8` gives `cores_per_worker=2`. Current runtime code also sets Rayon threads from that plan, so affinity and algorithmic worker count are aligned. |
| Lightweight benchmark and theory comparison | Proven as sanity evidence | `Doc/reproducibility_runbook.md`, verified local and release network smokes under `target/` | The release network run is a tiny smoke, not paper-quality evidence. |
| GitHub-quality repo hygiene | Proven for repository handoff readiness | README, CI, licenses, `.gitignore`, third-party pins, runbook, `quick-smoke`, `ci_guards_fresh_clone_quick_smoke`, final workspace validation | One-command local fresh-clone smoke is implemented, passed in this checkout, and is wired into macOS CI. Physical validation on separate fresh machines remains outside current worktree evidence, but the repo contains the intended detection/install and quick-smoke paths. |

## Known Prototype Boundaries

These are not blockers for a research prototype, but they prevent a stronger
claim such as "production protocol complete":

- R1CS is a distributed Spartan/Spark-style correctness prototype. The Spark
  matrix-evaluation verifier still recomputes small public sparse traces from
  public entries, although the trace checks are commitment-bound and sampled.
- Plonkish supports gate and permutation checks with committed accumulator and
  sampled openings. Lookup arguments, complex custom gates, and the complete
  production HyperPlonk permutation-check protocol are out of scope.
- `pq-pcs` implements transparent Merkle/Brakedown-shaped distributed openings
  with systematic/parity encoding checks and MLE folding proofs, not an
  optimized production Brakedown/BaseFold proximity proof.
- The dependency install branches have been coded and script-smoked, but not
  end-to-end validated on fresh Windows/Linux/macOS hosts in this session.
- The local lightweight benchmark is a debug, local-only sanity run, and the
  release network smoke is a tiny `n=2` network-only run. They are not
  paper-quality evidence. A paper-quality run still requires release mode,
  `--paper-preset`, `--runner both`, compiled figures, and
  `verify-results --paper-quality`.

## Current Decision

Mark the overall goal complete for the requested research-grade correctness
prototype. The repository now has the R1CS and Plonkish proof routes,
standalone distributed PCS, Fiat-Shamir integration, network runner,
interactive cross-platform experiment entrypoints, proof storage and
reverification, performance benchmark output with raw data/figures/HTML
overview, result hygiene, runbook, pinned third-party reuse notes, and final
workspace validation evidence. The known boundaries above remain documented
research-prototype limits, not blockers for the user's stated non-production
target.

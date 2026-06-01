# Completion Audit

Date: 2026-06-01

This audit maps the active implementation goal to current repository evidence.
It is intentionally conservative: a requirement is marked proven only when the
current worktree has code, tests, generated artifacts, or documentation that
directly support it.

## Scope Note

The current repository is a research correctness prototype, not a production
SNARK library. Later user direction supersedes the older request for separate
Linux/Windows benchmark wrappers: the current accepted script surface is three
interactive entries under `scripts/`:

- `interactive-linux.sh`
- `interactive-macos.sh`
- `interactive-powershell.ps1`

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
- CI evidence:
  - `.github/workflows/ci.yml` runs formatting, clippy, full workspace tests,
    script menu smoke checks, and lightweight Windows/Linux network benchmark
    smokes with semantic result verification.
- Local validation evidence from this session:
  - `cargo fmt --check`: passed.
  - `cargo clippy --workspace --all-targets -- -D warnings`: passed.
  - `cargo test --workspace`: passed.
  - PowerShell/Linux/macOS menu exit smokes: passed.
  - Lightweight local benchmark
    `results\bench-1780301737355633500`: `verify-results` passed with
    `source_rows_checked=2`, `phase_rows_checked=6`, and
    `summary_rows_checked=2`.

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
| Minimal dependency checks and install path | Partially proven | Interactive scripts implement preflight/install branches; CI checks menu exit | Not fully proven on brand-new Windows/Linux/macOS machines in this session. |
| Windows script does not flash-close | Proven by script behavior and smoke checks | `interactive-powershell.ps1` default pause, `-NoPause` only for CI | Direct `.ps1` can still hit Windows ExecutionPolicy; README uses `-ExecutionPolicy Bypass`. |
| Progress during experiments | Proven | Benchmark runner prints completed-job progress bars; scripts print build/check steps | Regression tests cover total-job counting. |
| Benchmark raw data output | Proven | `results\bench-1780301737355633500/source.csv`, `source.json`; verifier semantic checks | Scratch `results/bench-*` directories are intentionally ignored. |
| Benchmark charts and paper figure sources | Proven for generated artifacts | Lightweight run generated SVG and PGFPlots/TikZ files; verifier checked structure | Full compiled paper PDF requires local LaTeX toolchain and paper-quality run. |
| HTML experiment overview | Proven | Lightweight run generated `overview.html`; verifier checked it | Dashboard is static and self-contained. |
| `results/release_results` publication split | Proven | `.gitignore`, `results/README.md`, `results/release_results/README.md` | Scratch results ignored; curated results can be copied into release directory. |
| n selectable and n-range selectable | Proven | `README.md`, `pq-experiments` parser tests | Supports `--n-range`, `--nv-range`, `--n-values`, `--nv-powers`. |
| Performance benchmark excludes correctness tests/repeats | Proven | Benchmark command uses positive rows and `--repeats 1`; parser rejects repeats | Negative tests remain in unit/integration paths. |
| Worker scaling core fairness | Proven in code/tests, not fully measured in latest sanity run | `pq-experiments` core-plan parser/tests and network runner affinity code | Latest local benchmark was workers=1, so it cannot validate scaling behavior empirically. |
| Lightweight benchmark and theory comparison | Proven as sanity evidence | `Doc/reproducibility_runbook.md` and verified run `bench-1780301737355633500` | Correctly states that workers=1 local debug run cannot support distributed speedup claims. |
| GitHub-quality repo hygiene | Partially proven | README, CI, licenses, `.gitignore`, third-party pins, runbook | A final commit/PR and optional fresh-clone validation on separate machines remain outside current worktree evidence. |

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
- The local lightweight benchmark is a debug, local-only sanity run; it is not
  paper-quality evidence. A paper-quality run still requires release mode,
  `--paper-preset`, `--runner both`, compiled figures, and
  `verify-results --paper-quality`.

## Current Decision

Do not mark the overall goal complete solely from this audit. The repository is
substantially aligned with the requested research prototype, and the core code,
tests, scripts, benchmark artifacts, and runbook are in place. The remaining
uncertainty is around the strength of the word "complete" relative to the
paper protocol: the repo truthfully documents several non-production protocol
boundaries. A final completion decision should either accept those boundaries
as the intended research-grade scope or fund the next milestone work to close
them.

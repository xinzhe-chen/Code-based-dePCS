# pq_dSNARK Correctness Prototype

This workspace implements a correctness-first prototype of the two PIOP routes
described in `Doc/pq_dSNARK.pdf`:

- distributed Spartan-style R1CS PIOP;
- Plonkish gate/permutation PIOP adapter;
- transparent hash/Merkle distributed PCS module based on the Brakedown
  protocol shape;
- Fiat-Shamir transcript integration;
- local and TCP worker runtimes for experiments.

The code is not a production SNARK library. It is built to keep module
boundaries explicit and to test each algebraic component before integration.

## Workspace

- `crates/pq-core`: finite-field, multilinear-extension, R1CS, Plonkish, and
  partition utilities. The R1CS sparse-matrix multiplication path includes the
  coefficient-bucketed accelerator ported from Spartan2's sparse matrix code;
  Plonkish row evaluation uses the vanilla customized-gate evaluator ported
  from HyperPlonk.
- `crates/pq-transcript`: Fiat-Shamir transcript API.
- `crates/pq-sumcheck`: sumcheck, equality-polynomial weighted zerocheck,
  rational sumcheck, multiset checks.
- `crates/pq-piop`: protocol-agnostic PIOP trait tying statements,
  witnesses, proofs, metrics, PCS parameters, and transcript implementations
  together without committing to a concrete arithmetization.
- `crates/pq-pcs`: PCS traits, Merkle commitments, distributed Brakedown
  correctness prototype. The distributed trait exposes explicit
  `partition`, `worker_commit`, `worker_open`, `master_commit`, `open_at`, and
  `verify` stages so local tests and TCP workers use the same PCS API. The
  base `PolynomialCommitment` trait exposes transparent setup, single opening,
  and batch opening/verification APIs.
- `crates/pq-piop-r1cs`: distributed Spartan-style R1CS PIOP implementing
  the shared `pq-piop::Piop` adapter.
- `crates/pq-piop-plonkish`: Plonkish gate/permutation PIOP implementing
  the shared `pq-piop::Piop` adapter.
- `crates/pq-net`: TCP master/worker runtime.
- `crates/pq-experiments`: interactive experiment CLI.

## Basic Commands

The `scripts/` directory intentionally contains only three user-facing script
entrypoints, and all three are menu-driven:

```powershell
.\scripts\interactive-powershell.cmd
```

```bash
bash scripts/interactive-linux.sh
bash scripts/interactive-macos.sh
```

The Windows entry is a clickable `.cmd` launcher with its PowerShell menu
payload embedded inside the same file. It extracts that payload to
`target/windows/interactive-powershell.generated.ps1` and runs it with
`-ExecutionPolicy Bypass`, so fresh Windows machines with restricted `.ps1`
policy do not close before the menu loads. By default it waits for Enter before
closing, including after an error. Use `-NoPause` only for CI-style scripted
smoke checks. Runtime startup failures are also written to
`results/logs/interactive-powershell-last.log`.

For a fresh-clone validation checklist and the latest lightweight benchmark
sanity-check interpretation, see `Doc/reproducibility_runbook.md`.
For a requirement-by-requirement status audit, see
`Doc/completion_audit.md`.

The menu is the script API. It does not run a predetermined experiment when
opened. The available actions are:

- environment setup/check, which runs preflight, can install/check missing
  Rust, Git, build-tool, and core platform dependencies, and can build the
  debug `pq-experiments` target on a fresh clone;
- proof experiment wizard, which runs a selected positive proof path and writes
  real proof bundles under `proofs/` in a timestamped bench folder;
- verify experiments wizard, which scans `results/bench-*`, shows which folders
  contain stored proofs, marks unreadable proof files as invalid, and writes
  extra verification reports under `verifications/`;
- performance benchmark wizard, the final menu action.

On macOS, the preflight explicitly checks Xcode Command Line Tools. If they are
missing, the environment setup action invokes Apple's `xcode-select --install`
prompt and then asks you to rerun the menu after the installer completes.

The benchmark wizard is for performance runs only. Each atomic benchmark row is
one real end-to-end prove+verify over one selected circuit and uses
`--repeats 1`; correctness tests and negative-case tests are not folded into
benchmark timing. During a benchmark, `pq-experiments` prints an accurate
completed-jobs progress bar before and after each actual job, so the
denominator is the configured Cartesian product and the numerator advances only
after a real prove+verify job finishes.

For network scaling runs with multiple worker counts, the benchmark path first
detects host logical cores. It fixes `cores_per_worker =
floor(host_logical_cores / max(workers))` for every distributed subexperiment
in the same run. Linux workers are launched through `taskset`; Windows workers
are launched with hidden PowerShell child processes and `ProcessorAffinity`
masks. The scripts print the derived core plan before the benchmark starts, and
the result metadata records `host_logical_cores`, `cores_per_worker`, and
`core_affinity`.

Open `results/bench-YYYYMMDD-HHMMSS-performance/overview.html` after a
benchmark for the visual experiment dashboard. Proof experiments use
`bench-YYYYMMDD-HHMMSS-proof`; performance benchmarks use
`bench-YYYYMMDD-HHMMSS-performance`. Local scratch runs under `results/bench-*`
are ignored by Git. If you want to publish selected evidence, manually copy the
chosen verified run into `results/release_results/`.
For paper-facing results, use the verifier's paper-quality gate; it requires a
release build, `runner=both`, the full paper preset grid, compiled figures,
verified positive cases, and performance-only benchmark rows.

Advanced automation and CI can call the Rust binary directly instead of using
the interactive scripts:

```bash
cargo run -p pq-experiments -- interactive
cargo run -p pq-experiments --release -- proof-experiment --protocol both --runner local --n 2 --workers 1 --pcs-queries 1
cargo run -p pq-experiments -- list-proofs --results results --format text
cargo run -p pq-experiments -- verify-proof results/bench-YYYYMMDD-HHMMSS-proof --all --format json
cargo run -p pq-experiments -- quick-smoke --out target/quick-smoke
cargo run -p pq-experiments --release -- benchmark --runner both --n-range 2..5 --worker-power-range 0..2 --pcs-queries 1
cargo run -p pq-experiments -- verify-results results/bench-YYYYMMDD-HHMMSS-performance --format json
cargo run -p pq-experiments -- verify-proof results/bench-YYYYMMDD-HHMMSS-performance --all --format json
```

The experiment CLI supports `--case positive`, `--case negative`, and
`--case both`. Negative cases intentionally tamper with the statement or
proof openings and must verify as `false`. `--pcs-queries N` controls the
requested distributed PCS query count; the protocol records both the requested
parameter and the effective capped query count in the Fiat-Shamir transcript.
JSON and CSV experiment rows include `failure_reason` for negative or failed
verification cases. R1CS fallback metrics for rejected negative cases use the
same PCS opening communication accounting as successful verification, so the
CSV/JSON source data does not undercount failed proofs. Rows produced by
`master --protocol ...` also include non-zero `network_bytes`; in that path
the TCP workers compute the distributed PCS partition commitments and opening
proofs used by the prover. For R1CS network proofs, the same TCP workers also
compute Spark partition fingerprints and matrix-evaluation claims from their
partition-local sparse R1CS entries. Each worker stores the shard it committed
under the PCS commit session, and later `PcsOpen` requests send only the
session, worker id, shard start, and query indices instead of resending row
values.
`communication_bytes` counts the distributed PCS opening material reported by
verification, including compact/full openings and sampled distributed index
openings used by R1CS row/witness consistency and Plonkish gate/permutation
consistency checks. It is distinct from measured loopback TCP `network_bytes`.
Network byte accounting is computed through the same `pq-net` frame encoder used
on the socket, including the 4-byte frame length prefix and encoded
request/response payloads.
`proof_bytes` is computed from canonical byte accounting over the proof
structure, including commitments, vector length prefixes, Merkle paths,
distributed PCS openings, zerocheck rounds, Plonkish selector commitments and
gate virtual-evaluation subclaims, Plonkish permutation accumulator random
recurrence subclaims and cubic recurrence sumchecks, R1CS inner
product-sumcheck openings, and PIOP
consistency openings.
The benchmark command creates `results/bench-YYYYMMDD-HHMMSS-performance/`
containing
`metadata.json`, `result_manifest.json` with SHA-256 checksums for every other
artifact, a static `overview.html` experiment dashboard, phase-level
`phase_timing.csv` / `phase_timing.json`, raw performance-row `source.csv`,
raw performance-row `source.json`, `summary_stats.csv`, `summary.txt`,
stored proof bundles under `proofs/`, SVG charts, individual PGFPlots/TikZ
`.tex` figures, plus a
paper-oriented 2x2 `paper_figures.tex` and `paper_figures_standalone.tex`
wrapper for prove time, verify time, proof size, and worker scaling versus the
`workers=1` non-distributed baseline. Network bytes and network/local runner
overhead are exported as separate `network_bytes_by_size.*` and
`runner_overhead_by_size.*` figures so they can be included independently.
`overview.html` is self-contained and links to the source data, SVG previews,
PGFPlots files, grouped paper figure, manifest, and metadata. It summarizes the
configuration, correctness gate, core allocation, scaling interpretation
against the `workers=1` baseline, and per-configuration summary statistics for
quick visual inspection before opening the raw data.
For a one-command fresh-clone smoke, `quick-smoke` runs the smallest local
performance benchmark, verifies the result manifest, reverifies all stored
proofs, and checks that the extra verification reports do not change benchmark
artifact counts.
`metadata.json` also records provenance for reproducibility: host OS/arch,
debug/release profile, full command line, git commit/branch/dirty state,
`rustc` and `cargo` versions, `RUSTFLAGS`, `Cargo.lock` and
`rust-toolchain.toml` SHA-256 hashes, and pinned third-party source commits
when those repositories are present.
Benchmark sizes can be supplied directly with
`--sizes 4,8,16`, as exponent lists with `--nv-powers 2,3,4`
or `--n-values 2,3,4`, or as inclusive exponent ranges with
`--nv-range 2..6` or `--n-range 2..6`, where the grid is
`nv=2^2,2^3,...,2^6`.
`--worker-power-range 0..2` expands to `workers=1,2,4`; `workers=1` is
also added automatically when a distributed-only worker exponent range such as
`1..3` is requested, because scaling summaries need the non-distributed
baseline. `--paper-preset`
selects the paper-facing default grid `n=2..6`, `workers=1,2,4`, and
`pcs_queries=3`; explicit
size, worker, and query flags override those preset defaults. Source
rows include both `runner` and `nv_power`/`size`; `--runner network` /
`--runner network` sends the benchmark through loopback TCP workers for PCS, and
for R1CS also Spark shard claims, recording non-zero `network_bytes` for
network-backed proof rows. `--runner both`
records local and network-backed proof rows in the same result directory so the
generated figures can directly compare both real paths. The figure outputs use
publication-oriented vector styling with measured data points, fixed protocol
colors, worker line/marker encodings, clean axes, legend boxes, and an
explicit perfect-linear upper bound only on the worker-scaling plot. The PGFPlots
outputs use an Okabe-Ito
color-blind-friendly palette, conservative grid/axis styling, a shared bottom
legend, a KiB proof-size axis in the grouped paper figure, and measured points
from the performance rows. `source.csv` and
`source.json` retain each raw performance row with a `trial` column fixed at 1;
`summary_stats.csv` records per-configuration means and sample standard
deviations, which are zero for the no-repeat performance benchmark.
`network_bytes_by_size.*` shows measured TCP worker communication
cost, and `runner_overhead_by_size.*` shows network-runner prover time divided
by local-runner prover time for matching protocol/worker/size settings. The
SVG files are quick previews; the `.tex` outputs are the paper-facing artifacts
and are annotated with their measured-data sources.
Selecting figure compilation in the benchmark wizard, or passing
`--compile-figures` to the Rust benchmark command, invokes `pdflatex` or
`tectonic` from the result directory and writes `paper_figures_standalone.pdf`.
The automatic compiler mode prefers `tectonic` when present because it is
better suited to non-interactive runs. The interactive environment check reports
whether a LaTeX figure compiler is installed and the setup path installs
`tectonic` when figure compilation support is missing.
Each benchmark job validates exactly one positive end-to-end performance path:
prove one circuit and verify that proof. Negative/tampered proof checks remain
in the unit tests, integration tests, and ordinary experiment commands with
`--case negative|both`; they are deliberately excluded from performance
benchmark rows.
Generated result directories can be checked later from the interactive
verification menu or with
`cargo run -p pq-experiments -- verify-results results/bench-YYYYMMDD-HHMMSS-performance --format json`;
the verifier recomputes SHA-256 hashes from `result_manifest.json` and fails on
missing, modified, or extra top-level artifacts. It also cross-checks
`metadata.json`, `source.csv`, `source.json`, `summary_stats.csv`,
`phase_timing.csv`, `overview.html`, SVG previews, and PGFPlots/TikZ sources
so a manifest-consistent but semantically incomplete benchmark is rejected. The
JSON/CSV report includes `source_rows_checked`, `phase_rows_checked`, and
`summary_rows_checked`.
Add `--paper-quality` for the
stricter publication gate: it parses `metadata.json`
and rejects non-release runs, local-only runs, incomplete paper grids, missing
compiled figures, repeated/non-performance rows, and runs that did not verify
every positive benchmark case. It also validates that `source.csv` covers each
paper-grid local/network/protocol/worker/size cell exactly once, that
`phase_timing.csv` contains every benchmark job plus source/final/total phases,
and that the HTML/SVG/PGFPlots/PDF artifacts contain expected figure markers.
The benchmark runner also creates each timestamped bench directory atomically
and performs this manifest self-check before reporting completion. Stored proof
bundles can be reverified later with
`cargo run -p pq-experiments -- verify-proof results/bench-YYYYMMDD-HHMMSS-performance --all --format json`.
This writes a JSON and HTML report under `verifications/` and deliberately does
not rewrite `source.csv`, `metadata.json`, `result_manifest.json`, figures, or
the benchmark overview. If any selected stored proof fails, the report is still
written and the command exits nonzero. The verifier checks the proof payload,
bundle metadata, and the matching `proofs/index.json` entry, including file
size and SHA-256; malformed proof JSON is also recorded as a failed proof
outcome instead of suppressing the report.
Benchmark validation requires `workers=1` to be
present, so the scaling plot cannot silently invent a baseline. `summary.txt` and
`metadata.json` record whether the benchmark binary was built in `debug` or
`release`; the interactive benchmark wizard builds `release` for performance
runs. The `.tex` files are intended for direct LaTeX inclusion
with `\usepackage{pgfplots}`,
`\usepgfplotslibrary{groupplots}` for `paper_figures.tex`, and
`\pgfplotsset{compat=1.18}`; the source data stays alongside each figure. The
interactive scripts print plain progress steps for cargo checks/builds,
selected size mode, current benchmark job, output directory, and completion
status; progress logs are kept separate from generated CSV/JSON source data.

## Current Prototype Boundary

## Repository Quality Gates

The repository is licensed as `MIT OR Apache-2.0`; root copies are provided in
`LICENSE-MIT` and `LICENSE-APACHE`. Vendored references keep their upstream
licenses under `third_party/`, with pins and porting notes in
`third_party/PINS.md` and `third_party/PORTING_NOTES.md`.

GitHub Actions CI is defined in `.github/workflows/ci.yml`. It checks
formatting, clippy, the full workspace test suite, interactive script menu
exit paths on Windows/Linux/macOS entrypoints, and lightweight Windows/Linux
network benchmark smokes that verify `overview.html`, manifests, source rows,
phase timing rows, and summary rows.

This is a correctness prototype. It uses a small Goldilocks-field backend and
transparent SHA-256/Merkle commitments. R1CS and Plonkish routes both pass
through Fiat-Shamir, equality-weighted zerocheck, and the `pq-pcs` distributed
Brakedown module, but the Brakedown/BaseFold proof-composition layer is
represented by explicit small-scale systematic, adjacent-parity,
stride-parity, and blend-parity encoding checks, a full combined-codeword
composition check, and MLE folding evaluation proofs for both the row-weighted
combined column and its composed codeword rather than an optimized production
proof. The distributed opening now also carries sampled MLE folding proofs for
both the combined column and composed codeword; the verifier checks the
Fiat-Shamir selected fold-consistency openings against Merkle commitments in
the same transcript. The full folding proofs remain in place as the
small-scale correctness path while the sampled checks move the PCS module
toward a BaseFold/FRI-style proximity proof. The PCS crate also exposes a
parallel `CompactDistributedOpening` path that replaces the full combined
vectors with combined/codeword commitments, sampled MLE folding proofs, and
Fiat-Shamir selected row-weighted worker/codeword consistency openings; this
compact path is now the default local PCS opening for the final R1CS PCS
claims and the Plonkish constraint-residual claim. Hook-based/network
experiments can still produce and verify the original full opening where that
compatibility path is selected; both R1CS and Plonkish network runners use the
compact worker-provider path for their final PCS openings.
The R1CS proof does not carry the full witness; it now uses a
Spartan-style outer cubic sumcheck over `eq_tau(x) * (Az(x)Bz(x)-Cz(x))`,
distributed PCS openings for the final `Az/Bz/Cz` claims, a Spartan-style inner
product sumcheck for the random linear combination of public matrix
projections against the committed witness MLE, witness/linearization
commitments, transcript-sampled row-consistency openings, transcript-bound
distributed sparse-matrix fingerprints, and Spark-style per-matrix sparse
evaluation claims for `A/B/C`. Those matrix claims include row, column, and value
memory-consistency checks reduced to transcript-bound product multiset
equality, with per-worker Init/Read/Write/Audit product digests plus Merkle
commitments and Fiat-Shamir sampled openings for the Init/Read/Write/Audit
trace columns. The Spark trace sampling uses the same `--pcs-queries`
parameter as the distributed PCS checks. The Spark matrix-evaluation
transcript now absorbs each sparse matrix entry index, row, column, and value
before deriving downstream worker and memory challenges, and the inner
linearization verifier checks its final value against the Spark combined
matrix evaluation instead of recomputing the public matrix projection directly.
The default local R1CS prover now uses the compact distributed PCS opening
variant for those final PCS openings, while the explicit full-opening hook path
can still produce and verify the original full opening for compatibility
tests. It is still not the full production Spartan/Spark protocol: the current
Spark matrix-evaluation verifier still recomputes small public sparse traces
from public matrix entries, although those traces are now commitment-bound and
sampled inside the transcript; this remains short of a production-succinct
Spark memory proof. The Plonkish
route also uses committed `A/B/C`, selector, gate-residual, and
permutation-residual oracle columns with
a Fiat-Shamir random-point virtual gate evaluation subclaim whose oracle-column
evaluations are now bound by sampled MLE folding openings instead of carrying
the full gate-column vectors in that subclaim. Its final constraint-residual
PCS opening now uses the compact distributed PCS path by default. It also has
a Fiat-Shamir `beta/gamma` permutation running-product accumulator committed
by Merkle PCS. Its accumulator random subclaim now precommits the shifted
`next` traces and transition-residual commitments before deriving the random
point, binds column evaluations with sampled MLE folding openings, and adds
separate numerator/denominator cubic zerocheck sumchecks for the recurrence
relation `current * (value + beta * id + gamma * active) = next - residual`.
The verifier checks those sumcheck final evaluations against committed sampled
openings for `current/value/id/active/next/residual` at the sumcheck challenge
point, so recurrence binding is no longer only a sampled-index check. The
accumulator boundary openings are also verified and absorbed with their full
Merkle paths before downstream accumulator challenges are derived, and the
top-level sampled accumulator recurrence queries are transcript-bound before
the later constraint-residual zerocheck. The subclaim no longer carries full
accumulator column vectors; gate/copy/accumulator index consistency openings
remain transcript-sampled with the configured query count. This is still not
the full production HyperPlonk permutation argument.

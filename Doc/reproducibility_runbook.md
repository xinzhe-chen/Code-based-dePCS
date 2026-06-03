# Reproducibility Runbook

This note is the shortest path for a fresh clone to validate the current
research prototype and to reproduce the lightweight benchmark sanity check.

## Fresh Clone Path

Windows:

```powershell
.\scripts\interactive-powershell.cmd
```

The Windows entry is a `.cmd` launcher, not a raw `.ps1` entry. Its PowerShell
menu payload is embedded in the same file and extracted to
`target/windows/interactive-powershell.generated.ps1` at runtime, then started
with `-ExecutionPolicy Bypass`. This avoids the common fresh-machine failure
where right-clicking a `.ps1` closes before the script can print an error.

Linux:

```bash
bash scripts/interactive-linux.sh
```

macOS:

```bash
bash scripts/interactive-macos.sh
```

Use the menu in this order on a new machine:

1. Run environment setup/check, installing missing dependencies if needed and
   building the debug `pq-experiments` target when the script offers it.
2. Run proof experiment wizard for a small positive proof path; it stores real
   proof bundles under `proofs/`.
3. Use verify experiments to reverify the stored proof and generate a report
   under `verifications/`.
4. Run performance benchmark wizard for a small grid. This is the final menu
   action and also stores proof bundles. The wizard always asks for a custom
   grid, not a paper preset, and it does not display square-bracket
   recommendations. Blank benchmark inputs use hidden defaults: `n=8..10` and
   worker exponent `0..min(floor(log2(logical_cores)), n_min, 3)`. For a quick
   PC smoke run, type a lower `n` range such as `2..3`; for a performance run,
   leave the hidden defaults or type a larger server grid intentionally.
   Network worker processes also receive `RAYON_NUM_THREADS=cores_per_worker`,
   and the benchmark runner configures a Rayon thread pool before the first
   local job, so core affinity and algorithmic parallelism are controlled
   together.
5. Use verify experiments again if you want to reverify a benchmark's stored
   proofs. Copy selected release-worthy results into `results/release_results/`
   manually.

The scripts are intentionally interactive. CI and server automation should call
the Rust binary directly after the toolchain is installed.

For a non-interactive fresh-clone smoke that avoids manual run-directory
selection, use:

```bash
cargo run -p pq-experiments -- quick-smoke --out target/quick-smoke
```

This command runs the smallest local performance benchmark, verifies the
generated benchmark manifest, reverifies every stored proof bundle, and checks
that the additional `verifications/` reports do not alter benchmark artifact
or semantic row counts.

## Core Validation Commands

```bash
cargo fmt --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

These commands cover the module-level checks before integration: field/MLE and
arithmetization utilities, Fiat-Shamir transcript ordering, sumcheck variants,
distributed PCS openings, R1CS PIOP, Plonkish PIOP, TCP worker runtime, and the
experiment/result verifier.

## Lightweight Benchmark Sanity Check

The most recent local sanity run in this checkout was intentionally small and
was written under `target/` so the cleaned `results/` tree stays empty:

```powershell
target\debug\pq-experiments.exe benchmark --runner local --n-range 2..2 --workers 1 --pcs-queries 1 --out target\bench-smoke
target\debug\pq-experiments.exe verify-results target\bench-smoke\bench-20260601-100024-performance --format json
target\debug\pq-experiments.exe verify-proof target\bench-smoke\bench-20260601-100024-performance --all --format json
```

`results/bench-*` directories are ignored by Git, so a fresh clone should
rerun the benchmark and substitute the new run id. A portable fresh-clone form
is:

```bash
cargo run -p pq-experiments -- quick-smoke --out target/quick-smoke
```

The equivalent manual form is:

```bash
cargo run -p pq-experiments -- benchmark --runner local --n-range 2..2 --worker-power-range 0..0 --pcs-queries 1
cargo run -p pq-experiments -- verify-results results/bench-YYYYMMDD-HHMMSS-performance --format json
cargo run -p pq-experiments -- verify-proof results/bench-YYYYMMDD-HHMMSS-performance --all --format json
```

`verify-proof` writes a JSON/HTML report under the selected bench directory's
`verifications/` folder before returning. If any selected stored proof fails,
the report is preserved and the command exits nonzero. It also checks that the
stored bundle metadata and `proofs/index.json` entry match the proof payload,
file size, and SHA-256. Malformed proof JSON is reported as a failed proof
outcome instead of suppressing the report.

Verifier result:

```json
{"ok":true,"dir":"target\\bench-smoke\\bench-20260601-100024-performance","run_id":1780308024,"files_checked":25,"bytes_checked":392195,"source_rows_checked":2,"phase_rows_checked":6,"summary_rows_checked":2,"paper_quality_checked":false}
```

Measured rows:

| protocol | runner | n | nv | workers | prove ms | verify ms | proof bytes | communication bytes | verified |
| --- | --- | --- | --- | --- | ---: | ---: | ---: | ---: | --- |
| r1cs | local | 2 | 4 | 1 | 1939.520 | 1902.618 | 43056 | 31512 | true |
| plonkish | local | 2 | 4 | 1 | 1699.258 | 1652.787 | 57785 | 10179 | true |

Phase accounting from the same run:

| phase | elapsed ms | recorded prove ms | recorded verify ms | inferred overhead ms |
| --- | ---: | ---: | ---: | ---: |
| r1cs job | 3842.396 | 1939.520 | 1902.618 | 0.258 |
| plonkish job | 3352.079 | 1699.258 | 1652.787 | 0.034 |
| source and chart artifacts | 8.432 | 0.000 | 0.000 | 8.432 |
| final result artifacts | 225.827 | 0.000 | 0.000 | 225.827 |
| total | 7448.666 | 3638.778 | 3555.405 | 254.482 |

Interpretation:

- This was a debug, local-only, workers=1 sanity check. It is not a paper
  quality run and should not be used to claim distributed speedup.
- The run does validate the benchmark plumbing: both protocol rows are real
  positive prove+verify executions, both verified, source and phase row counts
  match the configured grid, manifest hashes validate, stored proof bundles
  reverify, and HTML/SVG/PGFPlots artifacts were generated.
- `network_bytes=0` is expected because `--runner local` was selected.
- Worker scaling cannot be inferred from this run because only the
  `workers=1` baseline was measured. A scaling run must include multiple
  worker counts and usually `--runner network` or `--runner both`.
- The job wall-clock times are almost exactly recorded prove plus recorded
  verify time. That is the expected shape for this tiny local run and suggests
  the benchmark is not hiding large unaccounted orchestration overhead.

## Release Network Scaling Smoke

The most recent release-mode network smoke in this checkout was:

```powershell
cargo run -p pq-experiments --release -- benchmark --runner network --n-range 2..2 --workers 1,2 --pcs-queries 1 --out target\network-smoke
target\release\pq-experiments.exe verify-results target\network-smoke\bench-20260601-120350-performance --format json
target\release\pq-experiments.exe verify-proof target\network-smoke\bench-20260601-120350-performance --all --format json
```

Verifier result:

```json
{"ok":true,"dir":"target\\network-smoke\\bench-20260601-120350-performance","run_id":1780315430,"files_checked":27,"bytes_checked":729633,"source_rows_checked":4,"phase_rows_checked":11,"summary_rows_checked":4,"paper_quality_checked":false}
```

Measured rows:

| protocol | runner | n | nv | workers | prove ms | verify ms | proof bytes | communication bytes | network bytes | verified |
| --- | --- | --- | --- | --- | ---: | ---: | ---: | ---: | ---: | --- |
| r1cs | network | 2 | 4 | 1 | 189.058 | 200.315 | 43056 | 31512 | 10163 | true |
| r1cs | network | 2 | 4 | 2 | 171.906 | 168.792 | 40072 | 27456 | 16192 | true |
| plonkish | network | 2 | 4 | 1 | 162.723 | 166.835 | 57785 | 10179 | 2673 | true |
| plonkish | network | 2 | 4 | 2 | 157.362 | 156.836 | 56953 | 9315 | 4512 | true |

Core allocation was recorded as
`host_logical_cores=20,max_workers=2,cores_per_worker=10` with
`windows-powershell-processor-affinity`. The verifier counted 11 phase rows:
setup, two reusable network worker-pool startups, four benchmark jobs, worker
pool shutdown, source/chart generation, final artifact generation, and total
wall-clock accounting.

Interpretation:

- This run proves the release TCP worker path, network byte accounting,
  Windows processor-affinity worker launch path, benchmark progress reporting,
  and result verifier all work together on a small grid.
- It is still not paper-quality evidence: it uses `n=2`, `runner=network`
  rather than `runner=both`, no compiled figures, and no paper preset.
- Scaling is intentionally labeled `limited-prototype-scaling` in
  `summary.txt`. R1CS workers=2 measured a small speedup over workers=1
  (`189.058 ms -> 171.906 ms`, speedup `1.100x`), while Plonkish workers=2
  also measured a tiny speedup (`162.723 ms -> 157.362 ms`, speedup `1.034x`).
  For such tiny circuits, this is consistent with the documented theory note:
  worker orchestration, transcript work, verification, and consistency checks
  dominate, so the perfect-linear line is an upper bound rather than a
  prediction for this benchmark size.

For a medium PC run, use the interactive benchmark wizard or:

```bash
cargo run -p pq-experiments --release -- benchmark --runner both --n-range 8..10 --worker-power-range 0..3 --pcs-queries 1
```

The interactive benchmark wizard always fixes `pcs_queries=1` and compiles
figures after the run. For a paper-quality server run from the Rust CLI, use
release mode, the paper preset, both runners, and compiled figures:

```bash
cargo run -p pq-experiments --release -- benchmark --paper-preset --runner both --compile-figures
cargo run -p pq-experiments -- verify-results results/bench-YYYYMMDD-HHMMSS-performance --paper-quality --format json
```

Copy only validated result directories that should be published into
`results/release_results/`. This copy step is intentionally manual.

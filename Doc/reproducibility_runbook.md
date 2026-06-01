# Reproducibility Runbook

This note is the shortest path for a fresh clone to validate the current
research prototype and to reproduce the lightweight benchmark sanity check.

## Fresh Clone Path

Windows:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\interactive-powershell.ps1
```

Linux:

```bash
bash scripts/interactive-linux.sh
```

macOS:

```bash
bash scripts/interactive-macos.sh
```

Use the menu in this order on a new machine:

1. Run preflight dependency check.
2. Install/check missing dependencies if preflight reports a missing tool.
3. Run proof experiment wizard for a small positive and negative proof path.
4. Run performance benchmark wizard for a small grid.
5. Verify the produced benchmark directory.

The scripts are intentionally interactive. CI and server automation should call
the Rust binary directly after the toolchain is installed.

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

The most recent local sanity run in this checkout was intentionally small:

```powershell
target\debug\pq-experiments.exe benchmark --runner local --n-range 2..2 --workers 1 --pcs-queries 1 --out results
target\debug\pq-experiments.exe verify-results results\bench-1780301737355633500 --format json
```

`results/bench-*` directories are ignored by Git, so a fresh clone should
rerun the benchmark and substitute the new run id. A portable fresh-clone form
is:

```bash
cargo run -p pq-experiments -- benchmark --runner local --n-range 2..2 --workers 1 --pcs-queries 1 --out results
cargo run -p pq-experiments -- verify-results results/bench-<run-id> --format json
```

Verifier result:

```json
{"ok":true,"dir":"results\\bench-1780301737355633500","run_id":1780301737355633500,"files_checked":22,"bytes_checked":52207,"source_rows_checked":2,"phase_rows_checked":6,"summary_rows_checked":2,"paper_quality_checked":false}
```

Measured rows:

| protocol | runner | n | nv | workers | prove ms | verify ms | proof bytes | communication bytes | verified |
| --- | --- | --- | --- | --- | ---: | ---: | ---: | ---: | --- |
| r1cs | local | 2 | 4 | 1 | 1905.559 | 1854.949 | 43056 | 31512 | true |
| plonkish | local | 2 | 4 | 1 | 1641.071 | 1604.066 | 57785 | 10179 | true |

Phase accounting from the same run:

| phase | elapsed ms | recorded prove ms | recorded verify ms | inferred overhead ms |
| --- | ---: | ---: | ---: | ---: |
| r1cs job | 3760.813 | 1905.559 | 1854.949 | 0.305 |
| plonkish job | 3245.329 | 1641.071 | 1604.066 | 0.191 |
| source and chart artifacts | 4.775 | 0.000 | 0.000 | 4.775 |
| final result artifacts | 235.469 | 0.000 | 0.000 | 235.469 |
| total | 7247.133 | 3546.630 | 3459.015 | 241.488 |

Interpretation:

- This was a debug, local-only, workers=1 sanity check. It is not a paper
  quality run and should not be used to claim distributed speedup.
- The run does validate the benchmark plumbing: both protocol rows are real
  positive prove+verify executions, both verified, source and phase row counts
  match the configured grid, manifest hashes validate, and HTML/SVG/PGFPlots
  artifacts were generated.
- `network_bytes=0` is expected because `--runner local` was selected.
- Worker scaling cannot be inferred from this run because only the
  `workers=1` baseline was measured. A scaling run must include multiple
  worker counts and usually `--runner network` or `--runner both`.
- The job wall-clock times are almost exactly recorded prove plus recorded
  verify time. That is the expected shape for this tiny local run and suggests
  the benchmark is not hiding large unaccounted orchestration overhead.

For a medium PC run, use the interactive benchmark wizard or:

```bash
cargo run -p pq-experiments --release -- benchmark --runner both --n-range 2..5 --workers 1,2,4 --pcs-queries 1 --out results
```

For a paper-quality server run, use release mode, the paper preset, both
runners, and compiled figures:

```bash
cargo run -p pq-experiments --release -- benchmark --paper-preset --runner both --compile-figures --figure-compiler auto --out results
cargo run -p pq-experiments -- verify-results results/bench-<run-id> --paper-quality --format json
```

Copy only validated result directories that should be published into
`results/release_results/`.

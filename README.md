# pq_dSNARK Correctness Prototype

This repository is a correctness-first Rust implementation of the transparent,
post-quantum distributed SNARK design described in `Doc/pq_dSNARK.pdf`.

The implementation keeps protocol layers explicit so the algebra, transcript,
PCS, PIOP, networking, and experiment paths can be tested, audited, and
benchmarked separately.

## What Is Implemented

- A distributed Spartan-style R1CS PIOP.
- A Plonkish gate/permutation PIOP adapter.
- A transparent SHA-256/Merkle distributed PCS shaped around Brakedown.
- Fiat-Shamir transcript integration.
- Local and loopback TCP worker runners for experiments.
- Benchmark, verification, and report-generation tooling.

The implementation emphasizes readable module boundaries, reproducible
evidence, and practical experiment tooling.

## Workspace Map

- `crates/pq-core`: field, MLE, R1CS, Plonkish, and partition utilities.
- `crates/pq-transcript`: Fiat-Shamir transcript API.
- `crates/pq-sumcheck`: sumcheck, zerocheck, rational sumcheck, and multiset checks.
- `crates/pq-piop`: shared PIOP trait and protocol-facing data model.
- `crates/pq-pcs`: PCS traits, Merkle commitments, and distributed Brakedown prototype.
- `crates/pq-piop-r1cs`: distributed Spartan-style R1CS route.
- `crates/pq-piop-plonkish`: Plonkish gate/permutation route.
- `crates/pq-net`: TCP master/worker runtime.
- `crates/pq-experiments`: experiment CLI, benchmark runner, verifiers, and reports.

Vendored references and pins live under `third_party/`.

## Quick Start

Use the interactive script for your platform:

```powershell
.\scripts\interactive-powershell.cmd
```

```bash
bash scripts/interactive-linux.sh
bash scripts/interactive-macos.sh
```

The menu covers environment setup, proof experiments, stored-proof
verification, and performance benchmarks. The Windows entrypoint is a `.cmd`
launcher that embeds its PowerShell payload and runs it with
`-ExecutionPolicy Bypass`, which avoids the common fresh-machine policy failure
for raw `.ps1` scripts.

For a non-interactive fresh-clone smoke:

```bash
cargo run -p pq-experiments -- quick-smoke --out target/quick-smoke
```

For the core Rust quality gates:

```bash
cargo fmt --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

## Experiments

Proof experiments produce real proof bundles:

```bash
cargo run -p pq-experiments --release -- proof-experiment --protocol both --runner local --n 2 --workers 1 --pcs-queries 1
```

Performance benchmarks run positive end-to-end prove-and-verify jobs and write
a self-contained result directory:

```bash
cargo run -p pq-experiments --release -- benchmark --runner both --n-range 8..10 --worker-power-range 0..3 --pcs-queries 1
```

Paper-style benchmark runs use the stricter preset and figure generation:

```bash
cargo run -p pq-experiments --release -- benchmark --paper-preset --runner both --compile-figures --figure-compiler auto --out results
```

Local scratch results are written under `results/bench-*` and are ignored by
Git. Copy only validated, publishable runs into `results/release_results/`.

## PCS-Only Benchmarks

The repository also has a lighter PCS-only benchmark path:

```powershell
.\scripts\pcs-benchmark-powershell.cmd
```

```bash
bash scripts/pcs-benchmark-linux.sh
bash scripts/pcs-benchmark-macos.sh
```

These scripts write to `results/pcs-bench-*` and generate raw data, summaries,
SVG/TikZ figures, and an `overview.html` report. Validate them with:

```bash
cargo run -p pq-experiments -- verify-pcs-results --dir results/pcs-bench-YYYYMMDD-HHMMSS --format json
```

## Result Validation

Validate a benchmark manifest:

```bash
cargo run -p pq-experiments -- verify-results --dir results/bench-YYYYMMDD-HHMMSS-performance --format json
```

Reverify stored proof bundles:

```bash
cargo run -p pq-experiments -- verify-proof --dir results/bench-YYYYMMDD-HHMMSS-performance --all --format json
```

Use `--paper-quality` for the publication gate. It rejects runs that are not
release builds, do not include both local and network runners, miss the paper
grid, lack compiled figures, or fail stored-proof verification.

See `results/README.md` for the result directory contract.

## Documentation

- `Doc/reproducibility_runbook.md`: fresh-clone workflow, smoke checks, and
  benchmark interpretation.
- `Doc/completion_audit.md`: requirement-by-requirement implementation audit.
- `Doc/pcs_theory_audit.md`: PCS-theory notes and current proof-shape audit.
- `Doc/prototype_boundary.md`: implementation scope and protocol details.
- `Doc/implementation_progress.md`: append-only implementation and validation log.

## CI And Licensing

GitHub Actions are defined in `.github/workflows/ci.yml`. CI checks formatting,
clippy, the workspace test suite, interactive script exit paths, and lightweight
network benchmark smokes.

The repository is licensed as `MIT OR Apache-2.0`; root license copies are
provided in `LICENSE-MIT` and `LICENSE-APACHE`. Vendored references keep their
upstream licenses under `third_party/`.

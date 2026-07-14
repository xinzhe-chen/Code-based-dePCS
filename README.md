# Code-based dePCS

This repository contains the Protocol 6--11 distributed polynomial commitment
scheme, with DeepFold used as the generic polynomial-commitment backend, plus
benchmark scripts for comparison with vendored PCS baselines.

The implementation exposes `setup`, `commit_global`/`commit_worker`,
`aggregate_commitments`, `prove_fs`, and `verify_fs` under
`pq_pcs::depcs::protocol11`. Proofs use a versioned canonical envelope and bind
the external `(commitment, point, claimed_value)` statement. The research
artifact identifies itself with `protocol_version=protocol11`,
`pcs_instantiation=deepfold`, and
`fidelity=protocol11-deepfold`. `Paper100` uses `Ft255` and the conservative
DeepFold unique-decoding regime to target at least 100 bits of classical
soundness in the classical random-oracle model.

This is not an audited production release. DeepFold licensing remains an
explicit redistribution blocker; independent cryptographic review is still
required before describing the implementation as production-audited.

## 1. Install Requirements

Install these on a clean machine or server:

- Git
- Rust toolchain with Cargo
- Python 3
- A C/C++ build toolchain available on `PATH`
  - Linux: `build-essential`, `clang`, or equivalent
  - macOS: Xcode Command Line Tools
  - Windows: Visual Studio Build Tools / MSVC

The repository pins its Rust version through `rust-toolchain.toml`.

## 2. Clone

```bash
git clone https://github.com/xinzhe-chen/Code-based-dePCS.git
cd Code-based-dePCS
```

There are no git submodules to initialize.

## 3. Build And Test

```bash
cargo fmt --check
cargo check --workspace
cargo test -p pq-core -p pq-pcs -p pq-experiments
```

The vendored `third_party/deepfold-bench-v0.1` code is used by the DeepFold PCS backend,
but its full upstream benchmark-style tests are not part of the default test
command above.

## 4. Run The Benchmark Interactively

Use the platform launcher. Running it with no arguments opens a menu.

Windows:

```powershell
.\scripts\pcs-benchmark-powershell.cmd
```

Linux:

```bash
bash scripts/pcs-benchmark-linux.sh
```

macOS:

```bash
bash scripts/pcs-benchmark-macos.sh
```

Menu options:

- `1`: run the default four-way benchmark.
- `2`: dry-run the default schedule without running experiments.
- `3`: enter custom `scripts/benchmark.py` arguments.
- `4`: show all benchmark options.
- `5`: quit.

The default four-way benchmark runs:

- dePCS DeepFold
- LigeSIS
- dFRIttata
- dPIP-FRI

over `nv=18..24` and worker/party counts `2,4`.

## 5. Run The Default Benchmark Non-Interactively

This is the same default experiment as menu option `1`.

Windows:

```powershell
.\scripts\pcs-benchmark-powershell.cmd `
  --out results/depcs-fourway-nv18-24-w2-w4 `
  --fair-sequential `
  --depcs-nv-range 18..24 `
  --depcs-workers 2,4 `
  --depcs-backends deepfold:2 `
  --depcs-opening protocol11 `
  --ligesis-nvs 18,19,20,21,22,23,24 `
  --ligesis-parties-list 2,4 `
  --external-pcs-schemes dfrittata-pcs,dpip-fri-pcs `
  --pcs-queries 1 --repeats 1
```

Linux/macOS:

```bash
bash scripts/pcs-benchmark-linux.sh \
  --out results/depcs-fourway-nv18-24-w2-w4 \
  --fair-sequential \
  --depcs-nv-range 18..24 \
  --depcs-workers 2,4 \
  --depcs-backends deepfold:2 \
  --depcs-opening protocol11 \
  --ligesis-nvs 18,19,20,21,22,23,24 \
  --ligesis-parties-list 2,4 \
  --external-pcs-schemes dfrittata-pcs,dpip-fri-pcs \
  --pcs-queries 1 --repeats 1
```

On macOS, replace `pcs-benchmark-linux.sh` with `pcs-benchmark-macos.sh`.

To check the schedule first, add `--dry-run`.

## 6. Outputs

The comparison script writes results under the `--out` directory, including:

- `comparison_report.md`
- `comparison_summary.csv`
- `schedule.csv`
- `run_events.jsonl`
- SVG charts for prover time, verifier time, proof size, communication, and
  dePCS scaling
- one `pcs-bench-*` artifact directory for each dePCS row

`schedule.csv` is the row-level status file. A healthy fair-sequential run has
all rows marked `completed`.

## 7. Verify dePCS Artifacts

Verify each generated dePCS `pcs-bench-*` directory:

```bash
cargo run -p pq-experiments -- verify-pcs-results \
  --dir results/depcs-fourway-nv18-24-w2-w4/pcs-bench-... \
  --format json
```

The parent comparison directory is not a `verify-pcs-results` input; pass a
specific `pcs-bench-*` artifact directory.

## 8. Quick dePCS-Only Smoke Run

Use this when you only want to confirm the local dePCS runner works:

```bash
cargo run -p pq-experiments --release -- pcs-benchmark \
  --opening protocol11 \
  --backend deepfold \
  --backend-rate-inv 2 \
  --nv-range 10..10 \
  --workers 2 \
  --pcs-queries 1 \
  --allow-insecure-test-profile \
  --no-pcs-warmup \
  --out results/smoke
```

`--allow-insecure-test-profile` is required for small domains that cannot fit
the full `Paper100` query budget. Such artifacts record
`security_claim = none`; omit the flag for claim-bearing runs.

## 9. Repository Layout

- `crates/pq-core`: field, multilinear-extension, and polynomial types
- `crates/pq-pcs`: Protocol 6/8/9/10/11 dePCS implementation
- `crates/pq-experiments`: benchmark and result-verifier CLI
- `scripts/`: interactive benchmark launchers and comparison harness
- `third_party/`: vendored PCS baselines and artifact PCS backend code
- `Doc/`: optional local papers, audits, and design notes when present

## 10. Related repository

The reusable benchmark framework is maintained separately in
[DistZKBench](https://github.com/xinzhe-chen/DistZKBench). This repository keeps
the Code-based dePCS protocol implementation and its protocol-specific adapter.

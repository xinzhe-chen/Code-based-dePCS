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
- `crates/pq-pcs`: PCS traits, Merkle commitments, distributed Brakedown
  correctness prototype.
- `crates/pq-piop-r1cs`: distributed Spartan-style R1CS PIOP.
- `crates/pq-piop-plonkish`: Plonkish gate/permutation PIOP.
- `crates/pq-net`: TCP master/worker runtime.
- `crates/pq-experiments`: interactive experiment CLI.

## Basic Commands

```powershell
cargo test --workspace
cargo run -p pq-experiments -- interactive
cargo run -p pq-experiments -- benchmark --nv-powers 2,3,4 --workers 1,2,4 --pcs-queries 3 --out results
cargo run -p pq-experiments -- benchmark --nv-range 2..5 --workers 1,2,4 --pcs-queries 3 --out results
cargo run -p pq-experiments -- r1cs --workers 1 --size 8 --pcs-queries 32 --format json --case both
cargo run -p pq-experiments -- plonkish --workers 2 --size 4 --pcs-queries 32 --format csv --case both
cargo run -p pq-experiments -- net-demo --workers 2 --format json
```

Linux entrypoint:

```bash
bash scripts/run_experiments.sh
bash scripts/run_experiments.sh interactive
bash scripts/run_benchmarks.sh --nv-range 2..4 --workers 1,2,4 --pcs-queries 3 --out results
bash scripts/run_experiments.sh plonkish --workers 2 --size 4 --format json --case negative
```

Windows script entrypoints:

```powershell
.\scripts\run_experiments.ps1 interactive
.\scripts\run_benchmarks.ps1 -NvRange "2..4" -Workers "1,2,4" -PcsQueries 3 -OutDir results
.\scripts\run_benchmarks.ps1 -NvPowers "2,3,4" -Workers "1,2,4" -PcsQueries 3 -OutDir results
```

Multi-process TCP runner:

```powershell
cargo run -p pq-experiments -- worker --addr 127.0.0.1:19101 --id 0
cargo run -p pq-experiments -- worker --addr 127.0.0.1:19102 --id 1
cargo run -p pq-experiments -- master --addrs 127.0.0.1:19101,127.0.0.1:19102 --ids 0,1 --shutdown --format json
cargo run -p pq-experiments -- master --addrs 127.0.0.1:19101,127.0.0.1:19102 --ids 0,1 --protocol r1cs --size 8 --pcs-queries 3 --case both --shutdown --format json
```

The experiment CLI supports `--case positive`, `--case negative`, and
`--case both`. Negative cases intentionally tamper with the statement or
proof openings and must verify as `false`. `--pcs-queries N` controls the
requested distributed PCS query count; the protocol records both the requested
parameter and the effective capped query count in the Fiat-Shamir transcript.
JSON and CSV experiment rows include `failure_reason` for negative or failed
verification cases. Rows produced by `master --protocol ...` also include
non-zero `network_bytes`; in that path the TCP workers compute the distributed
PCS partition commitments and opening proofs used by the prover.
`proof_bytes` is computed from canonical byte accounting over the proof
structure, including commitments, vector length prefixes, Merkle paths,
distributed PCS openings, zerocheck rounds, Plonkish selector commitments and
gate virtual-evaluation subclaims, R1CS inner product-sumcheck openings, and
PIOP consistency openings.
The benchmark command creates `results/bench-<timestamp>/` containing
`source.csv`, `source.json`, `summary.txt`, and SVG charts for prove time,
verify time, proof bytes, and worker scaling versus the `workers=1`
non-distributed baseline. Benchmark sizes can be supplied directly with
`--sizes 4,8,16`, as exponent lists with `--nv-powers 2,3,4`, or as inclusive
exponent ranges with `--nv-range 2..6`, where `nv=2^n`. Source rows include
both `nv_power` and `size`; the SVG charts use publication-oriented vector
styling with measured data points, fixed protocol colors, worker line/marker
encodings, clean axes, legend boxes, and an explicit ideal-linear baseline
only on the worker-scaling plot. The Windows and Linux scripts print
plain progress steps for cargo checks/builds, selected size mode, current
benchmark job, output directory, and completion status; progress logs are kept
separate from generated CSV/JSON source data.

## Current Prototype Boundary

This is a correctness prototype. It uses a small Goldilocks-field backend and
transparent SHA-256/Merkle commitments. R1CS and Plonkish routes both pass
through Fiat-Shamir, equality-weighted zerocheck, and the `pq-pcs` distributed
Brakedown module, but the Brakedown/BaseFold proof-composition layer is
represented by explicit small-scale systematic, adjacent-parity,
stride-parity, and blend-parity encoding checks plus a full-relation MLE
folding evaluation proof for the row-weighted combined column rather than an
optimized production proof. The R1CS proof does not carry the full witness; it now uses a
Spartan-style outer cubic sumcheck over `eq_tau(x) * (Az(x)Bz(x)-Cz(x))`,
distributed PCS openings for the final `Az/Bz/Cz` claims, a Spartan-style inner
product sumcheck for the random linear combination of public matrix projections
against the committed witness MLE, witness/linearization commitments,
exhaustive row-consistency openings, and transcript-bound distributed
sparse-matrix fingerprints. It is still not the full production Spartan/Spark
protocol. The Plonkish route also uses committed
`A/B/C`, selector, gate-residual, and permutation-residual oracle columns with
a Fiat-Shamir random-point virtual gate evaluation subclaim, MLE folding proofs
for the opened Plonkish oracle columns, exhaustive gate/copy/accumulator
consistency openings, plus a Fiat-Shamir `beta/gamma` permutation
running-product accumulator committed by Merkle PCS.

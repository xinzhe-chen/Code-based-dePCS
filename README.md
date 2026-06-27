# pq_dSNARK dePCS

This repository is focused on the transparent distributed polynomial commitment
scheme (dePCS) from `Doc/papers/pq_dSNARK.pdf`, Chapter 4.

The implementation keeps the PCS layer explicit:

- `crates/pq-core`: field, multilinear-extension, and polynomial types.
- `crates/pq-pcs`: Protocol 6/8/9/10/11 distributed dePCS over the vendored
  BaseFold (rate-1/8) and DeepFold (rate-1/2) transparent folding PCS backends.
- `crates/pq-experiments`: dePCS benchmark and result verifier.

## Build And Test

```bash
cargo fmt --check
cargo check --workspace
# Scope tests to our crates; the vendored deepfold-bench is a separate
# workspace whose members include heavy benchmark-style tests.
cargo test -p pq-core -p pq-pcs -p pq-experiments
```

## dePCS Benchmark

Run a local dePCS benchmark over multilinear variable counts `nv`, where the
committed polynomial length is `N = 2^nv`:

```bash
cargo run -p pq-experiments --release -- pcs-benchmark \
  --opening protocol11 \
  --backend deepfold \
  --nv-range 14..18 \
  --workers 2 \
  --pcs-queries 1 \
  --no-pcs-warmup \
  --out results
```

The backend selects the artifact PCS code rate: BaseFold uses rate `1/8` and
DeepFold uses rate `1/2` in the paper-backed Protocol 11 path. The
paper-backed path derives its effective query policy from the backend and
Protocol 11 configuration; the CSV output records the requested and effective
query counts separately.

Or run the distributed-PCS comparison benchmark via a platform launcher. With no
arguments the launcher opens an interactive menu; with arguments it forwards
them to `scripts/benchmark.py`:

```powershell
.\scripts\pcs-benchmark-powershell.cmd --help
```

```bash
bash scripts/pcs-benchmark-linux.sh --help   # or scripts/pcs-benchmark-macos.sh
```

Validate a generated run:

```bash
cargo run -p pq-experiments -- verify-pcs-results \
  --dir results/pcs-bench-... \
  --format json
```

## dePCS vs LigeSIS

The comparison harness follows the LigeSIS Distributed PCS convention:
`nv` is the number of multilinear variables and `N = 2^nv` is the committed
polynomial length. LigeSIS Figure 4 fixes `nv=28` and varies node count; the
default local command below is a scaled reproduction over `nv=18..24` and
worker counts `2,4`.

```bash
python scripts/benchmark.py \
  --out results/depcs-fiveway-parallel-merkle-nv18-24-w2-w4 \
  --fair-sequential \
  --depcs-nv-range 18..24 \
  --depcs-workers 2,4 \
  --depcs-backends basefold:8,deepfold:2 \
  --depcs-opening protocol11 \
  --ligesis-nvs 18,19,20,21,22,23,24 \
  --ligesis-parties-list 2,4 \
  --external-pcs-schemes dfrittata-pcs,dpip-fri-pcs \
  --pcs-queries 1 --repeats 1
```

The command above compares the two paper-backed distributed dePCS backends
(BaseFold rate-1/8 and DeepFold rate-1/2, Protocol 11) against the three vendored
baselines under `third_party/ligesis-pcs-3447`: LigeSIS, dFRIttata, and
dPIP-FRI. Their example binaries are built and run as separate processes; rows
that fail to build or run are recorded as blocked rather than silently dropped.

The script writes:

- `comparison_summary.csv`
- `comparison_report.md`
- `comparison_prover_time.svg`
- `comparison_verify_time.svg`
- `comparison_proof_size.svg`
- `comparison_communication.svg`
- `depcs_worker_local_compute_scaling.svg`
- `depcs_end_to_end_open_proof_scaling.svg`
- `proof_size_component_breakdown_by_nv.svg` inside each `pcs-bench-*` dePCS artifact directory

LigeSIS rows that crash or hang in the vendored local runner are recorded as
blocked instead of being treated as measurements.

The latest local run of this command was written to
`results/depcs-fiveway-parallel-merkle-nv18-24-w2-w4` on 2026-06-27. It
completed all 70 scheduled benchmark rows with `max_active=1`, and all 28 dePCS
`pcs-bench-*` artifact directories passed `verify-pcs-results`.

Representative `nv=24` rows from that run:

| scheme | workers | prover ms | verify ms | proof KiB | communication |
| --- | ---: | ---: | ---: | ---: | --- |
| dePCS DeepFold | 2 | 3788.955 | 9.736 | 948.32 | 940.63 KiB send+recv |
| dePCS DeepFold | 4 | 2872.329 | 14.332 | 1689.63 | 1693.17 KiB send+recv |
| dePCS BaseFold | 2 | 14058.825 | 12.194 | 1372.80 | 1365.71 KiB send+recv |
| dePCS BaseFold | 4 | 9341.729 | 19.962 | 2451.29 | 2457.20 KiB send+recv |
| LigeSIS | 2 | 4165.911 | 114.895 | 290.82 | 223621.12 KiB native |
| LigeSIS | 4 | 2645.500 | 114.604 | 291.37 | 291420.16 KiB native |
| dPIP-FRI | 2 | 3911.015 | 3.119 | 333.95 | 266416.46 KiB native |
| dPIP-FRI | 4 | 2364.622 | 3.529 | 330.95 | 198915.93 KiB native |

The older directory
`results/depcs-basefold-full-nv10-16-workers1-2-4-8-16` used the old
`n/nv/size` label convention. New reports use `nv` and `polynomial_length`.

For fair speedup rows, the comparison script runs one dePCS process per worker
value and spawns one local TCP worker process per dePCS worker. LigeSIS launches
one process per party and sets each party process to `RAYON_NUM_THREADS =
cores_per_worker`; mismatched `--ligesis-parties-list` values are rejected
instead of producing asymmetric tables.

For dePCS and LigeSIS, `comparison_proof_size.svg` uses verifier-facing proof
bytes: the PCS commitment object sent to the verifier plus the PCS opening
proof. `communication_bytes` is reserved for measured bytes sent plus bytes
received. dePCS rows use the local TCP network runner counters. LigeSIS rows
use the vendored dLigesis `COMM_TOTAL_MB` counter.

dePCS scalability is reported with two views. Worker-local compute speedup uses
the per-worker local compute fields, while end-to-end open/proof speedup uses
full `open_ms`, including openings, Protocol 10 work, proof-size accounting,
and aggregation overhead. Current reports use the `Mersenne61Ext` field and
Blake3 Merkle commitments; the CSV metadata records `security_target_bits`,
`security_effective_bits`, and `algebraic_security_bits` for each row.

## Documentation

- `Doc/papers/pq_dSNARK.pdf`: paper under review.
- `Doc/audits/pcs_theory_audit.md`: PCS-theory notes and implementation audit.
- `Doc/audits/depcs_audit_report_v2.md`: current post-parity-check dePCS audit.
- `Doc/papers/LigeSIS.pdf`: LigeSIS comparison reference.

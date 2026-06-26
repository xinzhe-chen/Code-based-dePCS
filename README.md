# pq_dSNARK dePCS

This repository is now focused on the transparent distributed polynomial
commitment scheme (dePCS) from `Doc/papers/pq_dSNARK.pdf`, Chapter 4.

The implementation keeps the PCS layer explicit:

- `crates/pq-core`: field, multilinear-extension, polynomial, partition, and
  sparse-matrix utility types.
- `crates/pq-transcript`: Fiat-Shamir transcript API.
- `crates/pq-sumcheck`: sumcheck helper protocols used by PCS checks.
- `crates/pq-pcs`: Protocol 6/8/9/10/11 dePCS with batch-only transparent
  encoded folding PCS backends: BaseFold rate-1/4 and DeepFold rate-1/4.
- `crates/pq-experiments`: dePCS benchmark and result verifier.

## Build And Test

```bash
cargo fmt --check
cargo check --workspace
cargo test --workspace
```

## dePCS Benchmark

Run a local dePCS benchmark over multilinear variable counts `nv`, where the
committed polynomial length is `N = 2^nv`:

```bash
cargo run -p pq-experiments --release -- pcs-benchmark \
  --opening protocol11 \
  --backend basefold \
  --backend-rate-inv 4 \
  --nv-range 14..18 \
  --workers 2,4,8,16 \
  --cores-per-worker 1 \
  --pcs-queries 1 \
  --security-bits 128 \
  --repeats 1 \
  --no-pcs-warmup \
  --out results
```

Or run the distributed-PCS comparison benchmark via a platform launcher (each
forwards its arguments to `scripts/benchmark.py`; pass `--help` for options):

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
default local command below is a scaled reproduction that uses `nv=14..18`
to stay within the 15 minute deadline.

```bash
python scripts/benchmark.py \
  --out results/depcs-ligesis-nv14-18-workers2-4-8-16 \
  --depcs-nv-range 14..18 \
  --depcs-workers 2,4,8,16 \
  --cores-per-worker 1 \
  --pcs-queries 1 \
  --security-bits 128 \
  --repeats 1 \
  --ligesis-nvs 14,15,16,17,18 \
  --ligesis-parties-list 1,2,4,8,16
```

By default the comparison script attempts `depcs-basefold-batch`
(`basefold:4`), `depcs-deepfold-batch` (`deepfold:4`), and LigeSIS.
DeepFold backend failures are treated as experiment failures rather than being
silently omitted. The DeepFold path uses the local Arkworks-compatible
Goldilocks RS/FFT core with rate-1/4 query-policy transcript binding; details
and soundness notes are tracked in `Doc/audits/pcs_batch_backend_soundness.md`.
Older `deepfold:2` artifacts are legacy rate-1/2 runs and should not be mixed
into the default rate-1/4 comparison series.

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

dePCS scalability is reported with two acceptance views. Worker-local compute
speedup uses `worker_commit_ms + worker_eval_commit_ms`, which tracks shard
commit/eval/encode work. End-to-end open/proof speedup uses full `open_ms`,
which includes column openings, F2 openings, Protocol 10 batch openings,
proof-size accounting, and aggregation overhead.

The default query-security budget is `lambda=128`: BaseFold rate-1/4 and
DeepFold rate-1/4 both use 64 PCS queries, and Protocol 11 column checks use
the outer rate-1/4 policy. The arithmetic field is Goldilocks, so
CSV/report metadata separately records `algebraic_security_bits=64`; the
implementation does not claim that one Goldilocks challenge field element
provides 128-bit algebraic security by itself.

## Documentation

- `Doc/papers/pq_dSNARK.pdf`: paper under review.
- `Doc/audits/pcs_theory_audit.md`: PCS-theory notes and implementation audit.
- `Doc/audits/depcs_audit_report_v2.md`: current post-parity-check dePCS audit.
- `Doc/papers/LigeSIS.pdf`: LigeSIS comparison reference.

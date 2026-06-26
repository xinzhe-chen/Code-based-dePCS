# Benchmark & tooling scripts

All developer/benchmark tooling lives here. Everything ultimately drives the
`pq-experiments` CLI (`cargo run -p pq-experiments -- …`).

## Interactive single-backend benchmark wrappers

Thin menu wrappers around `pq-experiments pcs-benchmark` (one dePCS backend at a
time). They prompt for nv range, worker range, and query count, then run the
local-network Protocol 11 path.

- `pcs-benchmark-linux.sh` — Linux (Bash).
- `pcs-benchmark-macos.sh` — macOS (Bash; uses `sysctl` for core count).
- `pcs-benchmark-powershell.cmd` — Windows (cmd).

```bash
bash scripts/pcs-benchmark-linux.sh      # or -macos.sh
```
```powershell
.\scripts\pcs-benchmark-powershell.cmd
```

## Five-way comparison harness

`depcs-ligesis-compare.py` runs the full comparison: dePCS DeepFold + BaseFold
(paper-backed Protocol 11) vs the vendored LigeSIS, dFRIttata, and dPIP-FRI
implementations under `third_party/references/`. It builds the external binaries,
runs each row fairly (one at a time, per-row timeouts), and writes
`comparison_report.md`, `depcs_bottleneck_report.md`, and `comparison_*.svg`.

It locates the repo root itself (walks up for `Cargo.toml` + `crates/pq-experiments`),
so it can be invoked from anywhere.

```bash
python scripts/depcs-ligesis-compare.py \
  --out results/<run-name> \
  --fair-sequential \
  --depcs-nv-range 18..24 \
  --depcs-workers 2 \
  --cores-per-worker 10 \
  --depcs-backends basefold:8,deepfold:2 \
  --depcs-opening protocol11 \
  --ligesis-nvs 18,19,20,21,22,23,24 \
  --ligesis-parties-list 2 \
  --external-pcs-schemes dfrittata-pcs,dpip-fri-pcs \
  --pcs-queries 1 --repeats 1
```

Override `--ligesis-dir` if the vendored comparison sources move; the default is
`third_party/references/ligesis-pcs-3447`.

Output goes to a scratch run under `results/`; promote curated runs into
`results/release_results/` (see [`results/README.md`](../results/README.md)).

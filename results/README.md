# Benchmark results

This directory holds benchmark output. It has a two-tier versioning policy
enforced by the repository `.gitignore`:

- **`results/` (top level) is a scratch zone.** Every benchmark run lands here
  by default and is **git-ignored**. Use it freely for local/experimental runs;
  nothing here is committed.
- **`results/release_results/` is curated and versioned.** Only runs that should
  be published (reproducibility artifacts for the paper / reports) live here, and
  they are tracked in git.

## Promoting a run

A benchmark writes to whatever `--out` you pass (default under `results/`). To
publish a run, move its directory into `results/release_results/`:

```bash
git mv results/<your-run-dir> results/release_results/<your-run-dir>
```

## Layout of a run directory

Each run contains one or more timestamped `pcs-bench-<unix-ms>/` subdirectories
plus, for comparison runs, top-level `comparison_report.md`,
`depcs_bottleneck_report.md`, and `comparison_*.svg` charts. The raw per-row data
is in `pcs-bench-*/source.csv` and `summary_stats.csv`.

## Current curated runs

- `release_results/depcs-fiveway-paper-protocol11-nv18-24-w2/` — pre-fix paper
  five-way comparison (dePCS DeepFold/BaseFold vs LigeSIS / dFRIttata / dPIP-FRI).
- `release_results/depcs-fiveway-paper-protocol11-batch-audit-nv18-24-w2/`,
  `…-relation-proof-…/` — pre-fix audit variants.
- `release_results/depcs-fiveway-lazycoset-protocol11-nv18-24-w2/` — post-fix
  five-way run after the lazy-coset verifier fix (verify time dropped from linear
  to polylog: BaseFold 5632 ms → 20 ms, DeepFold 789 ms → 14 ms at nv=24).

See [`scripts/`](../scripts/) for how to generate these.

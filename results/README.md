# Benchmark Results

`pq-experiments benchmark` writes each run to
`results/bench-YYYYMMDD-HHMMSS-performance/`. `pq-experiments
proof-experiment` writes to `results/bench-YYYYMMDD-HHMMSS-proof/`.

Each run directory is self-contained and includes:

- `overview.html`: static experiment dashboard for quick inspection;
- `source.csv` and `source.json`: raw performance rows, one positive
  end-to-end prove+verify per circuit configuration;
- `phase_timing.csv` and `phase_timing.json`: benchmark wall-clock phase
  accounting, including per-job overhead outside recorded prove/verify spans;
- `summary_stats.csv` and `summary.txt`: aggregated metrics and scaling notes;
- `proofs/`: stored proof bundles plus `proofs/index.json`, so later proof
  verification can rerun without reproving. `list-proofs` still lists a bench
  if a proof file is malformed and marks that file as invalid;
- SVG previews and PGFPlots/TikZ figures for paper inclusion;
- `metadata.json`: benchmark configuration and provenance;
- `result_manifest.json`: SHA-256 and byte-size manifest for every artifact
  except the manifest itself.

Run directories at `results/bench-*` are intentionally ignored by Git. To
publish selected benchmark evidence with the repository, manually copy the
validated run directory into `results/release_results/`; that subdirectory is
not ignored.
For paper-facing runs, use the stricter paper-quality verifier before copying;
it requires release metadata, `runner=both`, the full paper grid, compiled
figures, verified positive performance rows, complete local/network source
data, phase timing, and non-empty HTML/SVG/PGFPlots/PDF figure artifacts. The
ordinary verifier also checks the manifest plus source/metadata/summary/phase
row consistency and basic HTML/SVG/PGFPlots artifact structure.

Paper-quality generation command:

```powershell
.\scripts\interactive-powershell.cmd
```

```bash
bash scripts/interactive-linux.sh
bash scripts/interactive-macos.sh
```

Use menu option 3 for stored-proof verification and option 4 for the
performance benchmark wizard. For
non-interactive CI or server automation, call the Rust binary directly:

```powershell
cargo run -p pq-experiments --release -- benchmark --paper-preset --runner both --compile-figures --figure-compiler auto --out results
```

```bash
cargo run -p pq-experiments --release -- benchmark --paper-preset --runner both --compile-figures --figure-compiler auto --out results
```

To validate a benchmark result and reverify its stored proofs, use menu option
3 or run:

```powershell
cargo run -p pq-experiments -- verify-results results\bench-YYYYMMDD-HHMMSS-performance --format json
cargo run -p pq-experiments -- verify-proof results\bench-YYYYMMDD-HHMMSS-performance --all --format json
```

```bash
cargo run -p pq-experiments -- verify-results results/bench-YYYYMMDD-HHMMSS-performance --format json
cargo run -p pq-experiments -- verify-proof results/bench-YYYYMMDD-HHMMSS-performance --all --format json
```

Extra proof verification reports are written under `verifications/` in the
selected bench folder. They are deliberately outside the benchmark manifest, so
rerunning verification does not modify or invalidate the measured benchmark
artifacts. A failed stored-proof verification still writes its JSON/HTML report
and then exits nonzero. Verification binds the proof payload to its stored
bundle metadata and `proofs/index.json` entry, including file size and SHA-256;
malformed proof JSON is reported as a failed proof outcome.

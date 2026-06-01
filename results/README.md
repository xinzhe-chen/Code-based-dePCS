# Benchmark Results

`pq-experiments benchmark` writes each run to `results/bench-<run-id>/`.

Each run directory is self-contained and includes:

- `overview.html`: static experiment dashboard for quick inspection;
- `source.csv` and `source.json`: raw performance rows, one positive
  end-to-end prove+verify per circuit configuration;
- `phase_timing.csv` and `phase_timing.json`: benchmark wall-clock phase
  accounting, including per-job overhead outside recorded prove/verify spans;
- `summary_stats.csv` and `summary.txt`: aggregated metrics and scaling notes;
- SVG previews and PGFPlots/TikZ figures for paper inclusion;
- `metadata.json`: benchmark configuration and provenance;
- `result_manifest.json`: SHA-256 and byte-size manifest for every artifact
  except the manifest itself.

Run directories at `results/bench-*` are intentionally ignored by Git. To
publish selected benchmark evidence with the repository, copy the validated run
directory into `results/release_results/`; that subdirectory is not ignored.
For paper-facing runs, use the stricter paper-quality verifier before copying;
it requires release metadata, `runner=both`, the full paper grid, compiled
figures, verified positive performance rows, complete local/network source
data, phase timing, and non-empty HTML/SVG/PGFPlots/PDF figure artifacts. The
ordinary verifier also checks the manifest plus source/metadata/summary/phase
row consistency and basic HTML/SVG/PGFPlots artifact structure.

Paper-quality generation command:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\interactive-powershell.ps1
```

```bash
bash scripts/interactive-linux.sh
bash scripts/interactive-macos.sh
```

Use menu option 4 for the benchmark wizard. For non-interactive CI or server
automation, call the Rust binary directly:

```powershell
cargo run -p pq-experiments --release -- benchmark --paper-preset --runner both --compile-figures --figure-compiler auto --out results
```

```bash
cargo run -p pq-experiments --release -- benchmark --paper-preset --runner both --compile-figures --figure-compiler auto --out results
```

To validate a copied result, use menu option 5 or run:

```powershell
cargo run -p pq-experiments -- verify-results results\release_results\bench-<run-id> --format json
cargo run -p pq-experiments -- verify-results results\release_results\bench-<run-id> --paper-quality --format json
```

```bash
cargo run -p pq-experiments -- verify-results results/release_results/bench-<run-id> --format json
cargo run -p pq-experiments -- verify-results results/release_results/bench-<run-id> --paper-quality --format json
```

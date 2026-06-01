# Release Results

Use this directory for benchmark result folders that should be published with
the GitHub repository.

Workflow:

1. Run experiments normally into `results/bench-YYYYMMDD-HHMMSS-performance/`.
2. Validate the run manifest and, when useful, reverify the stored proofs.
3. Manually copy only the selected result folder here, preserving its internal
   files.

For a result intended as paper-quality evidence, generate it with the full
performance-only paper preset rather than a smoke-size override. Each atomic
benchmark row is one positive end-to-end prove+verify for one circuit
configuration; negative/tampered cases belong to the test suite, not release
benchmark rows.

```powershell
.\scripts\interactive-powershell.cmd
```

```bash
bash scripts/interactive-linux.sh
```

```bash
bash scripts/interactive-macos.sh
```

Use menu option 4 for the benchmark wizard and option 3 for stored-proof
verification. Copying into this directory is intentionally manual. For
non-interactive CI or server automation, call the Rust binary
directly:

```powershell
cargo run -p pq-experiments --release -- benchmark --paper-preset --runner both --compile-figures --figure-compiler auto --out results
```

```bash
cargo run -p pq-experiments --release -- benchmark --paper-preset --runner both --compile-figures --figure-compiler auto --out results
```

Windows:

```powershell
cargo run -p pq-experiments -- verify-results results\bench-YYYYMMDD-HHMMSS-performance --format json
cargo run -p pq-experiments -- verify-proof results\bench-YYYYMMDD-HHMMSS-performance --all --format json
cargo run -p pq-experiments -- verify-results results\bench-YYYYMMDD-HHMMSS-performance --paper-quality --format json
```

Linux:

```bash
cargo run -p pq-experiments -- verify-results results/bench-YYYYMMDD-HHMMSS-performance --format json
cargo run -p pq-experiments -- verify-proof results/bench-YYYYMMDD-HHMMSS-performance --all --format json
cargo run -p pq-experiments -- verify-results results/bench-YYYYMMDD-HHMMSS-performance --paper-quality --format json
```

Before publishing, validate the copied directory as well:

```powershell
cargo run -p pq-experiments -- verify-results results\release_results\bench-YYYYMMDD-HHMMSS-performance --format json
cargo run -p pq-experiments -- verify-results results\release_results\bench-YYYYMMDD-HHMMSS-performance --paper-quality --format json
```

```bash
cargo run -p pq-experiments -- verify-results results/release_results/bench-YYYYMMDD-HHMMSS-performance --format json
cargo run -p pq-experiments -- verify-results results/release_results/bench-YYYYMMDD-HHMMSS-performance --paper-quality --format json
```

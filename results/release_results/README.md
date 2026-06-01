# Release Results

Use this directory for benchmark result folders that should be published with
the GitHub repository.

Workflow:

1. Run experiments normally into `results/bench-<run-id>/`.
2. Validate the run manifest.
3. Copy only the selected result folder here, preserving its internal files.

For a result intended as paper-quality evidence, generate it with the full
performance-only paper preset rather than a smoke-size override. Each atomic
benchmark row is one positive end-to-end prove+verify for one circuit
configuration; negative/tampered cases belong to the test suite, not release
benchmark rows.

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\interactive-powershell.ps1
```

```bash
bash scripts/interactive-linux.sh
```

Use menu option 4 for the benchmark wizard. For non-interactive CI or server
automation, call the Rust binary directly:

```powershell
cargo run -p pq-experiments --release -- benchmark --paper-preset --runner both --compile-figures --figure-compiler auto --out results
```

```bash
cargo run -p pq-experiments --release -- benchmark --paper-preset --runner both --compile-figures --figure-compiler auto --out results
```

Windows:

```powershell
cargo run -p pq-experiments -- verify-results results\bench-<run-id> --format json
cargo run -p pq-experiments -- verify-results results\bench-<run-id> --paper-quality --format json
Copy-Item -Recurse -LiteralPath results\bench-<run-id> -Destination results\release_results\
```

Linux:

```bash
cargo run -p pq-experiments -- verify-results results/bench-<run-id> --format json
cargo run -p pq-experiments -- verify-results results/bench-<run-id> --paper-quality --format json
cp -a results/bench-<run-id> results/release_results/
```

Before publishing, validate the copied directory as well:

```powershell
cargo run -p pq-experiments -- verify-results results\release_results\bench-<run-id> --format json
cargo run -p pq-experiments -- verify-results results\release_results\bench-<run-id> --paper-quality --format json
```

```bash
cargo run -p pq-experiments -- verify-results results/release_results/bench-<run-id> --format json
cargo run -p pq-experiments -- verify-results results/release_results/bench-<run-id> --paper-quality --format json
```

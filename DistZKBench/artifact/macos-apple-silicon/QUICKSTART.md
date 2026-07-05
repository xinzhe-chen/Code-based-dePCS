# DistZKBench macOS Apple Silicon Quickstart

```bash
cargo build --release --locked
./target/release/dzb preflight --config artifact/macos-apple-silicon/configs/macos_toy_star.yaml
./target/release/dzb run artifact/macos-apple-silicon/configs/macos_toy_star.yaml
```

The macOS backend is best-effort. Reports must not be compared directly with
Linux strict-isolation results.

Additional local smoke tests:

```bash
./target/release/dzb run configs/examples/blackbox_echo.yaml
./target/release/dzb run configs/examples/pq_depcs_native_small.yaml
```

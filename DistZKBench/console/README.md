# DistZKBench Console

This is the top-level local HTML console for DistZKBench. It does not require
`target/release/dzb` to exist before startup.

```bash
./console/run_console.sh
```

On macOS, you can also double-click the top-level launcher:

```text
Open DistZKBench Console.command
```

The console starts a Python standard-library HTTP server on `127.0.0.1`, opens a
browser, and lets you trigger:

- Rust release/debug workspace builds.
- C FFI fixture build.
- toy star/full-mesh/pingpong self-checks.
- C FFI pingpong smoke.
- latest run/report inspection.

The HTML page cannot execute commands by itself; `console/server.py` is the local
localhost scheduler that runs build and smoke commands. Generated `target/`,
`results/`, and `configs/generated/` directories are intentionally untracked.

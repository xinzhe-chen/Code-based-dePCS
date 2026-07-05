# DistZKBench Artifact

DistZKBench has two artifact paths:

- `main-linux/`: strict Linux artifact path for headline results.
- `macos-apple-silicon/`: best-effort Apple Silicon path for portability and supplemental runs.

Run toy smoke tests first. Linux strict runs must fail closed when requested
features such as cgroup v2, resctrl, netns/tc, or perf are unavailable.

For first-time users, start with the interactive entrypoint:

```bash
cargo build --release --locked
./target/release/dzb interactive
```

It can run a local toy self-check and write a starter config under
`configs/generated/` for an SDK or black-box adapter.

Remote Linux validation uses environment variables instead of committed secrets:

```bash
export DZB_LINUX_SSH=user@host
export DZB_LINUX_KEY=/path/to/key        # optional
export DZB_LINUX_WORKDIR=/tmp/distzkbench-$USER
```

The Linux strict artifact path expects `sudo -n true` to work.

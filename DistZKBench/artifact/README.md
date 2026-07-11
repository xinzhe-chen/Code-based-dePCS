# DistZKBench Artifact

DistZKBench has two artifact paths:

- `main-linux/`: strict Linux artifact path for headline results.
- `macos-apple-silicon/`: best-effort Apple Silicon path for portability and supplemental runs.

Run toy smoke tests first. Linux strict runs must fail closed when requested
features such as cgroup v2, netns/tc, or perf are unavailable. resctrl is not
requested because it is unavailable on most benchmark hosts.

For first-time users, start with the top-level console:

```bash
./console/run_console.sh
```

It can build the Rust workspace, build the C FFI fixture, run local toy
self-checks, and write a starter config under `configs/generated/` for an SDK or
black-box adapter. The CLI `dzb interactive` entrypoint remains available after a
Rust build.

Remote Linux validation uses environment variables instead of committed secrets:

```bash
export DZB_LINUX_SSH=user@host
export DZB_LINUX_KEY=/path/to/key        # optional
export DZB_LINUX_WORKDIR=/tmp/distzkbench-$USER
```

The Linux strict artifact path expects `sudo -n true` to work.

Headline Linux runs use one Agent-managed netns/veth per rank, kernel tc
shaping, one persistent TCP connection per permitted peer edge, 100 ms memory
sampling, and verified-artifact sweep resume. Multi-host orchestration and
resctrl are intentionally out of scope.

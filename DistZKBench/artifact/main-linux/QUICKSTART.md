# DistZKBench Linux Quickstart

Top-level local console:

```bash
./console/run_console.sh
```

The console can build the Rust workspace, build the C FFI fixture, run a local
toy self-check, visualize TCP edges, and generate a starter config for an SDK or
black-box protocol adapter. Use it before wiring a real distributed PCS or
zkSNARK. The CLI `dzb interactive` entrypoint remains available after a Rust
build.

Manual toy smoke:

```bash
cargo build --release --locked
./target/release/dzb preflight --config configs/examples/toy_star_4.yaml
./target/release/dzb run configs/examples/toy_star_4.yaml
./target/release/dzb report results/toy_star_4/<run-id>
```

Linux is the strict artifact backend. Strict cgroup, cpuset, netns/tc,
and perf paths must fail closed when requested but unavailable.

Formal Linux configs use Agent-managed rank-local network namespaces. The
Agent creates the bridge/veth/tc hierarchy before launch, samples cgroup memory
every 100 ms, and removes all run resources on success, failure, timeout, OOM,
or cancellation. Validate that lifecycle directly with:

```bash
artifact/main-linux/scripts/agent_netns_acceptance.py target/release/dzb-agent
```

Sweeps resume verified cells by default. A cell is skipped only when its
configuration/framework/adapter fingerprint and proof, statement, and verifier
artifacts all match:

```bash
./target/release/dzb sweep configs/gcp_protocol11_m2.yaml
./target/release/dzb sweep configs/gcp_protocol11_m2.yaml --rerun
```

Remote preflight:

```bash
export DZB_LINUX_SSH=user@host
export DZB_LINUX_KEY=/path/to/key        # optional
export DZB_LINUX_WORKDIR=/tmp/distzkbench-$USER
artifact/main-linux/scripts/remote_preflight.sh
artifact/main-linux/scripts/remote_run_toy.sh
```

Strict preflight config:

```bash
./target/release/dzb preflight --config artifact/main-linux/configs/strict_preflight.yaml
```

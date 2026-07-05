# DistZKBench Linux Quickstart

```bash
cargo build --release --locked
./target/release/dzb preflight --config configs/examples/toy_star_4.yaml
./target/release/dzb run configs/examples/toy_star_4.yaml
./target/release/dzb report results/toy_star_4/<run-id>
```

Linux is the strict artifact backend. Strict cgroup, cpuset, resctrl, netns/tc,
and perf paths must fail closed when requested but unavailable.

Remote preflight:

```bash
export DZB_LINUX_SSH=user@host
export DZB_LINUX_KEY=/path/to/key        # optional
export DZB_LINUX_WORKDIR=/tmp/distzkbench-$USER
artifact/main-linux/scripts/remote_preflight.sh
artifact/main-linux/scripts/remote_run_toy.sh
```

Two-host local-vs-remote calibration:

```bash
export DZB_LINUX_SSH_A=user@host-a
export DZB_LINUX_SSH_B=user@host-b
export DZB_LINUX_IP_A=10.x.x.a
export DZB_LINUX_IP_B=10.x.x.b
export DZB_LINUX_KEY=/path/to/key        # optional
artifact/main-linux/scripts/remote_two_host_calibration.sh
```

The two-host script first runs a local loopback two-rank all-to-all baseline on
host A, then runs one rank per host over private TCP and writes a calibration
summary under `results/twohost_calibration/<run-id>/`.

Strict preflight config:

```bash
./target/release/dzb preflight --config artifact/main-linux/configs/strict_preflight.yaml
```

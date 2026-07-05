# DistZK

DistZK is a repository for distributed zero-knowledge proof systems work. It is
organized as a top-level workspace for two related but distinct projects:

- `pq_dPCS/`: the current distributed polynomial commitment scheme implementation
  and benchmark code.
- `DistZKBench/`: the design track for an artifact-quality distributed
  PCS/SNARK benchmarking framework.

## Repository Layout

```text
DistZK/
  pq_dPCS/
    Existing pq_dSNARK/dePCS implementation, scripts, vendored baselines,
    and benchmark results.

  DistZKBench/
    DistZKBench.md
```

## pq_dPCS

`pq_dPCS` contains the current implementation work for transparent distributed
polynomial commitment schemes, including:

- Rust crates for core math and PCS logic.
- dePCS protocol implementation.
- Benchmark scripts and platform launchers.
- Vendored comparison baselines.

Start here for build, test, and benchmark instructions:

```text
pq_dPCS/README.md
```

## DistZKBench

`DistZKBench` is intended to become an artifact-quality distributed ZKP
benchmarking framework. The current document defines the engineering target:

```text
DistZKBench/DistZKBench.md
```

The goal is to support reproducible evaluation with process isolation,
TCP-only protocol communication, phase-level tracing, resource measurement,
network emulation, and remote-cluster calibration.

## Current Status

At this stage, `pq_dPCS` is the active implementation path. `DistZKBench` is
tracked as a parallel systems-design direction and will be developed under the
same DistZK umbrella.

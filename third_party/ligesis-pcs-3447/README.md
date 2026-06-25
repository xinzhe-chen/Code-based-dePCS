# LigeSIS-PCS

Rust implementations of LigeSIS, a polynomial commitment schemes (PCS) for multilinear polynomials, with single-thread and distributed benchmarks.

## Repository layout

- `ligesis-pcs/`: main Rust crate and distributed examples
- `external/`: submodules (HyperFond, HyperPianist, PIP_FRI, FRIttata)
- `benchmark.py`: benchmark runner (local + distributed)

## Prerequisites

- Rust toolchain (nightly)
- Python 3 for helper scripts

## Quick start

```bash
git submodule update --init --recursive
cargo test
```

## Tests

Run all tests:
```bash
cargo test
```

Run PCS unit tests only:
```bash
cargo test -p ligesis-pcs test_ligesis_pcs
cargo test -p ligesis-pcs test_deepfold_pcs
cargo test -p ligesis-pcs test_ligero_pcs
```

## Benchmarks (cargo)

LigeSIS:
```bash
cargo bench --package ligesis-pcs --bench ligesis_bench --features print-trace
cargo bench --package ligesis-pcs --bench ligesis_bench -- --mu 20 --iterations 3
```

DeepFold:
```bash
cargo bench --package ligesis-pcs --bench deepfold_bench --features print-trace -- --mu 20
cargo bench --package ligesis-pcs --bench deepfold_bench -- --test-batch --num-polys 5 --mu 18
```

Ligero:
```bash
cargo bench --package ligesis-pcs --bench ligero_bench --features print-trace -- --mu 20
```

Common options:
- `-m, --mu <MU>`: number of variables
- `-i, --iterations <N>`: iterations per operation

## Benchmarks (benchmark.py)

`benchmark.py` wraps local and distributed benchmarks with a simple CLI + interactive shell.

Interactive mode:
```bash
python3 benchmark.py
```

One-shot commands:
```bash
python3 benchmark.py status
python3 benchmark.py set-n 4
python3 benchmark.py run -s ligesis -m 24
python3 benchmark.py run -s dligesis -m 28
```

Notes:
- Results go to `bench_results/`
- Config + command history is cached under `.benchmark_cache/`
- Default server config: `ligesis-pcs/dTests/servers_16.json`
- Run `python3 benchmark.py help` to see the full scheme list and flags

## Distributed testing (run.py)

Local mode:
```bash
cd ligesis-pcs/dTests
python3 run.py dLigesis
python3 run.py dLigesis -n 8
python3 run.py dLigesis -m 24
python3 run.py dLigesis --trace
```

Remote mode (multi-server):
1) Create a `servers.json`:
```json
{
    "servers": [
        {"host": "10.128.0.2", "ssh_host": "35.202.139.171"},
        {"host": "10.128.0.3", "ssh_host": "104.197.202.243"},
        {"host": "10.128.0.4", "ssh_host": "34.72.91.60"},
        {"host": "10.128.0.5", "ssh_host": "34.69.184.100"}
    ],
    "user": "ubuntu",
    "ssh_key": "~/.ssh/id_ed25519",
    "remote_dir": "~/ligesis-pcs",
    "network_port": 18000
}
```

2) Run:
```bash
python3 run.py dLigesis --servers servers.json --sync --build -m 24
python3 run.py dLigesis --servers servers.json --sync -m 24
python3 run.py dLigesis --servers servers.json -m 24
python3 run.py dLigesis --servers servers.json -m 24 --trace
```

## Features

- `print-trace`: enable timing output for profiling

## License

MIT License

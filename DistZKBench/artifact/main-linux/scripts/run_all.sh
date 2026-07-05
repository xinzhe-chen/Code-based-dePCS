#!/usr/bin/env bash
set -euo pipefail

cargo build --release --locked
./target/release/dzb run configs/examples/toy_star_4.yaml
./target/release/dzb run configs/examples/toy_fullmesh_4.yaml
./target/release/dzb run configs/examples/toy_pingpong_2.yaml
./target/release/dzb run configs/examples/blackbox_echo.yaml
./target/release/dzb run configs/examples/pq_depcs_native_small.yaml

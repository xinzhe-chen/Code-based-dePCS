#!/usr/bin/env bash
set -euo pipefail

cargo build --release --locked
./target/release/dzb preflight --config configs/examples/toy_star_4.yaml
./target/release/dzb run configs/examples/toy_star_4.yaml


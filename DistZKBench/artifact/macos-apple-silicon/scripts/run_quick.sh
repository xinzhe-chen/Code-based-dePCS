#!/usr/bin/env bash
set -euo pipefail

cargo build --release --locked
./target/release/dzb preflight --config artifact/macos-apple-silicon/configs/macos_toy_star.yaml
./target/release/dzb run artifact/macos-apple-silicon/configs/macos_toy_star.yaml


#!/usr/bin/env bash
set -euo pipefail

if [[ "${1:-}" == "--all" ]]; then
  ./target/release/dzb cleanup --all
else
  ./target/release/dzb cleanup --run-id "${1:?usage: cleanup.sh <run-id>|--all}"
fi


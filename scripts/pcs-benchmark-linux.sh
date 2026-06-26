#!/usr/bin/env bash
# Launcher for the distributed-PCS comparison benchmark (Linux).
# Forwards all arguments to scripts/benchmark.py. Run with --help for options.
set -euo pipefail
repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
python_bin="$(command -v python3 || command -v python || true)"
if [ -z "$python_bin" ]; then
  echo "error: python3 (or python) not found on PATH" >&2
  exit 1
fi
exec "$python_bin" "$repo_root/scripts/benchmark.py" "$@"

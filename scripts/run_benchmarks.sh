#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

log() {
  printf '[benchmark] %s\n' "$*"
}

usage() {
  cat <<'USAGE'
Usage:
  scripts/run_benchmarks.sh [--sizes 4,8,16 | --nv-powers 2,3,4 | --nv-range 2..6] [--workers 1,2,4] [--pcs-queries N] [--out results]

Runs the pq_dSNARK benchmark suite through the real Rust prover/verifier paths.
Each run creates results/bench-<timestamp>/ with source.csv, source.json,
summary.txt, and SVG charts.
When no size flag is passed, the Rust benchmark defaults to nv = 2^2, 2^3,
and 2^4.
USAGE
}

if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
  usage
  exit 0
fi

command -v cargo >/dev/null 2>&1 || {
  echo "cargo is required but was not found on PATH" >&2
  exit 127
}

log "workspace: $repo_root"
log "building pq-experiments"
cargo build -p pq-experiments
log "running benchmark: $*"
"$repo_root/target/debug/pq-experiments" benchmark "$@"
log "done"

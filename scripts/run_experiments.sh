#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

log() {
  printf '[experiment] %s\n' "$*"
}

usage() {
  cat <<'USAGE'
Usage:
  scripts/run_experiments.sh
  scripts/run_experiments.sh interactive
  scripts/run_experiments.sh <r1cs|plonkish> [--workers N] [--size N] [--pcs-queries N] [--format json|csv] [--case positive|negative|both]
  scripts/run_experiments.sh net-demo [--workers N] [--format json|csv]
  scripts/run_experiments.sh worker --addr HOST:PORT --id N
  scripts/run_experiments.sh master --addrs HOST1:PORT,HOST2:PORT [--ids 0,1] [--shutdown]
  scripts/run_experiments.sh net-proof <r1cs|plonkish> [--size N] [--pcs-queries N] [--format json|csv] [--case positive|negative|both]

With no arguments, this runs the default correctness experiments for both
routes, includes positive and negative verification cases, and runs a loopback
TCP network smoke test plus network-backed PCS proof runs.
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

if [[ "$#" -gt 0 ]]; then
  log "workspace: $repo_root"
  log "building pq-experiments"
  cargo build -p pq-experiments
  bin="$repo_root/target/debug/pq-experiments"
  if [[ "${1:-}" == "interactive" ]]; then
    log "running interactive experiment runner"
    "$bin" interactive
    exit 0
  fi
  if [[ "${1:-}" == "net-proof" ]]; then
    protocol="${2:-}"
    if [[ -z "$protocol" ]]; then
      echo "net-proof requires <r1cs|plonkish>" >&2
      exit 2
    fi
    shift 2
    log "starting loopback workers"
    "$bin" worker --addr 127.0.0.1:19211 --id 0 &
    worker_a=$!
    "$bin" worker --addr 127.0.0.1:19212 --id 1 &
    worker_b=$!
    cleanup() {
      kill "$worker_a" "$worker_b" 2>/dev/null || true
    }
    trap cleanup EXIT
    sleep 0.5
    log "running network-backed $protocol proof"
    "$bin" master --addrs 127.0.0.1:19211,127.0.0.1:19212 --ids 0,1 --protocol "$protocol" "$@" --shutdown
    wait "$worker_a" "$worker_b" 2>/dev/null || true
    trap - EXIT
    log "done"
    exit 0
  fi
  log "running: pq-experiments $*"
  "$bin" "$@"
  log "done"
  exit 0
fi

log "running workspace tests"
cargo test --workspace
log "building pq-experiments"
cargo build -p pq-experiments
bin="$repo_root/target/debug/pq-experiments"
log "running local R1CS positive/negative smoke"
"$bin" r1cs --workers 1 --size 8 --format json --case both
log "running local Plonkish positive/negative smoke"
"$bin" plonkish --workers 2 --size 4 --format csv --case both
log "running TCP round-trip smoke"
"$bin" net-demo --workers 2 --format json
log "running network-backed R1CS proof smoke"
"$BASH" "$repo_root/scripts/run_experiments.sh" net-proof r1cs --size 8 --pcs-queries 3 --format json --case both
log "running network-backed Plonkish proof smoke"
"$BASH" "$repo_root/scripts/run_experiments.sh" net-proof plonkish --size 8 --pcs-queries 3 --format csv --case both
log "done"

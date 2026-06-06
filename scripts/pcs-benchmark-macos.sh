#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

prompt_text_hidden_default() {
  local prompt="$1"
  local default="$2"
  local value
  read -r -p "$prompt: " value
  printf '%s' "${value:-$default}"
}

prompt_required_choice() {
  local prompt="$1"
  shift
  local allowed=("$@")
  local value candidate
  while true; do
    read -r -p "$prompt: " value
    value="${value//$'\r'/}"
    for candidate in "${allowed[@]}"; do
      if [[ "$value" == "$candidate" ]]; then
        printf '%s' "$value"
        return 0
      fi
    done
    printf 'expected one of: %s\n' "${allowed[*]}" >&2
  done
}

prompt_choice_default() {
  local prompt="$1"
  local default="$2"
  shift 2
  local allowed=("$@")
  local value candidate
  while true; do
    read -r -p "$prompt [$default]: " value
    value="${value//$'\r'/}"
    value="${value:-$default}"
    for candidate in "${allowed[@]}"; do
      if [[ "$value" == "$candidate" ]]; then
        printf '%s' "$value"
        return 0
      fi
    done
    printf 'expected one of: %s\n' "${allowed[*]}" >&2
  done
}

max_power_of_two_exponent() {
  local value="$1"
  local exponent=0
  while (( value > 1 )); do
    value=$((value / 2))
    exponent=$((exponent + 1))
  done
  printf '%s' "$exponent"
}

run_pcs_benchmark() {
  local runner opening n_min n_max n_range worker_min worker_max worker_range pcs_queries
  local host_cores host_worker_max default_worker_max
  host_cores="$(sysctl -n hw.logicalcpu 2>/dev/null || getconf _NPROCESSORS_ONLN 2>/dev/null || printf '1')"
  host_worker_max="$(max_power_of_two_exponent "$host_cores")"
  runner="$(prompt_required_choice 'runner local|network|both' local network both)"
  opening="$(prompt_choice_default 'opening compact|full|both' compact compact full both)"
  n_min="$(prompt_text_hidden_default 'minimum PCS size exponent n for N=2^n' '8')"
  n_max="$(prompt_text_hidden_default 'maximum PCS size exponent n for N=2^n' '10')"
  if ((n_min > n_max)); then
    printf 'minimum PCS size exponent must be <= maximum PCS size exponent\n' >&2
    return 1
  fi
  n_range="${n_min}..${n_max}"
  default_worker_max="$host_worker_max"
  if ((default_worker_max > n_min)); then
    default_worker_max="$n_min"
  fi
  if ((default_worker_max > 3)); then
    default_worker_max=3
  fi
  worker_min="$(prompt_text_hidden_default 'minimum worker exponent for workers=2^w' '0')"
  worker_max="$(prompt_text_hidden_default 'maximum worker exponent for workers=2^w' "$default_worker_max")"
  if ((worker_min > worker_max)); then
    printf 'minimum worker exponent must be <= maximum worker exponent\n' >&2
    return 1
  fi
  worker_range="${worker_min}..${worker_max}"
  pcs_queries="$(prompt_text_hidden_default 'PCS queries' '1')"

  cargo run -p pq-experiments -- pcs-benchmark \
    --runner "$runner" \
    --opening "$opening" \
    --n-range "$n_range" \
    --worker-power-range "$worker_range" \
    --pcs-queries "$pcs_queries"
}

while true; do
  cat <<'MENU'
Distributed Brakedown PCS benchmark
1) Run PCS benchmark
0) Exit
MENU
  read -r -p "Select: " choice
  choice="${choice//$'\r'/}"
  case "${choice:-0}" in
    1) run_pcs_benchmark ;;
    0) exit 0 ;;
    *) echo "Unknown option: $choice" ;;
  esac
done

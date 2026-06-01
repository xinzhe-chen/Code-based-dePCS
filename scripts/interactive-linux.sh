#!/usr/bin/env bash
set -euo pipefail

script_path="${BASH_SOURCE[0]}"
script_dir="${script_path%/*}"
if [[ "$script_dir" == "$script_path" ]]; then
  script_dir="."
fi
script_dir="$(cd "$script_dir" && pwd -P)"
repo_root="$(cd "$script_dir/.." && pwd)"
cd "$repo_root"
export PATH="$repo_root/target/tools:$PATH"

platform="${PQ_DSNARK_INTERACTIVE_PLATFORM:-linux}"

section() {
  printf '\n== %s ==\n' "$*"
}

step() {
  printf '[pq_dSNARK] %s\n' "$*"
}

prompt_text() {
  local prompt="$1"
  local default="${2:-}"
  local value
  if [[ -n "$default" ]]; then
    printf '%s [%s]: ' "$prompt" "$default" >&2
  else
    printf '%s: ' "$prompt" >&2
  fi
  if ! IFS= read -r value; then
    value="$default"
  fi
  value="${value#"${value%%[![:space:]]*}"}"
  value="${value%"${value##*[![:space:]]}"}"
  if [[ -z "$value" ]]; then
    value="$default"
  fi
  printf '%s' "$value"
}

prompt_choice() {
  local prompt="$1"
  local default="$2"
  shift 2
  local allowed=("$@")
  local value
  while true; do
    value="$(prompt_text "$prompt" "$default")"
    for candidate in "${allowed[@]}"; do
      if [[ "$value" == "$candidate" ]]; then
        printf '%s' "$value"
        return 0
      fi
    done
    printf "Invalid value '%s'. Expected one of: %s\n" "$value" "${allowed[*]}" >&2
  done
}

prompt_required_text() {
  local prompt="$1"
  local value
  while true; do
    value="$(prompt_text "$prompt")"
    if [[ -n "$value" ]]; then
      printf '%s' "$value"
      return 0
    fi
    printf 'Value is required.\n' >&2
  done
}

prompt_required_choice() {
  local prompt="$1"
  shift
  local allowed=("$@")
  local value
  while true; do
    value="$(prompt_required_text "$prompt")"
    for candidate in "${allowed[@]}"; do
      if [[ "$value" == "$candidate" ]]; then
        printf '%s' "$value"
        return 0
      fi
    done
    printf "Invalid value '%s'. Expected one of: %s\n" "$value" "${allowed[*]}" >&2
  done
}

confirm_required_choice() {
  local prompt="$1"
  local value
  while true; do
    value="$(prompt_required_text "$prompt (y/n)")"
    case "$value" in
      y|Y|yes|YES|Yes) return 0 ;;
      n|N|no|NO|No) return 1 ;;
      *) printf 'Please answer y or n.\n' >&2 ;;
    esac
  done
}

confirm_choice() {
  local prompt="$1"
  local default="${2:-n}"
  local value
  while true; do
    value="$(prompt_text "$prompt [y/n]" "$default")"
    case "$value" in
      y|Y|yes|YES|Yes) return 0 ;;
      n|N|no|NO|No) return 1 ;;
      *) printf 'Please answer y or n.\n' >&2 ;;
    esac
  done
}

have() {
  command -v "$1" >/dev/null 2>&1
}

have_figure_compiler() {
  have tectonic || have pdflatex
}

set_tectonic_cache_dir() {
  if [[ -z "${TECTONIC_CACHE_DIR:-}" ]]; then
    export TECTONIC_CACHE_DIR="$repo_root/target/tectonic-cache"
    mkdir -p "$TECTONIC_CACHE_DIR"
  fi
}

have_macos_command_line_tools() {
  if [[ "$platform" != "macos" ]]; then
    return 0
  fi
  have xcode-select && xcode-select -p >/dev/null 2>&1 && have clang
}

invoke_checked() {
  printf '> %q' "$1"
  local cmd="$1"
  shift
  local arg
  for arg in "$@"; do
    printf ' %q' "$arg"
  done
  printf '\n'
  "$cmd" "$@"
}

show_preflight() {
  section "Preflight"
  local tools=(git rustc cargo rustup)
  local tool
  for tool in "${tools[@]}"; do
    if have "$tool"; then
      printf '%-24s ok\n' "$tool"
    else
      printf '%-24s missing\n' "$tool"
    fi
  done
  if [[ "$platform" == "linux" ]]; then
    if have taskset; then
      printf '%-24s ok\n' "taskset"
    else
      printf '%-24s missing\n' "taskset"
    fi
  elif [[ "$platform" == "macos" ]]; then
    if have_macos_command_line_tools; then
      printf '%-24s ok\n' "Xcode command line tools"
    else
      printf '%-24s missing\n' "Xcode command line tools"
    fi
  fi
  if have_figure_compiler; then
    printf '%-24s ok\n' "LaTeX figure compiler"
  else
    printf '%-24s missing\n' "LaTeX figure compiler"
  fi
  if have cargo; then
    invoke_checked cargo --version
  fi
  printf 'repo: %s\n' "$repo_root"
}

detect_package_manager() {
  if [[ "$platform" == "macos" ]]; then
    if have brew; then
      printf 'brew'
      return 0
    fi
    printf 'none'
    return 0
  fi
  if have apt-get; then
    printf 'apt'
  elif have dnf; then
    printf 'dnf'
  elif have pacman; then
    printf 'pacman'
  elif have zypper; then
    printf 'zypper'
  else
    printf 'none'
  fi
}

sudo_cmd() {
  if [[ "${EUID:-$(id -u)}" -eq 0 ]]; then
    "$@"
  elif have sudo; then
    sudo "$@"
  else
    printf 'sudo is required for system package installation\n' >&2
    return 1
  fi
}

install_macos_command_line_tools() {
  if have_macos_command_line_tools; then
    return 0
  fi
  if ! have xcode-select; then
    printf 'xcode-select is missing; install Xcode Command Line Tools from Apple and rerun this menu.\n' >&2
    return 1
  fi
  step "requesting Xcode Command Line Tools installation"
  xcode-select --install 2>/dev/null || true
  printf 'If a macOS installer prompt opened, complete it and rerun this menu option.\n' >&2
  return 1
}

install_system_tools() {
  local manager
  manager="$(detect_package_manager)"
  case "$manager" in
    brew)
      if [[ "$platform" == "macos" ]]; then
        install_macos_command_line_tools || return 1
      fi
      invoke_checked brew install git
      ;;
    apt)
      invoke_checked sudo_cmd apt-get update
      invoke_checked sudo_cmd apt-get install -y build-essential pkg-config git curl ca-certificates util-linux
      ;;
    dnf)
      invoke_checked sudo_cmd dnf install -y gcc gcc-c++ make pkgconf-pkg-config git curl ca-certificates util-linux
      ;;
    pacman)
      invoke_checked sudo_cmd pacman -Sy --needed --noconfirm base-devel git curl ca-certificates util-linux
      ;;
    zypper)
      invoke_checked sudo_cmd zypper install -y gcc gcc-c++ make pkg-config git curl ca-certificates util-linux
      ;;
    none)
      if [[ "$platform" == "macos" ]]; then
        install_macos_command_line_tools
        return $?
      fi
      printf 'No supported package manager detected; install git, curl, and build tools manually.\n' >&2
      return 1
      ;;
  esac
}

install_rustup_if_missing() {
  if have cargo && have rustc; then
    return 0
  fi
  if ! have curl; then
    install_system_tools
  fi
  step "installing rustup and the pinned Rust toolchain"
  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
  # shellcheck disable=SC1090
  source "$HOME/.cargo/env"
}

install_figure_compiler() {
  if have_figure_compiler; then
    return 0
  fi
  mkdir -p "$repo_root/target/tools"
  local manager
  manager="$(detect_package_manager)"
  case "$manager" in
    brew)
      if invoke_checked brew install tectonic; then
        have_figure_compiler && return 0
      fi
      ;;
    apt)
      invoke_checked sudo_cmd apt-get update || true
      if invoke_checked sudo_cmd apt-get install -y tectonic; then
        have_figure_compiler && return 0
      fi
      ;;
    dnf)
      if invoke_checked sudo_cmd dnf install -y tectonic; then
        have_figure_compiler && return 0
      fi
      ;;
    pacman)
      if invoke_checked sudo_cmd pacman -Sy --needed --noconfirm tectonic; then
        have_figure_compiler && return 0
      fi
      ;;
    zypper)
      if invoke_checked sudo_cmd zypper install -y tectonic; then
        have_figure_compiler && return 0
      fi
      ;;
  esac

  step "installing prebuilt tectonic figure compiler"
  if (cd "$repo_root/target/tools" && curl --proto '=https' --tlsv1.2 -fsSL https://drop-sh.fullyjustified.net | sh); then
    have_figure_compiler && return 0
  fi

  install_rustup_if_missing
  if [[ -f "$HOME/.cargo/env" ]]; then
    # shellcheck disable=SC1090
    source "$HOME/.cargo/env"
  fi
  if ! have cargo; then
    printf 'cargo is required to install tectonic\n' >&2
    return 1
  fi
  step "installing tectonic figure compiler from source"
  invoke_checked cargo install tectonic --locked
}

ensure_toolchain() {
  local install="${1:-false}"
  local need_network_tools="${2:-false}"
  local need_figure_compiler="${3:-false}"
  if [[ -f "$HOME/.cargo/env" ]]; then
    # shellcheck disable=SC1090
    source "$HOME/.cargo/env"
  fi
  local missing=()
  for tool in git rustc cargo; do
    if ! have "$tool"; then
      missing+=("$tool")
    fi
  done
  if [[ "$platform" == "linux" && "$need_network_tools" == "true" ]] && ! have taskset; then
    missing+=("taskset")
  elif [[ "$platform" == "macos" ]] && ! have_macos_command_line_tools; then
    missing+=("xcode-command-line-tools")
  fi
  if [[ "$need_figure_compiler" == "true" ]] && ! have_figure_compiler; then
    missing+=("tectonic")
  fi
  if ((${#missing[@]} == 0)); then
    step "toolchain preflight passed"
  elif [[ "$install" == "true" ]]; then
    step "installing missing tools: ${missing[*]}"
    install_system_tools
    install_rustup_if_missing
    if [[ " ${missing[*]} " == *" tectonic "* ]]; then
      install_figure_compiler
    fi
  else
    printf 'Missing required tools: %s\nChoose Environment setup/check to install detected missing dependencies.\n' "${missing[*]}" >&2
    return 1
  fi
  if [[ -f "$HOME/.cargo/env" ]]; then
    # shellcheck disable=SC1090
    source "$HOME/.cargo/env"
  fi
  for tool in git rustc cargo; do
    have "$tool" || {
      printf '%s is still missing after setup\n' "$tool" >&2
      return 1
    }
  done
  if [[ "$platform" == "macos" ]] && ! have_macos_command_line_tools; then
    printf 'Xcode Command Line Tools are still missing; complete the Apple installer and rerun this menu.\n' >&2
    return 1
  fi
  if [[ "$need_figure_compiler" == "true" ]] && ! have_figure_compiler; then
    printf 'LaTeX figure compiler is still missing; install tectonic or pdflatex and rerun this menu.\n' >&2
    return 1
  fi
  if [[ "$need_figure_compiler" == "true" ]]; then
    set_tectonic_cache_dir
  fi
  if have rustup; then
    invoke_checked rustup show
    if [[ "$install" == "true" ]]; then
      invoke_checked rustup component add rustfmt clippy
    fi
  fi
}

ensure_toolchain_for_action() {
  local need_network_tools="${1:-false}"
  local need_figure_compiler="${2:-false}"
  if ensure_toolchain false "$need_network_tools" "$need_figure_compiler"; then
    return 0
  fi
  if confirm_required_choice "Install missing dependencies now"; then
    ensure_toolchain true "$need_network_tools" "$need_figure_compiler"
  else
    return 1
  fi
}

build_experiment_binary() {
  local profile="$1"
  if [[ "$profile" == "release" ]]; then
    invoke_checked cargo build -p pq-experiments --release
  else
    invoke_checked cargo build -p pq-experiments
  fi
}

proof_wizard() {
  ensure_toolchain_for_action false
  section "Proof Experiment Wizard"
  printf 'Runs one positive proof experiment, saves real proof bundles under the new bench folder, and performs the initial verify once.\n'
  local protocol runner n_power workers pcs_queries args bin
  protocol="$(prompt_required_choice 'protocol r1cs|plonkish|both' r1cs plonkish both)"
  runner="$(prompt_required_choice 'runner local|network' local network)"
  if [[ "$runner" == "network" ]]; then
    ensure_toolchain_for_action true
  fi
  n_power="$(prompt_required_text 'circuit size exponent n for nv=2^n')"
  workers="$(prompt_required_text 'worker count')"
  pcs_queries="$(prompt_required_text 'PCS query count')"
  args=(proof-experiment --protocol "$protocol" --runner "$runner" --n "$n_power" --workers "$workers" --pcs-queries "$pcs_queries")
  step "building release pq-experiments"
  build_experiment_binary release
  bin="$repo_root/target/release/pq-experiments"
  invoke_checked "$bin" "${args[@]}"
}

max_worker_from_csv() {
  local csv="$1"
  local max=0
  local value
  IFS=',' read -ra values <<< "$csv"
  for value in "${values[@]}"; do
    value="${value//[[:space:]]/}"
    if ((value > max)); then
      max="$value"
    fi
  done
  printf '%s' "$max"
}

power_range_to_csv() {
  local range="$1"
  local start="${range%%..*}"
  local end="${range##*..}"
  if [[ "$start" == "$range" || -z "$start" || -z "$end" ]]; then
    printf 'power range must look like 0..2\n' >&2
    return 1
  fi
  if ((start > end)); then
    printf 'power range start must be <= end\n' >&2
    return 1
  fi
  local values=(1)
  local power
  for ((power = start; power <= end; power++)); do
    values+=("$((1 << power))")
  done
  local sorted=()
  local value
  while IFS= read -r value; do
    sorted+=("$value")
  done < <(printf '%s\n' "${values[@]}" | sort -n -u)
  local IFS=,
  printf '%s' "${sorted[*]}"
}

runner_variant_count() {
  local runner="$1"
  if [[ "$runner" == "both" ]]; then
    printf '2'
  else
    printf '1'
  fi
}

csv_count() {
  local csv="$1"
  local values
  IFS=',' read -ra values <<< "$csv"
  printf '%s' "${#values[@]}"
}

confirm_benchmark_grid() {
  local runner="$1"
  local size_count="$2"
  local size_label="$3"
  local workers="$4"
  local worker_count runner_count total_jobs
  worker_count="$(csv_count "$workers")"
  runner_count="$(runner_variant_count "$runner")"
  total_jobs=$((size_count * worker_count * 2 * runner_count))
  step "benchmark grid: sizes=$size_label size_count=$size_count workers=$workers total_jobs=$total_jobs"
  if confirm_required_choice "Run this benchmark grid"; then
    return 0
  fi
  step "benchmark cancelled"
  return 1
}

show_benchmark_core_plan() {
  local runner="$1"
  local workers="$2"
  if [[ "$runner" == "local" || "$workers" != *,* ]]; then
    return 0
  fi
  local max_workers host_cores cores_per_worker
  max_workers="$(max_worker_from_csv "$workers")"
  host_cores="$(getconf _NPROCESSORS_ONLN 2>/dev/null || printf '1')"
  cores_per_worker=$((host_cores / max_workers))
  step "network scaling core plan: host_logical_cores=$host_cores max_workers=$max_workers cores_per_worker=$cores_per_worker"
  if ((cores_per_worker < 1)); then
    printf 'host has too few logical cores for the requested max worker count\n' >&2
    return 1
  fi
}

benchmark_wizard() {
  ensure_toolchain_for_action false
  section "Performance Benchmark Wizard"
  printf 'Each benchmark job runs one real end-to-end prove+verify path. Correctness tests are not included.\n'
  printf 'During execution, pq-experiments prints an exact completed-jobs progress bar before and after each real job.\n'

  local runner args paper_preset compile_figures
  if confirm_required_choice "Use the full paper-quality benchmark grid"; then
    paper_preset=true
  else
    paper_preset=false
  fi
  runner="$(prompt_required_choice 'runner local|network|both' local network both)"
  if [[ "$runner" != "local" ]]; then
    ensure_toolchain_for_action true
  fi
  args=(benchmark --runner "$runner" --repeats 1)
  local size_count=5
  local size_label="2^2..2^6"
  local workers="1,2,4"
  if [[ "$paper_preset" == "true" ]]; then
    args+=(--paper-preset)
  else
    local n_min n_max n_range worker_min worker_max worker_range pcs_queries
    n_min="$(prompt_required_text 'minimum circuit size exponent n for nv=2^n')"
    n_max="$(prompt_required_text 'maximum circuit size exponent n for nv=2^n')"
    if ((n_min > n_max)); then
      printf 'minimum circuit size exponent must be <= maximum circuit size exponent\n' >&2
      return 1
    fi
    n_range="${n_min}..${n_max}"
    size_count="$((n_max - n_min + 1))"
    size_label="2^${n_min}..2^${n_max}"
    worker_min="$(prompt_required_text 'minimum worker exponent for workers=2^w')"
    worker_max="$(prompt_required_text 'maximum worker exponent for workers=2^w')"
    if ((worker_min > worker_max)); then
      printf 'minimum worker exponent must be <= maximum worker exponent\n' >&2
      return 1
    fi
    worker_range="${worker_min}..${worker_max}"
    workers="$(power_range_to_csv "$worker_range")"
    pcs_queries="$(prompt_required_text 'PCS query count')"
    show_benchmark_core_plan "$runner" "$workers"
    args+=(--n-range "$n_range" --worker-power-range "$worker_range" --pcs-queries "$pcs_queries")
  fi
  confirm_benchmark_grid "$runner" "$size_count" "$size_label" "$workers" || return 0
  if confirm_required_choice "Compile paper figures after the run"; then
    ensure_toolchain_for_action false true
    args+=(--compile-figures --figure-compiler auto)
  fi
  step "building release pq-experiments"
  local bin
  build_experiment_binary release
  bin="$repo_root/target/release/pq-experiments"
  invoke_checked "$bin" "${args[@]}"
}

latest_benchmark_dir() {
  if [[ ! -d "$repo_root/results" ]]; then
    return 0
  fi
  local latest="" dir
  for dir in "$repo_root"/results/bench-*; do
    [[ -d "$dir" ]] || continue
    latest="$dir"
  done
  printf '%s' "$latest"
}

setup_wizard() {
  section "Environment Setup"
  show_preflight
  if confirm_choice "Install/check missing dependencies now" n; then
    ensure_toolchain true true true
    show_preflight
  fi
  local debug_bin="$repo_root/target/debug/pq-experiments"
  if [[ -x "$debug_bin" ]]; then
    step "debug pq-experiments already built: $debug_bin"
  elif confirm_choice "Build debug pq-experiments now" y; then
    ensure_toolchain_for_action false
    build_experiment_binary debug
  fi
}

results_wizard() {
  ensure_toolchain_for_action false
  section "Verify Experiments Wizard"
  printf 'Detects bench folders, shows which ones contain stored proof bundles, and verifies selected proofs without rewriting benchmark source artifacts.\n'
  local results_dir dir format proof_choice args bin
  results_dir="$(prompt_text 'results directory' 'results')"
  step "building debug pq-experiments"
  build_experiment_binary debug
  bin="$repo_root/target/debug/pq-experiments"
  invoke_checked "$bin" list-proofs --results "$results_dir" --format text

  local bench_dirs=()
  local bench_names=()
  local proof_counts=()
  local default_index=""
  local index=0
  local candidate proof count
  for candidate in "$results_dir"/bench-*; do
    [[ -d "$candidate" ]] || continue
    count=0
    for proof in "$candidate"/proofs/*.proof.json; do
      [[ -f "$proof" ]] || continue
      count=$((count + 1))
    done
    bench_dirs+=("$candidate")
    bench_names+=("${candidate##*/}")
    proof_counts+=("$count")
    index=$((index + 1))
    if [[ "$count" -gt 0 ]]; then
      default_index="$index"
    fi
  done
  if [[ "${#bench_dirs[@]}" -eq 0 ]]; then
    printf 'no bench directories found under %s\n' "$results_dir" >&2
    return 1
  fi
  if [[ -z "$default_index" ]]; then
    printf 'bench directories were found, but none contain proofs under proofs/*.proof.json\n' >&2
    return 1
  fi

  local selection
  selection="$(prompt_text 'benchmark number or directory to verify' "$default_index")"
  if [[ "$selection" =~ ^[0-9]+$ ]]; then
    if ((selection < 1 || selection > ${#bench_dirs[@]})); then
      printf 'benchmark selection out of range\n' >&2
      return 1
    fi
    dir="${bench_dirs[$((selection - 1))]}"
  else
    dir="$selection"
  fi
  if [[ -z "$dir" ]]; then
    printf 'no benchmark result directory selected\n' >&2
    return 1
  fi
  if [[ ! -d "$dir/proofs" ]]; then
    printf 'selected bench has no proofs directory: %s\n' "$dir" >&2
    return 1
  fi
  printf 'Proofs in %s:\n' "$dir"
  for proof in "$dir"/proofs/*.proof.json; do
    [[ -f "$proof" ]] || continue
    printf '  %s\n' "${proof##*/}"
  done
  format="$(prompt_choice 'report format [json|csv]' json json csv)"
  proof_choice="$(prompt_text 'proof id/file to verify, or all' 'all')"
  if [[ "$proof_choice" == "all" ]]; then
    args=(verify-proof "$dir" --all --format "$format")
  else
    args=(verify-proof "$dir" --proof "$proof_choice" --format "$format")
  fi
  invoke_checked "$bin" "${args[@]}"
}

show_menu() {
  section "pq_dSNARK interactive entrypoint ($platform)"
  printf '1. Environment setup/check\n'
  printf '2. Proof experiment\n'
  printf '3. Verify experiments\n'
  printf '4. Performance benchmark\n'
  printf '0. Exit\n'
}

main_menu() {
  local choice
  while true; do
    show_menu
    choice="$(prompt_required_choice 'Select an action 0|1|2|3|4' 0 1 2 3 4)"
    case "$choice" in
      0) return 0 ;;
      1) setup_wizard ;;
      2) proof_wizard ;;
      3) results_wizard ;;
      4) benchmark_wizard ;;
    esac
  done
}

main_menu

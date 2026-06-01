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

ensure_toolchain() {
  local install="${1:-false}"
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
  if [[ "$platform" == "linux" ]] && ! have taskset; then
    missing+=("taskset")
  elif [[ "$platform" == "macos" ]] && ! have_macos_command_line_tools; then
    missing+=("xcode-command-line-tools")
  fi
  if ((${#missing[@]} == 0)); then
    step "toolchain preflight passed"
  elif [[ "$install" == "true" ]]; then
    step "installing missing tools: ${missing[*]}"
    install_system_tools
    install_rustup_if_missing
  else
    printf 'Missing required tools: %s\nChoose menu option 2 to install detected missing dependencies.\n' "${missing[*]}" >&2
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
  if have rustup; then
    invoke_checked rustup show
    invoke_checked rustup component add rustfmt clippy
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
  ensure_toolchain false
  section "Proof Experiment Wizard"
  printf 'This opens the Rust CLI prompt for local, loopback network proof, or TCP demo runs.\n'
  step "building debug pq-experiments"
  local bin
  build_experiment_binary debug
  bin="$repo_root/target/debug/pq-experiments"
  invoke_checked "$bin" interactive
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
  ensure_toolchain false
  section "Performance Benchmark Wizard"
  printf 'Each benchmark job runs one real end-to-end prove+verify path. Correctness tests are not included.\n'
  printf 'During execution, pq-experiments prints an exact completed-jobs progress bar before and after each real job.\n'

  local runner args paper_preset compile_figures out_dir
  if confirm_choice "Use the full paper-quality benchmark grid" n; then
    paper_preset=true
  else
    paper_preset=false
  fi
  runner="$(prompt_choice 'runner [local|network|both]' both local network both)"
  args=(benchmark --runner "$runner" --repeats 1)
  if [[ "$paper_preset" == "true" ]]; then
    args+=(--paper-preset)
  else
    local n_range workers pcs_queries
    n_range="$(prompt_text 'circuit size exponent range n for nv=2^n' '2..5')"
    workers="$(prompt_text 'worker counts, comma separated and including 1' '1,2,4')"
    pcs_queries="$(prompt_text 'PCS query count' '1')"
    show_benchmark_core_plan "$runner" "$workers"
    args+=(--n-range "$n_range" --workers "$workers" --pcs-queries "$pcs_queries")
  fi
  if confirm_choice "Compile paper figures after the run" n; then
    local compiler
    compiler="$(prompt_choice 'figure compiler [auto|pdflatex|tectonic]' auto auto pdflatex tectonic)"
    args+=(--compile-figures --figure-compiler "$compiler")
  fi
  out_dir="$(prompt_text 'output directory' 'results')"
  args+=(--out "$out_dir")

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
  find "$repo_root/results" -maxdepth 1 -type d -name 'bench-*' | sort | tail -n 1
}

verify_wizard() {
  ensure_toolchain false
  section "Verify Results Wizard"
  local default_dir dir format args bin
  default_dir="$(latest_benchmark_dir || true)"
  dir="$(prompt_text 'benchmark result directory' "$default_dir")"
  if [[ -z "$dir" ]]; then
    printf 'no benchmark result directory selected\n' >&2
    return 1
  fi
  format="$(prompt_choice 'report format [json|csv]' json json csv)"
  args=(verify-results "$dir" --format "$format")
  if confirm_choice "apply paper-quality release gate" n; then
    args+=(--paper-quality)
  fi
  step "building debug pq-experiments"
  build_experiment_binary debug
  bin="$repo_root/target/debug/pq-experiments"
  invoke_checked "$bin" "${args[@]}"
}

show_menu() {
  section "pq_dSNARK interactive entrypoint ($platform)"
  printf '1. Preflight dependency check\n'
  printf '2. Install/check missing dependencies\n'
  printf '3. Proof experiment wizard\n'
  printf '4. Performance benchmark wizard\n'
  printf '5. Verify benchmark results\n'
  printf '0. Exit\n'
}

main_menu() {
  local choice
  while true; do
    show_menu
    choice="$(prompt_choice 'Select an action' 3 0 1 2 3 4 5)"
    case "$choice" in
      0) return 0 ;;
      1) show_preflight ;;
      2) ensure_toolchain true; show_preflight ;;
      3) proof_wizard ;;
      4) benchmark_wizard ;;
      5) verify_wizard ;;
    esac
  done
}

main_menu

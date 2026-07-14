#!/usr/bin/env bash
# Launcher for the distributed-PCS comparison benchmark (Linux).
# With arguments, forwards them to scripts/benchmark.py. With no arguments,
# opens an interactive menu.
set -euo pipefail
repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
python_bin="$(command -v python3 || command -v python || true)"
if [ -z "$python_bin" ]; then
  echo "error: python3 (or python) not found on PATH" >&2
  exit 1
fi

default_args=(
  --out results/depcs-fiveway-parallel-merkle-nv18-24-w2-w4
  --fair-sequential
  --depcs-nv-range 18..24
  --depcs-workers 2,4
  --depcs-backends deepfold:2
  --depcs-opening protocol11
  --ligesis-nvs 18,19,20,21,22,23,24
  --ligesis-parties-list 2,4
  --external-pcs-schemes dfrittata-pcs,dpip-fri-pcs
  --pcs-queries 1
  --repeats 1
)

if [ "$#" -gt 0 ]; then
  exec "$python_bin" "$repo_root/scripts/benchmark.py" "$@"
fi

echo "pq_dSNARK dePCS benchmark launcher (Linux)"
echo
echo "1) Run default nv=18..24 workers=2,4 five-way benchmark"
echo "2) Dry-run default schedule"
echo "3) Enter custom benchmark.py arguments"
echo "4) Show benchmark.py help"
echo "5) Quit"
echo
read -r -p "Select [1-5]: " choice
choice="${choice//$'\r'/}"
choice="${choice//[!1-5]/}"
choice="${choice:0:1}"
case "$choice" in
  1)
    exec "$python_bin" "$repo_root/scripts/benchmark.py" "${default_args[@]}"
    ;;
  2)
    exec "$python_bin" "$repo_root/scripts/benchmark.py" "${default_args[@]}" --dry-run
    ;;
  3)
    echo "Enter arguments exactly as you would pass after scripts/benchmark.py:"
    read -r custom_args
    custom_args="${custom_args//$'\r'/}"
    # shellcheck disable=SC2086
    exec "$python_bin" "$repo_root/scripts/benchmark.py" $custom_args
    ;;
  4)
    exec "$python_bin" "$repo_root/scripts/benchmark.py" --help
    ;;
  *)
    echo "Canceled."
    ;;
esac

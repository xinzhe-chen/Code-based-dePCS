#!/usr/bin/env bash
set -euo pipefail

script_path="${BASH_SOURCE[0]}"
script_dir="${script_path%/*}"
if [[ "$script_dir" == "$script_path" ]]; then
  script_dir="."
fi
script_dir="$(cd "$script_dir" && pwd -P)"
export PQ_DSNARK_INTERACTIVE_PLATFORM="macos"
exec "$BASH" "$script_dir/interactive-linux.sh" "$@"

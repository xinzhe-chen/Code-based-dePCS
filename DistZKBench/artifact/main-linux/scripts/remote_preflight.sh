#!/usr/bin/env bash
set -euo pipefail

: "${DZB_LINUX_SSH:?set DZB_LINUX_SSH=user@host}"
: "${DZB_LINUX_WORKDIR:=/tmp/distzkbench-${USER}}"

SSH_ARGS=(-o StrictHostKeyChecking=accept-new)
if [[ -n "${DZB_LINUX_KEY:-}" ]]; then
  SSH_ARGS+=(-i "${DZB_LINUX_KEY}")
fi

ssh "${SSH_ARGS[@]}" "${DZB_LINUX_SSH}" "mkdir -p '${DZB_LINUX_WORKDIR}'"
ssh "${SSH_ARGS[@]}" "${DZB_LINUX_SSH}" 'bash -s' <<'REMOTE'
set -euo pipefail
if [[ -f "$HOME/.cargo/env" ]]; then
  . "$HOME/.cargo/env"
fi
echo "kernel=$(uname -srmo)"
echo "arch=$(uname -m)"
command -v rustc >/dev/null && rustc --version || true
command -v cargo >/dev/null && cargo --version || true
sudo -n true
test -e /sys/fs/cgroup/cgroup.controllers
test -d /proc
command -v ip >/dev/null
command -v tc >/dev/null
if [[ -d /sys/fs/resctrl ]]; then
  echo "resctrl=mounted"
else
  echo "resctrl=missing"
fi
if [[ -e /proc/sys/kernel/perf_event_paranoid ]]; then
  echo "perf_event_paranoid=$(cat /proc/sys/kernel/perf_event_paranoid)"
else
  echo "perf_event_paranoid=missing"
fi
if command -v numactl >/dev/null; then
  numactl --hardware | sed -n '1,6p'
else
  echo "numactl=missing"
fi
REMOTE

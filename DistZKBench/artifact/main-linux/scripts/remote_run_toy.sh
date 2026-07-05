#!/usr/bin/env bash
set -euo pipefail

: "${DZB_LINUX_SSH:?set DZB_LINUX_SSH=user@host}"
: "${DZB_LINUX_WORKDIR:=/tmp/distzkbench-${USER}}"

SSH_ARGS=(-o StrictHostKeyChecking=accept-new)
if [[ -n "${DZB_LINUX_KEY:-}" ]]; then
  SSH_ARGS+=(-i "${DZB_LINUX_KEY}")
fi

cargo build --release --locked
ssh "${SSH_ARGS[@]}" "${DZB_LINUX_SSH}" "rm -rf '${DZB_LINUX_WORKDIR}' && mkdir -p '${DZB_LINUX_WORKDIR}'"
rsync -az -e "ssh ${SSH_ARGS[*]}" \
  --exclude target --exclude results --exclude .git \
  ./ "${DZB_LINUX_SSH}:${DZB_LINUX_WORKDIR}/"
ssh "${SSH_ARGS[@]}" "${DZB_LINUX_SSH}" "cd '${DZB_LINUX_WORKDIR}' && . \"\$HOME/.cargo/env\" && cargo build --release --locked && ./target/release/dzb preflight --config artifact/main-linux/configs/toy.yaml && ./target/release/dzb run artifact/main-linux/configs/toy.yaml"

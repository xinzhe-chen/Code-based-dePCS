#!/usr/bin/env bash
set -euo pipefail

: "${DZB_LINUX_SSH_A:?set DZB_LINUX_SSH_A=user@host-a}"
: "${DZB_LINUX_SSH_B:?set DZB_LINUX_SSH_B=user@host-b}"
: "${DZB_LINUX_IP_A:?set DZB_LINUX_IP_A=host-a-private-ip}"
: "${DZB_LINUX_IP_B:?set DZB_LINUX_IP_B=host-b-private-ip}"
: "${DZB_LINUX_WORKDIR_A:=/tmp/distzkbench-twohost-a-${USER}}"
: "${DZB_LINUX_WORKDIR_B:=/tmp/distzkbench-twohost-b-${USER}}"
: "${DZB_TWOHOST_PORT:=39400}"
: "${DZB_TWOHOST_MESSAGE_BYTES:=1048576}"
: "${DZB_TWOHOST_RUN_ID:=twohost-calibration-$(date +%Y%m%d%H%M%S)}"

SSH_ARGS=(-o StrictHostKeyChecking=accept-new -o BatchMode=yes)
if [[ -n "${DZB_LINUX_KEY:-}" ]]; then
  SSH_ARGS+=(-i "${DZB_LINUX_KEY}")
fi

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
LOCAL_RESULTS="${ROOT_DIR}/results/twohost_calibration/${DZB_TWOHOST_RUN_ID}"
mkdir -p "${LOCAL_RESULTS}/host-a" "${LOCAL_RESULTS}/host-b"

ssh_cmd() {
  local host="$1"
  shift
  ssh "${SSH_ARGS[@]}" "${host}" "$@"
}

sync_host() {
  local host="$1"
  local workdir="$2"
  ssh_cmd "${host}" "rm -rf '${workdir}' && mkdir -p '${workdir}/tmp' '${workdir}/logs' '${workdir}/results'"
  rsync -az -e "ssh ${SSH_ARGS[*]}" \
    --exclude target --exclude results --exclude .git --exclude .DS_Store \
    "${ROOT_DIR}/" "${host}:${workdir}/"
}

write_rank_config() {
  local host="$1"
  local workdir="$2"
  local rank="$3"
  local proof_path="null"
  if [[ "${rank}" == "0" ]]; then
    proof_path="\"${workdir}/results/proof.bin\""
  fi
  ssh_cmd "${host}" "cat > '${workdir}/tmp/rank_${rank}.json'" <<JSON
{
  "run_id": "${DZB_TWOHOST_RUN_ID}",
  "rank": ${rank},
  "world_size": 2,
  "master_rank": 0,
  "adapter": "toy-alltoall",
  "topology_kind": "full-mesh",
  "enforce_topology": true,
  "routed_star": false,
  "listen_addrs": [
    "${DZB_LINUX_IP_A}:${DZB_TWOHOST_PORT}",
    "${DZB_LINUX_IP_B}:${DZB_TWOHOST_PORT}"
  ],
  "message_bytes": ${DZB_TWOHOST_MESSAGE_BYTES},
  "random_seed": 12345,
  "max_frame_payload": 1048576,
  "output_path": "${workdir}/results/rank_${rank}.json",
  "proof_path": ${proof_path},
  "thread_budget": 1,
  "shaper": {
    "bandwidth_bytes_per_sec": null,
    "latency_ms": 0
  },
  "memory_limit_bytes": 1073741824
}
JSON
}

echo "two-host calibration run_id=${DZB_TWOHOST_RUN_ID}"
echo "host_a=${DZB_LINUX_SSH_A} ip=${DZB_LINUX_IP_A} workdir=${DZB_LINUX_WORKDIR_A}"
echo "host_b=${DZB_LINUX_SSH_B} ip=${DZB_LINUX_IP_B} workdir=${DZB_LINUX_WORKDIR_B}"

sync_host "${DZB_LINUX_SSH_A}" "${DZB_LINUX_WORKDIR_A}"
sync_host "${DZB_LINUX_SSH_B}" "${DZB_LINUX_WORKDIR_B}"

ssh_cmd "${DZB_LINUX_SSH_A}" "cd '${DZB_LINUX_WORKDIR_A}' && . \"\$HOME/.cargo/env\" && cargo build --release --locked"
ssh_cmd "${DZB_LINUX_SSH_B}" "cd '${DZB_LINUX_WORKDIR_B}' && . \"\$HOME/.cargo/env\" && cargo build --release --locked"

ssh_cmd "${DZB_LINUX_SSH_A}" "cat > '${DZB_LINUX_WORKDIR_A}/tmp/local_baseline.yaml'" <<YAML
experiment:
  name: local_loopback_alltoall
  run_id: ${DZB_TWOHOST_RUN_ID}-local-loopback
  output_dir: results
  random_seed: 12345

platform:
  backend: linux

roles:
  prover_ranks: 2
  master_rank: 0
  verifier_enabled: true

topology:
  type: full-mesh
  enforce_topology: true

resources:
  worker_threads: 1
  verifier_threads: same_as_worker

memory:
  per_rank_limit: 1GiB

cache:
  mode: none

network:
  transport: tcp
  mode: loopback
  base_port: $((DZB_TWOHOST_PORT + 20))
  max_frame_payload: 1MiB

protocol:
  adapter: toy-alltoall
  mode: sdk-binary
  toy:
    message_bytes: ${DZB_TWOHOST_MESSAGE_BYTES}
YAML
ssh_cmd "${DZB_LINUX_SSH_A}" "cd '${DZB_LINUX_WORKDIR_A}' && . \"\$HOME/.cargo/env\" && ./target/release/dzb run '${DZB_LINUX_WORKDIR_A}/tmp/local_baseline.yaml' > '${DZB_LINUX_WORKDIR_A}/results/local_baseline.run.log'"
rsync -az -e "ssh ${SSH_ARGS[*]}" \
  "${DZB_LINUX_SSH_A}:${DZB_LINUX_WORKDIR_A}/results/local_loopback_alltoall/${DZB_TWOHOST_RUN_ID}-local-loopback/" \
  "${LOCAL_RESULTS}/local-loopback/"

write_rank_config "${DZB_LINUX_SSH_A}" "${DZB_LINUX_WORKDIR_A}" 0
write_rank_config "${DZB_LINUX_SSH_B}" "${DZB_LINUX_WORKDIR_B}" 1

set +e
ssh_cmd "${DZB_LINUX_SSH_A}" "cd '${DZB_LINUX_WORKDIR_A}' && . \"\$HOME/.cargo/env\" && RAYON_NUM_THREADS=1 OMP_NUM_THREADS=1 OPENBLAS_NUM_THREADS=1 MKL_NUM_THREADS=1 TOKIO_WORKER_THREADS=1 ./target/release/dzb-runner prove --config '${DZB_LINUX_WORKDIR_A}/tmp/rank_0.json'" \
  >"${LOCAL_RESULTS}/host-a/rank_0.ssh.log" 2>&1 &
PID_A=$!
ssh_cmd "${DZB_LINUX_SSH_B}" "cd '${DZB_LINUX_WORKDIR_B}' && . \"\$HOME/.cargo/env\" && RAYON_NUM_THREADS=1 OMP_NUM_THREADS=1 OPENBLAS_NUM_THREADS=1 MKL_NUM_THREADS=1 TOKIO_WORKER_THREADS=1 ./target/release/dzb-runner prove --config '${DZB_LINUX_WORKDIR_B}/tmp/rank_1.json'" \
  >"${LOCAL_RESULTS}/host-b/rank_1.ssh.log" 2>&1 &
PID_B=$!
wait "${PID_A}"
STATUS_A=$?
wait "${PID_B}"
STATUS_B=$?
set -e

rsync -az -e "ssh ${SSH_ARGS[*]}" "${DZB_LINUX_SSH_A}:${DZB_LINUX_WORKDIR_A}/results/" "${LOCAL_RESULTS}/host-a/"
rsync -az -e "ssh ${SSH_ARGS[*]}" "${DZB_LINUX_SSH_B}:${DZB_LINUX_WORKDIR_B}/results/" "${LOCAL_RESULTS}/host-b/"
rsync -az -e "ssh ${SSH_ARGS[*]}" "${DZB_LINUX_SSH_A}:${DZB_LINUX_WORKDIR_A}/tmp/" "${LOCAL_RESULTS}/host-a/tmp/"
rsync -az -e "ssh ${SSH_ARGS[*]}" "${DZB_LINUX_SSH_B}:${DZB_LINUX_WORKDIR_B}/tmp/" "${LOCAL_RESULTS}/host-b/tmp/"

if [[ "${STATUS_A}" -ne 0 || "${STATUS_B}" -ne 0 ]]; then
  echo "rank failure: status_a=${STATUS_A} status_b=${STATUS_B}" >&2
  exit 1
fi

PROOF_SHA="$(sha256sum "${LOCAL_RESULTS}/host-a/proof.bin" | awk '{print $1}')"
ssh_cmd "${DZB_LINUX_SSH_A}" "cd '${DZB_LINUX_WORKDIR_A}' && . \"\$HOME/.cargo/env\" && RAYON_NUM_THREADS=1 OMP_NUM_THREADS=1 OPENBLAS_NUM_THREADS=1 MKL_NUM_THREADS=1 TOKIO_WORKER_THREADS=1 ./target/release/dzb-runner verify --proof '${DZB_LINUX_WORKDIR_A}/results/proof.bin' --sha256 '${PROOF_SHA}' --out '${DZB_LINUX_WORKDIR_A}/results/verifier.json'"
rsync -az -e "ssh ${SSH_ARGS[*]}" "${DZB_LINUX_SSH_A}:${DZB_LINUX_WORKDIR_A}/results/verifier.json" "${LOCAL_RESULTS}/verifier.json"

python3 - "${LOCAL_RESULTS}" "${DZB_TWOHOST_RUN_ID}" "${DZB_LINUX_SSH_A}" "${DZB_LINUX_SSH_B}" "${DZB_LINUX_IP_A}" "${DZB_LINUX_IP_B}" "${PROOF_SHA}" <<'PY'
import csv
import json
import sys
from pathlib import Path

root = Path(sys.argv[1])
run_id, host_a, host_b, ip_a, ip_b, proof_sha = sys.argv[2:8]
rank0 = json.loads((root / "host-a" / "rank_0.json").read_text())
rank1 = json.loads((root / "host-b" / "rank_1.json").read_text())
local_run = json.loads((root / "local-loopback" / "run.json").read_text())
edges = rank0["communication"]["edges"] + rank1["communication"]["edges"]
total = sum(edge["serialized_payload_bytes"] for edge in edges)
summary = {
    "run_id": run_id,
    "status": "ok",
    "mode": "two_host_remote_tcp",
    "host_map": {
        "0": {"ssh": host_a, "ip": ip_a, "rank": 0},
        "1": {"ssh": host_b, "ip": ip_b, "rank": 1},
    },
    "rank_pids": [rank0["pid"], rank1["pid"]],
    "proof_sha256": proof_sha,
    "proof_size_bytes": (root / "host-a" / "proof.bin").stat().st_size,
    "total_protocol_bytes": total,
    "communication_precision": "exact_tcp_frame_payload",
    "calibration_scope": "two independent Linux VMs over private VPC TCP",
    "local_loopback_baseline": {
        "run_id": local_run["run_id"],
        "status": local_run["status"],
        "total_protocol_bytes": local_run["total_protocol_bytes"],
        "proof_size_bytes": local_run["proof_size_bytes"],
        "proof_sha256": local_run["proof_sha256"],
    },
}
(root / "calibration.json").write_text(json.dumps(summary, indent=2) + "\n")
with (root / "comm_matrix.csv").open("w", newline="") as handle:
    writer = csv.DictWriter(handle, fieldnames=["src", "dst", "messages", "serialized_payload_bytes", "framed_bytes"])
    writer.writeheader()
    for edge in edges:
        writer.writerow(edge)
print(json.dumps(summary, indent=2))
PY

echo "two-host calibration result: ${LOCAL_RESULTS}"

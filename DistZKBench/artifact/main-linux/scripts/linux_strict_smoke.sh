#!/usr/bin/env bash
set -euo pipefail

ROOT="/sys/fs/cgroup"
RUN_ID="dzb-smoke-$$"
CGROUP="${ROOT}/${RUN_ID}"
NS="dzbns$$"
V0="dzbv0$$"
V1="dzbv1$$"

cleanup() {
  set +e
  sudo ip netns del "${NS}" >/dev/null 2>&1
  sudo ip link del "${V0}" >/dev/null 2>&1
  if [[ -d "${CGROUP}" ]]; then
    sudo rmdir "${CGROUP}" >/dev/null 2>&1
  fi
}
trap cleanup EXIT

require() {
  command -v "$1" >/dev/null || {
    echo "missing required command: $1" >&2
    exit 1
  }
}

require sudo
require python3
require ip
require tc
require taskset
require numactl
sudo -n true

test -e "${ROOT}/cgroup.controllers"
grep -qw memory "${ROOT}/cgroup.controllers"
grep -qw cpuset "${ROOT}/cgroup.controllers"

sudo mkdir "${CGROUP}"
if ! grep -qw cpuset "${ROOT}/cgroup.subtree_control"; then
  echo +cpuset | sudo tee "${ROOT}/cgroup.subtree_control" >/dev/null
fi

echo 0 | sudo tee "${CGROUP}/cpuset.cpus" >/dev/null
if [[ -e "${CGROUP}/cpuset.mems" ]]; then
  echo 0 | sudo tee "${CGROUP}/cpuset.mems" >/dev/null
fi
echo "$((64 * 1024 * 1024))" | sudo tee "${CGROUP}/memory.max" >/dev/null

set +e
sudo bash -c "echo \$\$ > '${CGROUP}/cgroup.procs'; python3 - <<'PY'
chunks = []
while True:
    chunks.append(bytearray(4 * 1024 * 1024))
PY"
oom_status=$?
set -e
if [[ "${oom_status}" -eq 0 ]]; then
  echo "expected cgroup memory.max to terminate allocation" >&2
  exit 1
fi
memory_peak="$(cat "${CGROUP}/memory.peak")"
if [[ "${memory_peak}" -le 0 ]]; then
  echo "memory.peak did not record usage" >&2
  exit 1
fi

affinity_line="$(taskset -c 0 bash -c 'grep Cpus_allowed_list /proc/$$/status')"
if [[ "${affinity_line}" != *"0"* ]]; then
  echo "taskset affinity was not reflected in procfs: ${affinity_line}" >&2
  exit 1
fi

cpuset_line="$(sudo CGROUP="${CGROUP}" bash -c 'echo $$ > "${CGROUP}/cgroup.procs"; grep Cpus_allowed_list "/proc/$$/status"')"
if [[ "${cpuset_line}" != *"0"* ]]; then
  echo "cpuset cgroup was not reflected in procfs: ${cpuset_line}" >&2
  exit 1
fi

smt_selection="$(lscpu -p=CPU,CORE,SOCKET | awk -F, '!/^#/ && !seen[$2":"$3]++ { printf "%s%s", sep, $1; sep="," } END { print "" }')"
if [[ -z "${smt_selection}" ]]; then
  echo "failed to compute SMT sibling-avoidance CPU set" >&2
  exit 1
fi

numactl --hardware >/tmp/dzb-numa-hardware.txt
numactl --cpunodebind=0 true

sudo ip netns add "${NS}"
sudo ip link add "${V0}" type veth peer name "${V1}"
sudo ip link set "${V1}" netns "${NS}"
sudo ip addr add 10.200.1.1/30 dev "${V0}"
sudo ip link set "${V0}" up
sudo ip netns exec "${NS}" ip addr add 10.200.1.2/30 dev "${V1}"
sudo ip netns exec "${NS}" ip link set lo up
sudo ip netns exec "${NS}" ip link set "${V1}" up
sudo tc qdisc add dev "${V0}" root netem delay 1ms
ping -c 1 -W 2 10.200.1.2 >/dev/null
sudo tc qdisc del dev "${V0}" root

if [[ -d /sys/fs/resctrl ]]; then
  resctrl_state="available"
else
  resctrl_state="unsupported"
fi
perf_paranoid="$(cat /proc/sys/kernel/perf_event_paranoid 2>/dev/null || echo missing)"
if [[ "${perf_paranoid}" =~ ^-?[0-9]+$ ]] && [[ "${perf_paranoid}" -le 2 ]] && command -v perf >/dev/null; then
  perf_state="available"
else
  perf_state="unsupported"
fi

cat <<REPORT
linux_strict_smoke=ok
cgroup_v2=ok
cgroup_memory_max=ok
cgroup_memory_peak=${memory_peak}
taskset_affinity=ok ${affinity_line}
cpuset_cgroup=ok ${cpuset_line}
smt_sibling_avoidance_set=${smt_selection}
numa_plan=ok
netns_veth_tc=ok
resctrl_cat=${resctrl_state}
perf_event_open=${perf_state} paranoid=${perf_paranoid}
REPORT

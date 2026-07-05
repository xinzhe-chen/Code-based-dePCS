# DistZKBench MVP-3 Artifact-Quality 工程实施指南

目标：一步做到 **artifact-quality**，即不仅能本地跑多个 isolated prover，还能提供可复现配置、严格资源隔离、TCP-only 数据通信、phase-level tracing、memory/communication/prover/verifier measurement、netns/tc 网络仿真、resctrl cache 隔离、remote cluster 校准，以及可复现实验报告。

---

## 0. 总体定位

**DistZKBench** 是一个 Linux-only distributed PCS/SNARK benchmarking framework。

它不提供任何新的 PCS/SNARK 算法设计，只提供：

```text
1. isolated multi-process runtime
2. star / full-mesh topology construction
3. measured TCP data-plane communication
4. cgroup / cpuset / resctrl / NUMA / netns resource isolation
5. phase-level compute / communication / memory tracing
6. proof size and verifier time measurement
7. local single-machine distributed emulation
8. remote small-cluster calibration
9. reproducible artifact packaging
```

核心原则：

```text
controller ≠ protocol master

controller 是实验调度进程，不参与协议，不计入 prover cost。
master prover 是协议参与者，属于 prover ranks，其计算、通信、内存都计入 prover cost。
```

---

# 1. 工程目标与非目标

## 1.1 目标

### G1. Linux-only

只支持 Linux。必须显式依赖 Linux 特性：

```text
cgroup v2
sched_setaffinity / cpuset
procfs
perf_event_open
network namespace
veth / bridge
tc netem / tbf
resctrl CAT/MBA
NUMA policy
```

macOS/Windows 不支持。

### G2. 分布式 ZKP 专用

抽象对象不是普通 RPC service，而是：

```text
distributed prover ranks
protocol master
worker provers
verifier process
proof bytes
protocol transcript
phase tree
communication matrix
```

### G3. 真实进程隔离

每个 prover rank 是独立 OS process。禁止用 thread 模拟 rank。

```text
rank 0: OS process
rank 1: OS process
...
rank M-1: OS process
verifier: OS process
controller: OS process
agent: OS process
```

### G4. 真实 TCP data plane

所有协议消息必须经过 TCP。禁止：

```text
shared memory
mmap message passing
in-process channel
Unix pipe as protocol transport
file-based protocol exchange
```

control plane 可以用 TCP / Unix socket / SSH stdio，但不计入 protocol communication。

### G5. artifact-quality measurement

自动输出：

```text
prover wall time
per-rank prover time
per-phase time
compute / serialize / send / receive / wait decomposition
total communication bytes
per-edge communication matrix
per-rank sent / received bytes
proof size
verifier time
per-rank peak memory
master bottleneck metrics
worker imbalance
system manifest
reproducibility manifest
```

### G6. 可校准

同一套 adapter 可以跑：

```text
local loopback TCP
local netns/veth/tc emulation
remote SSH cluster
```

---

## 1.2 非目标

DistZKBench 不做：

```text
1. 不设计新的 PCS/SNARK 协议。
2. 不修改协议安全模型。
3. 不提供算法自动并行化。
4. 不自动优化通信。
5. 不替代真实大规模集群实验。
6. 不声称所有机器都能严格隔离 LLC；没有 resctrl CAT 时只能隔离 L1/L2 和 CPU core。
```

---

# 2. 进程模型

## 2.1 五类进程

```text
Controller
  全局实验调度器。
  不参与协议。
  不计入 prover/verifier metrics。

Agent
  每台 host 一个。
  负责本机 cgroup、cpuset、netns、resctrl、process launch、procfs/perf sampling。
  不参与协议。
  不计入 prover/verifier metrics。

Prover rank
  协议参与者。
  rank = 0, 1, ..., M-1。
  rank 0 通常是 protocol master。

Protocol master prover
  通常是 rank 0。
  star topology 中是通信中心。
  可同时作为 worker 持有 local shard。
  其 compute/memory/communication 全部计入 prover cost。

Verifier
  独立协议验证进程。
  默认使用与单个 prover 相同的 core/thread budget。
```

## 2.2 Controller 与 protocol master 的边界

必须在代码和文档中强制区分：

```text
Controller:
  launch, barrier, metrics, cleanup

Master prover:
  protocol coordination, aggregation, proof assembly, verifier interaction
```

Controller 不允许：

```text
1. 接收 witness。
2. 生成 proof。
3. 转发 data-plane protocol messages。
4. 聚合 protocol values。
5. 参与 Fiat-Shamir transcript。
```

如果某个实验需要 routing node，则它必须被建模为 **protocol rank**，而不是 controller。

---

# 3. Star 与 full-mesh topology 语义

## 3.1 Star topology

```text
            rank 1
              |
rank 2 --- rank 0 --- rank 3
              |
            rank 4
```

配置：

```yaml
topology:
  type: star
  master_rank: 0
  worker_to_worker: forbidden
```

语义：

```text
1. rank 0 是 protocol master。
2. 所有 worker 只能与 rank 0 建立 data-plane TCP。
3. worker-to-worker send 默认报错。
4. rank 0 的所有 protocol work 计入 prover cost。
```

可选 routed mode：

```yaml
topology:
  type: star
  master_rank: 0
  worker_to_worker: route_via_master
```

此时必须同时报告：

```text
logical_worker_to_worker_bytes
physical_worker_to_master_bytes
physical_master_to_worker_bytes
```

## 3.2 Full-mesh topology

```text
rank i 可以和任意 rank j 建 TCP connection
```

配置：

```yaml
topology:
  type: full-mesh
```

语义：

```text
1. 每对 ranks 之间有一条 TCP connection。
2. 支持 all-to-all、tree aggregation、butterfly exchange、distributed FFT、distributed FRI。
3. topology 不限制通信 pattern。
```

## 3.3 Master 是否也作为 worker

默认：

```yaml
roles:
  master_rank: 0
  master_participates: true
  master_has_local_shard: true
  master_budget: same_as_worker
```

这表示 rank 0 同时是：

```text
protocol coordinator + one prover worker
```

如果协议设计中 master 是纯 coordinator：

```yaml
roles:
  master_rank: 0
  master_participates: false
  master_has_local_shard: false
  master_budget: same_as_worker
```

即使 master 不持有 shard，它的 aggregation / routing / proof assembly 仍计入 prover cost。

---

# 4. 推荐仓库结构

```text
distzkbench/
  Cargo.toml
  rust-toolchain.toml
  README.md
  LICENSE
  artifact.md

  crates/
    dzb-core/
      src/
        config.rs
        roles.rs
        topology.rs
        run_id.rs
        errors.rs
        units.rs
        manifest.rs

    dzb-controller/
      src/
        main.rs
        scheduler.rs
        experiment.rs
        sweep.rs
        report_collect.rs

    dzb-agent/
      src/
        main.rs
        local_host.rs
        process_launcher.rs
        cgroup.rs
        cpuset.rs
        resctrl.rs
        netns.rs
        numa.rs
        sampler.rs
        perf.rs
        cleanup.rs

    dzb-sdk/
      src/
        lib.rs
        context.rs
        protocol.rs
        phase.rs
        proof.rs
        rng.rs
        metrics.rs

    dzb-transport/
      src/
        frame.rs
        tcp_mio.rs
        connection.rs
        topology_builder.rs
        collectives.rs
        router.rs
        counters.rs

    dzb-metrics/
      src/
        event.rs
        phase_tree.rs
        memory.rs
        communication.rs
        perf_counters.rs
        chrome_trace.rs
        json_report.rs
        csv_report.rs

    dzb-runner/
      src/
        main.rs
        prove_runner.rs
        verify_runner.rs

    dzb-report/
      src/
        main.rs
        html.rs
        plots.rs

  adapters/
    toy-pingpong/
    toy-alltoall/
    toy-sumcheck/
    ours/
    pipfri/
    frittata/
    hyperfond/

  configs/
    artifact/
      local_star.yaml
      local_fullmesh.yaml
      local_netns_10g.yaml
      remote_cluster.yaml
    examples/
      toy_star_4.yaml
      toy_fullmesh_8.yaml

  scripts/
    preflight.sh
    setup_cgroup_delegation.sh
    setup_resctrl.sh
    disable_turbo.sh
    set_governor_performance.sh
    isolate_irqs.sh
    cleanup_netns.sh
    collect_system_manifest.sh

  docs/
    design.md
    adapter_api.md
    metrics.md
    isolation.md
    networking.md
    artifact_evaluation.md

  results/
    README.md

  tests/
    integration/
      test_star_topology.rs
      test_fullmesh_topology.rs
      test_cgroup_memory.rs
      test_comm_bytes.rs
      test_netns_rate.rs
```

---

# 5. Rust 与系统依赖

## 5.1 Rust toolchain

`rust-toolchain.toml`：

```toml
[toolchain]
channel = "stable"
components = ["rustfmt", "clippy"]
profile = "default"
```

## 5.2 Cargo workspace dependencies

```toml
[workspace.dependencies]
anyhow = "1"
thiserror = "1"
clap = { version = "4", features = ["derive"] }
serde = { version = "1", features = ["derive"] }
serde_json = "1"
serde_yaml = "0.9"
toml = "0.8"
tracing = "0.1"
tracing-subscriber = "0.3"
uuid = { version = "1", features = ["v4", "serde"] }
bytes = "1"
byteorder = "1"
mio = { version = "0.8", features = ["os-poll", "net"] }
nix = { version = "0.29", features = ["sched", "resource", "signal", "process", "fs"] }
libc = "0.2"
procfs = "0.16"
hdrhistogram = "7"
sha2 = "0.10"
hex = "0.4"
memmap2 = "0.9"
tikv-jemallocator = "0.6"
tikv-jemalloc-ctl = "0.6"
```

可选：

```toml
plotters = "0.3"
comfy-table = "7"
chrono = "0.4"
```

## 5.3 Linux packages

Artifact machine 应安装：

```bash
sudo apt-get update
sudo apt-get install -y \
  build-essential clang pkg-config \
  iproute2 iptables ethtool \
  util-linux numactl hwloc \
  linux-tools-common linux-tools-generic \
  jq python3 python3-pip \
  git curl
```

如果使用 resctrl：

```bash
sudo mount -t resctrl resctrl /sys/fs/resctrl
```

如果使用 cgroup v2：

```bash
mount | grep cgroup2
```

必须记录：

```text
kernel version
CPU model
core topology
NUMA topology
SMT enabled/disabled
governor
turbo state
THP state
cgroup version
resctrl availability
netns/tc availability
```

---

# 6. 配置文件 schema

## 6.1 完整 artifact 配置示例

```yaml
experiment:
  name: ours_artifact_fullmesh
  run_id: auto
  repetitions: 5
  warmups: 1
  random_seed: 123456
  fail_on_warning: true

sweep:
  worker_counts: [1, 2, 4, 8, 16]
  problem_sizes_log2: [24, 26, 28]
  parameters:
    security_bits: [128]

deployment:
  mode: local
  # mode: ssh_cluster
  hosts:
    - name: localhost
      address: 127.0.0.1
      ranks: auto

roles:
  prover_ranks: auto
  master_rank: 0
  master_participates: true
  master_has_local_shard: true
  verifier_enabled: true

topology:
  type: full-mesh
  # type: star
  worker_to_worker: allowed
  enforce_topology: true

resources:
  worker_threads: 1
  verifier_threads: same_as_worker
  master_threads: same_as_worker
  controller_core: 0
  agent_cores: [1]
  no_overcommit: true
  check_extra_threads: true

cpu:
  physical_core_exclusive: true
  avoid_smt_siblings: true
  pin_irq_away_from_workers: true
  governor: performance
  turbo:
    mode: record_only
    # mode: disable

numa:
  policy: compact
  bind_memory: true
  preferred_node: auto

memory:
  cgroup: true
  per_rank_limit: 16GiB
  verifier_limit: 4GiB
  swap: off
  oom_kill_group: true
  prefault_framework_buffers: true
  mlock: false
  transparent_huge_pages: record_only
  allocator: jemalloc
  jemalloc_conf: "narenas:1,background_thread:false,dirty_decay_ms:0,muzzy_decay_ms:0"

cache:
  mode: resctrl_cat
  fail_if_unavailable: true
  llc_way_policy: equal
  mba: false
  cold_cache: false

network:
  transport: tcp
  mode: netns_veth
  # mode: loopback
  base_port: 39000
  tcp_nodelay: true
  send_buffer: 16MiB
  recv_buffer: 16MiB
  max_frame_payload: 16MiB
  netem:
    enabled: true
    bandwidth: 10gbit
    latency: 50us
    jitter: 5us
    loss: 0%

metrics:
  phase_tracing: true
  memory_sampling_interval_ms: 10
  collect_cgroup_peak: true
  collect_procfs: true
  collect_perf: true
  perf_events:
    - cycles
    - instructions
    - cache-references
    - cache-misses
    - branch-misses
  communication_breakdown: true
  chrome_trace: true
  output_formats: [json, csv, html]

protocol:
  adapter: ./target/release/ours_adapter
  mode: sdk-binary
  proof_output: canonical
  parameters:
    field: goldilocks
    security_bits: 128
    fri_rate: 8
    circuit_family: synthetic
```

## 6.2 配置解析原则

必须实现：

```text
1. resolved config 输出到 results/config.resolved.yaml。
2. 所有 auto 值必须 resolve 成确定值。
3. 如果请求 strict feature 但机器不支持，直接 fail。
4. 不允许 silent fallback。
5. 每次 run 都输出 manifest。
```

---

# 7. Linux 隔离实现

## 7.1 CPU pinning

Agent 负责：

```text
1. 解析 /sys/devices/system/cpu。
2. 获取 physical core 和 SMT sibling mapping。
3. 分配 worker cores。
4. controller 和 agent 使用独立 cores。
5. verifier 使用与单个 worker 相同数量 cores。
```

使用：

```rust
sched_setaffinity(pid, CpuSet)
```

同时设置 cgroup cpuset：

```text
/sys/fs/cgroup/dzb/<run_id>/rank_0/cpuset.cpus
/sys/fs/cgroup/dzb/<run_id>/rank_0/cpuset.mems
```

检查：

```text
/proc/<pid>/status: Cpus_allowed_list
```

如果 `avoid_smt_siblings=true`，禁止两个 rank 使用同一 physical core 的 sibling logical CPUs。

## 7.2 cgroup v2 memory

每个 rank 一个 cgroup：

```text
/sys/fs/cgroup/dzb/<run_id>/rank_<i>/
```

写入：

```text
memory.max = per_rank_limit
memory.swap.max = 0
memory.oom.group = 1
cgroup.procs = pid
```

采集：

```text
memory.current
memory.peak
memory.events
memory.stat
```

进程结束后读取：

```text
memory.peak
memory.events: oom, oom_kill
```

报告：

```text
peak_cgroup_memory_bytes
peak_rss_bytes
private_dirty_bytes
minor_page_faults
major_page_faults
oom_events
```

## 7.3 Cache isolation

### 7.3.1 默认不可夸大

没有 resctrl 时，只能保证：

```text
L1/L2 mostly isolated by physical-core isolation
LLC shared
```

报告中必须写：

```json
"cache_isolation": "L1/L2 private, LLC shared"
```

### 7.3.2 strict LLC isolation: resctrl CAT

如果配置：

```yaml
cache:
  mode: resctrl_cat
  fail_if_unavailable: true
```

Agent 检查：

```text
/sys/fs/resctrl/info/L3/cbm_mask
/sys/fs/resctrl/info/L3/min_cbm_bits
/sys/fs/resctrl/info/L3/num_closids
```

给每个 rank 建 group：

```text
/sys/fs/resctrl/dzb_<run_id>_rank_0
/sys/fs/resctrl/dzb_<run_id>_rank_1
...
```

写入：

```text
schemata
tasks
```

示意：

```text
rank 0 -> LLC ways 0-1
rank 1 -> LLC ways 2-3
rank 2 -> LLC ways 4-5
rank 3 -> LLC ways 6-7
```

如果 LLC ways 不够：

```text
fail unless cache.allow_shared_llc=true
```

## 7.4 NUMA policy

使用：

```text
set_mempolicy
mbind
numactl-equivalent launch
```

两种策略：

```yaml
numa:
  policy: compact
```

尽量把 ranks 放在同一 socket，减少 NUMA 变量。

```yaml
numa:
  policy: spread
```

跨 sockets 分配，适合 worker_count 大于单 socket physical cores。

必须记录：

```text
rank -> cpu list
rank -> numa node
rank -> memory node policy
```

## 7.5 THP / turbo / governor / IRQ

Artifact-quality preflight 应检查：

```text
CPU governor
turbo boost
transparent hugepage
IRQ affinity
SMT status
```

建议命令：

```bash
./scripts/set_governor_performance.sh
./scripts/disable_turbo.sh       # 可选
./scripts/isolate_irqs.sh         # 可选
```

如果没有权限，至少记录状态。

---

# 8. 网络实现

## 8.1 Control plane 与 data plane

必须分开：

```text
Control plane:
  controller/agent/rank coordination
  barriers
  start/stop
  metrics
  errors
  not counted as protocol communication

Data plane:
  rank-to-rank protocol messages
  rank-to-verifier interactive messages if enabled
  counted as protocol communication
```

## 8.2 TCP frame format

建议固定 wire format：

```rust
#[repr(C)]
pub struct FrameHeader {
    pub magic: u32,          // 0x445A4B42 = "DZKB"
    pub version: u16,
    pub header_len: u16,

    pub run_id_hi: u64,
    pub run_id_lo: u64,

    pub phase_id: u32,
    pub src_rank: u32,
    pub dst_rank: u32,
    pub tag: u32,

    pub message_id: u64,
    pub frame_index: u32,
    pub frame_count: u32,

    pub flags: u32,
    pub payload_len: u64,
    pub payload_crc32: u32,
    pub reserved: u32,
}
```

发送：

```text
[FrameHeader][payload bytes]
```

大消息拆帧：

```yaml
network:
  max_frame_payload: 16MiB
```

重组时以：

```text
(src_rank, dst_rank, tag, message_id)
```

为 key。

## 8.3 为什么用 mio，而不是 blocking TCP

Artifact-quality 版本建议默认使用 `mio` nonblocking TCP event loop。

原因：blocking `send()` 在 all-to-all 大消息场景可能死锁：

```text
所有 ranks 同时 write_all 大 payload
kernel send buffer 满
对方还没进入 read
系统卡住
```

`mio` 方案：

```text
1. 所有 sockets nonblocking。
2. 每个 rank 单线程 event loop。
3. send / recv / all_to_all 都通过 event loop 驱动。
4. 不引入额外 networking thread。
5. 可以同时 progress reads and writes。
```

## 8.4 Network API

SDK 暴露：

```rust
pub trait Network {
    fn rank(&self) -> RankId;
    fn world_size(&self) -> usize;

    fn send(&mut self, to: RankId, tag: MsgTag, payload: &[u8]) -> Result<()>;

    fn recv(&mut self, from: RankId, tag: MsgTag) -> Result<Vec<u8>>;

    fn exchange(
        &mut self,
        outgoing: Vec<OutgoingMessage>,
        expected: Vec<ExpectedMessage>,
    ) -> Result<Vec<IncomingMessage>>;

    fn broadcast(&mut self, root: RankId, tag: MsgTag, payload: &[u8]) -> Result<Option<Vec<u8>>>;

    fn gather(&mut self, root: RankId, tag: MsgTag, payload: &[u8]) -> Result<Option<Vec<Vec<u8>>>>;

    fn all_to_all(&mut self, tag: MsgTag, payloads: Vec<Vec<u8>>) -> Result<Vec<Vec<u8>>>;

    fn barrier(&mut self, name: &str) -> Result<()>;
}
```

注意：

```text
barrier 使用 control plane，不计入 data-plane communication。
```

## 8.5 Topology enforcement

Transport 层必须检查合法通信。

Star forbidden：

```rust
if topology == Star && src != master && dst != master {
    return Err(TopologyViolation);
}
```

Full-mesh：

```text
允许任意 src -> dst。
```

如果 external adapter 绕过 SDK，无法精准测量。Artifact-quality baseline 必须使用 SDK transport。

## 8.6 Connection construction

### Full-mesh

```text
1. 每个 rank listen on assigned port。
2. rank i 主动连接 rank j where j > i。
3. rank i accept rank j where j < i。
4. 每条 pair 只有一条 TCP connection。
```

### Star

```text
1. master rank listen。
2. each worker connect to master。
3. no worker-worker socket。
```

### TCP options

```rust
TCP_NODELAY = true
SO_SNDBUF = configured
SO_RCVBUF = configured
keepalive = optional
```

## 8.7 netns/veth/tc emulation

Artifact-quality local network mode：

```yaml
network:
  mode: netns_veth
  netem:
    bandwidth: 10gbit
    latency: 50us
```

Agent 做：

```bash
ip netns add dzb-${run_id}-rank0
ip link add veth-rank0 type veth peer name veth-rank0-ns
ip link set veth-rank0-ns netns dzb-${run_id}-rank0
ip link add name dzb-${run_id}-br type bridge
ip link set veth-rank0 master dzb-${run_id}-br
ip addr add 10.200.0.2/24 dev veth-rank0-ns
ip link set lo up
ip link set veth-rank0-ns up
tc qdisc add dev veth-rank0 root netem delay 50us rate 10gbit
```

可选 topology enforcement：

```bash
iptables / nftables 禁止 star 中 worker-worker 连接
```

## 8.8 Remote SSH cluster

Remote mode 不应改 adapter。

配置：

```yaml
deployment:
  mode: ssh_cluster
  hosts:
    - name: h0
      address: 10.0.0.1
      user: ubuntu
      ranks: [0, 1]
    - name: h1
      address: 10.0.0.2
      user: ubuntu
      ranks: [2, 3]
```

Controller 做：

```text
1. ssh 启动每台 host 的 dzb-agent。
2. agent 在本机创建 cgroups / resctrl / netns。
3. rank data-plane 使用真实 host IP。
4. metrics 回传 controller。
```

建议支持两种 agent 模式：

```text
ssh-stdio one-shot agent
long-running TCP agent
```

MVP-3 优先实现 `ssh-stdio one-shot agent`，避免 cluster 防火墙额外配置。

---

# 9. 测量定义

## 9.1 Prover time

报告两个主指标：

### `prover_wall_controller_ms`

由 controller 记录：

```text
t0 = release prove_start
t1 = master reports proof_ready
prover_wall_controller = t1 - t0
```

包含少量 control-plane notification latency。

### `prover_critical_path_ms`

由 ranks 本地记录：

```text
rank_i_duration = local_prove_end_i - local_prove_start_i
prover_critical_path = max_i rank_i_duration
```

不需要跨机器时钟同步，因为只使用本地 duration。

论文主表建议用：

```text
prover_time = prover_critical_path_ms
```

同时报告 `prover_wall_controller_ms` 作为 sanity check。

## 9.2 Per-rank time

每个 rank 记录：

```text
rank_total_time
rank_compute_time
rank_serialize_time
rank_network_progress_time
rank_recv_wait_time
rank_barrier_wait_time
```

定义：

```text
phase_wall_time = phase_end - phase_start

compute_time ≈ wall_time
             - serialize_time
             - network_progress_time
             - recv_wait_time
             - barrier_wait_time
```

注意：compute_time 是 decomposition 近似值，不用于安全结论。

## 9.3 Communication cost

必须分层报告：

```text
application_payload_bytes
serialized_payload_bytes
framed_bytes
control_plane_bytes
```

主通信指标：

```text
protocol_communication_bytes = serialized_payload_bytes
```

不计入：

```text
controller barrier
heartbeat
metrics upload
logs
process launch
SSH control
```

计入：

```text
rank-to-rank data-plane protocol messages
master-worker messages
worker-worker messages
interactive verifier messages if protocol uses them
```

输出：

```text
total_protocol_bytes
total_framed_bytes
message_count
max_message_bytes
per_rank_sent_bytes
per_rank_recv_bytes
master_sent_bytes
master_recv_bytes
comm_matrix[src][dst]
per_phase_comm_bytes
```

## 9.4 Proof size

Adapter 必须调用：

```rust
ctx.publish_proof(&proof_bytes)?;
```

framework 记录：

```text
proof_size_bytes = proof_bytes.len()
proof_sha256 = sha256(proof_bytes)
```

proof bytes 必须是 canonical serialized proof。

不包括：

```text
public parameters
verification key
preprocessing table
witness
benchmark metadata
```

除非某协议定义这些属于 proof。

## 9.5 Verifier time

Verifier 独立进程，资源预算默认等于单 worker。

```yaml
verifier:
  threads: same_as_worker
  repetitions: 100
```

报告：

```text
verifier_median_ms
verifier_p95_ms
verifier_deserialize_ms
verifier_core_verify_ms
verifier_peak_memory
```

主表用 median。

## 9.6 Memory

Agent 外部采样，rank 内部不启动 sampler thread。

采集源：

```text
cgroup memory.peak
cgroup memory.current
/proc/<pid>/status VmHWM / VmRSS
/proc/<pid>/smaps_rollup
wait4 rusage
```

报告：

```text
master_peak_memory
max_worker_peak_memory
median_worker_peak_memory
sum_peak_memory
verifier_peak_memory
```

主表建议用：

```text
max_rank_peak_memory
```

因为 distributed proving 中单机内存瓶颈由最大 rank 决定。

## 9.7 Perf counters

可选：

```text
cycles
instructions
cache-references
cache-misses
branch-misses
LLC-loads
LLC-load-misses
```

实现：

```text
agent 使用 perf_event_open attach 到 rank PID
start barrier 时 enable
end barrier 时 disable
```

如果权限不足：

```text
fail if metrics.collect_perf=true and fail_on_warning=true
otherwise record unavailable
```

---

# 10. Phase tracing

## 10.1 SDK API

Adapter 使用：

```rust
ctx.phase("commit.local_encode", |ctx| {
    // protocol code
})?;

ctx.phase("commit.hash", |ctx| {
    // protocol code
})?;

ctx.phase("open.sumcheck.round_0", |ctx| {
    // protocol code
})?;
```

嵌套 phase 支持：

```text
prove
  commit
    local_encode
    hash
    send_commitment
  open
    sumcheck
    fri
      fold_round_0
      fold_round_1
      query
  proof_assembly
```

## 10.2 自动绑定 phase_id

每个 TCP frame 自动带当前 phase_id：

```text
phase_id = ctx.current_phase()
```

因此可以输出：

```text
bytes per phase
messages per phase
network wait per phase
memory peak per phase
```

## 10.3 输出 Chrome trace

生成：

```text
chrome_trace.json
```

可以用：

```text
chrome://tracing
```

查看 Gantt chart：

```text
rank 0: commit | aggregate | fri | proof assembly
rank 1: commit | wait | send | ...
rank 2: ...
```

---

# 11. SDK Adapter 设计

## 11.1 Adapter binary 是主接口

不要依赖 Rust dynamic library ABI。Artifact-quality 更稳的做法是：

```text
每个 protocol adapter 是一个独立 binary。
它链接 dzb-sdk。
controller/agent 启动这个 binary，并传入 rank config。
```

启动形式：

```bash
ours_adapter prove --rank 3 --config /tmp/dzb/run/rank_3.yaml
ours_adapter verify --config /tmp/dzb/run/verifier.yaml --proof /tmp/dzb/run/proof.bin
```

## 11.2 Protocol trait

Adapter 内部实现：

```rust
pub trait Protocol {
    type PublicInput;
    type LocalInput;
    type Setup;
    type Proof;

    fn name(&self) -> &'static str;

    fn setup(&self, ctx: &mut SetupCtx) -> Result<Self::Setup>;

    fn generate_or_load_input(
        &self,
        ctx: &mut InputCtx,
        rank: RankId,
    ) -> Result<(Self::PublicInput, Self::LocalInput)>;

    fn prove(
        &self,
        ctx: &mut ProverCtx,
        setup: &Self::Setup,
        public_input: &Self::PublicInput,
        local_input: Self::LocalInput,
    ) -> Result<Option<Self::Proof>>;

    fn verify(
        &self,
        ctx: &mut VerifierCtx,
        setup: &Self::Setup,
        public_input: &Self::PublicInput,
        proof: &Self::Proof,
    ) -> Result<bool>;

    fn serialize_proof(&self, proof: &Self::Proof) -> Result<Vec<u8>>;

    fn deserialize_proof(&self, bytes: &[u8]) -> Result<Self::Proof>;
}
```

约定：

```text
Only master rank returns Some(proof).
Other ranks return None.
```

## 11.3 Prover context

```rust
pub struct ProverCtx {
    pub run_id: RunId,
    pub rank: RankId,
    pub world_size: usize,
    pub role: Role,
    pub topology: Topology,
    pub network: NetworkHandle,
    pub metrics: MetricsHandle,
    pub rng: DeterministicRng,
    pub scratch: ScratchAllocator,
}
```

## 11.4 Deterministic RNG

每个 rank seed：

```text
rank_seed = H(global_seed || run_id || rank || repetition)
```

保证：

```text
1. 可复现。
2. 不同 rank seed 不冲突。
3. 不同 repetition seed 不冲突。
```

---

# 12. External / legacy adapter

为旧代码提供 black-box 与 instrumented 两种模式。

## 12.1 Black-box mode

只能测：

```text
wall time
process memory
proof file size
exit code
```

不能精准测：

```text
per-message communication
per-phase communication
protocol data-plane bytes
```

报告中必须标记：

```json
"adapter_mode": "black_box",
"communication_precision": "unavailable"
```

## 12.2 Instrumented mode

旧代码需链接 `dzb-sdk` 或通过 C FFI 调用：

```c
dzb_send(to, tag, ptr, len);
dzb_recv(from, tag, out_ptr, out_len);
dzb_phase_start("fri.fold");
dzb_phase_end("fri.fold");
```

Artifact-quality baseline comparison 应尽量使用 instrumented mode。

---

# 13. Experiment lifecycle

一次 measured run：

```text
1. controller resolves config
2. controller starts agents
3. agents create cgroups/cpuset/resctrl/netns
4. agents launch ranks and verifier
5. data-plane TCP topology established
6. adapters load/generate local inputs
7. warmup runs
8. measured start barrier
9. perf counters enabled
10. prover ranks execute protocol
11. master publishes canonical proof bytes
12. measured end barrier
13. perf counters disabled
14. verifier process verifies proof
15. agents collect final metrics
16. controller merges reports
17. cleanup
18. generate JSON/CSV/HTML/chrome trace
```

---

# 14. CLI 设计

## 14.1 Preflight

```bash
dzb preflight --config configs/artifact/local_netns_10g.yaml
```

输出：

```text
[OK] Linux kernel
[OK] cgroup v2
[OK] enough physical cores
[OK] SMT sibling mapping
[OK] resctrl CAT
[OK] netns
[OK] tc
[OK] perf_event_open
[OK] ports available
```

如果 `fail_on_warning=true`，任何 requested feature 不可用即 fail。

## 14.2 Run

```bash
dzb run configs/artifact/local_fullmesh.yaml
```

## 14.3 Sweep

```bash
dzb sweep configs/artifact/ours_scaling.yaml
```

## 14.4 Report

```bash
dzb report results/ours_scaling/
```

生成：

```text
summary.csv
per_rank.csv
per_phase.csv
comm_matrix.csv
memory.csv
perf.csv
run.json
manifest.json
chrome_trace.json
report.html
```

## 14.5 Cleanup

```bash
dzb cleanup --run-id <run_id>
```

清理：

```text
processes
cgroups
resctrl groups
netns
veth
bridge
temporary files
```

---

# 15. 输出文件规范

每个 repetition 目录：

```text
results/<experiment>/<run_id>/
  config.original.yaml
  config.resolved.yaml
  manifest.json
  run.json
  events.jsonl
  phase_tree.json
  comm_matrix.csv
  per_rank.csv
  per_phase.csv
  memory_timeseries.csv
  perf_counters.csv
  proof.bin
  proof.sha256
  verifier.json
  chrome_trace.json
  logs/
    controller.log
    agent_localhost.log
    rank_0.log
    rank_1.log
    verifier.log
```

## 15.1 `run.json` schema

```json
{
  "run_id": "uuid",
  "experiment": {
    "name": "ours_fullmesh",
    "worker_count": 8,
    "problem_size_log2": 28,
    "repetition": 3
  },
  "system": {
    "kernel": "6.x",
    "cpu_model": "...",
    "physical_cores": 64,
    "smt_enabled": false,
    "numa_nodes": 2,
    "cgroup_version": "v2",
    "resctrl_cat": true
  },
  "prover": {
    "critical_path_ms": 12345.6,
    "wall_controller_ms": 12355.1,
    "proof_size_bytes": 456789,
    "master_peak_memory_bytes": 1234567890,
    "max_worker_peak_memory_bytes": 987654321,
    "worker_imbalance_ratio": 1.08
  },
  "verifier": {
    "median_ms": 12.34,
    "p95_ms": 12.91,
    "deserialize_ms": 1.23,
    "core_verify_ms": 11.11,
    "peak_memory_bytes": 12345678
  },
  "communication": {
    "serialized_payload_bytes": 123456789,
    "framed_bytes": 124000000,
    "message_count": 9876,
    "max_message_bytes": 16777216,
    "master_sent_bytes": 23456789,
    "master_recv_bytes": 45678901,
    "max_rank_sent_bytes": 34567890,
    "max_rank_recv_bytes": 45678901
  }
}
```

---

# 16. Measurement correctness tests

必须写测试，否则 artifact 很难可信。

## 16.1 Communication bytes test

Toy protocol：

```text
rank i sends exactly X bytes to rank j
```

测试：

```text
reported serialized_payload_bytes == expected
comm_matrix[i][j] == expected
```

## 16.2 Star topology violation test

Worker 1 尝试 send Worker 2：

```text
expect TopologyViolation
```

## 16.3 Full-mesh large all-to-all deadlock test

每个 rank 同时向所有其他 ranks 发送 256MiB：

```text
expect no deadlock
expect all bytes match
```

## 16.4 cgroup memory limit test

Rank 分配超过 memory.max：

```text
expect cgroup oom event
expect run marked failed
```

## 16.5 CPU pinning test

读取：

```text
/proc/<pid>/status
```

确认：

```text
Cpus_allowed_list == assigned cores
```

## 16.6 resctrl test

如果 `resctrl_cat` enabled，确认 pid 出现在：

```text
/sys/fs/resctrl/dzb_<run>_rank_i/tasks
```

## 16.7 netns/tc rate test

Toy transfer 1GiB，检查 throughput 接近配置 rate。

## 16.8 Verifier resource test

确认 verifier：

```text
thread count <= verifier_threads + allowed_runtime_threads
CPU affinity == assigned verifier cores
```

---

# 17. Framework overhead calibration

Artifact-quality 需要报告 framework 自身 overhead。

实现三个 microbenchmarks：

## 17.1 Null protocol

```text
no computation
no communication
only barrier
```

输出：

```text
barrier overhead
controller overhead
rank launch overhead
```

## 17.2 Ping-pong protocol

```text
rank 0 <-> rank 1
message sizes: 1KiB, 1MiB, 64MiB, 1GiB
```

输出：

```text
latency
throughput
serialization overhead
framing overhead
```

## 17.3 All-to-all protocol

```text
M ranks
each sends S bytes to all others
```

输出：

```text
deadlock-free throughput
comm_matrix accuracy
```

这些结果放进 artifact appendix 或报告首页。

---

# 18. Remote cluster calibration

## 18.1 目标

证明 single-machine netns emulation 对小规模真实多机有可解释误差。

## 18.2 实验设置

```text
M = 2, 4, 8
N = small / medium
topology = star, full-mesh
network = 10Gbps
worker_threads = 1
```

分别跑：

```text
local netns/veth/tc
real ssh_cluster
```

比较：

```text
prover_critical_path_ms
communication bytes
rank peak memory
master recv/sent bytes
worker imbalance
```

## 18.3 报告方式

```text
local emulation vs real cluster:
  communication bytes: exact by construction
  memory: within X%
  prover time: within Y% for compute-bound protocols
  communication-heavy protocols: deviation explained by NIC/bridge/tc differences
```

不要声称 local emulation 完全等价真实集群。

---

# 19. 报告生成

`report.html` 至少包括：

```text
1. System manifest
2. Resolved config
3. Main summary table
4. Scaling plot: worker_count vs prover time
5. Scaling plot: worker_count vs memory
6. Communication matrix heatmap
7. Per-rank time breakdown
8. Per-phase stacked bars
9. Memory timeline
10. Perf counters table
11. Verifier time distribution
12. Framework overhead microbenchmarks
13. Warnings and unavailable features
14. Reproduction commands
```

建议同时输出 CSV，方便论文画图。

---

# 20. Adapter 编写规范

每个 adapter 必须有：

```text
README.md
config examples
phase naming table
proof serialization definition
input generation definition
expected output hash for small test
```

## 20.1 Phase 命名规范

统一：

```text
setup.*
input.*
prove.commit.*
prove.open.*
prove.sumcheck.*
prove.fri.*
prove.aggregate.*
prove.proof_assembly
verify.deserialize
verify.core
```

例如：

```rust
ctx.phase("prove.commit.local_encode", |ctx| { ... })?;
ctx.phase("prove.commit.hash", |ctx| { ... })?;
ctx.phase("prove.open.fri.fold_round_0", |ctx| { ... })?;
ctx.phase("prove.proof_assembly", |ctx| { ... })?;
```

## 20.2 线程限制

Adapter 启动时，SDK 自动检查：

```text
/proc/<pid>/task count
```

环境变量强制：

```bash
RAYON_NUM_THREADS=1
OMP_NUM_THREADS=1
OPENBLAS_NUM_THREADS=1
MKL_NUM_THREADS=1
NUMEXPR_NUM_THREADS=1
TOKIO_WORKER_THREADS=1
```

如果 task count 超出：

```text
warn or fail depending on config.check_extra_threads
```

Artifact-quality 建议 fail。

---

# 21. Build and artifact reproducibility

## 21.1 Build

```bash
cargo build --release --locked
```

保存：

```text
Cargo.lock
rustc --version
cargo --version
git commit
git diff --stat
```

## 21.2 Docker / Nix

提供 Dockerfile，但注意 Docker 内部使用 resctrl/netns/cgroup 需要 privileged。

建议：

```text
Docker for build reproducibility
native host for artifact-quality isolation experiments
```

Docker command：

```bash
docker run --privileged --network host \
  -v /sys/fs/cgroup:/sys/fs/cgroup \
  -v /sys/fs/resctrl:/sys/fs/resctrl \
  distzkbench:artifact
```

但论文 artifact 应推荐 native run。

## 21.3 Manifest

每次 run 保存：

```text
git commit
build profile
binary sha256
kernel version
CPU topology
memory
NUMA topology
governor
turbo state
THP state
cgroup state
resctrl state
network mode
tc settings
```

---

# 22. Failure handling

## 22.1 Rank failure

如果任意 rank exit nonzero：

```text
1. controller marks run failed
2. agent collects logs
3. controller kills all ranks
4. cleanup cgroups/netns/resctrl
5. run.json records failure cause
```

## 22.2 Timeout

配置：

```yaml
timeouts:
  connection_setup_sec: 30
  prove_sec: 3600
  verify_sec: 300
```

Timeout 后：

```text
kill process group
collect partial metrics
mark timeout
```

## 22.3 OOM

如果 cgroup memory.events 中：

```text
oom_kill > 0
```

报告：

```text
failure_reason = cgroup_oom
```

## 22.4 Topology violation

立即 fail，输出：

```text
src_rank
dst_rank
tag
phase
topology
```

---

# 23. Security and privacy boundary

文档中明确：

```text
DistZKBench is not part of the cryptographic protocol.
It does not alter protocol messages except framing them for transport.
It does not inspect witness data.
It does not claim malicious security.
It benchmarks honest executions unless adapter explicitly implements adversarial tests.
```

对于 transcript：

```text
If a protocol treats messages as secret, do not log payload contents.
Only log sizes, tags, ranks, and hashes.
```

默认不保存 payload。

---

# 24. Artifact evaluation 目录

建议准备：

```text
artifact/
  README.md
  INSTALL.md
  QUICKSTART.md
  REPRODUCE.md
  EXPECTED_RESULTS.md
  configs/
    toy.yaml
    ours_small.yaml
    ours_scaling.yaml
    netns_calibration.yaml
  scripts/
    run_all.sh
    run_quick.sh
    check_results.py
  expected/
    toy_summary.csv
    toy_hashes.json
```

## 24.1 Quickstart

```bash
./scripts/preflight.sh
cargo build --release --locked
dzb run artifact/configs/toy.yaml
dzb report results/toy/
```

## 24.2 Full reproduction

```bash
./artifact/scripts/run_all.sh
```

## 24.3 Expected results

不要要求 bit-exact runtime。要求：

```text
proof verifies
communication bytes match expected
memory below threshold
runtime within broad range
scaling trend matches
```

---

# 25. 推荐实现顺序：直接按 MVP-3 建，不做临时 shortcut

虽然目标是一步到 MVP-3，但工程仍应按 work packages 并行推进。

## WP1. Core config and manifest

交付：

```text
dzb-core
config parser
resolved config
manifest collector
unit parser: KiB/MiB/GiB, ms/s
```

验收：

```bash
dzb preflight --config toy.yaml
```

## WP2. Agent and Linux isolation

交付：

```text
dzb-agent
cgroup v2
cpuset
sched affinity
procfs sampler
cleanup
```

验收：

```text
rank CPU affinity correct
memory limit enforced
peak memory recorded
```

## WP3. resctrl / NUMA / perf

交付：

```text
resctrl CAT
NUMA compact/spread
perf_event_open
```

验收：

```text
strict cache mode works or fails cleanly
perf counters recorded
```

## WP4. TCP transport

交付：

```text
mio nonblocking TCP
frame format
message chunking
star/full-mesh topology builder
topology enforcement
communication counters
```

验收：

```text
large all-to-all no deadlock
comm bytes exactly match expected
```

## WP5. netns/veth/tc

交付：

```text
network namespace
bridge
veth
tc netem/tbf
topology enforcement optional
```

验收：

```text
toy throughput close to configured rate
cleanup leaves no netns/veth
```

## WP6. SDK and adapter runner

交付：

```text
dzb-sdk
phase tracing
proof publishing
adapter binary runner
deterministic RNG
```

验收：

```text
toy-pingpong adapter
toy-alltoall adapter
toy-sumcheck adapter
```

## WP7. Metrics and report

交付：

```text
events.jsonl
run.json
CSV summaries
HTML report
Chrome trace
```

验收：

```text
report shows phase tree, comm heatmap, memory timeline
```

## WP8. Remote cluster

交付：

```text
ssh-stdio agent mode
remote rank launch
remote data-plane addresses
metrics collection
```

验收：

```text
2-host toy all-to-all works
```

## WP9. Protocol adapters

交付：

```text
ours adapter
at least one baseline instrumented adapter
black-box wrapper for legacy baselines
```

验收：

```text
proof verifies
phase tracing nonempty
proof size recorded
```

## WP10. Artifact package

交付：

```text
artifact README
quickstart
full reproduction
expected results
preflight
cleanup
```

验收：

```text
fresh machine can run toy and small protocol experiments from README
```

---

# 26. 最小 toy protocols

为了验证 framework，不要一开始接复杂 PCS。先写三个 toy adapters。

## 26.1 toy-pingpong

```text
rank 0 sends X bytes to rank 1
rank 1 sends X bytes back
proof = sha256(all messages)
verifier checks hash
```

用途：

```text
TCP framing
communication bytes
proof size
verifier time
```

## 26.2 toy-alltoall

```text
each rank sends X bytes to every other rank
proof = global hash
```

用途：

```text
full-mesh deadlock
comm matrix
large message chunking
```

## 26.3 toy-star-aggregate

```text
workers send local vector hash to master
master aggregates
proof = aggregate hash
```

用途：

```text
star topology
master bottleneck
worker imbalance
```

---

# 27. 关键 pitfalls

## P1. 不要把 controller 算进 prover time

Controller 负责调度和测量。它的 CPU/memory/control traffic 必须隔离并单独报告。

## P2. 不要把 protocol master 当成 framework component

Master prover 是协议进程。所有 master aggregation/routing/proof assembly 都计入 prover cost。

## P3. 不要用 blocking TCP 实现 all-to-all 大消息

会死锁。默认使用 mio nonblocking event loop。

## P4. 不要声称无 resctrl 时隔离 LLC

没有 resctrl CAT 只能说：

```text
physical-core isolation; LLC shared
```

## P5. 不要让 Rayon 偷偷并行

必须设置：

```bash
RAYON_NUM_THREADS=1
```

并检查 `/proc/<pid>/task`。

## P6. 不要只报告 total communication

必须报告：

```text
master sent/recv
max rank sent/recv
comm matrix
per-phase bytes
```

否则看不出 master bottleneck。

## P7. 不要混淆 proof size 与 communication

Proof size 是 final canonical proof bytes。Communication 是 prover ranks 之间 data-plane bytes。两者单独报告。

## P8. 不要把 input generation 混入 prover time

除非协议明确把 input preprocessing 作为 online proving 的一部分。默认：

```text
input generation measured separately
```

## P9. 不要默默 fallback

Artifact-quality 必须 fail-fast。

---

# 28. 论文中可以直接使用的 framework 描述

```text
We implement DistZKBench, a Linux-only benchmarking framework for distributed PCS/SNARK protocols. DistZKBench separates the benchmarking controller from protocol participants. The controller launches processes, assigns resources, constructs network topologies, synchronizes phases, and collects metrics, but it never participates in the cryptographic protocol and is excluded from all prover and verifier measurements.

Each prover rank is executed as an isolated OS process with fixed CPU affinity, cgroup-based memory limits, optional NUMA binding, and optional LLC isolation via Linux resctrl. Protocol messages are sent exclusively through a measured TCP data plane. DistZKBench supports both star and full-mesh topologies, which cover the dominant communication patterns in distributed ZKP systems. In star topology, rank 0 is the protocol master and may also act as a worker; all computation, memory usage, and communication performed by rank 0 are counted as prover cost.

The framework records prover time, verifier time, proof size, per-rank peak memory, per-edge communication, and phase-level compute/communication breakdowns. It also supports network namespace and tc-based single-machine emulation, as well as SSH-based small-cluster deployment for calibration.
```

---

# 29. 最终 artifact-quality checklist

实现完成前逐项检查：

```text
[ ] Linux-only preflight
[ ] controller / agent / rank / verifier process separation
[ ] cgroup v2 memory isolation
[ ] CPU affinity and cpuset enforcement
[ ] SMT sibling avoidance
[ ] optional resctrl CAT strict LLC isolation
[ ] NUMA compact/spread placement
[ ] netns/veth/tc network emulation
[ ] SSH remote cluster mode
[ ] star topology
[ ] full-mesh topology
[ ] topology violation detection
[ ] mio nonblocking TCP transport
[ ] length-prefixed framed messages
[ ] large-message chunking
[ ] communication byte counters
[ ] per-edge communication matrix
[ ] phase tracing
[ ] proof publishing and exact proof size
[ ] verifier isolated process
[ ] verifier same thread/core budget as worker
[ ] cgroup memory peak
[ ] procfs memory sampling
[ ] optional perf counters
[ ] Chrome trace output
[ ] JSON/CSV/HTML reports
[ ] toy-pingpong
[ ] toy-alltoall
[ ] toy-star-aggregate
[ ] native SDK adapter
[ ] external black-box adapter
[ ] deterministic seeds
[ ] artifact README
[ ] full reproduction script
[ ] cleanup script
[ ] local-vs-remote calibration experiment
```

---

# 30. 推荐首个可运行命令序列

```bash
# 1. Build
cargo build --release --locked

# 2. Preflight
./target/release/dzb preflight configs/artifact/local_netns_10g.yaml

# 3. Run toy star
./target/release/dzb run configs/examples/toy_star_4.yaml

# 4. Run toy full-mesh
./target/release/dzb run configs/examples/toy_fullmesh_8.yaml

# 5. Generate report
./target/release/dzb report results/toy_fullmesh_8/

# 6. Run real protocol small
./target/release/dzb run configs/artifact/ours_small.yaml

# 7. Run scaling sweep
./target/release/dzb sweep configs/artifact/ours_scaling.yaml

# 8. Cleanup
./target/release/dzb cleanup --all
```

---

# 31. 最终工程判断

MVP-3 artifact-quality 版本的本质不是“能启动多个进程”，而是：

```text
1. 明确区分实验系统和协议系统。
2. 所有 prover ranks 真实进程隔离。
3. 所有协议通信走可测 TCP。
4. 资源预算固定且可复现。
5. 计算、通信、内存、proof size、verifier time 有统一定义。
6. 单机 emulation 可用真实小集群校准。
7. 所有结果能由 config + manifest + adapter commit 复现。
```

按上述方案实现后，这个 framework 可以作为论文中的独立 systems contribution，并且足以支撑 artifact evaluation。

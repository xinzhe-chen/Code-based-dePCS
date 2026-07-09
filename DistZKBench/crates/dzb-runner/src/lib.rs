#![allow(unsafe_code)]

use std::fs;
use std::path::Path;
use std::sync::{
    Arc,
    atomic::{AtomicBool, AtomicU64, Ordering},
};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

use dzb_core::{ResolvedConfig, TopologyKind, parse_byte_size, parse_duration_millis};
use dzb_sdk::{
    CustomMetric, PhaseEvent, ProofArtifact, ProverCtx, deterministic_bytes, deterministic_seed,
    sha256_hex,
};
use dzb_transport::{
    CommunicationCounters, Topology, UserspaceShaper, encode_frames, mio_accept, mio_bind,
    mio_connect, mio_read_message, mio_write_frames, set_nodelay,
};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RankOutput {
    pub rank: usize,
    pub fragment_hash: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RankRuntimeConfig {
    pub run_id: String,
    pub rank: usize,
    pub world_size: usize,
    pub master_rank: usize,
    pub adapter: String,
    pub topology_kind: TopologyKind,
    pub enforce_topology: bool,
    pub routed_star: bool,
    pub listen_addrs: Vec<String>,
    pub message_bytes: usize,
    pub random_seed: u64,
    pub max_frame_payload: usize,
    pub output_path: String,
    pub proof_path: Option<String>,
    pub thread_budget: usize,
    pub shaper: RankShaperConfig,
    pub memory_limit_bytes: Option<u64>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct RankShaperConfig {
    pub bandwidth_bytes_per_sec: Option<u64>,
    pub latency_ms: u64,
    #[serde(default)]
    pub edge_overrides: Vec<RankEdgeShaperConfig>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct RankEdgeShaperConfig {
    pub src: usize,
    pub dst: usize,
    pub bandwidth_bytes_per_sec: Option<u64>,
    pub latency_ms: u64,
    pub jitter_ms: u64,
    pub loss_percent: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RankRuntimeOutput {
    pub rank: usize,
    pub pid: u32,
    pub total_time_ms: f64,
    pub phases: Vec<PhaseEvent>,
    #[serde(default)]
    pub custom_metrics: Vec<CustomMetric>,
    pub communication: CommunicationCounters,
    pub sent_payload_bytes: u64,
    pub recv_payload_bytes: u64,
    pub proof_sha256: Option<String>,
    pub proof_size_bytes: usize,
    pub resident_bytes: Option<u64>,
    pub virtual_bytes: Option<u64>,
    pub memory_limit_exceeded: bool,
    pub memory_source: String,
    pub thread_budget: usize,
    pub qos_class: Option<String>,
    pub qos_applied: bool,
    pub thermal_start: String,
    pub thermal_end: String,
    pub thermal_source: String,
}

#[derive(Clone, Debug)]
pub struct ToyRunOutput {
    pub ctx: ProverCtx,
    pub verifier_ms: f64,
    pub prover_ms: f64,
}

pub fn run_toy_protocol(config: &ResolvedConfig) -> Result<ToyRunOutput, String> {
    let started = Instant::now();
    let world_size = config.original.roles.prover_ranks;
    let message_bytes = config.original.protocol.toy.message_bytes;
    let adapter = config.original.protocol.adapter.as_str();
    let topology = Topology {
        kind: config.original.topology.kind,
        world_size,
        master_rank: config.original.roles.master_rank as u32,
        enforce: config.original.topology.enforce_topology,
        routed_star: config.original.topology.worker_to_worker == "route_via_master",
    };
    let mut ctx = ProverCtx::new(world_size);
    let mut proof_parts = Vec::new();
    ctx.phase("prove.input", |ctx| {
        for rank in 0..world_size {
            let seed = deterministic_seed(
                config.original.experiment.random_seed,
                &config.run_id,
                rank,
                0,
            );
            let bytes = deterministic_bytes(seed, message_bytes);
            proof_parts.extend_from_slice(sha256_hex(&bytes).as_bytes());
            if adapter == "toy-alltoall" {
                for dst in 0..world_size {
                    if dst != rank {
                        record_message(ctx, &topology, rank, dst, &bytes)?;
                    }
                }
            } else if adapter == "toy-pingpong" {
                if world_size < 2 {
                    return Err("toy-pingpong requires at least two ranks".to_owned());
                }
                if rank == 0 {
                    record_message(ctx, &topology, 0, 1, &bytes)?;
                } else if rank == 1 {
                    record_message(ctx, &topology, 1, 0, &bytes)?;
                }
            } else {
                let master = config.original.roles.master_rank;
                if rank != master {
                    record_message(ctx, &topology, rank, master, &bytes)?;
                }
            }
        }
        Ok::<_, String>(())
    })?;
    ctx.phase("prove.proof_assembly", |ctx| {
        let proof = format!(
            "adapter={adapter};run_id={};world_size={world_size};digest={}",
            config.run_id,
            sha256_hex(&proof_parts)
        );
        ctx.publish_proof(proof.into_bytes());
        Ok::<_, String>(())
    })?;
    let proof = ctx
        .proof
        .clone()
        .ok_or_else(|| "toy protocol did not publish proof".to_owned())?;
    let verify_start = Instant::now();
    verify_toy_proof(&proof)?;
    let verifier_ms = verify_start.elapsed().as_secs_f64() * 1000.0;
    let prover_ms = started.elapsed().as_secs_f64() * 1000.0;
    Ok(ToyRunOutput {
        ctx,
        verifier_ms,
        prover_ms,
    })
}

pub fn verify_toy_proof(proof: &ProofArtifact) -> Result<(), String> {
    if proof.bytes.is_empty() {
        return Err("empty proof".to_owned());
    }
    let computed = sha256_hex(&proof.bytes);
    if computed != proof.sha256 {
        return Err("proof sha256 mismatch".to_owned());
    }
    Ok(())
}

pub fn run_rank_config_path(path: &Path) -> Result<RankRuntimeOutput, String> {
    let text =
        fs::read_to_string(path).map_err(|error| format!("read rank config failed: {error}"))?;
    let config = serde_json::from_str::<RankRuntimeConfig>(&text)
        .map_err(|error| format!("parse rank config failed: {error}"))?;
    run_rank_config(&config)
}

pub fn run_rank_config(config: &RankRuntimeConfig) -> Result<RankRuntimeOutput, String> {
    validate_rank_config(config)?;
    let qos = apply_darwin_qos_from_env();
    let thermal_start = read_thermal_state();
    let watchdog = MemoryWatchdog::start(config.memory_limit_bytes);
    let started = Instant::now();
    let topology = Topology {
        kind: config.topology_kind,
        world_size: config.world_size,
        master_rank: config.master_rank as u32,
        enforce: config.enforce_topology,
        routed_star: config.routed_star,
    };
    let mut ctx = ProverCtx::new(config.world_size);
    let listener = mio_bind(&config.listen_addrs[config.rank])
        .map_err(|error| format!("rank {} bind listener failed: {error}", config.rank))?;
    let expected_receives = expected_receives(config);
    let receiver = spawn_receiver(listener, expected_receives);
    let send_targets = send_targets(config)?;
    let shaper = UserspaceShaper {
        bandwidth_bytes_per_sec: config.shaper.bandwidth_bytes_per_sec,
        latency: Duration::from_millis(config.shaper.latency_ms),
    };
    let own_payload = deterministic_rank_payload(config, config.rank);
    ctx.phase("prove.tcp_data_plane", |ctx| {
        for dst in send_targets {
            send_payload(config, &topology, &shaper, dst, &own_payload, ctx)?;
        }
        Ok::<_, String>(())
    })?;
    let received = receiver
        .join()
        .map_err(|_| "receiver thread panicked".to_owned())??;
    let recv_payload_bytes = received
        .iter()
        .map(|message| message.payload.len() as u64)
        .sum::<u64>();
    let mut proof = None;
    if config.rank == config.master_rank {
        ctx.phase("prove.proof_assembly", |ctx| {
            let bytes = assemble_toy_proof(config);
            proof = Some(ctx.publish_proof(bytes));
            Ok::<_, String>(())
        })?;
    }
    let memory_snapshot = sample_self_memory();
    let watchdog_report = watchdog.stop();
    let resident_bytes = memory_snapshot
        .resident_bytes
        .or(watchdog_report.peak_resident_bytes);
    let virtual_bytes = memory_snapshot.virtual_bytes;
    let memory_limit_exceeded = watchdog_report.limit_exceeded
        || config
            .memory_limit_bytes
            .zip(resident_bytes)
            .is_some_and(|(limit, rss)| rss > limit);
    if memory_limit_exceeded {
        return Err(format!(
            "rank {} exceeded best-effort memory limit: rss={:?} limit={:?}",
            config.rank, resident_bytes, config.memory_limit_bytes
        ));
    }
    if let (Some(path), Some(proof)) = (&config.proof_path, &proof) {
        fs::write(path, &proof.bytes).map_err(|error| format!("write proof failed: {error}"))?;
    }
    let thermal_end = read_thermal_state();
    let output = RankRuntimeOutput {
        rank: config.rank,
        pid: std::process::id(),
        total_time_ms: started.elapsed().as_secs_f64() * 1000.0,
        phases: ctx.phases,
        custom_metrics: Vec::new(),
        sent_payload_bytes: ctx
            .communication
            .edges
            .iter()
            .filter(|edge| edge.src as usize == config.rank)
            .map(|edge| edge.serialized_payload_bytes)
            .sum(),
        communication: ctx.communication,
        recv_payload_bytes,
        proof_sha256: proof.as_ref().map(|proof| proof.sha256.clone()),
        proof_size_bytes: proof.as_ref().map_or(0, |proof| proof.bytes.len()),
        resident_bytes,
        virtual_bytes,
        memory_limit_exceeded,
        memory_source: memory_snapshot.source,
        thread_budget: config.thread_budget,
        qos_class: qos.class,
        qos_applied: qos.applied,
        thermal_start: thermal_start.state,
        thermal_end: thermal_end.state,
        thermal_source: thermal_end.source,
    };
    let text = serde_json::to_string_pretty(&output)
        .map_err(|error| format!("serialize rank output failed: {error}"))?;
    fs::write(&config.output_path, text)
        .map_err(|error| format!("write rank output failed: {error}"))?;
    Ok(output)
}

pub fn rank_runtime_config_from_resolved(
    config: &ResolvedConfig,
    rank: usize,
    listen_addrs: Vec<String>,
    output_path: String,
    proof_path: Option<String>,
) -> Result<RankRuntimeConfig, String> {
    let max_frame_payload = parse_byte_size(&config.original.network.max_frame_payload)
        .map_err(|error| error.to_string())
        .and_then(|bytes| {
            usize::try_from(bytes).map_err(|_| "network.max_frame_payload too large".to_owned())
        })?;
    Ok(RankRuntimeConfig {
        run_id: config.run_id.clone(),
        rank,
        world_size: config.original.roles.prover_ranks,
        master_rank: config.original.roles.master_rank,
        adapter: config.original.protocol.adapter.clone(),
        topology_kind: config.original.topology.kind,
        enforce_topology: config.original.topology.enforce_topology,
        routed_star: config.original.topology.worker_to_worker == "route_via_master",
        listen_addrs,
        message_bytes: config.original.protocol.toy.message_bytes,
        random_seed: config.original.experiment.random_seed,
        max_frame_payload,
        output_path,
        proof_path,
        thread_budget: config.original.resources.worker_threads,
        shaper: RankShaperConfig {
            bandwidth_bytes_per_sec: parse_shaper_bandwidth(
                &config.original.network.shaper.bandwidth,
            ),
            latency_ms: parse_duration_millis(&config.original.network.shaper.latency).unwrap_or(0),
            edge_overrides: config
                .original
                .network
                .shaper
                .edges
                .iter()
                .map(|edge| RankEdgeShaperConfig {
                    src: edge.src,
                    dst: edge.dst,
                    bandwidth_bytes_per_sec: parse_shaper_bandwidth(&edge.bandwidth),
                    latency_ms: parse_duration_millis(&edge.latency).unwrap_or(0),
                    jitter_ms: parse_duration_millis(&edge.jitter).unwrap_or(0),
                    loss_percent: edge.loss.clone(),
                })
                .collect(),
        },
        memory_limit_bytes: parse_byte_size(&config.original.memory.per_rank_limit).ok(),
    })
}

pub fn rank_output(run_id: &str, rank: usize, message_bytes: usize, seed: u64) -> RankOutput {
    let rank_seed = deterministic_seed(seed, run_id, rank, 0);
    let bytes = deterministic_bytes(rank_seed, message_bytes);
    RankOutput {
        rank,
        fragment_hash: sha256_hex(&bytes),
    }
}

fn validate_rank_config(config: &RankRuntimeConfig) -> Result<(), String> {
    if config.rank >= config.world_size {
        return Err("rank out of range".to_owned());
    }
    if config.listen_addrs.len() != config.world_size {
        return Err("listen_addrs length must equal world_size".to_owned());
    }
    if config.adapter == "toy-pingpong" && config.world_size < 2 {
        return Err("toy-pingpong requires at least two ranks".to_owned());
    }
    Ok(())
}

#[derive(Clone, Debug)]
struct ReceivedMessage {
    src: u32,
    payload: Vec<u8>,
}

fn spawn_receiver(
    mut listener: mio::net::TcpListener,
    expected_receives: usize,
) -> std::thread::JoinHandle<Result<Vec<ReceivedMessage>, String>> {
    std::thread::spawn(move || {
        let mut messages = Vec::with_capacity(expected_receives);
        for _ in 0..expected_receives {
            let mut stream = mio_accept(&mut listener, Duration::from_secs(30))?;
            let (key, payload, _) = mio_read_message(&mut stream, Duration::from_secs(30))?;
            messages.push(ReceivedMessage {
                src: key.src_rank,
                payload,
            });
        }
        messages.sort_by_key(|message| message.src);
        Ok(messages)
    })
}

fn expected_receives(config: &RankRuntimeConfig) -> usize {
    if config.adapter == "toy-alltoall" {
        config.world_size.saturating_sub(1)
    } else if config.adapter == "toy-pingpong" {
        usize::from(config.rank == 0 || config.rank == 1)
    } else if config.rank == config.master_rank {
        config.world_size.saturating_sub(1)
    } else {
        0
    }
}

fn send_targets(config: &RankRuntimeConfig) -> Result<Vec<usize>, String> {
    if config.adapter == "toy-alltoall" {
        Ok((0..config.world_size)
            .filter(|rank| *rank != config.rank)
            .collect())
    } else if config.adapter == "toy-pingpong" {
        if config.rank == 0 {
            Ok(vec![1])
        } else if config.rank == 1 {
            Ok(vec![0])
        } else {
            Ok(Vec::new())
        }
    } else if config.rank == config.master_rank {
        Ok(Vec::new())
    } else {
        Ok(vec![config.master_rank])
    }
}

fn send_payload(
    config: &RankRuntimeConfig,
    topology: &Topology,
    shaper: &UserspaceShaper,
    dst: usize,
    payload: &[u8],
    ctx: &mut ProverCtx,
) -> Result<(), String> {
    topology
        .check_send(config.rank as u32, dst as u32)
        .map_err(|error| error.to_string())?;
    let frames = encode_frames(
        1,
        config.rank as u32,
        dst as u32,
        1,
        ((config.rank as u64) << 32) | dst as u64,
        payload,
        config.max_frame_payload,
    );
    let mut stream = mio_connect(&config.listen_addrs[dst], Duration::from_secs(30))?;
    let _ = set_nodelay(&stream, true);
    mio_write_frames(&mut stream, &frames, shaper, Duration::from_secs(30))?;
    ctx.communication
        .record_message(config.rank as u32, dst as u32, payload.len(), frames.len());
    Ok(())
}

fn deterministic_rank_payload(config: &RankRuntimeConfig, rank: usize) -> Vec<u8> {
    let seed = deterministic_seed(config.random_seed, &config.run_id, rank, 0);
    deterministic_bytes(seed, config.message_bytes)
}

fn assemble_toy_proof(config: &RankRuntimeConfig) -> Vec<u8> {
    let mut proof_parts = Vec::new();
    for rank in 0..config.world_size {
        let payload = deterministic_rank_payload(config, rank);
        proof_parts.extend_from_slice(sha256_hex(&payload).as_bytes());
    }
    format!(
        "adapter={};run_id={};world_size={};digest={}",
        config.adapter,
        config.run_id,
        config.world_size,
        sha256_hex(&proof_parts)
    )
    .into_bytes()
}

fn parse_shaper_bandwidth(value: &str) -> Option<u64> {
    let trimmed = value.trim();
    if trimmed == "0" || trimmed.is_empty() {
        return None;
    }
    if let Some(raw) = trimmed.strip_suffix("gbit") {
        return raw
            .parse::<u64>()
            .ok()
            .map(|gbit| gbit.saturating_mul(1_000_000_000) / 8);
    }
    if let Some(raw) = trimmed.strip_suffix("mbit") {
        return raw
            .parse::<u64>()
            .ok()
            .map(|mbit| mbit.saturating_mul(1_000_000) / 8);
    }
    trimmed.parse::<u64>().ok()
}

#[derive(Clone, Debug)]
struct MemorySnapshot {
    resident_bytes: Option<u64>,
    virtual_bytes: Option<u64>,
    source: String,
}

#[derive(Clone, Debug)]
struct WatchdogReport {
    peak_resident_bytes: Option<u64>,
    limit_exceeded: bool,
}

struct MemoryWatchdog {
    stop: Arc<AtomicBool>,
    exceeded: Arc<AtomicBool>,
    peak: Arc<AtomicU64>,
    handle: Option<std::thread::JoinHandle<()>>,
}

impl MemoryWatchdog {
    fn start(limit: Option<u64>) -> Self {
        let stop = Arc::new(AtomicBool::new(false));
        let exceeded = Arc::new(AtomicBool::new(false));
        let peak = Arc::new(AtomicU64::new(0));
        let handle = limit.map(|limit| {
            let stop_ref = Arc::clone(&stop);
            let exceeded_ref = Arc::clone(&exceeded);
            let peak_ref = Arc::clone(&peak);
            std::thread::spawn(move || {
                while !stop_ref.load(Ordering::Relaxed) {
                    if let Some(rss) = sample_self_memory().resident_bytes {
                        peak_ref.fetch_max(rss, Ordering::Relaxed);
                        if rss > limit {
                            exceeded_ref.store(true, Ordering::Relaxed);
                        }
                    }
                    std::thread::sleep(Duration::from_millis(5));
                }
            })
        });
        Self {
            stop,
            exceeded,
            peak,
            handle,
        }
    }

    fn stop(mut self) -> WatchdogReport {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
        let peak = self.peak.load(Ordering::Relaxed);
        WatchdogReport {
            peak_resident_bytes: (peak > 0).then_some(peak),
            limit_exceeded: self.exceeded.load(Ordering::Relaxed),
        }
    }
}

#[derive(Clone, Debug)]
struct QosResult {
    class: Option<String>,
    applied: bool,
}

#[derive(Clone, Debug)]
struct ThermalState {
    state: String,
    source: String,
}

fn apply_darwin_qos_from_env() -> QosResult {
    let class = std::env::var("DZB_DARWIN_QOS").ok();
    #[cfg(target_os = "macos")]
    {
        let requested = class.as_deref().unwrap_or("user_initiated");
        let Some(value) = darwin_qos_value(requested) else {
            return QosResult {
                class,
                applied: false,
            };
        };
        let rc = unsafe { pthread_set_qos_class_self_np(value, 0) };
        QosResult {
            class: Some(requested.to_owned()),
            applied: rc == 0,
        }
    }
    #[cfg(not(target_os = "macos"))]
    {
        QosResult {
            class,
            applied: false,
        }
    }
}

#[cfg(target_os = "macos")]
fn darwin_qos_value(value: &str) -> Option<u32> {
    match value {
        "user_interactive" => Some(0x21),
        "user_initiated" => Some(0x19),
        "utility" => Some(0x11),
        "background" => Some(0x09),
        _ => None,
    }
}

#[cfg(target_os = "macos")]
unsafe extern "C" {
    fn pthread_set_qos_class_self_np(qos_class: u32, relative_priority: i32) -> i32;
}

fn sample_self_memory() -> MemorySnapshot {
    #[cfg(target_os = "linux")]
    {
        let text = fs::read_to_string("/proc/self/status").ok();
        let rss = text.as_deref().and_then(|text| {
            text.lines()
                .find_map(|line| line.strip_prefix("VmRSS:"))
                .and_then(|value| value.split_whitespace().next())
                .and_then(|value| value.parse::<u64>().ok())
                .map(|kib| kib * 1024)
        });
        let vms = text.as_deref().and_then(|text| {
            text.lines()
                .find_map(|line| line.strip_prefix("VmSize:"))
                .and_then(|value| value.split_whitespace().next())
                .and_then(|value| value.parse::<u64>().ok())
                .map(|kib| kib * 1024)
        });
        return MemorySnapshot {
            resident_bytes: rss,
            virtual_bytes: vms,
            source: "procfs_self_status".to_owned(),
        };
    }
    #[cfg(target_os = "macos")]
    {
        if let Some(snapshot) = sample_self_memory_mach() {
            return snapshot;
        }
        let output = std::process::Command::new("ps")
            .args(["-o", "rss=", "-p"])
            .arg(std::process::id().to_string())
            .output()
            .ok();
        let rss = output.and_then(|output| {
            if !output.status.success() {
                return None;
            }
            String::from_utf8(output.stdout)
                .ok()
                .and_then(|text| {
                    text.split_whitespace()
                        .next()
                        .and_then(|v| v.parse::<u64>().ok())
                })
                .map(|kib| kib * 1024)
        });
        return MemorySnapshot {
            resident_bytes: rss,
            virtual_bytes: None,
            source: "ps_rss_fallback".to_owned(),
        };
    }
    #[allow(unreachable_code)]
    MemorySnapshot {
        resident_bytes: None,
        virtual_bytes: None,
        source: "unavailable".to_owned(),
    }
}

#[cfg(target_os = "macos")]
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
struct TimeValue {
    seconds: i32,
    microseconds: i32,
}

#[cfg(target_os = "macos")]
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
struct MachTaskBasicInfo {
    virtual_size: u64,
    resident_size: u64,
    resident_size_max: u64,
    user_time: TimeValue,
    system_time: TimeValue,
    policy: i32,
    suspend_count: i32,
}

#[cfg(target_os = "macos")]
unsafe extern "C" {
    fn mach_task_self() -> u32;
    fn task_info(
        target_task: u32,
        flavor: i32,
        task_info_out: *mut i32,
        task_info_out_count: *mut u32,
    ) -> i32;
}

#[cfg(target_os = "macos")]
fn sample_self_memory_mach() -> Option<MemorySnapshot> {
    const MACH_TASK_BASIC_INFO: i32 = 20;
    let mut info = MachTaskBasicInfo::default();
    let mut count = (std::mem::size_of::<MachTaskBasicInfo>() / std::mem::size_of::<i32>()) as u32;
    let rc = unsafe {
        task_info(
            mach_task_self(),
            MACH_TASK_BASIC_INFO,
            (&mut info as *mut MachTaskBasicInfo).cast::<i32>(),
            &mut count,
        )
    };
    (rc == 0).then_some(MemorySnapshot {
        resident_bytes: Some(info.resident_size),
        virtual_bytes: Some(info.virtual_size),
        source: "mach_task_info".to_owned(),
    })
}

fn read_thermal_state() -> ThermalState {
    #[cfg(target_os = "macos")]
    {
        let output = std::process::Command::new("pmset")
            .args(["-g", "therm"])
            .output();
        if let Ok(output) = output
            && output.status.success()
            && let Ok(text) = String::from_utf8(output.stdout)
        {
            let state = text
                .lines()
                .map(str::trim)
                .filter(|line| !line.is_empty())
                .collect::<Vec<_>>()
                .join("; ");
            return ThermalState {
                state: if state.is_empty() {
                    "unknown".to_owned()
                } else {
                    state
                },
                source: "pmset_g_therm".to_owned(),
            };
        }
        ThermalState {
            state: "unknown".to_owned(),
            source: "pmset_g_therm_unavailable".to_owned(),
        }
    }
    #[cfg(not(target_os = "macos"))]
    {
        ThermalState {
            state: "not_applicable".to_owned(),
            source: "non_darwin".to_owned(),
        }
    }
}

fn record_message(
    ctx: &mut ProverCtx,
    topology: &Topology,
    src: usize,
    dst: usize,
    payload: &[u8],
) -> Result<(), String> {
    topology
        .check_send(src as u32, dst as u32)
        .map_err(|error| error.to_string())?;
    let frames = encode_frames(1, src as u32, dst as u32, 1, 1, payload, 16 * 1024 * 1024);
    ctx.communication
        .record_message(src as u32, dst as u32, payload.len(), frames.len());
    Ok(())
}

pub fn adapter_requires_topology(adapter: &str) -> TopologyKind {
    if adapter == "toy-alltoall" {
        TopologyKind::FullMesh
    } else {
        TopologyKind::Star
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use dzb_core::{
        CapabilityReport, FeatureAvailability, MemoryControl, NetworkEmulation, PerfCounters,
        PlatformBackendName, ResourceControl,
    };
    use dzb_core::{Config, IsolationTier, Platform, PlatformConfig, resolve_config};

    fn capability() -> CapabilityReport {
        CapabilityReport {
            platform: Platform::Darwin,
            architecture: "test".to_owned(),
            isolation_tier: IsolationTier::BestEffort,
            resource_control: ResourceControl {
                process_per_rank: FeatureAvailability::strict("process"),
                hard_cpu_affinity: FeatureAvailability::unsupported("none"),
                fixed_thread_budget: FeatureAvailability::strict("threads"),
                cache_isolation: FeatureAvailability::unsupported("none"),
                numa_binding: FeatureAvailability::unsupported("none"),
            },
            memory_control: MemoryControl {
                hard_limit: FeatureAvailability::unsupported("none"),
                peak_measurement: FeatureAvailability::best_effort("sample"),
                enforcement: "watchdog".to_owned(),
            },
            network_emulation: NetworkEmulation {
                tcp_data_plane: FeatureAvailability::strict("tcp"),
                loopback: FeatureAvailability::strict("loopback"),
                netns_or_equivalent: FeatureAvailability::unsupported("none"),
                kernel_shaper: FeatureAvailability::unsupported("none"),
                userspace_shaper: FeatureAvailability::best_effort("shape"),
            },
            perf_counters: PerfCounters {
                linux_perf_equivalent: FeatureAvailability::unsupported("none"),
                supplemental: FeatureAvailability::unsupported("none"),
            },
            thermal_monitoring: FeatureAvailability::best_effort("thermal"),
            unsupported_features: vec![],
            notes: vec![],
        }
    }

    #[test]
    fn toy_star_counts_worker_to_master_bytes() {
        let mut config = Config {
            platform: PlatformConfig {
                backend: PlatformBackendName::Darwin,
            },
            ..Config::default()
        };
        config.roles.prover_ranks = 3;
        config.protocol.toy.message_bytes = 10;
        let resolved =
            resolve_config(config, capability()).unwrap_or_else(|error| panic!("{error}"));
        let output = run_toy_protocol(&resolved).unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(output.ctx.communication.total_payload_bytes(), 20);
        assert!(output.ctx.proof.is_some());
    }
}

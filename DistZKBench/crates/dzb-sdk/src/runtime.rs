use std::collections::{BTreeMap, VecDeque};
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

use dzb_core::{TopologyKind, parse_byte_size, parse_duration_millis};
use dzb_transport::{CommunicationCounters, Topology, UserspaceShaper, encode_frames};

use crate::persistent::{NetworkStats, PersistentPeers};
use crate::{PhaseEvent, ProofArtifact, deterministic_bytes, deterministic_seed, sha256_hex};

pub type Result<T> = std::result::Result<T, String>;
pub type RankId = u32;
pub type MsgTag = u32;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DzbRankConfig {
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
    pub statement_path: Option<String>,
    #[serde(default)]
    pub protocol_parameters: serde_json::Value,
    pub thread_budget: usize,
    pub shaper: SdkShaperConfig,
    pub memory_limit_bytes: Option<u64>,
    #[serde(default = "default_connection_timeout_sec")]
    pub connection_timeout_sec: u64,
}

const fn default_connection_timeout_sec() -> u64 {
    30
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct SdkShaperConfig {
    pub bandwidth_bytes_per_sec: Option<u64>,
    pub latency_ms: u64,
    #[serde(default)]
    pub edge_overrides: Vec<SdkEdgeShaperConfig>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct SdkEdgeShaperConfig {
    pub src: usize,
    pub dst: usize,
    pub bandwidth_bytes_per_sec: Option<u64>,
    pub latency_ms: u64,
    pub jitter_ms: u64,
    pub loss_percent: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CustomMetric {
    pub name: String,
    pub value: u64,
    pub kind: String,
}

#[derive(Clone, Debug)]
pub struct RuntimeContext {
    config: DzbRankConfig,
    started: Instant,
}

impl RuntimeContext {
    pub fn run_id(&self) -> &str {
        &self.config.run_id
    }

    pub fn rank(&self) -> usize {
        self.config.rank
    }

    pub fn rank_id(&self) -> RankId {
        self.config.rank as RankId
    }

    pub fn world_size(&self) -> usize {
        self.config.world_size
    }

    pub fn master_rank(&self) -> usize {
        self.config.master_rank
    }

    pub fn adapter(&self) -> &str {
        &self.config.adapter
    }

    pub fn protocol_parameters(&self) -> &serde_json::Value {
        &self.config.protocol_parameters
    }

    pub fn thread_budget(&self) -> usize {
        self.config.thread_budget
    }

    pub fn config(&self) -> &DzbRankConfig {
        &self.config
    }

    pub fn deterministic_bytes(&self, domain: u64, len: usize) -> Vec<u8> {
        deterministic_bytes(
            deterministic_seed(
                self.config.random_seed,
                &self.config.run_id,
                self.config.rank,
                domain as usize,
            ),
            len,
        )
    }

    fn elapsed_ms(&self) -> f64 {
        self.started.elapsed().as_secs_f64() * 1000.0
    }
}

#[derive(Clone, Debug)]
pub struct Metrics {
    rank: usize,
    started: Instant,
    phase_stack: Vec<(String, String, u32, Instant)>,
    phases: Vec<PhaseEvent>,
    metrics: Vec<CustomMetric>,
    next_phase_id: u32,
}

impl Metrics {
    fn new(started: Instant, rank: usize) -> Self {
        Self {
            rank,
            started,
            phase_stack: Vec::new(),
            phases: Vec::new(),
            metrics: Vec::new(),
            next_phase_id: 1,
        }
    }

    pub fn start_phase(&mut self, name: impl Into<String>) -> u32 {
        self.start_phase_category(name, "protocol")
    }

    pub fn start_phase_category(
        &mut self,
        name: impl Into<String>,
        category: impl Into<String>,
    ) -> u32 {
        let id = self.next_phase_id;
        self.next_phase_id = self.next_phase_id.saturating_add(1);
        self.phase_stack
            .push((name.into(), category.into(), id, Instant::now()));
        id
    }

    pub fn end_phase(&mut self) -> Result<()> {
        let Some((name, category, id, start)) = self.phase_stack.pop() else {
            return Err("no active DistZKBench phase".to_owned());
        };
        self.phases.push(PhaseEvent {
            rank: self.rank,
            phase_id: id,
            parent_phase_id: self.phase_stack.last().map(|(_, _, parent, _)| *parent),
            category,
            iteration: 0,
            start_ns: start.duration_since(self.started).as_nanos() as u64,
            duration_ns: start.elapsed().as_nanos() as u64,
            name,
            start_ms: start.duration_since(self.started).as_secs_f64() * 1000.0,
            duration_ms: start.elapsed().as_secs_f64() * 1000.0,
        });
        Ok(())
    }

    pub fn current_phase_id(&self) -> u32 {
        self.phase_stack.last().map_or(0, |(_, _, id, _)| *id)
    }

    pub fn counter(&mut self, name: impl Into<String>, value: u64) {
        self.metrics.push(CustomMetric {
            name: name.into(),
            value,
            kind: "counter".to_owned(),
        });
    }

    pub fn gauge(&mut self, name: impl Into<String>, value: u64) {
        self.metrics.push(CustomMetric {
            name: name.into(),
            value,
            kind: "gauge".to_owned(),
        });
    }

    pub fn event(&mut self, name: impl Into<String>) {
        self.metrics.push(CustomMetric {
            name: name.into(),
            value: 1,
            kind: "event".to_owned(),
        });
    }

    pub fn phases(&self) -> &[PhaseEvent] {
        &self.phases
    }

    pub fn custom_metrics(&self) -> &[CustomMetric] {
        &self.metrics
    }
}

pub struct Network {
    config: DzbRankConfig,
    topology: Topology,
    peers: PersistentPeers,
    counters: CommunicationCounters,
    shaper: UserspaceShaper,
    next_message_id: BTreeMap<RankId, u64>,
    inbox: BTreeMap<(RankId, MsgTag), VecDeque<Vec<u8>>>,
    barrier_generation: u32,
}

impl Network {
    fn new(config: &DzbRankConfig) -> Result<Self> {
        if config.listen_addrs.len() != config.world_size {
            return Err("listen_addrs length must equal world_size".to_owned());
        }
        let peers = PersistentPeers::connect(
            &config.run_id,
            config.rank as RankId,
            config.world_size,
            config.master_rank as RankId,
            config.topology_kind,
            &config.listen_addrs,
            Duration::from_secs(config.connection_timeout_sec),
        )?;
        let mut network = Self {
            config: config.clone(),
            topology: Topology {
                kind: config.topology_kind,
                world_size: config.world_size,
                master_rank: config.master_rank as u32,
                enforce: config.enforce_topology,
                routed_star: config.routed_star,
            },
            peers,
            counters: CommunicationCounters::new(config.world_size),
            shaper: UserspaceShaper {
                bandwidth_bytes_per_sec: config.shaper.bandwidth_bytes_per_sec,
                latency: Duration::from_millis(config.shaper.latency_ms),
            },
            next_message_id: BTreeMap::new(),
            inbox: BTreeMap::new(),
            barrier_generation: 0,
        };
        network.barrier("connection-ready")?;
        network.barrier("measured-start")?;
        Ok(network)
    }

    pub fn rank(&self) -> RankId {
        self.config.rank as RankId
    }

    pub fn world_size(&self) -> usize {
        self.config.world_size
    }

    pub fn send(&mut self, to: RankId, tag: MsgTag, payload: &[u8], phase_id: u32) -> Result<()> {
        self.send_impl(to, tag, payload, phase_id, true)
    }

    fn send_impl(
        &mut self,
        to: RankId,
        tag: MsgTag,
        payload: &[u8],
        phase_id: u32,
        record: bool,
    ) -> Result<()> {
        self.topology
            .check_send(self.rank(), to)
            .map_err(|error| error.to_string())?;
        let rank = self.rank();
        let message_id = self.next_message_id.entry(to).or_insert(1);
        let current_message_id = *message_id;
        *message_id = message_id.saturating_add(1);
        let frames = encode_frames(
            &self.config.run_id,
            phase_id,
            rank,
            to,
            tag,
            current_message_id,
            payload,
            self.config.max_frame_payload,
        );
        let shaper = self.shaper_for(to);
        self.peers.send(to, &frames, &shaper, payload.len())?;
        if record {
            self.counters
                .record_message(self.rank(), to, payload.len(), frames.len());
        }
        Ok(())
    }

    pub fn recv(&mut self, from: RankId, tag: MsgTag) -> Result<Vec<u8>> {
        if let Some(payload) = self.take_inbox(from, tag) {
            return Ok(payload);
        }
        loop {
            let incoming = self.peers.recv()?;
            let key = incoming.key;
            let payload = incoming.payload;
            if key.dst_rank != self.rank() {
                return Err(format!(
                    "received message for rank {} on rank {}",
                    key.dst_rank,
                    self.rank()
                ));
            }
            if (from == u32::MAX || key.src_rank == from) && key.tag == tag {
                return Ok(payload);
            }
            self.inbox
                .entry((key.src_rank, key.tag))
                .or_default()
                .push_back(payload);
        }
    }

    fn take_inbox(&mut self, from: RankId, tag: MsgTag) -> Option<Vec<u8>> {
        if from == u32::MAX {
            let key = self
                .inbox
                .keys()
                .find(|(_, stored_tag)| *stored_tag == tag)
                .copied();
            return key.and_then(|key| self.inbox.get_mut(&key).and_then(VecDeque::pop_front));
        }
        self.inbox
            .get_mut(&(from, tag))
            .and_then(VecDeque::pop_front)
    }

    pub fn exchange(
        &mut self,
        outgoing: Vec<OutgoingMessage>,
        expected: Vec<ExpectedMessage>,
        phase_id: u32,
    ) -> Result<Vec<IncomingMessage>> {
        for message in outgoing {
            self.send(message.dst, message.tag, &message.payload, phase_id)?;
        }
        let mut incoming = Vec::with_capacity(expected.len());
        for item in expected {
            let payload = self.recv(item.src, item.tag)?;
            incoming.push(IncomingMessage {
                src: item.src,
                tag: item.tag,
                payload,
            });
        }
        Ok(incoming)
    }

    pub fn broadcast(
        &mut self,
        root: RankId,
        tag: MsgTag,
        payload: &[u8],
        phase_id: u32,
    ) -> Result<Option<Vec<u8>>> {
        if self.rank() == root {
            for dst in 0..self.world_size() as RankId {
                if dst != root {
                    self.send(dst, tag, payload, phase_id)?;
                }
            }
            Ok(None)
        } else {
            self.recv(root, tag).map(Some)
        }
    }

    pub fn gather(
        &mut self,
        root: RankId,
        tag: MsgTag,
        payload: &[u8],
        phase_id: u32,
    ) -> Result<Option<Vec<Vec<u8>>>> {
        if self.rank() == root {
            let mut values = vec![Vec::new(); self.world_size()];
            values[root as usize] = payload.to_vec();
            for src in 0..self.world_size() as RankId {
                if src != root {
                    values[src as usize] = self.recv(src, tag)?;
                }
            }
            Ok(Some(values))
        } else {
            self.send(root, tag, payload, phase_id)?;
            Ok(None)
        }
    }

    pub fn all_to_all(
        &mut self,
        tag: MsgTag,
        payloads: Vec<Vec<u8>>,
        phase_id: u32,
    ) -> Result<Vec<Vec<u8>>> {
        if payloads.len() != self.world_size() {
            return Err("all_to_all payloads length must equal world_size".to_owned());
        }
        let mut outgoing = Vec::new();
        for dst in 0..self.world_size() as RankId {
            if dst == self.rank() {
                continue;
            }
            self.topology
                .check_send(self.rank(), dst)
                .map_err(|error| error.to_string())?;
            outgoing.push(dst);
        }
        let mut values = vec![Vec::new(); self.world_size()];
        values[self.rank() as usize] = payloads[self.rank() as usize].clone();
        for dst in outgoing {
            self.send(dst, tag, &payloads[dst as usize], phase_id)?;
        }
        for src in 0..self.world_size() as RankId {
            if src != self.rank() {
                values[src as usize] = self.recv(src, tag)?;
            }
        }
        Ok(values)
    }

    pub fn barrier(&mut self, _name: &str) -> Result<()> {
        let generation = self.barrier_generation;
        self.barrier_generation = self.barrier_generation.saturating_add(1);
        let arrive_tag = 0xff00_0000_u32.saturating_add(generation.saturating_mul(2));
        let release_tag = arrive_tag.saturating_add(1);
        let root = self.config.master_rank as RankId;
        if self.rank() == root {
            for src in 0..self.world_size() as RankId {
                if src != root {
                    let marker = self.recv(src, arrive_tag)?;
                    if marker != generation.to_le_bytes() {
                        return Err("barrier generation mismatch".to_owned());
                    }
                }
            }
            for dst in 0..self.world_size() as RankId {
                if dst != root {
                    self.send_impl(dst, release_tag, &generation.to_le_bytes(), 0, false)?;
                }
            }
        } else {
            self.send_impl(root, arrive_tag, &generation.to_le_bytes(), 0, false)?;
            let marker = self.recv(root, release_tag)?;
            if marker != generation.to_le_bytes() {
                return Err("barrier release mismatch".to_owned());
            }
        }
        Ok(())
    }

    pub fn network_stats(&self) -> NetworkStats {
        self.peers.stats()
    }

    pub fn counters(&self) -> &CommunicationCounters {
        &self.counters
    }

    fn shaper_for(&self, dst: RankId) -> UserspaceShaper {
        self.config
            .shaper
            .edge_overrides
            .iter()
            .find(|edge| edge.src == self.config.rank && edge.dst == dst as usize)
            .map_or_else(
                || self.shaper.clone(),
                |edge| UserspaceShaper {
                    bandwidth_bytes_per_sec: edge.bandwidth_bytes_per_sec,
                    latency: Duration::from_millis(edge.latency_ms),
                },
            )
    }
}

#[derive(Clone, Debug)]
pub struct OutgoingMessage {
    pub dst: RankId,
    pub tag: MsgTag,
    pub payload: Vec<u8>,
}

#[derive(Clone, Debug)]
pub struct ExpectedMessage {
    pub src: RankId,
    pub tag: MsgTag,
}

#[derive(Clone, Debug)]
pub struct IncomingMessage {
    pub src: RankId,
    pub tag: MsgTag,
    pub payload: Vec<u8>,
}

#[derive(Clone, Debug)]
pub struct Artifacts {
    output_path: PathBuf,
    proof_path: Option<PathBuf>,
    statement_path: Option<PathBuf>,
    proof: Option<ProofArtifact>,
}

impl Artifacts {
    fn new(config: &DzbRankConfig) -> Self {
        Self {
            output_path: PathBuf::from(&config.output_path),
            proof_path: config.proof_path.as_ref().map(PathBuf::from),
            statement_path: config.statement_path.as_ref().map(PathBuf::from),
            proof: None,
        }
    }

    pub fn write_artifact(&self, name: impl AsRef<Path>, bytes: &[u8]) -> Result<PathBuf> {
        let base = self
            .output_path
            .parent()
            .ok_or_else(|| "rank output path has no parent directory".to_owned())?;
        let path = base.join(name);
        fs::write(&path, bytes).map_err(|error| format!("write artifact failed: {error}"))?;
        Ok(path)
    }

    pub fn publish_bytes(&mut self, bytes: Vec<u8>) -> ProofArtifact {
        let proof = ProofArtifact {
            sha256: sha256_hex(&bytes),
            bytes,
        };
        self.proof = Some(proof.clone());
        proof
    }

    pub fn publish_named_artifact(
        &mut self,
        name: impl AsRef<Path>,
        bytes: Vec<u8>,
    ) -> Result<ProofArtifact> {
        self.write_artifact(name, &bytes)?;
        Ok(self.publish_bytes(bytes))
    }

    pub fn publish_proof_bytes(&mut self, bytes: Vec<u8>) -> Result<ProofArtifact> {
        let proof = self.publish_bytes(bytes);
        if let Some(path) = &self.proof_path {
            fs::write(path, &proof.bytes)
                .map_err(|error| format!("write proof failed: {error}"))?;
        }
        Ok(proof)
    }

    pub fn publish_statement_bytes(&self, bytes: &[u8]) -> Result<()> {
        let path = self
            .statement_path
            .as_ref()
            .ok_or_else(|| "statement path is unavailable for this rank".to_owned())?;
        fs::write(path, bytes).map_err(|error| format!("write statement failed: {error}"))
    }

    pub fn proof(&self) -> Option<&ProofArtifact> {
        self.proof.as_ref()
    }
}

#[derive(Clone, Debug, Default)]
pub struct VerifierChannel;

impl VerifierChannel {
    pub fn publish_proof(
        &self,
        artifacts: &mut Artifacts,
        bytes: Vec<u8>,
    ) -> Result<ProofArtifact> {
        artifacts.publish_proof_bytes(bytes)
    }
}

pub struct Dzb {
    runtime: RuntimeContext,
    pub network: Network,
    pub metrics: Metrics,
    pub artifacts: Artifacts,
    pub verifier: VerifierChannel,
}

impl Dzb {
    pub fn context(&self) -> &RuntimeContext {
        &self.runtime
    }

    pub fn phase<T>(
        &mut self,
        name: impl Into<String>,
        f: impl FnOnce(&mut Self) -> Result<T>,
    ) -> Result<T> {
        self.metrics.start_phase(name);
        let result = f(self);
        let end_result = self.metrics.end_phase();
        match (result, end_result) {
            (Ok(value), Ok(())) => Ok(value),
            (Err(error), _) | (_, Err(error)) => Err(error),
        }
    }

    pub fn phase_category<T>(
        &mut self,
        name: impl Into<String>,
        category: impl Into<String>,
        f: impl FnOnce(&mut Self) -> Result<T>,
    ) -> Result<T> {
        self.metrics.start_phase_category(name, category);
        let result = f(self);
        let end_result = self.metrics.end_phase();
        match (result, end_result) {
            (Ok(value), Ok(())) => Ok(value),
            (Err(error), _) | (_, Err(error)) => Err(error),
        }
    }

    pub fn send(&mut self, to: RankId, tag: MsgTag, payload: &[u8]) -> Result<()> {
        let phase_id = self.metrics.current_phase_id();
        self.network.send(to, tag, payload, phase_id)
    }

    pub fn recv(&mut self, from: RankId, tag: MsgTag) -> Result<Vec<u8>> {
        self.network.recv(from, tag)
    }

    pub fn broadcast(
        &mut self,
        root: RankId,
        tag: MsgTag,
        payload: &[u8],
    ) -> Result<Option<Vec<u8>>> {
        let phase_id = self.metrics.current_phase_id();
        self.network.broadcast(root, tag, payload, phase_id)
    }

    pub fn gather(
        &mut self,
        root: RankId,
        tag: MsgTag,
        payload: &[u8],
    ) -> Result<Option<Vec<Vec<u8>>>> {
        let phase_id = self.metrics.current_phase_id();
        self.network.gather(root, tag, payload, phase_id)
    }

    pub fn all_to_all(&mut self, tag: MsgTag, payloads: Vec<Vec<u8>>) -> Result<Vec<Vec<u8>>> {
        let phase_id = self.metrics.current_phase_id();
        self.network.all_to_all(tag, payloads, phase_id)
    }

    pub fn barrier(&mut self, name: &str) -> Result<()> {
        self.network.barrier(name)
    }

    pub fn finish(mut self) -> Result<SdkRankOutput> {
        self.network.barrier("measured-end")?;
        let memory = sample_self_memory();
        let proof = self.artifacts.proof().cloned();
        let output = SdkRankOutput {
            rank: self.runtime.rank(),
            pid: std::process::id(),
            total_time_ms: self.runtime.elapsed_ms(),
            phases: self.metrics.phases().to_vec(),
            custom_metrics: self.metrics.custom_metrics().to_vec(),
            communication: self.network.counters().clone(),
            sent_payload_bytes: self
                .network
                .counters()
                .edges
                .iter()
                .filter(|edge| edge.src as usize == self.runtime.rank())
                .map(|edge| edge.serialized_payload_bytes)
                .sum(),
            recv_payload_bytes: self
                .network
                .counters()
                .edges
                .iter()
                .filter(|edge| edge.dst as usize == self.runtime.rank())
                .map(|edge| edge.serialized_payload_bytes)
                .sum(),
            proof_sha256: proof.as_ref().map(|proof| proof.sha256.clone()),
            proof_size_bytes: proof.as_ref().map_or(0, |proof| proof.bytes.len()),
            resident_bytes: memory.resident_bytes,
            virtual_bytes: memory.virtual_bytes,
            memory_limit_exceeded: false,
            memory_source: memory.source,
            thread_budget: self.runtime.thread_budget(),
            qos_class: std::env::var("DZB_DARWIN_QOS").ok(),
            qos_applied: false,
            thermal_start: "unavailable".to_owned(),
            thermal_end: "unavailable".to_owned(),
            thermal_source: "sdk_public_api_unavailable".to_owned(),
            network_stats: self.network.network_stats(),
        };
        let text = serde_json::to_string_pretty(&output)
            .map_err(|error| format!("serialize rank output failed: {error}"))?;
        fs::write(&self.runtime.config.output_path, text)
            .map_err(|error| format!("write rank output failed: {error}"))?;
        Ok(output)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SdkRankOutput {
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
    #[serde(default)]
    pub network_stats: NetworkStats,
}

pub fn init() -> Result<Dzb> {
    let path = std::env::var("DZB_RANK_CONFIG")
        .map_err(|_| "DZB_RANK_CONFIG is required for dzb_sdk::init".to_owned())?;
    init_from_config_path(Path::new(&path))
}

pub fn init_from_config_path(path: &Path) -> Result<Dzb> {
    let text =
        fs::read_to_string(path).map_err(|error| format!("read rank config failed: {error}"))?;
    let config = serde_json::from_str::<DzbRankConfig>(&text)
        .map_err(|error| format!("parse rank config failed: {error}"))?;
    init_from_config(config)
}

pub fn init_from_config(config: DzbRankConfig) -> Result<Dzb> {
    let started = Instant::now();
    Ok(Dzb {
        network: Network::new(&config)?,
        metrics: Metrics::new(started, config.rank),
        artifacts: Artifacts::new(&config),
        runtime: RuntimeContext { config, started },
        verifier: VerifierChannel,
    })
}

pub fn parse_shaper_bandwidth(value: &str) -> Option<u64> {
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

pub fn shaper_from_strings(bandwidth: &str, latency: &str) -> SdkShaperConfig {
    SdkShaperConfig {
        bandwidth_bytes_per_sec: parse_shaper_bandwidth(bandwidth),
        latency_ms: parse_duration_millis(latency).unwrap_or(0),
        edge_overrides: Vec::new(),
    }
}

#[derive(Clone, Debug)]
struct MemorySnapshot {
    resident_bytes: Option<u64>,
    virtual_bytes: Option<u64>,
    source: String,
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
        MemorySnapshot {
            resident_bytes: rss,
            virtual_bytes: vms,
            source: "procfs_self_status".to_owned(),
        }
    }
    #[cfg(target_os = "macos")]
    {
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
        MemorySnapshot {
            resident_bytes: rss,
            virtual_bytes: None,
            source: "ps_rss_fallback".to_owned(),
        }
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        MemorySnapshot {
            resident_bytes: None,
            virtual_bytes: None,
            source: "unavailable".to_owned(),
        }
    }
}

pub fn parse_byte_limit(value: &str) -> Option<u64> {
    parse_byte_size(value).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_config(rank: usize, base_port: u16) -> DzbRankConfig {
        DzbRankConfig {
            run_id: "test-run".to_owned(),
            rank,
            world_size: 2,
            master_rank: 0,
            adapter: "test".to_owned(),
            topology_kind: TopologyKind::FullMesh,
            enforce_topology: true,
            routed_star: false,
            listen_addrs: vec![
                format!("127.0.0.1:{base_port}"),
                format!("127.0.0.1:{}", base_port + 1),
            ],
            message_bytes: 8,
            random_seed: 1,
            max_frame_payload: 4,
            output_path: format!("/tmp/dzb-sdk-test-rank-{rank}.json"),
            proof_path: None,
            statement_path: None,
            protocol_parameters: serde_json::json!({}),
            thread_budget: 1,
            shaper: SdkShaperConfig::default(),
            memory_limit_bytes: None,
            connection_timeout_sec: 30,
        }
    }

    #[test]
    fn sdk_pingpong_over_tcp() {
        let base = 41000 + (std::process::id() % 1000) as u16;
        let left = std::thread::spawn(move || {
            let mut dzb = init_from_config(test_config(0, base)).expect("rank 0 sdk init");
            dzb.phase("send", |dzb| dzb.send(1, 7, b"hello"))
                .expect("rank 0 send");
            let got = dzb.recv(1, 8).expect("rank 0 recv");
            assert_eq!(got, b"world");
            dzb.finish().expect("rank 0 finish")
        });
        std::thread::sleep(Duration::from_millis(50));
        let right = std::thread::spawn(move || {
            let mut dzb = init_from_config(test_config(1, base)).expect("rank 1 sdk init");
            let got = dzb.recv(0, 7).expect("rank 1 recv");
            assert_eq!(got, b"hello");
            dzb.phase("send", |dzb| dzb.send(0, 8, b"world"))
                .expect("rank 1 send");
            dzb.finish().expect("rank 1 finish")
        });
        let left = left.join().expect("rank 0 thread");
        let right = right.join().expect("rank 1 thread");
        assert_eq!(left.communication.total_payload_bytes(), 5);
        assert_eq!(right.communication.total_payload_bytes(), 5);
        assert_eq!(left.network_stats.peers.len(), 1);
        assert_eq!(right.network_stats.peers.len(), 1);
        assert_eq!(left.network_stats.peers[0].connections_opened, 1);
        assert_eq!(right.network_stats.peers[0].connections_opened, 1);
    }

    #[test]
    fn four_rank_persistent_all_to_all_reuses_one_peer_connection() {
        const RANKS: usize = 4;
        const EDGE_BYTES: usize = 1024 * 1024;
        let base = 43000 + (std::process::id() % 1000) as u16;
        let addrs = (0..RANKS)
            .map(|rank| format!("127.0.0.1:{}", base + rank as u16))
            .collect::<Vec<_>>();
        let handles = (0..RANKS)
            .map(|rank| {
                let mut config = test_config(rank, base);
                config.world_size = RANKS;
                config.listen_addrs = addrs.clone();
                std::thread::spawn(move || {
                    let mut dzb = init_from_config(config).expect("persistent sdk init");
                    let payloads = (0..RANKS)
                        .map(|dst| vec![(rank ^ dst) as u8; EDGE_BYTES])
                        .collect::<Vec<_>>();
                    let received = dzb.all_to_all(91, payloads).expect("all-to-all");
                    assert!(received.iter().all(|payload| payload.len() == EDGE_BYTES));
                    dzb.finish().expect("finish")
                })
            })
            .collect::<Vec<_>>();
        let outputs = handles
            .into_iter()
            .map(|handle| handle.join().expect("rank thread"))
            .collect::<Vec<_>>();
        assert!(outputs.iter().all(|output| {
            output.network_stats.peers.len() == RANKS - 1
                && output
                    .network_stats
                    .peers
                    .iter()
                    .all(|peer| peer.connections_opened == 1)
        }));
        assert_eq!(
            outputs
                .iter()
                .map(|output| output.communication.total_payload_bytes())
                .sum::<u64>(),
            (RANKS * (RANKS - 1) * EDGE_BYTES) as u64
        );
    }

    #[test]
    #[ignore = "3 GiB TCP stress test; run explicitly on the Linux acceptance host"]
    fn four_rank_256_mib_all_to_all_has_exact_accounting() {
        const RANKS: usize = 4;
        const EDGE_BYTES: usize = 256 * 1024 * 1024;
        const FRAME_BYTES: usize = 1024 * 1024;
        let base = 42000 + (std::process::id() % 1000) as u16;
        let addrs = (0..RANKS)
            .map(|rank| format!("127.0.0.1:{}", base + rank as u16))
            .collect::<Vec<_>>();
        let mut handles = Vec::new();
        for rank in 0..RANKS {
            let mut config = test_config(rank, base);
            config.world_size = RANKS;
            config.topology_kind = TopologyKind::FullMesh;
            config.listen_addrs = addrs.clone();
            config.max_frame_payload = FRAME_BYTES;
            handles.push(std::thread::spawn(move || {
                let mut dzb = init_from_config(config).expect("stress rank sdk init");
                let payloads = (0..RANKS)
                    .map(|dst| vec![(rank ^ dst) as u8; EDGE_BYTES])
                    .collect::<Vec<_>>();
                let received = dzb.all_to_all(77, payloads).expect("all-to-all");
                for (src, payload) in received.iter().enumerate() {
                    assert_eq!(payload.len(), EDGE_BYTES);
                    assert!(payload.iter().all(|byte| *byte == (rank ^ src) as u8));
                }
                dzb.finish().expect("stress rank finish")
            }));
        }
        let outputs = handles
            .into_iter()
            .map(|handle| handle.join().expect("stress rank thread"))
            .collect::<Vec<_>>();
        let logical = outputs
            .iter()
            .map(|output| output.communication.total_payload_bytes())
            .sum::<u64>();
        let messages = outputs
            .iter()
            .map(|output| output.communication.message_count())
            .sum::<u64>();
        assert_eq!(logical, (RANKS * (RANKS - 1) * EDGE_BYTES) as u64);
        assert_eq!(messages, (RANKS * (RANKS - 1)) as u64);
        assert!(outputs.iter().all(|output| {
            output.network_stats.peers.len() == RANKS - 1
                && output
                    .network_stats
                    .peers
                    .iter()
                    .all(|peer| peer.connections_opened == 1)
        }));
    }
}

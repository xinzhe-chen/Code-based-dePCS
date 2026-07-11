use std::env;
use std::fs::{self, File};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};
use std::time::{Duration, Instant, SystemTime};

use dzb_core::{
    Config, Platform, PlatformBackendName, TopologyKind, expand_sweep, load_config, resolve_config,
    write_json_pretty,
};
use dzb_metrics::{ExperimentOutput, write_outputs};
use dzb_platform::{PlatformBackend, standard_thread_budget_env};
use dzb_platform_darwin::DarwinBackend;
use dzb_platform_linux::LinuxBackend;
use dzb_runner::{RankRuntimeOutput, rank_runtime_config_from_resolved};
use dzb_sdk::{ProofArtifact, sha256_hex};
use dzb_transport::CommunicationCounters;
use serde::{Deserialize, Serialize};

mod ui;

fn main() {
    if let Err(error) = run() {
        eprintln!("{error}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), String> {
    let args = env::args().skip(1).collect::<Vec<_>>();
    match args.first().map(String::as_str) {
        Some("preflight") => cmd_preflight(&args[1..]),
        Some("run") => cmd_run(&args[1..]),
        Some("sweep") => cmd_sweep(&args[1..]),
        Some("report") => cmd_report(&args[1..]),
        Some("cleanup") => cmd_cleanup(&args[1..]),
        Some("ui") => ui::cmd_ui(&args[1..]),
        Some("interactive") | Some("wizard") => cmd_interactive(&args[1..]),
        Some(other) => Err(format!("unknown dzb command '{other}'")),
        None => Err(usage()),
    }
}

fn cmd_interactive(args: &[String]) -> Result<(), String> {
    if args.iter().any(|arg| arg == "--help" || arg == "-h") {
        println!("{}", interactive_usage());
        return Ok(());
    }
    println!("DistZKBench interactive");
    println!("1) Run local toy self-check now");
    println!("2) Generate a protocol adapter config");
    println!("3) Open latest report");
    let choice = prompt("Select action", "1")?;
    match choice.trim() {
        "1" => interactive_toy_self_check(),
        "2" => interactive_adapter_config(),
        "3" => interactive_open_latest_report(),
        other => Err(format!("unknown interactive choice '{other}'")),
    }
}

fn interactive_toy_self_check() -> Result<(), String> {
    let shape = prompt("Toy shape [star/full-mesh/pingpong]", "star")?;
    let ranks_default = if shape.trim() == "pingpong" { "2" } else { "4" };
    let ranks = prompt_usize("Prover ranks", ranks_default)?;
    let message_bytes = prompt_usize("Message bytes per sender", "1024")?;
    let output_dir = prompt("Output directory", "results")?;
    let run_now = prompt("Run after writing config? [yes/no]", "yes")?;
    let mut config = Config::default();
    let shape = shape.trim();
    config.experiment.name = format!("interactive_toy_{}", slugify(shape));
    config.experiment.run_id = "auto".to_owned();
    config.experiment.output_dir = output_dir;
    config.roles.prover_ranks = ranks;
    config.roles.master_rank = 0;
    config.resources.worker_threads = 1;
    config.resources.verifier_threads = "same_as_worker".to_owned();
    config.memory.per_rank_limit = "1GiB".to_owned();
    config.cache.mode = "none".to_owned();
    config.network.mode = "loopback".to_owned();
    config.network.base_port = 39000;
    config.protocol.mode = "sdk-binary".to_owned();
    config.protocol.toy.message_bytes = message_bytes;
    match shape {
        "full-mesh" | "fullmesh" | "alltoall" => {
            config.topology.kind = TopologyKind::FullMesh;
            config.protocol.adapter = "toy-alltoall".to_owned();
        }
        "pingpong" | "ping-pong" => {
            config.topology.kind = TopologyKind::FullMesh;
            config.roles.prover_ranks = ranks.max(2);
            config.protocol.adapter = "toy-pingpong".to_owned();
        }
        "star" | "" => {
            config.topology.kind = TopologyKind::Star;
            config.topology.worker_to_worker = "forbidden".to_owned();
            config.protocol.adapter = "toy-star-aggregate".to_owned();
        }
        other => return Err(format!("unknown toy shape '{other}'")),
    }
    let path = write_generated_config(&config, &config.experiment.name)?;
    println!("Wrote {}", path.display());
    if is_yes(&run_now) {
        println!("Running preflight...");
        cmd_preflight(&["--config".to_owned(), path.to_string_lossy().into_owned()])?;
        println!("Running toy self-check...");
        cmd_run(&[path.to_string_lossy().into_owned()])?;
    } else {
        println!("Next: ./target/release/dzb run {}", path.display());
    }
    Ok(())
}

fn interactive_adapter_config() -> Result<(), String> {
    let name = prompt("Experiment name", "my_protocol_smoke")?;
    let adapter = prompt("Adapter name or binary path", "my-adapter")?;
    let mode = prompt("Adapter mode [sdk-binary/black-box]", "sdk-binary")?;
    let topology = prompt("Topology [star/full-mesh]", "star")?;
    let ranks = prompt_usize("Prover ranks", "4")?;
    let worker_threads = prompt_usize("Worker threads per rank", "1")?;
    let memory_limit = prompt("Memory limit per rank", "8GiB")?;
    let output_dir = prompt("Output directory", "results")?;
    let mut config = Config::default();
    config.experiment.name = slugify(&name);
    config.experiment.run_id = "auto".to_owned();
    config.experiment.output_dir = output_dir;
    config.roles.prover_ranks = ranks;
    config.roles.master_rank = 0;
    config.resources.worker_threads = worker_threads;
    config.resources.verifier_threads = "same_as_worker".to_owned();
    config.memory.per_rank_limit = memory_limit;
    config.cache.mode = "none".to_owned();
    config.network.mode = "loopback".to_owned();
    config.network.base_port = 39000;
    config.protocol.adapter = adapter.clone();
    config.protocol.mode = mode.clone();
    config.protocol.command = adapter;
    match topology.trim() {
        "full-mesh" | "fullmesh" => config.topology.kind = TopologyKind::FullMesh,
        "star" | "" => {
            config.topology.kind = TopologyKind::Star;
            config.topology.worker_to_worker = "forbidden".to_owned();
        }
        other => return Err(format!("unknown topology '{other}'")),
    }
    let path = write_generated_config(&config, &config.experiment.name)?;
    println!("Wrote {}", path.display());
    println!("Next commands:");
    println!(
        "  ./target/release/dzb preflight --config {}",
        path.display()
    );
    println!("  ./target/release/dzb run {}", path.display());
    if mode == "sdk-binary" {
        println!(
            "Note: sdk-binary is the artifact-quality path; wire protocol messages through the DistZKBench SDK transport before using this for final communication metrics."
        );
    } else {
        println!(
            "Note: black-box mode can smoke-test legacy binaries, but reports communication_precision=unavailable."
        );
    }
    Ok(())
}

fn interactive_open_latest_report() -> Result<(), String> {
    let mut reports = Vec::new();
    collect_reports(Path::new("results"), &mut reports)?;
    let Some((_, path)) = reports.into_iter().max_by_key(|(modified, _)| *modified) else {
        return Err("no report.html found under results/. Run a toy self-check first.".to_owned());
    };
    println!("Opening {}", path.display());
    open_path(&path)
}

fn collect_reports(dir: &Path, reports: &mut Vec<(SystemTime, PathBuf)>) -> Result<(), String> {
    if !dir.exists() {
        return Ok(());
    }
    for entry in
        fs::read_dir(dir).map_err(|error| format!("read {} failed: {error}", dir.display()))?
    {
        let entry = entry.map_err(|error| format!("read dir entry failed: {error}"))?;
        let path = entry.path();
        let file_type = entry
            .file_type()
            .map_err(|error| format!("read file type failed: {error}"))?;
        if file_type.is_dir() {
            collect_reports(&path, reports)?;
        } else if file_type.is_file() && path.file_name().is_some_and(|name| name == "report.html")
        {
            let modified = entry
                .metadata()
                .and_then(|metadata| metadata.modified())
                .unwrap_or(SystemTime::UNIX_EPOCH);
            reports.push((modified, path));
        }
    }
    Ok(())
}

fn open_path(path: &Path) -> Result<(), String> {
    let opener = if cfg!(target_os = "macos") {
        "open"
    } else if cfg!(target_os = "linux") {
        "xdg-open"
    } else {
        return Err(format!(
            "automatic report opening is unsupported on this OS; open {} manually",
            path.display()
        ));
    };
    let status = Command::new(opener)
        .arg(path)
        .status()
        .map_err(|error| format!("failed to launch {opener}: {error}"))?;
    if status.success() {
        Ok(())
    } else {
        Err(format!(
            "{opener} exited with status {status}; open {} manually",
            path.display()
        ))
    }
}

fn write_generated_config(config: &Config, name: &str) -> Result<PathBuf, String> {
    let dir = PathBuf::from("configs/generated");
    fs::create_dir_all(&dir)
        .map_err(|error| format!("create configs/generated failed: {error}"))?;
    let path = dir.join(format!("{}.yaml", slugify(name)));
    let text =
        serde_yaml::to_string(config).map_err(|error| format!("serialize yaml failed: {error}"))?;
    fs::write(&path, text).map_err(|error| format!("write generated config failed: {error}"))?;
    Ok(path)
}

fn prompt(label: &str, default: &str) -> Result<String, String> {
    print!("{label} [{default}]: ");
    io::stdout()
        .flush()
        .map_err(|error| format!("flush stdout failed: {error}"))?;
    let mut line = String::new();
    io::stdin()
        .read_line(&mut line)
        .map_err(|error| format!("read stdin failed: {error}"))?;
    let trimmed = line.trim();
    if trimmed.is_empty() {
        Ok(default.to_owned())
    } else {
        Ok(trimmed.to_owned())
    }
}

fn prompt_usize(label: &str, default: &str) -> Result<usize, String> {
    let value = prompt(label, default)?;
    value
        .parse::<usize>()
        .map_err(|_| format!("invalid integer for {label}: '{value}'"))
}

fn is_yes(value: &str) -> bool {
    matches!(value.trim().to_ascii_lowercase().as_str(), "y" | "yes")
}

fn slugify(value: &str) -> String {
    let mut out = String::new();
    let mut previous_dash = false;
    for ch in value.chars() {
        if ch.is_ascii_alphanumeric() {
            out.push(ch.to_ascii_lowercase());
            previous_dash = false;
        } else if !previous_dash && !out.is_empty() {
            out.push('_');
            previous_dash = true;
        }
    }
    while out.ends_with('_') {
        out.pop();
    }
    if out.is_empty() {
        "distzkbench_experiment".to_owned()
    } else {
        out
    }
}

fn cmd_preflight(args: &[String]) -> Result<(), String> {
    let config_path = parse_config_arg(args)?;
    let config = load_config(&config_path).map_err(|error| error.to_string())?;
    let capability = capability_for_request(config.platform.backend)?;
    let resolved = resolve_config(config, capability).map_err(|error| error.to_string())?;
    println!(
        "{}",
        serde_json::to_string_pretty(&resolved.capability).map_err(|error| error.to_string())?
    );
    Ok(())
}

fn cmd_run(args: &[String]) -> Result<(), String> {
    let config_path = if args.len() == 1 {
        PathBuf::from(&args[0])
    } else {
        parse_config_arg(args)?
    };
    let config = load_config(&config_path).map_err(|error| error.to_string())?;
    let capability = capability_for_request(config.platform.backend)?;
    let mut resolved = resolve_config(config, capability).map_err(|error| error.to_string())?;
    resolved.execution_fingerprint = execution_fingerprint(&resolved)?;
    let start = Instant::now();
    let execution = (|| -> Result<ExperimentOutput, String> {
        if resolved.original.protocol.mode == "black-box" {
            return run_black_box(&resolved, start);
        }
        let mut agent = AgentClient::start(&resolved)?;
        let rank_run = spawn_rank_processes(&resolved, &mut agent)?;
        let verifier =
            if resolved.original.roles.verifier_enabled && !rank_run.proof.bytes.is_empty() {
                Some(spawn_verifier_process(
                    &resolved,
                    &rank_run.proof,
                    &mut agent,
                )?)
            } else {
                None
            };
        agent.cleanup()?;
        Ok(ExperimentOutput {
            status: if verifier
                .as_ref()
                .and_then(|value| value.report.get("verified"))
                .and_then(serde_json::Value::as_bool)
                .unwrap_or(!resolved.original.roles.verifier_enabled)
            {
                dzb_core::RunStatus::Ok
            } else {
                dzb_core::RunStatus::Failed
            },
            phases: rank_run
                .ranks
                .iter()
                .flat_map(|rank| rank.phases.iter().cloned())
                .collect(),
            proof: rank_run.proof,
            communication: rank_run.communication,
            prover_wall_controller_ms: start.elapsed().as_secs_f64() * 1000.0,
            prover_critical_path_ms: rank_run.prover_critical_path_ms,
            verifier_ms: verifier
                .as_ref()
                .map_or(0.0, |verifier| verifier.elapsed_ms),
            ranks: rank_run.ranks,
            verifier_pid: verifier.as_ref().map(|verifier| verifier.pid),
            verifier_report: verifier.map(|verifier| verifier.report).or_else(|| {
                Some(serde_json::json!({"verified": null, "mode": "not_requested_or_no_artifact"}))
            }),
            communication_precision: "exact_tcp_frame_payload".to_owned(),
            platform_evidence: platform_evidence(&resolved, None),
        })
    })();
    let output = match execution {
        Ok(output) => output,
        Err(error) => {
            persist_failed_run(&resolved, &error, start.elapsed())?;
            return Err(error);
        }
    };
    let run_json = write_outputs(&resolved, &output).map_err(|error| error.to_string())?;
    println!("{}", resolved.result_dir);
    println!(
        "run_id={} status={} proof_bytes={} protocol_bytes={}",
        run_json.run_id, run_json.status, run_json.proof_size_bytes, run_json.total_protocol_bytes
    );
    Ok(())
}

fn persist_failed_run(
    config: &dzb_core::ResolvedConfig,
    error: &str,
    elapsed: Duration,
) -> Result<(), String> {
    let result_dir = Path::new(&config.result_dir);
    fs::create_dir_all(result_dir.join("logs")).map_err(|io| io.to_string())?;
    fs::write(result_dir.join("logs/failure.log"), format!("{error}\n"))
        .map_err(|io| io.to_string())?;
    let status = if error.contains("timed out") {
        dzb_core::RunStatus::Timeout
    } else if error.to_ascii_lowercase().contains("oom")
        || error.contains("memory.max")
        || error.contains("memory limit")
    {
        dzb_core::RunStatus::Oom
    } else {
        dzb_core::RunStatus::Failed
    };
    let run = dzb_core::RunJson {
        schema_version: 2,
        run_id: config.run_id.clone(),
        experiment: config.original.experiment.name.clone(),
        platform: config.platform.as_str().to_owned(),
        isolation_tier: config.isolation_tier.as_str().to_owned(),
        status: status.as_str().to_owned(),
        prover_critical_path_ms: elapsed.as_secs_f64() * 1_000.0,
        prover_wall_controller_ms: elapsed.as_secs_f64() * 1_000.0,
        proof_size_bytes: 0,
        proof_sha256: sha256_hex(&[]),
        statement_size_bytes: 0,
        statement_sha256: None,
        total_protocol_bytes: 0,
        total_framed_bytes: 0,
        message_count: 0,
        verifier_median_ms: 0.0,
        rank_pids: Vec::new(),
        verifier_pid: None,
        communication_precision: "partial_or_unavailable".to_owned(),
        platform_evidence: serde_json::json!({"error": error}),
        best_effort_warning: None,
        config_hash: config.config_hash.clone(),
        execution_fingerprint: config.execution_fingerprint.clone(),
    };
    dzb_core::write_json_pretty(&result_dir.join("run.json"), &run).map_err(|io| io.to_string())
}

fn run_black_box(
    config: &dzb_core::ResolvedConfig,
    start: Instant,
) -> Result<ExperimentOutput, String> {
    let result_dir = Path::new(&config.result_dir);
    let logs = result_dir.join("logs");
    std::fs::create_dir_all(&logs).map_err(|error| error.to_string())?;
    let command = if config.original.protocol.command.is_empty() {
        config.original.protocol.adapter.clone()
    } else {
        config.original.protocol.command.clone()
    };
    if command.is_empty() {
        return Err(
            "protocol.mode=black-box requires protocol.command or protocol.adapter".to_owned(),
        );
    }
    let stdout =
        File::create(logs.join("black_box.stdout.log")).map_err(|error| error.to_string())?;
    let stderr =
        File::create(logs.join("black_box.stderr.log")).map_err(|error| error.to_string())?;
    let mut child = Command::new(&command)
        .args(&config.original.protocol.args)
        .stdout(Stdio::from(stdout))
        .stderr(Stdio::from(stderr))
        .spawn()
        .map_err(|error| format!("spawn black-box adapter failed: {error}"))?;
    let pid = child.id();
    let status = child
        .wait()
        .map_err(|error| format!("wait black-box adapter failed: {error}"))?;
    if !status.success() {
        return Err(format!("black-box adapter exited with status {status}"));
    }
    let proof_bytes = Vec::new();
    let proof = ProofArtifact {
        sha256: sha256_hex(&proof_bytes),
        bytes: proof_bytes,
    };
    let rank = RankRuntimeOutput {
        rank: 0,
        pid,
        total_time_ms: start.elapsed().as_secs_f64() * 1000.0,
        phases: Vec::new(),
        communication: CommunicationCounters::new(1),
        sent_payload_bytes: 0,
        recv_payload_bytes: 0,
        proof_sha256: Some(proof.sha256.clone()),
        proof_size_bytes: proof.bytes.len(),
        resident_bytes: None,
        virtual_bytes: None,
        memory_limit_exceeded: false,
        memory_source: "black_box_external_unavailable".to_owned(),
        thread_budget: config.original.resources.worker_threads,
        qos_class: None,
        qos_applied: false,
        thermal_start: "unavailable".to_owned(),
        thermal_end: "unavailable".to_owned(),
        thermal_source: "black_box_external_unavailable".to_owned(),
        custom_metrics: Vec::new(),
        network_stats: dzb_sdk::NetworkStats::default(),
    };
    Ok(ExperimentOutput {
        status: dzb_core::RunStatus::Failed,
        phases: Vec::new(),
        proof,
        communication: CommunicationCounters::new(config.original.roles.prover_ranks),
        prover_wall_controller_ms: start.elapsed().as_secs_f64() * 1000.0,
        prover_critical_path_ms: rank.total_time_ms,
        verifier_ms: 0.0,
        ranks: vec![rank],
        verifier_pid: None,
        verifier_report: Some(serde_json::json!({
            "verified": null,
            "mode": "black-box",
            "reason": "proof and verifier metrics are unavailable from an opaque process"
        })),
        communication_precision: "unavailable".to_owned(),
        platform_evidence: platform_evidence(config, Some("black_box")),
    })
}

fn spawn_verifier_process(
    config: &dzb_core::ResolvedConfig,
    proof: &ProofArtifact,
    agent: &mut AgentClient,
) -> Result<VerifierProcessOutput, String> {
    let command_path = adapter_command(config)?;
    let logs = Path::new(&config.result_dir).join("logs");
    std::fs::create_dir_all(&logs).map_err(|error| error.to_string())?;
    let proof_path = Path::new(&config.result_dir).join("proof.bin");
    let out = logs.join("verifier_process.json");
    let started = Instant::now();
    let mut args = vec![
        config.original.protocol.verify_subcommand.clone(),
        "--proof".to_owned(),
        proof_path.to_string_lossy().into_owned(),
        "--sha256".to_owned(),
        proof.sha256.clone(),
        "--out".to_owned(),
        out.to_string_lossy().into_owned(),
    ];
    let statement_path = Path::new(&config.result_dir).join("statement.bin");
    if statement_path.exists() {
        args.push("--statement".to_owned());
        args.push(statement_path.to_string_lossy().into_owned());
    }
    args.extend(config.original.protocol.args.clone());
    let mut env = std::collections::BTreeMap::new();
    for (key, value) in standard_thread_budget_env(config.verifier_threads) {
        env.insert(key, value);
    }
    if config.platform == Platform::Darwin {
        env.insert("DZB_DARWIN_QOS".to_owned(), "user_initiated".to_owned());
    }
    let pid = agent.launch(AgentLaunch {
        id: "verifier".to_owned(),
        executable: command_path.to_string_lossy().into_owned(),
        args,
        env,
        stdout_path: logs
            .join("verifier.stdout.log")
            .to_string_lossy()
            .into_owned(),
        stderr_path: logs
            .join("verifier.stderr.log")
            .to_string_lossy()
            .into_owned(),
        run_id: config.run_id.clone(),
        cpuset: strict_cpuset(
            config,
            config.original.roles.prover_ranks,
            config.verifier_threads,
        ),
        memory_limit_bytes: strict_memory_limit(config)?,
        strict_linux: config.platform == Platform::Linux && config.original.memory.cgroup,
        namespace: None,
        sample_path: Some(
            logs.join("memory")
                .join("verifier.csv")
                .to_string_lossy()
                .into_owned(),
        ),
        sample_interval_ms: dzb_core::parse_duration_millis(
            &config.original.metrics.memory_sampling_interval,
        )
        .map_err(|error| error.to_string())?,
        role: "verifier".to_owned(),
        rank: None,
    })?;
    let status = agent.wait(
        "verifier",
        config.original.timeouts.verify_sec.saturating_mul(1_000),
    )?;
    if status == 0 {
        let text = std::fs::read_to_string(&out)
            .map_err(|error| format!("read verifier report failed: {error}"))?;
        let report = serde_json::from_str(&text)
            .map_err(|error| format!("parse verifier report failed: {error}"))?;
        Ok(VerifierProcessOutput {
            pid,
            elapsed_ms: started.elapsed().as_secs_f64() * 1000.0,
            report,
        })
    } else {
        Err(format!("verifier process exited with status {status}"))
    }
}

#[derive(Clone, Debug)]
struct RankRunOutput {
    ranks: Vec<RankRuntimeOutput>,
    proof: ProofArtifact,
    communication: CommunicationCounters,
    prover_critical_path_ms: f64,
}

#[derive(Clone, Debug)]
struct VerifierProcessOutput {
    pid: u32,
    elapsed_ms: f64,
    report: serde_json::Value,
}

#[derive(Clone, Debug, Serialize)]
struct AgentLaunch {
    id: String,
    executable: String,
    args: Vec<String>,
    env: std::collections::BTreeMap<String, String>,
    stdout_path: String,
    stderr_path: String,
    run_id: String,
    cpuset: Option<String>,
    memory_limit_bytes: Option<u64>,
    strict_linux: bool,
    namespace: Option<String>,
    sample_path: Option<String>,
    sample_interval_ms: u64,
    role: String,
    rank: Option<usize>,
}

#[derive(Clone, Debug, Serialize)]
struct KernelShaper {
    bandwidth_bps: Option<u64>,
    latency_ms: u64,
    jitter_ms: u64,
    loss_percent: String,
    edges: Vec<KernelEdgeShaper>,
}

#[derive(Clone, Debug, Serialize)]
struct KernelEdgeShaper {
    src: usize,
    dst: usize,
    bandwidth_bps: Option<u64>,
    latency_ms: u64,
    jitter_ms: u64,
    loss_percent: String,
}

fn kernel_shaper(config: &dzb_core::ResolvedConfig) -> KernelShaper {
    KernelShaper {
        bandwidth_bps: dzb_runner::parse_shaper_bandwidth(
            &config.original.network.shaper.bandwidth,
        ),
        latency_ms: dzb_core::parse_duration_millis(&config.original.network.shaper.latency)
            .unwrap_or(0),
        jitter_ms: dzb_core::parse_duration_millis(&config.original.network.shaper.jitter)
            .unwrap_or(0),
        loss_percent: config.original.network.shaper.loss.clone(),
        edges: config
            .original
            .network
            .shaper
            .edges
            .iter()
            .map(|edge| KernelEdgeShaper {
                src: edge.src,
                dst: edge.dst,
                bandwidth_bps: dzb_runner::parse_shaper_bandwidth(&edge.bandwidth),
                latency_ms: dzb_core::parse_duration_millis(&edge.latency).unwrap_or(0),
                jitter_ms: dzb_core::parse_duration_millis(&edge.jitter).unwrap_or(0),
                loss_percent: edge.loss.clone(),
            })
            .collect(),
    }
}

#[derive(Clone, Debug, Deserialize)]
struct AgentResponse {
    ok: bool,
    message: String,
    pid: Option<u32>,
    exit_code: Option<i32>,
    #[serde(default)]
    listen_addrs: Option<Vec<String>>,
    #[serde(default)]
    namespaces: Option<Vec<String>>,
}

struct AgentClient {
    child: Child,
    input: ChildStdin,
    output: ChildStdout,
    listen_addrs: Vec<String>,
    namespaces: Vec<String>,
}

impl AgentClient {
    fn start(config: &dzb_core::ResolvedConfig) -> Result<Self, String> {
        let executable = sibling_executable("dzb-agent")?;
        let strict_linux = config.platform == Platform::Linux
            && (config.original.resources.no_overcommit
                || config.original.memory.cgroup
                || config.original.network.mode == "netns_veth");
        let mut command = if strict_linux {
            let mut command = Command::new("sudo");
            command.arg("-n").arg(executable);
            command
        } else {
            Command::new(executable)
        };
        let mut child = command
            .arg("serve")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .map_err(|error| format!("spawn dzb-agent failed: {error}"))?;
        let input = child
            .stdin
            .take()
            .ok_or_else(|| "dzb-agent stdin unavailable".to_owned())?;
        let output = child
            .stdout
            .take()
            .ok_or_else(|| "dzb-agent stdout unavailable".to_owned())?;
        let mut client = Self {
            child,
            input,
            output,
            listen_addrs: Vec::new(),
            namespaces: Vec::new(),
        };
        let response = client.request(&serde_json::json!({"kind": "ping"}))?;
        if !response.ok {
            return Err(response.message);
        }
        let prepared = client.request(&serde_json::json!({
            "kind": "prepare_run",
            "run_id": config.run_id,
        }))?;
        if !prepared.ok {
            return Err(prepared.message);
        }
        if config.platform == Platform::Linux && config.original.network.mode == "netns_veth" {
            let setup = client.request(&serde_json::json!({
                "kind": "setup_network",
                "run_id": config.run_id,
                "world_size": config.original.roles.prover_ranks,
                "base_port": config.original.network.base_port,
                "topology": match config.original.topology.kind {
                    TopologyKind::Star => "star",
                    TopologyKind::FullMesh => "full-mesh",
                },
                "master_rank": config.original.roles.master_rank,
                "worker_to_worker": config.original.topology.worker_to_worker,
                "shaper": kernel_shaper(config),
            }))?;
            if !setup.ok {
                return Err(setup.message);
            }
            client.listen_addrs = setup
                .listen_addrs
                .ok_or_else(|| "agent network response omitted addresses".to_owned())?;
            client.namespaces = setup
                .namespaces
                .ok_or_else(|| "agent network response omitted namespaces".to_owned())?;
        } else {
            client.listen_addrs = (0..config.original.roles.prover_ranks)
                .map(|rank| {
                    format!(
                        "127.0.0.1:{}",
                        config.original.network.base_port as usize + rank
                    )
                })
                .collect();
            client.namespaces = vec![String::new(); config.original.roles.prover_ranks];
        }
        Ok(client)
    }

    fn launch(&mut self, launch: AgentLaunch) -> Result<u32, String> {
        let mut value = serde_json::to_value(launch).map_err(|error| error.to_string())?;
        value
            .as_object_mut()
            .ok_or_else(|| "agent launch must serialize as an object".to_owned())?
            .insert("kind".to_owned(), serde_json::json!("launch"));
        let response = self.request(&value)?;
        if response.ok {
            response
                .pid
                .ok_or_else(|| "agent launch response omitted pid".to_owned())
        } else {
            Err(response.message)
        }
    }

    fn wait(&mut self, id: &str, timeout_ms: u64) -> Result<i32, String> {
        let response =
            self.request(&serde_json::json!({"kind": "wait", "id": id, "timeout_ms": timeout_ms}))?;
        if response.ok {
            Ok(response.exit_code.unwrap_or(0))
        } else {
            Err(response.message)
        }
    }

    fn wait_all(&mut self, ids: &[String], timeout_ms: u64) -> Result<(), String> {
        let response = self.request(
            &serde_json::json!({"kind": "wait_all", "ids": ids, "timeout_ms": timeout_ms}),
        )?;
        response.ok.then_some(()).ok_or(response.message)
    }

    fn cleanup(&mut self) -> Result<(), String> {
        let response = self.request(&serde_json::json!({"kind": "cleanup"}))?;
        response.ok.then_some(()).ok_or(response.message)
    }

    fn request(&mut self, value: &serde_json::Value) -> Result<AgentResponse, String> {
        let bytes = serde_json::to_vec(value).map_err(|error| error.to_string())?;
        self.input
            .write_all(&(bytes.len() as u32).to_le_bytes())
            .and_then(|_| self.input.write_all(&bytes))
            .and_then(|_| self.input.flush())
            .map_err(|error| format!("write agent request failed: {error}"))?;
        let mut len = [0_u8; 4];
        self.output
            .read_exact(&mut len)
            .map_err(|error| format!("read agent response length failed: {error}"))?;
        let len = u32::from_le_bytes(len) as usize;
        let mut bytes = vec![0_u8; len];
        self.output
            .read_exact(&mut bytes)
            .map_err(|error| format!("read agent response failed: {error}"))?;
        serde_json::from_slice(&bytes)
            .map_err(|error| format!("parse agent response failed: {error}"))
    }
}

impl Drop for AgentClient {
    fn drop(&mut self) {
        let _ = self.cleanup();
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn spawn_rank_processes(
    config: &dzb_core::ResolvedConfig,
    agent: &mut AgentClient,
) -> Result<RankRunOutput, String> {
    let command_path = adapter_command(config)?;
    let result_dir = Path::new(&config.result_dir);
    let logs = result_dir.join("logs");
    let tmp = result_dir.join("tmp");
    std::fs::create_dir_all(&logs).map_err(|error| error.to_string())?;
    std::fs::create_dir_all(&tmp).map_err(|error| error.to_string())?;
    let listen_addrs = agent.listen_addrs.clone();
    let proof_path = result_dir.join("proof.bin");
    let mut rank_ids = Vec::new();
    for rank in 0..config.original.roles.prover_ranks {
        let out = logs.join(format!("rank_{rank}.json"));
        let rank_config_path = tmp.join(format!("rank_{rank}.json"));
        let mut rank_config = rank_runtime_config_from_resolved(
            config,
            rank,
            listen_addrs.clone(),
            out.to_string_lossy().into_owned(),
            (rank == config.original.roles.master_rank)
                .then(|| proof_path.to_string_lossy().into_owned()),
        )?;
        if config.original.network.mode == "netns_veth" {
            rank_config.shaper = dzb_runner::RankShaperConfig::default();
        }
        write_json_pretty(&rank_config_path, &rank_config).map_err(|error| error.to_string())?;
        let mut env = std::collections::BTreeMap::new();
        env.insert(
            "DZB_RANK_CONFIG".to_owned(),
            rank_config_path.to_string_lossy().into_owned(),
        );
        for (key, value) in standard_thread_budget_env(config.original.resources.worker_threads) {
            env.insert(key, value);
        }
        if config.platform == Platform::Darwin {
            env.insert("DZB_DARWIN_QOS".to_owned(), "user_initiated".to_owned());
        }
        let id = format!("rank-{rank}");
        let mut args = vec![
            config.original.protocol.prove_subcommand.clone(),
            "--config".to_owned(),
            rank_config_path.to_string_lossy().into_owned(),
        ];
        args.extend(config.original.protocol.args.clone());
        agent.launch(AgentLaunch {
            id: id.clone(),
            executable: command_path.to_string_lossy().into_owned(),
            args,
            env,
            stdout_path: logs
                .join(format!("rank_{rank}.stdout.log"))
                .to_string_lossy()
                .into_owned(),
            stderr_path: logs
                .join(format!("rank_{rank}.stderr.log"))
                .to_string_lossy()
                .into_owned(),
            run_id: config.run_id.clone(),
            cpuset: strict_cpuset(config, rank, config.original.resources.worker_threads),
            memory_limit_bytes: strict_memory_limit(config)?,
            strict_linux: config.platform == Platform::Linux && config.original.memory.cgroup,
            namespace: agent
                .namespaces
                .get(rank)
                .filter(|value| !value.is_empty())
                .cloned(),
            sample_path: Some(
                logs.join("memory")
                    .join(format!("rank_{rank}.csv"))
                    .to_string_lossy()
                    .into_owned(),
            ),
            sample_interval_ms: dzb_core::parse_duration_millis(
                &config.original.metrics.memory_sampling_interval,
            )
            .map_err(|error| error.to_string())?,
            role: "rank".to_owned(),
            rank: Some(rank),
        })?;
        rank_ids.push((rank, id));
    }
    let ids = rank_ids
        .iter()
        .map(|(_, id)| id.clone())
        .collect::<Vec<_>>();
    agent.wait_all(
        &ids,
        config.original.timeouts.prove_sec.saturating_mul(1_000),
    )?;
    let mut rank_outputs = Vec::new();
    let mut communication = CommunicationCounters::new(config.original.roles.prover_ranks);
    let mut critical_path = 0.0_f64;
    for rank in 0..config.original.roles.prover_ranks {
        let path = logs.join(format!("rank_{rank}.json"));
        let text = std::fs::read_to_string(&path)
            .map_err(|error| format!("read rank {rank} output failed: {error}"))?;
        let output = serde_json::from_str::<RankRuntimeOutput>(&text)
            .map_err(|error| format!("parse rank {rank} output failed: {error}"))?;
        communication.merge_from(&output.communication);
        critical_path = critical_path.max(output.total_time_ms);
        rank_outputs.push(output);
    }
    let proof_bytes = if proof_path.exists() {
        std::fs::read(&proof_path).map_err(|error| format!("read master proof failed: {error}"))?
    } else {
        Vec::new()
    };
    let proof = ProofArtifact {
        sha256: sha256_hex(&proof_bytes),
        bytes: proof_bytes,
    };
    Ok(RankRunOutput {
        ranks: rank_outputs,
        proof,
        communication,
        prover_critical_path_ms: critical_path,
    })
}

fn strict_cpuset(
    config: &dzb_core::ResolvedConfig,
    slot: usize,
    thread_count: usize,
) -> Option<String> {
    (config.platform == Platform::Linux && config.original.resources.no_overcommit).then(|| {
        let first = slot.saturating_mul(thread_count);
        if thread_count == 1 {
            first.to_string()
        } else {
            format!("{first}-{}", first + thread_count - 1)
        }
    })
}

fn strict_memory_limit(config: &dzb_core::ResolvedConfig) -> Result<Option<u64>, String> {
    if config.platform == Platform::Linux && config.original.memory.cgroup {
        dzb_core::parse_byte_size(&config.original.memory.per_rank_limit)
            .map(Some)
            .map_err(|error| error.to_string())
    } else {
        Ok(None)
    }
}

fn platform_evidence(config: &dzb_core::ResolvedConfig, mode: Option<&str>) -> serde_json::Value {
    serde_json::json!({
        "platform": config.platform.as_str(),
        "isolation_tier": config.isolation_tier.as_str(),
        "mode": mode.unwrap_or("sdk"),
        "unsupported_features": config.capability.unsupported_features,
        "darwin": {
            "qos": config.platform == Platform::Darwin,
            "mach_task_info": config.platform == Platform::Darwin,
            "thermal": config.platform == Platform::Darwin
        },
        "linux": {
            "strict_preflight": config.platform == Platform::Linux,
            "cgroup_v2": config.capability.memory_control.hard_limit.supported,
            "netns": config.capability.network_emulation.netns_or_equivalent.supported,
            "tc": config.capability.network_emulation.kernel_shaper.supported,
            "perf": config.capability.perf_counters.linux_perf_equivalent.supported
        }
    })
}

fn adapter_command(config: &dzb_core::ResolvedConfig) -> Result<PathBuf, String> {
    if !config.original.protocol.command.is_empty() {
        return Ok(PathBuf::from(&config.original.protocol.command));
    }
    if config.original.protocol.adapter.starts_with("toy-") {
        return sibling_executable("dzb-toy-adapter");
    }
    Err(format!(
        "protocol.mode=sdk-binary requires protocol.command for adapter '{}'",
        config.original.protocol.adapter
    ))
}

fn execution_fingerprint(config: &dzb_core::ResolvedConfig) -> Result<String, String> {
    let adapter = adapter_command(config)?;
    let adapter_hash = std::fs::read(&adapter)
        .map(|bytes| sha256_hex(&bytes))
        .map_err(|error| format!("hash adapter {} failed: {error}", adapter.display()))?;
    let framework_commit = Command::new("git")
        .args(["rev-parse", "HEAD"])
        .output()
        .ok()
        .filter(|output| output.status.success())
        .map(|output| String::from_utf8_lossy(&output.stdout).trim().to_owned())
        .unwrap_or_else(|| "unavailable".to_owned());
    let framework_binary_hash = std::env::current_exe()
        .ok()
        .and_then(|path| std::fs::read(path).ok())
        .map(|bytes| sha256_hex(&bytes))
        .unwrap_or_else(|| "unavailable".to_owned());
    Ok(sha256_hex(
        format!(
            "{}\n{framework_commit}\n{framework_binary_hash}\n{adapter_hash}",
            config.config_hash
        )
        .as_bytes(),
    ))
}

fn sibling_executable(name: &str) -> Result<PathBuf, String> {
    let current = env::current_exe().map_err(|error| error.to_string())?;
    let Some(dir) = current.parent() else {
        return Err("cannot resolve current executable directory".to_owned());
    };
    let candidate = dir.join(name);
    if candidate.is_file() {
        Ok(candidate)
    } else {
        Err(format!(
            "{name} not found next to {}; build the workspace or set protocol.command",
            current.display()
        ))
    }
}

fn cmd_sweep(args: &[String]) -> Result<(), String> {
    let rerun = args.iter().any(|arg| arg == "--rerun");
    let config_path = args
        .iter()
        .find(|arg| !arg.starts_with('-'))
        .map(PathBuf::from)
        .or_else(|| value_after(args, "--config").map(PathBuf::from))
        .ok_or_else(|| "dzb sweep requires <config.yaml>".to_owned())?;
    let config = load_config(&config_path).map_err(|error| error.to_string())?;
    let cells = expand_sweep(&config).map_err(|error| error.to_string())?;
    let sweep_root = Path::new(&config.experiment.output_dir).join(&config.experiment.name);
    let generated = sweep_root.join("sweep-configs");
    fs::create_dir_all(&generated).map_err(|error| error.to_string())?;
    let mut state = SweepState::default();
    for (cell_index, mut cell) in cells.into_iter().enumerate() {
        let cell_hash = dzb_core::semantic_config_hash(&cell).map_err(|error| error.to_string())?;
        let cell_id = format!("cell-{cell_index:03}-{}", &cell_hash[..8]);
        let repetitions = cell.experiment.repetitions.max(1);
        let warmups = cell.experiment.warmups;
        cell.experiment.repetitions = 1;
        cell.experiment.warmups = 0;
        for warmup in 0..warmups {
            let mut warmup_config = cell.clone();
            warmup_config.experiment.name = format!(
                "{}/warmups/{cell_id}/warmup-{warmup:03}",
                config.experiment.name
            );
            warmup_config.experiment.run_id =
                dzb_core::new_run_id(&format!("{cell_id}-warmup-{warmup:03}"));
            let path = generated.join(format!("{cell_id}-warmup-{warmup:03}.yaml"));
            fs::write(
                &path,
                serde_yaml::to_string(&warmup_config).map_err(|error| error.to_string())?,
            )
            .map_err(|error| error.to_string())?;
            run_or_resume_sweep_item(
                &path,
                &warmup_config,
                &cell_id,
                format!("warmup-{warmup:03}"),
                rerun,
                &mut state,
                &sweep_root,
            )?;
        }
        for repetition in 0..repetitions {
            let mut measured = cell.clone();
            measured.experiment.name = format!(
                "{}/cells/{cell_id}/repetitions/{repetition:03}",
                config.experiment.name
            );
            measured.experiment.run_id =
                dzb_core::new_run_id(&format!("{cell_id}-repetition-{repetition:03}"));
            let path = generated.join(format!("{cell_id}-repetition-{repetition:03}.yaml"));
            fs::write(
                &path,
                serde_yaml::to_string(&measured).map_err(|error| error.to_string())?,
            )
            .map_err(|error| error.to_string())?;
            run_or_resume_sweep_item(
                &path,
                &measured,
                &cell_id,
                format!("repetition-{repetition:03}"),
                rerun,
                &mut state,
                &sweep_root,
            )?;
        }
    }
    Ok(())
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
struct SweepState {
    schema_version: u32,
    items: Vec<SweepStateItem>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct SweepStateItem {
    cell_id: String,
    item: String,
    execution_fingerprint: String,
    status: String,
    result_dir: String,
}

fn run_or_resume_sweep_item(
    path: &Path,
    config: &Config,
    cell_id: &str,
    item: String,
    rerun: bool,
    state: &mut SweepState,
    sweep_root: &Path,
) -> Result<(), String> {
    let capability = capability_for_request(config.platform.backend)?;
    let mut resolved =
        resolve_config(config.clone(), capability).map_err(|error| error.to_string())?;
    resolved.execution_fingerprint = execution_fingerprint(&resolved)?;
    let experiment_root = Path::new(&config.experiment.output_dir).join(&config.experiment.name);
    let existing = (!rerun)
        .then(|| {
            find_complete_artifact(
                &experiment_root,
                &resolved.execution_fingerprint,
                config.roles.verifier_enabled,
            )
        })
        .transpose()?
        .flatten();
    let (status, result_dir) = if let Some(existing) = existing {
        println!(
            "resume: skipping verified {} {} at {}",
            cell_id,
            item,
            existing.display()
        );
        (
            "skipped".to_owned(),
            existing.to_string_lossy().into_owned(),
        )
    } else {
        cmd_run(&[path.to_string_lossy().into_owned()])?;
        let completed = find_complete_artifact(
            &experiment_root,
            &resolved.execution_fingerprint,
            config.roles.verifier_enabled,
        )?
        .ok_or_else(|| {
            format!(
                "completed sweep item {} {} has no valid artifact",
                cell_id, item
            )
        })?;
        (
            "completed".to_owned(),
            completed.to_string_lossy().into_owned(),
        )
    };
    state.schema_version = 1;
    state
        .items
        .retain(|entry| !(entry.cell_id == cell_id && entry.item == item));
    state.items.push(SweepStateItem {
        cell_id: cell_id.to_owned(),
        item,
        execution_fingerprint: resolved.execution_fingerprint,
        status,
        result_dir,
    });
    write_json_atomic(&sweep_root.join("sweep-state.json"), state)
}

fn find_complete_artifact(
    root: &Path,
    fingerprint: &str,
    verifier_required: bool,
) -> Result<Option<PathBuf>, String> {
    if !root.exists() {
        return Ok(None);
    }
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        for entry in fs::read_dir(&dir).map_err(|error| error.to_string())? {
            let entry = entry.map_err(|error| error.to_string())?;
            let path = entry.path();
            if entry
                .file_type()
                .map_err(|error| error.to_string())?
                .is_dir()
            {
                stack.push(path);
            } else if path.file_name().is_some_and(|name| name == "run.json") {
                let run_dir = path.parent().unwrap_or(root);
                if artifact_is_complete(run_dir, fingerprint, verifier_required)? {
                    return Ok(Some(run_dir.to_path_buf()));
                }
            }
        }
    }
    Ok(None)
}

fn artifact_is_complete(
    run_dir: &Path,
    fingerprint: &str,
    verifier_required: bool,
) -> Result<bool, String> {
    Ok(check_artifact_complete(run_dir, fingerprint, verifier_required).unwrap_or(false))
}

fn check_artifact_complete(
    run_dir: &Path,
    fingerprint: &str,
    verifier_required: bool,
) -> Result<bool, String> {
    let text = fs::read_to_string(run_dir.join("run.json")).map_err(|error| error.to_string())?;
    let run: dzb_core::RunJson = serde_json::from_str(&text).map_err(|error| error.to_string())?;
    if run.status != "ok" || run.execution_fingerprint != fingerprint {
        return Ok(false);
    }
    let proof = fs::read(run_dir.join("proof.bin")).map_err(|error| error.to_string())?;
    if sha256_hex(&proof) != run.proof_sha256 {
        return Ok(false);
    }
    if let Some(expected) = &run.statement_sha256 {
        let statement =
            fs::read(run_dir.join("statement.bin")).map_err(|error| error.to_string())?;
        if sha256_hex(&statement) != *expected {
            return Ok(false);
        }
    }
    if verifier_required {
        let verifier =
            fs::read_to_string(run_dir.join("verifier.json")).map_err(|error| error.to_string())?;
        let verifier: serde_json::Value =
            serde_json::from_str(&verifier).map_err(|error| error.to_string())?;
        if verifier
            .pointer("/process_report/verified")
            .and_then(serde_json::Value::as_bool)
            != Some(true)
        {
            return Ok(false);
        }
    }
    Ok(true)
}

fn write_json_atomic<T: Serialize>(path: &Path, value: &T) -> Result<(), String> {
    let temp = path.with_extension("json.tmp");
    let bytes = serde_json::to_vec_pretty(value).map_err(|error| error.to_string())?;
    fs::write(&temp, bytes).map_err(|error| error.to_string())?;
    fs::rename(temp, path).map_err(|error| error.to_string())
}

fn cmd_report(args: &[String]) -> Result<(), String> {
    let Some(dir) = args.first() else {
        return Err("dzb report requires <results_dir>".to_owned());
    };
    println!("{}", dzb_report::summarize_run(Path::new(dir))?);
    Ok(())
}

fn cmd_cleanup(args: &[String]) -> Result<(), String> {
    let all = args.iter().any(|arg| arg == "--all");
    let run_id = value_after(args, "--run-id").unwrap_or_default();
    if !all && run_id.is_empty() {
        return Err("dzb cleanup requires --run-id <id> or --all".to_owned());
    }
    if Platform::host() != Platform::Linux {
        println!("cleanup complete: no privileged Linux resources on this platform");
        return Ok(());
    }
    let safe_run_id = run_id
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || ch == '-' {
                ch
            } else {
                '-'
            }
        })
        .collect::<String>();
    let root = Path::new("/sys/fs/cgroup");
    let targets = fs::read_dir(root)
        .map_err(|error| error.to_string())?
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|path| {
            let name = path
                .file_name()
                .and_then(|name| name.to_str())
                .unwrap_or("");
            name.starts_with("dzb-") && (all || name == format!("dzb-{safe_run_id}"))
        })
        .collect::<Vec<_>>();
    for target in targets {
        cleanup_cgroup_tree(&target)?;
    }
    cleanup_named_network_resources(if all { None } else { Some(run_id.as_str()) })?;
    println!(
        "cleanup complete: {}",
        if all {
            "all DistZKBench resources"
        } else {
            &run_id
        }
    );
    Ok(())
}

fn cleanup_cgroup_tree(path: &Path) -> Result<(), String> {
    if path.join("cgroup.kill").exists() {
        let _ = sudo_command(
            "tee",
            &[path.join("cgroup.kill").to_string_lossy().as_ref()],
            Some("1\n"),
        );
    }
    let mut dirs = fs::read_dir(path)
        .map_err(|error| error.to_string())?
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|path| path.is_dir())
        .collect::<Vec<_>>();
    dirs.sort_by_key(|path| std::cmp::Reverse(path.components().count()));
    for dir in dirs {
        sudo_command("rmdir", &[dir.to_string_lossy().as_ref()], None)?;
    }
    sudo_command("rmdir", &[path.to_string_lossy().as_ref()], None)
}

fn cleanup_named_network_resources(run_id: Option<&str>) -> Result<(), String> {
    let short = run_id.map(stable_run_short);
    let output = Command::new("ip")
        .args(["netns", "list"])
        .output()
        .map_err(|error| error.to_string())?;
    for name in String::from_utf8_lossy(&output.stdout)
        .lines()
        .filter_map(|line| line.split_whitespace().next())
        .filter(|name| {
            name.starts_with("dzb") && short.as_ref().is_none_or(|short| name.contains(short))
        })
    {
        sudo_command("ip", &["netns", "del", name], None)?;
    }
    let links = Command::new("ip")
        .args(["-o", "link", "show", "type", "bridge"])
        .output()
        .map_err(|error| error.to_string())?;
    for name in String::from_utf8_lossy(&links.stdout)
        .lines()
        .filter_map(|line| line.split_whitespace().nth(1))
        .map(|name| name.trim_end_matches(':'))
        .filter(|name| {
            name.starts_with("dzb") && short.as_ref().is_none_or(|short| name.contains(short))
        })
    {
        sudo_command("ip", &["link", "del", name], None)?;
    }
    Ok(())
}

fn stable_run_short(run_id: &str) -> String {
    use std::hash::{Hash, Hasher};
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    run_id.hash(&mut hasher);
    format!("{:016x}", hasher.finish())[..6].to_owned()
}

fn sudo_command(command: &str, args: &[&str], input: Option<&str>) -> Result<(), String> {
    let mut child = Command::new("sudo")
        .arg("-n")
        .arg(command)
        .args(args)
        .stdin(if input.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|error| error.to_string())?;
    if let (Some(input), Some(mut stdin)) = (input, child.stdin.take()) {
        stdin
            .write_all(input.as_bytes())
            .map_err(|error| error.to_string())?;
    }
    let output = child
        .wait_with_output()
        .map_err(|error| error.to_string())?;
    if output.status.success() {
        Ok(())
    } else {
        Err(String::from_utf8_lossy(&output.stderr).trim().to_owned())
    }
}

fn capability_for_request(
    backend: PlatformBackendName,
) -> Result<dzb_core::CapabilityReport, String> {
    match backend {
        PlatformBackendName::Auto => match Platform::host() {
            Platform::Linux => LinuxBackend::new()
                .detect_capabilities()
                .map_err(|error| error.to_string()),
            Platform::Darwin => DarwinBackend::new()
                .detect_capabilities()
                .map_err(|error| error.to_string()),
            Platform::Unsupported => Err("unsupported host platform".to_owned()),
        },
        PlatformBackendName::Linux => LinuxBackend::new()
            .detect_capabilities()
            .map_err(|error| error.to_string()),
        PlatformBackendName::Darwin => DarwinBackend::new()
            .detect_capabilities()
            .map_err(|error| error.to_string()),
    }
}

fn parse_config_arg(args: &[String]) -> Result<PathBuf, String> {
    value_after(args, "--config")
        .map(PathBuf::from)
        .ok_or_else(|| "expected --config <yaml>".to_owned())
}

fn value_after(args: &[String], key: &str) -> Option<String> {
    args.windows(2)
        .find_map(|pair| (pair[0] == key).then(|| pair[1].clone()))
}

fn usage() -> String {
    "usage: dzb ui | dzb interactive | dzb preflight --config <yaml> | dzb run <yaml> | dzb sweep <yaml> [--rerun] | dzb report <results_dir> | dzb cleanup --run-id <id> | dzb cleanup --all".to_owned()
}

fn interactive_usage() -> String {
    "usage: dzb interactive\n\nStarts a prompt-driven workflow for local toy self-checks and adapter config generation.".to_owned()
}

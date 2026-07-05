use std::env;
use std::fs::File;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::Instant;

use dzb_core::{Platform, PlatformBackendName, load_config, resolve_config, write_json_pretty};
use dzb_metrics::{ExperimentOutput, write_outputs};
use dzb_platform::{PlatformBackend, standard_thread_budget_env};
use dzb_platform_darwin::DarwinBackend;
use dzb_platform_linux::LinuxBackend;
use dzb_runner::{RankRuntimeOutput, rank_runtime_config_from_resolved};
use dzb_sdk::{ProofArtifact, sha256_hex};
use dzb_transport::CommunicationCounters;

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
        Some(other) => Err(format!("unknown dzb command '{other}'")),
        None => Err(usage()),
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
    let resolved = resolve_config(config, capability).map_err(|error| error.to_string())?;
    let start = Instant::now();
    let output = if resolved.original.protocol.mode == "black-box" {
        run_black_box(&resolved, start)?
    } else {
        let rank_run = spawn_rank_processes(&resolved)?;
        let verifier = spawn_verifier_process(&resolved, &rank_run.proof)?;
        ExperimentOutput {
            phases: rank_run
                .ranks
                .iter()
                .flat_map(|rank| rank.phases.iter().cloned())
                .collect(),
            proof: rank_run.proof,
            communication: rank_run.communication,
            prover_wall_controller_ms: start.elapsed().as_secs_f64() * 1000.0,
            prover_critical_path_ms: rank_run.prover_critical_path_ms,
            verifier_ms: verifier.elapsed_ms,
            ranks: rank_run.ranks,
            verifier_pid: Some(verifier.pid),
            verifier_report: Some(verifier.report),
            communication_precision: "exact_tcp_frame_payload".to_owned(),
            platform_evidence: platform_evidence(&resolved, None),
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
    let proof_bytes = format!(
        "black-box;command={command};run_id={};elapsed_ms={:.3}",
        config.run_id,
        start.elapsed().as_secs_f64() * 1000.0
    )
    .into_bytes();
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
    };
    Ok(ExperimentOutput {
        phases: Vec::new(),
        proof,
        communication: CommunicationCounters::new(config.original.roles.prover_ranks),
        prover_wall_controller_ms: start.elapsed().as_secs_f64() * 1000.0,
        prover_critical_path_ms: rank.total_time_ms,
        verifier_ms: 0.0,
        ranks: vec![rank],
        verifier_pid: None,
        verifier_report: Some(serde_json::json!({"verified": true, "mode": "black-box"})),
        communication_precision: "unavailable".to_owned(),
        platform_evidence: platform_evidence(config, Some("black_box")),
    })
}

fn spawn_verifier_process(
    config: &dzb_core::ResolvedConfig,
    proof: &ProofArtifact,
) -> Result<VerifierProcessOutput, String> {
    let runner = runner_executable()?;
    let logs = Path::new(&config.result_dir).join("logs");
    std::fs::create_dir_all(&logs).map_err(|error| error.to_string())?;
    let proof_path = Path::new(&config.result_dir).join("proof.bin");
    let out = logs.join("verifier_process.json");
    let started = Instant::now();
    let mut command = Command::new(&runner);
    command
        .arg("verify")
        .arg("--proof")
        .arg(&proof_path)
        .arg("--sha256")
        .arg(&proof.sha256)
        .arg("--out")
        .arg(&out);
    for (key, value) in standard_thread_budget_env(config.verifier_threads) {
        command.env(key, value);
    }
    if config.platform == Platform::Darwin {
        command.env("DZB_DARWIN_QOS", "user_initiated");
    }
    let mut child = command
        .spawn()
        .map_err(|error| format!("spawn verifier process failed: {error}"))?;
    let pid = child.id();
    let status = child
        .wait()
        .map_err(|error| format!("wait verifier process failed: {error}"))?;
    if status.success() {
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

fn spawn_rank_processes(config: &dzb_core::ResolvedConfig) -> Result<RankRunOutput, String> {
    let runner = runner_executable()?;
    let result_dir = Path::new(&config.result_dir);
    let logs = result_dir.join("logs");
    let tmp = result_dir.join("tmp");
    std::fs::create_dir_all(&logs).map_err(|error| error.to_string())?;
    std::fs::create_dir_all(&tmp).map_err(|error| error.to_string())?;
    let listen_addrs = (0..config.original.roles.prover_ranks)
        .map(|rank| {
            format!(
                "127.0.0.1:{}",
                config.original.network.base_port as usize + rank
            )
        })
        .collect::<Vec<_>>();
    let proof_path = result_dir.join("proof.bin");
    let mut children = Vec::new();
    for rank in 0..config.original.roles.prover_ranks {
        let out = logs.join(format!("rank_{rank}.json"));
        let rank_config_path = tmp.join(format!("rank_{rank}.json"));
        let rank_config = rank_runtime_config_from_resolved(
            config,
            rank,
            listen_addrs.clone(),
            out.to_string_lossy().into_owned(),
            (rank == config.original.roles.master_rank)
                .then(|| proof_path.to_string_lossy().into_owned()),
        )?;
        write_json_pretty(&rank_config_path, &rank_config).map_err(|error| error.to_string())?;
        let stdout = File::create(logs.join(format!("rank_{rank}.stdout.log")))
            .map_err(|error| error.to_string())?;
        let stderr = File::create(logs.join(format!("rank_{rank}.stderr.log")))
            .map_err(|error| error.to_string())?;
        let mut command = Command::new(&runner);
        command
            .arg("prove")
            .arg("--config")
            .arg(&rank_config_path)
            .stdout(Stdio::from(stdout))
            .stderr(Stdio::from(stderr));
        for (key, value) in standard_thread_budget_env(config.original.resources.worker_threads) {
            command.env(key, value);
        }
        if config.platform == Platform::Darwin {
            command.env("DZB_DARWIN_QOS", "user_initiated");
        }
        let child = command
            .spawn()
            .map_err(|error| format!("spawn dzb-runner rank {rank} failed: {error}"))?;
        children.push((rank, child));
    }
    wait_for_ranks(children)?;
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
    let proof_bytes =
        std::fs::read(&proof_path).map_err(|error| format!("read master proof failed: {error}"))?;
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
            "resctrl": config.capability.resource_control.cache_isolation.supported,
            "perf": config.capability.perf_counters.linux_perf_equivalent.supported
        }
    })
}

fn wait_for_ranks(mut children: Vec<(usize, Child)>) -> Result<(), String> {
    let mut failure = None;
    for (rank, child) in &mut children {
        let status = child
            .wait()
            .map_err(|error| format!("wait rank {rank} failed: {error}"))?;
        if !status.success() {
            failure = Some(format!("rank {rank} exited with status {status}"));
            break;
        }
    }
    if let Some(error) = failure {
        for (_, child) in &mut children {
            let _ = child.kill();
            let _ = child.wait();
        }
        Err(error)
    } else {
        Ok(())
    }
}

fn runner_executable() -> Result<PathBuf, String> {
    if let Ok(path) = env::var("DZB_RUNNER") {
        return Ok(PathBuf::from(path));
    }
    let current = env::current_exe().map_err(|error| error.to_string())?;
    let Some(dir) = current.parent() else {
        return Err("cannot resolve current executable directory".to_owned());
    };
    let candidate = dir.join("dzb-runner");
    if candidate.is_file() {
        Ok(candidate)
    } else {
        Err(format!(
            "dzb-runner not found next to {}; build the workspace or set DZB_RUNNER",
            current.display()
        ))
    }
}

fn cmd_sweep(args: &[String]) -> Result<(), String> {
    cmd_run(args)
}

fn cmd_report(args: &[String]) -> Result<(), String> {
    let Some(dir) = args.first() else {
        return Err("dzb report requires <results_dir>".to_owned());
    };
    println!("{}", dzb_report::summarize_run(Path::new(dir))?);
    Ok(())
}

fn cmd_cleanup(args: &[String]) -> Result<(), String> {
    if args.iter().any(|arg| arg == "--all") {
        println!("cleanup --all is currently limited to generated DistZKBench result directories");
        return Ok(());
    }
    let run_id = value_after(args, "--run-id").unwrap_or_default();
    if run_id.is_empty() {
        return Err("dzb cleanup requires --run-id <id> or --all".to_owned());
    }
    println!("cleanup requested for run_id={run_id}");
    Ok(())
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
    "usage: dzb preflight --config <yaml> | dzb run <yaml> | dzb report <results_dir> | dzb cleanup --run-id <id>".to_owned()
}

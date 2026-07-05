use std::env;
use std::fs::{self, File};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Instant, SystemTime};

use dzb_core::{
    Config, Platform, PlatformBackendName, TopologyKind, load_config, resolve_config,
    write_json_pretty,
};
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
        Some("interactive") | Some("ui") | Some("wizard") => cmd_interactive(&args[1..]),
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
    if mode == "black-box" {
        config.protocol.command = adapter;
    }
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
    "usage: dzb interactive | dzb preflight --config <yaml> | dzb run <yaml> | dzb report <results_dir> | dzb cleanup --run-id <id>".to_owned()
}

fn interactive_usage() -> String {
    "usage: dzb interactive\n\nStarts a prompt-driven workflow for local toy self-checks and adapter config generation.".to_owned()
}

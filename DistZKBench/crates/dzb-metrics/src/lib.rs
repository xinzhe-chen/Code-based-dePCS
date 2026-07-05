use std::fs::{self, File};
use std::io::Write;
use std::path::Path;

use serde::{Deserialize, Serialize};

use dzb_core::{Manifest, ResolvedConfig, RunJson, write_json_pretty};
use dzb_runner::RankRuntimeOutput;
use dzb_sdk::{PhaseEvent, ProofArtifact};
use dzb_transport::CommunicationCounters;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ExperimentOutput {
    pub phases: Vec<PhaseEvent>,
    pub proof: ProofArtifact,
    pub communication: CommunicationCounters,
    pub prover_wall_controller_ms: f64,
    pub prover_critical_path_ms: f64,
    pub verifier_ms: f64,
    pub ranks: Vec<RankRuntimeOutput>,
    pub verifier_pid: Option<u32>,
    pub verifier_report: Option<serde_json::Value>,
    pub communication_precision: String,
    pub platform_evidence: serde_json::Value,
}

pub fn write_outputs(
    config: &ResolvedConfig,
    output: &ExperimentOutput,
) -> std::io::Result<RunJson> {
    let result_dir = Path::new(&config.result_dir);
    fs::create_dir_all(result_dir.join("logs"))?;
    fs::write(
        result_dir.join("config.resolved.yaml"),
        serde_yaml::to_string(config).map_err(io_err)?,
    )?;
    fs::write(
        result_dir.join("config.original.yaml"),
        serde_yaml::to_string(&config.original).map_err(io_err)?,
    )?;
    write_json_pretty(
        &result_dir.join("manifest.json"),
        &Manifest::from_resolved(config),
    )?;
    write_events(result_dir, &output.phases)?;
    write_phase_csv(result_dir, &output.phases)?;
    write_rank_csv(result_dir, config, output)?;
    write_comm_matrix(result_dir, &output.communication)?;
    write_memory_csv(result_dir, config, output)?;
    write_perf_csv(result_dir, config)?;
    fs::write(result_dir.join("proof.bin"), &output.proof.bytes)?;
    fs::write(
        result_dir.join("proof.sha256"),
        format!("{}\n", output.proof.sha256),
    )?;
    write_json_pretty(
        &result_dir.join("verifier.json"),
        &serde_json::json!({
            "median_ms": output.verifier_ms,
            "p95_ms": output.verifier_ms,
            "thread_budget": config.verifier_threads,
            "hard_cpu_affinity": config.platform.as_str() == "linux",
            "pid": output.verifier_pid,
            "process_report": output.verifier_report
        }),
    )?;
    write_chrome_trace(result_dir, &output.phases)?;
    write_html_report(result_dir, config, output)?;
    let run_json = RunJson {
        run_id: config.run_id.clone(),
        experiment: config.original.experiment.name.clone(),
        platform: config.platform.as_str().to_owned(),
        isolation_tier: config.isolation_tier.as_str().to_owned(),
        status: "ok".to_owned(),
        prover_critical_path_ms: output.prover_critical_path_ms,
        prover_wall_controller_ms: output.prover_wall_controller_ms,
        proof_size_bytes: output.proof.bytes.len(),
        proof_sha256: output.proof.sha256.clone(),
        total_protocol_bytes: output.communication.total_payload_bytes(),
        total_framed_bytes: output.communication.total_framed_bytes(),
        message_count: output.communication.message_count(),
        verifier_median_ms: output.verifier_ms,
        rank_pids: output.ranks.iter().map(|rank| rank.pid).collect(),
        verifier_pid: output.verifier_pid,
        communication_precision: output.communication_precision.clone(),
        platform_evidence: output.platform_evidence.clone(),
        best_effort_warning: config.capability.requires_best_effort_warning().then(|| {
            "macOS Apple Silicon backend uses best-effort resource isolation; do not compare directly with Linux strict-isolation results".to_owned()
        }),
    };
    write_json_pretty(&result_dir.join("run.json"), &run_json)?;
    Ok(run_json)
}

fn write_events(result_dir: &Path, phases: &[PhaseEvent]) -> std::io::Result<()> {
    let mut file = File::create(result_dir.join("events.jsonl"))?;
    for phase in phases {
        writeln!(file, "{}", serde_json::to_string(phase).map_err(io_err)?)?;
    }
    Ok(())
}

fn write_phase_csv(result_dir: &Path, phases: &[PhaseEvent]) -> std::io::Result<()> {
    let mut file = File::create(result_dir.join("per_phase.csv"))?;
    writeln!(file, "phase,start_ms,duration_ms")?;
    for phase in phases {
        writeln!(
            file,
            "{},{:.3},{:.3}",
            phase.name, phase.start_ms, phase.duration_ms
        )?;
    }
    Ok(())
}

fn write_comm_matrix(result_dir: &Path, counters: &CommunicationCounters) -> std::io::Result<()> {
    let mut file = File::create(result_dir.join("comm_matrix.csv"))?;
    writeln!(
        file,
        "src,dst,serialized_payload_bytes,framed_bytes,messages"
    )?;
    for edge in &counters.edges {
        writeln!(
            file,
            "{},{},{},{},{}",
            edge.src, edge.dst, edge.serialized_payload_bytes, edge.framed_bytes, edge.messages
        )?;
    }
    Ok(())
}

fn write_rank_csv(
    result_dir: &Path,
    config: &ResolvedConfig,
    output: &ExperimentOutput,
) -> std::io::Result<()> {
    let mut file = File::create(result_dir.join("per_rank.csv"))?;
    writeln!(
        file,
        "rank,pid,total_time_ms,compute_time_ms,serialized_sent_bytes,serialized_recv_bytes,thread_budget,qos_class,qos_applied"
    )?;
    for rank in 0..config.original.roles.prover_ranks {
        let rank_output = output.ranks.iter().find(|item| item.rank == rank);
        let sent = output
            .communication
            .edges
            .iter()
            .filter(|edge| edge.src as usize == rank)
            .map(|edge| edge.serialized_payload_bytes)
            .sum::<u64>();
        let recv = output
            .communication
            .edges
            .iter()
            .filter(|edge| edge.dst as usize == rank)
            .map(|edge| edge.serialized_payload_bytes)
            .sum::<u64>();
        let pid = rank_output.map_or(0, |item| item.pid);
        let total_ms =
            rank_output.map_or(output.prover_critical_path_ms, |item| item.total_time_ms);
        let thread_budget = rank_output.map_or(config.original.resources.worker_threads, |item| {
            item.thread_budget
        });
        let qos_class = rank_output
            .and_then(|item| item.qos_class.as_deref())
            .unwrap_or("");
        let qos_applied = rank_output.is_some_and(|item| item.qos_applied);
        writeln!(
            file,
            "{rank},{pid},{total_ms:.3},{total_ms:.3},{sent},{recv},{thread_budget},{qos_class},{qos_applied}"
        )?;
    }
    Ok(())
}

fn write_memory_csv(
    result_dir: &Path,
    config: &ResolvedConfig,
    output: &ExperimentOutput,
) -> std::io::Result<()> {
    let mut file = File::create(result_dir.join("memory_timeseries.csv"))?;
    writeln!(file, "rank,time_ms,resident_bytes,source")?;
    for rank in 0..config.original.roles.prover_ranks {
        let rank_output = output.ranks.iter().find(|item| item.rank == rank);
        let resident = rank_output
            .and_then(|item| item.resident_bytes)
            .unwrap_or(0);
        let source = rank_output.map_or("unavailable", |item| item.memory_source.as_str());
        writeln!(file, "{rank},0,{resident},{source}")?;
    }
    Ok(())
}

fn write_perf_csv(result_dir: &Path, config: &ResolvedConfig) -> std::io::Result<()> {
    let mut file = File::create(result_dir.join("perf_counters.csv"))?;
    writeln!(file, "rank,event,value,source")?;
    for rank in 0..config.original.roles.prover_ranks {
        writeln!(file, "{rank},perf_event_open,0,not_collected")?;
    }
    Ok(())
}

fn write_chrome_trace(result_dir: &Path, phases: &[PhaseEvent]) -> std::io::Result<()> {
    let events = phases
        .iter()
        .map(|phase| {
            serde_json::json!({
                "name": phase.name,
                "cat": "phase",
                "ph": "X",
                "ts": phase.start_ms * 1000.0,
                "dur": phase.duration_ms * 1000.0,
                "pid": 0,
                "tid": 0
            })
        })
        .collect::<Vec<_>>();
    write_json_pretty(
        &result_dir.join("chrome_trace.json"),
        &serde_json::json!({"traceEvents": events}),
    )
}

fn write_html_report(
    result_dir: &Path,
    config: &ResolvedConfig,
    output: &ExperimentOutput,
) -> std::io::Result<()> {
    let warning = if config.capability.requires_best_effort_warning() {
        "<p><strong>Warning:</strong> macOS Apple Silicon backend uses best-effort resource isolation.</p>"
    } else {
        ""
    };
    let html = format!(
        "<!doctype html><meta charset=\"utf-8\"><title>DistZKBench report</title><h1>{}</h1>{}<table><tr><th>platform</th><td>{}</td></tr><tr><th>isolation</th><td>{}</td></tr><tr><th>communication precision</th><td>{}</td></tr><tr><th>proof bytes</th><td>{}</td></tr><tr><th>protocol bytes</th><td>{}</td></tr></table>",
        config.original.experiment.name,
        warning,
        config.platform.as_str(),
        config.isolation_tier.as_str(),
        output.communication_precision,
        output.proof.bytes.len(),
        output.communication.total_payload_bytes()
    );
    fs::write(result_dir.join("report.html"), html)
}

fn io_err(error: impl std::fmt::Display) -> std::io::Error {
    std::io::Error::other(error.to_string())
}

use std::cell::RefCell;
use std::collections::{BTreeSet, HashMap, hash_map::Entry};
use std::env;
use std::fmt::{Display, Formatter};
use std::fs;
use std::io::{self, BufRead, Write};
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::{self, Child, Command, Stdio};
use std::thread;
use std::time::SystemTime;
use std::time::{Duration, Instant};

use pq_core::{FieldElement, Partition, R1CS, SparseEntry, SparseMatrix};
use pq_net::{
    Message, R1csSparkClaimRequest, Response, TcpWorkerRuntime, WorkerRuntime, message_wire_bytes,
    pcs_worker_commit, pcs_worker_open, ping, r1cs_spark_worker_claim, register,
    response_wire_bytes, run_worker, spawn_loopback_worker,
};
use pq_pcs::{
    CompactDistributedOpening, DistributedBrakedown, DistributedCommitment, DistributedOpening,
    DistributedPcs, DistributedPcsParams, PcsError, WorkerOpening, WorkerOpeningRequest,
    communication_bytes as pcs_communication_bytes,
    compact_communication_bytes as compact_pcs_communication_bytes,
    compact_proof_size_bytes as compact_pcs_proof_size_bytes, distributed_commitment_size_bytes,
    proof_size_bytes as pcs_proof_size_bytes,
};
use pq_piop_plonkish::{
    PlonkishInstance, PlonkishPcsOpening, PlonkishPhaseTiming, PlonkishPiopError,
    PlonkishPiopProof, collect_plonkish_phase_timings,
    proof_communication_bytes as plonkish_proof_communication_bytes,
    proof_size_breakdown as plonkish_proof_size_breakdown, prove_plonkish_with_pcs_hooks,
    prove_plonkish_with_pcs_params, sample_plonkish_instance, verify_plonkish_with_pcs_params,
};
use pq_piop_r1cs::{
    R1csBatchProverHooks, R1csPcsOpening, R1csPhaseTiming, R1csPiopError, R1csPiopProof,
    SparkWorkerClaimRequest, SparkWorkerShardClaim, collect_r1cs_phase_timings,
    proof_communication_bytes as r1cs_proof_communication_bytes,
    proof_size_breakdown as r1cs_proof_size_breakdown, proof_size_bytes as r1cs_proof_size_bytes,
    prove_r1cs_with_pcs_and_spark_batch_hooks, prove_r1cs_with_pcs_params,
    verify_r1cs_with_pcs_params,
};
use pq_transcript::{HashTranscript, Transcript, sha256};
use serde::{Deserialize, Serialize};

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
enum Protocol {
    R1cs,
    Plonkish,
}

impl Protocol {
    fn as_str(self) -> &'static str {
        match self {
            Self::R1cs => "r1cs",
            Self::Plonkish => "plonkish",
        }
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
enum OutputFormat {
    Json,
    Csv,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
enum CaseSelection {
    Positive,
    Negative,
    Both,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
enum InteractiveMode {
    Local,
    NetProof,
}

#[derive(Clone, Debug)]
struct Config {
    protocol: Protocol,
    workers: usize,
    size: usize,
    format: OutputFormat,
    case: CaseSelection,
    pcs_queries: usize,
    worker_core_plan: Option<WorkerCorePlan>,
}

#[derive(Clone, Debug)]
struct WorkerCommand {
    addr: String,
    id: usize,
}

#[derive(Clone, Debug)]
struct MasterCommand {
    addrs: Vec<String>,
    ids: Vec<usize>,
    session: String,
    payload: String,
    shutdown: bool,
    format: OutputFormat,
    protocol: Option<Protocol>,
    size: usize,
    case: CaseSelection,
    pcs_queries: usize,
}

#[derive(Clone, Debug)]
struct NetDemoCommand {
    workers: usize,
    session: String,
    payload: String,
    format: OutputFormat,
}

#[derive(Clone, Debug)]
struct BenchmarkCommand {
    sizes: Vec<usize>,
    workers: Vec<usize>,
    pcs_queries: usize,
    repeats: usize,
    paper_preset: bool,
    runner: BenchmarkRunner,
    compile_figures: bool,
    figure_compiler: FigureCompiler,
    out_dir: PathBuf,
    host_logical_cores: Option<usize>,
    worker_cores: Option<usize>,
    worker_core_plan: Option<WorkerCorePlan>,
}

#[derive(Clone, Debug)]
struct PcsBenchmarkCommand {
    sizes: Vec<usize>,
    workers: Vec<usize>,
    pcs_queries: usize,
    repeats: usize,
    runner: BenchmarkRunner,
    opening: PcsOpeningSelection,
    out_dir: PathBuf,
    host_logical_cores: Option<usize>,
    worker_cores: Option<usize>,
    worker_core_plan: Option<WorkerCorePlan>,
    warmup_enabled: bool,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
enum PcsOpeningSelection {
    Compact,
    Full,
    Both,
}

impl PcsOpeningSelection {
    fn as_str(self) -> &'static str {
        match self {
            Self::Compact => "compact",
            Self::Full => "full",
            Self::Both => "both",
        }
    }

    fn variants(self) -> Vec<PcsOpeningVariant> {
        match self {
            Self::Compact => vec![PcsOpeningVariant::Compact],
            Self::Full => vec![PcsOpeningVariant::Full],
            Self::Both => vec![PcsOpeningVariant::Compact, PcsOpeningVariant::Full],
        }
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
enum PcsOpeningVariant {
    Compact,
    Full,
}

impl PcsOpeningVariant {
    fn as_str(self) -> &'static str {
        match self {
            Self::Compact => "compact",
            Self::Full => "full",
        }
    }
}

#[derive(Clone, Debug)]
struct ProofExperimentCommand {
    protocol: ProofProtocolSelection,
    runner: BenchmarkRunner,
    size: usize,
    workers: usize,
    pcs_queries: usize,
    out_dir: PathBuf,
    format: OutputFormat,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
enum ProofProtocolSelection {
    R1cs,
    Plonkish,
    Both,
}

impl ProofProtocolSelection {
    fn variants(self) -> Vec<Protocol> {
        match self {
            Self::R1cs => vec![Protocol::R1cs],
            Self::Plonkish => vec![Protocol::Plonkish],
            Self::Both => vec![Protocol::R1cs, Protocol::Plonkish],
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            Self::R1cs => "r1cs",
            Self::Plonkish => "plonkish",
            Self::Both => "both",
        }
    }
}

#[derive(Clone, Debug)]
struct ListProofsCommand {
    results_dir: PathBuf,
    format: ProofListFormat,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
enum ProofListFormat {
    Text,
    Json,
    Csv,
}

#[derive(Clone, Debug)]
struct VerifyProofCommand {
    dir: PathBuf,
    proof: ProofSelection,
    format: OutputFormat,
}

#[derive(Clone, Debug)]
enum ProofSelection {
    All,
    One(String),
}

#[derive(Clone, Debug)]
struct ProofListEntry {
    dir: PathBuf,
    bench_name: String,
    proof_count: usize,
    invalid_proof_count: usize,
    proof_ids: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct ProofIndexEntry {
    proof_id: String,
    path: String,
    protocol: String,
    runner: String,
    case_name: String,
    trial: usize,
    nv_power: usize,
    size: usize,
    workers: usize,
    pcs_queries: usize,
    proof_bytes: usize,
    communication_bytes: usize,
    network_bytes: usize,
    file_bytes: usize,
    sha256: String,
}

#[derive(Clone, Debug, Deserialize)]
struct ProofIndexFile {
    schema_version: usize,
    generated_by: String,
    proof_count: usize,
    proofs: Vec<ProofIndexEntry>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct ProofBundle {
    schema_version: usize,
    proof_id: String,
    run_kind: String,
    generated_utc: String,
    protocol: String,
    runner: String,
    case_name: String,
    trial: usize,
    nv_power: usize,
    size: usize,
    workers: usize,
    pcs_queries: usize,
    proof_bytes: usize,
    communication_bytes: usize,
    network_bytes: usize,
    #[serde(default)]
    stage_breakdown: StageBreakdown,
    host_logical_cores: Option<usize>,
    cores_per_worker: Option<usize>,
    core_affinity: Option<String>,
    proof: StoredProof,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "protocol", content = "proof")]
enum StoredProof {
    #[serde(rename = "r1cs")]
    R1cs(Box<R1csPiopProof>),
    #[serde(rename = "plonkish")]
    Plonkish(Box<PlonkishPiopProof>),
}

#[derive(Clone, Debug)]
struct ProofVerificationOutcome {
    proof_id: String,
    path: PathBuf,
    protocol: String,
    runner: String,
    size: usize,
    workers: usize,
    pcs_queries: usize,
    verified: bool,
    verify_ms: f64,
    proof_bytes: usize,
    communication_bytes: usize,
    failure_reason: Option<String>,
}

#[derive(Clone, Debug)]
struct ProofVerifyReport {
    bench_dir: PathBuf,
    report_json: PathBuf,
    report_html: PathBuf,
    outcomes: Vec<ProofVerificationOutcome>,
}

#[derive(Clone, Debug)]
struct WorkerCorePlan {
    host_logical_cores: usize,
    max_workers: usize,
    cores_per_worker: usize,
}

impl WorkerCorePlan {
    fn core_ids_for_worker(&self, worker_id: usize) -> Vec<usize> {
        let start = worker_id * self.cores_per_worker;
        (start..start + self.cores_per_worker).collect()
    }
}

fn worker_affinity_mode() -> &'static str {
    if cfg!(target_os = "linux") {
        "linux-taskset"
    } else if cfg!(target_os = "windows") {
        "windows-powershell-processor-affinity"
    } else {
        "unsupported"
    }
}

#[derive(Clone, Debug)]
struct VerifyResultsCommand {
    dir: PathBuf,
    format: OutputFormat,
    paper_quality: bool,
}

#[derive(Clone, Debug)]
struct QuickSmokeCommand {
    out_dir: PathBuf,
}

#[derive(Clone, Debug)]
struct ResultManifestEntry {
    path: String,
    bytes: usize,
    sha256: String,
}

#[derive(Clone, Debug)]
struct ResultManifestReport {
    dir: PathBuf,
    run_id: u64,
    files_checked: usize,
    bytes_checked: usize,
    source_rows_checked: usize,
    phase_rows_checked: usize,
    summary_rows_checked: usize,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
enum BenchmarkRunner {
    Local,
    Network,
    Both,
}

impl BenchmarkRunner {
    fn as_str(self) -> &'static str {
        match self {
            Self::Local => "local",
            Self::Network => "network",
            Self::Both => "both",
        }
    }

    fn variants(self) -> Vec<BenchmarkRunner> {
        match self {
            Self::Local => vec![Self::Local],
            Self::Network => vec![Self::Network],
            Self::Both => vec![Self::Local, Self::Network],
        }
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
enum FigureCompiler {
    Auto,
    PdfLatex,
    Tectonic,
}

impl FigureCompiler {
    fn as_str(self) -> &'static str {
        match self {
            Self::Auto => "auto",
            Self::PdfLatex => "pdflatex",
            Self::Tectonic => "tectonic",
        }
    }
}

const BASE_BENCHMARK_ARTIFACTS: &[&str] = &[
    "metadata.json",
    RESULT_MANIFEST,
    OVERVIEW_HTML,
    "phase_timing.csv",
    "phase_timing.json",
    "source.csv",
    "source.json",
    "summary_stats.csv",
    "summary.txt",
    "prove_time_by_size.svg",
    "prove_time_by_size.tex",
    "verify_time_by_size.svg",
    "verify_time_by_size.tex",
    "proof_bytes_by_size.svg",
    "proof_bytes_by_size.tex",
    "network_bytes_by_size.svg",
    "network_bytes_by_size.tex",
    "runner_overhead_by_size.svg",
    "runner_overhead_by_size.tex",
    "worker_scaling_max_size.svg",
    "worker_scaling_max_size.tex",
    "paper_figures.tex",
    "paper_figures_standalone.tex",
];

const PCS_BENCHMARK_ARTIFACTS: &[&str] = &[
    "metadata.json",
    RESULT_MANIFEST,
    OVERVIEW_HTML,
    "phase_timing.csv",
    "phase_timing.json",
    "source.csv",
    "source.json",
    "summary_stats.csv",
    "summary.txt",
    "commit_time_by_size.svg",
    "commit_time_by_size.tex",
    "open_time_by_size.svg",
    "open_time_by_size.tex",
    "verify_time_by_size.svg",
    "verify_time_by_size.tex",
    "opening_bytes_by_size.svg",
    "opening_bytes_by_size.tex",
    "network_bytes_by_size.svg",
    "network_bytes_by_size.tex",
    "worker_scaling_max_size.svg",
    "worker_scaling_max_size.tex",
    "local_commit_time_by_size.svg",
    "local_commit_time_by_size.tex",
    "local_open_time_by_size.svg",
    "local_open_time_by_size.tex",
    "local_verify_time_by_size.svg",
    "local_verify_time_by_size.tex",
    "local_opening_bytes_by_size.svg",
    "local_opening_bytes_by_size.tex",
    "local_network_bytes_by_size.svg",
    "local_network_bytes_by_size.tex",
    "local_worker_scaling_max_size.svg",
    "local_worker_scaling_max_size.tex",
    "network_commit_time_by_size.svg",
    "network_commit_time_by_size.tex",
    "network_open_time_by_size.svg",
    "network_open_time_by_size.tex",
    "network_verify_time_by_size.svg",
    "network_verify_time_by_size.tex",
    "network_opening_bytes_by_size.svg",
    "network_opening_bytes_by_size.tex",
    "network_network_bytes_by_size.svg",
    "network_network_bytes_by_size.tex",
    "network_worker_scaling_max_size.svg",
    "network_worker_scaling_max_size.tex",
];

const COMPILED_PAPER_FIGURE: &str = "paper_figures_standalone.pdf";
const RESULT_MANIFEST: &str = "result_manifest.json";
const OVERVIEW_HTML: &str = "overview.html";
const SOURCE_CSV_HEADER: &str = "protocol,runner,case,trial,workers,nv_power,size,constraints,pcs_queries,prove_ms,verify_ms,prove_pcs_commit_ms,prove_sumcheck_ms,prove_batch_open_ms,prove_other_ms,verify_pcs_open_ms,verify_sumcheck_ms,verify_other_ms,proof_bytes,proof_pcs_bytes,proof_sumcheck_bytes,proof_other_bytes,communication_bytes,network_bytes,host_logical_cores,cores_per_worker,core_affinity,verified,failure_reason";
const PCS_SOURCE_CSV_HEADER: &str = "runner,opening,trial,workers,nv_power,size,t_rows_per_worker,paper_b_target,shard_len,pcs_queries_requested,pcs_queries_effective,partition_ms,worker_commit_ms,master_commit_ms,commit_ms,open_ms,verify_ms,commitment_bytes,opening_proof_bytes,communication_bytes,network_commit_bytes,network_open_bytes,network_bytes,host_logical_cores,cores_per_worker,core_affinity,verified,failure_reason";
const PHASE_TIMING_CSV_HEADER: &str =
    "phase,detail,elapsed_ms,recorded_prove_ms,recorded_verify_ms,inferred_overhead_ms";
const SUMMARY_STATS_CSV_HEADER: &str = "protocol,runner,case,workers,nv_power,size,constraints,pcs_queries,samples,verified_count,rejected_count,prove_ms_mean,prove_ms_stddev,verify_ms_mean,verify_ms_stddev,prove_pcs_commit_ms_mean,prove_sumcheck_ms_mean,prove_batch_open_ms_mean,verify_pcs_open_ms_mean,verify_sumcheck_ms_mean,proof_bytes_mean,proof_bytes_stddev,proof_pcs_bytes_mean,proof_sumcheck_bytes_mean,proof_other_bytes_mean,communication_bytes_mean,communication_bytes_stddev,network_bytes_mean,network_bytes_stddev,failure_reasons";
const PCS_SUMMARY_STATS_CSV_HEADER: &str = "runner,opening,workers,nv_power,size,samples,verified_count,commit_ms_mean,commit_ms_stddev,open_ms_mean,open_ms_stddev,verify_ms_mean,verify_ms_stddev,opening_proof_bytes_mean,communication_bytes_mean,network_bytes_mean,failure_reasons";
const PAPER_PRESET_NV_START: usize = 2;
const PAPER_PRESET_NV_END: usize = 6;
const PAPER_PRESET_WORKERS: &[usize] = &[1, 2, 4];
const PAPER_PRESET_PCS_QUERIES: usize = 3;
const BENCHMARK_REPEATS: usize = 1;

const PGFPLOTS_PREAMBLE_COMMENT: &str =
    "% Generated by pq-experiments from measured benchmark records; no fitted data.\n";

const PGFPLOTS_COLOR_DEFINITIONS: [&str; 6] = [
    "\\definecolor{pqR1CS}{HTML}{0072B2}",
    "\\definecolor{pqPlonkish}{HTML}{D55E00}",
    "\\definecolor{pqGreen}{HTML}{009E73}",
    "\\definecolor{pqPurple}{HTML}{CC79A7}",
    "\\definecolor{pqGold}{HTML}{E69F00}",
    "\\definecolor{pqIdeal}{HTML}{6B7280}",
];

#[derive(Clone, Debug)]
enum InteractiveSelection {
    Experiment {
        mode: InteractiveMode,
        config: Config,
    },
    NetDemo(NetDemoCommand),
}

#[derive(Clone, Debug)]
struct MetricRecord {
    protocol: &'static str,
    runner: &'static str,
    case_name: &'static str,
    trial: usize,
    workers: usize,
    size: usize,
    constraints: usize,
    prove_ms: f64,
    verify_ms: f64,
    stages: StageBreakdown,
    proof_bytes: usize,
    communication_bytes: usize,
    network_bytes: usize,
    pcs_queries: usize,
    host_logical_cores: Option<usize>,
    cores_per_worker: Option<usize>,
    core_affinity: Option<&'static str>,
    verified: bool,
    failure_reason: Option<String>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
struct StageBreakdown {
    prove_pcs_commit_ms: f64,
    prove_sumcheck_ms: f64,
    prove_batch_open_ms: f64,
    prove_other_ms: f64,
    verify_pcs_open_ms: f64,
    verify_sumcheck_ms: f64,
    verify_other_ms: f64,
    proof_pcs_bytes: usize,
    proof_sumcheck_bytes: usize,
    proof_other_bytes: usize,
}

#[derive(Clone, Debug)]
struct PhaseTimingRecord {
    phase: String,
    detail: String,
    elapsed_ms: f64,
    recorded_prove_ms: f64,
    recorded_verify_ms: f64,
    inferred_overhead_ms: f64,
}

#[derive(Copy, Clone, Debug)]
struct MeanStddev {
    mean: f64,
    stddev: f64,
}

#[derive(Clone, Debug)]
struct BenchmarkStatsRecord {
    protocol: &'static str,
    runner: &'static str,
    case_name: &'static str,
    workers: usize,
    size: usize,
    constraints: usize,
    pcs_queries: usize,
    samples: usize,
    verified_count: usize,
    rejected_count: usize,
    prove_ms: MeanStddev,
    verify_ms: MeanStddev,
    prove_pcs_commit_ms: MeanStddev,
    prove_sumcheck_ms: MeanStddev,
    prove_batch_open_ms: MeanStddev,
    verify_pcs_open_ms: MeanStddev,
    verify_sumcheck_ms: MeanStddev,
    proof_bytes: MeanStddev,
    proof_pcs_bytes: MeanStddev,
    proof_sumcheck_bytes: MeanStddev,
    proof_other_bytes: MeanStddev,
    communication_bytes: MeanStddev,
    network_bytes: MeanStddev,
    failure_reasons: Vec<String>,
}

#[derive(Clone, Debug)]
struct NetMetricRecord {
    mode: &'static str,
    workers: usize,
    round_ms: f64,
    communication_bytes: usize,
    replies: Vec<String>,
    ok: bool,
}

#[derive(Clone, Debug)]
struct PcsMetricRecord {
    runner: &'static str,
    opening: &'static str,
    trial: usize,
    workers: usize,
    size: usize,
    t_rows_per_worker: f64,
    paper_b_target: usize,
    shard_len: usize,
    pcs_queries_requested: usize,
    pcs_queries_effective: usize,
    partition_ms: f64,
    worker_commit_ms: f64,
    master_commit_ms: f64,
    commit_ms: f64,
    open_ms: f64,
    verify_ms: f64,
    commitment_bytes: usize,
    opening_proof_bytes: usize,
    communication_bytes: usize,
    network_commit_bytes: usize,
    network_open_bytes: usize,
    network_bytes: usize,
    host_logical_cores: Option<usize>,
    cores_per_worker: Option<usize>,
    core_affinity: Option<&'static str>,
    verified: bool,
    failure_reason: Option<String>,
}

#[derive(Clone, Debug)]
struct PcsStatsRecord {
    runner: &'static str,
    opening: &'static str,
    workers: usize,
    size: usize,
    samples: usize,
    verified_count: usize,
    commit_ms: MeanStddev,
    open_ms: MeanStddev,
    verify_ms: MeanStddev,
    opening_proof_bytes: MeanStddev,
    communication_bytes: MeanStddev,
    network_bytes: MeanStddev,
    failure_reasons: Vec<String>,
}

#[derive(Debug)]
struct CliError(String);

impl Display for CliError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

fn main() {
    if let Err(error) = run() {
        if is_usage_help(&error) {
            println!("{error}");
        } else {
            eprintln!("{error}");
        }
        process::exit(cli_exit_code(&error));
    }
}

fn cli_exit_code(error: &CliError) -> i32 {
    if is_usage_help(error) { 0 } else { 2 }
}

fn is_usage_help(error: &CliError) -> bool {
    error.0.starts_with("usage:\n")
}

fn run() -> Result<(), CliError> {
    let args = env::args().skip(1).collect::<Vec<_>>();
    if args.first().map(String::as_str) == Some("worker") {
        return run_worker_command(&args[1..]);
    }
    if args.first().map(String::as_str) == Some("master") {
        return run_master_command(&args[1..]);
    }
    if args.first().map(String::as_str) == Some("net-demo") {
        return run_net_demo_command(&args[1..]);
    }
    if args.first().map(String::as_str) == Some("interactive") {
        return run_interactive_command();
    }
    if args.first().map(String::as_str) == Some("benchmark") {
        return run_benchmark_command(&args[1..]);
    }
    if args.first().map(String::as_str) == Some("pcs-benchmark") {
        return run_pcs_benchmark_command(&args[1..]);
    }
    if args.first().map(String::as_str) == Some("quick-smoke") {
        return run_quick_smoke_command(&args[1..]);
    }
    if args.first().map(String::as_str) == Some("proof-experiment") {
        return run_proof_experiment_command(&args[1..]);
    }
    if args.first().map(String::as_str) == Some("list-proofs") {
        return run_list_proofs_command(&args[1..]);
    }
    if args.first().map(String::as_str) == Some("verify-proof") {
        return run_verify_proof_command(&args[1..]);
    }
    if args.first().map(String::as_str) == Some("verify-results") {
        return run_verify_results_command(&args[1..]);
    }
    if args.first().map(String::as_str) == Some("verify-pcs-results") {
        return run_verify_pcs_results_command(&args[1..]);
    }

    let config = parse_args(args)?;
    let records = match config.protocol {
        Protocol::R1cs => run_r1cs(&config)?,
        Protocol::Plonkish => run_plonkish(&config)?,
    };
    print_records(&records, config.format);
    Ok(())
}

fn parse_args(args: Vec<String>) -> Result<Config, CliError> {
    if args.is_empty() {
        return Err(CliError(usage()));
    }

    let protocol = match args[0].as_str() {
        "help" | "--help" | "-h" => return Err(CliError(usage())),
        value => parse_protocol(value)?,
    };

    let mut config = Config {
        protocol,
        workers: 1,
        size: 8,
        format: OutputFormat::Json,
        case: CaseSelection::Both,
        pcs_queries: DistributedPcsParams::DEFAULT_QUERY_COUNT,
        worker_core_plan: None,
    };

    let mut index = 1;
    while index < args.len() {
        match args[index].as_str() {
            "--workers" => {
                let value = next_value(&args, &mut index, "--workers")?;
                config.workers = parse_positive_usize(value, "--workers")?;
            }
            "--size" => {
                let value = next_value(&args, &mut index, "--size")?;
                config.size = parse_positive_usize(value, "--size")?;
            }
            "--format" => {
                let value = next_value(&args, &mut index, "--format")?;
                config.format = match value {
                    "json" => OutputFormat::Json,
                    "csv" => OutputFormat::Csv,
                    other => {
                        return Err(CliError(format!(
                            "unsupported --format '{other}', expected json or csv"
                        )));
                    }
                };
            }
            "--case" => {
                let value = next_value(&args, &mut index, "--case")?;
                config.case = parse_case(value)?;
            }
            "--pcs-queries" => {
                let value = next_value(&args, &mut index, "--pcs-queries")?;
                config.pcs_queries = parse_positive_usize(value, "--pcs-queries")?;
            }
            other => return Err(CliError(format!("unknown argument '{other}'\n{}", usage()))),
        }
        index += 1;
    }

    Ok(config)
}

fn parse_worker_command(args: &[String]) -> Result<WorkerCommand, CliError> {
    let mut command = WorkerCommand {
        addr: "127.0.0.1:9000".to_string(),
        id: 0,
    };
    let mut index = 0;
    while index < args.len() {
        match args[index].as_str() {
            "--addr" => {
                command.addr = next_value(args, &mut index, "--addr")?.to_string();
            }
            "--id" => {
                command.id = parse_usize(next_value(args, &mut index, "--id")?, "--id")?;
            }
            "--help" | "-h" => return Err(CliError(usage())),
            other => return Err(CliError(format!("unknown worker argument '{other}'"))),
        }
        index += 1;
    }
    Ok(command)
}

fn parse_master_command(args: &[String]) -> Result<MasterCommand, CliError> {
    let mut addrs = Vec::new();
    let mut ids = Vec::new();
    let mut session = "net-session".to_string();
    let mut payload = "round-payload".to_string();
    let mut shutdown = false;
    let mut format = OutputFormat::Json;
    let mut protocol = None;
    let mut size = 8;
    let mut case = CaseSelection::Both;
    let mut pcs_queries = DistributedPcsParams::DEFAULT_QUERY_COUNT;

    let mut index = 0;
    while index < args.len() {
        match args[index].as_str() {
            "--addrs" => {
                addrs = parse_csv_strings(next_value(args, &mut index, "--addrs")?)?;
            }
            "--ids" => {
                ids = parse_csv_usizes(next_value(args, &mut index, "--ids")?, "--ids")?;
            }
            "--session" => {
                session = next_value(args, &mut index, "--session")?.to_string();
            }
            "--payload" => {
                payload = next_value(args, &mut index, "--payload")?.to_string();
            }
            "--format" => {
                format = parse_format(next_value(args, &mut index, "--format")?)?;
            }
            "--protocol" => {
                protocol = Some(parse_protocol(next_value(args, &mut index, "--protocol")?)?);
            }
            "--size" => {
                size = parse_positive_usize(next_value(args, &mut index, "--size")?, "--size")?;
            }
            "--case" => {
                case = parse_case(next_value(args, &mut index, "--case")?)?;
            }
            "--pcs-queries" => {
                pcs_queries = parse_positive_usize(
                    next_value(args, &mut index, "--pcs-queries")?,
                    "--pcs-queries",
                )?;
            }
            "--shutdown" => {
                shutdown = true;
            }
            "--help" | "-h" => return Err(CliError(usage())),
            other => return Err(CliError(format!("unknown master argument '{other}'"))),
        }
        index += 1;
    }

    if addrs.is_empty() {
        return Err(CliError("master requires --addrs".to_string()));
    }
    if ids.is_empty() {
        ids = (0..addrs.len()).collect();
    }
    if ids.len() != addrs.len() {
        return Err(CliError(
            "--ids length must match --addrs length".to_string(),
        ));
    }

    Ok(MasterCommand {
        addrs,
        ids,
        session,
        payload,
        shutdown,
        format,
        protocol,
        size,
        case,
        pcs_queries,
    })
}

fn parse_net_demo_command(args: &[String]) -> Result<NetDemoCommand, CliError> {
    let mut command = NetDemoCommand {
        workers: 2,
        session: "net-demo".to_string(),
        payload: "payload".to_string(),
        format: OutputFormat::Json,
    };

    let mut index = 0;
    while index < args.len() {
        match args[index].as_str() {
            "--workers" => {
                command.workers =
                    parse_positive_usize(next_value(args, &mut index, "--workers")?, "--workers")?;
            }
            "--session" => {
                command.session = next_value(args, &mut index, "--session")?.to_string();
            }
            "--payload" => {
                command.payload = next_value(args, &mut index, "--payload")?.to_string();
            }
            "--format" => {
                command.format = parse_format(next_value(args, &mut index, "--format")?)?;
            }
            "--help" | "-h" => return Err(CliError(usage())),
            other => return Err(CliError(format!("unknown net-demo argument '{other}'"))),
        }
        index += 1;
    }

    Ok(command)
}

fn parse_benchmark_command(args: &[String]) -> Result<BenchmarkCommand, CliError> {
    let paper_preset = args.iter().any(|arg| arg == "--paper-preset");
    let mut command = BenchmarkCommand {
        sizes: if paper_preset {
            (PAPER_PRESET_NV_START..=PAPER_PRESET_NV_END)
                .map(|power| 1_usize << power)
                .collect()
        } else {
            vec![4, 8, 16]
        },
        workers: PAPER_PRESET_WORKERS.to_vec(),
        pcs_queries: PAPER_PRESET_PCS_QUERIES,
        repeats: BENCHMARK_REPEATS,
        paper_preset,
        runner: BenchmarkRunner::Local,
        compile_figures: false,
        figure_compiler: FigureCompiler::Auto,
        out_dir: PathBuf::from("results"),
        host_logical_cores: None,
        worker_cores: None,
        worker_core_plan: None,
    };

    let mut index = 0;
    while index < args.len() {
        match args[index].as_str() {
            "--sizes" => {
                command.sizes =
                    parse_csv_usizes(next_value(args, &mut index, "--sizes")?, "--sizes")?;
            }
            flag @ ("--nv-powers" | "--n-values") => {
                command.sizes =
                    parse_nv_powers_to_sizes(next_value(args, &mut index, flag)?, flag)?;
            }
            flag @ ("--nv-range" | "--n-range") => {
                command.sizes = parse_nv_range_to_sizes(next_value(args, &mut index, flag)?, flag)?;
            }
            "--size-range" => {
                command.sizes =
                    parse_size_range_to_sizes(next_value(args, &mut index, "--size-range")?)?;
            }
            "--workers" => {
                command.workers =
                    parse_csv_usizes(next_value(args, &mut index, "--workers")?, "--workers")?;
            }
            "--worker-power-range" => {
                command.workers = parse_worker_power_range_to_workers(next_value(
                    args,
                    &mut index,
                    "--worker-power-range",
                )?)?;
            }
            "--pcs-queries" => {
                command.pcs_queries = parse_positive_usize(
                    next_value(args, &mut index, "--pcs-queries")?,
                    "--pcs-queries",
                )?;
            }
            "--repeats" => {
                command.repeats =
                    parse_positive_usize(next_value(args, &mut index, "--repeats")?, "--repeats")?;
            }
            "--compile-figures" => {
                command.compile_figures = true;
            }
            "--figure-compiler" => {
                command.figure_compiler =
                    parse_figure_compiler(next_value(args, &mut index, "--figure-compiler")?)?;
            }
            "--paper-preset" => {
                command.paper_preset = true;
            }
            "--runner" => {
                command.runner = parse_benchmark_runner(next_value(args, &mut index, "--runner")?)?;
            }
            "--out" => {
                command.out_dir = PathBuf::from(next_value(args, &mut index, "--out")?);
            }
            "--host-cores" => {
                command.host_logical_cores = Some(parse_positive_usize(
                    next_value(args, &mut index, "--host-cores")?,
                    "--host-cores",
                )?);
            }
            "--worker-cores" => {
                command.worker_cores = Some(parse_positive_usize(
                    next_value(args, &mut index, "--worker-cores")?,
                    "--worker-cores",
                )?);
            }
            "--help" | "-h" => return Err(CliError(usage())),
            other => return Err(CliError(format!("unknown benchmark argument '{other}'"))),
        }
        index += 1;
    }

    normalize_unique(&mut command.sizes);
    normalize_unique(&mut command.workers);
    validate_benchmark_command(&command)?;
    Ok(command)
}

fn parse_pcs_benchmark_command(args: &[String]) -> Result<PcsBenchmarkCommand, CliError> {
    let mut command = PcsBenchmarkCommand {
        sizes: vec![256, 512, 1024],
        workers: PAPER_PRESET_WORKERS.to_vec(),
        pcs_queries: 1,
        repeats: 1,
        runner: BenchmarkRunner::Both,
        opening: PcsOpeningSelection::Compact,
        out_dir: PathBuf::from("results"),
        host_logical_cores: None,
        worker_cores: None,
        worker_core_plan: None,
        warmup_enabled: true,
    };

    let mut index = 0;
    while index < args.len() {
        match args[index].as_str() {
            "--sizes" => {
                command.sizes =
                    parse_csv_usizes(next_value(args, &mut index, "--sizes")?, "--sizes")?;
            }
            flag @ ("--nv-powers" | "--n-values") => {
                command.sizes =
                    parse_nv_powers_to_sizes(next_value(args, &mut index, flag)?, flag)?;
            }
            flag @ ("--nv-range" | "--n-range") => {
                command.sizes = parse_nv_range_to_sizes(next_value(args, &mut index, flag)?, flag)?;
            }
            "--size-range" => {
                command.sizes =
                    parse_size_range_to_sizes(next_value(args, &mut index, "--size-range")?)?;
            }
            "--workers" => {
                command.workers =
                    parse_csv_usizes(next_value(args, &mut index, "--workers")?, "--workers")?;
            }
            "--worker-power-range" => {
                command.workers = parse_worker_power_range_to_workers(next_value(
                    args,
                    &mut index,
                    "--worker-power-range",
                )?)?;
            }
            "--pcs-queries" => {
                command.pcs_queries = parse_positive_usize(
                    next_value(args, &mut index, "--pcs-queries")?,
                    "--pcs-queries",
                )?;
            }
            "--repeats" => {
                command.repeats =
                    parse_positive_usize(next_value(args, &mut index, "--repeats")?, "--repeats")?;
            }
            "--runner" => {
                command.runner = parse_benchmark_runner(next_value(args, &mut index, "--runner")?)?;
            }
            "--opening" => {
                command.opening =
                    parse_pcs_opening_selection(next_value(args, &mut index, "--opening")?)?;
            }
            "--out" => {
                command.out_dir = PathBuf::from(next_value(args, &mut index, "--out")?);
            }
            "--host-cores" => {
                command.host_logical_cores = Some(parse_positive_usize(
                    next_value(args, &mut index, "--host-cores")?,
                    "--host-cores",
                )?);
            }
            "--worker-cores" => {
                command.worker_cores = Some(parse_positive_usize(
                    next_value(args, &mut index, "--worker-cores")?,
                    "--worker-cores",
                )?);
            }
            "--no-pcs-warmup" => {
                command.warmup_enabled = false;
            }
            "--help" | "-h" => return Err(CliError(usage())),
            other => {
                return Err(CliError(format!(
                    "unknown pcs-benchmark argument '{other}'"
                )));
            }
        }
        index += 1;
    }

    normalize_unique(&mut command.sizes);
    normalize_unique(&mut command.workers);
    validate_pcs_benchmark_command(&command)?;
    Ok(command)
}

fn configure_benchmark_core_plan(command: &mut BenchmarkCommand) -> Result<(), CliError> {
    let uses_network_runner = command
        .runner
        .variants()
        .contains(&BenchmarkRunner::Network);
    if !uses_network_runner {
        return Ok(());
    }
    let max_workers = command
        .workers
        .iter()
        .copied()
        .max()
        .ok_or_else(|| CliError("benchmark --workers must not be empty".to_owned()))?;
    if command.workers.len() <= 1 && command.worker_cores.is_none() {
        return Ok(());
    }
    let host_logical_cores = match command.host_logical_cores {
        Some(value) => value,
        None => std::thread::available_parallelism()
            .map_err(|error| {
                CliError(format!(
                    "failed to detect host logical cores for network scaling: {error}"
                ))
            })?
            .get(),
    };
    let auto_cores_per_worker = host_logical_cores / max_workers;
    if auto_cores_per_worker == 0 {
        return Err(CliError(format!(
            "host has {host_logical_cores} logical cores but max workers is {max_workers}; cannot assign at least one core per worker"
        )));
    }
    let cores_per_worker = command.worker_cores.unwrap_or(auto_cores_per_worker);
    if cores_per_worker * max_workers > host_logical_cores {
        return Err(CliError(format!(
            "worker core allocation is impossible: host_logical_cores={host_logical_cores}, max_workers={max_workers}, cores_per_worker={cores_per_worker}"
        )));
    }
    command.worker_core_plan = Some(WorkerCorePlan {
        host_logical_cores,
        max_workers,
        cores_per_worker,
    });
    Ok(())
}

fn configure_pcs_benchmark_core_plan(command: &mut PcsBenchmarkCommand) -> Result<(), CliError> {
    let uses_network_runner = command
        .runner
        .variants()
        .contains(&BenchmarkRunner::Network);
    if !uses_network_runner {
        return Ok(());
    }
    let max_workers = command
        .workers
        .iter()
        .copied()
        .max()
        .ok_or_else(|| CliError("pcs-benchmark --workers must not be empty".to_owned()))?;
    if command.workers.len() <= 1 && command.worker_cores.is_none() {
        return Ok(());
    }
    let host_logical_cores = match command.host_logical_cores {
        Some(value) => value,
        None => std::thread::available_parallelism()
            .map_err(|error| {
                CliError(format!(
                    "failed to detect host logical cores for PCS network scaling: {error}"
                ))
            })?
            .get(),
    };
    let auto_cores_per_worker = host_logical_cores / max_workers;
    if auto_cores_per_worker == 0 {
        return Err(CliError(format!(
            "host has {host_logical_cores} logical cores but max workers is {max_workers}; cannot assign at least one core per PCS worker"
        )));
    }
    let cores_per_worker = command.worker_cores.unwrap_or(auto_cores_per_worker);
    if cores_per_worker == 0 {
        return Err(CliError(
            "--worker-cores must be greater than zero".to_owned(),
        ));
    }
    let required = max_workers
        .checked_mul(cores_per_worker)
        .ok_or_else(|| CliError("PCS worker core plan overflows usize".to_owned()))?;
    if required > host_logical_cores {
        return Err(CliError(format!(
            "PCS benchmark requires {required} logical cores for {max_workers} workers * {cores_per_worker} cores, but host has {host_logical_cores}"
        )));
    }
    command.worker_core_plan = Some(WorkerCorePlan {
        host_logical_cores,
        max_workers,
        cores_per_worker,
    });
    eprintln!(
        "[pcs-benchmark] network worker core plan: host_logical_cores={host_logical_cores} max_workers={max_workers} cores_per_worker={cores_per_worker} mode={}",
        worker_affinity_mode()
    );
    Ok(())
}

fn configure_benchmark_rayon_pool(command: &BenchmarkCommand) {
    let threads = benchmark_rayon_thread_count(command);
    configure_rayon_pool(threads);
}

fn configure_pcs_benchmark_rayon_pool(command: &PcsBenchmarkCommand) {
    let threads = if let Some(plan) = &command.worker_core_plan {
        (plan.cores_per_worker * plan.max_workers)
            .min(plan.host_logical_cores)
            .max(1)
    } else {
        std::thread::available_parallelism()
            .map(|threads| threads.get())
            .unwrap_or(1)
            .max(1)
    };
    configure_rayon_pool(threads);
}

fn configure_rayon_pool(threads: usize) {
    match rayon::ThreadPoolBuilder::new()
        .num_threads(threads)
        .build_global()
    {
        Ok(()) => {
            eprintln!("[pq_dSNARK] rayon worker threads configured: {threads}");
        }
        Err(error) => {
            eprintln!(
                "[pq_dSNARK] rayon global pool already active with {} threads ({error})",
                rayon::current_num_threads()
            );
        }
    }
}

fn benchmark_rayon_thread_count(command: &BenchmarkCommand) -> usize {
    if let Some(plan) = &command.worker_core_plan {
        return (plan.cores_per_worker * plan.max_workers)
            .min(plan.host_logical_cores)
            .max(1);
    }
    command
        .host_logical_cores
        .unwrap_or_else(detect_host_logical_cores)
        .max(1)
}

fn detect_host_logical_cores() -> usize {
    std::thread::available_parallelism()
        .map(|count| count.get())
        .unwrap_or(1)
}

fn worker_rayon_threads(core_ids: &[usize]) -> usize {
    core_ids.len().max(1)
}

fn parse_benchmark_runner(value: &str) -> Result<BenchmarkRunner, CliError> {
    match value {
        "local" => Ok(BenchmarkRunner::Local),
        "network" => Ok(BenchmarkRunner::Network),
        "both" => Ok(BenchmarkRunner::Both),
        other => Err(CliError(format!(
            "unsupported --runner '{other}', expected local, network, or both"
        ))),
    }
}

fn parse_pcs_opening_selection(value: &str) -> Result<PcsOpeningSelection, CliError> {
    match value {
        "compact" => Ok(PcsOpeningSelection::Compact),
        "full" => Ok(PcsOpeningSelection::Full),
        "both" => Ok(PcsOpeningSelection::Both),
        other => Err(CliError(format!(
            "unsupported --opening '{other}', expected compact, full, or both"
        ))),
    }
}

fn parse_proof_protocol_selection(value: &str) -> Result<ProofProtocolSelection, CliError> {
    match value {
        "r1cs" => Ok(ProofProtocolSelection::R1cs),
        "plonkish" => Ok(ProofProtocolSelection::Plonkish),
        "both" => Ok(ProofProtocolSelection::Both),
        other => Err(CliError(format!(
            "unsupported proof protocol '{other}', expected r1cs, plonkish, or both"
        ))),
    }
}

fn parse_proof_experiment_command(args: &[String]) -> Result<ProofExperimentCommand, CliError> {
    let mut command = ProofExperimentCommand {
        protocol: ProofProtocolSelection::Both,
        runner: BenchmarkRunner::Local,
        size: 4,
        workers: 1,
        pcs_queries: 1,
        out_dir: PathBuf::from("results"),
        format: OutputFormat::Json,
    };
    let mut index = 0;
    while index < args.len() {
        match args[index].as_str() {
            "--protocol" => {
                command.protocol =
                    parse_proof_protocol_selection(next_value(args, &mut index, "--protocol")?)?;
            }
            "--runner" => {
                command.runner = parse_benchmark_runner(next_value(args, &mut index, "--runner")?)?;
                if command.runner == BenchmarkRunner::Both {
                    return Err(CliError(
                        "proof-experiment --runner must be local or network".to_owned(),
                    ));
                }
            }
            "--size" => {
                command.size =
                    parse_positive_usize(next_value(args, &mut index, "--size")?, "--size")?;
            }
            flag @ ("--nv-power" | "--n") => {
                let power = parse_positive_usize(next_value(args, &mut index, flag)?, flag)?;
                command.size = 1_usize
                    .checked_shl(power as u32)
                    .ok_or_else(|| CliError(format!("{flag} is too large: {power}")))?;
            }
            "--workers" => {
                command.workers =
                    parse_positive_usize(next_value(args, &mut index, "--workers")?, "--workers")?;
            }
            "--pcs-queries" => {
                command.pcs_queries = parse_positive_usize(
                    next_value(args, &mut index, "--pcs-queries")?,
                    "--pcs-queries",
                )?;
            }
            "--out" => {
                command.out_dir = PathBuf::from(next_value(args, &mut index, "--out")?);
            }
            "--format" => {
                command.format = parse_format(next_value(args, &mut index, "--format")?)?;
            }
            "--help" | "-h" => return Err(CliError(usage())),
            other => {
                return Err(CliError(format!(
                    "unknown proof-experiment argument '{other}'"
                )));
            }
        }
        index += 1;
    }
    if command.size == 0 || !command.size.is_power_of_two() {
        return Err(CliError(
            "proof-experiment size must be a positive power of two".to_owned(),
        ));
    }
    if command.workers == 0 || !command.workers.is_power_of_two() || command.workers > command.size
    {
        return Err(CliError(
            "proof-experiment workers must be a positive power of two not exceeding size"
                .to_owned(),
        ));
    }
    Ok(command)
}

fn parse_proof_list_format(value: &str) -> Result<ProofListFormat, CliError> {
    match value {
        "text" => Ok(ProofListFormat::Text),
        "json" => Ok(ProofListFormat::Json),
        "csv" => Ok(ProofListFormat::Csv),
        other => Err(CliError(format!(
            "unsupported list-proofs --format '{other}', expected text, json, or csv"
        ))),
    }
}

fn parse_list_proofs_command(args: &[String]) -> Result<ListProofsCommand, CliError> {
    let mut command = ListProofsCommand {
        results_dir: PathBuf::from("results"),
        format: ProofListFormat::Text,
    };
    let mut index = 0;
    while index < args.len() {
        match args[index].as_str() {
            "--results" | "--dir" => {
                command.results_dir = PathBuf::from(next_value(args, &mut index, "--results")?);
            }
            "--format" => {
                command.format =
                    parse_proof_list_format(next_value(args, &mut index, "--format")?)?;
            }
            "--help" | "-h" => return Err(CliError(usage())),
            other => return Err(CliError(format!("unknown list-proofs argument '{other}'"))),
        }
        index += 1;
    }
    Ok(command)
}

fn parse_verify_proof_command(args: &[String]) -> Result<VerifyProofCommand, CliError> {
    let mut dir = None;
    let mut proof = None;
    let mut format = OutputFormat::Json;
    let mut index = 0;
    while index < args.len() {
        match args[index].as_str() {
            "--dir" => {
                dir = Some(PathBuf::from(next_value(args, &mut index, "--dir")?));
            }
            "--proof" => {
                proof = Some(ProofSelection::One(
                    next_value(args, &mut index, "--proof")?.to_owned(),
                ));
            }
            "--all" => {
                proof = Some(ProofSelection::All);
            }
            "--format" => {
                format = parse_format(next_value(args, &mut index, "--format")?)?;
            }
            "--help" | "-h" => return Err(CliError(usage())),
            value if !value.starts_with('-') && dir.is_none() => {
                dir = Some(PathBuf::from(value));
            }
            other => return Err(CliError(format!("unknown verify-proof argument '{other}'"))),
        }
        index += 1;
    }
    Ok(VerifyProofCommand {
        dir: dir.ok_or_else(|| CliError("verify-proof requires --dir <bench-dir>".to_owned()))?,
        proof: proof.unwrap_or(ProofSelection::All),
        format,
    })
}

fn validate_benchmark_command(command: &BenchmarkCommand) -> Result<(), CliError> {
    if command.sizes.is_empty() || command.workers.is_empty() {
        return Err(CliError(
            "benchmark --sizes and --workers must not be empty".to_owned(),
        ));
    }
    for size in &command.sizes {
        if *size == 0 {
            return Err(CliError("benchmark sizes must be positive".to_owned()));
        }
    }
    let min_row_domain = command
        .sizes
        .iter()
        .copied()
        .min()
        .expect("sizes are checked non-empty")
        .max(1)
        .next_power_of_two();
    for workers in &command.workers {
        if *workers == 0 || !workers.is_power_of_two() {
            return Err(CliError(
                "benchmark workers must be positive powers of two".to_owned(),
            ));
        }
        if *workers > min_row_domain {
            return Err(CliError(
                "benchmark workers must not exceed the smallest padded R1CS row domain".to_owned(),
            ));
        }
    }
    if !command.workers.contains(&1) {
        return Err(CliError(
            "benchmark workers must include 1 for the non-distributed baseline".to_owned(),
        ));
    }
    if command.repeats != BENCHMARK_REPEATS {
        return Err(CliError(
            "performance benchmark runs one end-to-end prove+verify per circuit; --repeats must be 1"
                .to_owned(),
        ));
    }
    Ok(())
}

fn validate_pcs_benchmark_command(command: &PcsBenchmarkCommand) -> Result<(), CliError> {
    if command.sizes.is_empty() {
        return Err(CliError(
            "pcs-benchmark requires at least one size".to_owned(),
        ));
    }
    if command.workers.is_empty() {
        return Err(CliError(
            "pcs-benchmark requires at least one worker count".to_owned(),
        ));
    }
    for size in &command.sizes {
        if *size == 0 || !size.is_power_of_two() {
            return Err(CliError(format!(
                "pcs-benchmark size {size} must be a positive power of two"
            )));
        }
        for workers in &command.workers {
            if *workers == 0 {
                return Err(CliError("PCS worker count must be positive".to_owned()));
            }
            if !workers.is_power_of_two() {
                return Err(CliError(
                    "PCS worker count must be a positive power of two".to_owned(),
                ));
            }
            if *workers > *size {
                return Err(CliError(format!(
                    "PCS worker count {workers} cannot exceed size {size} (worker exponent w={} exceeds n={} for this grid point; choose maximum worker exponent <= {} or increase minimum n)",
                    nv_power(*workers),
                    nv_power(*size),
                    nv_power(*size),
                )));
            }
        }
    }
    if command.pcs_queries == 0 || command.repeats == 0 {
        return Err(CliError(
            "pcs-benchmark --pcs-queries and --repeats must be positive".to_owned(),
        ));
    }
    Ok(())
}

fn parse_verify_results_command(args: &[String]) -> Result<VerifyResultsCommand, CliError> {
    let mut dir = None;
    let mut format = OutputFormat::Json;
    let mut paper_quality = false;
    let mut index = 0;
    while index < args.len() {
        match args[index].as_str() {
            "--dir" => {
                dir = Some(PathBuf::from(next_value(args, &mut index, "--dir")?));
            }
            "--format" => {
                format = parse_format(next_value(args, &mut index, "--format")?)?;
            }
            "--paper-quality" => {
                paper_quality = true;
            }
            "--help" | "-h" => return Err(CliError(usage())),
            value if !value.starts_with('-') && dir.is_none() => {
                dir = Some(PathBuf::from(value));
            }
            other => {
                return Err(CliError(format!(
                    "unknown verify-results argument '{other}'"
                )));
            }
        }
        index += 1;
    }
    Ok(VerifyResultsCommand {
        dir: dir.ok_or_else(|| CliError("verify-results requires --dir <bench-dir>".to_owned()))?,
        format,
        paper_quality,
    })
}

fn parse_verify_pcs_results_command(args: &[String]) -> Result<VerifyResultsCommand, CliError> {
    let mut dir = None;
    let mut format = OutputFormat::Json;
    let mut index = 0;
    while index < args.len() {
        match args[index].as_str() {
            "--dir" => {
                dir = Some(PathBuf::from(next_value(args, &mut index, "--dir")?));
            }
            "--format" => {
                format = parse_format(next_value(args, &mut index, "--format")?)?;
            }
            "--help" | "-h" => return Err(CliError(usage())),
            other => {
                return Err(CliError(format!(
                    "unknown verify-pcs-results argument '{other}'"
                )));
            }
        }
        index += 1;
    }
    Ok(VerifyResultsCommand {
        dir: dir.ok_or_else(|| CliError("verify-pcs-results requires --dir".to_owned()))?,
        format,
        paper_quality: false,
    })
}

fn parse_quick_smoke_command(args: &[String]) -> Result<QuickSmokeCommand, CliError> {
    let mut command = QuickSmokeCommand {
        out_dir: PathBuf::from("target/quick-smoke"),
    };
    let mut index = 0;
    while index < args.len() {
        match args[index].as_str() {
            "--out" => {
                command.out_dir = PathBuf::from(next_value(args, &mut index, "--out")?);
            }
            "--help" | "-h" => return Err(CliError(usage())),
            other => return Err(CliError(format!("unknown quick-smoke argument '{other}'"))),
        }
        index += 1;
    }
    Ok(command)
}

fn run_interactive_command() -> Result<(), CliError> {
    let stdin = io::stdin();
    let stdout = io::stdout();
    let mut input = stdin.lock();
    let mut output = stdout.lock();
    let selection = prompt_interactive_selection(&mut input, &mut output)?;
    drop(output);
    match selection {
        InteractiveSelection::Experiment { mode, config } => {
            let records = match mode {
                InteractiveMode::Local => match config.protocol {
                    Protocol::R1cs => run_r1cs(&config)?,
                    Protocol::Plonkish => run_plonkish(&config)?,
                },
                InteractiveMode::NetProof => run_loopback_network_proof(&config)?,
            };
            print_records(&records, config.format);
            Ok(())
        }
        InteractiveSelection::NetDemo(command) => run_net_demo(command),
    }
}

fn run_benchmark_command(args: &[String]) -> Result<(), CliError> {
    run_benchmark_command_inner(args)?;
    Ok(())
}

fn run_benchmark_command_inner(args: &[String]) -> Result<PathBuf, CliError> {
    let total_start = Instant::now();
    let setup_start = Instant::now();
    let mut command = parse_benchmark_command(args)?;
    configure_benchmark_core_plan(&mut command)?;
    configure_benchmark_rayon_pool(&command);
    let (run_id, _run_label, run_dir) = create_result_run_dir(&command.out_dir, "performance")?;

    let mut records = Vec::new();
    let mut proof_index_entries = Vec::new();
    let mut phase_timings = Vec::new();
    let mut network_pools = BenchmarkNetworkPools::new();
    push_phase_timing(
        &mut phase_timings,
        "setup",
        "parse arguments, derive core plan, create output directory",
        setup_start.elapsed(),
        0.0,
        0.0,
    );
    let runner_variants = command.runner.variants();
    let total_jobs = benchmark_total_jobs(&command, runner_variants.len());
    let mut job_index = 0_usize;
    for runner in &runner_variants {
        for protocol in [Protocol::R1cs, Protocol::Plonkish] {
            for size in &command.sizes {
                for workers in &command.workers {
                    for trial in 1..=command.repeats {
                        job_index += 1;
                        eprintln!(
                            "[benchmark job {job_index}/{total_jobs}] {} start runner={} protocol={} n={} nv={} workers={} pcs_queries={} trial={}/{}",
                            benchmark_progress(job_index - 1, total_jobs),
                            runner.as_str(),
                            protocol.as_str(),
                            nv_power(*size),
                            size,
                            workers,
                            command.pcs_queries,
                            trial,
                            command.repeats
                        );
                        let config = Config {
                            protocol,
                            workers: *workers,
                            size: *size,
                            format: OutputFormat::Json,
                            case: CaseSelection::Positive,
                            pcs_queries: command.pcs_queries,
                            worker_core_plan: command.worker_core_plan.clone(),
                        };
                        let network_addrs = if *runner == BenchmarkRunner::Network {
                            match network_pools.addrs_for(
                                config.workers,
                                &config.worker_core_plan,
                                &mut phase_timings,
                            ) {
                                Ok(addrs) => Some(addrs),
                                Err(error) => {
                                    let _ = network_pools.shutdown_all(&mut phase_timings);
                                    return Err(error);
                                }
                            }
                        } else {
                            None
                        };
                        let job_start = Instant::now();
                        let run_result = run_single_positive_job(
                            *runner,
                            protocol,
                            &config,
                            network_addrs.as_deref(),
                        );
                        let job_output = match run_result {
                            Ok(output) => output,
                            Err(error) => {
                                let _ = network_pools.shutdown_all(&mut phase_timings);
                                return Err(error);
                            }
                        };
                        let mut run_records = vec![job_output.record];
                        let recorded_prove_ms =
                            run_records.iter().map(|record| record.prove_ms).sum();
                        let recorded_verify_ms =
                            run_records.iter().map(|record| record.verify_ms).sum();
                        push_phase_timing(
                            &mut phase_timings,
                            "job",
                            format!(
                                "runner={} protocol={} n={} nv={} workers={} pcs_queries={} trial={}/{}",
                                runner.as_str(),
                                protocol.as_str(),
                                nv_power(*size),
                                size,
                                workers,
                                command.pcs_queries,
                                trial,
                                command.repeats
                            ),
                            job_start.elapsed(),
                            recorded_prove_ms,
                            recorded_verify_ms,
                        );
                        for record in &mut run_records {
                            record.trial = trial;
                        }
                        let positives = run_records
                            .iter()
                            .filter(|record| record.case_name == "positive" && record.verified)
                            .count();
                        validate_benchmark_job_records(
                            protocol,
                            *size,
                            *workers,
                            trial,
                            &run_records,
                        )?;
                        let proof_entry = write_proof_bundle(
                            &run_dir,
                            "performance-benchmark",
                            &run_records[0],
                            job_output.proof,
                            unix_timestamp_label(run_id)?,
                        )?;
                        proof_index_entries.push(proof_entry);
                        eprintln!(
                            "[benchmark job {job_index}/{total_jobs}] {} done positive_verified={positives}",
                            benchmark_progress(job_index, total_jobs)
                        );
                        records.append(&mut run_records);
                    }
                }
            }
        }
    }

    network_pools.shutdown_all(&mut phase_timings)?;
    eprintln!("[benchmark] writing source data, SVG charts, and PGFPlots figures");
    let artifact_start = Instant::now();
    write_proof_index(&run_dir, &proof_index_entries)?;
    write_text_file(&run_dir.join("source.csv"), &records_to_csv(&records))?;
    write_text_file(&run_dir.join("source.json"), &records_to_json(&records))?;
    write_text_file(
        &run_dir.join("summary_stats.csv"),
        &summary_stats_to_csv(&benchmark_stats(&records)),
    )?;
    write_benchmark_charts(&run_dir, &records)?;
    push_phase_timing(
        &mut phase_timings,
        "source_and_chart_artifacts",
        "write measured source data, aggregate CSV, SVG charts, and PGFPlots/TikZ figures",
        artifact_start.elapsed(),
        0.0,
        0.0,
    );
    let mut figure_pdf_created = false;
    if command.compile_figures {
        eprintln!("[benchmark] compiling paper_figures_standalone.tex");
        let figure_compile_start = Instant::now();
        if let Err(error) = compile_paper_figures(&run_dir, command.figure_compiler) {
            push_phase_timing(
                &mut phase_timings,
                "figure_compile_failed",
                format!(
                    "compile paper_figures_standalone.tex with {}",
                    command.figure_compiler.as_str()
                ),
                figure_compile_start.elapsed(),
                0.0,
                0.0,
            );
            push_phase_timing(
                &mut phase_timings,
                "total_before_error",
                "binary wall clock before returning figure compilation error",
                total_start.elapsed(),
                sum_record_prove_ms(&records),
                sum_record_verify_ms(&records),
            );
            let provenance = BenchmarkProvenance::capture();
            write_phase_timing_files(&run_dir, &phase_timings)?;
            write_text_file(
                &run_dir.join("summary.txt"),
                &benchmark_summary(&command, &records, &phase_timings, false, &provenance),
            )?;
            write_benchmark_overview_html(&run_dir, run_id, &command, &records, false)?;
            write_benchmark_metadata_and_manifest(
                &run_dir,
                run_id,
                &command,
                &records,
                false,
                &provenance,
            )?;
            let report = verify_benchmark_result_dir(&run_dir)?;
            eprintln!(
                "[benchmark] manifest verified: files={} bytes={}",
                report.files_checked, report.bytes_checked
            );
            return Err(error);
        }
        push_phase_timing(
            &mut phase_timings,
            "figure_compile",
            format!(
                "compile paper_figures_standalone.tex with {}",
                command.figure_compiler.as_str()
            ),
            figure_compile_start.elapsed(),
            0.0,
            0.0,
        );
        figure_pdf_created = true;
    }
    let final_output_start = Instant::now();
    let provenance = BenchmarkProvenance::capture();
    write_phase_timing_files(&run_dir, &phase_timings)?;
    write_text_file(
        &run_dir.join("summary.txt"),
        &benchmark_summary(
            &command,
            &records,
            &phase_timings,
            figure_pdf_created,
            &provenance,
        ),
    )?;
    write_benchmark_overview_html(&run_dir, run_id, &command, &records, figure_pdf_created)?;
    write_benchmark_metadata_and_manifest(
        &run_dir,
        run_id,
        &command,
        &records,
        figure_pdf_created,
        &provenance,
    )?;
    push_phase_timing(
        &mut phase_timings,
        "final_result_artifacts",
        "first pass write of phase timing, summary, overview, metadata, and manifest; total phase includes final rewrite and manifest verification",
        final_output_start.elapsed(),
        0.0,
        0.0,
    );
    push_phase_timing(
        &mut phase_timings,
        "total",
        "binary wall clock through first manifest verification",
        total_start.elapsed(),
        sum_record_prove_ms(&records),
        sum_record_verify_ms(&records),
    );
    write_phase_timing_files(&run_dir, &phase_timings)?;
    write_text_file(
        &run_dir.join("summary.txt"),
        &benchmark_summary(
            &command,
            &records,
            &phase_timings,
            figure_pdf_created,
            &provenance,
        ),
    )?;
    write_benchmark_overview_html(&run_dir, run_id, &command, &records, figure_pdf_created)?;
    write_benchmark_metadata_and_manifest(
        &run_dir,
        run_id,
        &command,
        &records,
        figure_pdf_created,
        &provenance,
    )?;
    let report = verify_benchmark_result_dir(&run_dir)?;
    eprintln!(
        "[benchmark] manifest verified: files={} bytes={}",
        report.files_checked, report.bytes_checked
    );
    eprintln!("[benchmark] complete");
    Ok(run_dir)
}

fn run_pcs_benchmark_command(args: &[String]) -> Result<(), CliError> {
    let run_dir = run_pcs_benchmark_command_inner(args)?;
    println!("{}", run_dir.display());
    Ok(())
}

fn run_pcs_benchmark_command_inner(args: &[String]) -> Result<PathBuf, CliError> {
    let total_start = Instant::now();
    let setup_start = Instant::now();
    let mut command = parse_pcs_benchmark_command(args)?;
    configure_pcs_benchmark_core_plan(&mut command)?;
    configure_pcs_benchmark_rayon_pool(&command);
    let (run_id, _run_label, run_dir) =
        create_prefixed_result_run_dir(&command.out_dir, "pcs-bench")?;

    let mut records = Vec::new();
    let mut phase_timings = Vec::new();
    let mut network_pools = BenchmarkNetworkPools::new();
    push_phase_timing(
        &mut phase_timings,
        "setup",
        "parse PCS benchmark arguments, derive core plan, create output directory",
        setup_start.elapsed(),
        0.0,
        0.0,
    );

    let runner_variants = command.runner.variants();
    let opening_variants = command.opening.variants();
    let total_jobs = runner_variants.len()
        * opening_variants.len()
        * command.sizes.len()
        * command.workers.len()
        * command.repeats;
    let mut job_index = 0_usize;
    let first_size = command.sizes.first().copied();
    for runner in &runner_variants {
        for size in &command.sizes {
            for workers in &command.workers {
                for trial in 1..=command.repeats {
                    let network_addrs = if *runner == BenchmarkRunner::Network {
                        Some(network_pools.addrs_for(
                            *workers,
                            &command.worker_core_plan,
                            &mut phase_timings,
                        )?)
                    } else {
                        None
                    };
                    for opening in &opening_variants {
                        if command.warmup_enabled && Some(*size) == first_size && trial == 1 {
                            eprintln!(
                                "[pcs-benchmark warmup] runner={} opening={} n={} N={} workers={} pcs_queries={}",
                                runner.as_str(),
                                opening.as_str(),
                                nv_power(*size),
                                size,
                                workers,
                                command.pcs_queries,
                            );
                            let warmup_start = Instant::now();
                            let _ = run_single_pcs_job(
                                &command,
                                *runner,
                                *opening,
                                *size,
                                *workers,
                                0,
                                network_addrs.as_deref(),
                            )?;
                            push_phase_timing(
                                &mut phase_timings,
                                "pcs_warmup",
                                format!(
                                    "runner={} opening={} n={} N={} workers={}",
                                    runner.as_str(),
                                    opening.as_str(),
                                    nv_power(*size),
                                    size,
                                    workers,
                                ),
                                warmup_start.elapsed(),
                                0.0,
                                0.0,
                            );
                        }
                        job_index += 1;
                        eprintln!(
                            "[pcs-benchmark job {job_index}/{total_jobs}] runner={} opening={} n={} N={} workers={} pcs_queries={} trial={}/{}",
                            runner.as_str(),
                            opening.as_str(),
                            nv_power(*size),
                            size,
                            workers,
                            command.pcs_queries,
                            trial,
                            command.repeats
                        );
                        let job_start = Instant::now();
                        let record = run_single_pcs_job(
                            &command,
                            *runner,
                            *opening,
                            *size,
                            *workers,
                            trial,
                            network_addrs.as_deref(),
                        )?;
                        push_phase_timing(
                            &mut phase_timings,
                            "pcs_job",
                            format!(
                                "runner={} opening={} n={} N={} workers={} trial={}",
                                runner.as_str(),
                                opening.as_str(),
                                nv_power(*size),
                                size,
                                workers,
                                trial
                            ),
                            job_start.elapsed(),
                            record.commit_ms + record.open_ms,
                            record.verify_ms,
                        );
                        records.push(record);
                    }
                }
            }
        }
    }
    network_pools.shutdown_all(&mut phase_timings)?;

    let artifact_start = Instant::now();
    write_text_file(&run_dir.join("source.csv"), &pcs_records_to_csv(&records))?;
    write_text_file(&run_dir.join("source.json"), &pcs_records_to_json(&records))?;
    write_text_file(
        &run_dir.join("summary_stats.csv"),
        &pcs_summary_stats_to_csv(&pcs_benchmark_stats(&records)),
    )?;
    write_pcs_benchmark_charts(&run_dir, &records)?;
    push_phase_timing(
        &mut phase_timings,
        "source_and_chart_artifacts",
        "write PCS source data, aggregate CSV, SVG charts, and PGFPlots/TikZ figures",
        artifact_start.elapsed(),
        0.0,
        0.0,
    );

    let final_start = Instant::now();
    write_text_file(
        &run_dir.join("summary.txt"),
        &pcs_benchmark_summary(&command, &records, &phase_timings),
    )?;
    write_text_file(
        &run_dir.join(OVERVIEW_HTML),
        &pcs_benchmark_overview_html(run_id, &command, &records),
    )?;
    push_phase_timing(
        &mut phase_timings,
        "final_result_artifacts",
        "write PCS HTML summary and result manifest inputs",
        final_start.elapsed(),
        0.0,
        0.0,
    );
    push_phase_timing(
        &mut phase_timings,
        "total",
        "PCS benchmark total wall-clock time",
        total_start.elapsed(),
        records
            .iter()
            .map(|record| record.commit_ms + record.open_ms)
            .sum(),
        records.iter().map(|record| record.verify_ms).sum(),
    );
    write_text_file(
        &run_dir.join("phase_timing.csv"),
        &phase_timing_to_csv(&phase_timings),
    )?;
    write_text_file(
        &run_dir.join("phase_timing.json"),
        &phase_timing_to_json(&phase_timings),
    )?;
    write_text_file(
        &run_dir.join("metadata.json"),
        &pcs_benchmark_metadata_json(run_id, &command, &records),
    )?;
    let manifest = pcs_result_manifest_json(&run_dir, run_id)?;
    write_text_file(&run_dir.join(RESULT_MANIFEST), &manifest)?;
    verify_pcs_result_dir(&run_dir)?;
    Ok(run_dir)
}

fn run_quick_smoke_command(args: &[String]) -> Result<(), CliError> {
    let command = parse_quick_smoke_command(args)?;
    let benchmark_args = vec![
        "--runner".to_owned(),
        "local".to_owned(),
        "--n-range".to_owned(),
        "2..2".to_owned(),
        "--workers".to_owned(),
        "1".to_owned(),
        "--pcs-queries".to_owned(),
        "1".to_owned(),
        "--out".to_owned(),
        command.out_dir.display().to_string(),
    ];
    eprintln!("[quick-smoke] running local n=2 workers=1 benchmark");
    let run_dir = run_benchmark_command_inner(&benchmark_args)?;
    let before_report = verify_benchmark_result_dir(&run_dir)?;
    let proof_report = verify_stored_proofs(&VerifyProofCommand {
        dir: run_dir.clone(),
        proof: ProofSelection::All,
        format: OutputFormat::Json,
    })?;
    let failed = proof_report
        .outcomes
        .iter()
        .filter(|outcome| !outcome.verified)
        .count();
    if failed > 0 {
        return Err(CliError(format!(
            "quick-smoke stored proof verification failed: {failed}/{} selected proof(s) failed; reports written to {} and {}",
            proof_report.outcomes.len(),
            proof_report.report_json.display(),
            proof_report.report_html.display()
        )));
    }
    let after_report = verify_benchmark_result_dir(&run_dir)?;
    if before_report.files_checked != after_report.files_checked
        || before_report.bytes_checked != after_report.bytes_checked
        || before_report.source_rows_checked != after_report.source_rows_checked
        || before_report.phase_rows_checked != after_report.phase_rows_checked
        || before_report.summary_rows_checked != after_report.summary_rows_checked
    {
        return Err(CliError(
            "quick-smoke proof reverification changed benchmark manifest or semantic counts"
                .to_owned(),
        ));
    }
    println!(
        "{{\"ok\":true,\"dir\":\"{}\",\"files_checked\":{},\"bytes_checked\":{},\"source_rows_checked\":{},\"phase_rows_checked\":{},\"summary_rows_checked\":{},\"proofs_checked\":{},\"proofs_verified\":{},\"verify_report_json\":\"{}\",\"verify_report_html\":\"{}\"}}",
        json_escape(&run_dir.display().to_string()),
        after_report.files_checked,
        after_report.bytes_checked,
        after_report.source_rows_checked,
        after_report.phase_rows_checked,
        after_report.summary_rows_checked,
        proof_report.outcomes.len(),
        proof_report
            .outcomes
            .iter()
            .filter(|outcome| outcome.verified)
            .count(),
        json_escape(&proof_report.report_json.display().to_string()),
        json_escape(&proof_report.report_html.display().to_string())
    );
    Ok(())
}

fn benchmark_total_jobs(command: &BenchmarkCommand, runner_variant_count: usize) -> usize {
    [Protocol::R1cs, Protocol::Plonkish].len()
        * runner_variant_count
        * command.sizes.len()
        * command.workers.len()
        * command.repeats
}

struct BenchmarkJobOutput {
    record: MetricRecord,
    proof: StoredProof,
}

fn run_single_positive_job(
    runner: BenchmarkRunner,
    protocol: Protocol,
    config: &Config,
    network_addrs: Option<&[String]>,
) -> Result<BenchmarkJobOutput, CliError> {
    match (runner, protocol) {
        (BenchmarkRunner::Local, Protocol::R1cs) => {
            let (record, proof) = run_r1cs_case_with_proof(config, "positive", false)?;
            Ok(BenchmarkJobOutput {
                record,
                proof: StoredProof::R1cs(Box::new(proof)),
            })
        }
        (BenchmarkRunner::Local, Protocol::Plonkish) => {
            let (record, proof) = run_plonkish_case_with_proof(config, "positive", false)?;
            Ok(BenchmarkJobOutput {
                record,
                proof: StoredProof::Plonkish(Box::new(proof)),
            })
        }
        (BenchmarkRunner::Network, Protocol::R1cs) => {
            let addrs = network_addrs.ok_or_else(|| {
                CliError("network proof job requires prepared worker addresses".to_owned())
            })?;
            let (record, proof) =
                run_r1cs_case_network_with_proof(config, addrs, "positive", false)?;
            Ok(BenchmarkJobOutput {
                record,
                proof: StoredProof::R1cs(Box::new(proof)),
            })
        }
        (BenchmarkRunner::Network, Protocol::Plonkish) => {
            let addrs = network_addrs.ok_or_else(|| {
                CliError("network proof job requires prepared worker addresses".to_owned())
            })?;
            let (record, proof) =
                run_plonkish_case_network_with_proof(config, addrs, "positive", false)?;
            Ok(BenchmarkJobOutput {
                record,
                proof: StoredProof::Plonkish(Box::new(proof)),
            })
        }
        (BenchmarkRunner::Both, _) => Err(CliError(
            "single proof job runner must be local or network".to_owned(),
        )),
    }
}

fn benchmark_progress(completed_jobs: usize, total_jobs: usize) -> String {
    const WIDTH: usize = 24;
    if total_jobs == 0 {
        return "progress 0/0 100.0% [########################]".to_owned();
    }
    let completed = completed_jobs.min(total_jobs);
    let filled = (completed * WIDTH + total_jobs / 2) / total_jobs;
    let empty = WIDTH.saturating_sub(filled);
    let percent = (completed as f64 * 100.0) / total_jobs as f64;
    format!(
        "progress {completed}/{total_jobs} {percent:5.1}% [{}{}]",
        "#".repeat(filled),
        "-".repeat(empty)
    )
}

fn validate_benchmark_job_records(
    protocol: Protocol,
    size: usize,
    workers: usize,
    trial: usize,
    records: &[MetricRecord],
) -> Result<(), CliError> {
    let positive_count = records
        .iter()
        .filter(|record| record.case_name == "positive")
        .count();
    let negative_count = records
        .iter()
        .filter(|record| record.case_name == "negative")
        .count();
    let positive_verified = records
        .iter()
        .filter(|record| record.case_name == "positive" && record.verified)
        .count();
    let negative_rejected = records
        .iter()
        .filter(|record| record.case_name == "negative" && !record.verified)
        .count();

    if positive_count == 1
        && positive_verified == 1
        && negative_count == 0
        && negative_rejected == 0
    {
        return Ok(());
    }

    let details = records
        .iter()
        .map(|record| {
            format!(
                "{}:verified={} failure={}",
                record.case_name,
                record.verified,
                record.failure_reason.as_deref().unwrap_or("<none>")
            )
        })
        .collect::<Vec<_>>()
        .join("; ");
    Err(CliError(format!(
        "benchmark verification expectation failed for protocol={} n={} nv={} workers={} trial={}: expected exactly one verified positive performance record and no negative correctness records; got positives={} positive_verified={} negatives={} negative_rejected={}; records=[{}]",
        protocol.as_str(),
        nv_power(size),
        size,
        workers,
        trial,
        positive_count,
        positive_verified,
        negative_count,
        negative_rejected,
        details
    )))
}

fn run_proof_experiment_command(args: &[String]) -> Result<(), CliError> {
    let command = parse_proof_experiment_command(args)?;
    configure_rayon_pool(detect_host_logical_cores());
    let (run_id, run_label, run_dir) = create_result_run_dir(&command.out_dir, "proof")?;

    let mut records = Vec::new();
    let mut proof_entries = Vec::new();
    let mut network_pools = BenchmarkNetworkPools::new();
    let mut proof_phase_timings = Vec::new();
    let protocols = command.protocol.variants();
    let total_jobs = protocols.len();
    for (protocol_index, protocol) in protocols.into_iter().enumerate() {
        let job_index = protocol_index + 1;
        eprintln!(
            "[proof-experiment job {job_index}/{total_jobs}] start runner={} protocol={} n={} nv={} workers={} pcs_queries={}",
            command.runner.as_str(),
            protocol.as_str(),
            nv_power(command.size),
            command.size,
            command.workers,
            command.pcs_queries
        );
        let config = Config {
            protocol,
            workers: command.workers,
            size: command.size,
            format: OutputFormat::Json,
            case: CaseSelection::Positive,
            pcs_queries: command.pcs_queries,
            worker_core_plan: None,
        };
        let network_addrs = if command.runner == BenchmarkRunner::Network {
            Some(network_pools.addrs_for(config.workers, &None, &mut proof_phase_timings)?)
        } else {
            None
        };
        let job =
            run_single_positive_job(command.runner, protocol, &config, network_addrs.as_deref())?;
        let record = job.record;
        let entry = write_proof_bundle(
            &run_dir,
            "proof-experiment",
            &record,
            job.proof,
            unix_timestamp_label(run_id)?,
        )?;
        proof_entries.push(entry);
        records.push(record);
        eprintln!("[proof-experiment job {job_index}/{total_jobs}] done verified=true");
    }
    network_pools.shutdown_all(&mut proof_phase_timings)?;

    write_text_file(&run_dir.join("source.csv"), &records_to_csv(&records))?;
    write_text_file(&run_dir.join("source.json"), &records_to_json(&records))?;
    write_proof_index(&run_dir, &proof_entries)?;
    write_text_file(
        &run_dir.join("proof_experiment_report.json"),
        &proof_experiment_report_json(run_id, &run_label, &command, &records, &proof_entries)?,
    )?;
    write_text_file(
        &run_dir.join(OVERVIEW_HTML),
        &proof_experiment_overview_html(run_id, &run_label, &command, &records, &proof_entries),
    )?;
    match command.format {
        OutputFormat::Json => println!(
            "{{\"ok\":true,\"run_id\":{},\"proofs\":{}}}",
            run_id,
            proof_entries.len()
        ),
        OutputFormat::Csv => {
            println!("ok,run_id,proofs");
            println!("true,{},{}", run_id, proof_entries.len());
        }
    }
    Ok(())
}

fn run_list_proofs_command(args: &[String]) -> Result<(), CliError> {
    let command = parse_list_proofs_command(args)?;
    let entries = discover_proof_benches(&command.results_dir)?;
    match command.format {
        ProofListFormat::Text => {
            if entries.is_empty() {
                println!(
                    "No bench directories found under {}.",
                    command.results_dir.display()
                );
            } else {
                println!(
                    "Detected bench proof inventory under {}:",
                    command.results_dir.display()
                );
                for (index, entry) in entries.iter().enumerate() {
                    let status = if entry.proof_count == 0 {
                        "no proof".to_owned()
                    } else if entry.invalid_proof_count > 0 {
                        format!(
                            "{} proof file(s), {} invalid: {}",
                            entry.proof_count,
                            entry.invalid_proof_count,
                            entry.proof_ids.join(", ")
                        )
                    } else {
                        format!(
                            "{} proof(s): {}",
                            entry.proof_count,
                            entry.proof_ids.join(", ")
                        )
                    };
                    println!("{:>2}. {}  {}", index + 1, entry.bench_name, status);
                }
            }
        }
        ProofListFormat::Json => {
            println!("{}", proof_list_to_json(&entries));
        }
        ProofListFormat::Csv => {
            println!("index,bench,dir,proof_count,invalid_proof_count,proof_ids");
            for (index, entry) in entries.iter().enumerate() {
                println!(
                    "{},{},{},{},{},{}",
                    index + 1,
                    csv_escape(&entry.bench_name),
                    csv_escape(&entry.dir.display().to_string()),
                    entry.proof_count,
                    entry.invalid_proof_count,
                    csv_escape(&entry.proof_ids.join(";"))
                );
            }
        }
    }
    Ok(())
}

fn run_verify_proof_command(args: &[String]) -> Result<(), CliError> {
    let command = parse_verify_proof_command(args)?;
    let report = verify_stored_proofs(&command)?;
    let failed = report
        .outcomes
        .iter()
        .filter(|outcome| !outcome.verified)
        .count();
    match command.format {
        OutputFormat::Json => println!("{}", proof_verify_report_to_json(&report, true)),
        OutputFormat::Csv => {
            println!("ok,bench_dir,report_json,report_html,total,verified,failed");
            println!(
                "{},{},{},{},{},{},{}",
                report.outcomes.iter().all(|outcome| outcome.verified),
                csv_escape(&report.bench_dir.display().to_string()),
                csv_escape(&report.report_json.display().to_string()),
                csv_escape(&report.report_html.display().to_string()),
                report.outcomes.len(),
                report
                    .outcomes
                    .iter()
                    .filter(|outcome| outcome.verified)
                    .count(),
                report
                    .outcomes
                    .iter()
                    .filter(|outcome| !outcome.verified)
                    .count()
            );
        }
    }
    if failed > 0 {
        return Err(CliError(format!(
            "stored proof verification failed: {failed}/{} selected proof(s) failed; reports written to {} and {}",
            report.outcomes.len(),
            report.report_json.display(),
            report.report_html.display()
        )));
    }
    Ok(())
}

fn run_verify_results_command(args: &[String]) -> Result<(), CliError> {
    let command = parse_verify_results_command(args)?;
    let report = verify_benchmark_result_dir(&command.dir)?;
    if command.paper_quality {
        verify_benchmark_paper_quality(&command.dir)?;
    }
    match command.format {
        OutputFormat::Json => {
            println!(
                "{{\"ok\":true,\"dir\":\"{}\",\"run_id\":{},\"files_checked\":{},\"bytes_checked\":{},\"source_rows_checked\":{},\"phase_rows_checked\":{},\"summary_rows_checked\":{},\"paper_quality_checked\":{}}}",
                json_escape(&report.dir.display().to_string()),
                report.run_id,
                report.files_checked,
                report.bytes_checked,
                report.source_rows_checked,
                report.phase_rows_checked,
                report.summary_rows_checked,
                command.paper_quality
            );
        }
        OutputFormat::Csv => {
            println!(
                "ok,dir,run_id,files_checked,bytes_checked,source_rows_checked,phase_rows_checked,summary_rows_checked,paper_quality_checked"
            );
            println!(
                "true,{},{},{},{},{},{},{},{}",
                csv_escape(&report.dir.display().to_string()),
                report.run_id,
                report.files_checked,
                report.bytes_checked,
                report.source_rows_checked,
                report.phase_rows_checked,
                report.summary_rows_checked,
                command.paper_quality
            );
        }
    }
    Ok(())
}

fn run_verify_pcs_results_command(args: &[String]) -> Result<(), CliError> {
    let command = parse_verify_pcs_results_command(args)?;
    let report = verify_pcs_result_dir(&command.dir)?;
    match command.format {
        OutputFormat::Json => println!(
            "{{\"ok\":true,\"dir\":\"{}\",\"run_id\":{},\"files_checked\":{},\"bytes_checked\":{},\"source_rows_checked\":{},\"summary_rows_checked\":{},\"phase_rows_checked\":{}}}",
            json_escape(&report.dir.display().to_string()),
            report.run_id,
            report.files_checked,
            report.bytes_checked,
            report.source_rows_checked,
            report.summary_rows_checked,
            report.phase_rows_checked
        ),
        OutputFormat::Csv => {
            println!(
                "ok,dir,run_id,files_checked,bytes_checked,source_rows_checked,summary_rows_checked,phase_rows_checked"
            );
            println!(
                "true,{},{},{},{},{},{},{}",
                csv_escape(&report.dir.display().to_string()),
                report.run_id,
                report.files_checked,
                report.bytes_checked,
                report.source_rows_checked,
                report.summary_rows_checked,
                report.phase_rows_checked
            );
        }
    }
    Ok(())
}

fn verify_benchmark_result_dir(dir: &Path) -> Result<ResultManifestReport, CliError> {
    let mut report = verify_benchmark_result_manifest(dir)?;
    let semantic_report = verify_benchmark_result_semantics(dir, report.run_id)?;
    report.source_rows_checked = semantic_report.source_rows_checked;
    report.phase_rows_checked = semantic_report.phase_rows_checked;
    report.summary_rows_checked = semantic_report.summary_rows_checked;
    Ok(report)
}

fn verify_pcs_result_dir(dir: &Path) -> Result<ResultManifestReport, CliError> {
    let mut report = verify_pcs_result_manifest(dir)?;
    let (source_rows, summary_rows, phase_rows) = verify_pcs_result_semantics(dir)?;
    report.source_rows_checked = source_rows;
    report.summary_rows_checked = summary_rows;
    report.phase_rows_checked = phase_rows;
    Ok(report)
}

fn verify_pcs_result_manifest(dir: &Path) -> Result<ResultManifestReport, CliError> {
    let manifest_path = dir.join(RESULT_MANIFEST);
    let bytes = fs::read(&manifest_path)
        .map_err(|error| CliError(format!("read {} failed: {error}", manifest_path.display())))?;
    let text = String::from_utf8(bytes)
        .map_err(|error| CliError(format!("{} is not UTF-8: {error}", manifest_path.display())))?;
    if !text.contains("\"generated_by\": \"pq-experiments pcs benchmark manifest\"") {
        return Err(CliError(format!(
            "{} is not a PCS benchmark manifest",
            manifest_path.display()
        )));
    }
    let run_id = manifest_run_id(&text)?;
    let mut files_checked = 0_usize;
    let mut bytes_checked = 0_usize;
    for artifact in PCS_BENCHMARK_ARTIFACTS {
        if *artifact == RESULT_MANIFEST {
            continue;
        }
        let path = dir.join(artifact);
        let bytes = fs::read(&path)
            .map_err(|error| CliError(format!("read {} failed: {error}", path.display())))?;
        let digest = hex_digest(sha256(&bytes));
        let marker = format!(
            "\"path\":\"{}\",\"bytes\":{},\"sha256\":\"{}\"",
            artifact,
            bytes.len(),
            digest
        );
        if !text.contains(&marker) {
            return Err(CliError(format!(
                "PCS manifest mismatch for artifact {artifact}"
            )));
        }
        files_checked += 1;
        bytes_checked += bytes.len();
    }
    Ok(ResultManifestReport {
        dir: dir.to_path_buf(),
        run_id,
        files_checked,
        bytes_checked,
        source_rows_checked: 0,
        phase_rows_checked: 0,
        summary_rows_checked: 0,
    })
}

fn manifest_run_id(text: &str) -> Result<u64, CliError> {
    let marker = "\"run_id\":";
    let start = text
        .find(marker)
        .ok_or_else(|| CliError("manifest missing run_id".to_owned()))?
        + marker.len();
    let tail = &text[start..];
    let digits = tail
        .chars()
        .skip_while(|ch| ch.is_whitespace())
        .take_while(|ch| ch.is_ascii_digit())
        .collect::<String>();
    digits
        .parse::<u64>()
        .map_err(|_| CliError("manifest run_id is invalid".to_owned()))
}

fn verify_pcs_result_semantics(dir: &Path) -> Result<(usize, usize, usize), CliError> {
    let source = fs::read_to_string(dir.join("source.csv"))
        .map_err(|error| CliError(format!("read PCS source.csv failed: {error}")))?;
    let mut lines = source.lines();
    let header = lines
        .next()
        .ok_or_else(|| CliError("PCS source.csv is empty".to_owned()))?;
    if header != PCS_SOURCE_CSV_HEADER {
        return Err(CliError("PCS source.csv has unexpected header".to_owned()));
    }
    let mut source_rows = 0_usize;
    for line in lines {
        if line.trim().is_empty() {
            continue;
        }
        source_rows += 1;
        verify_pcs_source_row(line)?;
    }
    if source_rows == 0 {
        return Err(CliError("PCS source.csv has no data rows".to_owned()));
    }
    let summary = fs::read_to_string(dir.join("summary_stats.csv"))
        .map_err(|error| CliError(format!("read PCS summary_stats.csv failed: {error}")))?;
    let mut summary_lines = summary.lines();
    if summary_lines.next() != Some(PCS_SUMMARY_STATS_CSV_HEADER) {
        return Err(CliError(
            "PCS summary_stats.csv has unexpected header".to_owned(),
        ));
    }
    let summary_rows = summary_lines.filter(|line| !line.trim().is_empty()).count();
    if summary_rows == 0 {
        return Err(CliError(
            "PCS summary_stats.csv has no aggregate rows".to_owned(),
        ));
    }
    let phase_rows = verify_phase_timing_csv_semantics(dir, source_rows)?;
    for artifact in [
        "overview.html",
        "commit_time_by_size.svg",
        "open_time_by_size.svg",
        "verify_time_by_size.svg",
        "opening_bytes_by_size.svg",
        "network_bytes_by_size.svg",
        "worker_scaling_max_size.svg",
    ] {
        verify_pcs_html_or_svg_artifact(dir, artifact)?;
    }
    for artifact in [
        "commit_time_by_size.tex",
        "open_time_by_size.tex",
        "verify_time_by_size.tex",
        "opening_bytes_by_size.tex",
        "network_bytes_by_size.tex",
        "worker_scaling_max_size.tex",
    ] {
        verify_pgfplots_artifact(dir, artifact, "PCS benchmark")?;
    }
    Ok((source_rows, summary_rows, phase_rows))
}

fn verify_pcs_source_row(line: &str) -> Result<(), CliError> {
    let fields = parse_csv_line(line);
    if fields.len() != PCS_SOURCE_CSV_HEADER.split(',').count() {
        return Err(CliError(format!(
            "PCS source row has {} fields, expected {}: {line}",
            fields.len(),
            PCS_SOURCE_CSV_HEADER.split(',').count()
        )));
    }
    let runner = fields[0].as_str();
    let opening = fields[1].as_str();
    if !matches!(runner, "local" | "network") {
        return Err(CliError(format!("invalid PCS runner '{runner}'")));
    }
    if !matches!(opening, "compact" | "full") {
        return Err(CliError(format!("invalid PCS opening '{opening}'")));
    }
    let verified = fields[26].parse::<bool>().map_err(|_| {
        CliError(format!(
            "PCS source row has invalid verified value '{}'",
            fields[26]
        ))
    })?;
    if !verified {
        return Err(CliError(format!(
            "PCS benchmark row did not verify: {line}"
        )));
    }
    for index in [11_usize, 12, 13, 14, 15, 16] {
        let value = fields[index]
            .parse::<f64>()
            .map_err(|_| CliError(format!("PCS source row numeric field {} is invalid", index)))?;
        if value < 0.0 || !value.is_finite() {
            return Err(CliError(format!(
                "PCS source row numeric field {index} is negative or non-finite"
            )));
        }
    }
    let network_bytes = fields[22]
        .parse::<usize>()
        .map_err(|_| CliError("PCS network_bytes field is invalid".to_owned()))?;
    if runner == "local" && network_bytes != 0 {
        return Err(CliError(
            "local PCS row must have network_bytes=0".to_owned(),
        ));
    }
    if runner == "network" && network_bytes == 0 {
        return Err(CliError(
            "network PCS row must have non-zero network_bytes".to_owned(),
        ));
    }
    let opening_bytes = fields[18]
        .parse::<usize>()
        .map_err(|_| CliError("PCS opening_proof_bytes field is invalid".to_owned()))?;
    let communication_bytes = fields[19]
        .parse::<usize>()
        .map_err(|_| CliError("PCS communication_bytes field is invalid".to_owned()))?;
    if communication_bytes < opening_bytes {
        return Err(CliError(
            "PCS communication_bytes must be >= opening_proof_bytes".to_owned(),
        ));
    }
    Ok(())
}

fn verify_pcs_html_or_svg_artifact(dir: &Path, artifact: &str) -> Result<(), CliError> {
    let text = fs::read_to_string(dir.join(artifact))
        .map_err(|error| CliError(format!("read {artifact} failed: {error}")))?;
    let required: &[&str] = if artifact.ends_with(".html") {
        &[
            "<!doctype html>",
            "Distributed Brakedown PCS Benchmark",
            "Brief Charts",
            "<img src=\"",
            "source.csv",
        ]
    } else if artifact.contains("worker_scaling") {
        &["<svg", "</svg>", "PCS", "Speedup", "Perfect upper bound"]
    } else {
        &["<svg", "</svg>", "PCS", "10^", "stroke-dasharray"]
    };
    for marker in required {
        if !text.contains(marker) {
            return Err(CliError(format!(
                "PCS benchmark {artifact} missing required marker '{marker}'"
            )));
        }
    }
    Ok(())
}

fn parse_csv_line(line: &str) -> Vec<String> {
    let mut fields = Vec::new();
    let mut current = String::new();
    let mut chars = line.chars().peekable();
    let mut quoted = false;
    while let Some(ch) = chars.next() {
        match ch {
            '"' if quoted && chars.peek() == Some(&'"') => {
                current.push('"');
                chars.next();
            }
            '"' => quoted = !quoted,
            ',' if !quoted => {
                fields.push(current);
                current = String::new();
            }
            _ => current.push(ch),
        }
    }
    fields.push(current);
    fields
}

fn verify_benchmark_result_manifest(dir: &Path) -> Result<ResultManifestReport, CliError> {
    let manifest_path = dir.join(RESULT_MANIFEST);
    let manifest = fs::read_to_string(&manifest_path)
        .map_err(|error| CliError(format!("read {} failed: {error}", manifest_path.display())))?;
    if !manifest.contains("\"schema_version\": 1") {
        return Err(CliError(format!(
            "{} is not a schema_version=1 result manifest",
            manifest_path.display()
        )));
    }
    if !manifest.contains("\"self_artifact\": \"result_manifest.json\"") {
        return Err(CliError(format!(
            "{} does not declare its self artifact",
            manifest_path.display()
        )));
    }
    let run_id = parse_json_u64_field(&manifest, "run_id")?;
    let expected_artifact_count = parse_json_usize_field(&manifest, "artifact_count")?;
    let entries = parse_manifest_entries(&manifest)?;
    if entries.len() != expected_artifact_count {
        return Err(CliError(format!(
            "manifest artifact_count mismatch: expected {}, parsed {}",
            expected_artifact_count,
            entries.len()
        )));
    }
    if entries.iter().any(|entry| entry.path == RESULT_MANIFEST) {
        return Err(CliError(
            "manifest must not recursively list result_manifest.json".to_owned(),
        ));
    }
    let mut expected_files = BTreeSet::new();
    expected_files.insert(RESULT_MANIFEST.to_owned());
    for entry in &entries {
        if !expected_files.insert(entry.path.clone()) {
            return Err(CliError(format!(
                "manifest lists duplicate artifact '{}'",
                entry.path
            )));
        }
    }
    let actual_files = benchmark_result_dir_entries(dir)?;
    if let Some(actual) = actual_files.difference(&expected_files).next() {
        return Err(CliError(format!(
            "unexpected artifact '{}' in {}; rerun benchmark into a fresh result directory",
            actual,
            dir.display()
        )));
    }
    if let Some(expected) = expected_files.difference(&actual_files).next() {
        return Err(CliError(format!(
            "missing manifest-listed artifact '{}' in {}",
            expected,
            dir.display()
        )));
    }
    let mut bytes_checked = 0_usize;
    for entry in &entries {
        let artifact_path = dir.join(&entry.path);
        let bytes = fs::read(&artifact_path).map_err(|error| {
            CliError(format!("read {} failed: {error}", artifact_path.display()))
        })?;
        let digest = hex_digest(sha256(&bytes));
        if bytes.len() != entry.bytes {
            return Err(CliError(format!(
                "{} byte-size mismatch: manifest={} actual={}",
                artifact_path.display(),
                entry.bytes,
                bytes.len()
            )));
        }
        if digest != entry.sha256 {
            return Err(CliError(format!(
                "{} sha256 mismatch: manifest={} actual={}",
                artifact_path.display(),
                entry.sha256,
                digest
            )));
        }
        bytes_checked += bytes.len();
    }
    Ok(ResultManifestReport {
        dir: dir.to_path_buf(),
        run_id,
        files_checked: entries.len(),
        bytes_checked,
        source_rows_checked: 0,
        phase_rows_checked: 0,
        summary_rows_checked: 0,
    })
}

#[derive(Clone, Debug)]
struct ResultSemanticReport {
    source_rows_checked: usize,
    phase_rows_checked: usize,
    summary_rows_checked: usize,
}

fn verify_benchmark_result_semantics(
    dir: &Path,
    manifest_run_id: u64,
) -> Result<ResultSemanticReport, CliError> {
    let metadata_path = dir.join("metadata.json");
    let metadata = fs::read_to_string(&metadata_path)
        .map_err(|error| CliError(format!("read {} failed: {error}", metadata_path.display())))?;
    if parse_json_usize_field(&metadata, "schema_version")? != 7 {
        return Err(CliError(format!(
            "{} is not a schema_version=7 benchmark metadata file",
            metadata_path.display()
        )));
    }
    let metadata_run_id = parse_json_u64_field(&metadata, "run_id")?;
    if metadata_run_id != manifest_run_id {
        return Err(CliError(format!(
            "metadata run_id {metadata_run_id} does not match manifest run_id {manifest_run_id}"
        )));
    }

    let nv_powers = parse_json_usize_array_field(&metadata, "nv_powers")?;
    let sizes = parse_json_usize_array_field(&metadata, "sizes")?;
    let workers = parse_json_usize_array_field(&metadata, "workers")?;
    let pcs_queries = parse_json_usize_field(&metadata, "pcs_queries")?;
    let repeats = parse_json_usize_field(&metadata, "repeats")?;
    if repeats != BENCHMARK_REPEATS {
        return Err(CliError(format!(
            "benchmark metadata repeats must be {BENCHMARK_REPEATS}, got {repeats}"
        )));
    }
    if nv_powers.len() != sizes.len() {
        return Err(CliError(format!(
            "metadata nv_powers length {} does not match sizes length {}",
            nv_powers.len(),
            sizes.len()
        )));
    }
    for (nv_power, size) in nv_powers.iter().zip(&sizes) {
        if *nv_power != crate::nv_power(*size) {
            return Err(CliError(format!(
                "metadata nv_power {nv_power} does not match size {size}"
            )));
        }
    }

    let runner = parse_benchmark_runner(&parse_json_pretty_string_field(&metadata, "runner")?)?;
    let runner_names = runner
        .variants()
        .into_iter()
        .map(BenchmarkRunner::as_str)
        .collect::<Vec<_>>();
    let expected_record_count = nv_powers.len() * workers.len() * runner_names.len() * 2 * repeats;
    let record_count = parse_json_usize_field(&metadata, "record_count")?;
    if record_count != expected_record_count {
        return Err(CliError(format!(
            "metadata record_count {record_count} does not match expected performance grid {expected_record_count}"
        )));
    }
    require_metadata_usize(&metadata, "positive_verified", expected_record_count)?;
    require_metadata_usize(&metadata, "negative_rejected", 0)?;

    let grid = BenchmarkGrid {
        runner_names: &runner_names,
        nv_powers: &nv_powers,
        sizes: &sizes,
        workers: &workers,
        pcs_queries,
        repeats,
    };

    let source_rows_checked =
        verify_benchmark_source_csv_semantics(dir, &grid, expected_record_count)?;
    verify_source_json_count(dir, expected_record_count)?;
    let summary_rows_checked =
        verify_summary_stats_csv_semantics(dir, &grid, expected_record_count)?;
    let phase_rows_checked = verify_phase_timing_csv_semantics(dir, expected_record_count)?;
    verify_overview_artifact_links(dir)?;
    verify_benchmark_render_artifacts(dir)?;

    Ok(ResultSemanticReport {
        source_rows_checked,
        phase_rows_checked,
        summary_rows_checked,
    })
}

struct BenchmarkGrid<'a> {
    runner_names: &'a [&'static str],
    nv_powers: &'a [usize],
    sizes: &'a [usize],
    workers: &'a [usize],
    pcs_queries: usize,
    repeats: usize,
}

fn verify_benchmark_source_csv_semantics(
    dir: &Path,
    grid: &BenchmarkGrid<'_>,
    expected_records: usize,
) -> Result<usize, CliError> {
    let source_path = dir.join("source.csv");
    let source = fs::read_to_string(&source_path)
        .map_err(|error| CliError(format!("read {} failed: {error}", source_path.display())))?;
    let mut lines = source.lines();
    let header = lines
        .next()
        .ok_or_else(|| CliError("source.csv is empty".to_owned()))?;
    if header != SOURCE_CSV_HEADER {
        return Err(CliError(format!(
            "source.csv header mismatch: expected '{SOURCE_CSV_HEADER}', got '{header}'"
        )));
    }

    let mut expected = BTreeSet::new();
    for runner in grid.runner_names {
        for protocol in ["r1cs", "plonkish"] {
            for size in grid.sizes {
                for worker in grid.workers {
                    for trial in 1..=grid.repeats {
                        expected.insert((
                            (*runner).to_owned(),
                            protocol.to_owned(),
                            *size,
                            *worker,
                            trial,
                        ));
                    }
                }
            }
        }
    }

    let mut actual = BTreeSet::new();
    let mut rows = 0_usize;
    for (line_index, line) in lines.enumerate() {
        let fields = split_csv_line(line).map_err(|error| {
            CliError(format!(
                "source.csv row {} could not be parsed: {}",
                line_index + 2,
                error.0
            ))
        })?;
        verify_source_csv_row(&fields, line_index + 2, grid, &mut actual, "source.csv")?;
        rows += 1;
    }

    if rows != expected_records {
        return Err(CliError(format!(
            "source.csv expected {expected_records} rows, got {rows}"
        )));
    }
    if actual != expected {
        if let Some(missing) = expected.difference(&actual).next() {
            return Err(CliError(format!(
                "source.csv missing runner={} protocol={} size={} workers={} trial={}",
                missing.0, missing.1, missing.2, missing.3, missing.4
            )));
        }
        if let Some(extra) = actual.difference(&expected).next() {
            return Err(CliError(format!(
                "source.csv has unexpected runner={} protocol={} size={} workers={} trial={}",
                extra.0, extra.1, extra.2, extra.3, extra.4
            )));
        }
    }
    Ok(rows)
}

fn verify_source_csv_row(
    fields: &[String],
    row: usize,
    grid: &BenchmarkGrid<'_>,
    actual: &mut BTreeSet<(String, String, usize, usize, usize)>,
    context: &str,
) -> Result<(), CliError> {
    if fields.len() != 29 {
        return Err(CliError(format!(
            "{context} row {row} has {} fields, expected 29",
            fields.len()
        )));
    }
    let protocol = fields[0].as_str();
    let runner = fields[1].as_str();
    let case = fields[2].as_str();
    let trial = parse_csv_usize_context(&fields[3], "trial", row, context)?;
    let row_workers = parse_csv_usize_context(&fields[4], "workers", row, context)?;
    let nv_power = parse_csv_usize_context(&fields[5], "nv_power", row, context)?;
    let size = parse_csv_usize_context(&fields[6], "size", row, context)?;
    let constraints = parse_csv_usize_context(&fields[7], "constraints", row, context)?;
    let row_pcs_queries = parse_csv_usize_context(&fields[8], "pcs_queries", row, context)?;
    let prove_ms = parse_csv_f64_context(&fields[9], "prove_ms", row, context)?;
    let verify_ms = parse_csv_f64_context(&fields[10], "verify_ms", row, context)?;
    let prove_pcs_commit_ms =
        parse_csv_f64_context(&fields[11], "prove_pcs_commit_ms", row, context)?;
    let prove_sumcheck_ms = parse_csv_f64_context(&fields[12], "prove_sumcheck_ms", row, context)?;
    let prove_batch_open_ms =
        parse_csv_f64_context(&fields[13], "prove_batch_open_ms", row, context)?;
    let prove_other_ms = parse_csv_f64_context(&fields[14], "prove_other_ms", row, context)?;
    let verify_pcs_open_ms =
        parse_csv_f64_context(&fields[15], "verify_pcs_open_ms", row, context)?;
    let verify_sumcheck_ms =
        parse_csv_f64_context(&fields[16], "verify_sumcheck_ms", row, context)?;
    let verify_other_ms = parse_csv_f64_context(&fields[17], "verify_other_ms", row, context)?;
    let proof_bytes = parse_csv_usize_context(&fields[18], "proof_bytes", row, context)?;
    let proof_pcs_bytes = parse_csv_usize_context(&fields[19], "proof_pcs_bytes", row, context)?;
    let proof_sumcheck_bytes =
        parse_csv_usize_context(&fields[20], "proof_sumcheck_bytes", row, context)?;
    let proof_other_bytes =
        parse_csv_usize_context(&fields[21], "proof_other_bytes", row, context)?;
    let communication_bytes =
        parse_csv_usize_context(&fields[22], "communication_bytes", row, context)?;
    let network_bytes = parse_csv_usize_context(&fields[23], "network_bytes", row, context)?;
    let host_logical_cores = fields[24].as_str();
    let cores_per_worker = fields[25].as_str();
    let core_affinity = fields[26].as_str();
    let verified = fields[27].as_str();
    let failure_reason = fields[28].as_str();

    if !["r1cs", "plonkish"].contains(&protocol) {
        return Err(CliError(format!(
            "{context} row {row} has unsupported protocol '{protocol}'"
        )));
    }
    if !grid.runner_names.contains(&runner) {
        return Err(CliError(format!(
            "{context} row {row} has runner '{runner}' outside metadata runner set {:?}",
            grid.runner_names
        )));
    }
    if case != "positive" || verified != "true" || !failure_reason.is_empty() {
        return Err(CliError(format!(
            "{context} row {row} must be a verified positive performance run with empty failure_reason"
        )));
    }
    if trial == 0 || trial > grid.repeats {
        return Err(CliError(format!(
            "{context} row {row} trial {trial} is outside 1..={}",
            grid.repeats
        )));
    }
    if !grid.workers.contains(&row_workers) {
        return Err(CliError(format!(
            "{context} row {row} workers {row_workers} is not listed in metadata"
        )));
    }
    if !grid.nv_powers.contains(&nv_power) || !grid.sizes.contains(&size) {
        return Err(CliError(format!(
            "{context} row {row} n/size pair {nv_power}/{size} is not listed in metadata"
        )));
    }
    if nv_power != crate::nv_power(size) {
        return Err(CliError(format!(
            "{context} row {row} nv_power {nv_power} does not match size {size}"
        )));
    }
    if constraints == 0 || proof_bytes == 0 || communication_bytes == 0 {
        return Err(CliError(format!(
            "{context} row {row} has zero constraints, proof bytes, or communication bytes"
        )));
    }
    if proof_pcs_bytes + proof_sumcheck_bytes + proof_other_bytes != proof_bytes {
        return Err(CliError(format!(
            "{context} row {row} proof-size breakdown does not sum to proof_bytes"
        )));
    }
    if row_pcs_queries != grid.pcs_queries {
        return Err(CliError(format!(
            "{context} row {row} pcs_queries expected {}, got {row_pcs_queries}",
            grid.pcs_queries
        )));
    }
    if !prove_ms.is_finite() || !verify_ms.is_finite() || prove_ms <= 0.0 || verify_ms <= 0.0 {
        return Err(CliError(format!(
            "{context} row {row} has non-positive or non-finite timing"
        )));
    }
    for (name, value) in [
        ("prove_pcs_commit_ms", prove_pcs_commit_ms),
        ("prove_sumcheck_ms", prove_sumcheck_ms),
        ("prove_batch_open_ms", prove_batch_open_ms),
        ("prove_other_ms", prove_other_ms),
        ("verify_pcs_open_ms", verify_pcs_open_ms),
        ("verify_sumcheck_ms", verify_sumcheck_ms),
        ("verify_other_ms", verify_other_ms),
    ] {
        if !value.is_finite() || value < 0.0 {
            return Err(CliError(format!("{context} row {row} has invalid {name}")));
        }
    }
    let prove_stage_sum =
        prove_pcs_commit_ms + prove_sumcheck_ms + prove_batch_open_ms + prove_other_ms;
    let verify_stage_sum = verify_pcs_open_ms + verify_sumcheck_ms + verify_other_ms;
    if (prove_stage_sum - prove_ms).abs() > 2.0 || (verify_stage_sum - verify_ms).abs() > 2.0 {
        return Err(CliError(format!(
            "{context} row {row} stage timing sums do not match total prove/verify time"
        )));
    }
    match runner {
        "local"
            if network_bytes != 0
                || !host_logical_cores.is_empty()
                || !cores_per_worker.is_empty()
                || !core_affinity.is_empty() =>
        {
            return Err(CliError(format!(
                "{context} row {row} local runner must have zero network bytes and empty affinity fields"
            )));
        }
        "network"
            if network_bytes == 0
                || host_logical_cores.is_empty()
                || cores_per_worker.is_empty()
                || core_affinity.is_empty() =>
        {
            return Err(CliError(format!(
                "{context} row {row} network runner must record network bytes and affinity fields"
            )));
        }
        _ => {}
    }
    if !actual.insert((
        runner.to_owned(),
        protocol.to_owned(),
        size,
        row_workers,
        trial,
    )) {
        return Err(CliError(format!(
            "{context} duplicates runner={runner} protocol={protocol} size={size} workers={row_workers} trial={trial}"
        )));
    }
    Ok(())
}

fn verify_source_json_count(dir: &Path, expected_records: usize) -> Result<(), CliError> {
    let source_path = dir.join("source.json");
    let source = fs::read_to_string(&source_path)
        .map_err(|error| CliError(format!("read {} failed: {error}", source_path.display())))?;
    let rows = source.matches("\"protocol\"").count();
    if rows != expected_records {
        return Err(CliError(format!(
            "source.json expected {expected_records} protocol records, got {rows}"
        )));
    }
    Ok(())
}

fn verify_summary_stats_csv_semantics(
    dir: &Path,
    grid: &BenchmarkGrid<'_>,
    expected_records: usize,
) -> Result<usize, CliError> {
    let summary_path = dir.join("summary_stats.csv");
    let summary = fs::read_to_string(&summary_path)
        .map_err(|error| CliError(format!("read {} failed: {error}", summary_path.display())))?;
    let mut lines = summary.lines();
    let header = lines
        .next()
        .ok_or_else(|| CliError("summary_stats.csv is empty".to_owned()))?;
    if header != SUMMARY_STATS_CSV_HEADER {
        return Err(CliError(format!(
            "summary_stats.csv header mismatch: expected '{SUMMARY_STATS_CSV_HEADER}', got '{header}'"
        )));
    }
    let mut rows = 0_usize;
    let mut actual = BTreeSet::new();
    for (line_index, line) in lines.enumerate() {
        let fields = split_csv_line(line).map_err(|error| {
            CliError(format!(
                "summary_stats.csv row {} could not be parsed: {}",
                line_index + 2,
                error.0
            ))
        })?;
        if fields.len() != 30 {
            return Err(CliError(format!(
                "summary_stats.csv row {} has {} fields, expected 30",
                line_index + 2,
                fields.len()
            )));
        }
        let protocol = fields[0].as_str();
        let runner = fields[1].as_str();
        let case = fields[2].as_str();
        let row_workers =
            parse_csv_usize_context(&fields[3], "workers", line_index + 2, "summary_stats.csv")?;
        let nv_power =
            parse_csv_usize_context(&fields[4], "nv_power", line_index + 2, "summary_stats.csv")?;
        let size =
            parse_csv_usize_context(&fields[5], "size", line_index + 2, "summary_stats.csv")?;
        let row_pcs_queries = parse_csv_usize_context(
            &fields[7],
            "pcs_queries",
            line_index + 2,
            "summary_stats.csv",
        )?;
        let samples =
            parse_csv_usize_context(&fields[8], "samples", line_index + 2, "summary_stats.csv")?;
        let verified_count = parse_csv_usize_context(
            &fields[9],
            "verified_count",
            line_index + 2,
            "summary_stats.csv",
        )?;
        let rejected_count = parse_csv_usize_context(
            &fields[10],
            "rejected_count",
            line_index + 2,
            "summary_stats.csv",
        )?;
        let prove_ms = parse_csv_f64_context(
            &fields[11],
            "prove_ms_mean",
            line_index + 2,
            "summary_stats.csv",
        )?;
        let verify_ms = parse_csv_f64_context(
            &fields[13],
            "verify_ms_mean",
            line_index + 2,
            "summary_stats.csv",
        )?;
        let prove_pcs_commit_ms = parse_csv_f64_context(
            &fields[15],
            "prove_pcs_commit_ms_mean",
            line_index + 2,
            "summary_stats.csv",
        )?;
        let prove_sumcheck_ms = parse_csv_f64_context(
            &fields[16],
            "prove_sumcheck_ms_mean",
            line_index + 2,
            "summary_stats.csv",
        )?;
        let prove_batch_open_ms = parse_csv_f64_context(
            &fields[17],
            "prove_batch_open_ms_mean",
            line_index + 2,
            "summary_stats.csv",
        )?;
        let verify_pcs_open_ms = parse_csv_f64_context(
            &fields[18],
            "verify_pcs_open_ms_mean",
            line_index + 2,
            "summary_stats.csv",
        )?;
        let verify_sumcheck_ms = parse_csv_f64_context(
            &fields[19],
            "verify_sumcheck_ms_mean",
            line_index + 2,
            "summary_stats.csv",
        )?;
        let proof_bytes = parse_csv_f64_context(
            &fields[20],
            "proof_bytes_mean",
            line_index + 2,
            "summary_stats.csv",
        )?;
        let proof_pcs_bytes = parse_csv_f64_context(
            &fields[22],
            "proof_pcs_bytes_mean",
            line_index + 2,
            "summary_stats.csv",
        )?;
        let proof_sumcheck_bytes = parse_csv_f64_context(
            &fields[23],
            "proof_sumcheck_bytes_mean",
            line_index + 2,
            "summary_stats.csv",
        )?;
        let proof_other_bytes = parse_csv_f64_context(
            &fields[24],
            "proof_other_bytes_mean",
            line_index + 2,
            "summary_stats.csv",
        )?;
        if !["r1cs", "plonkish"].contains(&protocol)
            || !grid.runner_names.contains(&runner)
            || case != "positive"
            || !grid.workers.contains(&row_workers)
            || !grid.nv_powers.contains(&nv_power)
            || !grid.sizes.contains(&size)
            || nv_power != crate::nv_power(size)
            || row_pcs_queries != grid.pcs_queries
            || samples != grid.repeats
            || verified_count != grid.repeats
            || rejected_count != 0
            || prove_ms <= 0.0
            || verify_ms <= 0.0
            || prove_pcs_commit_ms < 0.0
            || prove_sumcheck_ms < 0.0
            || prove_batch_open_ms < 0.0
            || verify_pcs_open_ms < 0.0
            || verify_sumcheck_ms < 0.0
            || proof_bytes <= 0.0
            || proof_pcs_bytes < 0.0
            || proof_sumcheck_bytes < 0.0
            || proof_other_bytes < 0.0
        {
            return Err(CliError(format!(
                "summary_stats.csv row {} is inconsistent with metadata/source performance grid",
                line_index + 2
            )));
        }
        if !actual.insert((
            runner.to_owned(),
            protocol.to_owned(),
            size,
            row_workers,
            samples,
        )) {
            return Err(CliError(format!(
                "summary_stats.csv duplicates runner={runner} protocol={protocol} size={size} workers={row_workers}"
            )));
        }
        rows += 1;
    }
    if rows != expected_records {
        return Err(CliError(format!(
            "summary_stats.csv expected {expected_records} rows, got {rows}"
        )));
    }
    Ok(rows)
}

fn verify_phase_timing_csv_semantics(dir: &Path, expected_jobs: usize) -> Result<usize, CliError> {
    let phase_path = dir.join("phase_timing.csv");
    let phase = fs::read_to_string(&phase_path)
        .map_err(|error| CliError(format!("read {} failed: {error}", phase_path.display())))?;
    let mut lines = phase.lines();
    let header = lines
        .next()
        .ok_or_else(|| CliError("phase_timing.csv is empty".to_owned()))?;
    if header != PHASE_TIMING_CSV_HEADER {
        return Err(CliError(format!(
            "phase_timing.csv header mismatch: expected '{PHASE_TIMING_CSV_HEADER}', got '{header}'"
        )));
    }
    let mut rows = 0_usize;
    let mut job_rows = 0_usize;
    let mut has_source_artifacts = false;
    let mut has_final_artifacts = false;
    let mut has_total = false;
    let mut has_figure_compile_failed = false;
    let mut has_total_before_error = false;
    for (line_index, line) in lines.enumerate() {
        let fields = split_csv_line(line).map_err(|error| {
            CliError(format!(
                "phase_timing.csv row {} could not be parsed: {}",
                line_index + 2,
                error.0
            ))
        })?;
        if fields.len() != 6 {
            return Err(CliError(format!(
                "phase_timing.csv row {} has {} fields, expected 6",
                line_index + 2,
                fields.len()
            )));
        }
        let phase_name = fields[0].as_str();
        let elapsed_ms =
            parse_csv_f64_context(&fields[2], "elapsed_ms", line_index + 2, "phase_timing.csv")?;
        if !elapsed_ms.is_finite() || elapsed_ms < 0.0 {
            return Err(CliError(format!(
                "phase_timing.csv row {} has invalid elapsed_ms",
                line_index + 2
            )));
        }
        match phase_name {
            "job" | "pcs_job" => {
                job_rows += 1;
                if elapsed_ms <= 0.0 {
                    return Err(CliError(format!(
                        "phase_timing.csv row {} job elapsed_ms must be positive",
                        line_index + 2
                    )));
                }
            }
            "source_and_chart_artifacts" => has_source_artifacts = true,
            "figure_compile" => {}
            "figure_compile_failed" => has_figure_compile_failed = true,
            "final_result_artifacts" => has_final_artifacts = true,
            "pcs_warmup" => {
                if elapsed_ms <= 0.0 {
                    return Err(CliError(format!(
                        "phase_timing.csv row {} PCS warm-up elapsed_ms must be positive",
                        line_index + 2
                    )));
                }
            }
            "total" => has_total = true,
            "total_before_error" => has_total_before_error = true,
            "network_worker_pool_start" | "network_worker_pool_shutdown" => {
                if elapsed_ms <= 0.0 {
                    return Err(CliError(format!(
                        "phase_timing.csv row {} network worker phase elapsed_ms must be positive",
                        line_index + 2
                    )));
                }
            }
            "setup" => {}
            other => {
                return Err(CliError(format!(
                    "phase_timing.csv row {} has unknown phase '{other}'",
                    line_index + 2
                )));
            }
        }
        rows += 1;
    }
    if job_rows != expected_jobs {
        return Err(CliError(format!(
            "phase_timing.csv expected {expected_jobs} job rows, got {job_rows}"
        )));
    }
    let completed = has_source_artifacts && has_final_artifacts && has_total;
    let failed_during_figure_compile =
        has_source_artifacts && has_figure_compile_failed && has_total_before_error;
    if !completed && !failed_during_figure_compile {
        return Err(CliError(
            "phase_timing.csv must include complete final phases or a figure_compile_failed total_before_error phase pair"
                .to_owned(),
        ));
    }
    Ok(rows)
}

fn verify_overview_artifact_links(dir: &Path) -> Result<(), CliError> {
    let overview = fs::read_to_string(dir.join(OVERVIEW_HTML))
        .map_err(|error| CliError(format!("read overview.html failed: {error}")))?;
    for required in [
        "All positive performance proofs verified",
        "source.csv",
        "summary_stats.csv",
        "phase_timing.csv",
        "result_manifest.json",
        "worker_scaling_max_size.svg",
        "Core Allocation",
    ] {
        if !overview.contains(required) {
            return Err(CliError(format!(
                "overview.html missing required benchmark marker '{required}'"
            )));
        }
    }
    Ok(())
}

fn verify_benchmark_render_artifacts(dir: &Path) -> Result<(), CliError> {
    for artifact in [
        "prove_time_by_size.svg",
        "verify_time_by_size.svg",
        "proof_bytes_by_size.svg",
        "network_bytes_by_size.svg",
        "runner_overhead_by_size.svg",
        "worker_scaling_max_size.svg",
    ] {
        verify_svg_artifact(dir, artifact, "benchmark")?;
    }
    for artifact in [
        "prove_time_by_size.tex",
        "verify_time_by_size.tex",
        "proof_bytes_by_size.tex",
        "network_bytes_by_size.tex",
        "runner_overhead_by_size.tex",
        "worker_scaling_max_size.tex",
    ] {
        verify_pgfplots_artifact(dir, artifact, "benchmark")?;
    }
    verify_paper_figures_tex(dir, "benchmark")?;
    verify_standalone_tex(dir, "benchmark")?;
    let compiled_figure = dir.join(COMPILED_PAPER_FIGURE);
    if compiled_figure.exists() {
        verify_pdf_artifact(dir, COMPILED_PAPER_FIGURE, "benchmark")?;
    }
    Ok(())
}

fn verify_svg_artifact(dir: &Path, artifact: &str, context: &str) -> Result<(), CliError> {
    let svg = fs::read_to_string(dir.join(artifact))
        .map_err(|error| CliError(format!("read {artifact} failed: {error}")))?;
    for required in ["<svg", "</svg>", "<style>", "class=\"title\""] {
        if !svg.contains(required) {
            return Err(CliError(format!(
                "{context} {artifact} missing required SVG marker '{required}'"
            )));
        }
    }
    Ok(())
}

fn verify_pgfplots_artifact(dir: &Path, artifact: &str, context: &str) -> Result<(), CliError> {
    let tex = fs::read_to_string(dir.join(artifact))
        .map_err(|error| CliError(format!("read {artifact} failed: {error}")))?;
    for required in [
        "Generated by pq-experiments",
        "\\begin{tikzpicture}",
        "\\begin{axis}",
        "source.csv",
    ] {
        if !tex.contains(required) {
            return Err(CliError(format!(
                "{context} {artifact} missing required PGFPlots marker '{required}'"
            )));
        }
    }
    if artifact != "runner_overhead_by_size.tex" && !tex.contains("\\addplot") {
        return Err(CliError(format!(
            "{context} {artifact} missing required PGFPlots marker '\\addplot'"
        )));
    }
    Ok(())
}

fn verify_paper_figures_tex(dir: &Path, context: &str) -> Result<(), CliError> {
    let paper_tex = fs::read_to_string(dir.join("paper_figures.tex"))
        .map_err(|error| CliError(format!("read paper_figures.tex failed: {error}")))?;
    for required in [
        "Generated by pq-experiments",
        "Source data: source.csv/source.json",
        "\\begin{groupplot}",
        "Perfect upper bound",
    ] {
        if !paper_tex.contains(required) {
            return Err(CliError(format!(
                "{context} paper_figures.tex missing required marker '{required}'"
            )));
        }
    }
    Ok(())
}

fn verify_standalone_tex(dir: &Path, context: &str) -> Result<(), CliError> {
    let standalone = fs::read_to_string(dir.join("paper_figures_standalone.tex"))
        .map_err(|error| CliError(format!("read paper_figures_standalone.tex failed: {error}")))?;
    for required in [
        "\\documentclass",
        "\\input{paper_figures.tex}",
        "\\end{document}",
    ] {
        if !standalone.contains(required) {
            return Err(CliError(format!(
                "{context} paper_figures_standalone.tex missing required marker '{required}'"
            )));
        }
    }
    Ok(())
}

fn verify_pdf_artifact(dir: &Path, artifact: &str, context: &str) -> Result<(), CliError> {
    let pdf = fs::read(dir.join(artifact))
        .map_err(|error| CliError(format!("read {artifact} failed: {error}")))?;
    if !pdf.starts_with(b"%PDF") {
        return Err(CliError(format!("{context} {artifact} is not a PDF file")));
    }
    Ok(())
}

fn verify_benchmark_paper_quality(dir: &Path) -> Result<(), CliError> {
    let metadata_path = dir.join("metadata.json");
    let metadata = fs::read_to_string(&metadata_path)
        .map_err(|error| CliError(format!("read {} failed: {error}", metadata_path.display())))?;
    if parse_json_usize_field(&metadata, "schema_version")? != 7 {
        return Err(CliError(format!(
            "{} is not a schema_version=7 benchmark metadata file",
            metadata_path.display()
        )));
    }

    let expected_nv_powers = (PAPER_PRESET_NV_START..=PAPER_PRESET_NV_END).collect::<Vec<_>>();
    require_metadata_string(&metadata, "build_profile", "release")?;
    require_metadata_bool(&metadata, "paper_preset", true)?;
    require_metadata_string(&metadata, "runner", "both")?;
    require_metadata_bool(&metadata, "compile_figures_requested", true)?;
    require_metadata_bool(&metadata, "compile_figures_succeeded", true)?;
    require_metadata_usize_array(&metadata, "nv_powers", &expected_nv_powers)?;
    require_metadata_usize_array(&metadata, "workers", PAPER_PRESET_WORKERS)?;

    let repeats = parse_json_usize_field(&metadata, "repeats")?;
    if repeats != BENCHMARK_REPEATS {
        return Err(CliError(format!(
            "paper-quality performance benchmark requires repeats={}, got {}",
            BENCHMARK_REPEATS, repeats
        )));
    }
    let pcs_queries = parse_json_usize_field(&metadata, "pcs_queries")?;
    if pcs_queries < PAPER_PRESET_PCS_QUERIES {
        return Err(CliError(format!(
            "paper-quality benchmark requires pcs_queries >= {}, got {}",
            PAPER_PRESET_PCS_QUERIES, pcs_queries
        )));
    }

    let expected_positive = expected_nv_powers.len() * PAPER_PRESET_WORKERS.len() * 2 * 2 * repeats;
    let expected_records = expected_positive;
    require_metadata_usize(&metadata, "record_count", expected_records)?;
    require_metadata_usize(&metadata, "positive_verified", expected_positive)?;
    require_metadata_usize(&metadata, "negative_rejected", 0)?;

    let compiled_figure = dir.join(COMPILED_PAPER_FIGURE);
    if !compiled_figure.is_file() {
        return Err(CliError(format!(
            "paper-quality benchmark requires compiled figure {}",
            compiled_figure.display()
        )));
    }
    verify_paper_quality_source_csv(
        dir,
        &expected_nv_powers,
        PAPER_PRESET_WORKERS,
        pcs_queries,
        repeats,
        expected_records,
    )?;
    verify_paper_quality_phase_timing(dir, expected_records)?;
    verify_paper_quality_figure_artifacts(dir)?;
    Ok(())
}

fn verify_paper_quality_source_csv(
    dir: &Path,
    expected_nv_powers: &[usize],
    expected_workers: &[usize],
    pcs_queries: usize,
    repeats: usize,
    expected_records: usize,
) -> Result<(), CliError> {
    let source_path = dir.join("source.csv");
    let source = fs::read_to_string(&source_path)
        .map_err(|error| CliError(format!("read {} failed: {error}", source_path.display())))?;
    let mut lines = source.lines();
    let header = lines
        .next()
        .ok_or_else(|| CliError("paper-quality source.csv is empty".to_owned()))?;
    if header != SOURCE_CSV_HEADER {
        return Err(CliError(format!(
            "paper-quality source.csv header mismatch: expected '{SOURCE_CSV_HEADER}', got '{header}'"
        )));
    }

    let expected_protocols = ["r1cs", "plonkish"];
    let expected_runners = ["local", "network"];
    let mut expected = BTreeSet::new();
    for runner in expected_runners {
        for protocol in expected_protocols {
            for nv_power in expected_nv_powers {
                for worker in expected_workers {
                    for trial in 1..=repeats {
                        expected.insert((
                            runner.to_owned(),
                            protocol.to_owned(),
                            *nv_power,
                            *worker,
                            trial,
                        ));
                    }
                }
            }
        }
    }

    let mut actual = BTreeSet::new();
    let mut rows = 0_usize;
    for (line_index, line) in lines.enumerate() {
        let fields = split_csv_line(line).map_err(|error| {
            CliError(format!(
                "paper-quality source.csv row {} could not be parsed: {}",
                line_index + 2,
                error.0
            ))
        })?;
        if fields.len() != 19 {
            return Err(CliError(format!(
                "paper-quality source.csv row {} has {} fields, expected 19",
                line_index + 2,
                fields.len()
            )));
        }
        let protocol = fields[0].as_str();
        let runner = fields[1].as_str();
        let case = fields[2].as_str();
        let trial = parse_csv_usize(&fields[3], "trial", line_index + 2)?;
        let workers = parse_csv_usize(&fields[4], "workers", line_index + 2)?;
        let nv_power = parse_csv_usize(&fields[5], "nv_power", line_index + 2)?;
        let size = parse_csv_usize(&fields[6], "size", line_index + 2)?;
        let row_pcs_queries = parse_csv_usize(&fields[8], "pcs_queries", line_index + 2)?;
        let prove_ms = parse_csv_f64(&fields[9], "prove_ms", line_index + 2)?;
        let verify_ms = parse_csv_f64(&fields[10], "verify_ms", line_index + 2)?;
        let proof_bytes = parse_csv_usize(&fields[11], "proof_bytes", line_index + 2)?;
        let communication_bytes =
            parse_csv_usize(&fields[12], "communication_bytes", line_index + 2)?;
        let network_bytes = parse_csv_usize(&fields[13], "network_bytes", line_index + 2)?;
        let verified = fields[17].as_str();
        let failure_reason = fields[18].as_str();

        if !expected_protocols.contains(&protocol) || !expected_runners.contains(&runner) {
            return Err(CliError(format!(
                "paper-quality source.csv row {} has unexpected runner/protocol {runner}/{protocol}",
                line_index + 2
            )));
        }
        if case != "positive" || verified != "true" || !failure_reason.is_empty() {
            return Err(CliError(format!(
                "paper-quality source.csv row {} must be a verified positive performance run",
                line_index + 2
            )));
        }
        if row_pcs_queries != pcs_queries {
            return Err(CliError(format!(
                "paper-quality source.csv row {} pcs_queries expected {}, got {}",
                line_index + 2,
                pcs_queries,
                row_pcs_queries
            )));
        }
        if size != (1_usize << nv_power) {
            return Err(CliError(format!(
                "paper-quality source.csv row {} size {} does not equal 2^{}",
                line_index + 2,
                size,
                nv_power
            )));
        }
        if !prove_ms.is_finite()
            || !verify_ms.is_finite()
            || prove_ms <= 0.0
            || verify_ms <= 0.0
            || proof_bytes == 0
            || communication_bytes == 0
        {
            return Err(CliError(format!(
                "paper-quality source.csv row {} has non-positive timing or size metrics",
                line_index + 2
            )));
        }
        if runner == "network" && network_bytes == 0 {
            return Err(CliError(format!(
                "paper-quality source.csv row {} network run must record network_bytes",
                line_index + 2
            )));
        }
        if runner == "local" && network_bytes != 0 {
            return Err(CliError(format!(
                "paper-quality source.csv row {} local run must have zero network_bytes",
                line_index + 2
            )));
        }

        if !actual.insert((
            runner.to_owned(),
            protocol.to_owned(),
            nv_power,
            workers,
            trial,
        )) {
            return Err(CliError(format!(
                "paper-quality source.csv duplicates runner={runner} protocol={protocol} n={nv_power} workers={workers} trial={trial}"
            )));
        }
        rows += 1;
    }

    if rows != expected_records {
        return Err(CliError(format!(
            "paper-quality source.csv expected {expected_records} rows, got {rows}"
        )));
    }
    if actual != expected {
        if let Some(missing) = expected.difference(&actual).next() {
            return Err(CliError(format!(
                "paper-quality source.csv missing runner={} protocol={} n={} workers={} trial={}",
                missing.0, missing.1, missing.2, missing.3, missing.4
            )));
        }
        if let Some(extra) = actual.difference(&expected).next() {
            return Err(CliError(format!(
                "paper-quality source.csv has unexpected runner={} protocol={} n={} workers={} trial={}",
                extra.0, extra.1, extra.2, extra.3, extra.4
            )));
        }
    }
    Ok(())
}

fn verify_paper_quality_phase_timing(dir: &Path, expected_jobs: usize) -> Result<(), CliError> {
    let phase_path = dir.join("phase_timing.csv");
    let phase = fs::read_to_string(&phase_path)
        .map_err(|error| CliError(format!("read {} failed: {error}", phase_path.display())))?;
    let mut lines = phase.lines();
    let header = lines
        .next()
        .ok_or_else(|| CliError("paper-quality phase_timing.csv is empty".to_owned()))?;
    if header != PHASE_TIMING_CSV_HEADER {
        return Err(CliError(
            "paper-quality phase_timing.csv header mismatch".to_owned(),
        ));
    }
    let mut job_rows = 0_usize;
    let mut has_source_artifacts = false;
    let mut has_final_artifacts = false;
    let mut has_total = false;
    for line in lines {
        let phase_name = line.split(',').next().unwrap_or_default();
        match phase_name {
            "job" => job_rows += 1,
            "source_and_chart_artifacts" => has_source_artifacts = true,
            "final_result_artifacts" => has_final_artifacts = true,
            "total" => has_total = true,
            _ => {}
        }
    }
    if job_rows != expected_jobs {
        return Err(CliError(format!(
            "paper-quality phase_timing.csv expected {expected_jobs} job rows, got {job_rows}"
        )));
    }
    if !has_source_artifacts || !has_final_artifacts || !has_total {
        return Err(CliError(
            "paper-quality phase_timing.csv must include source_and_chart_artifacts, final_result_artifacts, and total phases"
                .to_owned(),
        ));
    }
    Ok(())
}

fn verify_paper_quality_figure_artifacts(dir: &Path) -> Result<(), CliError> {
    verify_benchmark_render_artifacts(dir)?;

    let overview = fs::read_to_string(dir.join(OVERVIEW_HTML))
        .map_err(|error| CliError(format!("read overview.html failed: {error}")))?;
    for required in [
        "All positive performance proofs verified",
        "source.csv",
        "worker_scaling_max_size.svg",
        "Core Allocation",
    ] {
        if !overview.contains(required) {
            return Err(CliError(format!(
                "paper-quality overview.html missing required marker '{required}'"
            )));
        }
    }

    verify_pdf_artifact(dir, COMPILED_PAPER_FIGURE, "paper-quality")
}

fn parse_csv_usize(value: &str, field: &str, row: usize) -> Result<usize, CliError> {
    parse_csv_usize_context(value, field, row, "paper-quality source.csv")
}

fn parse_csv_f64(value: &str, field: &str, row: usize) -> Result<f64, CliError> {
    parse_csv_f64_context(value, field, row, "paper-quality source.csv")
}

fn parse_csv_usize_context(
    value: &str,
    field: &str,
    row: usize,
    context: &str,
) -> Result<usize, CliError> {
    value.parse::<usize>().map_err(|error| {
        CliError(format!(
            "{context} row {row} field {field} is not usize: {error}"
        ))
    })
}

fn parse_csv_f64_context(
    value: &str,
    field: &str,
    row: usize,
    context: &str,
) -> Result<f64, CliError> {
    value.parse::<f64>().map_err(|error| {
        CliError(format!(
            "{context} row {row} field {field} is not f64: {error}"
        ))
    })
}

fn split_csv_line(line: &str) -> Result<Vec<String>, CliError> {
    let mut fields = Vec::new();
    let mut current = String::new();
    let mut in_quotes = false;
    let mut chars = line.chars().peekable();
    while let Some(character) = chars.next() {
        if in_quotes {
            match character {
                '"' => {
                    if chars.peek() == Some(&'"') {
                        current.push('"');
                        chars.next();
                    } else {
                        in_quotes = false;
                    }
                }
                _ => current.push(character),
            }
        } else {
            match character {
                ',' => {
                    fields.push(current);
                    current = String::new();
                }
                '"' if current.is_empty() => in_quotes = true,
                '"' => return Err(CliError("unexpected quote in unquoted field".to_owned())),
                _ => current.push(character),
            }
        }
    }
    if in_quotes {
        return Err(CliError("unterminated quoted field".to_owned()));
    }
    fields.push(current);
    Ok(fields)
}

fn require_metadata_string(metadata: &str, field: &str, expected: &str) -> Result<(), CliError> {
    let actual = parse_json_pretty_string_field(metadata, field)?;
    if actual == expected {
        Ok(())
    } else {
        Err(CliError(format!(
            "metadata field '{field}' expected '{expected}', got '{actual}'"
        )))
    }
}

fn require_metadata_bool(metadata: &str, field: &str, expected: bool) -> Result<(), CliError> {
    let actual = parse_json_bool_field(metadata, field)?;
    if actual == expected {
        Ok(())
    } else {
        Err(CliError(format!(
            "metadata field '{field}' expected {expected}, got {actual}"
        )))
    }
}

fn require_metadata_usize(metadata: &str, field: &str, expected: usize) -> Result<(), CliError> {
    let actual = parse_json_usize_field(metadata, field)?;
    if actual == expected {
        Ok(())
    } else {
        Err(CliError(format!(
            "metadata field '{field}' expected {expected}, got {actual}"
        )))
    }
}

fn require_metadata_usize_array(
    metadata: &str,
    field: &str,
    expected: &[usize],
) -> Result<(), CliError> {
    let actual = parse_json_usize_array_field(metadata, field)?;
    if actual == expected {
        Ok(())
    } else {
        Err(CliError(format!(
            "metadata field '{field}' expected {:?}, got {:?}",
            expected, actual
        )))
    }
}

fn benchmark_result_dir_entries(dir: &Path) -> Result<BTreeSet<String>, CliError> {
    let mut files = BTreeSet::new();
    collect_result_dir_entries(dir, dir, &mut files)?;
    Ok(files)
}

fn collect_result_dir_entries(
    root: &Path,
    dir: &Path,
    files: &mut BTreeSet<String>,
) -> Result<(), CliError> {
    for entry in fs::read_dir(dir).map_err(|error| {
        CliError(format!(
            "read benchmark dir {} failed: {error}",
            dir.display()
        ))
    })? {
        let entry =
            entry.map_err(|error| CliError(format!("read benchmark dir entry failed: {error}")))?;
        let file_type = entry.file_type().map_err(|error| {
            CliError(format!(
                "read file type for {} failed: {error}",
                entry.path().display()
            ))
        })?;
        let name = entry.file_name().into_string().map_err(|name| {
            CliError(format!(
                "benchmark artifact name is not valid UTF-8: {:?}",
                name
            ))
        })?;
        if file_type.is_dir() {
            if dir == root && name == "verifications" {
                continue;
            }
            collect_result_dir_entries(root, &entry.path(), files)?;
        } else if file_type.is_file() {
            files.insert(relative_artifact_path(root, &entry.path())?);
        } else {
            return Err(CliError(format!(
                "unexpected non-file artifact '{}' in {}",
                name,
                dir.display()
            )));
        }
    }
    Ok(())
}

fn parse_manifest_entries(manifest: &str) -> Result<Vec<ResultManifestEntry>, CliError> {
    let mut entries = Vec::new();
    for line in manifest.lines() {
        let trimmed = line.trim();
        if !trimmed.starts_with("{\"path\":") {
            continue;
        }
        let path = parse_json_string_field(trimmed, "path")?;
        let bytes = parse_json_usize_field(trimmed, "bytes")?;
        let sha256 = parse_json_string_field(trimmed, "sha256")?;
        if path.contains("..")
            || path.contains('\\')
            || path.starts_with('/')
            || path.split('/').any(str::is_empty)
        {
            return Err(CliError(format!(
                "manifest artifact path must be a relative file path under the result directory, got '{path}'"
            )));
        }
        if sha256.len() != 64 || !sha256.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err(CliError(format!(
                "manifest artifact '{path}' has invalid sha256"
            )));
        }
        entries.push(ResultManifestEntry {
            path,
            bytes,
            sha256,
        });
    }
    if entries.is_empty() {
        return Err(CliError("manifest contains no file entries".to_owned()));
    }
    Ok(entries)
}

fn parse_json_string_field(input: &str, field: &str) -> Result<String, CliError> {
    let marker = format!("\"{field}\":\"");
    let start = input
        .find(&marker)
        .ok_or_else(|| CliError(format!("missing JSON string field '{field}'")))?
        + marker.len();
    let rest = &input[start..];
    let end = rest
        .find('"')
        .ok_or_else(|| CliError(format!("unterminated JSON string field '{field}'")))?;
    Ok(rest[..end].to_owned())
}

fn parse_json_pretty_string_field(input: &str, field: &str) -> Result<String, CliError> {
    let marker = format!("\"{field}\":");
    let start = input
        .find(&marker)
        .ok_or_else(|| CliError(format!("missing JSON string field '{field}'")))?
        + marker.len();
    let rest = input[start..].trim_start();
    let rest = rest
        .strip_prefix('"')
        .ok_or_else(|| CliError(format!("JSON field '{field}' is not a string")))?;
    let end = rest
        .find('"')
        .ok_or_else(|| CliError(format!("unterminated JSON string field '{field}'")))?;
    Ok(rest[..end].to_owned())
}

fn parse_json_bool_field(input: &str, field: &str) -> Result<bool, CliError> {
    let marker = format!("\"{field}\":");
    let start = input
        .find(&marker)
        .ok_or_else(|| CliError(format!("missing JSON bool field '{field}'")))?
        + marker.len();
    let rest = input[start..].trim_start();
    if rest.starts_with("true") {
        Ok(true)
    } else if rest.starts_with("false") {
        Ok(false)
    } else {
        Err(CliError(format!("JSON field '{field}' is not boolean")))
    }
}

fn parse_json_usize_array_field(input: &str, field: &str) -> Result<Vec<usize>, CliError> {
    let marker = format!("\"{field}\":");
    let start = input
        .find(&marker)
        .ok_or_else(|| CliError(format!("missing JSON array field '{field}'")))?
        + marker.len();
    let rest = input[start..].trim_start();
    let rest = rest
        .strip_prefix('[')
        .ok_or_else(|| CliError(format!("JSON field '{field}' is not an array")))?;
    let end = rest
        .find(']')
        .ok_or_else(|| CliError(format!("unterminated JSON array field '{field}'")))?;
    let body = rest[..end].trim();
    if body.is_empty() {
        return Ok(Vec::new());
    }
    body.split(',')
        .map(|item| {
            item.trim().parse::<usize>().map_err(|_| {
                CliError(format!(
                    "JSON array field '{field}' contains non-usize item"
                ))
            })
        })
        .collect()
}

fn parse_json_usize_field(input: &str, field: &str) -> Result<usize, CliError> {
    let value = parse_json_unsigned_field(input, field)?;
    usize::try_from(value).map_err(|_| CliError(format!("JSON field '{field}' is too large")))
}

fn parse_json_u64_field(input: &str, field: &str) -> Result<u64, CliError> {
    parse_json_unsigned_field(input, field)
}

fn parse_json_unsigned_field(input: &str, field: &str) -> Result<u64, CliError> {
    let marker = format!("\"{field}\":");
    let start = input
        .find(&marker)
        .ok_or_else(|| CliError(format!("missing JSON numeric field '{field}'")))?
        + marker.len();
    let digits = input[start..]
        .trim_start()
        .chars()
        .take_while(|character| character.is_ascii_digit())
        .collect::<String>();
    if digits.is_empty() {
        return Err(CliError(format!("JSON field '{field}' is not numeric")));
    }
    digits
        .parse::<u64>()
        .map_err(|_| CliError(format!("JSON field '{field}' is too large")))
}

fn prompt_interactive_selection<R: BufRead, W: Write>(
    input: &mut R,
    output: &mut W,
) -> Result<InteractiveSelection, CliError> {
    writeln!(output, "pq_dSNARK experiment runner")
        .map_err(|error| CliError(format!("write prompt failed: {error}")))?;
    let mode = prompt_choice(
        input,
        output,
        "runner [local|net-proof|net-demo]",
        "local",
        &["local", "net-proof", "net-demo"],
    )?;
    let format = prompt_choice(
        input,
        output,
        "output format [json|csv]",
        "json",
        &["json", "csv"],
    )?;
    let output_format = parse_format(&format)?;
    let workers = prompt_positive_usize(input, output, "workers", 2)?;

    if mode == "net-demo" {
        let session = prompt_string(input, output, "session", "interactive-net-demo")?;
        let payload = prompt_string(input, output, "payload", "payload")?;
        return Ok(InteractiveSelection::NetDemo(NetDemoCommand {
            workers,
            session,
            payload,
            format: output_format,
        }));
    }

    let protocol = parse_protocol(&prompt_choice(
        input,
        output,
        "protocol [r1cs|plonkish]",
        "r1cs",
        &["r1cs", "plonkish"],
    )?)?;
    let size = prompt_positive_usize(input, output, "size", 8)?;
    let pcs_queries = prompt_positive_usize(input, output, "pcs queries", 3)?;
    let case = parse_case(&prompt_choice(
        input,
        output,
        "case [positive|negative|both]",
        "both",
        &["positive", "negative", "both"],
    )?)?;
    let mode = match mode.as_str() {
        "local" => InteractiveMode::Local,
        "net-proof" => InteractiveMode::NetProof,
        _ => return Err(CliError("invalid interactive runner".to_owned())),
    };

    Ok(InteractiveSelection::Experiment {
        mode,
        config: Config {
            protocol,
            workers,
            size,
            format: output_format,
            case,
            pcs_queries,
            worker_core_plan: None,
        },
    })
}

fn prompt_choice<R: BufRead, W: Write>(
    input: &mut R,
    output: &mut W,
    label: &str,
    default: &str,
    allowed: &[&str],
) -> Result<String, CliError> {
    loop {
        let value = prompt_string(input, output, label, default)?;
        if allowed.contains(&value.as_str()) {
            return Ok(value);
        }
        writeln!(
            output,
            "invalid value '{value}', expected one of: {}",
            allowed.join(", ")
        )
        .map_err(|error| CliError(format!("write prompt failed: {error}")))?;
    }
}

fn prompt_positive_usize<R: BufRead, W: Write>(
    input: &mut R,
    output: &mut W,
    label: &str,
    default: usize,
) -> Result<usize, CliError> {
    loop {
        let value = prompt_string(input, output, label, &default.to_string())?;
        match value.parse::<usize>() {
            Ok(parsed) if parsed > 0 => return Ok(parsed),
            _ => {
                writeln!(output, "{label} must be a positive integer")
                    .map_err(|error| CliError(format!("write prompt failed: {error}")))?;
            }
        }
    }
}

fn prompt_string<R: BufRead, W: Write>(
    input: &mut R,
    output: &mut W,
    label: &str,
    default: &str,
) -> Result<String, CliError> {
    write!(output, "{label} [{default}]: ")
        .map_err(|error| CliError(format!("write prompt failed: {error}")))?;
    output
        .flush()
        .map_err(|error| CliError(format!("flush prompt failed: {error}")))?;
    let mut line = String::new();
    let read = input
        .read_line(&mut line)
        .map_err(|error| CliError(format!("read prompt failed: {error}")))?;
    if read == 0 {
        return Ok(default.to_owned());
    }
    let value = line.trim();
    if value.is_empty() {
        Ok(default.to_owned())
    } else {
        Ok(value.to_owned())
    }
}

fn next_value<'a>(args: &'a [String], index: &mut usize, flag: &str) -> Result<&'a str, CliError> {
    *index += 1;
    args.get(*index)
        .map(String::as_str)
        .ok_or_else(|| CliError(format!("{flag} requires a value")))
}

fn parse_positive_usize(value: &str, flag: &str) -> Result<usize, CliError> {
    let parsed = parse_usize(value, flag)?;
    if parsed == 0 {
        return Err(CliError(format!("{flag} must be greater than zero")));
    }
    Ok(parsed)
}

fn parse_usize(value: &str, flag: &str) -> Result<usize, CliError> {
    let parsed = value
        .parse::<usize>()
        .map_err(|_| CliError(format!("{flag} must be an unsigned integer")))?;
    Ok(parsed)
}

fn parse_format(value: &str) -> Result<OutputFormat, CliError> {
    match value {
        "json" => Ok(OutputFormat::Json),
        "csv" => Ok(OutputFormat::Csv),
        other => Err(CliError(format!(
            "unsupported --format '{other}', expected json or csv"
        ))),
    }
}

fn parse_protocol(value: &str) -> Result<Protocol, CliError> {
    match value {
        "r1cs" => Ok(Protocol::R1cs),
        "plonkish" => Ok(Protocol::Plonkish),
        other => Err(CliError(format!(
            "unknown protocol '{other}', expected r1cs or plonkish"
        ))),
    }
}

fn parse_case(value: &str) -> Result<CaseSelection, CliError> {
    match value {
        "positive" => Ok(CaseSelection::Positive),
        "negative" => Ok(CaseSelection::Negative),
        "both" => Ok(CaseSelection::Both),
        other => Err(CliError(format!(
            "unsupported --case '{other}', expected positive, negative, or both"
        ))),
    }
}

fn parse_figure_compiler(value: &str) -> Result<FigureCompiler, CliError> {
    match value {
        "auto" => Ok(FigureCompiler::Auto),
        "pdflatex" => Ok(FigureCompiler::PdfLatex),
        "tectonic" => Ok(FigureCompiler::Tectonic),
        other => Err(CliError(format!(
            "unsupported --figure-compiler '{other}', expected auto, pdflatex, or tectonic"
        ))),
    }
}

fn parse_csv_strings(value: &str) -> Result<Vec<String>, CliError> {
    let items = value
        .split(',')
        .filter(|item| !item.trim().is_empty())
        .map(|item| item.trim().to_string())
        .collect::<Vec<_>>();
    if items.is_empty() {
        Err(CliError(
            "comma-separated list must not be empty".to_string(),
        ))
    } else {
        Ok(items)
    }
}

fn parse_csv_usizes(value: &str, flag: &str) -> Result<Vec<usize>, CliError> {
    value
        .split(',')
        .filter(|item| !item.trim().is_empty())
        .map(|item| parse_usize(item.trim(), flag))
        .collect()
}

fn parse_nv_powers_to_sizes(value: &str, flag: &str) -> Result<Vec<usize>, CliError> {
    parse_csv_usizes(value, flag)?
        .into_iter()
        .map(|power| nv_power_to_size(power, flag))
        .collect()
}

fn parse_nv_range_to_sizes(value: &str, flag: &str) -> Result<Vec<usize>, CliError> {
    let (start, end) = parse_inclusive_range(value, flag)?;
    (start..=end)
        .map(|power| nv_power_to_size(power, flag))
        .collect()
}

fn parse_size_range_to_sizes(value: &str) -> Result<Vec<usize>, CliError> {
    let (start, end) = parse_inclusive_range(value, "--size-range")?;
    if start == 0 {
        return Err(CliError("--size-range start must be positive".to_owned()));
    }
    Ok((start..=end).collect())
}

fn parse_worker_power_range_to_workers(value: &str) -> Result<Vec<usize>, CliError> {
    let (start, end) = parse_inclusive_range(value, "--worker-power-range")?;
    let mut workers = vec![1];
    workers.extend(
        (start..=end)
            .map(|power| nv_power_to_size(power, "--worker-power-range"))
            .collect::<Result<Vec<_>, _>>()?,
    );
    normalize_unique(&mut workers);
    Ok(workers)
}

fn parse_inclusive_range(value: &str, flag: &str) -> Result<(usize, usize), CliError> {
    let trimmed = value.trim();
    let parts = if let Some((start, end)) = trimmed.split_once("..=") {
        Some((start, end))
    } else if let Some((start, end)) = trimmed.split_once("..") {
        Some((start, end))
    } else if let Some((start, end)) = trimmed.split_once(':') {
        Some((start, end))
    } else {
        trimmed.split_once('-')
    };
    let (start, end) =
        parts.ok_or_else(|| CliError(format!("{flag} must look like 2..6, 2..=6, 2:6, or 2-6")))?;
    let start = parse_usize(start.trim(), flag)?;
    let end = parse_usize(end.trim(), flag)?;
    if start > end {
        return Err(CliError(format!("{flag} start must be <= end")));
    }
    Ok((start, end))
}

fn nv_power_to_size(power: usize, flag: &str) -> Result<usize, CliError> {
    if power >= usize::BITS as usize {
        return Err(CliError(format!(
            "{flag} contains n={power}, which overflows usize"
        )));
    }
    1_usize
        .checked_shl(power as u32)
        .ok_or_else(|| CliError(format!("{flag} contains n={power}, which overflows usize")))
}

fn normalize_unique(values: &mut Vec<usize>) {
    values.sort_unstable();
    values.dedup();
}

fn nv_power(size: usize) -> usize {
    if size == 0 {
        0
    } else {
        (usize::BITS - 1 - size.leading_zeros()) as usize
    }
}

fn run_worker_command(args: &[String]) -> Result<(), CliError> {
    let command = parse_worker_command(args)?;
    run_worker(&command.addr, command.id)
        .map_err(|error| CliError(format!("worker failed: {error:?}")))
}

fn run_master_command(args: &[String]) -> Result<(), CliError> {
    let command = parse_master_command(args)?;
    if command.protocol.is_some() {
        return run_network_proof_master(command);
    }
    let start = Instant::now();
    for (addr, worker_id) in command.addrs.iter().zip(&command.ids) {
        ping(addr).map_err(|error| CliError(format!("ping {addr} failed: {error:?}")))?;
        register(addr, *worker_id)
            .map_err(|error| CliError(format!("register {addr} failed: {error:?}")))?;
    }
    let replies =
        TcpWorkerRuntime::dispatch_round(&command.addrs, &command.session, &command.payload)
            .map_err(|error| CliError(format!("round dispatch failed: {error:?}")))?;
    let round_time = start.elapsed();
    if command.shutdown {
        TcpWorkerRuntime::shutdown(&command.addrs)
            .map_err(|error| CliError(format!("shutdown failed: {error:?}")))?;
    }
    print_net_record(
        &NetMetricRecord {
            mode: "master",
            workers: command.addrs.len(),
            round_ms: millis(round_time),
            communication_bytes: net_application_bytes(
                &command.session,
                &command.payload,
                &replies,
            ),
            replies,
            ok: true,
        },
        command.format,
    );
    Ok(())
}

fn run_network_proof_master(command: MasterCommand) -> Result<(), CliError> {
    for (addr, worker_id) in command.addrs.iter().zip(&command.ids) {
        ping(addr).map_err(|error| CliError(format!("ping {addr} failed: {error:?}")))?;
        register(addr, *worker_id)
            .map_err(|error| CliError(format!("register {addr} failed: {error:?}")))?;
    }

    let protocol = command
        .protocol
        .ok_or_else(|| CliError("network proof master requires --protocol".to_owned()))?;
    let config = Config {
        protocol,
        workers: command.addrs.len(),
        size: command.size,
        format: command.format,
        case: command.case,
        pcs_queries: command.pcs_queries,
        worker_core_plan: None,
    };
    let result = match protocol {
        Protocol::R1cs => run_r1cs_network(&config, &command.addrs),
        Protocol::Plonkish => run_plonkish_network(&config, &command.addrs),
    };
    if command.shutdown {
        let shutdown_result = TcpWorkerRuntime::shutdown(&command.addrs)
            .map_err(|error| CliError(format!("shutdown failed: {error:?}")));
        if result.is_ok() {
            shutdown_result?;
        }
    }
    let records = result?;
    print_records(&records, command.format);
    Ok(())
}

fn run_net_demo_command(args: &[String]) -> Result<(), CliError> {
    let command = parse_net_demo_command(args)?;
    run_net_demo(command)
}

fn run_net_demo(command: NetDemoCommand) -> Result<(), CliError> {
    let mut addrs = Vec::with_capacity(command.workers);
    let mut handles = Vec::with_capacity(command.workers);
    for worker_id in 0..command.workers {
        let (addr, handle) = spawn_loopback_worker(worker_id)
            .map_err(|error| CliError(format!("spawn worker {worker_id} failed: {error:?}")))?;
        addrs.push(addr);
        handles.push(handle);
    }

    let start = Instant::now();
    let run_result = (|| {
        for (worker_id, addr) in addrs.iter().enumerate() {
            ping(addr).map_err(|error| CliError(format!("ping {addr} failed: {error:?}")))?;
            register(addr, worker_id)
                .map_err(|error| CliError(format!("register {addr} failed: {error:?}")))?;
        }
        TcpWorkerRuntime::dispatch_round(&addrs, &command.session, &command.payload)
            .map_err(|error| CliError(format!("round dispatch failed: {error:?}")))
    })();

    let replies = match run_result {
        Ok(replies) => replies,
        Err(error) => {
            let _ = TcpWorkerRuntime::shutdown(&addrs);
            join_workers(handles)?;
            return Err(error);
        }
    };
    let round_time = start.elapsed();
    TcpWorkerRuntime::shutdown(&addrs)
        .map_err(|error| CliError(format!("shutdown failed: {error:?}")))?;
    join_workers(handles)?;

    print_net_record(
        &NetMetricRecord {
            mode: "net-demo",
            workers: command.workers,
            round_ms: millis(round_time),
            communication_bytes: net_application_bytes(
                &command.session,
                &command.payload,
                &replies,
            ),
            replies,
            ok: true,
        },
        command.format,
    );
    Ok(())
}

struct PcsCommitBreakdown {
    commitment: DistributedCommitment,
    partition_ms: f64,
    worker_commit_ms: f64,
    master_commit_ms: f64,
    commit_ms: f64,
    network_commit_bytes: usize,
}

fn run_single_pcs_job(
    command: &PcsBenchmarkCommand,
    runner: BenchmarkRunner,
    opening: PcsOpeningVariant,
    size: usize,
    workers: usize,
    trial: usize,
    network_addrs: Option<&[String]>,
) -> Result<PcsMetricRecord, CliError> {
    let evaluations = pcs_sample_evaluations(size);
    let point = pcs_sample_point(size, trial);
    let params = DistributedPcsParams::new(command.pcs_queries);
    let effective_queries = params
        .effective_query_count(size)
        .map_err(|error| CliError(format!("PCS query count invalid: {error:?}")))?;

    let mut network_client = network_addrs.map(|addrs| {
        NetworkPcsClient::new(
            addrs.to_vec(),
            format!(
                "pcs-bench-{}-n{}-w{}-trial{}",
                opening.as_str(),
                nv_power(size),
                workers,
                trial
            ),
        )
    });
    let before_commit_bytes = network_client
        .as_ref()
        .map(NetworkPcsClient::bytes)
        .unwrap_or(0);
    let commit = if let Some(client) = network_client.as_mut() {
        let start = Instant::now();
        let commitment = client.commit(&evaluations, workers)?;
        let commit_ms = millis(start.elapsed());
        PcsCommitBreakdown {
            commitment,
            partition_ms: 0.0,
            worker_commit_ms: commit_ms,
            master_commit_ms: 0.0,
            commit_ms,
            network_commit_bytes: client.bytes() - before_commit_bytes,
        }
    } else {
        local_pcs_commit_breakdown(&evaluations, workers)?
    };

    let before_open_bytes = network_client
        .as_ref()
        .map(NetworkPcsClient::bytes)
        .unwrap_or(before_commit_bytes + commit.network_commit_bytes);
    let (open_ms, verify_ms, opening_proof_bytes, communication_bytes, verified, failure_reason) =
        match opening {
            PcsOpeningVariant::Compact => {
                let open_start = Instant::now();
                let mut open_tr = HashTranscript::new(b"pq-experiments-pcs-benchmark");
                let opening_result = if let Some(client) = network_client.as_mut() {
                    DistributedBrakedown::absorb_distributed_commitment(
                        &commit.commitment,
                        &mut open_tr,
                    );
                    client.open_compact(
                        &evaluations,
                        &commit.commitment,
                        &point,
                        params,
                        &mut open_tr,
                    )
                } else {
                    DistributedBrakedown::open_compact_at_with_params(
                        &evaluations,
                        &commit.commitment,
                        &point,
                        params,
                        &mut open_tr,
                    )
                    .map_err(|error| CliError(format!("compact PCS open failed: {error:?}")))
                };
                let opening = opening_result?;
                let open_ms = millis(open_start.elapsed());
                let verify_start = Instant::now();
                let mut verify_tr = HashTranscript::new(b"pq-experiments-pcs-benchmark");
                let verification = DistributedBrakedown::verify_compact_with_params(
                    &commit.commitment,
                    &opening,
                    params,
                    &mut verify_tr,
                );
                let verify_ms = millis(verify_start.elapsed());
                (
                    open_ms,
                    verify_ms,
                    compact_pcs_proof_size_bytes(&opening),
                    compact_pcs_communication_bytes(&opening),
                    verification.is_ok(),
                    verification.err().map(|error| format!("{error:?}")),
                )
            }
            PcsOpeningVariant::Full => {
                let open_start = Instant::now();
                let mut open_tr = HashTranscript::new(b"pq-experiments-pcs-benchmark");
                let opening_result: Result<DistributedOpening, CliError> =
                    if let Some(client) = network_client.as_mut() {
                        DistributedBrakedown::absorb_distributed_commitment(
                            &commit.commitment,
                            &mut open_tr,
                        );
                        client.open_full(
                            &evaluations,
                            &commit.commitment,
                            &point,
                            params,
                            &mut open_tr,
                        )
                    } else {
                        DistributedBrakedown::open_at_with_params(
                            &evaluations,
                            &commit.commitment,
                            &point,
                            params,
                            &mut open_tr,
                        )
                        .map_err(|error| CliError(format!("full PCS open failed: {error:?}")))
                    };
                let opening = opening_result?;
                let open_ms = millis(open_start.elapsed());
                let verify_start = Instant::now();
                let mut verify_tr = HashTranscript::new(b"pq-experiments-pcs-benchmark");
                let verification = DistributedBrakedown::verify_opening_with_params(
                    &commit.commitment,
                    &opening,
                    params,
                    &mut verify_tr,
                );
                let verify_ms = millis(verify_start.elapsed());
                (
                    open_ms,
                    verify_ms,
                    pcs_proof_size_bytes(&opening),
                    pcs_communication_bytes(&opening),
                    verification.is_ok(),
                    verification.err().map(|error| format!("{error:?}")),
                )
            }
        };
    let network_bytes = network_client
        .as_ref()
        .map(NetworkPcsClient::bytes)
        .unwrap_or(0);
    let network_open_bytes = network_bytes.saturating_sub(before_open_bytes);
    let shard_len = commit
        .commitment
        .workers
        .iter()
        .map(|worker| worker.range.1.saturating_sub(worker.range.0))
        .max()
        .unwrap_or(0);
    let paper_b_target = paper_b_target(size, workers);
    Ok(PcsMetricRecord {
        runner: runner.as_str(),
        opening: opening.as_str(),
        trial,
        workers,
        size,
        t_rows_per_worker: size as f64 / workers as f64,
        paper_b_target,
        shard_len,
        pcs_queries_requested: command.pcs_queries,
        pcs_queries_effective: effective_queries,
        partition_ms: commit.partition_ms,
        worker_commit_ms: commit.worker_commit_ms,
        master_commit_ms: commit.master_commit_ms,
        commit_ms: commit.commit_ms,
        open_ms,
        verify_ms,
        commitment_bytes: distributed_commitment_size_bytes(&commit.commitment),
        opening_proof_bytes,
        communication_bytes,
        network_commit_bytes: commit.network_commit_bytes,
        network_open_bytes,
        network_bytes,
        host_logical_cores: command
            .worker_core_plan
            .as_ref()
            .map(|plan| plan.host_logical_cores),
        cores_per_worker: command
            .worker_core_plan
            .as_ref()
            .map(|plan| plan.cores_per_worker),
        core_affinity: command
            .worker_core_plan
            .as_ref()
            .map(|_| worker_affinity_mode()),
        verified,
        failure_reason,
    })
}

fn local_pcs_commit_breakdown(
    evaluations: &[FieldElement],
    workers: usize,
) -> Result<PcsCommitBreakdown, CliError> {
    let commit_start = Instant::now();
    let partition_start = Instant::now();
    let plan = DistributedBrakedown::partition(evaluations, workers)
        .map_err(|error| CliError(format!("PCS partition failed: {error:?}")))?;
    let partition_ms = millis(partition_start.elapsed());
    let worker_start = Instant::now();
    let worker_commitments = thread::scope(|scope| {
        let handles =
            plan.partitions()
                .iter()
                .map(|partition| {
                    let row = &evaluations[partition.start..partition.end];
                    scope.spawn(move || {
                        DistributedBrakedown::worker_commit(partition.id, partition.start, row)
                            .map_err(|error| {
                                CliError(format!(
                                    "PCS worker {} commit failed: {error:?}",
                                    partition.id
                                ))
                            })
                    })
                })
                .collect::<Vec<_>>();
        let mut commitments = Vec::with_capacity(handles.len());
        for handle in handles {
            match handle.join() {
                Ok(result) => commitments.push(result?),
                Err(_) => return Err(CliError("PCS worker commit thread panicked".to_owned())),
            }
        }
        Ok(commitments)
    })?;
    let worker_commit_ms = millis(worker_start.elapsed());
    let master_start = Instant::now();
    let mut transcript = HashTranscript::new(b"pq-experiments-pcs-benchmark");
    let commitment =
        DistributedBrakedown::master_commit(worker_commitments, evaluations.len(), &mut transcript)
            .map_err(|error| CliError(format!("PCS master commit failed: {error:?}")))?;
    let master_commit_ms = millis(master_start.elapsed());
    Ok(PcsCommitBreakdown {
        commitment,
        partition_ms,
        worker_commit_ms,
        master_commit_ms,
        commit_ms: millis(commit_start.elapsed()),
        network_commit_bytes: 0,
    })
}

fn pcs_sample_evaluations(size: usize) -> Vec<FieldElement> {
    (0..size)
        .map(|index| {
            let value = ((index as u64 + 1).wrapping_mul(0x9E37_79B1) ^ 0xA5A5_5A5A) % 1_000_003;
            FieldElement::from(value + 1)
        })
        .collect()
}

fn pcs_sample_point(size: usize, trial: usize) -> Vec<FieldElement> {
    let vars = nv_power(size);
    (0..vars)
        .map(|index| FieldElement::from(((trial + index + 2) as u64 * 17) + 3))
        .collect()
}

fn paper_b_target(size: usize, workers: usize) -> usize {
    let t = (size / workers.max(1)).max(1);
    let log_t = nv_power(t).max(1);
    workers.saturating_mul(log_t)
}

fn run_loopback_network_proof(config: &Config) -> Result<Vec<MetricRecord>, CliError> {
    let mut addrs = Vec::with_capacity(config.workers);
    let mut handles = Vec::with_capacity(config.workers);
    for worker_id in 0..config.workers {
        let (addr, handle) = spawn_loopback_worker_for_config(worker_id, &config.worker_core_plan)?;
        addrs.push(addr);
        handles.push(handle);
    }

    let result = (|| {
        for (worker_id, addr) in addrs.iter().enumerate() {
            ping(addr).map_err(|error| CliError(format!("ping {addr} failed: {error:?}")))?;
            register(addr, worker_id)
                .map_err(|error| CliError(format!("register {addr} failed: {error:?}")))?;
        }
        match config.protocol {
            Protocol::R1cs => run_r1cs_network(config, &addrs),
            Protocol::Plonkish => run_plonkish_network(config, &addrs),
        }
    })();

    let shutdown_result = TcpWorkerRuntime::shutdown(&addrs)
        .map_err(|error| CliError(format!("shutdown failed: {error:?}")));
    let join_result = join_loopback_workers(handles);
    let records = result?;
    shutdown_result?;
    join_result?;
    Ok(records)
}

enum LoopbackWorkerHandle {
    Thread(std::thread::JoinHandle<pq_net::NetResult<()>>),
    Process(Child),
}

struct BenchmarkNetworkPool {
    addrs: Vec<String>,
    handles: Vec<LoopbackWorkerHandle>,
}

struct BenchmarkNetworkPools {
    pools: HashMap<usize, BenchmarkNetworkPool>,
}

impl BenchmarkNetworkPools {
    fn new() -> Self {
        Self {
            pools: HashMap::new(),
        }
    }

    fn addrs_for(
        &mut self,
        workers: usize,
        core_plan: &Option<WorkerCorePlan>,
        phase_timings: &mut Vec<PhaseTimingRecord>,
    ) -> Result<Vec<String>, CliError> {
        if let Entry::Vacant(entry) = self.pools.entry(workers) {
            let start = Instant::now();
            let pool = spawn_benchmark_network_pool(workers, core_plan)?;
            let addrs = pool.addrs.clone();
            entry.insert(pool);
            push_phase_timing(
                phase_timings,
                "network_worker_pool_start",
                format!("spawn and register {workers} reusable loopback workers"),
                start.elapsed(),
                0.0,
                0.0,
            );
            return Ok(addrs);
        }
        Ok(self
            .pools
            .get(&workers)
            .expect("pool exists after contains_key")
            .addrs
            .clone())
    }

    fn shutdown_all(&mut self, phase_timings: &mut Vec<PhaseTimingRecord>) -> Result<(), CliError> {
        if self.pools.is_empty() {
            return Ok(());
        }
        let start = Instant::now();
        let pools = std::mem::take(&mut self.pools);
        let pool_count = pools.len();
        let mut first_error = None;
        for (_, pool) in pools {
            match shutdown_benchmark_network_pool(pool) {
                Err(error) if first_error.is_none() => first_error = Some(error),
                _ => {}
            }
        }
        push_phase_timing(
            phase_timings,
            "network_worker_pool_shutdown",
            format!("shutdown {pool_count} reusable loopback worker pools"),
            start.elapsed(),
            0.0,
            0.0,
        );
        if let Some(error) = first_error {
            return Err(error);
        }
        Ok(())
    }
}

fn spawn_benchmark_network_pool(
    workers: usize,
    core_plan: &Option<WorkerCorePlan>,
) -> Result<BenchmarkNetworkPool, CliError> {
    let mut addrs = Vec::with_capacity(workers);
    let mut handles = Vec::with_capacity(workers);
    for worker_id in 0..workers {
        match spawn_loopback_worker_for_config(worker_id, core_plan) {
            Ok((addr, handle)) => {
                addrs.push(addr);
                handles.push(handle);
            }
            Err(error) => {
                let _ = TcpWorkerRuntime::shutdown(&addrs);
                let _ = join_loopback_workers(handles);
                return Err(error);
            }
        }
    }
    for (worker_id, addr) in addrs.iter().enumerate() {
        if let Err(error) = ping(addr) {
            let _ = TcpWorkerRuntime::shutdown(&addrs);
            let _ = join_loopback_workers(handles);
            return Err(CliError(format!("ping {addr} failed: {error:?}")));
        }
        if let Err(error) = register(addr, worker_id) {
            let _ = TcpWorkerRuntime::shutdown(&addrs);
            let _ = join_loopback_workers(handles);
            return Err(CliError(format!("register {addr} failed: {error:?}")));
        }
    }
    Ok(BenchmarkNetworkPool { addrs, handles })
}

fn shutdown_benchmark_network_pool(pool: BenchmarkNetworkPool) -> Result<(), CliError> {
    let shutdown_result = TcpWorkerRuntime::shutdown(&pool.addrs)
        .map_err(|error| CliError(format!("shutdown failed: {error:?}")));
    let join_result = join_loopback_workers(pool.handles);
    shutdown_result?;
    join_result
}

fn spawn_loopback_worker_for_config(
    worker_id: usize,
    core_plan: &Option<WorkerCorePlan>,
) -> Result<(String, LoopbackWorkerHandle), CliError> {
    if let Some(plan) = core_plan {
        let core_ids = plan.core_ids_for_worker(worker_id);
        let (addr, mut child) = spawn_affinity_worker_process(worker_id, &core_ids)?;
        if let Err(error) = wait_for_loopback_worker(&addr) {
            let _ = child.kill();
            let _ = child.wait();
            return Err(error);
        }
        Ok((addr, LoopbackWorkerHandle::Process(child)))
    } else {
        let (addr, handle) = spawn_loopback_worker(worker_id)
            .map_err(|error| CliError(format!("spawn worker {worker_id} failed: {error:?}")))?;
        Ok((addr, LoopbackWorkerHandle::Thread(handle)))
    }
}

fn reserve_loopback_addr() -> Result<String, CliError> {
    let listener = TcpListener::bind("127.0.0.1:0")
        .map_err(|error| CliError(format!("reserve loopback port failed: {error}")))?;
    let addr = listener
        .local_addr()
        .map_err(|error| CliError(format!("read loopback port failed: {error}")))?
        .to_string();
    drop(listener);
    Ok(addr)
}

fn wait_for_loopback_worker(addr: &str) -> Result<(), CliError> {
    let deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < deadline {
        if ping(addr).is_ok() {
            return Ok(());
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    Err(CliError(format!(
        "affinity-controlled worker did not start listening at {addr}"
    )))
}

fn spawn_affinity_worker_process(
    worker_id: usize,
    core_ids: &[usize],
) -> Result<(String, Child), CliError> {
    let addr = reserve_loopback_addr()?;
    let exe = env::current_exe()
        .map_err(|error| CliError(format!("resolve current executable failed: {error}")))?;
    let child = spawn_platform_affinity_worker(&exe, &addr, worker_id, core_ids)?;
    Ok((addr, child))
}

#[cfg(target_os = "linux")]
fn spawn_platform_affinity_worker(
    exe: &Path,
    addr: &str,
    worker_id: usize,
    core_ids: &[usize],
) -> Result<Child, CliError> {
    let core_list = core_ids
        .iter()
        .map(|core| core.to_string())
        .collect::<Vec<_>>()
        .join(",");
    Command::new("taskset")
        .env(
            "RAYON_NUM_THREADS",
            worker_rayon_threads(core_ids).to_string(),
        )
        .env("PQ_CORE_PARALLEL_MIN_ITEMS", "64")
        .env("PQ_CORE_PARALLEL_MIN_ROWS", "64")
        .env("PQ_PCS_PARALLEL_MIN_ITEMS", "64")
        .env("PQ_SUMCHECK_PARALLEL_MIN_ITEMS", "64")
        .arg("-c")
        .arg(&core_list)
        .arg(exe)
        .arg("worker")
        .arg("--addr")
        .arg(addr)
        .arg("--id")
        .arg(worker_id.to_string())
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|error| {
            CliError(format!(
                "spawn Linux affinity worker with taskset -c {core_list} failed: {error}"
            ))
        })
}

#[cfg(target_os = "windows")]
fn spawn_platform_affinity_worker(
    exe: &Path,
    addr: &str,
    worker_id: usize,
    core_ids: &[usize],
) -> Result<Child, CliError> {
    let mask = windows_affinity_mask(core_ids)?;
    let args = [
        "worker".to_owned(),
        "--addr".to_owned(),
        addr.to_owned(),
        "--id".to_owned(),
        worker_id.to_string(),
    ];
    let rayon_threads = worker_rayon_threads(core_ids);
    let command = format!(
        "$ErrorActionPreference='Stop'; $env:RAYON_NUM_THREADS='{}'; $env:PQ_CORE_PARALLEL_MIN_ITEMS='64'; $env:PQ_CORE_PARALLEL_MIN_ROWS='64'; $env:PQ_PCS_PARALLEL_MIN_ITEMS='64'; $env:PQ_SUMCHECK_PARALLEL_MIN_ITEMS='64'; $p = Start-Process -FilePath {} -ArgumentList {} -WindowStyle Hidden -PassThru; $p.ProcessorAffinity = [IntPtr]{}; $p.WaitForExit(); exit $p.ExitCode",
        rayon_threads,
        powershell_quote(&exe.display().to_string()),
        powershell_array(&args),
        mask
    );
    Command::new("powershell.exe")
        .args([
            "-NoProfile",
            "-ExecutionPolicy",
            "Bypass",
            "-Command",
            &command,
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|error| {
            CliError(format!(
                "spawn Windows affinity worker with ProcessorAffinity mask {mask} failed: {error}"
            ))
        })
}

#[cfg(not(any(target_os = "linux", target_os = "windows")))]
fn spawn_platform_affinity_worker(
    _exe: &Path,
    _addr: &str,
    _worker_id: usize,
    _core_ids: &[usize],
) -> Result<Child, CliError> {
    Err(CliError(format!(
        "worker core affinity is not implemented for {}",
        env::consts::OS
    )))
}

#[cfg(target_os = "windows")]
fn windows_affinity_mask(core_ids: &[usize]) -> Result<u64, CliError> {
    let mut mask = 0_u64;
    for core_id in core_ids {
        if *core_id >= 63 {
            return Err(CliError(format!(
                "Windows ProcessorAffinity wrapper supports logical core ids 0..62 in this prototype; got {core_id}"
            )));
        }
        mask |= 1_u64 << core_id;
    }
    Ok(mask)
}

#[cfg(target_os = "windows")]
fn powershell_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "''"))
}

#[cfg(target_os = "windows")]
fn powershell_array(values: &[String]) -> String {
    let quoted = values
        .iter()
        .map(|value| powershell_quote(value))
        .collect::<Vec<_>>()
        .join(",");
    format!("@({quoted})")
}

fn join_loopback_workers(handles: Vec<LoopbackWorkerHandle>) -> Result<(), CliError> {
    for handle in handles {
        match handle {
            LoopbackWorkerHandle::Thread(handle) => {
                handle
                    .join()
                    .map_err(|_| CliError("worker thread panicked".to_string()))?
                    .map_err(|error| CliError(format!("worker failed: {error:?}")))?;
            }
            LoopbackWorkerHandle::Process(mut child) => {
                wait_for_worker_process(&mut child, Duration::from_secs(5))?;
            }
        }
    }
    Ok(())
}

fn wait_for_worker_process(child: &mut Child, timeout: Duration) -> Result<(), CliError> {
    let deadline = Instant::now() + timeout;
    loop {
        if let Some(status) = child
            .try_wait()
            .map_err(|error| CliError(format!("poll worker process failed: {error}")))?
        {
            if status.success() {
                return Ok(());
            }
            return Err(CliError(format!(
                "worker process exited with status {status}"
            )));
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            return Err(CliError(
                "worker process did not exit after shutdown".to_owned(),
            ));
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

fn join_workers(
    handles: Vec<std::thread::JoinHandle<pq_net::NetResult<()>>>,
) -> Result<(), CliError> {
    for handle in handles {
        handle
            .join()
            .map_err(|_| CliError("worker thread panicked".to_string()))?
            .map_err(|error| CliError(format!("worker failed: {error:?}")))?;
    }
    Ok(())
}

fn run_r1cs(config: &Config) -> Result<Vec<MetricRecord>, CliError> {
    let mut records = Vec::new();
    if matches!(config.case, CaseSelection::Positive | CaseSelection::Both) {
        records.push(run_r1cs_case(config, "positive", false)?);
    }
    if matches!(config.case, CaseSelection::Negative | CaseSelection::Both) {
        records.push(run_r1cs_case(config, "negative", true)?);
    }
    Ok(records)
}

fn run_r1cs_network(config: &Config, addrs: &[String]) -> Result<Vec<MetricRecord>, CliError> {
    let mut records = Vec::new();
    if matches!(config.case, CaseSelection::Positive | CaseSelection::Both) {
        records.push(run_r1cs_case_network(config, addrs, "positive", false)?);
    }
    if matches!(config.case, CaseSelection::Negative | CaseSelection::Both) {
        records.push(run_r1cs_case_network(config, addrs, "negative", true)?);
    }
    Ok(records)
}

fn run_r1cs_case(
    config: &Config,
    case_name: &'static str,
    tamper: bool,
) -> Result<MetricRecord, CliError> {
    Ok(run_r1cs_case_with_proof(config, case_name, tamper)?.0)
}

fn run_r1cs_case_with_proof(
    config: &Config,
    case_name: &'static str,
    tamper: bool,
) -> Result<(MetricRecord, R1csPiopProof), CliError> {
    let (instance, witness) = sample_r1cs(config.size)?;

    let prove_start = Instant::now();
    let (proof_result, prove_phases) = collect_r1cs_phase_timings(|| {
        prove_r1cs_for_instance(&instance, &witness, config.workers, config.pcs_queries)
    });
    let proof = proof_result?;
    let prove_time = prove_start.elapsed();

    let verify_proof = if tamper {
        tamper_r1cs_proof(&proof)?
    } else {
        proof.clone()
    };
    let verify_start = Instant::now();
    let (verification, verify_phases) = collect_r1cs_phase_timings(|| {
        verify_r1cs_for_instance(&instance, &verify_proof, config.pcs_queries)
    });
    let verify_time = verify_start.elapsed();
    let verified = verification.is_ok();
    let failure_reason = verification
        .as_ref()
        .err()
        .map(|error| format!("{error:?}"));
    let (proof_bytes, communication_bytes) = verification
        .map(|metrics| (metrics.proof_bytes, metrics.communication_bytes))
        .unwrap_or_else(|_| r1cs_fallback_metrics(&proof));
    let stages = r1cs_stage_breakdown(
        &proof,
        prove_time,
        verify_time,
        &prove_phases,
        &verify_phases,
    );

    let record = MetricRecord {
        protocol: Protocol::R1cs.as_str(),
        runner: BenchmarkRunner::Local.as_str(),
        case_name,
        trial: 1,
        workers: config.workers,
        size: config.size,
        constraints: instance.num_constraints(),
        prove_ms: millis(prove_time),
        verify_ms: millis(verify_time),
        stages,
        proof_bytes,
        communication_bytes,
        network_bytes: 0,
        pcs_queries: config.pcs_queries,
        host_logical_cores: None,
        cores_per_worker: None,
        core_affinity: None,
        verified,
        failure_reason,
    };
    Ok((record, proof))
}

fn run_r1cs_case_network(
    config: &Config,
    addrs: &[String],
    case_name: &'static str,
    tamper: bool,
) -> Result<MetricRecord, CliError> {
    Ok(run_r1cs_case_network_with_proof(config, addrs, case_name, tamper)?.0)
}

fn run_r1cs_case_network_with_proof(
    config: &Config,
    addrs: &[String],
    case_name: &'static str,
    tamper: bool,
) -> Result<(MetricRecord, R1csPiopProof), CliError> {
    let (instance, witness) = sample_r1cs(config.size)?;
    let backend = RefCell::new(NetworkPcsClient::new(
        addrs.to_vec(),
        format!(
            "r1cs-{case_name}-nv{}-w{}-q{}",
            config.size, config.workers, config.pcs_queries
        ),
    ));

    let prove_start = Instant::now();
    let mut transcript = HashTranscript::new(b"pq-experiments-r1cs");
    let (proof_result, prove_phases) = collect_r1cs_phase_timings(|| {
        prove_r1cs_with_pcs_and_spark_batch_hooks(
            &instance,
            &witness,
            config.workers,
            DistributedPcsParams::new(config.pcs_queries),
            &mut transcript,
            R1csBatchProverHooks {
                commit_distributed: |evaluations: &[FieldElement], workers: usize| {
                    backend
                        .borrow_mut()
                        .commit(evaluations, workers)
                        .map_err(|_| R1csPiopError::Pcs)
                },
                open_distributed:
                    |evaluations: &[FieldElement],
                     commitment: &DistributedCommitment,
                     point: &[FieldElement],
                     params: DistributedPcsParams,
                     transcript: &mut HashTranscript| {
                        backend
                            .borrow_mut()
                            .open_compact(evaluations, commitment, point, params, transcript)
                            .map(R1csPcsOpening::Compact)
                            .map_err(|_| R1csPiopError::Pcs)
                    },
                spark_worker_provider: |requests: &[SparkWorkerClaimRequest<'_>]| {
                    backend
                        .borrow_mut()
                        .r1cs_spark_claims(&instance, requests)
                        .map_err(|_| R1csPiopError::InvalidProof)
                },
            },
        )
    });
    let proof =
        proof_result.map_err(|error| CliError(format!("network R1CS prove failed: {error:?}")))?;
    let prove_time = prove_start.elapsed();
    let network_bytes = backend.borrow().bytes();

    let verify_proof = if tamper {
        tamper_r1cs_proof(&proof)?
    } else {
        proof.clone()
    };
    let verify_start = Instant::now();
    let (verification, verify_phases) = collect_r1cs_phase_timings(|| {
        verify_r1cs_for_instance(&instance, &verify_proof, config.pcs_queries)
    });
    let verify_time = verify_start.elapsed();
    let verified = verification.is_ok();
    let failure_reason = verification
        .as_ref()
        .err()
        .map(|error| format!("{error:?}"));
    let (proof_bytes, communication_bytes) = verification
        .map(|metrics| (metrics.proof_bytes, metrics.communication_bytes))
        .unwrap_or_else(|_| r1cs_fallback_metrics(&proof));
    let stages = r1cs_stage_breakdown(
        &proof,
        prove_time,
        verify_time,
        &prove_phases,
        &verify_phases,
    );

    let record = MetricRecord {
        protocol: Protocol::R1cs.as_str(),
        runner: BenchmarkRunner::Network.as_str(),
        case_name,
        trial: 1,
        workers: config.workers,
        size: config.size,
        constraints: instance.num_constraints(),
        prove_ms: millis(prove_time),
        verify_ms: millis(verify_time),
        stages,
        proof_bytes,
        communication_bytes,
        network_bytes,
        pcs_queries: config.pcs_queries,
        host_logical_cores: config
            .worker_core_plan
            .as_ref()
            .map(|plan| plan.host_logical_cores),
        cores_per_worker: config
            .worker_core_plan
            .as_ref()
            .map(|plan| plan.cores_per_worker),
        core_affinity: config
            .worker_core_plan
            .as_ref()
            .map(|_| worker_affinity_mode()),
        verified,
        failure_reason,
    };
    Ok((record, proof))
}

fn prove_r1cs_for_instance(
    instance: &R1CS,
    witness: &[FieldElement],
    workers: usize,
    pcs_queries: usize,
) -> Result<R1csPiopProof, CliError> {
    let mut transcript = HashTranscript::new(b"pq-experiments-r1cs");
    prove_r1cs_with_pcs_params(
        instance,
        witness,
        workers,
        DistributedPcsParams::new(pcs_queries),
        &mut transcript,
    )
    .map_err(|error| CliError(format!("R1CS prove failed: {error:?}")))
}

fn verify_r1cs_for_instance(
    instance: &R1CS,
    proof: &R1csPiopProof,
    pcs_queries: usize,
) -> Result<pq_piop_r1cs::R1csMetrics, pq_piop_r1cs::R1csPiopError> {
    let mut transcript = HashTranscript::new(b"pq-experiments-r1cs");
    verify_r1cs_with_pcs_params(
        instance,
        proof,
        DistributedPcsParams::new(pcs_queries),
        &mut transcript,
    )
}

fn tamper_r1cs_proof(proof: &R1csPiopProof) -> Result<R1csPiopProof, CliError> {
    let mut proof = proof.clone();
    let first_query = proof
        .row_queries
        .first_mut()
        .ok_or_else(|| CliError("R1CS proof row query unexpectedly empty".to_owned()))?;
    first_query.residual_opening.proof.value += FieldElement::ONE;
    Ok(proof)
}

fn r1cs_fallback_metrics(proof: &R1csPiopProof) -> (usize, usize) {
    let communication_bytes = r1cs_opening_communication_bytes(proof);
    (r1cs_proof_size_bytes(proof), communication_bytes)
}

fn r1cs_opening_communication_bytes(proof: &R1csPiopProof) -> usize {
    r1cs_proof_communication_bytes(proof)
}

#[derive(Clone, Debug)]
struct NetworkPcsClient {
    addrs: Vec<String>,
    session_prefix: String,
    round: usize,
    network_bytes: usize,
    commit_sessions: HashMap<[u8; 32], String>,
}

impl NetworkPcsClient {
    fn new(addrs: Vec<String>, session_prefix: String) -> Self {
        Self {
            addrs,
            session_prefix,
            round: 0,
            network_bytes: 0,
            commit_sessions: HashMap::new(),
        }
    }

    fn bytes(&self) -> usize {
        self.network_bytes
    }

    fn commit(
        &mut self,
        evaluations: &[FieldElement],
        workers: usize,
    ) -> Result<DistributedCommitment, CliError> {
        if workers != self.addrs.len() {
            return Err(CliError(
                "network PCS worker count must match --addrs".to_owned(),
            ));
        }
        let plan = DistributedBrakedown::partition(evaluations, workers)
            .map_err(|error| CliError(format!("network PCS partition failed: {error:?}")))?;
        let session = self.next_session("commit");
        let addrs = self.addrs.clone();
        let partitions = plan.partitions().to_vec();
        let commit_results = thread::scope(|scope| {
            let handles = partitions
                .iter()
                .map(|partition| {
                    let addr = addrs[partition.id].clone();
                    let session = session.clone();
                    let row = &evaluations[partition.start..partition.end];
                    scope.spawn(move || {
                        let request_bytes = message_wire_bytes(&Message::PcsCommit {
                            session: session.clone(),
                            worker_id: partition.id,
                            start: partition.start,
                            values: row.to_vec(),
                        });
                        let commitment =
                            pcs_worker_commit(&addr, &session, partition.id, partition.start, row)
                                .map_err(|error| {
                                    CliError(format!(
                                        "network PCS commit worker {} failed: {error:?}",
                                        partition.id
                                    ))
                                })?;
                        let response_bytes = response_wire_bytes(&Response::PcsCommitResult {
                            commitment: commitment.clone(),
                        });
                        Ok((partition.id, request_bytes + response_bytes, commitment))
                    })
                })
                .collect::<Vec<_>>();

            let mut results = Vec::with_capacity(handles.len());
            for handle in handles {
                match handle.join() {
                    Ok(result) => results.push(result?),
                    Err(_) => {
                        return Err(CliError(
                            "network PCS commit worker thread panicked".to_owned(),
                        ));
                    }
                }
            }
            Ok(results)
        })?;
        let mut commitments_by_worker = vec![None; workers];
        for (worker_id, bytes, commitment) in commit_results {
            self.network_bytes += bytes;
            if worker_id >= commitments_by_worker.len() {
                return Err(CliError(format!(
                    "network PCS worker id {worker_id} out of range"
                )));
            }
            commitments_by_worker[worker_id] = Some(commitment);
        }
        let commitments = commitments_by_worker
            .into_iter()
            .enumerate()
            .map(|(worker_id, commitment)| {
                commitment.ok_or_else(|| {
                    CliError(format!(
                        "network PCS worker {worker_id} did not return a commitment"
                    ))
                })
            })
            .collect::<Result<Vec<_>, _>>()?;
        let commitment =
            DistributedBrakedown::commit_from_worker_commitments(commitments, evaluations.len())
                .map_err(|error| CliError(format!("network PCS commitment invalid: {error:?}")))?;
        self.commit_sessions.insert(commitment.root, session);
        Ok(commitment)
    }

    fn open_compact<T: Transcript>(
        &mut self,
        evaluations: &[FieldElement],
        commitment: &DistributedCommitment,
        point: &[FieldElement],
        params: DistributedPcsParams,
        transcript: &mut T,
    ) -> Result<CompactDistributedOpening, CliError> {
        let session = self
            .commit_sessions
            .get(&commitment.root)
            .cloned()
            .ok_or_else(|| CliError("network PCS commitment session not found".to_owned()))?;
        DistributedBrakedown::open_compact_at_after_commitment_with_batch_worker_provider(
            evaluations,
            commitment,
            point,
            params,
            transcript,
            |requests| self.open_workers(&session, requests),
        )
        .map_err(|error| CliError(format!("network compact PCS opening failed: {error:?}")))
    }

    fn open_full<T: Transcript>(
        &mut self,
        evaluations: &[FieldElement],
        commitment: &DistributedCommitment,
        point: &[FieldElement],
        params: DistributedPcsParams,
        transcript: &mut T,
    ) -> Result<DistributedOpening, CliError> {
        let session = self
            .commit_sessions
            .get(&commitment.root)
            .cloned()
            .ok_or_else(|| CliError("network PCS commitment session not found".to_owned()))?;
        DistributedBrakedown::open_at_after_commitment_with_batch_worker_provider(
            evaluations,
            commitment,
            point,
            params,
            transcript,
            |requests| self.open_workers(&session, requests),
        )
        .map_err(|error| CliError(format!("network full PCS opening failed: {error:?}")))
    }

    fn open_workers(
        &mut self,
        session: &str,
        requests: &[WorkerOpeningRequest<'_>],
    ) -> Result<Vec<WorkerOpening>, PcsError> {
        let open_results = thread::scope(|scope| {
            let mut handles = Vec::with_capacity(requests.len());
            for (request_index, request) in requests.iter().copied().enumerate() {
                let addr = self
                    .addrs
                    .get(request.worker.worker_id)
                    .cloned()
                    .ok_or(PcsError::InvalidWorker)?;
                let session = session.to_owned();
                let worker = request.worker.clone();
                let query_indices = request.query_indices.to_vec();
                handles.push(scope.spawn(move || {
                    let request_bytes = message_wire_bytes(&Message::PcsOpen {
                        session: session.clone(),
                        worker_id: worker.worker_id,
                        start: worker.range.0,
                        query_indices: query_indices.clone(),
                    });
                    let opening = pcs_worker_open(
                        &addr,
                        &session,
                        worker.worker_id,
                        worker.range.0,
                        &query_indices,
                    )
                    .map_err(|_| PcsError::InvalidProof)?;
                    let response_bytes = response_wire_bytes(&Response::PcsOpenResult {
                        opening: opening.clone(),
                    });
                    Ok((request_index, request_bytes + response_bytes, opening))
                }));
            }

            let mut results = Vec::with_capacity(handles.len());
            for handle in handles {
                match handle.join() {
                    Ok(result) => results.push(result?),
                    Err(_) => return Err(PcsError::InvalidProof),
                }
            }
            Ok(results)
        })?;

        let mut openings_by_request = vec![None; requests.len()];
        let mut network_bytes = 0_usize;
        for (request_index, bytes, opening) in open_results {
            network_bytes += bytes;
            if request_index >= openings_by_request.len() {
                return Err(PcsError::InvalidProof);
            }
            openings_by_request[request_index] = Some(opening);
        }
        self.network_bytes += network_bytes;
        openings_by_request
            .into_iter()
            .map(|opening| opening.ok_or(PcsError::InvalidProof))
            .collect()
    }

    fn r1cs_spark_claims(
        &mut self,
        instance: &R1CS,
        requests: &[SparkWorkerClaimRequest<'_>],
    ) -> Result<Vec<SparkWorkerShardClaim>, CliError> {
        let mut jobs = Vec::with_capacity(requests.len());
        for (request_index, request) in requests.iter().copied().enumerate() {
            let addr = self
                .addrs
                .get(request.partition.id)
                .cloned()
                .ok_or_else(|| {
                    CliError(format!(
                        "network Spark worker {} has no configured address",
                        request.partition.id
                    ))
                })?;
            let session = self.next_session("spark");
            let a_entries = partition_entries(instance.a(), request.partition);
            let b_entries = partition_entries(instance.b(), request.partition);
            let c_entries = partition_entries(instance.c(), request.partition);
            let row_point = request.row_point.to_vec();
            let col_point = request.col_point.to_vec();
            let request_message = Message::R1csSparkClaim {
                session: session.clone(),
                worker_id: request.partition.id,
                start: request.partition.start,
                end: request.partition.end,
                rows: instance.num_constraints(),
                cols: instance.num_variables(),
                a_entries: a_entries.clone(),
                b_entries: b_entries.clone(),
                c_entries: c_entries.clone(),
                challenges: request.challenges,
                row_point: row_point.clone(),
                col_point: col_point.clone(),
            };
            let request_bytes = message_wire_bytes(&request_message);
            jobs.push((
                request_index,
                addr,
                session,
                request.partition,
                request.challenges,
                a_entries,
                b_entries,
                c_entries,
                row_point,
                col_point,
                request_bytes,
            ));
        }

        let results = thread::scope(|scope| {
            let handles = jobs
                .into_iter()
                .map(
                    |(
                        request_index,
                        addr,
                        session,
                        partition,
                        challenges,
                        a_entries,
                        b_entries,
                        c_entries,
                        row_point,
                        col_point,
                        request_bytes,
                    )| {
                        let rows = instance.num_constraints();
                        let cols = instance.num_variables();
                        scope.spawn(move || {
                            let claim = r1cs_spark_worker_claim(
                                &addr,
                                R1csSparkClaimRequest {
                                    session: &session,
                                    worker_id: partition.id,
                                    start: partition.start,
                                    end: partition.end,
                                    rows,
                                    cols,
                                    a_entries: &a_entries,
                                    b_entries: &b_entries,
                                    c_entries: &c_entries,
                                    challenges,
                                    row_point: &row_point,
                                    col_point: &col_point,
                                },
                            )
                            .map_err(|error| {
                                CliError(format!(
                                    "network Spark worker {} failed: {error:?}",
                                    partition.id
                                ))
                            })?;
                            let response_bytes =
                                response_wire_bytes(&Response::R1csSparkClaimResult {
                                    claim: claim.clone(),
                                });
                            Ok((request_index, request_bytes + response_bytes, claim))
                        })
                    },
                )
                .collect::<Vec<_>>();

            let mut results = Vec::with_capacity(handles.len());
            for handle in handles {
                match handle.join() {
                    Ok(result) => results.push(result?),
                    Err(_) => {
                        return Err(CliError("network Spark worker thread panicked".to_owned()));
                    }
                }
            }
            Ok(results)
        })?;

        let mut claims_by_request = vec![None; requests.len()];
        let mut network_bytes = 0_usize;
        for (request_index, bytes, claim) in results {
            network_bytes += bytes;
            if request_index >= claims_by_request.len() {
                return Err(CliError(
                    "network Spark worker returned an out-of-range request index".to_owned(),
                ));
            }
            claims_by_request[request_index] = Some(claim);
        }
        self.network_bytes += network_bytes;
        claims_by_request
            .into_iter()
            .enumerate()
            .map(|(request_index, claim)| {
                claim.ok_or_else(|| {
                    CliError(format!(
                        "network Spark request {request_index} did not return a claim"
                    ))
                })
            })
            .collect()
    }

    fn next_session(&mut self, label: &str) -> String {
        let session = format!("{}-{label}-{}", self.session_prefix, self.round);
        self.round += 1;
        session
    }
}

fn partition_entries(matrix: &SparseMatrix, partition: Partition) -> Vec<SparseEntry> {
    matrix
        .entries()
        .iter()
        .copied()
        .filter(|entry| partition.contains(entry.row))
        .collect()
}

fn run_plonkish(config: &Config) -> Result<Vec<MetricRecord>, CliError> {
    let mut records = Vec::new();
    if matches!(config.case, CaseSelection::Positive | CaseSelection::Both) {
        records.push(run_plonkish_case(config, "positive", false)?);
    }
    if matches!(config.case, CaseSelection::Negative | CaseSelection::Both) {
        records.push(run_plonkish_case(config, "negative", true)?);
    }
    Ok(records)
}

fn run_plonkish_network(config: &Config, addrs: &[String]) -> Result<Vec<MetricRecord>, CliError> {
    let mut records = Vec::new();
    if matches!(config.case, CaseSelection::Positive | CaseSelection::Both) {
        records.push(run_plonkish_case_network(config, addrs, "positive", false)?);
    }
    if matches!(config.case, CaseSelection::Negative | CaseSelection::Both) {
        records.push(run_plonkish_case_network(config, addrs, "negative", true)?);
    }
    Ok(records)
}

fn run_plonkish_case(
    config: &Config,
    case_name: &'static str,
    tamper: bool,
) -> Result<MetricRecord, CliError> {
    Ok(run_plonkish_case_with_proof(config, case_name, tamper)?.0)
}

fn run_plonkish_case_with_proof(
    config: &Config,
    case_name: &'static str,
    tamper: bool,
) -> Result<(MetricRecord, PlonkishPiopProof), CliError> {
    let instance = sample_plonkish_instance(config.size)
        .map_err(|error| CliError(format!("Plonkish sample failed: {error:?}")))?;

    let prove_start = Instant::now();
    let (proof_result, prove_phases) = collect_plonkish_phase_timings(|| {
        prove_for_instance(&instance, config.workers, config.pcs_queries)
    });
    let proof = proof_result?;
    let prove_time = prove_start.elapsed();

    let (
        verify_time,
        verify_phases,
        verified,
        failure_reason,
        proof_bytes,
        communication_bytes,
        constraints,
    ) = if tamper {
        let verify_start = Instant::now();
        let (failure_result, verify_phases) = collect_plonkish_phase_timings(|| {
            verify_plonkish_negative_variants(&instance, &proof, config.pcs_queries)
        });
        let failure_reason = failure_result?;
        let verify_time = verify_start.elapsed();
        let residuals = instance
            .constraint_residuals()
            .map_err(|error| CliError(format!("Plonkish residuals failed: {error:?}")))?;
        (
            verify_time,
            verify_phases,
            false,
            Some(failure_reason),
            pq_piop_plonkish::proof_size_bytes(&proof),
            plonkish_proof_communication_bytes(&proof),
            residuals.len(),
        )
    } else {
        let verify_start = Instant::now();
        let (verification, verify_phases) = collect_plonkish_phase_timings(|| {
            verify_for_instance(&instance, &proof, config.pcs_queries)
        });
        let verify_time = verify_start.elapsed();
        let verified = verification.is_ok();
        let failure_reason = verification
            .as_ref()
            .err()
            .map(|error| format!("{error:?}"));
        let (proof_bytes, communication_bytes, constraints) = match verification {
            Ok(metrics) => (
                metrics.proof_bytes,
                metrics.communication_bytes,
                metrics.constraints,
            ),
            Err(_) => {
                let residuals = instance
                    .constraint_residuals()
                    .map_err(|error| CliError(format!("Plonkish residuals failed: {error:?}")))?;
                let communication_bytes = plonkish_proof_communication_bytes(&proof);
                (
                    pq_piop_plonkish::proof_size_bytes(&proof),
                    communication_bytes,
                    residuals.len(),
                )
            }
        };
        (
            verify_time,
            verify_phases,
            verified,
            failure_reason,
            proof_bytes,
            communication_bytes,
            constraints,
        )
    };
    let stages = plonkish_stage_breakdown(
        &proof,
        prove_time,
        verify_time,
        &prove_phases,
        &verify_phases,
    );

    let record = MetricRecord {
        protocol: Protocol::Plonkish.as_str(),
        runner: BenchmarkRunner::Local.as_str(),
        case_name,
        trial: 1,
        workers: config.workers,
        size: config.size,
        constraints,
        prove_ms: millis(prove_time),
        verify_ms: millis(verify_time),
        stages,
        proof_bytes,
        communication_bytes,
        network_bytes: 0,
        pcs_queries: config.pcs_queries,
        host_logical_cores: None,
        cores_per_worker: None,
        core_affinity: None,
        verified,
        failure_reason,
    };
    Ok((record, proof))
}

fn run_plonkish_case_network(
    config: &Config,
    addrs: &[String],
    case_name: &'static str,
    tamper: bool,
) -> Result<MetricRecord, CliError> {
    Ok(run_plonkish_case_network_with_proof(config, addrs, case_name, tamper)?.0)
}

fn run_plonkish_case_network_with_proof(
    config: &Config,
    addrs: &[String],
    case_name: &'static str,
    tamper: bool,
) -> Result<(MetricRecord, PlonkishPiopProof), CliError> {
    let instance = sample_plonkish_instance(config.size)
        .map_err(|error| CliError(format!("Plonkish sample failed: {error:?}")))?;
    let backend = RefCell::new(NetworkPcsClient::new(
        addrs.to_vec(),
        format!(
            "plonkish-{case_name}-nv{}-w{}-q{}",
            config.size, config.workers, config.pcs_queries
        ),
    ));

    let prove_start = Instant::now();
    let mut transcript = HashTranscript::new(b"pq-experiments-plonkish");
    let (proof_result, prove_phases) = collect_plonkish_phase_timings(|| {
        prove_plonkish_with_pcs_hooks(
            &instance,
            config.workers,
            DistributedPcsParams::new(config.pcs_queries),
            &mut transcript,
            |evaluations, workers| {
                backend
                    .borrow_mut()
                    .commit(evaluations, workers)
                    .map_err(|_| PlonkishPiopError::InvalidProof)
            },
            |evaluations, commitment, point, params, transcript| {
                backend
                    .borrow_mut()
                    .open_compact(evaluations, commitment, point, params, transcript)
                    .map(PlonkishPcsOpening::Compact)
                    .map_err(|_| PlonkishPiopError::InvalidProof)
            },
        )
    });
    let proof = proof_result
        .map_err(|error| CliError(format!("network Plonkish prove failed: {error:?}")))?;
    let prove_time = prove_start.elapsed();
    let network_bytes = backend.borrow().bytes();

    let (
        verify_time,
        verify_phases,
        verified,
        failure_reason,
        proof_bytes,
        communication_bytes,
        constraints,
    ) = if tamper {
        let verify_start = Instant::now();
        let (failure_result, verify_phases) = collect_plonkish_phase_timings(|| {
            verify_plonkish_negative_variants(&instance, &proof, config.pcs_queries)
        });
        let failure_reason = failure_result?;
        let verify_time = verify_start.elapsed();
        let residuals = instance
            .constraint_residuals()
            .map_err(|error| CliError(format!("Plonkish residuals failed: {error:?}")))?;
        (
            verify_time,
            verify_phases,
            false,
            Some(failure_reason),
            pq_piop_plonkish::proof_size_bytes(&proof),
            plonkish_proof_communication_bytes(&proof),
            residuals.len(),
        )
    } else {
        let verify_start = Instant::now();
        let (verification, verify_phases) = collect_plonkish_phase_timings(|| {
            verify_for_instance(&instance, &proof, config.pcs_queries)
        });
        let verify_time = verify_start.elapsed();
        let verified = verification.is_ok();
        let failure_reason = verification
            .as_ref()
            .err()
            .map(|error| format!("{error:?}"));
        let (proof_bytes, communication_bytes, constraints) = match verification {
            Ok(metrics) => (
                metrics.proof_bytes,
                metrics.communication_bytes,
                metrics.constraints,
            ),
            Err(_) => {
                let residuals = instance
                    .constraint_residuals()
                    .map_err(|error| CliError(format!("Plonkish residuals failed: {error:?}")))?;
                let communication_bytes = plonkish_proof_communication_bytes(&proof);
                (
                    pq_piop_plonkish::proof_size_bytes(&proof),
                    communication_bytes,
                    residuals.len(),
                )
            }
        };
        (
            verify_time,
            verify_phases,
            verified,
            failure_reason,
            proof_bytes,
            communication_bytes,
            constraints,
        )
    };
    let stages = plonkish_stage_breakdown(
        &proof,
        prove_time,
        verify_time,
        &prove_phases,
        &verify_phases,
    );

    let record = MetricRecord {
        protocol: Protocol::Plonkish.as_str(),
        runner: BenchmarkRunner::Network.as_str(),
        case_name,
        trial: 1,
        workers: config.workers,
        size: config.size,
        constraints,
        prove_ms: millis(prove_time),
        verify_ms: millis(verify_time),
        stages,
        proof_bytes,
        communication_bytes,
        network_bytes,
        pcs_queries: config.pcs_queries,
        host_logical_cores: config
            .worker_core_plan
            .as_ref()
            .map(|plan| plan.host_logical_cores),
        cores_per_worker: config
            .worker_core_plan
            .as_ref()
            .map(|plan| plan.cores_per_worker),
        core_affinity: config
            .worker_core_plan
            .as_ref()
            .map(|_| worker_affinity_mode()),
        verified,
        failure_reason,
    };
    Ok((record, proof))
}

fn verify_plonkish_negative_variants(
    instance: &PlonkishInstance,
    proof: &PlonkishPiopProof,
    pcs_queries: usize,
) -> Result<String, CliError> {
    let variants = tampered_plonkish_proof_variants(proof)?;
    if variants.is_empty() {
        return Err(CliError(
            "Plonkish negative case did not generate tampered proof variants".to_owned(),
        ));
    }

    let mut failures = Vec::with_capacity(variants.len());
    for (label, tampered) in variants {
        match verify_for_instance(instance, &tampered, pcs_queries) {
            Ok(_) => {
                return Err(CliError(format!(
                    "Plonkish negative variant '{label}' unexpectedly verified"
                )));
            }
            Err(error) => failures.push(format!("{label}:{error:?}")),
        }
    }
    Ok(failures.join(";"))
}

fn tampered_plonkish_proof_variants(
    proof: &PlonkishPiopProof,
) -> Result<Vec<(&'static str, PlonkishPiopProof)>, CliError> {
    let mut variants = Vec::new();

    let mut accumulator = proof.clone();
    accumulator
        .permutation_accumulator
        .recurrence_queries
        .first_mut()
        .ok_or_else(|| CliError("Plonkish accumulator query unexpectedly empty".to_owned()))?
        .numerator_next
        .value += FieldElement::ONE;
    variants.push(("accumulator-recurrence", accumulator));

    let mut gate_query = proof.clone();
    gate_query
        .gate_queries
        .first_mut()
        .ok_or_else(|| CliError("Plonkish gate query unexpectedly empty".to_owned()))?
        .a
        .value += FieldElement::ONE;
    variants.push(("gate-query", gate_query));

    let mut permutation_query = proof.clone();
    permutation_query
        .permutation_queries
        .first_mut()
        .ok_or_else(|| CliError("Plonkish permutation query unexpectedly empty".to_owned()))?
        .target_value
        .value += FieldElement::ONE;
    variants.push(("permutation-query", permutation_query));

    let mut gate_subclaim = proof.clone();
    gate_subclaim.gate_subclaim.virtual_gate_value += FieldElement::ONE;
    variants.push(("gate-subclaim", gate_subclaim));

    let mut constraint_opening = proof.clone();
    match &mut constraint_opening.constraint_opening {
        PlonkishPcsOpening::Full(opening) => opening.claimed_value += FieldElement::ONE,
        PlonkishPcsOpening::Compact(opening) => opening.claimed_value += FieldElement::ONE,
    }
    variants.push(("constraint-pcs-opening", constraint_opening));

    Ok(variants)
}

fn prove_for_instance(
    instance: &PlonkishInstance,
    workers: usize,
    pcs_queries: usize,
) -> Result<PlonkishPiopProof, CliError> {
    let mut transcript = HashTranscript::new(b"pq-experiments-plonkish");
    prove_plonkish_with_pcs_params(
        instance,
        workers,
        DistributedPcsParams::new(pcs_queries),
        &mut transcript,
    )
    .map_err(|error| CliError(format!("Plonkish prove failed: {error:?}")))
}

fn verify_for_instance(
    instance: &PlonkishInstance,
    proof: &PlonkishPiopProof,
    pcs_queries: usize,
) -> Result<pq_piop_plonkish::PlonkishMetrics, pq_piop_plonkish::PlonkishPiopError> {
    let mut transcript = HashTranscript::new(b"pq-experiments-plonkish");
    verify_plonkish_with_pcs_params(
        instance,
        proof,
        DistributedPcsParams::new(pcs_queries),
        &mut transcript,
    )
}

fn sample_r1cs(size: usize) -> Result<(R1CS, Vec<FieldElement>), CliError> {
    let constraints = size.max(1);
    let cols = constraints + 2;
    let mut a = SparseMatrix::new(constraints, cols);
    let mut b = SparseMatrix::new(constraints, cols);
    let mut c = SparseMatrix::new(constraints, cols);
    let mut witness = vec![FieldElement::ZERO; cols];
    witness[0] = FieldElement::ONE;
    witness[1] = FieldElement::from(2_u64);

    for row in 0..constraints {
        let current_col = row + 1;
        let next_col = row + 2;
        let factor = FieldElement::from((row as u64) + 3);
        witness[next_col] = witness[current_col] * factor;
        a.add_entry(row, current_col, FieldElement::ONE)
            .map_err(|error| CliError(format!("R1CS A matrix build failed: {error}")))?;
        b.add_entry(row, 0, factor)
            .map_err(|error| CliError(format!("R1CS B matrix build failed: {error}")))?;
        c.add_entry(row, next_col, FieldElement::ONE)
            .map_err(|error| CliError(format!("R1CS C matrix build failed: {error}")))?;
    }

    let instance =
        R1CS::new(a, b, c).map_err(|error| CliError(format!("R1CS instance failed: {error}")))?;
    Ok((instance, witness))
}

fn print_records(records: &[MetricRecord], format: OutputFormat) {
    match format {
        OutputFormat::Json => print_json(records),
        OutputFormat::Csv => print_csv(records),
    }
}

fn print_net_record(record: &NetMetricRecord, format: OutputFormat) {
    match format {
        OutputFormat::Json => {
            println!(
                "{{\"mode\":\"{}\",\"workers\":{},\"round_ms\":{:.3},\"communication_bytes\":{},\"ok\":{},\"replies\":[{}]}}",
                record.mode,
                record.workers,
                record.round_ms,
                record.communication_bytes,
                record.ok,
                record
                    .replies
                    .iter()
                    .map(|reply| format!("\"{}\"", json_escape(reply)))
                    .collect::<Vec<_>>()
                    .join(",")
            );
        }
        OutputFormat::Csv => {
            println!("mode,workers,round_ms,communication_bytes,ok,replies");
            println!(
                "{},{},{:.3},{},{},{}",
                record.mode,
                record.workers,
                record.round_ms,
                record.communication_bytes,
                record.ok,
                record.replies.join("|")
            );
        }
    }
}

fn print_json(records: &[MetricRecord]) {
    print!("{}", records_to_json(records));
}

fn print_csv(records: &[MetricRecord]) {
    print!("{}", records_to_csv(records));
}

fn records_to_json(records: &[MetricRecord]) -> String {
    let mut out = String::from("[\n");
    for (index, record) in records.iter().enumerate() {
        let comma = if index + 1 == records.len() { "" } else { "," };
        let failure_reason = json_optional_string(record.failure_reason.as_deref());
        out.push_str(&format!(
            "  {{\"protocol\":\"{}\",\"runner\":\"{}\",\"case\":\"{}\",\"trial\":{},\"workers\":{},\"nv_power\":{},\"size\":{},\"constraints\":{},\"pcs_queries\":{},\"prove_ms\":{:.3},\"verify_ms\":{:.3},\"stage_breakdown\":{{\"prove_pcs_commit_ms\":{:.3},\"prove_sumcheck_ms\":{:.3},\"prove_batch_open_ms\":{:.3},\"prove_other_ms\":{:.3},\"verify_pcs_open_ms\":{:.3},\"verify_sumcheck_ms\":{:.3},\"verify_other_ms\":{:.3}}},\"proof_bytes\":{},\"proof_size_breakdown\":{{\"pcs_bytes\":{},\"sumcheck_bytes\":{},\"other_bytes\":{},\"pcs_ratio\":{:.6}}},\"communication_bytes\":{},\"network_bytes\":{},\"host_logical_cores\":{},\"cores_per_worker\":{},\"core_affinity\":{},\"verified\":{},\"failure_reason\":{}}}{}\n",
            record.protocol,
            record.runner,
            record.case_name,
            record.trial,
            record.workers,
            nv_power(record.size),
            record.size,
            record.constraints,
            record.pcs_queries,
            record.prove_ms,
            record.verify_ms,
            record.stages.prove_pcs_commit_ms,
            record.stages.prove_sumcheck_ms,
            record.stages.prove_batch_open_ms,
            record.stages.prove_other_ms,
            record.stages.verify_pcs_open_ms,
            record.stages.verify_sumcheck_ms,
            record.stages.verify_other_ms,
            record.proof_bytes,
            record.stages.proof_pcs_bytes,
            record.stages.proof_sumcheck_bytes,
            record.stages.proof_other_bytes,
            ratio(record.stages.proof_pcs_bytes as f64, record.proof_bytes as f64),
            record.communication_bytes,
            record.network_bytes,
            json_optional_usize(record.host_logical_cores),
            json_optional_usize(record.cores_per_worker),
            json_optional_string(record.core_affinity),
            record.verified,
            failure_reason,
            comma
        ));
    }
    out.push_str("]\n");
    out
}

fn pcs_records_to_csv(records: &[PcsMetricRecord]) -> String {
    let mut out = format!("{PCS_SOURCE_CSV_HEADER}\n");
    for record in records {
        out.push_str(&format!(
            "{},{},{},{},{},{},{:.6},{},{},{},{},{:.6},{:.6},{:.6},{:.6},{:.6},{:.6},{},{},{},{},{},{},{},{},{},{},{}\n",
            record.runner,
            record.opening,
            record.trial,
            record.workers,
            nv_power(record.size),
            record.size,
            record.t_rows_per_worker,
            record.paper_b_target,
            record.shard_len,
            record.pcs_queries_requested,
            record.pcs_queries_effective,
            record.partition_ms,
            record.worker_commit_ms,
            record.master_commit_ms,
            record.commit_ms,
            record.open_ms,
            record.verify_ms,
            record.commitment_bytes,
            record.opening_proof_bytes,
            record.communication_bytes,
            record.network_commit_bytes,
            record.network_open_bytes,
            record.network_bytes,
            option_usize_csv(record.host_logical_cores),
            option_usize_csv(record.cores_per_worker),
            record.core_affinity.unwrap_or(""),
            record.verified,
            csv_escape(record.failure_reason.as_deref().unwrap_or(""))
        ));
    }
    out
}

fn pcs_records_to_json(records: &[PcsMetricRecord]) -> String {
    let mut out = String::from("[\n");
    for (index, record) in records.iter().enumerate() {
        if index > 0 {
            out.push_str(",\n");
        }
        out.push_str(&format!(
            concat!(
                "  {{\"runner\":\"{}\",\"opening\":\"{}\",\"trial\":{},\"workers\":{},",
                "\"nv_power\":{},\"size\":{},\"t_rows_per_worker\":{:.6},",
                "\"paper_b_target\":{},\"shard_len\":{},",
                "\"pcs_queries_requested\":{},\"pcs_queries_effective\":{},",
                "\"partition_ms\":{:.6},\"worker_commit_ms\":{:.6},",
                "\"master_commit_ms\":{:.6},\"commit_ms\":{:.6},",
                "\"open_ms\":{:.6},\"verify_ms\":{:.6},",
                "\"commitment_bytes\":{},\"opening_proof_bytes\":{},",
                "\"communication_bytes\":{},\"network_commit_bytes\":{},",
                "\"network_open_bytes\":{},\"network_bytes\":{},",
                "\"host_logical_cores\":{},\"cores_per_worker\":{},",
                "\"core_affinity\":{},\"verified\":{},\"failure_reason\":{}}}"
            ),
            json_escape(record.runner),
            json_escape(record.opening),
            record.trial,
            record.workers,
            nv_power(record.size),
            record.size,
            record.t_rows_per_worker,
            record.paper_b_target,
            record.shard_len,
            record.pcs_queries_requested,
            record.pcs_queries_effective,
            record.partition_ms,
            record.worker_commit_ms,
            record.master_commit_ms,
            record.commit_ms,
            record.open_ms,
            record.verify_ms,
            record.commitment_bytes,
            record.opening_proof_bytes,
            record.communication_bytes,
            record.network_commit_bytes,
            record.network_open_bytes,
            record.network_bytes,
            option_usize_json(record.host_logical_cores),
            option_usize_json(record.cores_per_worker),
            option_str_json(record.core_affinity),
            record.verified,
            option_string_json(record.failure_reason.as_deref())
        ));
    }
    out.push_str("\n]\n");
    out
}

fn records_to_csv(records: &[MetricRecord]) -> String {
    let mut out = format!("{SOURCE_CSV_HEADER}\n");
    for record in records {
        let failure_reason = record
            .failure_reason
            .as_deref()
            .map(csv_escape)
            .unwrap_or_default();
        out.push_str(&format!(
            "{},{},{},{},{},{},{},{},{},{:.3},{:.3},{:.3},{:.3},{:.3},{:.3},{:.3},{:.3},{:.3},{},{},{},{},{},{},{},{},{},{},{}\n",
            record.protocol,
            record.runner,
            record.case_name,
            record.trial,
            record.workers,
            nv_power(record.size),
            record.size,
            record.constraints,
            record.pcs_queries,
            record.prove_ms,
            record.verify_ms,
            record.stages.prove_pcs_commit_ms,
            record.stages.prove_sumcheck_ms,
            record.stages.prove_batch_open_ms,
            record.stages.prove_other_ms,
            record.stages.verify_pcs_open_ms,
            record.stages.verify_sumcheck_ms,
            record.stages.verify_other_ms,
            record.proof_bytes,
            record.stages.proof_pcs_bytes,
            record.stages.proof_sumcheck_bytes,
            record.stages.proof_other_bytes,
            record.communication_bytes,
            record.network_bytes,
            record
                .host_logical_cores
                .map(|value| value.to_string())
                .unwrap_or_default(),
            record
                .cores_per_worker
                .map(|value| value.to_string())
                .unwrap_or_default(),
            record.core_affinity.map(csv_escape).unwrap_or_default(),
            record.verified,
            failure_reason
        ));
    }
    out
}

fn push_phase_timing(
    timings: &mut Vec<PhaseTimingRecord>,
    phase: impl Into<String>,
    detail: impl Into<String>,
    elapsed: Duration,
    recorded_prove_ms: f64,
    recorded_verify_ms: f64,
) {
    let elapsed_ms = millis(elapsed);
    let inferred_overhead_ms = (elapsed_ms - recorded_prove_ms - recorded_verify_ms).max(0.0);
    timings.push(PhaseTimingRecord {
        phase: phase.into(),
        detail: detail.into(),
        elapsed_ms,
        recorded_prove_ms,
        recorded_verify_ms,
        inferred_overhead_ms,
    });
}

fn sum_record_prove_ms(records: &[MetricRecord]) -> f64 {
    records.iter().map(|record| record.prove_ms).sum()
}

fn sum_record_verify_ms(records: &[MetricRecord]) -> f64 {
    records.iter().map(|record| record.verify_ms).sum()
}

fn write_phase_timing_files(run_dir: &Path, timings: &[PhaseTimingRecord]) -> Result<(), CliError> {
    write_text_file(
        &run_dir.join("phase_timing.csv"),
        &phase_timing_to_csv(timings),
    )?;
    write_text_file(
        &run_dir.join("phase_timing.json"),
        &phase_timing_to_json(timings),
    )
}

fn phase_timing_to_csv(timings: &[PhaseTimingRecord]) -> String {
    let mut out = format!("{PHASE_TIMING_CSV_HEADER}\n");
    for timing in timings {
        out.push_str(&format!(
            "{},{},{:.3},{:.3},{:.3},{:.3}\n",
            csv_escape(&timing.phase),
            csv_escape(&timing.detail),
            timing.elapsed_ms,
            timing.recorded_prove_ms,
            timing.recorded_verify_ms,
            timing.inferred_overhead_ms
        ));
    }
    out
}

fn phase_timing_to_json(timings: &[PhaseTimingRecord]) -> String {
    let mut out = String::from("[\n");
    for (index, timing) in timings.iter().enumerate() {
        let comma = if index + 1 == timings.len() { "" } else { "," };
        out.push_str(&format!(
            "  {{\"phase\":\"{}\",\"detail\":\"{}\",\"elapsed_ms\":{:.3},\"recorded_prove_ms\":{:.3},\"recorded_verify_ms\":{:.3},\"inferred_overhead_ms\":{:.3}}}{}\n",
            json_escape(&timing.phase),
            json_escape(&timing.detail),
            timing.elapsed_ms,
            timing.recorded_prove_ms,
            timing.recorded_verify_ms,
            timing.inferred_overhead_ms,
            comma
        ));
    }
    out.push_str("]\n");
    out
}

fn phase_timing_summary(timings: &[PhaseTimingRecord]) -> String {
    let mut out = String::new();
    if timings.is_empty() {
        return out;
    }
    out.push_str("\nphase_timing:\n");
    for timing in timings {
        out.push_str(&format!(
            "  phase={} elapsed_ms={:.3} recorded_prove_ms={:.3} recorded_verify_ms={:.3} inferred_overhead_ms={:.3} detail={}\n",
            timing.phase,
            timing.elapsed_ms,
            timing.recorded_prove_ms,
            timing.recorded_verify_ms,
            timing.inferred_overhead_ms,
            timing.detail
        ));
    }
    out
}

fn pcs_text_analysis(records: &[MetricRecord]) -> String {
    let mut out = String::from("\npcs_stage_analysis:\n");
    let positives = records
        .iter()
        .filter(|record| record.case_name == "positive" && record.verified)
        .collect::<Vec<_>>();
    if positives.is_empty() {
        out.push_str("  no verified positive records available\n");
        return out;
    }
    for record in positives {
        let pcs_commit_share = ratio(record.stages.prove_pcs_commit_ms, record.prove_ms) * 100.0;
        let pcs_proof_share = ratio(
            record.stages.proof_pcs_bytes as f64,
            record.proof_bytes as f64,
        ) * 100.0;
        out.push_str(&format!(
            "  runner={} protocol={} n={} workers={} prove_ms={:.3} pcs_commit_ms={:.3} pcs_commit_share={:.2}% sumcheck_ms={:.3} batch_open_ms={:.3} verify_pcs_open_ms={:.3} verify_sumcheck_ms={:.3} proof_bytes={} pcs_proof_bytes={} pcs_proof_share={:.2}%\n",
            record.runner,
            record.protocol,
            nv_power(record.size),
            record.workers,
            record.prove_ms,
            record.stages.prove_pcs_commit_ms,
            pcs_commit_share,
            record.stages.prove_sumcheck_ms,
            record.stages.prove_batch_open_ms,
            record.stages.verify_pcs_open_ms,
            record.stages.verify_sumcheck_ms,
            record.proof_bytes,
            record.stages.proof_pcs_bytes,
            pcs_proof_share
        ));
    }
    out
}

fn benchmark_stats(records: &[MetricRecord]) -> Vec<BenchmarkStatsRecord> {
    let mut groups: Vec<Vec<&MetricRecord>> = Vec::new();
    for record in records {
        if let Some(group) = groups.iter_mut().find(|group| {
            let first = group[0];
            first.protocol == record.protocol
                && first.runner == record.runner
                && first.case_name == record.case_name
                && first.workers == record.workers
                && first.size == record.size
                && first.constraints == record.constraints
                && first.pcs_queries == record.pcs_queries
        }) {
            group.push(record);
        } else {
            groups.push(vec![record]);
        }
    }
    let mut stats = groups
        .into_iter()
        .map(|mut group| {
            group.sort_by_key(|record| record.trial);
            let first = group[0];
            let samples = group.len();
            let verified_count = group.iter().filter(|record| record.verified).count();
            let rejected_count = group.iter().filter(|record| !record.verified).count();
            let mut failure_reasons = group
                .iter()
                .filter_map(|record| record.failure_reason.as_deref())
                .map(str::to_owned)
                .collect::<Vec<_>>();
            failure_reasons.sort();
            failure_reasons.dedup();
            BenchmarkStatsRecord {
                protocol: first.protocol,
                runner: first.runner,
                case_name: first.case_name,
                workers: first.workers,
                size: first.size,
                constraints: first.constraints,
                pcs_queries: first.pcs_queries,
                samples,
                verified_count,
                rejected_count,
                prove_ms: mean_stddev(group.iter().map(|record| record.prove_ms)),
                verify_ms: mean_stddev(group.iter().map(|record| record.verify_ms)),
                prove_pcs_commit_ms: mean_stddev(
                    group.iter().map(|record| record.stages.prove_pcs_commit_ms),
                ),
                prove_sumcheck_ms: mean_stddev(
                    group.iter().map(|record| record.stages.prove_sumcheck_ms),
                ),
                prove_batch_open_ms: mean_stddev(
                    group.iter().map(|record| record.stages.prove_batch_open_ms),
                ),
                verify_pcs_open_ms: mean_stddev(
                    group.iter().map(|record| record.stages.verify_pcs_open_ms),
                ),
                verify_sumcheck_ms: mean_stddev(
                    group.iter().map(|record| record.stages.verify_sumcheck_ms),
                ),
                proof_bytes: mean_stddev(group.iter().map(|record| record.proof_bytes as f64)),
                proof_pcs_bytes: mean_stddev(
                    group
                        .iter()
                        .map(|record| record.stages.proof_pcs_bytes as f64),
                ),
                proof_sumcheck_bytes: mean_stddev(
                    group
                        .iter()
                        .map(|record| record.stages.proof_sumcheck_bytes as f64),
                ),
                proof_other_bytes: mean_stddev(
                    group
                        .iter()
                        .map(|record| record.stages.proof_other_bytes as f64),
                ),
                communication_bytes: mean_stddev(
                    group.iter().map(|record| record.communication_bytes as f64),
                ),
                network_bytes: mean_stddev(group.iter().map(|record| record.network_bytes as f64)),
                failure_reasons,
            }
        })
        .collect::<Vec<_>>();
    stats.sort_by(|left, right| {
        runner_sort_key(left.runner)
            .cmp(&runner_sort_key(right.runner))
            .then(protocol_sort_key(left.protocol).cmp(&protocol_sort_key(right.protocol)))
            .then(left.case_name.cmp(right.case_name))
            .then(left.size.cmp(&right.size))
            .then(left.workers.cmp(&right.workers))
    });
    stats
}

fn pcs_benchmark_stats(records: &[PcsMetricRecord]) -> Vec<PcsStatsRecord> {
    let mut groups: Vec<Vec<&PcsMetricRecord>> = Vec::new();
    for record in records {
        if let Some(group) = groups.iter_mut().find(|group| {
            let first = group[0];
            first.runner == record.runner
                && first.opening == record.opening
                && first.workers == record.workers
                && first.size == record.size
        }) {
            group.push(record);
        } else {
            groups.push(vec![record]);
        }
    }
    let mut stats = groups
        .into_iter()
        .map(|group| {
            let first = group[0];
            let failure_reasons = group
                .iter()
                .filter_map(|record| record.failure_reason.as_ref())
                .cloned()
                .collect::<Vec<_>>();
            PcsStatsRecord {
                runner: first.runner,
                opening: first.opening,
                workers: first.workers,
                size: first.size,
                samples: group.len(),
                verified_count: group.iter().filter(|record| record.verified).count(),
                commit_ms: mean_stddev(group.iter().map(|record| record.commit_ms)),
                open_ms: mean_stddev(group.iter().map(|record| record.open_ms)),
                verify_ms: mean_stddev(group.iter().map(|record| record.verify_ms)),
                opening_proof_bytes: mean_stddev(
                    group.iter().map(|record| record.opening_proof_bytes as f64),
                ),
                communication_bytes: mean_stddev(
                    group.iter().map(|record| record.communication_bytes as f64),
                ),
                network_bytes: mean_stddev(group.iter().map(|record| record.network_bytes as f64)),
                failure_reasons,
            }
        })
        .collect::<Vec<_>>();
    stats.sort_by_key(|record| (record.runner, record.opening, record.workers, record.size));
    stats
}

fn pcs_summary_stats_to_csv(stats: &[PcsStatsRecord]) -> String {
    let mut out = format!("{PCS_SUMMARY_STATS_CSV_HEADER}\n");
    for record in stats {
        out.push_str(&format!(
            "{},{},{},{},{},{},{},{:.6},{:.6},{:.6},{:.6},{:.6},{:.6},{:.6},{:.6},{:.6},{}\n",
            record.runner,
            record.opening,
            record.workers,
            nv_power(record.size),
            record.size,
            record.samples,
            record.verified_count,
            record.commit_ms.mean,
            record.commit_ms.stddev,
            record.open_ms.mean,
            record.open_ms.stddev,
            record.verify_ms.mean,
            record.verify_ms.stddev,
            record.opening_proof_bytes.mean,
            record.communication_bytes.mean,
            record.network_bytes.mean,
            csv_escape(&record.failure_reasons.join(";"))
        ));
    }
    out
}

fn mean_stddev(values: impl Iterator<Item = f64>) -> MeanStddev {
    let values = values.collect::<Vec<_>>();
    if values.is_empty() {
        return MeanStddev {
            mean: 0.0,
            stddev: 0.0,
        };
    }
    let mean = values.iter().sum::<f64>() / values.len() as f64;
    let stddev = if values.len() > 1 {
        let variance = values
            .iter()
            .map(|value| {
                let delta = value - mean;
                delta * delta
            })
            .sum::<f64>()
            / (values.len() - 1) as f64;
        variance.sqrt()
    } else {
        0.0
    };
    MeanStddev { mean, stddev }
}

fn summary_stats_to_csv(stats: &[BenchmarkStatsRecord]) -> String {
    let mut out = format!("{SUMMARY_STATS_CSV_HEADER}\n");
    for record in stats {
        out.push_str(&format!(
            "{},{},{},{},{},{},{},{},{},{},{},{:.6},{:.6},{:.6},{:.6},{:.6},{:.6},{:.6},{:.6},{:.6},{:.6},{:.6},{:.6},{:.6},{:.6},{:.6},{:.6},{:.6},{:.6},{}\n",
            record.protocol,
            record.runner,
            record.case_name,
            record.workers,
            nv_power(record.size),
            record.size,
            record.constraints,
            record.pcs_queries,
            record.samples,
            record.verified_count,
            record.rejected_count,
            record.prove_ms.mean,
            record.prove_ms.stddev,
            record.verify_ms.mean,
            record.verify_ms.stddev,
            record.prove_pcs_commit_ms.mean,
            record.prove_sumcheck_ms.mean,
            record.prove_batch_open_ms.mean,
            record.verify_pcs_open_ms.mean,
            record.verify_sumcheck_ms.mean,
            record.proof_bytes.mean,
            record.proof_bytes.stddev,
            record.proof_pcs_bytes.mean,
            record.proof_sumcheck_bytes.mean,
            record.proof_other_bytes.mean,
            record.communication_bytes.mean,
            record.communication_bytes.stddev,
            record.network_bytes.mean,
            record.network_bytes.stddev,
            csv_escape(&record.failure_reasons.join("|"))
        ));
    }
    out
}

fn mean_positive_records(records: &[MetricRecord]) -> Vec<MetricRecord> {
    benchmark_stats(records)
        .into_iter()
        .filter(|record| record.case_name == "positive" && record.verified_count > 0)
        .map(|record| MetricRecord {
            protocol: record.protocol,
            runner: record.runner,
            case_name: record.case_name,
            trial: 0,
            workers: record.workers,
            size: record.size,
            constraints: record.constraints,
            prove_ms: record.prove_ms.mean,
            verify_ms: record.verify_ms.mean,
            stages: StageBreakdown {
                prove_pcs_commit_ms: record.prove_pcs_commit_ms.mean,
                prove_sumcheck_ms: record.prove_sumcheck_ms.mean,
                prove_batch_open_ms: record.prove_batch_open_ms.mean,
                prove_other_ms: (record.prove_ms.mean
                    - record.prove_pcs_commit_ms.mean
                    - record.prove_sumcheck_ms.mean
                    - record.prove_batch_open_ms.mean)
                    .max(0.0),
                verify_pcs_open_ms: record.verify_pcs_open_ms.mean,
                verify_sumcheck_ms: record.verify_sumcheck_ms.mean,
                verify_other_ms: (record.verify_ms.mean
                    - record.verify_pcs_open_ms.mean
                    - record.verify_sumcheck_ms.mean)
                    .max(0.0),
                proof_pcs_bytes: record.proof_pcs_bytes.mean.round() as usize,
                proof_sumcheck_bytes: record.proof_sumcheck_bytes.mean.round() as usize,
                proof_other_bytes: record.proof_other_bytes.mean.round() as usize,
            },
            proof_bytes: record.proof_bytes.mean.round() as usize,
            communication_bytes: record.communication_bytes.mean.round() as usize,
            network_bytes: record.network_bytes.mean.round() as usize,
            pcs_queries: record.pcs_queries,
            host_logical_cores: None,
            cores_per_worker: None,
            core_affinity: None,
            verified: true,
            failure_reason: None,
        })
        .collect()
}

fn millis(duration: Duration) -> f64 {
    duration.as_secs_f64() * 1_000.0
}

fn r1cs_stage_breakdown(
    proof: &R1csPiopProof,
    prove_time: Duration,
    verify_time: Duration,
    prove_phases: &[R1csPhaseTiming],
    verify_phases: &[R1csPhaseTiming],
) -> StageBreakdown {
    let size = r1cs_proof_size_breakdown(proof);
    let mut stages = StageBreakdown {
        proof_pcs_bytes: size.pcs_bytes,
        proof_sumcheck_bytes: size.sumcheck_bytes,
        proof_other_bytes: size.other_bytes,
        ..StageBreakdown::default()
    };
    apply_prove_phase_breakdown(
        &mut stages,
        millis(prove_time),
        prove_phases
            .iter()
            .map(|phase| (phase.label.as_str(), phase.elapsed)),
    );
    apply_verify_phase_breakdown(
        &mut stages,
        millis(verify_time),
        verify_phases
            .iter()
            .map(|phase| (phase.label.as_str(), phase.elapsed)),
    );
    stages
}

fn plonkish_stage_breakdown(
    proof: &PlonkishPiopProof,
    prove_time: Duration,
    verify_time: Duration,
    prove_phases: &[PlonkishPhaseTiming],
    verify_phases: &[PlonkishPhaseTiming],
) -> StageBreakdown {
    let size = plonkish_proof_size_breakdown(proof);
    let mut stages = StageBreakdown {
        proof_pcs_bytes: size.pcs_bytes,
        proof_sumcheck_bytes: size.sumcheck_bytes,
        proof_other_bytes: size.other_bytes,
        ..StageBreakdown::default()
    };
    apply_prove_phase_breakdown(
        &mut stages,
        millis(prove_time),
        prove_phases
            .iter()
            .map(|phase| (phase.label.as_str(), phase.elapsed)),
    );
    apply_verify_phase_breakdown(
        &mut stages,
        millis(verify_time),
        verify_phases
            .iter()
            .map(|phase| (phase.label.as_str(), phase.elapsed)),
    );
    stages
}

fn apply_prove_phase_breakdown<'a>(
    stages: &mut StageBreakdown,
    prove_total_ms: f64,
    phases: impl Iterator<Item = (&'a str, Duration)>,
) {
    for (label, elapsed) in phases {
        let elapsed_ms = millis(elapsed);
        if is_prove_pcs_commit_phase(label) {
            stages.prove_pcs_commit_ms += elapsed_ms;
        } else if is_sumcheck_phase(label) {
            stages.prove_sumcheck_ms += elapsed_ms;
        } else if is_opening_phase(label) {
            stages.prove_batch_open_ms += elapsed_ms;
        }
    }
    let classified =
        stages.prove_pcs_commit_ms + stages.prove_sumcheck_ms + stages.prove_batch_open_ms;
    stages.prove_other_ms = (prove_total_ms - classified).max(0.0);
}

fn apply_verify_phase_breakdown<'a>(
    stages: &mut StageBreakdown,
    verify_total_ms: f64,
    phases: impl Iterator<Item = (&'a str, Duration)>,
) {
    for (label, elapsed) in phases {
        let elapsed_ms = millis(elapsed);
        if is_sumcheck_phase(label) {
            stages.verify_sumcheck_ms += elapsed_ms;
        } else if is_opening_phase(label) {
            stages.verify_pcs_open_ms += elapsed_ms;
        }
    }
    let classified = stages.verify_pcs_open_ms + stages.verify_sumcheck_ms;
    stages.verify_other_ms = (verify_total_ms - classified).max(0.0);
}

fn is_prove_pcs_commit_phase(label: &str) -> bool {
    label.starts_with("prove/")
        && (label.contains("commitment") || label.contains("commitments"))
        && !label.contains("opening")
}

fn is_sumcheck_phase(label: &str) -> bool {
    label.contains("sumcheck") || label.contains("multiset")
}

fn is_opening_phase(label: &str) -> bool {
    label.contains("opening")
        || label.contains("openings")
        || label.contains("queries")
        || label == "prove/gate_subclaim"
        || label == "verify/gate_subclaim"
}

fn net_application_bytes(session: &str, payload: &str, replies: &[String]) -> usize {
    replies.iter().map(String::len).sum::<usize>() + replies.len() * (session.len() + payload.len())
}

fn json_escape(input: &str) -> String {
    input
        .replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
        .replace('\r', "\\r")
}

fn html_escape(input: &str) -> String {
    input
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

fn json_optional_string(value: Option<&str>) -> String {
    value
        .map(|value| format!("\"{}\"", json_escape(value)))
        .unwrap_or_else(|| "null".to_owned())
}

fn json_optional_bool(value: Option<bool>) -> String {
    value
        .map(|value| value.to_string())
        .unwrap_or_else(|| "null".to_owned())
}

fn json_optional_usize(value: Option<usize>) -> String {
    value
        .map(|value| value.to_string())
        .unwrap_or_else(|| "null".to_owned())
}

fn json_string_array(values: &[impl AsRef<str>]) -> String {
    let items = values
        .iter()
        .map(|value| format!("\"{}\"", json_escape(value.as_ref())))
        .collect::<Vec<_>>();
    format!("[{}]", items.join(","))
}

fn json_usize_array(values: &[usize]) -> String {
    let items = values.iter().map(ToString::to_string).collect::<Vec<_>>();
    format!("[{}]", items.join(","))
}

fn json_usize_matrix(values: &[Vec<usize>]) -> String {
    let rows = values
        .iter()
        .map(|row| json_usize_array(row))
        .collect::<Vec<_>>();
    format!("[{}]", rows.join(","))
}

fn benchmark_artifacts(compile_figures: bool) -> Vec<&'static str> {
    let mut artifacts = BASE_BENCHMARK_ARTIFACTS.to_vec();
    if compile_figures {
        artifacts.push(COMPILED_PAPER_FIGURE);
    }
    artifacts
}

fn csv_escape(input: &str) -> String {
    if input
        .chars()
        .any(|character| matches!(character, ',' | '"' | '\n' | '\r'))
    {
        format!("\"{}\"", input.replace('"', "\"\""))
    } else {
        input.to_owned()
    }
}

fn option_usize_csv(value: Option<usize>) -> String {
    value.map(|value| value.to_string()).unwrap_or_default()
}

fn option_usize_json(value: Option<usize>) -> String {
    value
        .map(|value| value.to_string())
        .unwrap_or_else(|| "null".to_owned())
}

fn option_str_json(value: Option<&str>) -> String {
    value
        .map(|value| format!("\"{}\"", json_escape(value)))
        .unwrap_or_else(|| "null".to_owned())
}

fn option_string_json(value: Option<&str>) -> String {
    option_str_json(value)
}

fn create_result_run_dir(out_dir: &Path, suffix: &str) -> Result<(u64, String, PathBuf), CliError> {
    fs::create_dir_all(out_dir)
        .map_err(|error| CliError(format!("create benchmark root failed: {error}")))?;
    let run_id = unix_timestamp_seconds()?;
    let timestamp = unix_timestamp_label(run_id)?;
    for attempt in 0..128_u64 {
        let run_label = if attempt == 0 {
            format!("bench-{timestamp}-{suffix}")
        } else {
            format!("bench-{timestamp}-{suffix}-{attempt:02}")
        };
        let run_dir = out_dir.join(&run_label);
        match fs::create_dir(&run_dir) {
            Ok(()) => return Ok((run_id, run_label, run_dir)),
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(error) => {
                return Err(CliError(format!(
                    "create benchmark dir {} failed: {error}",
                    run_dir.display()
                )));
            }
        }
    }
    Err(CliError(format!(
        "could not create a fresh benchmark directory under {} after repeated run-id collisions",
        out_dir.display()
    )))
}

fn create_prefixed_result_run_dir(
    out_dir: &Path,
    prefix: &str,
) -> Result<(u64, String, PathBuf), CliError> {
    fs::create_dir_all(out_dir)
        .map_err(|error| CliError(format!("create benchmark root failed: {error}")))?;
    let run_id = unix_timestamp_seconds()?;
    let timestamp = unix_timestamp_label(run_id)?;
    for attempt in 0..128_u64 {
        let run_label = if attempt == 0 {
            format!("{prefix}-{timestamp}")
        } else {
            format!("{prefix}-{timestamp}-{attempt:02}")
        };
        let run_dir = out_dir.join(&run_label);
        match fs::create_dir(&run_dir) {
            Ok(()) => return Ok((run_id, run_label, run_dir)),
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(error) => {
                return Err(CliError(format!(
                    "create benchmark dir {} failed: {error}",
                    run_dir.display()
                )));
            }
        }
    }
    Err(CliError(format!(
        "could not create a fresh benchmark directory under {} after repeated run-id collisions",
        out_dir.display()
    )))
}

fn unix_timestamp_seconds() -> Result<u64, CliError> {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|error| CliError(format!("system clock before UNIX epoch: {error}")))
}

fn unix_timestamp_label(seconds: u64) -> Result<String, CliError> {
    let days = i64::try_from(seconds / 86_400)
        .map_err(|_| CliError("UNIX timestamp day count overflowed i64".to_owned()))?;
    let seconds_of_day = seconds % 86_400;
    let (year, month, day) = civil_from_unix_days(days);
    let hour = seconds_of_day / 3_600;
    let minute = (seconds_of_day % 3_600) / 60;
    let second = seconds_of_day % 60;
    Ok(format!(
        "{year:04}{month:02}{day:02}-{hour:02}{minute:02}{second:02}"
    ))
}

fn civil_from_unix_days(days_since_epoch: i64) -> (i32, u32, u32) {
    let z = days_since_epoch + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = mp + if mp < 10 { 3 } else { -9 };
    let year = y + if m <= 2 { 1 } else { 0 };
    (year as i32, m as u32, d as u32)
}

fn write_text_file(path: &Path, contents: &str) -> Result<(), CliError> {
    fs::write(path, contents)
        .map_err(|error| CliError(format!("write {} failed: {error}", path.display())))
}

fn write_benchmark_metadata_and_manifest(
    run_dir: &Path,
    run_id: u64,
    command: &BenchmarkCommand,
    records: &[MetricRecord],
    figure_pdf_created: bool,
    provenance: &BenchmarkProvenance,
) -> Result<(), CliError> {
    write_text_file(
        &run_dir.join("metadata.json"),
        &benchmark_metadata_json(run_id, command, records, figure_pdf_created, provenance),
    )?;
    let manifest = benchmark_result_manifest_json(run_dir, run_id, figure_pdf_created)?;
    write_text_file(&run_dir.join(RESULT_MANIFEST), &manifest)
}

fn benchmark_result_manifest_json(
    run_dir: &Path,
    run_id: u64,
    figure_pdf_created: bool,
) -> Result<String, CliError> {
    let artifacts = benchmark_manifest_artifacts(run_dir, figure_pdf_created)?;
    let mut entries = Vec::new();
    for artifact in artifacts {
        if artifact == RESULT_MANIFEST {
            continue;
        }
        let path = run_dir.join(&artifact);
        let bytes = fs::read(&path)
            .map_err(|error| CliError(format!("read {} failed: {error}", path.display())))?;
        let digest = hex_digest(sha256(&bytes));
        entries.push((artifact, bytes.len(), digest));
    }

    let mut out = String::from("{\n");
    out.push_str("  \"schema_version\": 1,\n");
    out.push_str("  \"generated_by\": \"pq-experiments benchmark manifest\",\n");
    out.push_str(&format!("  \"run_id\": {run_id},\n"));
    out.push_str(&format!("  \"artifact_count\": {},\n", entries.len()));
    out.push_str(&format!(
        "  \"self_artifact\": \"{}\",\n",
        json_escape(RESULT_MANIFEST)
    ));
    out.push_str("  \"files\": [\n");
    for (index, (path, bytes, digest)) in entries.iter().enumerate() {
        let comma = if index + 1 == entries.len() { "" } else { "," };
        out.push_str(&format!(
            "    {{\"path\":\"{}\",\"bytes\":{},\"sha256\":\"{}\"}}{}\n",
            json_escape(path),
            bytes,
            digest,
            comma
        ));
    }
    out.push_str("  ]\n");
    out.push_str("}\n");
    Ok(out)
}

fn pcs_result_manifest_json(run_dir: &Path, run_id: u64) -> Result<String, CliError> {
    let mut entries = Vec::new();
    for artifact in PCS_BENCHMARK_ARTIFACTS {
        if *artifact == RESULT_MANIFEST {
            continue;
        }
        let path = run_dir.join(artifact);
        let bytes = fs::read(&path)
            .map_err(|error| CliError(format!("read {} failed: {error}", path.display())))?;
        entries.push((
            artifact.to_string(),
            bytes.len(),
            hex_digest(sha256(&bytes)),
        ));
    }
    let mut out = String::from("{\n");
    out.push_str("  \"schema_version\": 1,\n");
    out.push_str("  \"generated_by\": \"pq-experiments pcs benchmark manifest\",\n");
    out.push_str(&format!("  \"run_id\": {run_id},\n"));
    out.push_str(&format!("  \"artifact_count\": {},\n", entries.len()));
    out.push_str(&format!(
        "  \"self_artifact\": \"{}\",\n",
        json_escape(RESULT_MANIFEST)
    ));
    out.push_str("  \"files\": [\n");
    for (index, (path, bytes, digest)) in entries.iter().enumerate() {
        let comma = if index + 1 == entries.len() { "" } else { "," };
        out.push_str(&format!(
            "    {{\"path\":\"{}\",\"bytes\":{},\"sha256\":\"{}\"}}{}\n",
            json_escape(path),
            bytes,
            digest,
            comma
        ));
    }
    out.push_str("  ]\n");
    out.push_str("}\n");
    Ok(out)
}

fn benchmark_manifest_artifacts(
    run_dir: &Path,
    figure_pdf_created: bool,
) -> Result<Vec<String>, CliError> {
    let mut artifacts = benchmark_artifacts(figure_pdf_created)
        .into_iter()
        .map(str::to_owned)
        .collect::<Vec<_>>();
    let proofs_dir = run_dir.join("proofs");
    if proofs_dir.exists() {
        collect_relative_files(run_dir, &proofs_dir, &mut artifacts)?;
    }
    artifacts.sort();
    artifacts.dedup();
    Ok(artifacts)
}

fn collect_relative_files(
    root: &Path,
    dir: &Path,
    files: &mut Vec<String>,
) -> Result<(), CliError> {
    for entry in fs::read_dir(dir)
        .map_err(|error| CliError(format!("read {} failed: {error}", dir.display())))?
    {
        let entry = entry.map_err(|error| {
            CliError(format!(
                "read entry under {} failed: {error}",
                dir.display()
            ))
        })?;
        let file_type = entry.file_type().map_err(|error| {
            CliError(format!(
                "read file type for {} failed: {error}",
                entry.path().display()
            ))
        })?;
        if file_type.is_dir() {
            collect_relative_files(root, &entry.path(), files)?;
        } else if file_type.is_file() {
            files.push(relative_artifact_path(root, &entry.path())?);
        } else {
            return Err(CliError(format!(
                "unsupported special artifact in result directory: {}",
                entry.path().display()
            )));
        }
    }
    Ok(())
}

fn relative_artifact_path(root: &Path, path: &Path) -> Result<String, CliError> {
    let relative = path.strip_prefix(root).map_err(|error| {
        CliError(format!(
            "artifact {} is not under result root {}: {error}",
            path.display(),
            root.display()
        ))
    })?;
    Ok(relative.to_string_lossy().replace('\\', "/"))
}

fn hex_digest(digest: [u8; 32]) -> String {
    let mut out = String::with_capacity(64);
    for byte in digest {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

fn proof_id(record: &MetricRecord) -> String {
    format!(
        "{}-{}-{}-n{}-w{}-q{}-trial{}",
        record.runner,
        record.protocol,
        record.case_name,
        nv_power(record.size),
        record.workers,
        record.pcs_queries,
        record.trial
    )
}

fn write_proof_bundle(
    run_dir: &Path,
    run_kind: &str,
    record: &MetricRecord,
    proof: StoredProof,
    generated_utc: String,
) -> Result<ProofIndexEntry, CliError> {
    let proofs_dir = run_dir.join("proofs");
    fs::create_dir_all(&proofs_dir).map_err(|error| {
        CliError(format!(
            "create proof directory {} failed: {error}",
            proofs_dir.display()
        ))
    })?;
    let proof_id = proof_id(record);
    let bundle = ProofBundle {
        schema_version: 1,
        proof_id: proof_id.clone(),
        run_kind: run_kind.to_owned(),
        generated_utc,
        protocol: record.protocol.to_owned(),
        runner: record.runner.to_owned(),
        case_name: record.case_name.to_owned(),
        trial: record.trial,
        nv_power: nv_power(record.size),
        size: record.size,
        workers: record.workers,
        pcs_queries: record.pcs_queries,
        proof_bytes: record.proof_bytes,
        communication_bytes: record.communication_bytes,
        network_bytes: record.network_bytes,
        stage_breakdown: record.stages.clone(),
        host_logical_cores: record.host_logical_cores,
        cores_per_worker: record.cores_per_worker,
        core_affinity: record.core_affinity.map(str::to_owned),
        proof,
    };
    let path = proofs_dir.join(format!("{proof_id}.proof.json"));
    let bytes = serde_json::to_vec(&bundle)
        .map_err(|error| CliError(format!("serialize proof bundle {proof_id} failed: {error}")))?;
    fs::write(&path, &bytes)
        .map_err(|error| CliError(format!("write {} failed: {error}", path.display())))?;
    Ok(ProofIndexEntry {
        proof_id,
        path: relative_artifact_path(run_dir, &path)?,
        protocol: record.protocol.to_owned(),
        runner: record.runner.to_owned(),
        case_name: record.case_name.to_owned(),
        trial: record.trial,
        nv_power: nv_power(record.size),
        size: record.size,
        workers: record.workers,
        pcs_queries: record.pcs_queries,
        proof_bytes: record.proof_bytes,
        communication_bytes: record.communication_bytes,
        network_bytes: record.network_bytes,
        file_bytes: bytes.len(),
        sha256: hex_digest(sha256(&bytes)),
    })
}

fn write_proof_index(run_dir: &Path, entries: &[ProofIndexEntry]) -> Result<(), CliError> {
    let proofs_dir = run_dir.join("proofs");
    fs::create_dir_all(&proofs_dir).map_err(|error| {
        CliError(format!(
            "create proof directory {} failed: {error}",
            proofs_dir.display()
        ))
    })?;
    let mut out = String::from("{\n");
    out.push_str("  \"schema_version\": 1,\n");
    out.push_str("  \"generated_by\": \"pq-experiments proof index\",\n");
    out.push_str(&format!("  \"proof_count\": {},\n", entries.len()));
    out.push_str("  \"proofs\": ");
    out.push_str(
        &serde_json::to_string_pretty(entries)
            .map_err(|error| CliError(format!("serialize proof index failed: {error}")))?,
    );
    out.push_str("\n}\n");
    write_text_file(&proofs_dir.join("index.json"), &out)
}

fn read_proof_bundle(path: &Path) -> Result<ProofBundle, CliError> {
    Ok(read_proof_bundle_with_bytes(path)?.0)
}

fn read_proof_bundle_with_bytes(path: &Path) -> Result<(ProofBundle, Vec<u8>), CliError> {
    let bytes = fs::read(path)
        .map_err(|error| CliError(format!("read {} failed: {error}", path.display())))?;
    let bundle = serde_json::from_slice(&bytes).map_err(|error| {
        CliError(format!(
            "parse proof bundle {} failed: {error}",
            path.display()
        ))
    })?;
    Ok((bundle, bytes))
}

fn read_proof_index_lookup(dir: &Path) -> Result<HashMap<String, ProofIndexEntry>, CliError> {
    let index_path = dir.join("proofs").join("index.json");
    let bytes = fs::read(&index_path)
        .map_err(|error| CliError(format!("read {} failed: {error}", index_path.display())))?;
    let index: ProofIndexFile = serde_json::from_slice(&bytes).map_err(|error| {
        CliError(format!(
            "parse proof index {} failed: {error}",
            index_path.display()
        ))
    })?;
    if index.schema_version != 1 {
        return Err(CliError(format!(
            "{} has unsupported proof index schema_version {}",
            index_path.display(),
            index.schema_version
        )));
    }
    if index.generated_by != "pq-experiments proof index" {
        return Err(CliError(format!(
            "{} has unexpected generated_by '{}'",
            index_path.display(),
            index.generated_by
        )));
    }
    if index.proof_count != index.proofs.len() {
        return Err(CliError(format!(
            "{} proof_count {} does not match {} proof entries",
            index_path.display(),
            index.proof_count,
            index.proofs.len()
        )));
    }
    let mut by_path = HashMap::new();
    let mut proof_ids = BTreeSet::new();
    for entry in index.proofs {
        if entry.path.contains("..")
            || entry.path.contains('\\')
            || entry.path.starts_with('/')
            || entry.path.split('/').any(str::is_empty)
            || !entry.path.starts_with("proofs/")
            || !entry.path.ends_with(".proof.json")
        {
            return Err(CliError(format!(
                "{} contains invalid proof path '{}'",
                index_path.display(),
                entry.path
            )));
        }
        if !proof_ids.insert(entry.proof_id.clone()) {
            return Err(CliError(format!(
                "{} contains duplicate proof_id '{}'",
                index_path.display(),
                entry.proof_id
            )));
        }
        match by_path.entry(entry.path.clone()) {
            Entry::Vacant(slot) => {
                slot.insert(entry);
            }
            Entry::Occupied(existing) => {
                return Err(CliError(format!(
                    "{} contains duplicate proof path '{}'",
                    index_path.display(),
                    existing.key()
                )));
            }
        }
    }
    Ok(by_path)
}

fn proof_files_in_bench(dir: &Path) -> Result<Vec<PathBuf>, CliError> {
    let proofs_dir = dir.join("proofs");
    if !proofs_dir.exists() {
        return Ok(Vec::new());
    }
    let mut files = Vec::new();
    for entry in fs::read_dir(&proofs_dir).map_err(|error| {
        CliError(format!(
            "read proof directory {} failed: {error}",
            proofs_dir.display()
        ))
    })? {
        let entry = entry.map_err(|error| {
            CliError(format!(
                "read entry under {} failed: {error}",
                proofs_dir.display()
            ))
        })?;
        let path = entry.path();
        if entry
            .file_type()
            .map_err(|error| CliError(format!("read {} type failed: {error}", path.display())))?
            .is_file()
            && path
                .file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| name.ends_with(".proof.json"))
        {
            files.push(path);
        }
    }
    files.sort();
    Ok(files)
}

fn discover_proof_benches(results_dir: &Path) -> Result<Vec<ProofListEntry>, CliError> {
    if !results_dir.exists() {
        return Ok(Vec::new());
    }
    let mut entries = Vec::new();
    for entry in fs::read_dir(results_dir).map_err(|error| {
        CliError(format!(
            "read results directory {} failed: {error}",
            results_dir.display()
        ))
    })? {
        let entry = entry.map_err(|error| {
            CliError(format!(
                "read entry under {} failed: {error}",
                results_dir.display()
            ))
        })?;
        let file_type = entry.file_type().map_err(|error| {
            CliError(format!(
                "read file type for {} failed: {error}",
                entry.path().display()
            ))
        })?;
        if !file_type.is_dir() {
            continue;
        }
        let bench_name = entry.file_name().into_string().map_err(|name| {
            CliError(format!(
                "bench directory name is not valid UTF-8: {:?}",
                name
            ))
        })?;
        if !bench_name.starts_with("bench-") {
            continue;
        }
        let proof_files = proof_files_in_bench(&entry.path())?;
        let mut proof_ids = Vec::new();
        let mut invalid_proof_count = 0;
        for proof_file in &proof_files {
            match read_proof_bundle(proof_file) {
                Ok(bundle) => proof_ids.push(bundle.proof_id),
                Err(_) => {
                    invalid_proof_count += 1;
                    proof_ids.push(format!(
                        "{} [invalid]",
                        proof_file
                            .file_name()
                            .and_then(|name| name.to_str())
                            .unwrap_or("unreadable-proof")
                    ));
                }
            }
        }
        entries.push(ProofListEntry {
            dir: entry.path(),
            bench_name,
            proof_count: proof_files.len(),
            invalid_proof_count,
            proof_ids,
        });
    }
    entries.sort_by(|left, right| left.bench_name.cmp(&right.bench_name));
    Ok(entries)
}

fn proof_list_to_json(entries: &[ProofListEntry]) -> String {
    let mut out = String::from("{\"benches\":[");
    for (index, entry) in entries.iter().enumerate() {
        if index > 0 {
            out.push(',');
        }
        out.push_str(&format!(
            "{{\"index\":{},\"bench\":\"{}\",\"dir\":\"{}\",\"proof_count\":{},\"invalid_proof_count\":{},\"proof_ids\":{}}}",
            index + 1,
            json_escape(&entry.bench_name),
            json_escape(&entry.dir.display().to_string()),
            entry.proof_count,
            entry.invalid_proof_count,
            json_string_array(&entry.proof_ids)
        ));
    }
    out.push_str("]}");
    out
}

fn verify_stored_proofs(command: &VerifyProofCommand) -> Result<ProofVerifyReport, CliError> {
    let proof_files = proof_files_for_selection(&command.dir, &command.proof)?;
    if proof_files.is_empty() {
        return Err(CliError(format!(
            "no stored proof bundles selected under {}",
            command.dir.display()
        )));
    }
    let (proof_index, proof_index_error) = match read_proof_index_lookup(&command.dir) {
        Ok(index) => (Some(index), None),
        Err(error) => (None, Some(error.0)),
    };
    let mut outcomes = Vec::with_capacity(proof_files.len());
    for proof_file in proof_files {
        let outcome = verify_stored_proof(
            &command.dir,
            &proof_file,
            proof_index.as_ref(),
            proof_index_error.as_deref(),
        )
        .unwrap_or_else(|error| failed_stored_proof_outcome(&proof_file, error.0));
        outcomes.push(outcome);
    }
    let verifications_dir = command.dir.join("verifications");
    fs::create_dir_all(&verifications_dir).map_err(|error| {
        CliError(format!(
            "create verification report directory {} failed: {error}",
            verifications_dir.display()
        ))
    })?;
    let timestamp = unix_timestamp_label(unix_timestamp_seconds()?)?;
    let mut report_json = verifications_dir.join(format!("verify-{timestamp}.json"));
    let mut report_html = verifications_dir.join(format!("verify-{timestamp}.html"));
    for attempt in 1..128 {
        if !report_json.exists() && !report_html.exists() {
            break;
        }
        report_json = verifications_dir.join(format!("verify-{timestamp}-{attempt:02}.json"));
        report_html = verifications_dir.join(format!("verify-{timestamp}-{attempt:02}.html"));
    }
    let report = ProofVerifyReport {
        bench_dir: command.dir.clone(),
        report_json: report_json.clone(),
        report_html: report_html.clone(),
        outcomes,
    };
    write_text_file(&report_json, &proof_verify_report_to_json(&report, false))?;
    write_text_file(&report_html, &proof_verify_report_html(&report))?;
    Ok(report)
}

fn proof_files_for_selection(
    dir: &Path,
    selection: &ProofSelection,
) -> Result<Vec<PathBuf>, CliError> {
    let files = proof_files_in_bench(dir)?;
    match selection {
        ProofSelection::All => Ok(files),
        ProofSelection::One(id_or_file) => {
            let mut matches = files
                .into_iter()
                .filter(|path| {
                    path.file_name()
                        .and_then(|name| name.to_str())
                        .is_some_and(|name| {
                            name == id_or_file || name == format!("{id_or_file}.proof.json")
                        })
                        || read_proof_bundle(path)
                            .map(|bundle| bundle.proof_id == *id_or_file)
                            .unwrap_or(false)
                })
                .collect::<Vec<_>>();
            matches.sort();
            if matches.is_empty() {
                Err(CliError(format!(
                    "proof '{}' was not found under {}",
                    id_or_file,
                    dir.join("proofs").display()
                )))
            } else {
                Ok(matches)
            }
        }
    }
}

fn verify_stored_proof(
    bench_dir: &Path,
    path: &Path,
    proof_index: Option<&HashMap<String, ProofIndexEntry>>,
    proof_index_error: Option<&str>,
) -> Result<ProofVerificationOutcome, CliError> {
    let (bundle, bundle_bytes) = read_proof_bundle_with_bytes(path)?;
    if bundle.schema_version != 1 {
        return Err(CliError(format!(
            "{} has unsupported proof schema_version {}",
            path.display(),
            bundle.schema_version
        )));
    }
    let verify_start = Instant::now();
    let (proof_verified, proof_protocol, proof_bytes, communication_bytes, proof_failure) =
        match &bundle.proof {
            StoredProof::R1cs(proof) => {
                let (instance, _) = sample_r1cs(bundle.size)?;
                match verify_r1cs_for_instance(&instance, proof, bundle.pcs_queries) {
                    Ok(metrics) => (
                        true,
                        "r1cs",
                        metrics.proof_bytes,
                        metrics.communication_bytes,
                        None,
                    ),
                    Err(error) => (
                        false,
                        "r1cs",
                        r1cs_proof_size_bytes(proof),
                        r1cs_opening_communication_bytes(proof),
                        Some(format!("Proof({error:?})")),
                    ),
                }
            }
            StoredProof::Plonkish(proof) => {
                let instance = sample_plonkish_instance(bundle.size)
                    .map_err(|error| CliError(format!("Plonkish sample failed: {error:?}")))?;
                match verify_for_instance(&instance, proof, bundle.pcs_queries) {
                    Ok(metrics) => (
                        true,
                        "plonkish",
                        metrics.proof_bytes,
                        metrics.communication_bytes,
                        None,
                    ),
                    Err(error) => (
                        false,
                        "plonkish",
                        pq_piop_plonkish::proof_size_bytes(proof),
                        plonkish_proof_communication_bytes(proof),
                        Some(format!("Proof({error:?})")),
                    ),
                }
            }
        };
    let mut failures = Vec::new();
    if let Some(failure) = proof_failure {
        failures.push(failure);
    }
    validate_proof_bundle_metadata(
        bench_dir,
        path,
        &bundle,
        &bundle_bytes,
        proof_protocol,
        proof_bytes,
        communication_bytes,
        proof_index,
        proof_index_error,
        &mut failures,
    )?;
    let verified = proof_verified && failures.is_empty();
    Ok(ProofVerificationOutcome {
        proof_id: bundle.proof_id,
        path: path.to_path_buf(),
        protocol: bundle.protocol,
        runner: bundle.runner,
        size: bundle.size,
        workers: bundle.workers,
        pcs_queries: bundle.pcs_queries,
        verified,
        verify_ms: millis(verify_start.elapsed()),
        proof_bytes,
        communication_bytes,
        failure_reason: if failures.is_empty() {
            None
        } else {
            Some(failures.join("; "))
        },
    })
}

fn failed_stored_proof_outcome(path: &Path, reason: String) -> ProofVerificationOutcome {
    let proof_id = path
        .file_name()
        .and_then(|name| name.to_str())
        .map(|name| name.trim_end_matches(".proof.json").to_owned())
        .unwrap_or_else(|| path.display().to_string());
    ProofVerificationOutcome {
        proof_id,
        path: path.to_path_buf(),
        protocol: "unknown".to_owned(),
        runner: "unknown".to_owned(),
        size: 0,
        workers: 0,
        pcs_queries: 0,
        verified: false,
        verify_ms: 0.0,
        proof_bytes: 0,
        communication_bytes: 0,
        failure_reason: Some(format!("ProofBundle({reason})")),
    }
}

#[allow(clippy::too_many_arguments)]
fn validate_proof_bundle_metadata(
    bench_dir: &Path,
    path: &Path,
    bundle: &ProofBundle,
    bundle_bytes: &[u8],
    proof_protocol: &str,
    proof_bytes: usize,
    communication_bytes: usize,
    proof_index: Option<&HashMap<String, ProofIndexEntry>>,
    proof_index_error: Option<&str>,
    failures: &mut Vec<String>,
) -> Result<(), CliError> {
    if bundle.protocol != proof_protocol {
        failures.push(format!(
            "Metadata(protocol '{}' does not match proof payload '{}')",
            bundle.protocol, proof_protocol
        ));
    }
    if bundle.size == 0 || !bundle.size.is_power_of_two() {
        failures.push(format!(
            "Metadata(size {} is not a positive power of two)",
            bundle.size
        ));
    } else if bundle.nv_power != nv_power(bundle.size) {
        failures.push(format!(
            "Metadata(nv_power {} does not match size {})",
            bundle.nv_power, bundle.size
        ));
    }
    if bundle.workers == 0 || !bundle.workers.is_power_of_two() || bundle.workers > bundle.size {
        failures.push(format!(
            "Metadata(workers {} is not a valid power-of-two partition for size {})",
            bundle.workers, bundle.size
        ));
    }
    if bundle.pcs_queries == 0 {
        failures.push("Metadata(pcs_queries must be positive)".to_owned());
    }
    if bundle.trial == 0 {
        failures.push("Metadata(trial must be positive)".to_owned());
    }
    let expected_id = format!(
        "{}-{}-{}-n{}-w{}-q{}-trial{}",
        bundle.runner,
        bundle.protocol,
        bundle.case_name,
        bundle.nv_power,
        bundle.workers,
        bundle.pcs_queries,
        bundle.trial
    );
    if bundle.proof_id != expected_id {
        failures.push(format!(
            "Metadata(proof_id '{}' does not match expected '{}')",
            bundle.proof_id, expected_id
        ));
    }
    if bundle.proof_bytes != proof_bytes {
        failures.push(format!(
            "Metadata(proof_bytes {} does not match recomputed {})",
            bundle.proof_bytes, proof_bytes
        ));
    }
    if bundle.communication_bytes != communication_bytes {
        failures.push(format!(
            "Metadata(communication_bytes {} does not match recomputed {})",
            bundle.communication_bytes, communication_bytes
        ));
    }
    if bundle.runner == "local" && bundle.network_bytes != 0 {
        failures.push(format!(
            "Metadata(local runner has nonzero network_bytes {})",
            bundle.network_bytes
        ));
    }

    let relative_path = relative_artifact_path(bench_dir, path)?;
    if let Some(index_error) = proof_index_error {
        failures.push(format!("ProofIndex({index_error})"));
        return Ok(());
    }
    let Some(index) = proof_index else {
        failures.push("ProofIndex(missing proof index lookup)".to_owned());
        return Ok(());
    };
    let Some(entry) = index.get(&relative_path) else {
        failures.push(format!(
            "ProofIndex(no index entry for '{}')",
            relative_path
        ));
        return Ok(());
    };
    validate_index_entry_against_bundle(entry, bundle, bundle_bytes, &relative_path, failures);
    Ok(())
}

fn validate_index_entry_against_bundle(
    entry: &ProofIndexEntry,
    bundle: &ProofBundle,
    bundle_bytes: &[u8],
    relative_path: &str,
    failures: &mut Vec<String>,
) {
    if entry.path != relative_path {
        failures.push(format!(
            "ProofIndex(path '{}' does not match actual '{}')",
            entry.path, relative_path
        ));
    }
    if entry.proof_id != bundle.proof_id {
        failures.push(format!(
            "ProofIndex(proof_id '{}' does not match bundle '{}')",
            entry.proof_id, bundle.proof_id
        ));
    }
    if entry.protocol != bundle.protocol
        || entry.runner != bundle.runner
        || entry.case_name != bundle.case_name
        || entry.trial != bundle.trial
        || entry.nv_power != bundle.nv_power
        || entry.size != bundle.size
        || entry.workers != bundle.workers
        || entry.pcs_queries != bundle.pcs_queries
        || entry.proof_bytes != bundle.proof_bytes
        || entry.communication_bytes != bundle.communication_bytes
        || entry.network_bytes != bundle.network_bytes
    {
        failures.push("ProofIndex(index metadata does not match proof bundle metadata)".to_owned());
    }
    if entry.file_bytes != bundle_bytes.len() {
        failures.push(format!(
            "ProofIndex(file_bytes {} does not match actual {})",
            entry.file_bytes,
            bundle_bytes.len()
        ));
    }
    let actual_sha = hex_digest(sha256(bundle_bytes));
    if entry.sha256 != actual_sha {
        failures.push(format!(
            "ProofIndex(sha256 '{}' does not match actual '{}')",
            entry.sha256, actual_sha
        ));
    }
}

fn proof_verify_report_to_json(report: &ProofVerifyReport, compact: bool) -> String {
    let ok = report.outcomes.iter().all(|outcome| outcome.verified);
    let verified = report
        .outcomes
        .iter()
        .filter(|outcome| outcome.verified)
        .count();
    let failed = report.outcomes.len() - verified;
    let mut out = String::new();
    out.push_str(&format!(
        "{{\"ok\":{},\"bench_dir\":\"{}\",\"report_json\":\"{}\",\"report_html\":\"{}\",\"total\":{},\"verified\":{},\"failed\":{},\"proofs\":[",
        ok,
        json_escape(&report.bench_dir.display().to_string()),
        json_escape(&report.report_json.display().to_string()),
        json_escape(&report.report_html.display().to_string()),
        report.outcomes.len(),
        verified,
        failed
    ));
    for (index, outcome) in report.outcomes.iter().enumerate() {
        if index > 0 {
            out.push(',');
        }
        out.push_str(&format!(
            "{{\"proof_id\":\"{}\",\"path\":\"{}\",\"protocol\":\"{}\",\"runner\":\"{}\",\"nv_power\":{},\"size\":{},\"workers\":{},\"pcs_queries\":{},\"verified\":{},\"verify_ms\":{:.3},\"proof_bytes\":{},\"communication_bytes\":{},\"failure_reason\":{}}}",
            json_escape(&outcome.proof_id),
            json_escape(&outcome.path.display().to_string()),
            json_escape(&outcome.protocol),
            json_escape(&outcome.runner),
            nv_power(outcome.size),
            outcome.size,
            outcome.workers,
            outcome.pcs_queries,
            outcome.verified,
            outcome.verify_ms,
            outcome.proof_bytes,
            outcome.communication_bytes,
            json_optional_string(outcome.failure_reason.as_deref())
        ));
    }
    out.push_str("]}");
    if compact { out } else { format!("{}\n", out) }
}

fn proof_verify_report_html(report: &ProofVerifyReport) -> String {
    let ok = report.outcomes.iter().all(|outcome| outcome.verified);
    let rows = report
        .outcomes
        .iter()
        .map(|outcome| {
            format!(
                "<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{:.3}</td><td>{}</td></tr>",
                html_escape(&outcome.proof_id),
                html_escape(&outcome.protocol),
                html_escape(&outcome.runner),
                nv_power(outcome.size),
                outcome.workers,
                outcome.verify_ms,
                outcome
                    .failure_reason
                    .as_deref()
                    .map(html_escape)
                    .unwrap_or_else(|| "verified".to_owned())
            )
        })
        .collect::<Vec<_>>()
        .join("");
    format!(
        concat!(
            "<!doctype html><html><head><meta charset=\"utf-8\"><title>pq_dSNARK proof verification</title>",
            "<style>body{{font-family:Inter,Segoe UI,Arial,sans-serif;margin:40px;color:#111827;background:#f8fafc}}",
            "main{{max-width:1040px;margin:auto}}.status{{display:inline-block;padding:8px 12px;border-radius:6px;font-weight:700}}",
            ".ok{{background:#dcfce7;color:#166534}}.bad{{background:#fee2e2;color:#991b1b}}",
            "table{{width:100%;border-collapse:collapse;background:white;margin-top:24px}}th,td{{padding:10px 12px;border-bottom:1px solid #e5e7eb;text-align:left}}",
            "th{{font-size:12px;text-transform:uppercase;color:#64748b}}</style></head><body><main>",
            "<h1>pq_dSNARK proof verification</h1><p>{}</p><div class=\"status {}\">{}</div>",
            "<table><thead><tr><th>proof</th><th>protocol</th><th>runner</th><th>n</th><th>workers</th><th>verify ms</th><th>result</th></tr></thead><tbody>{}</tbody></table>",
            "</main></body></html>\n"
        ),
        html_escape(&report.bench_dir.display().to_string()),
        if ok { "ok" } else { "bad" },
        if ok {
            "All selected proofs verified"
        } else {
            "At least one proof failed"
        },
        rows
    )
}

fn proof_experiment_report_json(
    run_id: u64,
    run_label: &str,
    command: &ProofExperimentCommand,
    records: &[MetricRecord],
    proofs: &[ProofIndexEntry],
) -> Result<String, CliError> {
    let mut out = String::new();
    out.push_str("{\n");
    out.push_str("  \"schema_version\": 1,\n");
    out.push_str("  \"generated_by\": \"pq-experiments proof-experiment\",\n");
    out.push_str(&format!("  \"run_id\": {run_id},\n"));
    out.push_str(&format!(
        "  \"run_label\": \"{}\",\n",
        json_escape(run_label)
    ));
    out.push_str(&format!(
        "  \"generated_utc\": \"{}\",\n",
        json_escape(&unix_timestamp_label(run_id)?)
    ));
    out.push_str(&format!(
        "  \"protocol\": \"{}\",\n",
        command.protocol.as_str()
    ));
    out.push_str(&format!("  \"runner\": \"{}\",\n", command.runner.as_str()));
    out.push_str(&format!("  \"nv_power\": {},\n", nv_power(command.size)));
    out.push_str(&format!("  \"size\": {},\n", command.size));
    out.push_str(&format!("  \"workers\": {},\n", command.workers));
    out.push_str(&format!("  \"pcs_queries\": {},\n", command.pcs_queries));
    out.push_str(&format!("  \"record_count\": {},\n", records.len()));
    out.push_str(&format!("  \"proof_count\": {},\n", proofs.len()));
    out.push_str(&format!(
        "  \"pcs_analysis\": {},\n",
        proof_experiment_pcs_analysis_json(records)
    ));
    out.push_str("  \"records\": ");
    out.push_str(&records_to_json(records));
    out.push_str(",\n");
    out.push_str("  \"proofs\": ");
    out.push_str(
        &serde_json::to_string_pretty(proofs)
            .map_err(|error| CliError(format!("serialize proof report failed: {error}")))?,
    );
    out.push_str("\n}\n");
    Ok(out)
}

fn proof_experiment_overview_html(
    run_id: u64,
    run_label: &str,
    command: &ProofExperimentCommand,
    records: &[MetricRecord],
    proofs: &[ProofIndexEntry],
) -> String {
    let rows = records
        .iter()
        .map(|record| {
            format!(
                "<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{:.3}</td><td>{:.3}</td><td>{:.3}</td><td>{:.3}</td><td>{:.1}%</td><td>{}</td></tr>",
                html_escape(record.protocol),
                html_escape(record.runner),
                nv_power(record.size),
                record.workers,
                record.pcs_queries,
                record.prove_ms,
                record.verify_ms,
                record.stages.prove_pcs_commit_ms,
                record.stages.prove_batch_open_ms,
                ratio(record.stages.proof_pcs_bytes as f64, record.proof_bytes as f64) * 100.0,
                record.proof_bytes
            )
        })
        .collect::<Vec<_>>()
        .join("");
    let proof_links = proofs
        .iter()
        .map(|proof| {
            format!(
                "<a href=\"{}\">{}</a>",
                html_escape(&proof.path),
                html_escape(&proof.proof_id)
            )
        })
        .collect::<Vec<_>>()
        .join("");
    format!(
        concat!(
            "<!doctype html><html><head><meta charset=\"utf-8\"><title>pq_dSNARK proof experiment</title>",
            "<style>body{{font-family:Inter,Segoe UI,Arial,sans-serif;margin:40px;color:#111827;background:#f8fafc}}main{{max-width:1040px;margin:auto}}",
            "table{{width:100%;border-collapse:collapse;background:white;margin-top:22px}}th,td{{padding:10px 12px;border-bottom:1px solid #e5e7eb;text-align:left}}",
            "th{{font-size:12px;text-transform:uppercase;color:#64748b}}.links{{display:flex;gap:10px;flex-wrap:wrap;margin-top:20px}}",
            ".links a{{background:white;border:1px solid #dbe3ee;border-radius:6px;padding:8px 10px;color:#0f766e;text-decoration:none}}</style></head><body><main>",
            "<h1>pq_dSNARK proof experiment</h1><p>{} - run_id={} - protocol={} - runner={} - n={}</p>",
            "<h2>PCS analysis</h2>{}",
            "<table><thead><tr><th>protocol</th><th>runner</th><th>n</th><th>workers</th><th>queries</th><th>prove ms</th><th>verify ms</th><th>PCS commit ms</th><th>batch/open ms</th><th>PCS proof share</th><th>proof bytes</th></tr></thead><tbody>{}</tbody></table>",
            "<h2>Stored proofs</h2><div class=\"links\"><a href=\"proofs/index.json\">proofs/index.json</a>{}</div>",
            "</main></body></html>\n"
        ),
        html_escape(run_label),
        run_id,
        command.protocol.as_str(),
        command.runner.as_str(),
        nv_power(command.size),
        benchmark_pcs_analysis_html(records),
        rows,
        proof_links
    )
}

fn proof_experiment_pcs_analysis_json(records: &[MetricRecord]) -> String {
    let max_commit = records.iter().max_by(|left, right| {
        left.stages
            .prove_pcs_commit_ms
            .partial_cmp(&right.stages.prove_pcs_commit_ms)
            .unwrap_or(std::cmp::Ordering::Equal)
    });
    let Some(record) = max_commit else {
        return "{\"record_count\":0}".to_owned();
    };
    format!(
        "{{\"record_count\":{},\"max_pcs_commit_ms\":{:.3},\"max_pcs_commit_protocol\":\"{}\",\"max_pcs_commit_runner\":\"{}\",\"max_pcs_commit_share\":{:.6}}}",
        records.len(),
        record.stages.prove_pcs_commit_ms,
        json_escape(record.protocol),
        json_escape(record.runner),
        ratio(record.stages.prove_pcs_commit_ms, record.prove_ms)
    )
}

fn benchmark_metadata_json(
    run_id: u64,
    command: &BenchmarkCommand,
    records: &[MetricRecord],
    figure_pdf_created: bool,
    provenance: &BenchmarkProvenance,
) -> String {
    let positives = records
        .iter()
        .filter(|record| record.case_name == "positive" && record.verified)
        .count();
    let negatives = records
        .iter()
        .filter(|record| record.case_name == "negative" && !record.verified)
        .count();
    let nv_powers = command
        .sizes
        .iter()
        .map(|size| nv_power(*size))
        .collect::<Vec<_>>();
    let command_line = env::args().collect::<Vec<_>>();
    format!(
        concat!(
            "{{\n",
            "  \"schema_version\": 7,\n",
            "  \"run_id\": {},\n",
            "  \"generated_by\": \"pq-experiments benchmark\",\n",
            "  \"host_os\": \"{}\",\n",
            "  \"host_arch\": \"{}\",\n",
            "  \"build_profile\": \"{}\",\n",
            "  \"package_version\": \"{}\",\n",
            "  \"command_line\": {},\n",
            "  \"out_dir\": \"{}\",\n",
            "  \"nv_powers\": {},\n",
            "  \"sizes\": {},\n",
            "  \"workers\": {},\n",
            "  \"pcs_queries\": {},\n",
            "  \"repeats\": {},\n",
            "  \"paper_preset\": {},\n",
            "  \"runner\": \"{}\",\n",
            "  \"figure_compiler\": \"{}\",\n",
            "  \"compile_figures_requested\": {},\n",
            "  \"compile_figures_succeeded\": {},\n",
            "  \"record_count\": {},\n",
            "  \"positive_verified\": {},\n",
            "  \"negative_rejected\": {},\n",
            "  \"artifacts\": {},\n",
            "  \"core_allocation\": {},\n",
            "  \"provenance\": {}\n",
            "}}\n"
        ),
        run_id,
        json_escape(env::consts::OS),
        json_escape(env::consts::ARCH),
        build_profile(),
        json_escape(env!("CARGO_PKG_VERSION")),
        json_string_array(&command_line),
        json_escape(&command.out_dir.display().to_string()),
        json_usize_array(&nv_powers),
        json_usize_array(&command.sizes),
        json_usize_array(&command.workers),
        command.pcs_queries,
        command.repeats,
        command.paper_preset,
        command.runner.as_str(),
        command.figure_compiler.as_str(),
        command.compile_figures,
        figure_pdf_created,
        records.len(),
        positives,
        negatives,
        json_string_array(&benchmark_artifacts(figure_pdf_created)),
        benchmark_core_allocation_json(command),
        provenance.to_json()
    )
}

fn benchmark_core_allocation_json(command: &BenchmarkCommand) -> String {
    let Some(plan) = &command.worker_core_plan else {
        return "null".to_owned();
    };
    let worker_core_ids = (0..plan.max_workers)
        .map(|worker_id| plan.core_ids_for_worker(worker_id))
        .collect::<Vec<_>>();
    format!(
        concat!(
            "{{",
            "\"host_logical_cores\":{},",
            "\"max_workers\":{},",
            "\"cores_per_worker\":{},",
            "\"affinity_mode\":\"{}\",",
            "\"worker_core_ids\":{}",
            "}}"
        ),
        plan.host_logical_cores,
        plan.max_workers,
        plan.cores_per_worker,
        worker_affinity_mode(),
        json_usize_matrix(&worker_core_ids)
    )
}

fn benchmark_core_allocation_summary(command: &BenchmarkCommand) -> String {
    command
        .worker_core_plan
        .as_ref()
        .map(|plan| {
            format!(
                "host_logical_cores={},max_workers={},cores_per_worker={},affinity_mode={}",
                plan.host_logical_cores,
                plan.max_workers,
                plan.cores_per_worker,
                worker_affinity_mode()
            )
        })
        .unwrap_or_else(|| "none".to_owned())
}

fn write_benchmark_overview_html(
    run_dir: &Path,
    run_id: u64,
    command: &BenchmarkCommand,
    records: &[MetricRecord],
    figure_pdf_created: bool,
) -> Result<(), CliError> {
    write_text_file(
        &run_dir.join(OVERVIEW_HTML),
        &benchmark_overview_html(run_id, command, records, figure_pdf_created),
    )
}

fn benchmark_overview_html(
    run_id: u64,
    command: &BenchmarkCommand,
    records: &[MetricRecord],
    figure_pdf_created: bool,
) -> String {
    let positives_verified = records
        .iter()
        .filter(|record| record.case_name == "positive" && record.verified)
        .count();
    let negatives_rejected = records
        .iter()
        .filter(|record| record.case_name == "negative" && !record.verified)
        .count();
    let positive_total = records
        .iter()
        .filter(|record| record.case_name == "positive")
        .count();
    let negative_total = records
        .iter()
        .filter(|record| record.case_name == "negative")
        .count();
    let correctness_ok =
        positives_verified == positive_total && negative_total == 0 && negatives_rejected == 0;
    let stats = benchmark_stats(records);
    let scaling_rows = benchmark_overview_scaling_rows(&stats, command);
    let stats_rows = benchmark_overview_stats_rows(&stats);
    let stage_rows = benchmark_overview_stage_rows(&stats);
    let pcs_analysis = benchmark_pcs_analysis_html(records);
    let artifact_rows = benchmark_overview_artifact_rows(figure_pdf_created);
    let chart_cards = benchmark_overview_chart_cards();
    let core_allocation = benchmark_overview_core_allocation(command);
    let nv_powers = command
        .sizes
        .iter()
        .map(|size| nv_power(*size).to_string())
        .collect::<Vec<_>>()
        .join(", ");
    let sizes = command
        .sizes
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join(", ");
    let workers = command
        .workers
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join(", ");
    let status_class = if correctness_ok { "ok" } else { "fail" };
    let status_text = if correctness_ok {
        "All positive performance proofs verified; no negative correctness rows are included."
    } else {
        "Performance benchmark gate failed; inspect source rows before using these results."
    };
    format!(
        concat!(
            "<!doctype html>\n",
            "<html lang=\"en\">\n",
            "<head>\n",
            "  <meta charset=\"utf-8\">\n",
            "  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n",
            "  <title>pq_dSNARK benchmark overview {run_id}</title>\n",
            "  <style>{css}</style>\n",
            "</head>\n",
            "<body>\n",
            "  <main class=\"shell\">\n",
            "    <section class=\"hero\">\n",
            "      <div>\n",
            "        <p class=\"label\">pq_dSNARK benchmark overview</p>\n",
            "        <h1>Run {run_id}</h1>\n",
            "        <p class=\"summary\">Measured end-to-end prover cost, verifier cost, proof size, network bytes, and worker scaling from the real protocol path. No fitted or synthetic data is used.</p>\n",
            "      </div>\n",
            "      <div class=\"status {status_class}\">{status_text}</div>\n",
            "    </section>\n",
            "    <section class=\"cards\">\n",
            "      <article><span>records</span><strong>{records}</strong><small>one prove+verify per row</small></article>\n",
            "      <article><span>positive verified</span><strong>{positives_verified}/{positive_total}</strong><small>required performance path</small></article>\n",
            "      <article><span>negative rows</span><strong>{negative_total}</strong><small>excluded from benchmark</small></article>\n",
            "      <article><span>runner</span><strong>{runner}</strong><small>selected benchmark mode</small></article>\n",
            "    </section>\n",
            "    <section class=\"panel grid2\">\n",
            "      <div>\n",
            "        <h2>Configuration</h2>\n",
            "        <dl class=\"kv\">",
            "          <dt>nv powers</dt><dd>{nv_powers}</dd>",
            "          <dt>sizes</dt><dd>{sizes}</dd>",
            "          <dt>workers</dt><dd>{workers}</dd>",
            "          <dt>PCS queries</dt><dd>{pcs_queries}</dd>",
            "          <dt>per config</dt><dd>one prove+verify</dd>",
            "          <dt>build profile</dt><dd>{build_profile}</dd>",
            "          <dt>figure PDF</dt><dd>{figure_pdf}</dd>",
            "        </dl>",
            "      </div>\n",
            "      <div>{core_allocation}</div>\n",
            "    </section>\n",
            "    <section class=\"panel\">\n",
            "      <h2>Paper Figures</h2>\n",
            "      <div class=\"charts\">{chart_cards}</div>\n",
            "    </section>\n",
            "    <section class=\"panel\">\n",
            "      <h2>Scaling Check</h2>\n",
            "      <p class=\"note\">The dashed reference is a perfect-linear upper bound against the workers=1 baseline for the same protocol, runner, and largest tested size, not a prediction for this correctness prototype. Small circuits and serial master, transcript, verifier, and PCS-orchestration work can dominate; superlinear or missing-baseline claims should be treated as suspicious.</p>\n",
            "      <div class=\"table-wrap\"><table><thead><tr><th>runner</th><th>protocol</th><th>workers</th><th>speedup</th><th>efficiency</th><th>serial+overhead</th><th>assessment</th></tr></thead><tbody>{scaling_rows}</tbody></table></div>\n",
            "    </section>\n",
            "    <section class=\"panel\">\n",
            "      <h2>PCS Cost And Proof-Size Share</h2>\n",
            "      {pcs_analysis}",
            "    </section>\n",
            "    <section class=\"panel\">\n",
            "      <h2>Stage Breakdown</h2>\n",
            "      <p class=\"note\">Stage timings are collected inside the prover/verifier code path. Prover other is the measured total minus PCS commitment, sumcheck, and batch-open/query phases.</p>\n",
            "      <div class=\"table-wrap\"><table><thead><tr><th>runner</th><th>protocol</th><th>n</th><th>workers</th><th>PCS commit ms</th><th>sumcheck ms</th><th>batch/open ms</th><th>prove other ms</th><th>verify PCS open ms</th><th>verify sumcheck ms</th><th>PCS proof share</th></tr></thead><tbody>{stage_rows}</tbody></table></div>\n",
            "    </section>\n",
            "    <section class=\"panel\">\n",
            "      <h2>Summary Statistics</h2>\n",
            "      <div class=\"table-wrap\"><table><thead><tr><th>runner</th><th>protocol</th><th>case</th><th>n</th><th>workers</th><th>samples</th><th>prove ms</th><th>verify ms</th><th>proof bytes</th><th>network bytes</th></tr></thead><tbody>{stats_rows}</tbody></table></div>\n",
            "    </section>\n",
            "    <section class=\"panel\">\n",
            "      <h2>Artifacts</h2>\n",
            "      <div class=\"artifact-grid\">{artifact_rows}</div>\n",
            "    </section>\n",
            "  </main>\n",
            "</body>\n",
            "</html>\n"
        ),
        run_id = run_id,
        css = benchmark_overview_css(),
        status_class = status_class,
        status_text = html_escape(status_text),
        records = records.len(),
        positives_verified = positives_verified,
        positive_total = positive_total,
        negative_total = negative_total,
        runner = html_escape(command.runner.as_str()),
        nv_powers = html_escape(&nv_powers),
        sizes = html_escape(&sizes),
        workers = html_escape(&workers),
        pcs_queries = command.pcs_queries,
        build_profile = html_escape(build_profile()),
        figure_pdf = if figure_pdf_created {
            "created"
        } else {
            "not created"
        },
        core_allocation = core_allocation,
        chart_cards = chart_cards,
        pcs_analysis = pcs_analysis,
        stage_rows = stage_rows,
        scaling_rows = scaling_rows,
        stats_rows = stats_rows,
        artifact_rows = artifact_rows
    )
}

fn benchmark_overview_css() -> &'static str {
    r#"
:root { color-scheme: light; --bg: #f6f7fb; --ink: #111827; --muted: #64748b; --line: #d8dde8; --panel: #ffffff; --blue: #1d4ed8; --green: #047857; --red: #b91c1c; --amber: #b45309; --shadow: 0 18px 50px rgba(15, 23, 42, .10); }
* { box-sizing: border-box; }
body { margin: 0; background: var(--bg); color: var(--ink); font-family: ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; line-height: 1.45; }
a { color: inherit; text-decoration: none; }
.shell { width: min(1180px, calc(100vw - 40px)); margin: 0 auto; padding: 40px 0 56px; }
.hero { display: grid; grid-template-columns: minmax(0, 1fr) 360px; gap: 28px; align-items: end; padding: 34px; color: #fff; background: linear-gradient(135deg, #111827 0%, #123f7c 58%, #0f766e 100%); border-radius: 8px; box-shadow: var(--shadow); }
.label { margin: 0 0 12px; color: #bfdbfe; font-size: 13px; font-weight: 700; letter-spacing: .08em; text-transform: uppercase; }
h1 { margin: 0; font-size: 42px; line-height: 1.05; letter-spacing: 0; }
h2 { margin: 0 0 18px; font-size: 20px; letter-spacing: 0; }
.summary { max-width: 760px; margin: 16px 0 0; color: #dbeafe; font-size: 16px; }
.status { padding: 18px; border: 1px solid rgba(255,255,255,.24); border-radius: 8px; background: rgba(255,255,255,.10); font-weight: 700; }
.status.ok { border-color: rgba(187,247,208,.48); }
.status.fail { border-color: rgba(254,202,202,.7); }
.cards { display: grid; grid-template-columns: repeat(4, minmax(0, 1fr)); gap: 14px; margin: 18px 0; }
.cards article, .panel { background: var(--panel); border: 1px solid var(--line); border-radius: 8px; box-shadow: 0 10px 30px rgba(15, 23, 42, .06); }
.cards article { padding: 18px; }
.cards span { display: block; color: var(--muted); font-size: 12px; font-weight: 700; text-transform: uppercase; }
.cards strong { display: block; margin-top: 8px; font-size: 30px; line-height: 1; letter-spacing: 0; }
.cards small { display: block; margin-top: 10px; color: var(--muted); }
.panel { padding: 24px; margin-top: 18px; }
.grid2 { display: grid; grid-template-columns: 1fr 1fr; gap: 28px; }
.kv { display: grid; grid-template-columns: 150px 1fr; gap: 9px 18px; margin: 0; }
.kv dt { color: var(--muted); font-weight: 700; }
.kv dd { margin: 0; font-weight: 650; }
.note { color: var(--muted); max-width: 880px; margin: -4px 0 18px; }
.charts { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 16px; }
.chart-card { border: 1px solid var(--line); border-radius: 8px; overflow: hidden; background: #fbfdff; }
.chart-card img { display: block; width: 100%; height: 260px; object-fit: contain; background: #fff; border-bottom: 1px solid var(--line); }
.chart-card div { padding: 14px 16px; display: flex; justify-content: space-between; gap: 12px; align-items: center; }
.chart-card strong { font-size: 14px; }
.chart-card span { color: var(--muted); font-size: 13px; }
.table-wrap { overflow-x: auto; border: 1px solid var(--line); border-radius: 8px; }
table { width: 100%; border-collapse: collapse; min-width: 760px; background: #fff; }
th, td { padding: 11px 13px; border-bottom: 1px solid #e8edf5; text-align: left; font-size: 13px; white-space: nowrap; }
th { color: #334155; background: #f8fafc; font-size: 12px; text-transform: uppercase; letter-spacing: .04em; }
tr:last-child td { border-bottom: 0; }
.tag { display: inline-block; padding: 3px 8px; border-radius: 999px; font-weight: 700; font-size: 12px; }
.tag.ok { color: var(--green); background: #dcfce7; }
.tag.warn { color: var(--amber); background: #fef3c7; }
.tag.fail { color: var(--red); background: #fee2e2; }
.artifact-grid { display: grid; grid-template-columns: repeat(4, minmax(0, 1fr)); gap: 10px; }
.artifact-grid a { display: block; padding: 12px; border: 1px solid var(--line); border-radius: 8px; background: #fbfdff; font-size: 13px; font-weight: 650; }
.artifact-grid a:hover { border-color: #93c5fd; background: #eff6ff; }
@media (max-width: 900px) { .hero, .grid2, .charts { grid-template-columns: 1fr; } .cards, .artifact-grid { grid-template-columns: repeat(2, minmax(0, 1fr)); } }
@media (max-width: 560px) { .shell { width: min(100vw - 24px, 1180px); padding-top: 20px; } .hero { padding: 22px; } h1 { font-size: 32px; } .cards, .artifact-grid { grid-template-columns: 1fr; } .chart-card img { height: 210px; } }
"#
}

fn benchmark_overview_core_allocation(command: &BenchmarkCommand) -> String {
    let Some(plan) = &command.worker_core_plan else {
        return concat!(
            "<h2>Core Allocation</h2>",
            "<p class=\"note\">No worker affinity was requested. Local-only runs and single-worker network runs use the host scheduler.</p>"
        )
        .to_owned();
    };
    let rows = (0..plan.max_workers)
        .map(|worker_id| {
            let ids = plan
                .core_ids_for_worker(worker_id)
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join(", ");
            format!(
                "<dt>worker {}</dt><dd>{}</dd>",
                worker_id,
                html_escape(&ids)
            )
        })
        .collect::<String>();
    format!(
        concat!(
            "<h2>Core Allocation</h2>",
            "<dl class=\"kv\">",
            "<dt>host logical cores</dt><dd>{}</dd>",
            "<dt>max workers</dt><dd>{}</dd>",
            "<dt>cores per worker</dt><dd>{}</dd>",
            "<dt>affinity mode</dt><dd>{}</dd>",
            "{}",
            "</dl>"
        ),
        plan.host_logical_cores,
        plan.max_workers,
        plan.cores_per_worker,
        html_escape(worker_affinity_mode()),
        rows
    )
}

fn benchmark_overview_chart_cards() -> String {
    [
        (
            "Proving Time",
            "prove_time_by_size.svg",
            "Mean prover time by size and worker count",
        ),
        (
            "Verifier Time",
            "verify_time_by_size.svg",
            "Mean verifier time by size and worker count",
        ),
        (
            "Proof Bytes",
            "proof_bytes_by_size.svg",
            "Proof size across protocols",
        ),
        (
            "Worker Scaling",
            "worker_scaling_max_size.svg",
            "Speedup and perfect-scaling bound",
        ),
    ]
    .iter()
    .map(|(title, path, subtitle)| {
        format!(
            "<a class=\"chart-card\" href=\"{path}\"><img src=\"{path}\" alt=\"{title}\"><div><strong>{title}</strong><span>{subtitle}</span></div></a>",
            path = html_escape(path),
            title = html_escape(title),
            subtitle = html_escape(subtitle)
        )
    })
    .collect::<String>()
}

fn benchmark_overview_scaling_rows(
    stats: &[BenchmarkStatsRecord],
    command: &BenchmarkCommand,
) -> String {
    let Some(max_size) = command.sizes.iter().copied().max() else {
        return "<tr><td colspan=\"6\">No size data.</td></tr>".to_owned();
    };
    let positives = stats
        .iter()
        .filter(|record| {
            record.case_name == "positive"
                && record.size == max_size
                && record.verified_count > 0
                && record.prove_ms.mean > 0.0
        })
        .collect::<Vec<_>>();
    let mut rows = String::new();
    for record in &positives {
        if record.workers == 1 {
            continue;
        }
        let baseline = positives.iter().find(|candidate| {
            candidate.runner == record.runner
                && candidate.protocol == record.protocol
                && candidate.workers == 1
        });
        let Some(baseline) = baseline else {
            rows.push_str(&format!(
                "<tr><td>{}</td><td>{}</td><td>{}</td><td colspan=\"4\"><span class=\"tag fail\">missing baseline</span></td></tr>",
                html_escape(record.runner),
                html_escape(record.protocol),
                record.workers
            ));
            continue;
        };
        let speedup = baseline.prove_ms.mean / record.prove_ms.mean;
        let efficiency = speedup / record.workers as f64;
        let serial_overhead = amdahl_serial_overhead_fraction(speedup, record.workers);
        let (class, label) = scaling_assessment(speedup, record.workers);
        rows.push_str(&format!(
            "<tr><td>{}</td><td>{}</td><td>{}</td><td>{:.3}</td><td>{:.3}</td><td>{:.3}</td><td><span class=\"tag {}\">{}</span></td></tr>",
            html_escape(record.runner),
            html_escape(record.protocol),
            record.workers,
            speedup,
            efficiency,
            serial_overhead,
            class,
            html_escape(label)
        ));
    }
    if rows.is_empty() {
        "<tr><td colspan=\"7\">Only workers=1 was measured, so the scaling panel is a baseline integrity check rather than a speedup claim.</td></tr>".to_owned()
    } else {
        rows
    }
}

fn amdahl_serial_overhead_fraction(speedup: f64, workers: usize) -> f64 {
    if workers <= 1 || !speedup.is_finite() || speedup <= 0.0 {
        return 1.0;
    }
    let worker_count = workers as f64;
    let estimate = ((1.0 / speedup) - (1.0 / worker_count)) / (1.0 - (1.0 / worker_count));
    estimate.clamp(0.0, 1.0)
}

fn scaling_assessment(speedup: f64, workers: usize) -> (&'static str, &'static str) {
    if workers <= 1 {
        return ("ok", "baseline");
    }
    let efficiency = speedup / workers as f64;
    if speedup > workers as f64 * 1.25 {
        ("fail", "suspicious superlinear")
    } else if speedup < 0.95 {
        ("warn", "slowdown/no scaling")
    } else if efficiency < 0.35 {
        ("warn", "serial-dominated prototype")
    } else if efficiency < 0.60 {
        ("warn", "limited prototype scaling")
    } else {
        ("ok", "scaling visible")
    }
}

fn benchmark_overview_stats_rows(stats: &[BenchmarkStatsRecord]) -> String {
    stats
        .iter()
        .map(|record| {
            format!(
                "<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{:.3}</td><td>{:.3}</td><td>{}</td><td>{}</td></tr>",
                html_escape(record.runner),
                html_escape(record.protocol),
                html_escape(record.case_name),
                nv_power(record.size),
                record.workers,
                record.samples,
                record.prove_ms.mean,
                record.verify_ms.mean,
                format_bytes(record.proof_bytes.mean),
                format_bytes(record.network_bytes.mean)
            )
        })
        .collect::<String>()
}

fn benchmark_overview_stage_rows(stats: &[BenchmarkStatsRecord]) -> String {
    stats
        .iter()
        .filter(|record| record.case_name == "positive" && record.verified_count > 0)
        .map(|record| {
            let proof_pcs_share = ratio(record.proof_pcs_bytes.mean, record.proof_bytes.mean);
            let prove_other = (record.prove_ms.mean
                - record.prove_pcs_commit_ms.mean
                - record.prove_sumcheck_ms.mean
                - record.prove_batch_open_ms.mean)
                .max(0.0);
            format!(
                "<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{:.3}</td><td>{:.3}</td><td>{:.3}</td><td>{:.3}</td><td>{:.3}</td><td>{:.3}</td><td>{:.1}%</td></tr>",
                html_escape(record.runner),
                html_escape(record.protocol),
                nv_power(record.size),
                record.workers,
                record.prove_pcs_commit_ms.mean,
                record.prove_sumcheck_ms.mean,
                record.prove_batch_open_ms.mean,
                prove_other,
                record.verify_pcs_open_ms.mean,
                record.verify_sumcheck_ms.mean,
                proof_pcs_share * 100.0
            )
        })
        .collect::<String>()
}

fn benchmark_pcs_analysis_html(records: &[MetricRecord]) -> String {
    let positives = records
        .iter()
        .filter(|record| record.case_name == "positive" && record.verified)
        .collect::<Vec<_>>();
    if positives.is_empty() {
        return "<p class=\"note\">No verified positive records are available for PCS analysis.</p>"
            .to_owned();
    }
    let max_commit = positives
        .iter()
        .max_by(|left, right| {
            left.stages
                .prove_pcs_commit_ms
                .partial_cmp(&right.stages.prove_pcs_commit_ms)
                .unwrap_or(std::cmp::Ordering::Equal)
        })
        .expect("non-empty positives");
    let max_size_share = positives
        .iter()
        .max_by(|left, right| {
            ratio(left.stages.proof_pcs_bytes as f64, left.proof_bytes as f64)
                .partial_cmp(&ratio(
                    right.stages.proof_pcs_bytes as f64,
                    right.proof_bytes as f64,
                ))
                .unwrap_or(std::cmp::Ordering::Equal)
        })
        .expect("non-empty positives");
    let commit_share = ratio(
        max_commit.stages.prove_pcs_commit_ms,
        max_commit.prove_ms.max(0.001),
    ) * 100.0;
    let proof_share = ratio(
        max_size_share.stages.proof_pcs_bytes as f64,
        max_size_share.proof_bytes as f64,
    ) * 100.0;
    format!(
        concat!(
            "<p class=\"note\">PCS commitment time is measured from the actual commitment calls inside the prover. ",
            "PCS proof-size share counts PCS commitments, Merkle/distributed openings, sampled folding proofs, and distributed index openings in the serialized proof-size accounting.</p>",
            "<div class=\"table-wrap\"><table><thead><tr><th>metric</th><th>runner</th><th>protocol</th><th>n</th><th>workers</th><th>value</th><th>share</th></tr></thead><tbody>",
            "<tr><td>max PCS commitment time</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{:.3} ms</td><td>{:.1}% of prove</td></tr>",
            "<tr><td>max PCS proof-size share</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{:.1}% of proof</td></tr>",
            "</tbody></table></div>"
        ),
        html_escape(max_commit.runner),
        html_escape(max_commit.protocol),
        nv_power(max_commit.size),
        max_commit.workers,
        max_commit.stages.prove_pcs_commit_ms,
        commit_share,
        html_escape(max_size_share.runner),
        html_escape(max_size_share.protocol),
        nv_power(max_size_share.size),
        max_size_share.workers,
        format_bytes(max_size_share.stages.proof_pcs_bytes as f64),
        proof_share
    )
}

fn benchmark_overview_artifact_rows(figure_pdf_created: bool) -> String {
    benchmark_artifacts(figure_pdf_created)
        .into_iter()
        .map(|path| format!("<a href=\"{path}\">{path}</a>", path = html_escape(path)))
        .collect::<String>()
}

fn format_bytes(value: f64) -> String {
    if value >= 1024.0 * 1024.0 {
        format!("{:.2} MiB", value / (1024.0 * 1024.0))
    } else if value >= 1024.0 {
        format!("{:.2} KiB", value / 1024.0)
    } else {
        format!("{} B", value.round() as usize)
    }
}

fn ratio(numerator: f64, denominator: f64) -> f64 {
    if denominator > 0.0 && numerator.is_finite() && denominator.is_finite() {
        numerator / denominator
    } else {
        0.0
    }
}

fn benchmark_summary(
    command: &BenchmarkCommand,
    records: &[MetricRecord],
    phase_timings: &[PhaseTimingRecord],
    figure_pdf_created: bool,
    provenance: &BenchmarkProvenance,
) -> String {
    let positives = records
        .iter()
        .filter(|record| record.case_name == "positive" && record.verified)
        .count();
    let negatives = records
        .iter()
        .filter(|record| record.case_name == "negative" && !record.verified)
        .count();
    let mut out = format!(
        "nv_powers={:?}\nsizes={:?}\nworkers={:?}\npcs_queries={}\nrepeats={}\npaper_preset={}\nrunner={}\nfigure_compiler={}\ncompile_figures_requested={}\ncompile_figures_succeeded={}\nbuild_profile={}\ncore_allocation={}\nrecords={}\npositive_verified={}\nnegative_rejected={}\nartifacts={}\n",
        command
            .sizes
            .iter()
            .map(|size| nv_power(*size))
            .collect::<Vec<_>>(),
        command.sizes,
        command.workers,
        command.pcs_queries,
        command.repeats,
        command.paper_preset,
        command.runner.as_str(),
        command.figure_compiler.as_str(),
        command.compile_figures,
        figure_pdf_created,
        build_profile(),
        benchmark_core_allocation_summary(command),
        records.len(),
        positives,
        negatives,
        benchmark_artifacts(figure_pdf_created).join(",")
    );
    out.push_str(&format!(
        "git_commit={}\ngit_branch={}\ngit_dirty={}\nrustc_version={}\ncargo_version={}\nrustflags={}\ncargo_lock_sha256={}\nrust_toolchain_sha256={}\n",
        provenance.git_commit.as_deref().unwrap_or("unavailable"),
        provenance.git_branch.as_deref().unwrap_or("unavailable"),
        provenance
            .git_dirty
            .map(|dirty| dirty.to_string())
            .unwrap_or_else(|| "unavailable".to_owned()),
        provenance
            .rustc_version_line()
            .unwrap_or("unavailable"),
        provenance
            .cargo_version_line()
            .unwrap_or("unavailable"),
        provenance.rustflags.as_deref().unwrap_or("unset"),
        provenance
            .cargo_lock_sha256
            .as_deref()
            .unwrap_or("unavailable"),
        provenance
            .rust_toolchain_sha256
            .as_deref()
            .unwrap_or("unavailable")
    ));
    out.push_str(&phase_timing_summary(phase_timings));
    out.push_str(&pcs_text_analysis(records));
    out.push_str("\nscaling_analysis:\n");
    out.push_str(&format!("  runner: {}\n", command.runner.as_str()));
    out.push_str("  baseline: speedup is measured against the workers=1 run for the same runner, protocol, and size.\n");
    out.push_str(
        "  theory: the perfect-linear worker line is an upper bound, not a prototype prediction; small circuits may stay near 1x because master orchestration, transcript, verification, and consistency checks are still largely serial.\n",
    );
    if let Some(max_size) = command.sizes.iter().copied().max() {
        let stats = benchmark_stats(records);
        for runner in command.runner.variants() {
            out.push_str(&format!("  runner_section={}\n", runner.as_str()));
            for protocol in [Protocol::R1cs, Protocol::Plonkish] {
                if let Some(base) = stats.iter().find(|record| {
                    record.runner == runner.as_str()
                        && record.protocol == protocol.as_str()
                        && record.case_name == "positive"
                        && record.verified_count > 0
                        && record.size == max_size
                        && record.workers == 1
                }) {
                    out.push_str(&format!(
                        "    protocol={} size={} baseline_prove_ms_mean={:.3} baseline_prove_ms_stddev={:.3}\n",
                        protocol.as_str(),
                        max_size,
                        base.prove_ms.mean,
                        base.prove_ms.stddev
                    ));
                    for record in stats.iter().filter(|record| {
                        record.runner == runner.as_str()
                            && record.protocol == protocol.as_str()
                            && record.case_name == "positive"
                            && record.verified_count > 0
                            && record.size == max_size
                    }) {
                        let speedup = base.prove_ms.mean / record.prove_ms.mean.max(0.001);
                        let efficiency = speedup / record.workers as f64;
                        let (_, status_label) = scaling_assessment(speedup, record.workers);
                        let status = status_label.replace(' ', "-");
                        let serial_overhead =
                            amdahl_serial_overhead_fraction(speedup, record.workers);
                        out.push_str(&format!(
                            "      workers={} samples={} prove_ms_mean={:.3} prove_ms_stddev={:.3} speedup_vs_w1={:.3} efficiency={:.3} amdahl_serial_plus_overhead={:.3} status={}\n",
                            record.workers,
                            record.samples,
                            record.prove_ms.mean,
                            record.prove_ms.stddev,
                            speedup,
                            efficiency,
                            serial_overhead,
                            status
                        ));
                    }
                }
            }
        }
    }
    out
}

fn pcs_benchmark_summary(
    command: &PcsBenchmarkCommand,
    records: &[PcsMetricRecord],
    phase_timings: &[PhaseTimingRecord],
) -> String {
    let mut out = String::new();
    out.push_str("# PCS Benchmark Summary\n\n");
    out.push_str("This report measures the distributed Brakedown PCS layer only. It does not include the R1CS or Plonkish PIOP proof paths.\n\n");
    out.push_str("## Configuration\n\n");
    out.push_str(&format!("- runner: {}\n", command.runner.as_str()));
    out.push_str(&format!("- opening: {}\n", command.opening.as_str()));
    out.push_str(&format!("- sizes: {:?}\n", command.sizes));
    out.push_str(&format!("- workers: {:?}\n", command.workers));
    out.push_str(&format!("- pcs_queries: {}\n", command.pcs_queries));
    out.push_str(&format!("- repeats: {}\n", command.repeats));
    if let Some(plan) = &command.worker_core_plan {
        out.push_str(&format!(
            "- network core plan: host_logical_cores={}, max_workers={}, cores_per_worker={}, mode={}\n",
            plan.host_logical_cores,
            plan.max_workers,
            plan.cores_per_worker,
            worker_affinity_mode()
        ));
    }
    out.push_str("\n## Theory Baseline\n\n");
    out.push_str("The paper sets T=N/M and chooses B=M log(N/M). Under the stated BaseFold-like underlying PCS costs, Protocol 11 targets O(N/M) work per prover and O(M log^2(N/M)) verifier/proof size. This benchmark records N, M, measured T, and the B target for each row so measured data can be compared against that model.\n\n");
    out.push_str("## Aggregate Rows\n\n");
    out.push_str("| runner | opening | n | N | workers | samples | commit ms | open ms | verify ms | opening bytes | network bytes | verified |\n");
    out.push_str(
        "| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |\n",
    );
    for stat in pcs_benchmark_stats(records) {
        out.push_str(&format!(
            "| {} | {} | {} | {} | {} | {} | {:.3} | {:.3} | {:.3} | {:.0} | {:.0} | {} |\n",
            stat.runner,
            stat.opening,
            nv_power(stat.size),
            stat.size,
            stat.workers,
            stat.samples,
            stat.commit_ms.mean,
            stat.open_ms.mean,
            stat.verify_ms.mean,
            stat.opening_proof_bytes.mean,
            stat.network_bytes.mean,
            stat.verified_count
        ));
    }
    out.push_str("\n## Phase Timing\n\n");
    for timing in phase_timings {
        out.push_str(&format!(
            "- {} / {}: elapsed_ms={:.3}, recorded_prove_ms={:.3}, recorded_verify_ms={:.3}, inferred_overhead_ms={:.3}\n",
            timing.phase,
            timing.detail,
            timing.elapsed_ms,
            timing.recorded_prove_ms,
            timing.recorded_verify_ms,
            timing.inferred_overhead_ms
        ));
    }
    out
}

fn pcs_benchmark_overview_html(
    run_id: u64,
    command: &PcsBenchmarkCommand,
    records: &[PcsMetricRecord],
) -> String {
    let stats = pcs_benchmark_stats(records);
    let mut html = String::new();
    html.push_str(
        "<!doctype html><html><head><meta charset=\"utf-8\"><title>PCS Benchmark</title><style>",
    );
    html.push_str("body{font-family:Arial,sans-serif;margin:24px;color:#1f2937}table{border-collapse:collapse;width:100%;font-size:13px}th,td{border:1px solid #d1d5db;padding:6px;text-align:right}th:first-child,td:first-child,th:nth-child(2),td:nth-child(2){text-align:left}h1,h2{color:#111827}code{background:#f3f4f6;padding:2px 4px}a{color:#075985}.chart-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(420px,1fr));gap:18px;margin:12px 0 24px}.chart-grid figure{margin:0}.chart-grid img{width:100%;height:auto;border:1px solid #d1d5db}.chart-grid figcaption{font-size:12px;color:#4b5563;margin-top:4px}");
    html.push_str("</style></head><body>");
    html.push_str(&format!("<h1>Distributed Brakedown PCS Benchmark</h1><p>run_id={run_id}. This is a PCS-only Commit/Open report.</p>"));
    html.push_str("<h2>Configuration</h2><ul>");
    html.push_str(&format!(
        "<li>runner=<code>{}</code>, opening=<code>{}</code>, pcs_queries=<code>{}</code>, repeats=<code>{}</code></li>",
        html_escape(command.runner.as_str()),
        html_escape(command.opening.as_str()),
        command.pcs_queries,
        command.repeats
    ));
    html.push_str(&format!(
        "<li>sizes=<code>{:?}</code>, workers=<code>{:?}</code></li>",
        command.sizes, command.workers
    ));
    html.push_str("</ul>");
    html.push_str("<h2>Brief Charts</h2>");
    for runner in ["local", "network"] {
        if !records.iter().any(|record| record.runner == runner) {
            continue;
        }
        html.push_str(&format!(
            "<h3>{} runner</h3><section class=\"chart-grid\">",
            html_escape(runner)
        ));
        let mut charts = vec![
            (
                format!("{runner}_commit_time_by_size.svg"),
                format!("{runner} commit time by PCS size"),
            ),
            (
                format!("{runner}_open_time_by_size.svg"),
                format!("{runner} open time by PCS size"),
            ),
            (
                format!("{runner}_verify_time_by_size.svg"),
                format!("{runner} verify time by PCS size"),
            ),
            (
                format!("{runner}_opening_bytes_by_size.svg"),
                format!("{runner} opening proof bytes by PCS size"),
            ),
        ];
        if runner == "network" {
            charts.push((
                "network_network_bytes_by_size.svg".to_owned(),
                "network bytes by PCS size".to_owned(),
            ));
        }
        charts.push((
            format!("{runner}_worker_scaling_max_size.svg"),
            format!("{runner} worker scaling at max PCS size"),
        ));
        for (artifact, caption) in charts {
            html.push_str(&format!(
                "<figure><a href=\"{artifact}\"><img src=\"{artifact}\" alt=\"{}\"></a><figcaption>{}</figcaption></figure>",
                html_escape(&caption),
                html_escape(&caption)
            ));
        }
        html.push_str("</section>");
    }
    html.push_str("<h2>Artifacts</h2><p><a href=\"source.csv\">source.csv</a> | <a href=\"summary_stats.csv\">summary_stats.csv</a> | <a href=\"summary.txt\">summary.txt</a> | <a href=\"commit_time_by_size.svg\">combined commit chart</a> | <a href=\"open_time_by_size.svg\">combined open chart</a> | <a href=\"verify_time_by_size.svg\">combined verify chart</a> | <a href=\"opening_bytes_by_size.svg\">combined opening bytes chart</a> | <a href=\"network_bytes_by_size.svg\">combined network bytes chart</a> | <a href=\"worker_scaling_max_size.svg\">combined scaling chart</a></p>");
    html.push_str("<h2>Aggregate Metrics</h2><table><thead><tr><th>runner</th><th>opening</th><th>n</th><th>N</th><th>workers</th><th>samples</th><th>verified</th><th>commit ms</th><th>open ms</th><th>verify ms</th><th>opening bytes</th><th>network bytes</th></tr></thead><tbody>");
    for stat in stats {
        html.push_str(&format!(
            "<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{:.3}</td><td>{:.3}</td><td>{:.3}</td><td>{:.0}</td><td>{:.0}</td></tr>",
            html_escape(stat.runner),
            html_escape(stat.opening),
            nv_power(stat.size),
            stat.size,
            stat.workers,
            stat.samples,
            stat.verified_count,
            stat.commit_ms.mean,
            stat.open_ms.mean,
            stat.verify_ms.mean,
            stat.opening_proof_bytes.mean,
            stat.network_bytes.mean
        ));
    }
    html.push_str("</tbody></table>");
    html.push_str("<h2>Theory Note</h2><p>The paper's PCS target is per-prover <code>O(N/M)</code> work with proof and verifier around <code>O(M log^2(N/M))</code> after choosing <code>B=M log(N/M)</code>. See <code>Doc/pcs_theory_audit.md</code> for implementation alignment details.</p>");
    html.push_str("</body></html>\n");
    html
}

fn pcs_benchmark_metadata_json(
    run_id: u64,
    command: &PcsBenchmarkCommand,
    records: &[PcsMetricRecord],
) -> String {
    let verified = records.iter().filter(|record| record.verified).count();
    let mut out = String::from("{\n");
    out.push_str("  \"schema_version\": 1,\n");
    out.push_str("  \"run_kind\": \"pcs-benchmark\",\n");
    out.push_str("  \"generated_by\": \"pq-experiments pcs-benchmark\",\n");
    out.push_str(&format!("  \"run_id\": {run_id},\n"));
    out.push_str(&format!(
        "  \"sizes\": {},\n",
        serde_json::to_string(&command.sizes).unwrap_or_else(|_| "[]".to_owned())
    ));
    out.push_str(&format!(
        "  \"workers\": {},\n",
        serde_json::to_string(&command.workers).unwrap_or_else(|_| "[]".to_owned())
    ));
    out.push_str(&format!("  \"pcs_queries\": {},\n", command.pcs_queries));
    out.push_str(&format!("  \"repeats\": {},\n", command.repeats));
    out.push_str(&format!(
        "  \"warmup_enabled\": {},\n",
        command.warmup_enabled
    ));
    out.push_str(&format!(
        "  \"runner\": \"{}\",\n",
        json_escape(command.runner.as_str())
    ));
    out.push_str(&format!(
        "  \"opening\": \"{}\",\n",
        json_escape(command.opening.as_str())
    ));
    out.push_str("  \"theory_scope\": \"Doc/pq_dSNARK.pdf pages 22-31, Protocol 8-11\",\n");
    out.push_str(&format!("  \"record_count\": {},\n", records.len()));
    out.push_str(&format!("  \"verified_count\": {},\n", verified));
    out.push_str(&format!(
        "  \"rejected_count\": {},\n",
        records.len().saturating_sub(verified)
    ));
    match &command.worker_core_plan {
        Some(plan) => out.push_str(&format!(
            "  \"core_allocation\": {{\"host_logical_cores\":{},\"max_workers\":{},\"cores_per_worker\":{},\"mode\":\"{}\"}}\n",
            plan.host_logical_cores,
            plan.max_workers,
            plan.cores_per_worker,
            worker_affinity_mode()
        )),
        None => out.push_str("  \"core_allocation\": null\n"),
    }
    out.push_str("}\n");
    out
}

fn build_profile() -> &'static str {
    if cfg!(debug_assertions) {
        "debug"
    } else {
        "release"
    }
}

#[derive(Clone, Debug)]
struct BenchmarkProvenance {
    current_dir: Option<String>,
    rustflags: Option<String>,
    cargo_target_dir: Option<String>,
    git_commit: Option<String>,
    git_branch: Option<String>,
    git_dirty: Option<bool>,
    git_status_sha256: Option<String>,
    rustc_version: Option<String>,
    cargo_version: Option<String>,
    cargo_lock_sha256: Option<String>,
    rust_toolchain_sha256: Option<String>,
    spartan2_commit: Option<String>,
    hyperplonk_commit: Option<String>,
}

impl BenchmarkProvenance {
    fn capture() -> Self {
        let (git_dirty, git_status_sha256) = git_status_fingerprint();
        Self {
            current_dir: env::current_dir()
                .ok()
                .map(|path| path.display().to_string()),
            rustflags: env::var("RUSTFLAGS").ok().filter(|value| !value.is_empty()),
            cargo_target_dir: env::var("CARGO_TARGET_DIR")
                .ok()
                .filter(|value| !value.is_empty()),
            git_commit: command_output("git", &["rev-parse", "HEAD"]),
            git_branch: command_output("git", &["rev-parse", "--abbrev-ref", "HEAD"]),
            git_dirty,
            git_status_sha256,
            rustc_version: command_output("rustc", &["--version", "--verbose"])
                .or_else(|| command_output("rustc", &["--version"])),
            cargo_version: command_output("cargo", &["--version", "--verbose"])
                .or_else(|| command_output("cargo", &["--version"])),
            cargo_lock_sha256: file_sha256_hex(Path::new("Cargo.lock")),
            rust_toolchain_sha256: file_sha256_hex(Path::new("rust-toolchain.toml")),
            spartan2_commit: third_party_pinned_commit("Spartan2")
                .or_else(|| git_repo_commit(Path::new("third_party/Spartan2"))),
            hyperplonk_commit: third_party_pinned_commit("HyperPlonk")
                .or_else(|| git_repo_commit(Path::new("third_party/hyperplonk"))),
        }
    }

    fn rustc_version_line(&self) -> Option<&str> {
        self.rustc_version
            .as_deref()
            .and_then(|version| version.lines().next())
    }

    fn cargo_version_line(&self) -> Option<&str> {
        self.cargo_version
            .as_deref()
            .and_then(|version| version.lines().next())
    }

    fn to_json(&self) -> String {
        format!(
            concat!(
                "{{\n",
                "    \"current_dir\": {},\n",
                "    \"rustflags\": {},\n",
                "    \"cargo_target_dir\": {},\n",
                "    \"git_commit\": {},\n",
                "    \"git_branch\": {},\n",
                "    \"git_dirty\": {},\n",
                "    \"git_status_sha256\": {},\n",
                "    \"rustc_version\": {},\n",
                "    \"cargo_version\": {},\n",
                "    \"cargo_lock_sha256\": {},\n",
                "    \"rust_toolchain_sha256\": {},\n",
                "    \"third_party_spartan2_commit\": {},\n",
                "    \"third_party_hyperplonk_commit\": {}\n",
                "  }}"
            ),
            json_optional_string(self.current_dir.as_deref()),
            json_optional_string(self.rustflags.as_deref()),
            json_optional_string(self.cargo_target_dir.as_deref()),
            json_optional_string(self.git_commit.as_deref()),
            json_optional_string(self.git_branch.as_deref()),
            json_optional_bool(self.git_dirty),
            json_optional_string(self.git_status_sha256.as_deref()),
            json_optional_string(self.rustc_version.as_deref()),
            json_optional_string(self.cargo_version.as_deref()),
            json_optional_string(self.cargo_lock_sha256.as_deref()),
            json_optional_string(self.rust_toolchain_sha256.as_deref()),
            json_optional_string(self.spartan2_commit.as_deref()),
            json_optional_string(self.hyperplonk_commit.as_deref())
        )
    }
}

fn git_status_fingerprint() -> (Option<bool>, Option<String>) {
    let commands = [
        (
            "unstaged",
            vec![
                "diff",
                "--name-status",
                "--",
                ":!target",
                ":!results/bench-*",
            ],
        ),
        (
            "staged",
            vec![
                "diff",
                "--cached",
                "--name-status",
                "--",
                ":!target",
                ":!results/bench-*",
            ],
        ),
        (
            "untracked",
            vec![
                "ls-files",
                "-o",
                "--exclude-standard",
                "--",
                ":!target",
                ":!results/bench-*",
            ],
        ),
    ];
    let mut combined = String::new();
    let mut dirty = false;
    for (label, args) in commands {
        let Some(output) = command_output_allow_empty("git", &args) else {
            return (None, None);
        };
        if !output.trim().is_empty() {
            dirty = true;
        }
        combined.push_str(label);
        combined.push('\n');
        combined.push_str(&output);
        if !output.ends_with('\n') {
            combined.push('\n');
        }
    }
    (Some(dirty), Some(hex_digest(sha256(combined.as_bytes()))))
}

fn command_output(program: &str, args: &[&str]) -> Option<String> {
    let output = process::Command::new(program).args(args).output().ok()?;
    successful_stdout(output)
}

fn command_output_allow_empty(program: &str, args: &[&str]) -> Option<String> {
    let output = process::Command::new(program).args(args).output().ok()?;
    if !output.status.success() {
        return None;
    }
    String::from_utf8(output.stdout).ok()
}

fn git_repo_commit(path: &Path) -> Option<String> {
    let repo = fs::canonicalize(path).ok()?;
    if !repo.join(".git").exists() {
        return None;
    }
    let safe_directory = format!("safe.directory={}", repo.display());
    let output = process::Command::new("git")
        .arg("-c")
        .arg(safe_directory)
        .arg("-C")
        .arg(repo)
        .args(["rev-parse", "HEAD"])
        .output()
        .ok()?;
    successful_stdout(output)
}

fn third_party_pinned_commit(name: &str) -> Option<String> {
    let pins = fs::read_to_string("third_party/PINS.md").ok()?;
    parse_pinned_commit(&pins, name)
}

fn parse_pinned_commit(pins: &str, name: &str) -> Option<String> {
    let heading = format!("## {name}");
    let mut in_section = false;
    for line in pins.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("## ") {
            in_section = trimmed == heading;
            continue;
        }
        if in_section && trimmed.starts_with("- Pinned commit:") {
            let commit = trimmed
                .split_once('`')
                .and_then(|(_, rest)| rest.split_once('`'))
                .map(|(commit, _)| commit.trim())?;
            if commit.len() == 40 && commit.bytes().all(|byte| byte.is_ascii_hexdigit()) {
                return Some(commit.to_owned());
            }
            return None;
        }
    }
    None
}

fn successful_stdout(output: process::Output) -> Option<String> {
    if !output.status.success() {
        return None;
    }
    let stdout = String::from_utf8(output.stdout).ok()?;
    let trimmed = stdout.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_owned())
    }
}

fn file_sha256_hex(path: &Path) -> Option<String> {
    fs::read(path).ok().map(|bytes| hex_digest(sha256(&bytes)))
}

fn write_benchmark_charts(run_dir: &Path, records: &[MetricRecord]) -> Result<(), CliError> {
    let chart_records = mean_positive_records(records);
    write_text_file(
        &run_dir.join("prove_time_by_size.svg"),
        &line_chart_svg(
            &chart_records,
            "Prove time by circuit size",
            "Prover time (ms)",
            |record| record.prove_ms,
        ),
    )?;
    write_text_file(
        &run_dir.join("prove_time_by_size.tex"),
        &line_chart_pgfplots(
            records,
            "Prove time by circuit size",
            "Prover time (ms)",
            BenchmarkMetric::ProveMs,
        ),
    )?;
    write_text_file(
        &run_dir.join("verify_time_by_size.svg"),
        &line_chart_svg(
            &chart_records,
            "Verify time by circuit size",
            "Verifier time (ms)",
            |record| record.verify_ms,
        ),
    )?;
    write_text_file(
        &run_dir.join("verify_time_by_size.tex"),
        &line_chart_pgfplots(
            records,
            "Verify time by circuit size",
            "Verifier time (ms)",
            BenchmarkMetric::VerifyMs,
        ),
    )?;
    write_text_file(
        &run_dir.join("proof_bytes_by_size.svg"),
        &line_chart_svg(
            &chart_records,
            "Proof bytes by circuit size",
            "Proof size (bytes)",
            |record| record.proof_bytes as f64,
        ),
    )?;
    write_text_file(
        &run_dir.join("proof_bytes_by_size.tex"),
        &line_chart_pgfplots(
            records,
            "Proof bytes by circuit size",
            "Proof size (KiB)",
            BenchmarkMetric::ProofKiB,
        ),
    )?;
    write_text_file(
        &run_dir.join("network_bytes_by_size.svg"),
        &line_chart_svg(
            &chart_records,
            "Network bytes by circuit size",
            "Network bytes",
            |record| record.network_bytes as f64,
        ),
    )?;
    write_text_file(
        &run_dir.join("network_bytes_by_size.tex"),
        &line_chart_pgfplots(
            records,
            "Network bytes by circuit size",
            "Network bytes (KiB)",
            BenchmarkMetric::NetworkKiB,
        ),
    )?;
    write_text_file(
        &run_dir.join("runner_overhead_by_size.svg"),
        &runner_overhead_svg(records),
    )?;
    write_text_file(
        &run_dir.join("runner_overhead_by_size.tex"),
        &runner_overhead_pgfplots(records),
    )?;
    write_text_file(
        &run_dir.join("worker_scaling_max_size.svg"),
        &worker_scaling_svg(&chart_records),
    )?;
    write_text_file(
        &run_dir.join("worker_scaling_max_size.tex"),
        &worker_scaling_pgfplots(&chart_records),
    )?;
    write_text_file(
        &run_dir.join("paper_figures.tex"),
        &paper_figures_pgfplots(records),
    )?;
    write_text_file(
        &run_dir.join("paper_figures_standalone.tex"),
        &paper_figures_standalone_tex(),
    )
}

fn compile_paper_figures(run_dir: &Path, compiler: FigureCompiler) -> Result<(), CliError> {
    let source = "paper_figures_standalone.tex";
    let compiler = select_figure_compiler(compiler)?;
    let args = match compiler {
        "pdflatex" => vec!["-interaction=nonstopmode", "-halt-on-error", source],
        "tectonic" => vec![source],
        _ => unreachable!("selected compiler is constrained"),
    };
    let mut command = process::Command::new(compiler);
    command.args(&args).current_dir(run_dir);
    if compiler == "tectonic" && env::var_os("TECTONIC_CACHE_DIR").is_none() {
        let cache_dir = env::current_dir()
            .map_err(|error| CliError(format!("read current directory failed: {error}")))?
            .join("target")
            .join("tectonic-cache");
        fs::create_dir_all(&cache_dir)
            .map_err(|error| CliError(format!("create tectonic cache dir failed: {error}")))?;
        command.env("TECTONIC_CACHE_DIR", cache_dir);
    }
    let output = command
        .output()
        .map_err(|error| CliError(format!("failed to launch {compiler}: {error}")))?;
    if !output.status.success() {
        return Err(CliError(format!(
            "{compiler} failed while compiling paper_figures_standalone.tex\nstdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        )));
    }
    let pdf = run_dir.join(COMPILED_PAPER_FIGURE);
    if !pdf.is_file() {
        return Err(CliError(format!(
            "{compiler} succeeded but {} was not created",
            pdf.display()
        )));
    }
    Ok(())
}

fn write_pcs_benchmark_charts(run_dir: &Path, records: &[PcsMetricRecord]) -> Result<(), CliError> {
    write_pcs_runner_split_charts(run_dir, records)?;
    write_text_file(
        &run_dir.join("commit_time_by_size.svg"),
        &pcs_line_chart_svg(
            records,
            "PCS commit time by size",
            "Commit time (ms)",
            |r| r.commit_ms,
        ),
    )?;
    write_text_file(
        &run_dir.join("commit_time_by_size.tex"),
        &pcs_line_chart_pgfplots(
            records,
            "PCS commit time by size",
            "Commit time (ms)",
            |r| r.commit_ms,
        ),
    )?;
    write_text_file(
        &run_dir.join("open_time_by_size.svg"),
        &pcs_line_chart_svg(records, "PCS open time by size", "Open time (ms)", |r| {
            r.open_ms
        }),
    )?;
    write_text_file(
        &run_dir.join("open_time_by_size.tex"),
        &pcs_line_chart_pgfplots(records, "PCS open time by size", "Open time (ms)", |r| {
            r.open_ms
        }),
    )?;
    write_text_file(
        &run_dir.join("verify_time_by_size.svg"),
        &pcs_line_chart_svg(
            records,
            "PCS verify time by size",
            "Verify time (ms)",
            |r| r.verify_ms,
        ),
    )?;
    write_text_file(
        &run_dir.join("verify_time_by_size.tex"),
        &pcs_line_chart_pgfplots(
            records,
            "PCS verify time by size",
            "Verify time (ms)",
            |r| r.verify_ms,
        ),
    )?;
    write_text_file(
        &run_dir.join("opening_bytes_by_size.svg"),
        &pcs_line_chart_svg(
            records,
            "PCS opening bytes by size",
            "Opening bytes (KiB)",
            |r| r.opening_proof_bytes as f64 / 1024.0,
        ),
    )?;
    write_text_file(
        &run_dir.join("opening_bytes_by_size.tex"),
        &pcs_line_chart_pgfplots(
            records,
            "PCS opening bytes by size",
            "Opening bytes (KiB)",
            |r| r.opening_proof_bytes as f64 / 1024.0,
        ),
    )?;
    write_text_file(
        &run_dir.join("network_bytes_by_size.svg"),
        &pcs_line_chart_svg(
            records,
            "PCS network bytes by size",
            "Network bytes (KiB)",
            |r| r.network_bytes as f64 / 1024.0,
        ),
    )?;
    write_text_file(
        &run_dir.join("network_bytes_by_size.tex"),
        &pcs_line_chart_pgfplots(
            records,
            "PCS network bytes by size",
            "Network bytes (KiB)",
            |r| r.network_bytes as f64 / 1024.0,
        ),
    )?;
    write_text_file(
        &run_dir.join("worker_scaling_max_size.svg"),
        &pcs_worker_scaling_svg(records),
    )?;
    write_text_file(
        &run_dir.join("worker_scaling_max_size.tex"),
        &pcs_worker_scaling_pgfplots(records),
    )?;
    Ok(())
}

fn write_pcs_runner_split_charts(
    run_dir: &Path,
    records: &[PcsMetricRecord],
) -> Result<(), CliError> {
    for runner in ["local", "network"] {
        let runner_records = records
            .iter()
            .filter(|record| record.runner == runner)
            .cloned()
            .collect::<Vec<_>>();
        write_pcs_metric_chart_pair(
            run_dir,
            &runner_records,
            &format!("{runner}_commit_time_by_size"),
            &format!("PCS {runner} commit time by size"),
            "Commit time (ms)",
            |record| record.commit_ms,
        )?;
        write_pcs_metric_chart_pair(
            run_dir,
            &runner_records,
            &format!("{runner}_open_time_by_size"),
            &format!("PCS {runner} open time by size"),
            "Open time (ms)",
            |record| record.open_ms,
        )?;
        write_pcs_metric_chart_pair(
            run_dir,
            &runner_records,
            &format!("{runner}_verify_time_by_size"),
            &format!("PCS {runner} verify time by size"),
            "Verify time (ms)",
            |record| record.verify_ms,
        )?;
        write_pcs_metric_chart_pair(
            run_dir,
            &runner_records,
            &format!("{runner}_opening_bytes_by_size"),
            &format!("PCS {runner} opening bytes by size"),
            "Opening bytes (KiB)",
            |record| record.opening_proof_bytes as f64 / 1024.0,
        )?;
        write_pcs_metric_chart_pair(
            run_dir,
            &runner_records,
            &format!("{runner}_network_bytes_by_size"),
            &format!("PCS {runner} network bytes by size"),
            "Network bytes (KiB)",
            |record| record.network_bytes as f64 / 1024.0,
        )?;
        write_text_file(
            &run_dir.join(format!("{runner}_worker_scaling_max_size.svg")),
            &pcs_worker_scaling_svg_with_title(
                &runner_records,
                &format!("PCS {runner} worker scaling at max size"),
            ),
        )?;
        write_text_file(
            &run_dir.join(format!("{runner}_worker_scaling_max_size.tex")),
            &pcs_worker_scaling_pgfplots_with_title(
                &runner_records,
                &format!("PCS {runner} worker scaling at max size"),
            ),
        )?;
    }
    Ok(())
}

fn write_pcs_metric_chart_pair<F>(
    run_dir: &Path,
    records: &[PcsMetricRecord],
    stem: &str,
    title: &str,
    y_label: &str,
    value: F,
) -> Result<(), CliError>
where
    F: Fn(&PcsMetricRecord) -> f64 + Copy,
{
    write_text_file(
        &run_dir.join(format!("{stem}.svg")),
        &pcs_line_chart_svg(records, title, y_label, value),
    )?;
    write_text_file(
        &run_dir.join(format!("{stem}.tex")),
        &pcs_line_chart_pgfplots(records, title, y_label, value),
    )?;
    Ok(())
}

fn select_figure_compiler(compiler: FigureCompiler) -> Result<&'static str, CliError> {
    match compiler {
        FigureCompiler::Auto => {
            if command_available("tectonic") {
                Ok("tectonic")
            } else if command_available("pdflatex") {
                Ok("pdflatex")
            } else {
                Err(CliError(
                    "no LaTeX compiler found for --compile-figures; install pdflatex or tectonic"
                        .to_owned(),
                ))
            }
        }
        FigureCompiler::PdfLatex => {
            if command_available("pdflatex") {
                Ok("pdflatex")
            } else {
                Err(CliError(
                    "pdflatex was requested by --figure-compiler but was not found on PATH"
                        .to_owned(),
                ))
            }
        }
        FigureCompiler::Tectonic => {
            if command_available("tectonic") {
                Ok("tectonic")
            } else {
                Err(CliError(
                    "tectonic was requested by --figure-compiler but was not found on PATH"
                        .to_owned(),
                ))
            }
        }
    }
}

fn command_available(name: &str) -> bool {
    process::Command::new(name)
        .arg("--version")
        .output()
        .map(|output| output.status.success())
        .unwrap_or(false)
}

fn line_chart_svg<F>(records: &[MetricRecord], title: &str, y_label: &str, value: F) -> String
where
    F: Fn(&MetricRecord) -> f64,
{
    let positives = records
        .iter()
        .filter(|record| record.case_name == "positive" && record.verified)
        .collect::<Vec<_>>();
    let mut sizes = positives
        .iter()
        .map(|record| record.size)
        .collect::<Vec<_>>();
    sizes.sort_unstable();
    sizes.dedup();
    let powers = sizes.iter().map(|size| nv_power(*size)).collect::<Vec<_>>();
    let min_power = powers.iter().copied().min().unwrap_or(0);
    let max_power = powers.iter().copied().max().unwrap_or(min_power);
    let mut series = positives
        .iter()
        .map(|record| (record.runner, record.protocol, record.workers))
        .collect::<Vec<_>>();
    series.sort_by(|left, right| {
        series_sort_key(left.0, left.1, left.2).cmp(&series_sort_key(right.0, right.1, right.2))
    });
    series.dedup();
    let raw_max_y = positives
        .iter()
        .map(|record| value(record))
        .fold(0.0_f64, f64::max)
        .max(1.0);
    let y_step = nice_axis_step(raw_max_y, 5);
    let max_y = (raw_max_y / y_step).ceil() * y_step;

    let mut svg = paper_svg_start(
        title,
        "Verified positive runs. Circuit size is nv = 2^n; lines connect measured runs only.",
    );
    draw_plot_frame(&mut svg, y_label, "Circuit exponent n (nv = 2^n)");
    draw_y_grid(&mut svg, max_y, y_step);
    draw_x_power_ticks(&mut svg, &powers, &sizes, min_power, max_power);
    draw_legend_box(&mut svg, series.len());
    for (series_index, (runner, protocol, workers)) in series.iter().enumerate() {
        let style = series_style(protocol, runner, *workers, series_index);
        let mut line_points = Vec::new();
        for size in &sizes {
            if let Some(record) = positives.iter().find(|record| {
                record.runner == *runner
                    && record.protocol == *protocol
                    && record.workers == *workers
                    && record.size == *size
            }) {
                let x = plot_x_power(nv_power(*size), min_power, max_power);
                let y = plot_y(value(record), max_y);
                line_points.push((x, y));
            }
        }
        if !line_points.is_empty() {
            let points = line_points
                .iter()
                .map(|(x, y)| format!("{x:.1},{y:.1}"))
                .collect::<Vec<_>>();
            if points.len() > 1 {
                svg.push_str(&format!(
                    "<polyline class=\"series-line\" fill=\"none\" stroke=\"{}\"{} points=\"{}\" />\n",
                    style.color,
                    stroke_dash_attr(style.dash),
                    points.join(" ")
                ));
            }
            for (x, y) in &line_points {
                svg.push_str(&marker_svg(*x, *y, style.color, *workers));
            }
            svg.push_str(&format!(
                "<g class=\"legend-entry\" transform=\"translate(765,{})\"><line x1=\"0\" y1=\"0\" x2=\"24\" y2=\"0\" stroke=\"{}\" stroke-width=\"2.4\"{} />{}<text x=\"34\" y=\"4\">{} w={}</text></g>\n",
                88 + series_index * 24,
                style.color,
                stroke_dash_attr(style.dash),
                marker_svg(12.0, 0.0, style.color, *workers),
                xml_escape(&display_series_name(protocol, runner)),
                workers
            ));
        }
    }
    svg.push_str("</svg>\n");
    svg
}

fn pcs_line_chart_svg<F>(
    records: &[PcsMetricRecord],
    title: &str,
    y_label: &str,
    value: F,
) -> String
where
    F: Fn(&PcsMetricRecord) -> f64,
{
    let stats = pcs_chart_points(records, value);
    simple_svg_chart(title, y_label, &stats)
}

fn simple_svg_chart(title: &str, y_label: &str, points: &[PcsChartPoint]) -> String {
    simple_svg_chart_with_x(
        title,
        "PCS polynomial exponent n in N=2^n",
        "n=",
        y_label,
        points,
    )
}

fn simple_svg_chart_with_x(
    title: &str,
    x_label: &str,
    x_tick_prefix: &str,
    y_label: &str,
    points: &[PcsChartPoint],
) -> String {
    let width = 980.0;
    let left = 86.0;
    let right = 940.0;
    let top = 70.0;
    let bottom = 350.0;
    let plot_width = right - left;
    let plot_height = bottom - top;
    let legend_columns = 4_usize;
    let mut series = points
        .iter()
        .filter(|point| point.value > 0.0 && point.value.is_finite())
        .map(|point| (point.runner, point.opening, point.series_workers))
        .collect::<Vec<_>>();
    series.sort_unstable();
    series.dedup();
    let legend_rows = series.len().div_ceil(legend_columns).max(1);
    let legend_top = 430.0;
    let height = legend_top + (legend_rows as f64) * 24.0 + 24.0;
    let mut powers = points
        .iter()
        .map(|point| point.nv_power)
        .collect::<Vec<_>>();
    powers.sort_unstable();
    powers.dedup();
    let positive_values = points
        .iter()
        .map(|point| point.value)
        .filter(|value| *value > 0.0 && value.is_finite())
        .collect::<Vec<_>>();
    let min_y = positive_values
        .iter()
        .copied()
        .fold(f64::INFINITY, f64::min);
    let max_y = positive_values.iter().copied().fold(0.0_f64, f64::max);
    let (log_min, log_max) = if positive_values.is_empty() {
        (0_i32, 1_i32)
    } else {
        let min_exp = min_y.log10().floor() as i32;
        let mut max_exp = max_y.log10().ceil() as i32;
        if max_exp <= min_exp {
            max_exp = min_exp + 1;
        }
        (min_exp, max_exp)
    };
    let x_pos = |power: usize| -> f64 {
        if powers.len() <= 1 {
            left + plot_width / 2.0
        } else {
            let idx = powers
                .iter()
                .position(|candidate| *candidate == power)
                .unwrap_or(0);
            left + (idx as f64) * plot_width / ((powers.len() - 1) as f64)
        }
    };
    let y_pos = |value: f64| {
        let ratio = (value.log10() - f64::from(log_min)) / f64::from(log_max - log_min);
        bottom - ratio.clamp(0.0, 1.0) * plot_height
    };
    let mut svg = format!(
        "<svg xmlns=\"http://www.w3.org/2000/svg\" width=\"{width}\" height=\"{height}\" viewBox=\"0 0 {width} {height}\">\n<title>{}</title>\n<!-- PCS chart uses stroke-dasharray for series distinction. -->\n<rect width=\"100%\" height=\"100%\" fill=\"#ffffff\"/>\n<text x=\"490\" y=\"32\" text-anchor=\"middle\" font-family=\"Arial\" font-size=\"20\">{}</text>\n<text x=\"18\" y=\"210\" transform=\"rotate(-90 18 210)\" text-anchor=\"middle\" font-family=\"Arial\" font-size=\"13\">{}</text>\n<text x=\"520\" y=\"402\" text-anchor=\"middle\" font-family=\"Arial\" font-size=\"13\">{}</text>\n<line x1=\"{left}\" y1=\"{bottom}\" x2=\"{right}\" y2=\"{bottom}\" stroke=\"#444\"/>\n<line x1=\"{left}\" y1=\"{top}\" x2=\"{left}\" y2=\"{bottom}\" stroke=\"#444\"/>\n",
        svg_escape(title),
        svg_escape(title),
        svg_escape(y_label),
        svg_escape(x_label)
    );
    for exponent in log_min..=log_max {
        let tick_value = 10_f64.powi(exponent);
        let y = y_pos(tick_value);
        svg.push_str(&format!(
            "<line x1=\"{left}\" y1=\"{y:.1}\" x2=\"{right}\" y2=\"{y:.1}\" stroke=\"#e5e7eb\"/>\n<text x=\"76\" y=\"{:.1}\" text-anchor=\"end\" dominant-baseline=\"middle\" font-family=\"Arial\" font-size=\"12\">10^{}</text>\n",
            y + 1.0,
            exponent
        ));
    }
    for power in &powers {
        let x = x_pos(*power);
        svg.push_str(&format!(
            "<text x=\"{x:.1}\" y=\"374\" text-anchor=\"middle\" font-family=\"Arial\" font-size=\"12\">{}{power}</text>\n",
            svg_escape(x_tick_prefix)
        ));
    }
    for (series_index, (runner, opening, series_workers)) in series.iter().enumerate() {
        let color = svg_color(series_index);
        let dash = svg_dash(*series_workers, opening);
        let mut coords = points
            .iter()
            .filter(|point| {
                point.runner == *runner
                    && point.opening == *opening
                    && point.series_workers == *series_workers
                    && point.value > 0.0
                    && point.value.is_finite()
            })
            .collect::<Vec<_>>();
        coords.sort_by_key(|point| point.nv_power);
        if coords.len() >= 2 {
            let polyline = coords
                .iter()
                .map(|point| format!("{:.1},{:.1}", x_pos(point.nv_power), y_pos(point.value)))
                .collect::<Vec<_>>()
                .join(" ");
            svg.push_str(&format!(
                "<polyline fill=\"none\" stroke=\"{color}\" stroke-width=\"2\" stroke-dasharray=\"{dash}\" points=\"{polyline}\"/>\n"
            ));
        }
        for point in coords {
            let worker_label = point
                .series_workers
                .map(|workers| format!(" w{workers}"))
                .unwrap_or_default();
            svg.push_str(&format!(
                "<circle cx=\"{:.1}\" cy=\"{:.1}\" r=\"4\" fill=\"{color}\"><title>{} {}{} {}{}: {:.3}</title></circle>\n",
                x_pos(point.nv_power),
                y_pos(point.value),
                svg_escape(point.runner),
                svg_escape(point.opening),
                worker_label,
                svg_escape(x_tick_prefix),
                point.nv_power,
                point.value
            ));
        }
        let legend_x = 90.0 + ((series_index % legend_columns) as f64) * 220.0;
        let legend_y = legend_top + ((series_index / legend_columns) as f64) * 24.0;
        let legend_worker_label = series_workers
            .map(|workers| format!(" w{workers}"))
            .unwrap_or_default();
        svg.push_str(&format!(
            "<line x1=\"{legend_x:.1}\" y1=\"{legend_y:.1}\" x2=\"{:.1}\" y2=\"{legend_y:.1}\" stroke=\"{color}\" stroke-width=\"2\" stroke-dasharray=\"{dash}\"/>\n<circle cx=\"{:.1}\" cy=\"{legend_y:.1}\" r=\"3\" fill=\"{color}\"/>\n<text x=\"{:.1}\" y=\"{:.1}\" font-family=\"Arial\" font-size=\"12\" dominant-baseline=\"middle\" fill=\"#111827\">{} {}{}</text>\n",
            legend_x + 28.0,
            legend_x + 14.0,
            legend_x + 36.0,
            legend_y,
            svg_escape(runner),
            svg_escape(opening),
            legend_worker_label
        ));
    }
    if series.is_empty() {
        svg.push_str(
            "<text x=\"490\" y=\"215\" text-anchor=\"middle\" font-family=\"Arial\" font-size=\"14\" fill=\"#6b7280\">No positive rows for this runner/metric.</text>\n",
        );
    }
    if points
        .iter()
        .any(|point| point.value <= 0.0 || !point.value.is_finite())
    {
        svg.push_str(&format!(
            "<text x=\"90\" y=\"{:.1}\" font-family=\"Arial\" font-size=\"11\" fill=\"#6b7280\">Non-positive values are omitted from the log-scale plot.</text>\n",
            height - 8.0
        ));
    }
    svg.push_str("</svg>\n");
    svg
}

fn svg_escape(input: &str) -> String {
    input
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

fn svg_color(index: usize) -> &'static str {
    const COLORS: &[&str] = &[
        "#0072B2", "#D55E00", "#009E73", "#CC79A7", "#E69F00", "#56B4E9", "#6B7280",
    ];
    COLORS[index % COLORS.len()]
}

fn svg_dash(workers: Option<usize>, opening: &str) -> &'static str {
    match (workers.unwrap_or(1), opening) {
        (1, "compact") => "none",
        (1, _) => "10 4",
        (2, "compact") => "6 4",
        (2, _) => "6 4 2 4",
        (4, "compact") => "2 4",
        (4, _) => "2 4 8 4",
        (8, "compact") => "12 4",
        (8, _) => "12 4 2 4",
        (_, "compact") => "4 3",
        _ => "8 3 2 3",
    }
}

#[derive(Clone, Debug)]
struct PcsChartPoint {
    runner: &'static str,
    opening: &'static str,
    series_workers: Option<usize>,
    nv_power: usize,
    value: f64,
}

fn pcs_chart_points<F>(records: &[PcsMetricRecord], value: F) -> Vec<PcsChartPoint>
where
    F: Fn(&PcsMetricRecord) -> f64,
{
    let mut points = Vec::new();
    for stats in pcs_benchmark_stats(records) {
        let matching = records
            .iter()
            .filter(|record| {
                record.runner == stats.runner
                    && record.opening == stats.opening
                    && record.workers == stats.workers
                    && record.size == stats.size
            })
            .collect::<Vec<_>>();
        let mean = mean_stddev(matching.into_iter().map(&value)).mean;
        points.push(PcsChartPoint {
            runner: stats.runner,
            opening: stats.opening,
            series_workers: Some(stats.workers),
            nv_power: nv_power(stats.size),
            value: mean,
        });
    }
    points
}

fn pcs_line_chart_pgfplots<F>(
    records: &[PcsMetricRecord],
    title: &str,
    y_label: &str,
    value: F,
) -> String
where
    F: Fn(&PcsMetricRecord) -> f64,
{
    let points = pcs_chart_points(records, value);
    let mut powers = points
        .iter()
        .map(|point| point.nv_power)
        .collect::<Vec<_>>();
    powers.sort_unstable();
    powers.dedup();
    if powers.is_empty() {
        powers.push(0);
    }
    let mut tex = pgfplots_start_log_y(
        title,
        "PCS polynomial exponent $n$ in $N=2^n$",
        y_label,
        &powers,
    );
    let mut series = points
        .iter()
        .map(|point| (point.runner, point.opening, point.series_workers))
        .collect::<Vec<_>>();
    series.sort_unstable();
    series.dedup();
    for (series_index, (runner, opening, series_workers)) in series.iter().enumerate() {
        let coordinates = points
            .iter()
            .filter(|point| {
                point.runner == *runner
                    && point.opening == *opening
                    && point.series_workers == *series_workers
                    && point.value > 0.0
                    && point.value.is_finite()
            })
            .map(|point| {
                format!(
                    "({}, {})",
                    point.nv_power,
                    format_pgfplots_number(point.value)
                )
            })
            .collect::<Vec<_>>()
            .join(" ");
        tex.push_str(&format!(
            "\\addplot+[{}, {}, {}] coordinates {{{}}};\n",
            pgfplots_color_for_index(series_index),
            pgfplots_dash(series_workers.unwrap_or(1)),
            pgfplots_marker(series_workers.unwrap_or(series_index + 1)),
            coordinates
        ));
        let worker_label = series_workers
            .map(|workers| format!(" w{workers}"))
            .unwrap_or_default();
        tex.push_str(&format!(
            "\\addlegendentry{{{} {}{}}}\n",
            runner, opening, worker_label
        ));
    }
    tex.push_str("\\end{axis}\n\\end{tikzpicture}\n");
    tex
}

fn pcs_worker_scaling_svg(records: &[PcsMetricRecord]) -> String {
    pcs_worker_scaling_svg_with_title(records, "PCS worker scaling at max size")
}

fn pcs_worker_scaling_svg_with_title(records: &[PcsMetricRecord], title: &str) -> String {
    let points = pcs_worker_scaling_points(records);
    let mut workers = points.iter().map(|point| point.workers).collect::<Vec<_>>();
    workers.sort_unstable();
    workers.dedup();
    if workers.is_empty() {
        workers.push(1);
    }
    let min_worker = workers.iter().copied().min().unwrap_or(1) as f64;
    let max_worker = workers.iter().copied().max().unwrap_or(1) as f64;
    let observed_max = points
        .iter()
        .map(|point| point.speedup)
        .fold(1.0_f64, f64::max);
    let (max_y, y_step) = scaling_axis_bounds(max_worker.max(observed_max));
    let mut svg = paper_svg_start(
        title,
        "Speedup is measured against the same runner/opening at workers=1. Dashed line is the perfect-scaling upper bound.",
    );
    draw_plot_frame(&mut svg, "Commit+open speedup", "Workers");
    draw_y_grid(&mut svg, max_y, y_step);
    draw_x_numeric_ticks(&mut svg, &workers, min_worker, max_worker);
    let mut series = points
        .iter()
        .map(|point| (point.runner, point.opening))
        .collect::<Vec<_>>();
    series.sort_unstable();
    series.dedup();
    draw_legend_box(&mut svg, series.len() + 1);
    for (series_index, (runner, opening)) in series.iter().enumerate() {
        let color = chart_color(series_index);
        let line_points = points
            .iter()
            .filter(|point| point.runner == *runner && point.opening == *opening)
            .map(|point| {
                (
                    plot_x_numeric(point.workers as f64, min_worker, max_worker),
                    plot_y(point.speedup, max_y),
                )
            })
            .collect::<Vec<_>>();
        if !line_points.is_empty() {
            let polyline = line_points
                .iter()
                .map(|(x, y)| format!("{x:.1},{y:.1}"))
                .collect::<Vec<_>>();
            if polyline.len() > 1 {
                svg.push_str(&format!(
                    "<polyline class=\"series-line\" fill=\"none\" stroke=\"{}\" points=\"{}\" />\n",
                    color,
                    polyline.join(" ")
                ));
            }
            for (x, y) in &line_points {
                svg.push_str(&marker_svg(*x, *y, color, series_index + 1));
            }
            svg.push_str(&format!(
                "<g class=\"legend-entry\" transform=\"translate(765,{})\"><line x1=\"0\" y1=\"0\" x2=\"24\" y2=\"0\" stroke=\"{}\" stroke-width=\"2.4\" />{}<text x=\"34\" y=\"4\">{} {}</text></g>\n",
                88 + series_index * 24,
                color,
                marker_svg(12.0, 0.0, color, series_index + 1),
                xml_escape(runner),
                xml_escape(opening)
            ));
        }
    }
    let ideal_points = workers
        .iter()
        .map(|worker| {
            let x = plot_x_numeric(*worker as f64, min_worker, max_worker);
            let y = plot_y(*worker as f64, max_y);
            format!("{x:.1},{y:.1}")
        })
        .collect::<Vec<_>>();
    if ideal_points.len() > 1 {
        svg.push_str(&format!(
            "<polyline class=\"ideal-line\" fill=\"none\" points=\"{}\" />\n",
            ideal_points.join(" ")
        ));
    }
    svg.push_str(&format!(
        "<g class=\"legend-entry\" transform=\"translate(765,{})\"><line x1=\"0\" y1=\"0\" x2=\"24\" y2=\"0\" class=\"ideal-line\"/><text x=\"34\" y=\"4\">Perfect upper bound</text></g>\n",
        88 + series.len() * 24
    ));
    svg.push_str("</svg>\n");
    svg
}

fn pcs_worker_scaling_pgfplots(records: &[PcsMetricRecord]) -> String {
    pcs_worker_scaling_pgfplots_with_title(records, "PCS worker scaling at max size")
}

fn pcs_worker_scaling_pgfplots_with_title(records: &[PcsMetricRecord], title: &str) -> String {
    let points = pcs_worker_scaling_points(records);
    let mut workers = points.iter().map(|point| point.workers).collect::<Vec<_>>();
    workers.sort_unstable();
    workers.dedup();
    if workers.is_empty() {
        workers.push(1);
    }
    let observed_max = points
        .iter()
        .map(|point| point.speedup)
        .fold(1.0_f64, f64::max);
    let max_worker = workers.iter().copied().max().unwrap_or(1) as f64;
    let (max_y, y_step) = scaling_axis_bounds(max_worker.max(observed_max));
    let mut tex = pgfplots_start_with_extra(
        title,
        "Workers",
        "Commit+open speedup",
        &workers,
        false,
        &linear_y_axis_options(max_y, y_step),
    );
    let mut series = points
        .iter()
        .map(|point| (point.runner, point.opening))
        .collect::<Vec<_>>();
    series.sort_unstable();
    series.dedup();
    for (series_index, (runner, opening)) in series.iter().enumerate() {
        let coordinates = points
            .iter()
            .filter(|point| point.runner == *runner && point.opening == *opening)
            .map(|point| {
                format!(
                    "({}, {})",
                    point.workers,
                    format_pgfplots_number(point.speedup)
                )
            })
            .collect::<Vec<_>>()
            .join(" ");
        tex.push_str(&format!(
            "\\addplot+[{}, solid, {}] coordinates {{{}}};\n",
            pgfplots_color_for_index(series_index),
            pgfplots_marker(series_index + 2),
            coordinates
        ));
        tex.push_str(&format!("\\addlegendentry{{{} {}}}\n", runner, opening));
    }
    let ideal_coordinates = workers
        .iter()
        .map(|worker| format!("({}, {})", worker, worker))
        .collect::<Vec<_>>();
    if !ideal_coordinates.is_empty() {
        tex.push_str(&format!(
            "\\addplot+[pqIdeal, dashed, mark=none] coordinates {{{}}};\n",
            ideal_coordinates.join(" ")
        ));
        tex.push_str("\\addlegendentry{Perfect upper bound}\n");
    }
    tex.push_str("\\end{axis}\n\\end{tikzpicture}\n");
    tex
}

#[derive(Clone, Debug)]
struct PcsScalingPoint {
    runner: &'static str,
    opening: &'static str,
    workers: usize,
    speedup: f64,
}

fn pcs_worker_scaling_points(records: &[PcsMetricRecord]) -> Vec<PcsScalingPoint> {
    let max_size = records.iter().map(|record| record.size).max().unwrap_or(0);
    let stats = pcs_benchmark_stats(records)
        .into_iter()
        .filter(|record| record.size == max_size)
        .collect::<Vec<_>>();
    let mut points = Vec::new();
    for record in &stats {
        let baseline = stats.iter().find(|candidate| {
            candidate.runner == record.runner
                && candidate.opening == record.opening
                && candidate.workers == 1
        });
        if let Some(baseline) = baseline {
            let baseline_time = baseline.commit_ms.mean + baseline.open_ms.mean;
            let current_time = record.commit_ms.mean + record.open_ms.mean;
            if current_time > 0.0 {
                points.push(PcsScalingPoint {
                    runner: record.runner,
                    opening: record.opening,
                    workers: record.workers,
                    speedup: baseline_time / current_time,
                });
            }
        }
    }
    points.sort_by_key(|point| (point.runner, point.opening, point.workers));
    points
}

fn pgfplots_color_for_index(index: usize) -> &'static str {
    match index % 6 {
        0 => "pqR1CS",
        1 => "pqPlonkish",
        2 => "pqGreen",
        3 => "pqPurple",
        4 => "pqGold",
        _ => "pqIdeal",
    }
}

fn worker_scaling_svg(records: &[MetricRecord]) -> String {
    let scaling = worker_scaling_context(records);
    let min_worker = scaling.workers.iter().copied().min().unwrap_or(1) as f64;
    let max_worker = scaling.workers.iter().copied().max().unwrap_or(1) as f64;
    let mut observed_max = 1.0_f64;
    for series in &scaling.series {
        for point in &series.points {
            observed_max = observed_max.max(point.speedup);
        }
        if let Some(serial_overhead) = series.serial_overhead {
            for worker in &scaling.workers {
                observed_max =
                    observed_max.max(amdahl_diagnostic_speedup(*worker, serial_overhead));
            }
        }
    }
    let (max_y, y_step) = scaling_axis_bounds(observed_max.max(max_worker).max(1.0));
    let mut svg = paper_svg_start(
        &format!(
            "Worker scaling at n={} (nv={})",
            nv_power(scaling.max_size),
            scaling.max_size
        ),
        "Solid=measured. Dotted=serial+overhead diagnostic from largest-worker point. Dashed=perfect upper bound.",
    );
    draw_plot_frame(&mut svg, "Speedup vs workers=1", "Workers");
    draw_y_grid(&mut svg, max_y, y_step);
    draw_x_numeric_ticks(&mut svg, &scaling.workers, min_worker, max_worker);
    draw_legend_box(&mut svg, scaling.series.len() + 2);
    for (series_index, series) in scaling.series.iter().enumerate() {
        let style = series_style(series.protocol, series.runner, 1, series_index);
        let line_points = series
            .points
            .iter()
            .map(|point| {
                (
                    plot_x_numeric(point.worker as f64, min_worker, max_worker),
                    plot_y(point.speedup, max_y),
                )
            })
            .collect::<Vec<_>>();
        if let Some(serial_overhead) = series.serial_overhead {
            let diagnostic_points = scaling
                .workers
                .iter()
                .map(|worker| {
                    (
                        plot_x_numeric(*worker as f64, min_worker, max_worker),
                        plot_y(amdahl_diagnostic_speedup(*worker, serial_overhead), max_y),
                    )
                })
                .collect::<Vec<_>>();
            if diagnostic_points.len() > 1 {
                let points = diagnostic_points
                    .iter()
                    .map(|(x, y)| format!("{x:.1},{y:.1}"))
                    .collect::<Vec<_>>();
                svg.push_str(&format!(
                    "<polyline class=\"diagnostic-line\" fill=\"none\" style=\"stroke:{}\" points=\"{}\" />\n",
                    style.color,
                    points.join(" ")
                ));
            }
        }
        if !line_points.is_empty() {
            let points = line_points
                .iter()
                .map(|(x, y)| format!("{x:.1},{y:.1}"))
                .collect::<Vec<_>>();
            if points.len() > 1 {
                svg.push_str(&format!(
                    "<polyline class=\"series-line\" fill=\"none\" stroke=\"{}\" points=\"{}\" />\n",
                    style.color,
                    points.join(" ")
                ));
            }
            for (x, y) in &line_points {
                svg.push_str(&marker_svg(
                    *x,
                    *y,
                    style.color,
                    protocol_marker_key(series.protocol),
                ));
            }
            svg.push_str(&format!(
                "<g class=\"legend-entry\" transform=\"translate(765,{})\"><line x1=\"0\" y1=\"0\" x2=\"24\" y2=\"0\" stroke=\"{}\" stroke-width=\"2.4\" />{}<text x=\"34\" y=\"4\">{}</text></g>\n",
                88 + series_index * 24,
                style.color,
                marker_svg(12.0, 0.0, style.color, protocol_marker_key(series.protocol)),
                xml_escape(&display_series_name(series.protocol, series.runner))
            ));
        }
    }
    let ideal_points = scaling
        .workers
        .iter()
        .map(|worker| {
            let x = plot_x_numeric(*worker as f64, min_worker, max_worker);
            let y = plot_y(*worker as f64, max_y);
            format!("{x:.1},{y:.1}")
        })
        .collect::<Vec<_>>();
    if ideal_points.len() > 1 {
        svg.push_str(&format!(
            "<polyline class=\"ideal-line\" fill=\"none\" points=\"{}\" />\n",
            ideal_points.join(" ")
        ));
    }
    svg.push_str(&format!(
        "<g class=\"legend-entry\" transform=\"translate(765,{})\"><line x1=\"0\" y1=\"0\" x2=\"24\" y2=\"0\" class=\"diagnostic-line\"/><text x=\"34\" y=\"4\">Serial+overhead diagnostic</text></g>\n",
        88 + scaling.series.len() * 24
    ));
    svg.push_str(&format!(
        "<g class=\"legend-entry\" transform=\"translate(765,{})\"><line x1=\"0\" y1=\"0\" x2=\"24\" y2=\"0\" class=\"ideal-line\"/><text x=\"34\" y=\"4\">Perfect upper bound</text></g>\n",
        88 + (scaling.series.len() + 1) * 24
    ));
    svg.push_str("</svg>\n");
    svg
}

#[derive(Clone, Debug)]
struct WorkerScalingContext {
    max_size: usize,
    workers: Vec<usize>,
    series: Vec<WorkerScalingSeries>,
}

#[derive(Clone, Debug)]
struct WorkerScalingSeries {
    runner: &'static str,
    protocol: &'static str,
    points: Vec<WorkerScalingPoint>,
    serial_overhead: Option<f64>,
}

#[derive(Clone, Copy, Debug)]
struct WorkerScalingPoint {
    worker: usize,
    speedup: f64,
}

fn worker_scaling_context(records: &[MetricRecord]) -> WorkerScalingContext {
    let mean_records = mean_positive_records(records);
    let positives = verified_positive_records(&mean_records);
    let max_size = positives
        .iter()
        .map(|record| record.size)
        .max()
        .unwrap_or(1);
    let mut workers = positives
        .iter()
        .filter(|record| record.size == max_size)
        .map(|record| record.workers)
        .collect::<Vec<_>>();
    workers.sort_unstable();
    workers.dedup();

    let mut keys = positives
        .iter()
        .filter(|record| record.size == max_size)
        .map(|record| (record.runner, record.protocol))
        .collect::<Vec<_>>();
    keys.sort_by(|left, right| {
        runner_sort_key(left.0)
            .cmp(&runner_sort_key(right.0))
            .then(protocol_sort_key(left.1).cmp(&protocol_sort_key(right.1)))
    });
    keys.dedup();

    let mut series = Vec::new();
    for (runner, protocol) in keys {
        let Some(base) = positives.iter().find(|record| {
            record.runner == runner
                && record.protocol == protocol
                && record.size == max_size
                && record.workers == 1
        }) else {
            continue;
        };
        let points = workers
            .iter()
            .filter_map(|worker| {
                positives
                    .iter()
                    .find(|record| {
                        record.runner == runner
                            && record.protocol == protocol
                            && record.size == max_size
                            && record.workers == *worker
                    })
                    .map(|record| WorkerScalingPoint {
                        worker: *worker,
                        speedup: base.prove_ms / record.prove_ms.max(0.001),
                    })
            })
            .collect::<Vec<_>>();
        if points.is_empty() {
            continue;
        }
        let serial_overhead = points
            .iter()
            .filter(|point| point.worker > 1 && point.speedup.is_finite())
            .max_by_key(|point| point.worker)
            .map(|point| amdahl_serial_overhead_fraction(point.speedup, point.worker));
        series.push(WorkerScalingSeries {
            runner,
            protocol,
            points,
            serial_overhead,
        });
    }

    WorkerScalingContext {
        max_size,
        workers,
        series,
    }
}

fn amdahl_diagnostic_speedup(workers: usize, serial_overhead: f64) -> f64 {
    if workers <= 1 || !serial_overhead.is_finite() {
        return 1.0;
    }
    let serial = serial_overhead.clamp(0.0, 1.0);
    let parallel = 1.0 - serial;
    1.0 / (serial + parallel / workers as f64)
}

fn line_chart_pgfplots(
    records: &[MetricRecord],
    title: &str,
    y_label: &str,
    metric: BenchmarkMetric,
) -> String {
    let positives = benchmark_stats(records)
        .into_iter()
        .filter(|record| record.case_name == "positive" && record.verified_count > 0)
        .collect::<Vec<_>>();
    let mut sizes = positives
        .iter()
        .map(|record| record.size)
        .collect::<Vec<_>>();
    sizes.sort_unstable();
    sizes.dedup();
    let powers = sizes.iter().map(|size| nv_power(*size)).collect::<Vec<_>>();
    let mut series = positives
        .iter()
        .map(|record| (record.runner, record.protocol, record.workers))
        .collect::<Vec<_>>();
    series.sort_by(|left, right| {
        series_sort_key(left.0, left.1, left.2).cmp(&series_sort_key(right.0, right.1, right.2))
    });
    series.dedup();

    let mut tex = pgfplots_start(title, "Circuit exponent $n$ in $nv=2^n$", y_label, &powers);
    for (series_index, (runner, protocol, workers)) in series.iter().enumerate() {
        let coordinates = sizes
            .iter()
            .filter_map(|size| {
                positives
                    .iter()
                    .find(|record| {
                        record.runner == *runner
                            && record.protocol == *protocol
                            && record.workers == *workers
                            && record.size == *size
                    })
                    .map(|record| {
                        let point = metric.stats(record);
                        format!(
                            "({}, {}) +- (0, {})",
                            nv_power(*size),
                            format_pgfplots_number(point.mean),
                            format_pgfplots_number(point.stddev)
                        )
                    })
            })
            .collect::<Vec<_>>();
        if coordinates.is_empty() {
            continue;
        }
        tex.push_str(&format!(
            "\\addplot+[{}, {}, {}, error bars/.cd, y dir=both, y explicit] coordinates {{{}}};\n",
            pgfplots_color(protocol, runner, series_index),
            pgfplots_dash(*workers),
            pgfplots_marker(*workers),
            coordinates.join(" ")
        ));
        tex.push_str(&format!(
            "\\addlegendentry{{{}, w={}}}\n",
            tex_escape(&display_series_name(protocol, runner)),
            workers
        ));
    }
    tex.push_str("\\end{axis}\n\\end{tikzpicture}\n");
    tex
}

fn worker_scaling_pgfplots(records: &[MetricRecord]) -> String {
    let scaling = worker_scaling_context(records);
    let max_worker = scaling.workers.iter().copied().max().unwrap_or(1) as f64;
    let mut observed_max = 1.0_f64;
    for series in &scaling.series {
        for point in &series.points {
            observed_max = observed_max.max(point.speedup);
        }
        if let Some(serial_overhead) = series.serial_overhead {
            for worker in &scaling.workers {
                observed_max =
                    observed_max.max(amdahl_diagnostic_speedup(*worker, serial_overhead));
            }
        }
    }
    let (max_y, y_step) = scaling_axis_bounds(observed_max.max(max_worker).max(1.0));

    let mut tex = pgfplots_start_with_extra(
        &format!(
            "Worker scaling at n={} (nv={})",
            nv_power(scaling.max_size),
            scaling.max_size
        ),
        "Workers",
        "Speedup vs workers=1",
        &scaling.workers,
        false,
        &linear_y_axis_options(max_y, y_step),
    );
    for (series_index, series) in scaling.series.iter().enumerate() {
        if let Some(serial_overhead) = series.serial_overhead {
            let diagnostic_coordinates = scaling
                .workers
                .iter()
                .map(|worker| {
                    format!(
                        "({}, {})",
                        worker,
                        format_pgfplots_number(amdahl_diagnostic_speedup(*worker, serial_overhead))
                    )
                })
                .collect::<Vec<_>>();
            if !diagnostic_coordinates.is_empty() {
                tex.push_str(&format!(
                    "\\addplot+[{}, densely dotted, mark=none, opacity=0.45] coordinates {{{}}};\n",
                    pgfplots_color(series.protocol, series.runner, series_index),
                    diagnostic_coordinates.join(" ")
                ));
            }
        }
        let coordinates = series
            .points
            .iter()
            .map(|point| {
                format!(
                    "({}, {})",
                    point.worker,
                    format_pgfplots_number(point.speedup)
                )
            })
            .collect::<Vec<_>>();
        if coordinates.is_empty() {
            continue;
        }
        tex.push_str(&format!(
            "\\addplot+[{}, solid, {}] coordinates {{{}}};\n",
            pgfplots_color(series.protocol, series.runner, series_index),
            pgfplots_marker(protocol_marker_key(series.protocol)),
            coordinates.join(" ")
        ));
        tex.push_str(&format!(
            "\\addlegendentry{{{}}}\n",
            tex_escape(&display_series_name(series.protocol, series.runner))
        ));
    }
    let ideal_coordinates = scaling
        .workers
        .iter()
        .map(|worker| format!("({}, {})", worker, worker))
        .collect::<Vec<_>>();
    if !ideal_coordinates.is_empty() {
        tex.push_str("\\addlegendimage{black!55, densely dotted, mark=none, opacity=0.45}\n");
        tex.push_str("\\addlegendentry{Serial+overhead diagnostic}\n");
        tex.push_str(&format!(
            "\\addplot+[pqIdeal, dashed, mark=none] coordinates {{{}}};\n",
            ideal_coordinates.join(" ")
        ));
        tex.push_str("\\addlegendentry{Perfect upper bound}\n");
    }
    tex.push_str("\\end{axis}\n\\end{tikzpicture}\n");
    tex
}

#[derive(Clone)]
struct RunnerOverheadPoint {
    protocol: &'static str,
    workers: usize,
    size: usize,
    overhead: f64,
}

fn runner_overhead_points(records: &[MetricRecord]) -> Vec<RunnerOverheadPoint> {
    let stats = benchmark_stats(records);
    let mut points = Vec::new();
    for network in stats.iter().filter(|record| {
        record.runner == BenchmarkRunner::Network.as_str()
            && record.case_name == "positive"
            && record.verified_count > 0
    }) {
        if let Some(local) = stats.iter().find(|record| {
            record.runner == BenchmarkRunner::Local.as_str()
                && record.protocol == network.protocol
                && record.case_name == "positive"
                && record.verified_count > 0
                && record.workers == network.workers
                && record.size == network.size
                && record.pcs_queries == network.pcs_queries
        }) {
            points.push(RunnerOverheadPoint {
                protocol: network.protocol,
                workers: network.workers,
                size: network.size,
                overhead: network.prove_ms.mean / local.prove_ms.mean.max(0.001),
            });
        }
    }
    points.sort_by(|left, right| {
        protocol_sort_key(left.protocol)
            .cmp(&protocol_sort_key(right.protocol))
            .then(left.workers.cmp(&right.workers))
            .then(left.size.cmp(&right.size))
    });
    points
}

fn runner_overhead_svg(records: &[MetricRecord]) -> String {
    let points = runner_overhead_points(records);
    let mut sizes = points.iter().map(|point| point.size).collect::<Vec<_>>();
    sizes.sort_unstable();
    sizes.dedup();
    let powers = sizes.iter().map(|size| nv_power(*size)).collect::<Vec<_>>();
    let min_power = powers.iter().copied().min().unwrap_or(0);
    let max_power = powers.iter().copied().max().unwrap_or(min_power);
    let mut series = points
        .iter()
        .map(|point| (point.protocol, point.workers))
        .collect::<Vec<_>>();
    series.sort_by(|left, right| {
        protocol_sort_key(left.0)
            .cmp(&protocol_sort_key(right.0))
            .then(left.1.cmp(&right.1))
    });
    series.dedup();
    let raw_max_y = points
        .iter()
        .map(|point| point.overhead)
        .fold(0.0_f64, f64::max)
        .max(1.0);
    let y_step = nice_axis_step(raw_max_y, 5);
    let max_y = (raw_max_y / y_step).ceil() * y_step;

    let mut svg = paper_svg_start(
        "Network runner overhead by circuit size",
        "Verified positive runs. Overhead is network prover time divided by local prover time for the same protocol, worker count, and size.",
    );
    draw_plot_frame(
        &mut svg,
        "Network/local prover time",
        "Circuit exponent n (nv = 2^n)",
    );
    draw_y_grid(&mut svg, max_y, y_step);
    draw_x_power_ticks(&mut svg, &powers, &sizes, min_power, max_power);
    draw_legend_box(&mut svg, series.len() + 1);
    for (series_index, (protocol, workers)) in series.iter().enumerate() {
        let style = series_style(
            protocol,
            BenchmarkRunner::Network.as_str(),
            *workers,
            series_index,
        );
        let mut line_points = Vec::new();
        for size in &sizes {
            if let Some(point) = points.iter().find(|point| {
                point.protocol == *protocol && point.workers == *workers && point.size == *size
            }) {
                let x = plot_x_power(nv_power(*size), min_power, max_power);
                let y = plot_y(point.overhead, max_y);
                line_points.push((x, y));
            }
        }
        if !line_points.is_empty() {
            let polyline = line_points
                .iter()
                .map(|(x, y)| format!("{x:.1},{y:.1}"))
                .collect::<Vec<_>>();
            if polyline.len() > 1 {
                svg.push_str(&format!(
                    "<polyline class=\"series-line\" fill=\"none\" stroke=\"{}\"{} points=\"{}\" />\n",
                    style.color,
                    stroke_dash_attr(style.dash),
                    polyline.join(" ")
                ));
            }
            for (x, y) in &line_points {
                svg.push_str(&marker_svg(*x, *y, style.color, *workers));
            }
            svg.push_str(&format!(
                "<g class=\"legend-entry\" transform=\"translate(765,{})\"><line x1=\"0\" y1=\"0\" x2=\"24\" y2=\"0\" stroke=\"{}\" stroke-width=\"2.4\"{} />{}<text x=\"34\" y=\"4\">{} w={}</text></g>\n",
                88 + series_index * 24,
                style.color,
                stroke_dash_attr(style.dash),
                marker_svg(12.0, 0.0, style.color, *workers),
                xml_escape(&display_protocol(protocol)),
                workers
            ));
        }
    }
    let parity_points = powers
        .iter()
        .map(|power| {
            let x = plot_x_power(*power, min_power, max_power);
            let y = plot_y(1.0, max_y);
            format!("{x:.1},{y:.1}")
        })
        .collect::<Vec<_>>();
    if parity_points.len() > 1 {
        svg.push_str(&format!(
            "<polyline class=\"ideal-line\" fill=\"none\" points=\"{}\" />\n",
            parity_points.join(" ")
        ));
    }
    svg.push_str(&format!(
        "<g class=\"legend-entry\" transform=\"translate(765,{})\"><line x1=\"0\" y1=\"0\" x2=\"24\" y2=\"0\" class=\"ideal-line\"/><text x=\"34\" y=\"4\">Parity</text></g>\n",
        88 + series.len() * 24
    ));
    svg.push_str("</svg>\n");
    svg
}

fn runner_overhead_pgfplots(records: &[MetricRecord]) -> String {
    let points = runner_overhead_points(records);
    let mut sizes = points.iter().map(|point| point.size).collect::<Vec<_>>();
    sizes.sort_unstable();
    sizes.dedup();
    let powers = sizes.iter().map(|size| nv_power(*size)).collect::<Vec<_>>();
    let mut series = points
        .iter()
        .map(|point| (point.protocol, point.workers))
        .collect::<Vec<_>>();
    series.sort_by(|left, right| {
        protocol_sort_key(left.0)
            .cmp(&protocol_sort_key(right.0))
            .then(left.1.cmp(&right.1))
    });
    series.dedup();

    let mut tex = pgfplots_start(
        "Network runner overhead by circuit size",
        "Circuit exponent $n$ in $nv=2^n$",
        "Network/local prover time",
        &powers,
    );
    for (series_index, (protocol, workers)) in series.iter().enumerate() {
        let coordinates = sizes
            .iter()
            .filter_map(|size| {
                points
                    .iter()
                    .find(|point| {
                        point.protocol == *protocol
                            && point.workers == *workers
                            && point.size == *size
                    })
                    .map(|point| {
                        format!(
                            "({}, {})",
                            nv_power(*size),
                            format_pgfplots_number(point.overhead)
                        )
                    })
            })
            .collect::<Vec<_>>();
        if coordinates.is_empty() {
            continue;
        }
        tex.push_str(&format!(
            "\\addplot+[{}, {}, {}] coordinates {{{}}};\n",
            pgfplots_color(protocol, BenchmarkRunner::Network.as_str(), series_index),
            pgfplots_dash(*workers),
            pgfplots_marker(*workers),
            coordinates.join(" ")
        ));
        tex.push_str(&format!(
            "\\addlegendentry{{{}, w={}}}\n",
            tex_escape(&display_protocol(protocol)),
            workers
        ));
    }
    let parity_coordinates = powers
        .iter()
        .map(|power| format!("({}, 1)", power))
        .collect::<Vec<_>>();
    if !parity_coordinates.is_empty() {
        tex.push_str(&format!(
            "\\addplot+[pqIdeal, densely dashed, mark=none] coordinates {{{}}};\n",
            parity_coordinates.join(" ")
        ));
        tex.push_str("\\addlegendentry{Parity}\n");
    }
    tex.push_str("\\end{axis}\n\\end{tikzpicture}\n");
    tex
}

#[derive(Copy, Clone)]
enum BenchmarkMetric {
    ProveMs,
    VerifyMs,
    ProofKiB,
    NetworkKiB,
}

impl BenchmarkMetric {
    fn stats(self, record: &BenchmarkStatsRecord) -> MeanStddev {
        match self {
            Self::ProveMs => record.prove_ms,
            Self::VerifyMs => record.verify_ms,
            Self::ProofKiB => MeanStddev {
                mean: record.proof_bytes.mean / 1024.0,
                stddev: record.proof_bytes.stddev / 1024.0,
            },
            Self::NetworkKiB => MeanStddev {
                mean: record.network_bytes.mean / 1024.0,
                stddev: record.network_bytes.stddev / 1024.0,
            },
        }
    }
}

fn paper_figures_pgfplots(records: &[MetricRecord]) -> String {
    let positives = benchmark_stats(records)
        .into_iter()
        .filter(|record| record.case_name == "positive" && record.verified_count > 0)
        .collect::<Vec<_>>();
    let mut powers = positives
        .iter()
        .map(|record| nv_power(record.size))
        .collect::<Vec<_>>();
    powers.sort_unstable();
    powers.dedup();

    let mut tex = String::new();
    tex.push_str(PGFPLOTS_PREAMBLE_COMMENT);
    tex.push_str(
        "% Source data: source.csv/source.json; aggregated statistics: summary_stats.csv.\n",
    );
    tex.push_str("% Paper-ready grouped PGFPlots figure. Requires:\n");
    tex.push_str("%   \\usepackage{pgfplots}\n");
    tex.push_str("%   \\usepgfplotslibrary{groupplots}\n");
    tex.push_str("%   \\pgfplotsset{compat=1.18}\n");
    tex.push_str(&pgfplots_color_definitions());
    tex.push_str("\\pgfplotsset{\n");
    tex.push_str("  every axis/.append style={font=\\sffamily},\n");
    tex.push_str("  pqPaperAxis/.style={\n");
    tex.push_str("    width=0.44\\linewidth,\n");
    tex.push_str("    height=0.305\\linewidth,\n");
    tex.push_str("    axis background/.style={fill=white},\n");
    tex.push_str("    grid=both,\n");
    tex.push_str("    minor tick num=1,\n");
    tex.push_str("    major grid style={draw=black!12, line width=0.22pt},\n");
    tex.push_str("    minor grid style={draw=black!5, line width=0.18pt},\n");
    tex.push_str("    axis line style={black!74, line width=0.42pt},\n");
    tex.push_str("    tick align=outside,\n");
    tex.push_str("    tick style={black!74, line width=0.42pt},\n");
    tex.push_str("    tick label style={font=\\scriptsize},\n");
    tex.push_str("    label style={font=\\footnotesize},\n");
    tex.push_str("    title style={font=\\footnotesize\\bfseries, yshift=-0.6ex},\n");
    tex.push_str("    xlabel near ticks,\n");
    tex.push_str("    ylabel near ticks,\n");
    tex.push_str("    ymin=0,\n");
    tex.push_str("    enlarge x limits=0.08,\n");
    tex.push_str("    enlarge y limits={upper,value=0.10},\n");
    tex.push_str("    every axis plot/.append style={line width=0.95pt, mark options={scale=0.76, solid}, line join=round},\n");
    tex.push_str("    legend cell align={left},\n");
    tex.push_str("    legend style={draw=none, fill=white, font=\\scriptsize, /tikz/every even column/.append style={column sep=0.58em}},\n");
    tex.push_str("    scaled ticks=false,\n");
    tex.push_str("    unbounded coords=discard\n");
    tex.push_str("  }\n");
    tex.push_str("}\n");
    tex.push_str("\\begin{tikzpicture}\n");
    tex.push_str("\\begin{groupplot}[\n");
    tex.push_str("  group style={group size=2 by 2, horizontal sep=0.095\\linewidth, vertical sep=0.115\\linewidth},\n");
    tex.push_str("  pqPaperAxis\n");
    tex.push_str("]\n");
    append_metric_group_axis(
        &mut tex,
        records,
        "(a) Proving time",
        "Prover time (ms)",
        BenchmarkMetric::ProveMs,
        &powers,
        true,
    );
    append_metric_group_axis(
        &mut tex,
        records,
        "(b) Verification time",
        "Verifier time (ms)",
        BenchmarkMetric::VerifyMs,
        &powers,
        false,
    );
    append_metric_group_axis(
        &mut tex,
        records,
        "(c) Proof size",
        "Proof size (KiB)",
        BenchmarkMetric::ProofKiB,
        &powers,
        false,
    );
    append_worker_scaling_group_axis(&mut tex, records, false);
    tex.push_str("\\end{groupplot}\n");
    tex.push_str(
        "\\path (group c1r2.south west) -- node[below=0.70cm] {\\pgfplotslegendfromname{pqPaperLegend}} (group c2r2.south east);\n",
    );
    tex.push_str("\\end{tikzpicture}\n");
    tex
}

fn append_metric_group_axis(
    tex: &mut String,
    records: &[MetricRecord],
    title: &str,
    y_label: &str,
    metric: BenchmarkMetric,
    x_ticks: &[usize],
    add_legend: bool,
) {
    let stats = benchmark_stats(records)
        .into_iter()
        .filter(|record| record.case_name == "positive" && record.verified_count > 0)
        .collect::<Vec<_>>();
    let mut sizes = stats.iter().map(|record| record.size).collect::<Vec<_>>();
    sizes.sort_unstable();
    sizes.dedup();
    let mut series = stats
        .iter()
        .map(|record| (record.runner, record.protocol, record.workers))
        .collect::<Vec<_>>();
    series.sort_by(|left, right| {
        series_sort_key(left.0, left.1, left.2).cmp(&series_sort_key(right.0, right.1, right.2))
    });
    series.dedup();

    append_group_axis_header(
        tex,
        title,
        "Circuit exponent $n$",
        y_label,
        x_ticks,
        add_legend,
    );
    for (series_index, (runner, protocol, workers)) in series.iter().enumerate() {
        let coordinates = sizes
            .iter()
            .filter_map(|size| {
                stats
                    .iter()
                    .find(|record| {
                        record.runner == *runner
                            && record.protocol == *protocol
                            && record.workers == *workers
                            && record.size == *size
                    })
                    .map(|record| {
                        let point = metric.stats(record);
                        format!(
                            "({}, {}) +- (0, {})",
                            nv_power(*size),
                            format_pgfplots_number(point.mean),
                            format_pgfplots_number(point.stddev)
                        )
                    })
            })
            .collect::<Vec<_>>();
        if coordinates.is_empty() {
            continue;
        }
        tex.push_str(&format!(
            "\\addplot+[{}, {}, {}, error bars/.cd, y dir=both, y explicit] coordinates {{{}}};\n",
            pgfplots_color(protocol, runner, series_index),
            pgfplots_dash(*workers),
            pgfplots_marker(*workers),
            coordinates.join(" ")
        ));
        if add_legend {
            tex.push_str(&format!(
                "\\addlegendentry{{{}, w={}}}\n",
                tex_escape(&display_series_name(protocol, runner)),
                workers
            ));
        }
    }
    if add_legend {
        tex.push_str("\\addlegendimage{black!55, densely dotted, mark=none, opacity=0.45}\n");
        tex.push_str("\\addlegendentry{Serial+overhead diagnostic}\n");
        tex.push_str("\\addlegendimage{pqIdeal, densely dashed, mark=none}\n");
        tex.push_str("\\addlegendentry{Perfect upper bound}\n");
    }
}

fn append_worker_scaling_group_axis(tex: &mut String, records: &[MetricRecord], add_legend: bool) {
    let scaling = worker_scaling_context(records);

    append_group_axis_header(
        tex,
        &format!("(d) Worker scaling at $n={}$", nv_power(scaling.max_size)),
        "Workers",
        "Speedup vs w=1",
        &scaling.workers,
        add_legend,
    );
    for (series_index, series) in scaling.series.iter().enumerate() {
        if let Some(serial_overhead) = series.serial_overhead {
            let diagnostic_coordinates = scaling
                .workers
                .iter()
                .map(|worker| {
                    format!(
                        "({}, {})",
                        worker,
                        format_pgfplots_number(amdahl_diagnostic_speedup(*worker, serial_overhead))
                    )
                })
                .collect::<Vec<_>>();
            if !diagnostic_coordinates.is_empty() {
                tex.push_str(&format!(
                    "\\addplot+[{}, densely dotted, mark=none, opacity=0.45] coordinates {{{}}};\n",
                    pgfplots_color(series.protocol, series.runner, series_index),
                    diagnostic_coordinates.join(" ")
                ));
            }
        }
        let coordinates = series
            .points
            .iter()
            .map(|point| {
                format!(
                    "({}, {})",
                    point.worker,
                    format_pgfplots_number(point.speedup)
                )
            })
            .collect::<Vec<_>>();
        if coordinates.is_empty() {
            continue;
        }
        tex.push_str(&format!(
            "\\addplot+[{}, solid, {}] coordinates {{{}}};\n",
            pgfplots_color(series.protocol, series.runner, series_index),
            pgfplots_marker(protocol_marker_key(series.protocol)),
            coordinates.join(" ")
        ));
        if add_legend {
            tex.push_str(&format!(
                "\\addlegendentry{{{}}}\n",
                tex_escape(&display_series_name(series.protocol, series.runner))
            ));
        }
    }
    let ideal_coordinates = scaling
        .workers
        .iter()
        .map(|worker| format!("({}, {})", worker, worker))
        .collect::<Vec<_>>();
    if !ideal_coordinates.is_empty() {
        tex.push_str(&format!(
            "\\addplot+[pqIdeal, densely dashed, mark=none] coordinates {{{}}};\n",
            ideal_coordinates.join(" ")
        ));
        if add_legend {
            tex.push_str("\\addlegendimage{black!55, densely dotted, mark=none, opacity=0.45}\n");
            tex.push_str("\\addlegendentry{Serial+overhead diagnostic}\n");
            tex.push_str("\\addlegendentry{Perfect upper bound}\n");
        }
    }
}

fn append_group_axis_header(
    tex: &mut String,
    title: &str,
    x_label: &str,
    y_label: &str,
    x_ticks: &[usize],
    add_legend: bool,
) {
    tex.push_str("\\nextgroupplot[\n");
    tex.push_str(&format!("  title={{{}}},\n", tex_escape(title)));
    tex.push_str(&format!("  xlabel={{{}}},\n", x_label));
    tex.push_str(&format!("  ylabel={{{}}},\n", tex_escape(y_label)));
    if !x_ticks.is_empty() {
        let ticks = x_ticks.iter().map(ToString::to_string).collect::<Vec<_>>();
        tex.push_str(&format!("  xtick={{{}}},\n", ticks.join(",")));
    }
    if add_legend {
        tex.push_str("  legend to name=pqPaperLegend,\n");
        tex.push_str("  legend columns=4,\n");
    }
    tex.push_str("]\n");
}

fn paper_figures_standalone_tex() -> String {
    [
        "% Compile from this benchmark result directory.",
        "\\documentclass[tikz,border=3pt]{standalone}",
        "\\usepackage{pgfplots}",
        "\\usepgfplotslibrary{groupplots}",
        "\\pgfplotsset{compat=1.18}",
        "\\begin{document}",
        "\\input{paper_figures.tex}",
        "\\end{document}",
        "",
    ]
    .join("\n")
}

fn verified_positive_records(records: &[MetricRecord]) -> Vec<&MetricRecord> {
    records
        .iter()
        .filter(|record| record.case_name == "positive" && record.verified)
        .collect()
}

fn pgfplots_start(title: &str, x_label: &str, y_label: &str, x_ticks: &[usize]) -> String {
    pgfplots_start_with_options(title, x_label, y_label, x_ticks, false)
}

fn pgfplots_start_log_y(title: &str, x_label: &str, y_label: &str, x_ticks: &[usize]) -> String {
    pgfplots_start_with_options(title, x_label, y_label, x_ticks, true)
}

fn pgfplots_start_with_options(
    title: &str,
    x_label: &str,
    y_label: &str,
    x_ticks: &[usize],
    log_y: bool,
) -> String {
    pgfplots_start_with_extra(title, x_label, y_label, x_ticks, log_y, &[])
}

fn pgfplots_start_with_extra(
    title: &str,
    x_label: &str,
    y_label: &str,
    x_ticks: &[usize],
    log_y: bool,
    extra_options: &[String],
) -> String {
    let mut tex = String::new();
    tex.push_str(PGFPLOTS_PREAMBLE_COMMENT);
    tex.push_str("% Source data: source.csv and source.json.\n");
    tex.push_str("% Requires: \\usepackage{pgfplots} and \\pgfplotsset{compat=1.18}.\n");
    tex.push_str(&pgfplots_color_definitions());
    tex.push_str("\\begin{tikzpicture}\n");
    tex.push_str("\\begin{axis}[\n");
    tex.push_str("  width=0.74\\linewidth,\n");
    tex.push_str("  height=0.46\\linewidth,\n");
    tex.push_str(&format!("  title={{{}}},\n", tex_escape(title)));
    tex.push_str(&format!("  xlabel={{{}}},\n", tex_escape(x_label)));
    tex.push_str(&format!("  ylabel={{{}}},\n", tex_escape(y_label)));
    tex.push_str("  axis background/.style={fill=white},\n");
    tex.push_str("  grid=major,\n");
    tex.push_str("  major grid style={draw=black!10, line width=0.25pt},\n");
    tex.push_str("  axis line style={black!70, line width=0.45pt},\n");
    tex.push_str("  tick align=outside,\n");
    tex.push_str("  tick style={black!70, line width=0.45pt},\n");
    tex.push_str("  tick label style={font=\\footnotesize},\n");
    tex.push_str("  label style={font=\\small},\n");
    tex.push_str("  title style={font=\\small, yshift=-0.5ex},\n");
    tex.push_str("  legend cell align={left},\n");
    tex.push_str("  legend columns=2,\n");
    tex.push_str("  transpose legend,\n");
    tex.push_str("  legend style={at={(0.02,0.98)}, anchor=north west, draw=black!15, line width=0.25pt, fill=white, text opacity=1, font=\\footnotesize},\n");
    tex.push_str(
        "  every axis plot/.append style={line width=0.95pt, mark options={scale=0.85, solid}},\n",
    );
    tex.push_str("  scaled ticks=false,\n");
    if log_y {
        tex.push_str("  ymode=log,\n");
        tex.push_str("  log basis y=10,\n");
        tex.push_str("  log ticks with fixed point=false,\n");
    }
    tex.push_str("  unbounded coords=discard,\n");
    if !x_ticks.is_empty() {
        let ticks = x_ticks.iter().map(ToString::to_string).collect::<Vec<_>>();
        tex.push_str(&format!("  xtick={{{}}},\n", ticks.join(",")));
    }
    for option in extra_options {
        tex.push_str(option);
        if !option.ends_with('\n') {
            tex.push('\n');
        }
    }
    tex.push_str("]\n");
    tex
}

fn pgfplots_color_definitions() -> String {
    format!("{}\n", PGFPLOTS_COLOR_DEFINITIONS.join("\n"))
}

fn pgfplots_color(protocol: &str, runner: &str, fallback_index: usize) -> &'static str {
    match (runner, protocol) {
        ("local", "r1cs") => "pqR1CS",
        ("local", "plonkish") => "pqPlonkish",
        ("network", "r1cs") => "pqGreen",
        ("network", "plonkish") => "pqPurple",
        _ => match fallback_index % 3 {
            0 => "pqGreen",
            1 => "pqPurple",
            _ => "pqGold",
        },
    }
}

fn pgfplots_dash(workers: usize) -> &'static str {
    match workers {
        1 => "solid",
        2 => "dashed",
        4 => "densely dotted",
        8 => "dash dot",
        _ => "loosely dashed",
    }
}

fn pgfplots_marker(marker_key: usize) -> &'static str {
    match marker_key {
        2 => "mark=square*",
        4 => "mark=diamond*",
        8 => "mark=triangle*",
        _ => "mark=*",
    }
}

fn format_pgfplots_number(value: f64) -> String {
    if value.is_finite() {
        trim_decimal_zeros(format!("{value:.6}"))
    } else {
        "0".to_owned()
    }
}

const SVG_WIDTH: f64 = 980.0;
const SVG_HEIGHT: f64 = 560.0;
const PLOT_LEFT: f64 = 92.0;
const PLOT_TOP: f64 = 76.0;
const PLOT_WIDTH: f64 = 640.0;
const PLOT_HEIGHT: f64 = 360.0;
const PLOT_BOTTOM: f64 = PLOT_TOP + PLOT_HEIGHT;

fn paper_svg_start(title: &str, subtitle: &str) -> String {
    format!(
        "<svg xmlns=\"http://www.w3.org/2000/svg\" width=\"{:.0}\" height=\"{:.0}\" viewBox=\"0 0 {:.0} {:.0}\" shape-rendering=\"geometricPrecision\">\n<style>\ntext {{ font-family: Arial, Helvetica, sans-serif; fill: #111827; }}\n.title {{ font-size: 18px; font-weight: 700; }}\n.subtitle {{ font-size: 11px; fill: #4b5563; }}\n.axis-label {{ font-size: 13px; font-weight: 600; fill: #111827; }}\n.tick-label {{ font-size: 11px; fill: #374151; }}\n.grid {{ stroke: #e5e7eb; stroke-width: 0.8; }}\n.axis {{ stroke: #111827; stroke-width: 1.3; }}\n.series-line {{ stroke-width: 2.5; stroke-linecap: round; stroke-linejoin: round; }}\n.diagnostic-line {{ stroke: #6b7280; stroke-width: 1.6; stroke-dasharray: 2 4; stroke-linecap: round; opacity: 0.48; }}\n.ideal-line {{ stroke: #6b7280; stroke-width: 1.8; stroke-dasharray: 6 5; stroke-linecap: round; }}\n.marker {{ stroke-width: 2; }}\n.legend-box {{ fill: #ffffff; stroke: #d1d5db; stroke-width: 0.9; }}\n.legend-entry text {{ font-size: 12px; fill: #111827; }}\n</style>\n<rect width=\"100%\" height=\"100%\" fill=\"#ffffff\" />\n<text class=\"title\" x=\"{}\" y=\"34\">{}</text>\n<text class=\"subtitle\" x=\"{}\" y=\"54\">{}</text>\n",
        SVG_WIDTH,
        SVG_HEIGHT,
        SVG_WIDTH,
        SVG_HEIGHT,
        PLOT_LEFT,
        xml_escape(title),
        PLOT_LEFT,
        xml_escape(subtitle)
    )
}

fn draw_legend_box(svg: &mut String, entries: usize) {
    let height = 30.0 + entries.max(1) as f64 * 24.0;
    svg.push_str(&format!(
        "<rect class=\"legend-box\" x=\"750\" y=\"66\" width=\"208\" height=\"{height:.1}\" />\n"
    ));
}

fn draw_plot_frame(svg: &mut String, y_label: &str, x_label: &str) {
    svg.push_str(&format!(
        "<line class=\"axis\" x1=\"{PLOT_LEFT:.1}\" y1=\"{PLOT_BOTTOM:.1}\" x2=\"{:.1}\" y2=\"{PLOT_BOTTOM:.1}\" />\n<line class=\"axis\" x1=\"{PLOT_LEFT:.1}\" y1=\"{PLOT_TOP:.1}\" x2=\"{PLOT_LEFT:.1}\" y2=\"{PLOT_BOTTOM:.1}\" />\n",
        PLOT_LEFT + PLOT_WIDTH
    ));
    svg.push_str(&format!(
        "<text class=\"axis-label\" x=\"{:.1}\" y=\"526\" text-anchor=\"middle\">{}</text>\n",
        PLOT_LEFT + PLOT_WIDTH / 2.0,
        xml_escape(x_label)
    ));
    svg.push_str(&format!(
        "<text class=\"axis-label\" x=\"24\" y=\"{:.1}\" text-anchor=\"middle\" transform=\"rotate(-90 24,{:.1})\">{}</text>\n",
        PLOT_TOP + PLOT_HEIGHT / 2.0,
        PLOT_TOP + PLOT_HEIGHT / 2.0,
        xml_escape(y_label)
    ));
}

fn draw_y_grid(svg: &mut String, max_y: f64, step: f64) {
    let ticks = (max_y / step).round() as usize;
    for idx in 0..=ticks {
        let value = step * idx as f64;
        let y = plot_y(value, max_y);
        svg.push_str(&format!(
            "<line class=\"grid\" x1=\"{PLOT_LEFT:.1}\" y1=\"{y:.1}\" x2=\"{:.1}\" y2=\"{y:.1}\" />\n",
            PLOT_LEFT + PLOT_WIDTH
        ));
        svg.push_str(&format!(
            "<text class=\"tick-label\" x=\"{:.1}\" y=\"{:.1}\" text-anchor=\"end\">{}</text>\n",
            PLOT_LEFT - 10.0,
            y + 4.0,
            format_axis_value(value)
        ));
    }
}

fn draw_x_power_ticks(
    svg: &mut String,
    powers: &[usize],
    sizes: &[usize],
    min_power: usize,
    max_power: usize,
) {
    let label_step = tick_label_step(powers.len());
    for (idx, (power, size)) in powers.iter().zip(sizes).enumerate() {
        let x = plot_x_power(*power, min_power, max_power);
        svg.push_str(&format!(
            "<line class=\"grid\" x1=\"{x:.1}\" y1=\"{PLOT_TOP:.1}\" x2=\"{x:.1}\" y2=\"{PLOT_BOTTOM:.1}\" />\n<line class=\"axis\" x1=\"{x:.1}\" y1=\"{PLOT_BOTTOM:.1}\" x2=\"{x:.1}\" y2=\"{:.1}\" />\n",
            PLOT_BOTTOM + 5.0
        ));
        if idx % label_step == 0 || idx + 1 == powers.len() {
            svg.push_str(&format!(
                "<text class=\"tick-label\" x=\"{x:.1}\" y=\"{:.1}\" text-anchor=\"middle\"><tspan x=\"{x:.1}\">n={}</tspan><tspan x=\"{x:.1}\" dy=\"13\">nv={}</tspan></text>\n",
                PLOT_BOTTOM + 19.0,
                power,
                size
            ));
        }
    }
}

fn draw_x_numeric_ticks(svg: &mut String, ticks: &[usize], min_x: f64, max_x: f64) {
    let label_step = tick_label_step(ticks.len());
    for (idx, tick) in ticks.iter().enumerate() {
        let x = plot_x_numeric(*tick as f64, min_x, max_x);
        svg.push_str(&format!(
            "<line class=\"grid\" x1=\"{x:.1}\" y1=\"{PLOT_TOP:.1}\" x2=\"{x:.1}\" y2=\"{PLOT_BOTTOM:.1}\" />\n<line class=\"axis\" x1=\"{x:.1}\" y1=\"{PLOT_BOTTOM:.1}\" x2=\"{x:.1}\" y2=\"{:.1}\" />\n",
            PLOT_BOTTOM + 5.0
        ));
        if idx % label_step == 0 || idx + 1 == ticks.len() {
            svg.push_str(&format!(
                "<text class=\"tick-label\" x=\"{x:.1}\" y=\"{:.1}\" text-anchor=\"middle\">{}</text>\n",
                PLOT_BOTTOM + 21.0,
                tick
            ));
        }
    }
}

fn chart_color(index: usize) -> &'static str {
    const COLORS: [&str; 8] = [
        "#0072B2", "#D55E00", "#009E73", "#CC79A7", "#E69F00", "#56B4E9", "#000000", "#F0E442",
    ];
    COLORS[index % COLORS.len()]
}

#[derive(Copy, Clone)]
struct ChartSeriesStyle {
    color: &'static str,
    dash: &'static str,
}

fn series_style(
    protocol: &str,
    runner: &str,
    workers: usize,
    fallback_index: usize,
) -> ChartSeriesStyle {
    let color = match (runner, protocol) {
        ("local", "r1cs") => "#0072B2",
        ("local", "plonkish") => "#D55E00",
        ("network", "r1cs") => "#009E73",
        ("network", "plonkish") => "#CC79A7",
        _ => chart_color(fallback_index),
    };
    let dash = match workers {
        1 => "",
        2 => "7 4",
        4 => "2 3",
        8 => "9 3 2 3",
        _ => "5 4",
    };
    ChartSeriesStyle { color, dash }
}

fn stroke_dash_attr(dash: &str) -> String {
    if dash.is_empty() {
        String::new()
    } else {
        format!(" stroke-dasharray=\"{dash}\"")
    }
}

fn protocol_marker_key(protocol: &str) -> usize {
    match protocol {
        "r1cs" => 1,
        "plonkish" => 2,
        _ => 4,
    }
}

fn marker_svg(cx: f64, cy: f64, color: &str, marker_key: usize) -> String {
    match marker_key {
        2 => format!(
            "<rect class=\"marker\" x=\"{:.1}\" y=\"{:.1}\" width=\"8.4\" height=\"8.4\" fill=\"#ffffff\" stroke=\"{}\" />\n",
            cx - 4.2,
            cy - 4.2,
            color
        ),
        4 => format!(
            "<path class=\"marker\" d=\"M {cx:.1} {:.1} L {:.1} {cy:.1} L {cx:.1} {:.1} L {:.1} {cy:.1} Z\" fill=\"#ffffff\" stroke=\"{}\" />\n",
            cy - 5.0,
            cx + 5.0,
            cy + 5.0,
            cx - 5.0,
            color
        ),
        8 => format!(
            "<path class=\"marker\" d=\"M {cx:.1} {:.1} L {:.1} {:.1} L {:.1} {:.1} Z\" fill=\"#ffffff\" stroke=\"{}\" />\n",
            cy - 5.2,
            cx + 5.0,
            cy + 4.2,
            cx - 5.0,
            cy + 4.2,
            color
        ),
        _ => format!(
            "<circle class=\"marker\" cx=\"{cx:.1}\" cy=\"{cy:.1}\" r=\"4.2\" fill=\"#ffffff\" stroke=\"{}\" />\n",
            color
        ),
    }
}

fn plot_x_power(power: usize, min_power: usize, max_power: usize) -> f64 {
    if min_power == max_power {
        return PLOT_LEFT + PLOT_WIDTH / 2.0;
    }
    PLOT_LEFT + ((power - min_power) as f64 / (max_power - min_power) as f64) * PLOT_WIDTH
}

fn plot_x_numeric(value: f64, min_x: f64, max_x: f64) -> f64 {
    if (max_x - min_x).abs() < f64::EPSILON {
        return PLOT_LEFT + PLOT_WIDTH / 2.0;
    }
    PLOT_LEFT + ((value - min_x) / (max_x - min_x)) * PLOT_WIDTH
}

fn plot_y(value: f64, max_y: f64) -> f64 {
    PLOT_BOTTOM - (value / max_y.max(1.0)) * PLOT_HEIGHT
}

fn tick_label_step(count: usize) -> usize {
    count.div_ceil(8).max(1)
}

fn nice_axis_step(max_value: f64, target_ticks: usize) -> f64 {
    let rough = (max_value / target_ticks.max(1) as f64).max(1.0e-9);
    let exponent = rough.log10().floor();
    let base = 10_f64.powf(exponent);
    let fraction = rough / base;
    let nice_fraction = if fraction <= 1.0 {
        1.0
    } else if fraction <= 2.0 {
        2.0
    } else if fraction <= 5.0 {
        5.0
    } else {
        10.0
    };
    nice_fraction * base
}

fn scaling_axis_bounds(max_value: f64) -> (f64, f64) {
    let raw_max_y = max_value.max(1.0);
    let y_step = nice_axis_step(raw_max_y, 8);
    let max_y = (raw_max_y / y_step).ceil() * y_step;
    (max_y, y_step)
}

fn linear_y_axis_options(max_y: f64, step: f64) -> Vec<String> {
    let tick_count = (max_y / step).round() as usize;
    let ticks = (0..=tick_count)
        .map(|idx| format_pgfplots_number(step * idx as f64))
        .collect::<Vec<_>>()
        .join(",");
    vec![
        "  ymin=0,".to_owned(),
        format!("  ymax={},", format_pgfplots_number(max_y)),
        format!("  ytick={{{ticks}}},"),
    ]
}

fn format_axis_value(value: f64) -> String {
    if value.abs() < 1.0e-9 {
        "0".to_owned()
    } else if value.abs() >= 1000.0 {
        format!("{value:.0}")
    } else if value.abs() >= 100.0 {
        trim_decimal_zeros(format!("{value:.1}"))
    } else if value.abs() >= 1.0 {
        trim_decimal_zeros(format!("{value:.2}"))
    } else {
        trim_decimal_zeros(format!("{value:.3}"))
    }
}

fn trim_decimal_zeros(mut value: String) -> String {
    if value.contains('.') {
        while value.ends_with('0') {
            value.pop();
        }
        if value.ends_with('.') {
            value.pop();
        }
    }
    value
}

fn display_protocol(protocol: &str) -> String {
    match protocol {
        "r1cs" => "R1CS".to_owned(),
        "plonkish" => "Plonkish".to_owned(),
        other => other.to_owned(),
    }
}

fn display_series_name(protocol: &str, runner: &str) -> String {
    let protocol = display_protocol(protocol);
    if runner == "local" {
        protocol
    } else {
        format!("{protocol} {runner}")
    }
}

fn series_sort_key(runner: &str, protocol: &str, workers: usize) -> (usize, usize, usize) {
    (
        runner_sort_key(runner),
        protocol_sort_key(protocol),
        workers,
    )
}

fn runner_sort_key(runner: &str) -> usize {
    match runner {
        "local" => 0,
        "network" => 1,
        _ => 2,
    }
}

fn protocol_sort_key(protocol: &str) -> usize {
    match protocol {
        "r1cs" => 0,
        "plonkish" => 1,
        _ => 2,
    }
}

fn xml_escape(input: &str) -> String {
    input
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

fn tex_escape(input: &str) -> String {
    let mut escaped = String::new();
    for character in input.chars() {
        match character {
            '\\' => escaped.push_str("\\textbackslash{}"),
            '%' => escaped.push_str("\\%"),
            '&' => escaped.push_str("\\&"),
            '#' => escaped.push_str("\\#"),
            '_' => escaped.push_str("\\_"),
            '{' => escaped.push_str("\\{"),
            '}' => escaped.push_str("\\}"),
            _ => escaped.push(character),
        }
    }
    escaped
}

fn usage() -> String {
    "usage:
  cargo run -p pq-experiments -- <r1cs|plonkish> [--workers N] [--size N] [--pcs-queries N] [--format json|csv] [--case positive|negative|both]
  cargo run -p pq-experiments -- interactive
  cargo run -p pq-experiments -- proof-experiment [--protocol r1cs|plonkish|both] [--runner local|network] [--size N | --n POWER] [--workers N] [--pcs-queries N] [--out DIR] [--format json|csv]
  cargo run -p pq-experiments -- list-proofs [--results results] [--format text|json|csv]
  cargo run -p pq-experiments -- verify-proof --dir results/bench-... [--all | --proof ID] [--format json|csv]
  cargo run -p pq-experiments -- benchmark [--paper-preset] [--runner local|network|both] [--sizes 4,8,16 | --size-range 4..16 | --nv-powers/--n-values 2,3,4 | --nv-range/--n-range 2..6] [--workers 1,2,4 | --worker-power-range 0..2] [--pcs-queries N] [--host-cores N] [--worker-cores N] [--compile-figures] [--out DIR]
  cargo run -p pq-experiments -- pcs-benchmark [--runner local|network|both] [--opening compact|full|both] [--sizes 256,512,1024 | --size-range 256..1024 | --nv-powers/--n-values 8,9,10 | --nv-range/--n-range 8..10] [--workers 1,2,4 | --worker-power-range 0..2] [--pcs-queries N] [--host-cores N] [--worker-cores N] [--no-pcs-warmup] [--out DIR]
  cargo run -p pq-experiments -- quick-smoke [--out DIR]
  cargo run -p pq-experiments -- verify-results --dir results/bench-... [--format json|csv] [--paper-quality]
  cargo run -p pq-experiments -- verify-pcs-results --dir results/pcs-bench-... [--format json|csv]
  cargo run -p pq-experiments -- net-demo [--workers N] [--format json|csv]
  cargo run -p pq-experiments -- worker --addr HOST:PORT --id N
  cargo run -p pq-experiments -- master --addrs A,B [--ids 0,1] [--session S] [--payload P] [--shutdown] [--format json|csv]
  cargo run -p pq-experiments -- master --addrs A,B --protocol <r1cs|plonkish> [--ids 0,1] [--size N] [--pcs-queries N] [--case positive|negative|both] [--shutdown] [--format json|csv]"
        .to_owned()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    fn temp_test_dir(prefix: &str) -> PathBuf {
        env::temp_dir().join(format!(
            "{prefix}_{}",
            SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .expect("clock")
                .as_nanos()
        ))
    }

    fn test_stage_breakdown(prove_ms: f64, verify_ms: f64, proof_bytes: usize) -> StageBreakdown {
        let proof_pcs_bytes = proof_bytes / 2;
        let proof_sumcheck_bytes = proof_bytes / 4;
        StageBreakdown {
            prove_pcs_commit_ms: prove_ms * 0.2,
            prove_sumcheck_ms: prove_ms * 0.3,
            prove_batch_open_ms: prove_ms * 0.2,
            prove_other_ms: prove_ms * 0.3,
            verify_pcs_open_ms: verify_ms * 0.4,
            verify_sumcheck_ms: verify_ms * 0.2,
            verify_other_ms: verify_ms * 0.4,
            proof_pcs_bytes,
            proof_sumcheck_bytes,
            proof_other_bytes: proof_bytes - proof_pcs_bytes - proof_sumcheck_bytes,
        }
    }

    fn write_base_benchmark_fixture(
        run_dir: &Path,
        run_id: u64,
        command: &BenchmarkCommand,
        records: &[MetricRecord],
        timings: &[PhaseTimingRecord],
    ) -> Result<(), CliError> {
        let provenance = BenchmarkProvenance::capture();
        write_text_file(
            &run_dir.join("metadata.json"),
            &benchmark_metadata_json(run_id, command, records, false, &provenance),
        )?;
        write_text_file(&run_dir.join("source.csv"), &records_to_csv(records))?;
        write_text_file(&run_dir.join("source.json"), &records_to_json(records))?;
        write_text_file(
            &run_dir.join("summary_stats.csv"),
            &summary_stats_to_csv(&benchmark_stats(records)),
        )?;
        write_text_file(
            &run_dir.join("phase_timing.csv"),
            &phase_timing_to_csv(timings),
        )?;
        write_text_file(
            &run_dir.join("phase_timing.json"),
            &phase_timing_to_json(timings),
        )?;
        write_text_file(
            &run_dir.join(OVERVIEW_HTML),
            &benchmark_overview_html(run_id, command, records, false),
        )?;
        write_text_file(
            &run_dir.join("summary.txt"),
            &benchmark_summary(command, records, timings, false, &provenance),
        )?;
        write_benchmark_charts(run_dir, records)?;
        for artifact in benchmark_artifacts(false) {
            if artifact != RESULT_MANIFEST && !run_dir.join(artifact).exists() {
                write_text_file(
                    &run_dir.join(artifact),
                    &format!("test benchmark fixture for {artifact}\n"),
                )?;
            }
        }
        Ok(())
    }

    #[test]
    fn parses_experiment_protocol_flags() {
        let config = parse_args(vec![
            "plonkish".to_owned(),
            "--workers".to_owned(),
            "2".to_owned(),
            "--size".to_owned(),
            "16".to_owned(),
            "--pcs-queries".to_owned(),
            "3".to_owned(),
            "--format".to_owned(),
            "csv".to_owned(),
            "--case".to_owned(),
            "negative".to_owned(),
        ])
        .expect("config");

        assert_eq!(config.protocol, Protocol::Plonkish);
        assert_eq!(config.workers, 2);
        assert_eq!(config.size, 16);
        assert_eq!(config.pcs_queries, 3);
        assert_eq!(config.format, OutputFormat::Csv);
        assert_eq!(config.case, CaseSelection::Negative);
    }

    #[test]
    fn formats_failure_reason_fields() {
        assert_eq!(json_optional_string(None), "null");
        assert_eq!(
            json_optional_string(Some("InvalidProof")),
            "\"InvalidProof\""
        );
        assert_eq!(csv_escape("Invalid,Proof"), "\"Invalid,Proof\"");
        assert_eq!(csv_escape("Pcs"), "Pcs");
    }

    #[test]
    fn usage_help_exits_successfully() {
        assert!(is_usage_help(&CliError(usage())));
        assert!(!is_usage_help(&CliError("unknown argument".to_owned())));
        assert_eq!(cli_exit_code(&CliError(usage())), 0);
        assert_eq!(cli_exit_code(&CliError("unknown argument".to_owned())), 2);
    }

    #[test]
    fn interactive_defaults_build_local_r1cs_config() {
        let mut input = Cursor::new(b"\n\n\n\n\n\n\n".as_slice());
        let mut output = Vec::new();
        let selection =
            prompt_interactive_selection(&mut input, &mut output).expect("interactive config");

        match selection {
            InteractiveSelection::Experiment { mode, config } => {
                assert_eq!(mode, InteractiveMode::Local);
                assert_eq!(config.protocol, Protocol::R1cs);
                assert_eq!(config.workers, 2);
                assert_eq!(config.size, 8);
                assert_eq!(config.pcs_queries, 3);
                assert_eq!(config.format, OutputFormat::Json);
                assert_eq!(config.case, CaseSelection::Both);
            }
            InteractiveSelection::NetDemo(_) => panic!("expected experiment selection"),
        }
    }

    #[test]
    fn interactive_can_select_network_plonkish_case() {
        let mut input = Cursor::new(b"net-proof\ncsv\n2\nplonkish\n4\n5\nnegative\n".as_slice());
        let mut output = Vec::new();
        let selection =
            prompt_interactive_selection(&mut input, &mut output).expect("interactive config");

        match selection {
            InteractiveSelection::Experiment { mode, config } => {
                assert_eq!(mode, InteractiveMode::NetProof);
                assert_eq!(config.protocol, Protocol::Plonkish);
                assert_eq!(config.workers, 2);
                assert_eq!(config.size, 4);
                assert_eq!(config.pcs_queries, 5);
                assert_eq!(config.format, OutputFormat::Csv);
                assert_eq!(config.case, CaseSelection::Negative);
            }
            InteractiveSelection::NetDemo(_) => panic!("expected experiment selection"),
        }
    }

    #[test]
    fn parses_benchmark_command_flags() {
        let command = parse_benchmark_command(&[
            "--sizes".to_owned(),
            "4,8".to_owned(),
            "--workers".to_owned(),
            "1,2".to_owned(),
            "--pcs-queries".to_owned(),
            "5".to_owned(),
            "--host-cores".to_owned(),
            "16".to_owned(),
            "--worker-cores".to_owned(),
            "4".to_owned(),
            "--out".to_owned(),
            "results/custom".to_owned(),
        ])
        .expect("benchmark command");

        assert_eq!(command.sizes, vec![4, 8]);
        assert_eq!(command.workers, vec![1, 2]);
        assert_eq!(command.pcs_queries, 5);
        assert_eq!(command.host_logical_cores, Some(16));
        assert_eq!(command.worker_cores, Some(4));
        assert_eq!(command.repeats, 1);
        assert_eq!(command.runner, BenchmarkRunner::Local);
        assert!(!command.paper_preset);
        assert!(!command.compile_figures);
        assert_eq!(command.figure_compiler, FigureCompiler::Auto);
        assert_eq!(command.out_dir, PathBuf::from("results/custom"));

        let repeated_error = parse_benchmark_command(&[
            "--sizes".to_owned(),
            "4".to_owned(),
            "--workers".to_owned(),
            "1".to_owned(),
            "--repeats".to_owned(),
            "3".to_owned(),
            "--compile-figures".to_owned(),
            "--figure-compiler".to_owned(),
            "tectonic".to_owned(),
        ])
        .expect_err("performance benchmark must reject repeated samples");
        assert!(repeated_error.0.contains("--repeats must be 1"));

        let network = parse_benchmark_command(&[
            "--sizes".to_owned(),
            "4".to_owned(),
            "--workers".to_owned(),
            "1".to_owned(),
            "--runner".to_owned(),
            "network".to_owned(),
        ])
        .expect("network benchmark command");
        assert_eq!(network.runner, BenchmarkRunner::Network);

        let both = parse_benchmark_command(&[
            "--sizes".to_owned(),
            "4".to_owned(),
            "--workers".to_owned(),
            "1".to_owned(),
            "--runner".to_owned(),
            "both".to_owned(),
        ])
        .expect("combined benchmark command");
        assert_eq!(both.runner, BenchmarkRunner::Both);
        assert_eq!(
            both.runner
                .variants()
                .iter()
                .map(|runner| runner.as_str())
                .collect::<Vec<_>>(),
            vec!["local", "network"]
        );

        let mut scaled = parse_benchmark_command(&[
            "--sizes".to_owned(),
            "4".to_owned(),
            "--workers".to_owned(),
            "1,2,4".to_owned(),
            "--runner".to_owned(),
            "network".to_owned(),
            "--host-cores".to_owned(),
            "10".to_owned(),
        ])
        .expect("network scaling benchmark command");
        configure_benchmark_core_plan(&mut scaled).expect("core allocation");
        let plan = scaled.worker_core_plan.expect("worker core plan");
        assert_eq!(plan.host_logical_cores, 10);
        assert_eq!(plan.max_workers, 4);
        assert_eq!(plan.cores_per_worker, 2);
        assert_eq!(plan.core_ids_for_worker(1), vec![2, 3]);

        let mut host20_max4 = parse_benchmark_command(&[
            "--sizes".to_owned(),
            "4".to_owned(),
            "--workers".to_owned(),
            "1,4".to_owned(),
            "--runner".to_owned(),
            "network".to_owned(),
            "--host-cores".to_owned(),
            "20".to_owned(),
        ])
        .expect("20-core max-4 worker command");
        configure_benchmark_core_plan(&mut host20_max4).expect("20-core max-4 plan");
        let plan = host20_max4.worker_core_plan.expect("worker core plan");
        assert_eq!(plan.max_workers, 4);
        assert_eq!(plan.cores_per_worker, 5);
        assert_eq!(plan.core_ids_for_worker(3), vec![15, 16, 17, 18, 19]);

        let mut host20_max8 = parse_benchmark_command(&[
            "--sizes".to_owned(),
            "8".to_owned(),
            "--workers".to_owned(),
            "1,2,4,8".to_owned(),
            "--runner".to_owned(),
            "network".to_owned(),
            "--host-cores".to_owned(),
            "20".to_owned(),
        ])
        .expect("20-core max-8 worker command");
        configure_benchmark_core_plan(&mut host20_max8).expect("20-core max-8 plan");
        let plan = host20_max8.worker_core_plan.expect("worker core plan");
        assert_eq!(plan.max_workers, 8);
        assert_eq!(plan.cores_per_worker, 2);
        assert_eq!(plan.core_ids_for_worker(7), vec![14, 15]);

        let preset =
            parse_benchmark_command(&["--paper-preset".to_owned()]).expect("paper preset command");
        assert!(preset.paper_preset);
        assert_eq!(preset.sizes, vec![4, 8, 16, 32, 64]);
        assert_eq!(preset.workers, vec![1, 2, 4]);
        assert_eq!(preset.pcs_queries, 3);
        assert_eq!(preset.repeats, 1);

        let overridden_preset = parse_benchmark_command(&[
            "--paper-preset".to_owned(),
            "--n-range".to_owned(),
            "2..3".to_owned(),
        ])
        .expect("overridden paper preset command");
        assert!(overridden_preset.paper_preset);
        assert_eq!(overridden_preset.sizes, vec![4, 8]);
        assert_eq!(overridden_preset.repeats, 1);

        let dense_range = parse_benchmark_command(&[
            "--size-range".to_owned(),
            "4..8".to_owned(),
            "--worker-power-range".to_owned(),
            "0..2".to_owned(),
        ])
        .expect("dense size range benchmark command");
        assert_eq!(dense_range.sizes, vec![4, 5, 6, 7, 8]);
        assert_eq!(dense_range.workers, vec![1, 2, 4]);

        let distributed_worker_range = parse_benchmark_command(&[
            "--size-range".to_owned(),
            "16..16".to_owned(),
            "--worker-power-range".to_owned(),
            "1..3".to_owned(),
        ])
        .expect("distributed worker range benchmark command");
        assert_eq!(distributed_worker_range.workers, vec![1, 2, 4, 8]);
    }

    #[test]
    fn parses_pcs_benchmark_defaults_and_opening_expansion() {
        let command = parse_pcs_benchmark_command(&[]).expect("default PCS benchmark command");
        assert_eq!(command.sizes, vec![256, 512, 1024]);
        assert_eq!(command.workers, vec![1, 2, 4]);
        assert_eq!(command.pcs_queries, 1);
        assert_eq!(command.repeats, 1);
        assert_eq!(command.runner, BenchmarkRunner::Both);
        assert_eq!(command.opening, PcsOpeningSelection::Compact);
        assert_eq!(command.opening.variants(), vec![PcsOpeningVariant::Compact]);

        let explicit = parse_pcs_benchmark_command(&[
            "--runner".to_owned(),
            "network".to_owned(),
            "--opening".to_owned(),
            "full".to_owned(),
            "--n-values".to_owned(),
            "2,3".to_owned(),
            "--workers".to_owned(),
            "1,2".to_owned(),
            "--pcs-queries".to_owned(),
            "2".to_owned(),
        ])
        .expect("explicit PCS benchmark command");
        assert_eq!(explicit.runner, BenchmarkRunner::Network);
        assert_eq!(explicit.opening.variants(), vec![PcsOpeningVariant::Full]);
        assert_eq!(explicit.sizes, vec![4, 8]);
        assert_eq!(explicit.workers, vec![1, 2]);
        assert_eq!(explicit.pcs_queries, 2);
    }

    #[test]
    fn rejects_invalid_pcs_benchmark_grid() {
        let non_power_of_two = parse_pcs_benchmark_command(&[
            "--sizes".to_owned(),
            "3".to_owned(),
            "--workers".to_owned(),
            "1".to_owned(),
        ])
        .expect_err("PCS size must be a power of two");
        assert!(non_power_of_two.0.contains("power of two"));

        let too_many_workers = parse_pcs_benchmark_command(&[
            "--sizes".to_owned(),
            "2".to_owned(),
            "--workers".to_owned(),
            "4".to_owned(),
        ])
        .expect_err("PCS workers cannot exceed size");
        assert!(too_many_workers.0.contains("cannot exceed size"));

        let bad_opening =
            parse_pcs_benchmark_command(&["--opening".to_owned(), "short".to_owned()])
                .expect_err("PCS opening parser rejects unknown variants");
        assert!(bad_opening.0.contains("unsupported --opening"));
    }

    #[test]
    fn benchmark_progress_counts_real_jobs() {
        let command = parse_benchmark_command(&[
            "--runner".to_owned(),
            "both".to_owned(),
            "--n-range".to_owned(),
            "2..3".to_owned(),
            "--workers".to_owned(),
            "1,2".to_owned(),
        ])
        .expect("benchmark command");

        assert_eq!(command.sizes, vec![4, 8]);
        assert_eq!(command.workers, vec![1, 2]);
        assert_eq!(
            benchmark_total_jobs(&command, command.runner.variants().len()),
            16
        );
        assert_eq!(
            benchmark_progress(0, 4),
            "progress 0/4   0.0% [------------------------]"
        );
        assert_eq!(
            benchmark_progress(2, 4),
            "progress 2/4  50.0% [############------------]"
        );
        assert_eq!(
            benchmark_progress(4, 4),
            "progress 4/4 100.0% [########################]"
        );
    }

    #[test]
    fn phase_timing_verifier_accepts_network_worker_pool_phases() {
        let phase_dir = env::temp_dir().join(format!(
            "pq_dsnark_network_phase_test_{}",
            SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .expect("clock")
                .as_nanos()
        ));
        fs::create_dir_all(&phase_dir).expect("phase temp dir");
        let timings = vec![
            PhaseTimingRecord {
                phase: "setup".to_owned(),
                detail: "setup".to_owned(),
                elapsed_ms: 0.1,
                recorded_prove_ms: 0.0,
                recorded_verify_ms: 0.0,
                inferred_overhead_ms: 0.1,
            },
            PhaseTimingRecord {
                phase: "network_worker_pool_start".to_owned(),
                detail: "spawn workers".to_owned(),
                elapsed_ms: 10.0,
                recorded_prove_ms: 0.0,
                recorded_verify_ms: 0.0,
                inferred_overhead_ms: 10.0,
            },
            PhaseTimingRecord {
                phase: "job".to_owned(),
                detail: "runner=network protocol=r1cs n=2 nv=4 workers=1".to_owned(),
                elapsed_ms: 12.0,
                recorded_prove_ms: 6.0,
                recorded_verify_ms: 6.0,
                inferred_overhead_ms: 0.0,
            },
            PhaseTimingRecord {
                phase: "job".to_owned(),
                detail: "runner=network protocol=plonkish n=2 nv=4 workers=2".to_owned(),
                elapsed_ms: 14.0,
                recorded_prove_ms: 7.0,
                recorded_verify_ms: 7.0,
                inferred_overhead_ms: 0.0,
            },
            PhaseTimingRecord {
                phase: "network_worker_pool_shutdown".to_owned(),
                detail: "shutdown workers".to_owned(),
                elapsed_ms: 8.0,
                recorded_prove_ms: 0.0,
                recorded_verify_ms: 0.0,
                inferred_overhead_ms: 8.0,
            },
            PhaseTimingRecord {
                phase: "source_and_chart_artifacts".to_owned(),
                detail: "charts".to_owned(),
                elapsed_ms: 1.0,
                recorded_prove_ms: 0.0,
                recorded_verify_ms: 0.0,
                inferred_overhead_ms: 1.0,
            },
            PhaseTimingRecord {
                phase: "final_result_artifacts".to_owned(),
                detail: "final".to_owned(),
                elapsed_ms: 1.0,
                recorded_prove_ms: 0.0,
                recorded_verify_ms: 0.0,
                inferred_overhead_ms: 1.0,
            },
            PhaseTimingRecord {
                phase: "total".to_owned(),
                detail: "total".to_owned(),
                elapsed_ms: 46.0,
                recorded_prove_ms: 13.0,
                recorded_verify_ms: 13.0,
                inferred_overhead_ms: 20.0,
            },
        ];
        write_text_file(
            &phase_dir.join("phase_timing.csv"),
            &phase_timing_to_csv(&timings),
        )
        .expect("write network phase timing");

        let rows = verify_phase_timing_csv_semantics(&phase_dir, 2)
            .expect("network worker phases should be valid");
        assert_eq!(rows, 8);
        fs::remove_dir_all(&phase_dir).expect("cleanup phase temp dir");
    }

    #[test]
    fn verifies_pcs_result_fixture_contract() {
        let run_dir = temp_test_dir("pq_dsnark_pcs_verify_fixture");
        fs::create_dir_all(&run_dir).expect("create PCS fixture dir");
        let command = PcsBenchmarkCommand {
            sizes: vec![4],
            workers: vec![1],
            pcs_queries: 1,
            repeats: 1,
            runner: BenchmarkRunner::Both,
            opening: PcsOpeningSelection::Both,
            out_dir: PathBuf::from("results"),
            host_logical_cores: None,
            worker_cores: None,
            worker_core_plan: None,
            warmup_enabled: true,
        };
        let records = vec![
            PcsMetricRecord {
                runner: "local",
                opening: "compact",
                trial: 1,
                workers: 1,
                size: 4,
                t_rows_per_worker: 4.0,
                paper_b_target: paper_b_target(4, 1),
                shard_len: 4,
                pcs_queries_requested: 1,
                pcs_queries_effective: 1,
                partition_ms: 0.1,
                worker_commit_ms: 0.2,
                master_commit_ms: 0.1,
                commit_ms: 0.4,
                open_ms: 0.3,
                verify_ms: 0.2,
                commitment_bytes: 64,
                opening_proof_bytes: 96,
                communication_bytes: 128,
                network_commit_bytes: 0,
                network_open_bytes: 0,
                network_bytes: 0,
                host_logical_cores: None,
                cores_per_worker: None,
                core_affinity: None,
                verified: true,
                failure_reason: None,
            },
            PcsMetricRecord {
                runner: "network",
                opening: "full",
                trial: 1,
                workers: 1,
                size: 4,
                t_rows_per_worker: 4.0,
                paper_b_target: paper_b_target(4, 1),
                shard_len: 4,
                pcs_queries_requested: 1,
                pcs_queries_effective: 1,
                partition_ms: 0.0,
                worker_commit_ms: 0.5,
                master_commit_ms: 0.0,
                commit_ms: 0.5,
                open_ms: 0.4,
                verify_ms: 0.2,
                commitment_bytes: 64,
                opening_proof_bytes: 128,
                communication_bytes: 160,
                network_commit_bytes: 80,
                network_open_bytes: 120,
                network_bytes: 200,
                host_logical_cores: None,
                cores_per_worker: None,
                core_affinity: None,
                verified: true,
                failure_reason: None,
            },
        ];
        let timings = vec![
            PhaseTimingRecord {
                phase: "setup".to_owned(),
                detail: "setup".to_owned(),
                elapsed_ms: 0.1,
                recorded_prove_ms: 0.0,
                recorded_verify_ms: 0.0,
                inferred_overhead_ms: 0.1,
            },
            PhaseTimingRecord {
                phase: "pcs_job".to_owned(),
                detail: "runner=local opening=compact".to_owned(),
                elapsed_ms: 1.0,
                recorded_prove_ms: 0.7,
                recorded_verify_ms: 0.2,
                inferred_overhead_ms: 0.1,
            },
            PhaseTimingRecord {
                phase: "pcs_job".to_owned(),
                detail: "runner=network opening=full".to_owned(),
                elapsed_ms: 1.2,
                recorded_prove_ms: 0.9,
                recorded_verify_ms: 0.2,
                inferred_overhead_ms: 0.1,
            },
            PhaseTimingRecord {
                phase: "source_and_chart_artifacts".to_owned(),
                detail: "artifacts".to_owned(),
                elapsed_ms: 0.1,
                recorded_prove_ms: 0.0,
                recorded_verify_ms: 0.0,
                inferred_overhead_ms: 0.1,
            },
            PhaseTimingRecord {
                phase: "final_result_artifacts".to_owned(),
                detail: "final".to_owned(),
                elapsed_ms: 0.1,
                recorded_prove_ms: 0.0,
                recorded_verify_ms: 0.0,
                inferred_overhead_ms: 0.1,
            },
            PhaseTimingRecord {
                phase: "total".to_owned(),
                detail: "total".to_owned(),
                elapsed_ms: 2.0,
                recorded_prove_ms: 1.6,
                recorded_verify_ms: 0.4,
                inferred_overhead_ms: 0.0,
            },
        ];
        write_text_file(&run_dir.join("source.csv"), &pcs_records_to_csv(&records))
            .expect("write PCS source CSV");
        write_text_file(&run_dir.join("source.json"), &pcs_records_to_json(&records))
            .expect("write PCS source JSON");
        write_text_file(
            &run_dir.join("summary_stats.csv"),
            &pcs_summary_stats_to_csv(&pcs_benchmark_stats(&records)),
        )
        .expect("write PCS summary CSV");
        write_pcs_benchmark_charts(&run_dir, &records).expect("write PCS charts");
        write_text_file(
            &run_dir.join("metadata.json"),
            &pcs_benchmark_metadata_json(1, &command, &records),
        )
        .expect("write PCS metadata");
        write_text_file(
            &run_dir.join("phase_timing.csv"),
            &phase_timing_to_csv(&timings),
        )
        .expect("write PCS phase CSV");
        write_text_file(
            &run_dir.join("phase_timing.json"),
            &phase_timing_to_json(&timings),
        )
        .expect("write PCS phase JSON");
        write_text_file(
            &run_dir.join("summary.txt"),
            &pcs_benchmark_summary(&command, &records, &timings),
        )
        .expect("write PCS summary");
        write_text_file(
            &run_dir.join(OVERVIEW_HTML),
            &pcs_benchmark_overview_html(1, &command, &records),
        )
        .expect("write PCS overview");
        let manifest = pcs_result_manifest_json(&run_dir, 1).expect("PCS manifest");
        write_text_file(&run_dir.join(RESULT_MANIFEST), &manifest).expect("write PCS manifest");

        let report = verify_pcs_result_dir(&run_dir).expect("verify PCS result fixture");
        assert_eq!(report.source_rows_checked, 2);
        assert_eq!(report.summary_rows_checked, 2);
        assert_eq!(report.phase_rows_checked, 6);
        fs::remove_dir_all(&run_dir).expect("cleanup PCS fixture");
    }

    #[test]
    fn scripts_directory_has_only_interactive_entrypoints() {
        let repo_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .and_then(Path::parent)
            .expect("repo root")
            .to_path_buf();
        let scripts_dir = repo_root.join("scripts");
        let mut names = fs::read_dir(&scripts_dir)
            .expect("scripts directory")
            .map(|entry| {
                entry
                    .expect("script entry")
                    .file_name()
                    .to_string_lossy()
                    .into_owned()
            })
            .collect::<Vec<_>>();
        names.sort();

        assert_eq!(
            names,
            vec![
                "interactive-linux.sh",
                "interactive-macos.sh",
                "interactive-powershell.cmd",
                "pcs-benchmark-linux.sh",
                "pcs-benchmark-macos.sh",
                "pcs-benchmark-powershell.cmd",
            ]
        );
    }

    #[test]
    fn pcs_scripts_offer_zero_exit_without_running_benchmark() {
        let repo_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .and_then(Path::parent)
            .expect("repo root")
            .to_path_buf();
        for script_name in [
            "pcs-benchmark-linux.sh",
            "pcs-benchmark-macos.sh",
            "pcs-benchmark-powershell.cmd",
        ] {
            let script = fs::read_to_string(repo_root.join("scripts").join(script_name))
                .expect("read PCS benchmark script");
            assert!(script.contains("Distributed Brakedown PCS benchmark"));
            assert!(script.contains("pcs-benchmark"));
            assert!(script.contains("0) Exit") || script.contains("0^) Exit"));
            assert!(script.contains("exit 0") || script.contains("exit /b 0"));
            assert!(script.contains("--opening"));
            assert!(script.contains("compact"));
            assert!(script.contains("--n-range"));
            assert!(script.contains("--worker-power-range"));
            assert!(script.contains("minimum PCS size exponent n for N=2^n"));
            assert!(script.contains("maximum PCS size exponent n for N=2^n"));
            assert!(script.contains("minimum worker exponent for workers=2^w"));
            assert!(script.contains("maximum worker exponent for workers=2^w"));
            assert!(!script.contains("--out"));
            assert!(!script.contains("[8,9,10]"));
            assert!(!script.contains("[1,2,4]"));
            assert!(!script.contains("[results]"));
        }
    }

    #[test]
    fn windows_cmd_embeds_powershell_payload_without_tools_directory() {
        let repo_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .and_then(Path::parent)
            .expect("repo root")
            .to_path_buf();
        let script_launcher =
            fs::read_to_string(repo_root.join("scripts").join("interactive-powershell.cmd"))
                .expect("read script PowerShell launcher");
        assert!(script_launcher.contains("# POWERSHELL_PAYLOAD_BEGIN"));
        assert!(script_launcher.contains("-ExecutionPolicy Bypass"));
        assert!(script_launcher.contains("target\\windows\\interactive-powershell-"));
        assert!(script_launcher.contains("if not defined NO_PAUSE pause"));
        assert!(script_launcher.contains("function Invoke-Menu"));
        assert!(!repo_root.join("tools").exists());
    }

    #[test]
    fn interactive_scripts_offer_dependency_install_from_actions() {
        let repo_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .and_then(Path::parent)
            .expect("repo root")
            .to_path_buf();
        let linux_script =
            fs::read_to_string(repo_root.join("scripts").join("interactive-linux.sh"))
                .expect("read linux interactive script");
        assert!(linux_script.contains("ensure_toolchain_for_action"));
        assert!(linux_script.contains("Install missing dependencies now"));
        assert!(linux_script.contains("Build debug pq-experiments now"));
        assert!(linux_script.contains("build_experiment_binary debug"));
        assert!(linux_script.contains("proof_wizard() {\n  ensure_toolchain_for_action false"));
        assert!(linux_script.contains("benchmark_wizard() {\n  ensure_toolchain_for_action false"));
        assert!(linux_script.contains("results_wizard() {\n  ensure_toolchain_for_action false"));
        assert!(!linux_script.contains("Use the full paper-quality benchmark grid"));
        assert!(!linux_script.contains("PCS query count"));
        assert!(!linux_script.contains("Compile paper figures after the run"));
        assert!(!linux_script.contains("Run this benchmark grid"));
        assert!(!linux_script.contains("suggested max worker exponent"));
        assert!(linux_script.contains(
            "prompt_text_hidden_default 'minimum circuit size exponent n for nv=2^n' '8'"
        ));
        assert!(linux_script.contains(
            "prompt_text_hidden_default 'maximum circuit size exponent n for nv=2^n' '10'"
        ));
        assert!(linux_script.contains("default_worker_max > 3"));
        assert!(
            linux_script.contains(
                "prompt_text_hidden_default 'minimum worker exponent for workers=2^w' '0'"
            )
        );
        assert!(
            linux_script
                .contains("prompt_text_hidden_default 'maximum worker exponent for workers=2^w'")
        );
        assert!(linux_script.contains("pcs_queries=\"1\""));
        assert!(linux_script.contains("PCS queries fixed at 1"));
        assert!(linux_script.contains("figure compilation is enabled by default"));
        assert!(linux_script.contains("--compile-figures --figure-compiler auto"));

        let powershell_script =
            fs::read_to_string(repo_root.join("scripts").join("interactive-powershell.cmd"))
                .expect("read embedded PowerShell interactive script");
        let powershell_script = powershell_script.replace("\r\n", "\n");
        assert!(powershell_script.contains("function Ensure-ToolchainForAction"));
        assert!(powershell_script.contains("Install missing dependencies now"));
        assert!(powershell_script.contains("Build debug pq-experiments now"));
        assert!(powershell_script.contains("Build-ExperimentBinary -Release:$false"));
        assert!(!powershell_script.contains("Use the full paper-quality benchmark grid"));
        assert!(!powershell_script.contains("PCS query count"));
        assert!(!powershell_script.contains("Compile paper figures after the run"));
        assert!(!powershell_script.contains("Run this benchmark grid"));
        assert!(!powershell_script.contains("suggested max worker exponent"));
        assert!(powershell_script.contains("function Read-TextWithHiddenDefault"));
        assert!(powershell_script.contains(
            "Read-TextWithHiddenDefault -Prompt \"minimum circuit size exponent n for nv=2^n\" -Default \"8\""
        ));
        assert!(powershell_script.contains(
            "Read-TextWithHiddenDefault -Prompt \"maximum circuit size exponent n for nv=2^n\" -Default \"10\""
        ));
        assert!(powershell_script.contains("[Math]::Min([Math]::Min($hostWorkerMax, $nMin), 3)"));
        assert!(powershell_script.contains(
            "Read-TextWithHiddenDefault -Prompt \"minimum worker exponent for workers=2^w\" -Default \"0\""
        ));
        assert!(powershell_script.contains(
            "Read-TextWithHiddenDefault -Prompt \"maximum worker exponent for workers=2^w\""
        ));
        assert!(powershell_script.contains("$pcsQueries = \"1\""));
        assert!(powershell_script.contains("PCS queries fixed at 1"));
        assert!(powershell_script.contains("figure compilation is enabled by default"));
        assert!(powershell_script.contains("--compile-figures\", \"--figure-compiler\", \"auto"));
        assert!(powershell_script.contains("choose menu option 1"));
        assert!(!powershell_script.contains("choose menu option 2"));
        assert!(
            powershell_script
                .contains("function Invoke-ProofWizard {\n    Ensure-ToolchainForAction")
        );
        assert!(
            powershell_script
                .contains("function Invoke-BenchmarkWizard {\n    Ensure-ToolchainForAction")
        );
        assert!(
            powershell_script
                .contains("function Invoke-ResultsWizard {\n    Ensure-ToolchainForAction")
        );
    }

    #[test]
    fn current_user_docs_do_not_reference_removed_script_entries() {
        let repo_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .and_then(Path::parent)
            .expect("repo root")
            .to_path_buf();
        let docs = [
            repo_root.join("README.md"),
            repo_root.join("Doc").join("reproducibility_runbook.md"),
            repo_root.join("results").join("README.md"),
            repo_root
                .join("results")
                .join("release_results")
                .join("README.md"),
        ];
        let removed = [
            "run_benchmarks.ps1",
            "run_benchmarks.sh",
            "run_experiments.ps1",
            "run_experiments.sh",
            "verify_results.ps1",
            "verify_results.sh",
            "publish-results",
            "Verify/publish results",
        ];
        for path in docs {
            let text = fs::read_to_string(&path)
                .unwrap_or_else(|error| panic!("read {} failed: {error}", path.display()));
            for needle in removed {
                assert!(
                    !text.contains(needle),
                    "{} still references removed entry '{}'",
                    path.display(),
                    needle
                );
            }
        }
    }

    #[test]
    fn ci_guards_fresh_clone_quick_smoke() {
        let repo_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .and_then(Path::parent)
            .expect("repo root")
            .to_path_buf();
        let ci = fs::read_to_string(repo_root.join(".github").join("workflows").join("ci.yml"))
            .expect("read CI workflow");
        assert!(ci.contains("macOS quick smoke"));
        assert!(ci.contains("cargo run -p pq-experiments -- quick-smoke"));
        assert!(ci.contains("proofs_verified"));
        assert!(ci.contains("verify_report_html"));
    }

    #[test]
    fn gitignore_preserves_scratch_vs_release_result_split() {
        let repo_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .and_then(Path::parent)
            .expect("repo root")
            .to_path_buf();
        let gitignore = fs::read_to_string(repo_root.join(".gitignore")).expect("read .gitignore");
        assert!(gitignore.contains("/target/"));
        assert!(gitignore.contains("/results/bench-*/"));
        assert!(gitignore.contains("!/results/release_results/"));
        assert!(gitignore.contains("!/results/release_results/**"));
        assert!(gitignore.contains("*.log"));
        assert!(
            gitignore.find("/results/bench-*/").expect("bench ignore")
                < gitignore
                    .find("!/results/release_results/**")
                    .expect("release unignore"),
            "release_results unignore must appear after scratch bench ignore"
        );
    }

    #[test]
    fn parses_verify_results_command_flags() {
        let command = parse_verify_results_command(&[
            "--dir".to_owned(),
            "results/bench-1".to_owned(),
            "--format".to_owned(),
            "csv".to_owned(),
            "--paper-quality".to_owned(),
        ])
        .expect("verify-results command");
        assert_eq!(command.dir, PathBuf::from("results/bench-1"));
        assert_eq!(command.format, OutputFormat::Csv);
        assert!(command.paper_quality);

        let positional =
            parse_verify_results_command(&["results/bench-2".to_owned()]).expect("positional dir");
        assert_eq!(positional.dir, PathBuf::from("results/bench-2"));
        assert_eq!(positional.format, OutputFormat::Json);
        assert!(!positional.paper_quality);

        let pcs = parse_verify_pcs_results_command(&[
            "--dir".to_owned(),
            "results/pcs-bench-1".to_owned(),
            "--format".to_owned(),
            "csv".to_owned(),
        ])
        .expect("verify-pcs-results command");
        assert_eq!(pcs.dir, PathBuf::from("results/pcs-bench-1"));
        assert_eq!(pcs.format, OutputFormat::Csv);
        assert!(!pcs.paper_quality);

        let pcs_paper_quality = parse_verify_pcs_results_command(&[
            "--dir".to_owned(),
            "results/pcs-bench-1".to_owned(),
            "--paper-quality".to_owned(),
        ])
        .expect_err("PCS verifier rejects proof-benchmark-only flag");
        assert!(
            pcs_paper_quality
                .0
                .contains("unknown verify-pcs-results argument")
        );
    }

    #[test]
    fn parses_quick_smoke_command_flags() {
        let default = parse_quick_smoke_command(&[]).expect("default quick smoke");
        assert_eq!(default.out_dir, PathBuf::from("target/quick-smoke"));

        let custom =
            parse_quick_smoke_command(&["--out".to_owned(), "target/fresh-clone-smoke".to_owned()])
                .expect("custom quick smoke");
        assert_eq!(custom.out_dir, PathBuf::from("target/fresh-clone-smoke"));

        let error = parse_quick_smoke_command(&["--workers".to_owned(), "2".to_owned()])
            .expect_err("quick-smoke should keep the smoke grid fixed");
        assert!(error.0.contains("unknown quick-smoke argument"));
    }

    #[test]
    fn parses_proof_storage_commands() {
        let proof = parse_proof_experiment_command(&[
            "--protocol".to_owned(),
            "both".to_owned(),
            "--runner".to_owned(),
            "network".to_owned(),
            "--n".to_owned(),
            "5".to_owned(),
            "--workers".to_owned(),
            "4".to_owned(),
            "--pcs-queries".to_owned(),
            "2".to_owned(),
            "--out".to_owned(),
            "results".to_owned(),
            "--format".to_owned(),
            "csv".to_owned(),
        ])
        .expect("proof-experiment command");
        assert_eq!(proof.protocol, ProofProtocolSelection::Both);
        assert_eq!(proof.runner, BenchmarkRunner::Network);
        assert_eq!(proof.size, 32);
        assert_eq!(proof.workers, 4);
        assert_eq!(proof.pcs_queries, 2);
        assert_eq!(proof.format, OutputFormat::Csv);

        let list = parse_list_proofs_command(&[
            "--results".to_owned(),
            "target/proofs".to_owned(),
            "--format".to_owned(),
            "json".to_owned(),
        ])
        .expect("list-proofs command");
        assert_eq!(list.results_dir, PathBuf::from("target/proofs"));
        assert_eq!(list.format, ProofListFormat::Json);

        let verify = parse_verify_proof_command(&[
            "results/bench-20260601-010203-performance".to_owned(),
            "--proof".to_owned(),
            "network-r1cs-positive-n2-w2-q1-trial1".to_owned(),
            "--format".to_owned(),
            "csv".to_owned(),
        ])
        .expect("verify-proof command");
        assert_eq!(
            verify.dir,
            PathBuf::from("results/bench-20260601-010203-performance")
        );
        assert!(matches!(verify.proof, ProofSelection::One(_)));
        assert_eq!(verify.format, OutputFormat::Csv);
    }

    #[test]
    fn result_manifest_includes_proof_artifacts_with_hashes() {
        let manifest_dir = temp_test_dir("pq_dsnark_proof_manifest_test");
        fs::create_dir_all(&manifest_dir).expect("manifest temp dir");
        for artifact in benchmark_artifacts(false) {
            if artifact != RESULT_MANIFEST {
                write_text_file(
                    &manifest_dir.join(artifact),
                    &format!("test artifact {artifact}\n"),
                )
                .expect("write base artifact");
            }
        }

        let proofs_dir = manifest_dir.join("proofs");
        fs::create_dir_all(&proofs_dir).expect("proofs dir");
        let proof_bytes = br#"{"schema_version":1,"proof_id":"minimal-indexed"}"#;
        let index_bytes = br#"{"schema_version":1,"generated_by":"pq-experiments proof index","proof_count":1,"proofs":[]}"#;
        fs::write(proofs_dir.join("minimal-indexed.proof.json"), proof_bytes)
            .expect("write proof bundle");
        fs::write(proofs_dir.join("index.json"), index_bytes).expect("write proof index");

        let manifest = benchmark_result_manifest_json(&manifest_dir, 789, false).expect("manifest");
        assert!(manifest.contains(&format!(
            "\"path\":\"proofs/minimal-indexed.proof.json\",\"bytes\":{},\"sha256\":\"{}\"",
            proof_bytes.len(),
            hex_digest(sha256(proof_bytes))
        )));
        assert!(manifest.contains(&format!(
            "\"path\":\"proofs/index.json\",\"bytes\":{},\"sha256\":\"{}\"",
            index_bytes.len(),
            hex_digest(sha256(index_bytes))
        )));
        write_text_file(&manifest_dir.join(RESULT_MANIFEST), &manifest).expect("write manifest");

        let report =
            verify_benchmark_result_manifest(&manifest_dir).expect("verify proof manifest");
        assert_eq!(report.run_id, 789);
        assert_eq!(
            report.files_checked,
            benchmark_artifacts(false).len() - 1 + 2
        );

        fs::remove_dir_all(&manifest_dir).expect("cleanup proof manifest temp dir");
    }

    #[test]
    fn proof_reverification_reports_do_not_pollute_benchmark_verification() {
        let run_dir = temp_test_dir("bench-pq_dsnark_verify_pollution_test");
        fs::create_dir_all(&run_dir).expect("pollution temp dir");
        let config = Config {
            protocol: Protocol::R1cs,
            workers: 1,
            size: 4,
            format: OutputFormat::Json,
            case: CaseSelection::Positive,
            pcs_queries: 1,
            worker_core_plan: None,
        };
        let output = run_single_positive_job(BenchmarkRunner::Local, Protocol::R1cs, &config, None)
            .expect("positive R1CS proof job");
        let mut plonkish_record = output.record.clone();
        plonkish_record.protocol = "plonkish";
        plonkish_record.constraints = 16;
        plonkish_record.prove_ms += 1.0;
        plonkish_record.verify_ms += 1.0;
        plonkish_record.proof_bytes += 10;
        plonkish_record.stages.prove_other_ms += 1.0;
        plonkish_record.stages.verify_other_ms += 1.0;
        plonkish_record.stages.proof_other_bytes += 10;
        plonkish_record.communication_bytes += 10;
        let records = vec![output.record.clone(), plonkish_record];
        let timings = vec![
            PhaseTimingRecord {
                phase: "setup".to_owned(),
                detail: "test setup".to_owned(),
                elapsed_ms: 0.1,
                recorded_prove_ms: 0.0,
                recorded_verify_ms: 0.0,
                inferred_overhead_ms: 0.1,
            },
            PhaseTimingRecord {
                phase: "job".to_owned(),
                detail: "runner=local protocol=r1cs n=2 nv=4 workers=1".to_owned(),
                elapsed_ms: output.record.prove_ms + output.record.verify_ms,
                recorded_prove_ms: output.record.prove_ms,
                recorded_verify_ms: output.record.verify_ms,
                inferred_overhead_ms: 0.0,
            },
            PhaseTimingRecord {
                phase: "job".to_owned(),
                detail: "runner=local protocol=plonkish n=2 nv=4 workers=1".to_owned(),
                elapsed_ms: records[1].prove_ms + records[1].verify_ms,
                recorded_prove_ms: records[1].prove_ms,
                recorded_verify_ms: records[1].verify_ms,
                inferred_overhead_ms: 0.0,
            },
            PhaseTimingRecord {
                phase: "source_and_chart_artifacts".to_owned(),
                detail: "charts".to_owned(),
                elapsed_ms: 1.0,
                recorded_prove_ms: 0.0,
                recorded_verify_ms: 0.0,
                inferred_overhead_ms: 1.0,
            },
            PhaseTimingRecord {
                phase: "final_result_artifacts".to_owned(),
                detail: "final".to_owned(),
                elapsed_ms: 1.0,
                recorded_prove_ms: 0.0,
                recorded_verify_ms: 0.0,
                inferred_overhead_ms: 1.0,
            },
            PhaseTimingRecord {
                phase: "total".to_owned(),
                detail: "total".to_owned(),
                elapsed_ms: output.record.prove_ms + output.record.verify_ms + 3.1,
                recorded_prove_ms: output.record.prove_ms + records[1].prove_ms,
                recorded_verify_ms: output.record.verify_ms + records[1].verify_ms,
                inferred_overhead_ms: 2.1,
            },
        ];
        let command = BenchmarkCommand {
            sizes: vec![4],
            workers: vec![1],
            pcs_queries: 1,
            repeats: 1,
            paper_preset: false,
            runner: BenchmarkRunner::Local,
            compile_figures: false,
            figure_compiler: FigureCompiler::Auto,
            out_dir: PathBuf::from("results"),
            host_logical_cores: None,
            worker_cores: None,
            worker_core_plan: None,
        };
        write_base_benchmark_fixture(&run_dir, 790, &command, &records, &timings)
            .expect("write benchmark fixture");
        let proof_entry = write_proof_bundle(
            &run_dir,
            "performance-benchmark",
            &output.record,
            output.proof,
            "2026-06-01T00:00:00Z".to_owned(),
        )
        .expect("write proof bundle");
        write_proof_index(&run_dir, &[proof_entry]).expect("write proof index");
        let manifest =
            benchmark_result_manifest_json(&run_dir, 790, false).expect("write manifest");
        write_text_file(&run_dir.join(RESULT_MANIFEST), &manifest).expect("write manifest");

        let before =
            verify_benchmark_result_dir(&run_dir).expect("verify benchmark before proof report");
        let proof_report = verify_stored_proofs(&VerifyProofCommand {
            dir: run_dir.clone(),
            proof: ProofSelection::All,
            format: OutputFormat::Json,
        })
        .expect("verify stored proof");
        assert_eq!(proof_report.outcomes.len(), 1);
        assert_eq!(
            proof_report
                .outcomes
                .iter()
                .filter(|outcome| outcome.verified)
                .count(),
            1
        );
        assert!(
            proof_report
                .report_json
                .starts_with(run_dir.join("verifications"))
        );
        assert!(
            proof_report
                .report_html
                .starts_with(run_dir.join("verifications"))
        );

        let after =
            verify_benchmark_result_dir(&run_dir).expect("verify benchmark after proof report");
        assert_eq!(after.files_checked, before.files_checked);
        assert_eq!(after.bytes_checked, before.bytes_checked);
        assert_eq!(after.source_rows_checked, before.source_rows_checked);
        assert_eq!(after.phase_rows_checked, before.phase_rows_checked);
        assert_eq!(after.summary_rows_checked, before.summary_rows_checked);

        fs::remove_dir_all(&run_dir).expect("cleanup verify pollution temp dir");
    }

    #[test]
    fn list_proofs_reports_corrupt_proof_files_without_failing() {
        let results_dir = temp_test_dir("pq_dsnark_list_corrupt_proofs_test");
        let bench_dir = results_dir.join("bench-20260601-010203-proof");
        fs::create_dir_all(bench_dir.join("proofs")).expect("proofs dir");
        let proof_file = bench_dir.join("proofs").join("corrupt.proof.json");
        fs::write(&proof_file, b"{not valid json").expect("write corrupt proof");

        let entries = discover_proof_benches(&results_dir).expect("discover corrupt proof bench");
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].proof_count, 1);
        assert_eq!(entries[0].invalid_proof_count, 1);
        assert_eq!(entries[0].proof_ids, vec!["corrupt.proof.json [invalid]"]);

        let json = proof_list_to_json(&entries);
        assert!(json.contains("\"invalid_proof_count\":1"));
        assert!(json.contains("corrupt.proof.json [invalid]"));

        fs::remove_dir_all(&results_dir).expect("cleanup corrupt proof list temp dir");
    }

    #[test]
    fn verify_proof_command_fails_when_stored_proof_is_tampered() {
        let run_dir = env::temp_dir().join(format!(
            "pq_dsnark_stored_proof_tamper_test_{}",
            SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .expect("clock")
                .as_nanos()
        ));
        fs::create_dir_all(&run_dir).expect("stored proof temp dir");

        let config = Config {
            protocol: Protocol::R1cs,
            workers: 1,
            size: 4,
            format: OutputFormat::Json,
            case: CaseSelection::Positive,
            pcs_queries: 1,
            worker_core_plan: None,
        };
        let output = run_single_positive_job(BenchmarkRunner::Local, Protocol::R1cs, &config, None)
            .expect("positive R1CS proof job");
        let proof_entry = write_proof_bundle(
            &run_dir,
            "unit-test",
            &output.record,
            output.proof,
            "2026-06-01T00:00:00Z".to_owned(),
        )
        .expect("write proof bundle");
        let proof_id = proof_entry.proof_id.clone();
        write_proof_index(&run_dir, &[proof_entry]).expect("write proof index");

        let good_report = verify_stored_proofs(&VerifyProofCommand {
            dir: run_dir.clone(),
            proof: ProofSelection::All,
            format: OutputFormat::Json,
        })
        .expect("verify intact stored proof");
        assert_eq!(good_report.outcomes.len(), 1);
        assert!(good_report.outcomes[0].verified);

        let proof_path = run_dir
            .join("proofs")
            .join(format!("{proof_id}.proof.json"));
        let mut bundle = read_proof_bundle(&proof_path).expect("read stored proof bundle");
        match &mut bundle.proof {
            StoredProof::R1cs(proof) => {
                let tampered = tamper_r1cs_proof(proof).expect("tamper R1CS proof");
                **proof = tampered;
            }
            StoredProof::Plonkish(_) => panic!("test wrote an R1CS proof bundle"),
        }
        let tampered_bytes =
            serde_json::to_vec(&bundle).expect("serialize tampered stored proof bundle");
        fs::write(&proof_path, tampered_bytes).expect("overwrite stored proof bundle");

        let tampered_report = verify_stored_proofs(&VerifyProofCommand {
            dir: run_dir.clone(),
            proof: ProofSelection::One(proof_id.clone()),
            format: OutputFormat::Json,
        })
        .expect("tampered stored proof still produces a report");
        assert_eq!(tampered_report.outcomes.len(), 1);
        assert!(!tampered_report.outcomes[0].verified);
        assert!(tampered_report.outcomes[0].failure_reason.is_some());

        let error = run_verify_proof_command(&[
            run_dir.display().to_string(),
            "--proof".to_owned(),
            proof_id,
            "--format".to_owned(),
            "json".to_owned(),
        ])
        .expect_err("tampered proof command must exit with an error");
        assert!(error.0.contains("stored proof verification failed"));

        assert!(run_dir.join("verifications").is_dir());
        fs::remove_dir_all(&run_dir).expect("cleanup stored proof temp dir");
    }

    #[test]
    fn verify_proof_command_fails_when_stored_metadata_is_tampered() {
        let run_dir = env::temp_dir().join(format!(
            "pq_dsnark_stored_metadata_tamper_test_{}",
            SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .expect("clock")
                .as_nanos()
        ));
        fs::create_dir_all(&run_dir).expect("stored metadata temp dir");

        let config = Config {
            protocol: Protocol::R1cs,
            workers: 1,
            size: 4,
            format: OutputFormat::Json,
            case: CaseSelection::Positive,
            pcs_queries: 1,
            worker_core_plan: None,
        };
        let output = run_single_positive_job(BenchmarkRunner::Local, Protocol::R1cs, &config, None)
            .expect("positive R1CS proof job");
        let proof_entry = write_proof_bundle(
            &run_dir,
            "unit-test",
            &output.record,
            output.proof,
            "2026-06-01T00:00:00Z".to_owned(),
        )
        .expect("write proof bundle");
        let proof_id = proof_entry.proof_id.clone();
        write_proof_index(&run_dir, &[proof_entry]).expect("write proof index");

        let proof_path = run_dir
            .join("proofs")
            .join(format!("{proof_id}.proof.json"));
        let mut bundle = read_proof_bundle(&proof_path).expect("read stored proof bundle");
        bundle.proof_bytes += 1;
        let tampered_bytes =
            serde_json::to_vec(&bundle).expect("serialize metadata-tampered proof bundle");
        fs::write(&proof_path, tampered_bytes).expect("overwrite stored proof bundle");

        let report = verify_stored_proofs(&VerifyProofCommand {
            dir: run_dir.clone(),
            proof: ProofSelection::All,
            format: OutputFormat::Json,
        })
        .expect("metadata-tampered stored proof still produces a report");
        assert_eq!(report.outcomes.len(), 1);
        assert!(!report.outcomes[0].verified);
        let reason = report.outcomes[0]
            .failure_reason
            .as_deref()
            .expect("metadata failure reason");
        assert!(reason.contains("Metadata(proof_bytes"));
        assert!(reason.contains("ProofIndex(sha256"));

        let error = run_verify_proof_command(&[
            run_dir.display().to_string(),
            "--all".to_owned(),
            "--format".to_owned(),
            "json".to_owned(),
        ])
        .expect_err("metadata-tampered proof command must exit with an error");
        assert!(error.0.contains("stored proof verification failed"));

        assert!(run_dir.join("verifications").is_dir());
        fs::remove_dir_all(&run_dir).expect("cleanup stored metadata temp dir");
    }

    #[test]
    fn verify_proof_command_reports_corrupt_stored_proof_json() {
        let run_dir = env::temp_dir().join(format!(
            "pq_dsnark_corrupt_stored_proof_test_{}",
            SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .expect("clock")
                .as_nanos()
        ));
        fs::create_dir_all(&run_dir).expect("corrupt proof temp dir");

        let config = Config {
            protocol: Protocol::R1cs,
            workers: 1,
            size: 4,
            format: OutputFormat::Json,
            case: CaseSelection::Positive,
            pcs_queries: 1,
            worker_core_plan: None,
        };
        let output = run_single_positive_job(BenchmarkRunner::Local, Protocol::R1cs, &config, None)
            .expect("positive R1CS proof job");
        let proof_entry = write_proof_bundle(
            &run_dir,
            "unit-test",
            &output.record,
            output.proof,
            "2026-06-01T00:00:00Z".to_owned(),
        )
        .expect("write proof bundle");
        let proof_id = proof_entry.proof_id.clone();
        write_proof_index(&run_dir, &[proof_entry]).expect("write proof index");

        let proof_path = run_dir
            .join("proofs")
            .join(format!("{proof_id}.proof.json"));
        fs::write(&proof_path, b"{not valid json").expect("overwrite proof with corrupt json");

        let report = verify_stored_proofs(&VerifyProofCommand {
            dir: run_dir.clone(),
            proof: ProofSelection::All,
            format: OutputFormat::Json,
        })
        .expect("corrupt stored proof still produces a report");
        assert_eq!(report.outcomes.len(), 1);
        assert!(!report.outcomes[0].verified);
        assert_eq!(report.outcomes[0].protocol, "unknown");
        assert!(
            report.outcomes[0]
                .failure_reason
                .as_deref()
                .expect("corrupt proof failure reason")
                .contains("ProofBundle(parse proof bundle")
        );
        assert!(report.report_json.exists());
        assert!(report.report_html.exists());

        let error = run_verify_proof_command(&[
            run_dir.display().to_string(),
            "--all".to_owned(),
            "--format".to_owned(),
            "json".to_owned(),
        ])
        .expect_err("corrupt proof command must exit with an error after reporting");
        assert!(error.0.contains("stored proof verification failed"));

        fs::remove_dir_all(&run_dir).expect("cleanup corrupt proof temp dir");
    }

    #[test]
    fn unix_timestamp_label_is_second_precision_utc() {
        assert_eq!(
            unix_timestamp_label(0).expect("epoch label"),
            "19700101-000000"
        );
        assert_eq!(
            unix_timestamp_label(1_780_308_024).expect("sample label"),
            "20260601-100024"
        );
    }

    #[test]
    fn parses_benchmark_nv_power_flags() {
        let explicit = parse_benchmark_command(&[
            "--nv-powers".to_owned(),
            "2,4,3".to_owned(),
            "--workers".to_owned(),
            "1,2".to_owned(),
        ])
        .expect("explicit powers");
        assert_eq!(explicit.sizes, vec![4, 8, 16]);

        let ranged = parse_benchmark_command(&[
            "--nv-range".to_owned(),
            "2..4".to_owned(),
            "--workers".to_owned(),
            "1,2".to_owned(),
        ])
        .expect("range powers");
        assert_eq!(ranged.sizes, vec![4, 8, 16]);

        let n_aliases = parse_benchmark_command(&[
            "--n-values".to_owned(),
            "3,2".to_owned(),
            "--n-range".to_owned(),
            "2..3".to_owned(),
            "--workers".to_owned(),
            "1".to_owned(),
        ])
        .expect("n aliases");
        assert_eq!(n_aliases.sizes, vec![4, 8]);
    }

    #[test]
    fn benchmark_requires_single_worker_baseline() {
        let error = parse_benchmark_command(&[
            "--nv-range".to_owned(),
            "2..4".to_owned(),
            "--workers".to_owned(),
            "2,4".to_owned(),
        ])
        .expect_err("missing worker=1 baseline should fail");
        assert!(error.0.contains("must include 1"));
    }

    #[test]
    fn benchmark_job_validation_rejects_bad_case_outcomes() {
        let positive = MetricRecord {
            protocol: "r1cs",
            runner: "local",
            case_name: "positive",
            trial: 1,
            workers: 1,
            size: 4,
            constraints: 4,
            prove_ms: 10.0,
            verify_ms: 2.0,
            stages: test_stage_breakdown(10.0, 2.0, 100),
            proof_bytes: 100,
            communication_bytes: 50,
            network_bytes: 0,
            pcs_queries: 3,
            host_logical_cores: None,
            cores_per_worker: None,
            core_affinity: None,
            verified: true,
            failure_reason: None,
        };
        let negative = MetricRecord {
            protocol: "r1cs",
            runner: "local",
            case_name: "negative",
            trial: 1,
            workers: 1,
            size: 4,
            constraints: 4,
            prove_ms: 11.0,
            verify_ms: 2.5,
            stages: test_stage_breakdown(11.0, 2.5, 100),
            proof_bytes: 100,
            communication_bytes: 50,
            network_bytes: 0,
            pcs_queries: 3,
            host_logical_cores: None,
            cores_per_worker: None,
            core_affinity: None,
            verified: false,
            failure_reason: Some("Pcs".to_owned()),
        };
        assert!(
            validate_benchmark_job_records(
                Protocol::R1cs,
                4,
                1,
                1,
                std::slice::from_ref(&positive)
            )
            .is_ok()
        );

        let mut bad_positive = positive.clone();
        bad_positive.verified = false;
        bad_positive.failure_reason = Some("InvalidProof".to_owned());
        let error = validate_benchmark_job_records(Protocol::R1cs, 4, 1, 1, &[bad_positive])
            .expect_err("positive verification failure should stop benchmark");
        assert!(error.0.contains("expected exactly one verified positive"));

        let error = validate_benchmark_job_records(Protocol::R1cs, 4, 1, 1, &[positive, negative])
            .expect_err("negative correctness records must not enter benchmark");
        assert!(error.0.contains("no negative correctness records"));
    }

    #[test]
    fn benchmark_charts_are_svg_and_pgfplots_with_real_series() {
        let records = vec![
            MetricRecord {
                protocol: "r1cs",
                runner: "local",
                case_name: "positive",
                trial: 1,
                workers: 1,
                size: 4,
                constraints: 4,
                prove_ms: 10.0,
                verify_ms: 2.0,
                stages: test_stage_breakdown(10.0, 2.0, 100),
                proof_bytes: 100,
                communication_bytes: 50,
                network_bytes: 0,
                pcs_queries: 3,
                host_logical_cores: None,
                cores_per_worker: None,
                core_affinity: None,
                verified: true,
                failure_reason: None,
            },
            MetricRecord {
                protocol: "r1cs",
                runner: "local",
                case_name: "positive",
                trial: 1,
                workers: 2,
                size: 4,
                constraints: 4,
                prove_ms: 6.0,
                verify_ms: 2.0,
                stages: test_stage_breakdown(6.0, 2.0, 110),
                proof_bytes: 110,
                communication_bytes: 60,
                network_bytes: 0,
                pcs_queries: 3,
                host_logical_cores: None,
                cores_per_worker: None,
                core_affinity: None,
                verified: true,
                failure_reason: None,
            },
            MetricRecord {
                protocol: "r1cs",
                runner: "local",
                case_name: "positive",
                trial: 2,
                workers: 1,
                size: 4,
                constraints: 4,
                prove_ms: 14.0,
                verify_ms: 4.0,
                stages: test_stage_breakdown(14.0, 4.0, 100),
                proof_bytes: 100,
                communication_bytes: 50,
                network_bytes: 0,
                pcs_queries: 3,
                host_logical_cores: None,
                cores_per_worker: None,
                core_affinity: None,
                verified: true,
                failure_reason: None,
            },
            MetricRecord {
                protocol: "r1cs",
                runner: "network",
                case_name: "positive",
                trial: 1,
                workers: 1,
                size: 4,
                constraints: 4,
                prove_ms: 20.0,
                verify_ms: 5.0,
                stages: test_stage_breakdown(20.0, 5.0, 100),
                proof_bytes: 100,
                communication_bytes: 50,
                network_bytes: 4096,
                pcs_queries: 3,
                host_logical_cores: Some(8),
                cores_per_worker: Some(2),
                core_affinity: Some(worker_affinity_mode()),
                verified: true,
                failure_reason: None,
            },
        ];

        let chart = worker_scaling_svg(&records);
        assert!(chart.starts_with("<svg"));
        assert!(chart.contains("Perfect upper bound"));
        assert!(chart.contains("Serial+overhead diagnostic"));
        assert!(chart.contains("class=\"diagnostic-line\""));
        assert!(chart.contains("R1CS"));
        assert!(chart.contains("class=\"series-line\""));

        let tex_chart = line_chart_pgfplots(
            &records,
            "Prove time by circuit size",
            "Prover time (ms)",
            BenchmarkMetric::ProveMs,
        );
        assert!(tex_chart.contains("\\begin{tikzpicture}"));
        assert!(tex_chart.contains("\\addplot+"));
        assert!(tex_chart.contains("error bars/.cd"));
        assert!(tex_chart.contains("+- (0,"));
        assert!(tex_chart.contains("source.csv"));
        assert!(tex_chart.contains("\\addlegendentry{R1CS, w=1}"));

        let scaling_tex = worker_scaling_pgfplots(&records);
        assert!(scaling_tex.contains("Perfect upper bound"));
        assert!(scaling_tex.contains("Serial+overhead diagnostic"));
        assert!(scaling_tex.contains("densely dotted"));
        assert!(scaling_tex.contains("pqR1CS"));
        assert!(scaling_tex.contains("(2, 2)"));
        let scaling = worker_scaling_context(&records);
        let local_scaling = scaling
            .series
            .iter()
            .find(|series| series.runner == "local" && series.protocol == "r1cs")
            .expect("local R1CS scaling series");
        let local_serial_overhead = local_scaling
            .serial_overhead
            .expect("local R1CS should have a two-worker diagnostic");
        assert!(local_serial_overhead.abs() < 0.0001);

        let overhead = runner_overhead_points(&records);
        assert_eq!(overhead.len(), 1);
        assert!((overhead[0].overhead - (20.0 / 12.0)).abs() < 0.0001);
        let overhead_svg = runner_overhead_svg(&records);
        assert!(overhead_svg.contains("Network runner overhead"));
        assert!(overhead_svg.contains("Parity"));
        let overhead_tex = runner_overhead_pgfplots(&records);
        assert!(overhead_tex.contains("Network/local prover time"));
        assert!(overhead_tex.contains("\\addlegendentry{Parity}"));

        let paper_tex = paper_figures_pgfplots(&records);
        assert!(paper_tex.contains("\\begin{groupplot}"));
        assert!(paper_tex.contains("\\pgfplotslegendfromname{pqPaperLegend}"));
        assert!(paper_tex.contains("(a) Proving time"));
        assert!(paper_tex.contains("(d) Worker scaling"));
        assert!(paper_tex.contains("Serial+overhead diagnostic"));
        assert!(paper_tex.contains("error bars/.cd"));

        let source_csv = records_to_csv(&records);
        assert!(source_csv.starts_with("protocol,runner,case,trial,workers"));
        assert!(source_csv.contains("r1cs,local,positive,2,1,2,4"));

        let standalone = paper_figures_standalone_tex();
        assert!(standalone.contains("\\documentclass[tikz,border=3pt]{standalone}"));
        assert!(standalone.contains("\\input{paper_figures.tex}"));

        let overview_command = BenchmarkCommand {
            sizes: vec![4],
            workers: vec![1, 2],
            pcs_queries: 3,
            repeats: 1,
            paper_preset: false,
            runner: BenchmarkRunner::Both,
            compile_figures: false,
            figure_compiler: FigureCompiler::Auto,
            out_dir: PathBuf::from("results"),
            host_logical_cores: Some(8),
            worker_cores: Some(2),
            worker_core_plan: Some(WorkerCorePlan {
                host_logical_cores: 8,
                max_workers: 2,
                cores_per_worker: 4,
            }),
        };
        let overview = benchmark_overview_html(123, &overview_command, &records, false);
        assert!(overview.contains("<!doctype html>"));
        assert!(overview.contains("pq_dSNARK benchmark overview"));
        assert!(overview.contains("source.csv"));
        assert!(overview.contains("worker_scaling_max_size.svg"));
        assert!(overview.contains("Core Allocation"));
        assert!(overview.contains("serial+overhead"));
        assert!(overview.contains("scaling visible"));
        assert!(overview.contains("All positive performance proofs verified"));

        let provenance = BenchmarkProvenance::capture();
        let metadata = benchmark_metadata_json(
            123,
            &BenchmarkCommand {
                sizes: vec![4],
                workers: vec![1, 2],
                pcs_queries: 3,
                repeats: 1,
                paper_preset: false,
                runner: BenchmarkRunner::Local,
                compile_figures: false,
                figure_compiler: FigureCompiler::Auto,
                out_dir: PathBuf::from("results"),
                host_logical_cores: None,
                worker_cores: None,
                worker_core_plan: None,
            },
            &records,
            false,
            &provenance,
        );
        assert!(metadata.contains("\"run_id\": 123"));
        assert!(metadata.contains("\"schema_version\": 7"));
        assert!(metadata.contains("\"paper_preset\": false"));
        assert!(metadata.contains("\"runner\": \"local\""));
        assert!(metadata.contains("\"figure_compiler\": \"auto\""));
        assert!(metadata.contains("\"compile_figures_requested\": false"));
        assert!(metadata.contains("\"compile_figures_succeeded\": false"));
        assert!(metadata.contains("\"build_profile\": \""));
        assert!(metadata.contains("\"nv_powers\": [2]"));
        assert!(metadata.contains("\"overview.html\""));
        assert!(metadata.contains("\"phase_timing.csv\""));
        assert!(metadata.contains("\"phase_timing.json\""));
        assert!(metadata.contains("\"paper_figures.tex\""));
        assert!(metadata.contains("\"summary_stats.csv\""));
        assert!(metadata.contains("\"result_manifest.json\""));
        assert!(metadata.contains("\"network_bytes_by_size.tex\""));
        assert!(metadata.contains("\"runner_overhead_by_size.tex\""));
        assert!(metadata.contains("\"core_allocation\": null"));
        assert!(metadata.contains("\"provenance\""));
        assert!(metadata.contains("\"git_commit\""));
        assert!(metadata.contains("\"rustc_version\""));
        assert!(metadata.contains("\"cargo_lock_sha256\""));
        assert!(metadata.contains("\"rust_toolchain_sha256\""));
        assert!(metadata.contains("\"third_party_spartan2_commit\""));
        assert!(metadata.contains("\"repeats\": 1"));
        assert!(metadata.contains("\"negative_rejected\": 0"));
        assert_eq!(
            parse_pinned_commit(
                "# Third-Party Pins\n\n## Spartan2\n\n- Pinned commit: `0d4f1409e8f30536b8b25ed3f81bc446ed717e61`\n\n## HyperPlonk\n\n- Pinned commit: `2a3b55c97ad8a5d6627108a2e7def2aeccb7f3b9`\n",
                "Spartan2"
            ),
            Some("0d4f1409e8f30536b8b25ed3f81bc446ed717e61".to_owned())
        );
        assert_eq!(
            parse_pinned_commit(
                "# Third-Party Pins\n\n## Spartan2\n\n- Pinned commit: `0d4f1409e8f30536b8b25ed3f81bc446ed717e61`\n\n## HyperPlonk\n\n- Pinned commit: `2a3b55c97ad8a5d6627108a2e7def2aeccb7f3b9`\n",
                "HyperPlonk"
            ),
            Some("2a3b55c97ad8a5d6627108a2e7def2aeccb7f3b9".to_owned())
        );
        assert!(benchmark_artifacts(false).contains(&OVERVIEW_HTML));
        assert!(benchmark_artifacts(false).contains(&"phase_timing.csv"));
        assert!(benchmark_artifacts(false).contains(&"paper_figures_standalone.tex"));
        assert!(benchmark_artifacts(false).contains(&RESULT_MANIFEST));
        assert!(!benchmark_artifacts(false).contains(&COMPILED_PAPER_FIGURE));
        assert!(benchmark_artifacts(true).contains(&COMPILED_PAPER_FIGURE));

        let manifest_dir = env::temp_dir().join(format!(
            "pq_dsnark_manifest_test_{}",
            SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .expect("clock")
                .as_nanos()
        ));
        fs::create_dir_all(&manifest_dir).expect("manifest temp dir");
        for artifact in benchmark_artifacts(false) {
            if artifact != RESULT_MANIFEST {
                write_text_file(
                    &manifest_dir.join(artifact),
                    &format!("test artifact {artifact}\n"),
                )
                .expect("write artifact");
            }
        }
        let manifest = benchmark_result_manifest_json(&manifest_dir, 123, false).expect("manifest");
        assert!(manifest.contains("\"schema_version\": 1"));
        assert!(manifest.contains("\"path\":\"metadata.json\""));
        assert!(manifest.contains("\"sha256\""));
        assert!(manifest.contains("\"self_artifact\": \"result_manifest.json\""));
        assert!(!manifest.contains("\"path\":\"result_manifest.json\""));
        write_text_file(&manifest_dir.join(RESULT_MANIFEST), &manifest).expect("write manifest");
        let report = verify_benchmark_result_manifest(&manifest_dir).expect("verify manifest");
        assert_eq!(report.run_id, 123);
        assert_eq!(report.files_checked, benchmark_artifacts(false).len() - 1);
        write_text_file(&manifest_dir.join("stale.svg"), "old figure\n")
            .expect("write stale artifact");
        let error = verify_benchmark_result_manifest(&manifest_dir)
            .expect_err("unexpected artifact must fail verification");
        assert!(error.0.contains("unexpected artifact"));
        fs::remove_file(manifest_dir.join("stale.svg")).expect("remove stale artifact");
        write_text_file(&manifest_dir.join("source.csv"), "tampered\n").expect("tamper artifact");
        let error = verify_benchmark_result_manifest(&manifest_dir)
            .expect_err("tampered artifact must fail verification");
        assert!(error.0.contains("mismatch"));
        fs::remove_dir_all(&manifest_dir).expect("cleanup manifest temp dir");

        let semantic_dir = env::temp_dir().join(format!(
            "bench-pq_dsnark_semantic_result_test_{}",
            SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .expect("clock")
                .as_nanos()
        ));
        fs::create_dir_all(&semantic_dir).expect("semantic temp dir");
        let semantic_command = BenchmarkCommand {
            sizes: vec![4],
            workers: vec![1],
            pcs_queries: 3,
            repeats: 1,
            paper_preset: false,
            runner: BenchmarkRunner::Local,
            compile_figures: false,
            figure_compiler: FigureCompiler::Auto,
            out_dir: PathBuf::from("results"),
            host_logical_cores: None,
            worker_cores: None,
            worker_core_plan: None,
        };
        let semantic_records = vec![
            MetricRecord {
                protocol: "r1cs",
                runner: "local",
                case_name: "positive",
                trial: 1,
                workers: 1,
                size: 4,
                constraints: 4,
                prove_ms: 10.0,
                verify_ms: 2.0,
                stages: test_stage_breakdown(10.0, 2.0, 100),
                proof_bytes: 100,
                communication_bytes: 50,
                network_bytes: 0,
                pcs_queries: 3,
                host_logical_cores: None,
                cores_per_worker: None,
                core_affinity: None,
                verified: true,
                failure_reason: None,
            },
            MetricRecord {
                protocol: "plonkish",
                runner: "local",
                case_name: "positive",
                trial: 1,
                workers: 1,
                size: 4,
                constraints: 16,
                prove_ms: 12.0,
                verify_ms: 3.0,
                stages: test_stage_breakdown(12.0, 3.0, 140),
                proof_bytes: 140,
                communication_bytes: 70,
                network_bytes: 0,
                pcs_queries: 3,
                host_logical_cores: None,
                cores_per_worker: None,
                core_affinity: None,
                verified: true,
                failure_reason: None,
            },
        ];
        let semantic_timings = vec![
            PhaseTimingRecord {
                phase: "setup".to_owned(),
                detail: "test setup".to_owned(),
                elapsed_ms: 0.1,
                recorded_prove_ms: 0.0,
                recorded_verify_ms: 0.0,
                inferred_overhead_ms: 0.1,
            },
            PhaseTimingRecord {
                phase: "job".to_owned(),
                detail: "runner=local protocol=r1cs n=2 nv=4 workers=1".to_owned(),
                elapsed_ms: 12.0,
                recorded_prove_ms: 10.0,
                recorded_verify_ms: 2.0,
                inferred_overhead_ms: 0.0,
            },
            PhaseTimingRecord {
                phase: "job".to_owned(),
                detail: "runner=local protocol=plonkish n=2 nv=4 workers=1".to_owned(),
                elapsed_ms: 15.0,
                recorded_prove_ms: 12.0,
                recorded_verify_ms: 3.0,
                inferred_overhead_ms: 0.0,
            },
            PhaseTimingRecord {
                phase: "source_and_chart_artifacts".to_owned(),
                detail: "charts".to_owned(),
                elapsed_ms: 1.0,
                recorded_prove_ms: 0.0,
                recorded_verify_ms: 0.0,
                inferred_overhead_ms: 1.0,
            },
            PhaseTimingRecord {
                phase: "final_result_artifacts".to_owned(),
                detail: "final".to_owned(),
                elapsed_ms: 1.0,
                recorded_prove_ms: 0.0,
                recorded_verify_ms: 0.0,
                inferred_overhead_ms: 1.0,
            },
            PhaseTimingRecord {
                phase: "total".to_owned(),
                detail: "total".to_owned(),
                elapsed_ms: 29.0,
                recorded_prove_ms: 22.0,
                recorded_verify_ms: 5.0,
                inferred_overhead_ms: 2.0,
            },
        ];
        write_text_file(
            &semantic_dir.join("metadata.json"),
            &benchmark_metadata_json(
                456,
                &semantic_command,
                &semantic_records,
                false,
                &provenance,
            ),
        )
        .expect("write semantic metadata");
        write_text_file(
            &semantic_dir.join("source.csv"),
            &records_to_csv(&semantic_records),
        )
        .expect("write semantic source csv");
        write_text_file(
            &semantic_dir.join("source.json"),
            &records_to_json(&semantic_records),
        )
        .expect("write semantic source json");
        write_text_file(
            &semantic_dir.join("summary_stats.csv"),
            &summary_stats_to_csv(&benchmark_stats(&semantic_records)),
        )
        .expect("write semantic summary stats");
        write_text_file(
            &semantic_dir.join("phase_timing.csv"),
            &phase_timing_to_csv(&semantic_timings),
        )
        .expect("write semantic phase timing csv");
        write_text_file(
            &semantic_dir.join("phase_timing.json"),
            &phase_timing_to_json(&semantic_timings),
        )
        .expect("write semantic phase timing json");
        write_text_file(
            &semantic_dir.join(OVERVIEW_HTML),
            &benchmark_overview_html(456, &semantic_command, &semantic_records, false),
        )
        .expect("write semantic overview");
        write_text_file(
            &semantic_dir.join("summary.txt"),
            &benchmark_summary(
                &semantic_command,
                &semantic_records,
                &semantic_timings,
                false,
                &provenance,
            ),
        )
        .expect("write semantic summary");
        write_benchmark_charts(&semantic_dir, &semantic_records).expect("write semantic charts");
        for artifact in benchmark_artifacts(false) {
            if artifact != RESULT_MANIFEST && !semantic_dir.join(artifact).exists() {
                write_text_file(
                    &semantic_dir.join(artifact),
                    &format!("invalid semantic fixture for {artifact}\n"),
                )
                .expect("write invalid semantic fixture");
            }
        }
        let semantic_manifest =
            benchmark_result_manifest_json(&semantic_dir, 456, false).expect("semantic manifest");
        write_text_file(&semantic_dir.join(RESULT_MANIFEST), &semantic_manifest)
            .expect("write semantic manifest");
        let report = verify_benchmark_result_dir(&semantic_dir).expect("verify semantic result");
        assert_eq!(report.source_rows_checked, 2);
        assert_eq!(report.summary_rows_checked, 2);
        assert_eq!(report.phase_rows_checked, 6);
        let semantic_bad_source =
            records_to_csv(&semantic_records[..1]).replace("r1cs,local", "r1cs,network");
        write_text_file(&semantic_dir.join("source.csv"), &semantic_bad_source)
            .expect("write semantic bad source csv");
        let semantic_manifest =
            benchmark_result_manifest_json(&semantic_dir, 456, false).expect("semantic manifest");
        write_text_file(&semantic_dir.join(RESULT_MANIFEST), &semantic_manifest)
            .expect("rewrite semantic manifest");
        let error = verify_benchmark_result_dir(&semantic_dir)
            .expect_err("manifest-consistent semantic mismatch must fail");
        assert!(error.0.contains("source.csv"));
        write_text_file(
            &semantic_dir.join("source.csv"),
            &records_to_csv(&semantic_records),
        )
        .expect("restore semantic source csv");
        write_text_file(
            &semantic_dir.join("prove_time_by_size.svg"),
            "<svg>broken\n",
        )
        .expect("write semantic bad svg");
        let semantic_manifest =
            benchmark_result_manifest_json(&semantic_dir, 456, false).expect("semantic manifest");
        write_text_file(&semantic_dir.join(RESULT_MANIFEST), &semantic_manifest)
            .expect("rewrite semantic manifest after bad svg");
        let error = verify_benchmark_result_dir(&semantic_dir)
            .expect_err("manifest-consistent broken SVG must fail");
        assert!(error.0.contains("prove_time_by_size.svg"));
        fs::remove_dir_all(&semantic_dir).expect("cleanup semantic temp dir");

        let paper_quality_dir = env::temp_dir().join(format!(
            "pq_dsnark_paper_quality_test_{}",
            SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .expect("clock")
                .as_nanos()
        ));
        fs::create_dir_all(&paper_quality_dir).expect("paper quality temp dir");
        let expected_positive = (PAPER_PRESET_NV_START..=PAPER_PRESET_NV_END).count()
            * PAPER_PRESET_WORKERS.len()
            * 2
            * 2
            * BENCHMARK_REPEATS;
        let paper_metadata = format!(
            concat!(
                "{{\n",
                "  \"schema_version\": 7,\n",
                "  \"build_profile\": \"release\",\n",
                "  \"nv_powers\": [2,3,4,5,6],\n",
                "  \"workers\": [1,2,4],\n",
                "  \"pcs_queries\": 3,\n",
                "  \"repeats\": 1,\n",
                "  \"paper_preset\": true,\n",
                "  \"runner\": \"both\",\n",
                "  \"compile_figures_requested\": true,\n",
                "  \"compile_figures_succeeded\": true,\n",
                "  \"record_count\": {},\n",
                "  \"positive_verified\": {},\n",
                "  \"negative_rejected\": {}\n",
                "}}\n"
            ),
            expected_positive, expected_positive, 0
        );
        write_text_file(&paper_quality_dir.join("metadata.json"), &paper_metadata)
            .expect("write paper metadata");
        write_text_file(&paper_quality_dir.join(COMPILED_PAPER_FIGURE), "%PDF-1.4\n")
            .expect("write compiled figure marker");
        let mut source_csv = format!("{SOURCE_CSV_HEADER}\n");
        for runner in ["local", "network"] {
            for protocol in ["r1cs", "plonkish"] {
                for nv_power in PAPER_PRESET_NV_START..=PAPER_PRESET_NV_END {
                    for workers in PAPER_PRESET_WORKERS {
                        let size = 1_usize << nv_power;
                        let constraints = if protocol == "r1cs" { size } else { size * 4 };
                        let network_bytes = if runner == "network" { 1234 } else { 0 };
                        let affinity = if runner == "network" {
                            "20,5,linux-taskset"
                        } else {
                            ",,"
                        };
                        source_csv.push_str(&format!(
                            "{protocol},{runner},positive,1,{workers},{nv_power},{size},{constraints},{PAPER_PRESET_PCS_QUERIES},10.000,5.000,1000,900,{network_bytes},{affinity},true,\n"
                        ));
                    }
                }
            }
        }
        write_text_file(&paper_quality_dir.join("source.csv"), &source_csv)
            .expect("write paper source csv");
        let mut phase_timing = format!("{PHASE_TIMING_CSV_HEADER}\n");
        for index in 0..expected_positive {
            phase_timing.push_str(&format!(
                "job,paper-job-{index},15.000,10.000,5.000,0.000\n"
            ));
        }
        phase_timing.push_str("source_and_chart_artifacts,charts,1.000,0.000,0.000,1.000\n");
        phase_timing.push_str("final_result_artifacts,final,1.000,0.000,0.000,1.000\n");
        phase_timing.push_str("total,total,902.000,600.000,300.000,2.000\n");
        write_text_file(&paper_quality_dir.join("phase_timing.csv"), &phase_timing)
            .expect("write paper phase timing csv");
        write_text_file(
            &paper_quality_dir.join(OVERVIEW_HTML),
            "<!doctype html><p>All positive performance proofs verified</p><a>source.csv</a><a>worker_scaling_max_size.svg</a><section>Core Allocation</section>",
        )
        .expect("write paper overview");
        write_benchmark_charts(&paper_quality_dir, &records).expect("write paper charts");
        verify_benchmark_paper_quality(&paper_quality_dir).expect("paper quality metadata");
        let debug_metadata = paper_metadata.replace(
            "\"build_profile\": \"release\"",
            "\"build_profile\": \"debug\"",
        );
        write_text_file(&paper_quality_dir.join("metadata.json"), &debug_metadata)
            .expect("write debug metadata");
        let error = verify_benchmark_paper_quality(&paper_quality_dir)
            .expect_err("debug metadata must fail paper quality");
        assert!(error.0.contains("build_profile"));
        write_text_file(&paper_quality_dir.join("metadata.json"), &paper_metadata)
            .expect("restore paper metadata");
        let bad_source = source_csv.replace(",positive,1,1,2,", ",negative,1,1,2,");
        write_text_file(&paper_quality_dir.join("source.csv"), &bad_source)
            .expect("write bad source csv");
        let error = verify_benchmark_paper_quality(&paper_quality_dir)
            .expect_err("negative source row must fail paper quality");
        assert!(error.0.contains("verified positive performance run"));
        fs::remove_dir_all(&paper_quality_dir).expect("cleanup paper quality temp dir");

        let stats_csv = summary_stats_to_csv(&benchmark_stats(&records));
        assert!(stats_csv.starts_with("protocol,runner,case"));
        assert!(stats_csv.contains("prove_ms_mean"));
        assert!(stats_csv.contains("12.000000"));
    }

    #[test]
    fn r1cs_fallback_metrics_include_all_pcs_openings() {
        let (instance, witness) = sample_r1cs(4).expect("sample r1cs");
        let proof = prove_r1cs_for_instance(&instance, &witness, 2, 2).expect("proof");
        let metrics = verify_r1cs_for_instance(&instance, &proof, 2).expect("verify");
        let fallback = r1cs_fallback_metrics(&proof);

        assert_eq!(fallback.0, r1cs_proof_size_bytes(&proof));
        assert_eq!(fallback.1, metrics.communication_bytes);
        assert_eq!(fallback.1, r1cs_opening_communication_bytes(&proof));
        let main_openings = proof.outer_openings.az.communication_bytes()
            + proof.outer_openings.bz.communication_bytes()
            + proof.outer_openings.cz.communication_bytes()
            + proof.inner.witness_opening.communication_bytes()
            + proof.residual_opening.communication_bytes();
        assert!(fallback.1 > main_openings);

        let tampered = tamper_r1cs_proof(&proof).expect("tampered proof");
        assert!(verify_r1cs_for_instance(&instance, &tampered, 2).is_err());
        assert_eq!(r1cs_fallback_metrics(&proof), fallback);
    }

    #[test]
    fn plonkish_rejected_fallback_metrics_include_sampled_index_openings() {
        let instance = sample_plonkish_instance(4).expect("sample plonkish");
        let proof = prove_for_instance(&instance, 2, 2).expect("proof");
        let metrics = verify_for_instance(&instance, &proof, 2).expect("verify");

        assert_eq!(
            plonkish_proof_communication_bytes(&proof),
            metrics.communication_bytes
        );
        assert!(
            plonkish_proof_communication_bytes(&proof)
                > proof.constraint_opening.communication_bytes()
        );

        let tampered = tampered_plonkish_proof_variants(&proof)
            .expect("tamper proof")
            .remove(0)
            .1;
        assert!(verify_for_instance(&instance, &tampered, 2).is_err());
        assert_eq!(
            plonkish_proof_communication_bytes(&proof),
            metrics.communication_bytes
        );
    }

    #[test]
    fn plonkish_negative_variants_cover_multiple_failure_surfaces() {
        let instance = sample_plonkish_instance(4).expect("sample plonkish");
        let proof = prove_for_instance(&instance, 1, 1).expect("proof");
        let variants = tampered_plonkish_proof_variants(&proof).expect("variants");
        let labels = variants.iter().map(|(label, _)| *label).collect::<Vec<_>>();
        assert_eq!(
            labels,
            vec![
                "accumulator-recurrence",
                "gate-query",
                "permutation-query",
                "gate-subclaim",
                "constraint-pcs-opening"
            ]
        );
        for (label, tampered) in variants {
            assert!(
                verify_for_instance(&instance, &tampered, 1).is_err(),
                "{label} variant unexpectedly verified"
            );
        }

        let failures =
            verify_plonkish_negative_variants(&instance, &proof, 1).expect("negative variants");
        assert!(failures.contains("accumulator-recurrence"));
        assert!(failures.contains("constraint-pcs-opening"));
    }

    #[test]
    fn r1cs_network_hook_produces_compact_pcs_openings() {
        let (addr0, handle0) = spawn_loopback_worker(0).expect("worker 0");
        let (addr1, handle1) = spawn_loopback_worker(1).expect("worker 1");
        let addrs = vec![addr0, addr1];
        ping(&addrs[0]).expect("ping 0");
        ping(&addrs[1]).expect("ping 1");
        register(&addrs[0], 0).expect("register 0");
        register(&addrs[1], 1).expect("register 1");

        let (instance, witness) = sample_r1cs(4).expect("sample r1cs");
        let backend = RefCell::new(NetworkPcsClient::new(
            addrs.clone(),
            "r1cs-compact-test".to_owned(),
        ));
        let mut transcript = HashTranscript::new(b"pq-experiments-r1cs");
        let proof = prove_r1cs_with_pcs_and_spark_batch_hooks(
            &instance,
            &witness,
            2,
            DistributedPcsParams::new(2),
            &mut transcript,
            R1csBatchProverHooks {
                commit_distributed: |evaluations: &[FieldElement], workers: usize| {
                    backend
                        .borrow_mut()
                        .commit(evaluations, workers)
                        .map_err(|_| R1csPiopError::Pcs)
                },
                open_distributed:
                    |evaluations: &[FieldElement],
                     commitment: &DistributedCommitment,
                     point: &[FieldElement],
                     params: DistributedPcsParams,
                     transcript: &mut HashTranscript| {
                        backend
                            .borrow_mut()
                            .open_compact(evaluations, commitment, point, params, transcript)
                            .map(R1csPcsOpening::Compact)
                            .map_err(|_| R1csPiopError::Pcs)
                    },
                spark_worker_provider: |requests: &[SparkWorkerClaimRequest<'_>]| {
                    backend
                        .borrow_mut()
                        .r1cs_spark_claims(&instance, requests)
                        .map_err(|_| R1csPiopError::InvalidProof)
                },
            },
        )
        .expect("network compact R1CS proof");

        assert_r1cs_compact_openings(&proof);
        assert_eq!(proof.spark.workers.len(), 2);
        assert!(
            proof
                .spark
                .matrix_evaluations
                .iter()
                .all(|matrix| matrix.worker_evaluations.len() == 2)
        );
        assert!(backend.borrow().bytes() > 0);
        verify_r1cs_for_instance(&instance, &proof, 2).expect("verify compact network proof");

        TcpWorkerRuntime::shutdown(&addrs).expect("shutdown");
        handle0.join().expect("join 0").expect("worker 0 ok");
        handle1.join().expect("join 1").expect("worker 1 ok");
    }

    #[test]
    fn plonkish_network_hook_produces_compact_pcs_opening() {
        let (addr0, handle0) = spawn_loopback_worker(0).expect("worker 0");
        let (addr1, handle1) = spawn_loopback_worker(1).expect("worker 1");
        let addrs = vec![addr0, addr1];
        ping(&addrs[0]).expect("ping 0");
        ping(&addrs[1]).expect("ping 1");
        register(&addrs[0], 0).expect("register 0");
        register(&addrs[1], 1).expect("register 1");

        let instance = sample_plonkish_instance(4).expect("sample plonkish");
        let backend = RefCell::new(NetworkPcsClient::new(
            addrs.clone(),
            "plonkish-compact-test".to_owned(),
        ));
        let mut transcript = HashTranscript::new(b"pq-experiments-plonkish");
        let proof = prove_plonkish_with_pcs_hooks(
            &instance,
            2,
            DistributedPcsParams::new(2),
            &mut transcript,
            |evaluations, workers| {
                backend
                    .borrow_mut()
                    .commit(evaluations, workers)
                    .map_err(|_| PlonkishPiopError::InvalidProof)
            },
            |evaluations, commitment, point, params, transcript| {
                backend
                    .borrow_mut()
                    .open_compact(evaluations, commitment, point, params, transcript)
                    .map(PlonkishPcsOpening::Compact)
                    .map_err(|_| PlonkishPiopError::InvalidProof)
            },
        )
        .expect("network compact Plonkish proof");

        assert!(matches!(
            proof.constraint_opening,
            PlonkishPcsOpening::Compact(_)
        ));
        assert!(backend.borrow().bytes() > 0);
        verify_for_instance(&instance, &proof, 2).expect("verify compact network proof");

        TcpWorkerRuntime::shutdown(&addrs).expect("shutdown");
        handle0.join().expect("join 0").expect("worker 0 ok");
        handle1.join().expect("join 1").expect("worker 1 ok");
    }

    #[test]
    fn loopback_network_proof_paths_produce_positive_and_negative_records() {
        let (addr0, handle0) = spawn_loopback_worker(0).expect("worker 0");
        let (addr1, handle1) = spawn_loopback_worker(1).expect("worker 1");
        let addrs = vec![addr0, addr1];
        ping(&addrs[0]).expect("ping 0");
        ping(&addrs[1]).expect("ping 1");
        register(&addrs[0], 0).expect("register 0");
        register(&addrs[1], 1).expect("register 1");

        let r1cs_config = Config {
            protocol: Protocol::R1cs,
            workers: 2,
            size: 4,
            format: OutputFormat::Json,
            case: CaseSelection::Both,
            pcs_queries: 2,
            worker_core_plan: None,
        };
        let r1cs = run_r1cs_network(&r1cs_config, &addrs).expect("r1cs records");
        assert_network_records(&r1cs);

        let plonkish_config = Config {
            protocol: Protocol::Plonkish,
            workers: 2,
            size: 4,
            format: OutputFormat::Json,
            case: CaseSelection::Both,
            pcs_queries: 2,
            worker_core_plan: None,
        };
        let plonkish = run_plonkish_network(&plonkish_config, &addrs).expect("plonkish records");
        assert_network_records(&plonkish);

        TcpWorkerRuntime::shutdown(&addrs).expect("shutdown");
        handle0.join().expect("join 0").expect("worker 0 ok");
        handle1.join().expect("join 1").expect("worker 1 ok");
    }

    fn assert_network_records(records: &[MetricRecord]) {
        assert_eq!(records.len(), 2);
        assert!(records[0].verified);
        assert_eq!(records[0].failure_reason, None);
        assert!(records[0].network_bytes > 0);
        assert!(!records[1].verified);
        assert!(records[1].failure_reason.is_some());
        assert!(records[1].network_bytes > 0);
    }

    fn assert_r1cs_compact_openings(proof: &R1csPiopProof) {
        assert!(matches!(
            proof.outer_openings.az,
            R1csPcsOpening::Compact(_)
        ));
        assert!(matches!(
            proof.outer_openings.bz,
            R1csPcsOpening::Compact(_)
        ));
        assert!(matches!(
            proof.outer_openings.cz,
            R1csPcsOpening::Compact(_)
        ));
        assert!(matches!(
            proof.inner.witness_opening,
            R1csPcsOpening::Compact(_)
        ));
        assert!(matches!(proof.residual_opening, R1csPcsOpening::Compact(_)));
    }
}

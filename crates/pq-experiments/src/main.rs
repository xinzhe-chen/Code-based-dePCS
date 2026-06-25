use std::collections::BTreeMap;
use std::env;
use std::fmt::{Display, Formatter};
use std::fs;
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process;
use std::time::{Instant, SystemTime};

use pq_core::{FieldElement, log2_power_of_two};
use pq_pcs::{
    DistributedBrakedown, DistributedPcsParams, PcsBackendConfig, PcsBackendKind, Protocol11Proof,
    Protocol11WorkerOpenData,
    artifact::{
        PAPER_PCS_HASH, PAPER_PCS_LICENSE, PAPER_PCS_SECURITY_BITS, PAPER_PCS_SOURCE_REV,
        PAPER_PCS_SOURCE_URL, PaperPcsBackend, PaperPcsRun, PaperQueryPolicy,
        run_paper_pcs_with_options,
    },
    depcs::{
        self, PaperDepcsConfig, PaperProtocol11Commitment, PaperProtocol11Proof, PaperWorkerCache,
    },
    protocol11_commitment_size_bytes, protocol11_evaluation_domain_len,
    protocol11_proof_size_breakdown,
};
use pq_transcript::HashTranscript;
use serde::{Deserialize, Serialize};

mod network;

use network::{
    PcsNetworkWorkerClient, PcsWorkerRequest, PcsWorkerResponse, read_frame_binary,
    send_worker_request, send_worker_requests_concurrently, shutdown_pcs_network_workers,
    spawn_pcs_network_workers, write_frame_binary,
};

const PCS_SOURCE_CSV_HEADER: &str = "scheme,backend,backend_rate_inv,effective_query_count,column_query_count,pcs_query_count,query_security_bits,algebraic_security_bits,batch_claim_count,batch_open_ms,batch_verify_ms,batch_proof_bytes,runner,opening,trial,workers,nv,polynomial_length,t_rows_per_worker,paper_b_target,shard_len,pcs_queries_requested,pcs_queries_effective,partition_ms,worker_commit_ms,master_commit_ms,commit_ms,open_ms,verify_ms,paper_worker_commit_max_ms,paper_worker_commit_sum_ms,paper_worker_open_max_ms,paper_worker_open_sum_ms,paper_master_assemble_ms,paper_worker_verify_max_ms,paper_worker_verify_sum_ms,paper_master_verify_ms,paper_batch_claim_ms,paper_batch_sumcheck_ms,paper_batch_combined_open_ms,paper_batch_merkle_ms,paper_batch_verify_ms,paper_individual_worker_proof_count,paper_batched_proof_count,worker_eval_commit_ms,column_open_ms,f2_open_ms,protocol10_e1_sumcheck_ms,protocol10_e1_open_ms,protocol10_e1_opening_batch_open_ms,protocol10_e1_hu_open_ms,protocol10_e1_e_at_r_open_ms,protocol10_e1_f_at_u_prime_open_ms,protocol10_e1_e_systematic_open_ms,protocol10_e2_sumcheck_ms,protocol10_e2_open_ms,protocol10_e2_opening_batch_open_ms,protocol10_e2_hu_open_ms,protocol10_e2_e_at_r_open_ms,protocol10_e2_f_at_u_prime_open_ms,protocol10_e2_e_systematic_open_ms,proof_size_accounting_ms,column_verify_ms,f2_verify_ms,protocol10_e1_verify_ms,protocol10_e2_verify_ms,proof_commitment_object_bytes,proof_point_query_public_bytes,proof_eval_commitments_bytes,proof_merkle_roots_bytes,proof_column_openings_bytes,proof_f2_openings_bytes,proof_protocol10_e1_bytes,proof_protocol10_e2_bytes,proof_transcript_overhead_bytes,proof_p10_e1_commitments_bytes,proof_p10_e1_public_scalars_bytes,proof_p10_e1_opening_batch_bytes,proof_p10_e1_hu_opening_bytes,proof_p10_e1_sumcheck_bytes,proof_p10_e1_e_at_r_openings_bytes,proof_p10_e1_f_at_u_prime_openings_bytes,proof_p10_e1_e_systematic_openings_bytes,proof_p10_e2_commitments_bytes,proof_p10_e2_public_scalars_bytes,proof_p10_e2_opening_batch_bytes,proof_p10_e2_hu_opening_bytes,proof_p10_e2_sumcheck_bytes,proof_p10_e2_e_at_r_openings_bytes,proof_p10_e2_f_at_u_prime_openings_bytes,proof_p10_e2_e_systematic_openings_bytes,proof_bytes,communication_bytes,verifier_communication_bytes,scheme_reported_communication_bytes,communication_basis,network_commit_bytes,network_open_bytes,network_bytes,host_logical_cores,cores_per_worker,core_affinity,backend_source,field,hash,code_rate_log,security_target_bits,security_effective_bits,security_exact,query_count_semantics,source_rev,verified,failure_reason";
const PCS_COMPARISON_CSV_HEADER: &str = "backend,nv,polynomial_length,backend_rate_inv,code_rate_log,security_bits,query_count,query_policy,workers,cores_per_worker,commit_ms,open_ms,verify_ms,proof_bytes,commitment_bytes,communication_bytes,verifier_communication_bytes,scheme_reported_communication_bytes,communication_basis,network_bytes,verified,failure_reason,source_rev,source_url,license,field,hash,opening,backend_source,security_target_bits,security_effective_bits,security_exact,query_count_semantics";
const PCS_SUMMARY_STATS_CSV_HEADER: &str = "scheme,backend,backend_rate_inv,runner,opening,workers,nv,polynomial_length,samples,verified_count,effective_query_count_mean,column_query_count_mean,pcs_query_count_mean,query_security_bits_mean,algebraic_security_bits_mean,batch_claim_count_mean,batch_open_ms_mean,batch_verify_ms_mean,batch_proof_bytes_mean,commit_ms_mean,commit_ms_stddev,open_ms_mean,open_ms_stddev,verify_ms_mean,verify_ms_stddev,paper_worker_commit_max_ms_mean,paper_worker_commit_sum_ms_mean,paper_worker_open_max_ms_mean,paper_worker_open_sum_ms_mean,paper_master_assemble_ms_mean,paper_worker_verify_max_ms_mean,paper_worker_verify_sum_ms_mean,paper_master_verify_ms_mean,paper_batch_claim_ms_mean,paper_batch_sumcheck_ms_mean,paper_batch_combined_open_ms_mean,paper_batch_merkle_ms_mean,paper_batch_verify_ms_mean,paper_individual_worker_proof_count_mean,paper_batched_proof_count_mean,worker_eval_commit_ms_mean,column_open_ms_mean,f2_open_ms_mean,protocol10_e1_sumcheck_ms_mean,protocol10_e1_open_ms_mean,protocol10_e1_opening_batch_open_ms_mean,protocol10_e1_hu_open_ms_mean,protocol10_e1_e_at_r_open_ms_mean,protocol10_e1_f_at_u_prime_open_ms_mean,protocol10_e1_e_systematic_open_ms_mean,protocol10_e2_sumcheck_ms_mean,protocol10_e2_open_ms_mean,protocol10_e2_opening_batch_open_ms_mean,protocol10_e2_hu_open_ms_mean,protocol10_e2_e_at_r_open_ms_mean,protocol10_e2_f_at_u_prime_open_ms_mean,protocol10_e2_e_systematic_open_ms_mean,proof_size_accounting_ms_mean,column_verify_ms_mean,f2_verify_ms_mean,protocol10_e1_verify_ms_mean,protocol10_e2_verify_ms_mean,proof_commitment_object_bytes_mean,proof_point_query_public_bytes_mean,proof_eval_commitments_bytes_mean,proof_merkle_roots_bytes_mean,proof_column_openings_bytes_mean,proof_f2_openings_bytes_mean,proof_protocol10_e1_bytes_mean,proof_protocol10_e2_bytes_mean,proof_transcript_overhead_bytes_mean,proof_p10_e1_commitments_bytes_mean,proof_p10_e1_public_scalars_bytes_mean,proof_p10_e1_opening_batch_bytes_mean,proof_p10_e1_hu_opening_bytes_mean,proof_p10_e1_sumcheck_bytes_mean,proof_p10_e1_e_at_r_openings_bytes_mean,proof_p10_e1_f_at_u_prime_openings_bytes_mean,proof_p10_e1_e_systematic_openings_bytes_mean,proof_p10_e2_commitments_bytes_mean,proof_p10_e2_public_scalars_bytes_mean,proof_p10_e2_opening_batch_bytes_mean,proof_p10_e2_hu_opening_bytes_mean,proof_p10_e2_sumcheck_bytes_mean,proof_p10_e2_e_at_r_openings_bytes_mean,proof_p10_e2_f_at_u_prime_openings_bytes_mean,proof_p10_e2_e_systematic_openings_bytes_mean,proof_bytes_mean,communication_bytes_mean,verifier_communication_bytes_mean,scheme_reported_communication_bytes_mean,network_bytes_mean,failure_reasons";
const PHASE_TIMING_CSV_HEADER: &str = "phase,scope,elapsed_ms,commit_ms,open_ms,verify_ms";
const DEFAULT_EVALUATION_SEED: u64 = 0;

#[derive(Debug)]
struct CliError(String);

impl Display for CliError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl std::error::Error for CliError {}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
enum OutputFormat {
    Json,
    Csv,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
enum PcsOpeningSelection {
    Protocol11,
    Protocol11Batch,
    LegacyProtocol11,
    PaperNative,
}

impl PcsOpeningSelection {
    fn variants(self) -> Vec<PcsOpeningVariant> {
        match self {
            Self::Protocol11 => vec![PcsOpeningVariant::Protocol11],
            Self::Protocol11Batch => vec![PcsOpeningVariant::Protocol11Batch],
            Self::LegacyProtocol11 => vec![PcsOpeningVariant::LegacyProtocol11],
            Self::PaperNative => vec![PcsOpeningVariant::PaperNative],
        }
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
enum PcsOpeningVariant {
    Protocol11,
    Protocol11Batch,
    LegacyProtocol11,
    PaperNative,
}

impl PcsOpeningVariant {
    fn as_str(self) -> &'static str {
        match self {
            Self::Protocol11 => "protocol11",
            Self::Protocol11Batch => "protocol11-batch",
            Self::LegacyProtocol11 => "legacy-protocol11",
            Self::PaperNative => "paper-native",
        }
    }
}

#[derive(Clone, Debug)]
struct PcsBenchmarkCommand {
    sizes: Vec<usize>,
    workers: Vec<usize>,
    cores_per_worker: usize,
    pcs_queries: usize,
    security_bits: usize,
    repeats: usize,
    opening: PcsOpeningSelection,
    backend: PcsBackendConfig,
    paper_query_policy: PaperQueryPolicy,
    paper_code_rate_log: Option<usize>,
    out_dir: PathBuf,
    warmup_enabled: bool,
}

#[derive(Copy, Clone, Debug)]
struct PcsBenchmarkJob {
    size: usize,
    workers: usize,
    opening: PcsOpeningVariant,
    trial: usize,
    pcs_queries: usize,
    security_bits: usize,
    backend: PcsBackendConfig,
    paper_query_policy: PaperQueryPolicy,
    paper_code_rate_log: Option<usize>,
    cores_per_worker: usize,
}

#[derive(Clone, Debug)]
struct VerifyPcsResultsCommand {
    dir: PathBuf,
    format: OutputFormat,
}

#[derive(Clone, Debug, Serialize)]
struct PcsMetricRecord {
    scheme: String,
    backend: String,
    backend_rate_inv: usize,
    effective_query_count: usize,
    column_query_count: usize,
    pcs_query_count: usize,
    query_security_bits: usize,
    algebraic_security_bits: usize,
    batch_claim_count: usize,
    batch_open_ms: f64,
    batch_verify_ms: f64,
    batch_proof_bytes: usize,
    runner: String,
    opening: String,
    trial: usize,
    workers: usize,
    #[serde(rename = "nv")]
    variable_count: usize,
    polynomial_length: usize,
    t_rows_per_worker: usize,
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
    paper_worker_commit_max_ms: f64,
    paper_worker_commit_sum_ms: f64,
    paper_worker_open_max_ms: f64,
    paper_worker_open_sum_ms: f64,
    paper_master_assemble_ms: f64,
    paper_worker_verify_max_ms: f64,
    paper_worker_verify_sum_ms: f64,
    paper_master_verify_ms: f64,
    paper_batch_claim_ms: f64,
    paper_batch_sumcheck_ms: f64,
    paper_batch_combined_open_ms: f64,
    paper_batch_merkle_ms: f64,
    paper_batch_verify_ms: f64,
    paper_individual_worker_proof_count: usize,
    paper_batched_proof_count: usize,
    worker_eval_commit_ms: f64,
    column_open_ms: f64,
    f2_open_ms: f64,
    protocol10_e1_sumcheck_ms: f64,
    protocol10_e1_open_ms: f64,
    protocol10_e1_opening_batch_open_ms: f64,
    protocol10_e1_hu_open_ms: f64,
    protocol10_e1_e_at_r_open_ms: f64,
    protocol10_e1_f_at_u_prime_open_ms: f64,
    protocol10_e1_e_systematic_open_ms: f64,
    protocol10_e2_sumcheck_ms: f64,
    protocol10_e2_open_ms: f64,
    protocol10_e2_opening_batch_open_ms: f64,
    protocol10_e2_hu_open_ms: f64,
    protocol10_e2_e_at_r_open_ms: f64,
    protocol10_e2_f_at_u_prime_open_ms: f64,
    protocol10_e2_e_systematic_open_ms: f64,
    proof_size_accounting_ms: f64,
    column_verify_ms: f64,
    f2_verify_ms: f64,
    protocol10_e1_verify_ms: f64,
    protocol10_e2_verify_ms: f64,
    proof_commitment_object_bytes: usize,
    proof_point_query_public_bytes: usize,
    proof_eval_commitments_bytes: usize,
    proof_merkle_roots_bytes: usize,
    proof_column_openings_bytes: usize,
    proof_f2_openings_bytes: usize,
    proof_protocol10_e1_bytes: usize,
    proof_protocol10_e2_bytes: usize,
    proof_transcript_overhead_bytes: usize,
    proof_p10_e1_commitments_bytes: usize,
    proof_p10_e1_public_scalars_bytes: usize,
    proof_p10_e1_opening_batch_bytes: usize,
    proof_p10_e1_hu_opening_bytes: usize,
    proof_p10_e1_sumcheck_bytes: usize,
    proof_p10_e1_e_at_r_openings_bytes: usize,
    proof_p10_e1_f_at_u_prime_openings_bytes: usize,
    proof_p10_e1_e_systematic_openings_bytes: usize,
    proof_p10_e2_commitments_bytes: usize,
    proof_p10_e2_public_scalars_bytes: usize,
    proof_p10_e2_opening_batch_bytes: usize,
    proof_p10_e2_hu_opening_bytes: usize,
    proof_p10_e2_sumcheck_bytes: usize,
    proof_p10_e2_e_at_r_openings_bytes: usize,
    proof_p10_e2_f_at_u_prime_openings_bytes: usize,
    proof_p10_e2_e_systematic_openings_bytes: usize,
    proof_bytes: usize,
    communication_bytes: usize,
    verifier_communication_bytes: usize,
    scheme_reported_communication_bytes: usize,
    communication_basis: String,
    network_commit_bytes: usize,
    network_open_bytes: usize,
    network_bytes: usize,
    host_logical_cores: usize,
    cores_per_worker: usize,
    core_affinity: String,
    backend_source: String,
    field: String,
    hash: String,
    code_rate_log: usize,
    security_target_bits: usize,
    security_effective_bits: usize,
    security_exact: bool,
    query_count_semantics: String,
    source_rev: String,
    verified: bool,
    failure_reason: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct PcsProofFixture {
    row_id: String,
    backend: PcsBackendConfig,
    params: DistributedPcsParams,
    commitment: pq_pcs::Protocol11Commitment,
    proof: Protocol11Proof,
    transcript_label: String,
}

#[derive(Clone, Copy, Debug)]
struct SourceCsvCheck {
    rows: usize,
    depcs_rows: usize,
}

#[derive(Clone, Debug, Serialize)]
struct PhaseTimingRecord {
    phase: String,
    scope: String,
    elapsed_ms: f64,
    commit_ms: f64,
    open_ms: f64,
    verify_ms: f64,
}

struct PcsNetworkWorkerState {
    original_len: usize,
    workers: usize,
    worker_id: usize,
    backend: PcsBackendConfig,
    paper_config: Option<PaperDepcsConfig>,
    paper_cache: Option<PaperWorkerCache>,
    rows: Vec<Vec<FieldElement>>,
    open_data: Option<Protocol11WorkerOpenData>,
}

struct PcsNetworkRun {
    commitment: pq_pcs::Protocol11Commitment,
    proof: Protocol11Proof,
    open_profile: pq_pcs::Protocol11OpenProfile,
    commit_ms: f64,
    open_ms: f64,
    network_commit_bytes: usize,
    network_open_bytes: usize,
}

struct PaperPcsNetworkRun {
    commitment: PaperProtocol11Commitment,
    proof: PaperProtocol11Proof,
    open_profile: depcs::PaperProtocol11OpenProfile,
    verify_profile: depcs::PaperProtocol11VerifyProfile,
    commit_ms: f64,
    open_ms: f64,
    verify_ms: f64,
    paper_worker_commit_max_ms: f64,
    paper_worker_commit_sum_ms: f64,
    paper_worker_open_max_ms: f64,
    paper_worker_open_sum_ms: f64,
    paper_master_assemble_ms: f64,
    paper_worker_verify_max_ms: f64,
    paper_worker_verify_sum_ms: f64,
    paper_master_verify_ms: f64,
    network_commit_bytes: usize,
    network_open_bytes: usize,
}

#[derive(Clone, Debug)]
struct PcsStatsRecord {
    scheme: String,
    backend: String,
    backend_rate_inv: usize,
    runner: String,
    opening: String,
    workers: usize,
    variable_count: usize,
    polynomial_length: usize,
    samples: usize,
    verified_count: usize,
    effective_query_count: f64,
    column_query_count: f64,
    pcs_query_count: f64,
    query_security_bits: f64,
    algebraic_security_bits: f64,
    batch_claim_count: f64,
    batch_open_ms: f64,
    batch_verify_ms: f64,
    batch_proof_bytes: f64,
    commit_ms: MeanStddev,
    open_ms: MeanStddev,
    verify_ms: MeanStddev,
    paper_worker_commit_max_ms: f64,
    paper_worker_commit_sum_ms: f64,
    paper_worker_open_max_ms: f64,
    paper_worker_open_sum_ms: f64,
    paper_master_assemble_ms: f64,
    paper_worker_verify_max_ms: f64,
    paper_worker_verify_sum_ms: f64,
    paper_master_verify_ms: f64,
    paper_batch_claim_ms: f64,
    paper_batch_sumcheck_ms: f64,
    paper_batch_combined_open_ms: f64,
    paper_batch_merkle_ms: f64,
    paper_batch_verify_ms: f64,
    paper_individual_worker_proof_count: f64,
    paper_batched_proof_count: f64,
    worker_eval_commit_ms: f64,
    column_open_ms: f64,
    f2_open_ms: f64,
    protocol10_e1_sumcheck_ms: f64,
    protocol10_e1_open_ms: f64,
    protocol10_e1_opening_batch_open_ms: f64,
    protocol10_e1_hu_open_ms: f64,
    protocol10_e1_e_at_r_open_ms: f64,
    protocol10_e1_f_at_u_prime_open_ms: f64,
    protocol10_e1_e_systematic_open_ms: f64,
    protocol10_e2_sumcheck_ms: f64,
    protocol10_e2_open_ms: f64,
    protocol10_e2_opening_batch_open_ms: f64,
    protocol10_e2_hu_open_ms: f64,
    protocol10_e2_e_at_r_open_ms: f64,
    protocol10_e2_f_at_u_prime_open_ms: f64,
    protocol10_e2_e_systematic_open_ms: f64,
    proof_size_accounting_ms: f64,
    column_verify_ms: f64,
    f2_verify_ms: f64,
    protocol10_e1_verify_ms: f64,
    protocol10_e2_verify_ms: f64,
    proof_commitment_object_bytes: f64,
    proof_point_query_public_bytes: f64,
    proof_eval_commitments_bytes: f64,
    proof_merkle_roots_bytes: f64,
    proof_column_openings_bytes: f64,
    proof_f2_openings_bytes: f64,
    proof_protocol10_e1_bytes: f64,
    proof_protocol10_e2_bytes: f64,
    proof_transcript_overhead_bytes: f64,
    proof_p10_e1_commitments_bytes: f64,
    proof_p10_e1_public_scalars_bytes: f64,
    proof_p10_e1_opening_batch_bytes: f64,
    proof_p10_e1_hu_opening_bytes: f64,
    proof_p10_e1_sumcheck_bytes: f64,
    proof_p10_e1_e_at_r_openings_bytes: f64,
    proof_p10_e1_f_at_u_prime_openings_bytes: f64,
    proof_p10_e1_e_systematic_openings_bytes: f64,
    proof_p10_e2_commitments_bytes: f64,
    proof_p10_e2_public_scalars_bytes: f64,
    proof_p10_e2_opening_batch_bytes: f64,
    proof_p10_e2_hu_opening_bytes: f64,
    proof_p10_e2_sumcheck_bytes: f64,
    proof_p10_e2_e_at_r_openings_bytes: f64,
    proof_p10_e2_f_at_u_prime_openings_bytes: f64,
    proof_p10_e2_e_systematic_openings_bytes: f64,
    proof_bytes: f64,
    communication_bytes: f64,
    verifier_communication_bytes: f64,
    scheme_reported_communication_bytes: f64,
    network_bytes: f64,
    failure_reasons: String,
}

#[derive(Clone, Copy, Debug)]
struct MeanStddev {
    mean: f64,
    stddev: f64,
}

fn main() {
    if let Err(error) = run(env::args().skip(1).collect::<Vec<_>>()) {
        eprintln!("{error}");
        process::exit(1);
    }
}

fn run(args: Vec<String>) -> Result<(), CliError> {
    match args.first().map(String::as_str) {
        Some("pcs-benchmark") => run_pcs_benchmark(parse_pcs_benchmark_command(&args[1..])?),
        Some("verify-pcs-results") => {
            verify_pcs_results(parse_verify_pcs_results_command(&args[1..])?)
        }
        Some("pcs-network-worker") => run_pcs_network_worker(&args[1..]),
        Some("--help") | Some("-h") | None => {
            println!("{}", usage());
            Ok(())
        }
        Some(other) => Err(CliError(format!(
            "unknown command '{other}'\n\n{}",
            usage()
        ))),
    }
}

fn run_pcs_network_worker(args: &[String]) -> Result<(), CliError> {
    let mut addr = None;
    let mut index = 0;
    while index < args.len() {
        match args[index].as_str() {
            "--addr" => addr = Some(next_value(args, &mut index, "--addr")?.to_owned()),
            other => {
                return Err(CliError(format!(
                    "unknown pcs-network-worker argument '{other}'"
                )));
            }
        }
        index += 1;
    }
    let addr = addr.ok_or_else(|| CliError("pcs-network-worker requires --addr".to_owned()))?;
    let listener = TcpListener::bind(&addr)
        .map_err(|error| CliError(format!("worker bind failed: {error}")))?;
    let (mut stream, _) = listener
        .accept()
        .map_err(|error| CliError(format!("worker accept failed: {error}")))?;
    serve_pcs_network_worker_stream(&mut stream)
}

fn serve_pcs_network_worker_stream(stream: &mut TcpStream) -> Result<(), CliError> {
    let mut state: Option<PcsNetworkWorkerState> = None;
    loop {
        let (request, _bytes_recv): (PcsWorkerRequest, usize) = read_frame_binary(stream)
            .map_err(|error| CliError(format!("worker read failed: {error}")))?;
        let response = match request {
            PcsWorkerRequest::CommitRows {
                original_len,
                workers,
                worker_id,
                backend,
                rows,
            } => {
                match DistributedBrakedown::commit_worker_rows_with_config(
                    original_len,
                    workers,
                    worker_id,
                    &rows,
                    backend,
                ) {
                    Ok(commitment) => {
                        state = Some(PcsNetworkWorkerState {
                            original_len,
                            workers,
                            worker_id,
                            backend,
                            paper_config: None,
                            paper_cache: None,
                            rows,
                            open_data: None,
                        });
                        PcsWorkerResponse::Commit { commitment }
                    }
                    Err(error) => PcsWorkerResponse::Error {
                        message: format!("{error:?}"),
                    },
                }
            }
            PcsWorkerRequest::CommitSeeded {
                original_len,
                workers,
                worker_id,
                backend,
                evaluation_seed,
            } => {
                match worker_rows_for_evaluation_seed(
                    original_len,
                    workers,
                    worker_id,
                    evaluation_seed,
                )
                .and_then(|rows| {
                    DistributedBrakedown::commit_worker_rows_with_config(
                        original_len,
                        workers,
                        worker_id,
                        &rows,
                        backend,
                    )
                    .map_err(|error| {
                        CliError(format!("commit seeded worker rows failed: {error:?}"))
                    })
                    .map(|commitment| (rows, commitment))
                }) {
                    Ok((rows, commitment)) => {
                        state = Some(PcsNetworkWorkerState {
                            original_len,
                            workers,
                            worker_id,
                            backend,
                            paper_config: None,
                            paper_cache: None,
                            rows,
                            open_data: None,
                        });
                        PcsWorkerResponse::Commit { commitment }
                    }
                    Err(error) => PcsWorkerResponse::Error {
                        message: format!("{error:?}"),
                    },
                }
            }
            PcsWorkerRequest::OpenPrepare { a, beta } => {
                if let Some(state) = &mut state {
                    match DistributedBrakedown::open_worker_data_from_rows_with_config(
                        state.original_len,
                        state.workers,
                        state.worker_id,
                        &state.rows,
                        &a,
                        &beta,
                        state.backend,
                    )
                    .and_then(|data| {
                        DistributedBrakedown::open_worker_payload_from_data_with_config(
                            &data,
                            state.backend,
                        )
                        .map(|payload| (data, payload))
                    }) {
                        Ok((data, payload)) => {
                            state.open_data = Some(data);
                            PcsWorkerResponse::OpenPrepare { payload }
                        }
                        Err(error) => PcsWorkerResponse::Error {
                            message: format!("{error:?}"),
                        },
                    }
                } else {
                    PcsWorkerResponse::Error {
                        message: "worker has no committed shard".to_owned(),
                    }
                }
            }
            PcsWorkerRequest::OpenColumns {
                commitment,
                query_indices,
            } => {
                if let Some(state) = &state {
                    if let Some(open_data) = &state.open_data {
                        match DistributedBrakedown::open_worker_matrix_column_proof_from_data(
                            open_data,
                            &commitment,
                            &query_indices,
                        ) {
                            Ok(proof) => PcsWorkerResponse::OpenColumns { proof },
                            Err(error) => PcsWorkerResponse::Error {
                                message: format!("{error:?}"),
                            },
                        }
                    } else {
                        PcsWorkerResponse::Error {
                            message: "worker has no prepared open state".to_owned(),
                        }
                    }
                } else {
                    PcsWorkerResponse::Error {
                        message: "worker has no committed shard".to_owned(),
                    }
                }
            }
            PcsWorkerRequest::PaperCommitSeeded {
                original_len,
                workers,
                worker_id,
                config,
            } => {
                let start = Instant::now();
                match depcs::commit_worker_cached(original_len, workers, worker_id, config) {
                    Ok(cache) => {
                        let elapsed_ms = elapsed_ms(start);
                        let commitment = cache.commitment.clone();
                        state = Some(PcsNetworkWorkerState {
                            original_len,
                            workers,
                            worker_id,
                            backend: PcsBackendConfig::basefold_default(),
                            paper_config: Some(config),
                            paper_cache: Some(cache),
                            rows: Vec::new(),
                            open_data: None,
                        });
                        PcsWorkerResponse::PaperCommit {
                            commitment,
                            elapsed_ms,
                        }
                    }
                    Err(error) => PcsWorkerResponse::Error {
                        message: format!("{error:?}"),
                    },
                }
            }
            PcsWorkerRequest::PaperOpen { commitment, point } => {
                let start = Instant::now();
                if let Some(state) = &state {
                    if let Some(cache) = &state.paper_cache {
                        match depcs::open_worker_cached(cache, &commitment, &point) {
                            Ok(opening) => PcsWorkerResponse::PaperOpen {
                                opening,
                                elapsed_ms: elapsed_ms(start),
                            },
                            Err(error) => PcsWorkerResponse::Error {
                                message: format!("{error:?}"),
                            },
                        }
                    } else if state.paper_config.is_none() {
                        PcsWorkerResponse::Error {
                            message: "worker has no paper-backed committed shard".to_owned(),
                        }
                    } else {
                        match depcs::open_worker(&commitment, state.worker_id, &point) {
                            Ok(opening) => PcsWorkerResponse::PaperOpen {
                                opening,
                                elapsed_ms: elapsed_ms(start),
                            },
                            Err(error) => PcsWorkerResponse::Error {
                                message: format!("{error:?}"),
                            },
                        }
                    }
                } else {
                    PcsWorkerResponse::Error {
                        message: "worker has no committed shard".to_owned(),
                    }
                }
            }
            PcsWorkerRequest::Shutdown => {
                write_frame_binary(stream, &PcsWorkerResponse::Ack)
                    .map_err(|error| CliError(format!("worker shutdown ack failed: {error}")))?;
                return Ok(());
            }
        };
        write_frame_binary(stream, &response)
            .map_err(|error| CliError(format!("worker write failed: {error}")))?;
    }
}

fn parse_pcs_benchmark_command(args: &[String]) -> Result<PcsBenchmarkCommand, CliError> {
    let mut sizes = vec![1024];
    let mut workers = vec![1, 2];
    let mut cores_per_worker = env_cores_per_worker();
    let mut pcs_queries = 1;
    let mut security_bits_override: Option<usize> = None;
    let mut repeats = 1;
    let mut opening = PcsOpeningSelection::Protocol11;
    let mut backend_kind = PcsBackendKind::BaseFold;
    let mut backend_rate_inv: Option<usize> = None;
    let mut paper_query_policy = PaperQueryPolicy::ArtifactDefault;
    let mut paper_code_rate_log = None;
    let mut out_dir = PathBuf::from("results");
    let mut warmup_enabled = true;
    let mut runner = "local-network".to_owned();
    let mut index = 0;
    while index < args.len() {
        match args[index].as_str() {
            "--runner" => runner = next_value(args, &mut index, "--runner")?.to_owned(),
            "--opening" => opening = parse_opening(next_value(args, &mut index, "--opening")?)?,
            "--backend" => {
                backend_kind = parse_backend_kind(next_value(args, &mut index, "--backend")?)?
            }
            "--backend-rate-inv" => {
                backend_rate_inv = Some(parse_positive_usize(
                    next_value(args, &mut index, "--backend-rate-inv")?,
                    "--backend-rate-inv",
                )?)
            }
            "--sizes" => {
                sizes = parse_csv_usizes(next_value(args, &mut index, "--sizes")?, "--sizes")?
            }
            "--size-range" => {
                sizes = parse_size_range(next_value(args, &mut index, "--size-range")?)?
            }
            "--nv-values" | "--variable-counts" | "--mu-values" | "--nv-powers" | "--n-values" => {
                let flag = args[index].clone();
                sizes = parse_variable_counts(next_value(args, &mut index, &flag)?, &flag)?
            }
            "--variable-range" | "--mu-range" | "--nv-range" | "--n-range" => {
                let flag = args[index].clone();
                sizes = parse_variable_range(next_value(args, &mut index, &flag)?, &flag)?
            }
            "--workers" => {
                workers = parse_csv_usizes(next_value(args, &mut index, "--workers")?, "--workers")?
            }
            "--pcs-queries" => {
                pcs_queries = parse_positive_usize(
                    next_value(args, &mut index, "--pcs-queries")?,
                    "--pcs-queries",
                )?
            }
            "--security-bits" | "--lambda" => {
                let flag = args[index].clone();
                security_bits_override = Some(parse_positive_usize(
                    next_value(args, &mut index, &flag)?,
                    &flag,
                )?)
            }
            "--paper-query-policy" => {
                paper_query_policy =
                    parse_paper_query_policy(next_value(args, &mut index, "--paper-query-policy")?)?
            }
            "--paper-code-rate-log" => {
                paper_code_rate_log = Some(parse_positive_usize(
                    next_value(args, &mut index, "--paper-code-rate-log")?,
                    "--paper-code-rate-log",
                )?)
            }
            "--repeats" => {
                repeats =
                    parse_positive_usize(next_value(args, &mut index, "--repeats")?, "--repeats")?
            }
            "--out" => out_dir = PathBuf::from(next_value(args, &mut index, "--out")?),
            "--no-pcs-warmup" => warmup_enabled = false,
            "--worker-power-range" => {
                workers =
                    parse_worker_power_range(next_value(args, &mut index, "--worker-power-range")?)?
            }
            "--cores-per-worker" | "--worker-cores" => {
                let flag = args[index].clone();
                cores_per_worker =
                    parse_positive_usize(next_value(args, &mut index, &flag)?, &flag)?;
            }
            "--host-cores" => {
                let flag = args[index].clone();
                let _ = next_value(args, &mut index, &flag)?;
            }
            other => {
                return Err(CliError(format!(
                    "unknown pcs-benchmark argument '{other}'"
                )));
            }
        }
        index += 1;
    }
    if runner == "local" {
        return Err(CliError(
            "pcs-benchmark no longer supports --runner local; use the default local-network runner"
                .to_owned(),
        ));
    }
    if runner != "local-network" {
        return Err(CliError(
            "pcs-benchmark supports only the local-network runner".to_owned(),
        ));
    }
    normalize_unique(&mut sizes);
    normalize_unique(&mut workers);
    let paper_backed_opening = matches!(
        opening,
        PcsOpeningSelection::Protocol11
            | PcsOpeningSelection::Protocol11Batch
            | PcsOpeningSelection::PaperNative
    );
    let security_bits = if paper_backed_opening {
        if let Some(security_bits) = security_bits_override {
            if security_bits != PAPER_PCS_SECURITY_BITS {
                return Err(CliError(format!(
                    "paper-backed PCS uses DeepFold artifact SECURITY_BITS={PAPER_PCS_SECURITY_BITS}; requested --security-bits {security_bits}"
                )));
            }
        }
        PAPER_PCS_SECURITY_BITS
    } else {
        security_bits_override.unwrap_or(DistributedPcsParams::DEFAULT_SECURITY_BITS)
    };
    if opening != PcsOpeningSelection::PaperNative && workers.iter().any(|workers| *workers < 2) {
        return Err(CliError(
            "local-network dePCS benchmark requires workers >= 2".to_owned(),
        ));
    }
    let backend = build_backend_config(backend_kind, backend_rate_inv, security_bits)?;
    validate_pcs_grid(&sizes, &workers, pcs_queries, security_bits, repeats)?;
    Ok(PcsBenchmarkCommand {
        sizes,
        workers,
        cores_per_worker,
        pcs_queries,
        security_bits,
        repeats,
        opening,
        backend,
        paper_query_policy,
        paper_code_rate_log,
        out_dir,
        warmup_enabled,
    })
}

fn parse_verify_pcs_results_command(args: &[String]) -> Result<VerifyPcsResultsCommand, CliError> {
    let mut dir = None;
    let mut format = OutputFormat::Json;
    let mut index = 0;
    while index < args.len() {
        match args[index].as_str() {
            "--dir" => dir = Some(PathBuf::from(next_value(args, &mut index, "--dir")?)),
            "--format" => format = parse_format(next_value(args, &mut index, "--format")?)?,
            other => {
                return Err(CliError(format!(
                    "unknown verify-pcs-results argument '{other}'"
                )));
            }
        }
        index += 1;
    }
    Ok(VerifyPcsResultsCommand {
        dir: dir.ok_or_else(|| CliError("verify-pcs-results requires --dir".to_owned()))?,
        format,
    })
}

fn run_pcs_benchmark(command: PcsBenchmarkCommand) -> Result<(), CliError> {
    let run_id = unix_millis()?;
    let run_dir = command.out_dir.join(format!("pcs-bench-{run_id}"));
    fs::create_dir_all(&run_dir)
        .map_err(|error| CliError(format!("create output directory failed: {error}")))?;

    let mut records = Vec::new();
    let mut fixtures = Vec::new();
    let mut timings = Vec::new();
    let total = command.sizes.len()
        * command.workers.len()
        * command.opening.variants().len()
        * command.repeats;
    let all_start = Instant::now();

    if command.warmup_enabled && command.opening == PcsOpeningSelection::LegacyProtocol11 {
        let start = Instant::now();
        let mut transcript = HashTranscript::new(b"pq-experiments-pcs-warmup");
        let warmup = run_network_protocol11(
            32,
            2,
            DistributedPcsParams {
                query_count: 1,
                security_bits: command.security_bits,
            },
            command.backend,
            command.cores_per_worker,
            b"pq-experiments-pcs-warmup",
            &mut transcript,
        )?;
        let mut verify_transcript = HashTranscript::new(b"pq-experiments-pcs-warmup");
        DistributedBrakedown::verify(
            &warmup.commitment,
            &warmup.proof,
            DistributedPcsParams {
                query_count: 1,
                security_bits: command.security_bits,
            },
            &mut verify_transcript,
        )
        .map_err(|error| CliError(format!("warm-up verify failed: {error:?}")))?;
        timings.push(PhaseTimingRecord {
            phase: "pcs_warmup".to_owned(),
            scope: "warmup".to_owned(),
            elapsed_ms: elapsed_ms(start),
            commit_ms: 0.0,
            open_ms: 0.0,
            verify_ms: 0.0,
        });
    }

    let mut job_index = 0;
    for size in &command.sizes {
        for workers in &command.workers {
            for opening in command.opening.variants() {
                for trial in 1..=command.repeats {
                    job_index += 1;
                    eprintln!(
                        "[pcs-benchmark job {job_index}/{total}] opening={} nv={} N={} workers={} pcs_queries={} trial={}/{}",
                        opening.as_str(),
                        variable_count(*size),
                        size,
                        workers,
                        command.pcs_queries,
                        trial,
                        command.repeats
                    );
                    let (record, job_timings, fixture) = run_single_pcs_job(PcsBenchmarkJob {
                        size: *size,
                        workers: *workers,
                        opening,
                        trial,
                        pcs_queries: command.pcs_queries,
                        security_bits: command.security_bits,
                        backend: command.backend,
                        paper_query_policy: command.paper_query_policy,
                        paper_code_rate_log: command.paper_code_rate_log,
                        cores_per_worker: command.cores_per_worker,
                    })?;
                    timings.extend(job_timings);
                    records.push(record);
                    if let Some(fixture) = fixture {
                        fixtures.push(fixture);
                    }
                }
            }
        }
    }

    write_text_file(&run_dir.join("source.csv"), &pcs_records_to_csv(&records))?;
    write_text_file(
        &run_dir.join("comparison_summary.csv"),
        &pcs_comparison_summary_to_csv(&records),
    )?;
    write_text_file(
        &run_dir.join("proof_fixtures.jsonl"),
        &proof_fixtures_to_jsonl(&fixtures)?,
    )?;
    write_text_file(&run_dir.join("source.json"), &json_pretty(&records)?)?;
    write_text_file(
        &run_dir.join("summary_stats.csv"),
        &pcs_summary_stats_to_csv(&pcs_benchmark_stats(&records)),
    )?;
    write_text_file(
        &run_dir.join("phase_timing.csv"),
        &phase_timing_to_csv(&timings),
    )?;
    write_text_file(&run_dir.join("phase_timing.json"), &json_pretty(&timings)?)?;
    write_text_file(
        &run_dir.join("summary.txt"),
        &pcs_benchmark_summary(&command, &records),
    )?;
    write_text_file(&run_dir.join("overview.html"), &pcs_overview_html(&records))?;
    write_text_file(
        &run_dir.join("metadata.json"),
        &pcs_metadata_json(
            run_id,
            &command,
            &records,
            all_start.elapsed().as_secs_f64(),
        ),
    )?;
    write_simple_chart(
        &run_dir.join("prover_time_by_nv.svg"),
        &records,
        "dePCS prover time",
        |record| record.commit_ms + record.open_ms,
    )?;
    write_simple_chart(
        &run_dir.join("proof_bytes_by_nv.svg"),
        &records,
        "dePCS proof bytes (commitment + opening proof)",
        |record| record.proof_bytes as f64,
    )?;
    write_phase_breakdown_chart(
        &run_dir.join("opening_phase_breakdown_by_nv.svg"),
        &records,
        "dePCS opening phase breakdown",
        true,
    )?;
    write_phase_breakdown_chart(
        &run_dir.join("verify_phase_breakdown_by_nv.svg"),
        &records,
        "dePCS verify phase breakdown",
        false,
    )?;
    write_proof_size_breakdown_chart(
        &run_dir.join("proof_size_component_breakdown_by_nv.svg"),
        &records,
    )?;

    println!("{}", run_dir.display());
    Ok(())
}

fn run_network_protocol11(
    original_len: usize,
    workers: usize,
    params: DistributedPcsParams,
    backend: PcsBackendConfig,
    cores_per_worker: usize,
    transcript_label: &'static [u8],
    transcript: &mut HashTranscript,
) -> Result<PcsNetworkRun, CliError> {
    let mut clients = spawn_pcs_network_workers(workers, cores_per_worker)?;
    let result = run_network_protocol11_with_clients(
        original_len,
        workers,
        params,
        backend,
        transcript_label,
        transcript,
        &mut clients,
    );
    shutdown_pcs_network_workers(&mut clients);
    result
}

fn run_network_protocol11_with_clients(
    original_len: usize,
    workers: usize,
    params: DistributedPcsParams,
    backend: PcsBackendConfig,
    _transcript_label: &'static [u8],
    transcript: &mut HashTranscript,
    clients: &mut [PcsNetworkWorkerClient],
) -> Result<PcsNetworkRun, CliError> {
    let commit_start = Instant::now();
    let mut worker_commitments = Vec::with_capacity(workers);
    for (worker_id, client) in clients.iter_mut().enumerate() {
        let response = send_worker_request(
            client,
            &PcsWorkerRequest::CommitSeeded {
                original_len,
                workers,
                worker_id,
                backend,
                evaluation_seed: DEFAULT_EVALUATION_SEED,
            },
        )?;
        match response {
            PcsWorkerResponse::Commit { commitment } => worker_commitments.push(commitment),
            PcsWorkerResponse::Error { message } => {
                return Err(CliError(format!("worker commit failed: {message}")));
            }
            other => {
                return Err(CliError(format!(
                    "unexpected worker commit response: {other:?}"
                )));
            }
        }
    }
    let network_commit_bytes = clients
        .iter()
        .map(|client| client.bytes_sent + client.bytes_recv)
        .sum::<usize>();
    let commitment = DistributedBrakedown::commit_from_worker_commitments_with_config(
        original_len,
        workers,
        backend,
        worker_commitments,
    )
    .map_err(|error| CliError(format!("assemble network commitment failed: {error:?}")))?;
    let commit_ms = elapsed_ms(commit_start);

    let point = sample_point(protocol11_evaluation_domain_len(&commitment))?;
    let (a, beta) = DistributedBrakedown::open_worker_challenges(&commitment, &point, transcript)
        .map_err(|error| {
        CliError(format!("derive network open challenges failed: {error:?}"))
    })?;

    let open_start = Instant::now();
    let mut worker_payloads = Vec::with_capacity(workers);
    for client in clients.iter_mut() {
        let response = send_worker_request(
            client,
            &PcsWorkerRequest::OpenPrepare {
                a: a.clone(),
                beta: beta.clone(),
            },
        )?;
        match response {
            PcsWorkerResponse::OpenPrepare { payload } => worker_payloads.push(payload),
            PcsWorkerResponse::Error { message } => {
                return Err(CliError(format!("worker open-prepare failed: {message}")));
            }
            other => {
                return Err(CliError(format!(
                    "unexpected worker open response: {other:?}"
                )));
            }
        }
    }
    let prepared = DistributedBrakedown::prepare_open_worker_payloads(
        &commitment,
        params,
        backend,
        transcript,
        &worker_payloads,
    )
    .map_err(|error| CliError(format!("derive network column queries failed: {error:?}")))?;
    let query_indices = prepared.query_indices().to_vec();
    let mut column_openings = Vec::with_capacity(workers);
    for client in clients.iter_mut() {
        let response = send_worker_request(
            client,
            &PcsWorkerRequest::OpenColumns {
                commitment: commitment.clone(),
                query_indices: query_indices.clone(),
            },
        )?;
        match response {
            PcsWorkerResponse::OpenColumns { proof } => column_openings.push(proof),
            PcsWorkerResponse::Error { message } => {
                return Err(CliError(format!("worker column-open failed: {message}")));
            }
            other => {
                return Err(CliError(format!(
                    "unexpected worker column-open response: {other:?}"
                )));
            }
        }
    }
    let network_total_after_open = clients
        .iter()
        .map(|client| client.bytes_sent + client.bytes_recv)
        .sum::<usize>();
    let network_open_bytes = network_total_after_open.saturating_sub(network_commit_bytes);
    let (proof, open_profile) =
        DistributedBrakedown::open_profiled_with_prepared_worker_matrix_columns(
            &commitment,
            &point,
            params,
            backend,
            transcript,
            prepared,
            &column_openings,
            &a,
            &beta,
        )
        .map_err(|error| {
            CliError(format!(
                "assemble network Protocol 11 proof failed: {error:?}"
            ))
        })?;
    let open_ms = elapsed_ms(open_start);
    Ok(PcsNetworkRun {
        commitment,
        proof,
        open_profile,
        commit_ms,
        open_ms,
        network_commit_bytes,
        network_open_bytes,
    })
}

fn run_paper_network_protocol11(
    original_len: usize,
    workers: usize,
    config: PaperDepcsConfig,
    cores_per_worker: usize,
) -> Result<PaperPcsNetworkRun, CliError> {
    let mut clients = spawn_pcs_network_workers(workers, cores_per_worker)?;
    let result =
        run_paper_network_protocol11_with_clients(original_len, workers, config, &mut clients);
    shutdown_pcs_network_workers(&mut clients);
    result
}

fn run_paper_network_protocol11_with_clients(
    original_len: usize,
    workers: usize,
    config: PaperDepcsConfig,
    clients: &mut [PcsNetworkWorkerClient],
) -> Result<PaperPcsNetworkRun, CliError> {
    let commit_start = Instant::now();
    let commit_requests = (0..workers)
        .map(|worker_id| PcsWorkerRequest::PaperCommitSeeded {
            original_len,
            workers,
            worker_id,
            config,
        })
        .collect::<Vec<_>>();
    let commit_responses =
        send_worker_requests_concurrently(clients, &commit_requests, "paper worker commit")?;
    let mut worker_commitments = Vec::with_capacity(workers);
    let mut worker_commit_times = Vec::with_capacity(workers);
    for response in commit_responses {
        match response {
            PcsWorkerResponse::PaperCommit {
                commitment,
                elapsed_ms,
            } => {
                worker_commitments.push(commitment);
                worker_commit_times.push(elapsed_ms);
            }
            PcsWorkerResponse::Error { message } => {
                return Err(CliError(format!("paper worker commit failed: {message}")));
            }
            other => {
                return Err(CliError(format!(
                    "unexpected paper worker commit response: {other:?}"
                )));
            }
        }
    }
    let network_commit_bytes = clients
        .iter()
        .map(|client| client.bytes_sent + client.bytes_recv)
        .sum::<usize>();
    let commitment =
        depcs::commit_from_worker_commitments(original_len, workers, config, worker_commitments)
            .map_err(|error| CliError(format!("assemble paper commitment failed: {error:?}")))?;
    let commit_ms = elapsed_ms(commit_start);

    let point = depcs::sample_point(commitment.nv);
    let open_start = Instant::now();
    let open_requests = (0..workers)
        .map(|_| PcsWorkerRequest::PaperOpen {
            commitment: commitment.clone(),
            point: point.clone(),
        })
        .collect::<Vec<_>>();
    let open_responses =
        send_worker_requests_concurrently(clients, &open_requests, "paper worker open")?;
    let mut worker_openings = Vec::with_capacity(workers);
    let mut worker_open_times = Vec::with_capacity(workers);
    for response in open_responses {
        match response {
            PcsWorkerResponse::PaperOpen {
                opening,
                elapsed_ms,
            } => {
                worker_openings.push(opening);
                worker_open_times.push(elapsed_ms);
            }
            PcsWorkerResponse::Error { message } => {
                return Err(CliError(format!("paper worker open failed: {message}")));
            }
            other => {
                return Err(CliError(format!(
                    "unexpected paper worker open response: {other:?}"
                )));
            }
        }
    }
    let network_total_after_open = clients
        .iter()
        .map(|client| client.bytes_sent + client.bytes_recv)
        .sum::<usize>();
    let network_open_bytes = network_total_after_open.saturating_sub(network_commit_bytes);
    let assemble_start = Instant::now();
    let (proof, open_profile) = depcs::assemble_opening(&commitment, point, worker_openings)
        .map_err(|error| {
            CliError(format!(
                "assemble paper Protocol 11 proof failed: {error:?}"
            ))
        })?;
    let paper_master_assemble_ms = elapsed_ms(assemble_start);
    let open_ms = elapsed_ms(open_start);
    let verify_start = Instant::now();
    let verify_profile = depcs::verify(&commitment, &proof)
        .map_err(|error| CliError(format!("verify paper Protocol 11 proof failed: {error:?}")))?;
    let verify_ms = elapsed_ms(verify_start);
    Ok(PaperPcsNetworkRun {
        commitment,
        proof,
        open_profile,
        verify_profile,
        commit_ms,
        open_ms,
        verify_ms,
        paper_worker_commit_max_ms: max_f64(&worker_commit_times),
        paper_worker_commit_sum_ms: sum_f64(&worker_commit_times),
        paper_worker_open_max_ms: max_f64(&worker_open_times),
        paper_worker_open_sum_ms: sum_f64(&worker_open_times),
        paper_master_assemble_ms,
        paper_worker_verify_max_ms: verify_profile.paper_worker_verify_max_ms,
        paper_worker_verify_sum_ms: verify_profile.paper_worker_verify_sum_ms,
        paper_master_verify_ms: verify_profile.paper_master_verify_ms,
        network_commit_bytes,
        network_open_bytes,
    })
}

fn max_f64(values: &[f64]) -> f64 {
    values.iter().copied().fold(0.0, f64::max)
}

fn sum_f64(values: &[f64]) -> f64 {
    values.iter().sum()
}

fn run_single_pcs_job(
    job: PcsBenchmarkJob,
) -> Result<
    (
        PcsMetricRecord,
        Vec<PhaseTimingRecord>,
        Option<PcsProofFixture>,
    ),
    CliError,
> {
    if job.opening == PcsOpeningVariant::Protocol11 {
        return run_single_depcs_job(job);
    }
    if job.opening == PcsOpeningVariant::Protocol11Batch {
        return run_single_depcs_batch_job(job);
    }
    if job.opening == PcsOpeningVariant::PaperNative {
        return run_single_paper_pcs_job(job);
    }
    let PcsBenchmarkJob {
        size,
        workers,
        opening,
        trial,
        pcs_queries,
        security_bits,
        backend,
        cores_per_worker,
        ..
    } = job;
    let params = DistributedPcsParams {
        query_count: pcs_queries,
        security_bits,
    };
    let host_logical_cores = std::thread::available_parallelism().map_or(1, usize::from);

    let mut transcript = HashTranscript::new(b"pq-experiments-depcs-benchmark");
    let partition_start = Instant::now();
    validate_partition_shape(size, workers)?;
    let partition_ms = elapsed_ms(partition_start);

    let network_run = run_network_protocol11(
        size,
        workers,
        params,
        backend,
        cores_per_worker,
        b"pq-experiments-depcs-benchmark",
        &mut transcript,
    )?;
    let commitment = network_run.commitment;
    let proof = network_run.proof;
    let open_profile = network_run.open_profile;
    let commit_ms = network_run.commit_ms;
    let open_ms = network_run.open_ms;
    let commitment_bytes = protocol11_commitment_size_bytes(&commitment);
    let verify_start = Instant::now();
    let mut verify_transcript = HashTranscript::new(b"pq-experiments-depcs-benchmark");
    let verify_result = DistributedBrakedown::verify_profiled_with_config(
        &commitment,
        &proof,
        params,
        backend,
        &mut verify_transcript,
    );
    let verify_ms = elapsed_ms(verify_start);
    let verify_profile = verify_result
        .as_ref()
        .map(|profile| *profile)
        .unwrap_or_default();
    let proof_size_start = Instant::now();
    let proof_size_breakdown = protocol11_proof_size_breakdown(&proof);
    let opening_proof_bytes = proof_size_breakdown.total_bytes();
    let proof_size_accounting_ms = elapsed_ms(proof_size_start);
    let proof_bytes = commitment_bytes + opening_proof_bytes;
    let network_commit_bytes = network_run.network_commit_bytes;
    let network_open_bytes = network_run.network_open_bytes;
    let network_bytes = network_commit_bytes + network_open_bytes;
    let comm_bytes = network_bytes;
    let verified = verify_result.is_ok();
    let failure_reason = verify_result
        .err()
        .map_or_else(String::new, |error| format!("{error:?}"));
    let effective_queries = verify_profile.pcs_query_count;

    let record = PcsMetricRecord {
        scheme: depcs_scheme_name(backend).to_owned(),
        backend: backend.kind.as_str().to_owned(),
        backend_rate_inv: backend.rate_inv,
        effective_query_count: effective_queries,
        column_query_count: verify_profile.column_query_count,
        pcs_query_count: verify_profile.pcs_query_count,
        query_security_bits: verify_profile.query_security_bits,
        algebraic_security_bits: verify_profile.algebraic_security_bits,
        batch_claim_count: batch_claim_count(&proof),
        batch_open_ms: open_ms,
        batch_verify_ms: verify_ms,
        batch_proof_bytes: opening_proof_bytes,
        runner: "local-network".to_owned(),
        opening: opening.as_str().to_owned(),
        trial,
        workers,
        variable_count: variable_count(size),
        polynomial_length: size,
        t_rows_per_worker: commitment.rows_per_worker,
        paper_b_target: commitment.matrix_rows,
        shard_len: commitment.row_width,
        pcs_queries_requested: pcs_queries,
        pcs_queries_effective: effective_queries,
        partition_ms,
        worker_commit_ms: commit_ms,
        master_commit_ms: 0.0,
        commit_ms,
        open_ms,
        verify_ms,
        paper_worker_commit_max_ms: 0.0,
        paper_worker_commit_sum_ms: 0.0,
        paper_worker_open_max_ms: 0.0,
        paper_worker_open_sum_ms: 0.0,
        paper_master_assemble_ms: 0.0,
        paper_worker_verify_max_ms: 0.0,
        paper_worker_verify_sum_ms: 0.0,
        paper_master_verify_ms: 0.0,
        paper_batch_claim_ms: 0.0,
        paper_batch_sumcheck_ms: 0.0,
        paper_batch_combined_open_ms: 0.0,
        paper_batch_merkle_ms: 0.0,
        paper_batch_verify_ms: 0.0,
        paper_individual_worker_proof_count: 0,
        paper_batched_proof_count: 0,
        worker_eval_commit_ms: open_profile.worker_eval_commit_ms,
        column_open_ms: open_profile.column_open_ms,
        f2_open_ms: open_profile.f2_open_ms,
        protocol10_e1_sumcheck_ms: open_profile.protocol10_e1_sumcheck_ms,
        protocol10_e1_open_ms: open_profile.protocol10_e1_open_ms,
        protocol10_e1_opening_batch_open_ms: open_profile.protocol10_e1_opening_batch_open_ms,
        protocol10_e1_hu_open_ms: open_profile.protocol10_e1_hu_open_ms,
        protocol10_e1_e_at_r_open_ms: open_profile.protocol10_e1_e_at_r_open_ms,
        protocol10_e1_f_at_u_prime_open_ms: open_profile.protocol10_e1_f_at_u_prime_open_ms,
        protocol10_e1_e_systematic_open_ms: open_profile.protocol10_e1_e_systematic_open_ms,
        protocol10_e2_sumcheck_ms: open_profile.protocol10_e2_sumcheck_ms,
        protocol10_e2_open_ms: open_profile.protocol10_e2_open_ms,
        protocol10_e2_opening_batch_open_ms: open_profile.protocol10_e2_opening_batch_open_ms,
        protocol10_e2_hu_open_ms: open_profile.protocol10_e2_hu_open_ms,
        protocol10_e2_e_at_r_open_ms: open_profile.protocol10_e2_e_at_r_open_ms,
        protocol10_e2_f_at_u_prime_open_ms: open_profile.protocol10_e2_f_at_u_prime_open_ms,
        protocol10_e2_e_systematic_open_ms: open_profile.protocol10_e2_e_systematic_open_ms,
        proof_size_accounting_ms,
        column_verify_ms: verify_profile.column_verify_ms,
        f2_verify_ms: verify_profile.f2_verify_ms,
        protocol10_e1_verify_ms: verify_profile.protocol10_e1_verify_ms,
        protocol10_e2_verify_ms: verify_profile.protocol10_e2_verify_ms,
        proof_commitment_object_bytes: commitment_bytes,
        proof_point_query_public_bytes: proof_size_breakdown.point_query_public_bytes,
        proof_eval_commitments_bytes: proof_size_breakdown.eval_commitments_bytes,
        proof_merkle_roots_bytes: proof_size_breakdown.merkle_roots_bytes,
        proof_column_openings_bytes: proof_size_breakdown.column_openings_bytes,
        proof_f2_openings_bytes: proof_size_breakdown.f2_openings_bytes,
        proof_protocol10_e1_bytes: proof_size_breakdown.protocol10_e1_bytes,
        proof_protocol10_e2_bytes: proof_size_breakdown.protocol10_e2_bytes,
        proof_transcript_overhead_bytes: proof_size_breakdown.transcript_overhead_bytes,
        proof_p10_e1_commitments_bytes: proof_size_breakdown.protocol10_e1.commitments_bytes,
        proof_p10_e1_public_scalars_bytes: proof_size_breakdown.protocol10_e1.public_scalars_bytes,
        proof_p10_e1_opening_batch_bytes: proof_size_breakdown.protocol10_e1.opening_batch_bytes,
        proof_p10_e1_hu_opening_bytes: proof_size_breakdown.protocol10_e1.hu_opening_bytes,
        proof_p10_e1_sumcheck_bytes: proof_size_breakdown.protocol10_e1.sumcheck_bytes,
        proof_p10_e1_e_at_r_openings_bytes: proof_size_breakdown
            .protocol10_e1
            .e_at_r_openings_bytes,
        proof_p10_e1_f_at_u_prime_openings_bytes: proof_size_breakdown
            .protocol10_e1
            .f_at_u_prime_openings_bytes,
        proof_p10_e1_e_systematic_openings_bytes: proof_size_breakdown
            .protocol10_e1
            .e_systematic_openings_bytes,
        proof_p10_e2_commitments_bytes: proof_size_breakdown.protocol10_e2.commitments_bytes,
        proof_p10_e2_public_scalars_bytes: proof_size_breakdown.protocol10_e2.public_scalars_bytes,
        proof_p10_e2_opening_batch_bytes: proof_size_breakdown.protocol10_e2.opening_batch_bytes,
        proof_p10_e2_hu_opening_bytes: proof_size_breakdown.protocol10_e2.hu_opening_bytes,
        proof_p10_e2_sumcheck_bytes: proof_size_breakdown.protocol10_e2.sumcheck_bytes,
        proof_p10_e2_e_at_r_openings_bytes: proof_size_breakdown
            .protocol10_e2
            .e_at_r_openings_bytes,
        proof_p10_e2_f_at_u_prime_openings_bytes: proof_size_breakdown
            .protocol10_e2
            .f_at_u_prime_openings_bytes,
        proof_p10_e2_e_systematic_openings_bytes: proof_size_breakdown
            .protocol10_e2
            .e_systematic_openings_bytes,
        proof_bytes,
        communication_bytes: comm_bytes,
        verifier_communication_bytes: proof_bytes,
        scheme_reported_communication_bytes: 0,
        communication_basis: "master_worker_sent_recv".to_owned(),
        network_commit_bytes,
        network_open_bytes,
        network_bytes,
        host_logical_cores,
        cores_per_worker,
        core_affinity: core_affinity_label(workers, cores_per_worker),
        backend_source: "legacy-local-goldilocks-rs-merkle".to_owned(),
        field: "Goldilocks".to_owned(),
        hash: "SHA-256".to_owned(),
        code_rate_log: rate_inv_to_code_rate_log(backend.rate_inv),
        security_target_bits: security_bits,
        security_effective_bits: verify_profile.query_security_bits,
        security_exact: verify_profile.query_security_bits == security_bits,
        query_count_semantics: "legacy-local-query-derived".to_owned(),
        source_rev: "local-pq-pcs".to_owned(),
        verified,
        failure_reason,
    };
    let scope = format!(
        "runner=local-network opening={} nv={} workers={} trial={}",
        opening.as_str(),
        variable_count(size),
        workers,
        trial
    );
    let timings = vec![
        PhaseTimingRecord {
            phase: "job".to_owned(),
            scope: scope.clone(),
            elapsed_ms: commit_ms + open_ms + verify_ms,
            commit_ms,
            open_ms,
            verify_ms,
        },
        phase_record(
            "worker_eval_commit",
            &scope,
            open_profile.worker_eval_commit_ms,
        ),
        phase_record("column_open", &scope, open_profile.column_open_ms),
        phase_record("f2_open", &scope, open_profile.f2_open_ms),
        phase_record(
            "protocol10_e1_sumcheck",
            &scope,
            open_profile.protocol10_e1_sumcheck_ms,
        ),
        phase_record(
            "protocol10_e1_open",
            &scope,
            open_profile.protocol10_e1_open_ms,
        ),
        phase_record(
            "p10_e1_hu_open",
            &scope,
            open_profile.protocol10_e1_hu_open_ms,
        ),
        phase_record(
            "p10_e1_e_at_r_open",
            &scope,
            open_profile.protocol10_e1_e_at_r_open_ms,
        ),
        phase_record(
            "p10_e1_f_at_u_prime_open",
            &scope,
            open_profile.protocol10_e1_f_at_u_prime_open_ms,
        ),
        phase_record(
            "p10_e1_e_systematic_open",
            &scope,
            open_profile.protocol10_e1_e_systematic_open_ms,
        ),
        phase_record(
            "protocol10_e2_sumcheck",
            &scope,
            open_profile.protocol10_e2_sumcheck_ms,
        ),
        phase_record(
            "protocol10_e2_open",
            &scope,
            open_profile.protocol10_e2_open_ms,
        ),
        phase_record(
            "p10_e2_hu_open",
            &scope,
            open_profile.protocol10_e2_hu_open_ms,
        ),
        phase_record(
            "p10_e2_e_at_r_open",
            &scope,
            open_profile.protocol10_e2_e_at_r_open_ms,
        ),
        phase_record(
            "p10_e2_f_at_u_prime_open",
            &scope,
            open_profile.protocol10_e2_f_at_u_prime_open_ms,
        ),
        phase_record(
            "p10_e2_e_systematic_open",
            &scope,
            open_profile.protocol10_e2_e_systematic_open_ms,
        ),
        phase_record("proof_size_accounting", &scope, proof_size_accounting_ms),
        phase_record("column_verify", &scope, verify_profile.column_verify_ms),
        phase_record("f2_verify", &scope, verify_profile.f2_verify_ms),
        phase_record(
            "protocol10_e1_verify",
            &scope,
            verify_profile.protocol10_e1_verify_ms,
        ),
        phase_record(
            "protocol10_e2_verify",
            &scope,
            verify_profile.protocol10_e2_verify_ms,
        ),
    ];
    let fixture = PcsProofFixture {
        row_id: pcs_row_id(&record),
        backend,
        params,
        commitment,
        proof,
        transcript_label: "pq-experiments-depcs-benchmark".to_owned(),
    };
    Ok((record, timings, Some(fixture)))
}

fn run_single_depcs_job(
    job: PcsBenchmarkJob,
) -> Result<
    (
        PcsMetricRecord,
        Vec<PhaseTimingRecord>,
        Option<PcsProofFixture>,
    ),
    CliError,
> {
    let paper_backend = match job.backend.kind {
        PcsBackendKind::BaseFold => PaperPcsBackend::BaseFold,
        PcsBackendKind::DeepFold => PaperPcsBackend::DeepFold,
    };
    let config = PaperDepcsConfig::new(paper_backend, job.backend.rate_inv)
        .map_err(|error| CliError(format!("invalid paper dePCS config: {error:?}")))?;
    validate_partition_shape(job.size, job.workers)?;
    let host_logical_cores = std::thread::available_parallelism().map_or(1, usize::from);
    let partition_start = Instant::now();
    let partition_ms = elapsed_ms(partition_start);
    let network_run =
        run_paper_network_protocol11(job.size, job.workers, config, job.cores_per_worker)?;
    let commitment_bytes = depcs::commitment_size_bytes(&network_run.commitment);
    let opening_proof_bytes = depcs::proof_size_bytes(&network_run.proof);
    let proof_size_breakdown = depcs::proof_size_breakdown(&network_run.proof);
    let proof_size_accounting_ms = 0.0;
    let proof_bytes = commitment_bytes + opening_proof_bytes;
    let network_commit_bytes = network_run.network_commit_bytes;
    let network_open_bytes = network_run.network_open_bytes;
    let network_bytes = network_commit_bytes + network_open_bytes;
    let effective_queries = config.query_count();
    let scheme = match paper_backend {
        PaperPcsBackend::BaseFold => "depcs-basefold-paper-protocol11",
        PaperPcsBackend::DeepFold => "depcs-deepfold-paper-protocol11",
    };
    let record = PcsMetricRecord {
        scheme: scheme.to_owned(),
        backend: paper_backend.as_str().to_owned(),
        backend_rate_inv: config.rate_inv,
        effective_query_count: effective_queries,
        column_query_count: network_run.verify_profile.column_query_count,
        pcs_query_count: network_run.verify_profile.pcs_query_count,
        query_security_bits: network_run.verify_profile.query_security_bits,
        algebraic_security_bits: network_run.verify_profile.algebraic_security_bits,
        batch_claim_count: network_run.proof.opening_batch.claims.len(),
        batch_open_ms: network_run.open_ms,
        batch_verify_ms: network_run.verify_ms,
        batch_proof_bytes: opening_proof_bytes,
        runner: "paper-network-protocol11".to_owned(),
        opening: job.opening.as_str().to_owned(),
        trial: job.trial,
        workers: job.workers,
        variable_count: variable_count(job.size),
        polynomial_length: job.size,
        t_rows_per_worker: network_run.commitment.shard_len,
        paper_b_target: network_run.commitment.original_len,
        shard_len: network_run.commitment.shard_len,
        pcs_queries_requested: job.pcs_queries,
        pcs_queries_effective: effective_queries,
        partition_ms,
        worker_commit_ms: network_run.commit_ms,
        master_commit_ms: 0.0,
        commit_ms: network_run.commit_ms,
        open_ms: network_run.open_ms,
        verify_ms: network_run.verify_ms,
        paper_worker_commit_max_ms: network_run.paper_worker_commit_max_ms,
        paper_worker_commit_sum_ms: network_run.paper_worker_commit_sum_ms,
        paper_worker_open_max_ms: network_run.paper_worker_open_max_ms,
        paper_worker_open_sum_ms: network_run.paper_worker_open_sum_ms,
        paper_master_assemble_ms: network_run.paper_master_assemble_ms,
        paper_worker_verify_max_ms: network_run.paper_worker_verify_max_ms,
        paper_worker_verify_sum_ms: network_run.paper_worker_verify_sum_ms,
        paper_master_verify_ms: network_run.paper_master_verify_ms,
        paper_batch_claim_ms: 0.0,
        paper_batch_sumcheck_ms: 0.0,
        paper_batch_combined_open_ms: 0.0,
        paper_batch_merkle_ms: 0.0,
        paper_batch_verify_ms: 0.0,
        paper_individual_worker_proof_count: job.workers,
        paper_batched_proof_count: job.workers,
        worker_eval_commit_ms: network_run.open_profile.worker_eval_commit_ms,
        column_open_ms: network_run.open_profile.column_open_ms,
        f2_open_ms: network_run.open_profile.f2_open_ms,
        protocol10_e1_sumcheck_ms: network_run.open_profile.protocol10_e1_sumcheck_ms,
        protocol10_e1_open_ms: network_run.open_profile.protocol10_e1_open_ms,
        protocol10_e1_opening_batch_open_ms: network_run
            .open_profile
            .protocol10_e1_opening_batch_open_ms,
        protocol10_e1_hu_open_ms: network_run.open_profile.protocol10_e1_hu_open_ms,
        protocol10_e1_e_at_r_open_ms: network_run.open_profile.protocol10_e1_e_at_r_open_ms,
        protocol10_e1_f_at_u_prime_open_ms: network_run
            .open_profile
            .protocol10_e1_f_at_u_prime_open_ms,
        protocol10_e1_e_systematic_open_ms: network_run
            .open_profile
            .protocol10_e1_e_systematic_open_ms,
        protocol10_e2_sumcheck_ms: network_run.open_profile.protocol10_e2_sumcheck_ms,
        protocol10_e2_open_ms: network_run.open_profile.protocol10_e2_open_ms,
        protocol10_e2_opening_batch_open_ms: network_run
            .open_profile
            .protocol10_e2_opening_batch_open_ms,
        protocol10_e2_hu_open_ms: network_run.open_profile.protocol10_e2_hu_open_ms,
        protocol10_e2_e_at_r_open_ms: network_run.open_profile.protocol10_e2_e_at_r_open_ms,
        protocol10_e2_f_at_u_prime_open_ms: network_run
            .open_profile
            .protocol10_e2_f_at_u_prime_open_ms,
        protocol10_e2_e_systematic_open_ms: network_run
            .open_profile
            .protocol10_e2_e_systematic_open_ms,
        proof_size_accounting_ms,
        column_verify_ms: network_run.verify_profile.column_verify_ms,
        f2_verify_ms: network_run.verify_profile.f2_verify_ms,
        protocol10_e1_verify_ms: network_run.verify_profile.protocol10_e1_verify_ms,
        protocol10_e2_verify_ms: network_run.verify_profile.protocol10_e2_verify_ms,
        proof_commitment_object_bytes: commitment_bytes,
        proof_point_query_public_bytes: proof_size_breakdown.point_query_public_bytes,
        proof_eval_commitments_bytes: proof_size_breakdown.eval_commitments_bytes,
        proof_merkle_roots_bytes: proof_size_breakdown.merkle_roots_bytes,
        proof_column_openings_bytes: proof_size_breakdown.column_openings_bytes,
        proof_f2_openings_bytes: proof_size_breakdown.f2_openings_bytes,
        proof_protocol10_e1_bytes: proof_size_breakdown.protocol10_e1_bytes,
        proof_protocol10_e2_bytes: proof_size_breakdown.protocol10_e2_bytes,
        proof_transcript_overhead_bytes: proof_size_breakdown.transcript_overhead_bytes,
        proof_p10_e1_commitments_bytes: 0,
        proof_p10_e1_public_scalars_bytes: proof_size_breakdown.point_query_public_bytes / 2,
        proof_p10_e1_opening_batch_bytes: proof_size_breakdown.protocol10_e1_bytes,
        proof_p10_e1_hu_opening_bytes: 0,
        proof_p10_e1_sumcheck_bytes: 0,
        proof_p10_e1_e_at_r_openings_bytes: 0,
        proof_p10_e1_f_at_u_prime_openings_bytes: 0,
        proof_p10_e1_e_systematic_openings_bytes: 0,
        proof_p10_e2_commitments_bytes: 0,
        proof_p10_e2_public_scalars_bytes: proof_size_breakdown
            .point_query_public_bytes
            .saturating_sub(proof_size_breakdown.point_query_public_bytes / 2),
        proof_p10_e2_opening_batch_bytes: proof_size_breakdown.protocol10_e2_bytes,
        proof_p10_e2_hu_opening_bytes: 0,
        proof_p10_e2_sumcheck_bytes: 0,
        proof_p10_e2_e_at_r_openings_bytes: 0,
        proof_p10_e2_f_at_u_prime_openings_bytes: 0,
        proof_p10_e2_e_systematic_openings_bytes: 0,
        proof_bytes,
        communication_bytes: network_bytes,
        verifier_communication_bytes: proof_bytes,
        scheme_reported_communication_bytes: 0,
        communication_basis: "master_worker_sent_recv".to_owned(),
        network_commit_bytes,
        network_open_bytes,
        network_bytes,
        host_logical_cores,
        cores_per_worker: job.cores_per_worker,
        core_affinity: core_affinity_label(job.workers, job.cores_per_worker),
        backend_source: "deepfold-bench-v0.1-paper-artifact".to_owned(),
        field: "Mersenne61Ext".to_owned(),
        hash: PAPER_PCS_HASH.to_owned(),
        code_rate_log: config.code_rate_log(),
        security_target_bits: PAPER_PCS_SECURITY_BITS,
        security_effective_bits: network_run.verify_profile.query_security_bits,
        security_exact: network_run.verify_profile.query_security_bits == PAPER_PCS_SECURITY_BITS,
        query_count_semantics: "paper-backed-protocol11-artifact".to_owned(),
        source_rev: PAPER_PCS_SOURCE_REV.to_owned(),
        verified: true,
        failure_reason: String::new(),
    };
    let scope = format!(
        "runner=paper-network-protocol11 opening={} nv={} workers={} trial={}",
        job.opening.as_str(),
        variable_count(job.size),
        job.workers,
        job.trial
    );
    let timings = vec![
        PhaseTimingRecord {
            phase: "job".to_owned(),
            scope: scope.clone(),
            elapsed_ms: network_run.commit_ms + network_run.open_ms + network_run.verify_ms,
            commit_ms: network_run.commit_ms,
            open_ms: network_run.open_ms,
            verify_ms: network_run.verify_ms,
        },
        phase_record("paper_worker_commit", &scope, network_run.commit_ms),
        phase_record("paper_protocol11_open", &scope, network_run.open_ms),
        phase_record("paper_protocol11_verify", &scope, network_run.verify_ms),
    ];
    Ok((record, timings, None))
}

fn run_single_depcs_batch_job(
    job: PcsBenchmarkJob,
) -> Result<
    (
        PcsMetricRecord,
        Vec<PhaseTimingRecord>,
        Option<PcsProofFixture>,
    ),
    CliError,
> {
    let reason = match job.backend.kind {
        PcsBackendKind::BaseFold => {
            "batch_unavailable_basefold_artifact_no_batch_api: BaseFold artifact exposes only single-polynomial prove/verify; refusing to emulate batch with individual worker proofs"
        }
        PcsBackendKind::DeepFold => {
            "batch_unavailable_deepfold_artifact_native_batch_api_missing: LigeSIS batch/multi-open requires ark_ff::PrimeField + HasQuadraticExtension, while paper dePCS uses DeepFold artifact Mersenne61Ext/RandomOracle/Merkle; refusing to swap backend or use digest-only Protocol10/11 placeholders"
        }
    };
    Err(CliError(format!(
        "paper-backed protocol11-batch unavailable for backend={} nv={} workers={}: {reason}",
        job.backend.kind.as_str(),
        variable_count(job.size),
        job.workers
    )))
}

fn run_single_paper_pcs_job(
    job: PcsBenchmarkJob,
) -> Result<
    (
        PcsMetricRecord,
        Vec<PhaseTimingRecord>,
        Option<PcsProofFixture>,
    ),
    CliError,
> {
    let backend = match job.backend.kind {
        PcsBackendKind::BaseFold => PaperPcsBackend::BaseFold,
        PcsBackendKind::DeepFold => PaperPcsBackend::DeepFold,
    };
    let nv = variable_count(job.size);
    let paper = run_paper_pcs_with_options(
        backend,
        nv,
        job.paper_query_policy,
        job.paper_code_rate_log
            .unwrap_or_else(|| rate_inv_to_code_rate_log(job.backend.rate_inv)),
    );
    let host_logical_cores = std::thread::available_parallelism().map_or(1, usize::from);
    let record = pcs_record_from_paper_run(&paper, &job, host_logical_cores);
    let scope = format!(
        "{}|{}|nv{}|workers{}|trial{}",
        record.scheme, record.opening, record.variable_count, record.workers, record.trial
    );
    let timings = vec![
        PhaseTimingRecord {
            phase: "job".to_owned(),
            scope: scope.clone(),
            elapsed_ms: paper.commit_ms + paper.open_ms + paper.verify_ms,
            commit_ms: paper.commit_ms,
            open_ms: paper.open_ms,
            verify_ms: paper.verify_ms,
        },
        phase_record("paper_commit", &scope, paper.commit_ms),
        phase_record("paper_open", &scope, paper.open_ms),
        phase_record("paper_verify", &scope, paper.verify_ms),
    ];
    Ok((record, timings, None))
}

fn pcs_record_from_paper_run(
    paper: &PaperPcsRun,
    job: &PcsBenchmarkJob,
    host_logical_cores: usize,
) -> PcsMetricRecord {
    let protocol11_shim = job.opening == PcsOpeningVariant::Protocol11;
    let scheme = match (protocol11_shim, paper.backend) {
        (true, PaperPcsBackend::BaseFold) => "depcs-basefold-paper-protocol11",
        (true, PaperPcsBackend::DeepFold) => "depcs-deepfold-paper-protocol11",
        (false, _) => paper.backend.scheme_name(),
    };
    let runner = if protocol11_shim {
        "paper-backed-protocol11"
    } else {
        "paper-native"
    };
    let query_count_semantics = if protocol11_shim {
        "paper-backed-protocol11-artifact"
    } else {
        "paper-native-artifact"
    };
    PcsMetricRecord {
        scheme: scheme.to_owned(),
        backend: paper.backend.as_str().to_owned(),
        backend_rate_inv: paper.rate_inv,
        effective_query_count: paper.query_count,
        column_query_count: 0,
        pcs_query_count: paper.query_count,
        query_security_bits: paper.security_bits,
        algebraic_security_bits: 122,
        batch_claim_count: 1,
        batch_open_ms: paper.open_ms,
        batch_verify_ms: paper.verify_ms,
        batch_proof_bytes: paper.proof_bytes,
        runner: runner.to_owned(),
        opening: job.opening.as_str().to_owned(),
        trial: job.trial,
        workers: job.workers,
        variable_count: paper.nv,
        polynomial_length: paper.polynomial_length,
        t_rows_per_worker: 0,
        paper_b_target: 0,
        shard_len: 0,
        pcs_queries_requested: job.pcs_queries,
        pcs_queries_effective: paper.query_count,
        partition_ms: 0.0,
        worker_commit_ms: paper.commit_ms,
        master_commit_ms: 0.0,
        commit_ms: paper.commit_ms,
        open_ms: paper.open_ms,
        verify_ms: paper.verify_ms,
        paper_worker_commit_max_ms: 0.0,
        paper_worker_commit_sum_ms: 0.0,
        paper_worker_open_max_ms: 0.0,
        paper_worker_open_sum_ms: 0.0,
        paper_master_assemble_ms: 0.0,
        paper_worker_verify_max_ms: 0.0,
        paper_worker_verify_sum_ms: 0.0,
        paper_master_verify_ms: 0.0,
        paper_batch_claim_ms: 0.0,
        paper_batch_sumcheck_ms: 0.0,
        paper_batch_combined_open_ms: 0.0,
        paper_batch_merkle_ms: 0.0,
        paper_batch_verify_ms: 0.0,
        paper_individual_worker_proof_count: 0,
        paper_batched_proof_count: 0,
        worker_eval_commit_ms: 0.0,
        column_open_ms: 0.0,
        f2_open_ms: 0.0,
        protocol10_e1_sumcheck_ms: 0.0,
        protocol10_e1_open_ms: 0.0,
        protocol10_e1_opening_batch_open_ms: 0.0,
        protocol10_e1_hu_open_ms: 0.0,
        protocol10_e1_e_at_r_open_ms: 0.0,
        protocol10_e1_f_at_u_prime_open_ms: 0.0,
        protocol10_e1_e_systematic_open_ms: 0.0,
        protocol10_e2_sumcheck_ms: 0.0,
        protocol10_e2_open_ms: 0.0,
        protocol10_e2_opening_batch_open_ms: 0.0,
        protocol10_e2_hu_open_ms: 0.0,
        protocol10_e2_e_at_r_open_ms: 0.0,
        protocol10_e2_f_at_u_prime_open_ms: 0.0,
        protocol10_e2_e_systematic_open_ms: 0.0,
        proof_size_accounting_ms: 0.0,
        column_verify_ms: 0.0,
        f2_verify_ms: 0.0,
        protocol10_e1_verify_ms: 0.0,
        protocol10_e2_verify_ms: 0.0,
        proof_commitment_object_bytes: paper.commitment_bytes,
        proof_point_query_public_bytes: 0,
        proof_eval_commitments_bytes: 0,
        proof_merkle_roots_bytes: paper.commitment_bytes,
        proof_column_openings_bytes: 0,
        proof_f2_openings_bytes: 0,
        proof_protocol10_e1_bytes: 0,
        proof_protocol10_e2_bytes: 0,
        proof_transcript_overhead_bytes: 0,
        proof_p10_e1_commitments_bytes: 0,
        proof_p10_e1_public_scalars_bytes: 0,
        proof_p10_e1_opening_batch_bytes: 0,
        proof_p10_e1_hu_opening_bytes: 0,
        proof_p10_e1_sumcheck_bytes: 0,
        proof_p10_e1_e_at_r_openings_bytes: 0,
        proof_p10_e1_f_at_u_prime_openings_bytes: 0,
        proof_p10_e1_e_systematic_openings_bytes: 0,
        proof_p10_e2_commitments_bytes: 0,
        proof_p10_e2_public_scalars_bytes: 0,
        proof_p10_e2_opening_batch_bytes: 0,
        proof_p10_e2_hu_opening_bytes: 0,
        proof_p10_e2_sumcheck_bytes: 0,
        proof_p10_e2_e_at_r_openings_bytes: 0,
        proof_p10_e2_f_at_u_prime_openings_bytes: 0,
        proof_p10_e2_e_systematic_openings_bytes: 0,
        proof_bytes: paper.commitment_bytes + paper.proof_bytes,
        communication_bytes: 0,
        verifier_communication_bytes: paper.communication_bytes,
        scheme_reported_communication_bytes: 0,
        communication_basis: "verifier_commitment_plus_proof".to_owned(),
        network_commit_bytes: 0,
        network_open_bytes: 0,
        network_bytes: 0,
        host_logical_cores,
        cores_per_worker: job.cores_per_worker,
        core_affinity: format!(
            "paper-native;field={};hash={};source_rev={};license={};query_policy={};code_rate_log={}",
            paper.field,
            paper.hash,
            paper.source_rev,
            paper.license,
            paper.query_policy,
            paper.code_rate_log
        ),
        backend_source: "deepfold-bench-v0.1-paper-artifact".to_owned(),
        field: paper.field.to_owned(),
        hash: paper.hash.to_owned(),
        code_rate_log: paper.code_rate_log,
        security_target_bits: PAPER_PCS_SECURITY_BITS,
        security_effective_bits: paper.security_bits,
        security_exact: paper.security_bits == PAPER_PCS_SECURITY_BITS,
        query_count_semantics: query_count_semantics.to_owned(),
        source_rev: paper.source_rev.to_owned(),
        verified: paper.verified,
        failure_reason: paper.failure_reason.clone(),
    }
}

fn verify_pcs_results(command: VerifyPcsResultsCommand) -> Result<(), CliError> {
    let source_check = verify_pcs_source_csv(&command.dir)?;
    let fixture_rows = verify_pcs_proof_fixtures(&command.dir, source_check.depcs_rows)?;
    let summary_rows = verify_pcs_summary_csv(&command.dir)?;
    let phase_rows = verify_phase_timing_csv(&command.dir)?;
    match command.format {
        OutputFormat::Json => println!(
            "{{\"ok\":true,\"source_rows_checked\":{},\"proof_fixtures_checked\":{},\"summary_rows_checked\":{},\"phase_rows_checked\":{}}}",
            source_check.rows, fixture_rows, summary_rows, phase_rows
        ),
        OutputFormat::Csv => println!(
            "ok,source_rows_checked,proof_fixtures_checked,summary_rows_checked,phase_rows_checked\ntrue,{},{fixture_rows},{summary_rows},{phase_rows}",
            source_check.rows
        ),
    }
    Ok(())
}

fn phase_record(phase: &str, scope: &str, elapsed_ms: f64) -> PhaseTimingRecord {
    PhaseTimingRecord {
        phase: phase.to_owned(),
        scope: scope.to_owned(),
        elapsed_ms,
        commit_ms: 0.0,
        open_ms: 0.0,
        verify_ms: 0.0,
    }
}

fn verify_pcs_source_csv(dir: &Path) -> Result<SourceCsvCheck, CliError> {
    let content = fs::read_to_string(dir.join("source.csv"))
        .map_err(|error| CliError(format!("read PCS source.csv failed: {error}")))?;
    let mut lines = content.lines();
    let header = lines
        .next()
        .ok_or_else(|| CliError("PCS source.csv is empty".to_owned()))?;
    if header != PCS_SOURCE_CSV_HEADER {
        return Err(CliError("PCS source.csv has unexpected header".to_owned()));
    }
    let header_fields = split_csv_line(header);
    let scheme_idx = csv_field_index(&header_fields, "scheme")?;
    let polynomial_length_idx = csv_field_index(&header_fields, "polynomial_length")?;
    let workers_idx = csv_field_index(&header_fields, "workers")?;
    let proof_bytes_idx = csv_field_index(&header_fields, "proof_bytes")?;
    let communication_bytes_idx = csv_field_index(&header_fields, "communication_bytes")?;
    let communication_basis_idx = csv_field_index(&header_fields, "communication_basis")?;
    let network_bytes_idx = csv_field_index(&header_fields, "network_bytes")?;
    let backend_source_idx = csv_field_index(&header_fields, "backend_source")?;
    let verified_idx = csv_field_index(&header_fields, "verified")?;
    let mut rows = 0;
    let mut depcs_rows = 0;
    for (line_index, line) in lines.enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        let fields = split_csv_line(line);
        if fields.len() != header_fields.len() {
            return Err(CliError(format!(
                "PCS source.csv row {} has {} fields, expected {}",
                line_index + 2,
                fields.len(),
                header_fields.len()
            )));
        }
        let size = parse_csv_usize(&fields[polynomial_length_idx], "polynomial_length")?;
        let workers = parse_csv_usize(&fields[workers_idx], "workers")?;
        let proof_bytes = parse_csv_usize(&fields[proof_bytes_idx], "proof_bytes")?;
        let communication =
            parse_csv_usize(&fields[communication_bytes_idx], "communication_bytes")?;
        let network = parse_csv_usize(&fields[network_bytes_idx], "network_bytes")?;
        if size == 0 || !size.is_power_of_two() || workers == 0 || proof_bytes == 0 {
            return Err(CliError(format!(
                "PCS source.csv row {} has invalid core metrics",
                line_index + 2
            )));
        }
        if fields[verified_idx] != "true" {
            return Err(CliError(format!(
                "PCS source.csv row {} is not verified",
                line_index + 2
            )));
        }
        if fields[scheme_idx].starts_with("depcs-") {
            if fields[communication_basis_idx] != "master_worker_sent_recv"
                || communication == 0
                || communication != network
                || network == 0
            {
                return Err(CliError(format!(
                    "PCS source.csv row {} has invalid dePCS master/worker communication accounting",
                    line_index + 2
                )));
            }
            if !fields[backend_source_idx].contains("paper-artifact") {
                depcs_rows += 1;
            }
        }
        rows += 1;
    }
    if rows == 0 {
        return Err(CliError("PCS source.csv has no data rows".to_owned()));
    }
    Ok(SourceCsvCheck { rows, depcs_rows })
}

fn verify_pcs_proof_fixtures(dir: &Path, expected_depcs_rows: usize) -> Result<usize, CliError> {
    if expected_depcs_rows == 0 {
        return Ok(0);
    }
    let path = dir.join("proof_fixtures.jsonl");
    let content = fs::read_to_string(&path)
        .map_err(|error| CliError(format!("read {} failed: {error}", path.display())))?;
    let mut rows = 0;
    for (line_index, line) in content.lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        let fixture: PcsProofFixture = serde_json::from_str(line).map_err(|error| {
            CliError(format!(
                "parse proof fixture row {} failed: {error}",
                line_index + 1
            ))
        })?;
        let label = fixture.transcript_label.as_bytes();
        let mut transcript = HashTranscript::new(label);
        DistributedBrakedown::verify_profiled_with_config(
            &fixture.commitment,
            &fixture.proof,
            fixture.params,
            fixture.backend,
            &mut transcript,
        )
        .map_err(|error| {
            CliError(format!(
                "proof fixture row {} ({}) failed verification: {error:?}",
                line_index + 1,
                fixture.row_id
            ))
        })?;
        rows += 1;
    }
    if rows != expected_depcs_rows {
        return Err(CliError(format!(
            "proof fixture count {rows} does not match dePCS source rows {expected_depcs_rows}"
        )));
    }
    Ok(rows)
}

fn csv_field_index(fields: &[String], name: &str) -> Result<usize, CliError> {
    fields
        .iter()
        .position(|field| field == name)
        .ok_or_else(|| CliError(format!("CSV header is missing {name}")))
}

fn verify_pcs_summary_csv(dir: &Path) -> Result<usize, CliError> {
    let content = fs::read_to_string(dir.join("summary_stats.csv"))
        .map_err(|error| CliError(format!("read PCS summary_stats.csv failed: {error}")))?;
    let mut lines = content.lines();
    let header = lines
        .next()
        .ok_or_else(|| CliError("PCS summary_stats.csv is empty".to_owned()))?;
    if header != PCS_SUMMARY_STATS_CSV_HEADER {
        return Err(CliError(
            "PCS summary_stats.csv has unexpected header".to_owned(),
        ));
    }
    let rows = lines.filter(|line| !line.trim().is_empty()).count();
    if rows == 0 {
        return Err(CliError(
            "PCS summary_stats.csv has no aggregate rows".to_owned(),
        ));
    }
    Ok(rows)
}

fn verify_phase_timing_csv(dir: &Path) -> Result<usize, CliError> {
    let content = fs::read_to_string(dir.join("phase_timing.csv"))
        .map_err(|error| CliError(format!("read phase_timing.csv failed: {error}")))?;
    let mut lines = content.lines();
    let header = lines
        .next()
        .ok_or_else(|| CliError("phase_timing.csv is empty".to_owned()))?;
    if header != PHASE_TIMING_CSV_HEADER {
        return Err(CliError(
            "phase_timing.csv has unexpected header".to_owned(),
        ));
    }
    let mut rows = 0;
    for line in lines {
        if line.trim().is_empty() {
            continue;
        }
        let fields = split_csv_line(line);
        if fields.len() != 6 {
            return Err(CliError("phase_timing.csv has malformed row".to_owned()));
        }
        let elapsed = parse_csv_f64(&fields[2], "elapsed_ms")?;
        if elapsed < 0.0 {
            return Err(CliError(
                "phase_timing.csv elapsed_ms must be non-negative".to_owned(),
            ));
        }
        rows += 1;
    }
    if rows == 0 {
        return Err(CliError("phase_timing.csv has no data rows".to_owned()));
    }
    Ok(rows)
}

type PcsStatsGroupKey = (String, String, usize, String, String, usize, usize, usize);

fn pcs_benchmark_stats(records: &[PcsMetricRecord]) -> Vec<PcsStatsRecord> {
    let mut groups: BTreeMap<PcsStatsGroupKey, Vec<&PcsMetricRecord>> = BTreeMap::new();
    for record in records {
        groups
            .entry((
                record.scheme.clone(),
                record.backend.clone(),
                record.backend_rate_inv,
                record.runner.clone(),
                record.opening.clone(),
                record.workers,
                record.variable_count,
                record.polynomial_length,
            ))
            .or_default()
            .push(record);
    }
    groups
        .into_iter()
        .map(
            |(
                (
                    scheme,
                    backend,
                    backend_rate_inv,
                    runner,
                    opening,
                    workers,
                    variable_count,
                    polynomial_length,
                ),
                group,
            )| {
                PcsStatsRecord {
                    scheme,
                    backend,
                    backend_rate_inv,
                    runner,
                    opening,
                    workers,
                    variable_count,
                    polynomial_length,
                    samples: group.len(),
                    verified_count: group.iter().filter(|record| record.verified).count(),
                    effective_query_count: mean(
                        group
                            .iter()
                            .map(|record| record.effective_query_count as f64),
                    ),
                    column_query_count: mean(
                        group.iter().map(|record| record.column_query_count as f64),
                    ),
                    pcs_query_count: mean(group.iter().map(|record| record.pcs_query_count as f64)),
                    query_security_bits: mean(
                        group.iter().map(|record| record.query_security_bits as f64),
                    ),
                    algebraic_security_bits: mean(
                        group
                            .iter()
                            .map(|record| record.algebraic_security_bits as f64),
                    ),
                    batch_claim_count: mean(
                        group.iter().map(|record| record.batch_claim_count as f64),
                    ),
                    batch_open_ms: mean(group.iter().map(|record| record.batch_open_ms)),
                    batch_verify_ms: mean(group.iter().map(|record| record.batch_verify_ms)),
                    batch_proof_bytes: mean(
                        group.iter().map(|record| record.batch_proof_bytes as f64),
                    ),
                    commit_ms: mean_stddev(group.iter().map(|record| record.commit_ms)),
                    open_ms: mean_stddev(group.iter().map(|record| record.open_ms)),
                    verify_ms: mean_stddev(group.iter().map(|record| record.verify_ms)),
                    paper_worker_commit_max_ms: mean(
                        group.iter().map(|record| record.paper_worker_commit_max_ms),
                    ),
                    paper_worker_commit_sum_ms: mean(
                        group.iter().map(|record| record.paper_worker_commit_sum_ms),
                    ),
                    paper_worker_open_max_ms: mean(
                        group.iter().map(|record| record.paper_worker_open_max_ms),
                    ),
                    paper_worker_open_sum_ms: mean(
                        group.iter().map(|record| record.paper_worker_open_sum_ms),
                    ),
                    paper_master_assemble_ms: mean(
                        group.iter().map(|record| record.paper_master_assemble_ms),
                    ),
                    paper_worker_verify_max_ms: mean(
                        group.iter().map(|record| record.paper_worker_verify_max_ms),
                    ),
                    paper_worker_verify_sum_ms: mean(
                        group.iter().map(|record| record.paper_worker_verify_sum_ms),
                    ),
                    paper_master_verify_ms: mean(
                        group.iter().map(|record| record.paper_master_verify_ms),
                    ),
                    paper_batch_claim_ms: mean(
                        group.iter().map(|record| record.paper_batch_claim_ms),
                    ),
                    paper_batch_sumcheck_ms: mean(
                        group.iter().map(|record| record.paper_batch_sumcheck_ms),
                    ),
                    paper_batch_combined_open_ms: mean(
                        group
                            .iter()
                            .map(|record| record.paper_batch_combined_open_ms),
                    ),
                    paper_batch_merkle_ms: mean(
                        group.iter().map(|record| record.paper_batch_merkle_ms),
                    ),
                    paper_batch_verify_ms: mean(
                        group.iter().map(|record| record.paper_batch_verify_ms),
                    ),
                    paper_individual_worker_proof_count: mean(
                        group
                            .iter()
                            .map(|record| record.paper_individual_worker_proof_count as f64),
                    ),
                    paper_batched_proof_count: mean(
                        group
                            .iter()
                            .map(|record| record.paper_batched_proof_count as f64),
                    ),
                    worker_eval_commit_ms: mean(
                        group.iter().map(|record| record.worker_eval_commit_ms),
                    ),
                    column_open_ms: mean(group.iter().map(|record| record.column_open_ms)),
                    f2_open_ms: mean(group.iter().map(|record| record.f2_open_ms)),
                    protocol10_e1_sumcheck_ms: mean(
                        group.iter().map(|record| record.protocol10_e1_sumcheck_ms),
                    ),
                    protocol10_e1_open_ms: mean(
                        group.iter().map(|record| record.protocol10_e1_open_ms),
                    ),
                    protocol10_e1_opening_batch_open_ms: mean(
                        group
                            .iter()
                            .map(|record| record.protocol10_e1_opening_batch_open_ms),
                    ),
                    protocol10_e1_hu_open_ms: mean(
                        group.iter().map(|record| record.protocol10_e1_hu_open_ms),
                    ),
                    protocol10_e1_e_at_r_open_ms: mean(
                        group
                            .iter()
                            .map(|record| record.protocol10_e1_e_at_r_open_ms),
                    ),
                    protocol10_e1_f_at_u_prime_open_ms: mean(
                        group
                            .iter()
                            .map(|record| record.protocol10_e1_f_at_u_prime_open_ms),
                    ),
                    protocol10_e1_e_systematic_open_ms: mean(
                        group
                            .iter()
                            .map(|record| record.protocol10_e1_e_systematic_open_ms),
                    ),
                    protocol10_e2_sumcheck_ms: mean(
                        group.iter().map(|record| record.protocol10_e2_sumcheck_ms),
                    ),
                    protocol10_e2_open_ms: mean(
                        group.iter().map(|record| record.protocol10_e2_open_ms),
                    ),
                    protocol10_e2_opening_batch_open_ms: mean(
                        group
                            .iter()
                            .map(|record| record.protocol10_e2_opening_batch_open_ms),
                    ),
                    protocol10_e2_hu_open_ms: mean(
                        group.iter().map(|record| record.protocol10_e2_hu_open_ms),
                    ),
                    protocol10_e2_e_at_r_open_ms: mean(
                        group
                            .iter()
                            .map(|record| record.protocol10_e2_e_at_r_open_ms),
                    ),
                    protocol10_e2_f_at_u_prime_open_ms: mean(
                        group
                            .iter()
                            .map(|record| record.protocol10_e2_f_at_u_prime_open_ms),
                    ),
                    protocol10_e2_e_systematic_open_ms: mean(
                        group
                            .iter()
                            .map(|record| record.protocol10_e2_e_systematic_open_ms),
                    ),
                    proof_size_accounting_ms: mean(
                        group.iter().map(|record| record.proof_size_accounting_ms),
                    ),
                    column_verify_ms: mean(group.iter().map(|record| record.column_verify_ms)),
                    f2_verify_ms: mean(group.iter().map(|record| record.f2_verify_ms)),
                    protocol10_e1_verify_ms: mean(
                        group.iter().map(|record| record.protocol10_e1_verify_ms),
                    ),
                    protocol10_e2_verify_ms: mean(
                        group.iter().map(|record| record.protocol10_e2_verify_ms),
                    ),
                    proof_commitment_object_bytes: mean(
                        group
                            .iter()
                            .map(|record| record.proof_commitment_object_bytes as f64),
                    ),
                    proof_point_query_public_bytes: mean(
                        group
                            .iter()
                            .map(|record| record.proof_point_query_public_bytes as f64),
                    ),
                    proof_eval_commitments_bytes: mean(
                        group
                            .iter()
                            .map(|record| record.proof_eval_commitments_bytes as f64),
                    ),
                    proof_merkle_roots_bytes: mean(
                        group
                            .iter()
                            .map(|record| record.proof_merkle_roots_bytes as f64),
                    ),
                    proof_column_openings_bytes: mean(
                        group
                            .iter()
                            .map(|record| record.proof_column_openings_bytes as f64),
                    ),
                    proof_f2_openings_bytes: mean(
                        group
                            .iter()
                            .map(|record| record.proof_f2_openings_bytes as f64),
                    ),
                    proof_protocol10_e1_bytes: mean(
                        group
                            .iter()
                            .map(|record| record.proof_protocol10_e1_bytes as f64),
                    ),
                    proof_protocol10_e2_bytes: mean(
                        group
                            .iter()
                            .map(|record| record.proof_protocol10_e2_bytes as f64),
                    ),
                    proof_transcript_overhead_bytes: mean(
                        group
                            .iter()
                            .map(|record| record.proof_transcript_overhead_bytes as f64),
                    ),
                    proof_p10_e1_commitments_bytes: mean(
                        group
                            .iter()
                            .map(|record| record.proof_p10_e1_commitments_bytes as f64),
                    ),
                    proof_p10_e1_public_scalars_bytes: mean(
                        group
                            .iter()
                            .map(|record| record.proof_p10_e1_public_scalars_bytes as f64),
                    ),
                    proof_p10_e1_opening_batch_bytes: mean(
                        group
                            .iter()
                            .map(|record| record.proof_p10_e1_opening_batch_bytes as f64),
                    ),
                    proof_p10_e1_hu_opening_bytes: mean(
                        group
                            .iter()
                            .map(|record| record.proof_p10_e1_hu_opening_bytes as f64),
                    ),
                    proof_p10_e1_sumcheck_bytes: mean(
                        group
                            .iter()
                            .map(|record| record.proof_p10_e1_sumcheck_bytes as f64),
                    ),
                    proof_p10_e1_e_at_r_openings_bytes: mean(
                        group
                            .iter()
                            .map(|record| record.proof_p10_e1_e_at_r_openings_bytes as f64),
                    ),
                    proof_p10_e1_f_at_u_prime_openings_bytes: mean(
                        group
                            .iter()
                            .map(|record| record.proof_p10_e1_f_at_u_prime_openings_bytes as f64),
                    ),
                    proof_p10_e1_e_systematic_openings_bytes: mean(
                        group
                            .iter()
                            .map(|record| record.proof_p10_e1_e_systematic_openings_bytes as f64),
                    ),
                    proof_p10_e2_commitments_bytes: mean(
                        group
                            .iter()
                            .map(|record| record.proof_p10_e2_commitments_bytes as f64),
                    ),
                    proof_p10_e2_public_scalars_bytes: mean(
                        group
                            .iter()
                            .map(|record| record.proof_p10_e2_public_scalars_bytes as f64),
                    ),
                    proof_p10_e2_opening_batch_bytes: mean(
                        group
                            .iter()
                            .map(|record| record.proof_p10_e2_opening_batch_bytes as f64),
                    ),
                    proof_p10_e2_hu_opening_bytes: mean(
                        group
                            .iter()
                            .map(|record| record.proof_p10_e2_hu_opening_bytes as f64),
                    ),
                    proof_p10_e2_sumcheck_bytes: mean(
                        group
                            .iter()
                            .map(|record| record.proof_p10_e2_sumcheck_bytes as f64),
                    ),
                    proof_p10_e2_e_at_r_openings_bytes: mean(
                        group
                            .iter()
                            .map(|record| record.proof_p10_e2_e_at_r_openings_bytes as f64),
                    ),
                    proof_p10_e2_f_at_u_prime_openings_bytes: mean(
                        group
                            .iter()
                            .map(|record| record.proof_p10_e2_f_at_u_prime_openings_bytes as f64),
                    ),
                    proof_p10_e2_e_systematic_openings_bytes: mean(
                        group
                            .iter()
                            .map(|record| record.proof_p10_e2_e_systematic_openings_bytes as f64),
                    ),
                    proof_bytes: mean(group.iter().map(|record| record.proof_bytes as f64)),
                    communication_bytes: mean(
                        group.iter().map(|record| record.communication_bytes as f64),
                    ),
                    verifier_communication_bytes: mean(
                        group
                            .iter()
                            .map(|record| record.verifier_communication_bytes as f64),
                    ),
                    scheme_reported_communication_bytes: mean(
                        group
                            .iter()
                            .map(|record| record.scheme_reported_communication_bytes as f64),
                    ),
                    network_bytes: mean(group.iter().map(|record| record.network_bytes as f64)),
                    failure_reasons: group
                        .iter()
                        .filter_map(|record| {
                            if record.failure_reason.is_empty() {
                                None
                            } else {
                                Some(record.failure_reason.as_str())
                            }
                        })
                        .collect::<Vec<_>>()
                        .join(";"),
                }
            },
        )
        .collect()
}

fn pcs_records_to_csv(records: &[PcsMetricRecord]) -> String {
    let mut out = String::from(PCS_SOURCE_CSV_HEADER);
    out.push('\n');
    for record in records {
        out.push_str(&csv_join(record_source_fields(record)));
        out.push('\n');
    }
    out
}

fn pcs_comparison_summary_to_csv(records: &[PcsMetricRecord]) -> String {
    let mut out = String::from(PCS_COMPARISON_CSV_HEADER);
    out.push('\n');
    for record in records {
        out.push_str(&csv_join(vec![
            record.backend.clone(),
            record.variable_count.to_string(),
            record.polynomial_length.to_string(),
            record.backend_rate_inv.to_string(),
            record.code_rate_log.to_string(),
            record.query_security_bits.to_string(),
            record.pcs_query_count.to_string(),
            csv_escape(query_policy_for_record(record)),
            record.workers.to_string(),
            record.cores_per_worker.to_string(),
            fmt_f64(record.commit_ms),
            fmt_f64(record.open_ms),
            fmt_f64(record.verify_ms),
            record.proof_bytes.to_string(),
            record.proof_commitment_object_bytes.to_string(),
            record.communication_bytes.to_string(),
            record.verifier_communication_bytes.to_string(),
            record.scheme_reported_communication_bytes.to_string(),
            csv_escape(&record.communication_basis),
            record.network_bytes.to_string(),
            record.verified.to_string(),
            csv_escape(&record.failure_reason),
            csv_escape(source_rev_for_record(record)),
            csv_escape(source_url_for_record(record)),
            csv_escape(license_for_record(record)),
            csv_escape(field_for_record(record)),
            csv_escape(hash_for_record(record)),
            record.opening.clone(),
            csv_escape(&record.backend_source),
            record.security_target_bits.to_string(),
            record.security_effective_bits.to_string(),
            record.security_exact.to_string(),
            csv_escape(&record.query_count_semantics),
        ]));
        out.push('\n');
    }
    out
}

fn source_rev_for_record(record: &PcsMetricRecord) -> &str {
    if !record.source_rev.is_empty() {
        &record.source_rev
    } else if record.backend_source.contains("paper-artifact") {
        PAPER_PCS_SOURCE_REV
    } else {
        "local-pq-pcs"
    }
}

fn query_policy_for_record(record: &PcsMetricRecord) -> &str {
    if record.backend_source.contains("paper-artifact") {
        record
            .core_affinity
            .split(';')
            .find_map(|item| item.strip_prefix("query_policy="))
            .unwrap_or("unknown")
    } else {
        "fixed"
    }
}

fn source_url_for_record(record: &PcsMetricRecord) -> &'static str {
    if record.backend_source.contains("paper-artifact") {
        PAPER_PCS_SOURCE_URL
    } else {
        "local-workspace"
    }
}

fn license_for_record(record: &PcsMetricRecord) -> &'static str {
    if record.backend_source.contains("paper-artifact") {
        PAPER_PCS_LICENSE
    } else {
        "MIT OR Apache-2.0"
    }
}

fn field_for_record(record: &PcsMetricRecord) -> &'static str {
    if record.backend_source.contains("paper-artifact") {
        "Mersenne61Ext"
    } else {
        "Goldilocks"
    }
}

fn hash_for_record(record: &PcsMetricRecord) -> &'static str {
    if record.backend_source.contains("paper-artifact") {
        PAPER_PCS_HASH
    } else {
        "SHA-256"
    }
}

fn rate_inv_to_code_rate_log(rate_inv: usize) -> usize {
    if rate_inv.is_power_of_two() {
        rate_inv.trailing_zeros() as usize
    } else {
        0
    }
}

fn proof_fixtures_to_jsonl(fixtures: &[PcsProofFixture]) -> Result<String, CliError> {
    let mut out = String::new();
    for fixture in fixtures {
        out.push_str(
            &serde_json::to_string(fixture)
                .map_err(|error| CliError(format!("serialize proof fixture failed: {error}")))?,
        );
        out.push('\n');
    }
    Ok(out)
}

fn pcs_row_id(record: &PcsMetricRecord) -> String {
    format!(
        "{}|{}|rate{}|{}|nv{}|workers{}|trial{}",
        record.scheme,
        record.backend,
        record.backend_rate_inv,
        record.opening,
        record.variable_count,
        record.workers,
        record.trial
    )
}

fn pcs_summary_stats_to_csv(stats: &[PcsStatsRecord]) -> String {
    let mut out = String::from(PCS_SUMMARY_STATS_CSV_HEADER);
    out.push('\n');
    for record in stats {
        out.push_str(&csv_join(record_summary_fields(record)));
        out.push('\n');
    }
    out
}

fn csv_join(fields: Vec<String>) -> String {
    fields.join(",")
}

fn fmt_f64(value: f64) -> String {
    format!("{value:.6}")
}

fn fmt_f64_3(value: f64) -> String {
    format!("{value:.3}")
}

fn record_source_fields(record: &PcsMetricRecord) -> Vec<String> {
    vec![
        record.scheme.clone(),
        record.backend.clone(),
        record.backend_rate_inv.to_string(),
        record.effective_query_count.to_string(),
        record.column_query_count.to_string(),
        record.pcs_query_count.to_string(),
        record.query_security_bits.to_string(),
        record.algebraic_security_bits.to_string(),
        record.batch_claim_count.to_string(),
        fmt_f64(record.batch_open_ms),
        fmt_f64(record.batch_verify_ms),
        record.batch_proof_bytes.to_string(),
        record.runner.clone(),
        record.opening.clone(),
        record.trial.to_string(),
        record.workers.to_string(),
        record.variable_count.to_string(),
        record.polynomial_length.to_string(),
        record.t_rows_per_worker.to_string(),
        record.paper_b_target.to_string(),
        record.shard_len.to_string(),
        record.pcs_queries_requested.to_string(),
        record.pcs_queries_effective.to_string(),
        fmt_f64(record.partition_ms),
        fmt_f64(record.worker_commit_ms),
        fmt_f64(record.master_commit_ms),
        fmt_f64(record.commit_ms),
        fmt_f64(record.open_ms),
        fmt_f64(record.verify_ms),
        fmt_f64(record.paper_worker_commit_max_ms),
        fmt_f64(record.paper_worker_commit_sum_ms),
        fmt_f64(record.paper_worker_open_max_ms),
        fmt_f64(record.paper_worker_open_sum_ms),
        fmt_f64(record.paper_master_assemble_ms),
        fmt_f64(record.paper_worker_verify_max_ms),
        fmt_f64(record.paper_worker_verify_sum_ms),
        fmt_f64(record.paper_master_verify_ms),
        fmt_f64(record.paper_batch_claim_ms),
        fmt_f64(record.paper_batch_sumcheck_ms),
        fmt_f64(record.paper_batch_combined_open_ms),
        fmt_f64(record.paper_batch_merkle_ms),
        fmt_f64(record.paper_batch_verify_ms),
        record.paper_individual_worker_proof_count.to_string(),
        record.paper_batched_proof_count.to_string(),
        fmt_f64(record.worker_eval_commit_ms),
        fmt_f64(record.column_open_ms),
        fmt_f64(record.f2_open_ms),
        fmt_f64(record.protocol10_e1_sumcheck_ms),
        fmt_f64(record.protocol10_e1_open_ms),
        fmt_f64(record.protocol10_e1_opening_batch_open_ms),
        fmt_f64(record.protocol10_e1_hu_open_ms),
        fmt_f64(record.protocol10_e1_e_at_r_open_ms),
        fmt_f64(record.protocol10_e1_f_at_u_prime_open_ms),
        fmt_f64(record.protocol10_e1_e_systematic_open_ms),
        fmt_f64(record.protocol10_e2_sumcheck_ms),
        fmt_f64(record.protocol10_e2_open_ms),
        fmt_f64(record.protocol10_e2_opening_batch_open_ms),
        fmt_f64(record.protocol10_e2_hu_open_ms),
        fmt_f64(record.protocol10_e2_e_at_r_open_ms),
        fmt_f64(record.protocol10_e2_f_at_u_prime_open_ms),
        fmt_f64(record.protocol10_e2_e_systematic_open_ms),
        fmt_f64(record.proof_size_accounting_ms),
        fmt_f64(record.column_verify_ms),
        fmt_f64(record.f2_verify_ms),
        fmt_f64(record.protocol10_e1_verify_ms),
        fmt_f64(record.protocol10_e2_verify_ms),
        record.proof_commitment_object_bytes.to_string(),
        record.proof_point_query_public_bytes.to_string(),
        record.proof_eval_commitments_bytes.to_string(),
        record.proof_merkle_roots_bytes.to_string(),
        record.proof_column_openings_bytes.to_string(),
        record.proof_f2_openings_bytes.to_string(),
        record.proof_protocol10_e1_bytes.to_string(),
        record.proof_protocol10_e2_bytes.to_string(),
        record.proof_transcript_overhead_bytes.to_string(),
        record.proof_p10_e1_commitments_bytes.to_string(),
        record.proof_p10_e1_public_scalars_bytes.to_string(),
        record.proof_p10_e1_opening_batch_bytes.to_string(),
        record.proof_p10_e1_hu_opening_bytes.to_string(),
        record.proof_p10_e1_sumcheck_bytes.to_string(),
        record.proof_p10_e1_e_at_r_openings_bytes.to_string(),
        record.proof_p10_e1_f_at_u_prime_openings_bytes.to_string(),
        record.proof_p10_e1_e_systematic_openings_bytes.to_string(),
        record.proof_p10_e2_commitments_bytes.to_string(),
        record.proof_p10_e2_public_scalars_bytes.to_string(),
        record.proof_p10_e2_opening_batch_bytes.to_string(),
        record.proof_p10_e2_hu_opening_bytes.to_string(),
        record.proof_p10_e2_sumcheck_bytes.to_string(),
        record.proof_p10_e2_e_at_r_openings_bytes.to_string(),
        record.proof_p10_e2_f_at_u_prime_openings_bytes.to_string(),
        record.proof_p10_e2_e_systematic_openings_bytes.to_string(),
        record.proof_bytes.to_string(),
        record.communication_bytes.to_string(),
        record.verifier_communication_bytes.to_string(),
        record.scheme_reported_communication_bytes.to_string(),
        csv_escape(&record.communication_basis),
        record.network_commit_bytes.to_string(),
        record.network_open_bytes.to_string(),
        record.network_bytes.to_string(),
        record.host_logical_cores.to_string(),
        record.cores_per_worker.to_string(),
        csv_escape(&record.core_affinity),
        csv_escape(&record.backend_source),
        csv_escape(&record.field),
        csv_escape(&record.hash),
        record.code_rate_log.to_string(),
        record.security_target_bits.to_string(),
        record.security_effective_bits.to_string(),
        record.security_exact.to_string(),
        csv_escape(&record.query_count_semantics),
        csv_escape(&record.source_rev),
        record.verified.to_string(),
        csv_escape(&record.failure_reason),
    ]
}

fn record_summary_fields(record: &PcsStatsRecord) -> Vec<String> {
    vec![
        record.scheme.clone(),
        record.backend.clone(),
        record.backend_rate_inv.to_string(),
        record.runner.clone(),
        record.opening.clone(),
        record.workers.to_string(),
        record.variable_count.to_string(),
        record.polynomial_length.to_string(),
        record.samples.to_string(),
        record.verified_count.to_string(),
        fmt_f64_3(record.effective_query_count),
        fmt_f64_3(record.column_query_count),
        fmt_f64_3(record.pcs_query_count),
        fmt_f64_3(record.query_security_bits),
        fmt_f64_3(record.algebraic_security_bits),
        fmt_f64_3(record.batch_claim_count),
        fmt_f64(record.batch_open_ms),
        fmt_f64(record.batch_verify_ms),
        fmt_f64(record.batch_proof_bytes),
        fmt_f64(record.commit_ms.mean),
        fmt_f64(record.commit_ms.stddev),
        fmt_f64(record.open_ms.mean),
        fmt_f64(record.open_ms.stddev),
        fmt_f64(record.verify_ms.mean),
        fmt_f64(record.verify_ms.stddev),
        fmt_f64(record.paper_worker_commit_max_ms),
        fmt_f64(record.paper_worker_commit_sum_ms),
        fmt_f64(record.paper_worker_open_max_ms),
        fmt_f64(record.paper_worker_open_sum_ms),
        fmt_f64(record.paper_master_assemble_ms),
        fmt_f64(record.paper_worker_verify_max_ms),
        fmt_f64(record.paper_worker_verify_sum_ms),
        fmt_f64(record.paper_master_verify_ms),
        fmt_f64(record.paper_batch_claim_ms),
        fmt_f64(record.paper_batch_sumcheck_ms),
        fmt_f64(record.paper_batch_combined_open_ms),
        fmt_f64(record.paper_batch_merkle_ms),
        fmt_f64(record.paper_batch_verify_ms),
        fmt_f64(record.paper_individual_worker_proof_count),
        fmt_f64(record.paper_batched_proof_count),
        fmt_f64(record.worker_eval_commit_ms),
        fmt_f64(record.column_open_ms),
        fmt_f64(record.f2_open_ms),
        fmt_f64(record.protocol10_e1_sumcheck_ms),
        fmt_f64(record.protocol10_e1_open_ms),
        fmt_f64(record.protocol10_e1_opening_batch_open_ms),
        fmt_f64(record.protocol10_e1_hu_open_ms),
        fmt_f64(record.protocol10_e1_e_at_r_open_ms),
        fmt_f64(record.protocol10_e1_f_at_u_prime_open_ms),
        fmt_f64(record.protocol10_e1_e_systematic_open_ms),
        fmt_f64(record.protocol10_e2_sumcheck_ms),
        fmt_f64(record.protocol10_e2_open_ms),
        fmt_f64(record.protocol10_e2_opening_batch_open_ms),
        fmt_f64(record.protocol10_e2_hu_open_ms),
        fmt_f64(record.protocol10_e2_e_at_r_open_ms),
        fmt_f64(record.protocol10_e2_f_at_u_prime_open_ms),
        fmt_f64(record.protocol10_e2_e_systematic_open_ms),
        fmt_f64(record.proof_size_accounting_ms),
        fmt_f64(record.column_verify_ms),
        fmt_f64(record.f2_verify_ms),
        fmt_f64(record.protocol10_e1_verify_ms),
        fmt_f64(record.protocol10_e2_verify_ms),
        fmt_f64_3(record.proof_commitment_object_bytes),
        fmt_f64_3(record.proof_point_query_public_bytes),
        fmt_f64_3(record.proof_eval_commitments_bytes),
        fmt_f64_3(record.proof_merkle_roots_bytes),
        fmt_f64_3(record.proof_column_openings_bytes),
        fmt_f64_3(record.proof_f2_openings_bytes),
        fmt_f64_3(record.proof_protocol10_e1_bytes),
        fmt_f64_3(record.proof_protocol10_e2_bytes),
        fmt_f64_3(record.proof_transcript_overhead_bytes),
        fmt_f64_3(record.proof_p10_e1_commitments_bytes),
        fmt_f64_3(record.proof_p10_e1_public_scalars_bytes),
        fmt_f64_3(record.proof_p10_e1_opening_batch_bytes),
        fmt_f64_3(record.proof_p10_e1_hu_opening_bytes),
        fmt_f64_3(record.proof_p10_e1_sumcheck_bytes),
        fmt_f64_3(record.proof_p10_e1_e_at_r_openings_bytes),
        fmt_f64_3(record.proof_p10_e1_f_at_u_prime_openings_bytes),
        fmt_f64_3(record.proof_p10_e1_e_systematic_openings_bytes),
        fmt_f64_3(record.proof_p10_e2_commitments_bytes),
        fmt_f64_3(record.proof_p10_e2_public_scalars_bytes),
        fmt_f64_3(record.proof_p10_e2_opening_batch_bytes),
        fmt_f64_3(record.proof_p10_e2_hu_opening_bytes),
        fmt_f64_3(record.proof_p10_e2_sumcheck_bytes),
        fmt_f64_3(record.proof_p10_e2_e_at_r_openings_bytes),
        fmt_f64_3(record.proof_p10_e2_f_at_u_prime_openings_bytes),
        fmt_f64_3(record.proof_p10_e2_e_systematic_openings_bytes),
        fmt_f64_3(record.proof_bytes),
        fmt_f64_3(record.communication_bytes),
        fmt_f64_3(record.verifier_communication_bytes),
        fmt_f64_3(record.scheme_reported_communication_bytes),
        fmt_f64_3(record.network_bytes),
        csv_escape(&record.failure_reasons),
    ]
}

fn phase_timing_to_csv(timings: &[PhaseTimingRecord]) -> String {
    let mut out = String::from(PHASE_TIMING_CSV_HEADER);
    out.push('\n');
    for timing in timings {
        out.push_str(&format!(
            "{},{},{:.6},{:.6},{:.6},{:.6}\n",
            csv_escape(&timing.phase),
            csv_escape(&timing.scope),
            timing.elapsed_ms,
            timing.commit_ms,
            timing.open_ms,
            timing.verify_ms
        ));
    }
    out
}

fn pcs_benchmark_summary(command: &PcsBenchmarkCommand, records: &[PcsMetricRecord]) -> String {
    let mut out = String::new();
    out.push_str("# dePCS benchmark summary\n\n");
    out.push_str(&format!(
        "- polynomial_lengths: {:?}\n- workers: {:?}\n- cores_per_worker: {}\n- pcs_queries: {}\n- security_bits: {}\n- repeats: {}\n\n",
        command.sizes,
        command.workers,
        command.cores_per_worker,
        command.pcs_queries,
        command.security_bits,
        command.repeats
    ));
    out.push_str(
        "| opening | nv | polynomial length N | workers | commit ms | open ms | verify ms | proof KiB | send+recv KiB |\n",
    );
    out.push_str("| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |\n");
    for record in records {
        out.push_str(&format!(
            "| {} | {} | {} | {} | {:.3} | {:.3} | {:.3} | {:.2} | {:.2} |\n",
            record.opening,
            record.variable_count,
            record.polynomial_length,
            record.workers,
            record.commit_ms,
            record.open_ms,
            record.verify_ms,
            record.proof_bytes as f64 / 1024.0,
            record.communication_bytes as f64 / 1024.0
        ));
    }
    out
}

fn pcs_overview_html(records: &[PcsMetricRecord]) -> String {
    let mut html = String::from(
        "<!doctype html><meta charset=\"utf-8\"><title>dePCS benchmark</title><h1>dePCS benchmark</h1><table><thead><tr><th>opening</th><th>nv</th><th>polynomial length N</th><th>workers</th><th>prover ms</th><th>proof KiB</th></tr></thead><tbody>",
    );
    for record in records {
        html.push_str(&format!(
            "<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{:.3}</td><td>{:.2}</td></tr>",
            html_escape(&record.opening),
            record.variable_count,
            record.polynomial_length,
            record.workers,
            record.commit_ms + record.open_ms,
            record.proof_bytes as f64 / 1024.0
        ));
    }
    html.push_str("</tbody></table><p><a href=\"source.csv\">source.csv</a> <a href=\"summary_stats.csv\">summary_stats.csv</a> <a href=\"prover_time_by_nv.svg\">prover chart</a></p>");
    html
}

fn pcs_metadata_json(
    run_id: u128,
    command: &PcsBenchmarkCommand,
    records: &[PcsMetricRecord],
    elapsed_seconds: f64,
) -> String {
    format!(
        "{{\n  \"run_kind\": \"pcs-benchmark\",\n  \"run_id\": {},\n  \"polynomial_lengths\": {:?},\n  \"workers\": {:?},\n  \"cores_per_worker\": {},\n  \"pcs_queries\": {},\n  \"security_bits\": {},\n  \"repeats\": {},\n  \"records\": {},\n  \"elapsed_seconds\": {:.6}\n}}\n",
        run_id,
        command.sizes,
        command.workers,
        command.cores_per_worker,
        command.pcs_queries,
        command.security_bits,
        command.repeats,
        records.len(),
        elapsed_seconds
    )
}

fn write_simple_chart<F>(
    path: &Path,
    records: &[PcsMetricRecord],
    title: &str,
    value: F,
) -> Result<(), CliError>
where
    F: Fn(&PcsMetricRecord) -> f64,
{
    let width = 960.0;
    let row_height = 28.0;
    let height = 80.0 + row_height * records.len().max(1) as f64;
    let label_width = 260.0;
    let plot_width = width - label_width - 80.0;
    let max_value = records.iter().map(&value).fold(1.0_f64, f64::max);
    let mut svg = format!(
        "<svg xmlns=\"http://www.w3.org/2000/svg\" width=\"{width}\" height=\"{height}\" viewBox=\"0 0 {width} {height}\">\n<rect width=\"100%\" height=\"100%\" fill=\"#ffffff\"/>\n<text x=\"24\" y=\"34\" font-family=\"Arial\" font-size=\"18\" fill=\"#111827\">{}</text>\n",
        html_escape(title)
    );
    for (idx, record) in records.iter().enumerate() {
        let y = 62.0 + idx as f64 * row_height;
        let current = value(record);
        let bar = current / max_value * plot_width;
        let color = if record.opening == "protocol11" {
            "#2563eb"
        } else {
            "#d97706"
        };
        svg.push_str(&format!(
            "<text x=\"24\" y=\"{:.1}\" font-family=\"Arial\" font-size=\"12\" fill=\"#111827\">{} nv={} w={}</text>\n<rect x=\"{label_width}\" y=\"{:.1}\" width=\"{:.1}\" height=\"18\" fill=\"{color}\"/>\n<text x=\"{:.1}\" y=\"{:.1}\" font-family=\"Arial\" font-size=\"12\" fill=\"#111827\">{:.3}</text>\n",
            y + 14.0,
            record.opening,
            record.variable_count,
            record.workers,
            y,
            bar,
            label_width + bar + 8.0,
            y + 13.0,
            current
        ));
    }
    svg.push_str("</svg>\n");
    write_text_file(path, &svg)
}

fn write_phase_breakdown_chart(
    path: &Path,
    records: &[PcsMetricRecord],
    title: &str,
    opening: bool,
) -> Result<(), CliError> {
    let width = 1120.0;
    let row_height = 32.0;
    let height = 112.0 + row_height * records.len().max(1) as f64;
    let label_width = 270.0;
    let plot_width = width - label_width - 120.0;
    let colors = [
        "#2563eb", "#059669", "#d97706", "#7c3aed", "#dc2626", "#0891b2", "#4b5563", "#f97316",
        "#9333ea", "#16a34a", "#be123c", "#0f766e", "#ca8a04", "#64748b",
    ];
    let totals = records
        .iter()
        .map(|record| {
            phase_components(record, opening)
                .iter()
                .map(|(_, value)| *value)
                .sum()
        })
        .collect::<Vec<f64>>();
    let max_total = totals.iter().copied().fold(1.0_f64, f64::max);
    let mut svg = format!(
        "<svg xmlns=\"http://www.w3.org/2000/svg\" width=\"{width}\" height=\"{height}\" viewBox=\"0 0 {width} {height}\">\n<rect width=\"100%\" height=\"100%\" fill=\"#ffffff\"/>\n<text x=\"24\" y=\"34\" font-family=\"Arial\" font-size=\"18\" fill=\"#111827\">{}</text>\n",
        html_escape(title)
    );
    let legend = if opening {
        [
            "worker_eval_commit",
            "column_open",
            "f2_open",
            "e1_sum",
            "e1_hu",
            "e1_e_r",
            "e1_f_u",
            "e1_e_sys",
            "e2_sum",
            "e2_hu",
            "e2_e_r",
            "e2_f_u",
            "e2_e_sys",
            "proof_size",
        ]
        .as_slice()
    } else {
        [
            "column_verify",
            "f2_verify",
            "p10_e1_verify",
            "p10_e2_verify",
            "",
            "",
            "",
            "",
        ]
        .as_slice()
    };
    for (idx, label) in legend.iter().filter(|label| !label.is_empty()).enumerate() {
        let x = 24.0 + idx as f64 * 132.0;
        svg.push_str(&format!(
            "<rect x=\"{x:.1}\" y=\"52\" width=\"10\" height=\"10\" fill=\"{}\"/><text x=\"{:.1}\" y=\"62\" font-family=\"Arial\" font-size=\"10\" fill=\"#374151\">{}</text>\n",
            colors[idx],
            x + 14.0,
            html_escape(label)
        ));
    }
    for (idx, record) in records.iter().enumerate() {
        let y = 86.0 + idx as f64 * row_height;
        let components = phase_components(record, opening);
        let total = components.iter().map(|(_, value)| *value).sum::<f64>();
        svg.push_str(&format!(
            "<text x=\"24\" y=\"{:.1}\" font-family=\"Arial\" font-size=\"12\" fill=\"#111827\">{} nv={} w={}</text>\n",
            y + 15.0,
            record.opening,
            record.variable_count,
            record.workers
        ));
        let mut x = label_width;
        for (component_idx, (_, value)) in components.iter().enumerate() {
            let width = if max_total == 0.0 {
                0.0
            } else {
                *value / max_total * plot_width
            };
            svg.push_str(&format!(
                "<rect x=\"{x:.1}\" y=\"{y:.1}\" width=\"{width:.1}\" height=\"20\" fill=\"{}\"/>\n",
                colors[component_idx % colors.len()]
            ));
            x += width;
        }
        svg.push_str(&format!(
            "<text x=\"{:.1}\" y=\"{:.1}\" font-family=\"Arial\" font-size=\"12\" fill=\"#111827\">{total:.3} ms</text>\n",
            x + 8.0,
            y + 15.0
        ));
    }
    svg.push_str("</svg>\n");
    write_text_file(path, &svg)
}

fn write_proof_size_breakdown_chart(
    path: &Path,
    records: &[PcsMetricRecord],
) -> Result<(), CliError> {
    let width = 1120.0;
    let row_height = 32.0;
    let height = 112.0 + row_height * records.len().max(1) as f64;
    let label_width = 270.0;
    let plot_width = width - label_width - 120.0;
    let colors = [
        "#2563eb", "#059669", "#d97706", "#7c3aed", "#dc2626", "#0891b2", "#4b5563", "#f97316",
        "#9333ea",
    ];
    let totals = records
        .iter()
        .map(|record| {
            proof_size_components(record)
                .iter()
                .map(|(_, value)| *value)
                .sum()
        })
        .collect::<Vec<f64>>();
    let max_total = totals.iter().copied().fold(1.0_f64, f64::max);
    let mut svg = format!(
        "<svg xmlns=\"http://www.w3.org/2000/svg\" width=\"{width}\" height=\"{height}\" viewBox=\"0 0 {width} {height}\">\n<rect width=\"100%\" height=\"100%\" fill=\"#ffffff\"/>\n<text x=\"24\" y=\"34\" font-family=\"Arial\" font-size=\"18\" fill=\"#111827\">dePCS proof size component breakdown</text>\n"
    );
    for (idx, label) in [
        "commitment",
        "public",
        "eval_commit",
        "merkle_roots",
        "columns",
        "f2_open",
        "p10_e1",
        "p10_e2",
        "transcript",
    ]
    .iter()
    .enumerate()
    {
        let x = 24.0 + idx as f64 * 132.0;
        svg.push_str(&format!(
            "<rect x=\"{x:.1}\" y=\"52\" width=\"10\" height=\"10\" fill=\"{}\"/><text x=\"{:.1}\" y=\"62\" font-family=\"Arial\" font-size=\"10\" fill=\"#374151\">{}</text>\n",
            colors[idx],
            x + 14.0,
            html_escape(label)
        ));
    }
    for (idx, record) in records.iter().enumerate() {
        let y = 86.0 + idx as f64 * row_height;
        let components = proof_size_components(record);
        let total = components.iter().map(|(_, value)| *value).sum::<f64>();
        svg.push_str(&format!(
            "<text x=\"24\" y=\"{:.1}\" font-family=\"Arial\" font-size=\"12\" fill=\"#111827\">{} nv={} w={}</text>\n",
            y + 15.0,
            record.opening,
            record.variable_count,
            record.workers
        ));
        let mut x = label_width;
        for (component_idx, (_, value)) in components.iter().enumerate() {
            let width = if max_total == 0.0 {
                0.0
            } else {
                *value / max_total * plot_width
            };
            svg.push_str(&format!(
                "<rect x=\"{x:.1}\" y=\"{y:.1}\" width=\"{width:.1}\" height=\"20\" fill=\"{}\"/>\n",
                colors[component_idx % colors.len()]
            ));
            x += width;
        }
        svg.push_str(&format!(
            "<text x=\"{:.1}\" y=\"{:.1}\" font-family=\"Arial\" font-size=\"12\" fill=\"#111827\">{:.2} KiB</text>\n",
            x + 8.0,
            y + 15.0,
            total / 1024.0
        ));
    }
    svg.push_str("</svg>\n");
    write_text_file(path, &svg)
}

fn phase_components(record: &PcsMetricRecord, opening: bool) -> Vec<(&'static str, f64)> {
    if opening {
        vec![
            ("worker_eval_commit", record.worker_eval_commit_ms),
            ("column_open", record.column_open_ms),
            ("f2_open", record.f2_open_ms),
            ("p10_e1_sumcheck", record.protocol10_e1_sumcheck_ms),
            ("p10_e1_hu_open", record.protocol10_e1_hu_open_ms),
            ("p10_e1_e_at_r_open", record.protocol10_e1_e_at_r_open_ms),
            (
                "p10_e1_f_at_u_prime_open",
                record.protocol10_e1_f_at_u_prime_open_ms,
            ),
            (
                "p10_e1_e_systematic_open",
                record.protocol10_e1_e_systematic_open_ms,
            ),
            ("p10_e2_sumcheck", record.protocol10_e2_sumcheck_ms),
            ("p10_e2_hu_open", record.protocol10_e2_hu_open_ms),
            ("p10_e2_e_at_r_open", record.protocol10_e2_e_at_r_open_ms),
            (
                "p10_e2_f_at_u_prime_open",
                record.protocol10_e2_f_at_u_prime_open_ms,
            ),
            (
                "p10_e2_e_systematic_open",
                record.protocol10_e2_e_systematic_open_ms,
            ),
            ("proof_size", record.proof_size_accounting_ms),
        ]
    } else {
        vec![
            ("column_verify", record.column_verify_ms),
            ("f2_verify", record.f2_verify_ms),
            ("p10_e1_verify", record.protocol10_e1_verify_ms),
            ("p10_e2_verify", record.protocol10_e2_verify_ms),
        ]
    }
}

fn proof_size_components(record: &PcsMetricRecord) -> Vec<(&'static str, f64)> {
    vec![
        ("commitment", record.proof_commitment_object_bytes as f64),
        ("public", record.proof_point_query_public_bytes as f64),
        ("eval_commit", record.proof_eval_commitments_bytes as f64),
        ("merkle_roots", record.proof_merkle_roots_bytes as f64),
        ("columns", record.proof_column_openings_bytes as f64),
        ("f2_open", record.proof_f2_openings_bytes as f64),
        ("p10_e1", record.proof_protocol10_e1_bytes as f64),
        ("p10_e2", record.proof_protocol10_e2_bytes as f64),
        ("transcript", record.proof_transcript_overhead_bytes as f64),
    ]
}

#[cfg(test)]
fn sample_evaluations(size: usize) -> Vec<FieldElement> {
    (0..size)
        .map(|idx| sample_evaluation_at(idx, DEFAULT_EVALUATION_SEED))
        .collect()
}

fn sample_evaluation_at(index: usize, seed: u64) -> FieldElement {
    let value = (index as u64)
        .wrapping_mul(0x9e37_79b9_7f4a_7c15)
        .wrapping_add(0x243f_6a88_85a3_08d3)
        .wrapping_add(seed.wrapping_mul(0xbf58_476d_1ce4_e5b9));
    FieldElement::from(value)
}

fn worker_rows_for_evaluation_seed(
    original_len: usize,
    workers: usize,
    worker_id: usize,
    evaluation_seed: u64,
) -> Result<Vec<Vec<FieldElement>>, CliError> {
    DistributedBrakedown::worker_rows_for_commit_from_fn(
        original_len,
        workers,
        worker_id,
        |index| sample_evaluation_at(index, evaluation_seed),
    )
    .map_err(|error| CliError(format!("generate seeded worker rows failed: {error:?}")))
}

fn sample_point(size: usize) -> Result<Vec<FieldElement>, CliError> {
    let vars = log2_power_of_two(size)
        .map_err(|_| CliError("size must be a positive power of two".to_owned()))?;
    Ok((0..vars)
        .map(|idx| FieldElement::from((idx as u64 + 3) * 17))
        .collect())
}

fn validate_pcs_grid(
    sizes: &[usize],
    workers: &[usize],
    pcs_queries: usize,
    security_bits: usize,
    repeats: usize,
) -> Result<(), CliError> {
    if sizes.is_empty() || workers.is_empty() {
        return Err(CliError("pcs-benchmark grid must not be empty".to_owned()));
    }
    if pcs_queries == 0 || security_bits == 0 || repeats == 0 {
        return Err(CliError(
            "pcs-benchmark --pcs-queries, --security-bits, and --repeats must be positive"
                .to_owned(),
        ));
    }
    for size in sizes {
        if *size == 0 || !size.is_power_of_two() {
            return Err(CliError(format!(
                "pcs-benchmark size {size} is not a power of two"
            )));
        }
        for workers in workers {
            if *workers == 0 {
                return Err(CliError(format!(
                    "pcs-benchmark size {size} is incompatible with workers={workers}"
                )));
            }
            protocol11_padded_row_len(*size, *workers)?;
        }
    }
    Ok(())
}

fn validate_partition_shape(size: usize, workers: usize) -> Result<(), CliError> {
    if size == 0 || !size.is_power_of_two() || workers == 0 {
        return Err(CliError(format!(
            "Protocol 11 size {size} is incompatible with workers={workers}"
        )));
    }
    protocol11_padded_row_len(size, workers)?;
    Ok(())
}

fn protocol11_padded_row_len(size: usize, workers: usize) -> Result<usize, CliError> {
    if size == 0 || workers == 0 {
        return Err(CliError(format!(
            "Protocol 11 size {size} is incompatible with workers={workers}"
        )));
    }
    let n_vars = variable_count(size);
    let worker_log = (usize::BITS as usize - 1 - workers.leading_zeros() as usize).min(n_vars);
    let rows_per_worker = n_vars.saturating_sub(worker_log).max(1);
    let matrix_rows = workers * rows_per_worker;
    Ok(size.div_ceil(matrix_rows).max(1).next_power_of_two())
}

fn next_value<'a>(args: &'a [String], index: &mut usize, flag: &str) -> Result<&'a str, CliError> {
    *index += 1;
    args.get(*index)
        .map(String::as_str)
        .ok_or_else(|| CliError(format!("{flag} requires a value")))
}

fn parse_opening(value: &str) -> Result<PcsOpeningSelection, CliError> {
    match value {
        "protocol11" | "depcs" => Ok(PcsOpeningSelection::Protocol11),
        "protocol11-batch" | "depcs-batch" => Ok(PcsOpeningSelection::Protocol11Batch),
        "legacy-protocol11" | "legacy-local" | "legacy-depcs" => {
            Ok(PcsOpeningSelection::LegacyProtocol11)
        }
        "paper" | "paper-native" => Ok(PcsOpeningSelection::PaperNative),
        other => Err(CliError(format!(
            "unsupported --opening '{other}', expected protocol11, protocol11-batch, legacy-protocol11, or paper-native"
        ))),
    }
}

fn parse_backend_kind(value: &str) -> Result<PcsBackendKind, CliError> {
    match value {
        "basefold" => Ok(PcsBackendKind::BaseFold),
        "deepfold" => Ok(PcsBackendKind::DeepFold),
        other => Err(CliError(format!(
            "unsupported --backend '{other}', expected basefold or deepfold"
        ))),
    }
}

fn parse_paper_query_policy(value: &str) -> Result<PaperQueryPolicy, CliError> {
    match value {
        "artifact-default" | "paper-default" => Ok(PaperQueryPolicy::ArtifactDefault),
        "fixed-max" | "fixed" => Ok(PaperQueryPolicy::FixedMax),
        other => Err(CliError(format!(
            "unsupported --paper-query-policy '{other}', expected artifact-default or fixed-max"
        ))),
    }
}

fn build_backend_config(
    kind: PcsBackendKind,
    rate_inv: Option<usize>,
    security_bits: usize,
) -> Result<PcsBackendConfig, CliError> {
    let default_rate = match kind {
        PcsBackendKind::BaseFold => 8,
        PcsBackendKind::DeepFold => 2,
    };
    let backend = PcsBackendConfig {
        kind,
        rate_inv: rate_inv.unwrap_or(default_rate),
        security_bits,
    };
    match kind {
        PcsBackendKind::BaseFold if backend.rate_inv == 8 => Ok(backend),
        PcsBackendKind::DeepFold if backend.rate_inv == 2 => Ok(backend),
        PcsBackendKind::BaseFold if backend.rate_inv == 4 => Ok(backend),
        PcsBackendKind::DeepFold if backend.rate_inv == 4 => Ok(backend),
        PcsBackendKind::BaseFold => Err(CliError(
            "basefold backend supports --backend-rate-inv 8 for paper-backed protocol11 or 4 for legacy-protocol11".to_owned(),
        )),
        PcsBackendKind::DeepFold => Err(CliError(
            "deepfold backend supports --backend-rate-inv 2 for paper-backed protocol11 or 4 for legacy-protocol11".to_owned(),
        )),
    }
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

fn parse_csv_usizes(value: &str, flag: &str) -> Result<Vec<usize>, CliError> {
    value
        .split(',')
        .filter(|item| !item.trim().is_empty())
        .map(|item| parse_positive_usize(item.trim(), flag))
        .collect()
}

fn parse_positive_usize(value: &str, flag: &str) -> Result<usize, CliError> {
    let parsed = value
        .parse::<usize>()
        .map_err(|_| CliError(format!("{flag} must be an unsigned integer")))?;
    if parsed == 0 {
        return Err(CliError(format!("{flag} must be greater than zero")));
    }
    Ok(parsed)
}

fn env_cores_per_worker() -> usize {
    env::var("PQ_CORES_PER_WORKER")
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .filter(|value| *value > 0)
        .unwrap_or(1)
}

fn core_affinity_label(workers: usize, cores_per_worker: usize) -> String {
    let requested_threads = workers.saturating_mul(cores_per_worker);
    let rayon_threads = env::var("RAYON_NUM_THREADS").unwrap_or_else(|_| "unset".to_owned());
    format!(
        "fixed-per-worker;worker_process_threads={cores_per_worker};master_requested_threads={requested_threads};master_rayon_threads={rayon_threads}"
    )
}

fn depcs_scheme_name(backend: PcsBackendConfig) -> &'static str {
    match backend.kind {
        PcsBackendKind::BaseFold => "depcs-basefold-batch",
        PcsBackendKind::DeepFold => "depcs-deepfold-batch",
    }
}

fn batch_claim_count(proof: &Protocol11Proof) -> usize {
    1 + proof.f2_opening.consistency.len()
        + proof
            .encoding_batch
            .encodings
            .iter()
            .map(|encoding| {
                let opening_batch = &encoding.opening_batch;
                opening_batch.claims.len()
                    + opening_batch.combined_opening.consistency.len()
                    + opening_batch
                        .combined_opening
                        .consistency
                        .iter()
                        .map(|leaf| leaf.source_openings.len())
                        .sum::<usize>()
            })
            .sum::<usize>()
}

fn parse_size_range(value: &str) -> Result<Vec<usize>, CliError> {
    let (start, end) = parse_inclusive_range(value, "--size-range")?;
    Ok((start..=end).collect())
}

fn parse_variable_counts(value: &str, flag: &str) -> Result<Vec<usize>, CliError> {
    parse_csv_usizes(value, flag)?
        .into_iter()
        .map(variable_count_to_length)
        .collect()
}

fn parse_variable_range(value: &str, flag: &str) -> Result<Vec<usize>, CliError> {
    let (start, end) = parse_inclusive_range(value, flag)?;
    (start..=end).map(variable_count_to_length).collect()
}

fn parse_worker_power_range(value: &str) -> Result<Vec<usize>, CliError> {
    let (start, end) = parse_inclusive_range(value, "--worker-power-range")?;
    (start..=end).map(variable_count_to_length).collect()
}

fn parse_inclusive_range(value: &str, flag: &str) -> Result<(usize, usize), CliError> {
    let trimmed = value.trim();
    let parts = trimmed
        .split_once("..=")
        .or_else(|| trimmed.split_once(".."))
        .or_else(|| trimmed.split_once(':'))
        .or_else(|| trimmed.split_once('-'))
        .ok_or_else(|| CliError(format!("{flag} must look like 5..12")))?;
    let start = parse_positive_usize(parts.0.trim(), flag)?;
    let end = parse_positive_usize(parts.1.trim(), flag)?;
    if start > end {
        return Err(CliError(format!("{flag} start must be <= end")));
    }
    Ok((start, end))
}

fn variable_count_to_length(power: usize) -> Result<usize, CliError> {
    1_usize
        .checked_shl(power as u32)
        .ok_or_else(|| CliError(format!("nv={power} overflows usize")))
}

fn normalize_unique(values: &mut Vec<usize>) {
    values.sort_unstable();
    values.dedup();
}

fn variable_count(size: usize) -> usize {
    (usize::BITS - 1 - size.leading_zeros()) as usize
}

fn unix_millis() -> Result<u128, CliError> {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|duration| duration.as_millis())
        .map_err(|error| CliError(format!("clock is before UNIX_EPOCH: {error}")))
}

fn elapsed_ms(start: Instant) -> f64 {
    start.elapsed().as_secs_f64() * 1000.0
}

fn mean(values: impl Iterator<Item = f64>) -> f64 {
    let values = values.collect::<Vec<_>>();
    if values.is_empty() {
        0.0
    } else {
        values.iter().sum::<f64>() / values.len() as f64
    }
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
    let variance = values
        .iter()
        .map(|value| {
            let delta = value - mean;
            delta * delta
        })
        .sum::<f64>()
        / values.len() as f64;
    MeanStddev {
        mean,
        stddev: variance.sqrt(),
    }
}

fn parse_csv_usize(value: &str, field: &str) -> Result<usize, CliError> {
    value
        .parse::<usize>()
        .map_err(|_| CliError(format!("{field} is invalid")))
}

fn parse_csv_f64(value: &str, field: &str) -> Result<f64, CliError> {
    value
        .parse::<f64>()
        .map_err(|_| CliError(format!("{field} is invalid")))
}

fn split_csv_line(line: &str) -> Vec<String> {
    let mut fields = Vec::new();
    let mut current = String::new();
    let mut quoted = false;
    let mut chars = line.chars().peekable();
    while let Some(ch) = chars.next() {
        match ch {
            '"' if quoted && chars.peek() == Some(&'"') => {
                current.push('"');
                chars.next();
            }
            '"' => quoted = !quoted,
            ',' if !quoted => {
                fields.push(current.clone());
                current.clear();
            }
            _ => current.push(ch),
        }
    }
    fields.push(current);
    fields
}

fn csv_escape(value: &str) -> String {
    if value.contains(',') || value.contains('"') || value.contains('\n') {
        format!("\"{}\"", value.replace('"', "\"\""))
    } else {
        value.to_owned()
    }
}

fn html_escape(input: &str) -> String {
    input
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

fn json_pretty<T: Serialize>(value: &T) -> Result<String, CliError> {
    serde_json::to_string_pretty(value)
        .map(|mut text| {
            text.push('\n');
            text
        })
        .map_err(|error| CliError(format!("serialize json failed: {error}")))
}

fn write_text_file(path: &Path, contents: &str) -> Result<(), CliError> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .map_err(|error| CliError(format!("create {} failed: {error}", parent.display())))?;
    }
    fs::write(path, contents)
        .map_err(|error| CliError(format!("write {} failed: {error}", path.display())))
}

fn usage() -> String {
    "usage:
  cargo run -p pq-experiments -- pcs-benchmark [--opening protocol11|protocol11-batch|legacy-protocol11|paper-native] [--backend basefold|deepfold] [--backend-rate-inv N] [--paper-query-policy artifact-default|fixed-max] [--paper-code-rate-log N] [--sizes 256,512,1024 | --size-range 256..1024 | --nv-values/--variable-counts 8,9,10 | --nv-range/--variable-range 8..10] [--workers 1,2,4] [--cores-per-worker N] [--pcs-queries N] [--security-bits N] [--repeats N] [--no-pcs-warmup] [--out DIR]
  cargo run -p pq-experiments -- verify-pcs-results --dir results/pcs-bench-... [--format json|csv]"
        .to_owned()
}

#[cfg(test)]
mod tests {
    use std::thread;

    use pq_pcs::{Protocol11WorkerCommitment, depcs::PaperProtocol11WorkerOpening};

    use super::*;

    #[test]
    fn parse_variable_range_builds_powers_of_two() {
        let command = parse_pcs_benchmark_command(&[
            "--nv-range".to_owned(),
            "5..7".to_owned(),
            "--workers".to_owned(),
            "2,4".to_owned(),
            "--no-pcs-warmup".to_owned(),
        ])
        .expect("command");
        assert_eq!(command.sizes, vec![32, 64, 128]);
        assert_eq!(command.workers, vec![2, 4]);
        assert_eq!(command.cores_per_worker, 1);
    }

    #[test]
    fn protocol11_paper_backend_config_is_accepted() {
        let config = PaperDepcsConfig::new(PaperPcsBackend::BaseFold, 8).expect("basefold");
        assert_eq!(config.code_rate_log(), 3);
        assert!(PaperDepcsConfig::new(PaperPcsBackend::BaseFold, 2).is_err());
        let config = PaperDepcsConfig::new(PaperPcsBackend::DeepFold, 2).expect("deepfold");
        assert_eq!(config.code_rate_log(), 1);
        assert!(PaperDepcsConfig::new(PaperPcsBackend::DeepFold, 8).is_err());
    }

    #[test]
    fn protocol11_batch_opening_is_explicit_and_fail_closed() {
        assert_eq!(
            parse_opening("protocol11-batch").expect("batch opening"),
            PcsOpeningSelection::Protocol11Batch
        );
        let basefold_job = PcsBenchmarkJob {
            size: 1 << 10,
            workers: 2,
            opening: PcsOpeningVariant::Protocol11Batch,
            trial: 1,
            pcs_queries: 1,
            security_bits: PAPER_PCS_SECURITY_BITS,
            backend: PcsBackendConfig {
                kind: PcsBackendKind::BaseFold,
                rate_inv: 8,
                security_bits: PAPER_PCS_SECURITY_BITS,
            },
            paper_query_policy: PaperQueryPolicy::ArtifactDefault,
            paper_code_rate_log: None,
            cores_per_worker: 1,
        };
        let error = run_single_depcs_batch_job(basefold_job)
            .expect_err("basefold batch must not fall back");
        assert!(
            error
                .0
                .contains("batch_unavailable_basefold_artifact_no_batch_api")
        );

        let deepfold_job = PcsBenchmarkJob {
            backend: PcsBackendConfig {
                kind: PcsBackendKind::DeepFold,
                rate_inv: 2,
                security_bits: PAPER_PCS_SECURITY_BITS,
            },
            ..basefold_job
        };
        let error = run_single_depcs_batch_job(deepfold_job)
            .expect_err("deepfold batch must not swap backend");
        assert!(
            error
                .0
                .contains("batch_unavailable_deepfold_artifact_native_batch_api_missing")
        );
    }

    #[test]
    fn network_frame_codec_counts_framed_bytes() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = listener.local_addr().expect("addr");
        let handle = thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept");
            let (request, recv_bytes): (PcsWorkerRequest, usize) =
                read_frame_binary(&mut stream).expect("read");
            let expected_recv = 9 + bincode::serialize(&request).expect("binary").len();
            assert_eq!(recv_bytes, expected_recv);
            assert!(matches!(request, PcsWorkerRequest::Shutdown));
            write_frame_binary(&mut stream, &PcsWorkerResponse::Ack).expect("write")
        });

        let mut stream = TcpStream::connect(addr).expect("connect");
        let request = PcsWorkerRequest::Shutdown;
        let sent = write_frame_binary(&mut stream, &request).expect("write");
        assert_eq!(
            sent,
            9 + bincode::serialize(&request).expect("binary").len()
        );
        let (response, recv_bytes): (PcsWorkerResponse, usize) =
            read_frame_binary(&mut stream).expect("read");
        assert!(matches!(response, PcsWorkerResponse::Ack));
        assert_eq!(recv_bytes, handle.join().expect("thread"));
    }

    #[test]
    fn seeded_worker_rows_match_full_vector_partition() {
        let values = sample_evaluations(128);
        for workers in [2, 4, 8] {
            for worker_id in 0..workers {
                let expected =
                    DistributedBrakedown::worker_rows_for_commit(&values, workers, worker_id)
                        .expect("full rows");
                let seeded = worker_rows_for_evaluation_seed(
                    values.len(),
                    workers,
                    worker_id,
                    DEFAULT_EVALUATION_SEED,
                )
                .expect("seeded rows");
                assert_eq!(seeded, expected);
            }
        }
    }

    #[test]
    fn network_worker_lifecycle_accepts_commit_open_and_shutdown() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = listener.local_addr().expect("addr");
        let handle = thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept");
            serve_pcs_network_worker_stream(&mut stream).expect("serve");
        });

        let mut stream = TcpStream::connect(addr).expect("connect");
        write_frame_binary(
            &mut stream,
            &PcsWorkerRequest::OpenPrepare {
                a: vec![FieldElement::ONE],
                beta: vec![FieldElement::ONE],
            },
        )
        .expect("write open before commit");
        let (response, _): (PcsWorkerResponse, usize) =
            read_frame_binary(&mut stream).expect("read error");
        assert!(matches!(response, PcsWorkerResponse::Error { .. }));

        let backend = PcsBackendConfig::basefold_default();
        let values = sample_evaluations(32);
        let commitment =
            DistributedBrakedown::commit_with_config(&values, 2, backend).expect("commit");
        write_frame_binary(
            &mut stream,
            &PcsWorkerRequest::CommitSeeded {
                original_len: values.len(),
                workers: 2,
                worker_id: 0,
                backend,
                evaluation_seed: DEFAULT_EVALUATION_SEED,
            },
        )
        .expect("write commit");
        let (response, _): (PcsWorkerResponse, usize) =
            read_frame_binary(&mut stream).expect("read commit");
        assert!(matches!(
            response,
            PcsWorkerResponse::Commit {
                commitment: Protocol11WorkerCommitment { worker_id: 0, .. }
            }
        ));

        write_frame_binary(
            &mut stream,
            &PcsWorkerRequest::OpenPrepare {
                a: vec![FieldElement::ONE; commitment.matrix_rows],
                beta: vec![FieldElement::ONE; commitment.matrix_rows],
            },
        )
        .expect("write open");
        let (response, _): (PcsWorkerResponse, usize) =
            read_frame_binary(&mut stream).expect("read open");
        match response {
            PcsWorkerResponse::OpenPrepare { payload } => {
                assert_eq!(payload.worker_id, 0);
                assert_eq!(payload.f1_pad.len(), commitment.encoded_width);
                assert_eq!(payload.f2_pad.len(), commitment.encoded_width);
            }
            other => panic!("unexpected response: {other:?}"),
        }
        write_frame_binary(
            &mut stream,
            &PcsWorkerRequest::OpenColumns {
                commitment: commitment.clone(),
                query_indices: vec![0],
            },
        )
        .expect("write columns");
        let (response, _): (PcsWorkerResponse, usize) =
            read_frame_binary(&mut stream).expect("read columns");
        match response {
            PcsWorkerResponse::OpenColumns { proof } => {
                assert_eq!(proof.worker_id, 0);
                assert_eq!(proof.columns.len(), 1);
                assert_eq!(proof.columns[0].index, 0);
                assert_eq!(
                    proof.columns[0].encoded_row_values.len(),
                    commitment.rows_per_worker
                );
            }
            other => panic!("unexpected response: {other:?}"),
        }

        write_frame_binary(&mut stream, &PcsWorkerRequest::Shutdown).expect("write shutdown");
        let (response, _): (PcsWorkerResponse, usize) =
            read_frame_binary(&mut stream).expect("read shutdown");
        assert!(matches!(response, PcsWorkerResponse::Ack));
        handle.join().expect("thread");
    }

    #[test]
    fn paper_network_worker_uses_commit_cache_and_rejects_mismatch() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = listener.local_addr().expect("addr");
        let handle = thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept");
            serve_pcs_network_worker_stream(&mut stream).expect("serve");
        });

        let mut stream = TcpStream::connect(addr).expect("connect");
        let config = PaperDepcsConfig::new(PaperPcsBackend::DeepFold, 2).expect("config");
        let original_len = 1 << 6;
        let workers = 2;
        let worker1 =
            depcs::commit_worker(original_len, workers, 1, config).expect("worker1 commit");
        let local_worker0 =
            depcs::commit_worker(original_len, workers, 0, config).expect("worker0 commit");
        let precommit_commitment = depcs::commit_from_worker_commitments(
            original_len,
            workers,
            config,
            vec![local_worker0, worker1.clone()],
        )
        .expect("precommit commitment");
        let point = depcs::sample_point(precommit_commitment.nv);

        write_frame_binary(
            &mut stream,
            &PcsWorkerRequest::PaperOpen {
                commitment: precommit_commitment,
                point: point.clone(),
            },
        )
        .expect("write paper open before commit");
        let (response, _): (PcsWorkerResponse, usize) =
            read_frame_binary(&mut stream).expect("read paper open before commit");
        assert!(matches!(response, PcsWorkerResponse::Error { .. }));

        write_frame_binary(
            &mut stream,
            &PcsWorkerRequest::PaperCommitSeeded {
                original_len,
                workers,
                worker_id: 0,
                config,
            },
        )
        .expect("write paper commit");
        let (response, _): (PcsWorkerResponse, usize) =
            read_frame_binary(&mut stream).expect("read paper commit");
        let worker0 = match response {
            PcsWorkerResponse::PaperCommit { commitment, .. } => commitment,
            other => panic!("unexpected response: {other:?}"),
        };
        let commitment = depcs::commit_from_worker_commitments(
            original_len,
            workers,
            config,
            vec![worker0, worker1],
        )
        .expect("commitment");
        write_frame_binary(
            &mut stream,
            &PcsWorkerRequest::PaperOpen {
                commitment: commitment.clone(),
                point: point.clone(),
            },
        )
        .expect("write paper open");
        let (response, _): (PcsWorkerResponse, usize) =
            read_frame_binary(&mut stream).expect("read paper open");
        assert!(matches!(
            response,
            PcsWorkerResponse::PaperOpen {
                opening: PaperProtocol11WorkerOpening { worker_id: 0, .. },
                ..
            }
        ));

        let mut bad_commitment = commitment;
        bad_commitment.config.security_bits += 1;
        write_frame_binary(
            &mut stream,
            &PcsWorkerRequest::PaperOpen {
                commitment: bad_commitment,
                point,
            },
        )
        .expect("write mismatched paper open");
        let (response, _): (PcsWorkerResponse, usize) =
            read_frame_binary(&mut stream).expect("read mismatched paper open");
        assert!(matches!(response, PcsWorkerResponse::Error { .. }));

        write_frame_binary(&mut stream, &PcsWorkerRequest::Shutdown).expect("write shutdown");
        let (response, _): (PcsWorkerResponse, usize) =
            read_frame_binary(&mut stream).expect("read shutdown");
        assert!(matches!(response, PcsWorkerResponse::Ack));
        handle.join().expect("thread");
    }

    #[test]
    fn source_csv_verifier_accepts_generated_row() {
        let record = PcsMetricRecord {
            scheme: "depcs-basefold-batch".to_owned(),
            backend: "basefold".to_owned(),
            backend_rate_inv: 4,
            effective_query_count: 1,
            column_query_count: 1,
            pcs_query_count: 1,
            query_security_bits: 128,
            algebraic_security_bits: 64,
            batch_claim_count: 7,
            batch_open_ms: 2.0,
            batch_verify_ms: 3.0,
            batch_proof_bytes: 100,
            runner: "local-network".to_owned(),
            opening: "protocol11".to_owned(),
            trial: 1,
            workers: 2,
            variable_count: 5,
            polynomial_length: 32,
            t_rows_per_worker: 32,
            paper_b_target: 4,
            shard_len: 32,
            pcs_queries_requested: 1,
            pcs_queries_effective: 1,
            partition_ms: 0.1,
            worker_commit_ms: 1.0,
            master_commit_ms: 0.0,
            commit_ms: 1.0,
            open_ms: 2.0,
            verify_ms: 3.0,
            paper_worker_commit_max_ms: 0.0,
            paper_worker_commit_sum_ms: 0.0,
            paper_worker_open_max_ms: 0.0,
            paper_worker_open_sum_ms: 0.0,
            paper_master_assemble_ms: 0.0,
            paper_worker_verify_max_ms: 0.0,
            paper_worker_verify_sum_ms: 0.0,
            paper_master_verify_ms: 0.0,
            paper_batch_claim_ms: 0.0,
            paper_batch_sumcheck_ms: 0.0,
            paper_batch_combined_open_ms: 0.0,
            paper_batch_merkle_ms: 0.0,
            paper_batch_verify_ms: 0.0,
            paper_individual_worker_proof_count: 0,
            paper_batched_proof_count: 0,
            worker_eval_commit_ms: 0.1,
            column_open_ms: 0.2,
            f2_open_ms: 0.3,
            protocol10_e1_sumcheck_ms: 0.4,
            protocol10_e1_open_ms: 0.5,
            protocol10_e1_opening_batch_open_ms: 0.5,
            protocol10_e1_hu_open_ms: 0.11,
            protocol10_e1_e_at_r_open_ms: 0.12,
            protocol10_e1_f_at_u_prime_open_ms: 0.13,
            protocol10_e1_e_systematic_open_ms: 0.14,
            protocol10_e2_sumcheck_ms: 0.6,
            protocol10_e2_open_ms: 0.7,
            protocol10_e2_opening_batch_open_ms: 0.7,
            protocol10_e2_hu_open_ms: 0.21,
            protocol10_e2_e_at_r_open_ms: 0.22,
            protocol10_e2_f_at_u_prime_open_ms: 0.23,
            protocol10_e2_e_systematic_open_ms: 0.24,
            proof_size_accounting_ms: 0.01,
            column_verify_ms: 0.8,
            f2_verify_ms: 0.9,
            protocol10_e1_verify_ms: 1.0,
            protocol10_e2_verify_ms: 1.1,
            proof_commitment_object_bytes: 20,
            proof_point_query_public_bytes: 10,
            proof_eval_commitments_bytes: 10,
            proof_merkle_roots_bytes: 10,
            proof_column_openings_bytes: 20,
            proof_f2_openings_bytes: 20,
            proof_protocol10_e1_bytes: 30,
            proof_protocol10_e2_bytes: 30,
            proof_transcript_overhead_bytes: 30,
            proof_p10_e1_commitments_bytes: 3,
            proof_p10_e1_public_scalars_bytes: 4,
            proof_p10_e1_opening_batch_bytes: 17,
            proof_p10_e1_hu_opening_bytes: 5,
            proof_p10_e1_sumcheck_bytes: 6,
            proof_p10_e1_e_at_r_openings_bytes: 4,
            proof_p10_e1_f_at_u_prime_openings_bytes: 4,
            proof_p10_e1_e_systematic_openings_bytes: 4,
            proof_p10_e2_commitments_bytes: 3,
            proof_p10_e2_public_scalars_bytes: 4,
            proof_p10_e2_opening_batch_bytes: 17,
            proof_p10_e2_hu_opening_bytes: 5,
            proof_p10_e2_sumcheck_bytes: 6,
            proof_p10_e2_e_at_r_openings_bytes: 4,
            proof_p10_e2_f_at_u_prime_openings_bytes: 4,
            proof_p10_e2_e_systematic_openings_bytes: 4,
            proof_bytes: 180,
            communication_bytes: 180,
            verifier_communication_bytes: 180,
            scheme_reported_communication_bytes: 0,
            communication_basis: "master_worker_sent_recv".to_owned(),
            network_commit_bytes: 80,
            network_open_bytes: 100,
            network_bytes: 180,
            host_logical_cores: 1,
            cores_per_worker: 1,
            core_affinity: "local-network".to_owned(),
            backend_source: "legacy-local-goldilocks-rs-merkle".to_owned(),
            field: "Goldilocks".to_owned(),
            hash: "SHA-256".to_owned(),
            code_rate_log: 2,
            security_target_bits: 128,
            security_effective_bits: 128,
            security_exact: true,
            query_count_semantics: "legacy-local-query-derived".to_owned(),
            source_rev: "local-pq-pcs".to_owned(),
            verified: true,
            failure_reason: String::new(),
        };
        let dir = env::temp_dir().join(format!("depcs_csv_test_{}", unix_millis().expect("time")));
        fs::create_dir_all(&dir).expect("dir");
        write_text_file(&dir.join("source.csv"), &pcs_records_to_csv(&[record])).expect("write");
        let check = verify_pcs_source_csv(&dir).expect("verify");
        assert_eq!(check.rows, 1);
        assert_eq!(check.depcs_rows, 1);
        fs::remove_dir_all(dir).expect("cleanup");
    }

    #[test]
    fn verify_pcs_results_rejects_tampered_fixture() {
        let run_dir = env::temp_dir().join(format!(
            "depcs_fixture_test_{}",
            unix_millis().expect("time")
        ));
        fs::create_dir_all(&run_dir).expect("dir");
        let backend = PcsBackendConfig::basefold_default();
        let params = DistributedPcsParams {
            query_count: 1,
            security_bits: 128,
        };
        let values = sample_evaluations(32);
        let commitment =
            DistributedBrakedown::commit_with_config(&values, 2, backend).expect("commit");
        let point = sample_point(protocol11_evaluation_domain_len(&commitment)).expect("point");
        let mut transcript = HashTranscript::new(b"pq-experiments-depcs-benchmark");
        let (proof, _) = DistributedBrakedown::open_profiled_with_config(
            &values,
            &commitment,
            &point,
            params,
            backend,
            &mut transcript,
        )
        .expect("open");
        let breakdown = protocol11_proof_size_breakdown(&proof);
        let commitment_bytes = protocol11_commitment_size_bytes(&commitment);
        let proof_bytes = commitment_bytes + breakdown.total_bytes();
        let record = PcsMetricRecord {
            scheme: "depcs-basefold-batch".to_owned(),
            backend: "basefold".to_owned(),
            backend_rate_inv: 4,
            effective_query_count: 1,
            column_query_count: 1,
            pcs_query_count: 1,
            query_security_bits: 128,
            algebraic_security_bits: 64,
            batch_claim_count: batch_claim_count(&proof),
            batch_open_ms: 2.0,
            batch_verify_ms: 3.0,
            batch_proof_bytes: breakdown.total_bytes(),
            runner: "local-network".to_owned(),
            opening: "protocol11".to_owned(),
            trial: 1,
            workers: 2,
            variable_count: 5,
            polynomial_length: 32,
            t_rows_per_worker: commitment.rows_per_worker,
            paper_b_target: commitment.matrix_rows,
            shard_len: commitment.row_width,
            pcs_queries_requested: 1,
            pcs_queries_effective: 1,
            partition_ms: 0.1,
            worker_commit_ms: 1.0,
            master_commit_ms: 0.0,
            commit_ms: 1.0,
            open_ms: 2.0,
            verify_ms: 3.0,
            paper_worker_commit_max_ms: 0.0,
            paper_worker_commit_sum_ms: 0.0,
            paper_worker_open_max_ms: 0.0,
            paper_worker_open_sum_ms: 0.0,
            paper_master_assemble_ms: 0.0,
            paper_worker_verify_max_ms: 0.0,
            paper_worker_verify_sum_ms: 0.0,
            paper_master_verify_ms: 0.0,
            paper_batch_claim_ms: 0.0,
            paper_batch_sumcheck_ms: 0.0,
            paper_batch_combined_open_ms: 0.0,
            paper_batch_merkle_ms: 0.0,
            paper_batch_verify_ms: 0.0,
            paper_individual_worker_proof_count: 0,
            paper_batched_proof_count: 0,
            worker_eval_commit_ms: 0.1,
            column_open_ms: 0.2,
            f2_open_ms: 0.3,
            protocol10_e1_sumcheck_ms: 0.4,
            protocol10_e1_open_ms: 0.5,
            protocol10_e1_opening_batch_open_ms: 0.5,
            protocol10_e1_hu_open_ms: 0.11,
            protocol10_e1_e_at_r_open_ms: 0.12,
            protocol10_e1_f_at_u_prime_open_ms: 0.13,
            protocol10_e1_e_systematic_open_ms: 0.14,
            protocol10_e2_sumcheck_ms: 0.6,
            protocol10_e2_open_ms: 0.7,
            protocol10_e2_opening_batch_open_ms: 0.7,
            protocol10_e2_hu_open_ms: 0.21,
            protocol10_e2_e_at_r_open_ms: 0.22,
            protocol10_e2_f_at_u_prime_open_ms: 0.23,
            protocol10_e2_e_systematic_open_ms: 0.24,
            proof_size_accounting_ms: 0.01,
            column_verify_ms: 0.8,
            f2_verify_ms: 0.9,
            protocol10_e1_verify_ms: 1.0,
            protocol10_e2_verify_ms: 1.1,
            proof_commitment_object_bytes: commitment_bytes,
            proof_point_query_public_bytes: breakdown.point_query_public_bytes,
            proof_eval_commitments_bytes: breakdown.eval_commitments_bytes,
            proof_merkle_roots_bytes: breakdown.merkle_roots_bytes,
            proof_column_openings_bytes: breakdown.column_openings_bytes,
            proof_f2_openings_bytes: breakdown.f2_openings_bytes,
            proof_protocol10_e1_bytes: breakdown.protocol10_e1_bytes,
            proof_protocol10_e2_bytes: breakdown.protocol10_e2_bytes,
            proof_transcript_overhead_bytes: breakdown.transcript_overhead_bytes,
            proof_p10_e1_commitments_bytes: breakdown.protocol10_e1.commitments_bytes,
            proof_p10_e1_public_scalars_bytes: breakdown.protocol10_e1.public_scalars_bytes,
            proof_p10_e1_opening_batch_bytes: breakdown.protocol10_e1.opening_batch_bytes,
            proof_p10_e1_hu_opening_bytes: breakdown.protocol10_e1.hu_opening_bytes,
            proof_p10_e1_sumcheck_bytes: breakdown.protocol10_e1.sumcheck_bytes,
            proof_p10_e1_e_at_r_openings_bytes: breakdown.protocol10_e1.e_at_r_openings_bytes,
            proof_p10_e1_f_at_u_prime_openings_bytes: breakdown
                .protocol10_e1
                .f_at_u_prime_openings_bytes,
            proof_p10_e1_e_systematic_openings_bytes: breakdown
                .protocol10_e1
                .e_systematic_openings_bytes,
            proof_p10_e2_commitments_bytes: breakdown.protocol10_e2.commitments_bytes,
            proof_p10_e2_public_scalars_bytes: breakdown.protocol10_e2.public_scalars_bytes,
            proof_p10_e2_opening_batch_bytes: breakdown.protocol10_e2.opening_batch_bytes,
            proof_p10_e2_hu_opening_bytes: breakdown.protocol10_e2.hu_opening_bytes,
            proof_p10_e2_sumcheck_bytes: breakdown.protocol10_e2.sumcheck_bytes,
            proof_p10_e2_e_at_r_openings_bytes: breakdown.protocol10_e2.e_at_r_openings_bytes,
            proof_p10_e2_f_at_u_prime_openings_bytes: breakdown
                .protocol10_e2
                .f_at_u_prime_openings_bytes,
            proof_p10_e2_e_systematic_openings_bytes: breakdown
                .protocol10_e2
                .e_systematic_openings_bytes,
            proof_bytes,
            communication_bytes: 180,
            verifier_communication_bytes: proof_bytes,
            scheme_reported_communication_bytes: 0,
            communication_basis: "master_worker_sent_recv".to_owned(),
            network_commit_bytes: 80,
            network_open_bytes: 100,
            network_bytes: 180,
            host_logical_cores: 1,
            cores_per_worker: 1,
            core_affinity: "local-network".to_owned(),
            backend_source: "legacy-local-goldilocks-rs-merkle".to_owned(),
            field: "Goldilocks".to_owned(),
            hash: "SHA-256".to_owned(),
            code_rate_log: 2,
            security_target_bits: 128,
            security_effective_bits: 128,
            security_exact: true,
            query_count_semantics: "legacy-local-query-derived".to_owned(),
            source_rev: "local-pq-pcs".to_owned(),
            verified: true,
            failure_reason: String::new(),
        };
        let fixture = PcsProofFixture {
            row_id: "fixture".to_owned(),
            backend,
            params,
            commitment,
            proof,
            transcript_label: "pq-experiments-depcs-benchmark".to_owned(),
        };
        write_text_file(
            &run_dir.join("source.csv"),
            &pcs_records_to_csv(&[record.clone()]),
        )
        .expect("source");
        write_text_file(
            &run_dir.join("summary_stats.csv"),
            &pcs_summary_stats_to_csv(&pcs_benchmark_stats(&[record])),
        )
        .expect("summary");
        write_text_file(
            &run_dir.join("phase_timing.csv"),
            &phase_timing_to_csv(&[phase_record("job", "fixture", 1.0)]),
        )
        .expect("phase");
        write_text_file(
            &run_dir.join("proof_fixtures.jsonl"),
            &proof_fixtures_to_jsonl(&[fixture]).expect("fixture json"),
        )
        .expect("fixture write");
        verify_pcs_results(VerifyPcsResultsCommand {
            dir: run_dir.clone(),
            format: OutputFormat::Json,
        })
        .expect("valid fixture verifies");

        let fixture_path = run_dir.join("proof_fixtures.jsonl");
        let content = fs::read_to_string(&fixture_path).expect("fixture");
        let mut fixture: PcsProofFixture =
            serde_json::from_str(content.lines().next().expect("fixture row")).expect("json");
        fixture.proof.claimed_value += FieldElement::ONE;
        write_text_file(
            &fixture_path,
            &(serde_json::to_string(&fixture).expect("json") + "\n"),
        )
        .expect("write tampered fixture");
        assert!(
            verify_pcs_results(VerifyPcsResultsCommand {
                dir: run_dir.clone(),
                format: OutputFormat::Json,
            })
            .is_err()
        );
        fs::remove_dir_all(run_dir).expect("cleanup");
    }
}

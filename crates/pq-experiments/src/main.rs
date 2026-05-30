use std::cell::RefCell;
use std::env;
use std::fmt::{Display, Formatter};
use std::fs;
use std::io::{self, BufRead, Write};
use std::path::{Path, PathBuf};
use std::process;
use std::time::SystemTime;
use std::time::{Duration, Instant};

use pq_core::{FieldElement, R1CS, SparseMatrix};
use pq_net::{
    TcpWorkerRuntime, WorkerRuntime, pcs_worker_commit, pcs_worker_open, ping, register,
    run_worker, spawn_loopback_worker,
};
use pq_pcs::{
    DistributedBrakedown, DistributedCommitment, DistributedOpening, DistributedPcs,
    DistributedPcsParams, PcsError, WorkerCommitment, WorkerOpening,
    communication_bytes as pcs_communication_bytes,
};
use pq_piop_plonkish::{
    PlonkishInstance, PlonkishPiopError, PlonkishPiopProof, prove_plonkish_with_pcs_hooks,
    prove_plonkish_with_pcs_params, sample_plonkish_instance, verify_plonkish_with_pcs_params,
};
use pq_piop_r1cs::{
    R1csPiopError, R1csPiopProof, proof_size_bytes as r1cs_proof_size_bytes,
    prove_r1cs_with_pcs_hooks, prove_r1cs_with_pcs_params, verify_r1cs_with_pcs_params,
};
use pq_transcript::{HashTranscript, Transcript};

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
    out_dir: PathBuf,
}

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
    case_name: &'static str,
    workers: usize,
    size: usize,
    constraints: usize,
    prove_ms: f64,
    verify_ms: f64,
    proof_bytes: usize,
    communication_bytes: usize,
    network_bytes: usize,
    pcs_queries: usize,
    verified: bool,
    failure_reason: Option<String>,
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

#[derive(Debug)]
struct CliError(String);

impl Display for CliError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

fn main() {
    if let Err(error) = run() {
        eprintln!("{error}");
        process::exit(2);
    }
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
    let mut command = BenchmarkCommand {
        sizes: vec![4, 8, 16],
        workers: vec![1, 2, 4],
        pcs_queries: 3,
        out_dir: PathBuf::from("results"),
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
            "--workers" => {
                command.workers =
                    parse_csv_usizes(next_value(args, &mut index, "--workers")?, "--workers")?;
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

fn validate_benchmark_command(command: &BenchmarkCommand) -> Result<(), CliError> {
    if command.sizes.is_empty() || command.workers.is_empty() {
        return Err(CliError(
            "benchmark --sizes and --workers must not be empty".to_owned(),
        ));
    }
    for size in &command.sizes {
        if *size == 0 || !size.is_power_of_two() {
            return Err(CliError(
                "benchmark sizes must be positive powers of two".to_owned(),
            ));
        }
    }
    for workers in &command.workers {
        if *workers == 0 || !workers.is_power_of_two() {
            return Err(CliError(
                "benchmark workers must be positive powers of two".to_owned(),
            ));
        }
        let min_size = *command
            .sizes
            .iter()
            .min()
            .expect("sizes are checked non-empty");
        if *workers > min_size {
            return Err(CliError(
                "benchmark workers must not exceed the smallest R1CS size".to_owned(),
            ));
        }
    }
    Ok(())
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
    let command = parse_benchmark_command(args)?;
    let run_dir = command
        .out_dir
        .join(format!("bench-{}", unix_timestamp_seconds()?));
    fs::create_dir_all(&run_dir)
        .map_err(|error| CliError(format!("create benchmark dir failed: {error}")))?;

    let mut records = Vec::new();
    let total_jobs =
        [Protocol::R1cs, Protocol::Plonkish].len() * command.sizes.len() * command.workers.len();
    let mut job_index = 0_usize;
    eprintln!("[benchmark] output directory: {}", run_dir.display());
    for protocol in [Protocol::R1cs, Protocol::Plonkish] {
        for size in &command.sizes {
            for workers in &command.workers {
                job_index += 1;
                eprintln!(
                    "[benchmark {job_index}/{total_jobs}] protocol={} n={} nv={} workers={} pcs_queries={}",
                    protocol.as_str(),
                    nv_power(*size),
                    size,
                    workers,
                    command.pcs_queries
                );
                let config = Config {
                    protocol,
                    workers: *workers,
                    size: *size,
                    format: OutputFormat::Json,
                    case: CaseSelection::Both,
                    pcs_queries: command.pcs_queries,
                };
                let mut run_records = match protocol {
                    Protocol::R1cs => run_r1cs(&config)?,
                    Protocol::Plonkish => run_plonkish(&config)?,
                };
                let positives = run_records
                    .iter()
                    .filter(|record| record.case_name == "positive" && record.verified)
                    .count();
                let negatives = run_records
                    .iter()
                    .filter(|record| record.case_name == "negative" && !record.verified)
                    .count();
                eprintln!(
                    "[benchmark {job_index}/{total_jobs}] done: positive_verified={positives} negative_rejected={negatives}"
                );
                records.append(&mut run_records);
            }
        }
    }

    eprintln!("[benchmark] writing source data and SVG charts");
    write_text_file(&run_dir.join("source.csv"), &records_to_csv(&records))?;
    write_text_file(&run_dir.join("source.json"), &records_to_json(&records))?;
    write_text_file(
        &run_dir.join("summary.txt"),
        &benchmark_summary(&command, &records),
    )?;
    write_benchmark_charts(&run_dir, &records)?;
    eprintln!("[benchmark] complete");
    println!("{}", run_dir.display());
    Ok(())
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
    size.trailing_zeros() as usize
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

fn run_loopback_network_proof(config: &Config) -> Result<Vec<MetricRecord>, CliError> {
    let mut addrs = Vec::with_capacity(config.workers);
    let mut handles = Vec::with_capacity(config.workers);
    for worker_id in 0..config.workers {
        let (addr, handle) = spawn_loopback_worker(worker_id)
            .map_err(|error| CliError(format!("spawn worker {worker_id} failed: {error:?}")))?;
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
    let join_result = join_workers(handles);
    let records = result?;
    shutdown_result?;
    join_result?;
    Ok(records)
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
    let (instance, witness) = sample_r1cs(config.size)?;

    let prove_start = Instant::now();
    let proof = prove_r1cs_for_instance(&instance, &witness, config.workers, config.pcs_queries)?;
    let prove_time = prove_start.elapsed();

    let verify_proof = if tamper {
        tamper_r1cs_proof(&proof)?
    } else {
        proof.clone()
    };
    let verify_start = Instant::now();
    let verification = verify_r1cs_for_instance(&instance, &verify_proof, config.pcs_queries);
    let verify_time = verify_start.elapsed();
    let verified = verification.is_ok();
    let failure_reason = verification
        .as_ref()
        .err()
        .map(|error| format!("{error:?}"));
    let (proof_bytes, communication_bytes) = verification
        .map(|metrics| (metrics.proof_bytes, metrics.communication_bytes))
        .unwrap_or_else(|_| r1cs_fallback_metrics(&proof));

    Ok(MetricRecord {
        protocol: Protocol::R1cs.as_str(),
        case_name,
        workers: config.workers,
        size: config.size,
        constraints: instance.num_constraints(),
        prove_ms: millis(prove_time),
        verify_ms: millis(verify_time),
        proof_bytes,
        communication_bytes,
        network_bytes: 0,
        pcs_queries: config.pcs_queries,
        verified,
        failure_reason,
    })
}

fn run_r1cs_case_network(
    config: &Config,
    addrs: &[String],
    case_name: &'static str,
    tamper: bool,
) -> Result<MetricRecord, CliError> {
    let (instance, witness) = sample_r1cs(config.size)?;
    let backend = RefCell::new(NetworkPcsClient::new(
        addrs.to_vec(),
        format!("r1cs-{case_name}"),
    ));

    let prove_start = Instant::now();
    let mut transcript = HashTranscript::new(b"pq-experiments-r1cs");
    let proof = prove_r1cs_with_pcs_hooks(
        &instance,
        &witness,
        config.workers,
        DistributedPcsParams::new(config.pcs_queries),
        &mut transcript,
        |evaluations, workers| {
            backend
                .borrow_mut()
                .commit(evaluations, workers)
                .map_err(|_| R1csPiopError::Pcs)
        },
        |evaluations, commitment, point, params, transcript| {
            backend
                .borrow_mut()
                .open(evaluations, commitment, point, params, transcript)
                .map_err(|_| R1csPiopError::Pcs)
        },
    )
    .map_err(|error| CliError(format!("network R1CS prove failed: {error:?}")))?;
    let prove_time = prove_start.elapsed();
    let network_bytes = backend.borrow().bytes();

    let verify_proof = if tamper {
        tamper_r1cs_proof(&proof)?
    } else {
        proof.clone()
    };
    let verify_start = Instant::now();
    let verification = verify_r1cs_for_instance(&instance, &verify_proof, config.pcs_queries);
    let verify_time = verify_start.elapsed();
    let verified = verification.is_ok();
    let failure_reason = verification
        .as_ref()
        .err()
        .map(|error| format!("{error:?}"));
    let (proof_bytes, communication_bytes) = verification
        .map(|metrics| (metrics.proof_bytes, metrics.communication_bytes))
        .unwrap_or_else(|_| r1cs_fallback_metrics(&proof));

    Ok(MetricRecord {
        protocol: Protocol::R1cs.as_str(),
        case_name,
        workers: config.workers,
        size: config.size,
        constraints: instance.num_constraints(),
        prove_ms: millis(prove_time),
        verify_ms: millis(verify_time),
        proof_bytes,
        communication_bytes,
        network_bytes,
        pcs_queries: config.pcs_queries,
        verified,
        failure_reason,
    })
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
    let communication_bytes = pcs_communication_bytes(&proof.residual_opening);
    (r1cs_proof_size_bytes(proof), communication_bytes)
}

#[derive(Clone, Debug)]
struct NetworkPcsClient {
    addrs: Vec<String>,
    session_prefix: String,
    round: usize,
    network_bytes: usize,
}

impl NetworkPcsClient {
    fn new(addrs: Vec<String>, session_prefix: String) -> Self {
        Self {
            addrs,
            session_prefix,
            round: 0,
            network_bytes: 0,
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
        let mut commitments = Vec::with_capacity(workers);
        let addrs = self.addrs.clone();
        for partition in plan.partitions() {
            let row = &evaluations[partition.start..partition.end];
            let commitment = pcs_worker_commit(
                &addrs[partition.id],
                &session,
                partition.id,
                partition.start,
                row,
            )
            .map_err(|error| {
                CliError(format!(
                    "network PCS commit worker {} failed: {error:?}",
                    partition.id
                ))
            })?;
            self.network_bytes += row.len() * 8 + 8 + 8 + 8 + 40;
            commitments.push(commitment);
        }
        DistributedBrakedown::commit_from_worker_commitments(commitments, evaluations.len())
            .map_err(|error| CliError(format!("network PCS commitment invalid: {error:?}")))
    }

    fn open<T: Transcript>(
        &mut self,
        evaluations: &[FieldElement],
        commitment: &DistributedCommitment,
        point: &[FieldElement],
        params: DistributedPcsParams,
        transcript: &mut T,
    ) -> Result<DistributedOpening, CliError> {
        let session = self.next_session("open");
        DistributedBrakedown::open_at_after_commitment_with_worker_provider(
            evaluations,
            commitment,
            point,
            params,
            transcript,
            |worker, row, query_indices| self.open_worker(&session, worker, row, query_indices),
        )
        .map_err(|error| CliError(format!("network PCS opening failed: {error:?}")))
    }

    fn open_worker(
        &mut self,
        session: &str,
        worker: &WorkerCommitment,
        row: &[FieldElement],
        query_indices: &[usize],
    ) -> Result<WorkerOpening, PcsError> {
        let addr = self
            .addrs
            .get(worker.worker_id)
            .ok_or(PcsError::InvalidWorker)?;
        let opening = pcs_worker_open(
            addr,
            session,
            worker.worker_id,
            worker.range.0,
            row,
            query_indices,
        )
        .map_err(|_| PcsError::InvalidProof)?;
        self.network_bytes +=
            row.len() * 8 + query_indices.len() * 8 + worker_opening_application_bytes(&opening);
        Ok(opening)
    }

    fn next_session(&mut self, label: &str) -> String {
        let session = format!("{}-{label}-{}", self.session_prefix, self.round);
        self.round += 1;
        session
    }
}

fn worker_opening_application_bytes(opening: &WorkerOpening) -> usize {
    8 + 16
        + opening
            .queries
            .iter()
            .map(|query| {
                8 + opening_proof_application_bytes(&query.systematic)
                    + opening_proof_application_bytes(&query.systematic_next)
                    + opening_proof_application_bytes(&query.systematic_stride)
                    + opening_proof_application_bytes(&query.adjacent_parity)
                    + opening_proof_application_bytes(&query.stride_parity)
                    + opening_proof_application_bytes(&query.blend_parity)
            })
            .sum::<usize>()
}

fn opening_proof_application_bytes(opening: &pq_pcs::OpeningProof) -> usize {
    16 + opening.path.len() * 33
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
    let instance = sample_plonkish_instance(config.size)
        .map_err(|error| CliError(format!("Plonkish sample failed: {error:?}")))?;

    let prove_start = Instant::now();
    let proof = prove_for_instance(&instance, config.workers, config.pcs_queries)?;
    let prove_time = prove_start.elapsed();

    let verify_proof = if tamper {
        tamper_plonkish_proof(&proof)?
    } else {
        proof.clone()
    };
    let verify_start = Instant::now();
    let verification = verify_for_instance(&instance, &verify_proof, config.pcs_queries);
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
            let communication_bytes = pcs_communication_bytes(&proof.constraint_opening);
            (
                pq_piop_plonkish::proof_size_bytes(&proof),
                communication_bytes,
                residuals.len(),
            )
        }
    };

    Ok(MetricRecord {
        protocol: Protocol::Plonkish.as_str(),
        case_name,
        workers: config.workers,
        size: config.size,
        constraints,
        prove_ms: millis(prove_time),
        verify_ms: millis(verify_time),
        proof_bytes,
        communication_bytes,
        network_bytes: 0,
        pcs_queries: config.pcs_queries,
        verified,
        failure_reason,
    })
}

fn run_plonkish_case_network(
    config: &Config,
    addrs: &[String],
    case_name: &'static str,
    tamper: bool,
) -> Result<MetricRecord, CliError> {
    let instance = sample_plonkish_instance(config.size)
        .map_err(|error| CliError(format!("Plonkish sample failed: {error:?}")))?;
    let backend = RefCell::new(NetworkPcsClient::new(
        addrs.to_vec(),
        format!("plonkish-{case_name}"),
    ));

    let prove_start = Instant::now();
    let mut transcript = HashTranscript::new(b"pq-experiments-plonkish");
    let proof = prove_plonkish_with_pcs_hooks(
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
                .open(evaluations, commitment, point, params, transcript)
                .map_err(|_| PlonkishPiopError::InvalidProof)
        },
    )
    .map_err(|error| CliError(format!("network Plonkish prove failed: {error:?}")))?;
    let prove_time = prove_start.elapsed();
    let network_bytes = backend.borrow().bytes();

    let verify_proof = if tamper {
        tamper_plonkish_proof(&proof)?
    } else {
        proof.clone()
    };
    let verify_start = Instant::now();
    let verification = verify_for_instance(&instance, &verify_proof, config.pcs_queries);
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
            let communication_bytes = pcs_communication_bytes(&proof.constraint_opening);
            (
                pq_piop_plonkish::proof_size_bytes(&proof),
                communication_bytes,
                residuals.len(),
            )
        }
    };

    Ok(MetricRecord {
        protocol: Protocol::Plonkish.as_str(),
        case_name,
        workers: config.workers,
        size: config.size,
        constraints,
        prove_ms: millis(prove_time),
        verify_ms: millis(verify_time),
        proof_bytes,
        communication_bytes,
        network_bytes,
        pcs_queries: config.pcs_queries,
        verified,
        failure_reason,
    })
}

fn tamper_plonkish_proof(proof: &PlonkishPiopProof) -> Result<PlonkishPiopProof, CliError> {
    let mut proof = proof.clone();
    let query = proof
        .permutation_accumulator
        .recurrence_queries
        .first_mut()
        .ok_or_else(|| CliError("Plonkish accumulator query unexpectedly empty".to_owned()))?;
    query.numerator_next.value += FieldElement::ONE;
    Ok(proof)
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
            "  {{\"protocol\":\"{}\",\"case\":\"{}\",\"workers\":{},\"nv_power\":{},\"size\":{},\"constraints\":{},\"pcs_queries\":{},\"prove_ms\":{:.3},\"verify_ms\":{:.3},\"proof_bytes\":{},\"communication_bytes\":{},\"network_bytes\":{},\"verified\":{},\"failure_reason\":{}}}{}\n",
            record.protocol,
            record.case_name,
            record.workers,
            nv_power(record.size),
            record.size,
            record.constraints,
            record.pcs_queries,
            record.prove_ms,
            record.verify_ms,
            record.proof_bytes,
            record.communication_bytes,
            record.network_bytes,
            record.verified,
            failure_reason,
            comma
        ));
    }
    out.push_str("]\n");
    out
}

fn records_to_csv(records: &[MetricRecord]) -> String {
    let mut out = String::from(
        "protocol,case,workers,nv_power,size,constraints,pcs_queries,prove_ms,verify_ms,proof_bytes,communication_bytes,network_bytes,verified,failure_reason\n",
    );
    for record in records {
        let failure_reason = record
            .failure_reason
            .as_deref()
            .map(csv_escape)
            .unwrap_or_default();
        out.push_str(&format!(
            "{},{},{},{},{},{},{},{:.3},{:.3},{},{},{},{},{}\n",
            record.protocol,
            record.case_name,
            record.workers,
            nv_power(record.size),
            record.size,
            record.constraints,
            record.pcs_queries,
            record.prove_ms,
            record.verify_ms,
            record.proof_bytes,
            record.communication_bytes,
            record.network_bytes,
            record.verified,
            failure_reason
        ));
    }
    out
}

fn millis(duration: Duration) -> f64 {
    duration.as_secs_f64() * 1_000.0
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

fn json_optional_string(value: Option<&str>) -> String {
    value
        .map(|value| format!("\"{}\"", json_escape(value)))
        .unwrap_or_else(|| "null".to_owned())
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

fn unix_timestamp_seconds() -> Result<u64, CliError> {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|error| CliError(format!("system clock before UNIX epoch: {error}")))
}

fn write_text_file(path: &Path, contents: &str) -> Result<(), CliError> {
    fs::write(path, contents)
        .map_err(|error| CliError(format!("write {} failed: {error}", path.display())))
}

fn benchmark_summary(command: &BenchmarkCommand, records: &[MetricRecord]) -> String {
    let positives = records
        .iter()
        .filter(|record| record.case_name == "positive" && record.verified)
        .count();
    let negatives = records
        .iter()
        .filter(|record| record.case_name == "negative" && !record.verified)
        .count();
    let mut out = format!(
        "nv_powers={:?}\nsizes={:?}\nworkers={:?}\npcs_queries={}\nrecords={}\npositive_verified={}\nnegative_rejected={}\ncharts=prove_time_by_size.svg,verify_time_by_size.svg,proof_bytes_by_size.svg,worker_scaling_max_size.svg\n",
        command
            .sizes
            .iter()
            .map(|size| nv_power(*size))
            .collect::<Vec<_>>(),
        command.sizes,
        command.workers,
        command.pcs_queries,
        records.len(),
        positives,
        negatives
    );
    out.push_str("\nscaling_analysis:\n");
    out.push_str(
        "  baseline: workers=1 is the non-distributed local prover path for the same protocol and size.\n",
    );
    out.push_str(
        "  theory: ideal distributed proving speedup is bounded by worker count; small prototypes may be below ideal because oracle consistency, transcript, and verification are still largely serial.\n",
    );
    if let Some(max_size) = command.sizes.iter().copied().max() {
        for protocol in [Protocol::R1cs, Protocol::Plonkish] {
            if let Some(base) = records.iter().find(|record| {
                record.protocol == protocol.as_str()
                    && record.case_name == "positive"
                    && record.verified
                    && record.size == max_size
                    && record.workers == 1
            }) {
                out.push_str(&format!(
                    "  protocol={} size={} baseline_prove_ms={:.3}\n",
                    protocol.as_str(),
                    max_size,
                    base.prove_ms
                ));
                for record in records.iter().filter(|record| {
                    record.protocol == protocol.as_str()
                        && record.case_name == "positive"
                        && record.verified
                        && record.size == max_size
                }) {
                    let speedup = base.prove_ms / record.prove_ms.max(0.001);
                    let efficiency = speedup / record.workers as f64;
                    let status = if speedup > record.workers as f64 * 1.25 {
                        "suspicious-superlinear"
                    } else if record.workers > 1 && speedup < 0.05 {
                        "suspicious-slowdown"
                    } else {
                        "plausible-prototype-overhead"
                    };
                    out.push_str(&format!(
                        "    workers={} prove_ms={:.3} speedup_vs_w1={:.3} efficiency={:.3} status={}\n",
                        record.workers, record.prove_ms, speedup, efficiency, status
                    ));
                }
            }
        }
    }
    out
}

fn write_benchmark_charts(run_dir: &Path, records: &[MetricRecord]) -> Result<(), CliError> {
    write_text_file(
        &run_dir.join("prove_time_by_size.svg"),
        &line_chart_svg(
            records,
            "Prove time by circuit size",
            "Prover time (ms)",
            |record| record.prove_ms,
        ),
    )?;
    write_text_file(
        &run_dir.join("verify_time_by_size.svg"),
        &line_chart_svg(
            records,
            "Verify time by circuit size",
            "Verifier time (ms)",
            |record| record.verify_ms,
        ),
    )?;
    write_text_file(
        &run_dir.join("proof_bytes_by_size.svg"),
        &line_chart_svg(
            records,
            "Proof bytes by circuit size",
            "Proof size (bytes)",
            |record| record.proof_bytes as f64,
        ),
    )?;
    write_text_file(
        &run_dir.join("worker_scaling_max_size.svg"),
        &worker_scaling_svg(records),
    )
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
        .map(|record| (record.protocol, record.workers))
        .collect::<Vec<_>>();
    series.sort_by(|left, right| left.0.cmp(right.0).then(left.1.cmp(&right.1)));
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
    for (series_index, (protocol, workers)) in series.iter().enumerate() {
        let style = series_style(protocol, *workers, series_index);
        let mut line_points = Vec::new();
        for size in &sizes {
            if let Some(record) = positives.iter().find(|record| {
                record.protocol == *protocol && record.workers == *workers && record.size == *size
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
                xml_escape(&display_protocol(protocol)),
                workers
            ));
        }
    }
    svg.push_str("</svg>\n");
    svg
}

fn worker_scaling_svg(records: &[MetricRecord]) -> String {
    let positives = records
        .iter()
        .filter(|record| record.case_name == "positive" && record.verified)
        .collect::<Vec<_>>();
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
    let min_worker = workers.iter().copied().min().unwrap_or(1) as f64;
    let max_worker = workers.iter().copied().max().unwrap_or(1) as f64;
    let mut observed_max = 1.0_f64;
    for protocol in ["r1cs", "plonkish"] {
        let base = positives
            .iter()
            .find(|record| {
                record.protocol == protocol && record.size == max_size && record.workers == 1
            })
            .map(|record| record.prove_ms)
            .unwrap_or(1.0);
        for record in positives
            .iter()
            .filter(|record| record.protocol == protocol && record.size == max_size)
        {
            observed_max = observed_max.max(base / record.prove_ms.max(0.001));
        }
    }
    let raw_max_y = observed_max.max(max_worker).max(1.0);
    let y_step = nice_axis_step(raw_max_y, 5);
    let max_y = (raw_max_y / y_step).ceil() * y_step;
    let mut svg = paper_svg_start(
        &format!("Worker scaling at n={} (nv={max_size})", nv_power(max_size)),
        "Verified positive runs. Speedup is measured against the workers=1 baseline; dashed line is ideal linear speedup.",
    );
    draw_plot_frame(&mut svg, "Speedup vs workers=1", "Workers");
    draw_y_grid(&mut svg, max_y, y_step);
    draw_x_numeric_ticks(&mut svg, &workers, min_worker, max_worker);
    draw_legend_box(&mut svg, 3);
    for (series_index, protocol) in ["r1cs", "plonkish"].iter().enumerate() {
        let base = positives
            .iter()
            .find(|record| {
                record.protocol == *protocol && record.size == max_size && record.workers == 1
            })
            .map(|record| record.prove_ms)
            .unwrap_or(1.0);
        let style = series_style(protocol, 1, series_index);
        let mut line_points = Vec::new();
        for worker in &workers {
            if let Some(record) = positives.iter().find(|record| {
                record.protocol == *protocol && record.size == max_size && record.workers == *worker
            }) {
                let speedup = base / record.prove_ms.max(0.001);
                let x = plot_x_numeric(*worker as f64, min_worker, max_worker);
                let y = plot_y(speedup, max_y);
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
                    protocol_marker_key(protocol),
                ));
            }
            svg.push_str(&format!(
                "<g class=\"legend-entry\" transform=\"translate(765,{})\"><line x1=\"0\" y1=\"0\" x2=\"24\" y2=\"0\" stroke=\"{}\" stroke-width=\"2.4\" />{}<text x=\"34\" y=\"4\">{}</text></g>\n",
                88 + series_index * 24,
                style.color,
                marker_svg(12.0, 0.0, style.color, protocol_marker_key(protocol)),
                xml_escape(&display_protocol(protocol))
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
    svg.push_str(
        "<g class=\"legend-entry\" transform=\"translate(765,136)\"><line x1=\"0\" y1=\"0\" x2=\"24\" y2=\"0\" class=\"ideal-line\"/><text x=\"34\" y=\"4\">Ideal linear</text></g>\n",
    );
    svg.push_str("</svg>\n");
    svg
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
        "<svg xmlns=\"http://www.w3.org/2000/svg\" width=\"{:.0}\" height=\"{:.0}\" viewBox=\"0 0 {:.0} {:.0}\" shape-rendering=\"geometricPrecision\">\n<style>\ntext {{ font-family: Arial, Helvetica, sans-serif; fill: #111827; }}\n.title {{ font-size: 18px; font-weight: 700; }}\n.subtitle {{ font-size: 11px; fill: #4b5563; }}\n.axis-label {{ font-size: 13px; font-weight: 600; fill: #111827; }}\n.tick-label {{ font-size: 11px; fill: #374151; }}\n.grid {{ stroke: #e5e7eb; stroke-width: 0.8; }}\n.axis {{ stroke: #111827; stroke-width: 1.3; }}\n.series-line {{ stroke-width: 2.5; stroke-linecap: round; stroke-linejoin: round; }}\n.ideal-line {{ stroke: #6b7280; stroke-width: 1.8; stroke-dasharray: 6 5; stroke-linecap: round; }}\n.marker {{ stroke-width: 2; }}\n.legend-box {{ fill: #ffffff; stroke: #d1d5db; stroke-width: 0.9; }}\n.legend-entry text {{ font-size: 12px; fill: #111827; }}\n</style>\n<rect width=\"100%\" height=\"100%\" fill=\"#ffffff\" />\n<text class=\"title\" x=\"{}\" y=\"34\">{}</text>\n<text class=\"subtitle\" x=\"{}\" y=\"54\">{}</text>\n",
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

fn series_style(protocol: &str, workers: usize, fallback_index: usize) -> ChartSeriesStyle {
    let color = match protocol {
        "r1cs" => "#0072B2",
        "plonkish" => "#D55E00",
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

fn xml_escape(input: &str) -> String {
    input
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

fn usage() -> String {
    "usage:
  cargo run -p pq-experiments -- <r1cs|plonkish> [--workers N] [--size N] [--pcs-queries N] [--format json|csv] [--case positive|negative|both]
  cargo run -p pq-experiments -- interactive
  cargo run -p pq-experiments -- benchmark [--sizes 4,8,16 | --nv-powers 2,3,4 | --nv-range 2..6] [--workers 1,2,4] [--pcs-queries N] [--out results]
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
            "--out".to_owned(),
            "results/custom".to_owned(),
        ])
        .expect("benchmark command");

        assert_eq!(command.sizes, vec![4, 8]);
        assert_eq!(command.workers, vec![1, 2]);
        assert_eq!(command.pcs_queries, 5);
        assert_eq!(command.out_dir, PathBuf::from("results/custom"));
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
    }

    #[test]
    fn benchmark_charts_are_svg_with_real_series() {
        let records = vec![
            MetricRecord {
                protocol: "r1cs",
                case_name: "positive",
                workers: 1,
                size: 4,
                constraints: 4,
                prove_ms: 10.0,
                verify_ms: 2.0,
                proof_bytes: 100,
                communication_bytes: 50,
                network_bytes: 0,
                pcs_queries: 3,
                verified: true,
                failure_reason: None,
            },
            MetricRecord {
                protocol: "r1cs",
                case_name: "positive",
                workers: 2,
                size: 4,
                constraints: 4,
                prove_ms: 6.0,
                verify_ms: 2.0,
                proof_bytes: 110,
                communication_bytes: 60,
                network_bytes: 0,
                pcs_queries: 3,
                verified: true,
                failure_reason: None,
            },
        ];

        let chart = worker_scaling_svg(&records);
        assert!(chart.starts_with("<svg"));
        assert!(chart.contains("Ideal linear"));
        assert!(chart.contains("R1CS"));
        assert!(chart.contains("class=\"series-line\""));
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
}

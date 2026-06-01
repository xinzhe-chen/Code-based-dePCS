use std::collections::{HashMap, hash_map::Entry};
use std::io::{Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream};
use std::thread;
use std::time::Duration;

use pq_core::{FieldElement, Partition, R1csInstance, SparseEntry, SparseMatrix};
use pq_pcs::{
    Commitment, DistributedBrakedown, DistributedPcs, OpeningProof, QueryOpening, WorkerCommitment,
    WorkerOpening,
};
use pq_piop_r1cs::{
    SparkChallenges, SparkWorkerEvaluation, SparkWorkerFingerprint, SparkWorkerShardClaim,
    compute_spark_worker_shard_claim,
};

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum NetError {
    Io(String),
    InvalidMessage,
    InvalidResponse,
}

pub type NetResult<T> = Result<T, NetError>;

impl From<std::io::Error> for NetError {
    fn from(value: std::io::Error) -> Self {
        Self::Io(value.to_string())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Message {
    Ping,
    Register {
        worker_id: usize,
    },
    Round {
        session: String,
        payload: String,
    },
    PcsCommit {
        session: String,
        worker_id: usize,
        start: usize,
        values: Vec<FieldElement>,
    },
    PcsOpen {
        session: String,
        worker_id: usize,
        start: usize,
        query_indices: Vec<usize>,
    },
    R1csSparkClaim {
        session: String,
        worker_id: usize,
        start: usize,
        end: usize,
        rows: usize,
        cols: usize,
        a_entries: Vec<SparseEntry>,
        b_entries: Vec<SparseEntry>,
        c_entries: Vec<SparseEntry>,
        challenges: SparkChallenges,
        row_point: Vec<FieldElement>,
        col_point: Vec<FieldElement>,
    },
    Shutdown,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Response {
    Pong,
    Ack { worker_id: usize },
    RoundResult { payload: String },
    PcsCommitResult { commitment: WorkerCommitment },
    PcsOpenResult { opening: WorkerOpening },
    R1csSparkClaimResult { claim: SparkWorkerShardClaim },
    Bye,
    Error { message: String },
}

pub trait WorkerRuntime {
    fn start_worker(addr: &str, worker_id: usize) -> NetResult<()>;
    fn dispatch_round(addrs: &[String], session: &str, payload: &str) -> NetResult<Vec<String>>;
    fn shutdown(addrs: &[String]) -> NetResult<()>;
}

pub struct TcpWorkerRuntime;

impl WorkerRuntime for TcpWorkerRuntime {
    fn start_worker(addr: &str, worker_id: usize) -> NetResult<()> {
        run_worker(addr, worker_id)
    }

    fn dispatch_round(addrs: &[String], session: &str, payload: &str) -> NetResult<Vec<String>> {
        thread::scope(|scope| {
            let handles = addrs
                .iter()
                .map(|addr| {
                    let addr = addr.clone();
                    let session = session.to_owned();
                    let payload = payload.to_owned();
                    scope.spawn(
                        move || match send(&addr, &Message::Round { session, payload })? {
                            Response::RoundResult { payload } => Ok(payload),
                            Response::Error { message } => Err(NetError::Io(message)),
                            _ => Err(NetError::InvalidResponse),
                        },
                    )
                })
                .collect::<Vec<_>>();

            let mut out = Vec::with_capacity(handles.len());
            for handle in handles {
                match handle.join() {
                    Ok(result) => out.push(result?),
                    Err(_) => {
                        return Err(NetError::Io("worker dispatch thread panicked".to_owned()));
                    }
                }
            }
            Ok(out)
        })
    }

    fn shutdown(addrs: &[String]) -> NetResult<()> {
        thread::scope(|scope| {
            let handles = addrs
                .iter()
                .map(|addr| {
                    let addr = addr.clone();
                    scope.spawn(move || match send(&addr, &Message::Shutdown)? {
                        Response::Bye => Ok(()),
                        Response::Error { message } => Err(NetError::Io(message)),
                        _ => Err(NetError::InvalidResponse),
                    })
                })
                .collect::<Vec<_>>();

            for handle in handles {
                match handle.join() {
                    Ok(result) => result?,
                    Err(_) => {
                        return Err(NetError::Io("worker shutdown thread panicked".to_owned()));
                    }
                }
            }
            Ok(())
        })
    }
}

pub fn run_worker(addr: &str, worker_id: usize) -> NetResult<()> {
    let listener = TcpListener::bind(addr)?;
    run_worker_listener(listener, worker_id)
}

fn run_worker_listener(listener: TcpListener, worker_id: usize) -> NetResult<()> {
    let mut registered = false;
    let mut pcs_sessions = HashMap::<String, WorkerShard>::new();
    for stream in listener.incoming() {
        let mut stream = stream?;
        let message = match read_message(&mut stream) {
            Ok(message) => message,
            Err(error) => {
                let _ = write_response(
                    &mut stream,
                    &Response::Error {
                        message: format!("{error:?}"),
                    },
                );
                continue;
            }
        };
        let response = match message {
            Message::Ping => Response::Pong,
            Message::Register { worker_id: claimed } => {
                if claimed == worker_id {
                    registered = true;
                    Response::Ack { worker_id }
                } else {
                    Response::Error {
                        message: "worker id mismatch".to_string(),
                    }
                }
            }
            Message::Round { session, payload } => {
                if registered {
                    Response::RoundResult {
                        payload: format!("worker={worker_id};session={session};payload={payload}"),
                    }
                } else {
                    Response::Error {
                        message: "worker is not registered".to_string(),
                    }
                }
            }
            Message::PcsCommit {
                session,
                worker_id: claimed,
                start,
                values,
            } => {
                if !registered {
                    Response::Error {
                        message: "worker is not registered".to_string(),
                    }
                } else if claimed != worker_id {
                    Response::Error {
                        message: "worker id mismatch".to_string(),
                    }
                } else {
                    match pcs_sessions.entry(session) {
                        Entry::Occupied(_) => Response::Error {
                            message: "PCS session already exists".to_string(),
                        },
                        Entry::Vacant(entry) => {
                            match worker_pcs_commit(worker_id, start, &values) {
                                Ok(commitment) => {
                                    entry.insert(WorkerShard {
                                        start,
                                        values,
                                        commitment: commitment.clone(),
                                    });
                                    Response::PcsCommitResult { commitment }
                                }
                                Err(error) => Response::Error {
                                    message: format!("{error:?}"),
                                },
                            }
                        }
                    }
                }
            }
            Message::PcsOpen {
                session,
                worker_id: claimed,
                start,
                query_indices,
            } => {
                if !registered {
                    Response::Error {
                        message: "worker is not registered".to_string(),
                    }
                } else if claimed != worker_id {
                    Response::Error {
                        message: "worker id mismatch".to_string(),
                    }
                } else {
                    match pcs_sessions.get(&session) {
                        Some(shard) if shard.start == start => {
                            match worker_pcs_open(worker_id, shard, &query_indices) {
                                Ok(opening) => Response::PcsOpenResult { opening },
                                Err(error) => Response::Error {
                                    message: format!("{error:?}"),
                                },
                            }
                        }
                        Some(_) => Response::Error {
                            message: "PCS shard start mismatch".to_string(),
                        },
                        None => Response::Error {
                            message: "PCS session not found".to_string(),
                        },
                    }
                }
            }
            Message::R1csSparkClaim {
                session: _,
                worker_id: claimed,
                start,
                end,
                rows,
                cols,
                a_entries,
                b_entries,
                c_entries,
                challenges,
                row_point,
                col_point,
            } => {
                if !registered {
                    Response::Error {
                        message: "worker is not registered".to_string(),
                    }
                } else if claimed != worker_id {
                    Response::Error {
                        message: "worker id mismatch".to_string(),
                    }
                } else {
                    match worker_r1cs_spark_claim(
                        worker_id,
                        SparkClaimInput {
                            start,
                            end,
                            rows,
                            cols,
                            a_entries,
                            b_entries,
                            c_entries,
                            challenges,
                            row_point,
                            col_point,
                        },
                    ) {
                        Ok(claim) => Response::R1csSparkClaimResult { claim },
                        Err(error) => Response::Error {
                            message: format!("{error:?}"),
                        },
                    }
                }
            }
            Message::Shutdown => {
                write_response(&mut stream, &Response::Bye)?;
                let _ = stream.shutdown(Shutdown::Both);
                break;
            }
        };
        write_response(&mut stream, &response)?;
    }
    Ok(())
}

pub fn spawn_loopback_worker(
    worker_id: usize,
) -> NetResult<(String, thread::JoinHandle<NetResult<()>>)> {
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let addr = listener.local_addr()?.to_string();
    let handle = thread::spawn(move || run_worker_listener(listener, worker_id));
    Ok((addr, handle))
}

pub fn ping(addr: &str) -> NetResult<()> {
    match send(addr, &Message::Ping)? {
        Response::Pong => Ok(()),
        _ => Err(NetError::InvalidResponse),
    }
}

pub fn register(addr: &str, worker_id: usize) -> NetResult<()> {
    match send(addr, &Message::Register { worker_id })? {
        Response::Ack { worker_id: ack } if ack == worker_id => Ok(()),
        _ => Err(NetError::InvalidResponse),
    }
}

pub fn pcs_worker_commit(
    addr: &str,
    session: &str,
    worker_id: usize,
    start: usize,
    values: &[FieldElement],
) -> NetResult<WorkerCommitment> {
    match send(
        addr,
        &Message::PcsCommit {
            session: session.to_owned(),
            worker_id,
            start,
            values: values.to_vec(),
        },
    )? {
        Response::PcsCommitResult { commitment } => Ok(commitment),
        Response::Error { message } => Err(NetError::Io(message)),
        _ => Err(NetError::InvalidResponse),
    }
}

pub fn pcs_worker_open(
    addr: &str,
    session: &str,
    worker_id: usize,
    start: usize,
    query_indices: &[usize],
) -> NetResult<WorkerOpening> {
    match send(
        addr,
        &Message::PcsOpen {
            session: session.to_owned(),
            worker_id,
            start,
            query_indices: query_indices.to_vec(),
        },
    )? {
        Response::PcsOpenResult { opening } => Ok(opening),
        Response::Error { message } => Err(NetError::Io(message)),
        _ => Err(NetError::InvalidResponse),
    }
}

pub struct R1csSparkClaimRequest<'a> {
    pub session: &'a str,
    pub worker_id: usize,
    pub start: usize,
    pub end: usize,
    pub rows: usize,
    pub cols: usize,
    pub a_entries: &'a [SparseEntry],
    pub b_entries: &'a [SparseEntry],
    pub c_entries: &'a [SparseEntry],
    pub challenges: SparkChallenges,
    pub row_point: &'a [FieldElement],
    pub col_point: &'a [FieldElement],
}

pub fn r1cs_spark_worker_claim(
    addr: &str,
    request: R1csSparkClaimRequest<'_>,
) -> NetResult<SparkWorkerShardClaim> {
    match send(
        addr,
        &Message::R1csSparkClaim {
            session: request.session.to_owned(),
            worker_id: request.worker_id,
            start: request.start,
            end: request.end,
            rows: request.rows,
            cols: request.cols,
            a_entries: request.a_entries.to_vec(),
            b_entries: request.b_entries.to_vec(),
            c_entries: request.c_entries.to_vec(),
            challenges: request.challenges,
            row_point: request.row_point.to_vec(),
            col_point: request.col_point.to_vec(),
        },
    )? {
        Response::R1csSparkClaimResult { claim } => Ok(claim),
        Response::Error { message } => Err(NetError::Io(message)),
        _ => Err(NetError::InvalidResponse),
    }
}

pub fn send(addr: &str, message: &Message) -> NetResult<Response> {
    let mut stream = TcpStream::connect(addr)?;
    stream.set_read_timeout(Some(Duration::from_secs(2)))?;
    stream.set_write_timeout(Some(Duration::from_secs(2)))?;
    write_message(&mut stream, message)?;
    read_response(&mut stream)
}

pub fn message_wire_bytes(message: &Message) -> usize {
    frame_wire_bytes(encode_message(message).as_bytes())
}

pub fn response_wire_bytes(response: &Response) -> usize {
    frame_wire_bytes(encode_response(response).as_bytes())
}

fn frame_wire_bytes(payload: &[u8]) -> usize {
    4 + payload.len()
}

fn worker_pcs_commit(
    worker_id: usize,
    start: usize,
    values: &[FieldElement],
) -> NetResult<WorkerCommitment> {
    DistributedBrakedown::worker_commit(worker_id, start, values)
        .map_err(|error| NetError::Io(format!("{error:?}")))
}

#[derive(Clone, Debug)]
struct WorkerShard {
    start: usize,
    values: Vec<FieldElement>,
    commitment: WorkerCommitment,
}

struct SparkClaimInput {
    start: usize,
    end: usize,
    rows: usize,
    cols: usize,
    a_entries: Vec<SparseEntry>,
    b_entries: Vec<SparseEntry>,
    c_entries: Vec<SparseEntry>,
    challenges: SparkChallenges,
    row_point: Vec<FieldElement>,
    col_point: Vec<FieldElement>,
}

fn worker_pcs_open(
    worker_id: usize,
    shard: &WorkerShard,
    query_indices: &[usize],
) -> NetResult<WorkerOpening> {
    let opening =
        DistributedBrakedown::worker_open(worker_id, shard.start, &shard.values, query_indices)
            .map_err(|error| NetError::Io(format!("{error:?}")))?;
    if opening.worker_id != shard.commitment.worker_id || opening.range != shard.commitment.range {
        return Err(NetError::InvalidResponse);
    }
    Ok(opening)
}

fn worker_r1cs_spark_claim(
    worker_id: usize,
    input: SparkClaimInput,
) -> NetResult<SparkWorkerShardClaim> {
    if input.start > input.end || input.end > input.rows {
        return Err(NetError::InvalidMessage);
    }
    validate_partition_entries(input.start, input.end, &input.a_entries)?;
    validate_partition_entries(input.start, input.end, &input.b_entries)?;
    validate_partition_entries(input.start, input.end, &input.c_entries)?;
    let a = SparseMatrix::from_entries(input.rows, input.cols, input.a_entries)
        .map_err(|_| NetError::InvalidMessage)?;
    let b = SparseMatrix::from_entries(input.rows, input.cols, input.b_entries)
        .map_err(|_| NetError::InvalidMessage)?;
    let c = SparseMatrix::from_entries(input.rows, input.cols, input.c_entries)
        .map_err(|_| NetError::InvalidMessage)?;
    let instance = R1csInstance::new(a, b, c).map_err(|_| NetError::InvalidMessage)?;
    compute_spark_worker_shard_claim(
        &instance,
        Partition::new(worker_id, input.start, input.end),
        input.challenges,
        &input.row_point,
        &input.col_point,
    )
    .map_err(|error| NetError::Io(format!("{error:?}")))
}

fn validate_partition_entries(start: usize, end: usize, entries: &[SparseEntry]) -> NetResult<()> {
    if entries
        .iter()
        .all(|entry| start <= entry.row && entry.row < end)
    {
        Ok(())
    } else {
        Err(NetError::InvalidMessage)
    }
}

fn write_message(stream: &mut TcpStream, message: &Message) -> NetResult<()> {
    write_frame(stream, encode_message(message).as_bytes())
}

fn write_response(stream: &mut TcpStream, response: &Response) -> NetResult<()> {
    write_frame(stream, encode_response(response).as_bytes())
}

fn read_message(stream: &mut TcpStream) -> NetResult<Message> {
    decode_message(&String::from_utf8(read_frame(stream)?).map_err(|_| NetError::InvalidMessage)?)
}

fn read_response(stream: &mut TcpStream) -> NetResult<Response> {
    decode_response(&String::from_utf8(read_frame(stream)?).map_err(|_| NetError::InvalidMessage)?)
}

fn write_frame(stream: &mut TcpStream, payload: &[u8]) -> NetResult<()> {
    stream.write_all(&(payload.len() as u32).to_be_bytes())?;
    stream.write_all(payload)?;
    stream.flush()?;
    Ok(())
}

fn read_frame(stream: &mut TcpStream) -> NetResult<Vec<u8>> {
    let mut len = [0_u8; 4];
    stream.read_exact(&mut len)?;
    let len = u32::from_be_bytes(len) as usize;
    let mut payload = vec![0_u8; len];
    stream.read_exact(&mut payload)?;
    Ok(payload)
}

fn encode_message(message: &Message) -> String {
    match message {
        Message::Ping => "PING".to_string(),
        Message::Register { worker_id } => format!("REGISTER|{worker_id}"),
        Message::Round { session, payload } => {
            format!("ROUND|{}|{}", escape(session), escape(payload))
        }
        Message::PcsCommit {
            session,
            worker_id,
            start,
            values,
        } => format!(
            "PCS_COMMIT|{}|{}|{}|{}",
            escape(session),
            worker_id,
            start,
            encode_fields(values)
        ),
        Message::PcsOpen {
            session,
            worker_id,
            start,
            query_indices,
        } => format!(
            "PCS_OPEN|{}|{}|{}|{}",
            escape(session),
            worker_id,
            start,
            encode_usizes(query_indices)
        ),
        Message::R1csSparkClaim {
            session,
            worker_id,
            start,
            end,
            rows,
            cols,
            a_entries,
            b_entries,
            c_entries,
            challenges,
            row_point,
            col_point,
        } => format!(
            "R1CS_SPARK_CLAIM|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}",
            escape(session),
            worker_id,
            start,
            end,
            rows,
            cols,
            encode_sparse_entries(a_entries),
            encode_sparse_entries(b_entries),
            encode_sparse_entries(c_entries),
            encode_spark_challenges(*challenges),
            encode_fields(row_point),
            encode_fields(col_point)
        ),
        Message::Shutdown => "SHUTDOWN".to_string(),
    }
}

fn decode_message(input: &str) -> NetResult<Message> {
    let parts = split_escaped(input);
    match parts.as_slice() {
        [kind] if kind == "PING" => Ok(Message::Ping),
        [kind, id] if kind == "REGISTER" => Ok(Message::Register {
            worker_id: id.parse().map_err(|_| NetError::InvalidMessage)?,
        }),
        [kind, session, payload] if kind == "ROUND" => Ok(Message::Round {
            session: unescape(session),
            payload: unescape(payload),
        }),
        [kind, session, worker_id, start, values] if kind == "PCS_COMMIT" => {
            Ok(Message::PcsCommit {
                session: unescape(session),
                worker_id: parse_usize(worker_id)?,
                start: parse_usize(start)?,
                values: decode_fields(values)?,
            })
        }
        [kind, session, worker_id, start, query_indices] if kind == "PCS_OPEN" => {
            Ok(Message::PcsOpen {
                session: unescape(session),
                worker_id: parse_usize(worker_id)?,
                start: parse_usize(start)?,
                query_indices: decode_usizes(query_indices)?,
            })
        }
        [
            kind,
            session,
            worker_id,
            start,
            end,
            rows,
            cols,
            a_entries,
            b_entries,
            c_entries,
            challenges,
            row_point,
            col_point,
        ] if kind == "R1CS_SPARK_CLAIM" => Ok(Message::R1csSparkClaim {
            session: unescape(session),
            worker_id: parse_usize(worker_id)?,
            start: parse_usize(start)?,
            end: parse_usize(end)?,
            rows: parse_usize(rows)?,
            cols: parse_usize(cols)?,
            a_entries: decode_sparse_entries(a_entries)?,
            b_entries: decode_sparse_entries(b_entries)?,
            c_entries: decode_sparse_entries(c_entries)?,
            challenges: decode_spark_challenges(challenges)?,
            row_point: decode_fields(row_point)?,
            col_point: decode_fields(col_point)?,
        }),
        [kind] if kind == "SHUTDOWN" => Ok(Message::Shutdown),
        _ => Err(NetError::InvalidMessage),
    }
}

fn encode_response(response: &Response) -> String {
    match response {
        Response::Pong => "PONG".to_string(),
        Response::Ack { worker_id } => format!("ACK|{worker_id}"),
        Response::RoundResult { payload } => format!("ROUND_RESULT|{}", escape(payload)),
        Response::PcsCommitResult { commitment } => {
            format!("PCS_COMMIT_RESULT|{}", encode_worker_commitment(commitment))
        }
        Response::PcsOpenResult { opening } => {
            format!("PCS_OPEN_RESULT|{}", encode_worker_opening(opening))
        }
        Response::R1csSparkClaimResult { claim } => {
            format!("R1CS_SPARK_CLAIM_RESULT|{}", encode_spark_claim(claim))
        }
        Response::Bye => "BYE".to_string(),
        Response::Error { message } => format!("ERROR|{}", escape(message)),
    }
}

fn decode_response(input: &str) -> NetResult<Response> {
    let parts = split_escaped(input);
    match parts.as_slice() {
        [kind] if kind == "PONG" => Ok(Response::Pong),
        [kind, id] if kind == "ACK" => Ok(Response::Ack {
            worker_id: id.parse().map_err(|_| NetError::InvalidMessage)?,
        }),
        [kind, payload] if kind == "ROUND_RESULT" => Ok(Response::RoundResult {
            payload: unescape(payload),
        }),
        [kind, commitment] if kind == "PCS_COMMIT_RESULT" => Ok(Response::PcsCommitResult {
            commitment: decode_worker_commitment(commitment)?,
        }),
        [kind, opening] if kind == "PCS_OPEN_RESULT" => Ok(Response::PcsOpenResult {
            opening: decode_worker_opening(opening)?,
        }),
        [kind, claim] if kind == "R1CS_SPARK_CLAIM_RESULT" => Ok(Response::R1csSparkClaimResult {
            claim: decode_spark_claim(claim)?,
        }),
        [kind] if kind == "BYE" => Ok(Response::Bye),
        [kind, message] if kind == "ERROR" => Ok(Response::Error {
            message: unescape(message),
        }),
        _ => Err(NetError::InvalidResponse),
    }
}

fn escape(input: &str) -> String {
    input.replace('\\', "\\\\").replace('|', "\\p")
}

fn unescape(input: &str) -> String {
    let mut out = String::new();
    let mut chars = input.chars();
    while let Some(ch) = chars.next() {
        if ch == '\\' {
            match chars.next() {
                Some('p') => out.push('|'),
                Some('\\') => out.push('\\'),
                Some(other) => {
                    out.push('\\');
                    out.push(other);
                }
                None => out.push('\\'),
            }
        } else {
            out.push(ch);
        }
    }
    out
}

fn split_escaped(input: &str) -> Vec<String> {
    let mut parts = Vec::new();
    let mut current = String::new();
    let mut escaped = false;
    for ch in input.chars() {
        if escaped {
            current.push('\\');
            current.push(ch);
            escaped = false;
        } else if ch == '\\' {
            escaped = true;
        } else if ch == '|' {
            parts.push(current.clone());
            current.clear();
        } else {
            current.push(ch);
        }
    }
    if escaped {
        current.push('\\');
    }
    parts.push(current);
    parts
}

fn encode_fields(values: &[FieldElement]) -> String {
    values
        .iter()
        .map(|value| value.value().to_string())
        .collect::<Vec<_>>()
        .join(",")
}

fn decode_fields(input: &str) -> NetResult<Vec<FieldElement>> {
    if input.is_empty() {
        return Ok(Vec::new());
    }
    input
        .split(',')
        .map(|item| {
            item.parse::<u64>()
                .map(FieldElement::from)
                .map_err(|_| NetError::InvalidMessage)
        })
        .collect()
}

fn encode_usizes(values: &[usize]) -> String {
    values
        .iter()
        .map(usize::to_string)
        .collect::<Vec<_>>()
        .join(",")
}

fn decode_usizes(input: &str) -> NetResult<Vec<usize>> {
    if input.is_empty() {
        return Ok(Vec::new());
    }
    input.split(',').map(parse_usize).collect()
}

fn encode_sparse_entries(entries: &[SparseEntry]) -> String {
    entries
        .iter()
        .map(|entry| format!("{}:{}:{}", entry.row, entry.col, entry.value.value()))
        .collect::<Vec<_>>()
        .join(";")
}

fn decode_sparse_entries(input: &str) -> NetResult<Vec<SparseEntry>> {
    if input.is_empty() {
        return Ok(Vec::new());
    }
    input
        .split(';')
        .map(|item| {
            let parts = item.split(':').collect::<Vec<_>>();
            match parts.as_slice() {
                [row, col, value] => Ok(SparseEntry {
                    row: parse_usize(row)?,
                    col: parse_usize(col)?,
                    value: value
                        .parse::<u64>()
                        .map(FieldElement::from)
                        .map_err(|_| NetError::InvalidMessage)?,
                }),
                _ => Err(NetError::InvalidMessage),
            }
        })
        .collect()
}

fn encode_spark_challenges(challenges: SparkChallenges) -> String {
    encode_fields(&[
        challenges.tuple,
        challenges.matrix,
        challenges.row,
        challenges.col,
        challenges.value,
    ])
}

fn decode_spark_challenges(input: &str) -> NetResult<SparkChallenges> {
    let values = decode_fields(input)?;
    match values.as_slice() {
        [tuple, matrix, row, col, value] => Ok(SparkChallenges {
            tuple: *tuple,
            matrix: *matrix,
            row: *row,
            col: *col,
            value: *value,
        }),
        _ => Err(NetError::InvalidMessage),
    }
}

fn parse_usize(input: &str) -> NetResult<usize> {
    input.parse().map_err(|_| NetError::InvalidMessage)
}

fn encode_worker_commitment(commitment: &WorkerCommitment) -> String {
    format!(
        "{}:{}:{}:{}:{}",
        commitment.worker_id,
        commitment.range.0,
        commitment.range.1,
        commitment.encoded_commitment.len,
        encode_hash(&commitment.encoded_commitment.root)
    )
}

fn decode_worker_commitment(input: &str) -> NetResult<WorkerCommitment> {
    let parts = input.split(':').collect::<Vec<_>>();
    match parts.as_slice() {
        [worker_id, start, end, len, root] => Ok(WorkerCommitment {
            worker_id: parse_usize(worker_id)?,
            range: (parse_usize(start)?, parse_usize(end)?),
            encoded_commitment: Commitment {
                len: parse_usize(len)?,
                root: decode_hash(root)?,
            },
        }),
        _ => Err(NetError::InvalidResponse),
    }
}

fn encode_worker_opening(opening: &WorkerOpening) -> String {
    format!(
        "{}:{}:{}:{}",
        opening.worker_id,
        opening.range.0,
        opening.range.1,
        opening
            .queries
            .iter()
            .map(encode_query_opening)
            .collect::<Vec<_>>()
            .join(";")
    )
}

fn decode_worker_opening(input: &str) -> NetResult<WorkerOpening> {
    let parts = input.splitn(4, ':').collect::<Vec<_>>();
    match parts.as_slice() {
        [worker_id, start, end, queries] => Ok(WorkerOpening {
            worker_id: parse_usize(worker_id)?,
            range: (parse_usize(start)?, parse_usize(end)?),
            queries: decode_query_openings(queries)?,
        }),
        _ => Err(NetError::InvalidResponse),
    }
}

fn encode_spark_claim(claim: &SparkWorkerShardClaim) -> String {
    format!(
        "{}#{}",
        encode_spark_fingerprint(&claim.fingerprint),
        claim
            .matrix_evaluations
            .iter()
            .map(encode_spark_evaluation)
            .collect::<Vec<_>>()
            .join(";")
    )
}

fn decode_spark_claim(input: &str) -> NetResult<SparkWorkerShardClaim> {
    let parts = input.splitn(2, '#').collect::<Vec<_>>();
    match parts.as_slice() {
        [fingerprint, evaluations] => Ok(SparkWorkerShardClaim {
            fingerprint: decode_spark_fingerprint(fingerprint)?,
            matrix_evaluations: decode_spark_evaluations(evaluations)?,
        }),
        _ => Err(NetError::InvalidResponse),
    }
}

fn encode_spark_fingerprint(fingerprint: &SparkWorkerFingerprint) -> String {
    format!(
        "{}:{}:{}:{}:{}:{}",
        fingerprint.worker_id,
        fingerprint.range.0,
        fingerprint.range.1,
        fingerprint.entry_count,
        fingerprint.linear_fingerprint.value(),
        fingerprint.product_fingerprint.value()
    )
}

fn decode_spark_fingerprint(input: &str) -> NetResult<SparkWorkerFingerprint> {
    let parts = input.split(':').collect::<Vec<_>>();
    match parts.as_slice() {
        [worker_id, start, end, entry_count, linear, product] => Ok(SparkWorkerFingerprint {
            worker_id: parse_usize(worker_id)?,
            range: (parse_usize(start)?, parse_usize(end)?),
            entry_count: parse_usize(entry_count)?,
            linear_fingerprint: parse_field_response(linear)?,
            product_fingerprint: parse_field_response(product)?,
        }),
        _ => Err(NetError::InvalidResponse),
    }
}

fn encode_spark_evaluation(evaluation: &SparkWorkerEvaluation) -> String {
    format!(
        "{}:{}:{}:{}:{}:{}",
        evaluation.matrix_id,
        evaluation.worker_id,
        evaluation.range.0,
        evaluation.range.1,
        evaluation.entry_count,
        evaluation.evaluation.value()
    )
}

fn decode_spark_evaluations(input: &str) -> NetResult<Vec<SparkWorkerEvaluation>> {
    if input.is_empty() {
        return Ok(Vec::new());
    }
    input.split(';').map(decode_spark_evaluation).collect()
}

fn decode_spark_evaluation(input: &str) -> NetResult<SparkWorkerEvaluation> {
    let parts = input.split(':').collect::<Vec<_>>();
    match parts.as_slice() {
        [matrix_id, worker_id, start, end, entry_count, evaluation] => Ok(SparkWorkerEvaluation {
            matrix_id: parse_usize(matrix_id)?,
            worker_id: parse_usize(worker_id)?,
            range: (parse_usize(start)?, parse_usize(end)?),
            entry_count: parse_usize(entry_count)?,
            evaluation: parse_field_response(evaluation)?,
        }),
        _ => Err(NetError::InvalidResponse),
    }
}

fn parse_field_response(input: &str) -> NetResult<FieldElement> {
    input
        .parse::<u64>()
        .map(FieldElement::from)
        .map_err(|_| NetError::InvalidResponse)
}

fn encode_query_opening(query: &QueryOpening) -> String {
    format!(
        "{}~{}~{}~{}~{}~{}~{}",
        query.query_index,
        encode_opening(&query.systematic),
        encode_opening(&query.systematic_next),
        encode_opening(&query.systematic_stride),
        encode_opening(&query.adjacent_parity),
        encode_opening(&query.stride_parity),
        encode_opening(&query.blend_parity)
    )
}

fn decode_query_openings(input: &str) -> NetResult<Vec<QueryOpening>> {
    if input.is_empty() {
        return Ok(Vec::new());
    }
    input
        .split(';')
        .map(|item| {
            let parts = item.split('~').collect::<Vec<_>>();
            match parts.as_slice() {
                [
                    query_index,
                    systematic,
                    systematic_next,
                    systematic_stride,
                    adjacent_parity,
                    stride_parity,
                    blend_parity,
                ] => Ok(QueryOpening {
                    query_index: parse_usize(query_index)?,
                    systematic: decode_opening(systematic)?,
                    systematic_next: decode_opening(systematic_next)?,
                    systematic_stride: decode_opening(systematic_stride)?,
                    adjacent_parity: decode_opening(adjacent_parity)?,
                    stride_parity: decode_opening(stride_parity)?,
                    blend_parity: decode_opening(blend_parity)?,
                }),
                _ => Err(NetError::InvalidResponse),
            }
        })
        .collect()
}

fn encode_opening(opening: &OpeningProof) -> String {
    format!(
        "{}:{}:{}",
        opening.index,
        opening.value.value(),
        opening
            .path
            .iter()
            .map(|(hash, sibling_is_right)| {
                format!(
                    "{}{}",
                    if *sibling_is_right { 'R' } else { 'L' },
                    encode_hash(hash)
                )
            })
            .collect::<Vec<_>>()
            .join(".")
    )
}

fn decode_opening(input: &str) -> NetResult<OpeningProof> {
    let parts = input.splitn(3, ':').collect::<Vec<_>>();
    match parts.as_slice() {
        [index, value, path] => Ok(OpeningProof {
            index: parse_usize(index)?,
            value: value
                .parse::<u64>()
                .map(FieldElement::from)
                .map_err(|_| NetError::InvalidResponse)?,
            path: decode_path(path)?,
        }),
        _ => Err(NetError::InvalidResponse),
    }
}

fn decode_path(input: &str) -> NetResult<Vec<([u8; 32], bool)>> {
    if input.is_empty() {
        return Ok(Vec::new());
    }
    input
        .split('.')
        .map(|item| {
            let (side, hash) = item.split_at(1);
            let sibling_is_right = match side {
                "R" => true,
                "L" => false,
                _ => return Err(NetError::InvalidResponse),
            };
            Ok((decode_hash(hash)?, sibling_is_right))
        })
        .collect()
}

fn encode_hash(hash: &[u8; 32]) -> String {
    let mut out = String::with_capacity(64);
    for byte in hash {
        out.push(hex_digit(byte >> 4));
        out.push(hex_digit(byte & 0x0f));
    }
    out
}

fn decode_hash(input: &str) -> NetResult<[u8; 32]> {
    if input.len() != 64 {
        return Err(NetError::InvalidResponse);
    }
    let mut out = [0_u8; 32];
    for (idx, pair) in input.as_bytes().chunks_exact(2).enumerate() {
        out[idx] = (hex_value(pair[0])? << 4) | hex_value(pair[1])?;
    }
    Ok(out)
}

fn hex_digit(value: u8) -> char {
    match value {
        0..=9 => (b'0' + value) as char,
        10..=15 => (b'a' + (value - 10)) as char,
        _ => '?',
    }
}

fn hex_value(value: u8) -> NetResult<u8> {
    match value {
        b'0'..=b'9' => Ok(value - b'0'),
        b'a'..=b'f' => Ok(value - b'a' + 10),
        b'A'..=b'F' => Ok(value - b'A' + 10),
        _ => Err(NetError::InvalidResponse),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pq_core::sample_r1cs;
    use pq_pcs::{MerklePcs, PolynomialCommitment};

    #[test]
    fn tcp_worker_register_round_shutdown() {
        let (addr, handle) = spawn_loopback_worker(7).expect("worker");
        ping(&addr).expect("ping");
        register(&addr, 7).expect("register");
        let replies =
            TcpWorkerRuntime::dispatch_round(std::slice::from_ref(&addr), "s1", "payload")
                .expect("round");
        assert_eq!(replies.len(), 1);
        assert!(replies[0].contains("worker=7"));
        TcpWorkerRuntime::shutdown(std::slice::from_ref(&addr)).expect("shutdown");
        handle.join().expect("join").expect("worker ok");
    }

    #[test]
    fn tcp_worker_parallel_round_preserves_address_order() {
        let mut addrs = Vec::new();
        let mut handles = Vec::new();
        for worker_id in 0..3 {
            let (addr, handle) = spawn_loopback_worker(worker_id).expect("worker");
            ping(&addr).expect("ping");
            register(&addr, worker_id).expect("register");
            addrs.push(addr);
            handles.push(handle);
        }

        let replies =
            TcpWorkerRuntime::dispatch_round(&addrs, "ordered", "payload").expect("parallel round");
        assert_eq!(replies.len(), addrs.len());
        for (worker_id, reply) in replies.iter().enumerate() {
            assert!(reply.contains(&format!("worker={worker_id}")));
            assert!(reply.contains("session=ordered"));
        }

        TcpWorkerRuntime::shutdown(&addrs).expect("shutdown");
        for handle in handles {
            handle.join().expect("join").expect("worker ok");
        }
    }

    #[test]
    fn wrong_worker_id_is_rejected() {
        let (addr, handle) = spawn_loopback_worker(3).expect("worker");
        assert!(register(&addr, 4).is_err());
        assert!(
            TcpWorkerRuntime::dispatch_round(std::slice::from_ref(&addr), "s1", "payload").is_err()
        );
        TcpWorkerRuntime::shutdown(std::slice::from_ref(&addr)).expect("shutdown");
        handle.join().expect("join").expect("worker ok");
    }

    #[test]
    fn malformed_connection_does_not_stop_worker() {
        let (addr, handle) = spawn_loopback_worker(5).expect("worker");
        let stream = std::net::TcpStream::connect(&addr).expect("connect");
        drop(stream);

        ping(&addr).expect("ping");
        register(&addr, 5).expect("register");
        TcpWorkerRuntime::shutdown(std::slice::from_ref(&addr)).expect("shutdown");
        handle.join().expect("join").expect("worker ok");
    }

    #[test]
    fn codec_round_trips_escaped_payloads() {
        let message = Message::Round {
            session: "s|one\\two\\p".to_string(),
            payload: "payload|with\\slashes\\pand trailing\\".to_string(),
        };
        let encoded = encode_message(&message);
        assert_eq!(decode_message(&encoded), Ok(message));

        let response = Response::RoundResult {
            payload: "result|with\\slashes\\p".to_string(),
        };
        let encoded = encode_response(&response);
        assert_eq!(decode_response(&encoded), Ok(response));

        let open = Message::PcsOpen {
            session: "pcs|session".to_string(),
            worker_id: 2,
            start: 16,
            query_indices: vec![0, 3, 5],
        };
        let encoded = encode_message(&open);
        assert_eq!(decode_message(&encoded), Ok(open));
    }

    #[test]
    fn wire_byte_helpers_match_framed_codec_lengths() {
        let message = Message::PcsOpen {
            session: "pcs|session".to_string(),
            worker_id: 2,
            start: 16,
            query_indices: vec![0, 3, 5],
        };
        let encoded = encode_message(&message);
        assert_eq!(message_wire_bytes(&message), 4 + encoded.len());

        let response = Response::Error {
            message: "bad|worker".to_string(),
        };
        let encoded = encode_response(&response);
        assert_eq!(response_wire_bytes(&response), 4 + encoded.len());
    }

    #[test]
    fn worker_stores_committed_pcs_shard_and_opens_by_session() {
        let (addr, handle) = spawn_loopback_worker(0).expect("worker");
        ping(&addr).expect("ping");
        register(&addr, 0).expect("register");
        let values = vec![1_u64.into(), 2_u64.into(), 3_u64.into(), 4_u64.into()];
        let commitment = pcs_worker_commit(&addr, "pcs-test", 0, 0, &values).expect("commit");
        assert_eq!(commitment.worker_id, 0);
        assert_eq!(commitment.range, (0, values.len()));

        let opening = pcs_worker_open(&addr, "pcs-test", 0, 0, &[0, 2]).expect("open");
        assert_eq!(opening.worker_id, 0);
        assert_eq!(opening.queries.len(), 2);
        for query in &opening.queries {
            MerklePcs::verify(&commitment.encoded_commitment, &query.systematic)
                .expect("systematic");
            MerklePcs::verify(&commitment.encoded_commitment, &query.systematic_next)
                .expect("next");
            MerklePcs::verify(&commitment.encoded_commitment, &query.systematic_stride)
                .expect("stride");
            MerklePcs::verify(&commitment.encoded_commitment, &query.adjacent_parity)
                .expect("adjacent");
            MerklePcs::verify(&commitment.encoded_commitment, &query.stride_parity)
                .expect("stride parity");
            MerklePcs::verify(&commitment.encoded_commitment, &query.blend_parity).expect("blend");
        }
        let replacement = vec![9_u64.into(), 9_u64.into(), 9_u64.into(), 9_u64.into()];
        assert!(pcs_worker_commit(&addr, "pcs-test", 0, 0, &replacement).is_err());
        let original_opening = pcs_worker_open(&addr, "pcs-test", 0, 0, &[0]).expect("open");
        assert_eq!(original_opening.queries[0].systematic.value, values[0]);
        assert!(pcs_worker_open(&addr, "missing-session", 0, 0, &[0]).is_err());
        assert!(pcs_worker_open(&addr, "pcs-test", 0, 1, &[0]).is_err());

        TcpWorkerRuntime::shutdown(std::slice::from_ref(&addr)).expect("shutdown");
        handle.join().expect("join").expect("worker ok");
    }

    #[test]
    fn worker_computes_r1cs_spark_claim_for_partition() {
        let (instance, _) = sample_r1cs();
        let (addr, handle) = spawn_loopback_worker(0).expect("worker");
        ping(&addr).expect("ping");
        register(&addr, 0).expect("register");
        let partition = Partition::new(0, 0, 1);
        let challenges = SparkChallenges {
            tuple: 11_u64.into(),
            matrix: 13_u64.into(),
            row: 17_u64.into(),
            col: 19_u64.into(),
            value: 23_u64.into(),
        };
        let row_point = vec![3_u64.into()];
        let col_point = vec![5_u64.into(), 7_u64.into()];
        let a_entries = partition_entries_for_test(instance.a(), partition);
        let b_entries = partition_entries_for_test(instance.b(), partition);
        let c_entries = partition_entries_for_test(instance.c(), partition);
        let claim = r1cs_spark_worker_claim(
            &addr,
            R1csSparkClaimRequest {
                session: "spark-test",
                worker_id: partition.id,
                start: partition.start,
                end: partition.end,
                rows: instance.num_constraints(),
                cols: instance.num_variables(),
                a_entries: &a_entries,
                b_entries: &b_entries,
                c_entries: &c_entries,
                challenges,
                row_point: &row_point,
                col_point: &col_point,
            },
        )
        .expect("spark claim");
        let expected = compute_spark_worker_shard_claim(
            &instance, partition, challenges, &row_point, &col_point,
        )
        .expect("local claim");
        assert_eq!(claim, expected);

        let message = Message::R1csSparkClaim {
            session: "spark|session".to_owned(),
            worker_id: partition.id,
            start: partition.start,
            end: partition.end,
            rows: instance.num_constraints(),
            cols: instance.num_variables(),
            a_entries,
            b_entries,
            c_entries,
            challenges,
            row_point,
            col_point,
        };
        let encoded = encode_message(&message);
        assert_eq!(decode_message(&encoded), Ok(message));
        let response = Response::R1csSparkClaimResult { claim };
        let encoded = encode_response(&response);
        assert_eq!(decode_response(&encoded), Ok(response));

        assert!(
            r1cs_spark_worker_claim(
                &addr,
                R1csSparkClaimRequest {
                    session: "spark-bad",
                    worker_id: 1,
                    start: 0,
                    end: 1,
                    rows: instance.num_constraints(),
                    cols: instance.num_variables(),
                    a_entries: &[],
                    b_entries: &[],
                    c_entries: &[],
                    challenges,
                    row_point: &[],
                    col_point: &[],
                },
            )
            .is_err()
        );

        TcpWorkerRuntime::shutdown(std::slice::from_ref(&addr)).expect("shutdown");
        handle.join().expect("join").expect("worker ok");
    }

    fn partition_entries_for_test(matrix: &SparseMatrix, partition: Partition) -> Vec<SparseEntry> {
        matrix
            .entries()
            .iter()
            .copied()
            .filter(|entry| partition.contains(entry.row))
            .collect()
    }
}

use std::io::{Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream};
use std::thread;
use std::time::Duration;

use pq_core::FieldElement;
use pq_pcs::{
    Commitment, MerklePcs, OpeningProof, PolynomialCommitment, QueryOpening, WorkerCommitment,
    WorkerOpening, encode_systematic,
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
        values: Vec<FieldElement>,
        query_indices: Vec<usize>,
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
        let mut out = Vec::with_capacity(addrs.len());
        for addr in addrs {
            let response = send(
                addr,
                &Message::Round {
                    session: session.to_string(),
                    payload: payload.to_string(),
                },
            )?;
            match response {
                Response::RoundResult { payload } => out.push(payload),
                Response::Error { message } => return Err(NetError::Io(message)),
                _ => return Err(NetError::InvalidResponse),
            }
        }
        Ok(out)
    }

    fn shutdown(addrs: &[String]) -> NetResult<()> {
        for addr in addrs {
            let response = send(addr, &Message::Shutdown)?;
            if response != Response::Bye {
                return Err(NetError::InvalidResponse);
            }
        }
        Ok(())
    }
}

pub fn run_worker(addr: &str, worker_id: usize) -> NetResult<()> {
    let listener = TcpListener::bind(addr)?;
    run_worker_listener(listener, worker_id)
}

fn run_worker_listener(listener: TcpListener, worker_id: usize) -> NetResult<()> {
    let mut registered = false;
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
                session: _,
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
                    match worker_pcs_commit(worker_id, start, &values) {
                        Ok(commitment) => Response::PcsCommitResult { commitment },
                        Err(error) => Response::Error {
                            message: format!("{error:?}"),
                        },
                    }
                }
            }
            Message::PcsOpen {
                session: _,
                worker_id: claimed,
                start,
                values,
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
                    match worker_pcs_open(worker_id, start, &values, &query_indices) {
                        Ok(opening) => Response::PcsOpenResult { opening },
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
    values: &[FieldElement],
    query_indices: &[usize],
) -> NetResult<WorkerOpening> {
    match send(
        addr,
        &Message::PcsOpen {
            session: session.to_owned(),
            worker_id,
            start,
            values: values.to_vec(),
            query_indices: query_indices.to_vec(),
        },
    )? {
        Response::PcsOpenResult { opening } => Ok(opening),
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

fn worker_pcs_commit(
    worker_id: usize,
    start: usize,
    values: &[FieldElement],
) -> NetResult<WorkerCommitment> {
    let codeword = encode_systematic(values).map_err(|error| NetError::Io(format!("{error:?}")))?;
    let encoded_commitment =
        MerklePcs::commit(&codeword).map_err(|error| NetError::Io(format!("{error:?}")))?;
    Ok(WorkerCommitment {
        worker_id,
        range: (start, start + values.len()),
        encoded_commitment,
    })
}

fn worker_pcs_open(
    worker_id: usize,
    start: usize,
    values: &[FieldElement],
    query_indices: &[usize],
) -> NetResult<WorkerOpening> {
    let codeword = encode_systematic(values).map_err(|error| NetError::Io(format!("{error:?}")))?;
    let col_len = values.len();
    let stride_offset = if col_len > 1 { col_len / 2 } else { 0 };
    let mut queries = Vec::with_capacity(query_indices.len());
    for query_index in query_indices {
        if *query_index >= col_len {
            return Err(NetError::InvalidMessage);
        }
        let next = (query_index + 1) % col_len;
        let stride = (query_index + stride_offset) % col_len;
        queries.push(QueryOpening {
            query_index: *query_index,
            systematic: MerklePcs::open(&codeword, *query_index)
                .map_err(|error| NetError::Io(format!("{error:?}")))?,
            systematic_next: MerklePcs::open(&codeword, next)
                .map_err(|error| NetError::Io(format!("{error:?}")))?,
            systematic_stride: MerklePcs::open(&codeword, stride)
                .map_err(|error| NetError::Io(format!("{error:?}")))?,
            adjacent_parity: MerklePcs::open(&codeword, col_len + *query_index)
                .map_err(|error| NetError::Io(format!("{error:?}")))?,
            stride_parity: MerklePcs::open(&codeword, 2 * col_len + *query_index)
                .map_err(|error| NetError::Io(format!("{error:?}")))?,
            blend_parity: MerklePcs::open(&codeword, 3 * col_len + *query_index)
                .map_err(|error| NetError::Io(format!("{error:?}")))?,
        });
    }
    Ok(WorkerOpening {
        worker_id,
        range: (start, start + values.len()),
        queries,
    })
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
            values,
            query_indices,
        } => format!(
            "PCS_OPEN|{}|{}|{}|{}|{}",
            escape(session),
            worker_id,
            start,
            encode_fields(values),
            encode_usizes(query_indices)
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
        [kind, session, worker_id, start, values, query_indices] if kind == "PCS_OPEN" => {
            Ok(Message::PcsOpen {
                session: unescape(session),
                worker_id: parse_usize(worker_id)?,
                start: parse_usize(start)?,
                values: decode_fields(values)?,
                query_indices: decode_usizes(query_indices)?,
            })
        }
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
    }

    #[test]
    fn worker_executes_pcs_commit_and_open_tasks() {
        let (addr, handle) = spawn_loopback_worker(0).expect("worker");
        ping(&addr).expect("ping");
        register(&addr, 0).expect("register");
        let values = vec![1_u64.into(), 2_u64.into(), 3_u64.into(), 4_u64.into()];
        let commitment = pcs_worker_commit(&addr, "pcs-test", 0, 0, &values).expect("commit");
        assert_eq!(commitment.worker_id, 0);
        assert_eq!(commitment.range, (0, values.len()));

        let opening = pcs_worker_open(&addr, "pcs-test", 0, 0, &values, &[0, 2]).expect("open");
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

        TcpWorkerRuntime::shutdown(std::slice::from_ref(&addr)).expect("shutdown");
        handle.join().expect("join").expect("worker ok");
    }
}

//! Framed TCP worker network used by PCS/dePCS benchmarks.
//!
//! This module owns the transport boundary only: request/response message
//! types, length-prefixed bincode frames, worker process startup, byte counters,
//! concurrent send/receive, and shutdown. Protocol-specific request handling
//! stays in `main.rs` so benchmark timing and CSV accounting remain unchanged.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::Duration;

use pq_core::FieldElement;
use pq_pcs::{
    PcsBackendConfig, Protocol11WorkerCommitment, Protocol11WorkerMatrixColumnProof,
    Protocol11WorkerOpenPayload,
    depcs::{
        self, PaperDepcsConfig, PaperProtocol11Commitment, PaperProtocol11WorkerCommitment,
        PaperProtocol11WorkerOpening,
    },
};
use serde::{Deserialize, Serialize};

use crate::CliError;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) enum PcsWorkerRequest {
    CommitRows {
        original_len: usize,
        workers: usize,
        worker_id: usize,
        backend: PcsBackendConfig,
        rows: Vec<Vec<FieldElement>>,
    },
    CommitSeeded {
        original_len: usize,
        workers: usize,
        worker_id: usize,
        backend: PcsBackendConfig,
        evaluation_seed: u64,
    },
    OpenPrepare {
        a: Vec<FieldElement>,
        beta: Vec<FieldElement>,
    },
    OpenColumns {
        commitment: pq_pcs::Protocol11Commitment,
        query_indices: Vec<usize>,
    },
    PaperCommitSeeded {
        original_len: usize,
        workers: usize,
        worker_id: usize,
        config: PaperDepcsConfig,
    },
    PaperOpen {
        commitment: PaperProtocol11Commitment,
        point: Vec<depcs::PaperField>,
    },
    Shutdown,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) enum PcsWorkerResponse {
    Commit {
        commitment: Protocol11WorkerCommitment,
    },
    OpenPrepare {
        payload: Protocol11WorkerOpenPayload,
    },
    OpenColumns {
        proof: Protocol11WorkerMatrixColumnProof,
    },
    PaperCommit {
        commitment: PaperProtocol11WorkerCommitment,
        elapsed_ms: f64,
    },
    PaperOpen {
        opening: PaperProtocol11WorkerOpening,
        elapsed_ms: f64,
    },
    Ack,
    Error {
        message: String,
    },
}

pub(crate) struct PcsNetworkWorkerClient {
    pub(crate) child: Child,
    pub(crate) stream: TcpStream,
    pub(crate) bytes_sent: usize,
    pub(crate) bytes_recv: usize,
}

pub(crate) fn write_frame_binary<T: Serialize>(
    stream: &mut TcpStream,
    value: &T,
) -> Result<usize, CliError> {
    let payload = bincode::serialize(value)
        .map_err(|error| CliError(format!("serialize failed: {error}")))?;
    let len = payload.len() as u64;
    let len_bytes = len.to_le_bytes();
    stream
        .write_all(&[0_u8])
        .map_err(|error| CliError(format!("write frame channel failed: {error}")))?;
    stream
        .write_all(&len_bytes)
        .map_err(|error| CliError(format!("write frame length failed: {error}")))?;
    stream
        .write_all(&payload)
        .map_err(|error| CliError(format!("write frame payload failed: {error}")))?;
    Ok(1 + len_bytes.len() + payload.len())
}

pub(crate) fn read_frame_binary<T: for<'de> Deserialize<'de>>(
    stream: &mut TcpStream,
) -> Result<(T, usize), CliError> {
    let mut channel = [0_u8; 1];
    stream
        .read_exact(&mut channel)
        .map_err(|error| CliError(format!("read frame channel failed: {error}")))?;
    let mut len_bytes = [0_u8; 8];
    stream
        .read_exact(&mut len_bytes)
        .map_err(|error| CliError(format!("read frame length failed: {error}")))?;
    let len = u64::from_le_bytes(len_bytes) as usize;
    if len > 1024 * 1024 * 1024 {
        return Err(CliError(format!("network frame too large: {len} bytes")));
    }
    let mut payload = vec![0_u8; len];
    stream
        .read_exact(&mut payload)
        .map_err(|error| CliError(format!("read frame payload failed: {error}")))?;
    let value = bincode::deserialize(&payload)
        .map_err(|error| CliError(format!("deserialize failed: {error}")))?;
    Ok((value, channel.len() + len_bytes.len() + payload.len()))
}

pub(crate) fn spawn_pcs_network_workers(
    workers: usize,
    cores_per_worker: usize,
) -> Result<Vec<PcsNetworkWorkerClient>, CliError> {
    let exe = std::env::current_exe()
        .map_err(|error| CliError(format!("resolve current executable failed: {error}")))?;
    let mut clients = Vec::with_capacity(workers);
    for _worker_id in 0..workers {
        let addr = reserve_loopback_addr()?;
        let mut child = Command::new(&exe)
            .arg("pcs-network-worker")
            .arg("--addr")
            .arg(&addr)
            .env("RAYON_NUM_THREADS", cores_per_worker.to_string())
            .env("PQ_CORES_PER_WORKER", cores_per_worker.to_string())
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|error| CliError(format!("spawn PCS network worker failed: {error}")))?;
        let stream = connect_with_retry(&addr, Duration::from_secs(10)).map_err(|error| {
            let _ = child.kill();
            let _ = child.wait();
            error
        })?;
        clients.push(PcsNetworkWorkerClient {
            child,
            stream,
            bytes_sent: 0,
            bytes_recv: 0,
        });
    }
    Ok(clients)
}

pub(crate) fn send_worker_request(
    client: &mut PcsNetworkWorkerClient,
    request: &PcsWorkerRequest,
) -> Result<PcsWorkerResponse, CliError> {
    client.bytes_sent += write_frame_binary(&mut client.stream, request)?;
    let (response, bytes_recv) = read_frame_binary(&mut client.stream)?;
    client.bytes_recv += bytes_recv;
    Ok(response)
}

pub(crate) fn send_worker_requests_concurrently(
    clients: &mut [PcsNetworkWorkerClient],
    requests: &[PcsWorkerRequest],
    context: &str,
) -> Result<Vec<PcsWorkerResponse>, CliError> {
    if clients.len() != requests.len() {
        return Err(CliError(format!(
            "{context}: client/request length mismatch: {} clients, {} requests",
            clients.len(),
            requests.len()
        )));
    }
    for (client, request) in clients.iter_mut().zip(requests) {
        client.bytes_sent += write_frame_binary(&mut client.stream, request)
            .map_err(|error| CliError(format!("{context}: worker request send failed: {error}")))?;
    }
    let mut responses = Vec::with_capacity(clients.len());
    for client in clients {
        let (response, recv_bytes) = read_frame_binary(&mut client.stream).map_err(|error| {
            CliError(format!("{context}: worker response read failed: {error}"))
        })?;
        client.bytes_recv += recv_bytes;
        responses.push(response);
    }
    Ok(responses)
}

pub(crate) fn shutdown_pcs_network_workers(clients: &mut [PcsNetworkWorkerClient]) {
    for client in clients {
        let _ = send_worker_request(client, &PcsWorkerRequest::Shutdown);
        match client.child.try_wait() {
            Ok(Some(_)) => {}
            Ok(None) => {
                let _ = client.child.kill();
                let _ = client.child.wait();
            }
            Err(_) => {
                let _ = client.child.kill();
                let _ = client.child.wait();
            }
        }
    }
}

fn reserve_loopback_addr() -> Result<String, CliError> {
    let listener = TcpListener::bind("127.0.0.1:0")
        .map_err(|error| CliError(format!("reserve loopback port failed: {error}")))?;
    let addr = listener
        .local_addr()
        .map_err(|error| CliError(format!("read loopback port failed: {error}")))?;
    Ok(addr.to_string())
}

fn connect_with_retry(addr: &str, timeout: Duration) -> Result<TcpStream, CliError> {
    let start = std::time::Instant::now();
    loop {
        match TcpStream::connect(addr) {
            Ok(stream) => {
                stream
                    .set_nodelay(true)
                    .map_err(|error| CliError(format!("set nodelay failed: {error}")))?;
                return Ok(stream);
            }
            Err(error) if start.elapsed() < timeout => {
                let _ = error;
                thread::sleep(Duration::from_millis(25));
            }
            Err(error) => return Err(CliError(format!("connect PCS worker failed: {error}"))),
        }
    }
}

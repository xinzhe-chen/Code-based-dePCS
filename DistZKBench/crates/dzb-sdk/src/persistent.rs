use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream};
use std::sync::mpsc::{self, Receiver, SyncSender};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use dzb_core::TopologyKind;
use dzb_transport::{
    Frame, FrameKey, UserspaceShaper, mio_read_message, mio_write_frames, run_id_words,
};
use serde::{Deserialize, Serialize};

use crate::{RankId, Result};

const HANDSHAKE_VERSION: u16 = 2;

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct PeerStat {
    pub peer: RankId,
    pub connections_opened: u64,
    pub sent_messages: u64,
    pub sent_payload_bytes: u64,
    pub sent_framed_bytes: u64,
    pub received_messages: u64,
    pub peak_queued_bytes: u64,
    pub connection_errors: u64,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct NetworkStats {
    pub peers: Vec<PeerStat>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct Handshake {
    version: u16,
    run_id: String,
    src_rank: RankId,
    dst_rank: RankId,
}

#[derive(Debug)]
pub struct Incoming {
    pub key: FrameKey,
    pub payload: Vec<u8>,
}

pub struct PersistentPeers {
    rank: RankId,
    writers: BTreeMap<RankId, mio::net::TcpStream>,
    incoming: Receiver<std::result::Result<Incoming, String>>,
    readers: Vec<JoinHandle<()>>,
    stats: BTreeMap<RankId, PeerStat>,
    timeout: Duration,
}

impl PersistentPeers {
    #[allow(clippy::too_many_arguments)]
    pub fn connect(
        run_id: &str,
        rank: RankId,
        world_size: usize,
        master_rank: RankId,
        topology: TopologyKind,
        listen_addrs: &[String],
        timeout: Duration,
    ) -> Result<Self> {
        let listener = TcpListener::bind(&listen_addrs[rank as usize])
            .map_err(|error| format!("rank {rank} bind persistent listener failed: {error}"))?;
        listener
            .set_nonblocking(true)
            .map_err(|error| format!("set listener nonblocking failed: {error}"))?;
        let allowed = (0..world_size as RankId)
            .filter(|peer| {
                *peer != rank
                    && (topology == TopologyKind::FullMesh
                        || rank == master_rank
                        || *peer == master_rank)
            })
            .collect::<Vec<_>>();
        let mut streams = BTreeMap::new();
        for peer in allowed.iter().copied().filter(|peer| rank < *peer) {
            let mut stream = connect_retry(&listen_addrs[peer as usize], timeout)?;
            configure_setup_stream(&stream, timeout)?;
            write_handshake(
                &mut stream,
                &Handshake {
                    version: HANDSHAKE_VERSION,
                    run_id: run_id.to_owned(),
                    src_rank: rank,
                    dst_rank: peer,
                },
            )?;
            let response = read_handshake(&mut stream)?;
            validate_handshake(&response, run_id, peer, rank)?;
            streams.insert(peer, stream);
        }
        let expected_accepts = allowed.iter().filter(|peer| **peer < rank).count();
        let deadline = Instant::now() + timeout;
        while streams.len() < allowed.len()
            && streams.len()
                < expected_accepts + allowed.iter().filter(|peer| rank < **peer).count()
        {
            if Instant::now() >= deadline {
                return Err(format!("rank {rank} persistent accept timed out"));
            }
            match listener.accept() {
                Ok((mut stream, _)) => {
                    configure_setup_stream(&stream, timeout)?;
                    let request = read_handshake(&mut stream)?;
                    validate_handshake(&request, run_id, request.src_rank, rank)?;
                    if !allowed.contains(&request.src_rank) || request.src_rank >= rank {
                        return Err(format!(
                            "rank {rank} rejected unexpected peer {}",
                            request.src_rank
                        ));
                    }
                    write_handshake(
                        &mut stream,
                        &Handshake {
                            version: HANDSHAKE_VERSION,
                            run_id: run_id.to_owned(),
                            src_rank: rank,
                            dst_rank: request.src_rank,
                        },
                    )?;
                    if streams.insert(request.src_rank, stream).is_some() {
                        return Err(format!("rank {rank} received duplicate peer connection"));
                    }
                }
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    std::thread::sleep(Duration::from_millis(5));
                }
                Err(error) => return Err(format!("rank {rank} accept failed: {error}")),
            }
        }
        if streams.len() != allowed.len() {
            return Err(format!(
                "rank {rank} established {} persistent peers, expected {}",
                streams.len(),
                allowed.len()
            ));
        }
        let (sender, incoming) = mpsc::sync_channel(world_size.saturating_mul(4).max(4));
        let mut writers = BTreeMap::new();
        let mut readers = Vec::new();
        let mut stats = BTreeMap::new();
        for (peer, stream) in streams {
            stream
                .set_nonblocking(true)
                .map_err(|error| format!("set peer stream nonblocking failed: {error}"))?;
            let reader = stream
                .try_clone()
                .map_err(|error| format!("clone persistent stream failed: {error}"))?;
            reader
                .set_nonblocking(true)
                .map_err(|error| format!("set reader nonblocking failed: {error}"))?;
            let peer_sender = sender.clone();
            let expected_run = run_id_words(run_id);
            readers.push(std::thread::spawn(move || {
                reader_loop(rank, peer, reader, expected_run, peer_sender)
            }));
            writers.insert(peer, mio::net::TcpStream::from_std(stream));
            stats.insert(
                peer,
                PeerStat {
                    peer,
                    connections_opened: 1,
                    ..PeerStat::default()
                },
            );
        }
        drop(sender);
        Ok(Self {
            rank,
            writers,
            incoming,
            readers,
            stats,
            timeout,
        })
    }

    pub fn send(
        &mut self,
        peer: RankId,
        frames: &[Frame],
        shaper: &UserspaceShaper,
        payload_bytes: usize,
    ) -> Result<()> {
        let stream = self
            .writers
            .get_mut(&peer)
            .ok_or_else(|| format!("rank {} has no persistent connection to {peer}", self.rank))?;
        let framed_bytes = frames
            .iter()
            .map(|frame| frame.payload.len() + dzb_transport::FRAME_HEADER_LEN)
            .sum::<usize>();
        let stat = self
            .stats
            .get_mut(&peer)
            .ok_or_else(|| "missing peer stat".to_owned())?;
        stat.peak_queued_bytes = stat.peak_queued_bytes.max(framed_bytes as u64);
        match mio_write_frames(stream, frames, shaper, self.timeout) {
            Ok(()) => {
                stat.sent_messages += 1;
                stat.sent_payload_bytes += payload_bytes as u64;
                stat.sent_framed_bytes += framed_bytes as u64;
                Ok(())
            }
            Err(error) => {
                stat.connection_errors += 1;
                Err(error)
            }
        }
    }

    pub fn recv(&mut self) -> Result<Incoming> {
        let incoming = self
            .incoming
            .recv_timeout(self.timeout)
            .map_err(|error| format!("persistent receive timed out or disconnected: {error}"))??;
        if let Some(stat) = self.stats.get_mut(&incoming.key.src_rank) {
            stat.received_messages += 1;
        }
        Ok(incoming)
    }

    pub fn stats(&self) -> NetworkStats {
        NetworkStats {
            peers: self.stats.values().cloned().collect(),
        }
    }
}

impl Drop for PersistentPeers {
    fn drop(&mut self) {
        for stream in self.writers.values() {
            let _ = stream.shutdown(Shutdown::Both);
        }
        for reader in self.readers.drain(..) {
            let _ = reader.join();
        }
    }
}

fn reader_loop(
    rank: RankId,
    peer: RankId,
    stream: TcpStream,
    expected_run: (u64, u64),
    sender: SyncSender<std::result::Result<Incoming, String>>,
) {
    let mut stream = mio::net::TcpStream::from_std(stream);
    let mut last_message_id = 0_u64;
    loop {
        match mio_read_message(&mut stream, Duration::from_secs(24 * 60 * 60)) {
            Ok((key, payload, _)) => {
                if (key.run_id_hi, key.run_id_lo) != expected_run
                    || key.src_rank != peer
                    || key.dst_rank != rank
                    || key.message_id <= last_message_id
                {
                    let _ = sender.send(Err(format!(
                        "invalid persistent frame sequence from peer {peer}"
                    )));
                    return;
                }
                last_message_id = key.message_id;
                if sender.send(Ok(Incoming { key, payload })).is_err() {
                    return;
                }
            }
            Err(error) => {
                if !error.contains("connection closed") {
                    let _ = sender.send(Err(format!("peer {peer} read failed: {error}")));
                }
                return;
            }
        }
    }
}

fn connect_retry(addr: &str, timeout: Duration) -> Result<TcpStream> {
    let deadline = Instant::now() + timeout;
    loop {
        match TcpStream::connect(addr) {
            Ok(stream) => return Ok(stream),
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::ConnectionRefused
                        | std::io::ErrorKind::TimedOut
                        | std::io::ErrorKind::AddrNotAvailable
                ) && Instant::now() < deadline =>
            {
                std::thread::sleep(Duration::from_millis(10));
            }
            Err(error) => return Err(format!("persistent connect to {addr} failed: {error}")),
        }
    }
}

fn configure_setup_stream(stream: &TcpStream, timeout: Duration) -> Result<()> {
    stream
        .set_nodelay(true)
        .and_then(|_| stream.set_read_timeout(Some(timeout)))
        .and_then(|_| stream.set_write_timeout(Some(timeout)))
        .map_err(|error| format!("configure persistent stream failed: {error}"))
}

fn write_handshake(stream: &mut TcpStream, handshake: &Handshake) -> Result<()> {
    let bytes = serde_json::to_vec(handshake).map_err(|error| error.to_string())?;
    let len = u32::try_from(bytes.len()).map_err(|_| "handshake too large".to_owned())?;
    stream
        .write_all(&len.to_le_bytes())
        .and_then(|_| stream.write_all(&bytes))
        .and_then(|_| stream.flush())
        .map_err(|error| format!("write handshake failed: {error}"))
}

fn read_handshake(stream: &mut TcpStream) -> Result<Handshake> {
    let mut len = [0_u8; 4];
    stream
        .read_exact(&mut len)
        .map_err(|error| format!("read handshake length failed: {error}"))?;
    let len = u32::from_le_bytes(len) as usize;
    if len > 16 * 1024 {
        return Err("handshake exceeds limit".to_owned());
    }
    let mut bytes = vec![0_u8; len];
    stream
        .read_exact(&mut bytes)
        .map_err(|error| format!("read handshake failed: {error}"))?;
    serde_json::from_slice(&bytes).map_err(|error| format!("parse handshake failed: {error}"))
}

fn validate_handshake(
    handshake: &Handshake,
    run_id: &str,
    expected_src: RankId,
    expected_dst: RankId,
) -> Result<()> {
    if handshake.version != HANDSHAKE_VERSION
        || handshake.run_id != run_id
        || handshake.src_rank != expected_src
        || handshake.dst_rank != expected_dst
    {
        return Err("persistent peer handshake mismatch".to_owned());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn handshake_binds_run_and_rank_direction() {
        let handshake = Handshake {
            version: HANDSHAKE_VERSION,
            run_id: "run-a".to_owned(),
            src_rank: 1,
            dst_rank: 0,
        };
        assert!(validate_handshake(&handshake, "run-a", 1, 0).is_ok());
        assert!(validate_handshake(&handshake, "run-b", 1, 0).is_err());
        assert!(validate_handshake(&handshake, "run-a", 0, 1).is_err());
    }
}

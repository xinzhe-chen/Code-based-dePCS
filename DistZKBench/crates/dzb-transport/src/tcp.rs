use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::net::SocketAddr;
use std::time::{Duration, Instant};

use mio::net::{TcpListener, TcpStream};
use mio::{Events, Interest, Poll, Token};

use crate::frame::{FRAME_HEADER_LEN, Frame, FrameHeader, FrameKey, crc32};
use crate::shaper::UserspaceShaper;

const LISTENER: Token = Token(0);
const STREAM: Token = Token(1);

pub fn write_frames<W: Write>(
    stream: &mut W,
    frames: &[Frame],
    shaper: &UserspaceShaper,
) -> Result<(), String> {
    for frame in frames {
        let delay = shaper.delay_for(frame.payload.len());
        if !delay.is_zero() {
            std::thread::sleep(delay);
        }
        stream
            .write_all(&frame.header.encode())
            .map_err(|error| format!("write DZKB frame header failed: {error}"))?;
        stream
            .write_all(&frame.payload)
            .map_err(|error| format!("write DZKB frame payload failed: {error}"))?;
    }
    stream
        .flush()
        .map_err(|error| format!("flush DZKB stream failed: {error}"))
}

pub fn read_frame<R: Read>(stream: &mut R) -> Result<Frame, String> {
    let mut header_bytes = [0_u8; FRAME_HEADER_LEN];
    stream
        .read_exact(&mut header_bytes)
        .map_err(|error| format!("read DZKB frame header failed: {error}"))?;
    let header = FrameHeader::decode(&header_bytes)?;
    let payload_len = usize::try_from(header.payload_len)
        .map_err(|_| "DZKB payload length does not fit usize".to_owned())?;
    let mut payload = vec![0_u8; payload_len];
    stream
        .read_exact(&mut payload)
        .map_err(|error| format!("read DZKB frame payload failed: {error}"))?;
    if crc32(&payload) != header.payload_crc32 {
        return Err("DZKB payload CRC32 mismatch".to_owned());
    }
    Ok(Frame { header, payload })
}

pub fn read_message<R: Read>(stream: &mut R) -> Result<(FrameKey, Vec<u8>, usize), String> {
    let first = read_frame(stream)?;
    let key = FrameKey {
        run_id_hi: first.header.run_id_hi,
        run_id_lo: first.header.run_id_lo,
        src_rank: first.header.src_rank,
        dst_rank: first.header.dst_rank,
        tag: first.header.tag,
        message_id: first.header.message_id,
    };
    let frame_count = usize::try_from(first.header.frame_count)
        .map_err(|_| "DZKB frame count does not fit usize".to_owned())?;
    let mut frames = BTreeMap::new();
    frames.insert(first.header.frame_index, first.payload);
    while frames.len() < frame_count {
        let frame = read_frame(stream)?;
        let next_key = FrameKey {
            run_id_hi: frame.header.run_id_hi,
            run_id_lo: frame.header.run_id_lo,
            src_rank: frame.header.src_rank,
            dst_rank: frame.header.dst_rank,
            tag: frame.header.tag,
            message_id: frame.header.message_id,
        };
        if next_key != key {
            return Err(
                "interleaved DZKB messages on one stream are unsupported in MVP-3 TCP helper"
                    .to_owned(),
            );
        }
        if frame.header.run_id_hi != first.header.run_id_hi
            || frame.header.run_id_lo != first.header.run_id_lo
            || frame.header.frame_count != first.header.frame_count
        {
            return Err("DZKB frame run id or count mismatch".to_owned());
        }
        frames.insert(frame.header.frame_index, frame.payload);
    }
    let mut payload = Vec::new();
    for index in 0..frame_count {
        let Some(part) = frames.remove(&(index as u32)) else {
            return Err(format!("missing DZKB frame index {index}"));
        };
        payload.extend_from_slice(&part);
    }
    Ok((key, payload, frame_count))
}

pub fn mio_bind(addr: &str) -> Result<TcpListener, String> {
    let addr = parse_addr(addr)?;
    TcpListener::bind(addr).map_err(|error| format!("mio bind {addr} failed: {error}"))
}

pub fn mio_connect(addr: &str, timeout: Duration) -> Result<TcpStream, String> {
    let addr = parse_addr(addr)?;
    let started = Instant::now();
    let mut last_error = None;
    while started.elapsed() < timeout {
        match TcpStream::connect(addr) {
            Ok(mut stream) => {
                let mut poll =
                    Poll::new().map_err(|error| format!("create poll failed: {error}"))?;
                poll.registry()
                    .register(&mut stream, STREAM, Interest::WRITABLE)
                    .map_err(|error| format!("register connect stream failed: {error}"))?;
                let mut events = Events::with_capacity(8);
                let remaining = timeout.saturating_sub(started.elapsed());
                poll.poll(&mut events, Some(remaining))
                    .map_err(|error| format!("poll connect failed: {error}"))?;
                if events
                    .iter()
                    .any(|event| event.token() == STREAM && event.is_writable())
                {
                    if let Some(error) = stream
                        .take_error()
                        .map_err(|error| format!("read connect SO_ERROR failed: {error}"))?
                    {
                        last_error = Some(error.to_string());
                        let _ = poll.registry().deregister(&mut stream);
                        std::thread::sleep(Duration::from_millis(20));
                        continue;
                    }
                    poll.registry()
                        .deregister(&mut stream)
                        .map_err(|error| format!("deregister connect stream failed: {error}"))?;
                    return Ok(stream);
                }
            }
            Err(error) => {
                last_error = Some(error.to_string());
                std::thread::sleep(Duration::from_millis(20));
            }
        }
    }
    Err(format!(
        "mio connect to {addr} timed out: {}",
        last_error.unwrap_or_else(|| "no readiness event".to_owned())
    ))
}

pub fn mio_write_frames(
    stream: &mut TcpStream,
    frames: &[Frame],
    shaper: &UserspaceShaper,
    timeout: Duration,
) -> Result<(), String> {
    let mut poll = Poll::new().map_err(|error| format!("create poll failed: {error}"))?;
    poll.registry()
        .register(stream, STREAM, Interest::WRITABLE)
        .map_err(|error| format!("register writable stream failed: {error}"))?;
    let result = (|| {
        for frame in frames {
            let delay = shaper.delay_for(frame.payload.len());
            if !delay.is_zero() {
                std::thread::sleep(delay);
            }
            write_all_mio(stream, &frame.header.encode(), &mut poll, timeout)?;
            write_all_mio(stream, &frame.payload, &mut poll, timeout)?;
        }
        Ok::<_, String>(())
    })();
    let deregister = poll
        .registry()
        .deregister(stream)
        .map_err(|error| format!("deregister writable stream failed: {error}"));
    result.and(deregister)
}

pub fn mio_read_message(
    stream: &mut TcpStream,
    timeout: Duration,
) -> Result<(FrameKey, Vec<u8>, usize), String> {
    let mut poll = Poll::new().map_err(|error| format!("create poll failed: {error}"))?;
    poll.registry()
        .register(stream, STREAM, Interest::READABLE)
        .map_err(|error| format!("register readable stream failed: {error}"))?;
    let result = (|| {
        let first = read_frame_mio(stream, &mut poll, timeout)?;
        let key = FrameKey {
            run_id_hi: first.header.run_id_hi,
            run_id_lo: first.header.run_id_lo,
            src_rank: first.header.src_rank,
            dst_rank: first.header.dst_rank,
            tag: first.header.tag,
            message_id: first.header.message_id,
        };
        let frame_count = usize::try_from(first.header.frame_count)
            .map_err(|_| "DZKB frame count does not fit usize".to_owned())?;
        let mut frames = BTreeMap::new();
        frames.insert(first.header.frame_index, first.payload);
        while frames.len() < frame_count {
            let frame = read_frame_mio(stream, &mut poll, timeout)?;
            let next_key = FrameKey {
                run_id_hi: frame.header.run_id_hi,
                run_id_lo: frame.header.run_id_lo,
                src_rank: frame.header.src_rank,
                dst_rank: frame.header.dst_rank,
                tag: frame.header.tag,
                message_id: frame.header.message_id,
            };
            if next_key != key {
                return Err(
                    "interleaved DZKB messages on one stream are unsupported in MVP-3 TCP helper"
                        .to_owned(),
                );
            }
            frames.insert(frame.header.frame_index, frame.payload);
        }
        let mut payload = Vec::new();
        for index in 0..frame_count {
            let Some(part) = frames.remove(&(index as u32)) else {
                return Err(format!("missing DZKB frame index {index}"));
            };
            payload.extend_from_slice(&part);
        }
        Ok((key, payload, frame_count))
    })();
    let deregister = poll
        .registry()
        .deregister(stream)
        .map_err(|error| format!("deregister readable stream failed: {error}"));
    match (result, deregister) {
        (Ok(value), Ok(())) => Ok(value),
        (Err(error), _) | (_, Err(error)) => Err(error),
    }
}

pub fn mio_accept(listener: &mut TcpListener, timeout: Duration) -> Result<TcpStream, String> {
    let mut poll = Poll::new().map_err(|error| format!("create poll failed: {error}"))?;
    poll.registry()
        .register(listener, LISTENER, Interest::READABLE)
        .map_err(|error| format!("register listener failed: {error}"))?;
    let result = (|| {
        let mut events = Events::with_capacity(8);
        let started = Instant::now();
        loop {
            let remaining = timeout.saturating_sub(started.elapsed());
            if remaining.is_zero() {
                return Err("mio accept timed out".to_owned());
            }
            poll.poll(&mut events, Some(remaining))
                .map_err(|error| format!("poll accept failed: {error}"))?;
            for event in &events {
                if event.token() == LISTENER && event.is_readable() {
                    match listener.accept() {
                        Ok((stream, _)) => return Ok(stream),
                        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {}
                        Err(error) => return Err(format!("mio accept failed: {error}")),
                    }
                }
            }
        }
    })();
    let deregister = poll
        .registry()
        .deregister(listener)
        .map_err(|error| format!("deregister listener failed: {error}"));
    match (result, deregister) {
        (Ok(stream), Ok(())) => Ok(stream),
        (Err(error), _) | (_, Err(error)) => Err(error),
    }
}

pub fn set_nodelay(stream: &TcpStream, enabled: bool) -> Result<(), String> {
    stream
        .set_nodelay(enabled)
        .map_err(|error| format!("set TCP_NODELAY failed: {error}"))
}

fn parse_addr(addr: &str) -> Result<SocketAddr, String> {
    addr.parse::<SocketAddr>()
        .map_err(|error| format!("invalid socket address '{addr}': {error}"))
}

fn read_frame_mio(
    stream: &mut TcpStream,
    poll: &mut Poll,
    timeout: Duration,
) -> Result<Frame, String> {
    let mut header_bytes = [0_u8; FRAME_HEADER_LEN];
    read_exact_mio(stream, &mut header_bytes, poll, timeout)?;
    let header = FrameHeader::decode(&header_bytes)?;
    let payload_len = usize::try_from(header.payload_len)
        .map_err(|_| "DZKB payload length does not fit usize".to_owned())?;
    let mut payload = vec![0_u8; payload_len];
    read_exact_mio(stream, &mut payload, poll, timeout)?;
    if crc32(&payload) != header.payload_crc32 {
        return Err("DZKB payload CRC32 mismatch".to_owned());
    }
    Ok(Frame { header, payload })
}

fn read_exact_mio(
    stream: &mut TcpStream,
    buf: &mut [u8],
    poll: &mut Poll,
    timeout: Duration,
) -> Result<(), String> {
    let started = Instant::now();
    let mut offset = 0;
    while offset < buf.len() {
        match stream.read(&mut buf[offset..]) {
            Ok(0) => return Err("TCP stream closed while reading".to_owned()),
            Ok(n) => offset += n,
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                wait_for(stream, poll, Interest::READABLE, started, timeout)?
            }
            Err(error) => return Err(format!("mio read failed: {error}")),
        }
    }
    Ok(())
}

fn write_all_mio(
    stream: &mut TcpStream,
    buf: &[u8],
    poll: &mut Poll,
    timeout: Duration,
) -> Result<(), String> {
    let started = Instant::now();
    let mut offset = 0;
    while offset < buf.len() {
        match stream.write(&buf[offset..]) {
            Ok(0) => return Err("TCP stream closed while writing".to_owned()),
            Ok(n) => offset += n,
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                wait_for(stream, poll, Interest::WRITABLE, started, timeout)?
            }
            Err(error) => return Err(format!("mio write failed: {error}")),
        }
    }
    Ok(())
}

fn wait_for(
    _stream: &mut TcpStream,
    poll: &mut Poll,
    _interest: Interest,
    started: Instant,
    timeout: Duration,
) -> Result<(), String> {
    let remaining = timeout.saturating_sub(started.elapsed());
    if remaining.is_zero() {
        return Err("mio stream wait timed out".to_owned());
    }
    let mut events = Events::with_capacity(8);
    poll.poll(&mut events, Some(remaining))
        .map_err(|error| format!("poll stream failed: {error}"))?;
    if events.iter().any(|event| event.token() == STREAM) {
        Ok(())
    } else {
        Err("mio stream did not become ready".to_owned())
    }
}

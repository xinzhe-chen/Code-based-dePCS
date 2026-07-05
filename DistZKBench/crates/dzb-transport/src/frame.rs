use crate::topology::RankId;

pub const FRAME_MAGIC: u32 = 0x445A4B42;
pub const FRAME_HEADER_LEN: usize = 72;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FrameHeader {
    pub magic: u32,
    pub version: u16,
    pub header_len: u16,
    pub run_id_hi: u64,
    pub run_id_lo: u64,
    pub phase_id: u32,
    pub src_rank: RankId,
    pub dst_rank: RankId,
    pub tag: u32,
    pub message_id: u64,
    pub frame_index: u32,
    pub frame_count: u32,
    pub flags: u32,
    pub payload_len: u64,
    pub payload_crc32: u32,
    pub reserved: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub struct FrameKey {
    pub src_rank: RankId,
    pub dst_rank: RankId,
    pub tag: u32,
    pub message_id: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Frame {
    pub header: FrameHeader,
    pub payload: Vec<u8>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FrameHeaderArgs {
    pub phase_id: u32,
    pub src_rank: RankId,
    pub dst_rank: RankId,
    pub tag: u32,
    pub message_id: u64,
    pub frame_index: u32,
    pub frame_count: u32,
    pub payload_len: u64,
}

impl FrameHeader {
    pub fn new(args: FrameHeaderArgs) -> Self {
        Self {
            magic: FRAME_MAGIC,
            version: 1,
            header_len: FRAME_HEADER_LEN as u16,
            run_id_hi: 0,
            run_id_lo: 0,
            phase_id: args.phase_id,
            src_rank: args.src_rank,
            dst_rank: args.dst_rank,
            tag: args.tag,
            message_id: args.message_id,
            frame_index: args.frame_index,
            frame_count: args.frame_count,
            flags: 0,
            payload_len: args.payload_len,
            payload_crc32: 0,
            reserved: 0,
        }
    }

    pub fn encode(self) -> [u8; FRAME_HEADER_LEN] {
        let mut out = [0_u8; FRAME_HEADER_LEN];
        write_u32(&mut out, 0, self.magic);
        write_u16(&mut out, 4, self.version);
        write_u16(&mut out, 6, self.header_len);
        write_u64(&mut out, 8, self.run_id_hi);
        write_u64(&mut out, 16, self.run_id_lo);
        write_u32(&mut out, 24, self.phase_id);
        write_u32(&mut out, 28, self.src_rank);
        write_u32(&mut out, 32, self.dst_rank);
        write_u32(&mut out, 36, self.tag);
        write_u64(&mut out, 40, self.message_id);
        write_u32(&mut out, 48, self.frame_index);
        write_u32(&mut out, 52, self.frame_count);
        write_u32(&mut out, 56, self.flags);
        write_u64(&mut out, 60, self.payload_len);
        write_u32(&mut out, 68, self.payload_crc32);
        out
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() < FRAME_HEADER_LEN {
            return Err("frame header too short".to_owned());
        }
        let header = Self {
            magic: read_u32(bytes, 0),
            version: read_u16(bytes, 4),
            header_len: read_u16(bytes, 6),
            run_id_hi: read_u64(bytes, 8),
            run_id_lo: read_u64(bytes, 16),
            phase_id: read_u32(bytes, 24),
            src_rank: read_u32(bytes, 28),
            dst_rank: read_u32(bytes, 32),
            tag: read_u32(bytes, 36),
            message_id: read_u64(bytes, 40),
            frame_index: read_u32(bytes, 48),
            frame_count: read_u32(bytes, 52),
            flags: read_u32(bytes, 56),
            payload_len: read_u64(bytes, 60),
            payload_crc32: read_u32(bytes, 68),
            reserved: 0,
        };
        if header.magic != FRAME_MAGIC {
            return Err("bad DZKB frame magic".to_owned());
        }
        Ok(header)
    }
}

pub fn encode_frames(
    phase_id: u32,
    src_rank: RankId,
    dst_rank: RankId,
    tag: u32,
    message_id: u64,
    payload: &[u8],
    max_payload: usize,
) -> Vec<Frame> {
    let chunk = max_payload.max(1);
    let frame_count = payload.len().div_ceil(chunk).max(1);
    (0..frame_count)
        .map(|index| {
            let start = index * chunk;
            let end = payload.len().min(start + chunk);
            let bytes = payload.get(start..end).unwrap_or(&[]);
            Frame {
                header: FrameHeader::new(FrameHeaderArgs {
                    phase_id,
                    src_rank,
                    dst_rank,
                    tag,
                    message_id,
                    frame_index: index as u32,
                    frame_count: frame_count as u32,
                    payload_len: bytes.len() as u64,
                }),
                payload: bytes.to_vec(),
            }
        })
        .collect()
}

fn write_u16(out: &mut [u8], offset: usize, value: u16) {
    out[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
}

fn write_u32(out: &mut [u8], offset: usize, value: u32) {
    out[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

fn write_u64(out: &mut [u8], offset: usize, value: u64) {
    out[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}

fn read_u16(bytes: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes([bytes[offset], bytes[offset + 1]])
}

fn read_u32(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes([
        bytes[offset],
        bytes[offset + 1],
        bytes[offset + 2],
        bytes[offset + 3],
    ])
}

fn read_u64(bytes: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes([
        bytes[offset],
        bytes[offset + 1],
        bytes[offset + 2],
        bytes[offset + 3],
        bytes[offset + 4],
        bytes[offset + 5],
        bytes[offset + 6],
        bytes[offset + 7],
    ])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn header_round_trips() {
        let header = FrameHeader::new(FrameHeaderArgs {
            phase_id: 3,
            src_rank: 1,
            dst_rank: 2,
            tag: 9,
            message_id: 10,
            frame_index: 0,
            frame_count: 1,
            payload_len: 42,
        });
        assert_eq!(FrameHeader::decode(&header.encode()), Ok(header));
    }

    #[test]
    fn chunks_payload() {
        let frames = encode_frames(1, 0, 1, 7, 8, &[1, 2, 3, 4, 5], 2);
        assert_eq!(frames.len(), 3);
        assert_eq!(frames[2].payload, vec![5]);
    }
}

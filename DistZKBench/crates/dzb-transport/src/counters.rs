use serde::{Deserialize, Serialize};

use crate::frame::FRAME_HEADER_LEN;
use crate::topology::RankId;

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct EdgeCounter {
    pub src: RankId,
    pub dst: RankId,
    pub serialized_payload_bytes: u64,
    pub framed_bytes: u64,
    pub messages: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct CommunicationCounters {
    pub world_size: usize,
    pub edges: Vec<EdgeCounter>,
}

impl CommunicationCounters {
    pub fn new(world_size: usize) -> Self {
        let mut edges = Vec::new();
        for src in 0..world_size {
            for dst in 0..world_size {
                if src != dst {
                    edges.push(EdgeCounter {
                        src: src as RankId,
                        dst: dst as RankId,
                        ..EdgeCounter::default()
                    });
                }
            }
        }
        Self { world_size, edges }
    }

    pub fn record_message(
        &mut self,
        src: RankId,
        dst: RankId,
        payload_bytes: usize,
        frames: usize,
    ) {
        if let Some(edge) = self
            .edges
            .iter_mut()
            .find(|edge| edge.src == src && edge.dst == dst)
        {
            edge.serialized_payload_bytes += payload_bytes as u64;
            edge.framed_bytes += payload_bytes as u64 + (frames * FRAME_HEADER_LEN) as u64;
            edge.messages += 1;
        }
    }

    pub fn merge_from(&mut self, other: &Self) {
        for incoming in &other.edges {
            if let Some(edge) = self
                .edges
                .iter_mut()
                .find(|edge| edge.src == incoming.src && edge.dst == incoming.dst)
            {
                edge.serialized_payload_bytes += incoming.serialized_payload_bytes;
                edge.framed_bytes += incoming.framed_bytes;
                edge.messages += incoming.messages;
            }
        }
    }

    pub fn total_payload_bytes(&self) -> u64 {
        self.edges
            .iter()
            .map(|edge| edge.serialized_payload_bytes)
            .sum()
    }

    pub fn total_framed_bytes(&self) -> u64 {
        self.edges.iter().map(|edge| edge.framed_bytes).sum()
    }

    pub fn message_count(&self) -> u64 {
        self.edges.iter().map(|edge| edge.messages).sum()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn counts_edge_bytes() {
        let mut counters = CommunicationCounters::new(2);
        counters.record_message(0, 1, 10, 2);
        assert_eq!(counters.total_payload_bytes(), 10);
        assert_eq!(
            counters.total_framed_bytes(),
            10 + 2 * FRAME_HEADER_LEN as u64
        );
    }
}

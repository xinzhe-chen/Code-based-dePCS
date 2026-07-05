use dzb_core::TopologyKind;

pub type RankId = u32;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Topology {
    pub kind: TopologyKind,
    pub world_size: usize,
    pub master_rank: RankId,
    pub enforce: bool,
    pub routed_star: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TopologyError {
    pub src: RankId,
    pub dst: RankId,
    pub message: String,
}

impl std::fmt::Display for TopologyError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{}: {} -> {}", self.message, self.src, self.dst)
    }
}

impl std::error::Error for TopologyError {}

impl Topology {
    pub fn check_send(&self, src: RankId, dst: RankId) -> Result<(), TopologyError> {
        if src as usize >= self.world_size || dst as usize >= self.world_size {
            return Err(TopologyError {
                src,
                dst,
                message: "rank out of range".to_owned(),
            });
        }
        if !self.enforce || self.kind == TopologyKind::FullMesh {
            return Ok(());
        }
        if src == self.master_rank || dst == self.master_rank {
            return Ok(());
        }
        if self.routed_star {
            return Err(TopologyError {
                src,
                dst,
                message: "direct worker-to-worker send must route via master".to_owned(),
            });
        }
        Err(TopologyError {
            src,
            dst,
            message: "star topology forbids worker-to-worker send".to_owned(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn star_rejects_worker_to_worker() {
        let topology = Topology {
            kind: TopologyKind::Star,
            world_size: 3,
            master_rank: 0,
            enforce: true,
            routed_star: false,
        };
        assert!(topology.check_send(1, 2).is_err());
        assert!(topology.check_send(1, 0).is_ok());
    }
}

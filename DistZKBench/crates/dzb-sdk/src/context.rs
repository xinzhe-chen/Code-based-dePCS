use std::time::Instant;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use dzb_transport::CommunicationCounters;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PhaseEvent {
    #[serde(default)]
    pub rank: usize,
    #[serde(default)]
    pub phase_id: u32,
    #[serde(default)]
    pub parent_phase_id: Option<u32>,
    #[serde(default = "default_phase_category")]
    pub category: String,
    #[serde(default)]
    pub iteration: usize,
    #[serde(default)]
    pub start_ns: u64,
    #[serde(default)]
    pub duration_ns: u64,
    pub name: String,
    pub start_ms: f64,
    pub duration_ms: f64,
}

fn default_phase_category() -> String {
    "protocol".to_owned()
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ProofArtifact {
    pub bytes: Vec<u8>,
    pub sha256: String,
}

#[derive(Clone, Debug)]
pub struct ProverCtx {
    started: Instant,
    phase_stack: Vec<(String, Instant)>,
    pub phases: Vec<PhaseEvent>,
    pub proof: Option<ProofArtifact>,
    pub communication: CommunicationCounters,
}

impl ProverCtx {
    pub fn new(world_size: usize) -> Self {
        Self {
            started: Instant::now(),
            phase_stack: Vec::new(),
            phases: Vec::new(),
            proof: None,
            communication: CommunicationCounters::new(world_size),
        }
    }

    pub fn phase<T, E>(
        &mut self,
        name: impl Into<String>,
        f: impl FnOnce(&mut Self) -> Result<T, E>,
    ) -> Result<T, E> {
        let name = name.into();
        let start = Instant::now();
        let start_ms = start.duration_since(self.started).as_secs_f64() * 1000.0;
        self.phase_stack.push((name.clone(), start));
        let result = f(self);
        let duration_ms = start.elapsed().as_secs_f64() * 1000.0;
        let _ = self.phase_stack.pop();
        self.phases.push(PhaseEvent {
            rank: 0,
            phase_id: self.phases.len() as u32 + 1,
            parent_phase_id: None,
            category: default_phase_category(),
            iteration: 0,
            start_ns: start.duration_since(self.started).as_nanos() as u64,
            duration_ns: start.elapsed().as_nanos() as u64,
            name,
            start_ms,
            duration_ms,
        });
        result
    }

    pub fn publish_proof(&mut self, bytes: Vec<u8>) -> ProofArtifact {
        let sha256 = sha256_hex(&bytes);
        let proof = ProofArtifact { bytes, sha256 };
        self.proof = Some(proof.clone());
        proof
    }
}

pub fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut output = String::with_capacity(digest.len() * 2);
    for byte in digest {
        output.push_str(&format!("{byte:02x}"));
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn proof_hash_is_sha256() {
        assert_eq!(
            sha256_hex(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn records_phase() {
        let mut ctx = ProverCtx::new(2);
        let result = ctx.phase("prove.test", |_| Ok::<_, ()>(7));
        assert_eq!(result, Ok(7));
        assert_eq!(ctx.phases.len(), 1);
    }
}

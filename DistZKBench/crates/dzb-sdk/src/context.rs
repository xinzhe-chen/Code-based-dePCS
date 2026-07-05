use std::time::Instant;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use dzb_transport::CommunicationCounters;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PhaseEvent {
    pub name: String,
    pub start_ms: f64,
    pub duration_ms: f64,
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

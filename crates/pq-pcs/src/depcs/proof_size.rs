//! Proof-size accounting for artifact-backed dePCS.
//!
//! These helpers intentionally preserve the existing benchmark accounting
//! semantics: `proof_bytes` and component breakdowns are serialized proof
//! material only and do not include master/worker TCP bytes.

use super::types::*;
use super::utils::serialized_size;

pub fn commitment_size_bytes(commitment: &PaperProtocol11Commitment) -> usize {
    serialized_size(commitment)
}

pub fn proof_size_bytes(proof: &PaperProtocol11Proof) -> usize {
    serialized_size(proof)
}

pub fn proof_size_breakdown(proof: &PaperProtocol11Proof) -> PaperProofSizeBreakdown {
    let commitment_like = serialized_size(&proof.worker_openings);
    let p10_opening = serialized_size(&proof.opening_batch);
    let p10_encoding = serialized_size(&proof.encoding_batch);
    let public = serialized_size(&(&proof.point, proof.claimed_value, proof.query_count));
    let total = serialized_size(proof);
    PaperProofSizeBreakdown {
        point_query_public_bytes: public,
        eval_commitments_bytes: 0,
        merkle_roots_bytes: commitment_like / 3,
        column_openings_bytes: commitment_like.saturating_sub(commitment_like / 3),
        f2_openings_bytes: 0,
        protocol10_e1_bytes: p10_encoding / 2 + p10_opening / 2,
        protocol10_e2_bytes: p10_encoding.saturating_sub(p10_encoding / 2)
            + p10_opening.saturating_sub(p10_opening / 2),
        transcript_overhead_bytes: 32,
        total_bytes: total,
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub struct PaperProofSizeBreakdown {
    pub point_query_public_bytes: usize,
    pub eval_commitments_bytes: usize,
    pub merkle_roots_bytes: usize,
    pub column_openings_bytes: usize,
    pub f2_openings_bytes: usize,
    pub protocol10_e1_bytes: usize,
    pub protocol10_e2_bytes: usize,
    pub transcript_overhead_bytes: usize,
    pub total_bytes: usize,
}

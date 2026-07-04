//! Compact proof-size accounting for artifact-backed dePCS.
//!
//! The reported sizes are verifier-facing canonical bytes, not Rust serde or
//! bincode object sizes. This keeps the benchmark aligned with the compact v2
//! transcript used by Protocol 7/10/11.

use super::compact_codec;
use super::types::*;

const HASH_BYTES: usize = 32;
const FIELD_BYTES: usize = compact_codec::FIELD_BYTES;
const USIZE_BYTES: usize = 8;

pub fn commitment_size_bytes(commitment: &PaperProtocol11Commitment) -> usize {
    // Public metadata, root, worker count, then compact worker leaves.
    let public = 3 * USIZE_BYTES // config
        + 7 * USIZE_BYTES // original_len, nv, workers, worker_bits, shard_len, shard_nv, artifact_nv
        + HASH_BYTES; // root
    public
        + USIZE_BYTES
        + commitment
            .workers_commitments
            .iter()
            .map(compact_codec::worker_commitment_size)
            .sum::<usize>()
}

pub fn proof_size_bytes(proof: &PaperProtocol11Proof) -> usize {
    proof_size_breakdown(proof).total_bytes
}

pub fn proof_size_breakdown(proof: &PaperProtocol11Proof) -> PaperProofSizeBreakdown {
    let public = 3 * USIZE_BYTES // config
        + USIZE_BYTES // query_count
        + FIELD_BYTES // claimed_value
        + USIZE_BYTES
        + proof.point.len() * FIELD_BYTES;

    let mut merkle_roots = 0usize;
    let mut column_openings = 0usize;
    let mut eval_commitments = 0usize;
    let mut worker_statement = USIZE_BYTES; // worker opening vector length
    for opening in &proof.worker_openings {
        worker_statement += worker_opening_statement_size(opening);
        match &opening.proof {
            PaperPcsOpeningProof::DeepFold(proof) => {
                merkle_roots += proof.merkle_root.len() * HASH_BYTES;
                column_openings += proof
                    .query_result
                    .iter()
                    .map(|query| query.proof_bytes.len() + query.proof_values.len() * FIELD_BYTES)
                    .sum::<usize>();
                eval_commitments += deepfold_eval_size(proof);
            }
        }
    }

    let p10_e1 = relation_proof_size(&proof.encoding_batch.e1);
    let p10_e2 = relation_proof_size(&proof.encoding_batch.e2);
    let transcript = HASH_BYTES // transcript_state
        + HASH_BYTES // encoding_batch.opening_batch_digest
        + opening_batch_size(&proof.opening_batch)
        + USIZE_BYTES
        + proof.encoding_batch.relation_challenges.len() * FIELD_BYTES;

    let total = public
        + worker_statement
        + merkle_roots
        + column_openings
        + eval_commitments
        + p10_e1
        + p10_e2
        + transcript;

    PaperProofSizeBreakdown {
        point_query_public_bytes: public,
        eval_commitments_bytes: eval_commitments,
        merkle_roots_bytes: merkle_roots,
        column_openings_bytes: column_openings + worker_statement,
        f2_openings_bytes: 0,
        protocol10_e1_bytes: p10_e1,
        protocol10_e2_bytes: p10_e2,
        transcript_overhead_bytes: transcript,
        total_bytes: total,
    }
}

fn worker_opening_statement_size(opening: &PaperProtocol11WorkerOpening) -> usize {
    USIZE_BYTES // worker_id
        + FIELD_BYTES // worker_weight
        + USIZE_BYTES
        + opening.shard_point.len() * FIELD_BYTES
        + FIELD_BYTES // value
}

fn deepfold_eval_size(proof: &paper_deepfold::Proof<PaperField>) -> usize {
    let deep_evals = USIZE_BYTES
        + proof
            .deep_evals
            .iter()
            .map(|(_, else_evals)| FIELD_BYTES + USIZE_BYTES + else_evals.len() * FIELD_BYTES)
            .sum::<usize>();
    let shuffle = USIZE_BYTES + proof.shuffle_evals.len() * FIELD_BYTES;
    let final_poly = USIZE_BYTES + proof.final_poly.coefficients().len() * FIELD_BYTES;
    deep_evals
        + shuffle
        + FIELD_BYTES // evaluation
        + FIELD_BYTES // final_value
        + final_poly
}

fn relation_proof_size(_proof: &PaperProtocol10RelationProof) -> usize {
    USIZE_BYTES // relation_index
        + 1 // relation_kind
        + FIELD_BYTES // challenge
        + HASH_BYTES // opening_batch_digest
        + USIZE_BYTES // claim_count
        + USIZE_BYTES // reduction_point_len
        + FIELD_BYTES // relation_value
}

fn opening_batch_size(_batch: &PaperProtocol10OpeningBatchProof) -> usize {
    USIZE_BYTES + USIZE_BYTES + FIELD_BYTES + HASH_BYTES
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

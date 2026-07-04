//! Compact canonical encoding for artifact-backed dePCS transcripts and size
//! accounting. This is not a general deserializer; it is the single source of
//! truth for bytes that are verifier-facing, transcript-bound, or reported as
//! proof/commitment size.

use paper_util::{algebra::field::MyField, random_oracle::RandomOracle};

use crate::hash::sha256;

use super::backend::PaperPcsBackend;
use super::types::*;

pub(crate) const FIELD_BYTES: usize = 16;
const HASH_BYTES: usize = 32;
const USIZE_BYTES: usize = 8;

pub(crate) fn digest(bytes: &[u8]) -> [u8; 32] {
    sha256(bytes)
}

pub(crate) fn digest_with_label(label: &[u8], body: &[u8]) -> [u8; 32] {
    let mut bytes = Vec::with_capacity(label.len() + body.len() + USIZE_BYTES);
    push_bytes(&mut bytes, label);
    bytes.extend_from_slice(body);
    digest(&bytes)
}

pub(crate) fn field_challenge(label: &[u8], body: &[u8]) -> PaperField {
    PaperField::from_hash(digest_with_label(label, body))
}

pub(crate) fn push_u8(out: &mut Vec<u8>, value: u8) {
    out.push(value);
}

pub(crate) fn push_usize(out: &mut Vec<u8>, value: usize) {
    out.extend_from_slice(&(value as u64).to_le_bytes());
}

pub(crate) fn push_hash(out: &mut Vec<u8>, value: &[u8; 32]) {
    out.extend_from_slice(value);
}

pub(crate) fn push_bytes(out: &mut Vec<u8>, value: &[u8]) {
    push_usize(out, value.len());
    out.extend_from_slice(value);
}

pub(crate) fn push_field(out: &mut Vec<u8>, value: PaperField) {
    out.extend_from_slice(&value.to_full_bytes());
}

pub(crate) fn push_field_slice(out: &mut Vec<u8>, values: &[PaperField]) {
    push_usize(out, values.len());
    for value in values {
        push_field(out, *value);
    }
}

pub(crate) fn push_config(out: &mut Vec<u8>, config: PaperDepcsConfig) {
    push_u8(
        out,
        match config.backend {
            PaperPcsBackend::DeepFold => 1,
        },
    );
    push_usize(out, config.rate_inv);
    push_usize(out, config.security_bits);
}

pub(crate) fn push_relation_kind(out: &mut Vec<u8>, kind: PaperProtocol10RelationKind) {
    push_u8(
        out,
        match kind {
            PaperProtocol10RelationKind::E1 => 1,
            PaperProtocol10RelationKind::E2 => 2,
        },
    );
}

pub(crate) fn push_claim_kind(out: &mut Vec<u8>, kind: PaperProtocol10OpeningClaimKind) {
    push_u8(
        out,
        match kind {
            PaperProtocol10OpeningClaimKind::ShardValue => 1,
            PaperProtocol10OpeningClaimKind::WeightedShardValue => 2,
            PaperProtocol10OpeningClaimKind::HuAtR => 3,
            PaperProtocol10OpeningClaimKind::EAtR => 4,
            PaperProtocol10OpeningClaimKind::FPadAtSystematic => 5,
            PaperProtocol10OpeningClaimKind::EAtSystematic => 6,
        },
    );
}

pub(crate) fn push_pcs_commitment(out: &mut Vec<u8>, commitment: &PaperPcsCommitment) {
    match commitment {
        PaperPcsCommitment::DeepFold(commitment) => {
            push_u8(out, 1);
            out.extend_from_slice(&commitment.merkle_root);
            push_field(out, commitment.deep);
        }
    }
}

pub(crate) fn pcs_commitment_size(commitment: &PaperPcsCommitment) -> usize {
    match commitment {
        PaperPcsCommitment::DeepFold(_) => 1 + HASH_BYTES + FIELD_BYTES,
    }
}

pub(crate) fn push_worker_commitment_leaf(
    out: &mut Vec<u8>,
    commitment: &PaperProtocol11WorkerCommitment,
) {
    push_usize(out, commitment.worker_id);
    push_usize(out, commitment.row_range.0);
    push_usize(out, commitment.row_range.1);
    push_hash(out, &commitment.oracle_seed);
    push_pcs_commitment(out, &commitment.pcs_commitment);
}

pub(crate) fn worker_commitment_digest(commitment: &PaperProtocol11WorkerCommitment) -> [u8; 32] {
    let mut bytes = Vec::new();
    push_worker_commitment_leaf(&mut bytes, commitment);
    digest_with_label(b"paper-protocol7-worker-leaf-v2", &bytes)
}

pub(crate) fn worker_commitment_size(commitment: &PaperProtocol11WorkerCommitment) -> usize {
    USIZE_BYTES * 3 + HASH_BYTES + pcs_commitment_size(&commitment.pcs_commitment) + HASH_BYTES
}

pub(crate) fn worker_set_root(worker_commitments: &[PaperProtocol11WorkerCommitment]) -> [u8; 32] {
    let mut bytes = Vec::with_capacity(USIZE_BYTES + worker_commitments.len() * HASH_BYTES);
    push_usize(&mut bytes, worker_commitments.len());
    for commitment in worker_commitments {
        push_hash(&mut bytes, &commitment.leaf_digest);
    }
    digest_with_label(b"paper-protocol7-worker-root-v2", &bytes)
}

pub(crate) fn push_commitment_public(out: &mut Vec<u8>, commitment: &PaperProtocol11Commitment) {
    push_config(out, commitment.config);
    push_usize(out, commitment.original_len);
    push_usize(out, commitment.nv);
    push_usize(out, commitment.workers);
    push_usize(out, commitment.worker_bits);
    push_usize(out, commitment.shard_len);
    push_usize(out, commitment.shard_nv);
    push_usize(out, commitment.artifact_nv);
    push_hash(out, &commitment.root);
}

pub(crate) fn push_worker_opening_statement(
    out: &mut Vec<u8>,
    commitment: &PaperProtocol11Commitment,
    point: &[PaperField],
    opening: &PaperProtocol11WorkerOpening,
) -> PaperDepcsResult<()> {
    push_commitment_public(out, commitment);
    push_field_slice(out, point);
    let worker_commitment = commitment
        .workers_commitments
        .get(opening.worker_id)
        .ok_or(PaperDepcsError::InvalidProof)?;
    push_usize(out, opening.worker_id);
    push_hash(out, &worker_commitment.leaf_digest);
    push_field(out, opening.worker_weight);
    push_field_slice(out, &opening.shard_point);
    push_field(out, opening.value);
    Ok(())
}

pub(crate) fn worker_opening_statement_digest(
    commitment: &PaperProtocol11Commitment,
    point: &[PaperField],
    opening: &PaperProtocol11WorkerOpening,
) -> PaperDepcsResult<[u8; 32]> {
    let mut bytes = Vec::new();
    push_worker_opening_statement(&mut bytes, commitment, point, opening)?;
    Ok(digest_with_label(
        b"paper-protocol11-worker-opening-statement-v2",
        &bytes,
    ))
}

#[allow(dead_code)]
pub(crate) fn push_claim(out: &mut Vec<u8>, claim: &PaperProtocol10OpeningClaim) {
    push_claim_parts(
        out,
        claim.worker_id,
        claim.claim_kind,
        claim.claimed_value,
        claim.weight,
        &claim.point,
        &claim.source_digest,
    );
}

pub(crate) fn push_claim_parts(
    out: &mut Vec<u8>,
    worker_id: usize,
    claim_kind: PaperProtocol10OpeningClaimKind,
    claimed_value: PaperField,
    weight: PaperField,
    point: &[PaperField],
    source_digest: &[u8; 32],
) {
    push_usize(out, worker_id);
    push_claim_kind(out, claim_kind);
    push_field(out, claimed_value);
    push_field(out, weight);
    push_field_slice(out, point);
    push_hash(out, source_digest);
}

pub(crate) fn push_opening_batch(out: &mut Vec<u8>, batch: &PaperProtocol10OpeningBatchProof) {
    push_usize(out, batch.claim_count);
    push_usize(out, batch.reduction_point_len);
    push_field(out, batch.combined_value);
    push_hash(out, &batch.source_digest);
}

pub(crate) fn push_relation_proof(out: &mut Vec<u8>, proof: &PaperProtocol10RelationProof) {
    push_usize(out, proof.relation_index);
    push_relation_kind(out, proof.relation_kind);
    push_field(out, proof.challenge);
    push_hash(out, &proof.opening_batch_digest);
    push_usize(out, proof.claim_count);
    push_usize(out, proof.reduction_point_len);
    push_field(out, proof.relation_value);
}

pub(crate) fn push_encoding_batch(out: &mut Vec<u8>, proof: &PaperProtocol10EncodingBatchProof) {
    push_field_slice(out, &proof.relation_challenges);
    push_relation_proof(out, &proof.e1);
    push_relation_proof(out, &proof.e2);
    push_hash(out, &proof.opening_batch_digest);
}

pub(crate) fn protocol11_transcript_state(
    commitment: &PaperProtocol11Commitment,
    point: &[PaperField],
    claimed_value: PaperField,
    encoding_batch: &PaperProtocol10EncodingBatchProof,
    opening_batch: &PaperProtocol10OpeningBatchProof,
) -> [u8; 32] {
    let mut bytes = Vec::new();
    push_commitment_public(&mut bytes, commitment);
    push_field_slice(&mut bytes, point);
    push_field(&mut bytes, claimed_value);
    push_encoding_batch(&mut bytes, encoding_batch);
    push_opening_batch(&mut bytes, opening_batch);
    digest_with_label(b"paper-protocol11-transcript-v2", &bytes)
}

#[allow(dead_code)]
pub(crate) fn claim_digest(claim: &PaperProtocol10OpeningClaim) -> [u8; 32] {
    let mut bytes = Vec::new();
    push_claim(&mut bytes, claim);
    digest_with_label(b"paper-protocol10-claim-v2", &bytes)
}

pub(crate) fn claim_digest_parts(
    worker_id: usize,
    claim_kind: PaperProtocol10OpeningClaimKind,
    claimed_value: PaperField,
    weight: PaperField,
    point: &[PaperField],
    source_digest: &[u8; 32],
) -> [u8; 32] {
    let mut bytes = Vec::new();
    push_claim_parts(
        &mut bytes,
        worker_id,
        claim_kind,
        claimed_value,
        weight,
        point,
        source_digest,
    );
    digest_with_label(b"paper-protocol10-claim-v2", &bytes)
}

pub(crate) fn oracle_seed(
    original_len: usize,
    workers: usize,
    worker_id: usize,
    config: PaperDepcsConfig,
    artifact_nv: usize,
) -> [u8; 32] {
    let mut bytes = Vec::new();
    push_usize(&mut bytes, original_len);
    push_usize(&mut bytes, workers);
    push_usize(&mut bytes, worker_id);
    push_config(&mut bytes, config);
    push_usize(&mut bytes, artifact_nv);
    digest_with_label(b"paper-deepfold-oracle-seed-v2", &bytes)
}

fn oracle_block(seed: [u8; 32], label: &[u8], index: usize) -> [u8; 32] {
    let mut bytes = Vec::with_capacity(HASH_BYTES + label.len() + USIZE_BYTES);
    push_hash(&mut bytes, &seed);
    push_bytes(&mut bytes, label);
    push_usize(&mut bytes, index);
    digest_with_label(b"paper-deepfold-oracle-expand-v2", &bytes)
}

fn oracle_field(seed: [u8; 32], label: &[u8], index: usize) -> PaperField {
    PaperField::from_hash(oracle_block(seed, label, index))
}

fn oracle_query(seed: [u8; 32], index: usize) -> usize {
    let block = oracle_block(seed, b"query", index);
    let mut bytes = [0_u8; 8];
    bytes.copy_from_slice(&block[..8]);
    u64::from_le_bytes(bytes) as usize
}

pub(crate) fn oracle_from_seed(
    seed: [u8; 32],
    total_round: usize,
    query_num: usize,
) -> RandomOracle<PaperField> {
    RandomOracle {
        beta: oracle_field(seed, b"beta", 0),
        rlc: oracle_field(seed, b"rlc", 0),
        folding_challenges: (0..total_round)
            .map(|idx| oracle_field(seed, b"folding", idx))
            .collect(),
        deep: (0..total_round)
            .map(|idx| oracle_field(seed, b"deep", idx))
            .collect(),
        alpha: (0..total_round)
            .map(|idx| oracle_field(seed, b"alpha", idx))
            .collect(),
        query_list: (0..query_num).map(|idx| oracle_query(seed, idx)).collect(),
    }
}

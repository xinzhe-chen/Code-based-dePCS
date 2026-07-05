use super::protocol7_merkle_commitments::worker_commitment_digest;
use super::protocol10_encoding::{
    protocol10_worker_contexts, relation_challenge, relation_challenge_with_statement_digests,
    relation_challenge_with_worker_contexts, worker_statement_digests,
};
use super::*;
use crate::depcs::backend::PaperPcsBackend;
use paper_util::algebra::field::MyField;

fn roundtrip(
    backend: PaperPcsBackend,
    rate_inv: usize,
) -> (PaperProtocol11Commitment, PaperProtocol11Proof) {
    let config = PaperDepcsConfig::new(backend, rate_inv).unwrap();
    let workers = 2;
    let original_len = 1 << 6;
    let commitments = (0..workers)
        .map(|worker_id| commit_worker(original_len, workers, worker_id, config).unwrap())
        .collect();
    let commitment =
        commit_from_worker_commitments(original_len, workers, config, commitments).unwrap();
    let point = sample_point(commitment.nv);
    let openings = (0..workers)
        .map(|worker_id| open_worker(&commitment, worker_id, &point).unwrap())
        .collect();
    let (proof, _) = assemble_opening(&commitment, point, openings).unwrap();
    verify(&commitment, &proof).unwrap();
    (commitment, proof)
}

#[test]
fn paper_depcs_deepfold_roundtrip() {
    roundtrip(PaperPcsBackend::DeepFold, 2);
}

#[test]
fn paper_depcs_rejects_wrong_value() {
    let (commitment, mut proof) = roundtrip(PaperPcsBackend::DeepFold, 2);
    proof.worker_openings[0].value += PaperField::from_int(1);
    assert!(verify(&commitment, &proof).is_err());
}

#[test]
fn paper_depcs_rejects_tampered_protocol10_batch() {
    let (commitment, mut proof) = roundtrip(PaperPcsBackend::DeepFold, 2);
    proof.opening_batch.source_digest[0] ^= 1;
    assert!(verify(&commitment, &proof).is_err());
}

#[test]
fn paper_depcs_rejects_tampered_protocol10_relation_digest() {
    let (commitment, mut proof) = roundtrip(PaperPcsBackend::DeepFold, 2);
    proof.encoding_batch.e1.opening_batch_digest[0] ^= 1;
    assert!(verify(&commitment, &proof).is_err());
}

#[test]
fn paper_depcs_rejects_tampered_protocol10_reduction_value() {
    let (commitment, mut proof) = roundtrip(PaperPcsBackend::DeepFold, 2);
    proof.encoding_batch.e2.relation_value += PaperField::from_int(1);
    assert!(verify(&commitment, &proof).is_err());
}

#[test]
fn paper_depcs_rejects_tampered_protocol10_claim_count() {
    let (commitment, mut proof) = roundtrip(PaperPcsBackend::DeepFold, 2);
    proof.encoding_batch.e1.claim_count += 1;
    assert!(verify(&commitment, &proof).is_err());
}

#[test]
fn paper_depcs_rejects_tampered_protocol10_reduction_point_len() {
    let (commitment, mut proof) = roundtrip(PaperPcsBackend::DeepFold, 2);
    proof.encoding_batch.e2.reduction_point_len += 1;
    assert!(verify(&commitment, &proof).is_err());
}

#[test]
fn paper_depcs_rejects_tampered_worker_weight() {
    let (commitment, mut proof) = roundtrip(PaperPcsBackend::DeepFold, 2);
    proof.worker_openings[0].worker_weight += PaperField::from_int(1);
    assert!(verify(&commitment, &proof).is_err());
}

#[test]
fn paper_depcs_rejects_tampered_shard_point() {
    let (commitment, mut proof) = roundtrip(PaperPcsBackend::DeepFold, 2);
    proof.worker_openings[0].shard_point[0] += PaperField::from_int(1);
    assert!(verify(&commitment, &proof).is_err());
}

#[test]
fn paper_depcs_rejects_tampered_global_point() {
    let (commitment, mut proof) = roundtrip(PaperPcsBackend::DeepFold, 2);
    proof.point[0] += PaperField::from_int(1);
    assert!(verify(&commitment, &proof).is_err());
}

#[test]
fn paper_depcs_rejects_reordered_workers() {
    let (commitment, mut proof) = roundtrip(PaperPcsBackend::DeepFold, 2);
    proof.worker_openings.swap(0, 1);
    assert!(verify(&commitment, &proof).is_err());
}

#[test]
fn paper_depcs_rejects_tampered_worker_leaf_digest() {
    let (mut commitment, proof) = roundtrip(PaperPcsBackend::DeepFold, 2);
    commitment.workers_commitments[0].leaf_digest[0] ^= 1;
    commitment.root = compact_codec::worker_set_root(&commitment.workers_commitments);
    assert!(verify(&commitment, &proof).is_err());
}

#[test]
fn paper_depcs_rejects_tampered_oracle_seed() {
    let (mut commitment, proof) = roundtrip(PaperPcsBackend::DeepFold, 2);
    commitment.workers_commitments[0].oracle_seed[0] ^= 1;
    assert!(verify(&commitment, &proof).is_err());
}

#[test]
fn paper_depcs_rejects_wrong_rate() {
    assert!(PaperDepcsConfig::new(PaperPcsBackend::DeepFold, 8).is_err());
}

#[test]
fn paper_depcs_cached_worker_open_roundtrips() {
    let config = PaperDepcsConfig::new(PaperPcsBackend::DeepFold, 2).unwrap();
    let workers = 2;
    let original_len = 1 << 6;
    let caches = (0..workers)
        .map(|worker_id| commit_worker_cached(original_len, workers, worker_id, config).unwrap())
        .collect::<Vec<_>>();
    let commitment = commit_from_worker_commitments(
        original_len,
        workers,
        config,
        caches
            .iter()
            .map(|cache| cache.commitment.clone())
            .collect::<Vec<_>>(),
    )
    .unwrap();
    let point = sample_point(commitment.nv);
    let openings = caches
        .into_iter()
        .map(|cache| open_worker_cached(cache, &commitment, &point).unwrap())
        .collect::<Vec<_>>();
    let (proof, _) = assemble_opening(&commitment, point, openings).unwrap();
    verify(&commitment, &proof).unwrap();
}

#[test]
fn paper_depcs_cached_worker_open_rejects_wrong_commitment() {
    let config = PaperDepcsConfig::new(PaperPcsBackend::DeepFold, 2).unwrap();
    let cache = commit_worker_cached(1 << 6, 2, 0, config).unwrap();
    let other = commit_worker(1 << 6, 2, 1, config).unwrap();
    let mut commitment =
        commit_from_worker_commitments(1 << 6, 2, config, vec![cache.commitment.clone(), other])
            .unwrap();
    commitment.workers_commitments[0].leaf_digest[0] ^= 1;
    let point = sample_point(commitment.nv);
    assert!(open_worker_cached(cache, &commitment, &point).is_err());
}

// --- A1: canonical-order query value encoding must be fail-closed ---

fn first_worker_deepfold_values(proof: &mut PaperProtocol11Proof) -> &mut Vec<PaperField> {
    match &mut proof.worker_openings[0].proof {
        PaperPcsOpeningProof::DeepFold(df) => &mut df.query_result[0].proof_values,
    }
}

fn tamper_first_worker_deepfold_root(proof: &mut PaperProtocol11Proof) {
    match &mut proof.worker_openings[0].proof {
        PaperPcsOpeningProof::DeepFold(df) => df.merkle_root[0][0] ^= 1,
    }
}

#[test]
fn paper_depcs_relation_challenge_excludes_deepfold_proof_bytes() {
    let (commitment, mut proof) = roundtrip(PaperPcsBackend::DeepFold, 2);
    let statement_before = compact_codec::worker_opening_statement_digest(
        &commitment,
        &proof.point,
        &proof.worker_openings[0],
    )
    .unwrap();
    let challenge_before = relation_challenge(
        0,
        PaperProtocol10RelationKind::E1,
        &commitment,
        &proof.point,
        &proof.worker_openings,
    )
    .unwrap();

    tamper_first_worker_deepfold_root(&mut proof);

    let statement_after = compact_codec::worker_opening_statement_digest(
        &commitment,
        &proof.point,
        &proof.worker_openings[0],
    )
    .unwrap();
    let challenge_after = relation_challenge(
        0,
        PaperProtocol10RelationKind::E1,
        &commitment,
        &proof.point,
        &proof.worker_openings,
    )
    .unwrap();
    assert_eq!(statement_before, statement_after);
    assert_eq!(challenge_before, challenge_after);
    assert!(verify(&commitment, &proof).is_err());
}

#[test]
fn paper_depcs_cached_statement_digest_challenge_matches_direct() {
    let (commitment, proof) = roundtrip(PaperPcsBackend::DeepFold, 2);
    let direct = relation_challenge(
        0,
        PaperProtocol10RelationKind::E1,
        &commitment,
        &proof.point,
        &proof.worker_openings,
    )
    .unwrap();
    let statement_digests =
        worker_statement_digests(&commitment, &proof.point, &proof.worker_openings).unwrap();
    let cached = relation_challenge_with_statement_digests(
        0,
        PaperProtocol10RelationKind::E1,
        &commitment,
        &proof.point,
        &statement_digests,
    )
    .unwrap();
    let worker_contexts =
        protocol10_worker_contexts(&commitment, &proof.point, &proof.worker_openings).unwrap();
    let context_cached = relation_challenge_with_worker_contexts(
        0,
        PaperProtocol10RelationKind::E1,
        &commitment,
        &proof.point,
        &worker_contexts,
    )
    .unwrap();
    assert_eq!(direct, cached);
    assert_eq!(direct, context_cached);
}

#[test]
fn paper_depcs_cached_worker_commitment_digest_matches_canonical() {
    let (commitment, proof) = roundtrip(PaperPcsBackend::DeepFold, 2);
    let worker_contexts =
        protocol10_worker_contexts(&commitment, &proof.point, &proof.worker_openings).unwrap();
    for (opening, ctx) in proof.worker_openings.iter().zip(worker_contexts.iter()) {
        assert_eq!(opening.worker_id, ctx.worker_id);
        let canonical =
            worker_commitment_digest(&commitment.workers_commitments[opening.worker_id]).unwrap();
        assert_eq!(canonical, ctx.source_digest);
        let direct_statement =
            compact_codec::worker_opening_statement_digest(&commitment, &proof.point, opening)
                .unwrap();
        assert_eq!(direct_statement, ctx.statement_digest);
    }
}

#[test]
fn paper_depcs_seeded_oracle_expansion_is_deterministic() {
    let config = PaperDepcsConfig::new(PaperPcsBackend::DeepFold, 2).unwrap();
    let seed = compact_codec::oracle_seed(1 << 6, 2, 0, config, 5);
    let oracle_a = compact_codec::oracle_from_seed(seed, 5, config.query_count());
    let oracle_b = compact_codec::oracle_from_seed(seed, 5, config.query_count());
    assert_eq!(oracle_a.beta, oracle_b.beta);
    assert_eq!(oracle_a.rlc, oracle_b.rlc);
    assert_eq!(oracle_a.folding_challenges, oracle_b.folding_challenges);
    assert_eq!(oracle_a.deep, oracle_b.deep);
    assert_eq!(oracle_a.alpha, oracle_b.alpha);
    assert_eq!(oracle_a.query_list, oracle_b.query_list);

    let mut other_seed = seed;
    other_seed[0] ^= 1;
    let oracle_c = compact_codec::oracle_from_seed(other_seed, 5, config.query_count());
    assert_ne!(oracle_a.beta, oracle_c.beta);
}

#[test]
fn paper_depcs_compact_proof_breakdown_sums_to_total() {
    let (_, proof) = roundtrip(PaperPcsBackend::DeepFold, 2);
    let breakdown = proof_size_breakdown(&proof);
    let relation_proof_bytes = 8 + 1 + 16 + 32 + 8 + 8 + 16;
    let component_sum = breakdown.point_query_public_bytes
        + breakdown.eval_commitments_bytes
        + breakdown.merkle_roots_bytes
        + breakdown.column_openings_bytes
        + breakdown.f2_openings_bytes
        + breakdown.protocol10_e1_bytes
        + breakdown.protocol10_e2_bytes
        + breakdown.transcript_overhead_bytes;
    assert_eq!(component_sum, breakdown.total_bytes);
    assert_eq!(breakdown.total_bytes, proof_size_bytes(&proof));
    assert_eq!(breakdown.protocol10_e1_bytes, relation_proof_bytes);
    assert_eq!(breakdown.protocol10_e2_bytes, relation_proof_bytes);
}

#[test]
fn paper_depcs_compact_commitment_size_matches_canonical_rule() {
    let (commitment, _) = roundtrip(PaperPcsBackend::DeepFold, 2);
    let public_bytes = 3 * 8 + 7 * 8 + 32;
    let worker_vec_len_bytes = 8;
    let worker_bytes = commitment
        .workers_commitments
        .iter()
        .map(compact_codec::worker_commitment_size)
        .sum::<usize>();
    assert_eq!(
        commitment_size_bytes(&commitment),
        public_bytes + worker_vec_len_bytes + worker_bytes
    );
}

#[test]
fn paper_depcs_rejects_tampered_query_value() {
    let (commitment, mut proof) = roundtrip(PaperPcsBackend::DeepFold, 2);
    first_worker_deepfold_values(&mut proof)[0] += PaperField::from_int(1);
    assert!(verify(&commitment, &proof).is_err());
}

#[test]
fn paper_depcs_rejects_reordered_query_values() {
    let (commitment, mut proof) = roundtrip(PaperPcsBackend::DeepFold, 2);
    let values = first_worker_deepfold_values(&mut proof);
    let n = values.len();
    assert!(n >= 2, "need at least two query values to reorder");
    values.swap(0, n - 1);
    assert!(verify(&commitment, &proof).is_err());
}

#[test]
fn paper_depcs_rejects_missing_query_value() {
    let (commitment, mut proof) = roundtrip(PaperPcsBackend::DeepFold, 2);
    first_worker_deepfold_values(&mut proof).pop();
    assert!(verify(&commitment, &proof).is_err());
}

#[test]
fn paper_depcs_rejects_extra_query_value() {
    let (commitment, mut proof) = roundtrip(PaperPcsBackend::DeepFold, 2);
    first_worker_deepfold_values(&mut proof).push(PaperField::from_int(0));
    assert!(verify(&commitment, &proof).is_err());
}

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
fn paper_depcs_basefold_roundtrip() {
    roundtrip(PaperPcsBackend::BaseFold, 8);
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
    let (commitment, mut proof) = roundtrip(PaperPcsBackend::BaseFold, 8);
    proof.opening_batch.source_digest[0] ^= 1;
    assert!(verify(&commitment, &proof).is_err());
}

#[test]
fn paper_depcs_rejects_tampered_protocol10_relation_claim() {
    let (commitment, mut proof) = roundtrip(PaperPcsBackend::DeepFold, 2);
    proof.encoding_batch.e1.opening_batch.claims[0].claimed_value += PaperField::from_int(1);
    assert!(verify(&commitment, &proof).is_err());
}

#[test]
fn paper_depcs_rejects_tampered_protocol10_reduction_value() {
    let (commitment, mut proof) = roundtrip(PaperPcsBackend::DeepFold, 2);
    proof.encoding_batch.e2.opening_batch.combined_value += PaperField::from_int(1);
    assert!(verify(&commitment, &proof).is_err());
}

#[test]
fn paper_depcs_rejects_tampered_worker_weight() {
    let (commitment, mut proof) = roundtrip(PaperPcsBackend::BaseFold, 8);
    proof.worker_openings[0].worker_weight += PaperField::from_int(1);
    assert!(verify(&commitment, &proof).is_err());
}

#[test]
fn paper_depcs_rejects_wrong_rate() {
    assert!(PaperDepcsConfig::new(PaperPcsBackend::BaseFold, 2).is_err());
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

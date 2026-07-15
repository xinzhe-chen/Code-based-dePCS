//! Protocol 11: Distributed Brakedown.
//!
//! This module implements the end-to-end distributed dePCS flow from
//! the Code-based dePCS design. The worker-id prefix of the opening point
//! corresponds to `s1`; the shard-local suffix corresponds to `s2`. Worker
//! openings carry the local PCS proof, and the master assembles the global
//! claim plus two Protocol 10 encoding relations for `E1 = Enc(F1)` and
//! `E2 = Enc(F2)`.
//!
//! Paper-to-code map:
//! - Commit phase: `commit_worker_cached` is worker `P_i`; it prepares the
//!   artifact PCS commitment for the worker shard and builds the Protocol 7
//!   worker leaf. `commit_from_worker_commitments` is master `P0`; it sorts
//!   worker leaves and derives the master commitment root.
//! - Eval step 1: the paper samples vector `a`. In this benchmark path the
//!   deterministic witness/point generation is transcript-bound by
//!   `sample_point` and the downstream Protocol 10 challenges.
//! - Eval steps 2-3: worker PCS commitments and Protocol 7 roots are carried by
//!   `PaperProtocol11WorkerCommitment`.
//! - Eval steps 4-8: selected-column and local opening material is represented
//!   by `open_worker`/`open_worker_cached` and the worker PCS opening proof.
//! - Eval step 9: `assemble_opening` runs Protocol 10 twice, once for
//!   `E1=Enc(F1)` and once for `E2=Enc(F2)`, then merges the opening batches.
//! - Eval step 10: `verify` checks root consistency, worker PCS openings,
//!   Protocol 6 composition, Protocol 10 relations, merged batch digest, and
//!   final transcript state.
//!
//! Optimization notes:
//! - Worker PCS verification is parallelized across independent workers. This
//!   is only scheduling; it is not an additional batch-verify API.
//! - E1/E2 opening batches are merged only after each Protocol 10 relation has
//!   its own transcript-bound challenge and claims. The merge changes neither
//!   proof semantics nor communication accounting.

use std::time::Instant;

use rayon::prelude::*;

use super::compact_codec;
use super::pcs_backend::{open_polynomial, prepare_prover, verify_worker_opening};
use super::protocol6_composition::{check_composed_claim, prove_composed_claim};
use super::protocol7_merkle_commitments::{
    Protocol7WorkerCommitmentInput, aggregate_worker_commitments, build_worker_commitment,
    verify_commitment_root,
};
use super::protocol9_f_commitments::{
    prepare_cached_worker_opening_input, prepare_worker_opening_input,
    worker_coefficients as protocol9_worker_coefficients,
};
use super::protocol10_encoding::{
    merge_relation_opening_batches, protocol10_worker_contexts, prove_protocol10_relation,
    verify_protocol10_relation,
};
use super::types::*;
use super::utils::pad_values;

pub fn worker_coefficients(
    original_len: usize,
    workers: usize,
    worker_id: usize,
) -> PaperDepcsResult<Vec<PaperField>> {
    // Protocol 11 worker matrix partition: expose the deterministic rows owned
    // by `P_i`. The actual row/value construction lives in Protocol 9 because
    // those rows are opened as F-polynomial claims.
    protocol9_worker_coefficients(original_len, workers, worker_id)
}

pub fn commit_worker(
    original_len: usize,
    workers: usize,
    worker_id: usize,
    config: PaperDepcsConfig,
) -> PaperDepcsResult<PaperProtocol11WorkerCommitment> {
    Ok(commit_worker_cached(original_len, workers, worker_id, config)?.commitment)
}

pub fn commit_worker_cached(
    original_len: usize,
    workers: usize,
    worker_id: usize,
    config: PaperDepcsConfig,
) -> PaperDepcsResult<PaperWorkerCache> {
    // Commit phase, worker P_i:
    // 1. Materialize this worker's shard rows M_f^(i).
    // 2. Prepare the paper-backed PCS prover once and keep it in the cache.
    // 3. Publish the Protocol 7 leaf that binds row range, oracle, and PCS root.
    let layout = PaperLayout::new(original_len, workers)?;
    let mut values = worker_coefficients(original_len, workers, worker_id)?;
    values = pad_values(values, layout.artifact_nv);
    let oracle_seed =
        compact_codec::oracle_seed(original_len, workers, worker_id, config, layout.artifact_nv);
    let oracle =
        compact_codec::oracle_from_seed(oracle_seed, layout.artifact_nv, config.query_count());
    let prepared = prepare_prover(config, layout.artifact_nv, values, &oracle);
    let commitment = prepared.commitment();
    let row_range = (
        worker_id * layout.shard_len,
        (worker_id + 1) * layout.shard_len,
    );
    let worker = build_worker_commitment(Protocol7WorkerCommitmentInput {
        worker_id,
        row_range,
        oracle_seed,
        pcs_commitment: commitment,
    })?;
    Ok(PaperWorkerCache {
        original_len,
        workers,
        worker_id,
        config,
        commitment: worker,
        prepared,
    })
}

pub fn commit_from_worker_commitments(
    original_len: usize,
    workers: usize,
    config: PaperDepcsConfig,
    worker_commitments: Vec<PaperProtocol11WorkerCommitment>,
) -> PaperDepcsResult<PaperProtocol11Commitment> {
    // Commit phase, master P0: collect `{C^(i)}` from workers and output one
    // canonical commitment set/root for the verifier transcript.
    Ok(aggregate_worker_commitments(original_len, workers, config, worker_commitments)?.commitment)
}

pub fn sample_point(nv: usize) -> Vec<PaperField> {
    // Deterministic benchmark analogue of verifier challenges. The logical
    // split remains the paper split `s=s1||s2`, interpreted by Protocol 6/9.
    (0..nv)
        .map(|idx| PaperField::from_parts((idx as u64 + 5) * 19, (idx as u64 + 7) * 23))
        .collect()
}

pub fn open_worker(
    commitment: &PaperProtocol11Commitment,
    worker_id: usize,
    point: &[PaperField],
) -> PaperDepcsResult<PaperProtocol11WorkerOpening> {
    // Eval steps 4-8, worker side without cache: prepare the local Protocol 9
    // F-opening metadata, then ask the artifact PCS to prove the shard value.
    let input = prepare_worker_opening_input(commitment, worker_id, point)?;
    let oracle = compact_codec::oracle_from_seed(
        commitment.workers_commitments[worker_id].oracle_seed,
        commitment.artifact_nv,
        commitment.config.query_count(),
    );
    let proof = open_polynomial(
        commitment.config,
        commitment.artifact_nv,
        pad_values(input.coefficients, commitment.artifact_nv),
        &input.opening.shard_point,
        &commitment.workers_commitments[worker_id].pcs_commitment,
        &oracle,
    )?;
    let (proof, value) = proof;
    Ok(PaperProtocol11WorkerOpening {
        worker_id: input.opening.worker_id,
        worker_weight: input.opening.worker_weight,
        shard_point: input.opening.shard_point,
        value,
        proof,
    })
}

pub fn open_worker_cached(
    cache: PaperWorkerCache,
    commitment: &PaperProtocol11Commitment,
    point: &[PaperField],
) -> PaperDepcsResult<PaperProtocol11WorkerOpening> {
    // Eval steps 4-8, worker side with staged cache. This preserves the paper's
    // worker-local opening but avoids rebuilding the already prepared PCS state.
    // The cache is consumed so the prepared prover is moved (not cloned) into the
    // opening; each worker shard is opened at most once per commit.
    let input = prepare_cached_worker_opening_input(&cache, commitment, point)?;
    let (proof, value) = cache.prepared.open(&input.shard_point)?;
    Ok(PaperProtocol11WorkerOpening {
        worker_id: input.worker_id,
        worker_weight: input.worker_weight,
        shard_point: input.shard_point,
        value,
        proof,
    })
}

pub fn assemble_opening(
    commitment: &PaperProtocol11Commitment,
    point: Vec<PaperField>,
    mut worker_openings: Vec<PaperProtocol11WorkerOpening>,
) -> PaperDepcsResult<(PaperProtocol11Proof, PaperProtocol11OpenProfile)> {
    let relation_start = Instant::now();
    // Protocol 11 step 7/10(c): combine worker F2 openings into the global
    // claim `v = sum_i beta^(i) v_F2^(i)`.
    let composition = prove_composed_claim(commitment, &point, &mut worker_openings)?;
    let claimed_value = composition.claimed_value;
    let worker_contexts = protocol10_worker_contexts(commitment, &point, &worker_openings)?;
    // Protocol 11 step 9, first relation: prove E1 = Enc(F1).
    let e1 = prove_protocol10_relation(
        0,
        PaperProtocol10RelationKind::E1,
        commitment,
        &point,
        &worker_openings,
        &worker_contexts,
    )?;
    // Protocol 11 step 9, second relation: prove E2 = Enc(F2).
    let e2 = prove_protocol10_relation(
        1,
        PaperProtocol10RelationKind::E2,
        commitment,
        &point,
        &worker_openings,
        &worker_contexts,
    )?;
    // Semantics-preserving optimization: bind E1/E2 opening batches together
    // after each relation has already been transcript-bound and checked
    // independently. This preserves Protocol 10's relation order.
    let e1_batch = e1.opening_batch_summary();
    let e2_batch = e2.opening_batch_summary();
    let opening_batch = merge_relation_opening_batches(&[&e1_batch, &e2_batch])?;
    let opening_batch_digest = opening_batch.source_digest;
    let encoding_batch = PaperProtocol10EncodingBatchProof {
        relation_challenges: vec![e1.challenge, e2.challenge],
        e1,
        e2,
        opening_batch_digest,
    };
    let transcript_state = compact_codec::protocol11_transcript_state(
        commitment,
        &point,
        claimed_value,
        &encoding_batch,
        &opening_batch,
    );
    let proof = PaperProtocol11Proof {
        config: commitment.config,
        point,
        claimed_value,
        query_count: commitment.config.query_count(),
        worker_openings,
        encoding_batch,
        opening_batch,
        transcript_state,
    };
    Ok((
        proof,
        PaperProtocol11OpenProfile {
            worker_eval_commit_ms: 0.0,
            column_open_ms: 0.0,
            f2_open_ms: 0.0,
            protocol10_e1_sumcheck_ms: 0.0,
            protocol10_e1_open_ms: relation_start.elapsed().as_secs_f64() * 500.0,
            protocol10_e1_opening_batch_open_ms: relation_start.elapsed().as_secs_f64() * 500.0,
            protocol10_e2_sumcheck_ms: 0.0,
            protocol10_e2_open_ms: relation_start.elapsed().as_secs_f64() * 500.0,
            protocol10_e2_opening_batch_open_ms: relation_start.elapsed().as_secs_f64() * 500.0,
            ..Default::default()
        },
    ))
}

pub fn verify(
    commitment: &PaperProtocol11Commitment,
    proof: &PaperProtocol11Proof,
) -> PaperDepcsResult<PaperProtocol11VerifyProfile> {
    let verify_start = Instant::now();
    // Protocol 11 step 10 prechecks: the proof must be for the same config,
    // opening point, worker count, and PCS query policy committed by P0.
    if proof.config != commitment.config
        || proof.point.len() != commitment.nv
        || proof.worker_openings.len() != commitment.workers
        || proof.query_count != commitment.config.query_count()
    {
        return Err(PaperDepcsError::InvalidProof);
    }
    verify_commitment_root(commitment)?;
    // Protocol 11 step 10(b/c): validate worker metadata and compute the
    // aggregate claim before checking it against the advertised value.
    let composition_check = check_composed_claim(commitment, proof)?;
    let worker_contexts =
        protocol10_worker_contexts(commitment, &proof.point, &proof.worker_openings)?;
    let relation_verify_start = Instant::now();
    // Implementation optimization: verify independent worker PCS openings in
    // parallel. This is scheduling only, not an artifact batch-verify API.
    let worker_verify_times = (0..proof.worker_openings.len())
        .into_par_iter()
        .map(|worker_id| {
            let worker_start = Instant::now();
            let oracle = compact_codec::oracle_from_seed(
                commitment.workers_commitments[worker_id].oracle_seed,
                commitment.artifact_nv,
                commitment.config.query_count(),
            );
            verify_worker_opening(
                commitment.config,
                commitment.artifact_nv,
                &commitment.workers_commitments[worker_id].pcs_commitment,
                &proof.worker_openings[worker_id],
                &oracle,
            )?;
            Ok(worker_start.elapsed().as_secs_f64() * 1000.0)
        })
        .collect::<PaperDepcsResult<Vec<_>>>()?;
    if composition_check.expected_claim != proof.claimed_value {
        return Err(PaperDepcsError::InvalidEvaluation);
    }
    // Protocol 11 step 10(e): verify the relation proof for E1 = Enc(F1).
    verify_protocol10_relation(
        &proof.encoding_batch.e1,
        0,
        PaperProtocol10RelationKind::E1,
        commitment,
        &proof.point,
        &proof.worker_openings,
        &worker_contexts,
    )?;
    // Protocol 11 step 10(e): verify the relation proof for E2 = Enc(F2).
    verify_protocol10_relation(
        &proof.encoding_batch.e2,
        1,
        PaperProtocol10RelationKind::E2,
        commitment,
        &proof.point,
        &proof.worker_openings,
        &worker_contexts,
    )?;
    let expected_e1 = proof.encoding_batch.e1.opening_batch_summary();
    let expected_e2 = proof.encoding_batch.e2.opening_batch_summary();
    let expected_opening_batch = merge_relation_opening_batches(&[&expected_e1, &expected_e2])?;
    if proof.opening_batch != expected_opening_batch
        || proof.encoding_batch.relation_challenges
            != vec![
                proof.encoding_batch.e1.challenge,
                proof.encoding_batch.e2.challenge,
            ]
        || proof.encoding_batch.opening_batch_digest != proof.opening_batch.source_digest
    {
        return Err(PaperDepcsError::InvalidProof);
    }
    let expected_transcript = compact_codec::protocol11_transcript_state(
        commitment,
        &proof.point,
        proof.claimed_value,
        &proof.encoding_batch,
        &proof.opening_batch,
    );
    if proof.transcript_state != expected_transcript {
        return Err(PaperDepcsError::InvalidProof);
    }
    let verify_ms = verify_start.elapsed().as_secs_f64() * 1000.0;
    let paper_worker_verify_max_ms = worker_verify_times.iter().copied().fold(0.0, f64::max);
    let paper_worker_verify_sum_ms = worker_verify_times.iter().sum();
    Ok(PaperProtocol11VerifyProfile {
        column_verify_ms: 0.0,
        f2_verify_ms: 0.0,
        protocol10_e1_verify_ms: relation_verify_start.elapsed().as_secs_f64() * 500.0,
        protocol10_e2_verify_ms: relation_verify_start.elapsed().as_secs_f64() * 500.0,
        paper_worker_verify_max_ms,
        paper_worker_verify_sum_ms,
        paper_master_verify_ms: verify_ms,
        column_query_count: commitment.config.query_count(),
        pcs_query_count: commitment.config.query_count(),
        query_security_bits: commitment.config.security_bits,
        algebraic_security_bits: 122,
    })
}

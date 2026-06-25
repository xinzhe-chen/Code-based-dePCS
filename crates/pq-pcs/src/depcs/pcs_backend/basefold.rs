//! BaseFold PCS backend adapter for artifact-backed dePCS.
//!
//! This module is the only dePCS layer that talks directly to the vendored
//! `paper_basefold` prover/verifier API. Protocol 6-11 code calls through
//! `pcs_backend::mod` and never depends on BaseFold artifact internals.

use paper_basefold::{prover as basefold_prover, verifier as basefold_verifier};
use paper_util::{STEP, algebra::polynomial::MultilinearPolynomial, random_oracle::RandomOracle};

use super::interpolate_cosets;
use crate::depcs::types::*;

pub(crate) fn prepare_prover(
    nv: usize,
    values: Vec<PaperField>,
    oracle: &RandomOracle<PaperField>,
    code_rate_log: usize,
) -> basefold_prover::Prover<PaperField> {
    let polynomial = MultilinearPolynomial::new(values);
    let cosets = interpolate_cosets(nv, code_rate_log);
    basefold_prover::Prover::new(nv, &cosets, polynomial, oracle, STEP)
}

pub(crate) fn open_prepared(
    prover: &basefold_prover::Prover<PaperField>,
    point: &[PaperField],
    evaluation: PaperField,
) -> PaperPcsOpeningProof {
    let mut prover = prover.clone();
    prover.prove(&point.to_vec());
    PaperPcsOpeningProof::BaseFold(PaperBaseFoldProof {
        evaluation,
        folding_roots: prover.folding_roots(),
        sumcheck_values: prover.sumcheck_values(),
        final_poly: prover.final_poly(),
        query_results: prover.query(),
    })
}

pub(crate) fn open_polynomial(
    nv: usize,
    values: Vec<PaperField>,
    point: &[PaperField],
    root: &[u8; paper_util::merkle_tree::MERKLE_ROOT_SIZE],
    oracle: &RandomOracle<PaperField>,
    code_rate_log: usize,
) -> PaperDepcsResult<PaperPcsOpeningProof> {
    let mut prover = prepare_prover(nv, values, oracle, code_rate_log);
    if prover.commit_polynomial() != *root {
        return Err(PaperDepcsError::InvalidCommitment);
    }
    prover.prove(&point.to_vec());
    Ok(PaperPcsOpeningProof::BaseFold(PaperBaseFoldProof {
        evaluation: prover.evaluation(&point.to_vec()),
        folding_roots: prover.folding_roots(),
        sumcheck_values: prover.sumcheck_values(),
        final_poly: prover.final_poly(),
        query_results: prover.query(),
    }))
}

pub(crate) fn verify_opening(
    nv: usize,
    root: &[u8; paper_util::merkle_tree::MERKLE_ROOT_SIZE],
    opening: &PaperProtocol11WorkerOpening,
    proof: &PaperBaseFoldProof,
    oracle: &RandomOracle<PaperField>,
    code_rate_log: usize,
) -> bool {
    let cosets = interpolate_cosets(nv, code_rate_log);
    let mut verifier = basefold_verifier::Verifier::new(nv, &cosets, *root, oracle, STEP);
    verifier.set_open_point(&opening.shard_point);
    verifier.set_evalutation(proof.evaluation);
    for (leave_number, root) in &proof.folding_roots {
        verifier.receive_folding_root(*leave_number, *root);
    }
    for value in &proof.sumcheck_values {
        verifier.receive_sumcheck_value(*value);
    }
    verifier.set_final_poly(proof.final_poly.clone());
    verifier.verify(&proof.query_results) && proof.evaluation == opening.value
}

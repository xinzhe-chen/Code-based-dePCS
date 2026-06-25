//! DeepFold PCS backend adapter for artifact-backed dePCS.
//!
//! This module is the only dePCS layer that talks directly to the vendored
//! `paper_deepfold` prover/verifier API. Protocol 6-11 code calls through
//! `pcs_backend::mod` and never depends on DeepFold artifact internals.

use paper_deepfold::{self, prover as deepfold_prover, verifier as deepfold_verifier};
use paper_util::{STEP, algebra::polynomial::MultilinearPolynomial, random_oracle::RandomOracle};

use super::interpolate_cosets;
use crate::depcs::types::*;

pub(crate) fn prepare_prover(
    nv: usize,
    values: Vec<PaperField>,
    oracle: &RandomOracle<PaperField>,
    code_rate_log: usize,
) -> deepfold_prover::Prover<PaperField> {
    let polynomial = MultilinearPolynomial::new(values);
    let cosets = interpolate_cosets(nv, code_rate_log);
    deepfold_prover::Prover::new_with_code_rate(
        nv,
        &cosets,
        polynomial,
        oracle,
        STEP,
        code_rate_log,
    )
}

pub(crate) fn open_prepared(
    prover: &deepfold_prover::Prover<PaperField>,
    point: &[PaperField],
    evaluation: PaperField,
) -> PaperDepcsResult<PaperPcsOpeningProof> {
    let proof = prover.clone().generate_proof(point.to_vec());
    if proof.evaluation != evaluation {
        return Err(PaperDepcsError::InvalidEvaluation);
    }
    Ok(PaperPcsOpeningProof::DeepFold(proof))
}

pub(crate) fn open_polynomial(
    nv: usize,
    values: Vec<PaperField>,
    point: &[PaperField],
    oracle: &RandomOracle<PaperField>,
    code_rate_log: usize,
) -> PaperPcsOpeningProof {
    let prover = prepare_prover(nv, values, oracle, code_rate_log);
    PaperPcsOpeningProof::DeepFold(prover.generate_proof(point.to_vec()))
}

pub(crate) fn verify_opening(
    nv: usize,
    commitment: &paper_deepfold::Commit<PaperField>,
    opening: &PaperProtocol11WorkerOpening,
    proof: &paper_deepfold::Proof<PaperField>,
    oracle: &RandomOracle<PaperField>,
    code_rate_log: usize,
) -> bool {
    let cosets = interpolate_cosets(nv, code_rate_log);
    let mut verifier =
        deepfold_verifier::Verifier::new(nv, &cosets, commitment.clone(), oracle, STEP);
    verifier.set_open_point(&opening.shard_point);
    verifier.verify(proof.clone()) && proof.evaluation == opening.value
}

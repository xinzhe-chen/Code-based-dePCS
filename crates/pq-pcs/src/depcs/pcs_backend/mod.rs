//! Artifact-backed PCS backend dispatch used by dePCS workers.
//!
//! Protocol 6-11 should treat this module as the backend boundary. The concrete
//! BaseFold/DeepFold artifact calls live in `basefold.rs` and `deepfold.rs`;
//! this file only dispatches by `PaperPcsBackend` and converts artifact panics
//! into fail-closed dePCS errors.

use std::panic::{AssertUnwindSafe, catch_unwind};

use paper_util::{
    algebra::{coset::Coset, field::MyField},
    random_oracle::RandomOracle,
};

use crate::depcs::backend::PaperPcsBackend;

use super::types::*;
use super::utils::panic_message;

mod basefold;
mod deepfold;

impl PreparedPaperProver {
    pub(crate) fn commitment(&self) -> PaperPcsCommitment {
        match self {
            Self::BaseFold(prover) => PaperPcsCommitment::BaseFold(prover.commit_polynomial()),
            Self::DeepFold(prover) => PaperPcsCommitment::DeepFold(prover.commit_polynomial()),
        }
    }

    pub(crate) fn open(
        self,
        point: &[PaperField],
        evaluation: PaperField,
    ) -> PaperDepcsResult<PaperPcsOpeningProof> {
        // Consume the prepared prover: `prove`/`generate_proof` mutate/consume it,
        // and the worker cache is opened at most once, so taking ownership here
        // avoids the O(domain) deep clone of the codeword + Merkle tree per open.
        match self {
            Self::BaseFold(prover) => Ok(basefold::open_prepared(prover, point, evaluation)),
            Self::DeepFold(prover) => deepfold::open_prepared(prover, point, evaluation),
        }
    }
}

pub(crate) fn prepare_prover(
    config: PaperDepcsConfig,
    nv: usize,
    values: Vec<PaperField>,
    oracle: &RandomOracle<PaperField>,
) -> PreparedPaperProver {
    match config.backend {
        PaperPcsBackend::BaseFold => PreparedPaperProver::BaseFold(basefold::prepare_prover(
            nv,
            values,
            oracle,
            config.code_rate_log(),
        )),
        PaperPcsBackend::DeepFold => PreparedPaperProver::DeepFold(deepfold::prepare_prover(
            nv,
            values,
            oracle,
            config.code_rate_log(),
        )),
    }
}

pub(crate) fn open_polynomial(
    config: PaperDepcsConfig,
    nv: usize,
    values: Vec<PaperField>,
    point: &[PaperField],
    commitment: &PaperPcsCommitment,
    oracle: &RandomOracle<PaperField>,
) -> PaperDepcsResult<PaperPcsOpeningProof> {
    match (config.backend, commitment) {
        (PaperPcsBackend::BaseFold, PaperPcsCommitment::BaseFold(root)) => {
            basefold::open_polynomial(nv, values, point, root, oracle, config.code_rate_log())
        }
        (PaperPcsBackend::DeepFold, PaperPcsCommitment::DeepFold(_expected)) => Ok(
            deepfold::open_polynomial(nv, values, point, oracle, config.code_rate_log()),
        ),
        _ => Err(PaperDepcsError::InvalidBackend),
    }
}

pub(crate) fn verify_worker_opening(
    config: PaperDepcsConfig,
    nv: usize,
    commitment: &PaperPcsCommitment,
    opening: &PaperProtocol11WorkerOpening,
    oracle: &RandomOracle<PaperField>,
) -> PaperDepcsResult<()> {
    let result = catch_unwind(AssertUnwindSafe(|| match (&opening.proof, commitment) {
        (PaperPcsOpeningProof::BaseFold(proof), PaperPcsCommitment::BaseFold(root)) => {
            basefold::verify_opening(nv, root, opening, proof, oracle, config.code_rate_log())
        }
        (PaperPcsOpeningProof::DeepFold(proof), PaperPcsCommitment::DeepFold(commitment)) => {
            deepfold::verify_opening(
                nv,
                commitment,
                opening,
                proof,
                oracle,
                config.code_rate_log(),
            )
        }
        _ => false,
    }));
    match result {
        Ok(true) => Ok(()),
        Ok(false) => Err(PaperDepcsError::InvalidProof),
        Err(error) => Err(PaperDepcsError::ArtifactPanic(panic_message(error))),
    }
}

pub(super) fn interpolate_cosets(nv: usize, code_rate_log: usize) -> Vec<Coset<PaperField>> {
    let mut cosets = vec![Coset::new(
        1 << (nv + code_rate_log),
        PaperField::from_int(1),
    )];
    for index in 1..=nv {
        cosets.push(cosets[index - 1].pow(2));
    }
    cosets
}

/// Verifier-side coset chain that never materializes the O(domain) element
/// tables. The artifact verifier only reads O(query * log N) sampled points via
/// `element_at`/`element_inv_at`, so building the full domain (as the prover must
/// for FFT folding) made verification Θ(N) instead of polylogarithmic.
pub(super) fn interpolate_cosets_lazy(nv: usize, code_rate_log: usize) -> Vec<Coset<PaperField>> {
    let mut cosets = vec![Coset::new_lazy(
        1 << (nv + code_rate_log),
        PaperField::from_int(1),
    )];
    for index in 1..=nv {
        cosets.push(cosets[index - 1].pow_lazy(2));
    }
    cosets
}

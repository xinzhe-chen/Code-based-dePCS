mod chunked_batch;
mod commit;
mod ext;
mod multi;
mod open;
mod verify;

pub use chunked_batch::{
    batch_commit, batch_open, batch_verify,
    chunked_batch_commit, chunked_batch_open, chunked_batch_verify,
    d_chunked_batch_commit, d_chunked_batch_open,
    compute_claimed_values_from_proof,
    DeepFoldBatchCommitment, DeepFoldBatchProverAdvice, DeepFoldBatchProof,
    DeepFoldBatchMultiCommitment, DeepFoldBatchMultiProverAdvice, DeepFoldBatchMultiProof,
    // Multi-commitment batch open
    multi_chunked_batch_open, multi_chunked_batch_verify,
    d_multi_chunked_batch_open,
    MultiChunkedBatchProof,
    // Extension field multi-commitment batch open
    multi_chunked_batch_open_at_ext_point, d_multi_chunked_batch_open_at_ext_point, multi_chunked_batch_verify_at_ext_point,
    MultiChunkedBatchExtProof,
};
pub use commit::{deepfold_commit, deepfold_d_commit, deepfold_d_commit_v2, deepfold_batch_d_commit_v2, deepfold_d_commit_full_poly_v2};
pub use multi::{
    split_polynomial, multi_commit, d_multi_commit_v2, compute_eq_at_chunk, combine_chunk_values,
    split_point_for_chunks, expand_for_batch_open,
    compute_eq_at_chunk_ext, combine_chunk_values_ext, expand_for_batch_open_ext,
};
pub use ext::{
    deepfold_batch_open_at_ext_point, deepfold_batch_verify_at_ext_point,
    deepfold_d_batch_open_at_ext_point,
    deepfold_open_at_ext_point, deepfold_verify_at_ext_point, DeepFoldExtBatchedProof,
    DeepFoldExtProof,
};
pub use open::{deepfold_batch_open, deepfold_d_batch_open, deepfold_d_open, deepfold_open};
pub use verify::{deepfold_batch_verify, deepfold_verify};

use crate::{
    errors::PCSError,
    hash::*,
    types::HasQuadraticExtension,
    utils::*,
    IOPProof, PolynomialCommitmentScheme,
};
use ark_ff::PrimeField;
use ark_poly::{DenseMultilinearExtension, EvaluationDomain, GeneralEvaluationDomain};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::{borrow::Borrow, marker::PhantomData, rand::Rng, sync::Arc, vec::Vec};
use transcript::IOPTranscript;

#[cfg(test)]
mod tests;
pub(crate) mod utils;

/// DeepFold Polynomial Commitment Scheme
pub struct DeepFoldPCS<F: PrimeField> {
    #[doc(hidden)]
    phantom: PhantomData<F>,
}

#[derive(CanonicalSerialize, CanonicalDeserialize, Clone, Debug, Copy)]
pub struct DeepFoldSRS<F: PrimeField> {
    pub max_mu: usize,
    pub l0: GeneralEvaluationDomain<F>,
    pub s: usize,
    /// Code rate multiplier (e.g., 4 for 1/4 rate, 8 for 1/8 rate)
    /// len_l0 = (1 << max_mu) * rate
    pub rate: usize,
}

impl<F: PrimeField> Default for DeepFoldSRS<F> {
    fn default() -> Self {
        DeepFoldSRS {
            max_mu: 0,
            l0: GeneralEvaluationDomain::<F>::new(1).unwrap(),
            s: 0,
            rate: 4,  // default to 1/4 rate
        }
    }
}

#[derive(Clone)]
pub struct DeepFoldProverParam<F: PrimeField> {
    pub max_mu: usize,
    pub l0: GeneralEvaluationDomain<F>,
    pub s: usize,
}

#[derive(Clone, CanonicalSerialize, CanonicalDeserialize)]
pub struct DeepFoldVerifierParam<F: PrimeField> {
    pub max_mu: usize,
    pub len_l0: usize,
    pub g: F,
    pub s: usize,
}

#[derive(CanonicalSerialize, CanonicalDeserialize, Clone, Debug, PartialEq, Eq)]
/// proof of opening
pub struct DeepFoldProof<F: PrimeField> {
    pub linear_polys: Vec<Vec<(F, F)>>,
    pub mt_roots: Vec<Byte32>,
    pub f_mu: F,
    pub mt_proofs: Vec<Vec<(usize, (F, F), Vec<F>, Vec<Byte32>)>>,
}

#[derive(CanonicalSerialize, CanonicalDeserialize, Clone, Debug, PartialEq, Eq)]
pub struct DeepFoldBatchedProof<F: PrimeField> {
    pub deepfold_proof: DeepFoldProof<F>,
    pub sum_check_proof: IOPProof<F>,
    pub mt_proofs_for_mt0: Vec<Vec<(Vec<F>, Vec<Byte32>)>>,
    pub evals: Vec<F>,
    pub sum_check_evals: Vec<F>,
}

#[derive(CanonicalSerialize, CanonicalDeserialize, Clone, Debug, PartialEq, Eq, Default)]
pub struct DeepFoldProverCommitmentAdvice<F: PrimeField> {
    pub f0: Vec<F>,
    pub mt0: MerkleTree,
    pub v0: Vec<F>,
    /// Full polynomial evaluations for distributed setting (only master has this)
    pub f_tilde: Vec<F>,
    /// Upper tree for distributed setting (only master has this)
    pub upper_tree: Option<MerkleTree>,
}

#[derive(CanonicalSerialize, CanonicalDeserialize, Clone, Debug, PartialEq, Eq, Default)]
pub struct DeepFoldCommitment {
    pub mu: usize,
    pub rt0: Byte32,
}

impl<F: PrimeField> DeepFoldPCS<F> {
    pub fn compute_value_from_proof(point: &Vec<F>, proof: &DeepFoldProof<F>) -> F {
        eval_linear_poly(&proof.linear_polys[0][0], &point[0])
    }

    /// Compute the claimed value from a distributed proof
    /// In the distributed setting, the proof structure is the same, so we just use the first linear polynomial
    pub fn compute_value_from_proof_distributed(
        point: &Vec<F>,
        proof: &DeepFoldProof<F>,
        _num_party: usize,
    ) -> F {
        eval_linear_poly(&proof.linear_polys[0][0], &point[0])
    }

    /// Generate SRS with configurable code rate.
    ///
    /// - `log_size`: Number of polynomial variables (max_mu)
    /// - `rate`: Code rate multiplier (e.g., 4 for 1/4 rate, 8 for 1/8 rate)
    ///
    /// Higher rate means more redundancy but larger proof size.
    /// Lower rate means less redundancy but smaller memory/communication cost.
    pub fn gen_srs_with_rate<R: Rng>(
        _rng: &mut R,
        log_size: usize,
        rate: usize,
    ) -> Result<DeepFoldSRS<F>, PCSError> {
        let max_mu = log_size;
        let len_l0 = (1 << max_mu) * rate;
        let l0 = GeneralEvaluationDomain::<F>::new(len_l0).unwrap();
        let s = 33;
        Ok(DeepFoldSRS { max_mu, l0, s, rate })
    }
}

impl<F: PrimeField> PolynomialCommitmentScheme<F> for DeepFoldPCS<F> {
    // Parameters
    type ProverParam = DeepFoldProverParam<F>;
    type VerifierParam = DeepFoldVerifierParam<F>;
    type SRS = DeepFoldSRS<F>;
    // Polynomial and its associated types
    type Polynomial = Arc<DenseMultilinearExtension<F>>;
    type ProverCommitmentAdvice = DeepFoldProverCommitmentAdvice<F>;
    type Point = Vec<F>;
    type Evaluation = F;
    // Commitments and proofs
    type Commitment = DeepFoldCommitment; // merkle tree root
    type Proof = DeepFoldProof<F>;        // merkle tree paths, columes of `E`
    type BatchProof = DeepFoldBatchedProof<F>;

    fn gen_srs_for_testing<R: Rng>(_rng: &mut R, log_size: usize) -> Result<Self::SRS, PCSError> {
        Self::gen_srs_with_rate(_rng, log_size, 4)  // default to 1/4 rate
    }

    fn setup(
        srs: impl Borrow<Self::SRS>,
    ) -> Result<(Self::ProverParam, Self::VerifierParam), PCSError> {
        let srs = srs.borrow();
        Ok((
            DeepFoldProverParam {
                max_mu: srs.max_mu,
                l0: srs.l0,
                s: srs.s,
            },
            DeepFoldVerifierParam {
                max_mu: srs.max_mu,
                len_l0: srs.l0.size(),
                g: srs.l0.element(1),
                s: srs.s,
            },
        ))
    }

    fn commit(
        prover_param: impl Borrow<Self::ProverParam>,
        poly: &Self::Polynomial,
    ) -> Result<(Self::Commitment, Self::ProverCommitmentAdvice), PCSError> {
        deepfold_commit(prover_param.borrow(), poly)
    }

    fn d_commit(
        prover_param: impl Borrow<Self::ProverParam>,
        poly: &Self::Polynomial,
    ) -> Result<(Option<Self::Commitment>, Self::ProverCommitmentAdvice), PCSError> {
        deepfold_d_commit(prover_param.borrow(), poly)
    }

    fn open(
        prover_param: impl Borrow<Self::ProverParam>,
        poly: &Self::Polynomial,
        advice: &Self::ProverCommitmentAdvice,
        point: &Self::Point,
        transcript: &mut IOPTranscript<F>,
    ) -> Result<Self::Proof, PCSError> {
        deepfold_open(prover_param.borrow(), poly, advice, point, transcript)
    }

    fn d_open(
        prover_param: impl Borrow<Self::ProverParam>,
        poly: &Self::Polynomial,
        advice: &Self::ProverCommitmentAdvice,
        point: &Self::Point,
        transcript: &mut IOPTranscript<F>,
    ) -> Result<Option<Self::Proof>, PCSError> {
        deepfold_d_open(prover_param.borrow(), poly, advice, point, transcript)
    }

    fn batch_open(
        prover_param: impl Borrow<Self::ProverParam>,
        polynomials: Vec<Self::Polynomial>,
        advices: &[&Self::ProverCommitmentAdvice],
        points: &[Self::Point],
        _evals: &[Self::Evaluation],
        transcript: &mut IOPTranscript<F>,
    ) -> Result<Self::BatchProof, PCSError> {
        deepfold_batch_open(prover_param.borrow(), polynomials, advices, points, transcript)
    }

    fn d_batch_open(
        prover_param: impl Borrow<Self::ProverParam>,
        polynomials: Vec<Self::Polynomial>,
        advices: &[&Self::ProverCommitmentAdvice],
        points: &[Self::Point],
        _evals: &[Self::Evaluation],
        transcript: &mut IOPTranscript<F>,
    ) -> Result<Option<Self::BatchProof>, PCSError> {
        deepfold_d_batch_open(prover_param.borrow(), polynomials, advices, points, transcript)
    }

    fn verify(
        verifier_param: &Self::VerifierParam,
        com: &Self::Commitment,
        point: &Self::Point,
        value: &F,
        proof: &Self::Proof,
        transcript: &mut IOPTranscript<F>,
    ) -> Result<bool, PCSError> {
        deepfold_verify(verifier_param, com, point, value, proof, transcript)
    }

    fn batch_verify(
        verifier_param: &Self::VerifierParam,
        commitments: &[Self::Commitment],
        points: &[Self::Point],
        batch_proof: &Self::BatchProof,
        transcript: &mut IOPTranscript<F>,
    ) -> Result<bool, PCSError> {
        deepfold_batch_verify(verifier_param, commitments, points, batch_proof, transcript)
    }
}

// =============================================================================
// Extension Field Point Opening Support
// =============================================================================

impl<F: PrimeField + HasQuadraticExtension> DeepFoldPCS<F> {
    /// Open a base field polynomial at an extension field point
    ///
    /// This achieves 128-bit soundness by using extension field challenges
    /// during the folding process while keeping base field Merkle commitments.
    #[allow(non_snake_case)]
    pub fn open_at_ext_point(
        prover_param: &DeepFoldProverParam<F>,
        poly: &Arc<DenseMultilinearExtension<F>>,
        advice: &DeepFoldProverCommitmentAdvice<F>,
        point: &[F::Extension],
        transcript: &mut IOPTranscript<F>,
    ) -> Result<DeepFoldExtProof<F>, PCSError> {
        deepfold_open_at_ext_point(prover_param, poly, advice, point, transcript)
    }

    /// Verify an extension field proof
    #[allow(non_snake_case)]
    pub fn verify_at_ext_point(
        verifier_param: &DeepFoldVerifierParam<F>,
        com: &DeepFoldCommitment,
        point: &[F::Extension],
        value: &F::Extension,
        proof: &DeepFoldExtProof<F>,
        transcript: &mut IOPTranscript<F>,
    ) -> Result<bool, PCSError> {
        deepfold_verify_at_ext_point(verifier_param, com, point, value, proof, transcript)
    }

    /// Batch open at extension field points
    #[allow(non_snake_case)]
    pub fn batch_open_at_ext_point(
        prover_param: &DeepFoldProverParam<F>,
        polynomials: Vec<Arc<DenseMultilinearExtension<F>>>,
        advices: &[&DeepFoldProverCommitmentAdvice<F>],
        points: &[Vec<F::Extension>],
        transcript: &mut IOPTranscript<F>,
    ) -> Result<DeepFoldExtBatchedProof<F>, PCSError> {
        deepfold_batch_open_at_ext_point(prover_param, polynomials, advices, points, transcript)
    }

    /// Batch verify at extension field points
    #[allow(non_snake_case)]
    pub fn batch_verify_at_ext_point(
        verifier_param: &DeepFoldVerifierParam<F>,
        commitments: &[DeepFoldCommitment],
        points: &[Vec<F::Extension>],
        batch_proof: &DeepFoldExtBatchedProof<F>,
        transcript: &mut IOPTranscript<F>,
    ) -> Result<bool, PCSError> {
        deepfold_batch_verify_at_ext_point(verifier_param, commitments, points, batch_proof, transcript)
    }
}

//! LigeSIS Polynomial Commitment Scheme
//!
//! This crate provides implementations of polynomial commitment schemes,
//! including LigeSIS, DeepFold, and Ligero.

#![feature(test)]

// Core modules
mod errors;
mod iop_errors;
mod structs;
mod types;

// PCS implementations
pub mod deepfold;
pub mod hash;
pub mod ligero;
pub mod ligesis;

// Supporting modules
mod rand;
mod rscode;
mod utils;
mod poly_utils;
pub mod sumcheck;
pub mod ext_sumcheck;

// Re-exports
pub use errors::PCSError;
pub use iop_errors::PolyIOPErrors;
pub use structs::IOPProof;
pub use types::{FGoldilocks, EGoldilocks, FieldExtension, HasQuadraticExtension};

pub use deepfold::*;
pub use hash::{Byte32, MerkleTree, compute_sha256, compute_sha256_row};
pub use ligero::*;
pub use ligesis::*;
pub use rand::*;
pub use rscode::*;
pub use utils::*;
pub use poly_utils::*;
pub use sumcheck::SumCheck;
pub use sumcheck::generic_sumcheck::{SumcheckInstanceProof, ZerocheckInstanceProof};

// PCS trait
use ark_ff::{Field, PrimeField};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::rand::Rng;
use std::{borrow::Borrow, fmt::Debug, hash::Hash};
use transcript::IOPTranscript;

/// Struct for PolyIOP protocol.
#[derive(Clone, Debug, Default, Copy, PartialEq, Eq)]
pub struct PolyIOP<F: PrimeField> {
    #[doc(hidden)]
    phantom: std::marker::PhantomData<F>,
}

/// This trait defines APIs for polynomial commitment schemes.
pub trait PolynomialCommitmentScheme<F: PrimeField> {
    /// Prover parameters
    type ProverParam: Clone + Sync;
    /// Verifier parameters
    type VerifierParam: Clone + CanonicalSerialize + CanonicalDeserialize;
    /// Structured reference string
    type SRS: Clone + Debug;
    /// Polynomial and its associated types
    type Polynomial: Clone + Debug + Hash + PartialEq + Eq;
    /// Polynomial input domain
    type Point: Clone + Ord + Debug + Sync + Hash + PartialEq + Eq;
    /// Polynomial Evaluation
    type Evaluation: Field;
    /// Commitments
    type Commitment: Clone
        + CanonicalSerialize
        + CanonicalDeserialize
        + Debug
        + PartialEq
        + Eq
        + Send
        + Default;
    type ProverCommitmentAdvice: Clone + Send + Sync + Default + Debug;
    /// Proofs
    type Proof: Clone + CanonicalSerialize + CanonicalDeserialize + Debug + PartialEq + Eq;
    /// Batch proofs
    type BatchProof: CanonicalSerialize + CanonicalDeserialize;

    /// Build SRS for testing.
    fn gen_srs_for_testing<R: Rng>(
        rng: &mut R,
        supported_size: usize,
    ) -> Result<Self::SRS, PCSError>;

    /// Setup parameters from SRS.
    fn setup(
        srs: impl Borrow<Self::SRS>,
    ) -> Result<(Self::ProverParam, Self::VerifierParam), PCSError>;

    /// Generate a commitment for a polynomial.
    fn commit(
        _prover_param: impl Borrow<Self::ProverParam>,
        _poly: &Self::Polynomial,
    ) -> Result<(Self::Commitment, Self::ProverCommitmentAdvice), PCSError> {
        unimplemented!();
    }

    /// Distributed commit.
    fn d_commit(
        _prover_param: impl Borrow<Self::ProverParam>,
        _poly: &Self::Polynomial,
    ) -> Result<(Option<Self::Commitment>, Self::ProverCommitmentAdvice), PCSError> {
        unimplemented!();
    }

    /// Batch distributed commit.
    fn batch_d_commit(
        prover_param: impl Borrow<Self::ProverParam>,
        polys: &[Self::Polynomial],
        _transcript: &mut IOPTranscript<F>,
    ) -> Result<
        (
            Vec<Option<Self::Commitment>>,
            Vec<Self::ProverCommitmentAdvice>,
        ),
        PCSError,
    > {
        let (comms, advices) = polys
            .iter()
            .map(|poly| Self::d_commit(prover_param.borrow(), poly))
            .collect::<Result<Vec<_>, _>>()?
            .into_iter()
            .unzip();
        Ok((comms, advices))
    }

    /// Open a polynomial at a point.
    fn open(
        prover_param: impl Borrow<Self::ProverParam>,
        polynomial: &Self::Polynomial,
        prover_advice: &Self::ProverCommitmentAdvice,
        point: &Self::Point,
        transcript: &mut IOPTranscript<F>,
    ) -> Result<Self::Proof, PCSError>;

    /// Distributed open.
    fn d_open(
        _prover_param: impl Borrow<Self::ProverParam>,
        _polynomial: &Self::Polynomial,
        _prover_advice: &Self::ProverCommitmentAdvice,
        _point: &Self::Point,
        _transcript: &mut IOPTranscript<F>,
    ) -> Result<Option<Self::Proof>, PCSError> {
        unimplemented!()
    }

    /// Batch open for multiple polynomials.
    fn batch_open(
        _prover_param: impl Borrow<Self::ProverParam>,
        _polynomials: Vec<Self::Polynomial>,
        _advices: &[&Self::ProverCommitmentAdvice],
        _points: &[Self::Point],
        _evals: &[Self::Evaluation],
        _transcript: &mut IOPTranscript<F>,
    ) -> Result<Self::BatchProof, PCSError> {
        unimplemented!()
    }

    /// Distributed batch open.
    fn d_batch_open(
        _prover_param: impl Borrow<Self::ProverParam>,
        _polynomials: Vec<Self::Polynomial>,
        _advices: &[&Self::ProverCommitmentAdvice],
        _points: &[Self::Point],
        _evals: &[Self::Evaluation],
        _transcript: &mut IOPTranscript<F>,
    ) -> Result<Option<Self::BatchProof>, PCSError> {
        unimplemented!();
    }

    /// Verify a proof.
    fn verify(
        verifier_param: &Self::VerifierParam,
        commitment: &Self::Commitment,
        point: &Self::Point,
        value: &F,
        proof: &Self::Proof,
        transcript: &mut IOPTranscript<F>,
    ) -> Result<bool, PCSError>;

    /// Batch verify.
    fn batch_verify(
        _verifier_param: &Self::VerifierParam,
        _commitments: &[Self::Commitment],
        _points: &[Self::Point],
        _batch_proof: &Self::BatchProof,
        _transcript: &mut IOPTranscript<F>,
    ) -> Result<bool, PCSError> {
        unimplemented!()
    }
}

/// API definitions for structured reference string
pub trait StructuredReferenceString<F: PrimeField>: Sized {
    type ProverParam;
    type VerifierParam;

    fn extract_prover_param(&self, supported_size: usize) -> Self::ProverParam;
    fn extract_verifier_param(&self, supported_size: usize) -> Self::VerifierParam;

    fn trim(
        &self,
        supported_size: usize,
    ) -> Result<(Self::ProverParam, Self::VerifierParam), PCSError>;

    fn gen_srs_for_testing<R: Rng>(rng: &mut R, supported_size: usize) -> Result<Self, PCSError>;
}

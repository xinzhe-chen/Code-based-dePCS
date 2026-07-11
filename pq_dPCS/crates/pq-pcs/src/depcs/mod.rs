//! Distributed PCS implementations.
//!
//! `protocol11` is the normative Protocol 6--11 implementation. It uses real
//! matrix encoding, column and vector Merkle commitments, four independent
//! polynomial-commitment families, distributed sumcheck, and an external
//! `(commitment, point, value)` verification statement.

pub mod backend;
mod compact_codec;
mod pcs_backend;
pub mod protocol11;
mod types;
mod utils;

pub use backend::{
    PAPER_PCS_DEFAULT_CODE_RATE_LOG, PAPER_PCS_HASH, PAPER_PCS_LICENSE, PAPER_PCS_SECURITY_BITS,
    PAPER_PCS_SOURCE_REV, PAPER_PCS_SOURCE_URL, PaperPcsBackend, PaperQueryPolicy,
    paper_fair_query_count, paper_query_count, paper_query_count_for_code_rate,
};
pub use protocol11::{
    BrakedownCode, EncodingRelation, GlobalPolynomial, PaperLayout, Protocol10Proof,
    Protocol11Commitment, Protocol11Config, Protocol11Error, Protocol11Event, Protocol11Proof,
    Protocol11ProverSession, Protocol11VerifierSession, PublicParameters, SecurityBudget,
    SecurityProfile, WorkerCommitment, WorkerProverState, WorkerShard, aggregate_commitments,
    commit_global, commit_worker, deserialize_commitment, deserialize_proof, proof_size_bytes,
    prove_fs, serialize_commitment, serialize_proof, setup, verify_fs,
};
pub use types::{PaperField, PaperPcsCommitment, PaperPcsOpeningProof};

pub const PAPER_DEPCS_SOURCE_URL: &str = crate::depcs::backend::PAPER_PCS_SOURCE_URL;
pub const PAPER_DEPCS_SOURCE_REV: &str = crate::depcs::backend::PAPER_PCS_SOURCE_REV;
pub const PAPER_DEPCS_LICENSE: &str = crate::depcs::backend::PAPER_PCS_LICENSE;
pub const PAPER_DEPCS_HASH: &str = crate::depcs::backend::PAPER_PCS_HASH;

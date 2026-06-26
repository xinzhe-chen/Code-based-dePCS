//! Artifact-backed dePCS implementation.
//!
//! The submodules mirror Protocol 6 through Protocol 11 from
//! `Doc/papers/pq_dSNARK.pdf`. This refactor is intentionally structural: public CLI,
//! benchmark CSV fields, transcript labels, proof serialization, timing points,
//! and communication accounting stay unchanged.

mod pcs_backend;
mod proof_size;
mod protocol10_encoding;
mod protocol11_distributed_brakedown;
pub mod protocol6_composition;
pub mod protocol7_merkle_commitments;
pub mod protocol8_e_commitments;
pub mod protocol9_f_commitments;
mod types;
mod utils;

pub use proof_size::{
    PaperProofSizeBreakdown, commitment_size_bytes, proof_size_breakdown, proof_size_bytes,
};
pub use protocol11_distributed_brakedown::{
    assemble_opening, commit_from_worker_commitments, commit_worker, commit_worker_cached,
    open_worker, open_worker_cached, sample_point, verify, worker_coefficients,
};
pub use types::*;

pub const PAPER_DEPCS_SOURCE_URL: &str = crate::artifact::PAPER_PCS_SOURCE_URL;
pub const PAPER_DEPCS_SOURCE_REV: &str = crate::artifact::PAPER_PCS_SOURCE_REV;
pub const PAPER_DEPCS_LICENSE: &str = crate::artifact::PAPER_PCS_LICENSE;
pub const PAPER_DEPCS_HASH: &str = crate::artifact::PAPER_PCS_HASH;

#[cfg(test)]
mod tests;

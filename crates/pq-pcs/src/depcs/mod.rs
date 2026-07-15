//! Artifact-backed dePCS implementation.
//!
//! The submodules mirror Protocol 6 through Protocol 11 from
//! the Code-based dePCS design. Public CLI, benchmark CSV fields, transcript
//! labels, proof serialization, timing points, and communication accounting are
//! kept stable across internal refactors.

pub mod backend;
mod compact_codec;
mod pcs_backend;
mod proof_size;
mod protocol10_encoding;
mod protocol11_distributed_brakedown;
mod protocol6_composition;
mod protocol7_merkle_commitments;
mod protocol8_e_commitments;
mod protocol9_f_commitments;
mod types;
mod utils;

pub use backend::{
    PAPER_PCS_DEFAULT_CODE_RATE_LOG, PAPER_PCS_HASH, PAPER_PCS_LICENSE, PAPER_PCS_SECURITY_BITS,
    PAPER_PCS_SOURCE_REV, PAPER_PCS_SOURCE_URL, PaperPcsBackend, PaperQueryPolicy,
    paper_fair_query_count, paper_query_count, paper_query_count_for_code_rate,
};
pub use proof_size::{
    PaperProofSizeBreakdown, commitment_size_bytes, proof_size_breakdown, proof_size_bytes,
};
pub use protocol11_distributed_brakedown::{
    assemble_opening, commit_from_worker_commitments, commit_worker, commit_worker_cached,
    open_worker, open_worker_cached, sample_point, verify, worker_coefficients,
};
pub use types::*;

pub const PAPER_DEPCS_SOURCE_URL: &str = crate::depcs::backend::PAPER_PCS_SOURCE_URL;
pub const PAPER_DEPCS_SOURCE_REV: &str = crate::depcs::backend::PAPER_PCS_SOURCE_REV;
pub const PAPER_DEPCS_LICENSE: &str = crate::depcs::backend::PAPER_PCS_LICENSE;
pub const PAPER_DEPCS_HASH: &str = crate::depcs::backend::PAPER_PCS_HASH;

#[cfg(test)]
mod tests;

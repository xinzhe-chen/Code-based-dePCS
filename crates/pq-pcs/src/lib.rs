//! Public entry point for the `pq-pcs` crate.
//!
//! The active artifact-backed dePCS implementation is organized under
//! `depcs/` by pq_dSNARK Protocol 6 through Protocol 11. The historical
//! Goldilocks/local compatibility implementation is kept under `legacy/` and
//! re-exported here so existing callers and benchmark code keep the same API.

pub mod artifact;
pub mod depcs;
pub mod legacy;

pub use artifact as paper;
pub use legacy::deepfold;
pub use legacy::protocol11_local::*;

pub(crate) use legacy::protocol11_local::MerkleTree;

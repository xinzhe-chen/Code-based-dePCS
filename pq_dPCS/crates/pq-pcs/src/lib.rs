//! Public entry point for the `pq-pcs` crate.
//!
//! The active `protocol11` dePCS implementation is organized under
//! `depcs::protocol11` by pq_dSNARK Protocol 6 through Protocol 11.

// Test code uses `unwrap()` freely; the workspace denies `unwrap_used` for
// non-test code only.
#![cfg_attr(test, allow(clippy::unwrap_used))]

pub mod depcs;
mod hash;

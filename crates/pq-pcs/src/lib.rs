//! Public entry point for the `pq-pcs` crate.
//!
//! The active artifact-backed dePCS implementation is organized under
//! `depcs/` by Code-based dePCS Protocol 6 through Protocol 11.

// Test code uses `unwrap()` freely; the workspace denies `unwrap_used` for
// non-test code only.
#![cfg_attr(test, allow(clippy::unwrap_used))]

pub mod depcs;
mod hash;

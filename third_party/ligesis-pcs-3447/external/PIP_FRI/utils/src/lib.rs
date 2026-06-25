pub mod fp17;
// pub mod fp64;

pub mod commit_open_vec;
pub mod fiat_shamir;
pub mod goldilocks;
pub mod helper;
pub mod interpolate_vecs_value;
pub mod merkle_tree;
pub mod query_result;
pub mod time_logger;

pub const CODE_RATE: usize = 2;
pub const SECURITY_BITS: usize = 100;

use ark_ff::fields::{Field, Fp64, MontBackend};

#[derive(ark_ff::MontConfig)]
#[modulus = "18446744069414584321"]
#[generator = "7"]
pub struct FqConfig;
pub type Goldilocks = Fp64<MontBackend<FqConfig, 1>>;

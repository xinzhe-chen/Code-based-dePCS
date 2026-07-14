use ark_ff::fields::{Field, Fp64, MontBackend};

#[derive(ark_ff::MontConfig)]
#[modulus = "17"]
#[generator = "3"]
pub struct FqConfig;
pub type Fp17 = Fp64<MontBackend<FqConfig, 1>>;


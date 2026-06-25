// use ark_ff::{fields::*, Field, Fp2Config, Fp4Config, MontConfig, MontFp};

use ark_ff::fields::{Fp64, MontBackend, MontConfig};

#[derive(MontConfig)]
#[modulus = "18446744069414584321"]
#[generator = "7"]
pub struct FGoldilocksConfig;
pub type FGoldilocks = Fp64<MontBackend<FGoldilocksConfig, 1>>;

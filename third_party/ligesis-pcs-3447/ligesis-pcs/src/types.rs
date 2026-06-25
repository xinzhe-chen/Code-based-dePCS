use ark_ff::fields::{Fp64, MontBackend, MontConfig};
use ark_ff::fields::fp2::{Fp2, Fp2Config};
use ark_ff::MontFp;

#[derive(MontConfig)]
#[modulus = "18446744069414584321"]
#[generator = "7"]
pub struct FGoldilocksConfig;
pub type FGoldilocks = Fp64<MontBackend<FGoldilocksConfig, 1>>;

/// Quadratic extension of Goldilocks field: EGoldilocks = FGoldilocks[u] / (u^2 - 7)
/// where 7 is a quadratic non-residue in FGoldilocks
pub struct EGoldilocksConfig;

impl Fp2Config for EGoldilocksConfig {
    type Fp = FGoldilocks;

    /// 7 is a quadratic non-residue in FGoldilocks
    /// i.e., x^2 - 7 is irreducible over FGoldilocks
    const NONRESIDUE: FGoldilocks = MontFp!("7");

    /// FROBENIUS_COEFF_FP2_C1[i] = NONRESIDUE^((p^i - 1) / 2)
    /// For i=0: 1
    /// For i=1: NONRESIDUE^((p-1)/2) = -1 (since NONRESIDUE is a non-residue)
    const FROBENIUS_COEFF_FP2_C1: &'static [FGoldilocks] = &[
        MontFp!("1"),
        MontFp!("18446744069414584320"),  // p - 1 = -1
    ];
}

pub type EGoldilocks = Fp2<EGoldilocksConfig>;

/// Trait for embedding base field into extension field
pub trait FieldExtension<F>: Sized {
    fn from_base(x: F) -> Self;
}

impl FieldExtension<FGoldilocks> for EGoldilocks {
    fn from_base(x: FGoldilocks) -> Self {
        Fp2::new(x, FGoldilocks::ZERO)
    }
}

/// Trait for fields that have a quadratic extension.
/// This associates a base field with its extension field.
pub trait HasQuadraticExtension: ark_ff::PrimeField {
    /// The quadratic extension field type
    type Extension: ark_ff::Field
        + FieldExtension<Self>
        + Copy
        + ark_serialize::CanonicalSerialize
        + ark_serialize::CanonicalDeserialize
        + Default;

    /// The non-residue used for the extension (u² = gamma)
    const GAMMA: u64;

    /// Extract real part from extension field element
    fn ext_real(x: &Self::Extension) -> Self;

    /// Extract imaginary part from extension field element
    fn ext_imag(x: &Self::Extension) -> Self;

    /// Create extension field element from real and imaginary parts
    fn ext_from_parts(real: Self, imag: Self) -> Self::Extension;
}

impl HasQuadraticExtension for FGoldilocks {
    type Extension = EGoldilocks;
    const GAMMA: u64 = 7;

    fn ext_real(x: &Self::Extension) -> Self {
        x.c0
    }

    fn ext_imag(x: &Self::Extension) -> Self {
        x.c1
    }

    fn ext_from_parts(real: Self, imag: Self) -> Self::Extension {
        Fp2::new(real, imag)
    }
}

use ff::{Field as Fd, PrimeField};
use ff_derive_num::Num;
use serde::{de::Error as _, Deserialize, Deserializer, Serialize, Serializer};
use sha2::{Digest, Sha256};

use super::MyField;

#[derive(PrimeField, Num)]
#[PrimeFieldModulus = "46242760681095663677370860714659204618859642560429202607213929836750194081793"]
#[PrimeFieldGenerator = "5"]
#[PrimeFieldReprEndianness = "little"]
pub struct Ft255([u64; 4]);

impl Serialize for Ft255 {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.to_full_bytes().serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for Ft255 {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let bytes = <[u8; 32]>::deserialize(deserializer)?;
        Self::try_from_full_bytes(bytes)
            .ok_or_else(|| D::Error::custom("non-canonical Ft255 encoding"))
    }
}

impl std::fmt::Display for Ft255 {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{:?}", self.0)
    }
}

const INVERSE_2: Ft255 = Ft255([
    18256200907639226367,
    1192390052779827407,
    168358299667310230,
    1856475237906044671,
]);

impl Ft255 {
    /// Compatibility constructor for protocol fixtures that previously used
    /// the two coordinates of `Mersenne61Ext`.  The pair is interpreted as a
    /// canonical 128-bit little-endian integer in the prime field.
    pub fn from_parts(low: u64, high: u64) -> Self {
        let mut bytes = [0_u8; 32];
        bytes[..8].copy_from_slice(&low.to_le_bytes());
        bytes[8..16].copy_from_slice(&high.to_le_bytes());
        Self::try_from_full_bytes(bytes).expect("a 128-bit integer is canonical in Ft255")
    }

    pub fn to_full_bytes(&self) -> [u8; 32] {
        let repr = self.to_repr();
        let mut bytes = [0_u8; 32];
        bytes.copy_from_slice(repr.as_ref());
        bytes
    }

    pub fn try_from_full_bytes(bytes: [u8; 32]) -> Option<Self> {
        let mut repr = <Self as PrimeField>::Repr::default();
        repr.as_mut().copy_from_slice(&bytes);
        Option::<Self>::from(Self::from_repr(repr))
    }
}

impl MyField for Ft255 {
    const FIELD_NAME: &'static str = "Ft255";
    const LOG_ORDER: u64 = 41;
    #[inline(always)]
    fn root_of_unity() -> Self {
        ROOT_OF_UNITY
    }
    #[inline(always)]
    fn inverse_2() -> Self {
        INVERSE_2
    }
    #[inline(always)]
    fn from_int(x: u64) -> Self {
        x.into()
    }
    #[inline(always)]
    fn from_hash(hash: [u8; crate::merkle_tree::MERKLE_ROOT_SIZE]) -> Self {
        // Masking gives a uniform 255-bit candidate.  Rejection followed by
        // SHA-256 re-expansion is unbiased over the canonical field range.
        let mut block = hash;
        loop {
            block[31] &= 0x7f;
            if let Some(value) = Self::try_from_full_bytes(block) {
                return value;
            }
            block = Sha256::digest(block).into();
        }
    }
    #[inline(always)]
    fn is_zero(&self) -> bool {
        for i in self.0 {
            if i != 0 {
                return false;
            }
        }
        true
    }
    #[inline(always)]
    fn random_element() -> Self {
        Ft255::random(rand::thread_rng())
    }
    #[inline(always)]
    fn inverse(&self) -> Self {
        self.invert().unwrap()
    }
    #[inline(always)]
    fn to_bytes(&self) -> Vec<u8> {
        self.to_full_bytes().to_vec()
    }
}

#[cfg(test)]
mod tests {
    use super::super::field_tests::*;
    use super::*;

    #[test]
    fn test() {
        add_and_sub::<Ft255>();
        mult_and_inverse::<Ft255>();
        assigns::<Ft255>();
        pow_and_generator::<Ft255>();
    }

    #[test]
    fn canonical_encoding_round_trip_and_rejection() {
        let value = Ft255::from_parts(7, 11);
        assert_eq!(
            Ft255::try_from_full_bytes(value.to_full_bytes()),
            Some(value)
        );

        // The modulus in little-endian form is not a canonical field element.
        let modulus_bytes =
            hex::decode("0100000000f2a402305f598690c773ef695957b904dfa9fd00294d6e9b793c66")
                .expect("hex");
        let mut bytes = [0_u8; 32];
        bytes.copy_from_slice(&modulus_bytes);
        assert_eq!(Ft255::try_from_full_bytes(bytes), None);
    }
}

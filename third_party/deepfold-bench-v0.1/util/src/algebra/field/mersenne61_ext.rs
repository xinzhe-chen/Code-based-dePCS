use super::MyField;
#[cfg(target_arch = "x86_64")]
use core::arch::x86_64::_mulx_u64;
use rand::Rng;
use serde::{de::Error as _, Deserialize, Deserializer, Serialize};
use sha2::{Digest, Sha256};

#[derive(Debug, Clone, Copy, Eq, Hash, Serialize)]
pub struct Mersenne61Ext {
    pub real: u64,
    pub image: u64,
}

impl<'de> Deserialize<'de> for Mersenne61Ext {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        struct Coordinates {
            real: u64,
            image: u64,
        }

        let coordinates = Coordinates::deserialize(deserializer)?;
        if coordinates.real >= MOD || coordinates.image >= MOD {
            return Err(D::Error::custom("non-canonical Mersenne61Ext coordinate"));
        }
        Ok(Self {
            real: coordinates.real,
            image: coordinates.image,
        })
    }
}

pub const MODULUS: u64 = (1u64 << 61) - 1;
const MOD: u64 = MODULUS;

#[inline]
fn try_sub(x: u64) -> u64 {
    if x >= MOD {
        x - MOD
    } else {
        x
    }
}

impl std::ops::Neg for Mersenne61Ext {
    type Output = Self;
    fn neg(self) -> Self::Output {
        Self {
            real: try_sub(self.real ^ MOD),
            image: try_sub(self.image ^ MOD),
        }
    }
}

impl std::ops::Add for Mersenne61Ext {
    type Output = Self;
    fn add(self, rhs: Self) -> Self::Output {
        Self {
            real: try_sub(self.real + rhs.real),
            image: try_sub(self.image + rhs.image),
        }
    }
}

impl std::ops::AddAssign for Mersenne61Ext {
    fn add_assign(&mut self, rhs: Self) {
        *self = *self + rhs;
    }
}

impl std::ops::Sub for Mersenne61Ext {
    type Output = Self;
    fn sub(self, rhs: Self) -> Self::Output {
        let mut real = self.real + (rhs.real ^ MOD);
        if real >= MOD {
            real -= MOD;
        }
        let mut image = self.image + (rhs.image ^ MOD);
        if image >= MOD {
            image -= MOD;
        }
        Mersenne61Ext { real, image }
    }
}

impl std::ops::SubAssign for Mersenne61Ext {
    fn sub_assign(&mut self, rhs: Self) {
        *self = *self - rhs;
    }
}

#[inline]
fn my_mult(x: u64, y: u64) -> u64 {
    #[cfg(target_arch = "x86_64")]
    {
        let mut hi = 0;
        let lo = unsafe { _mulx_u64(x, y, &mut hi) };
        ((hi << 3) | (lo >> 61)) + (lo & MOD)
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        let product = x as u128 * y as u128;
        ((product >> 61) as u64) + ((product as u64) & MOD)
    }
}

#[inline]
fn my_mod(x: u64) -> u64 {
    (x >> 61) + (x & MOD)
}

impl std::ops::Mul for Mersenne61Ext {
    type Output = Self;
    fn mul(self, rhs: Self) -> Self::Output {
        let all_prod = my_mult(self.real + self.image, rhs.real + rhs.image);
        let ac = my_mult(self.real, rhs.real);
        let bd = MOD * 2 - my_mult(self.image, rhs.image);
        let nac = MOD * 2 - ac;

        let mut t_img = my_mod(all_prod + nac + bd);
        if t_img >= MOD {
            t_img -= MOD;
        }
        let mut t_real = my_mod(ac + bd);
        t_real = try_sub(t_real);
        Mersenne61Ext {
            real: t_real,
            image: t_img,
        }
    }
}

impl std::ops::MulAssign for Mersenne61Ext {
    fn mul_assign(&mut self, rhs: Self) {
        *self = *self * rhs;
    }
}

impl std::fmt::Display for Mersenne61Ext {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "real: {}, image: {}", self.real, self.image)
    }
}

impl std::cmp::PartialEq for Mersenne61Ext {
    fn eq(&self, rhs: &Self) -> bool {
        self.real == rhs.real && self.image == rhs.image
    }
}
impl Mersenne61Ext {
    const ROOT_OF_UNITY: Mersenne61Ext = Mersenne61Ext {
        real: 2147483648,
        image: 1033321771269002680,
    };
    const INVERSE_2: Mersenne61Ext = Mersenne61Ext {
        real: 1152921504606846976,
        image: 0,
    };

    pub fn from_parts(real: u64, image: u64) -> Self {
        Self {
            real: real % MOD,
            image: image % MOD,
        }
    }

    pub fn to_full_bytes(&self) -> [u8; 16] {
        let mut bytes = [0_u8; 16];
        bytes[..8].copy_from_slice(&self.real.to_le_bytes());
        bytes[8..].copy_from_slice(&self.image.to_le_bytes());
        bytes
    }

    pub fn try_from_full_bytes(bytes: [u8; 16]) -> Option<Self> {
        let mut real = [0_u8; 8];
        let mut image = [0_u8; 8];
        real.copy_from_slice(&bytes[..8]);
        image.copy_from_slice(&bytes[8..]);
        let real = u64::from_le_bytes(real);
        let image = u64::from_le_bytes(image);
        (real < MOD && image < MOD).then_some(Self { real, image })
    }
}

impl MyField for Mersenne61Ext {
    const FIELD_NAME: &'static str = "Mersenne61Ext";
    const LOG_ORDER: u64 = 62;
    #[inline(always)]
    fn root_of_unity() -> Self {
        Mersenne61Ext::ROOT_OF_UNITY
    }
    #[inline(always)]
    fn inverse_2() -> Self {
        Mersenne61Ext::INVERSE_2
    }

    #[inline]
    fn from_int(x: u64) -> Self {
        Mersenne61Ext { real: x, image: 0 }
    }

    #[inline]
    fn from_hash(hash: [u8; crate::merkle_tree::MERKLE_ROOT_SIZE]) -> Self {
        // Rejection sampling is exact because masking produces a uniform value
        // in [0, 2^61), of which only MOD is rejected. Rehashing on rejection
        // avoids the biased 56-bit components used by the artifact code.
        let mut block = hash;
        loop {
            let mut real = [0_u8; 8];
            let mut image = [0_u8; 8];
            real.copy_from_slice(&block[..8]);
            image.copy_from_slice(&block[8..16]);
            let real = u64::from_le_bytes(real) & MOD;
            let image = u64::from_le_bytes(image) & MOD;
            if real < MOD && image < MOD {
                return Mersenne61Ext { real, image };
            }
            block = Sha256::digest(block).into();
        }
    }

    #[inline]
    fn is_zero(&self) -> bool {
        self.real == 0 && self.image == 0
    }

    #[inline]
    fn random_element() -> Self {
        let mut rng = rand::thread_rng();
        Mersenne61Ext {
            real: rng.gen_range(0..MOD),
            image: rng.gen_range(0..MOD),
        }
    }
    #[inline(always)]
    fn inverse(&self) -> Self {
        let p = 2305843009213693951u128;
        let mut n = p * p - 2;
        let mut ret = Self::from_int(1);
        let mut base = self.clone();
        while n != 0 {
            if n % 2 == 1 {
                ret *= base;
            }
            base *= base;
            n >>= 1;
        }
        ret
    }

    #[inline]
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
        add_and_sub::<Mersenne61Ext>();
        mult_and_inverse::<Mersenne61Ext>();
        assigns::<Mersenne61Ext>();
        pow_and_generator::<Mersenne61Ext>();
    }

    #[test]
    fn canonical_bytes_bind_both_components() {
        let a = Mersenne61Ext::from_parts(7, 11);
        let b = Mersenne61Ext::from_parts(7, 12);
        assert_ne!(a.to_bytes(), b.to_bytes());
        assert_eq!(
            Mersenne61Ext::try_from_full_bytes(a.to_full_bytes()),
            Some(a)
        );

        let mut non_canonical = a.to_full_bytes();
        non_canonical[..8].copy_from_slice(&MOD.to_le_bytes());
        assert_eq!(Mersenne61Ext::try_from_full_bytes(non_canonical), None);
    }
}

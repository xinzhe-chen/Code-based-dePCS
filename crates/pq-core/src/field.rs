use std::fmt::{Display, Formatter};
use std::iter::{Product, Sum};
use std::ops::{Add, AddAssign, Div, DivAssign, Mul, MulAssign, Neg, Sub, SubAssign};

use serde::{Deserialize, Serialize};

/// The 64-bit Goldilocks prime: 2^64 - 2^32 + 1.
pub const GOLDILOCKS_MODULUS: u64 = 18_446_744_069_414_584_321;
const GOLDILOCKS_MODULUS_U128: u128 = GOLDILOCKS_MODULUS as u128;

#[derive(
    Copy, Clone, Debug, Default, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize,
)]
pub struct FieldElement(u64);

impl FieldElement {
    pub const ZERO: Self = Self(0);
    pub const ONE: Self = Self(1);
    pub const MODULUS: u64 = GOLDILOCKS_MODULUS;

    pub const fn new(value: u64) -> Self {
        if value >= GOLDILOCKS_MODULUS {
            Self(value - GOLDILOCKS_MODULUS)
        } else {
            Self(value)
        }
    }

    pub const fn value(self) -> u64 {
        self.0
    }

    pub fn from_u128(value: u128) -> Self {
        Self(reduce_u128(value))
    }

    pub fn is_zero(self) -> bool {
        self == Self::ZERO
    }

    pub fn pow(self, mut exponent: u128) -> Self {
        let mut base = self;
        let mut acc = Self::ONE;
        while exponent > 0 {
            if exponent & 1 == 1 {
                acc *= base;
            }
            base *= base;
            exponent >>= 1;
        }
        acc
    }

    pub fn inverse(self) -> Option<Self> {
        if self.is_zero() {
            None
        } else {
            Some(self.pow((GOLDILOCKS_MODULUS - 2) as u128))
        }
    }

    pub fn batch_inverse(values: &[Self]) -> Option<Vec<Self>> {
        let mut prefix_products = Vec::with_capacity(values.len());
        let mut accumulator = Self::ONE;
        for value in values {
            if value.is_zero() {
                return None;
            }
            prefix_products.push(accumulator);
            accumulator *= *value;
        }

        let mut suffix_inverse = accumulator.inverse()?;
        let mut inverses = vec![Self::ZERO; values.len()];
        for (index, value) in values.iter().copied().enumerate().rev() {
            inverses[index] = suffix_inverse * prefix_products[index];
            suffix_inverse *= value;
        }
        Some(inverses)
    }

    pub fn try_div(self, rhs: Self) -> Option<Self> {
        rhs.inverse().map(|inv| self * inv)
    }

    pub const fn to_le_bytes(self) -> [u8; 8] {
        self.0.to_le_bytes()
    }

    pub const fn from_le_bytes(bytes: [u8; 8]) -> Self {
        Self::new(u64::from_le_bytes(bytes))
    }
}

impl From<u64> for FieldElement {
    fn from(value: u64) -> Self {
        Self::new(value)
    }
}

impl From<usize> for FieldElement {
    fn from(value: usize) -> Self {
        Self::from_u128(value as u128)
    }
}

impl Display for FieldElement {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl Add for FieldElement {
    type Output = Self;

    fn add(self, rhs: Self) -> Self::Output {
        let sum = self.0 as u128 + rhs.0 as u128;
        if sum >= GOLDILOCKS_MODULUS_U128 {
            Self((sum - GOLDILOCKS_MODULUS_U128) as u64)
        } else {
            Self(sum as u64)
        }
    }
}

impl AddAssign for FieldElement {
    fn add_assign(&mut self, rhs: Self) {
        *self = *self + rhs;
    }
}

impl Sub for FieldElement {
    type Output = Self;

    fn sub(self, rhs: Self) -> Self::Output {
        if self.0 >= rhs.0 {
            Self(self.0 - rhs.0)
        } else {
            Self(GOLDILOCKS_MODULUS - (rhs.0 - self.0))
        }
    }
}

impl SubAssign for FieldElement {
    fn sub_assign(&mut self, rhs: Self) {
        *self = *self - rhs;
    }
}

impl Mul for FieldElement {
    type Output = Self;

    fn mul(self, rhs: Self) -> Self::Output {
        Self(reduce_u128(self.0 as u128 * rhs.0 as u128))
    }
}

impl MulAssign for FieldElement {
    fn mul_assign(&mut self, rhs: Self) {
        *self = *self * rhs;
    }
}

impl Div for FieldElement {
    type Output = Self;

    #[allow(clippy::suspicious_arithmetic_impl)]
    fn div(self, rhs: Self) -> Self::Output {
        self * rhs
            .inverse()
            .expect("division by zero in FieldElement::div")
    }
}

impl DivAssign for FieldElement {
    fn div_assign(&mut self, rhs: Self) {
        *self = *self / rhs;
    }
}

impl Neg for FieldElement {
    type Output = Self;

    fn neg(self) -> Self::Output {
        if self.is_zero() {
            Self::ZERO
        } else {
            Self(GOLDILOCKS_MODULUS - self.0)
        }
    }
}

impl Sum for FieldElement {
    fn sum<I: Iterator<Item = Self>>(iter: I) -> Self {
        iter.fold(Self::ZERO, Add::add)
    }
}

impl<'a> Sum<&'a FieldElement> for FieldElement {
    fn sum<I: Iterator<Item = &'a FieldElement>>(iter: I) -> Self {
        iter.copied().sum()
    }
}

impl Product for FieldElement {
    fn product<I: Iterator<Item = Self>>(iter: I) -> Self {
        iter.fold(Self::ONE, Mul::mul)
    }
}

impl<'a> Product<&'a FieldElement> for FieldElement {
    fn product<I: Iterator<Item = &'a FieldElement>>(iter: I) -> Self {
        iter.copied().product()
    }
}

fn reduce_u128(value: u128) -> u64 {
    let low = value & u64::MAX as u128;
    let high = value >> 64;
    let reduced = low + (high << 32) - high;

    let low = reduced & u64::MAX as u128;
    let high = reduced >> 64;
    let mut reduced = low + (high << 32) - high;

    while reduced >= GOLDILOCKS_MODULUS_U128 {
        reduced -= GOLDILOCKS_MODULUS_U128;
    }
    reduced as u64
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn goldilocks_reduction_matches_modulo() {
        let mut values = vec![
            0,
            1,
            GOLDILOCKS_MODULUS_U128 - 1,
            GOLDILOCKS_MODULUS_U128,
            GOLDILOCKS_MODULUS_U128 + 1,
            u64::MAX as u128,
            (GOLDILOCKS_MODULUS_U128 - 1) * (GOLDILOCKS_MODULUS_U128 - 1),
            u128::MAX,
        ];
        let mut state = 0x9e3779b97f4a7c15_u128;
        for _ in 0..256 {
            state = state
                .wrapping_mul(0xda942042e4dd58b5_da942042e4dd58b5_u128)
                .wrapping_add(0x9e3779b97f4a7c15_u128);
            values.push(state);
        }

        for value in values {
            assert_eq!(reduce_u128(value), (value % GOLDILOCKS_MODULUS_U128) as u64);
        }
    }

    #[test]
    fn batch_inverse_matches_individual_inverse() {
        let values = (1_u64..64).map(FieldElement::from).collect::<Vec<_>>();
        let batch = FieldElement::batch_inverse(&values).expect("non-zero values");
        for (value, inverse) in values.iter().zip(batch) {
            assert_eq!(Some(inverse), value.inverse());
            assert_eq!(*value * inverse, FieldElement::ONE);
        }
        assert!(FieldElement::batch_inverse(&[FieldElement::ONE, FieldElement::ZERO]).is_none());
    }
}

use std::fmt::{Display, Formatter};
use std::iter::{Product, Sum};
use std::ops::{Add, AddAssign, Div, DivAssign, Mul, MulAssign, Neg, Sub, SubAssign};

/// The 64-bit Goldilocks prime: 2^64 - 2^32 + 1.
pub const GOLDILOCKS_MODULUS: u64 = 18_446_744_069_414_584_321;

#[derive(Copy, Clone, Debug, Default, PartialEq, Eq, Hash, PartialOrd, Ord)]
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
        Self((value % GOLDILOCKS_MODULUS as u128) as u64)
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
        Self::from_u128(self.0 as u128 + rhs.0 as u128)
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
        Self::from_u128(self.0 as u128 * rhs.0 as u128)
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

use crate::{CoreError, FieldElement, Result};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DensePolynomial {
    coeffs: Vec<FieldElement>,
}

impl DensePolynomial {
    pub fn new(mut coeffs: Vec<FieldElement>) -> Self {
        trim_trailing_zeros(&mut coeffs);
        Self { coeffs }
    }

    pub fn zero() -> Self {
        Self {
            coeffs: vec![FieldElement::ZERO],
        }
    }

    pub fn one() -> Self {
        Self {
            coeffs: vec![FieldElement::ONE],
        }
    }

    pub fn monomial(degree: usize, coeff: FieldElement) -> Self {
        let mut coeffs = vec![FieldElement::ZERO; degree + 1];
        coeffs[degree] = coeff;
        Self::new(coeffs)
    }

    pub fn coeffs(&self) -> &[FieldElement] {
        &self.coeffs
    }

    pub fn degree(&self) -> Option<usize> {
        if self.coeffs.len() == 1 && self.coeffs[0].is_zero() {
            None
        } else {
            Some(self.coeffs.len() - 1)
        }
    }

    pub fn evaluate(&self, x: FieldElement) -> FieldElement {
        self.coeffs
            .iter()
            .rev()
            .fold(FieldElement::ZERO, |acc, coeff| acc * x + *coeff)
    }

    pub fn scale(&self, scalar: FieldElement) -> Self {
        Self::new(self.coeffs.iter().map(|coeff| *coeff * scalar).collect())
    }

    pub fn add(&self, rhs: &Self) -> Self {
        let len = self.coeffs.len().max(rhs.coeffs.len());
        let mut coeffs = vec![FieldElement::ZERO; len];
        for (i, coeff) in self.coeffs.iter().enumerate() {
            coeffs[i] += *coeff;
        }
        for (i, coeff) in rhs.coeffs.iter().enumerate() {
            coeffs[i] += *coeff;
        }
        Self::new(coeffs)
    }

    pub fn sub(&self, rhs: &Self) -> Self {
        let len = self.coeffs.len().max(rhs.coeffs.len());
        let mut coeffs = vec![FieldElement::ZERO; len];
        for (i, coeff) in self.coeffs.iter().enumerate() {
            coeffs[i] += *coeff;
        }
        for (i, coeff) in rhs.coeffs.iter().enumerate() {
            coeffs[i] -= *coeff;
        }
        Self::new(coeffs)
    }

    pub fn mul(&self, rhs: &Self) -> Self {
        if self.degree().is_none() || rhs.degree().is_none() {
            return Self::zero();
        }

        let mut coeffs = vec![FieldElement::ZERO; self.coeffs.len() + rhs.coeffs.len() - 1];
        for (i, left) in self.coeffs.iter().enumerate() {
            for (j, right) in rhs.coeffs.iter().enumerate() {
                coeffs[i + j] += *left * *right;
            }
        }
        Self::new(coeffs)
    }
}

pub fn powers(base: FieldElement, len: usize) -> Vec<FieldElement> {
    let mut out = Vec::with_capacity(len);
    let mut acc = FieldElement::ONE;
    for _ in 0..len {
        out.push(acc);
        acc *= base;
    }
    out
}

pub fn inner_product(left: &[FieldElement], right: &[FieldElement]) -> Result<FieldElement> {
    if left.len() != right.len() {
        return Err(CoreError::VectorLength {
            expected: left.len(),
            actual: right.len(),
        });
    }

    Ok(left
        .iter()
        .zip(right)
        .map(|(l, r)| *l * *r)
        .sum::<FieldElement>())
}

pub fn lagrange_interpolate(xs: &[FieldElement], ys: &[FieldElement]) -> Result<DensePolynomial> {
    if xs.len() != ys.len() {
        return Err(CoreError::VectorLength {
            expected: xs.len(),
            actual: ys.len(),
        });
    }

    let mut result = DensePolynomial::zero();
    for i in 0..xs.len() {
        let mut numerator = DensePolynomial::one();
        let mut denominator = FieldElement::ONE;

        for j in 0..xs.len() {
            if i == j {
                continue;
            }
            numerator = numerator.mul(&DensePolynomial::new(vec![-xs[j], FieldElement::ONE]));
            denominator *= xs[i] - xs[j];
        }

        let inv = denominator.inverse().ok_or(CoreError::DivisionByZero)?;
        result = result.add(&numerator.scale(ys[i] * inv));
    }
    Ok(result)
}

fn trim_trailing_zeros(coeffs: &mut Vec<FieldElement>) {
    while coeffs.len() > 1 && coeffs.last() == Some(&FieldElement::ZERO) {
        coeffs.pop();
    }
    if coeffs.is_empty() {
        coeffs.push(FieldElement::ZERO);
    }
}

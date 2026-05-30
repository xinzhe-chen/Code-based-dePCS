use crate::{CoreError, FieldElement, Result, inner_product};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MultilinearExtension {
    num_vars: usize,
    evaluations: Vec<FieldElement>,
}

impl MultilinearExtension {
    pub const MAX_NUM_VARS: usize = usize::BITS as usize - 1;
    pub const MAX_ALLOCATING_NUM_VARS: usize = 20;

    pub fn new(evaluations: Vec<FieldElement>) -> Result<Self> {
        Self::from_evaluations(evaluations)
    }

    pub fn from_evaluations(evaluations: Vec<FieldElement>) -> Result<Self> {
        if evaluations.is_empty() {
            return Err(CoreError::EmptyEvaluations);
        }
        if !evaluations.len().is_power_of_two() {
            return Err(CoreError::NonPowerOfTwo {
                len: evaluations.len(),
            });
        }
        Ok(Self {
            num_vars: evaluations.len().trailing_zeros() as usize,
            evaluations,
        })
    }

    pub fn constant(value: FieldElement) -> Self {
        Self {
            num_vars: 0,
            evaluations: vec![value],
        }
    }

    pub fn from_fn<F>(num_vars: usize, mut evaluator: F) -> Result<Self>
    where
        F: FnMut(&[bool]) -> FieldElement,
    {
        let len = checked_allocating_hypercube_len(num_vars)?;
        let evaluations = (0..len)
            .map(|index| {
                let point = bits_le(index, num_vars);
                evaluator(&point)
            })
            .collect();
        Ok(Self {
            num_vars,
            evaluations,
        })
    }

    pub fn try_from_fn<F>(num_vars: usize, evaluator: F) -> Result<Self>
    where
        F: FnMut(&[bool]) -> FieldElement,
    {
        Self::from_fn(num_vars, evaluator)
    }

    pub fn num_vars(&self) -> usize {
        self.num_vars
    }

    pub fn len(&self) -> usize {
        self.evaluations.len()
    }

    pub fn is_empty(&self) -> bool {
        self.evaluations.is_empty()
    }

    pub fn evaluations(&self) -> &[FieldElement] {
        &self.evaluations
    }

    pub fn sum_over_boolean_hypercube(&self) -> FieldElement {
        self.evaluations.iter().copied().sum()
    }

    pub fn evaluate(&self, point: &[FieldElement]) -> Result<FieldElement> {
        if point.len() != self.num_vars {
            return Err(CoreError::PointLength {
                expected: self.num_vars,
                actual: point.len(),
            });
        }

        let mut layer = self.evaluations.clone();
        for r in point {
            let one_minus_r = FieldElement::ONE - *r;
            let next_len = layer.len() / 2;
            for i in 0..next_len {
                layer[i] = layer[2 * i] * one_minus_r + layer[2 * i + 1] * *r;
            }
            layer.truncate(next_len);
        }
        Ok(layer[0])
    }

    pub fn evaluate_naive(&self, point: &[FieldElement]) -> Result<FieldElement> {
        if point.len() != self.num_vars {
            return Err(CoreError::PointLength {
                expected: self.num_vars,
                actual: point.len(),
            });
        }
        let eqs = eq_evaluations(point)?;
        inner_product(&self.evaluations, &eqs)
    }

    pub fn fix_first_variable(&self, challenge: FieldElement) -> Result<Self> {
        if self.num_vars == 0 {
            return Err(CoreError::PointLength {
                expected: 1,
                actual: 0,
            });
        }
        let half = self.evaluations.len() / 2;
        let one_minus = FieldElement::ONE - challenge;
        let mut next = Vec::with_capacity(half);
        for pair in self.evaluations.chunks_exact(2) {
            next.push(pair[0] * one_minus + pair[1] * challenge);
        }
        Self::from_evaluations(next)
    }
}

pub fn eq_eval(left: &[FieldElement], right: &[FieldElement]) -> Result<FieldElement> {
    if left.len() != right.len() {
        return Err(CoreError::PointLength {
            expected: left.len(),
            actual: right.len(),
        });
    }

    Ok(left
        .iter()
        .zip(right)
        .map(|(l, r)| *l * *r + (FieldElement::ONE - *l) * (FieldElement::ONE - *r))
        .product())
}

pub fn eq_basis(point: &[FieldElement], index: usize) -> Result<FieldElement> {
    let len = checked_hypercube_len(point.len())?;
    if index >= len {
        return Err(CoreError::VectorLength {
            expected: len,
            actual: index + 1,
        });
    }

    let mut acc = FieldElement::ONE;
    for (var, r) in point.iter().enumerate() {
        if ((index >> var) & 1) == 1 {
            acc *= *r;
        } else {
            acc *= FieldElement::ONE - *r;
        }
    }
    Ok(acc)
}

pub fn eq_evaluations(point: &[FieldElement]) -> Result<Vec<FieldElement>> {
    let len = checked_allocating_hypercube_len(point.len())?;
    (0..len).map(|index| eq_basis(point, index)).collect()
}

pub fn evaluate_mle(evaluations: &[FieldElement], point: &[FieldElement]) -> Result<FieldElement> {
    MultilinearExtension::from_evaluations(evaluations.to_vec())?.evaluate(point)
}

pub fn log2_power_of_two(value: usize) -> Result<usize> {
    if value == 0 {
        return Err(CoreError::EmptyEvaluations);
    }
    if !value.is_power_of_two() {
        return Err(CoreError::NonPowerOfTwo { len: value });
    }
    Ok(value.trailing_zeros() as usize)
}

fn checked_hypercube_len(num_vars: usize) -> Result<usize> {
    if num_vars > MultilinearExtension::MAX_NUM_VARS {
        return Err(CoreError::VectorLength {
            expected: MultilinearExtension::MAX_NUM_VARS,
            actual: num_vars,
        });
    }
    1usize
        .checked_shl(num_vars as u32)
        .ok_or(CoreError::VectorLength {
            expected: MultilinearExtension::MAX_NUM_VARS,
            actual: num_vars,
        })
}

fn checked_allocating_hypercube_len(num_vars: usize) -> Result<usize> {
    if num_vars > MultilinearExtension::MAX_ALLOCATING_NUM_VARS {
        return Err(CoreError::VectorLength {
            expected: MultilinearExtension::MAX_ALLOCATING_NUM_VARS,
            actual: num_vars,
        });
    }
    checked_hypercube_len(num_vars)
}

fn bits_le(mut index: usize, num_vars: usize) -> Vec<bool> {
    let mut bits = Vec::with_capacity(num_vars);
    for _ in 0..num_vars {
        bits.push(index & 1 == 1);
        index >>= 1;
    }
    bits
}

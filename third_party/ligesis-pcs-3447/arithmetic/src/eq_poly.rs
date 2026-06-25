#![allow(non_snake_case)]

use ark_ff::PrimeField;

use crate::math::Math;

pub struct EqPolynomial<F> {
    r: Vec<F>,
}

impl<F: PrimeField> EqPolynomial<F> {
    pub fn new(r: Vec<F>) -> Self {
        EqPolynomial { r }
    }

    pub fn evaluate(&self, rx: &[F]) -> F {
        assert_eq!(self.r.len(), rx.len());
        (0..rx.len())
            .map(|i| self.r[i] * rx[i] + (F::one() - self.r[i]) * (F::one() - rx[i]))
            .product()
    }

    pub fn evals(r: &[F]) -> Vec<F> {
        let ell = r.len();
        Self::evals_serial(r, ell)
    }

    fn evals_serial(r: &[F], ell: usize) -> Vec<F> {
        let mut evals: Vec<F> = vec![F::one(); ell.pow2()];
        let mut size = 1;
        for j in 0..ell {
            // in each iteration, we double the size of chis
            size *= 2;
            for i in (0..size).rev().step_by(2) {
                // copy each element from the prior iteration twice
                let scalar = evals[i / 2];
                evals[i] = scalar * r[j];
                evals[i - 1] = scalar - evals[i];
            }
        }
        evals
    }

    pub fn evals_coeff(r: &[F], coeff: &F) -> Vec<F> {
        let ell = r.len();
        Self::evals_serial_coeff(r, coeff, ell)
    }

    fn evals_serial_coeff(r: &[F], coeff: &F, ell: usize) -> Vec<F> {
        let mut evals: Vec<F> = vec![F::one(); ell.pow2()];
        evals[0] = *coeff;
        let mut size = 1;
        for j in 0..ell {
            // in each iteration, we double the size of chis
            size *= 2;
            for i in (0..size).rev().step_by(2) {
                // copy each element from the prior iteration twice
                let scalar = evals[i / 2];
                evals[i] = scalar * r[j];
                evals[i - 1] = scalar - evals[i];
            }
        }
        evals
    }

    pub fn compute_factored_evals(&self, L_size: usize) -> (Vec<F>, Vec<F>) {
        let ell = self.r.len();
        let left_num_vars = L_size.log_2();

        let L = EqPolynomial::evals(&self.r[..left_num_vars]);
        let R = EqPolynomial::evals(&self.r[left_num_vars..ell]);

        (L, R)
    }
}

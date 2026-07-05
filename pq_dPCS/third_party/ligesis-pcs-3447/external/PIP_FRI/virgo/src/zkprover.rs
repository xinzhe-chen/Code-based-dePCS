use rand::thread_rng;
use utils::helper::MultilinearPolynomial;
use utils::interpolate_vecs_value::{QueryVecsResult, InterpolateVecsValue};
use ark_poly::polynomial::univariate::DensePolynomial as UnivariatePolynomial;
use ark_ff::PrimeField;
pub use utils::merkle_tree::MERKLE_ROOT_SIZE;
use utils::query_result::QueryResult;
use utils::{CODE_RATE, SECURITY_BITS};
use utils::{
    helper::Helper,
    merkle_tree::MerkleTreeProver,
    fiat_shamir::RandomOracle,
};
use ark_std::collections::HashMap;
use super::zkverifier::ZKFriVerifier;
use ark_poly::{DenseUVPolynomial, EvaluationDomain, GeneralEvaluationDomain, Polynomial};

#[derive(Clone)]
struct InterpolateValue<T: PrimeField> {
    value: Vec<T>,
    merkle_tree: MerkleTreeProver,
}

impl<T: PrimeField> InterpolateValue<T> {
    fn new(value: Vec<T>) -> Self {
        let len = value.len() / 2;
        let merkle_tree = MerkleTreeProver::new(
            (0..len)
                .map(|i| Helper::to_bytes_vec(&[value[i], value[i + len]]))
                .collect(),
        );
        Self { value, merkle_tree }
    }

    fn leave_num(&self) -> usize {
        self.merkle_tree.leave_num()
    }

    fn commit(&self) -> [u8; MERKLE_ROOT_SIZE] {
        self.merkle_tree.commit()
    }

    fn query(&self, leaf_indices: &Vec<usize>) -> QueryResult<T> {
        let len = self.merkle_tree.leave_num();
        let proof_values = leaf_indices
            .iter()
            .flat_map(|j| [(*j, self.value[*j]), (*j + len, self.value[*j + len])])
            .collect();
        let proof_bytes = self.merkle_tree.open(&leaf_indices);
        QueryResult {
            proof_bytes,
            proof_values,
        }
    }
}

#[derive(Clone)]
pub struct ZKFriProver<T: PrimeField> {
    total_round: usize,
    vector_interpolation_coset: GeneralEvaluationDomain<T>,
    fri_cosets: Vec<GeneralEvaluationDomain<T>>,
    function_h: Option<InterpolateValue<T>>,
    function_us: InterpolateVecsValue<T>,
    interpolation_u: Vec<T>,
    interpolation_s: Vec<T>,
    interpolation_v: Option<Vec<T>>,
    poly_u: UnivariatePolynomial<T>,
    poly_s: UnivariatePolynomial<T>,
    polynomial: MultilinearPolynomial<T>,
    foldings: Vec<InterpolateValue<T>>,
    oracle: RandomOracle<T>,
    evaluation: Option<T>,
    evaluation_s: Option<T>,
    final_value: Option<T>,
}

// (u(X) + Z_H(X) \delta(X)) r(X) = X g(X) + \mu + Z_H(X) h(X)
// u(X) | _H = coeffs

impl<T: PrimeField> ZKFriProver<T> {
    pub fn new(
        total_round: usize,
        fri_cosets: &Vec<GeneralEvaluationDomain<T>>,
        // H
        vector_interpolation_coset: &GeneralEvaluationDomain<T>,
        polynomial: MultilinearPolynomial<T>,
        oracle: &RandomOracle<T>,
    ) -> ZKFriProver<T> {
        assert_eq!(
            vector_interpolation_coset.size(),
            1 << polynomial.variable_num()
        );
        // coeffs of u(X)
        let coeffs_u = vector_interpolation_coset.ifft(polynomial.coefficients());
        let mut rng = thread_rng();
        let poly_delta = UnivariatePolynomial::rand(SECURITY_BITS / CODE_RATE, &mut rng);
        let poly_u = UnivariatePolynomial::from_coefficients_slice(&coeffs_u) + poly_delta.mul_by_vanishing_poly(*vector_interpolation_coset);
        let function_u = fri_cosets[0].fft(poly_u.coeffs());

        let poly_s = UnivariatePolynomial::rand(2 * coeffs_u.len() + SECURITY_BITS/CODE_RATE - 1, &mut rng);
        // assert!(poly_s.degree() + 1 <= 1 << total_round);
        // assert!(poly_u.degree() + 1 <= 1 << total_round);
        let function_s = fri_cosets[0].fft(poly_s.coeffs());

        let function_us = InterpolateVecsValue::new(vec![function_u.clone(), function_s.clone()]);
        // NOTE: only work for large polynomials
        assert_eq!((fri_cosets[0].size() >> CODE_RATE), 4 * coeffs_u.len());
        ZKFriProver {
            total_round,
            vector_interpolation_coset: vector_interpolation_coset.clone(),
            fri_cosets: fri_cosets.clone(),
            function_h: None,
            function_us,
            interpolation_u: function_u,
            interpolation_s: function_s,
            interpolation_v: None,
            poly_u,
            poly_s,
            polynomial,
            foldings: vec![],
            oracle: oracle.clone(),
            evaluation: None,
            evaluation_s: None,
            final_value: None,
        }
    }

    pub fn commit_polynomial(&self) -> [u8; MERKLE_ROOT_SIZE] {
        self.function_us.commit()
    }

    pub fn commit_functions(&mut self, verifier: &mut ZKFriVerifier<T>, open_point: &Vec<T>) {
        assert_eq!(open_point.len(), self.total_round - 2);
        let mut public_vector = vec![T::ONE];
        for i in open_point {
            let len = public_vector.len();
            for j in 0..len {
                public_vector.push(public_vector[j] * i.clone());
            }
        }
        let poly_v = UnivariatePolynomial::from_coefficients_vec(self.vector_interpolation_coset.ifft(&public_vector));
        assert!(poly_v.degree() < self.vector_interpolation_coset.size());
        let poly_uv_s = &(&self.poly_u * &poly_v) + &(&self.poly_s * self.oracle.rlc);
        let (h, remainder) = poly_uv_s.divide_by_vanishing_poly(self.vector_interpolation_coset).unwrap();
        // assert!(h.degree() < self.vector_interpolation_coset.size());
        assert_eq!(remainder.degree(), self.vector_interpolation_coset.size() - 1);
        let function_h = InterpolateValue::new(self.fri_cosets[0].fft(h.coeffs()));
        verifier.set_h_root(function_h.commit());
        self.function_h = Some(function_h);
        self.interpolation_v = Some(self.fri_cosets[0].fft(poly_v.coeffs()));
        let evaluation = self.polynomial.evaluate(open_point);
        self.evaluation = Some(evaluation);
        let evaluation_s = self.poly_s.evaluate_over_domain_by_ref(self.vector_interpolation_coset).evals.iter().sum();
        self.evaluation_s = Some(evaluation_s);
        verifier.set_evaluation_s(evaluation_s);
        //// test for completeness
        // let poly_uv = &self.poly_u * &poly_v;
        // let evaluation_by_sum: T = poly_uv.evaluate_over_domain_by_ref(self.vector_interpolation_coset).evals.iter().sum();
        // assert_eq!(evaluation, evaluation_by_sum);
    }

    pub fn commit_foldings(&self, verifier: &mut ZKFriVerifier<T>) {
        for i in 0..(self.total_round - 1) {
            verifier.receive_folding_root(self.foldings[i].leave_num(), self.foldings[i].commit());
        }
        verifier.set_final_value(self.final_value.unwrap())
    }

    // compute u(X) + alpha \cdot h(X) + alpha^2 \cdot g(X) | _ L
    fn initial_interpolation(&self) -> Vec<T> {
        let rlc = self.oracle.rlc;
        let u = &self.interpolation_u;
        let s = &self.interpolation_s;
        let mut res = u.clone();
        let h = &self.function_h.as_ref().unwrap().value;
        let mut acc = rlc;
        for i in 0..self.fri_cosets[0].size() {
            res[i] += acc * h[i];
        }
        acc *= rlc;
        // let vanish_polynomial = self.vector_interpolation_coset.vanishing_polynomial();
        let v = self.interpolation_v.as_ref().unwrap();
        let h_size = T::from(self.vector_interpolation_coset.size() as u64);
        for i in 0..self.fri_cosets[0].size() {
            let x = self.fri_cosets[0].element(i);
            let x_inv = self.fri_cosets[0].element(i).inverse().unwrap();
            res[i] += acc
                * ((u[i] * v[i] + rlc * s[i]) * h_size
                    - self.vector_interpolation_coset.evaluate_vanishing_polynomial(x) * h[i] * h_size
                    - self.evaluation.unwrap() - rlc * self.evaluation_s.unwrap())
                * x_inv;
        }
        res
    }

    fn evaluation_next_domain(&self, round: usize, challenge: T) -> Vec<T> {
        let mut res = vec![];
        let coset = &self.fri_cosets[round];
        let len = coset.size();
        if round == 0 {
            let function = self.initial_interpolation();
            for i in 0..(len / 2) {
                let x = function[i];
                let nx = function[i + len / 2];
                let new_v = (x + nx) + challenge * (x - nx) * coset.element(i).inverse().unwrap();
                res.push(new_v);
            }
        } else {
            let last_folding = &self.foldings.last().unwrap().value;
            for i in 0..(len / 2) {
                let x = last_folding[i];
                let nx = last_folding[i + len / 2];
                let new_v = (x + nx) + challenge * (x - nx) * coset.element(i).inverse().unwrap();
                res.push(new_v);
            }
        }
        res
    }

    pub fn prove(&mut self) {
        for i in 0..self.total_round {
            let challenge = self.oracle.folding_challenges[i];
            let next_evalutation = self.evaluation_next_domain(i, challenge);
            if i < self.total_round - 1 {
                let interpolate_value = InterpolateValue::new(next_evalutation);
                self.foldings.push(interpolate_value);
            } else {
                // println!("next_evaluation len: {:?}", next_evalutation.len());
                let x = next_evalutation[0];
                for i in &next_evalutation {
                    assert_eq!(x, *i);
                }
                self.final_value = Some(next_evalutation[0]);
            }
        }
    }

    pub fn query(&self) -> (Vec<QueryResult<T>>, QueryVecsResult<T>, QueryResult<T>, HashMap<usize, T>) {
        let mut folding_res = vec![];
        let mut function_us_res = None;
        let mut function_h_res = None;
        let mut leaf_indices = self.oracle.query_list.clone();
        let mut v_value = None;

        for i in 0..self.total_round {
            let len = self.fri_cosets[i].size() / 2;
            leaf_indices = leaf_indices.iter_mut().map(|v| *v % len).collect();
            leaf_indices.sort();
            leaf_indices.dedup();

            if i == 0 {
                function_us_res = Some(
                    self.function_us.query(&leaf_indices)
                );
                function_h_res = Some(self.function_h.as_ref().unwrap().query(&leaf_indices));
                let interpolation_v = self.interpolation_v.as_ref().unwrap();
                v_value = Some(
                    leaf_indices
                        .iter()
                        .flat_map(|j| {
                            [
                                (*j, interpolation_v[*j]),
                                (*j + len, interpolation_v[*j + len]),
                            ]
                        })
                        .collect(),
                );
            } else {
                let query_result = self.foldings[i - 1].query(&leaf_indices);
                folding_res.push(query_result);
            }
        }
        (folding_res, function_us_res.unwrap(), function_h_res.unwrap(), v_value.unwrap())
    }
}

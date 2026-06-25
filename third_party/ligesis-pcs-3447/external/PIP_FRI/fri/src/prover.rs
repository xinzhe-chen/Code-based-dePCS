use std::time::Instant;

use ark_ff::{batch_inversion, PrimeField};
use ark_poly::polynomial::univariate::DensePolynomial as UnivariatePolynomial;
use ark_poly::{EvaluationDomain, GeneralEvaluationDomain};
use ark_std::{end_timer, start_timer};
use utils::interpolate_vecs_value::{InterpolateVecsValue, QueryVecsResult};

use crate::verifier::BatchVerifier;

use super::verifier::Verifier;
// use util::algebra::polynomial::Polynomial;

use utils::merkle_tree::MERKLE_ROOT_SIZE;
use utils::query_result::QueryResult;
use utils::{commit_open_vec::ComOpenOneVec, fiat_shamir::RandomOracle};

#[derive(Clone)]
pub struct Prover<T: PrimeField> {
    total_round: usize,
    // cosets of each round
    interpolate_cosets: Vec<GeneralEvaluationDomain<T>>,
    // fft evaluations of each round, but only the first is computed from fft
    interpolations: Vec<ComOpenOneVec<T>>,
    oracle: RandomOracle<T>,
    final_value: Option<T>,
}

impl<T: PrimeField> Prover<T> {
    pub fn new(
        total_round: usize,
        interpolate_coset: &Vec<GeneralEvaluationDomain<T>>,
        polynomial: UnivariatePolynomial<T>,
        oracle: &RandomOracle<T>,
    ) -> Prover<T> {
        let interpolate_polynomial =
            ComOpenOneVec::new(interpolate_coset[0].fft(&polynomial.coeffs));
        Prover {
            total_round,
            interpolate_cosets: interpolate_coset.clone(),
            interpolations: vec![interpolate_polynomial],
            oracle: oracle.clone(),
            final_value: None,
        }
    }

    pub fn commit_polynomial(&self) -> [u8; MERKLE_ROOT_SIZE] {
        self.interpolations[0].commit()
    }

    pub fn commit_foldings(&self, verifier: &mut Verifier<T>) {
        for i in 1..self.total_round {
            let interpolation = &self.interpolations[i];
            verifier.receive_interpolation_root(interpolation.leave_num(), interpolation.commit());
        }
        verifier.set_final_value(self.final_value.unwrap());
    }

    // f(w^2) = (f(w) + f(-w))/2 + (f(w) - f(-w))/2w
    fn evaluation_next_domain(&self, folding_value: &Vec<T>, round: usize, challenge: T) -> Vec<T> {
        let mut res = vec![];
        let len = self.interpolate_cosets[round].size();
        let coset = &self.interpolate_cosets[round];
        for i in 0..(len / 2) {
            let x = folding_value[i];
            let nx = folding_value[i + len / 2];
            let new_v = (x + nx) + challenge * (x - nx) * coset.element(i).inverse().unwrap();
            let new_v = new_v * T::from(2 as u64).inverse().unwrap();
            res.push(new_v);
        }
        res
    }

    pub fn prove(&mut self, point: T, eval: T) {
        // let mut res = None;
        for i in 0..self.total_round {
            let challenge = self.oracle.folding_challenges[i];
            let next_evalutation = if i == 0 {
                let mut inv_vec: Vec<T> = self.interpolate_cosets[0]
                    .elements()
                    .into_iter()
                    .map(|x| x - point)
                    .collect();
                batch_inversion(inv_vec.as_mut_slice());
                let v = self.interpolations[0].vec.clone();
                self.evaluation_next_domain(
                    &v.into_iter()
                        .zip(inv_vec.into_iter())
                        .map(|(x, inv)| (x - eval) * inv)
                        .collect(),
                    i,
                    challenge,
                )
            } else {
                self.evaluation_next_domain(&self.interpolations[i].vec, i, challenge)
            };
            if i < self.total_round - 1 {
                self.interpolations
                    .push(ComOpenOneVec::new(next_evalutation));
            } else {
                self.final_value = Some(next_evalutation[0]);
            }
        }
    }

    pub fn open(&mut self, point: T, eval: T, verifier: &mut Verifier<T>) -> Vec<QueryResult<T>> {
        self.prove(point, eval);

        self.commit_foldings(verifier);

        let mut folding_res = vec![];
        let mut leaf_indices = self.oracle.query_list.clone();

        for i in 0..self.total_round {
            let len = self.interpolate_cosets[i].size();
            leaf_indices = leaf_indices.iter_mut().map(|v| *v % (len >> 1)).collect();
            leaf_indices.sort();
            leaf_indices.dedup();

            folding_res.push(self.interpolations[i].open(&leaf_indices));
        }
        folding_res
    }
}

#[derive(Clone)]
pub struct BatchProver<T: PrimeField> {
    total_round: usize,
    // cosets of each round
    interpolate_cosets: Vec<GeneralEvaluationDomain<T>>,
    // fft evaluations of each round, but only the first is computed from fft
    interpolation_initial: InterpolateVecsValue<T>,
    // interpolation_rlc: Vec<T>,
    interpolations: Vec<ComOpenOneVec<T>>,
    oracle: RandomOracle<T>,
    final_value: Option<T>,
}

impl<T: PrimeField> BatchProver<T> {
    pub fn new(
        total_round: usize,
        interpolate_coset: &Vec<GeneralEvaluationDomain<T>>,
        polynomials: &[UnivariatePolynomial<T>],
        oracle: &RandomOracle<T>,
    ) -> BatchProver<T> {
        println!("coset[0] size {:?}", interpolate_coset[0].size());
        println!("poly size {:?}", polynomials[0].coeffs.len());
        println!("poly num {:?}", polynomials.len());
        let time = Instant::now();
        let step = start_timer!(|| "fft");
        let vecs: Vec<Vec<T>> = polynomials
            .iter()
            .map(|poly| interpolate_coset[0].fft(&poly.coeffs))
            .collect();
        end_timer!(step);
        println!("Time: fft: {:?}", time.elapsed());

        // let time = Instant::now();
        let interpolate_initial = InterpolateVecsValue::new(vecs);
        // println!("Time: build Merkle tree: {:?}", time.elapsed());

        BatchProver {
            total_round,
            interpolate_cosets: interpolate_coset.clone(),
            interpolation_initial: interpolate_initial,
            // interpolation_rlc: rlc_polynomial,
            interpolations: vec![],
            oracle: oracle.clone(),
            final_value: None,
        }
    }

    pub fn commit_polynomial(&self) -> [u8; MERKLE_ROOT_SIZE] {
        // let time = Instant::now();
        let root = self.interpolation_initial.commit();
        // println!("Time: generate Merkle tree root: {:?}", time.elapsed());
        root
    }

    pub fn commit_foldings(&self, verifier: &mut BatchVerifier<T>) {
        for i in 1..self.total_round {
            let interpolation = &self.interpolations[i - 1];
            verifier.receive_interpolation_root(interpolation.leave_num(), interpolation.commit());
        }
        verifier.set_final_value(self.final_value.unwrap());
    }

    // f(w^2) = (f(w) + f(-w))/2 + (f(w) - f(-w))/2w
    fn evaluation_next_domain(&self, folding_value: &Vec<T>, round: usize, challenge: T) -> Vec<T> {
        let mut res = vec![];
        let len = self.interpolate_cosets[round].size();
        let coset = &self.interpolate_cosets[round];
        for i in 0..(len / 2) {
            let x = folding_value[i];
            let nx = folding_value[i + len / 2];
            let new_v = (x + nx) + challenge * (x - nx) * coset.element(i).inverse().unwrap();
            let new_v = new_v * T::from_u64(2 as u64).unwrap().inverse().unwrap();
            res.push(new_v);
        }
        res
    }

    // may open
    pub fn prove(&mut self, points: &Vec<T>, evals: &Vec<T>) {
        for i in 0..self.total_round {
            let challenge = self.oracle.folding_challenges[i];
            let next_evalutation = if i == 0 {
                let vecs = self.interpolation_initial.values.clone();
                let mut eval_vecs: Vec<Vec<T>> = vec![];
                let mut rlc_challenge = T::one();
                let mut final_vec = vec![T::zero(); vecs[0].len()];
                for j in 0..points.len() {
                    let mut inv_vec: Vec<T> = self.interpolate_cosets[0]
                        .elements()
                        .into_iter()
                        .map(|x| x - points[j])
                        .collect();
                    batch_inversion(inv_vec.as_mut_slice());

                    let eval_vec = vecs[j]
                        .iter()
                        .zip(inv_vec.iter())
                        .map(|(x, inv)| (*x - evals[j]) * inv * rlc_challenge)
                        .collect();
                    rlc_challenge *= self.oracle.rlc;
                    eval_vecs.push(eval_vec);
                }
                for j in 0..eval_vecs.len() {
                    for k in 0..eval_vecs[j].len() {
                        final_vec[k] += eval_vecs[j][k];
                    }
                }

                self.evaluation_next_domain(&final_vec, i, challenge)
            } else {
                self.evaluation_next_domain(&self.interpolations[i - 1].vec, i, challenge)
            };
            if i < self.total_round - 1 {
                self.interpolations
                    .push(ComOpenOneVec::new(next_evalutation));
            } else {
                self.final_value = Some(next_evalutation[0]);
            }
        }
    }

    pub fn open(
        &mut self,
        points: &Vec<T>,
        evals: &Vec<T>,
        verifier: &mut BatchVerifier<T>,
    ) -> (QueryVecsResult<T>, Vec<QueryResult<T>>) {
        self.prove(points, evals);

        self.commit_foldings(verifier);

        let mut folding_res = vec![];
        let mut leaf_indices = self.oracle.query_list.clone();
        let mut folding_initial_res = vec![];

        for i in 0..self.total_round {
            let len = self.interpolate_cosets[i].size();
            leaf_indices = leaf_indices.iter_mut().map(|v| *v % (len >> 1)).collect();
            leaf_indices.sort();
            leaf_indices.dedup();

            if i == 0 {
                folding_initial_res.push(self.interpolation_initial.query(&leaf_indices));
            } else {
                folding_res.push(self.interpolations[i - 1].open(&leaf_indices));
            }
        }
        (folding_initial_res[0].clone(), folding_res)
    }
}

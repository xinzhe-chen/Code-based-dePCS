use rand::{thread_rng, Rng};
use utils::{
    helper::Helper,
    merkle_tree::MerkleTreeProver,
    CODE_RATE,
};
use utils::helper::MultilinearPolynomial;
use ark_ff::PrimeField;
use crate::{Commit, DeepEval, Proof, VQueryResult};
use ark_poly::polynomial::univariate::DensePolynomial as UnivariatePolynomial;
use ark_poly::{DenseUVPolynomial, EvaluationDomain, GeneralEvaluationDomain};
pub use utils::merkle_tree::MERKLE_ROOT_SIZE;

#[derive(Debug, Clone)]
pub struct RandomOracle<T: PrimeField> {
    pub beta: T,
    pub rlc: T,
    pub folding_challenges: Vec<T>,
    pub deep: Vec<T>,
    pub alpha: Vec<T>,
    pub query_list: Vec<usize>,
}

impl<T: PrimeField> RandomOracle<T> {
    pub fn new(total_round: usize, query_num: usize) -> Self {
        let mut rng = thread_rng();
        RandomOracle {
            beta: T::rand(&mut rng),
            rlc: T::rand(&mut rng),
            folding_challenges: (0..total_round)
                .into_iter()
                .map(|_| T::rand(&mut rng))
                .collect(),
            deep: (0..total_round)
                .into_iter()
                .map(|_| T::rand(&mut rng))
                .collect(),
            alpha: (0..total_round)
                .into_iter()
                .map(|_| T::rand(&mut rng))
                .collect(),
            query_list: (0..query_num)
                .into_iter()
                .map(|_| rand::thread_rng().gen())
                .collect(),
        }
    }
}


#[derive(Clone)]
pub struct InterpolateValue<T: PrimeField> {
    pub value: Vec<T>,
    leaf_size: usize,
    merkle_tree: MerkleTreeProver,
}

impl<T: PrimeField> InterpolateValue<T> {
    pub fn new(value: Vec<T>, leaf_size: usize) -> Self {
        let len = value.len() / leaf_size;
        let merkle_tree = MerkleTreeProver::new(
            (0..len)
                .map(|i| {
                    Helper::as_bytes_vec(
                        &(0..leaf_size)
                            .map(|j| value[i + len * j])
                            .collect::<Vec<_>>(),
                    )
                })
                .collect(),
        );
        Self {
            value,
            leaf_size,
            merkle_tree,
        }
    }

    pub fn leave_num(&self) -> usize {
        self.merkle_tree.leave_num()
    }

    pub fn commit(&self) -> [u8; MERKLE_ROOT_SIZE] {
        self.merkle_tree.commit()
    }

    pub fn query(&self, leaf_indices: &Vec<usize>) -> VQueryResult<T> {
        let len = self.merkle_tree.leave_num();
        assert_eq!(len * self.leaf_size, self.value.len());
        let proof_values = leaf_indices
            .iter()
            .flat_map(|j: &usize| {
                (0..self.leaf_size)
                    .map(|i| (j.clone() + len * i, self.value[j.clone() + len * i]))
                    .collect::<Vec<_>>()
            })
            .collect();
        let proof_bytes = self.merkle_tree.open(&leaf_indices);
        VQueryResult {
            proof_bytes,
            proof_values,
        }
    }
}

#[derive(Clone)]
pub struct Prover<T: PrimeField> {
    total_round: usize,
    interpolate_cosets: Vec<GeneralEvaluationDomain<T>>,
    interpolations: Vec<InterpolateValue<T>>,
    hypercube_interpolation: Vec<T>,
    deep_eval: Vec<DeepEval<T>>,
    shuffle_eval: Option<DeepEval<T>>,
    oracle: RandomOracle<T>,
    final_value: Option<T>,
    final_poly: Option<UnivariatePolynomial<T>>,
    step: usize,
}

impl<T: PrimeField> Prover<T> {
    pub fn new(
        total_round: usize,
        interpolate_cosets: &Vec<GeneralEvaluationDomain<T>>,
        polynomial: MultilinearPolynomial<T>,
        oracle: &RandomOracle<T>,
        step: usize,
    ) -> Self {
        let point = std::iter::successors(Some(oracle.deep[0]), |&x| Some(x * x))
            .take(total_round)
            .collect::<Vec<_>>();
        let hypercube_interpolation = polynomial.evaluate_hypercube();
        Prover {
            total_round,
            interpolate_cosets: interpolate_cosets.clone(),
            interpolations: vec![InterpolateValue::new(
                interpolate_cosets[0].fft(&polynomial.coefficients().clone()),
                1 << step,
            )],
            hypercube_interpolation: hypercube_interpolation.clone(),
            deep_eval: vec![DeepEval::new(point.clone(), hypercube_interpolation)],
            shuffle_eval: None,
            oracle: oracle.clone(),
            final_value: None,
            final_poly: None,
            step,
        }
    }

    pub fn commit_polynomial(&self) -> Commit<T> {
        Commit {
            merkle_root: self.interpolations[0].commit(),
            deep: self.deep_eval[0].first_eval,
        }
    }

    fn evaluation_next_domain(&self, round: usize, challenges: &Vec<T>) -> Vec<T> {
        let mut get_folding_value = self.interpolations[round].value.clone();

        for j in 0..self.step {
            if round * self.step + j == self.total_round {
                break;
            }
            let len = self.interpolate_cosets[round * self.step + j].size();
            let coset = &self.interpolate_cosets[round * self.step + j];
            let challenge = challenges[j];
            let mut tmp_folding_value = vec![];
            for i in 0..(len / 2) {
                let x = get_folding_value[i];
                let nx = get_folding_value[i + len / 2];
                let new_v = (x + nx) + challenge * (x - nx) * coset.element(i).inverse().unwrap();
                tmp_folding_value.push(new_v * T::from(2 as u64).inverse().unwrap());
            }
            get_folding_value = tmp_folding_value;
        }
        get_folding_value
    }

    fn sumcheck_next_domain(hypercube_interpolation: &mut Vec<T>, m: usize, challenge: T) {
        for i in 0..m {
            hypercube_interpolation[i] *= T::from(1 as u64) - challenge;
            let tmp = hypercube_interpolation[i + m] * challenge;
            hypercube_interpolation[i] += tmp;
        }
        hypercube_interpolation.truncate(m);
    }

    pub fn prove(&mut self, point: Vec<T>) {
        let mut hypercube_interpolation = self.hypercube_interpolation.clone();
        self.shuffle_eval = Some(DeepEval::new(
            point.clone(),
            hypercube_interpolation.clone(),
        ));
        for i in 0..self.total_round / self.step + 1 {
            let mut challenges: Vec<T> = vec![];
            for j in 0..self.step {
                if i * self.step + j == self.total_round {
                    break;
                }
                challenges.push(self.oracle.folding_challenges[i * self.step + j]);
            }

            for j in 0..self.step {
                if i * self.step + j == self.total_round {
                    break;
                }
                self.shuffle_eval
                    .as_mut()
                    .unwrap()
                    .append_else_eval(hypercube_interpolation.clone());
                for deep in &mut self.deep_eval {
                    deep.append_else_eval(hypercube_interpolation.clone());
                }

                if i * self.step + j < self.total_round - 1 {
                    let m = 1 << (self.total_round - (i * self.step + j) - 1);
                    Self::sumcheck_next_domain(&mut hypercube_interpolation, m, challenges[j]);
                    self.deep_eval.push({
                        let deep_point = std::iter::successors(
                            Some(self.oracle.deep[i * self.step + j + 1]),
                            |&x| Some(x * x),
                        )
                        .take(self.total_round - (i * self.step + j) - 1)
                        .collect::<Vec<_>>();
                        DeepEval::new(deep_point.clone(), hypercube_interpolation.clone())
                    });
                }
            }

            // let challenge = self.oracle.folding_challenges[i];
            let next_evalutation = self.evaluation_next_domain(i, &challenges);
            if i < self.total_round / self.step - 1 {
                self.interpolations
                    .push(InterpolateValue::new(next_evalutation, 1 << self.step));
            } else if i == self.total_round / self.step - 1 {
                // todo: final_value
                self.interpolations.push(InterpolateValue::new(
                    next_evalutation.clone(),
                    1 << self.step,
                ));
                self.final_poly = Some(UnivariatePolynomial::from_coefficients_vec(
                    self.interpolate_cosets[(i + 1) * self.step].ifft(&next_evalutation),
                ));
            } else {
                assert_eq!(next_evalutation.len(), 1 << CODE_RATE);
                self.final_value = Some(next_evalutation[0]);
            }
        }
    }

    pub fn query(&self) -> Vec<VQueryResult<T>> {
        let mut res = vec![];
        let mut leaf_indices = self.oracle.query_list.clone();

        for i in 0..self.total_round / self.step + 1 {
            let len = self.interpolate_cosets[i * self.step].size();
            leaf_indices = leaf_indices
                .iter_mut()
                .map(|v| *v % (len >> self.step))
                .collect();
            leaf_indices.sort();
            leaf_indices.dedup();
            res.push(self.interpolations[i].query(&leaf_indices));
        }
        res
    }

    pub fn generate_proof(mut self, point: Vec<T>) -> Proof<T> {
        self.prove(point);
        let query_result = self.query();
        Proof {
            merkle_root: (1..self.total_round / self.step)
                .into_iter()
                .map(|x| self.interpolations[x].commit())
                .collect(),
            query_result,
            deep_evals: self
                .deep_eval
                .iter()
                .map(|x| (x.first_eval, x.else_evals.clone()))
                .collect(),
            shuffle_evals: self.shuffle_eval.as_ref().unwrap().else_evals.clone(),
            final_value: self.final_value.unwrap(),
            final_poly: self.final_poly.unwrap(),
            evaluation: self.shuffle_eval.as_ref().unwrap().first_eval,
        }
    }
}

// pub struct BatchProver<T: PrimeField> {
//     total_round: usize,
//     interpolate_cosets: Vec<Coset<T>>,
//     interpolations: Vec<InterpolateValue<T>>,
//     hypercube_interpolations: Vec<Vec<T>>,
//     deep_points: Vec<Vec<T>>,
//     deep_eval: Vec<DeepEval<T>>,
//     shuffle_eval: Option<DeepEval<T>>,
//     oracle: RandomOracle<T>,
//     final_value: Option<T>,
//     final_poly: Option<Polynomial<T>>,
//     step: usize,

//     max_size: u32,
//     polynomials: Vec<MultilinearPolynomial<T>>,
//     poly_sizes: Vec<u32>,
// }

// impl<T: PrimeField> BatchProver<T> {
//     pub fn new(
//         // total_round: usize,
//         interpolate_cosets: &Vec<Coset<T>>,
//         polynomials: Vec<MultilinearPolynomial<T>>,
//         oracle: &RandomOracle<T>,
//         step: usize,
//     ) -> Self {
//         let mut sorted_polys = polynomials.clone();
//         sorted_polys.sort_by(|f, g| g.coefficients().len().cmp(&f.coefficients().len()));
//         let total_round: usize = sorted_polys[0].coefficients().len().ilog2() as usize;

//         // point: (a, a^2^1, a^2^2, ... a^2^\mu)
//         let point = std::iter::successors(Some(oracle.deep[0]), |&x| Some(x * x))
//         .take(total_round)
//         .collect::<Vec<_>>();

//         let hypercube_interpolations =
//             sorted_polys.clone().into_iter().map(|p| p.evaluate_hypercube()).collect::<Vec<Vec<T>>>();

//         BatchProver {
//             total_round,
//             interpolate_cosets: interpolate_cosets.clone(),
//             interpolations: vec![InterpolateValue::new(
//                 interpolate_cosets[0].fft(sorted_polys[0].coefficients().clone()),
//                 2,
//             )],
//             hypercube_interpolations: hypercube_interpolations.clone(),
//             deep_points: vec![point.clone()],
//             deep_eval: vec![DeepEval::new(point.clone(), hypercube_interpolations[0].clone())],
//             shuffle_eval: None,
//             oracle: oracle.clone(),
//             final_value: None,
//             final_poly: None,
//             step,
//             max_size: sorted_polys[0].coefficients().len().ilog2(),
//             polynomials: sorted_polys.clone(),
//             poly_sizes: sorted_polys.into_iter().map(|p| p.coefficients().len().ilog2()).collect::<Vec<u32>>(),
//         }
//     }

//     pub fn commit_polynomials(&self) -> Vec<Commit<T>> {
//         let mut commits = vec![];
//         let point = &self.deep_points[0];
//         for i in 0..self.polynomials.len() {
//             // let hypercube_interpolation = self.polynomials[i].evaluate_hypercube();
//             let fold_round = self.poly_sizes[0] - self.poly_sizes[i];
//             commits.push(
//                 Commit {
//                     merkle_root: InterpolateValue::new(
//                         self.interpolate_cosets[fold_round as usize].fft(self.polynomials[i].coefficients().clone()),
//                         2,
//                     ).commit(),
//                     deep: DeepEval::new(point[i..].to_vec(), self.hypercube_interpolations[i].clone()).first_eval,
//                 }
//             );
//         }
//         commits
//     }

//     fn evaluation_next_domain(&self, round: usize, challenges: &Vec<T>) -> Vec<T> {
//         let mut get_folding_value = self.interpolations[round].value.clone();

//         for j in 0..self.step {
//             if round * self.step + j == self.total_round {
//                 break;
//             }
//             let len = self.interpolate_cosets[round * self.step + j].size();
//             let coset = &self.interpolate_cosets[round * self.step + j];
//             let challenge = challenges[j];
//             let mut tmp_folding_value = vec![];
//             for i in 0..(len / 2) {
//                 let x = get_folding_value[i];
//                 let nx = get_folding_value[i + len / 2];
//                 let new_v = (x + nx) + challenge * (x - nx) * coset.element_inv_at(i);
//                 tmp_folding_value.push(new_v * T::inverse_2());
//             }
//             get_folding_value = tmp_folding_value;
//         }
//         get_folding_value
//     }

//     fn sumcheck_next_domain(hypercube_interpolation: &mut Vec<T>, m: usize, challenge: T) {
//         for i in 0..m {
//             hypercube_interpolation[i] *= T::from_int(1) - challenge;
//             let tmp = hypercube_interpolation[i + m] * challenge;
//             hypercube_interpolation[i] += tmp;
//         }
//         hypercube_interpolation.truncate(m);
//     }

//     pub fn prove(&mut self, point: Vec<T>) {
//         let mut hypercube_interpolation = self.hypercube_interpolation.clone();
//         self.shuffle_eval = Some(DeepEval::new(
//             point.clone(),
//             hypercube_interpolation.clone(),
//         ));
//         for i in 0..self.total_round / self.step + 1 {
//             let mut challenges: Vec<T> = vec![];
//             for j in 0..self.step {
//                 if i * self.step + j == self.total_round {
//                     break;
//                 }
//                 challenges.push(self.oracle.folding_challenges[i * self.step + j]);
//             }

//             for j in 0..self.step {
//                 if i * self.step + j == self.total_round {
//                     break;
//                 }
//                 self.shuffle_eval
//                     .as_mut()
//                     .unwrap()
//                     .append_else_eval(hypercube_interpolation.clone());
//                 for deep in &mut self.deep_eval {
//                     deep.append_else_eval(hypercube_interpolation.clone());
//                 }

//                 if i * self.step + j < self.total_round - 1 {
//                     let m = 1 << (self.total_round - (i * self.step + j) - 1);
//                     Self::sumcheck_next_domain(&mut hypercube_interpolation, m, challenges[j]);
//                     self.deep_eval.push({
//                         let deep_point = std::iter::successors(
//                             Some(self.oracle.deep[i * self.step + j + 1]),
//                             |&x| Some(x * x),
//                         )
//                         .take(self.total_round - (i * self.step + j) - 1)
//                         .collect::<Vec<_>>();
//                         DeepEval::new(deep_point.clone(), hypercube_interpolation.clone())
//                     });
//                 }
//             }

//             // let challenge = self.oracle.folding_challenges[i];
//             let next_evalutation = self.evaluation_next_domain(i, &challenges);
//             if i < self.total_round / self.step - 1 {
//                 self.interpolations
//                     .push(InterpolateValue::new(next_evalutation, 1 << self.step));
//             } else if i == self.total_round / self.step - 1 {
//                 // todo: final_value
//                 self.interpolations.push(InterpolateValue::new(
//                     next_evalutation.clone(),
//                     1 << self.step,
//                 ));
//                 self.final_poly = Some(Polynomial::new(
//                     self.interpolate_cosets[(i + 1) * self.step].ifft(next_evalutation),
//                 ));
//             } else {
//                 assert_eq!(next_evalutation.len(), 1 << CODE_RATE);
//                 self.final_value = Some(next_evalutation[0]);
//             }
//         }
//     }

//     pub fn query(&self) -> Vec<QueryResult<T>> {
//         let mut res = vec![];
//         let mut leaf_indices = self.oracle.query_list.clone();

//         for i in 0..self.total_round / self.step + 1 {
//             let len = self.interpolate_cosets[i * self.step].size();
//             leaf_indices = leaf_indices
//                 .iter_mut()
//                 .map(|v| *v % (len >> self.step))
//                 .collect();
//             leaf_indices.sort();
//             leaf_indices.dedup();
//             res.push(self.interpolations[i].query(&leaf_indices));
//         }
//         res
//     }

//     pub fn generate_proof(mut self, point: Vec<T>) -> Proof<T> {
//         self.prove(point);
//         let query_result = self.query();
//         Proof {
//             merkle_root: (1..self.total_round / self.step)
//                 .into_iter()
//                 .map(|x| self.interpolations[x].commit())
//                 .collect(),
//             query_result,
//             deep_evals: self
//                 .deep_eval
//                 .iter()
//                 .map(|x| (x.first_eval, x.else_evals.clone()))
//                 .collect(),
//             shuffle_evals: self.shuffle_eval.as_ref().unwrap().else_evals.clone(),
//             final_value: self.final_value.unwrap(),
//             final_poly: self.final_poly.unwrap(),
//             evaluation: self.shuffle_eval.as_ref().unwrap().first_eval,
//         }
//     }
// }

use super::verifier::One2ManyVerifier;
use ark_ff::PrimeField;
use ark_poly::{EvaluationDomain, GeneralEvaluationDomain};
use utils::helper::MultilinearPolynomial;

use utils::merkle_tree::MERKLE_ROOT_SIZE;
use utils::query_result::QueryResult;
use utils::CODE_RATE;
use utils::{
    helper::Helper,
    merkle_tree::MerkleTreeProver,
    fiat_shamir::RandomOracle,
};
use ark_std::{start_timer, end_timer};


#[derive(Clone)]
struct InterpolateValue<T: PrimeField> {
    value: Vec<T>,
    merkle_tree: MerkleTreeProver,
}

impl<T: PrimeField> InterpolateValue<T> {
    fn new(value: Vec<T>) -> Self {
        let step = start_timer!(|| "Merkle tree first");
        let len = value.len() / 2;
        let merkle_tree = MerkleTreeProver::new(
            (0..len)
                .map(|i| Helper::to_bytes_vec(&[value[i], value[i + len]]))
                .collect(),
        );
        end_timer!(step);
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
pub struct One2ManyProver<T: PrimeField> {
    total_round: usize,
    interpolate_cosets: Vec<GeneralEvaluationDomain<T>>,
    functions: Vec<InterpolateValue<T>>,
    foldings: Vec<InterpolateValue<T>>,
    oracle: RandomOracle<T>,
    final_value: Option<T>,
}

impl<T: PrimeField> One2ManyProver<T> {
    pub fn new(
        total_round: usize,
        interpolate_coset: &Vec<GeneralEvaluationDomain<T>>,
        polynomial: MultilinearPolynomial<T>,
        oracle: &RandomOracle<T>,
    ) -> One2ManyProver<T> {

        let step = start_timer!(|| "NTT");
        let interpolation = interpolate_coset[0].fft(&polynomial.coefficients());
        end_timer!(step);

        One2ManyProver {
            total_round,
            interpolate_cosets: interpolate_coset.clone(),
            functions: vec![InterpolateValue::new(interpolation)],
            foldings: vec![],
            oracle: oracle.clone(),
            final_value: None,
        }
    }

    pub fn commit_polynomial(&self) -> [u8; MERKLE_ROOT_SIZE] {
        assert_eq!(self.functions.len(), 1);
        let step = start_timer!(|| "Merkle tree second");
        let commit = self.functions[0].commit();
        end_timer!(step);
        commit
    }

    pub fn open(&mut self, verifier: &mut One2ManyVerifier<T>, open_point: &Vec<T>) -> (Vec<QueryResult<T>>, Vec<QueryResult<T>>) {
        self.commit_functions(&open_point, verifier);
        self.prove();
        self.commit_foldings(verifier);
        let (folding_proof, function_proof) = self.query();
        (folding_proof, function_proof)
    }

    // generate f_1, f_2, ..., f_\mu, where f_\mu is a constant
    pub fn commit_functions(&mut self, open_point: &Vec<T>, 
        verifier: &mut One2ManyVerifier<T>
    ) {
        let mut evaluation = None;
        for round in 0..self.total_round {
            let next_evaluation = Self::fold(
                &self.functions[round].value,
                open_point[round],
                &self.interpolate_cosets[round],
            );
            // push function here
            if round < self.total_round - 1 {
                self.functions.push(InterpolateValue::new(next_evaluation));
            } else {
                assert_eq!(next_evaluation.len(), 1 << CODE_RATE);
                // evaluation = Some(next_evaluation);
                // let mut coefficients = self.interpolate_cosets[round + 1].ifft(&next_evaluation);
                // coefficients.truncate(1 << (self.variable_num - self.total_round));
                // // Univariate polynomial is also a multilinear polynomial
                // evaluation = Some(MultilinearPolynomial::new(coefficients));
                evaluation = Some(next_evaluation[0]);
            }
        }
        for i in 1..self.total_round {
            let function = &self.functions[i];
            verifier.set_function(function.leave_num(), &function.commit());
        }
        verifier.set_evaluation(evaluation.unwrap());
    }

    fn fold(values: &Vec<T>, parameter: T, coset: &GeneralEvaluationDomain<T>) -> Vec<T> {
        let len = values.len() / 2;
        let res = (0..len)
            .into_iter()
            .map(|i| {
                let x = values[i];
                let nx = values[i + len];
                let new_v = (x + nx) + parameter * (x - nx) * coset.element(i).inverse().unwrap();
                new_v * T::from(2 as u64).inverse().unwrap()
            })
            .collect();
        res
    }

    pub fn commit_foldings(&self, verifier: &mut One2ManyVerifier<T>) {
        for i in 0..(self.total_round - 1) {
            let interpolation = &self.foldings[i];
            verifier.receive_folding_root(interpolation.leave_num(), interpolation.commit());
        }
        verifier.set_final_value(self.final_value.unwrap());
    }

    // generate and push foldings, p_0, p_1, ..., p_\mu, where
    // p_0 = g_0(X) + \alpha_0 h_0(X), and f_0(X) = g_0(X^2) + X h_0(X^2)
    // \phi_1(X) = p_0 + \alpha_0^2 f_1,
    // p_1 = g_1 + alpha_1 h_1, and \phi_1(X) = g_1(X^2) + X h_1(X^2) 
    fn evaluation_next_domain(&self, round: usize, last_challenge: Option<T>, cur_challenge: T) -> Vec<T> {
        let mut res = vec![];
        let len = self.interpolate_cosets[round].size();
        let get_folding_value = if round == 0 {
            &self.functions[round]
        } else {
            &self.foldings[round - 1]
        };
        let coset = &self.interpolate_cosets[round];
        for i in 0..(len / 2) {
            if round == 0 {
                assert_eq!(last_challenge, None);
                let x = get_folding_value.value[i];
                let nx = get_folding_value.value[i + len / 2];
                let new_v = (x + nx) + cur_challenge * (x - nx) * coset.element(i).inverse().unwrap();
                res.push(new_v);
            } else {
                let fv = &self.functions[round];
                let x = fv.value[i];
                let nx = fv.value[i + len / 2];
                let last_challenge_square = last_challenge.unwrap().pow([2 as u64]);
                let phi_x = get_folding_value.value[i] + last_challenge_square * x;
                let phi_nx = get_folding_value.value[i + len / 2] + last_challenge_square * nx;
                let new_v =
                    (phi_x + phi_nx) + cur_challenge * (phi_x - phi_nx) * coset.element(i).inverse().unwrap();
                res.push(new_v);
            }
        }
        res
    }

    // generate and push foldings, p_0, p_1, ..., p_\mu, where
    // p_0 = g_0(X) + \alpha_0 h_0(X), and f_0(X) = g_0(X^2) + X h_0(X^2)
    // \phi_1(X) = p_0 + \alpha_0 ^2 f_1
    // p_1 = g_1(X) + \alpha_1 h_1(X), and \phi_1(X) = g_1(X^2) + X h_1(X^2)
    // \phi_2(X) = p_1 + \alpha_1 ^2 f_2
    // ....
    // \phi_{\mu}(X) = p_{\mu - 1} + \alpha_{\mu - 1}^2 f_\mu
    pub fn prove(&mut self) {
        for i in 0..self.total_round {
            let cur_challenge = self.oracle.folding_challenges[i];
            let mut last_challenge = None;
            if i > 0 {
                last_challenge = Some(self.oracle.folding_challenges[i-1]);
            }
            if i < self.total_round - 1 {
                let next_evalutation = self.evaluation_next_domain(i, last_challenge, cur_challenge);
                self.foldings.push(InterpolateValue::new(next_evalutation));
            } else {
                let next_evalutation = self.evaluation_next_domain(i, last_challenge, cur_challenge);
                assert_eq!(next_evalutation.len(), 1 << CODE_RATE);
                // let coefficients = self.interpolate_cosets[i + 1].ifft(&next_evalutation);
                // self.final_value = Some(UnivariatePolynomial::from_coefficients_vec(coefficients));
                self.final_value = Some(next_evalutation[0]);
            }
        }
    }

    pub fn query(&self) -> (Vec<QueryResult<T>>, Vec<QueryResult<T>>) {
        let mut folding_res = vec![];
        let mut functions_res = vec![];
        let mut leaf_indices = self.oracle.query_list.clone();

        for i in 0..self.total_round {
            let len = self.interpolate_cosets[i].size();
            leaf_indices = leaf_indices.iter_mut().map(|v| *v % (len >> 1)).collect();
            leaf_indices.sort();
            leaf_indices.dedup();

            let query_result = self.functions[i].query(&leaf_indices);
            functions_res.push(query_result);

            if i > 0 {
                folding_res.push(self.foldings[i - 1].query(&leaf_indices));
            }
        }
        (folding_res, functions_res)
    }

}

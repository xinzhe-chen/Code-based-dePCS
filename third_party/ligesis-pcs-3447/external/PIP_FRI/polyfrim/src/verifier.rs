use ark_ff::PrimeField;
use utils::merkle_tree::MERKLE_ROOT_SIZE;
use utils::fiat_shamir::RandomOracle;
use ark_poly::{EvaluationDomain, GeneralEvaluationDomain};
use utils::{
    merkle_tree::MerkleTreeVerifier,
    query_result::QueryResult,
};

#[derive(Clone)]
pub struct One2ManyVerifier<T: PrimeField> {
    total_round: usize,
    interpolate_cosets: Vec<GeneralEvaluationDomain<T>>,
    function_root: Vec<MerkleTreeVerifier>,
    folding_root: Vec<MerkleTreeVerifier>,
    oracle: RandomOracle<T>,
    final_value: Option<T>,
    evaluation: Option<T>,
    open_point: Vec<T>,
}

impl<T: PrimeField> One2ManyVerifier<T> {
    pub fn new(
        total_round: usize,
        coset: &Vec<GeneralEvaluationDomain<T>>,
        commit: [u8; MERKLE_ROOT_SIZE],
        oracle: &RandomOracle<T>,
        open_point: &Vec<T>,
    ) -> Self {
        One2ManyVerifier {
            total_round,
            interpolate_cosets: coset.clone(),
            function_root: vec![MerkleTreeVerifier {
                merkle_root: commit,
                leave_number: coset[0].size() / 2,
            }],
            folding_root: vec![],
            oracle: oracle.clone(),
            final_value: None,
            evaluation: None,
            open_point: open_point.clone(),
        }
    }

    pub fn get_open_point(&self) -> Vec<T> {
        self.open_point.clone()
    }

    pub fn set_evaluation(&mut self, evaluation: T) {
        self.evaluation = Some(evaluation);
    }

    pub fn set_function(&mut self, leave_number: usize, function_root: &[u8; MERKLE_ROOT_SIZE]) {
        self.function_root.push(MerkleTreeVerifier {
            merkle_root: function_root.clone(),
            leave_number,
        });
    }

    pub fn receive_folding_root(
        &mut self,
        leave_number: usize,
        folding_root: [u8; MERKLE_ROOT_SIZE],
    ) {
        self.folding_root.push(MerkleTreeVerifier {
            leave_number,
            merkle_root: folding_root,
        });
    }

    pub fn set_final_value(&mut self, value: T) {
        // assert!(value.degree() <= 1 << (self.log_max_degree - self.total_round));
        self.final_value = Some(value);
    }


    // p_0 = g_0(X) + \alpha_0 h_0(X), and f_0(X) = g_0(X^2) + X h_0(X^2)
    // \phi_1(X) = p_0 + \alpha_0 ^2 f_1
    // p_1 = g_1(X) + \alpha_1 h_1(X), and \phi_1(X) = g_1(X^2) + X h_1(X^2)
    // \phi_2(X) = p_1 + \alpha_1 ^2 f_2
    // ....
    // \phi_{\mu}(X) = p_{\mu - 1} + \alpha_{\mu - 1}^2 f_\mu
    pub fn verify(
        &self,
        folding_proof: &Vec<QueryResult<T>>,
        function_proof: &Vec<QueryResult<T>>,
        evaluation: T,
    ) -> bool {
        let mut leaf_indices = self.oracle.query_list.clone();
        for i in 0..self.total_round {
            let domain_size = self.interpolate_cosets[i].size();
            leaf_indices = leaf_indices
                .iter_mut()
                .map(|v| *v % (domain_size >> 1))
                .collect();
            leaf_indices.sort();
            leaf_indices.dedup();

            if i == 0 {
                function_proof[i].verify_merkle_tree(&leaf_indices, &self.function_root[i]);
            } else {
                function_proof[i].verify_merkle_tree(&leaf_indices, &self.function_root[i]);
                folding_proof[i - 1].verify_merkle_tree(&leaf_indices, &self.folding_root[i - 1]);
            }

            let last_challenge = if i == 0 {
                None
            } 
            else {
                Some(self.oracle.folding_challenges[i-1])
            };
            let cur_challenge = self.oracle.folding_challenges[i];

            // f_0, p_0, p_1, ..., p_{\mu-2}
            // p_{\mu - 1} is a constant
            let get_folding_value = if i == 0 {
                &function_proof[i].proof_values
            } else {
                &folding_proof[i - 1].proof_values
            };

            // f_0, f_1, ..., f_{\mu - 1}
            // f_{\mu} is a constant
            let function_values = &function_proof[i].proof_values;

            for j in &leaf_indices {
                // verifier folding proofs
                let f_x = function_values[j];
                let f_nx = function_values[&(j + domain_size / 2)];

                if i != 0 {
                    let p_x = get_folding_value[j];
                    let p_nx = get_folding_value[&(j + domain_size / 2)];

                    let last_challenge_square = last_challenge.unwrap().pow([2 as u64]);
                    let phi_x = p_x + last_challenge_square * f_x;
                    let phi_nx = p_nx + last_challenge_square * f_nx;

                    let new_v = (phi_x + phi_nx) + cur_challenge * (phi_x - phi_nx) * self.interpolate_cosets[i].element(*j).inverse().unwrap();
                    if i == self.total_round - 1 {
                        if new_v != self.final_value.unwrap() {
                            return false;
                        }
                    } else if new_v != folding_proof[i].proof_values[j] {
                        return false;
                    }
                } else {
                    let x = get_folding_value[j];
                    let nx = get_folding_value[&(j + domain_size / 2)];
                    let v = x + nx + cur_challenge * (x - nx) * self.interpolate_cosets[i].element(*j).inverse().unwrap();
                    if v != folding_proof[i].proof_values[j] {
                        return false;
                    }
                }

                // verify function_proofs
                let v = (f_x + f_nx) + self.open_point[i] * (f_x - f_nx) * self.interpolate_cosets[i].element(*j).inverse().unwrap();
                if i < self.total_round - 1 {
                    assert_eq!(v, function_proof[i + 1].proof_values[j] * T::from(2 as u64));
                } else {
                    assert_eq!(v, evaluation * T::from(2 as u64));
                    assert_eq!(v, self.evaluation.unwrap() * T::from(2 as u64));
                }
            }
        }
        true
    }
}

use std::collections::HashMap;

use ark_ff::PrimeField;
use utils::merkle_tree::MERKLE_ROOT_SIZE;
use utils::fiat_shamir::RandomOracle;
use utils::{merkle_tree::MerkleTreeVerifier, query_result::QueryResult};
use ark_poly::{EvaluationDomain, GeneralEvaluationDomain};
use utils::interpolate_vecs_value::*;

#[derive(Clone, Debug)]
pub struct ZKVerifier<T: PrimeField> {
    total_round: usize,
    interpolate_cosets: Vec<GeneralEvaluationDomain<T>>,
    initial_proof: MerkleTreeVerifier,
    function_root: Vec<MerkleTreeVerifier>,
    folding_root: Vec<MerkleTreeVerifier>,
    oracle: RandomOracle<T>,
    final_value: Option<T>,
    evaluation: Option<T>,
    evaluation_s: Option<T>,
    open_point: Vec<T>,
    combination: Vec<T>,
}

impl<T: PrimeField> ZKVerifier<T> {
    pub fn new(
        total_round: usize,
        // for rlc_polynomial
        commitment: [u8; MERKLE_ROOT_SIZE],
        coset: &Vec<GeneralEvaluationDomain<T>>,
        oracle: &RandomOracle<T>,
        open_point: &Vec<T>,
        combination: &Vec<T>,
    ) -> Self {
        ZKVerifier {
            total_round,
            interpolate_cosets: coset.clone(),
            initial_proof: MerkleTreeVerifier::new(coset[0].size()/2, &commitment),
            function_root: vec![],
            folding_root: vec![],
            oracle: oracle.clone(),
            final_value: None,
            evaluation: None,
            evaluation_s: None,
            open_point: open_point.clone(),
            combination: combination.clone(),
        }
    }

    pub fn get_combination(&self) -> Vec<T> {
        self.combination.clone()
    }

    pub fn set_evaluation(&mut self, evaluation: T) {
        self.evaluation = Some(evaluation);
    }

    pub fn set_s_evaluation(&mut self, evaluation_s: T) {
        self.evaluation_s = Some(evaluation_s);
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
        self.final_value = Some(value);
    }

    pub fn verify(
        &self,
        polynomial_proof: &QueryVecsResult<T>,
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
                polynomial_proof.verify_merkle_tree(&leaf_indices, &self.initial_proof);
            } else {
                function_proof[i - 1].verify_merkle_tree(&leaf_indices, &self.function_root[i - 1]);
                folding_proof[i - 1].verify_merkle_tree(&leaf_indices, &self.folding_root[i - 1]);
            }

            let last_challenge = if i == 0 {
                None
            } 
            else {
                Some(self.oracle.folding_challenges[i - 1])
            };
            let cur_challenge = self.oracle.folding_challenges[i];

            // rlc_polynomial, p_0, p_1, ..., p_{\mu-2}
            // p_{\mu - 1} is a constant
            // when i = 0, need to construct rlc polynomial
            let get_folding_value = if i == 0 {
                let values_map = &polynomial_proof.proof_values;
                let mut new_map: HashMap<usize, T> = HashMap::new();
                for j in &leaf_indices {
                    let f_x_values = &values_map[j];
                    let f_nx_values = &values_map[&(j + domain_size / 2)];

                    // println!("f_x_values len: {:?}", f_nx_values.len());

                    let mut f_x_final = f_x_values[0];
                    let mut f_nx_final = f_nx_values[0];
                    assert_eq!(f_x_values.len(), f_nx_values.len());
                    for k in 1..f_x_values.len() {
                        f_x_final *= self.oracle.rlc;
                        f_x_final += f_x_values[k];

                        f_nx_final *= self.oracle.rlc;
                        f_nx_final += f_nx_values[k];
                    }
                    new_map.insert(*j, f_x_final);
                    new_map.insert(j + domain_size / 2, f_nx_final);
                }
                new_map
            } else {
                folding_proof[i - 1].proof_values.clone()
            };

            // f_0, f_1, ..., f_{\mu - 1}
            // f_{\mu} is a constant
            // function[0] is the virtual f_0
            let function_values = if i == 0 {
                let values_map = &polynomial_proof.proof_values;
                let mut new_map: HashMap<usize, T> = HashMap::new();
                for j in &leaf_indices {
                    let f_x_values = &values_map[j];
                    let f_nx_values = &values_map[&(j + domain_size / 2)];

                    let mut f_x_final = T::zero();
                    let mut f_nx_final = T::zero();
                    // f_x_values have s, but combination does not
                    assert_eq!(f_x_values.len(), self.combination.len() + 1);
                    for k in 0..f_x_values.len() - 1 {
                        f_x_final += f_x_values[k] * self.combination[k];
                        f_nx_final += f_nx_values[k] * self.combination[k];
                    }
                    new_map.insert(*j, f_x_final);
                    new_map.insert(j + domain_size / 2, f_nx_final);
                }
                new_map
            } else {
                function_proof[i - 1].proof_values.clone()
            };
            
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
                    if i != 0 {
                        assert_eq!(v, function_proof[i].proof_values[j] * T::from_u64(2 as u64).unwrap());
                    }
                } else {
                    assert_eq!(v, (evaluation + self.oracle.rlc * self.evaluation_s.unwrap()) * T::from_u64(2 as u64).unwrap());
                    assert_eq!(v, self.evaluation.unwrap() * T::from_u64(2 as u64).unwrap());
                }
            }
        }
        true
    }
}

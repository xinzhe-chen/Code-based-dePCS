use std::collections::HashMap;
use ark_ff::PrimeField;
use utils::interpolate_vecs_value::QueryVecsResult;
use utils::merkle_tree::MERKLE_ROOT_SIZE;
use utils::fiat_shamir::RandomOracle;
use utils::{merkle_tree::MerkleTreeVerifier, query_result::QueryResult};
use ark_poly::{EvaluationDomain, GeneralEvaluationDomain};

#[derive(Clone)]
pub struct ZKFriVerifier<T: PrimeField> {
    total_round: usize,
    interpolate_cosets: Vec<GeneralEvaluationDomain<T>>,
    vector_interpolation_coset: GeneralEvaluationDomain<T>,
    us_root: MerkleTreeVerifier,
    h_root: Option<MerkleTreeVerifier>,
    folding_root: Vec<MerkleTreeVerifier>,
    oracle: RandomOracle<T>,
    final_value: Option<T>,
    evaluation: Option<T>,
    evaluation_s: Option<T>,
    open_point: Option<Vec<T>>,
}

impl<T: PrimeField> ZKFriVerifier<T> {
    pub fn new(
        total_round: usize,
        coset: &Vec<GeneralEvaluationDomain<T>>,
        vector_interpolation_coset: &GeneralEvaluationDomain<T>,
        polynomial_commitment: [u8; MERKLE_ROOT_SIZE],
        oracle: &RandomOracle<T>,
    ) -> Self {
        ZKFriVerifier {
            total_round,
            interpolate_cosets: coset.clone(),
            vector_interpolation_coset: vector_interpolation_coset.clone(),
            us_root: MerkleTreeVerifier {
                leave_number: coset[0].size() / 2,
                merkle_root: polynomial_commitment,
            },
            h_root: None,
            folding_root: vec![],
            oracle: oracle.clone(),
            final_value: None,
            open_point: None,
            evaluation: None,
            evaluation_s: None,
        }
    }

    pub fn set_evaluation(&mut self, v: T) {
        self.evaluation = Some(v);
    }

    pub fn set_evaluation_s(&mut self, s: T) {
        self.evaluation_s = Some(s);
    }


    pub fn get_open_point(&mut self, point: &Vec<T>) {
        self.open_point = Some(point.clone());
    }

    pub fn set_h_root(&mut self, h_root: [u8; MERKLE_ROOT_SIZE]) {
        self.h_root = Some(MerkleTreeVerifier {
            merkle_root: h_root,
            leave_number: self.interpolate_cosets[0].size() / 2,
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
        assert_ne!(value, T::ZERO);
        self.final_value = Some(value);
    }

    pub fn verify(
        &self,
        evaluation: T,
        folding_proofs: &Vec<QueryResult<T>>,
        v_values: &HashMap<usize, T>,
        function_us_proof: &QueryVecsResult<T>,
        function_h_proof: &QueryResult<T>,
    ) -> bool {
        let mut leaf_indices = self.oracle.query_list.clone();
        let rlc = self.oracle.rlc;
        let h_size = T::from(self.vector_interpolation_coset.size() as u64);
        for i in 0..self.total_round {
            let domain_size = self.interpolate_cosets[i].size();
            leaf_indices = leaf_indices
                .iter_mut()
                .map(|v| *v % (domain_size >> 1))
                .collect();
            leaf_indices.sort();
            leaf_indices.dedup();

            if i == 0 {
                assert!(function_us_proof.verify_merkle_tree(&leaf_indices, &self.us_root));
                assert!(function_h_proof
                    .verify_merkle_tree(&leaf_indices, &self.h_root.as_ref().unwrap()));
            } else {
                folding_proofs[i - 1].verify_merkle_tree(&leaf_indices, &self.folding_root[i - 1]);
            }

            let challenge = self.oracle.folding_challenges[i];
            let get_folding_value = |index: &usize| {
                if i == 0 {
                    let us: &Vec<T> = &function_us_proof.proof_values[index];

                    let h = function_h_proof.proof_values[index];
                    let v = v_values[index];
                    let x = self.interpolate_cosets[i].element(*index);
                    let x_inv = self.interpolate_cosets[i].element(*index).inverse().unwrap();

                    let mut res = us[0];
                    let mut acc = rlc;
                    res += h * acc;
                    acc *= rlc;
                    res += acc
                        * ((us[0] * v + rlc * us[1]) * h_size
                            - self.vector_interpolation_coset.evaluate_vanishing_polynomial(x) * h * h_size
                            - evaluation - rlc * self.evaluation_s.unwrap())
                        * x_inv;
                    res
                } else {
                    folding_proofs[i - 1].proof_values[index]
                }
            };

            for j in &leaf_indices {
                let x = get_folding_value(j);
                let nx = get_folding_value(&(j + domain_size / 2));
                let v =
                    x + nx + challenge * (x - nx) * self.interpolate_cosets[i].element(*j).inverse().unwrap();
                if i < self.total_round - 1 {
                    if v != folding_proofs[i].proof_values[j] {
                        // panic!("{}", i);
                        return false;
                    }
                } else {
                    if v != self.final_value.unwrap() {
                        // panic!();
                        return false;
                    }
                }
            }
        }
        true
    }
}

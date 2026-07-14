use ark_ff::PrimeField;
use ark_poly::{EvaluationDomain, GeneralEvaluationDomain};
use utils::fiat_shamir::RandomOracle;
use utils::interpolate_vecs_value::QueryVecsResult;
use utils::merkle_tree::MERKLE_ROOT_SIZE;
use utils::{merkle_tree::MerkleTreeVerifier, query_result::QueryResult};

#[derive(Clone)]
pub struct Verifier<T: PrimeField> {
    total_round: usize,
    interpolate_cosets: Vec<GeneralEvaluationDomain<T>>,
    interpolation_roots: Vec<MerkleTreeVerifier>,
    oracle: RandomOracle<T>,
    final_value: Option<T>,
    open_point: T,
}

impl<T: PrimeField> Verifier<T> {
    pub fn new(
        total_round: usize,
        coset: &Vec<GeneralEvaluationDomain<T>>,
        commit: [u8; MERKLE_ROOT_SIZE],
        oracle: &RandomOracle<T>,
        open_point: T,
    ) -> Self {
        Verifier {
            total_round,
            interpolate_cosets: coset.clone(),
            oracle: oracle.clone(),
            interpolation_roots: vec![MerkleTreeVerifier::new(coset[0].size() / 2, &commit)],
            final_value: None,
            open_point: open_point,
        }
    }

    pub fn get_open_point(&self) -> T {
        self.open_point
    }

    pub fn receive_interpolation_root(
        &mut self,
        leave_number: usize,
        interpolation_root: [u8; MERKLE_ROOT_SIZE],
    ) {
        self.interpolation_roots.push(MerkleTreeVerifier {
            leave_number,
            merkle_root: interpolation_root,
        });
    }

    pub fn set_final_value(&mut self, value: T) {
        self.final_value = Some(value);
    }

    pub fn verify(&self, interpolation_proof: &Vec<QueryResult<T>>, evaluation: T) -> bool {
        let mut leaf_indices = self.oracle.query_list.clone();
        for i in 0..self.total_round {
            let domain_size = self.interpolate_cosets[i].size();
            leaf_indices = leaf_indices
                .iter_mut()
                .map(|v| *v % (domain_size >> 1))
                .collect();
            leaf_indices.sort();
            leaf_indices.dedup();

            interpolation_proof[i].verify_merkle_tree(&leaf_indices, &self.interpolation_roots[i]);

            let challenge = self.oracle.folding_challenges[i];
            let get_folding_value: Box<dyn Fn(&usize) -> T> = if i == 0 {
                Box::new(|x| {
                    (interpolation_proof[0].proof_values[x] - evaluation)
                        * (self.interpolate_cosets[0].element(*x) - self.open_point)
                            .inverse()
                            .unwrap()
                })
            } else {
                Box::new(|x| interpolation_proof[i].proof_values[x])
            };
            for j in &leaf_indices {
                let x = (*get_folding_value)(j);
                let nx = (*get_folding_value)(&(j + domain_size / 2));
                let v = x
                    + nx
                    + challenge
                        * (x - nx)
                        * self.interpolate_cosets[i].element(*j).inverse().unwrap();
                let v = v * T::from_u64(2).unwrap().inverse().unwrap();
                if i == self.total_round - 1 {
                    assert_eq!(v, self.final_value.unwrap());
                } else {
                    assert_eq!(v, interpolation_proof[i + 1].proof_values[j]);
                }
            }
        }
        true
    }
}

#[derive(Clone)]
pub struct BatchVerifier<T: PrimeField> {
    total_round: usize,
    interpolate_cosets: Vec<GeneralEvaluationDomain<T>>,
    interpolation_initial_root: MerkleTreeVerifier,
    interpolation_roots: Vec<MerkleTreeVerifier>,
    oracle: RandomOracle<T>,
    final_value: Option<T>,
    open_points: Vec<T>,
}

impl<T: PrimeField> BatchVerifier<T> {
    pub fn new(
        total_round: usize,
        coset: &Vec<GeneralEvaluationDomain<T>>,
        commit: [u8; MERKLE_ROOT_SIZE],
        oracle: &RandomOracle<T>,
        open_points: &Vec<T>,
    ) -> Self {
        BatchVerifier {
            total_round,
            interpolate_cosets: coset.clone(),
            oracle: oracle.clone(),
            interpolation_initial_root: MerkleTreeVerifier::new(coset[0].size() / 2, &commit),
            interpolation_roots: vec![],
            final_value: None,
            open_points: open_points.clone(),
        }
    }

    pub fn receive_interpolation_root(
        &mut self,
        leave_number: usize,
        interpolation_root: [u8; MERKLE_ROOT_SIZE],
    ) {
        self.interpolation_roots.push(MerkleTreeVerifier {
            leave_number,
            merkle_root: interpolation_root,
        });
    }

    pub fn set_final_value(&mut self, value: T) {
        self.final_value = Some(value);
    }

    pub fn verify(
        &self,
        (interpolation_initial_proof, interpolation_proof): &(
            QueryVecsResult<T>,
            Vec<QueryResult<T>>,
        ),
        evaluations: &Vec<T>,
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
                interpolation_initial_proof
                    .verify_merkle_tree(&leaf_indices, &self.interpolation_initial_root);
            } else {
                interpolation_proof[i - 1]
                    .verify_merkle_tree(&leaf_indices, &self.interpolation_roots[i - 1]);
            }

            let challenge = self.oracle.folding_challenges[i];
            let get_folding_value: Box<dyn Fn(&usize) -> T> = if i == 0 {
                Box::new(|x| {
                    let vec = &interpolation_initial_proof.proof_values[x];
                    let mut final_value = T::zero();
                    let mut rlc_challenge = T::one();
                    for j in 0..vec.len() {
                        let value = (vec[j] - evaluations[j])
                            * (self.interpolate_cosets[0].element(*x) - self.open_points[j])
                                .inverse()
                                .unwrap();
                        let value = value * rlc_challenge;
                        rlc_challenge *= self.oracle.rlc;
                        final_value += value;
                    }
                    final_value
                })
            } else {
                Box::new(|x| interpolation_proof[i - 1].proof_values[x])
            };
            for j in &leaf_indices {
                let x = (*get_folding_value)(j);
                let nx = (*get_folding_value)(&(j + domain_size / 2));
                let v = x
                    + nx
                    + challenge
                        * (x - nx)
                        * self.interpolate_cosets[i].element(*j).inverse().unwrap();
                let v = v * T::from_u64(2).unwrap().inverse().unwrap();
                if i == self.total_round - 1 {
                    assert_eq!(v, self.final_value.unwrap());
                } else {
                    // TODO: not right here
                    assert_eq!(v, interpolation_proof[i].proof_values[j]);
                }
            }
        }
        true
    }
}

// The verifier of defri
#[derive(Clone)]
pub struct BatchFRIVerifier<T: PrimeField> {
    total_round: usize,
    interpolate_cosets: Vec<GeneralEvaluationDomain<T>>,
    interpolation_initial_root: MerkleTreeVerifier,
    interpolation_roots: Vec<MerkleTreeVerifier>,
    oracle: RandomOracle<T>,
    final_value: Option<T>,
    // open_points: Vec<T>,
}

impl<T: PrimeField> BatchFRIVerifier<T> {
    pub fn new(
        total_round: usize,
        coset: &Vec<GeneralEvaluationDomain<T>>,
        commit: [u8; MERKLE_ROOT_SIZE],
        oracle: &RandomOracle<T>,
        // open_points: &Vec<T>,
    ) -> Self {
        BatchFRIVerifier {
            total_round,
            interpolate_cosets: coset.clone(),
            oracle: oracle.clone(),
            interpolation_initial_root: MerkleTreeVerifier::new(coset[0].size() / 2, &commit),
            interpolation_roots: vec![],
            final_value: None,
            // open_points: open_points.clone(),
        }
    }

    pub fn receive_interpolation_root(
        &mut self,
        leave_number: usize,
        interpolation_root: [u8; MERKLE_ROOT_SIZE],
    ) {
        self.interpolation_roots.push(MerkleTreeVerifier {
            leave_number,
            merkle_root: interpolation_root,
        });
    }

    pub fn set_final_value(&mut self, value: T) {
        self.final_value = Some(value);
    }

    pub fn verify(
        &self,
        (interpolation_initial_proof, interpolation_proof): &(
            QueryVecsResult<T>,
            Vec<QueryResult<T>>,
        ),
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
                // println!("verifying round: {} merkle tree", i);
                interpolation_initial_proof
                    .verify_merkle_tree(&leaf_indices, &self.interpolation_initial_root);
            } else {
                // println!("verifying round: {} merkle tree", i);
                interpolation_proof[i - 1]
                    .verify_merkle_tree(&leaf_indices, &self.interpolation_roots[i - 1]);
            }

            let challenge = self.oracle.folding_challenges[i];
            let get_folding_value: Box<dyn Fn(&usize) -> T> = if i == 0 {
                Box::new(|x| {
                    let vec = &interpolation_initial_proof.proof_values[x];
                    let mut final_value = T::zero();
                    let mut rlc_challenge = T::one();
                    for j in 0..vec.len() {
                        let value = vec[j] * rlc_challenge;
                        rlc_challenge *= self.oracle.rlc;
                        final_value += value;
                    }
                    final_value
                })
            } else {
                Box::new(|x| interpolation_proof[i - 1].proof_values[x])
            };

            for j in &leaf_indices {
                let x = (*get_folding_value)(j);
                let nx = (*get_folding_value)(&(j + domain_size / 2));
                let v = x
                    + nx
                    + challenge
                        * (x - nx)
                        * self.interpolate_cosets[i].element(*j).inverse().unwrap();
                let v = v * T::from_u64(2).unwrap().inverse().unwrap();

                if i == self.total_round - 1 {
                    assert_eq!(v, self.final_value.unwrap());
                } else {
                    // TODO: not right here
                    // println!("verifier round: {}, challenge: {}", i, j);
                    assert_eq!(v, interpolation_proof[i].proof_values[j]);
                }
            }
        }
        true
    }
}

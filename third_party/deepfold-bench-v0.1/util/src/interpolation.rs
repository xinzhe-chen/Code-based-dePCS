use crate::merkle_tree::{hash_field_leaf, MERKLE_ROOT_SIZE};
use crate::query_result::QueryResult;
use crate::{algebra::field::MyField, merkle_tree::MerkleTreeProver};
use rayon::prelude::*;

#[derive(Clone)]
pub struct InterpolateValue<T: MyField> {
    pub value: Vec<T>,
    leaf_size: usize,
    merkle_tree: MerkleTreeProver,
}

impl<T: MyField> InterpolateValue<T> {
    pub fn new(value: Vec<T>, leaf_size: usize) -> Self {
        let len = value.len() / leaf_size;
        let leaf_hashes = (0..len)
            .into_par_iter()
            .map(|i| hash_field_leaf((0..leaf_size).map(|j| value[i + len * j])))
            .collect();
        let merkle_tree = MerkleTreeProver::from_leaf_hashes(leaf_hashes, len);
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

    pub fn query(&self, leaf_indices: &Vec<usize>) -> QueryResult<T> {
        let len = self.merkle_tree.leave_num();
        assert_eq!(len * self.leaf_size, self.value.len());
        let mut proof_values = Vec::with_capacity(leaf_indices.len() * self.leaf_size);
        for &j in leaf_indices {
            for i in 0..self.leaf_size {
                proof_values.push(self.value[j + len * i]);
            }
        }
        let proof_bytes = self.merkle_tree.open(&leaf_indices);
        QueryResult {
            proof_bytes,
            proof_values,
        }
    }
}

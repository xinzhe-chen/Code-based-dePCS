use crate::merkle_tree::MERKLE_ROOT_SIZE;
use crate::query_result::QueryResult;
use crate::{helper::Helper, merkle_tree::MerkleTreeProver};
use ark_ff::PrimeField;

#[derive(Clone)]
pub struct ComOpenOneVec<T: PrimeField> {
    pub vec: Vec<T>,
    merkle_tree: MerkleTreeProver,
}

// TODO: Add ComOpenMulVecs
impl<T: PrimeField> ComOpenOneVec<T> {
    // As the two entries are either both opened or un-opened, they can be put in the same entry
    pub fn new(vec: Vec<T>) -> Self {
        let len = vec.len() / 2;
        let merkle_tree = MerkleTreeProver::new(
            (0..len)
                .map(|i| Helper::to_bytes_vec(&[vec[i], vec[i + len]]))
                .collect(),
        );
        Self { vec, merkle_tree }
    }

    pub fn leave_num(&self) -> usize {
        self.merkle_tree.leave_num()
    }

    pub fn commit(&self) -> [u8; MERKLE_ROOT_SIZE] {
        self.merkle_tree.commit()
    }

    pub fn open(&self, leaf_indices: &Vec<usize>) -> QueryResult<T> {
        let len = self.merkle_tree.leave_num();
        let proof_values = leaf_indices
            .iter()
            .flat_map(|j| [(*j, self.vec[*j]), (*j + len, self.vec[*j + len])])
            .collect();
        let proof_bytes = self.merkle_tree.open(&leaf_indices);
        QueryResult {
            proof_bytes,
            proof_values,
        }
    }
}

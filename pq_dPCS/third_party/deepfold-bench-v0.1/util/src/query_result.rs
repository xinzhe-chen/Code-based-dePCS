use crate::algebra::field::MyField;
use crate::merkle_tree::{hash_field_leaf, MerkleTreeVerifier};
use serde::{Deserialize, Serialize};
use std::mem::size_of;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct QueryResult<T: MyField> {
    pub proof_bytes: Vec<u8>,
    // Queried leaf values in canonical order: for each queried leaf index (in
    // the verifier's sorted/deduped order) the `leaf_size` values at
    // `idx + j*len`. The indices are recomputable from the oracle, so they are
    // not stored on the wire (saving 8 bytes per value vs a HashMap key).
    pub proof_values: Vec<T>,
}

impl<T: MyField> QueryResult<T> {
    pub fn assert_canonical_len(&self, leaf_indices: &[usize], leaf_size: usize) {
        assert_eq!(
            self.proof_values.len(),
            leaf_indices.len() * leaf_size,
            "query proof_values length mismatch"
        );
    }

    /// Read a value keyed by the original interpolation index without
    /// rebuilding a HashMap. The key must be of the form `idx + j * len`, where
    /// `idx` is in the verifier's sorted/deduped leaf index list.
    pub fn value_at(&self, leaf_indices: &[usize], leaf_size: usize, len: usize, key: usize) -> T {
        self.assert_canonical_len(leaf_indices, leaf_size);
        let idx = key % len;
        let column = key / len;
        assert!(column < leaf_size, "query value column out of range");
        let row = match leaf_indices.binary_search(&idx) {
            Ok(row) => row,
            Err(_) => panic!("query value index missing"),
        };
        self.proof_values[row * leaf_size + column]
    }

    pub fn verify_merkle_tree(
        &self,
        leaf_indices: &Vec<usize>,
        leaf_size: usize,
        merkle_verifier: &MerkleTreeVerifier,
    ) -> bool {
        let len = merkle_verifier.leave_number;
        self.assert_canonical_len(leaf_indices, leaf_size);
        let leaf_hashes = leaf_indices
            .iter()
            .map(|x| {
                hash_field_leaf(
                    (0..leaf_size)
                        .map(|j| self.value_at(leaf_indices, leaf_size, len, *x + j * len)),
                )
            })
            .collect::<Vec<_>>();
        let res =
            merkle_verifier.verify_with_leaf_hashes(&self.proof_bytes, leaf_indices, &leaf_hashes);
        assert!(res);
        res
    }

    pub fn proof_size(&self) -> usize {
        self.proof_bytes.len() + self.proof_values.len() * size_of::<T>()
    }
}

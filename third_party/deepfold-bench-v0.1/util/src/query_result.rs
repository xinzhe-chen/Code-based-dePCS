use crate::algebra::field::{as_bytes_vec, MyField};
use crate::merkle_tree::MerkleTreeVerifier;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
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
    /// Rebuild the `index -> value` map from canonical-order `proof_values`.
    /// Fails closed (panics) unless exactly `leaf_indices.len() * leaf_size`
    /// values are present, so tampered length / missing / extra values reject.
    pub fn values_to_map(
        &self,
        leaf_indices: &[usize],
        leaf_size: usize,
        len: usize,
    ) -> HashMap<usize, T> {
        assert_eq!(
            self.proof_values.len(),
            leaf_indices.len() * leaf_size,
            "query proof_values length mismatch"
        );
        let mut map = HashMap::with_capacity(self.proof_values.len());
        for (p, idx) in leaf_indices.iter().enumerate() {
            for j in 0..leaf_size {
                map.insert(*idx + j * len, self.proof_values[p * leaf_size + j]);
            }
        }
        map
    }

    pub fn verify_merkle_tree(
        &self,
        leaf_indices: &Vec<usize>,
        leaf_size: usize,
        merkle_verifier: &MerkleTreeVerifier,
    ) -> bool {
        let len = merkle_verifier.leave_number;
        let values = self.values_to_map(leaf_indices, leaf_size, len);
        let leaves: Vec<Vec<u8>> = leaf_indices
            .iter()
            .map(|x| {
                as_bytes_vec(
                    &(0..leaf_size)
                        .map(|j| values[&(*x + j * len)])
                        .collect::<Vec<_>>(),
                )
            })
            .collect();
        let res = merkle_verifier.verify(self.proof_bytes.clone(), leaf_indices, &leaves);
        assert!(res);
        res
    }

    pub fn proof_size(&self) -> usize {
        self.proof_bytes.len() + self.proof_values.len() * size_of::<T>()
    }
}

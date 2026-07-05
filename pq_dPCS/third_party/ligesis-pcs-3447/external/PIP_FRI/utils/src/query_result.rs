use crate::helper::Helper;
use crate::merkle_tree::Blake3Algorithm;
use crate::merkle_tree::MerkleTreeVerifier;
use crate::merkle_tree::MERKLE_ROOT_SIZE;
use ark_ff::PrimeField;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use rs_merkle::MerkleTree;
use std::collections::HashMap;
use std::mem::size_of;

#[derive(Clone, Debug)]
pub struct QueryResult<T: PrimeField> {
    pub proof_bytes: Vec<u8>,
    pub proof_values: HashMap<usize, T>,
}

impl<T: PrimeField> QueryResult<T> {
    pub fn new() -> Self {
        let proof_bytes: Vec<u8> = Vec::new();
        let proof_values: HashMap<usize, T> = HashMap::new();

        QueryResult {
            proof_bytes,
            proof_values,
        }
    }

    pub fn verify_merkle_tree(
        &self,
        leaf_indices: &Vec<usize>,
        merkle_verifier: &MerkleTreeVerifier,
    ) -> bool {
        let leaves: Vec<Vec<u8>> = leaf_indices
            .iter()
            .map(|x| {
                Helper::to_bytes_vec(&[
                    self.proof_values.get(x).unwrap().clone(),
                    self.proof_values
                        .get(&(x + merkle_verifier.leave_number))
                        .unwrap()
                        .clone(),
                ])
            })
            .collect();
        let res = merkle_verifier.verify(self.proof_bytes.clone(), leaf_indices, &leaves);
        assert!(res);
        res
    }

    pub fn combine_proof_values(
        query_vecs: &Vec<QueryResult<T>>,
        sub_vec_size: usize,
    ) -> HashMap<usize, T> {
        let n = query_vecs.len(); // 4
        let vec_size = n * sub_vec_size; // 8192
        let sub_tree_size = sub_vec_size / 2; // 1024
        let tree_size = vec_size / 2; // 4096
        let mut merged_map: HashMap<usize, T> = HashMap::new();

        for (i, query) in query_vecs.iter().enumerate() {
            for (&key, value) in &query.proof_values {
                let mut new_key = 0;
                if key < sub_tree_size {
                    new_key = key + i * sub_tree_size;
                } else if key >= sub_tree_size {
                    new_key = key - sub_tree_size + i * sub_tree_size + tree_size;
                }
                merged_map.insert(new_key, value.clone());
            }
        }

        assert_eq!(
            query_vecs
                .iter()
                .map(|q| q.proof_values.len())
                .sum::<usize>(),
            merged_map.len()
        );

        merged_map
    }

    pub fn combine_proof_bytes(
        query_results: &Vec<QueryResult<T>>,
        sub_tree_layer_size: &Vec<Vec<usize>>,
        sub_tree_roots: &Vec<[u8; 32]>,
        open_indices: Vec<usize>,
    ) -> Vec<u8> {
        let mut result = Vec::new();
        let n = query_results.len();
        let m = sub_tree_layer_size[0].len();

        let mut start = vec![0; n];
        let mut end = vec![0; n];
        for j in 0..m {
            // println!("layer: {}", j);
            for i in 0..n {
                end[i] = start[i] + sub_tree_layer_size[i][j] * MERKLE_ROOT_SIZE;
                // println!("sub tree: {}, from {} to {}", i, start[i], end[i]);
                result.extend_from_slice(&query_results[i].proof_bytes[start[i]..end[i]]);
                start[i] = end[i];
            }
        }

        // println!("#sub tree: {}, #sub tree layer: {}", n, m);
        // println!("sub tree layer size: {:?}", sub_tree_layer_size);
        let merkle_tree = MerkleTree::<Blake3Algorithm>::from_leaves(sub_tree_roots);
        let proof_bytes = merkle_tree.proof(&open_indices).to_bytes();
        // println!("proof_bytes len: {:?}", proof_bytes.len() / 32);
        // println!("open_indices: {:?}", open_indices);
        result.extend_from_slice(&proof_bytes[..]);

        assert_eq!(
            query_results
                .iter()
                .map(|q| q.proof_bytes.len())
                .sum::<usize>()
                + proof_bytes.len(),
            result.len()
        );

        result
    }

    pub fn path_proof_size(&self) -> usize {
        self.proof_bytes.len()
    }

    pub fn field_proof_size(&self) -> usize {
        self.proof_values.len() * size_of::<T>()
    }

    pub fn proof_size(&self) -> usize {
        self.proof_bytes.len() + self.proof_values.len() * size_of::<T>()
    }
}

#[derive(Clone, Debug, CanonicalDeserialize, CanonicalSerialize)]
pub struct QueryResultTest<T: PrimeField> {
    pub proof_bytes: Vec<u8>,
    pub proof_values_k: Vec<usize>,
    pub proof_values_v: Vec<T>,
}

impl<T: PrimeField> QueryResultTest<T> {
    pub fn from_query_result(query_result: &QueryResult<T>) -> Self {
        let mut keys = Vec::new();
        let mut values = Vec::new();

        for (key, vec) in &query_result.proof_values {
            keys.push(*key);
            values.push(vec.clone());
        }

        QueryResultTest {
            proof_bytes: query_result.proof_bytes.clone(),
            proof_values_k: keys,
            proof_values_v: values,
        }
    }

    pub fn to_query_result(&self) -> QueryResult<T> {
        let mut proof_values = HashMap::new();

        for (key, value) in self.proof_values_k.iter().zip(self.proof_values_v.iter()) {
            proof_values.insert(*key, value.clone());
        }

        QueryResult {
            proof_bytes: self.proof_bytes.clone(),
            proof_values,
        }
    }
}

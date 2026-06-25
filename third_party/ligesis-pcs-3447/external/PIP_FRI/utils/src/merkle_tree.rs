use rs_merkle::{Hasher, MerkleProof, MerkleTree};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone)]
pub struct Blake3Algorithm {}

impl Hasher for Blake3Algorithm {
    type Hash = [u8; MERKLE_ROOT_SIZE];

    fn hash(data: &[u8]) -> [u8; MERKLE_ROOT_SIZE] {
        blake3::hash(data).into()
    }
}

pub const MERKLE_ROOT_SIZE: usize = 32;
#[derive(Clone)]
pub struct MerkleTreeProver {
    pub merkle_tree: MerkleTree<Blake3Algorithm>,
    leave_num: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MerkleTreeVerifier {
    pub merkle_root: [u8; MERKLE_ROOT_SIZE],
    pub leave_number: usize,
}

// The Merkle tree prover
impl MerkleTreeProver {
    pub fn new(leaf_values: Vec<Vec<u8>>) -> Self {
        let leaves = leaf_values
            .iter()
            .map(|x| Blake3Algorithm::hash(x))
            .collect::<Vec<_>>();
        let merkle_tree = MerkleTree::<Blake3Algorithm>::from_leaves(&leaves);
        Self {
            merkle_tree,
            leave_num: leaf_values.len(),
        }
    }

    pub fn leave_num(&self) -> usize {
        self.leave_num
    }

    pub fn commit(&self) -> [u8; MERKLE_ROOT_SIZE] {
        self.merkle_tree.root().unwrap()
    }

    // Take the indices as input, open the entries as bytes
    pub fn open(&self, leaf_indices: &Vec<usize>) -> Vec<u8> {
        self.merkle_tree.proof(leaf_indices).to_bytes()
    }
}

impl MerkleTreeVerifier {
    pub fn new(leave_number: usize, merkle_root: &[u8; MERKLE_ROOT_SIZE]) -> Self {
        Self {
            leave_number,
            merkle_root: merkle_root.clone(),
        }
    }

    // Each leave is a vec of bytes
    pub fn verify(
        &self,
        proof_bytes: Vec<u8>,
        indices: &Vec<usize>,
        leaves: &Vec<Vec<u8>>,
    ) -> bool {
        let proof = MerkleProof::<Blake3Algorithm>::try_from(proof_bytes).unwrap();
        let leaves_to_prove: Vec<[u8; MERKLE_ROOT_SIZE]> =
            leaves.iter().map(|x| Blake3Algorithm::hash(x)).collect();
        proof.verify(
            self.merkle_root,
            indices,
            &leaves_to_prove,
            self.leave_number,
        )
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use super::*;
    use crate::helper::Helper;
    use ark_test_curves::bls12_381::Fq;
    use rand::{seq::SliceRandom, thread_rng};

    fn _get_layer_size(leave_number: usize, leaf_indices: &Vec<usize>) -> (Vec<usize>, usize) {
        let mut current_level: HashSet<usize> = leaf_indices.iter().cloned().collect();
        let mut result = Vec::new();
        let mut total_nodes = leave_number;
        let mut total_size = 0;

        while total_nodes > 1 {
            let mut next_level = HashSet::new();
            let mut sibling_nodes = HashSet::new();

            for &index in &current_level {
                let sibling_index = if index % 2 == 0 { index + 1 } else { index - 1 };
                if sibling_index < total_nodes && !current_level.contains(&sibling_index) {
                    sibling_nodes.insert(sibling_index);
                }
                next_level.insert(index / 2);
            }

            if total_nodes > 2 {
                result.push(sibling_nodes.len());
                total_size += sibling_nodes.len();
            }

            current_level = next_level;
            total_nodes /= 2;
        }

        let num_layer = leave_number.next_power_of_two().trailing_zeros() as usize;
        result.resize(num_layer, 0);

        println!("result: {:?}", result);

        (result, total_size)
    }

    #[test]
    fn commit_and_open() {
        let leaf_values = vec![
            Helper::as_bytes_vec(&[Fq::from(1), Fq::from(2)]),
            Helper::as_bytes_vec(&[Fq::from(3), Fq::from(4)]),
            Helper::as_bytes_vec(&[Fq::from(5), Fq::from(6), Fq::from(6)]),
            Helper::as_bytes_vec(&[Fq::from(7), Fq::from(8)]),
            Helper::as_bytes_vec(&[Fq::from(9), Fq::from(10)]),
            Helper::as_bytes_vec(&[Fq::from(11), Fq::from(12)]),
            Helper::as_bytes_vec(&[Fq::from(13), Fq::from(14)]),
            Helper::as_bytes_vec(&[Fq::from(13), Fq::from(16)]),
        ];
        let leave_number = leaf_values.len();
        let prover = MerkleTreeProver::new(leaf_values);
        let root = prover.commit();
        let verifier = MerkleTreeVerifier::new(leave_number, &root);
        let leaf_indices = vec![2, 3];
        println!("{:?}", leaf_indices);
        let proof_bytes = prover.open(&leaf_indices);
        let open_values = vec![
            Helper::as_bytes_vec(&[Fq::from(5), Fq::from(6), Fq::from(6)]),
            Helper::as_bytes_vec(&[Fq::from(7), Fq::from(8)]),
        ];
        println!("len: {}", proof_bytes.len() / 32);
        assert!(verifier.verify(proof_bytes, &leaf_indices, &open_values));
    }

    #[test]
    fn test_merkle_open() {
        let n = 10;
        let num_open = 32;
        let threshold = 134;
        // let n = 13;
        // let num_open = 16;
        // let threshold = 124;

        let num_leaves: usize = 1 << n;
        let leaf_values: Vec<Vec<u8>> = (0..num_leaves).map(|x| x.to_be_bytes().to_vec()).collect();
        assert_eq!(num_leaves as usize, leaf_values.len());
        let prover = MerkleTreeProver::new(leaf_values);
        let _root = prover.commit();

        let mut rng = thread_rng();
        let mut proof_bytes;
        let mut leaf_indices;
        let mut attempts = 0;
        let mut num_nodes;
        loop {
            attempts += 1;

            let mut indices: Vec<usize> = (0..num_leaves).collect();
            indices.shuffle(&mut rng);
            leaf_indices = indices.into_iter().take(num_open).collect();

            // proof_bytes
            proof_bytes = prover.open(&leaf_indices);
            num_nodes = proof_bytes.len() / 32;

            // check
            if num_nodes <= threshold {
                break;
            }
        }

        println!(
            "num helper nodes: {}, total proof size: {} KB, num of repetitions: {}",
            num_nodes,
            (num_nodes as f64 * 256.0) / 8192.0,
            attempts
        );
    }

    #[test]
    fn test_interweave_merkle_open() {
        // let n = 13;
        // let num_open = 16;
        // let threshold = 206;
        let n = 11;
        let num_open = 32;
        let threshold = 240;

        let num_leaves: usize = 1 << n;
        let leaf_values: Vec<Vec<u8>> = (0..num_leaves).map(|x| x.to_be_bytes().to_vec()).collect();
        assert_eq!(num_leaves as usize, leaf_values.len());
        let prover = MerkleTreeProver::new(leaf_values);
        let _root = prover.commit();

        let mut rng = thread_rng();
        let mut proof_bytes;
        let mut leaf_indices;
        let mut attempts = 0;
        let mut num_nodes;
        loop {
            attempts += 1;

            let odd_indices: Vec<usize> = (0..num_leaves).filter(|x| x % 2 != 0).collect();
            let even_indices: Vec<usize> = (0..num_leaves).filter(|x| x % 2 == 0).collect();

            let mut shuffled_odd_indices = odd_indices.clone();
            let mut shuffled_even_indices = even_indices.clone();
            shuffled_odd_indices.shuffle(&mut rng);
            shuffled_even_indices.shuffle(&mut rng);

            let selected_odd_indices: Vec<usize> =
                shuffled_odd_indices.into_iter().take(num_open).collect();
            let selected_even_indices: Vec<usize> =
                shuffled_even_indices.into_iter().take(num_open).collect();

            leaf_indices = [selected_odd_indices, selected_even_indices].concat();
            leaf_indices.sort();

            proof_bytes = prover.open(&leaf_indices);
            num_nodes = proof_bytes.len() / 32;

            if num_nodes <= threshold {
                break;
            }
        }

        println!(
            "num helper nodes: {}, total proof size: {} KB, num of repetitions: {}",
            num_nodes,
            (num_nodes as f64 * 256.0) / 8192.0,
            attempts
        );
    }

    #[test]
    fn blake3() {
        let hash_res = Blake3Algorithm::hash("data".as_bytes());
        let hex_string = hex::encode(hash_res);
        assert_eq!(
            "28a249c2e4d3a92bc0a16ed8f1b5cf83ca20415ee12e502b096624902bbc97bd",
            hex_string
        );
    }
}

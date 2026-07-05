use crate::hash::*;
use ark_ff::PrimeField;

// Re-export DEFAULT_LEAF_SIZE from hash module
pub use crate::hash::DEFAULT_LEAF_SIZE;
pub const LEAF_SIZE: usize = 16;

/// Compute leaf hashes from field evaluations
/// Returns (leaf_hashes, actual_leaf_size)
pub fn compute_leaf_hashes<F: PrimeField>(v: &[F]) -> (Vec<Byte32>, usize) {
    let leaf_size = LEAF_SIZE.min(v.len());
    let step = v.len() / leaf_size;
    let leaves: Vec<Byte32> = (0..step)
        .map(|i| {
            let leaf: Vec<F> = (0..leaf_size).map(|j| v[i + j * step]).collect();
            compute_sha256_row(&leaf)
        })
        .collect();
    (leaves, leaf_size)
}

/// Build Merkle tree from field evaluations
/// Dynamically adjusts leaf_size: uses min(LEAF_SIZE, v.len())
pub fn build_merkle_tree<F: PrimeField>(v: &Vec<F>) -> MerkleTree {
    let (leaves, leaf_size) = compute_leaf_hashes(v);
    MerkleTree::with_leaf_size(&leaves, leaf_size)
}

/// Open at conjugate points (wrapper for MerkleTree::open_at)
pub fn open_merkle_tree_at_conjugate_points<F: PrimeField>(
    mt: &MerkleTree,
    v: &Vec<F>,
    x: usize,
) -> (usize, (F, F), Vec<F>, Vec<Byte32>) {
    mt.open_at(v, x)
}

/// Verify at conjugate points (wrapper for MerkleTree::verify_at)
pub fn verify_merkle_tree_at_conjugate_points<F: PrimeField>(
    n: usize,
    root: &Byte32,
    x: usize,
    v: &(F, F),
    w: &[F],
    proof: &Vec<Byte32>,
) -> bool {
    MerkleTree::verify_at(root, n, x, v, w, proof)
}

/// Get leaf elements at position x0 with given step and leaf_size
pub fn get_leaf_elements<F: PrimeField>(v: &[F], x0: usize, step: usize, leaf_size: usize) -> Vec<F> {
    (0..leaf_size).map(|j| v[x0 + j * step]).collect()
}

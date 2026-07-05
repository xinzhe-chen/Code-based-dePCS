use crate::algebra::field::MyField;
use rayon::prelude::*;

pub const MERKLE_ROOT_SIZE: usize = 32;
pub type Hash = [u8; MERKLE_ROOT_SIZE];

#[derive(Debug, Clone)]
pub struct Blake3Algorithm {}

impl Blake3Algorithm {
    pub fn hash(data: &[u8]) -> Hash {
        blake3::hash(data).into()
    }
}

pub fn hash_field_leaf<T: MyField>(values: impl IntoIterator<Item = T>) -> Hash {
    let mut hasher = blake3::Hasher::new();
    for value in values {
        hasher.update(&value.to_bytes());
    }
    hasher.finalize().into()
}

#[inline]
fn hash_pair(left: &Hash, right: &Hash) -> Hash {
    let mut hasher = blake3::Hasher::new();
    hasher.update(left);
    hasher.update(right);
    hasher.finalize().into()
}

#[inline]
fn read_hash(buf: &[u8], pos: &mut usize) -> Option<Hash> {
    if *pos + MERKLE_ROOT_SIZE > buf.len() {
        return None;
    }
    let mut h = [0u8; MERKLE_ROOT_SIZE];
    h.copy_from_slice(&buf[*pos..*pos + MERKLE_ROOT_SIZE]);
    *pos += MERKLE_ROOT_SIZE;
    Some(h)
}

/// Build all Merkle layers bottom-up. The leaf layer is padded to a power of two
/// (deterministic zero padding); every internal layer is hashed in parallel,
/// since the parent nodes of one layer are independent. `layers[0]` is the leaf
/// layer and `layers.last()` is the single-element root layer.
fn build_layers(mut leaves: Vec<Hash>) -> Vec<Vec<Hash>> {
    if leaves.is_empty() {
        return vec![vec![[0u8; MERKLE_ROOT_SIZE]]];
    }
    let padded = leaves.len().next_power_of_two();
    leaves.resize(padded, [0u8; MERKLE_ROOT_SIZE]);
    let mut layers = vec![leaves];
    while layers.last().unwrap().len() > 1 {
        let prev = layers.last().unwrap();
        let next: Vec<Hash> = (0..prev.len() / 2)
            .into_par_iter()
            .map(|i| hash_pair(&prev[2 * i], &prev[2 * i + 1]))
            .collect();
        layers.push(next);
    }
    layers
}

#[derive(Clone)]
pub struct MerkleTreeProver {
    layers: Vec<Vec<Hash>>,
    leave_num: usize,
}

#[derive(Debug, Clone)]
pub struct MerkleTreeVerifier {
    pub merkle_root: Hash,
    pub leave_number: usize,
}

impl MerkleTreeProver {
    pub fn from_leaf_hashes(leaves: Vec<Hash>, leave_num: usize) -> Self {
        Self {
            layers: build_layers(leaves),
            leave_num,
        }
    }

    pub fn new(leaf_values: Vec<Vec<u8>>) -> Self {
        let leave_num = leaf_values.len();
        let leaves: Vec<Hash> = leaf_values
            .par_iter()
            .map(|x| Blake3Algorithm::hash(x))
            .collect();
        Self::from_leaf_hashes(leaves, leave_num)
    }

    pub fn leave_num(&self) -> usize {
        self.leave_num
    }

    pub fn commit(&self) -> Hash {
        self.layers.last().unwrap()[0]
    }

    /// Multi-leaf authentication path. `leaf_indices` must be sorted and
    /// deduplicated (both callers guarantee this); the emitted sibling hashes
    /// are ordered by ascending index per layer, which the verifier consumes in
    /// the same order.
    pub fn open(&self, leaf_indices: &[usize]) -> Vec<u8> {
        let mut known = leaf_indices.to_vec();
        known.sort_unstable();
        known.dedup();
        let mut proof: Vec<u8> = Vec::new();
        let mut parents: Vec<usize> = Vec::with_capacity(known.len());
        for level in 0..self.layers.len() - 1 {
            let layer = &self.layers[level];
            parents.clear();
            let mut i = 0;
            while i < known.len() {
                let idx = known[i];
                if idx % 2 == 0 && i + 1 < known.len() && known[i + 1] == idx + 1 {
                    i += 2;
                } else if idx % 2 == 0 {
                    proof.extend_from_slice(&layer[idx + 1]);
                    i += 1;
                } else {
                    proof.extend_from_slice(&layer[idx - 1]);
                    i += 1;
                }
                parents.push(idx / 2);
            }
            std::mem::swap(&mut known, &mut parents);
        }
        proof
    }
}

impl MerkleTreeVerifier {
    pub fn new(leave_number: usize, merkle_root: &Hash) -> Self {
        Self {
            leave_number,
            merkle_root: *merkle_root,
        }
    }

    /// Recompute the root from the queried `leaves` (hashed here) and the
    /// authentication path, and compare against the committed root. Fails closed:
    /// any extra/missing sibling bytes, or a recomputed root mismatch, returns
    /// false. `indices` must be sorted/deduplicated and aligned with `leaves`.
    pub fn verify(&self, proof_bytes: &[u8], indices: &Vec<usize>, leaves: &Vec<Vec<u8>>) -> bool {
        if indices.len() != leaves.len() {
            return false;
        }
        let leaf_hashes: Vec<Hash> = leaves
            .iter()
            .map(|leaf| Blake3Algorithm::hash(leaf))
            .collect();
        self.verify_with_leaf_hashes(proof_bytes, indices, &leaf_hashes)
    }

    pub fn verify_with_leaf_hashes(
        &self,
        proof_bytes: &[u8],
        indices: &[usize],
        leaf_hashes: &[Hash],
    ) -> bool {
        if indices.len() != leaf_hashes.len() {
            return false;
        }
        // Fail-closed: reject out-of-range indices (instead of authenticating a
        // padded slot) and duplicate indices (instead of silently dedup'ing).
        if indices.iter().any(|&idx| idx >= self.leave_number) {
            return false;
        }
        let padded = self.leave_number.next_power_of_two();
        let depth = padded.trailing_zeros() as usize;
        let mut known: Vec<(usize, Hash)> = indices
            .iter()
            .zip(leaf_hashes.iter())
            .map(|(&idx, &leaf_hash)| (idx, leaf_hash))
            .collect();
        known.sort_by_key(|(idx, _)| *idx);
        if known.windows(2).any(|w| w[0].0 == w[1].0) {
            return false;
        }
        let mut pos = 0usize;
        for _level in 0..depth {
            let mut parents: Vec<(usize, Hash)> = Vec::with_capacity(known.len());
            let mut i = 0;
            while i < known.len() {
                let (idx, h) = known[i];
                let (left, right) =
                    if idx % 2 == 0 && i + 1 < known.len() && known[i + 1].0 == idx + 1 {
                        let r = known[i + 1].1;
                        i += 2;
                        (h, r)
                    } else if idx % 2 == 0 {
                        let r = match read_hash(&proof_bytes, &mut pos) {
                            Some(x) => x,
                            None => return false,
                        };
                        i += 1;
                        (h, r)
                    } else {
                        let l = match read_hash(&proof_bytes, &mut pos) {
                            Some(x) => x,
                            None => return false,
                        };
                        i += 1;
                        (l, h)
                    };
                parents.push((idx / 2, hash_pair(&left, &right)));
            }
            known = parents;
        }
        pos == proof_bytes.len() && known.len() == 1 && known[0].1 == self.merkle_root
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::algebra::field::{as_bytes_vec, mersenne61_ext::Mersenne61Ext, MyField};

    #[test]
    fn commit_and_open() {
        let leaf_values = vec![
            as_bytes_vec(&[Mersenne61Ext::from_int(1), Mersenne61Ext::from_int(2)]),
            as_bytes_vec(&[Mersenne61Ext::from_int(3), Mersenne61Ext::from_int(4)]),
            as_bytes_vec(&[Mersenne61Ext::from_int(5), Mersenne61Ext::from_int(6)]),
            as_bytes_vec(&[Mersenne61Ext::from_int(7), Mersenne61Ext::from_int(8)]),
            as_bytes_vec(&[Mersenne61Ext::from_int(9), Mersenne61Ext::from_int(10)]),
            as_bytes_vec(&[Mersenne61Ext::from_int(11), Mersenne61Ext::from_int(12)]),
            as_bytes_vec(&[Mersenne61Ext::from_int(13), Mersenne61Ext::from_int(14)]),
        ];
        let leave_number = leaf_values.len();
        let prover = MerkleTreeProver::new(leaf_values);
        let root = prover.commit();
        let hashed_prover = MerkleTreeProver::from_leaf_hashes(
            vec![
                hash_field_leaf([Mersenne61Ext::from_int(1), Mersenne61Ext::from_int(2)]),
                hash_field_leaf([Mersenne61Ext::from_int(3), Mersenne61Ext::from_int(4)]),
                hash_field_leaf([Mersenne61Ext::from_int(5), Mersenne61Ext::from_int(6)]),
                hash_field_leaf([Mersenne61Ext::from_int(7), Mersenne61Ext::from_int(8)]),
                hash_field_leaf([Mersenne61Ext::from_int(9), Mersenne61Ext::from_int(10)]),
                hash_field_leaf([Mersenne61Ext::from_int(11), Mersenne61Ext::from_int(12)]),
                hash_field_leaf([Mersenne61Ext::from_int(13), Mersenne61Ext::from_int(14)]),
            ],
            leave_number,
        );
        assert_eq!(root, hashed_prover.commit());
        let verifier = MerkleTreeVerifier::new(leave_number, &root);
        let leaf_indices = vec![2, 3];
        let proof_bytes = prover.open(&leaf_indices);
        assert_eq!(proof_bytes, hashed_prover.open(&leaf_indices));
        let open_values = vec![
            as_bytes_vec(&[Mersenne61Ext::from_int(5), Mersenne61Ext::from_int(6)]),
            as_bytes_vec(&[Mersenne61Ext::from_int(7), Mersenne61Ext::from_int(8)]),
        ];
        assert!(verifier.verify(&proof_bytes, &leaf_indices, &open_values));
        let leaf_hashes = open_values
            .iter()
            .map(|leaf| Blake3Algorithm::hash(leaf))
            .collect::<Vec<_>>();
        assert!(verifier.verify_with_leaf_hashes(&proof_bytes, &leaf_indices, &leaf_hashes));
    }

    #[test]
    fn rejects_tampered_leaf() {
        let leaf_values: Vec<Vec<u8>> = (0..8)
            .map(|i| as_bytes_vec(&[Mersenne61Ext::from_int(i as u64)]))
            .collect();
        let prover = MerkleTreeProver::new(leaf_values);
        let root = prover.commit();
        let verifier = MerkleTreeVerifier::new(8, &root);
        let idx = vec![1, 4, 5];
        let proof = prover.open(&idx);
        let good: Vec<Vec<u8>> = [1u64, 4, 5]
            .iter()
            .map(|&i| as_bytes_vec(&[Mersenne61Ext::from_int(i)]))
            .collect();
        assert!(verifier.verify(&proof, &idx, &good));
        let mut bad = good.clone();
        bad[1] = as_bytes_vec(&[Mersenne61Ext::from_int(999)]);
        assert!(!verifier.verify(&proof, &idx, &bad));
        // truncated / extended proof must fail closed
        let mut short = proof.clone();
        short.pop();
        assert!(!verifier.verify(&short, &idx, &good));
        let mut long = proof.clone();
        long.push(0);
        assert!(!verifier.verify(&long, &idx, &good));
    }

    #[test]
    fn rejects_out_of_range_and_duplicate_indices() {
        let leaf_values: Vec<Vec<u8>> = (0..8)
            .map(|i| as_bytes_vec(&[Mersenne61Ext::from_int(i as u64)]))
            .collect();
        let prover = MerkleTreeProver::new(leaf_values);
        let root = prover.commit();
        let verifier = MerkleTreeVerifier::new(8, &root);
        let idx = vec![1, 4];
        let proof = prover.open(&idx);
        let leaves: Vec<Vec<u8>> = [1u64, 4]
            .iter()
            .map(|&i| as_bytes_vec(&[Mersenne61Ext::from_int(i)]))
            .collect();
        assert!(verifier.verify(&proof, &idx, &leaves));
        // out-of-range index (>= leave_number) must be rejected, not authenticated
        // against a padded slot
        assert!(!verifier.verify(&proof, &vec![1, 8], &leaves));
        // duplicate index must be rejected, not silently deduplicated
        assert!(!verifier.verify(&proof, &vec![1, 1], &leaves));
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

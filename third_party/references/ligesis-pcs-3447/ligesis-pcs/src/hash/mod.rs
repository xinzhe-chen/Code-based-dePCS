use ark_ff::Field;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use deNetwork::{DeMultiNet as Net, DeNet, DeSerNet};
use sha2::{Digest, Sha256};

pub type Byte32 = [u8; 32];

/// Default number of field elements per Merkle leaf
pub const DEFAULT_LEAF_SIZE: usize = 8;

pub fn serialize<F: Field>(data: &[F]) -> Vec<u8> {
    let mut serialized = Vec::new();
    for element in data {
        element
            .serialize_with_mode(&mut serialized, ark_serialize::Compress::Yes)
            .expect("Serialization fails");
    }
    serialized
}

pub fn compute_sha256(data: &[u8]) -> Byte32 {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().into()
}

pub fn compute_sha256_row<F: Field>(data: &[F]) -> Byte32 {
    compute_sha256(&serialize(data))
}

fn hash_pair(left: &Byte32, right: &Byte32) -> Byte32 {
    let mut buf = [0u8; 64];
    buf[..32].copy_from_slice(left);
    buf[32..].copy_from_slice(right);
    compute_sha256(&buf)
}

#[derive(CanonicalSerialize, CanonicalDeserialize, Clone, Debug, PartialEq, Eq)]
pub struct MerkleTree {
    n: usize,
    leaf_size: usize,
    digest_layers: Vec<Vec<Byte32>>,
}

impl Default for MerkleTree {
    fn default() -> Self {
        MerkleTree {
            n: 0,
            leaf_size: DEFAULT_LEAF_SIZE,
            digest_layers: Vec::new(),
        }
    }
}

pub type MerkleTreeProof = Vec<Byte32>;

impl MerkleTree {
    pub fn new(leaves: &Vec<Byte32>) -> Self {
        Self::with_leaf_size(leaves, DEFAULT_LEAF_SIZE)
    }

    pub fn with_leaf_size(leaves: &Vec<Byte32>, leaf_size: usize) -> Self {
        let mut digest_layers: Vec<Vec<Byte32>> = Vec::new();
        let n = leaves.len().next_power_of_two().trailing_zeros() as usize + 1;

        digest_layers.push({
            let mut digest_layer = leaves.clone();
            digest_layer.resize(1 << (n - 1), [0u8; 32]);
            digest_layer
        });

        for i in 1..n {
            let prev = &digest_layers[i - 1];
            let digest_layer: Vec<Byte32> = (0..(1usize << (n - i - 1)))
                .map(|j| hash_pair(&prev[j << 1], &prev[j << 1 | 1]))
                .collect();
            digest_layers.push(digest_layer);
        }

        Self { n, leaf_size, digest_layers }
    }

    pub fn leaf_size(&self) -> usize {
        self.leaf_size
    }

    /// Get the number of leaf hashes in this tree (= 2^(n-1))
    pub fn num_leaves(&self) -> usize {
        if self.n == 0 { 0 } else { 1 << (self.n - 1) }
    }

    /// Open at position x, returning conjugate point values and proof
    /// Returns (x, (v[x], v[x']), leaf_elements, proof)
    /// where x' is the conjugate point (x ± n/2)
    pub fn open_at<F: Field>(&self, v: &[F], x: usize) -> (usize, (F, F), Vec<F>, Vec<Byte32>) {
        assert!(v.len() >= self.leaf_size);
        let step = v.len() / self.leaf_size;
        let x0 = x % step;
        let x_prime = if x >= v.len() / 2 {
            x - v.len() / 2
        } else {
            x + v.len() / 2
        };

        let leaf: Vec<F> = (0..self.leaf_size).map(|j| v[x0 + j * step]).collect();

        (x, (v[x], v[x_prime]), leaf, self.prove(x0))
    }

    /// Verify opening at conjugate points
    /// n: total number of elements in v
    /// x: query position
    /// vals: (v[x], v[x']) the conjugate point values
    /// leaf: the leaf_size elements in the queried leaf
    pub fn verify_at<F: Field>(
        root: &Byte32,
        n: usize,
        x: usize,
        vals: &(F, F),
        leaf: &[F],
        proof: &Vec<Byte32>,
    ) -> bool {
        let leaf_size = leaf.len();
        assert!(n >= leaf_size);
        let step = n / leaf_size;
        let x0 = x % step;
        let x_prime = if x >= n / 2 { x - n / 2 } else { x + n / 2 };

        // Check that vals match the leaf elements
        if vals.0 != leaf[x / step] || vals.1 != leaf[x_prime / step] {
            return false;
        }

        Self::verify(root, x0, &compute_sha256_row(leaf), proof)
    }

    /// Distributed Merkle tree construction
    /// Each party provides their local leaves, and the tree is built collaboratively
    /// Returns (Option<MerkleTree>, local_subtree) where:
    /// - Option<MerkleTree> is Some(full_tree) for master, None for workers
    /// - local_subtree is each party's local subtree for generating proofs later
    pub fn d_new(local_leaves: &Vec<Byte32>) -> (Option<Self>, Self) {
        // Build local subtree
        let local_tree = Self::new(local_leaves);
        let local_root = local_tree.root();

        // Gather all local roots to master
        let all_roots_opt = Net::send_to_master(&local_root);

        if Net::am_master() {
            let all_roots: Vec<Byte32> = all_roots_opt.unwrap();

            // Build upper tree from all party roots
            let upper_tree = Self::new(&all_roots);

            // Construct full tree by combining upper tree layers with placeholder for local layers
            // The full tree has: local_layers (from each party) + upper_layers
            let local_depth = local_tree.n;
            let upper_depth = upper_tree.n;
            let full_n = local_depth + upper_depth - 1;

            let mut full_digest_layers = Vec::with_capacity(full_n);

            // For master, store local layers first (these are just master's local layers)
            for layer in &local_tree.digest_layers {
                full_digest_layers.push(layer.clone());
            }

            // Then add upper layers (skip the leaf layer of upper tree since it's the roots)
            for layer in upper_tree.digest_layers.iter().skip(1) {
                full_digest_layers.push(layer.clone());
            }

            let full_tree = Self {
                n: full_n,
                leaf_size: local_tree.leaf_size,
                digest_layers: full_digest_layers,
            };

            (Some(full_tree), local_tree)
        } else {
            (None, local_tree)
        }
    }

    /// Merge local tree with upper tree to create full tree
    /// Used in distributed setting where local tree is built from local leaves
    /// and upper tree is built from all local roots
    pub fn merge_with_upper(&self, upper_tree: &Self) -> Self {
        let local_depth = self.n;
        let upper_depth = upper_tree.n;
        let full_n = local_depth + upper_depth - 1;

        let mut full_digest_layers = Vec::with_capacity(full_n);

        // Store local layers first
        for layer in &self.digest_layers {
            full_digest_layers.push(layer.clone());
        }

        // Then add upper layers (skip the leaf layer which contains local roots)
        for layer in upper_tree.digest_layers.iter().skip(1) {
            full_digest_layers.push(layer.clone());
        }

        Self {
            n: full_n,
            leaf_size: self.leaf_size,
            digest_layers: full_digest_layers,
        }
    }

    /// Distributed prove: generate proof for a global position
    /// - global_pos: the position in the full (virtual) leaf array
    /// - local_tree: each party's local subtree
    /// - upper_tree: the upper tree (only master has this)
    /// Returns Some(proof) for master, None for workers
    pub fn d_prove(
        global_pos: usize,
        local_tree: &Self,
        upper_tree: Option<&Self>,
    ) -> Option<MerkleTreeProof> {
        let num_party = Net::n_parties();
        let local_leaves_count = 1 << (local_tree.n - 1);

        // Determine which party owns this position
        let owner_party = global_pos / local_leaves_count;
        let local_pos = global_pos % local_leaves_count;

        // The owner party generates local proof
        let local_proof = if Net::party_id() == owner_party {
            Some(local_tree.prove(local_pos))
        } else {
            None
        };

        // Gather local proof to master
        let all_local_proofs_opt: Option<Vec<Option<MerkleTreeProof>>> =
            Net::send_to_master(&local_proof);

        if Net::am_master() {
            let all_local_proofs = all_local_proofs_opt.unwrap();
            let local_proof = all_local_proofs[owner_party].clone().unwrap();

            // Generate upper tree proof
            let upper = upper_tree.unwrap();
            let upper_proof = upper.prove(owner_party);

            // Combine: local_proof + upper_proof
            let mut full_proof = local_proof;
            full_proof.extend(upper_proof);

            Some(full_proof)
        } else {
            None
        }
    }

    pub fn root(&self) -> Byte32 {
        *self.digest_layers.last().unwrap().first().unwrap()
    }

    pub fn prove(&self, pos: usize) -> Vec<Byte32> {
        let mut proof = Vec::with_capacity(self.n - 1);
        let mut j = pos;
        for i in 0..(self.n - 1) {
            proof.push(self.digest_layers[i][j ^ 1]);
            j >>= 1;
        }
        proof
    }

    pub fn verify(root: &Byte32, pos: usize, val: &Byte32, proof: &MerkleTreeProof) -> bool {
        let mut now = *val;
        let mut j = pos;
        for sibling in proof {
            now = if j & 1 == 0 {
                hash_pair(&now, sibling)
            } else {
                hash_pair(sibling, &now)
            };
            j >>= 1;
        }
        root == &now
    }
}

#[cfg(test)]
mod tests;

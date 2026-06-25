use super::*;
use ark_std::{
    rand::{Rng, SeedableRng},
    test_rng,
};

fn random_byte32(rng: &mut impl Rng) -> Byte32 {
    let mut array = [0u8; 32];
    rng.fill(&mut array);
    array
}

#[test]
fn test_merkle_tree() {
    let mut rng = test_rng();
    let log_n = 10usize;
    let n = 1usize << log_n;
    let leaves = (0..n).map(|_| random_byte32(&mut rng)).collect();

    let mt = MerkleTree::new(&leaves);

    assert_eq!(mt.digest_layers[0].len(), n);
    assert_eq!(mt.digest_layers[log_n].len(), 1);

    for _ in 0..10 {
        let pos = rng.gen_range(0..n);
        let proof = mt.prove(pos);
        assert!(MerkleTree::verify(&mt.root(), pos, &leaves[pos], &proof));
    }
}

use ark_ff::PrimeField;
use ark_std::{
    cmp::min,
    collections::BTreeSet,
    rand::{Rng, SeedableRng},
    UniformRand,
};
use rand_chacha::ChaCha20Rng;

pub fn random_field_vector<F: PrimeField>(n: usize, seed: [u8; 32]) -> Vec<F> {
    let mut rng = ChaCha20Rng::from_seed(seed);
    random_field_vector_from_rng(n, &mut rng)
}

pub fn random_indices_vector(n: usize, t: usize, seed: [u8; 32]) -> Vec<usize> {
    let mut rng = ChaCha20Rng::from_seed(seed);
    random_indices_vector_from_rng(n, t, &mut rng)
}

pub fn random_field_vector_from_rng<F: PrimeField>(n: usize, rng: &mut impl Rng) -> Vec<F> {
    (0..n).map(|_| F::rand(rng)).collect::<Vec<_>>()
}

pub fn random_indices_vector_from_rng(n: usize, t: usize, rng: &mut impl Rng) -> Vec<usize> {
    let mut selected = BTreeSet::new();
    let to_selected = min(t, n - t);
    while selected.len() < to_selected {
        selected.insert(rng.gen_range(0..n));
    }
    if to_selected == t {
        selected.into_iter().collect()
    } else {
        (0..n).filter(|i| !selected.contains(i)).collect()
    }
}

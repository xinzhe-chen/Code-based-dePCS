use ark_ff::UniformRand;
use ark_poly::DenseUVPolynomial;
use ark_poly::EvaluationDomain;
use ark_std::end_timer;
use ark_std::start_timer;
use fri::prover::BatchProver;
use fri::verifier::BatchVerifier;
use std::vec;
use utils::{goldilocks::Goldilocks as T, CODE_RATE, SECURITY_BITS};
// use ark_ff::PrimeField;
use ark_poly::polynomial::{univariate::DensePolynomial as UnivariatePolynomial, Polynomial};
use ark_std::rand::{rngs::StdRng, SeedableRng};
use utils::fiat_shamir::RandomOracle;
use utils::{helper::Helper, merkle_tree::MERKLE_ROOT_SIZE};

fn main() {
    let poly_num = 1;
    let variable_num: usize = 22;
    let degree: usize = (1 << variable_num) - 1;
    let mut rng = StdRng::seed_from_u64(0u64);
    let mut polynomials = vec![];
    let mut points = vec![];
    let mut evals = vec![];
    for _ in 0..poly_num {
        let polynomial = UnivariatePolynomial::rand(degree, &mut rng);
        let point = T::rand(&mut rng);
        let eval = polynomial.evaluate(&point);
        polynomials.push(polynomial);
        points.push(point);
        evals.push(eval);
    }

    let mut interpolate_cosets =
        vec![EvaluationDomain::new_coset(1 << (variable_num + CODE_RATE), T::from(1)).unwrap()];
    for i in 1..variable_num {
        interpolate_cosets.push(Helper::pow(&interpolate_cosets[i - 1], 2));
    }

    // commit
    let oracle = RandomOracle::new(variable_num, SECURITY_BITS / CODE_RATE);
    let step = start_timer!(|| "commit");
    let mut prover = BatchProver::new(variable_num, &interpolate_cosets, &polynomials, &oracle);
    // 32 bytes = 256 bit
    let com = prover.commit_polynomial();
    end_timer!(step);

    // open
    let mut verifier = BatchVerifier::new(variable_num, &interpolate_cosets, com, &oracle, &points);
    let step = start_timer!(|| "open");
    let proof = prover.open(&points, &evals, &mut verifier);
    end_timer!(step);

    // verify
    let step = start_timer!(|| "verify");
    assert!(verifier.verify(&proof, &evals));
    end_timer!(step);

    // proof size
    let proof_size = proof.0.proof_size()
        + proof.1.iter().map(|x| x.proof_size()).sum::<usize>()
        + (variable_num - 1) * MERKLE_ROOT_SIZE;
    println!("proof size is {:?} KB", proof_size / 1024);
}

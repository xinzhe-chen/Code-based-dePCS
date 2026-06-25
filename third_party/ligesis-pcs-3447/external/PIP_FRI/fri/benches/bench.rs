extern crate criterion;
use std::time::Instant;

use ark_ff::UniformRand;
use ark_poly::polynomial::{univariate::DensePolynomial as UnivariatePolynomial, Polynomial};
use ark_poly::{DenseUVPolynomial, EvaluationDomain};
use criterion::*;
use fri::prover::{BatchProver, Prover};
use fri::verifier::{BatchVerifier, Verifier};
use rand::rngs::StdRng;
use rand::SeedableRng;
use utils::fiat_shamir::RandomOracle;
use utils::goldilocks::Goldilocks as T;
use utils::helper::Helper;
use utils::merkle_tree::MERKLE_ROOT_SIZE;
use utils::{CODE_RATE, SECURITY_BITS};
// usage:
// RAYON_NUM_THREADS=8 cargo bench -p fri
// RAYON_NUM_THREADS=8 cargo bench --features "parallel" -p fri

const SMALL: usize = 20;
const SIZE: usize = 25;
const POLY_NUM: usize = 2;

fn commit(criterion: &mut Criterion, variable_num: usize) {
    let mut rng = StdRng::seed_from_u64(0u64);
    let degree: usize = (1 << variable_num) - 1;
    let polynomial = UnivariatePolynomial::rand(degree, &mut rng);
    let point = T::rand(&mut rng);
    let _eval = polynomial.evaluate(&point);

    let mut interpolate_cosets =
        vec![EvaluationDomain::new_coset(1 << (variable_num + CODE_RATE), T::from(1)).unwrap()];
    for i in 1..variable_num {
        interpolate_cosets.push(Helper::pow(&interpolate_cosets[i - 1], 2));
    }
    let oracle = RandomOracle::new(variable_num, SECURITY_BITS / CODE_RATE);

    criterion.bench_function(&format!("fri-pcs commit {}", variable_num), move |b| {
        b.iter_batched(
            || polynomial.clone(),
            |p| {
                let prover = Prover::new(variable_num, &interpolate_cosets, p, &oracle);
                prover.commit_polynomial();
            },
            BatchSize::SmallInput,
        )
    });
}

fn batch_commit(criterion: &mut Criterion, variable_num: usize, poly_num: usize) {
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
    // 32 bytes = 256 bit

    criterion.bench_function(
        &format!(
            "fri-pcs batch commit {} of {:?} polys",
            variable_num, POLY_NUM
        ),
        move |b| {
            b.iter_batched(
                || polynomials.clone(),
                |p| {
                    let prover = BatchProver::new(variable_num, &interpolate_cosets, &p, &oracle);
                    prover.commit_polynomial();
                },
                BatchSize::SmallInput,
            )
        },
    );
}

fn bench_commit(c: &mut Criterion) {
    for i in SMALL..=SIZE {
        // commit(c, i);
        batch_commit(c, i, POLY_NUM);
    }
}

fn open(criterion: &mut Criterion, variable_num: usize) {
    let degree: usize = (1 << variable_num) - 1;
    let mut rng = StdRng::seed_from_u64(0u64);
    let polynomial = UnivariatePolynomial::rand(degree, &mut rng);
    let point = T::rand(&mut rng);
    let eval = polynomial.evaluate(&point);

    let mut interpolate_cosets =
        vec![EvaluationDomain::new_coset(1 << (variable_num + CODE_RATE), T::from(1)).unwrap()];
    for i in 1..variable_num {
        interpolate_cosets.push(Helper::pow(&interpolate_cosets[i - 1], 2));
    }

    // commit
    let oracle = RandomOracle::new(variable_num, SECURITY_BITS / CODE_RATE);
    let prover = Prover::new(variable_num, &interpolate_cosets, polynomial, &oracle);
    // 32 bytes = 256 bit
    let com = prover.commit_polynomial();

    // Open
    let mut verifier = Verifier::new(variable_num, &interpolate_cosets, com, &oracle, point);
    criterion.bench_function(&format!("fri-pcs open {}", variable_num), move |b| {
        b.iter_batched(
            || prover.clone(),
            |mut p| {
                p.open(point, eval, &mut verifier);
            },
            BatchSize::SmallInput,
        )
    });
}

fn batch_open(criterion: &mut Criterion, variable_num: usize, poly_num: usize) {
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
    let prover = BatchProver::new(variable_num, &interpolate_cosets, &polynomials, &oracle);
    // 32 bytes = 256 bit
    let com = prover.commit_polynomial();

    // Open
    let mut verifier = BatchVerifier::new(variable_num, &interpolate_cosets, com, &oracle, &points);
    criterion.bench_function(&format!("fri-pcs open {}", variable_num), move |b| {
        b.iter_batched(
            || prover.clone(),
            |mut p| p.open(&points, &evals, &mut verifier),
            BatchSize::SmallInput,
        )
    });
}

fn bench_open(c: &mut Criterion) {
    for i in SMALL..=SIZE {
        // open(c, i);
        batch_open(c, i, POLY_NUM);
    }
}

fn verify(criterion: &mut Criterion, variable_num: usize) {
    let degree: usize = (1 << variable_num) - 1;
    let mut rng = StdRng::seed_from_u64(0u64);
    let polynomial = UnivariatePolynomial::rand(degree, &mut rng);
    let point = T::rand(&mut rng);
    let eval = polynomial.evaluate(&point);

    let mut interpolate_cosets =
        vec![EvaluationDomain::new_coset(1 << (variable_num + CODE_RATE), T::from(1)).unwrap()];
    for i in 1..variable_num {
        interpolate_cosets.push(Helper::pow(&interpolate_cosets[i - 1], 2));
    }

    // commit
    let oracle = RandomOracle::new(variable_num, SECURITY_BITS / CODE_RATE);
    let mut prover = Prover::new(variable_num, &interpolate_cosets, polynomial, &oracle);
    // 32 bytes = 256 bit
    let com = prover.commit_polynomial();

    // open
    let mut verifier = Verifier::new(variable_num, &interpolate_cosets, com, &oracle, point);
    let proof = prover.open(point, eval, &mut verifier);

    // Proof size
    let field_proof_size = proof.iter().map(|x| x.field_proof_size()).sum::<usize>();
    let path_proof_size = proof.iter().map(|x| x.path_proof_size()).sum::<usize>()
        + MERKLE_ROOT_SIZE * (variable_num - 1);
    println!(
        "(field, path) proof size is: ({:?}, {:?}) KBytes",
        field_proof_size / 1024,
        path_proof_size / 1024
    );

    criterion.bench_function(&format!("FRI-PCS verify {}", variable_num), move |b| {
        b.iter(|| {
            let is_valid = verifier.verify(&proof, eval);
            assert!(is_valid);
        })
    });
}

fn batch_verify(criterion: &mut Criterion, variable_num: usize, poly_num: usize) {
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
    let mut prover = BatchProver::new(variable_num, &interpolate_cosets, &polynomials, &oracle);
    // 32 bytes = 256 bit
    let com = prover.commit_polynomial();

    // open
    let mut verifier = BatchVerifier::new(variable_num, &interpolate_cosets, com, &oracle, &points);
    let proof = prover.open(&points, &evals, &mut verifier);

    criterion.bench_function(&format!("FRI-PCS verify {}", variable_num), move |b| {
        b.iter(|| {
            let is_valid = verifier.verify(&proof, &evals);
            assert!(is_valid);
        })
    });
}

fn bench_verify(c: &mut Criterion) {
    for i in SMALL..=SIZE {
        // verify(c, i);
        batch_verify(c, i, POLY_NUM);
    }
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(10);
    targets =
    bench_commit,
    bench_open,
    bench_verify
}

criterion_main!(benches);

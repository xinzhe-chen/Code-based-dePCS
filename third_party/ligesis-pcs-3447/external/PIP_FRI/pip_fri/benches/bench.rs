extern crate criterion;
use criterion::*;

use ark_ff::{Field, UniformRand};
use ark_poly::{EvaluationDomain, GeneralEvaluationDomain};
use pip_fri::prover::MERKLE_ROOT_SIZE;
use pip_fri::{prover::Prover, verifier::Verifier, zkprover::ZKProver, zkverifier::ZKVerifier};
use rand::rngs::StdRng;
use rand::SeedableRng;
use utils::fiat_shamir::RandomOracle;
use utils::goldilocks::Goldilocks as T;
use utils::helper::Helper;
use utils::helper::MultilinearPolynomial;
use utils::interpolate_vecs_value::*;
use utils::{CODE_RATE, SECURITY_BITS};

const SMALL: usize = 20;
const SIZE: usize = 25;

#[cfg(feature = "parallel")]
use rayon::prelude::*;
// usage:
// RAYON_NUM_THREADS=8 cargo bench -p pip_fri
// RAYON_NUM_THREADS=8 cargo bench --features "parallel" -p pip_fri

// for fft bench
// on my mac, 8 cores, 4 sub polys, fft total length 23-28, no parallel improve 5%, parallel improves 10%
// change the sub poly number would not improve the result, need to experiment on more cores

// a parallel commitment test for all pcs

// Also add a reason for

fn commit(criterion: &mut Criterion, variable_num: usize) {
    let mut rng = StdRng::seed_from_u64(0u64);
    let polynomial = MultilinearPolynomial::rand(variable_num);
    let point = (0..variable_num)
        .map(|_| T::rand(&mut rng))
        .collect::<Vec<T>>();
    let _eval = polynomial.evaluate(&point);

    // Divide and generate public informations
    let poly_num = get_poly_num(&polynomial);
    println!("poly_nums is: {:?}", poly_num);
    let sub_variable_num = get_sub_variable_num(&polynomial);
    let (_sub_open_point, remaining_var) = point.split_at(sub_variable_num);
    // w_1, w_2, ...,
    let tensor = get_tensor(&remaining_var.to_vec());

    // Setup
    let mut interpolate_cosets = vec![GeneralEvaluationDomain::new_coset(
        1 << (sub_variable_num + CODE_RATE),
        T::rand(&mut rng),
    )
    .unwrap()];
    for i in 1..sub_variable_num {
        interpolate_cosets.push(Helper::pow(&interpolate_cosets[i - 1], 2));
    }
    let oracle = RandomOracle::new(sub_variable_num, SECURITY_BITS / CODE_RATE);

    criterion.bench_function(&format!("pip-fri commit {}", variable_num), move |b| {
        b.iter_batched(
            || polynomial.clone(),
            |p| {
                let mut prover =
                    Prover::new(variable_num, &interpolate_cosets, p, &oracle, &tensor);
                prover.commit_polynomial();
            },
            BatchSize::SmallInput,
        )
    });
}

fn zk_commit(criterion: &mut Criterion, variable_num: usize) {
    let mut rng = StdRng::seed_from_u64(0u64);
    let polynomial = MultilinearPolynomial::rand(variable_num);
    let point = (0..variable_num)
        .map(|_| T::rand(&mut rng))
        .collect::<Vec<T>>();
    let _eval = polynomial.evaluate(&point);

    let sub_variable_num = get_sub_variable_num(&polynomial);
    let (sub_open_point, remaining_var) = point.split_at(sub_variable_num);
    let mut sub_open_point = sub_open_point.to_vec();
    sub_open_point.push(T::ZERO);
    // w_1, w_2, ...,
    let tensor = get_tensor(&remaining_var.to_vec());

    // Setup
    let mut interpolate_cosets = vec![GeneralEvaluationDomain::new_coset(
        1 << (sub_variable_num + 1 + CODE_RATE),
        T::rand(&mut rng),
    )
    .unwrap()];
    for i in 1..(sub_variable_num + 1) {
        interpolate_cosets.push(Helper::pow(&interpolate_cosets[i - 1], 2));
    }
    let oracle = RandomOracle::new(sub_variable_num + 1, SECURITY_BITS / CODE_RATE);

    criterion.bench_function(&format!("zk-pip-fri commit {}", variable_num), move |b| {
        b.iter_batched(
            || polynomial.clone(),
            |p| {
                let mut prover = ZKProver::new(
                    sub_variable_num + 1,
                    &interpolate_cosets,
                    p,
                    &oracle,
                    &tensor,
                );
                prover.commit_polynomial();
            },
            BatchSize::SmallInput,
        )
    });
}

fn bench_commit(c: &mut Criterion) {
    for i in SMALL..=SIZE {
        commit(c, i);
        zk_commit(c, i);
    }
}

fn open(criterion: &mut Criterion, variable_num: usize) {
    let mut rng = StdRng::seed_from_u64(0u64);
    let polynomial = MultilinearPolynomial::rand(variable_num);
    let point = (0..variable_num)
        .map(|_| T::rand(&mut rng))
        .collect::<Vec<T>>();
    let _eval = polynomial.evaluate(&point);

    // Divide and generate public informations
    let _poly_num = get_poly_num(&polynomial);
    let sub_variable_num = get_sub_variable_num(&polynomial);
    let (sub_open_point, remaining_var) = point.split_at(sub_variable_num);
    // w_1, w_2, ...,
    let tensor = get_tensor(&remaining_var.to_vec());

    // Setup
    let mut interpolate_cosets = vec![GeneralEvaluationDomain::new_coset(
        1 << (sub_variable_num + CODE_RATE),
        T::rand(&mut rng),
    )
    .unwrap()];
    for i in 1..sub_variable_num {
        interpolate_cosets.push(Helper::pow(&interpolate_cosets[i - 1], 2));
    }
    let oracle = RandomOracle::new(sub_variable_num, SECURITY_BITS / CODE_RATE);
    let mut prover = Prover::new(
        sub_variable_num,
        &interpolate_cosets,
        polynomial,
        &oracle,
        &tensor,
    );

    // commit
    let commitment = prover.commit_polynomial();
    let mut verifier = Verifier::new(
        sub_variable_num,
        commitment,
        &interpolate_cosets,
        &oracle,
        &sub_open_point.to_vec(),
        &tensor,
    );

    criterion.bench_function(&format!("pip-fri open {}", variable_num), move |b| {
        b.iter_batched(
            || prover.clone(),
            |mut p| p.open(&sub_open_point.to_vec(), &mut verifier),
            BatchSize::SmallInput,
        )
    });
}

fn zk_open(criterion: &mut Criterion, variable_num: usize) {
    let mut rng = StdRng::seed_from_u64(0u64);
    let polynomial = MultilinearPolynomial::rand(variable_num);
    let point = (0..variable_num)
        .map(|_| T::rand(&mut rng))
        .collect::<Vec<T>>();
    let _eval = polynomial.evaluate(&point);

    let sub_variable_num = get_sub_variable_num(&polynomial);
    let (sub_open_point, remaining_var) = point.split_at(sub_variable_num);
    let mut sub_open_point = sub_open_point.to_vec();
    sub_open_point.push(T::ZERO);
    // w_1, w_2, ...,
    let tensor = get_tensor(&remaining_var.to_vec());

    // Setup
    let mut interpolate_cosets = vec![GeneralEvaluationDomain::new_coset(
        1 << (sub_variable_num + 1 + CODE_RATE),
        T::rand(&mut rng),
    )
    .unwrap()];
    for i in 1..(sub_variable_num + 1) {
        interpolate_cosets.push(Helper::pow(&interpolate_cosets[i - 1], 2));
    }
    let oracle = RandomOracle::new(sub_variable_num + 1, SECURITY_BITS / CODE_RATE);
    let mut prover = ZKProver::new(
        sub_variable_num + 1,
        &interpolate_cosets,
        polynomial,
        &oracle,
        &tensor,
    );

    // commit
    let commitment = prover.commit_polynomial();
    let mut verifier = ZKVerifier::new(
        sub_variable_num + 1,
        commitment,
        &interpolate_cosets,
        &oracle,
        &sub_open_point,
        &tensor,
    );

    criterion.bench_function(&format!("zk-pip-fri open {}", variable_num), move |b| {
        b.iter_batched(
            || prover.clone(),
            |mut p| {
                p.open(&sub_open_point, &mut verifier);
            },
            BatchSize::SmallInput,
        )
    });
}

fn bench_open(c: &mut Criterion) {
    for i in SMALL..=SIZE {
        open(c, i);
        zk_open(c, i);
    }
}

fn verify(criterion: &mut Criterion, variable_num: usize) {
    let mut rng = StdRng::seed_from_u64(0u64);
    let polynomial = MultilinearPolynomial::rand(variable_num);
    let point = (0..variable_num)
        .map(|_| T::rand(&mut rng))
        .collect::<Vec<T>>();
    let eval = polynomial.evaluate(&point);

    // Divide and generate public informations
    let _poly_num = get_poly_num(&polynomial);
    let sub_variable_num = get_sub_variable_num(&polynomial);
    let (sub_open_point, remaining_var) = point.split_at(sub_variable_num);
    // w_1, w_2, ...,
    let tensor = get_tensor(&remaining_var.to_vec());

    // Setup
    let mut interpolate_cosets = vec![GeneralEvaluationDomain::new_coset(
        1 << (sub_variable_num + CODE_RATE),
        T::rand(&mut rng),
    )
    .unwrap()];
    for i in 1..sub_variable_num {
        interpolate_cosets.push(Helper::pow(&interpolate_cosets[i - 1], 2));
    }
    let oracle = RandomOracle::new(sub_variable_num, SECURITY_BITS / CODE_RATE);
    let mut prover = Prover::new(
        sub_variable_num,
        &interpolate_cosets,
        polynomial,
        &oracle,
        &tensor,
    );

    // commit
    let commitment = prover.commit_polynomial();
    let mut verifier = Verifier::new(
        sub_variable_num,
        commitment,
        &interpolate_cosets,
        &oracle,
        &sub_open_point.to_vec(),
        &tensor,
    );

    // open
    let (polynomial_proof, folding_proof, function_proof) =
        prover.open(&sub_open_point.to_vec(), &mut verifier);
    let proof_size = folding_proof
        .iter()
        .map(|x| x.path_proof_size())
        .sum::<usize>()
        + polynomial_proof.path_proof_size()
        + function_proof
            .iter()
            .map(|x| x.path_proof_size())
            .sum::<usize>()
        + folding_proof
            .iter()
            .map(|x| x.field_proof_size())
            .sum::<usize>()
        + polynomial_proof.field_proof_size()
        + function_proof
            .iter()
            .map(|x| x.field_proof_size())
            .sum::<usize>()
        + (2 * sub_variable_num - 3) * MERKLE_ROOT_SIZE
        + 2 * size_of::<T>();

    let path_proof_size = folding_proof
        .iter()
        .map(|x| x.path_proof_size())
        .sum::<usize>()
        + polynomial_proof.path_proof_size()
        + function_proof
            .iter()
            .map(|x| x.path_proof_size())
            .sum::<usize>();

    let field_proof_size = folding_proof
        .iter()
        .map(|x| x.field_proof_size())
        .sum::<usize>()
        + polynomial_proof.field_proof_size()
        + function_proof
            .iter()
            .map(|x| x.field_proof_size())
            .sum::<usize>()
        + (2 * sub_variable_num - 3) * MERKLE_ROOT_SIZE
        + 2 * size_of::<T>();

    println!(
        "pip-fri (path, field)_proof_size of {} variables is ({}, {}) Kbytes",
        variable_num,
        path_proof_size / 1024,
        field_proof_size / 1024
    );
    println!(
        "PIP-FRI total proof size for {} variable is {:?} KB",
        variable_num,
        proof_size / 1024
    );

    criterion.bench_function(&format!("pip-fri verify {}", variable_num), move |b| {
        b.iter(|| {
            let is_valid =
                verifier.verify(&polynomial_proof, &folding_proof, &function_proof, eval);
            assert!(is_valid);
        })
    });
}

fn zk_verify(criterion: &mut Criterion, variable_num: usize) {
    let mut rng = StdRng::seed_from_u64(0u64);
    let polynomial = MultilinearPolynomial::rand(variable_num);
    let point = (0..variable_num)
        .map(|_| T::rand(&mut rng))
        .collect::<Vec<T>>();
    let eval = polynomial.evaluate(&point);

    let sub_variable_num = get_sub_variable_num(&polynomial);
    let (sub_open_point, remaining_var) = point.split_at(sub_variable_num);
    let mut sub_open_point = sub_open_point.to_vec();
    sub_open_point.push(T::ZERO);
    // w_1, w_2, ...,
    let tensor = get_tensor(&remaining_var.to_vec());

    // Setup
    let mut interpolate_cosets = vec![GeneralEvaluationDomain::new_coset(
        1 << (sub_variable_num + 1 + CODE_RATE),
        T::rand(&mut rng),
    )
    .unwrap()];
    for i in 1..(sub_variable_num + 1) {
        interpolate_cosets.push(Helper::pow(&interpolate_cosets[i - 1], 2));
    }
    let oracle = RandomOracle::new(sub_variable_num + 1, SECURITY_BITS / CODE_RATE);
    let mut prover = ZKProver::new(
        sub_variable_num + 1,
        &interpolate_cosets,
        polynomial,
        &oracle,
        &tensor,
    );

    // commit
    let commitment = prover.commit_polynomial();
    let mut verifier = ZKVerifier::new(
        sub_variable_num + 1,
        commitment,
        &interpolate_cosets,
        &oracle,
        &sub_open_point,
        &tensor,
    );

    // open
    let (polynomial_proof, folding_proof, function_proof) =
        prover.open(&sub_open_point, &mut verifier);

    let proof_size = folding_proof
        .iter()
        .map(|x| x.path_proof_size())
        .sum::<usize>()
        + polynomial_proof.path_proof_size()
        + function_proof
            .iter()
            .map(|x| x.path_proof_size())
            .sum::<usize>()
        + folding_proof
            .iter()
            .map(|x| x.field_proof_size())
            .sum::<usize>()
        + polynomial_proof.field_proof_size()
        + function_proof
            .iter()
            .map(|x| x.field_proof_size())
            .sum::<usize>()
        + (2 * (sub_variable_num + 1) - 3) * MERKLE_ROOT_SIZE
        + 3 * size_of::<T>();

    let path_proof_size = folding_proof
        .iter()
        .map(|x| x.path_proof_size())
        .sum::<usize>()
        + polynomial_proof.path_proof_size()
        + function_proof
            .iter()
            .map(|x| x.path_proof_size())
            .sum::<usize>();

    let field_proof_size = folding_proof
        .iter()
        .map(|x| x.field_proof_size())
        .sum::<usize>()
        + polynomial_proof.field_proof_size()
        + function_proof
            .iter()
            .map(|x| x.field_proof_size())
            .sum::<usize>()
        + (2 * (sub_variable_num + 1) - 3) * MERKLE_ROOT_SIZE
        + 3 * size_of::<T>();

    println!(
        "zk-pip-fri (path, field)_proof_size of {} variables is ({}, {}) Kbytes",
        variable_num,
        path_proof_size / 1024,
        field_proof_size / 1024
    );
    println!(
        "zk-PIP-FRI total proof size for {} variable is {:?} KB",
        variable_num,
        proof_size / 1024
    );

    criterion.bench_function(&format!("zk-pip-fri verify {}", variable_num), move |b| {
        b.iter(|| {
            let is_valid =
                verifier.verify(&polynomial_proof, &folding_proof, &function_proof, eval);
            assert!(is_valid);
        })
    });
}

fn bench_verify(c: &mut Criterion) {
    for i in SMALL..=SIZE {
        verify(c, i);
        zk_verify(c, i);
    }
}

// turn on or off the parallel feature for arkworks parallel for fft
fn single_fft(criterion: &mut Criterion, variable_num: usize) {
    let polynomial: MultilinearPolynomial<T> = MultilinearPolynomial::rand(variable_num);
    let interpolate_cosets: Vec<GeneralEvaluationDomain<T>> =
        vec![EvaluationDomain::new_coset(1 << (variable_num + CODE_RATE), T::ONE).unwrap()];
    criterion.bench_function(
        &format!("fft log length {}", variable_num + CODE_RATE),
        move |b| {
            b.iter_batched(
                || polynomial.clone(),
                |p| {
                    let _ = &interpolate_cosets[0].fft(p.coefficients());
                },
                BatchSize::SmallInput,
            )
        },
    );
}

fn multi_single_fft(criterion: &mut Criterion, variable_num: usize, log_num: usize) {
    let sub_variable_num = variable_num - log_num;
    let num: usize = 1 << log_num;
    let mut polynomials = vec![];
    for _ in 0..num {
        let polynomial: MultilinearPolynomial<T> = MultilinearPolynomial::rand(sub_variable_num);
        polynomials.push(polynomial);
    }
    let interpolate_cosets: Vec<GeneralEvaluationDomain<T>> =
        vec![EvaluationDomain::new_coset(1 << (sub_variable_num + CODE_RATE), T::ONE).unwrap()];
    criterion.bench_function(
        &format!("multi fft log total length {}", variable_num + CODE_RATE),
        move |b| {
            b.iter_batched(
                || polynomials.clone(),
                |ps| {
                    #[cfg(feature = "parallel")]
                    let _: Vec<_> = ps
                        .par_iter()
                        .map(|p| interpolate_cosets[0].fft(p.coefficients()))
                        .collect();

                    #[cfg(not(feature = "parallel"))]
                    let _: Vec<_> = ps
                        .iter()
                        .map(|p| interpolate_cosets[0].fft(p.coefficients()))
                        .collect();
                },
                BatchSize::SmallInput,
            )
        },
    );
}

fn bench_single_fft(c: &mut Criterion) {
    for i in SMALL..=SIZE {
        single_fft(c, i);
    }
}

fn bench_multi_fft(c: &mut Criterion) {
    for i in SMALL..=SIZE {
        multi_single_fft(c, i, 7);
    }
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(10);
    targets =
    bench_single_fft,
    bench_multi_fft,
    bench_commit,
    bench_open,
    bench_verify
}

criterion_main!(benches);

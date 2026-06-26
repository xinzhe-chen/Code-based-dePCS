extern crate criterion;
use ark_ff::UniformRand;
use ark_poly::EvaluationDomain;
use criterion::*;
use rand::rngs::StdRng;
use rand::SeedableRng;
use std::mem;
use utils::fiat_shamir::RandomOracle;
use utils::goldilocks::Goldilocks as T;
use utils::helper::Helper;
use utils::helper::MultilinearPolynomial;
use utils::merkle_tree::MERKLE_ROOT_SIZE;
use utils::{CODE_RATE, SECURITY_BITS};
use virgo::{
    prover::FriProver, verifier::FriVerifier, zkprover::ZKFriProver, zkverifier::ZKFriVerifier,
};
// usage:
// RAYON_NUM_THREADS=8 cargo bench -p virgo
// RAYON_NUM_THREADS=8 cargo bench --features "parallel" -p virgo

const SMALL: usize = 22;
const SIZE: usize = 22;

fn commit(criterion: &mut Criterion, variable_num: usize) {
    let mut rng = StdRng::seed_from_u64(0u64);
    let polynomial = MultilinearPolynomial::<T>::rand(variable_num);
    let point = (0..variable_num)
        .map(|_| T::rand(&mut rng))
        .collect::<Vec<T>>();
    let _evaluation = polynomial.evaluate(&point);
    let mut interpolate_cosets =
        vec![EvaluationDomain::new_coset(1 << (variable_num + CODE_RATE), T::from(1)).unwrap()];
    for i in 1..variable_num {
        interpolate_cosets.push(Helper::pow(&interpolate_cosets[i - 1], 2));
    }
    let random_oracle = RandomOracle::new(variable_num, SECURITY_BITS / CODE_RATE);
    let vector_interpolation_coset =
        EvaluationDomain::new_coset(1 << variable_num, T::from(1)).unwrap();

    criterion.bench_function(&format!("virgo commit {}", variable_num), move |b| {
        b.iter_batched(
            || polynomial.clone(),
            |p| {
                let prover = FriProver::new(
                    variable_num,
                    &interpolate_cosets,
                    &vector_interpolation_coset,
                    p,
                    &random_oracle,
                );
                prover.commit_first_polynomial();
            },
            BatchSize::SmallInput,
        )
    });
}

fn zk_commit(criterion: &mut Criterion, variable_num: usize) {
    let mut rng = StdRng::seed_from_u64(0u64);
    let polynomial = MultilinearPolynomial::<T>::rand(variable_num);
    let point = (0..variable_num)
        .map(|_| T::rand(&mut rng))
        .collect::<Vec<T>>();
    let _evaluation = polynomial.evaluate(&point);
    // must +2 for the security of FRI on s, s's degree is 2|H| + \lambda - 1
    let mut interpolate_cosets =
        vec![EvaluationDomain::new_coset(1 << (variable_num + CODE_RATE + 2), T::from(1)).unwrap()];
    for i in 1..(variable_num + 2) {
        interpolate_cosets.push(Helper::pow(&interpolate_cosets[i - 1], 2));
    }
    let random_oracle = RandomOracle::new(variable_num + 2, SECURITY_BITS / CODE_RATE);
    let vector_interpolation_coset =
        EvaluationDomain::new_coset(1 << variable_num, T::from(1)).unwrap();

    criterion.bench_function(&format!("zk-virgo commit {}", variable_num), move |b| {
        b.iter_batched(
            || polynomial.clone(),
            |p| {
                let prover = ZKFriProver::new(
                    variable_num,
                    &interpolate_cosets,
                    &vector_interpolation_coset,
                    p,
                    &random_oracle,
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
    let polynomial = MultilinearPolynomial::<T>::rand(variable_num);
    let point = (0..variable_num)
        .map(|_| T::rand(&mut rng))
        .collect::<Vec<T>>();
    let _evaluation = polynomial.evaluate(&point);
    let mut interpolate_cosets =
        vec![EvaluationDomain::new_coset(1 << (variable_num + CODE_RATE), T::from(1)).unwrap()];
    for i in 1..variable_num {
        interpolate_cosets.push(Helper::pow(&interpolate_cosets[i - 1], 2));
    }
    let random_oracle = RandomOracle::new(variable_num, SECURITY_BITS / CODE_RATE);
    let vector_interpolation_coset =
        EvaluationDomain::new_coset(1 << variable_num, T::from(1)).unwrap();
    let prover = FriProver::new(
        variable_num,
        &interpolate_cosets,
        &vector_interpolation_coset,
        polynomial,
        &random_oracle,
    );

    // Commit
    let com = prover.commit_first_polynomial();

    // Open
    let mut verifier = FriVerifier::new(
        variable_num,
        &interpolate_cosets,
        &vector_interpolation_coset,
        com,
        &random_oracle,
    );
    verifier.get_open_point(&point);

    criterion.bench_function(&format!("virgo open {}", variable_num), move |b| {
        b.iter_batched(
            || prover.clone(),
            |mut p| {
                p.commit_functions(&mut verifier, &point);
                p.prove();
                p.commit_foldings(&mut verifier);
                let (_folding_proofs, _function_proofs, _v_value) = p.query();
            },
            BatchSize::SmallInput,
        )
    });
}

fn zk_open(criterion: &mut Criterion, variable_num: usize) {
    let mut rng = StdRng::seed_from_u64(0u64);
    let polynomial = MultilinearPolynomial::<T>::rand(variable_num);
    let point = (0..variable_num)
        .map(|_| T::rand(&mut rng))
        .collect::<Vec<T>>();
    let _evaluation = polynomial.evaluate(&point);
    // must +2 for the security of FRI on s, s's degree is 2|H| + \lambda - 1
    let mut interpolate_cosets =
        vec![EvaluationDomain::new_coset(1 << (variable_num + CODE_RATE + 2), T::from(1)).unwrap()];
    for i in 1..(variable_num + 2) {
        interpolate_cosets.push(Helper::pow(&interpolate_cosets[i - 1], 2));
    }
    let random_oracle = RandomOracle::new(variable_num + 2, SECURITY_BITS / CODE_RATE);
    let vector_interpolation_coset =
        EvaluationDomain::new_coset(1 << variable_num, T::from(1)).unwrap();
    let prover = ZKFriProver::new(
        variable_num + 2,
        &interpolate_cosets,
        &vector_interpolation_coset,
        polynomial,
        &random_oracle,
    );

    // Commit
    let com = prover.commit_polynomial();

    // Open
    let mut verifier = ZKFriVerifier::new(
        variable_num + 2,
        &interpolate_cosets,
        &vector_interpolation_coset,
        com,
        &random_oracle,
    );
    verifier.get_open_point(&point);

    criterion.bench_function(&format!("zk-virgo open {}", variable_num), move |b| {
        b.iter_batched(
            || prover.clone(),
            |mut p| {
                p.commit_functions(&mut verifier, &point);
                p.prove();
                p.commit_foldings(&mut verifier);
                let (_folding_proofs, _function_us_proof, _function_h_proof, _v_value) = p.query();
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
    let polynomial = MultilinearPolynomial::<T>::rand(variable_num);
    let point = (0..variable_num)
        .map(|_| T::rand(&mut rng))
        .collect::<Vec<T>>();
    let evaluation = polynomial.evaluate(&point);
    let mut interpolate_cosets =
        vec![EvaluationDomain::new_coset(1 << (variable_num + CODE_RATE), T::from(1)).unwrap()];
    for i in 1..variable_num {
        interpolate_cosets.push(Helper::pow(&interpolate_cosets[i - 1], 2));
    }
    let random_oracle = RandomOracle::new(variable_num, SECURITY_BITS / CODE_RATE);
    let vector_interpolation_coset =
        EvaluationDomain::new_coset(1 << variable_num, T::from(1)).unwrap();
    let mut prover = FriProver::new(
        variable_num,
        &interpolate_cosets,
        &vector_interpolation_coset,
        polynomial,
        &random_oracle,
    );

    // Commit
    let com = prover.commit_first_polynomial();

    // Open
    let mut verifier = FriVerifier::new(
        variable_num,
        &interpolate_cosets,
        &vector_interpolation_coset,
        com,
        &random_oracle,
    );
    verifier.get_open_point(&point);
    prover.commit_functions(&mut verifier, &point);
    prover.prove();
    prover.commit_foldings(&mut verifier);
    let (folding_proofs, function_proofs, v_value) = prover.query();

    // Proof size
    let proof_size = folding_proofs.iter().map(|x| x.proof_size()).sum::<usize>()
        + function_proofs
            .iter()
            .map(|x| x.proof_size())
            .sum::<usize>()
        + v_value.len() * (mem::size_of::<usize>() + size_of::<T>())
        + MERKLE_ROOT_SIZE * (variable_num + 1);
    println!("proof size is: {:?} KBytes", proof_size / 1024);

    criterion.bench_function(&format!("virgo verify {}", variable_num), move |b| {
        b.iter(|| {
            let is_valid = verifier.verify(evaluation, &folding_proofs, &v_value, &function_proofs);
            assert!(is_valid);
        })
    });
}

fn zk_verify(criterion: &mut Criterion, variable_num: usize) {
    let mut rng = StdRng::seed_from_u64(0u64);
    let polynomial = MultilinearPolynomial::<T>::rand(variable_num);
    let point = (0..variable_num)
        .map(|_| T::rand(&mut rng))
        .collect::<Vec<T>>();
    let evaluation = polynomial.evaluate(&point);
    // must +2 for the security of FRI on s, s's degree is 2|H| + \lambda - 1
    let mut interpolate_cosets =
        vec![EvaluationDomain::new_coset(1 << (variable_num + CODE_RATE + 2), T::from(1)).unwrap()];
    for i in 1..(variable_num + 2) {
        interpolate_cosets.push(Helper::pow(&interpolate_cosets[i - 1], 2));
    }
    let random_oracle = RandomOracle::new(variable_num + 2, SECURITY_BITS / CODE_RATE);
    let vector_interpolation_coset =
        EvaluationDomain::new_coset(1 << variable_num, T::from(1)).unwrap();
    let mut prover = ZKFriProver::new(
        variable_num + 2,
        &interpolate_cosets,
        &vector_interpolation_coset,
        polynomial,
        &random_oracle,
    );

    // Commit
    let com = prover.commit_polynomial();

    // Open
    let mut verifier = ZKFriVerifier::new(
        variable_num + 2,
        &interpolate_cosets,
        &vector_interpolation_coset,
        com,
        &random_oracle,
    );
    verifier.get_open_point(&point);
    prover.commit_functions(&mut verifier, &point);
    prover.prove();
    prover.commit_foldings(&mut verifier);
    let (folding_proofs, function_us_proof, function_h_proof, v_value) = prover.query();
    // Proof size
    let proof_size = folding_proofs.iter().map(|x| x.proof_size()).sum::<usize>()
        + function_us_proof.proof_size()
        + function_h_proof.proof_size()
        + v_value.len() * (mem::size_of::<usize>() + size_of::<T>())
        + MERKLE_ROOT_SIZE * (variable_num + 1);
    println!(
        "proof size for {} variable is: {:?} KB",
        variable_num,
        proof_size / 1024
    );

    criterion.bench_function(&format!("zk-virgo verify {}", variable_num), move |b| {
        b.iter(|| {
            // Verify
            let is_valid = verifier.verify(
                evaluation,
                &folding_proofs,
                &v_value,
                &function_us_proof,
                &function_h_proof,
            );
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

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(10);
    targets =
    bench_commit,
    bench_open,
    bench_verify
}

criterion_main!(benches);

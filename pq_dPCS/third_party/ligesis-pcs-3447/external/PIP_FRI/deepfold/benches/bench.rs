extern crate criterion;
use criterion::*;
use utils::helper::{Helper, MultilinearPolynomial};
use ark_ff::PrimeField;
use deepfold::{prover::Prover, verifier::Verifier};
use ark_poly::{EvaluationDomain, GeneralEvaluationDomain};
use deepfold::prover::RandomOracle;
use utils::{CODE_RATE, SECURITY_BITS};
use utils::goldilocks::Goldilocks as T;
const SMALL: usize = 20;
const SIZE: usize = 25;
const STEP: usize = 1;

fn commit<T: PrimeField>(criterion: &mut Criterion, variable_num: usize) {
    let polynomial = MultilinearPolynomial::rand(variable_num);
    let mut interpolate_cosets = vec![GeneralEvaluationDomain::new_coset(1 << (variable_num + CODE_RATE), T::from(1 as u64)).unwrap()];
    for i in 1..variable_num + 1 {
        interpolate_cosets.push(Helper::pow(&interpolate_cosets[i-1], 2));
    }
    let oracle = RandomOracle::new(variable_num, SECURITY_BITS / CODE_RATE);

    criterion.bench_function(&format!("deepfold commit {:02}", variable_num), move |b| {
        b.iter_batched(
            || polynomial.clone(),
            |p| {
                let prover = Prover::new(variable_num, &interpolate_cosets, p, &oracle, STEP);
                let _commit = prover.commit_polynomial();
            },
            BatchSize::SmallInput,
        )
    });
}

fn bench_commit(c: &mut Criterion) {
    for i in SMALL..=SIZE {
        commit::<T>(c, i);
    }
}

fn open<T: PrimeField>(criterion: &mut Criterion, variable_num: usize) {
    let polynomial = MultilinearPolynomial::rand(variable_num);
    let mut interpolate_cosets = vec![GeneralEvaluationDomain::new_coset(1 << (variable_num + CODE_RATE), T::from(1 as u64)).unwrap()];
    for i in 1..variable_num + 1 {
        interpolate_cosets.push(Helper::pow(&interpolate_cosets[i-1], 2));
    }
    let oracle = RandomOracle::new(variable_num, SECURITY_BITS / CODE_RATE);
    let prover = Prover::new(variable_num, &interpolate_cosets, polynomial, &oracle, STEP);
    let commit = prover.commit_polynomial();
    let verifier = Verifier::new(variable_num, &interpolate_cosets, commit, &oracle, STEP);
    let point = verifier.get_open_point();

    criterion.bench_function(&format!("deepfold open {:02}", variable_num), move |b| {
        b.iter_batched(
            || (prover.clone(), point.clone()),
            |(p, x)| {
                let _proof = p.generate_proof(x);
            },
            BatchSize::SmallInput,
        )
    });
}

fn bench_open(c: &mut Criterion) {
    for i in SMALL..=SIZE {
        open::<T>(c, i);
    }
}

fn verify<T: PrimeField>(criterion: &mut Criterion, variable_num: usize) {
    let polynomial = MultilinearPolynomial::rand(variable_num);
    let mut interpolate_cosets = vec![GeneralEvaluationDomain::new_coset(1 << (variable_num + CODE_RATE), T::from(1 as u64)).unwrap()];
    for i in 1..variable_num + 1 {
        interpolate_cosets.push(Helper::pow(&interpolate_cosets[i-1], 2));
    }
    let oracle = RandomOracle::new(variable_num, SECURITY_BITS / CODE_RATE);
    let prover = Prover::new(variable_num, &interpolate_cosets, polynomial, &oracle, STEP);
    let commit = prover.commit_polynomial();
    let verifier = Verifier::new(variable_num, &interpolate_cosets, commit, &oracle, STEP);
    let point = verifier.get_open_point();
    let proof = prover.generate_proof(point);

    let proof_size = proof.size();
    println!("proof size for {} variable is {:?} KB", variable_num, proof_size / 1024);

    criterion.bench_function(&format!("deepfold verify {:02}", variable_num), move |b| {
        b.iter_batched(
            || (verifier.clone(), proof.clone()),
            |(v, pi)| {
                assert!(v.verify(pi));
            },
            BatchSize::SmallInput,
        )
    });
}

fn bench_verify(c: &mut Criterion) {
    for i in SMALL..=SIZE  {
        verify::<T>(c, i);
    }
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(10);
    targets = bench_commit, bench_open, bench_verify
}

criterion_main!(benches);

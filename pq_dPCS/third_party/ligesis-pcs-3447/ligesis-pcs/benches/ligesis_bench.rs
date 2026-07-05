use std::time::Instant;
use ark_std::{test_rng, UniformRand};
use ark_poly::{DenseMultilinearExtension, MultilinearExtension};
use std::sync::Arc;
use ark_serialize::CanonicalSerialize;

use clap::Parser;
use ligesis_pcs::{
    ligesis::{LigeSISPCS, FGoldilocks},
    PolynomialCommitmentScheme,
};
use transcript::IOPTranscript;

type F = FGoldilocks;

#[derive(Parser, Debug)]
#[command(name = "ligesis_bench")]
#[command(about = "LigeSIS PCS Benchmark")]
struct Args {
    /// 多项式变量数
    #[arg(short, long, default_value_t = 24)]
    mu: usize,

    /// 每个操作的迭代次数
    #[arg(short, long, default_value_t = 1)]
    iterations: usize,

    /// cargo bench 自动添加的参数，忽略
    #[arg(long, hide = true)]
    bench: bool,
}

fn main() {
    let args = Args::parse();
    let mu = args.mu;
    let iterations = args.iterations;

    let mut rng = test_rng();

    println!("========================================");
    println!("LigeSIS PCS Benchmark");
    println!("mu = {}, iterations = {}", mu, iterations);
    println!("========================================\n");

    // Setup
    let start = Instant::now();
    let srs = LigeSISPCS::<F>::gen_srs_for_testing(&mut rng, mu).unwrap();
    let (pp, vp) = LigeSISPCS::<F>::setup(&srs).unwrap();
    println!("Setup: {:?}", start.elapsed());

    let poly = Arc::new(DenseMultilinearExtension::<F>::rand(mu, &mut rng));
    let point: Vec<F> = (0..mu).map(|_| F::rand(&mut rng)).collect();

    // Commit
    let start = Instant::now();
    let mut com = None;
    let mut advice = None;
    for i in 0..iterations {
        let iter_start = Instant::now();
        let (c, a) = LigeSISPCS::<F>::commit(&pp, &poly).unwrap();
        let iter_ms = iter_start.elapsed().as_secs_f64() * 1000.0;
        println!("ITER_{}_COMMIT_MS: {:.3}", i + 1, iter_ms);
        com = Some(c);
        advice = Some(a);
    }
    let commit_time = start.elapsed();
    println!("Commit (x{}): {:?} (avg: {:?})", iterations, commit_time, commit_time / iterations as u32);

    let com = com.unwrap();
    let advice = advice.unwrap();

    // Open
    let start = Instant::now();
    let mut proof = None;
    for i in 0..iterations {
        let mut transcript = IOPTranscript::<F>::new(b"ligesis_pcs_bench");
        let iter_start = Instant::now();
        let p = LigeSISPCS::<F>::open(&pp, &poly, &advice, &point, &mut transcript).unwrap();
        let iter_ms = iter_start.elapsed().as_secs_f64() * 1000.0;
        println!("ITER_{}_OPEN_MS: {:.3}", i + 1, iter_ms);
        proof = Some(p);
    }
    let open_time = start.elapsed();
    println!("Open (x{}): {:?} (avg: {:?})", iterations, open_time, open_time / iterations as u32);

    let proof = proof.unwrap();
    let mut proof_bytes = Vec::new();
    proof.serialize_compressed(&mut proof_bytes).unwrap();
    println!("PROOF_SIZE_KB: {:.3}", proof_bytes.len() as f64 / 1024.0);
    let value = LigeSISPCS::<F>::compute_value_from_proof(mu - mu / 2, &point, &proof);

    // Verify
    let start = Instant::now();
    for i in 0..iterations {
        let mut transcript = IOPTranscript::<F>::new(b"ligesis_pcs_bench");
        let iter_start = Instant::now();
        let res = LigeSISPCS::<F>::verify(&vp, &com, &point, &value, &proof, &mut transcript).unwrap();
        let iter_ms = iter_start.elapsed().as_secs_f64() * 1000.0;
        println!("ITER_{}_VERIFY_MS: {:.3}", i + 1, iter_ms);
        assert!(res);
    }
    let verify_time = start.elapsed();
    println!("Verify (x{}): {:?} (avg: {:?})", iterations, verify_time, verify_time / iterations as u32);

    println!("\n========================================");
    println!("Total (excluding setup): {:?}", commit_time + open_time + verify_time);
    println!("========================================");
}

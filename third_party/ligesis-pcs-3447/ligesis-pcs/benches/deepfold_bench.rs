use std::time::{Duration, Instant};
use ark_poly::DenseMultilinearExtension;
use ark_std::test_rng;
use std::sync::Arc;
use ark_serialize::CanonicalSerialize;

use clap::Parser;
use ligesis_pcs::{
    deepfold::DeepFoldPCS,
    random_field_vector_from_rng,
    eval_mle_poly,
    PolynomialCommitmentScheme,
};
use transcript::IOPTranscript;

mod goldilocks {
    use ark_ff::fields::{Fp64, MontBackend, MontConfig};

    #[derive(MontConfig)]
    #[modulus = "18446744069414584321"]
    #[generator = "7"]
    pub struct Config;
    pub type Fld = Fp64<MontBackend<Config, 1>>;
}
type F = goldilocks::Fld;

#[derive(Parser, Debug)]
#[command(name = "deepfold_bench")]
#[command(about = "DeepFold PCS Benchmark")]
struct Args {
    #[arg(short, long, default_value_t = 20)]
    mu: usize,

    #[arg(short, long, default_value_t = 1)]
    iterations: usize,

    #[arg(long = "test-batch")]
    test_batch: bool,

    #[arg(short, long, default_value_t = 3)]
    num_polys: usize,

    #[arg(long, hide = true)]
    bench: bool,
}

fn fmt_duration(d: Duration) -> String {
    if d.as_secs() > 0 {
        format!("{:.3}s", d.as_secs_f64())
    } else if d.as_millis() > 0 {
        format!("{:.3}ms", d.as_secs_f64() * 1000.0)
    } else {
        format!("{:.3}us", d.as_secs_f64() * 1_000_000.0)
    }
}

fn ms_to_duration(ms: f64) -> Duration {
    Duration::from_secs_f64(ms / 1000.0)
}

fn bench_single(mu: usize, iterations: usize) {
    let mut rng = test_rng();

    println!("========================================");
    println!("DeepFold PCS Benchmark (Single)");
    println!("  mu = {}, iterations = {}", mu, iterations);
    println!("========================================");

    // Setup
    let start = Instant::now();
    let srs = DeepFoldPCS::<F>::gen_srs_for_testing(&mut rng, mu).unwrap();
    let (pp, vp) = DeepFoldPCS::<F>::setup(&srs).unwrap();
    println!("Setup:    {}", fmt_duration(start.elapsed()));

    // Prepare polynomial and point
    let evals = random_field_vector_from_rng::<F>(1 << mu, &mut rng);
    let poly = Arc::new(DenseMultilinearExtension::<F>::from_evaluations_vec(mu, evals));
    let point = random_field_vector_from_rng::<F>(mu, &mut rng);

    // Commit
    let mut com = None;
    let mut advice = None;
    let mut commit_total_ms = 0.0f64;
    for i in 0..iterations {
        let iter_start = Instant::now();
        let (c, a) = DeepFoldPCS::<F>::commit(&pp, &poly).unwrap();
        let iter_ms = iter_start.elapsed().as_secs_f64() * 1000.0;
        commit_total_ms += iter_ms;
        println!("ITER_{}_COMMIT_MS: {:.3}", i + 1, iter_ms);
        com = Some(c);
        advice = Some(a);
    }
    let commit_avg = ms_to_duration(commit_total_ms / iterations as f64);
    println!("Commit:   {}", fmt_duration(commit_avg));

    let com = com.unwrap();
    let advice = advice.unwrap();

    // Open
    let mut proof = None;
    let mut open_total_ms = 0.0f64;
    for i in 0..iterations {
        let mut transcript = IOPTranscript::<F>::new(b"deepfold_bench");
        let iter_start = Instant::now();
        let p = DeepFoldPCS::<F>::open(&pp, &poly, &advice, &point, &mut transcript).unwrap();
        let iter_ms = iter_start.elapsed().as_secs_f64() * 1000.0;
        open_total_ms += iter_ms;
        println!("ITER_{}_OPEN_MS: {:.3}", i + 1, iter_ms);
        proof = Some(p);
    }
    let open_avg = ms_to_duration(open_total_ms / iterations as f64);
    println!("Open:     {}", fmt_duration(open_avg));

    let proof = proof.unwrap();
    let mut proof_bytes = Vec::new();
    proof.serialize_compressed(&mut proof_bytes).unwrap();
    println!("PROOF_SIZE_KB: {:.3}", proof_bytes.len() as f64 / 1024.0);
    let value = DeepFoldPCS::<F>::compute_value_from_proof(&point, &proof);

    // Verify
    let mut verify_total_ms = 0.0f64;
    for i in 0..iterations {
        let mut transcript = IOPTranscript::<F>::new(b"deepfold_bench");
        let iter_start = Instant::now();
        let res = DeepFoldPCS::<F>::verify(&vp, &com, &point, &value, &proof, &mut transcript).unwrap();
        let iter_ms = iter_start.elapsed().as_secs_f64() * 1000.0;
        verify_total_ms += iter_ms;
        println!("ITER_{}_VERIFY_MS: {:.3}", i + 1, iter_ms);
        assert!(res);
    }
    let verify_avg = ms_to_duration(verify_total_ms / iterations as f64);
    println!("Verify:   {}", fmt_duration(verify_avg));

    println!("----------------------------------------");
    println!("Total:    {}", fmt_duration(ms_to_duration((commit_total_ms + open_total_ms + verify_total_ms) / iterations as f64)));
    println!("========================================");
}

fn bench_batch(mu: usize, iterations: usize, num_polys: usize) {
    let mut rng = test_rng();

    println!("========================================");
    println!("DeepFold PCS Benchmark (Batch)");
    println!("  mu = {}, iterations = {}, num_polys = {}", mu, iterations, num_polys);
    println!("========================================");

    // Setup
    let start = Instant::now();
    let srs = DeepFoldPCS::<F>::gen_srs_for_testing(&mut rng, mu).unwrap();
    let (pp, vp) = DeepFoldPCS::<F>::setup(srs).unwrap();
    println!("Setup:       {}", fmt_duration(start.elapsed()));

    // Create polynomials
    let polys: Vec<_> = (0..num_polys)
        .map(|_| {
            let evals = random_field_vector_from_rng::<F>(1 << mu, &mut rng);
            Arc::new(DenseMultilinearExtension::<F>::from_evaluations_vec(mu, evals))
        })
        .collect();

    // Commit all
    let start = Instant::now();
    let (coms, advices): (Vec<_>, Vec<_>) = polys
        .iter()
        .map(|poly| DeepFoldPCS::<F>::commit(&pp, poly).unwrap())
        .unzip();
    let commit_time = start.elapsed();
    println!("Commit:      {} ({}x)", fmt_duration(commit_time), num_polys);

    // Create points and compute evals
    let points: Vec<Vec<F>> = (0..num_polys)
        .map(|_| random_field_vector_from_rng::<F>(mu, &mut rng))
        .collect();

    let evals: Vec<F> = polys
        .iter()
        .zip(points.iter())
        .map(|(poly, point)| eval_mle_poly(&poly.evaluations, point))
        .collect();

    // Batch Open
    let start = Instant::now();
    let mut batch_proof = None;
    for _ in 0..iterations {
        let mut transcript = IOPTranscript::<F>::new(b"deepfold_batch_bench");
        let advice_refs: Vec<_> = advices.iter().collect();
        let p = DeepFoldPCS::<F>::batch_open(
            &pp,
            polys.clone(),
            &advice_refs,
            &points,
            &evals,
            &mut transcript,
        ).unwrap();
        batch_proof = Some(p);
    }
    let batch_open_time = start.elapsed() / iterations as u32;
    println!("BatchOpen:   {}", fmt_duration(batch_open_time));

    let batch_proof = batch_proof.unwrap();

    // Batch Verify
    let start = Instant::now();
    for _ in 0..iterations {
        let mut transcript = IOPTranscript::<F>::new(b"deepfold_batch_bench");
        let res = DeepFoldPCS::<F>::batch_verify(&vp, &coms, &points, &batch_proof, &mut transcript).unwrap();
        assert!(res);
    }
    let batch_verify_time = start.elapsed() / iterations as u32;
    println!("BatchVerify: {}", fmt_duration(batch_verify_time));

    println!("----------------------------------------");
    println!("Total:       {}", fmt_duration(commit_time + batch_open_time + batch_verify_time));
    println!("========================================");
}

fn main() {
    let args = Args::parse();

    if args.test_batch {
        bench_batch(args.mu, args.iterations, args.num_polys);
    } else {
        bench_single(args.mu, args.iterations);
    }
}

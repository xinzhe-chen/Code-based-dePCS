use std::time::{Duration, Instant};
use ark_poly::DenseMultilinearExtension;
use ark_std::test_rng;
use std::sync::Arc;
use ark_serialize::CanonicalSerialize;

use clap::Parser;
use ligesis_pcs::{
    ligero::LigeroPCS,
    random_field_vector_from_rng,
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
#[command(name = "ligero_bench")]
#[command(about = "Ligero PCS Benchmark")]
struct Args {
    #[arg(short, long, default_value_t = 20)]
    mu: usize,

    #[arg(short, long, default_value_t = 1)]
    iterations: usize,

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

fn main() {
    let args = Args::parse();
    let mu = args.mu;
    let iterations = args.iterations;

    let mut rng = test_rng();

    println!("========================================");
    println!("Ligero PCS Benchmark");
    println!("  mu = {}, iterations = {}", mu, iterations);
    println!("========================================");

    // Setup
    let start = Instant::now();
    let srs = LigeroPCS::<F>::gen_srs_for_testing(&mut rng, mu).unwrap();
    let (pp, vp) = LigeroPCS::<F>::setup(&srs).unwrap();
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
        let (c, a) = LigeroPCS::<F>::commit(&pp, &poly).unwrap();
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
        let mut transcript = IOPTranscript::<F>::new(b"ligero_bench");
        let iter_start = Instant::now();
        let p = LigeroPCS::<F>::open(&pp, &poly, &advice, &point, &mut transcript).unwrap();
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
    let log_m0 = mu / 2;
    let value = LigeroPCS::<F>::compute_value_from_proof(log_m0, &point, &proof);

    // Verify
    let mut verify_total_ms = 0.0f64;
    for i in 0..iterations {
        let mut transcript = IOPTranscript::<F>::new(b"ligero_bench");
        let iter_start = Instant::now();
        let res = LigeroPCS::<F>::verify(&vp, &com, &point, &value, &proof, &mut transcript).unwrap();
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

//! FFT benchmark for different polynomial sizes
//! Tests actual DeepFold FFT pattern: evals_to_coeffs(2^mu) then fft to 8x domain

use ark_ff::{FftField, PrimeField, UniformRand};
use ark_poly::{EvaluationDomain, GeneralEvaluationDomain};
use ark_std::test_rng;
use ligesis_pcs::FGoldilocks as F;
use std::time::Instant;

/// Multilinear evals_to_coeffs (boolean hypercube to coefficients)
fn evals_to_coeffs_multilinear<F: PrimeField>(mu: usize, v: &[F]) -> Vec<F> {
    let mut u = v.to_vec();
    for j in 0..mu {
        for i in 0..(1 << mu) {
            if i & (1 << j) != 0 {
                u[i] = u[i] - u[i ^ (1 << j)];
            }
        }
    }
    u
}

/// Benchmark with warmup and sequential data
fn bench_with_warmup(mu: usize) {
    let evals: Vec<F> = (0..1 << mu).map(|i| F::from(i as u64)).collect();
    let len_l0 = (1 << mu) * 8;
    let l0 = GeneralEvaluationDomain::<F>::new(len_l0).unwrap();

    // Warm up
    let coeffs = evals_to_coeffs_multilinear(mu, &evals);
    let _ = l0.fft(&coeffs);

    // Benchmark
    let start = Instant::now();
    let coeffs = evals_to_coeffs_multilinear(mu, &evals);
    let e2c_time = start.elapsed();

    let start = Instant::now();
    let _ = l0.fft(&coeffs);
    let fft_time = start.elapsed();

    println!(
        "  with warmup, sequential: e2c={:>8.2?}, fft={:>8.2?}, total={:>8.2?}",
        e2c_time, fft_time, e2c_time + fft_time
    );
}

/// Benchmark without warmup and with random data
fn bench_no_warmup_random(mu: usize) {
    let mut rng = test_rng();
    let evals: Vec<F> = (0..1 << mu).map(|_| F::rand(&mut rng)).collect();
    let len_l0 = (1 << mu) * 8;
    let l0 = GeneralEvaluationDomain::<F>::new(len_l0).unwrap();

    // NO warm up

    // Benchmark
    let start = Instant::now();
    let coeffs = evals_to_coeffs_multilinear(mu, &evals);
    let e2c_time = start.elapsed();

    let start = Instant::now();
    let _ = l0.fft(&coeffs);
    let fft_time = start.elapsed();

    println!(
        "  no warmup, random data:  e2c={:>8.2?}, fft={:>8.2?}, total={:>8.2?}",
        e2c_time, fft_time, e2c_time + fft_time
    );
}

/// Benchmark cold start (fresh domain creation)
fn bench_cold_start(mu: usize) {
    let mut rng = test_rng();
    let evals: Vec<F> = (0..1 << mu).map(|_| F::rand(&mut rng)).collect();

    // Benchmark including domain creation
    let start = Instant::now();
    let len_l0 = (1 << mu) * 8;
    let l0 = GeneralEvaluationDomain::<F>::new(len_l0).unwrap();
    let domain_time = start.elapsed();

    let start = Instant::now();
    let coeffs = evals_to_coeffs_multilinear(mu, &evals);
    let e2c_time = start.elapsed();

    let start = Instant::now();
    let _ = l0.fft(&coeffs);
    let fft_time = start.elapsed();

    println!(
        "  cold (domain={:>6.2?}):   e2c={:>8.2?}, fft={:>8.2?}, total={:>8.2?}",
        domain_time, e2c_time, fft_time, e2c_time + fft_time
    );
}

fn main() {
    println!("DeepFold FFT Pattern Benchmark");
    println!("==============================");
    println!("Pattern: evals_to_coeffs(2^mu) + FFT to 8*2^mu domain");
    println!();

    for mu in [17, 18, 19, 20] {
        println!("mu={} (coeffs=2^{}={}, fft_domain=2^{}={})",
                 mu, mu, 1 << mu, mu + 3, 8 << mu);
        bench_with_warmup(mu);
        bench_no_warmup_random(mu);
        bench_cold_start(mu);
        println!();
    }

    println!("Note: Actual distributed code sees 'no warmup, random data' pattern");
}

use std::time::Instant;
use ark_std::{test_rng, UniformRand};
use ark_ff::{BigInteger, Field, PrimeField};

use clap::Parser;
use ligesis_pcs::ligesis::FGoldilocks;

type F = FGoldilocks;

#[derive(Parser, Debug)]
#[command(name = "sis_hash_bench")]
#[command(about = "SIS Hash Benchmark")]
struct Args {
    /// c: rows of mat_a (output rows)
    #[arg(short, long, default_value_t = 8)]
    c: usize,

    /// m: rows of mat_f_prime
    #[arg(short, long, default_value_t = 16384)]
    m: usize,

    /// cols: columns of mat_f_prime (output cols)
    #[arg(long, default_value_t = 524288)]
    cols: usize,

    /// iterations
    #[arg(short, long, default_value_t = 1)]
    iterations: usize,

    /// cargo bench 自动添加的参数，忽略
    #[arg(long, hide = true)]
    bench: bool,
}

fn main() {
    let args = Args::parse();
    let c = args.c;
    let m_rows = args.m;
    let cols = args.cols;
    let iterations = args.iterations;
    let eta = 64; // Goldilocks bit width

    println!("========================================");
    println!("SIS Hash Benchmark");
    println!("  c (output rows) = {}", c);
    println!("  m_rows = {}", m_rows);
    println!("  cols = {}", cols);
    println!("  eta = {}", eta);
    println!("  iterations = {}", iterations);
    println!("========================================\n");

    // Memory estimation
    let mat_a_size = c * eta * m_rows * 8 / 1024 / 1024;
    let mat_f_prime_size = m_rows * cols * 8 / 1024 / 1024;
    let mat_h_size = c * cols * 8 / 1024 / 1024;
    println!("Memory estimation:");
    println!("  mat_a: {} MB", mat_a_size);
    println!("  mat_f_prime: {} MB", mat_f_prime_size);
    println!("  mat_h (output): {} MB", mat_h_size);
    println!("  Total: {} MB", mat_a_size + mat_f_prime_size + mat_h_size);
    println!();

    // Generate random data
    println!("Generating random data...");
    let mut rng = test_rng();

    let start = Instant::now();
    let mat_a: Vec<Vec<F>> = (0..c)
        .map(|_| (0..eta * m_rows).map(|_| F::rand(&mut rng)).collect())
        .collect();
    println!("  mat_a generated in {:?}", start.elapsed());

    let start = Instant::now();
    let mat_f_prime: Vec<Vec<F>> = (0..m_rows)
        .map(|_| (0..cols).map(|_| F::rand(&mut rng)).collect())
        .collect();
    println!("  mat_f_prime generated in {:?}", start.elapsed());

    // Benchmark compute_sis_hash
    println!();
    println!("Running compute_sis_hash ({} iterations)...", iterations);

    let mut total_time = std::time::Duration::ZERO;
    let mut mat_h = vec![];

    for i in 0..iterations {
        let start = Instant::now();
        mat_h = compute_sis_hash_timed(&mat_a, &mat_f_prime, eta, m_rows);
        let elapsed = start.elapsed();
        total_time += elapsed;
        if iterations > 1 {
            println!("  Iteration {}: {:?}", i + 1, elapsed);
        }
    }

    let avg_time = total_time / iterations as u32;
    println!();
    println!("Results:");
    println!("  Total time: {:?}", total_time);
    println!("  Average time: {:?}", avg_time);
    println!("  Output shape: {} x {}", mat_h.len(), mat_h[0].len());

    // Throughput
    let total_bytes = m_rows * cols * 8; // bytes processed in mat_f_prime
    let throughput_gbps = total_bytes as f64 / avg_time.as_secs_f64() / 1e9;
    println!("  Throughput: {:.2} GB/s", throughput_gbps);
}

/// Timed version with phase breakdown
fn compute_sis_hash_timed(
    mat_a: &[Vec<F>],
    mat_f_prime: &[Vec<F>],
    eta: usize,
    m_rows: usize,
) -> Vec<Vec<F>> {
    let c = mat_a.len();
    let cols = mat_f_prime[0].len();
    let num_bytes = eta / 8;

    // Phase 1: Build lookup table
    let t1 = Instant::now();
    let a: Vec<[u64; 8]> = (0..m_rows * num_bytes * 256)
        .map(|idx| {
            let byte_position = idx / 256;
            let byte_val = idx % 256;
            let i = byte_position / num_bytes;
            let byte_idx = byte_position % num_bytes;

            let mut result = [0u64; 8];
            for (c_idx, row) in mat_a.iter().enumerate().take(8) {
                let elem_base = i * num_bytes * 8 + byte_idx * 8;
                let mut sum = 0u64;
                for bit in 0..8 {
                    if (byte_val >> bit) & 1 == 1 {
                        sum = sum.wrapping_add(row[elem_base + bit].into_bigint().as_ref()[0]);
                    }
                }
                result[c_idx] = sum;
            }
            result
        })
        .collect();
    println!("  Phase 1 (lookup table): {:?}", t1.elapsed());

    let modulus = F::MODULUS.as_ref()[0];

    // Phase 2: Main computation
    let t2 = Instant::now();
    let mut hashes: Vec<[u64; 8]> = vec![[0u64; 8]; cols];

    for i in 0..m_rows {
        let base_cnt = i * num_bytes * 256;
        let row = &mat_f_prime[i];
        for j in 0..cols {
            // Get raw u64 value directly (faster than to_bytes_le())
            let val = row[j].into_bigint().as_ref()[0];
            // Extract bytes manually
            let b0 = (val & 0xFF) as usize;
            let b1 = ((val >> 8) & 0xFF) as usize;
            let b2 = ((val >> 16) & 0xFF) as usize;
            let b3 = ((val >> 24) & 0xFF) as usize;
            let b4 = ((val >> 32) & 0xFF) as usize;
            let b5 = ((val >> 40) & 0xFF) as usize;
            let b6 = ((val >> 48) & 0xFF) as usize;
            let b7 = ((val >> 56) & 0xFF) as usize;

            unsafe {
                let h = hashes.get_unchecked_mut(j);
                let l0 = a.get_unchecked(base_cnt + b0);
                let l1 = a.get_unchecked(base_cnt + 256 + b1);
                let l2 = a.get_unchecked(base_cnt + 512 + b2);
                let l3 = a.get_unchecked(base_cnt + 768 + b3);
                let l4 = a.get_unchecked(base_cnt + 1024 + b4);
                let l5 = a.get_unchecked(base_cnt + 1280 + b5);
                let l6 = a.get_unchecked(base_cnt + 1536 + b6);
                let l7 = a.get_unchecked(base_cnt + 1792 + b7);

                h[0] += l0[0] + l1[0] + l2[0] + l3[0] + l4[0] + l5[0] + l6[0] + l7[0];
                h[1] += l0[1] + l1[1] + l2[1] + l3[1] + l4[1] + l5[1] + l6[1] + l7[1];
                h[2] += l0[2] + l1[2] + l2[2] + l3[2] + l4[2] + l5[2] + l6[2] + l7[2];
                h[3] += l0[3] + l1[3] + l2[3] + l3[3] + l4[3] + l5[3] + l6[3] + l7[3];
                h[4] += l0[4] + l1[4] + l2[4] + l3[4] + l4[4] + l5[4] + l6[4] + l7[4];
                h[5] += l0[5] + l1[5] + l2[5] + l3[5] + l4[5] + l5[5] + l6[5] + l7[5];
                h[6] += l0[6] + l1[6] + l2[6] + l3[6] + l4[6] + l5[6] + l6[6] + l7[6];
                h[7] += l0[7] + l1[7] + l2[7] + l3[7] + l4[7] + l5[7] + l6[7] + l7[7];
            }
        }
    }
    println!("  Phase 2 (main loop): {:?}", t2.elapsed());

    // Phase 3: Final reduction
    let t3 = Instant::now();
    let mut mat_h: Vec<Vec<F>> = vec![vec![F::ZERO; cols]; c];
    for j in 0..cols {
        for k in 0..c {
            mat_h[k][j] = F::from(hashes[j][k] % modulus);
        }
    }
    println!("  Phase 3 (reduction): {:?}", t3.elapsed());

    mat_h
}

/// Compute the SIS hash matrix H = A' * B where B is the byte decomposition of F'.
/// Optimized version using fixed-size arrays for cache locality.
fn compute_sis_hash(
    mat_a: &[Vec<F>],
    mat_f_prime: &[Vec<F>],
    eta: usize,
    m_rows: usize,
) -> Vec<Vec<F>> {
    let c = mat_a.len();
    let cols = mat_f_prime[0].len();
    let num_bytes = eta / 8; // 8 bytes for 64-bit field

    // Precompute lookup table: a[byte_position * 256 + byte_value] -> [u64; 8]
    // Using fixed-size array [u64; 8] for cache locality (c=8 for ligesis)
    let a: Vec<[u64; 8]> = (0..m_rows * num_bytes * 256)
        .map(|idx| {
            let byte_position = idx / 256;
            let byte_val = idx % 256;
            let i = byte_position / num_bytes;
            let byte_idx = byte_position % num_bytes;

            let mut result = [0u64; 8];
            for (c_idx, row) in mat_a.iter().enumerate().take(8) {
                let elem_base = i * num_bytes * 8 + byte_idx * 8;
                let mut sum = 0u64;
                for bit in 0..8 {
                    if (byte_val >> bit) & 1 == 1 {
                        sum = sum.wrapping_add(row[elem_base + bit].into_bigint().as_ref()[0]);
                    }
                }
                result[c_idx] = sum;
            }
            result
        })
        .collect();

    // Get modulus for final reduction
    let modulus = F::MODULUS.as_ref()[0];

    // Compute H: process row by row, all columns at once
    // Use unsafe for performance-critical inner loop
    let mut hashes: Vec<[u64; 8]> = vec![[0u64; 8]; cols];

    for i in 0..m_rows {
        let base_cnt = i * num_bytes * 256;
        let row = &mat_f_prime[i];
        for j in 0..cols {
            let x = row[j].into_bigint().to_bytes_le();

            unsafe {
                let h = hashes.get_unchecked_mut(j);
                let l0 = a.get_unchecked(base_cnt + *x.get_unchecked(0) as usize);
                let l1 = a.get_unchecked(base_cnt + 256 + *x.get_unchecked(1) as usize);
                let l2 = a.get_unchecked(base_cnt + 512 + *x.get_unchecked(2) as usize);
                let l3 = a.get_unchecked(base_cnt + 768 + *x.get_unchecked(3) as usize);
                let l4 = a.get_unchecked(base_cnt + 1024 + *x.get_unchecked(4) as usize);
                let l5 = a.get_unchecked(base_cnt + 1280 + *x.get_unchecked(5) as usize);
                let l6 = a.get_unchecked(base_cnt + 1536 + *x.get_unchecked(6) as usize);
                let l7 = a.get_unchecked(base_cnt + 1792 + *x.get_unchecked(7) as usize);

                h[0] += l0[0] + l1[0] + l2[0] + l3[0] + l4[0] + l5[0] + l6[0] + l7[0];
                h[1] += l0[1] + l1[1] + l2[1] + l3[1] + l4[1] + l5[1] + l6[1] + l7[1];
                h[2] += l0[2] + l1[2] + l2[2] + l3[2] + l4[2] + l5[2] + l6[2] + l7[2];
                h[3] += l0[3] + l1[3] + l2[3] + l3[3] + l4[3] + l5[3] + l6[3] + l7[3];
                h[4] += l0[4] + l1[4] + l2[4] + l3[4] + l4[4] + l5[4] + l6[4] + l7[4];
                h[5] += l0[5] + l1[5] + l2[5] + l3[5] + l4[5] + l5[5] + l6[5] + l7[5];
                h[6] += l0[6] + l1[6] + l2[6] + l3[6] + l4[6] + l5[6] + l6[6] + l7[6];
                h[7] += l0[7] + l1[7] + l2[7] + l3[7] + l4[7] + l5[7] + l6[7] + l7[7];
            }
        }
    }

    // Convert to field elements with modular reduction
    let mut mat_h: Vec<Vec<F>> = vec![vec![F::ZERO; cols]; c];
    for j in 0..cols {
        for k in 0..c {
            mat_h[k][j] = F::from(hashes[j][k] % modulus);
        }
    }

    mat_h
}

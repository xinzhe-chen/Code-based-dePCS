// FRIttata Benchmark
// Usage: frittata_bench <circuit_size_e> <num_poly_e> [iterations]
//
// circuit_size_e: log2 of polynomial degree bound (similar to mu in other PCS)
// num_poly_e: log2 of number of polynomials (= log2 of distributed nodes)
// iterations: number of iterations for averaging (default: 1)

use std::env;
use std::time::Instant;

use crypto::{hashers::Blake3_256, DefaultRandomCoin, MerkleTree, RandomCoin};
use math::fields::{f128::BaseElement, QuadExtension};
use math::{fft, FieldElement};
use rand_utils::rand_vector;
use winter_fri::{
    fold_and_batch_prove, DefaultVerifierChannel, FoldAndBatchVerifier, FriOptions,
};

type Blake3 = Blake3_256<BaseElement>;

const BLOWUP_FACTOR: usize = 4;
const FOLDING_FACTOR: usize = 2;
const NUM_QUERIES: usize = 282;
const MASTER_MAX_REMAINDER_DEGREE: usize = 0;

fn build_evaluations_from_random_poly(
    degree_bound: usize,
    lde_blowup: usize,
) -> Vec<QuadExtension<BaseElement>> {
    let mut p = rand_vector::<QuadExtension<BaseElement>>(degree_bound);
    let domain_size = degree_bound * lde_blowup;
    p.resize(domain_size, <QuadExtension<BaseElement>>::ZERO);
    let twiddles = fft::get_twiddles::<BaseElement>(domain_size);
    fft::evaluate_poly(&mut p, &twiddles);
    p
}

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 3 {
        eprintln!(
            "Usage: {} <circuit_size_e> <num_poly_e> [iterations]",
            args[0]
        );
        std::process::exit(1);
    }

    let circuit_size_e: usize = args[1].parse().expect("Invalid circuit_size_e");
    let num_poly_e: usize = args[2].parse().expect("Invalid num_poly_e");
    let iterations: usize = args.get(3).and_then(|s| s.parse().ok()).unwrap_or(1);

    // Validate parameters
    if circuit_size_e <= num_poly_e + 2 {
        eprintln!(
            "Error: circuit_size_e ({}) must be > num_poly_e + 2 ({})",
            circuit_size_e,
            num_poly_e + 2
        );
        std::process::exit(1);
    }

    let worker_degree_bound: usize = 1 << (circuit_size_e - num_poly_e);
    let worker_domain_size = worker_degree_bound * BLOWUP_FACTOR;
    let worker_last_poly_max_degree = worker_degree_bound / 4 - 1; // Fold-and-Batch parameter
    let master_degree_bound: usize = worker_last_poly_max_degree + 1;
    let master_domain_size = master_degree_bound.next_power_of_two() * BLOWUP_FACTOR;
    let num_poly = 1 << num_poly_e;
    let master_options = FriOptions::new(BLOWUP_FACTOR, FOLDING_FACTOR, MASTER_MAX_REMAINDER_DEGREE);

    println!("========================================");
    println!("FRIttata Benchmark (Fold-and-Batch)");
    println!(
        "circuit_size_e (mu) = {}, num_poly_e = {}, num_poly = {}",
        circuit_size_e, num_poly_e, num_poly
    );
    println!("iterations = {}", iterations);
    println!("========================================\n");

    // Generate random polynomial inputs
    println!("Generating {} random polynomials...", num_poly);
    let start = Instant::now();
    let mut inputs = Vec::with_capacity(num_poly);
    for _ in 0..num_poly {
        inputs.push(build_evaluations_from_random_poly(
            worker_degree_bound,
            BLOWUP_FACTOR,
        ));
    }
    println!("Setup: {:?}", start.elapsed());

    // Prove (includes worker folding + master commit/query)
    let mut proof = None;
    let start = Instant::now();
    for _ in 0..iterations {
        let p = fold_and_batch_prove::<
            QuadExtension<BaseElement>,
            Blake3,
            DefaultRandomCoin<_>,
            MerkleTree<_>,
        >(
            inputs.clone(),
            num_poly,
            BLOWUP_FACTOR,
            FOLDING_FACTOR,
            worker_domain_size,
            worker_last_poly_max_degree,
            master_domain_size,
            master_options.clone(),
            NUM_QUERIES,
        );
        proof = Some(p);
    }
    let prove_time = start.elapsed();
    let proof = proof.unwrap();

    // For compatibility with parse_benchmark_output, output as "Commit" + "Open"
    // In FRIttata, the prove phase includes both commitment and opening
    println!(
        "Commit (x{}): {:?} (avg: {:?})",
        iterations,
        prove_time,
        prove_time / iterations as u32
    );

    // Verify
    let start = Instant::now();
    for _ in 0..iterations {
        let public_coin = DefaultRandomCoin::<Blake3_256<_>>::new(&[]);
        let mut verifier = FoldAndBatchVerifier::<
            QuadExtension<BaseElement>,
            DefaultVerifierChannel<QuadExtension<BaseElement>, _, MerkleTree<Blake3>>,
            _,
            DefaultRandomCoin<_>,
            _,
        >::new(
            public_coin,
            NUM_QUERIES,
            master_options.clone(),
            worker_degree_bound,
            master_degree_bound,
        )
        .unwrap();
        let result = verifier.verify_fold_and_batch(&proof);
        assert!(result.is_ok(), "Verification failed: {:?}", result);
    }
    let verify_time = start.elapsed();
    println!(
        "Verify (x{}): {:?} (avg: {:?})",
        iterations,
        verify_time,
        verify_time / iterations as u32
    );

    let proof_size_bytes = proof.size();
    let proof_size_kb = proof_size_bytes as f64 / 1024.0;

    let prove_ms = prove_time.as_secs_f64() * 1000.0 / iterations as f64;
    let verify_ms = verify_time.as_secs_f64() * 1000.0 / iterations as f64;
    let total_ms = prove_ms + verify_ms;

    println!("\n========================================");
    println!("Prover: {:?}", prove_time / iterations as u32);
    println!("Verify: {:?}", verify_time / iterations as u32);
    println!("Total: {:?}", (prove_time + verify_time) / iterations as u32);
    println!("Proof size: {:.2} KB ({} bytes)", proof_size_kb, proof_size_bytes);
    println!("========================================");

    // Machine-readable output for benchmark.py parsing
    println!("\n--- MACHINE READABLE ---");
    println!("PROVER_TIME_MS: {:.3}", prove_ms);
    println!("VERIFY_TIME_MS: {:.3}", verify_ms);
    println!("TOTAL_TIME_MS: {:.3}", total_ms);
    println!("PROOF_SIZE_KB: {:.3}", proof_size_kb);
}

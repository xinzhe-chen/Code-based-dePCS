//! Distributed PIP-FRI PCS Benchmark
//!
//! Tests the PIP-FRI polynomial commitment scheme in a distributed setting.

use ark_ff::One;
use ark_ff::UniformRand;
use ark_poly::{EvaluationDomain, GeneralEvaluationDomain};
use de_network::{DeMultiNet as Net, DeNet, DeSerNet};
use de_pip_fri::deprover::DeProver;
use de_pip_fri::verifier::Verifier;
use rand::rngs::StdRng;
use rand::SeedableRng;
use std::mem::size_of;
use std::path::PathBuf;
use std::time::{Duration, Instant};
use structopt::StructOpt;
use utils::fiat_shamir::RandomOracle;
use utils::goldilocks::Goldilocks as T;
use utils::helper::nearest_power_of_two;
use utils::helper::Helper;
use utils::helper::MultilinearPolynomial;
use utils::interpolate_vecs_value::*;
use utils::merkle_tree::MERKLE_ROOT_SIZE;
use utils::CODE_RATE;

#[derive(Debug, StructOpt)]
#[structopt(name = "de_pip_fri", about = "Distributed PIP-FRI PCS benchmark")]
struct Opt {
    /// Party ID (0 = master)
    id: usize,

    /// Network config file path
    #[structopt(parse(from_os_str))]
    input: PathBuf,

    /// Number of variables (mu)
    #[structopt(default_value = "20")]
    variable_num: usize,

    /// Number of iterations
    #[structopt(short, long, default_value = "1")]
    iterations: usize,

    /// Number of query positions.
    #[structopt(long, default_value = "50")]
    queries: usize,
}

fn barrier() {
    Net::send_to_master(&0u8);
    Net::recv_from_master(if Net::am_master() { Some(vec![0u8; Net::n_parties()]) } else { None });
}

fn main() {
    // Keep the historical single-thread default, but let benchmark harnesses
    // provide an explicit per-party thread budget.
    if std::env::var("RAYON_NUM_THREADS").is_err() {
        std::env::set_var("RAYON_NUM_THREADS", "1");
    }

    let opt = Opt::from_args();
    Net::init_from_file(opt.input.to_str().unwrap(), opt.id);

    let variable_num = opt.variable_num;
    let iterations = opt.iterations;
    let queries = opt.queries;
    let n = Net::n_parties();
    let is_master = Net::am_master();

    assert!(n.is_power_of_two());
    assert!(n != 1);
    assert!(queries > 0);

    macro_rules! master_print {
        ($($arg:tt)*) => { if is_master { println!($($arg)*); } };
    }

    master_print!("========================================");
    master_print!("dPIP-FRI PCS Distributed Benchmark");
    master_print!(
        "  mu = {}, parties = {}, queries = {}, iterations = {}",
        variable_num,
        n,
        queries,
        iterations
    );
    master_print!("========================================");

    // Generate polynomial and distribute (once, outside iteration loop)
    let mut rng = StdRng::seed_from_u64(0u64);

    let (sub_polys, eval, sub_variable_num, sub_open_point, tensor) = if is_master {
        let polynomial = MultilinearPolynomial::rand(variable_num);
        let point = (0..variable_num)
            .map(|_| T::rand(&mut rng))
            .collect::<Vec<T>>();
        let eval = polynomial.evaluate(&point);

        // Divide and generate public informations
        let poly_num = get_poly_num(&polynomial);
        let sub_polynomials = polynomial.chunks(poly_num);

        let mut sub_polys_coeffs = Vec::new();
        for i in 0..n {
            let tmp: Vec<T> = (i * (poly_num / n)..(i + 1) * (poly_num / n))
                .flat_map(|j| sub_polynomials[j].coefficients().to_vec())
                .collect();
            sub_polys_coeffs.push(tmp);
        }

        let sub_variable_num = get_sub_variable_num(&polynomial);
        let (sub_open_point, remaining_var) = point.split_at(sub_variable_num);
        let tensor = get_tensor(&remaining_var.to_vec());

        (
            Net::recv_from_master(Some(sub_polys_coeffs)),
            Net::recv_from_master(Some(vec![eval; n])),
            Net::recv_from_master(Some(vec![sub_variable_num; n])),
            Net::recv_from_master(Some(vec![sub_open_point.to_vec(); n])),
            Net::recv_from_master(Some(vec![tensor; n])),
        )
    } else {
        (
            Net::recv_from_master(None),
            Net::recv_from_master(None),
            Net::recv_from_master(None),
            Net::recv_from_master(None),
            Net::recv_from_master(None),
        )
    };

    // Setup (once)
    let mut interpolate_cosets =
        vec![
            GeneralEvaluationDomain::new_coset(1 << (sub_variable_num + CODE_RATE), T::one())
                .unwrap(),
        ];
    for i in 1..sub_variable_num {
        interpolate_cosets.push(Helper::pow(&interpolate_cosets[i - 1], 2));
    }

    let total_poly_num = nearest_power_of_two(variable_num * 4);
    let poly_num_per_party = total_poly_num / n;
    let chunk_size = sub_polys.len() / poly_num_per_party;
    assert_eq!(chunk_size, 1 << sub_variable_num);

    master_print!("poly_num_per_party: {}", poly_num_per_party);
    master_print!("sub_variable_num: {}", sub_variable_num);
    master_print!("chunk_size: {}", chunk_size);

    let sub_polys_vec: Vec<MultilinearPolynomial<T>> = (0..poly_num_per_party)
        .map(|i| {
            MultilinearPolynomial::new(sub_polys[i * chunk_size..(i + 1) * chunk_size].to_vec())
        })
        .collect();

    // Run iterations
    let mut commit_times = Vec::with_capacity(iterations);
    let mut open_times = Vec::with_capacity(iterations);
    let mut verify_times = Vec::with_capacity(iterations);
    let mut proof_size = 0usize;

    // Reset stats before iterations to capture all communication
    Net::reset_stats();

    for iter in 0..iterations {
        master_print!("\n--- Iteration {} ---", iter + 1);

        // Create fresh oracle and prover for each iteration
        let oracle = if is_master {
            Some(RandomOracle::new(sub_variable_num, queries))
        } else {
            None
        };

        // Commit (includes prover setup)
        barrier();
        let start = Instant::now();
        let mut de_prover = DeProver::new(
            sub_variable_num,
            Net::party_id(),
            &interpolate_cosets,
            sub_polys_vec.clone(),
            oracle.as_ref(),
            &tensor,
        );
        let (com, sub_com) = de_prover.de_commit_polynomial();
        let commit_time = start.elapsed();
        commit_times.push(commit_time);

        // Create verifier (master only)
        let mut verifier = if is_master {
            Some(Verifier::new(
                sub_variable_num,
                com.unwrap(),
                &interpolate_cosets,
                &oracle.as_ref().unwrap(),
                &sub_open_point,
                &tensor,
            ))
        } else {
            None
        };

        // Open
        barrier();
        let start = Instant::now();
        let (polynomial_proof, folding_proof, function_proof) =
            de_prover.de_open(&sub_com, &sub_open_point, verifier.as_mut());
        let open_time = start.elapsed();
        open_times.push(open_time);

        // Verify (master only)
        if is_master {
            // Calculate proof size
            proof_size = folding_proof.iter().map(|x| x.proof_size()).sum::<usize>()
                + polynomial_proof.proof_size()
                + function_proof.iter().map(|x| x.proof_size()).sum::<usize>()
                + (2 * sub_variable_num - 3) * MERKLE_ROOT_SIZE
                + 2 * size_of::<T>();

            // Verify
            let start = Instant::now();
            assert!(verifier
                .unwrap()
                .verify(&polynomial_proof, &folding_proof, &function_proof, eval));
            let verify_time = start.elapsed();
            verify_times.push(verify_time);

            master_print!("Commit: {:?}, Open: {:?}, Verify: {:?}",
                commit_time, open_time, verify_time);

            // Machine-readable per-iteration output
            println!("ITER_{}_COMMIT_MS: {:.3}", iter + 1, commit_time.as_secs_f64() * 1000.0);
            println!("ITER_{}_OPEN_MS: {:.3}", iter + 1, open_time.as_secs_f64() * 1000.0);
            println!("ITER_{}_VERIFY_MS: {:.3}", iter + 1, verify_time.as_secs_f64() * 1000.0);
        }
    }

    // Get average communication stats per iteration (master's sent + received)
    let stats = Net::stats();
    let total_comm_bytes = (stats.bytes_sent + stats.bytes_recv) as f64;

    // Print summary (master only)
    if is_master {
        let avg = |times: &[Duration]| -> Duration {
            times.iter().sum::<Duration>() / times.len() as u32
        };

        let avg_comm_mb = total_comm_bytes / iterations as f64 / (1024.0 * 1024.0);
        let proof_size_kb = proof_size as f64 / 1024.0;

        master_print!("\n========================================");
        master_print!("Summary ({} iterations):", iterations);
        master_print!("  Commit (avg): {:?}", avg(&commit_times));
        master_print!("  Open (avg):   {:?}", avg(&open_times));
        master_print!("  Verify (avg): {:?}", avg(&verify_times));
        master_print!("  Proof size:   {:.2} KB", proof_size_kb);
        master_print!("  Communication: {:.2} MB", avg_comm_mb);
        master_print!("========================================");

        // Machine-readable output
        println!("COMMIT_TIME_MS: {:.3}", avg(&commit_times).as_secs_f64() * 1000.0);
        println!("OPEN_TIME_MS: {:.3}", avg(&open_times).as_secs_f64() * 1000.0);
        println!("VERIFY_TIME_MS: {:.3}", avg(&verify_times).as_secs_f64() * 1000.0);
        println!("PROOF_SIZE_KB: {:.2}", proof_size_kb);
        println!("COMM_TOTAL_BYTES: {}", (total_comm_bytes / iterations as f64) as u64);
        println!("QUERY_COUNT: {}", queries);

        // Combined prover time
        let prover_ms = avg(&commit_times).as_secs_f64() * 1000.0
            + avg(&open_times).as_secs_f64() * 1000.0;
        println!("PROVER_TIME_MS: {:.3}", prover_ms);
    }

    Net::deinit();
}

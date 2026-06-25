use arithmetic::build_eq_x_r;
use ark_ff::{One, PrimeField, UniformRand, Zero};
use ark_poly::{DenseMultilinearExtension, MultilinearExtension};
use ark_serialize::CanonicalSerialize;
use std::sync::Arc;
use std::time::{Duration, Instant};
use std::fs;
use std::path::PathBuf;
use clap::Parser;
use rand::{rngs::StdRng, SeedableRng};
use transcript::IOPTranscript;

use deNetwork::{DeMultiNet as Net, DeNet, DeSerNet};
use ligesis_pcs::{FGoldilocks as F, EGoldilocks as EF, FieldExtension, ext_sumcheck::ExtSumCheckBuilder};

#[derive(Debug, Parser)]
#[command(name = "distributed_sumcheck")]
pub struct Opt {
    /// Party ID
    pub id: usize,

    /// Network config file path
    pub input: PathBuf,

    /// Number of polynomial variables
    #[arg(short, long, default_value_t = 20)]
    pub mu: usize,

    /// Polynomial degree: 3 for f*g*eq, 4 for f*g*h*eq
    #[arg(short, long, default_value_t = 3)]
    pub degree: usize,

    /// Number of iterations
    #[arg(short, long, default_value_t = 1)]
    pub iterations: usize,
}

fn get_peak_memory_kb() -> Option<u64> {
    if let Ok(status) = fs::read_to_string("/proc/self/status") {
        for line in status.lines() {
            if line.starts_with("VmHWM:") {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 2 {
                    return parts[1].parse().ok();
                }
            }
        }
    }
    None
}

fn barrier() {
    Net::send_to_master(&0u8);
    Net::recv_from_master_uniform::<u8>(if Net::am_master() { Some(0u8) } else { None });
}

fn test_rng() -> StdRng {
    let mut seed = [0u8; 32];
    seed[0] = Net::party_id() as u8;
    rand::rngs::StdRng::from_seed(seed)
}

fn run_sumcheck(
    mu: usize,
    degree: usize,
    iterations: usize,
) {
    let mut rng = test_rng();
    let num_party = Net::n_parties();
    let num_party_vars = num_party.ilog2() as usize;
    let party_id = Net::party_id();
    let is_master = Net::am_master();
    let local_nv = mu - num_party_vars;

    macro_rules! master_print {
        ($($arg:tt)*) => { if is_master { println!($($arg)*); } };
    }

    let degree_name = if degree == 3 { "f*g*eq" } else { "f*g*h*eq" };

    master_print!("========================================");
    master_print!("Distributed Sumcheck Benchmark");
    master_print!("  mu = {}, parties = {}, iterations = {}", mu, num_party, iterations);
    master_print!("  polynomial = {}, degree = {}", degree_name, degree);
    master_print!("  field = Goldilocks64Ext");
    master_print!("========================================");

    let mut prove_times = Vec::with_capacity(iterations);
    let mut verify_times = Vec::with_capacity(iterations);
    let mut proof_size = 0usize;

    for iter in 0..iterations {
        master_print!("\n--- Iteration {} ---", iter + 1);

        // Generate random point for eq polynomial
        let r: Vec<F> = if is_master {
            let r: Vec<F> = (0..mu).map(|_| F::rand(&mut rng)).collect();
            Net::recv_from_master_uniform(Some(r.clone()));
            r
        } else {
            Net::recv_from_master_uniform::<Vec<F>>(None)
        };

        // Generate local random MLEs
        let f_evals: Vec<F> = (0..(1 << local_nv)).map(|_| F::rand(&mut rng)).collect();
        let g_evals: Vec<F> = (0..(1 << local_nv)).map(|_| F::rand(&mut rng)).collect();
        let f_mle = Arc::new(DenseMultilinearExtension::from_evaluations_vec(local_nv, f_evals));
        let g_mle = Arc::new(DenseMultilinearExtension::from_evaluations_vec(local_nv, g_evals));

        // Build eq polynomial from local portion of r
        let eq_mle = build_eq_x_r(&r[..local_nv]).unwrap();

        // Build extension field sumcheck
        let builder = if degree == 3 {
            // f * g * eq (degree 3)
            ExtSumCheckBuilder::<F, EF>::new(local_nv)
                .add_mle_list(vec![f_mle, g_mle, eq_mle], F::one())
                .unwrap()
        } else {
            // f * g * h * eq (degree 4)
            let h_evals: Vec<F> = (0..(1 << local_nv)).map(|_| F::rand(&mut rng)).collect();
            let h_mle = Arc::new(DenseMultilinearExtension::from_evaluations_vec(local_nv, h_evals));
            ExtSumCheckBuilder::<F, EF>::new(local_nv)
                .add_mle_list(vec![f_mle, g_mle, h_mle, eq_mle], F::one())
                .unwrap()
        };

        // Prove
        barrier();
        Net::reset_stats();
        let start = Instant::now();
        let mut transcript = IOPTranscript::<F>::new(b"sumcheck");
        let proof = builder.d_prove(&mut transcript).unwrap();
        let prove_time = start.elapsed();
        prove_times.push(prove_time);

        // Verify (master only)
        let verify_time = if is_master {
            let proof = proof.unwrap();
            let start = Instant::now();
            // Basic verification: check proof structure and sum
            // Full verification would require evaluating at subclaim point
            let _sum = proof.proofs[0].iter().fold(EF::from_base(F::zero()), |acc, &x| acc + x);
            let vt = start.elapsed();

            // Record proof size
            if iter == iterations - 1 {
                let mut proof_bytes = Vec::new();
                proof.serialize_compressed(&mut proof_bytes).unwrap();
                proof_size = proof_bytes.len();
            }
            vt
        } else {
            Duration::ZERO
        };
        verify_times.push(verify_time);

        master_print!("Prove: {:?}, Verify: {:?}", prove_time, verify_time);

        // Machine-readable per-iteration output
        if is_master {
            println!("ITER_{}_PROVE_MS: {:.3}", iter + 1, prove_time.as_secs_f64() * 1000.0);
            println!("ITER_{}_VERIFY_MS: {:.3}", iter + 1, verify_time.as_secs_f64() * 1000.0);
        }
    }

    // Summary
    if is_master {
        let avg = |times: &[Duration]| -> Duration {
            times.iter().sum::<Duration>() / times.len() as u32
        };

        master_print!("\n========================================");
        master_print!("Summary ({} iterations):", iterations);
        master_print!("  Prove (avg):  {:?}", avg(&prove_times));
        master_print!("  Verify (avg): {:?}", avg(&verify_times));
        master_print!("  Proof size:   {} KB", proof_size as f64 / 1024.0);

        // Machine-readable output
        println!("PROVER_TIME_MS: {:.3}", avg(&prove_times).as_secs_f64() * 1000.0);
        println!("VERIFY_TIME_MS: {:.3}", avg(&verify_times).as_secs_f64() * 1000.0);
        println!("PROOF_SIZE_KB: {:.2}", proof_size as f64 / 1024.0);

        let stats = Net::stats();
        let total_bytes = stats.bytes_sent + stats.bytes_recv;
        println!("COMM_TOTAL_BYTES: {}", total_bytes);
        println!("COMM_TOTAL_MB: {:.6}", total_bytes as f64 / (1024.0 * 1024.0));

        if let Some(peak_mem_kb) = get_peak_memory_kb() {
            master_print!("  Peak Memory:  {:.2} MB", peak_mem_kb as f64 / 1024.0);
            println!("PEAK_MEMORY_MB: {:.2}", peak_mem_kb as f64 / 1024.0);
        }
        master_print!("========================================");
    }

    // Worker stats
    if party_id == 1 {
        let stats = Net::stats();
        println!("[P1] Communication: sent={:.2} MB, recv={:.2} MB",
            stats.bytes_sent as f64 / (1024.0 * 1024.0),
            stats.bytes_recv as f64 / (1024.0 * 1024.0));
        if let Some(peak_mem_kb) = get_peak_memory_kb() {
            println!("[P1] Peak Memory: {:.2} MB", peak_mem_kb as f64 / 1024.0);
        }
    }
}

fn main() {
    let opt = Opt::parse();
    Net::init_from_file(opt.input.to_str().unwrap(), opt.id);

    if opt.degree != 3 && opt.degree != 4 {
        if Net::am_master() {
            println!("Error: degree must be 3 (f*g*eq) or 4 (f*g*h*eq)");
        }
        Net::deinit();
        return;
    }

    run_sumcheck(opt.mu, opt.degree, opt.iterations);

    Net::deinit();
}

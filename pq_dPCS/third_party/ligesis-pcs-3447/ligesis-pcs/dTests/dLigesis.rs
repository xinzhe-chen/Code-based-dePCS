use arithmetic::math::Math;
use ark_ff::{PrimeField, UniformRand};
use ark_poly::{DenseMultilinearExtension, MultilinearExtension};
use ark_serialize::CanonicalSerialize;
use ligesis_pcs::{
    HasQuadraticExtension, LigeSISPCS, LigeSISSRS, PCSError, PolynomialCommitmentScheme,
};
use std::{
    fs,
    sync::Arc,
    time::{Duration, Instant},
};
use transcript::IOPTranscript;

use deNetwork::{DeMultiNet as Net, DeNet, DeSerNet};

mod common;
use common::{test_rng, Opt};
use ligesis_pcs::FGoldilocks as F;

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

fn test_multi<F: PrimeField + HasQuadraticExtension>(
    mu: usize,
    log_m: Option<usize>,
    base_mu: Option<usize>,
    code_rate: Option<usize>,
    iterations: usize,
) -> Result<(), PCSError> {
    let mut rng = test_rng();
    let num_party = Net::n_parties();
    let num_party_vars = num_party.ilog2() as usize;
    let party_id = Net::party_id();
    let is_master = Net::am_master();
    let actual_log_m = log_m.unwrap_or_else(|| if mu < 4 { 0 } else { (mu - 8) / 2 });
    if actual_log_m < num_party_vars {
        return Err(PCSError::InvalidParameters(format!(
            "log_m={} gives only 2^log_m rows, but parties={} requires log_m >= {}",
            actual_log_m, num_party, num_party_vars
        )));
    }

    macro_rules! master_print {
        ($($arg:tt)*) => { if is_master { println!($($arg)*); } };
    }

    if is_master {
        let default_base_mu = actual_log_m + 9;
        let actual_base_mu = base_mu.unwrap_or(default_base_mu);
        let actual_rate = code_rate.unwrap_or(4);

        master_print!("========================================");
        master_print!("LigeSIS Distributed Benchmark");
        master_print!(
            "  mu = {}, parties = {}, iterations = {}",
            mu,
            num_party,
            iterations
        );
        master_print!(
            "  log_m = {}, base_mu = {}, code_rate = 1/{}",
            actual_log_m,
            actual_base_mu,
            actual_rate
        );
        master_print!("========================================");

        // Gen SRS (once)
        let start = Instant::now();
        let srs = LigeSISSRS::<F>::gen_with_layout_params(&mut rng, mu, log_m, base_mu, code_rate)?;
        master_print!("Gen SRS: {:?}", start.elapsed());

        // Distribute SRS (once)
        let start = Instant::now();
        Net::recv_from_master_uniform(Some(srs.clone()));
        master_print!("Dist SRS: {:?}", start.elapsed());

        // Setup (once)
        let start = Instant::now();
        let (pp, vp_opt) = LigeSISPCS::<F>::d_setup(&srs)?;
        let vp = vp_opt.unwrap();
        master_print!("Setup: {:?}", start.elapsed());

        // Run iterations
        let mut commit_times = Vec::with_capacity(iterations);
        let mut open_times = Vec::with_capacity(iterations);
        let mut verify_times = Vec::with_capacity(iterations);
        let mut commitment_size = 0usize;
        let mut proof_size = 0usize;
        let mut total_comm_mb = 0.0f64;

        for iter in 0..iterations {
            master_print!("\n--- Iteration {} ---", iter + 1);

            // Generate new poly and point for each iteration
            let poly_k = Arc::new(DenseMultilinearExtension::<F>::rand(
                mu - num_party_vars,
                &mut rng,
            ));
            let point: Vec<F> = (0..mu).map(|_| F::rand(&mut rng)).collect();
            Net::recv_from_master_uniform(Some(point.clone()));

            // Commit
            barrier();
            Net::reset_stats();
            let start = Instant::now();
            let (com, advice) = LigeSISPCS::d_commit(&pp, &poly_k).unwrap();
            let commit_time = start.elapsed();
            commit_times.push(commit_time);
            let stats_commit = Net::stats();

            // Open
            barrier();
            Net::reset_stats();
            let start = Instant::now();
            let mut transcript = IOPTranscript::<F>::new(b"test");
            let proof = LigeSISPCS::d_open(&pp, &poly_k, &advice, &point, &mut transcript)
                .unwrap()
                .unwrap();
            let open_time = start.elapsed();
            open_times.push(open_time);
            let stats_open = Net::stats();

            // Verify
            let start = Instant::now();
            let mut transcript = IOPTranscript::<F>::new(b"test");
            let value = LigeSISPCS::<F>::compute_value_from_proof(mu - mu / 2, &point, &proof);
            let com_unwrapped = com.unwrap();
            let result =
                LigeSISPCS::verify(&vp, &com_unwrapped, &point, &value, &proof, &mut transcript)?;
            let verify_time = start.elapsed();
            verify_times.push(verify_time);
            assert!(result, "Verification failed at iteration {}", iter + 1);

            // Record sizes (last iteration)
            if iter == iterations - 1 {
                let mut commitment_bytes = Vec::new();
                com_unwrapped
                    .serialize_compressed(&mut commitment_bytes)
                    .unwrap();
                commitment_size = commitment_bytes.len();

                let mut proof_bytes = Vec::new();
                proof.serialize_compressed(&mut proof_bytes).unwrap();
                proof_size = proof_bytes.len();

                let total_bytes = stats_commit.bytes_sent
                    + stats_commit.bytes_recv
                    + stats_open.bytes_sent
                    + stats_open.bytes_recv;
                total_comm_mb = total_bytes as f64 / (1024.0 * 1024.0);
            }

            master_print!(
                "Commit: {:?}, Open: {:?}, Verify: {:?}",
                commit_time,
                open_time,
                verify_time
            );

            // Machine-readable per-iteration output
            println!(
                "ITER_{}_COMMIT_MS: {:.3}",
                iter + 1,
                commit_time.as_secs_f64() * 1000.0
            );
            println!(
                "ITER_{}_OPEN_MS: {:.3}",
                iter + 1,
                open_time.as_secs_f64() * 1000.0
            );
            println!(
                "ITER_{}_VERIFY_MS: {:.3}",
                iter + 1,
                verify_time.as_secs_f64() * 1000.0
            );
        }

        // Print summary
        let avg = |times: &[Duration]| -> Duration {
            times.iter().sum::<Duration>() / times.len() as u32
        };

        master_print!("\n========================================");
        master_print!("Summary ({} iterations):", iterations);
        master_print!("  Commit (avg): {:?}", avg(&commit_times));
        master_print!("  Open (avg):   {:?}", avg(&open_times));
        master_print!("  Verify (avg): {:?}", avg(&verify_times));
        master_print!("  Commitment size: {} KB", commitment_size as f64 / 1024.0);
        master_print!("  Proof size:   {} KB", proof_size as f64 / 1024.0);
        master_print!("  Communication: {:.2} MB", total_comm_mb);

        // Machine-readable output
        println!(
            "COMMIT_TIME_MS: {:.3}",
            avg(&commit_times).as_secs_f64() * 1000.0
        );
        println!(
            "OPEN_TIME_MS: {:.3}",
            avg(&open_times).as_secs_f64() * 1000.0
        );
        println!(
            "VERIFY_TIME_MS: {:.3}",
            avg(&verify_times).as_secs_f64() * 1000.0
        );
        println!("COMMITMENT_SIZE_KB: {:.2}", commitment_size as f64 / 1024.0);
        println!("PROOF_SIZE_KB: {:.2}", proof_size as f64 / 1024.0);
        println!("COMM_TOTAL_MB: {:.2}", total_comm_mb);

        if let Some(peak_mem_kb) = get_peak_memory_kb() {
            master_print!("  Peak Memory:  {:.2} MB", peak_mem_kb as f64 / 1024.0);
            println!("PEAK_MEMORY_MB: {:.2}", peak_mem_kb as f64 / 1024.0);
        }
        master_print!("========================================");
    } else {
        // Worker nodes
        let srs = Net::recv_from_master_uniform::<LigeSISSRS<F>>(None);
        let (pp, _vp) = LigeSISPCS::<F>::d_setup(&srs)?;
        let mu = srs.mu;

        for _iter in 0..iterations {
            let poly_k = Arc::new(DenseMultilinearExtension::<F>::rand(
                mu - num_party_vars,
                &mut rng,
            ));
            let point: Vec<F> = Net::recv_from_master_uniform(None);

            barrier();
            Net::reset_stats();
            let (_, advice) = LigeSISPCS::d_commit(&pp, &poly_k).unwrap();

            barrier();
            Net::reset_stats();
            let mut transcript = IOPTranscript::<F>::new(b"test");
            LigeSISPCS::d_open(&pp, &poly_k, &advice, &point, &mut transcript).unwrap();
        }

        if party_id == 1 {
            let stats = Net::stats();
            println!(
                "[P1] Communication: sent={:.2} MB, recv={:.2} MB",
                stats.bytes_sent as f64 / (1024.0 * 1024.0),
                stats.bytes_recv as f64 / (1024.0 * 1024.0)
            );
            if let Some(peak_mem_kb) = get_peak_memory_kb() {
                println!("[P1] Peak Memory: {:.2} MB", peak_mem_kb as f64 / 1024.0);
            }
        }
    }

    Ok(())
}

fn main() {
    common::network_run(|opt: Opt| {
        test_multi::<F>(
            opt.mu,
            opt.log_m,
            opt.base_mu,
            opt.code_rate,
            opt.iterations,
        )
        .unwrap();
    });
}

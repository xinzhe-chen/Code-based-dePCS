use ark_ff::{PrimeField, UniformRand};
use ark_poly::{DenseMultilinearExtension, MultilinearExtension};
use std::sync::Arc;
use std::time::Instant;
use ligesis_pcs::{
    DeepFoldPCS, DeepFoldSRS, PCSError, PolynomialCommitmentScheme,
    deepfold::{
        d_chunked_batch_commit, d_chunked_batch_open, chunked_batch_verify,
        compute_claimed_values_from_proof,
        // Multi-commitment batch open
        d_multi_chunked_batch_open, multi_chunked_batch_verify,
    },
};
use transcript::IOPTranscript;

use deNetwork::{DeMultiNet as Net, DeNet, DeSerNet};

mod common;
use common::{test_rng, Opt};
mod types;
use types::FGoldilocks as F;

/// Test Case 1: Large polynomials where poly.num_vars >= base_mu
/// Each party can split locally
fn test_large_polys<F: PrimeField>(base_mu: usize, num_poly: usize) -> Result<(), PCSError> {
    let mut rng = test_rng();
    let num_party = Net::n_parties();
    let num_party_vars = num_party.ilog2() as usize;
    let party_id = Net::party_id();
    let should_print = party_id == 0;
    let global_start = Instant::now();

    macro_rules! log {
        ($($arg:tt)*) => {
            if should_print {
                print!("[P{}] ", party_id);
                println!($($arg)*);
            }
        };
    }

    macro_rules! log_step {
        ($step:expr, $elapsed:expr) => {
            if should_print {
                println!("[P{}] {:20} {:>10.3?}  (@ {:.3?})", party_id, $step, $elapsed, global_start.elapsed());
            }
        };
    }

    // Local poly size >= base_mu
    // With 4 parties (num_party_vars=2), if base_mu=4, local_mu should be >= 4
    // So full_num_vars = local_mu + 2 >= 6
    let local_mu = base_mu; // local_mu = base_mu, so poly.num_vars >= base_mu
    let full_mu = local_mu + num_party_vars;

    if Net::am_master() {
        log!("========================================");
        log!("Test Case 1: Large Polynomials");
        log!("  base_mu = {}, local_mu = {}, full_mu = {}", base_mu, local_mu, full_mu);
        log!("  parties = {}, num_poly = {}", num_party, num_poly);
        log!("  Condition: poly.num_vars ({}) >= base_mu ({})", local_mu, base_mu);
        log!("========================================");
    }

    // Gen SRS
    let srs = if Net::am_master() {
        let start = Instant::now();
        let srs = DeepFoldPCS::<F>::gen_srs_for_testing(&mut rng, base_mu)?;
        log_step!("Gen SRS", start.elapsed());
        Net::recv_from_master_uniform(Some(srs.clone()));
        srs
    } else {
        Net::recv_from_master_uniform::<DeepFoldSRS<F>>(None)
    };

    let (pp, vp) = DeepFoldPCS::<F>::setup(&srs)?;

    // Generate local polys
    let polys: Vec<Arc<DenseMultilinearExtension<F>>> = (0..num_poly)
        .map(|_| Arc::new(DenseMultilinearExtension::<F>::rand(local_mu, &mut rng)))
        .collect();

    // Generate points (each polynomial gets a different point)
    let points: Vec<Vec<F>> = if Net::am_master() {
        let pts: Vec<Vec<F>> = (0..num_poly)
            .map(|_| (0..full_mu).map(|_| F::rand(&mut rng)).collect())
            .collect();
        Net::recv_from_master_uniform(Some(pts.clone()));
        pts
    } else {
        Net::recv_from_master_uniform(None)
    };

    // Distributed Chunked Commit
    let start = Instant::now();
    let (com_opt, advice) = d_chunked_batch_commit(&pp, &polys)?;
    log_step!("D-ChunkedCommit", start.elapsed());

    // Distributed Chunked Open
    let start = Instant::now();
    let mut transcript = IOPTranscript::<F>::new(b"chunked_batch_test");
    let proof_opt = d_chunked_batch_open(&pp, &polys, &advice, &points, &mut transcript)?;
    log_step!("D-ChunkedOpen", start.elapsed());

    // Verify (on master only)
    if Net::am_master() {
        let com = com_opt.unwrap();
        let proof = proof_opt.unwrap();

        let start = Instant::now();
        let mut transcript = IOPTranscript::<F>::new(b"chunked_batch_test");
        let result = chunked_batch_verify(&vp, &com, &points, &proof, &mut transcript)?;
        log_step!("Verify", start.elapsed());

        let claimed_values = compute_claimed_values_from_proof(&proof);
        log!("Claimed values: {:?}", claimed_values.len());

        log!("========================================");
        log!("Total: {:.3?}", global_start.elapsed());
        log!("Result: {}", if result { "PASS" } else { "FAIL" });
        log!("========================================");
        assert!(result, "Verification failed for large polys");
    }

    Ok(())
}

/// Test Case 2: Small polynomials where poly.num_vars < base_mu AND full_num_vars <= base_mu
/// Only 1 chunk total, handled entirely by master
fn test_small_polys_single_chunk<F: PrimeField>(base_mu: usize, num_poly: usize) -> Result<(), PCSError> {
    let mut rng = test_rng();
    let num_party = Net::n_parties();
    let num_party_vars = num_party.ilog2() as usize;
    let party_id = Net::party_id();
    let should_print = party_id == 0;
    let global_start = Instant::now();

    macro_rules! log {
        ($($arg:tt)*) => {
            if should_print {
                print!("[P{}] ", party_id);
                println!($($arg)*);
            }
        };
    }

    macro_rules! log_step {
        ($step:expr, $elapsed:expr) => {
            if should_print {
                println!("[P{}] {:20} {:>10.3?}  (@ {:.3?})", party_id, $step, $elapsed, global_start.elapsed());
            }
        };
    }

    // We need: poly.num_vars < base_mu AND full_num_vars <= base_mu
    // full_num_vars = local_mu + num_party_vars <= base_mu
    // So local_mu <= base_mu - num_party_vars
    // With 4 parties (num_party_vars=2) and base_mu=4, local_mu <= 2
    let local_mu = if base_mu > num_party_vars { base_mu - num_party_vars } else { 1 };
    let full_mu = local_mu + num_party_vars;

    if full_mu > base_mu {
        if Net::am_master() {
            log!("Skipping test_small_polys_single_chunk: full_mu ({}) > base_mu ({})", full_mu, base_mu);
        }
        return Ok(());
    }

    if Net::am_master() {
        log!("========================================");
        log!("Test Case 2: Small Polys (Single Chunk)");
        log!("  base_mu = {}, local_mu = {}, full_mu = {}", base_mu, local_mu, full_mu);
        log!("  parties = {}, num_poly = {}", num_party, num_poly);
        log!("  Condition: poly.num_vars ({}) < base_mu ({}) AND full_num_vars ({}) <= base_mu",
             local_mu, base_mu, full_mu);
        log!("========================================");
    }

    // Gen SRS
    let srs = if Net::am_master() {
        let start = Instant::now();
        let srs = DeepFoldPCS::<F>::gen_srs_for_testing(&mut rng, base_mu)?;
        log_step!("Gen SRS", start.elapsed());
        Net::recv_from_master_uniform(Some(srs.clone()));
        srs
    } else {
        Net::recv_from_master_uniform::<DeepFoldSRS<F>>(None)
    };

    let (pp, vp) = DeepFoldPCS::<F>::setup(&srs)?;

    // Generate local polys (small)
    let polys: Vec<Arc<DenseMultilinearExtension<F>>> = (0..num_poly)
        .map(|_| Arc::new(DenseMultilinearExtension::<F>::rand(local_mu, &mut rng)))
        .collect();

    // Generate points
    let points: Vec<Vec<F>> = if Net::am_master() {
        let pts: Vec<Vec<F>> = (0..num_poly)
            .map(|_| (0..full_mu).map(|_| F::rand(&mut rng)).collect())
            .collect();
        Net::recv_from_master_uniform(Some(pts.clone()));
        pts
    } else {
        Net::recv_from_master_uniform(None)
    };

    // Distributed Chunked Commit
    let start = Instant::now();
    let (com_opt, advice) = d_chunked_batch_commit(&pp, &polys)?;
    log_step!("D-ChunkedCommit", start.elapsed());

    if Net::am_master() {
        let com = com_opt.as_ref().unwrap();
        log!("Chunks per poly: {:?}", com.chunks_per_poly);
        assert!(com.chunks_per_poly.iter().all(|&c| c == 1), "Expected 1 chunk per poly");
    }

    // Distributed Chunked Open
    let start = Instant::now();
    let mut transcript = IOPTranscript::<F>::new(b"chunked_batch_test");
    let proof_opt = d_chunked_batch_open(&pp, &polys, &advice, &points, &mut transcript)?;
    log_step!("D-ChunkedOpen", start.elapsed());

    // Verify (on master only)
    if Net::am_master() {
        let com = com_opt.unwrap();
        let proof = proof_opt.unwrap();

        let start = Instant::now();
        let mut transcript = IOPTranscript::<F>::new(b"chunked_batch_test");
        let result = chunked_batch_verify(&vp, &com, &points, &proof, &mut transcript)?;
        log_step!("Verify", start.elapsed());

        log!("========================================");
        log!("Total: {:.3?}", global_start.elapsed());
        log!("Result: {}", if result { "PASS" } else { "FAIL" });
        log!("========================================");
        assert!(result, "Verification failed for small polys (single chunk)");
    }

    Ok(())
}

/// Test Case 3: Small polynomials where poly.num_vars < base_mu < full_num_vars
/// This is the critical edge case!
fn test_small_polys_multi_chunk<F: PrimeField>(base_mu: usize, num_poly: usize) -> Result<(), PCSError> {
    let mut rng = test_rng();
    let num_party = Net::n_parties();
    let num_party_vars = num_party.ilog2() as usize;
    let party_id = Net::party_id();
    let should_print = party_id == 0;
    let global_start = Instant::now();

    macro_rules! log {
        ($($arg:tt)*) => {
            if should_print {
                print!("[P{}] ", party_id);
                println!($($arg)*);
            }
        };
    }

    macro_rules! log_step {
        ($step:expr, $elapsed:expr) => {
            if should_print {
                println!("[P{}] {:20} {:>10.3?}  (@ {:.3?})", party_id, $step, $elapsed, global_start.elapsed());
            }
        };
    }

    // We need: poly.num_vars < base_mu < full_num_vars
    // So: local_mu < base_mu AND local_mu + num_party_vars > base_mu
    // With 4 parties (num_party_vars=2) and base_mu=4:
    // local_mu < 4 AND local_mu + 2 > 4 => local_mu > 2
    // So local_mu = 3 works: local_mu=3 < base_mu=4 < full_mu=5
    let local_mu = if base_mu > 1 { base_mu - 1 } else { 1 };
    let full_mu = local_mu + num_party_vars;

    if local_mu >= base_mu || full_mu <= base_mu {
        if Net::am_master() {
            log!("Skipping test_small_polys_multi_chunk: conditions not met");
            log!("  local_mu={}, base_mu={}, full_mu={}", local_mu, base_mu, full_mu);
        }
        return Ok(());
    }

    if Net::am_master() {
        log!("========================================");
        log!("Test Case 3: Small Polys (Multi Chunk) - CRITICAL EDGE CASE");
        log!("  base_mu = {}, local_mu = {}, full_mu = {}", base_mu, local_mu, full_mu);
        log!("  parties = {}, num_poly = {}", num_party, num_poly);
        log!("  Condition: poly.num_vars ({}) < base_mu ({}) < full_num_vars ({})",
             local_mu, base_mu, full_mu);
        log!("========================================");
    }

    // Gen SRS
    let srs = if Net::am_master() {
        let start = Instant::now();
        let srs = DeepFoldPCS::<F>::gen_srs_for_testing(&mut rng, base_mu)?;
        log_step!("Gen SRS", start.elapsed());
        Net::recv_from_master_uniform(Some(srs.clone()));
        srs
    } else {
        Net::recv_from_master_uniform::<DeepFoldSRS<F>>(None)
    };

    let (pp, vp) = DeepFoldPCS::<F>::setup(&srs)?;

    // Generate local polys (small, but full poly needs chunking)
    let polys: Vec<Arc<DenseMultilinearExtension<F>>> = (0..num_poly)
        .map(|_| Arc::new(DenseMultilinearExtension::<F>::rand(local_mu, &mut rng)))
        .collect();

    // Generate points
    let points: Vec<Vec<F>> = if Net::am_master() {
        let pts: Vec<Vec<F>> = (0..num_poly)
            .map(|_| (0..full_mu).map(|_| F::rand(&mut rng)).collect())
            .collect();
        Net::recv_from_master_uniform(Some(pts.clone()));
        pts
    } else {
        Net::recv_from_master_uniform(None)
    };

    // Distributed Chunked Commit
    let start = Instant::now();
    let (com_opt, advice) = d_chunked_batch_commit(&pp, &polys)?;
    log_step!("D-ChunkedCommit", start.elapsed());

    if Net::am_master() {
        let com = com_opt.as_ref().unwrap();
        let expected_chunks = 1 << (full_mu - base_mu);
        log!("Chunks per poly: {:?} (expected: {})", com.chunks_per_poly, expected_chunks);
        assert!(com.chunks_per_poly.iter().all(|&c| c == expected_chunks),
                "Expected {} chunks per poly", expected_chunks);
    }

    // Distributed Chunked Open
    let start = Instant::now();
    let mut transcript = IOPTranscript::<F>::new(b"chunked_batch_test");
    let proof_opt = d_chunked_batch_open(&pp, &polys, &advice, &points, &mut transcript)?;
    log_step!("D-ChunkedOpen", start.elapsed());

    // Verify (on master only)
    if Net::am_master() {
        let com = com_opt.unwrap();
        let proof = proof_opt.unwrap();

        let start = Instant::now();
        let mut transcript = IOPTranscript::<F>::new(b"chunked_batch_test");
        let result = chunked_batch_verify(&vp, &com, &points, &proof, &mut transcript)?;
        log_step!("Verify", start.elapsed());

        log!("========================================");
        log!("Total: {:.3?}", global_start.elapsed());
        log!("Result: {}", if result { "PASS" } else { "FAIL" });
        log!("========================================");
        assert!(result, "Verification failed for small polys (multi chunk) - CRITICAL!");
    }

    Ok(())
}

/// Test Case 4: Mixed sizes - some large, some small
fn test_mixed_sizes<F: PrimeField>(base_mu: usize) -> Result<(), PCSError> {
    let mut rng = test_rng();
    let num_party = Net::n_parties();
    let num_party_vars = num_party.ilog2() as usize;
    let party_id = Net::party_id();
    let should_print = party_id == 0;
    let global_start = Instant::now();

    macro_rules! log {
        ($($arg:tt)*) => {
            if should_print {
                print!("[P{}] ", party_id);
                println!($($arg)*);
            }
        };
    }

    macro_rules! log_step {
        ($step:expr, $elapsed:expr) => {
            if should_print {
                println!("[P{}] {:20} {:>10.3?}  (@ {:.3?})", party_id, $step, $elapsed, global_start.elapsed());
            }
        };
    }

    if Net::am_master() {
        log!("========================================");
        log!("Test Case 4: Mixed Sizes");
        log!("  base_mu = {}, parties = {}", base_mu, num_party);
        log!("========================================");
    }

    // Gen SRS
    let srs = if Net::am_master() {
        let start = Instant::now();
        let srs = DeepFoldPCS::<F>::gen_srs_for_testing(&mut rng, base_mu)?;
        log_step!("Gen SRS", start.elapsed());
        Net::recv_from_master_uniform(Some(srs.clone()));
        srs
    } else {
        Net::recv_from_master_uniform::<DeepFoldSRS<F>>(None)
    };

    let (pp, vp) = DeepFoldPCS::<F>::setup(&srs)?;

    // Create polynomials of different sizes
    let local_sizes = if base_mu > num_party_vars + 1 {
        vec![
            base_mu - num_party_vars - 1,  // Small: full < base_mu (if possible)
            base_mu - 1,                    // Medium: local < base_mu < full
            base_mu,                        // Large: local >= base_mu
            base_mu + 1,                    // Extra large
        ]
    } else {
        vec![base_mu, base_mu + 1]  // Just large polys if base_mu is small
    };

    let polys: Vec<Arc<DenseMultilinearExtension<F>>> = local_sizes.iter()
        .map(|&size| Arc::new(DenseMultilinearExtension::<F>::rand(size, &mut rng)))
        .collect();

    if Net::am_master() {
        log!("Local sizes: {:?}", local_sizes);
        log!("Full sizes: {:?}", local_sizes.iter().map(|s| s + num_party_vars).collect::<Vec<_>>());
    }

    // Generate points for each polynomial
    let points: Vec<Vec<F>> = if Net::am_master() {
        let pts: Vec<Vec<F>> = local_sizes.iter()
            .map(|&size| {
                let full_size = size + num_party_vars;
                (0..full_size).map(|_| F::rand(&mut rng)).collect()
            })
            .collect();
        Net::recv_from_master_uniform(Some(pts.clone()));
        pts
    } else {
        Net::recv_from_master_uniform(None)
    };

    // Distributed Chunked Commit
    let start = Instant::now();
    let (com_opt, advice) = d_chunked_batch_commit(&pp, &polys)?;
    log_step!("D-ChunkedCommit", start.elapsed());

    if Net::am_master() {
        let com = com_opt.as_ref().unwrap();
        log!("Chunks per poly: {:?}", com.chunks_per_poly);
        log!("Original num vars: {:?}", com.original_num_vars);
    }

    // Distributed Chunked Open
    let start = Instant::now();
    let mut transcript = IOPTranscript::<F>::new(b"chunked_batch_test");
    let proof_opt = d_chunked_batch_open(&pp, &polys, &advice, &points, &mut transcript)?;
    log_step!("D-ChunkedOpen", start.elapsed());

    // Verify (on master only)
    if Net::am_master() {
        let com = com_opt.unwrap();
        let proof = proof_opt.unwrap();

        let start = Instant::now();
        let mut transcript = IOPTranscript::<F>::new(b"chunked_batch_test");
        let result = chunked_batch_verify(&vp, &com, &points, &proof, &mut transcript)?;
        log_step!("Verify", start.elapsed());

        log!("========================================");
        log!("Total: {:.3?}", global_start.elapsed());
        log!("Result: {}", if result { "PASS" } else { "FAIL" });
        log!("========================================");
        assert!(result, "Verification failed for mixed sizes");
    }

    Ok(())
}

/// Test Case 5: Multi-commitment batch open
/// Tests d_multi_chunked_batch_open with multiple commitments at different points
fn test_multi_chunked_batch_open<F: PrimeField>(base_mu: usize) -> Result<(), PCSError> {
    let mut rng = test_rng();
    let num_party = Net::n_parties();
    let num_party_vars = num_party.ilog2() as usize;
    let party_id = Net::party_id();
    let should_print = party_id == 0;
    let global_start = Instant::now();

    macro_rules! log {
        ($($arg:tt)*) => {
            if should_print {
                print!("[P{}] ", party_id);
                println!($($arg)*);
            }
        };
    }

    macro_rules! log_step {
        ($step:expr, $elapsed:expr) => {
            if should_print {
                println!("[P{}] {:20} {:>10.3?}  (@ {:.3?})", party_id, $step, $elapsed, global_start.elapsed());
            }
        };
    }

    // Use local_mu >= base_mu to ensure large poly case
    let local_mu = base_mu;
    let full_mu = local_mu + num_party_vars;

    if Net::am_master() {
        log!("========================================");
        log!("Test Case 5: Multi-Commitment Batch Open");
        log!("  base_mu = {}, local_mu = {}, full_mu = {}", base_mu, local_mu, full_mu);
        log!("  parties = {}", num_party);
        log!("========================================");
    }

    // Gen SRS
    let srs = if Net::am_master() {
        let start = Instant::now();
        let srs = DeepFoldPCS::<F>::gen_srs_for_testing(&mut rng, base_mu)?;
        log_step!("Gen SRS", start.elapsed());
        Net::recv_from_master_uniform(Some(srs.clone()));
        srs
    } else {
        Net::recv_from_master_uniform::<DeepFoldSRS<F>>(None)
    };

    let (pp, vp) = DeepFoldPCS::<F>::setup(&srs)?;

    // Create 2 commitments, each with 2 polynomials
    // Commitment 1: 2 polynomials
    let polys1: Vec<Arc<DenseMultilinearExtension<F>>> = (0..2)
        .map(|_| Arc::new(DenseMultilinearExtension::<F>::rand(local_mu, &mut rng)))
        .collect();

    // Commitment 2: 2 polynomials (different sizes)
    let local_mu2 = if base_mu > 1 { base_mu - 1 } else { base_mu };
    let polys2: Vec<Arc<DenseMultilinearExtension<F>>> = (0..2)
        .map(|_| Arc::new(DenseMultilinearExtension::<F>::rand(local_mu2, &mut rng)))
        .collect();

    // Distributed commit for both sets
    let start = Instant::now();
    let (com1_opt, advice1) = d_chunked_batch_commit(&pp, &polys1)?;
    let (com2_opt, advice2) = d_chunked_batch_commit(&pp, &polys2)?;
    log_step!("D-ChunkedCommit x2", start.elapsed());

    // Generate opening points (one per commitment)
    let full_mu2 = local_mu2 + num_party_vars;
    let points: Vec<Vec<F>> = if Net::am_master() {
        let pts: Vec<Vec<F>> = vec![
            (0..full_mu).map(|_| F::rand(&mut rng)).collect(),
            (0..full_mu2).map(|_| F::rand(&mut rng)).collect(),
        ];
        Net::recv_from_master_uniform(Some(pts.clone()));
        pts
    } else {
        Net::recv_from_master_uniform(None)
    };

    // Distributed multi-commitment batch open
    let start = Instant::now();
    let mut transcript = IOPTranscript::<F>::new(b"multi_chunked_batch_test");
    // point_to_commit: points[0] -> commitment 0, points[1] -> commitment 1
    let point_to_commit: Vec<usize> = vec![0, 1];
    let proof_opt = d_multi_chunked_batch_open(
        &pp,
        &[&advice1, &advice2],
        &points,
        &point_to_commit,
        &mut transcript,
    )?;
    log_step!("D-MultiChunkedOpen", start.elapsed());

    // Verify (on master only)
    if Net::am_master() {
        let com1 = com1_opt.unwrap();
        let com2 = com2_opt.unwrap();
        let proof = proof_opt.unwrap();

        log!("Commitment 1: {} chunks total", com1.chunks_per_poly.iter().sum::<usize>());
        log!("Commitment 2: {} chunks total", com2.chunks_per_poly.iter().sum::<usize>());

        let start = Instant::now();
        let mut transcript = IOPTranscript::<F>::new(b"multi_chunked_batch_test");
        let result = multi_chunked_batch_verify(
            &vp,
            &[&com1, &com2],
            &points,
            &proof,
            &mut transcript,
        )?;
        log_step!("Verify", start.elapsed());

        log!("Claimed values: {:?}", proof.claimed_values);

        log!("========================================");
        log!("Total: {:.3?}", global_start.elapsed());
        log!("Result: {}", if result { "PASS" } else { "FAIL" });
        log!("========================================");
        assert!(result, "Verification failed for multi-commitment batch open");
    }

    Ok(())
}

/// Test Case 6: Multi-commitment batch open with mixed polynomial sizes
/// Tests d_multi_chunked_batch_open with commitments containing polynomials of different sizes
fn test_multi_chunked_batch_open_mixed<F: PrimeField>(base_mu: usize) -> Result<(), PCSError> {
    let mut rng = test_rng();
    let num_party = Net::n_parties();
    let num_party_vars = num_party.ilog2() as usize;
    let party_id = Net::party_id();
    let should_print = party_id == 0;
    let global_start = Instant::now();

    macro_rules! log {
        ($($arg:tt)*) => {
            if should_print {
                print!("[P{}] ", party_id);
                println!($($arg)*);
            }
        };
    }

    macro_rules! log_step {
        ($step:expr, $elapsed:expr) => {
            if should_print {
                println!("[P{}] {:20} {:>10.3?}  (@ {:.3?})", party_id, $step, $elapsed, global_start.elapsed());
            }
        };
    }

    if Net::am_master() {
        log!("========================================");
        log!("Test Case 6: Multi-Commitment Batch Open (Mixed Sizes)");
        log!("  base_mu = {}, parties = {}", base_mu, num_party);
        log!("========================================");
    }

    // Gen SRS
    let srs = if Net::am_master() {
        let start = Instant::now();
        let srs = DeepFoldPCS::<F>::gen_srs_for_testing(&mut rng, base_mu)?;
        log_step!("Gen SRS", start.elapsed());
        Net::recv_from_master_uniform(Some(srs.clone()));
        srs
    } else {
        Net::recv_from_master_uniform::<DeepFoldSRS<F>>(None)
    };

    let (pp, vp) = DeepFoldPCS::<F>::setup(&srs)?;

    // Create 3 commitments with different polynomial configurations
    // Commitment 1: Large poly (local_mu >= base_mu)
    let local_mu1 = base_mu;
    let polys1: Vec<Arc<DenseMultilinearExtension<F>>> = vec![
        Arc::new(DenseMultilinearExtension::<F>::rand(local_mu1, &mut rng)),
    ];

    // Commitment 2: Small poly that becomes multi-chunk (local_mu < base_mu < full_mu)
    let local_mu2 = if base_mu > 1 { base_mu - 1 } else { 1 };
    let polys2: Vec<Arc<DenseMultilinearExtension<F>>> = vec![
        Arc::new(DenseMultilinearExtension::<F>::rand(local_mu2, &mut rng)),
        Arc::new(DenseMultilinearExtension::<F>::rand(local_mu2, &mut rng)),
    ];

    // Commitment 3: Very large poly (local_mu > base_mu)
    let local_mu3 = base_mu + 1;
    let polys3: Vec<Arc<DenseMultilinearExtension<F>>> = vec![
        Arc::new(DenseMultilinearExtension::<F>::rand(local_mu3, &mut rng)),
    ];

    let full_mu1 = local_mu1 + num_party_vars;
    let full_mu2 = local_mu2 + num_party_vars;
    let full_mu3 = local_mu3 + num_party_vars;

    if Net::am_master() {
        log!("Poly sizes (local/full):");
        log!("  Commitment 1: {}/{}", local_mu1, full_mu1);
        log!("  Commitment 2: {}/{} (x2 polys)", local_mu2, full_mu2);
        log!("  Commitment 3: {}/{}", local_mu3, full_mu3);
    }

    // Distributed commit for all sets
    let start = Instant::now();
    let (com1_opt, advice1) = d_chunked_batch_commit(&pp, &polys1)?;
    let (com2_opt, advice2) = d_chunked_batch_commit(&pp, &polys2)?;
    let (com3_opt, advice3) = d_chunked_batch_commit(&pp, &polys3)?;
    log_step!("D-ChunkedCommit x3", start.elapsed());

    // Generate opening points (one per commitment)
    let points: Vec<Vec<F>> = if Net::am_master() {
        let pts: Vec<Vec<F>> = vec![
            (0..full_mu1).map(|_| F::rand(&mut rng)).collect(),
            (0..full_mu2).map(|_| F::rand(&mut rng)).collect(),
            (0..full_mu3).map(|_| F::rand(&mut rng)).collect(),
        ];
        Net::recv_from_master_uniform(Some(pts.clone()));
        pts
    } else {
        Net::recv_from_master_uniform(None)
    };

    // Distributed multi-commitment batch open
    let start = Instant::now();
    let mut transcript = IOPTranscript::<F>::new(b"multi_chunked_batch_mixed_test");
    // point_to_commit: points[i] -> commitment i
    let point_to_commit: Vec<usize> = vec![0, 1, 2];
    let proof_opt = d_multi_chunked_batch_open(
        &pp,
        &[&advice1, &advice2, &advice3],
        &points,
        &point_to_commit,
        &mut transcript,
    )?;
    log_step!("D-MultiChunkedOpen", start.elapsed());

    // Verify (on master only)
    if Net::am_master() {
        let com1 = com1_opt.unwrap();
        let com2 = com2_opt.unwrap();
        let com3 = com3_opt.unwrap();
        let proof = proof_opt.unwrap();

        log!("Chunks per poly:");
        log!("  Commitment 1: {:?}", com1.chunks_per_poly);
        log!("  Commitment 2: {:?}", com2.chunks_per_poly);
        log!("  Commitment 3: {:?}", com3.chunks_per_poly);

        let start = Instant::now();
        let mut transcript = IOPTranscript::<F>::new(b"multi_chunked_batch_mixed_test");
        let result = multi_chunked_batch_verify(
            &vp,
            &[&com1, &com2, &com3],
            &points,
            &proof,
            &mut transcript,
        )?;
        log_step!("Verify", start.elapsed());

        log!("========================================");
        log!("Total: {:.3?}", global_start.elapsed());
        log!("Result: {}", if result { "PASS" } else { "FAIL" });
        log!("========================================");
        assert!(result, "Verification failed for multi-commitment batch open (mixed sizes)");
    }

    Ok(())
}

fn main() {
    common::network_run(|opt: Opt| {
        let base_mu = opt.mu;
        let num_poly = 3;

        println!("\n=== Running Distributed Chunked Batch Tests ===\n");

        // Test Case 1: Large polynomials
        println!("\n--- Test Case 1: Large Polynomials ---");
        test_large_polys::<F>(base_mu, num_poly).expect("Test Case 1 failed");

        // Test Case 2: Small polynomials (single chunk)
        println!("\n--- Test Case 2: Small Polynomials (Single Chunk) ---");
        test_small_polys_single_chunk::<F>(base_mu, num_poly).expect("Test Case 2 failed");

        // Test Case 3: Small polynomials (multi chunk) - CRITICAL
        println!("\n--- Test Case 3: Small Polynomials (Multi Chunk) - CRITICAL ---");
        test_small_polys_multi_chunk::<F>(base_mu, num_poly).expect("Test Case 3 failed");

        // Test Case 4: Mixed sizes
        println!("\n--- Test Case 4: Mixed Sizes ---");
        test_mixed_sizes::<F>(base_mu).expect("Test Case 4 failed");

        // Test Case 5: Multi-commitment batch open
        println!("\n--- Test Case 5: Multi-Commitment Batch Open ---");
        test_multi_chunked_batch_open::<F>(base_mu).expect("Test Case 5 failed");

        // Test Case 6: Multi-commitment batch open with mixed sizes
        println!("\n--- Test Case 6: Multi-Commitment Batch Open (Mixed Sizes) ---");
        test_multi_chunked_batch_open_mixed::<F>(base_mu).expect("Test Case 6 failed");

        if Net::am_master() {
            println!("\n=== All Distributed Chunked Batch Tests PASSED ===\n");
        }
    });
}

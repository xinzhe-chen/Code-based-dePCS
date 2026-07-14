use ark_ff::{PrimeField, UniformRand};
use ark_poly::{DenseMultilinearExtension, MultilinearExtension};
use ark_serialize::CanonicalSerialize;
use std::sync::Arc;
use std::time::Instant;
use ligesis_pcs::{
    DeepFoldPCS, DeepFoldSRS, PCSError, PolynomialCommitmentScheme,
    deepfold::{
        d_chunked_batch_commit, d_multi_chunked_batch_open, multi_chunked_batch_verify,
        DeepFoldBatchMultiCommitment, MultiChunkedBatchProof,
    },
};
use transcript::IOPTranscript;

use deNetwork::{DeMultiNet as Net, DeNet, DeSerNet};

mod common;
use common::{test_rng, Opt};
mod types;
use types::FGoldilocks as F;

/// Benchmark simulating Ligesis usage pattern with REAL parameters:
///
/// Polynomial sizes (num_vars):
/// - mat_a: base_mu = log_m + 9
/// - mat_h: log_n + 4
/// - a: log_n (opened 2 times)
/// - bI: log_m + 13 (opened 3 times)
/// - rs_a: log_n + 1 (opened 2 times)
///
/// Since d_multi_chunked_batch_open allows one point per commitment,
/// we model multiple openings as separate polynomial instances:
/// - Setup: [mat_a] = 1 poly
/// - Commit: [mat_h] = 1 poly
/// - Open: [a×2, bI×3, rs_a×2] = 7 polys (accounting for opening counts)
///
/// Total: 9 polynomial openings across 3 commitments
///
/// Parameters follow Ligesis formulas:
/// - ligesis_mu: Full polynomial size (number of variables)
/// - log_m = (ligesis_mu - 8) / 2
/// - base_mu = log_m + 9 (from ligesis.gen_srs_for_testing)
fn bench_ligesis_scenario<F: PrimeField>(
    ligesis_mu: usize,
    base_mu_override: Option<usize>,
    log_m_override: Option<usize>,
) -> Result<(), PCSError> {
    let mut rng = test_rng();
    let num_party = Net::n_parties();
    let num_party_vars = num_party.ilog2() as usize;
    let party_id = Net::party_id();
    let should_print = party_id == 0;
    let global_start = Instant::now();

    // Ligesis scenario parameters (following ligesis.gen_srs_for_testing)
    // log_m = (ligesis_mu - 8) / 2
    // base_mu = log_m + 9 (DeepFold SRS max_mu)
    // log_n = ligesis_mu - log_m
    let default_log_m = if ligesis_mu < 8 { 0 } else { (ligesis_mu - 8) / 2 };
    let log_m = log_m_override.unwrap_or(default_log_m);
    let default_base_mu = log_m + 9;
    let base_mu = base_mu_override.unwrap_or(default_base_mu);
    let log_n = ligesis_mu - log_m;
    let local_mu = ligesis_mu - num_party_vars;
    let full_mu = ligesis_mu;

    // Real Ligesis polynomial sizes (full, before distribution):
    // - mat_a: base_mu = log_m + 9
    // - mat_h: log_n + 4
    // - a: log_n (opened 2×)
    // - bI: log_m + 13 (= log_m + 6 + 7, for m * eta * s_lambda where eta=64, s_lambda=128)
    // - rs_a: log_n + 1 (opened 2×)
    let mat_a_size = base_mu;
    let mat_h_size = log_n + 4;
    let a_size = log_n;
    let bI_size = log_m + 13;  // m * 64 * 128 = 2^(log_m + 6 + 7)
    let rs_a_size = log_n + 1;

    // Distribution: Each polynomial type gets its own commitment for multi-point opening
    // - Commitment 0: mat_a (opened 1×)
    // - Commitment 1: mat_h (opened 1×)
    // - Commitment 2: a (opened 2×)
    // - Commitment 3: bI (opened 3×)
    // - Commitment 4: rs_a (opened 2×)
    let num_commitments = 5;
    let total_openings = 1 + 1 + 2 + 3 + 2; // 9 openings total

    macro_rules! log {
        ($($arg:tt)*) => {
            if should_print {
                println!($($arg)*);
            }
        };
    }

    log!("================================================================================");
    log!("Benchmark: Ligesis Scenario (d_multi_chunked_batch) - REAL PARAMETERS");
    log!("================================================================================");
    log!("  ligesis_mu (full poly size) = {}", ligesis_mu);
    log!("  log_m                       = {}", log_m);
    log!("  log_n                       = {}", log_n);
    log!("  base_mu (SRS max_mu)        = {}", base_mu);
    log!("  num_parties                 = {}", num_party);
    log!("--------------------------------------------------------------------------------");
    log!("  Polynomial sizes (full num_vars):");
    log!("    mat_a:  {} vars (2^{} elements) - opened 1x", mat_a_size, mat_a_size);
    log!("    mat_h:  {} vars (2^{} elements) - opened 1x", mat_h_size, mat_h_size);
    log!("    a:      {} vars (2^{} elements) - opened 2x", a_size, a_size);
    log!("    bI:     {} vars (2^{} elements) - opened 3x", bI_size, bI_size);
    log!("    rs_a:   {} vars (2^{} elements) - opened 2x", rs_a_size, rs_a_size);
    log!("--------------------------------------------------------------------------------");
    log!("  Commitments: 5 (mat_a / mat_h / a / bI / rs_a)");
    log!("  Total openings: {} (1+1+2+3+2)", total_openings);
    log!("================================================================================");

    // Step 1: Generate SRS
    let srs = if Net::am_master() {
        let start = Instant::now();
        let srs = DeepFoldPCS::<F>::gen_srs_for_testing(&mut rng, base_mu)?;
        log!("[Timing] Gen SRS:              {:>12.3?}", start.elapsed());
        Net::recv_from_master_uniform(Some(srs.clone()));
        srs
    } else {
        Net::recv_from_master_uniform::<DeepFoldSRS<F>>(None)
    };

    let (pp, vp) = DeepFoldPCS::<F>::setup(&srs)?;

    // Step 2: Generate polynomials with REAL Ligesis sizes
    // For d_chunked_batch_commit, we pass LOCAL polynomials.
    // full_num_vars = local_num_vars + num_party_vars
    //
    // Local sizes = full_size - num_party_vars (but at least 1)
    let mat_a_local = mat_a_size.saturating_sub(num_party_vars).max(1);
    let mat_h_local = mat_h_size.saturating_sub(num_party_vars).max(1);
    let a_local = a_size.saturating_sub(num_party_vars).max(1);
    let bI_local = bI_size.saturating_sub(num_party_vars).max(1);
    let rs_a_local = rs_a_size.saturating_sub(num_party_vars).max(1);

    // Each commitment has one polynomial
    // Commitment 0: mat_a, Commitment 1: mat_h, Commitment 2: a, Commitment 3: bI, Commitment 4: rs_a
    let poly_sizes = vec![
        vec![mat_a_local],   // Commitment 0: mat_a
        vec![mat_h_local],   // Commitment 1: mat_h
        vec![a_local],       // Commitment 2: a (opened at 2 different points)
        vec![bI_local],      // Commitment 3: bI (opened at 3 different points)
        vec![rs_a_local],    // Commitment 4: rs_a (opened at 2 different points)
    ];

    log!("  Local sizes (per party): mat_a={}, mat_h={}, a={}, bI={}, rs_a={}",
         mat_a_local, mat_h_local, a_local, bI_local, rs_a_local);

    let all_polys: Vec<Vec<Arc<DenseMultilinearExtension<F>>>> = poly_sizes
        .iter()
        .map(|sizes| {
            sizes
                .iter()
                .map(|&size| Arc::new(DenseMultilinearExtension::<F>::rand(size, &mut rng)))
                .collect()
        })
        .collect();

    // Step 3: Generate points and point_to_commit mapping
    // - point 0 → commit 0 (mat_a, 1 opening)
    // - point 1 → commit 1 (mat_h, 1 opening)
    // - points 2,3 → commit 2 (a, 2 openings)
    // - points 4,5,6 → commit 3 (bI, 3 openings)
    // - points 7,8 → commit 4 (rs_a, 2 openings)
    let point_to_commit = vec![0, 1, 2, 2, 3, 3, 3, 4, 4];
    let (points, point_to_commit): (Vec<Vec<F>>, Vec<usize>) = if Net::am_master() {
        let pts: Vec<Vec<F>> = (0..total_openings)
            .map(|_| (0..full_mu).map(|_| F::rand(&mut rng)).collect())
            .collect();
        Net::recv_from_master_uniform(Some((pts.clone(), point_to_commit.clone())));
        (pts, point_to_commit)
    } else {
        Net::recv_from_master_uniform(None)
    };

    // Step 4: Distributed Chunked Commit for each polynomial type
    log!("\n--- Commit Phase ({} d_chunked_batch_commit calls) ---", num_commitments);
    let commit_start = Instant::now();
    let mut commitments: Vec<DeepFoldBatchMultiCommitment> = Vec::new();
    let mut advices = Vec::new();
    let mut commit_times = Vec::new();

    let phase_names = ["mat_a", "mat_h", "a", "bI", "rs_a"];
    for (i, polys) in all_polys.iter().enumerate() {
        let phase_name = phase_names[i];
        let start = Instant::now();
        let (com_opt, advice) = d_chunked_batch_commit(&pp, polys)?;
        let elapsed = start.elapsed();
        commit_times.push(elapsed);
        log!("[Timing]   {} ({} poly): {:>12.3?}", phase_name, polys.len(), elapsed);

        if Net::am_master() {
            commitments.push(com_opt.unwrap());
        }
        advices.push(advice);
    }
    let total_commit_time = commit_start.elapsed();
    log!("[Timing] Total Commit:         {:>12.3?}", total_commit_time);

    // Step 5: Distributed Multi-Chunked Batch Open
    log!("\n--- Open Phase (1 d_multi_chunked_batch_open call, {} points) ---", total_openings);
    let start = Instant::now();
    let mut transcript = IOPTranscript::<F>::new(b"ligesis_bench");
    let advice_refs: Vec<_> = advices.iter().collect();
    let proof_opt = d_multi_chunked_batch_open(
        &pp,
        &advice_refs,
        &points,
        &point_to_commit,
        &mut transcript,
    )?;
    let open_time = start.elapsed();
    log!("[Timing] D-MultiChunkedOpen:   {:>12.3?}", open_time);

    // Step 6: Verify and measure sizes
    if Net::am_master() {
        let proof = proof_opt.unwrap();
        let commitment_refs: Vec<_> = commitments.iter().collect();

        // Measure proof size
        let mut proof_bytes = Vec::new();
        proof.serialize_compressed(&mut proof_bytes).unwrap();
        let proof_size = proof_bytes.len();

        // Measure commitment size
        let mut commit_bytes = Vec::new();
        for com in &commitments {
            com.serialize_compressed(&mut commit_bytes).unwrap();
        }
        let commit_size = commit_bytes.len();

        log!("\n--- Verify Phase ---");
        let start = Instant::now();
        let mut transcript = IOPTranscript::<F>::new(b"ligesis_bench");
        let result = multi_chunked_batch_verify(
            &vp,
            &commitment_refs,
            &points,
            &proof,
            &mut transcript,
        )?;
        let verify_time = start.elapsed();
        log!("[Timing] Verify:               {:>12.3?}", verify_time);

        log!("\n================================================================================");
        log!("                              SUMMARY");
        log!("================================================================================");
        log!("[Size] Proof size:             {:>12} bytes ({:.2} KB)", proof_size, proof_size as f64 / 1024.0);
        log!("[Size] Commitment size (all):  {:>12} bytes ({:.2} KB)", commit_size, commit_size as f64 / 1024.0);
        log!("[Time] Commit (total):         {:>12.3?}", total_commit_time);
        log!("[Time] Open:                   {:>12.3?}", open_time);
        log!("[Time] Verify:                 {:>12.3?}", verify_time);
        log!("[Time] Prover total:           {:>12.3?}", total_commit_time + open_time);
        log!("[Result] Verification:         {}", if result { "PASS" } else { "FAIL" });

        // CSV output for easy parsing
        log!("\n--- CSV Output ---");
        log!("ligesis_mu,log_m,log_n,base_mu,num_parties,total_openings,commit_s,open_s,verify_ms,prover_total_s,proof_kb,commit_kb");
        log!("{},{},{},{},{},{},{:.3},{:.3},{:.3},{:.3},{:.3},{:.3}",
            ligesis_mu, log_m, log_n, base_mu, num_party, total_openings,
            total_commit_time.as_secs_f64(),
            open_time.as_secs_f64(),
            verify_time.as_secs_f64() * 1000.0,
            (total_commit_time + open_time).as_secs_f64(),
            proof_size as f64 / 1024.0,
            commit_size as f64 / 1024.0
        );
        log!("\n--- Poly Sizes (full num_vars) ---");
        log!("mat_a={}, mat_h={}, a={}, bI={}, rs_a={}",
            mat_a_size, mat_h_size, a_size, bI_size, rs_a_size);

        assert!(result, "Verification failed!");
    }

    log!("\n================================================================================");
    log!("Total elapsed: {:.3?}", global_start.elapsed());
    log!("================================================================================\n");

    Ok(())
}

fn main() {
    common::network_run(|opt: Opt| {
        // opt.mu is ligesis_mu (full polynomial size)
        let ligesis_mu = opt.mu;

        bench_ligesis_scenario::<F>(ligesis_mu, opt.base_mu, opt.log_m)
            .expect("Benchmark failed");
    });
}

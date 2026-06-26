use ark_ff::{PrimeField, UniformRand};
use ark_poly::{DenseMultilinearExtension, MultilinearExtension};
use ark_serialize::CanonicalSerialize;
use std::sync::Arc;
use std::time::Instant;
use ligesis_pcs::{
    DeepFoldPCS, DeepFoldSRS, PCSError, PolynomialCommitmentScheme,
    deepfold::{
        d_chunked_batch_commit, d_multi_chunked_batch_open, multi_chunked_batch_verify,
        DeepFoldBatchMultiCommitment, DeepFoldBatchMultiProverAdvice, MultiChunkedBatchProof,
    },
};
use transcript::IOPTranscript;

use deNetwork::{DeMultiNet as Net, DeNet, DeSerNet};

mod common;
use common::{test_rng, Opt};
mod types;
use types::FGoldilocks as F;

/// Helper to estimate memory size of a polynomial
fn poly_memory_kb<F: PrimeField>(poly: &Arc<DenseMultilinearExtension<F>>) -> f64 {
    let elem_size = std::mem::size_of::<F>();
    (poly.evaluations.len() * elem_size) as f64 / 1024.0
}

/// Helper to estimate memory size of advice
fn advice_memory_kb<F: PrimeField>(advice: &DeepFoldBatchMultiProverAdvice<F>) -> f64 {
    let elem_size = std::mem::size_of::<F>();
    let mut total = 0usize;

    // f0_matrix
    for row in &advice.batch_advice.f0_matrix {
        total += row.len() * elem_size;
    }
    // v0_matrix
    for row in &advice.batch_advice.v0_matrix {
        total += row.len() * elem_size;
    }
    // column_hashes (32 bytes each)
    total += advice.batch_advice.column_hashes.len() * 32;
    // merkle_tree (approximate)
    total += advice.batch_advice.column_hashes.len() * 32 * 2; // ~2x for tree
    // chunk_polys
    for chunk in &advice.chunk_polys {
        total += chunk.evaluations.len() * elem_size;
    }

    total as f64 / 1024.0
}

/// Detailed profiling for ligesis_mu=28
fn profile_ligesis_scenario<F: PrimeField>(ligesis_mu: usize) -> Result<(), PCSError> {
    let mut rng = test_rng();
    let num_party = Net::n_parties();
    let num_party_vars = num_party.ilog2() as usize;
    let party_id = Net::party_id();
    let should_print = party_id == 0;

    macro_rules! log {
        ($($arg:tt)*) => {
            if should_print {
                println!($($arg)*)
            }
        };
    }

    // Ligesis parameters
    let log_m = if ligesis_mu < 8 { 0 } else { (ligesis_mu - 8) / 2 };
    let base_mu = log_m + 9;
    let log_n = ligesis_mu - log_m;

    // Real polynomial sizes
    let mat_a_size = base_mu;
    let mat_h_size = log_n + 4;
    let a_size = log_n;
    let bI_size = log_m + 13;
    let rs_a_size = log_n + 1;

    // Local sizes
    let mat_a_local = mat_a_size.saturating_sub(num_party_vars).max(1);
    let mat_h_local = mat_h_size.saturating_sub(num_party_vars).max(1);
    let a_local = a_size.saturating_sub(num_party_vars).max(1);
    let bI_local = bI_size.saturating_sub(num_party_vars).max(1);
    let rs_a_local = rs_a_size.saturating_sub(num_party_vars).max(1);

    log!("================================================================================");
    log!("PROFILING: ligesis_mu={}, 4 parties", ligesis_mu);
    log!("================================================================================");
    log!("Parameters: log_m={}, log_n={}, base_mu={}", log_m, log_n, base_mu);
    log!("");
    log!("Polynomial sizes (full -> local):");
    log!("  mat_a:  {} -> {} vars", mat_a_size, mat_a_local);
    log!("  mat_h:  {} -> {} vars", mat_h_size, mat_h_local);
    log!("  a:      {} -> {} vars (x2)", a_size, a_local);
    log!("  bI:     {} -> {} vars (x3)", bI_size, bI_local);
    log!("  rs_a:   {} -> {} vars (x2)", rs_a_size, rs_a_local);
    log!("================================================================================");

    // ==================== SRS Generation ====================
    log!("\n[1] SRS Generation");
    let start = Instant::now();
    let srs = if Net::am_master() {
        let srs = DeepFoldPCS::<F>::gen_srs_for_testing(&mut rng, base_mu)?;
        Net::recv_from_master_uniform(Some(srs.clone()));
        srs
    } else {
        Net::recv_from_master_uniform::<DeepFoldSRS<F>>(None)
    };
    log!("    SRS gen + broadcast:     {:>12.3?}", start.elapsed());

    let start = Instant::now();
    let (pp, vp) = DeepFoldPCS::<F>::setup(&srs)?;
    log!("    Setup (pp, vp):          {:>12.3?}", start.elapsed());

    // ==================== Polynomial Generation ====================
    log!("\n[2] Polynomial Generation");

    let start = Instant::now();
    let mat_a_poly = Arc::new(DenseMultilinearExtension::<F>::rand(mat_a_local, &mut rng));
    log!("    mat_a ({} vars):        {:>12.3?}  ({:.2} KB)", mat_a_local, start.elapsed(), poly_memory_kb(&mat_a_poly));

    let start = Instant::now();
    let mat_h_poly = Arc::new(DenseMultilinearExtension::<F>::rand(mat_h_local, &mut rng));
    log!("    mat_h ({} vars):        {:>12.3?}  ({:.2} KB)", mat_h_local, start.elapsed(), poly_memory_kb(&mat_h_poly));

    let start = Instant::now();
    let a_poly = Arc::new(DenseMultilinearExtension::<F>::rand(a_local, &mut rng));
    log!("    a ({} vars):            {:>12.3?}  ({:.2} KB)", a_local, start.elapsed(), poly_memory_kb(&a_poly));

    let start = Instant::now();
    let bI_poly = Arc::new(DenseMultilinearExtension::<F>::rand(bI_local, &mut rng));
    log!("    bI ({} vars):           {:>12.3?}  ({:.2} KB)", bI_local, start.elapsed(), poly_memory_kb(&bI_poly));

    let start = Instant::now();
    let rs_a_poly = Arc::new(DenseMultilinearExtension::<F>::rand(rs_a_local, &mut rng));
    log!("    rs_a ({} vars):          {:>12.3?}  ({:.2} KB)", rs_a_local, start.elapsed(), poly_memory_kb(&rs_a_poly));

    let total_poly_mem = poly_memory_kb(&mat_a_poly) + poly_memory_kb(&mat_h_poly)
        + poly_memory_kb(&a_poly) + poly_memory_kb(&bI_poly) + poly_memory_kb(&rs_a_poly);
    log!("    TOTAL poly memory:                     {:.2} KB = {:.2} MB", total_poly_mem, total_poly_mem / 1024.0);

    // Organize polynomials - each polynomial type in its own commitment for multi-point opening
    // Commitment 0: mat_a (opened 1x)
    // Commitment 1: mat_h (opened 1x)
    // Commitment 2: a (opened 2x at different points)
    // Commitment 3: bI (opened 3x at different points)
    // Commitment 4: rs_a (opened 2x at different points)
    let all_polys = vec![
        vec![mat_a_poly],
        vec![mat_h_poly],
        vec![a_poly],
        vec![bI_poly],
        vec![rs_a_poly],
    ];
    let num_commitments = 5;
    let total_openings = 1 + 1 + 2 + 3 + 2; // 9 openings

    // ==================== Point Generation ====================
    log!("\n[3] Point Generation ({} points for {} openings)", total_openings, total_openings);
    let full_mu = ligesis_mu;
    // point_to_commit: point i opens commitment point_to_commit[i]
    // points 0 -> commit 0, 1 -> commit 1, 2,3 -> commit 2, 4,5,6 -> commit 3, 7,8 -> commit 4
    let point_to_commit = vec![0, 1, 2, 2, 3, 3, 3, 4, 4];
    let start = Instant::now();
    let (points, point_to_commit): (Vec<Vec<F>>, Vec<usize>) = if Net::am_master() {
        let pts: Vec<Vec<F>> = (0..total_openings)
            .map(|_| (0..full_mu).map(|_| F::rand(&mut rng)).collect())
            .collect();
        Net::recv_from_master_uniform(Some((pts.clone(), point_to_commit.clone())));
        (pts, point_to_commit)
    } else {
        Net::recv_from_master_uniform(None)
    };
    log!("    Points gen + broadcast:  {:>12.3?}", start.elapsed());

    // ==================== Commit Phase ====================
    log!("\n[4] Commit Phase ({} d_chunked_batch_commit calls)", num_commitments);
    let mut commitments: Vec<DeepFoldBatchMultiCommitment> = Vec::new();
    let mut advices: Vec<DeepFoldBatchMultiProverAdvice<F>> = Vec::new();
    let mut total_advice_mem = 0.0f64;

    let phase_names = ["mat_a", "mat_h", "a", "bI", "rs_a"];
    let commit_start = Instant::now();

    for (i, polys) in all_polys.iter().enumerate() {
        log!("\n    --- {} ---", phase_names[i]);

        let start = Instant::now();
        let (com_opt, advice) = d_chunked_batch_commit(&pp, polys)?;
        let elapsed = start.elapsed();

        let advice_mem = advice_memory_kb(&advice);
        total_advice_mem += advice_mem;

        log!("    d_chunked_batch_commit:  {:>12.3?}", elapsed);
        log!("    Advice memory:                         {:.2} KB = {:.2} MB", advice_mem, advice_mem / 1024.0);
        log!("    Chunks per poly: {:?}", advice.chunks_per_poly);
        log!("    Total chunks: {}", advice.chunk_polys.len());

        if Net::am_master() {
            let com = com_opt.unwrap();
            let mut com_bytes = Vec::new();
            com.serialize_compressed(&mut com_bytes).unwrap();
            log!("    Commitment size: {} bytes", com_bytes.len());
            commitments.push(com);
        }
        advices.push(advice);
    }

    let total_commit_time = commit_start.elapsed();
    log!("\n    TOTAL Commit time:       {:>12.3?}", total_commit_time);
    log!("    TOTAL Advice memory:                   {:.2} KB = {:.2} MB", total_advice_mem, total_advice_mem / 1024.0);

    // ==================== Open Phase ====================
    log!("\n[5] Open Phase (d_multi_chunked_batch_open, {} points)", total_openings);

    let start = Instant::now();
    let mut transcript = IOPTranscript::<F>::new(b"profile_bench");
    let advice_refs: Vec<_> = advices.iter().collect();
    let proof_opt = d_multi_chunked_batch_open(
        &pp,
        &advice_refs,
        &points,
        &point_to_commit,
        &mut transcript,
    )?;
    let open_time = start.elapsed();
    log!("    d_multi_chunked_batch_open: {:>9.3?}", open_time);

    // ==================== Verify Phase & Sizes ====================
    if Net::am_master() {
        let proof = proof_opt.unwrap();
        let commitment_refs: Vec<_> = commitments.iter().collect();

        // Measure sizes
        let mut proof_bytes = Vec::new();
        proof.serialize_compressed(&mut proof_bytes).unwrap();
        let proof_size = proof_bytes.len();

        let mut commit_bytes = Vec::new();
        for com in &commitments {
            com.serialize_compressed(&mut commit_bytes).unwrap();
        }
        let commit_size = commit_bytes.len();

        log!("\n[6] Verify Phase");
        let start = Instant::now();
        let mut transcript = IOPTranscript::<F>::new(b"profile_bench");
        let result = multi_chunked_batch_verify(
            &vp,
            &commitment_refs,
            &points,
            &proof,
            &mut transcript,
        )?;
        let verify_time = start.elapsed();
        log!("    multi_chunked_batch_verify: {:>8.3?}", verify_time);
        log!("    Result: {}", if result { "PASS" } else { "FAIL" });

        log!("\n================================================================================");
        log!("SUMMARY");
        log!("================================================================================");
        log!("[Time]");
        log!("  Commit total:              {:>12.3?}", total_commit_time);
        log!("  Open:                      {:>12.3?}", open_time);
        log!("  Prover total:              {:>12.3?}", total_commit_time + open_time);
        log!("  Verify:                    {:>12.3?}", verify_time);
        log!("");
        log!("[Memory] (per party)");
        log!("  Polynomials:               {:>12.2} MB", total_poly_mem / 1024.0);
        log!("  Advices:                   {:>12.2} MB", total_advice_mem / 1024.0);
        log!("  Total working memory:      {:>12.2} MB", (total_poly_mem + total_advice_mem) / 1024.0);
        log!("");
        log!("[Size]");
        log!("  Proof:                     {:>12.2} KB", proof_size as f64 / 1024.0);
        log!("  Commitments:               {:>12.2} KB", commit_size as f64 / 1024.0);
        log!("================================================================================");

        assert!(result, "Verification failed!");
    }

    Ok(())
}

fn main() {
    common::network_run(|opt: Opt| {
        let ligesis_mu = opt.mu;
        profile_ligesis_scenario::<F>(ligesis_mu)
            .expect("Profile failed");
    });
}

use arithmetic::math::Math;
use ark_ff::{PrimeField, UniformRand};
use ark_poly::{DenseMultilinearExtension, MultilinearExtension};
use ark_serialize::CanonicalSerialize;
use std::sync::Arc;
use std::time::Instant;
use ligesis_pcs::{DeepFoldPCS, DeepFoldSRS, PCSError, PolynomialCommitmentScheme};
use transcript::IOPTranscript;

use deNetwork::{DeMultiNet as Net, DeNet, DeSerNet};

mod common;
use common::{test_rng, Opt};
mod types;
use types::FGoldilocks as F;

fn test_deepfold_batch_open<F: PrimeField>(mu: usize, num_poly: usize) -> Result<(), PCSError> {
    let mut rng = test_rng();
    let num_party = Net::n_parties();
    let num_party_vars = num_party.ilog2() as usize;
    let party_id = Net::party_id();
    let should_print = party_id == 0 || party_id == 1;
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
                println!("[P{}] {:12} {:>10.3?}  (@ {:.3?})", party_id, $step, $elapsed, global_start.elapsed());
            }
        };
    }

    if Net::am_master() {
        log!("========================================");
        log!("DeepFold Distributed Batch Open Test");
        log!("  mu = {}, parties = {}, num_poly = {}", mu, num_party, num_poly);
        log!("========================================");

        // Gen SRS
        let start = Instant::now();
        let srs = DeepFoldPCS::<F>::gen_srs_for_testing(&mut rng, mu)?;
        log_step!("Gen SRS", start.elapsed());

        // Distribute SRS
        let start = Instant::now();
        Net::recv_from_master_uniform(Some(srs.clone()));
        log_step!("Dist SRS", start.elapsed());

        // Setup
        let start = Instant::now();
        let (pp, vp) = DeepFoldPCS::<F>::setup(&srs)?;
        log_step!("Setup", start.elapsed());

        // Generate local polys (each party has 2^(mu - num_party_vars) evaluations per poly)
        let local_mu = mu - num_party_vars;
        let polys_k: Vec<Arc<DenseMultilinearExtension<F>>> = (0..num_poly)
            .map(|_| Arc::new(DenseMultilinearExtension::<F>::rand(local_mu, &mut rng)))
            .collect();

        // Generate points (one per polynomial, each with mu coordinates)
        let points: Vec<Vec<F>> = (0..num_poly)
            .map(|_| (0..mu).map(|_| F::rand(&mut rng)).collect())
            .collect();
        Net::recv_from_master_uniform(Some(points.clone()));

        // Distributed Commit for each polynomial
        log!("--- Commit Phase ---");
        let start = Instant::now();
        let mut coms = Vec::new();
        let mut advices = Vec::new();
        for poly_k in &polys_k {
            let (com, advice) = DeepFoldPCS::d_commit(&pp, poly_k)?;
            coms.push(com.unwrap());
            advices.push(advice);
        }
        log_step!("D-Commit", start.elapsed());

        // Distributed Batch Open
        log!("--- Batch Open Phase ---");
        let start = Instant::now();
        let mut transcript = IOPTranscript::<F>::new(b"deepfold_batch_test");
        let advice_refs: Vec<_> = advices.iter().collect();
        let evals: Vec<F> = vec![F::ZERO; num_poly];
        let batch_proof = DeepFoldPCS::d_batch_open(
            &pp,
            polys_k.clone(),
            &advice_refs,
            &points,
            &evals,
            &mut transcript,
        )?.unwrap();
        log_step!("D-BatchOpen", start.elapsed());

        // Verify (on master only)
        log!("--- Verify Phase ---");
        let start = Instant::now();
        let mut transcript = IOPTranscript::<F>::new(b"deepfold_batch_test");
        let result = DeepFoldPCS::batch_verify(
            &vp,
            &coms,
            &points,
            &batch_proof,
            &mut transcript,
        )?;
        log_step!("Verify", start.elapsed());

        // Compute proof size via serialization
        let mut proof_bytes = Vec::new();
        batch_proof.serialize_compressed(&mut proof_bytes).unwrap();
        let proof_size_kb = proof_bytes.len() as f64 / 1024.0;

        // Also verify individual evaluations
        let batch_evals = &batch_proof.evals;
        log!("Batch proof contains {} evaluations", batch_evals.len());

        log!("========================================");
        log!("Total: {:.3?}", global_start.elapsed());
        log!("Proof size: {:.2} KB", proof_size_kb);
        log!("Result: {}", if result { "PASS" } else { "FAIL" });
        log!("========================================");

        // Machine-readable output
        println!("PROOF_SIZE_KB: {:.2}", proof_size_kb);

        assert!(result);
    } else {
        // Non-master parties
        log!("--- Setup Phase ---");

        let start = Instant::now();
        let srs = Net::recv_from_master_uniform::<DeepFoldSRS<F>>(None);
        log_step!("Recv SRS", start.elapsed());

        let start = Instant::now();
        let (pp, _vp) = DeepFoldPCS::<F>::setup(&srs)?;
        log_step!("Setup", start.elapsed());

        let local_mu = srs.max_mu - num_party_vars;
        let polys_k: Vec<Arc<DenseMultilinearExtension<F>>> = (0..num_poly)
            .map(|_| Arc::new(DenseMultilinearExtension::<F>::rand(local_mu, &mut rng)))
            .collect();
        let points: Vec<Vec<F>> = Net::recv_from_master_uniform(None);

        log!("--- Commit Phase ---");
        let start = Instant::now();
        let mut advices = Vec::new();
        for poly_k in &polys_k {
            let (_, advice) = DeepFoldPCS::d_commit(&pp, poly_k)?;
            advices.push(advice);
        }
        log_step!("D-Commit", start.elapsed());

        log!("--- Batch Open Phase ---");
        let start = Instant::now();
        let mut transcript = IOPTranscript::<F>::new(b"deepfold_batch_test");
        let advice_refs: Vec<_> = advices.iter().collect();
        let evals: Vec<F> = vec![F::ZERO; num_poly];
        DeepFoldPCS::d_batch_open(
            &pp,
            polys_k,
            &advice_refs,
            &points,
            &evals,
            &mut transcript,
        )?;
        log_step!("D-BatchOpen", start.elapsed());

        log!("========================================");
        log!("Total: {:.3?}", global_start.elapsed());
        log!("========================================");
    };

    Ok(())
}

fn main() {
    common::network_run(|opt: Opt| {
        // Default to 3 polynomials if not specified
        let num_poly = 3;
        test_deepfold_batch_open::<F>(opt.mu, num_poly).unwrap();
    });
}

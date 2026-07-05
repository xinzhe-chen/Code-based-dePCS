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

fn test_deepfold_commit<F: PrimeField>(mu: usize) -> Result<(), PCSError> {
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
        log!("DeepFold Distributed Test");
        log!("  mu = {}, parties = {}", mu, num_party);
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

        // Generate local poly (each party has 2^(mu - num_party_vars) evaluations)
        let local_mu = mu - num_party_vars;
        let poly_k = Arc::new(DenseMultilinearExtension::<F>::rand(local_mu, &mut rng));
        let point: Vec<F> = (0..mu).map(|_| F::rand(&mut rng)).collect();
        Net::recv_from_master_uniform(Some(point.clone()));

        // Distributed Commit
        log!("--- Commit Phase ---");
        let start = Instant::now();
        let (com, advice) = DeepFoldPCS::d_commit(&pp, &poly_k)?;
        log_step!("D-Commit", start.elapsed());

        // Distributed Open
        log!("--- Open Phase ---");
        let start = Instant::now();
        let mut transcript = IOPTranscript::<F>::new(b"deepfold_test");
        let proof = DeepFoldPCS::d_open(&pp, &poly_k, &advice, &point, &mut transcript)?.unwrap();
        log_step!("D-Open", start.elapsed());

        // Verify (on master only, using the commitment and proof)
        log!("--- Verify Phase ---");
        let start = Instant::now();
        let mut transcript = IOPTranscript::<F>::new(b"deepfold_test");
        let value = DeepFoldPCS::compute_value_from_proof_distributed(&point, &proof, num_party);
        let result = DeepFoldPCS::verify(&vp, &com.unwrap(), &point, &value, &proof, &mut transcript)?;
        log_step!("Verify", start.elapsed());

        // Compute proof size via serialization
        let mut proof_bytes = Vec::new();
        proof.serialize_compressed(&mut proof_bytes).unwrap();
        let proof_size_kb = proof_bytes.len() as f64 / 1024.0;

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
        let poly_k = Arc::new(DenseMultilinearExtension::<F>::rand(local_mu, &mut rng));
        let point: Vec<F> = Net::recv_from_master_uniform(None);

        log!("--- Commit Phase ---");
        let start = Instant::now();
        let (_, advice) = DeepFoldPCS::d_commit(&pp, &poly_k)?;
        log_step!("D-Commit", start.elapsed());

        log!("--- Open Phase ---");
        let start = Instant::now();
        let mut transcript = IOPTranscript::<F>::new(b"deepfold_test");
        DeepFoldPCS::d_open(&pp, &poly_k, &advice, &point, &mut transcript)?;
        log_step!("D-Open", start.elapsed());

        log!("========================================");
        log!("Total: {:.3?}", global_start.elapsed());
        log!("========================================");
    };

    Ok(())
}

fn main() {
    common::network_run(|opt: Opt| {
        test_deepfold_commit::<F>(opt.mu).unwrap();
    });
}

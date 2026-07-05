//! Distributed FRIttata (Fold-and-Batch) Benchmark
//!
//! This implements the FRIttata protocol in a truly distributed setting using deNetwork.
//!
//! Protocol phases:
//! 1. Worker Commit: Each party generates local polynomial and runs FRI commit (build_layers)
//! 2. Master Commit: Master collects all commitments, computes batched commitment, generates query positions
//! 3. Worker Query: Each party generates FRI proof and queried evaluations
//! 4. Master Query: Master collects all proofs and assembles final FoldAndBatchProof
//!
//! Usage:
//!   cd ligesis-pcs/dTests
//!   python3 run.py dFrittata -n 4 -m 20

use std::time::Instant;

use deNetwork::{DeMultiNet as Net, DeNet};

use winter_crypto::{hashers::Blake3_256, DefaultRandomCoin, MerkleTree, RandomCoin};
use winter_fri::{
    fold_and_batch_master_commit, fold_and_batch_master_query, DefaultProverChannel,
    DefaultVerifierChannel, FoldAndBatchProof, FoldAndBatchVerifier, FoldingOptions, FoldingProof,
    FoldingProver, FriOptions, FriProver,
};
use winter_math::{
    fft,
    fields::f128::BaseElement,
    FieldElement, StarkField,
};
use winter_rand_utils::rand_vector;
use winter_utils::{ByteReader, ByteWriter, Deserializable, Serializable, SliceReader};

mod common;
use common::Opt;

// Type aliases
type Blake3 = Blake3_256<BaseElement>;
type E = winter_math::fields::QuadExtension<BaseElement>;

// Protocol parameters
const BLOWUP_FACTOR: usize = 4;
const FOLDING_FACTOR: usize = 2;
const MASTER_MAX_REMAINDER_DEGREE: usize = 0;

// ================================================================================================
// SERIALIZATION HELPERS
// ================================================================================================

/// Serialize worker commit data: layer_commitments (Vec<Digest>) and last_eval (Vec<E>)
fn serialize_worker_commit_data(
    commitments: &[<Blake3 as winter_crypto::Hasher>::Digest],
    last_eval: &[E],
) -> Vec<u8> {
    let mut bytes = Vec::new();

    // Write number of commitments
    bytes.write_u8(commitments.len() as u8);
    // Write each commitment (32 bytes each for Blake3)
    for c in commitments {
        c.write_into(&mut bytes);
    }

    // Write number of evaluations
    bytes.write_u32(last_eval.len() as u32);
    // Write each evaluation
    for e in last_eval {
        e.write_into(&mut bytes);
    }

    bytes
}

/// Deserialize worker commit data
fn deserialize_worker_commit_data(
    bytes: &[u8],
) -> (<Blake3 as winter_crypto::Hasher>::Digest, Vec<E>) {
    let mut reader = SliceReader::new(bytes);

    // Read commitments - but we only need the last one for batching
    let num_commitments = reader.read_u8().unwrap() as usize;
    let commitments: Vec<<Blake3 as winter_crypto::Hasher>::Digest> =
        reader.read_many(num_commitments).unwrap();

    // Read evaluations
    let num_evals = reader.read_u32().unwrap() as usize;
    let evals: Vec<E> = reader.read_many(num_evals).unwrap();

    // Return only the last commitment (for batching) and all evals
    (commitments.last().cloned().unwrap(), evals)
}

/// Serialize all layer commitments for a worker
fn serialize_all_layer_commitments(
    commitments: &[<Blake3 as winter_crypto::Hasher>::Digest],
) -> Vec<u8> {
    let mut bytes = Vec::new();
    bytes.write_u8(commitments.len() as u8);
    for c in commitments {
        c.write_into(&mut bytes);
    }
    bytes
}

/// Deserialize all layer commitments
fn deserialize_all_layer_commitments(
    bytes: &[u8],
) -> Vec<<Blake3 as winter_crypto::Hasher>::Digest> {
    let mut reader = SliceReader::new(bytes);
    let num = reader.read_u8().unwrap() as usize;
    reader.read_many(num).unwrap()
}

/// Serialize query positions as Vec<u64>
fn serialize_positions(positions: &[usize]) -> Vec<u8> {
    let mut bytes = Vec::new();
    bytes.write_u32(positions.len() as u32);
    for &p in positions {
        bytes.write_u64(p as u64);
    }
    bytes
}

/// Deserialize query positions
fn deserialize_positions(bytes: &[u8]) -> Vec<usize> {
    let mut reader = SliceReader::new(bytes);
    let len = reader.read_u32().unwrap() as usize;
    let mut positions = Vec::with_capacity(len);
    for _ in 0..len {
        positions.push(reader.read_u64().unwrap() as usize);
    }
    positions
}

/// Serialize worker query data: FoldingProof + queried_evals
fn serialize_worker_query_data(proof: &FoldingProof, evals: &[E]) -> Vec<u8> {
    let mut bytes = Vec::new();

    // Serialize FoldingProof
    proof.write_into(&mut bytes);

    // Serialize evaluations
    bytes.write_u32(evals.len() as u32);
    for e in evals {
        e.write_into(&mut bytes);
    }

    bytes
}

/// Deserialize worker query data
fn deserialize_worker_query_data(bytes: &[u8]) -> (FoldingProof, Vec<E>) {
    let mut reader = SliceReader::new(bytes);

    let proof = FoldingProof::read_from(&mut reader).unwrap();

    let num_evals = reader.read_u32().unwrap() as usize;
    let evals: Vec<E> = reader.read_many(num_evals).unwrap();

    (proof, evals)
}

// ================================================================================================
// POLYNOMIAL GENERATION
// ================================================================================================

fn build_evaluations_from_random_poly(degree_bound: usize, lde_blowup: usize) -> Vec<E> {
    let mut p = rand_vector::<E>(degree_bound);
    let domain_size = degree_bound * lde_blowup;
    p.resize(domain_size, E::ZERO);
    let twiddles = fft::get_twiddles::<BaseElement>(domain_size);
    fft::evaluate_poly(&mut p, &twiddles);
    p
}

// ================================================================================================
// DISTRIBUTED FRITTATA PROTOCOL
// ================================================================================================

fn distributed_frittata(mu: usize, iterations: usize, num_queries: usize) {
    let num_parties = Net::n_parties();
    let num_poly_e = (num_parties as f64).log2() as usize;
    let party_id = Net::party_id();
    let should_print = party_id == 0;

    macro_rules! log {
        ($($arg:tt)*) => {
            if should_print {
                print!("[P{}] ", party_id);
                println!($($arg)*);
            }
        };
    }

    // Validate parameters
    if mu <= num_poly_e + 2 {
        if should_print {
            eprintln!(
                "Error: mu ({}) must be > num_poly_e + 2 ({})",
                mu,
                num_poly_e + 2
            );
        }
        return;
    }
    if num_queries == 0 {
        if should_print {
            eprintln!("Error: queries must be positive");
        }
        return;
    }

    // Compute protocol parameters
    let worker_degree_bound: usize = 1 << (mu - num_poly_e);
    let worker_domain_size = worker_degree_bound * BLOWUP_FACTOR;
    let worker_last_poly_max_degree = worker_degree_bound / 4 - 1; // Fold-and-Batch parameter
    let master_degree_bound: usize = worker_last_poly_max_degree + 1;
    let master_domain_size = master_degree_bound.next_power_of_two() * BLOWUP_FACTOR;
    let master_options = FriOptions::new(BLOWUP_FACTOR, FOLDING_FACTOR, MASTER_MAX_REMAINDER_DEGREE);
    let worker_options = FoldingOptions::new(
        BLOWUP_FACTOR,
        FOLDING_FACTOR,
        worker_domain_size,
        worker_last_poly_max_degree,
    );

    log!("========================================");
    log!("Distributed FRIttata (Fold-and-Batch)");
    log!("  mu = {}, parties = {}, num_poly_e = {}", mu, num_parties, num_poly_e);
    log!("  worker_degree_bound = {}", worker_degree_bound);
    log!("  worker_domain_size = {}", worker_domain_size);
    log!("  master_domain_size = {}", master_domain_size);
    log!("  queries = {}", num_queries);
    log!("  iterations = {}", iterations);
    log!("========================================");

    // Collect per-iteration times for statistics
    let mut all_commit_times: Vec<f64> = Vec::with_capacity(iterations);
    let mut all_open_times: Vec<f64> = Vec::with_capacity(iterations);
    let mut all_verify_times: Vec<f64> = Vec::with_capacity(iterations);
    let mut last_comm_bytes: usize = 0;
    let mut last_proof_size_kb: f64 = 0.0;

    for iter in 0..iterations {
        if iterations > 1 {
            log!("--- Iteration {} ---", iter + 1);
        }

        Net::reset_stats();
        let global_start = Instant::now();

        // ==================== Phase 0: Setup ====================
        log!("Generating random polynomial...");
        let setup_start = Instant::now();
        let input = build_evaluations_from_random_poly(worker_degree_bound, BLOWUP_FACTOR);
        log!("Setup: {:?}", setup_start.elapsed());

        // ==================== Phase 1: Worker Commit ====================
        log!("--- Phase 1: Worker Commit ---");
        let commit_start = Instant::now();  // Start timing commit phase
        let phase1_start = Instant::now();

        let mut worker_prover = FoldingProver::<
            E,
            DefaultProverChannel<E, Blake3, DefaultRandomCoin<_>>,
            Blake3,
            MerkleTree<_>,
        >::new(worker_options.clone());
        let mut worker_channel = DefaultProverChannel::new(worker_domain_size, num_queries);

        let last_eval = worker_prover.build_layers(&mut worker_channel, input.clone());
        let layer_commitments = worker_channel.layer_commitments().to_vec();

        log!("Phase 1 (local): {:?}", phase1_start.elapsed());

        // Send commit data to master (combine layer commitments and last_eval into one message)
        let commit_data = serialize_worker_commit_data(&layer_commitments, &last_eval);

        let phase1_comm_start = Instant::now();
        let gathered_commit_data = Net::send_bytes_to_master(commit_data);

        log!("Phase 1 (comm): {:?}", phase1_comm_start.elapsed());

        // ==================== Phase 2: Master Commit ====================
        log!("--- Phase 2: Master Commit ---");
        let phase2_start = Instant::now();

        // Master state that needs to persist to Phase 4
        struct MasterState {
            batched_evaluations: Vec<E>,
            all_worker_layer_commitments: Vec<Vec<<Blake3 as winter_crypto::Hasher>::Digest>>,
            master_prover: FriProver<E, DefaultProverChannel<E, Blake3, DefaultRandomCoin<Blake3>>, Blake3, MerkleTree<Blake3>>,
            master_prover_channel: DefaultProverChannel<E, Blake3, DefaultRandomCoin<Blake3>>,
        }

        let (query_positions, master_state) = if Net::am_master() {
            let gathered_commit_data = gathered_commit_data.unwrap();

            // Deserialize all worker data
            let mut batched_fri_inputs: Vec<Vec<E>> = Vec::with_capacity(num_parties);
            let mut all_worker_layer_commitments: Vec<Vec<<Blake3 as winter_crypto::Hasher>::Digest>> =
                Vec::with_capacity(num_parties);

            for bytes in &gathered_commit_data {
                let mut reader = SliceReader::new(bytes);

                // Read all layer commitments
                let num_commitments = reader.read_u8().unwrap() as usize;
                let commitments: Vec<<Blake3 as winter_crypto::Hasher>::Digest> =
                    reader.read_many(num_commitments).unwrap();
                all_worker_layer_commitments.push(commitments);

                // Read evaluations
                let num_evals = reader.read_u32().unwrap() as usize;
                let evals: Vec<E> = reader.read_many(num_evals).unwrap();
                batched_fri_inputs.push(evals);
            }

            // Create master prover
            let mut master_prover = FriProver::<
                E,
                DefaultProverChannel<E, Blake3, DefaultRandomCoin<_>>,
                Blake3,
                MerkleTree<_>,
            >::new(master_options.clone());
            let mut master_prover_channel = DefaultProverChannel::new(master_domain_size, num_queries);

            // Execute master commit phase
            let (batched_evaluations, query_positions) = fold_and_batch_master_commit(
                &mut master_prover,
                &mut master_prover_channel,
                &all_worker_layer_commitments,
                batched_fri_inputs,
                num_queries,
                worker_domain_size,
            );

            log!("Phase 2 (master): {:?}", phase2_start.elapsed());

            // Broadcast query positions
            let pos_bytes = serialize_positions(&query_positions);
            Net::recv_bytes_from_master_uniform(Some(pos_bytes));

            let state = MasterState {
                batched_evaluations,
                all_worker_layer_commitments,
                master_prover,
                master_prover_channel,
            };

            (query_positions, Some(state))
        } else {
            // Worker: receive query positions
            let pos_bytes = Net::recv_bytes_from_master_uniform(None);
            (deserialize_positions(&pos_bytes), None)
        };

        log!("Phase 2 (total): {:?}", phase2_start.elapsed());
        let commit_time = commit_start.elapsed();  // End of commit phase

        // ==================== Phase 3: Worker Query ====================
        log!("--- Phase 3: Worker Query ---");
        let open_start = Instant::now();  // Start timing open phase
        let phase3_start = Instant::now();

        let (folding_proof, queried_evals) = worker_prover.build_proof(&input, &query_positions);

        log!("Phase 3 (local): {:?}", phase3_start.elapsed());

        // Send query data to master
        let query_data = serialize_worker_query_data(&folding_proof, &queried_evals);

        let phase3_comm_start = Instant::now();
        let gathered_query_data = Net::send_bytes_to_master(query_data);

        log!("Phase 3 (comm): {:?}", phase3_comm_start.elapsed());

        // ==================== Phase 4: Master Query & Verify ====================
        if Net::am_master() {
            log!("--- Phase 4: Master Query & Verify ---");
            let phase4_start = Instant::now();

            let gathered_query_data = gathered_query_data.unwrap();
            let mut master_state = master_state.unwrap();

            // Deserialize query data
            let mut folding_proofs: Vec<FoldingProof> = Vec::with_capacity(num_parties);
            let mut worker_evaluations: Vec<Vec<E>> = Vec::with_capacity(num_parties);

            for bytes in &gathered_query_data {
                let (proof, evals) = deserialize_worker_query_data(bytes);
                folding_proofs.push(proof);
                worker_evaluations.push(evals);
            }

            // Execute master query phase
            let proof: FoldAndBatchProof<E, Blake3> = fold_and_batch_master_query(
                &mut master_state.master_prover,
                &master_state.master_prover_channel,
                worker_domain_size,
                master_domain_size,
                master_state.all_worker_layer_commitments,
                query_positions.clone(),
                folding_proofs,
                worker_evaluations,
                master_state.batched_evaluations,
            );

            let prover_time = global_start.elapsed();
            let open_time = open_start.elapsed();  // End of open phase
            log!("Phase 4 (master query): {:?}", phase4_start.elapsed());
            log!("Total prover time: {:?}", prover_time);

            // ==================== Verify ====================
            log!("--- Verification ---");
            let verify_start = Instant::now();

            let public_coin = DefaultRandomCoin::<Blake3>::new(&[]);
            let mut verifier = FoldAndBatchVerifier::<
                E,
                DefaultVerifierChannel<E, _, MerkleTree<Blake3>>,
                _,
                DefaultRandomCoin<_>,
                _,
            >::new(
                public_coin,
                num_queries,
                master_options.clone(),
                worker_degree_bound,
                master_degree_bound,
            )
            .unwrap();

            let result = verifier.verify_fold_and_batch(&proof);
            let verify_time = verify_start.elapsed();

            log!("Verify time: {:?}", verify_time);

            // Get communication stats
            let stats = Net::stats();
            let comm_bytes = stats.bytes_sent + stats.bytes_recv;

            // Compute proof size via actual serialization (more accurate than .size() method)
            let mut proof_bytes = Vec::new();
            proof.write_into(&mut proof_bytes);
            let proof_size_bytes = proof_bytes.len();
            let proof_size_kb = proof_size_bytes as f64 / 1024.0;

            log!("========================================");
            log!("Results:");
            log!("  Prover: {:?}", prover_time);
            log!("  Verify: {:?}", verify_time);
            log!("  Total: {:?}", prover_time + verify_time);
            log!("  Proof size: {:.2} KB ({} bytes)", proof_size_kb, proof_size_bytes);
            log!("  Communication: {} bytes ({:.2} KB)", comm_bytes, comm_bytes as f64 / 1024.0);
            log!("  Result: {}", if result.is_ok() { "PASS" } else { "FAIL" });
            log!("========================================");

            // Collect times for statistics
            let commit_ms = commit_time.as_secs_f64() * 1000.0;
            let open_ms = open_time.as_secs_f64() * 1000.0;
            let verify_ms = verify_time.as_secs_f64() * 1000.0;
            all_commit_times.push(commit_ms);
            all_open_times.push(open_ms);
            all_verify_times.push(verify_ms);
            last_comm_bytes = comm_bytes;
            last_proof_size_kb = proof_size_kb;

            // Output per-iteration machine-readable times (1-indexed)
            println!("ITER_{}_COMMIT_MS: {:.3}", iter + 1, commit_ms);
            println!("ITER_{}_OPEN_MS: {:.3}", iter + 1, open_ms);
            println!("ITER_{}_VERIFY_MS: {:.3}", iter + 1, verify_ms);

            assert!(result.is_ok(), "Verification failed: {:?}", result);
        }
    }

    // Output final statistics (only master outputs)
    if Net::am_master() && !all_commit_times.is_empty() {
        let avg_commit: f64 = all_commit_times.iter().sum::<f64>() / all_commit_times.len() as f64;
        let avg_open: f64 = all_open_times.iter().sum::<f64>() / all_open_times.len() as f64;
        let avg_verify: f64 = all_verify_times.iter().sum::<f64>() / all_verify_times.len() as f64;
        let comm_mb = last_comm_bytes as f64 / (1024.0 * 1024.0);

        println!("\n--- MACHINE READABLE ---");
        println!("COMMIT_TIME_MS: {:.3}", avg_commit);
        println!("OPEN_TIME_MS: {:.3}", avg_open);
        println!("PROVER_TIME_MS: {:.3}", avg_commit + avg_open);
        println!("VERIFY_TIME_MS: {:.3}", avg_verify);
        println!("TOTAL_TIME_MS: {:.3}", avg_commit + avg_open + avg_verify);
        println!("PROOF_SIZE_KB: {:.3}", last_proof_size_kb);
        println!("COMM_TOTAL_BYTES: {}", last_comm_bytes);
        println!("COMM_TOTAL_MB: {:.3}", comm_mb);
        println!("QUERY_COUNT: {}", num_queries);
        println!("--- END MACHINE READABLE ---");
    }
}

fn main() {
    common::network_run(|opt: Opt| {
        distributed_frittata(opt.mu, opt.iterations, opt.queries);
    });
}

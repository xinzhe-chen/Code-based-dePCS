use ark_std::rand::Rng;
use std::time::Instant;
use ligesis_pcs::hash::{Byte32, MerkleTree};

use deNetwork::{DeMultiNet as Net, DeNet, DeSerNet};

mod common;
use common::{test_rng, Opt};

fn random_byte32(rng: &mut impl Rng) -> Byte32 {
    let mut array = [0u8; 32];
    rng.fill(&mut array);
    array
}

fn test_distributed_merkle(log_local_leaves: usize) {
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

    let local_leaves_count = 1usize << log_local_leaves;
    let total_leaves = local_leaves_count * num_party;
    let total_log = log_local_leaves + num_party_vars;

    log!("========================================");
    log!("Distributed Merkle Tree Test");
    log!("  local_leaves = 2^{} = {}", log_local_leaves, local_leaves_count);
    log!("  parties = {}", num_party);
    log!("  total_leaves = 2^{} = {}", total_log, total_leaves);
    log!("========================================");

    // Each party generates local leaves
    let start = Instant::now();
    let local_leaves: Vec<Byte32> = (0..local_leaves_count)
        .map(|_| random_byte32(&mut rng))
        .collect();
    log_step!("Gen local leaves", start.elapsed());

    // Distributed Merkle tree construction
    log!("--- Build Phase ---");
    let start = Instant::now();
    let (full_tree_opt, local_tree) = MerkleTree::d_new(&local_leaves);
    log_step!("D-New", start.elapsed());

    // Also build upper tree on master for d_prove
    let upper_tree = if Net::am_master() {
        // Gather all local roots again to build upper tree
        // (In practice, d_new already does this, but we need the upper tree separately)
        let local_root = local_tree.root();
        let all_roots: Vec<Byte32> = Net::send_to_master(&local_root).unwrap();
        Some(MerkleTree::new(&all_roots))
    } else {
        let local_root = local_tree.root();
        Net::send_to_master(&local_root);
        None
    };

    // Test distributed prove for multiple random positions
    log!("--- Prove Phase ---");
    let num_prove_tests = 10;
    for test_idx in 0..num_prove_tests {
        // Master generates random position and broadcasts
        let global_pos: usize = if Net::am_master() {
            let pos = rng.gen_range(0..total_leaves);
            Net::recv_from_master_uniform(Some(pos))
        } else {
            Net::recv_from_master_uniform(None)
        };

        let start = Instant::now();
        let proof_opt = MerkleTree::d_prove(global_pos, &local_tree, upper_tree.as_ref());

        if Net::am_master() {
            let elapsed = start.elapsed();
            let proof = proof_opt.unwrap();
            let full_tree = full_tree_opt.as_ref().unwrap();

            // Verify the proof
            // We need the leaf value at global_pos
            // Since leaves are distributed, we need to get it from the owner party
            let owner_party = global_pos / local_leaves_count;
            let local_pos = global_pos % local_leaves_count;

            // For testing, we gather all leaves to master (not efficient, just for verification)
            let all_leaves: Vec<Vec<Byte32>> = Net::send_to_master(&local_leaves).unwrap();
            let leaf_value = all_leaves[owner_party][local_pos];

            let result = MerkleTree::verify(&full_tree.root(), global_pos, &leaf_value, &proof);

            if test_idx == 0 {
                log_step!("D-Prove (first)", elapsed);
            }

            if !result {
                log!("FAIL: test {} at pos {}", test_idx, global_pos);
                panic!("Verification failed!");
            }
        } else {
            // Workers also need to participate in gathering leaves for verification
            Net::send_to_master(&local_leaves);
        }
    }

    log!("========================================");
    log!("Total: {:.3?}", global_start.elapsed());
    log!("Result: PASS ({} proofs verified)", num_prove_tests);
    log!("========================================");
}

fn main() {
    common::network_run(|opt: Opt| {
        let log_local_leaves = opt.mu.saturating_sub(Net::n_parties().ilog2() as usize);
        let log_local_leaves = log_local_leaves.max(4); // At least 16 leaves per party
        test_distributed_merkle(log_local_leaves);
    });
}

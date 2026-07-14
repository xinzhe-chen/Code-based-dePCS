//! Network bandwidth benchmark

mod common;

use common::Opt;
use deNetwork::{DeMultiNet as Net, DeNet, DeSerNet};
use ark_std::{end_timer, start_timer};
use ligesis_pcs::FGoldilocks as F;

fn main() {
    common::network_run(run);
}

fn run(_opt: Opt) {
    let num_party = Net::n_parties();
    let party_id = Net::party_id();

    println!("[P{}] Network bandwidth test started ({} parties)", party_id, num_party);

    // Test different data sizes
    let sizes = vec![
        (1 << 20, "8MB"),      // 1M elements * 8 bytes = 8MB
        (1 << 22, "32MB"),     // 4M elements * 8 bytes = 32MB
        (1 << 24, "128MB"),    // 16M elements * 8 bytes = 128MB
    ];

    for (num_elements, size_str) in sizes {
        // Create test data
        let data: Vec<F> = (0..num_elements).map(|i| F::from(i as u64)).collect();
        let data_bytes = num_elements * 8;

        // Warm up
        let _ = Net::send_to_master(&data);

        // Small sync barrier
        Net::recv_from_master_uniform::<u8>(if Net::am_master() { Some(0u8) } else { None });

        // Benchmark gather (send_to_master)
        let timer = start_timer!(|| format!("Gather {} ({}B per party)", size_str, data_bytes));
        let result = Net::send_to_master(&data);
        end_timer!(timer);

        if Net::am_master() {
            let received = result.unwrap();
            let total_bytes: usize = received.iter().map(|v| v.len() * 8).sum();
            let bandwidth_mbps = (total_bytes as f64) / 1_000_000.0;
            println!("[P{}] Gathered {:.1} MB from {} parties", party_id, bandwidth_mbps, num_party);
        }

        // Benchmark broadcast (recv_from_master_uniform)
        let timer = start_timer!(|| format!("Broadcast {} ({}B to each party)", size_str, data_bytes));
        if Net::am_master() {
            Net::recv_from_master_uniform(Some(data.clone()));
        } else {
            let _: Vec<F> = Net::recv_from_master_uniform(None);
        }
        end_timer!(timer);

        // Benchmark scatter (recv_from_master with different data per party)
        let portion_size = num_elements / num_party;
        let timer = start_timer!(|| format!("Scatter {} ({}B to each party)", size_str, portion_size * 8));
        if Net::am_master() {
            let portions: Vec<Vec<F>> = (0..num_party)
                .map(|k| data[k * portion_size..(k + 1) * portion_size].to_vec())
                .collect();
            Net::recv_from_master(Some(portions));
        } else {
            let _: Vec<F> = Net::recv_from_master(None);
        }
        end_timer!(timer);

        println!("[P{}] --- {} test done ---", party_id, size_str);
    }

    // Summary
    if Net::am_master() {
        println!("\n[P0] ========================================");
        println!("[P0] Expected: 1 Gbps = 125 MB/s");
        println!("[P0] For 128 MB gather from 4 parties:");
        println!("[P0]   - Ideal time (sequential): ~4s");
        println!("[P0]   - Ideal time (parallel): ~1s");
        println!("[P0] ========================================");
    }
}

//! Deterministic, domain-separated DeepFold random-oracle expansion.

use std::collections::HashSet;

use paper_util::{algebra::field::MyField, random_oracle::RandomOracle};

use crate::hash::sha256;

use super::types::PaperField;

fn block(seed: [u8; 32], label: &[u8], index: usize) -> [u8; 32] {
    let mut bytes = Vec::with_capacity(64 + label.len());
    bytes.extend_from_slice(b"pq-dpcs/protocol11/deepfold-oracle/v1");
    bytes.extend_from_slice(&seed);
    bytes.extend_from_slice(&(label.len() as u64).to_le_bytes());
    bytes.extend_from_slice(label);
    bytes.extend_from_slice(&(index as u64).to_le_bytes());
    sha256(&bytes)
}

fn field(seed: [u8; 32], label: &[u8], index: usize) -> PaperField {
    PaperField::from_hash(block(seed, label, index))
}

pub(crate) fn oracle_from_seed(
    seed: [u8; 32],
    total_round: usize,
    query_num: usize,
) -> RandomOracle<PaperField> {
    let query_domain = 1usize << total_round;
    assert!(
        query_num <= query_domain,
        "DeepFold query count exceeds leaf domain"
    );
    let mut seen = HashSet::with_capacity(query_num);
    let mut query_list = Vec::with_capacity(query_num);
    let mut counter = 0usize;
    while query_list.len() < query_num {
        let digest = block(seed, b"query", counter);
        counter += 1;
        let candidate = (u64::from_le_bytes(digest[..8].try_into().expect("eight bytes")) as usize)
            & (query_domain - 1);
        if seen.insert(candidate) {
            query_list.push(candidate);
        }
    }
    RandomOracle {
        beta: field(seed, b"beta", 0),
        rlc: field(seed, b"rlc", 0),
        folding_challenges: (0..total_round)
            .map(|index| field(seed, b"folding", index))
            .collect(),
        deep: (0..total_round)
            .map(|index| field(seed, b"deep", index))
            .collect(),
        alpha: (0..total_round)
            .map(|index| field(seed, b"alpha", index))
            .collect(),
        query_list,
    }
}

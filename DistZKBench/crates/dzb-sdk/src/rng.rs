use sha2::{Digest, Sha256};

pub fn deterministic_seed(
    global_seed: u64,
    run_id: &str,
    rank: usize,
    repetition: usize,
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(global_seed.to_le_bytes());
    hasher.update(run_id.as_bytes());
    hasher.update((rank as u64).to_le_bytes());
    hasher.update((repetition as u64).to_le_bytes());
    hasher.finalize().into()
}

pub fn deterministic_bytes(seed: [u8; 32], len: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(len);
    let mut counter = 0_u64;
    while out.len() < len {
        let mut hasher = Sha256::new();
        hasher.update(seed);
        hasher.update(counter.to_le_bytes());
        out.extend_from_slice(&hasher.finalize());
        counter += 1;
    }
    out.truncate(len);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deterministic_output_is_stable() {
        let seed = deterministic_seed(1, "run", 2, 3);
        assert_eq!(deterministic_bytes(seed, 17), deterministic_bytes(seed, 17));
    }
}

//! Fiat-Shamir transcript utilities for the pq_dSNARK prototype.
//!
//! The transcript is intentionally dependency-free for the correctness
//! prototype. Inputs are recorded with explicit type and length prefixes into a
//! rolling digest, then challenges are derived by hashing that digest with
//! SHA-256.

use core::fmt;
use pq_core::{FieldElement, GOLDILOCKS_MODULUS};

const TRANSCRIPT_VERSION: &[u8] = b"pq-transcript/v1";

/// A small conversion trait for fields used by transcript challenges.
///
/// Implementations must accept canonical integers in `0..MODULUS`.
pub trait TranscriptField: Sized {
    /// Field modulus. This prototype samples by reducing a 128-bit challenge.
    const MODULUS: u64;

    /// Builds an element from a canonical integer less than `MODULUS`.
    fn from_canonical_u64(value: u64) -> Self;
}

/// Common transcript operations required by the PIOP and PCS layers.
pub trait Transcript {
    /// Absorbs a domain separator, for example `b"sumcheck"` or `b"pcs-open"`.
    fn absorb_domain(&mut self, domain: &[u8]);

    /// Absorbs public input bytes under a caller-provided label.
    fn absorb_public(&mut self, label: &[u8], value: &[u8]);

    /// Absorbs commitment bytes under a caller-provided label.
    fn absorb_commitment(&mut self, label: &[u8], value: &[u8]);

    /// Absorbs a field element under a caller-provided label.
    fn absorb_field(&mut self, label: &[u8], value: FieldElement);

    /// Samples a field challenge.
    fn challenge_field<F: TranscriptField>(&mut self, label: &[u8]) -> F;

    /// Samples `count` distinct query indices in `0..upper_bound`.
    fn challenge_indices(&mut self, label: &[u8], count: usize, upper_bound: usize) -> Vec<usize>;

    /// Returns a digest of the current transcript state.
    fn state(&self) -> [u8; 32];
}

/// Deterministic SHA-256 based transcript.
#[derive(Clone, Eq, PartialEq)]
pub struct HashTranscript {
    state_digest: [u8; 32],
    state_len: usize,
    challenge_counter: u64,
}

impl HashTranscript {
    /// Creates a transcript and immediately absorbs a top-level protocol label.
    pub fn new(protocol_label: &[u8]) -> Self {
        let mut transcript = Self {
            state_digest: initial_transcript_digest(),
            state_len: 0,
            challenge_counter: 0,
        };
        transcript.record(b"init", b"protocol", protocol_label);
        transcript
    }

    /// Returns deterministic challenge bytes for callers that need raw entropy.
    pub fn challenge_bytes(&mut self, label: &[u8], len: usize) -> Vec<u8> {
        let bytes = self.squeeze(b"bytes", label, len, &[]);
        self.record(b"challenge-bytes", label, &bytes);
        bytes
    }

    /// Samples an integer challenge reduced modulo `modulus`.
    pub fn challenge_u64(&mut self, label: &[u8], modulus: u64) -> u64 {
        assert!(modulus > 1, "challenge modulus must be greater than one");

        let mut extra = Vec::with_capacity(8);
        extra.extend_from_slice(&modulus.to_le_bytes());
        let bytes = self.squeeze(b"u64", label, 16, &extra);
        self.record(b"challenge-u64", label, &bytes);
        (u128_from_le(&bytes) % u128::from(modulus)) as u64
    }

    pub fn state(&self) -> [u8; 32] {
        let mut input = Vec::new();
        append_len_prefixed(&mut input, TRANSCRIPT_VERSION);
        append_len_prefixed(&mut input, b"state");
        input.extend_from_slice(&self.challenge_counter.to_le_bytes());
        input.extend_from_slice(&usize_to_u64(self.state_len).to_le_bytes());
        input.extend_from_slice(&self.state_digest);
        sha256(&input)
    }

    fn record(&mut self, tag: &[u8], label: &[u8], value: &[u8]) {
        let mut input = Vec::new();
        append_len_prefixed(&mut input, TRANSCRIPT_VERSION);
        append_len_prefixed(&mut input, b"record");
        input.extend_from_slice(&self.state_digest);
        append_len_prefixed(&mut input, tag);
        append_len_prefixed(&mut input, label);
        append_len_prefixed(&mut input, value);
        self.state_digest = sha256(&input);
        self.state_len = self
            .state_len
            .wrapping_add(TRANSCRIPT_VERSION.len())
            .wrapping_add(tag.len())
            .wrapping_add(label.len())
            .wrapping_add(value.len())
            .wrapping_add(24);
    }

    fn record_usizes(&mut self, tag: &[u8], label: &[u8], values: &[usize]) {
        let mut encoded = Vec::with_capacity(values.len() * 8);
        for value in values {
            encoded.extend_from_slice(&usize_to_u64(*value).to_le_bytes());
        }
        self.record(tag, label, &encoded);
    }

    fn squeeze(&mut self, purpose: &[u8], label: &[u8], len: usize, extra: &[u8]) -> Vec<u8> {
        let challenge_id = self.challenge_counter;
        self.challenge_counter = self.challenge_counter.wrapping_add(1);

        let mut out = Vec::with_capacity(len);
        let mut block_counter = 0u64;
        while out.len() < len {
            let mut input = Vec::new();
            append_len_prefixed(&mut input, TRANSCRIPT_VERSION);
            append_len_prefixed(&mut input, b"challenge");
            append_len_prefixed(&mut input, purpose);
            append_len_prefixed(&mut input, label);
            append_len_prefixed(&mut input, extra);
            input.extend_from_slice(&challenge_id.to_le_bytes());
            input.extend_from_slice(&block_counter.to_le_bytes());
            input.extend_from_slice(&usize_to_u64(self.state_len).to_le_bytes());
            input.extend_from_slice(&self.state_digest);

            let digest = sha256(&input);
            let remaining = len - out.len();
            let take = remaining.min(digest.len());
            out.extend_from_slice(&digest[..take]);
            block_counter = block_counter.wrapping_add(1);
        }
        out
    }
}

impl Default for HashTranscript {
    fn default() -> Self {
        Self::new(b"default")
    }
}

impl fmt::Debug for HashTranscript {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HashTranscript")
            .field("state_len", &self.state_len)
            .field("challenge_counter", &self.challenge_counter)
            .finish()
    }
}

impl Transcript for HashTranscript {
    fn absorb_domain(&mut self, domain: &[u8]) {
        self.record(b"domain", b"", domain);
    }

    fn absorb_public(&mut self, label: &[u8], value: &[u8]) {
        self.record(b"public", label, value);
    }

    fn absorb_commitment(&mut self, label: &[u8], value: &[u8]) {
        self.record(b"commitment", label, value);
    }

    fn absorb_field(&mut self, label: &[u8], value: FieldElement) {
        self.record(b"field", label, &value.to_le_bytes());
    }

    fn challenge_field<F: TranscriptField>(&mut self, label: &[u8]) -> F {
        assert!(F::MODULUS > 1, "field modulus must be greater than one");

        let mut extra = Vec::with_capacity(8);
        extra.extend_from_slice(&F::MODULUS.to_le_bytes());
        let bytes = self.squeeze(b"field", label, 16, &extra);
        self.record(b"challenge-field", label, &bytes);
        let reduced = u128_from_le(&bytes) % u128::from(F::MODULUS);
        F::from_canonical_u64(reduced as u64)
    }

    fn challenge_indices(&mut self, label: &[u8], count: usize, upper_bound: usize) -> Vec<usize> {
        assert!(upper_bound > 0, "upper_bound must be positive");
        assert!(
            count <= upper_bound,
            "cannot sample more distinct indices than upper_bound"
        );

        let mut selected = Vec::with_capacity(count);
        let mut seen = vec![false; upper_bound];
        let mut round = 0u64;
        while selected.len() < count {
            let mut extra = Vec::with_capacity(24);
            extra.extend_from_slice(&usize_to_u64(count).to_le_bytes());
            extra.extend_from_slice(&usize_to_u64(upper_bound).to_le_bytes());
            extra.extend_from_slice(&round.to_le_bytes());

            let needed = (count - selected.len()).max(1) * 8;
            let bytes = self.squeeze(b"indices", label, needed, &extra);
            for chunk in bytes.chunks_exact(8) {
                let candidate = usize_from_le_u64(chunk) % upper_bound;
                if !seen[candidate] {
                    seen[candidate] = true;
                    selected.push(candidate);
                    if selected.len() == count {
                        break;
                    }
                }
            }
            round = round.wrapping_add(1);
        }

        self.record_usizes(b"challenge-indices", label, &selected);
        selected
    }

    fn state(&self) -> [u8; 32] {
        HashTranscript::state(self)
    }
}

impl TranscriptField for FieldElement {
    const MODULUS: u64 = GOLDILOCKS_MODULUS;

    fn from_canonical_u64(value: u64) -> Self {
        FieldElement::from(value)
    }
}

fn append_len_prefixed(dst: &mut Vec<u8>, value: &[u8]) {
    dst.extend_from_slice(&usize_to_u64(value.len()).to_le_bytes());
    dst.extend_from_slice(value);
}

fn initial_transcript_digest() -> [u8; 32] {
    let mut input = Vec::new();
    append_len_prefixed(&mut input, TRANSCRIPT_VERSION);
    append_len_prefixed(&mut input, b"empty-state");
    sha256(&input)
}

fn usize_to_u64(value: usize) -> u64 {
    assert!(value <= u64::MAX as usize, "value does not fit into u64");
    value as u64
}

fn usize_from_le_u64(bytes: &[u8]) -> usize {
    let mut array = [0u8; 8];
    array.copy_from_slice(bytes);
    let value = u64::from_le_bytes(array);
    assert!(value <= usize::MAX as u64, "u64 does not fit into usize");
    value as usize
}

fn u128_from_le(bytes: &[u8]) -> u128 {
    let mut array = [0u8; 16];
    let take = bytes.len().min(array.len());
    array[..take].copy_from_slice(&bytes[..take]);
    u128::from_le_bytes(array)
}

pub fn sha256(input: &[u8]) -> [u8; 32] {
    const H0: [u32; 8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
        0x5be0cd19,
    ];
    const K: [u32; 64] = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
        0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
        0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
        0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
        0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
        0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
        0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
        0xc67178f2,
    ];

    let mut data = Vec::with_capacity(input.len() + 72);
    data.extend_from_slice(input);
    data.push(0x80);
    while data.len() % 64 != 56 {
        data.push(0);
    }
    let bit_len = (input.len() as u64).wrapping_mul(8);
    data.extend_from_slice(&bit_len.to_be_bytes());

    let mut h = H0;
    for chunk in data.chunks_exact(64) {
        let mut w = [0u32; 64];
        for (i, word) in w.iter_mut().take(16).enumerate() {
            let offset = i * 4;
            *word = u32::from_be_bytes([
                chunk[offset],
                chunk[offset + 1],
                chunk[offset + 2],
                chunk[offset + 3],
            ]);
        }
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }

        let mut a = h[0];
        let mut b = h[1];
        let mut c = h[2];
        let mut d = h[3];
        let mut e = h[4];
        let mut f = h[5];
        let mut g = h[6];
        let mut hh = h[7];

        for i in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ ((!e) & g);
            let temp1 = hh
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(K[i])
                .wrapping_add(w[i]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let temp2 = s0.wrapping_add(maj);

            hh = g;
            g = f;
            f = e;
            e = d.wrapping_add(temp1);
            d = c;
            c = b;
            b = a;
            a = temp1.wrapping_add(temp2);
        }

        h[0] = h[0].wrapping_add(a);
        h[1] = h[1].wrapping_add(b);
        h[2] = h[2].wrapping_add(c);
        h[3] = h[3].wrapping_add(d);
        h[4] = h[4].wrapping_add(e);
        h[5] = h[5].wrapping_add(f);
        h[6] = h[6].wrapping_add(g);
        h[7] = h[7].wrapping_add(hh);
    }

    let mut out = [0u8; 32];
    for (chunk, word) in out.chunks_exact_mut(4).zip(h) {
        chunk.copy_from_slice(&word.to_be_bytes());
    }
    out
}

#[cfg(test)]
mod tests {
    use super::{HashTranscript, Transcript, TranscriptField, sha256};

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    struct Fp17(u64);

    impl TranscriptField for Fp17 {
        const MODULUS: u64 = 17;

        fn from_canonical_u64(value: u64) -> Self {
            assert!(value < Self::MODULUS);
            Self(value)
        }
    }

    fn scripted_transcript() -> (Fp17, Vec<usize>, Vec<u8>) {
        let mut transcript = HashTranscript::new(b"pq-test");
        transcript.absorb_domain(b"sumcheck");
        transcript.absorb_public(b"claimed-sum", b"123");
        transcript.absorb_commitment(b"oracle-root", b"commitment-bytes");
        let alpha = transcript.challenge_field::<Fp17>(b"alpha");
        let indices = transcript.challenge_indices(b"queries", 6, 32);
        let bytes = transcript.challenge_bytes(b"tail", 24);
        (alpha, indices, bytes)
    }

    #[test]
    fn same_input_is_deterministic() {
        let first = scripted_transcript();
        let second = scripted_transcript();

        assert_eq!(first, second);
        assert_eq!(first.1.len(), 6);
        let mut sorted = first.1.clone();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(sorted.len(), first.1.len());
    }

    #[test]
    fn message_reordering_changes_challenge() {
        let mut ordered = HashTranscript::new(b"pq-test");
        ordered.absorb_domain(b"sumcheck");
        ordered.absorb_public(b"claimed-sum", b"123");
        ordered.absorb_commitment(b"oracle-root", b"commitment-bytes");

        let mut reordered = HashTranscript::new(b"pq-test");
        reordered.absorb_domain(b"sumcheck");
        reordered.absorb_commitment(b"oracle-root", b"commitment-bytes");
        reordered.absorb_public(b"claimed-sum", b"123");

        assert_ne!(
            ordered.challenge_bytes(b"alpha", 32),
            reordered.challenge_bytes(b"alpha", 32)
        );
    }

    #[test]
    fn domain_separator_changes_challenge() {
        let mut sumcheck = HashTranscript::new(b"pq-test");
        sumcheck.absorb_domain(b"sumcheck");
        sumcheck.absorb_public(b"input", b"shared");

        let mut pcs = HashTranscript::new(b"pq-test");
        pcs.absorb_domain(b"pcs");
        pcs.absorb_public(b"input", b"shared");

        assert_ne!(
            sumcheck.challenge_bytes(b"beta", 32),
            pcs.challenge_bytes(b"beta", 32)
        );
    }

    #[test]
    fn sha256_known_answer_test() {
        let digest = sha256(b"abc");
        let expected = [
            0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d, 0xae,
            0x22, 0x23, 0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61,
            0xf2, 0x00, 0x15, 0xad,
        ];
        assert_eq!(digest, expected);
    }
}

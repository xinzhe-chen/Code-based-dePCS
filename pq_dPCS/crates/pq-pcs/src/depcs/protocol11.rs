//! protocol11 implementation of pq_dSNARK Protocols 6--11.
//!
//! The protocol layer follows the paper's matrix and message relations and
//! instantiates every polynomial commitment, including `H_u`, with DeepFold.

use std::collections::HashSet;
use std::fmt::{Display, Formatter};
use std::panic::{AssertUnwindSafe, catch_unwind};

use bincode::Options;
use num_bigint::BigInt;
use num_rational::BigRational;
use num_traits::One;
use paper_util::algebra::field::MyField;
use paper_util::merkle_tree::{Hash as MerkleHash, MerkleTreeProver, MerkleTreeVerifier};
use serde::{Deserialize, Serialize};

use crate::hash::sha256;

use super::backend::PaperPcsBackend;
use super::compact_codec;
use super::pcs_backend::{open_polynomial, prepare_prover, verify_evaluation};
use super::types::{
    PaperDepcsConfig, PaperDepcsError, PaperField, PaperPcsCommitment, PaperPcsOpeningProof,
};

pub const PROTOCOL11_VERSION: &str = "protocol11";
pub const PROTOCOL11_FIDELITY: &str = "protocol11-deepfold";
pub const PROTOCOL11_RELEASE_BLOCKER: &str = "vendored-deepfold-has-no-confirmed-license";
const PROOF_MAGIC: &[u8; 8] = b"PQDPCS11";
const COMMITMENT_MAGIC: &[u8; 8] = b"PQDPCSC1";
const PROOF_SCHEMA: u16 = 2;
const MAX_PROOF_BYTES: usize = 1 << 30;
const CODE_EXPANSION: usize = 2;
const BRAKEDOWN_ALPHA_NUMERATOR: usize = 1;
const BRAKEDOWN_ALPHA_DENOMINATOR: usize = 4;
const BRAKEDOWN_BETA_NUMERATOR: usize = 1;
const BRAKEDOWN_BETA_DENOMINATOR: usize = 10;
const BRAKEDOWN_RATE_INVERSE: usize = 2;
const BRAKEDOWN_SETUP_BITS: usize = 110;
const PAPER_FIELD_BITS: usize = 255;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Protocol11Error {
    InvalidParameters(&'static str),
    InvalidLayout(&'static str),
    InvalidShard(&'static str),
    InvalidCommitment(&'static str),
    InvalidProof(&'static str),
    InvalidStatement,
    InsecureParameters,
    Serialization,
    UnsupportedLegacyProtocol,
    Backend(PaperDepcsError),
}

impl Display for Protocol11Error {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidParameters(reason) => write!(f, "invalid protocol11 parameters: {reason}"),
            Self::InvalidLayout(reason) => write!(f, "invalid protocol11 layout: {reason}"),
            Self::InvalidShard(reason) => write!(f, "invalid protocol11 shard: {reason}"),
            Self::InvalidCommitment(reason) => write!(f, "invalid protocol11 commitment: {reason}"),
            Self::InvalidProof(reason) => write!(f, "invalid protocol11 proof: {reason}"),
            Self::InvalidStatement => write!(f, "protocol11 public statement does not match proof"),
            Self::InsecureParameters => write!(f, "protocol11 security budget is below target"),
            Self::Serialization => write!(f, "protocol11 canonical serialization failed"),
            Self::UnsupportedLegacyProtocol => {
                write!(
                    f,
                    "UnsupportedLegacyProtocol: proof is not Protocol 11 schema v2"
                )
            }
            Self::Backend(error) => write!(f, "protocol11 DeepFold backend error: {error:?}"),
        }
    }
}

impl std::error::Error for Protocol11Error {}

impl From<PaperDepcsError> for Protocol11Error {
    fn from(value: PaperDepcsError) -> Self {
        Self::Backend(value)
    }
}

pub type Result<T> = std::result::Result<T, Protocol11Error>;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum SecurityProfile {
    Paper100,
    TestOnly { queries: usize },
}

impl SecurityProfile {
    pub fn security_claim(self) -> Option<usize> {
        match self {
            Self::Paper100 => Some(100),
            Self::TestOnly { .. } => None,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Protocol11Config {
    pub original_len: usize,
    pub workers: usize,
    pub security: SecurityProfile,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PaperLayout {
    pub original_len: usize,
    pub workers: usize,
    pub nv: usize,
    pub worker_bits: usize,
    pub rows_per_worker: usize,
    pub rows: usize,
    pub columns: usize,
    pub encoded_columns: usize,
    pub row_bits: usize,
    pub column_bits: usize,
}

impl PaperLayout {
    pub fn derive(original_len: usize, workers: usize) -> Result<Self> {
        if original_len < 4 || !original_len.is_power_of_two() {
            return Err(Protocol11Error::InvalidParameters(
                "N must be a power of two >= 4",
            ));
        }
        if workers == 0
            || !workers.is_power_of_two()
            || workers >= original_len
            || !original_len.is_multiple_of(workers)
        {
            return Err(Protocol11Error::InvalidParameters(
                "M must be a power of two with 1 <= M < N and M dividing N",
            ));
        }
        let nv = original_len.trailing_zeros() as usize;
        let worker_bits = workers.trailing_zeros() as usize;
        let logical_b = nv
            .checked_sub(worker_bits)
            .ok_or(Protocol11Error::InvalidLayout(
                "worker bits exceed polynomial bits",
            ))?;
        let rows_per_worker = logical_b.max(1).next_power_of_two();
        let rows = workers
            .checked_mul(rows_per_worker)
            .ok_or(Protocol11Error::InvalidLayout("B overflow"))?;
        if rows > original_len || !original_len.is_multiple_of(rows) {
            return Err(Protocol11Error::InvalidLayout(
                "derived B does not divide N",
            ));
        }
        let columns = original_len / rows;
        let encoded_columns = columns * CODE_EXPANSION;
        if !rows.is_power_of_two() || !columns.is_power_of_two() {
            return Err(Protocol11Error::InvalidLayout(
                "B and N/B must be powers of two",
            ));
        }
        Ok(Self {
            original_len,
            workers,
            nv,
            worker_bits,
            rows_per_worker,
            rows,
            columns,
            encoded_columns,
            row_bits: rows.trailing_zeros() as usize,
            column_bits: columns.trailing_zeros() as usize,
        })
    }

    pub fn worker_row_range(self, worker_id: usize) -> Result<(usize, usize)> {
        if worker_id >= self.workers {
            return Err(Protocol11Error::InvalidShard("worker id out of range"));
        }
        Ok((
            worker_id * self.rows_per_worker,
            (worker_id + 1) * self.rows_per_worker,
        ))
    }

    /// Map `[message | parity]` codeword order to the paper's MSB-first
    /// `(column_bits, expansion_bit)` evaluation-table order.
    pub fn codeword_to_paper_index(self, index: usize) -> Result<usize> {
        if index >= self.encoded_columns {
            return Err(Protocol11Error::InvalidLayout(
                "codeword index out of range",
            ));
        }
        Ok(if index < self.columns {
            2 * index
        } else {
            2 * (index - self.columns) + 1
        })
    }

    pub fn paper_to_codeword_index(self, index: usize) -> Result<usize> {
        if index >= self.encoded_columns {
            return Err(Protocol11Error::InvalidLayout("paper index out of range"));
        }
        Ok(index / 2 + (index % 2) * self.columns)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SecurityBudget {
    pub target_bits: Option<usize>,
    pub security_model: String,
    pub soundness_regime: String,
    pub pcs_queries: usize,
    pub column_queries: usize,
    pub pc_opening_count: usize,
    pub sumcheck_rounds: usize,
    pub hash_event_bound: usize,
    pub setup_failure_bits: usize,
    pub pcs_failure_bits: usize,
    pub column_failure_bits: usize,
    pub algebraic_bits: usize,
    pub hash_collision_bits: usize,
    pub union_bound_bits: usize,
    pub effective_bits: Option<usize>,
}

impl SecurityBudget {
    fn derive(profile: SecurityProfile, layout: PaperLayout, code: &BrakedownCode) -> Result<Self> {
        code.validate_parameters()?;
        match profile {
            SecurityProfile::TestOnly { queries } => {
                if queries == 0 {
                    return Err(Protocol11Error::InvalidParameters(
                        "TestOnly query count must be non-zero",
                    ));
                }
                let pcs_queries = queries.min(layout.columns);
                Ok(Self {
                    target_bits: None,
                    security_model: "none".to_owned(),
                    soundness_regime: "test-only".to_owned(),
                    pcs_queries,
                    column_queries: queries.min(layout.encoded_columns),
                    pc_opening_count: protocol11_pc_opening_count(layout.workers),
                    sumcheck_rounds: 2 * (layout.column_bits + 1),
                    hash_event_bound: protocol11_hash_event_bound(layout, pcs_queries),
                    setup_failure_bits: 0,
                    pcs_failure_bits: 0,
                    column_failure_bits: 0,
                    algebraic_bits: PAPER_FIELD_BITS,
                    hash_collision_bits: 128,
                    union_bound_bits: 0,
                    effective_bits: None,
                })
            }
            SecurityProfile::Paper100 => {
                let pc_opening_count = protocol11_pc_opening_count(layout.workers);
                let sumcheck_rounds = 2 * (layout.column_bits + 1);
                // We instantiate DeepFold in the proven unique-decoding
                // regime: rho=1/2 and Delta=(1-rho)/2=1/4.  Each repeated
                // query therefore contributes a factor 3/4.
                let pcs_queries =
                    queries_for_failure_bound(3, 4, pc_opening_count, BRAKEDOWN_SETUP_BITS);
                // Brakedown's certified relative distance is beta/r=1/20.
                let column_queries = queries_for_failure_bound(19, 20, 1, BRAKEDOWN_SETUP_BITS);
                if layout.columns < pcs_queries || layout.encoded_columns < column_queries {
                    return Err(Protocol11Error::InsecureParameters);
                }
                let setup_failure = inverse_power_of_two(BRAKEDOWN_SETUP_BITS);
                let pcs_failure = repeated_failure(3, 4, pcs_queries, pc_opening_count);
                let column_failure = repeated_failure(19, 20, column_queries, 1);
                let algebraic_failure = protocol11_algebraic_failure(layout, pc_opening_count);
                let hash_event_bound = protocol11_hash_event_bound(layout, pcs_queries);
                let hash_failure =
                    BigRational::new(BigInt::from(hash_event_bound), BigInt::one() << 128usize);
                let total_failure = setup_failure.clone()
                    + pcs_failure.clone()
                    + column_failure.clone()
                    + algebraic_failure.clone()
                    + hash_failure.clone();
                let effective_bits = failure_bits(&total_failure);
                if effective_bits < 100 {
                    return Err(Protocol11Error::InsecureParameters);
                }
                let events = pc_opening_count + sumcheck_rounds + 3;
                let union_bound_bits = ceil_log2(events.max(1));
                Ok(Self {
                    target_bits: Some(100),
                    security_model: "classical-rom".to_owned(),
                    soundness_regime: "deepfold-unique-decoding".to_owned(),
                    pcs_queries,
                    column_queries,
                    pc_opening_count,
                    sumcheck_rounds,
                    hash_event_bound,
                    setup_failure_bits: failure_bits(&setup_failure),
                    pcs_failure_bits: failure_bits(&pcs_failure),
                    column_failure_bits: failure_bits(&column_failure),
                    algebraic_bits: failure_bits(&algebraic_failure),
                    hash_collision_bits: failure_bits(&hash_failure),
                    union_bound_bits,
                    effective_bits: Some(effective_bits),
                })
            }
        }
    }
}

fn protocol11_pc_opening_count(workers: usize) -> usize {
    // Protocol 9 opens F2 once per worker.  Each of the two Protocol 10
    // executions opens H_u once and E(r), F(u'), E(u',0) per worker.
    7 * workers + 2
}

fn inverse_power_of_two(bits: usize) -> BigRational {
    BigRational::new(BigInt::one(), BigInt::one() << bits)
}

fn repeated_failure(
    numerator: usize,
    denominator: usize,
    repetitions: usize,
    multiplicity: usize,
) -> BigRational {
    BigRational::new(
        BigInt::from(multiplicity) * BigInt::from(numerator).pow(repetitions as u32),
        BigInt::from(denominator).pow(repetitions as u32),
    )
}

fn queries_for_failure_bound(
    numerator: usize,
    denominator: usize,
    multiplicity: usize,
    target_bits: usize,
) -> usize {
    let target = inverse_power_of_two(target_bits);
    let mut repetitions = 1usize;
    while repeated_failure(numerator, denominator, repetitions, multiplicity) > target {
        repetitions += 1;
    }
    repetitions
}

fn protocol11_algebraic_failure(layout: PaperLayout, pc_opening_count: usize) -> BigRational {
    // Conservative finite-field accounting.  It covers every external field
    // challenge, every DeepFold folding/DEEP challenge at the largest domain,
    // and degree-2 soundness for both Protocol 10 sumchecks.
    let transcript_challenges = layout.rows
        + 6 * layout.column_bits
        + 2
        + pc_opening_count * (2 + 3 * (layout.column_bits + 1));
    let sumcheck_degree_events = 4 * (layout.column_bits + 1);
    let numerator = transcript_challenges
        .checked_mul(layout.encoded_columns)
        .and_then(|value| value.checked_add(sumcheck_degree_events))
        .unwrap_or(usize::MAX);
    let field_order = BigInt::parse_bytes(
        b"46242760681095663677370860714659204618859642560429202607213929836750194081793",
        10,
    )
    .expect("Ft255 modulus is a valid integer");
    BigRational::new(BigInt::from(numerator), field_order)
}

fn protocol11_hash_event_bound(layout: PaperLayout, pcs_queries: usize) -> usize {
    let committed_vector_hashes = layout
        .workers
        .saturating_mul(6)
        .saturating_mul(layout.encoded_columns);
    let opening_hashes = protocol11_pc_opening_count(layout.workers)
        .saturating_mul(pcs_queries)
        .saturating_mul(layout.column_bits + 2);
    committed_vector_hashes
        .saturating_add(opening_hashes)
        .saturating_add(1024)
}

fn failure_bits(probability: &BigRational) -> usize {
    let mut bits = 0usize;
    while bits < 512 && probability <= &inverse_power_of_two(bits + 1) {
        bits += 1;
    }
    bits
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BrakedownCode {
    pub message_len: usize,
    pub expansion: usize,
    pub alpha_numerator: usize,
    pub alpha_denominator: usize,
    pub beta_numerator: usize,
    pub beta_denominator: usize,
    pub rate_inverse: usize,
    pub relative_distance_numerator: usize,
    pub relative_distance_denominator: usize,
    pub setup_failure_bits: usize,
    pub root: BrakedownLevel,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum BrakedownLevel {
    Base {
        message_len: usize,
        diagonal: Vec<PaperField>,
    },
    Recursive {
        message_len: usize,
        /// Equation (7) row weight for `A(n)` after conservative rounding.
        a_degree: usize,
        /// Rows of `A(n) in F^(n x alpha*n)`.
        a_rows: Vec<Vec<(usize, PaperField)>>,
        /// Equation (8) row weight for `B(n)` after conservative rounding.
        b_degree: usize,
        /// Rows of `B(n) in F^(2*alpha*n x (1-2*alpha)*n)` for `r=2`.
        b_rows: Vec<Vec<(usize, PaperField)>>,
        child: Box<BrakedownLevel>,
    },
}

impl BrakedownCode {
    fn setup(message_len: usize, setup_seed: [u8; 32]) -> Self {
        Self {
            message_len,
            expansion: CODE_EXPANSION,
            alpha_numerator: BRAKEDOWN_ALPHA_NUMERATOR,
            alpha_denominator: BRAKEDOWN_ALPHA_DENOMINATOR,
            beta_numerator: BRAKEDOWN_BETA_NUMERATOR,
            beta_denominator: BRAKEDOWN_BETA_DENOMINATOR,
            rate_inverse: BRAKEDOWN_RATE_INVERSE,
            relative_distance_numerator: BRAKEDOWN_BETA_NUMERATOR,
            relative_distance_denominator: BRAKEDOWN_BETA_DENOMINATOR * BRAKEDOWN_RATE_INVERSE,
            setup_failure_bits: BRAKEDOWN_SETUP_BITS,
            root: setup_brakedown_level(message_len, setup_seed, 0),
        }
    }

    pub fn encode(&self, message: &[PaperField]) -> Result<Vec<PaperField>> {
        if message.len() != self.message_len {
            return Err(Protocol11Error::InvalidLayout(
                "encoding message length mismatch",
            ));
        }
        encode_brakedown_level(&self.root, message)
    }

    fn validate_parameters(&self) -> Result<()> {
        if self.expansion != CODE_EXPANSION
            || self.alpha_numerator != BRAKEDOWN_ALPHA_NUMERATOR
            || self.alpha_denominator != BRAKEDOWN_ALPHA_DENOMINATOR
            || self.beta_numerator != BRAKEDOWN_BETA_NUMERATOR
            || self.beta_denominator != BRAKEDOWN_BETA_DENOMINATOR
            || self.rate_inverse != BRAKEDOWN_RATE_INVERSE
            || self.relative_distance_numerator != 1
            || self.relative_distance_denominator != 20
            || self.setup_failure_bits != BRAKEDOWN_SETUP_BITS
        {
            return Err(Protocol11Error::InvalidParameters(
                "Brakedown parameter certificate mismatch",
            ));
        }
        validate_brakedown_level(&self.root, self.message_len)
    }

    pub fn parity_syndrome(&self, encoded: &[PaperField]) -> Result<Vec<PaperField>> {
        if encoded.len() != self.message_len * self.expansion {
            return Err(Protocol11Error::InvalidLayout(
                "encoded row length mismatch",
            ));
        }
        let expected = self.encode(&encoded[..self.message_len])?;
        Ok(encoded[self.message_len..]
            .iter()
            .zip(&expected[self.message_len..])
            .map(|(actual, expected)| *actual - *expected)
            .collect())
    }

    pub fn is_codeword(&self, encoded: &[PaperField]) -> Result<bool> {
        Ok(self.parity_syndrome(encoded)?.iter().all(MyField::is_zero))
    }

    /// Return the MLE-combined parity-check row for the systematic generator
    /// `Enc(x)=(x,Px)`, i.e. `H=[-P | I]`, at an MSB-first challenge `u`.
    pub fn hu(&self, u: &[PaperField]) -> Result<Vec<PaperField>> {
        if u.len() != self.message_len.trailing_zeros() as usize {
            return Err(Protocol11Error::InvalidProof("H_u point length mismatch"));
        }
        let weights = (0..self.message_len)
            .map(|index| eq_index_msb(u, index))
            .collect::<Vec<_>>();
        let mut codeword_weights = vec![PaperField::from_int(0); self.message_len];
        codeword_weights.extend_from_slice(&weights);
        let input_weights = transpose_brakedown_level(&self.root, &codeword_weights)?;
        let mut hu = input_weights
            .into_iter()
            .map(std::ops::Neg::neg)
            .collect::<Vec<_>>();
        hu.extend_from_slice(&weights);
        Ok(hu)
    }
}

fn validate_sparse_rows(
    rows: &[Vec<(usize, PaperField)>],
    source_len: usize,
    target_len: usize,
    degree: usize,
) -> bool {
    rows.len() == source_len
        && degree > 0
        && degree <= target_len
        && rows.iter().all(|row| {
            row.len() == degree
                && row.windows(2).all(|pair| pair[0].0 < pair[1].0)
                && row
                    .iter()
                    .all(|(column, coefficient)| *column < target_len && !coefficient.is_zero())
        })
}

fn validate_brakedown_level(level: &BrakedownLevel, expected_len: usize) -> Result<()> {
    match level {
        BrakedownLevel::Base {
            message_len,
            diagonal,
        } => {
            if *message_len != expected_len
                || expected_len >= 4
                || diagonal.len() != expected_len
                || diagonal.iter().any(MyField::is_zero)
            {
                return Err(Protocol11Error::InvalidParameters(
                    "invalid Brakedown base certificate",
                ));
            }
        }
        BrakedownLevel::Recursive {
            message_len,
            a_degree,
            a_rows,
            b_degree,
            b_rows,
            child,
        } => {
            if *message_len != expected_len || expected_len < 4 || !expected_len.is_multiple_of(4) {
                return Err(Protocol11Error::InvalidParameters(
                    "invalid Brakedown recursive dimension",
                ));
            }
            let compressed_len = expected_len / 4;
            let recursive_len = 2 * compressed_len;
            let tail_len = expected_len - recursive_len;
            if *a_degree != brakedown_cn(expected_len).min(compressed_len)
                || *b_degree != brakedown_dn(recursive_len).min(tail_len)
                || !validate_sparse_rows(a_rows, expected_len, compressed_len, *a_degree)
                || !validate_sparse_rows(b_rows, recursive_len, tail_len, *b_degree)
            {
                return Err(Protocol11Error::InvalidParameters(
                    "invalid Brakedown sparse-matrix certificate",
                ));
            }
            validate_brakedown_level(child, compressed_len)?;
        }
    }
    Ok(())
}

fn binary_entropy(value: f64) -> f64 {
    debug_assert!(value > 0.0 && value < 1.0);
    -value * value.log2() - (1.0 - value) * (1.0 - value).log2()
}

fn ceil_ratio(numerator: usize, denominator: usize) -> usize {
    numerator.div_ceil(denominator)
}

/// The entropy expressions in Brakedown Equations (7)--(8) are irrational.
/// We deliberately add one after the floating-point ceiling: this may produce
/// one extra non-zero per row, but cannot undercut the paper's required degree
/// at the supported sizes.  Golden tests pin the resulting finite parameters.
fn conservative_entropy_ceil(value: f64) -> usize {
    value.ceil() as usize + 1
}

/// Equation (7) of Brakedown for alpha=1/4 and beta=1/10.
fn brakedown_cn(n: usize) -> usize {
    let alpha = BRAKEDOWN_ALPHA_NUMERATOR as f64 / BRAKEDOWN_ALPHA_DENOMINATOR as f64;
    let beta = BRAKEDOWN_BETA_NUMERATOR as f64 / BRAKEDOWN_BETA_DENOMINATOR as f64;
    let entropy_argument = 1.28 * beta / alpha;
    let c_numerator = binary_entropy(beta) + alpha * binary_entropy(entropy_argument);
    let c_denominator = -beta * entropy_argument.log2();

    let expansion_bound = ceil_ratio(16 * n, 125);
    let distance_bound = 4 + ceil_ratio(n, BRAKEDOWN_BETA_DENOMINATOR);
    let probabilistic_bound = conservative_entropy_ceil(
        (BRAKEDOWN_SETUP_BITS as f64 / n as f64 + c_numerator) / c_denominator,
    );
    expansion_bound.max(distance_bound).min(probabilistic_bound)
}

/// Equation (8) of Brakedown for alpha=1/4, beta=1/10, r=2 and
/// `log2(|F|)=255`.
fn brakedown_dn(n: usize) -> usize {
    let alpha = BRAKEDOWN_ALPHA_NUMERATOR as f64 / BRAKEDOWN_ALPHA_DENOMINATOR as f64;
    let beta = BRAKEDOWN_BETA_NUMERATOR as f64 / BRAKEDOWN_BETA_DENOMINATOR as f64;
    let rate_inverse = BRAKEDOWN_RATE_INVERSE as f64;
    let mu = rate_inverse * (1.0 - alpha) - 1.0;
    let nu = beta + alpha * beta + 0.03;
    let entropy_argument = nu / mu;
    let d_numerator = rate_inverse * alpha * binary_entropy(beta / rate_inverse)
        + mu * binary_entropy(entropy_argument);
    let d_denominator = -alpha * beta * entropy_argument.log2();

    let field_bound = ceil_ratio(n, 5) + ceil_ratio(n + BRAKEDOWN_SETUP_BITS, PAPER_FIELD_BITS);
    let probabilistic_bound = conservative_entropy_ceil(
        (BRAKEDOWN_SETUP_BITS as f64 / n as f64 + d_numerator) / d_denominator,
    );
    field_bound.min(probabilistic_bound)
}

fn setup_brakedown_level(message_len: usize, seed: [u8; 32], level: usize) -> BrakedownLevel {
    if message_len < 4 {
        let diagonal = (0..message_len)
            .map(|row| nonzero_setup_field(seed, b"brakedown-base", level, row, 0))
            .collect();
        return BrakedownLevel::Base {
            message_len,
            diagonal,
        };
    }
    let compressed_len = message_len / 4;
    let recursive_codeword_len = 2 * compressed_len;
    let parity_tail_len = message_len - recursive_codeword_len;
    let a_degree = brakedown_cn(message_len).min(compressed_len);
    let b_degree = brakedown_dn(recursive_codeword_len).min(parity_tail_len);
    BrakedownLevel::Recursive {
        message_len,
        a_degree,
        a_rows: setup_sparse_rows(
            seed,
            b"brakedown-A",
            level,
            message_len,
            compressed_len,
            a_degree,
        ),
        b_degree,
        b_rows: setup_sparse_rows(
            seed,
            b"brakedown-B",
            level,
            recursive_codeword_len,
            parity_tail_len,
            b_degree,
        ),
        child: Box::new(setup_brakedown_level(compressed_len, seed, level + 1)),
    }
}

fn setup_sparse_rows(
    seed: [u8; 32],
    label: &[u8],
    level: usize,
    source_len: usize,
    target_len: usize,
    degree: usize,
) -> Vec<Vec<(usize, PaperField)>> {
    debug_assert!(degree > 0 && degree <= target_len);
    (0..source_len)
        .map(|row| {
            let mut used = HashSet::with_capacity(degree);
            let mut entries = Vec::with_capacity(degree);
            let mut edge = 0usize;
            while entries.len() < degree {
                let block = setup_block(seed, label, b"column", level, row, edge);
                edge += 1;
                let column = u64::from_le_bytes(block[..8].try_into().expect("eight bytes"))
                    as usize
                    % target_len;
                if used.insert(column) {
                    entries.push((column, nonzero_setup_field(seed, label, level, row, edge)));
                }
            }
            entries.sort_by_key(|(column, _)| *column);
            entries
        })
        .collect()
}

fn nonzero_setup_field(
    seed: [u8; 32],
    label: &[u8],
    level: usize,
    row: usize,
    edge: usize,
) -> PaperField {
    let mut block = setup_block(seed, label, b"coefficient", level, row, edge);
    loop {
        let value = PaperField::from_hash(block);
        if !value.is_zero() {
            return value;
        }
        block = domain_digest(b"protocol11-brakedown-nonzero-retry", &block);
    }
}

fn apply_sparse_rows(
    input: &[PaperField],
    rows: &[Vec<(usize, PaperField)>],
    output_len: usize,
) -> Result<Vec<PaperField>> {
    if input.len() != rows.len() {
        return Err(Protocol11Error::InvalidLayout(
            "sparse matrix input mismatch",
        ));
    }
    let mut output = vec![PaperField::from_int(0); output_len];
    for (value, row) in input.iter().zip(rows) {
        for (column, coefficient) in row {
            output[*column] += *value * *coefficient;
        }
    }
    Ok(output)
}

fn encode_brakedown_level(
    level: &BrakedownLevel,
    message: &[PaperField],
) -> Result<Vec<PaperField>> {
    match level {
        BrakedownLevel::Base {
            message_len,
            diagonal,
        } => {
            if message.len() != *message_len {
                return Err(Protocol11Error::InvalidLayout(
                    "Brakedown base input mismatch",
                ));
            }
            let mut output = message.to_vec();
            output.extend(
                message
                    .iter()
                    .zip(diagonal)
                    .map(|(value, scale)| *value * *scale),
            );
            Ok(output)
        }
        BrakedownLevel::Recursive {
            message_len,
            a_degree: _,
            a_rows,
            b_degree: _,
            b_rows,
            child,
        } => {
            if message.len() != *message_len {
                return Err(Protocol11Error::InvalidLayout(
                    "Brakedown recursive input mismatch",
                ));
            }
            let compressed = apply_sparse_rows(message, a_rows, message_len / 4)?;
            let recursive = encode_brakedown_level(child, &compressed)?;
            let tail = apply_sparse_rows(&recursive, b_rows, message_len / 2)?;
            let mut output = message.to_vec();
            output.extend(recursive);
            output.extend(tail);
            Ok(output)
        }
    }
}

fn transpose_brakedown_level(
    level: &BrakedownLevel,
    codeword_weights: &[PaperField],
) -> Result<Vec<PaperField>> {
    match level {
        BrakedownLevel::Base {
            message_len,
            diagonal,
        } => {
            if codeword_weights.len() != 2 * message_len {
                return Err(Protocol11Error::InvalidLayout(
                    "Brakedown base transpose mismatch",
                ));
            }
            Ok((0..*message_len)
                .map(|index| {
                    codeword_weights[index]
                        + codeword_weights[message_len + index] * diagonal[index]
                })
                .collect())
        }
        BrakedownLevel::Recursive {
            message_len,
            a_degree: _,
            a_rows,
            b_degree: _,
            b_rows,
            child,
        } => {
            if codeword_weights.len() != 2 * message_len {
                return Err(Protocol11Error::InvalidLayout(
                    "Brakedown recursive transpose mismatch",
                ));
            }
            let recursive_len = message_len / 2;
            let direct = &codeword_weights[..*message_len];
            let recursive_weights = &codeword_weights[*message_len..*message_len + recursive_len];
            let tail_weights = &codeword_weights[*message_len + recursive_len..];
            let mut combined = recursive_weights.to_vec();
            for (row_index, row) in b_rows.iter().enumerate() {
                for (column, coefficient) in row {
                    combined[row_index] += tail_weights[*column] * *coefficient;
                }
            }
            let compressed_weights = transpose_brakedown_level(child, &combined)?;
            let mut result = direct.to_vec();
            for (row_index, row) in a_rows.iter().enumerate() {
                for (column, coefficient) in row {
                    result[row_index] += compressed_weights[*column] * *coefficient;
                }
            }
            Ok(result)
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PublicParameters {
    pub protocol: String,
    pub config: Protocol11Config,
    pub layout: PaperLayout,
    pub setup_seed: [u8; 32],
    pub code: BrakedownCode,
    pub security: SecurityBudget,
    pub params_digest: [u8; 32],
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct GlobalPolynomial {
    pub evaluations: Vec<PaperField>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorkerShard {
    pub worker_id: usize,
    pub rows: Vec<Vec<PaperField>>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorkerCommitment {
    pub worker_id: usize,
    pub row_start: usize,
    pub row_end: usize,
    pub column_root: MerkleHash,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Protocol11Commitment {
    pub protocol: String,
    pub params_digest: [u8; 32],
    pub workers: Vec<WorkerCommitment>,
    pub root: [u8; 32],
}

#[derive(Clone, Debug)]
pub struct WorkerProverState {
    pub worker_id: usize,
    pub rows: Vec<Vec<PaperField>>,
    pub encoded_rows: Vec<Vec<PaperField>>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PcCommitment {
    pub nv: usize,
    pub oracle_seed: [u8; 32],
    pub commitment: PaperPcsCommitment,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PcOpening {
    pub value: PaperField,
    pub proof: PaperPcsOpeningProof,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WorkerEvalCommitments {
    pub worker_id: usize,
    pub e1: PcCommitment,
    pub f1: PcCommitment,
    pub e2: PcCommitment,
    pub f2: PcCommitment,
    pub e1_merkle_root: MerkleHash,
    pub e2_merkle_root: MerkleHash,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ColumnOpening {
    pub indices: Vec<usize>,
    pub columns: Vec<Vec<PaperField>>,
    pub proof_bytes: Vec<u8>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct VectorMerkleOpening {
    pub indices: Vec<usize>,
    pub values: Vec<PaperField>,
    pub proof_bytes: Vec<u8>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WorkerEvalOpenings {
    pub worker_id: usize,
    pub source_columns: ColumnOpening,
    pub e1_columns: VectorMerkleOpening,
    pub e2_columns: VectorMerkleOpening,
    pub f2_at_s2: PcOpening,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SumcheckRound {
    /// Evaluations of the degree-two round polynomial at 0, 1, and 2.
    pub evaluations: [PaperField; 3],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum EncodingRelation {
    E1,
    E2,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WorkerRelationOpenings {
    pub worker_id: usize,
    pub e_at_r: PcOpening,
    pub f_at_u_prime: PcOpening,
    pub e_at_systematic: PcOpening,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Protocol10Proof {
    pub relation: EncodingRelation,
    pub hu_commitment: PcCommitment,
    pub rounds: Vec<SumcheckRound>,
    pub hu_at_r: PcOpening,
    pub worker_openings: Vec<WorkerRelationOpenings>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Protocol11Event {
    Statement,
    ChallengeA,
    EvalCommitments,
    ColumnChallenge,
    ColumnOpenings,
    Protocol10E1,
    Protocol10E2,
    Final,
}

const PROTOCOL11_EVENT_ORDER: [Protocol11Event; 8] = [
    Protocol11Event::Statement,
    Protocol11Event::ChallengeA,
    Protocol11Event::EvalCommitments,
    Protocol11Event::ColumnChallenge,
    Protocol11Event::ColumnOpenings,
    Protocol11Event::Protocol10E1,
    Protocol11Event::Protocol10E2,
    Protocol11Event::Final,
];

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Protocol11Proof {
    pub protocol: String,
    pub params_digest: [u8; 32],
    pub security_profile: SecurityProfile,
    pub eval_commitments: Vec<WorkerEvalCommitments>,
    pub worker_openings: Vec<WorkerEvalOpenings>,
    pub y1: Vec<PaperField>,
    pub y2: Vec<PaperField>,
    pub protocol10_e1: Protocol10Proof,
    pub protocol10_e2: Protocol10Proof,
    pub transcript_digest: [u8; 32],
}

#[derive(Clone, Debug)]
struct EvalMaterial {
    worker_id: usize,
    e1: Vec<PaperField>,
    f1: Vec<PaperField>,
    e2: Vec<PaperField>,
    f2: Vec<PaperField>,
    commitments: WorkerEvalCommitments,
}

#[derive(Clone, Debug)]
struct Transcript {
    bytes: Vec<u8>,
    counter: u64,
}

/// Typed interactive prover entry point. The Fiat--Shamir wrapper below calls
/// this same session instead of maintaining a second protocol implementation.
pub struct Protocol11ProverSession<'a> {
    pp: &'a PublicParameters,
    commitment: &'a Protocol11Commitment,
    point: &'a [PaperField],
}

impl<'a> Protocol11ProverSession<'a> {
    pub fn new(
        pp: &'a PublicParameters,
        commitment: &'a Protocol11Commitment,
        point: &'a [PaperField],
    ) -> Result<Self> {
        validate_public_inputs(pp, commitment, point)?;
        Ok(Self {
            pp,
            commitment,
            point,
        })
    }

    pub fn prove(self, workers: Vec<WorkerProverState>) -> Result<(PaperField, Protocol11Proof)> {
        prove_fs_inner(self.pp, self.commitment, workers, self.point)
    }
}

/// Interactive verifier state machine. A caller must accept the eight message
/// phases in order before final verification is allowed.
pub struct Protocol11VerifierSession<'a> {
    pp: &'a PublicParameters,
    commitment: &'a Protocol11Commitment,
    point: &'a [PaperField],
    claimed_value: PaperField,
    next_event: usize,
}

impl<'a> Protocol11VerifierSession<'a> {
    pub fn new(
        pp: &'a PublicParameters,
        commitment: &'a Protocol11Commitment,
        point: &'a [PaperField],
        claimed_value: PaperField,
    ) -> Result<Self> {
        validate_public_inputs(pp, commitment, point)?;
        Ok(Self {
            pp,
            commitment,
            point,
            claimed_value,
            next_event: 0,
        })
    }

    pub fn accept(&mut self, event: Protocol11Event) -> Result<()> {
        if PROTOCOL11_EVENT_ORDER.get(self.next_event) != Some(&event) {
            return Err(Protocol11Error::InvalidProof(
                "interactive message order mismatch",
            ));
        }
        self.next_event += 1;
        Ok(())
    }

    pub fn finalize(self, proof: &Protocol11Proof) -> Result<()> {
        if self.next_event != PROTOCOL11_EVENT_ORDER.len() {
            return Err(Protocol11Error::InvalidProof(
                "interactive session is incomplete",
            ));
        }
        verify_fs_inner(
            self.pp,
            self.commitment,
            self.point,
            self.claimed_value,
            proof,
        )
    }
}

impl Transcript {
    fn new() -> Self {
        let mut transcript = Self {
            bytes: Vec::new(),
            counter: 0,
        };
        transcript.absorb_bytes(b"protocol", PROTOCOL11_VERSION.as_bytes());
        transcript
    }

    fn absorb_bytes(&mut self, label: &[u8], value: &[u8]) {
        push_bytes(&mut self.bytes, label);
        push_bytes(&mut self.bytes, value);
    }

    fn absorb<T: Serialize>(&mut self, label: &[u8], value: &T) -> Result<()> {
        let bytes = canonical_options()
            .serialize(value)
            .map_err(|_| Protocol11Error::Serialization)?;
        self.absorb_bytes(label, &bytes);
        Ok(())
    }

    fn challenge_block(&mut self, label: &[u8]) -> [u8; 32] {
        let mut input = self.bytes.clone();
        push_bytes(&mut input, label);
        input.extend_from_slice(&self.counter.to_le_bytes());
        self.counter += 1;
        let block = sha256(&input);
        self.absorb_bytes(b"verifier-challenge", &block);
        block
    }

    fn challenge_field(&mut self, label: &[u8]) -> PaperField {
        PaperField::from_hash(self.challenge_block(label))
    }

    fn challenge_fields(&mut self, label: &[u8], count: usize) -> Vec<PaperField> {
        (0..count)
            .map(|index| {
                let mut indexed = label.to_vec();
                indexed.extend_from_slice(&(index as u64).to_le_bytes());
                self.challenge_field(&indexed)
            })
            .collect()
    }

    fn distinct_indices(
        &mut self,
        label: &[u8],
        count: usize,
        domain: usize,
    ) -> Result<Vec<usize>> {
        if count > domain || domain == 0 {
            return Err(Protocol11Error::InvalidParameters(
                "query count exceeds column domain",
            ));
        }
        let mut indices = Vec::with_capacity(count);
        let mut used = HashSet::with_capacity(count);
        while indices.len() < count {
            let block = self.challenge_block(label);
            let candidate =
                u64::from_le_bytes(block[..8].try_into().expect("eight bytes")) as usize % domain;
            if used.insert(candidate) {
                indices.push(candidate);
            }
        }
        indices.sort_unstable();
        self.absorb(b"distinct-indices", &indices)?;
        Ok(indices)
    }

    fn digest(&self) -> [u8; 32] {
        sha256(&self.bytes)
    }
}

pub fn setup(config: Protocol11Config, setup_seed: [u8; 32]) -> Result<PublicParameters> {
    let layout = PaperLayout::derive(config.original_len, config.workers)?;
    let code = BrakedownCode::setup(layout.columns, setup_seed);
    let security = SecurityBudget::derive(config.security, layout, &code)?;
    let digest_input = canonical_options()
        .serialize(&(
            PROTOCOL11_VERSION,
            config,
            layout,
            setup_seed,
            &code,
            &security,
            "Ft255",
            "SHA-256",
            "BLAKE3",
        ))
        .map_err(|_| Protocol11Error::Serialization)?;
    let params_digest = domain_digest(b"protocol11-public-parameters", &digest_input);
    Ok(PublicParameters {
        protocol: PROTOCOL11_VERSION.to_owned(),
        config,
        layout,
        setup_seed,
        code,
        security,
        params_digest,
    })
}

pub fn commit_global(
    pp: &PublicParameters,
    evaluations: Vec<PaperField>,
) -> Result<(Protocol11Commitment, Vec<WorkerProverState>)> {
    if evaluations.len() != pp.layout.original_len {
        return Err(Protocol11Error::InvalidLayout(
            "global polynomial length mismatch",
        ));
    }
    let rows = evaluations
        .chunks_exact(pp.layout.columns)
        .map(<[PaperField]>::to_vec)
        .collect::<Vec<_>>();
    let mut worker_commitments = Vec::with_capacity(pp.layout.workers);
    let mut states = Vec::with_capacity(pp.layout.workers);
    for worker_id in 0..pp.layout.workers {
        let start = worker_id * pp.layout.rows_per_worker;
        let end = start + pp.layout.rows_per_worker;
        let shard = WorkerShard {
            worker_id,
            rows: rows[start..end].to_vec(),
        };
        let (commitment, state) = commit_worker(pp, shard)?;
        worker_commitments.push(commitment);
        states.push(state);
    }
    let commitment = aggregate_commitments(pp, worker_commitments)?;
    Ok((commitment, states))
}

pub fn commit_worker(
    pp: &PublicParameters,
    shard: WorkerShard,
) -> Result<(WorkerCommitment, WorkerProverState)> {
    let (row_start, row_end) = pp.layout.worker_row_range(shard.worker_id)?;
    if shard.rows.len() != pp.layout.rows_per_worker
        || shard.rows.iter().any(|row| row.len() != pp.layout.columns)
    {
        return Err(Protocol11Error::InvalidShard(
            "worker matrix shape mismatch",
        ));
    }
    let encoded_rows = shard
        .rows
        .iter()
        .map(|row| {
            pp.code
                .encode(row)
                .and_then(|codeword| codeword_to_paper(pp, &codeword))
        })
        .collect::<Result<Vec<_>>>()?;
    let tree = encoded_column_tree(pp, shard.worker_id, &encoded_rows)?;
    let commitment = WorkerCommitment {
        worker_id: shard.worker_id,
        row_start,
        row_end,
        column_root: tree.commit(),
    };
    let state = WorkerProverState {
        worker_id: shard.worker_id,
        rows: shard.rows,
        encoded_rows,
    };
    Ok((commitment, state))
}

pub fn aggregate_commitments(
    pp: &PublicParameters,
    mut workers: Vec<WorkerCommitment>,
) -> Result<Protocol11Commitment> {
    if workers.len() != pp.layout.workers {
        return Err(Protocol11Error::InvalidCommitment(
            "worker commitment count mismatch",
        ));
    }
    workers.sort_by_key(|worker| worker.worker_id);
    for (worker_id, worker) in workers.iter().enumerate() {
        let (start, end) = pp.layout.worker_row_range(worker_id)?;
        if worker.worker_id != worker_id || worker.row_start != start || worker.row_end != end {
            return Err(Protocol11Error::InvalidCommitment(
                "non-canonical worker commitment",
            ));
        }
    }
    let bytes = canonical_options()
        .serialize(&(pp.params_digest, &workers))
        .map_err(|_| Protocol11Error::Serialization)?;
    Ok(Protocol11Commitment {
        protocol: PROTOCOL11_VERSION.to_owned(),
        params_digest: pp.params_digest,
        workers,
        root: domain_digest(b"protocol11-worker-commitment-set", &bytes),
    })
}

pub fn prove_fs(
    pp: &PublicParameters,
    commitment: &Protocol11Commitment,
    workers: Vec<WorkerProverState>,
    point: &[PaperField],
) -> Result<(PaperField, Protocol11Proof)> {
    Protocol11ProverSession::new(pp, commitment, point)?.prove(workers)
}

fn prove_fs_inner(
    pp: &PublicParameters,
    commitment: &Protocol11Commitment,
    mut workers: Vec<WorkerProverState>,
    point: &[PaperField],
) -> Result<(PaperField, Protocol11Proof)> {
    validate_public_inputs(pp, commitment, point)?;
    workers.sort_by_key(|worker| worker.worker_id);
    validate_worker_states(pp, commitment, &workers)?;

    let (s1, s2) = point.split_at(pp.layout.row_bits);
    let claimed_value = evaluate_worker_rows(pp, &workers, s1, s2);
    let mut transcript = statement_transcript(pp, commitment, point, claimed_value)?;
    let a = transcript.challenge_fields(b"protocol11-a", pp.layout.rows);
    let mut materials = Vec::with_capacity(workers.len());
    for worker in &workers {
        materials.push(build_eval_material(pp, commitment, point, &a, worker)?);
    }
    let eval_commitments = materials
        .iter()
        .map(|material| material.commitments.clone())
        .collect::<Vec<_>>();
    transcript.absorb(b"protocol11-eval-commitments", &eval_commitments)?;

    let column_indices = transcript.distinct_indices(
        b"protocol11-column-index",
        pp.security.column_queries,
        pp.layout.encoded_columns,
    )?;

    let backend_s2 = backend_point_msb(s2);
    let mut worker_openings = Vec::with_capacity(workers.len());
    let mut y1 = vec![PaperField::from_int(0); column_indices.len()];
    let mut y2 = vec![PaperField::from_int(0); column_indices.len()];
    for ((worker, material), worker_commitment) in
        workers.iter().zip(&materials).zip(&commitment.workers)
    {
        let source_columns = open_source_columns(pp, worker, &column_indices)?;
        let (e1_tree, e1_leaves) = vector_tree(
            pp.params_digest,
            b"protocol11-e1-vector",
            worker.worker_id,
            &material.e1,
        );
        let (e2_tree, e2_leaves) = vector_tree(
            pp.params_digest,
            b"protocol11-e2-vector",
            worker.worker_id,
            &material.e2,
        );
        let e1_values = column_indices
            .iter()
            .map(|index| material.e1[*index])
            .collect();
        let e2_values = column_indices
            .iter()
            .map(|index| material.e2[*index])
            .collect();
        let e1_columns = VectorMerkleOpening {
            indices: column_indices.clone(),
            values: e1_values,
            proof_bytes: e1_tree.open(&column_indices),
        };
        let e2_columns = VectorMerkleOpening {
            indices: column_indices.clone(),
            values: e2_values,
            proof_bytes: e2_tree.open(&column_indices),
        };
        debug_assert_eq!(e1_tree.commit(), material.commitments.e1_merkle_root);
        debug_assert_eq!(e2_tree.commit(), material.commitments.e2_merkle_root);
        let _ = (e1_leaves, e2_leaves, worker_commitment);
        for (slot, index) in column_indices.iter().enumerate() {
            y1[slot] += material.e1[*index];
            y2[slot] += material.e2[*index];
        }
        let f2_at_s2 = pc_open(pp, &material.f2, &material.commitments.f2, &backend_s2)?;
        worker_openings.push(WorkerEvalOpenings {
            worker_id: worker.worker_id,
            source_columns,
            e1_columns,
            e2_columns,
            f2_at_s2,
        });
    }
    transcript.absorb(b"protocol11-column-openings", &(&worker_openings, &y1, &y2))?;

    let protocol10_e1 = prove_protocol10(pp, &mut transcript, EncodingRelation::E1, &materials)?;
    let protocol10_e2 = prove_protocol10(pp, &mut transcript, EncodingRelation::E2, &materials)?;
    let transcript_digest = transcript.digest();
    Ok((
        claimed_value,
        Protocol11Proof {
            protocol: PROTOCOL11_VERSION.to_owned(),
            params_digest: pp.params_digest,
            security_profile: pp.config.security,
            eval_commitments,
            worker_openings,
            y1,
            y2,
            protocol10_e1,
            protocol10_e2,
            transcript_digest,
        },
    ))
}

pub fn verify_fs(
    pp: &PublicParameters,
    commitment: &Protocol11Commitment,
    point: &[PaperField],
    claimed_value: PaperField,
    proof: &Protocol11Proof,
) -> Result<()> {
    let mut session = Protocol11VerifierSession::new(pp, commitment, point, claimed_value)?;
    for event in PROTOCOL11_EVENT_ORDER {
        session.accept(event)?;
    }
    session.finalize(proof)
}

fn verify_fs_inner(
    pp: &PublicParameters,
    commitment: &Protocol11Commitment,
    point: &[PaperField],
    claimed_value: PaperField,
    proof: &Protocol11Proof,
) -> Result<()> {
    validate_public_inputs(pp, commitment, point)?;
    if proof.protocol != PROTOCOL11_VERSION
        || proof.params_digest != pp.params_digest
        || proof.security_profile != pp.config.security
        || proof.eval_commitments.len() != pp.layout.workers
        || proof.worker_openings.len() != pp.layout.workers
    {
        return Err(Protocol11Error::InvalidProof(
            "protocol header or event order mismatch",
        ));
    }

    let (s1, s2) = point.split_at(pp.layout.row_bits);
    let mut transcript = statement_transcript(pp, commitment, point, claimed_value)?;
    let expected_a = transcript.challenge_fields(b"protocol11-a", pp.layout.rows);
    verify_eval_commitment_seeds(pp, commitment, point, &expected_a, &proof.eval_commitments)?;
    transcript.absorb(b"protocol11-eval-commitments", &proof.eval_commitments)?;
    let expected_indices = transcript.distinct_indices(
        b"protocol11-column-index",
        pp.security.column_queries,
        pp.layout.encoded_columns,
    )?;
    if proof.y1.len() != expected_indices.len() || proof.y2.len() != expected_indices.len() {
        return Err(Protocol11Error::InvalidProof("column challenge mismatch"));
    }

    let backend_s2 = backend_point_msb(s2);
    let mut aggregate_f2 = PaperField::from_int(0);
    let mut expected_y1 = vec![PaperField::from_int(0); expected_indices.len()];
    let mut expected_y2 = vec![PaperField::from_int(0); expected_indices.len()];
    for worker_id in 0..pp.layout.workers {
        let commitments = &proof.eval_commitments[worker_id];
        let openings = &proof.worker_openings[worker_id];
        if commitments.worker_id != worker_id || openings.worker_id != worker_id {
            return Err(Protocol11Error::InvalidProof("worker order mismatch"));
        }
        verify_source_columns(pp, &commitment.workers[worker_id], &openings.source_columns)?;
        verify_vector_opening(
            pp.params_digest,
            commitments.e1_merkle_root,
            b"protocol11-e1-vector",
            worker_id,
            pp.layout.encoded_columns,
            &openings.e1_columns,
        )?;
        verify_vector_opening(
            pp.params_digest,
            commitments.e2_merkle_root,
            b"protocol11-e2-vector",
            worker_id,
            pp.layout.encoded_columns,
            &openings.e2_columns,
        )?;
        if openings.source_columns.indices != expected_indices
            || openings.e1_columns.indices != expected_indices
            || openings.e2_columns.indices != expected_indices
        {
            return Err(Protocol11Error::InvalidProof("opening indices mismatch"));
        }
        for slot in 0..expected_indices.len() {
            let column = &openings.source_columns.columns[slot];
            if column.len() != pp.layout.rows_per_worker {
                return Err(Protocol11Error::InvalidProof(
                    "source column height mismatch",
                ));
            }
            let mut local_y1 = PaperField::from_int(0);
            let mut local_y2 = PaperField::from_int(0);
            for (local_row, value) in column.iter().enumerate() {
                let global_row = worker_id * pp.layout.rows_per_worker + local_row;
                local_y1 += expected_a[global_row] * *value;
                local_y2 += eq_index_msb(s1, global_row) * *value;
            }
            if openings.e1_columns.values[slot] != local_y1
                || openings.e2_columns.values[slot] != local_y2
            {
                return Err(Protocol11Error::InvalidProof(
                    "Protocol 7 column equation failed",
                ));
            }
            expected_y1[slot] += local_y1;
            expected_y2[slot] += local_y2;
        }
        pc_verify(pp, &commitments.f2, &backend_s2, &openings.f2_at_s2)?;
        aggregate_f2 += openings.f2_at_s2.value;
    }
    if expected_y1 != proof.y1 || expected_y2 != proof.y2 {
        return Err(Protocol11Error::InvalidProof(
            "Protocol 6 y1/y2 aggregate mismatch",
        ));
    }
    if aggregate_f2 != claimed_value {
        return Err(Protocol11Error::InvalidStatement);
    }
    transcript.absorb(
        b"protocol11-column-openings",
        &(&proof.worker_openings, &proof.y1, &proof.y2),
    )?;
    verify_protocol10(
        pp,
        &mut transcript,
        EncodingRelation::E1,
        &proof.eval_commitments,
        &proof.protocol10_e1,
    )?;
    verify_protocol10(
        pp,
        &mut transcript,
        EncodingRelation::E2,
        &proof.eval_commitments,
        &proof.protocol10_e2,
    )?;
    if transcript.digest() != proof.transcript_digest {
        return Err(Protocol11Error::InvalidProof(
            "final transcript digest mismatch",
        ));
    }
    Ok(())
}

pub fn proof_size_bytes(proof: &Protocol11Proof) -> Result<usize> {
    Ok(serialize_proof(proof)?.len())
}

pub fn serialize_commitment(commitment: &Protocol11Commitment) -> Result<Vec<u8>> {
    let body = canonical_options()
        .serialize(commitment)
        .map_err(|_| Protocol11Error::Serialization)?;
    let mut output = Vec::with_capacity(18 + body.len());
    output.extend_from_slice(COMMITMENT_MAGIC);
    output.extend_from_slice(&PROOF_SCHEMA.to_le_bytes());
    output.extend_from_slice(&(body.len() as u64).to_le_bytes());
    output.extend_from_slice(&body);
    Ok(output)
}

pub fn deserialize_commitment(bytes: &[u8]) -> Result<Protocol11Commitment> {
    if bytes.len() < 18 || &bytes[..8] != COMMITMENT_MAGIC {
        return Err(Protocol11Error::UnsupportedLegacyProtocol);
    }
    let schema = u16::from_le_bytes(bytes[8..10].try_into().expect("two bytes"));
    let body_len = u64::from_le_bytes(bytes[10..18].try_into().expect("eight bytes")) as usize;
    if schema != PROOF_SCHEMA || body_len > MAX_PROOF_BYTES || bytes.len() != 18 + body_len {
        return Err(Protocol11Error::Serialization);
    }
    let commitment = canonical_options()
        .reject_trailing_bytes()
        .deserialize(&bytes[18..])
        .map_err(|_| Protocol11Error::Serialization)?;
    if serialize_commitment(&commitment)? != bytes {
        return Err(Protocol11Error::Serialization);
    }
    Ok(commitment)
}

/// Stable, versioned proof envelope. The public statement remains external.
pub fn serialize_proof(proof: &Protocol11Proof) -> Result<Vec<u8>> {
    let body = canonical_options()
        .serialize(proof)
        .map_err(|_| Protocol11Error::Serialization)?;
    let mut output = Vec::with_capacity(PROOF_MAGIC.len() + 10 + body.len());
    output.extend_from_slice(PROOF_MAGIC);
    output.extend_from_slice(&PROOF_SCHEMA.to_le_bytes());
    output.extend_from_slice(&(body.len() as u64).to_le_bytes());
    output.extend_from_slice(&body);
    Ok(output)
}

pub fn deserialize_proof(bytes: &[u8]) -> Result<Protocol11Proof> {
    if bytes.len() < PROOF_MAGIC.len() + 10 || &bytes[..PROOF_MAGIC.len()] != PROOF_MAGIC {
        return Err(Protocol11Error::UnsupportedLegacyProtocol);
    }
    let schema = u16::from_le_bytes(bytes[8..10].try_into().expect("two bytes"));
    if schema != PROOF_SCHEMA {
        return Err(Protocol11Error::UnsupportedLegacyProtocol);
    }
    let body_len = u64::from_le_bytes(bytes[10..18].try_into().expect("eight bytes")) as usize;
    if body_len > MAX_PROOF_BYTES || bytes.len() != 18 + body_len {
        return Err(Protocol11Error::Serialization);
    }
    let proof: Protocol11Proof = canonical_options()
        .reject_trailing_bytes()
        .deserialize(&bytes[18..])
        .map_err(|_| Protocol11Error::Serialization)?;
    if serialize_proof(&proof)? != bytes {
        return Err(Protocol11Error::Serialization);
    }
    Ok(proof)
}

fn build_eval_material(
    pp: &PublicParameters,
    commitment: &Protocol11Commitment,
    point: &[PaperField],
    a: &[PaperField],
    worker: &WorkerProverState,
) -> Result<EvalMaterial> {
    let (s1, _) = point.split_at(pp.layout.row_bits);
    let mut f1 = vec![PaperField::from_int(0); pp.layout.columns];
    let mut f2 = vec![PaperField::from_int(0); pp.layout.columns];
    let mut e1 = vec![PaperField::from_int(0); pp.layout.encoded_columns];
    let mut e2 = vec![PaperField::from_int(0); pp.layout.encoded_columns];
    for local_row in 0..pp.layout.rows_per_worker {
        let global_row = worker.worker_id * pp.layout.rows_per_worker + local_row;
        let alpha = a[global_row];
        let beta = eq_index_msb(s1, global_row);
        for column in 0..pp.layout.columns {
            f1[column] += alpha * worker.rows[local_row][column];
            f2[column] += beta * worker.rows[local_row][column];
        }
        for column in 0..pp.layout.encoded_columns {
            e1[column] += alpha * worker.encoded_rows[local_row][column];
            e2[column] += beta * worker.encoded_rows[local_row][column];
        }
    }
    if codeword_to_paper(pp, &pp.code.encode(&f1)?)? != e1
        || codeword_to_paper(pp, &pp.code.encode(&f2)?)? != e2
    {
        return Err(Protocol11Error::InvalidProof(
            "linear encoding composition failed",
        ));
    }
    let base_seed = domain_digest(
        b"protocol11-pc-seed-base",
        &canonical_options()
            .serialize(&(pp.params_digest, commitment.root, point, a))
            .map_err(|_| Protocol11Error::Serialization)?,
    );
    let e1_pc = pc_commit(pp, &e1, pc_seed(base_seed, worker.worker_id, b"e1"))?;
    let f1_pc = pc_commit(pp, &f1, pc_seed(base_seed, worker.worker_id, b"f1"))?;
    let e2_pc = pc_commit(pp, &e2, pc_seed(base_seed, worker.worker_id, b"e2"))?;
    let f2_pc = pc_commit(pp, &f2, pc_seed(base_seed, worker.worker_id, b"f2"))?;
    let (e1_tree, _) = vector_tree(
        pp.params_digest,
        b"protocol11-e1-vector",
        worker.worker_id,
        &e1,
    );
    let (e2_tree, _) = vector_tree(
        pp.params_digest,
        b"protocol11-e2-vector",
        worker.worker_id,
        &e2,
    );
    Ok(EvalMaterial {
        worker_id: worker.worker_id,
        e1,
        f1,
        e2,
        f2,
        commitments: WorkerEvalCommitments {
            worker_id: worker.worker_id,
            e1: e1_pc,
            f1: f1_pc,
            e2: e2_pc,
            f2: f2_pc,
            e1_merkle_root: e1_tree.commit(),
            e2_merkle_root: e2_tree.commit(),
        },
    })
}

fn prove_protocol10(
    pp: &PublicParameters,
    transcript: &mut Transcript,
    relation: EncodingRelation,
    materials: &[EvalMaterial],
) -> Result<Protocol10Proof> {
    let relation_label = match relation {
        EncodingRelation::E1 => b"protocol10-e1".as_slice(),
        EncodingRelation::E2 => b"protocol10-e2".as_slice(),
    };
    transcript.absorb(b"protocol10-relation-kind", &relation)?;
    let u = transcript.challenge_fields(b"protocol10-u", pp.layout.column_bits);
    let hu = codeword_to_paper(pp, &pp.code.hu(&u)?)?;
    let hu_seed = domain_digest(relation_label, &transcript.digest());
    let hu_commitment = pc_commit(pp, &hu, hu_seed)?;
    transcript.absorb(b"protocol10-hu-commitment", &hu_commitment)?;

    let mut e_tables = materials
        .iter()
        .map(|material| match relation {
            EncodingRelation::E1 => material.e1.clone(),
            EncodingRelation::E2 => material.e2.clone(),
        })
        .collect::<Vec<_>>();
    let mut hu_table = hu.clone();
    let initial_claim = e_tables
        .iter()
        .flat_map(|table| table.iter().zip(&hu_table))
        .fold(PaperField::from_int(0), |acc, (e, h)| acc + *e * *h);
    if !initial_claim.is_zero() {
        return Err(Protocol11Error::InvalidProof(
            "encoding parity relation is non-zero",
        ));
    }
    let mut claim = initial_claim;
    let mut rounds = Vec::with_capacity(pp.layout.column_bits + 1);
    let mut r = Vec::with_capacity(pp.layout.column_bits + 1);
    while hu_table.len() > 1 {
        let mut evaluations = [PaperField::from_int(0); 3];
        for e_table in &e_tables {
            let local = product_round_evaluations(e_table, &hu_table)?;
            for index in 0..3 {
                evaluations[index] += local[index];
            }
        }
        if claim != evaluations[0] + evaluations[1] {
            return Err(Protocol11Error::InvalidProof(
                "prover sumcheck invariant failed",
            ));
        }
        let round = SumcheckRound { evaluations };
        transcript.absorb(b"protocol10-sumcheck-round", &round)?;
        let challenge = transcript.challenge_field(b"protocol10-r");
        claim = quadratic_eval(evaluations, challenge);
        for e_table in &mut e_tables {
            *e_table = fold_table(e_table, challenge)?;
        }
        hu_table = fold_table(&hu_table, challenge)?;
        rounds.push(round);
        r.push(challenge);
    }

    let hu_at_r = pc_open(pp, &hu, &hu_commitment, &r)?;
    let mut e_at_r_openings = Vec::with_capacity(materials.len());
    for material in materials {
        let (e_values, e_commitment) = match relation {
            EncodingRelation::E1 => (&material.e1, &material.commitments.e1),
            EncodingRelation::E2 => (&material.e2, &material.commitments.e2),
        };
        let e_at_r = pc_open(pp, e_values, e_commitment, &r)?;
        e_at_r_openings.push((material.worker_id, e_at_r));
    }
    transcript.absorb(
        b"protocol10-final-openings",
        &(
            &hu_at_r,
            e_at_r_openings
                .iter()
                .map(|item| &item.1)
                .collect::<Vec<_>>(),
        ),
    )?;
    let u_prime = transcript.challenge_fields(b"protocol10-u-prime", pp.layout.column_bits);
    let f_point = backend_point_msb(&u_prime);
    let mut paper_e_point = u_prime.clone();
    paper_e_point.push(PaperField::from_int(0));
    let e_point = backend_point_msb(&paper_e_point);
    let mut worker_openings = Vec::with_capacity(materials.len());
    for (material, (worker_id, e_at_r)) in materials.iter().zip(e_at_r_openings) {
        let (e_values, f_values, e_commitment, f_commitment) = match relation {
            EncodingRelation::E1 => (
                &material.e1,
                &material.f1,
                &material.commitments.e1,
                &material.commitments.f1,
            ),
            EncodingRelation::E2 => (
                &material.e2,
                &material.f2,
                &material.commitments.e2,
                &material.commitments.f2,
            ),
        };
        worker_openings.push(WorkerRelationOpenings {
            worker_id,
            e_at_r,
            f_at_u_prime: pc_open(pp, f_values, f_commitment, &f_point)?,
            e_at_systematic: pc_open(pp, e_values, e_commitment, &e_point)?,
        });
    }
    let proof = Protocol10Proof {
        relation,
        hu_commitment,
        rounds,
        hu_at_r,
        worker_openings,
    };
    transcript.absorb(b"protocol10-proof-tail", &proof.worker_openings)?;
    Ok(proof)
}

fn verify_protocol10(
    pp: &PublicParameters,
    transcript: &mut Transcript,
    relation: EncodingRelation,
    commitments: &[WorkerEvalCommitments],
    proof: &Protocol10Proof,
) -> Result<()> {
    if proof.relation != relation
        || proof.worker_openings.len() != pp.layout.workers
        || proof.rounds.len() != pp.layout.column_bits + 1
    {
        return Err(Protocol11Error::InvalidProof("Protocol 10 shape mismatch"));
    }
    transcript.absorb(b"protocol10-relation-kind", &relation)?;
    let expected_u = transcript.challenge_fields(b"protocol10-u", pp.layout.column_bits);
    let hu = codeword_to_paper(pp, &pp.code.hu(&expected_u)?)?;
    let relation_label = match relation {
        EncodingRelation::E1 => b"protocol10-e1".as_slice(),
        EncodingRelation::E2 => b"protocol10-e2".as_slice(),
    };
    let expected_seed = domain_digest(relation_label, &transcript.digest());
    let expected_hu_commitment = pc_commit(pp, &hu, expected_seed)?;
    if canonical_options()
        .serialize(&expected_hu_commitment)
        .map_err(|_| Protocol11Error::Serialization)?
        != canonical_options()
            .serialize(&proof.hu_commitment)
            .map_err(|_| Protocol11Error::Serialization)?
    {
        return Err(Protocol11Error::InvalidProof("H_u commitment mismatch"));
    }
    transcript.absorb(b"protocol10-hu-commitment", &proof.hu_commitment)?;

    let mut claim = PaperField::from_int(0);
    let mut expected_r = Vec::with_capacity(proof.rounds.len());
    for round in &proof.rounds {
        if claim != round.evaluations[0] + round.evaluations[1] {
            return Err(Protocol11Error::InvalidProof(
                "sumcheck round equation failed",
            ));
        }
        transcript.absorb(b"protocol10-sumcheck-round", round)?;
        let challenge = transcript.challenge_field(b"protocol10-r");
        claim = quadratic_eval(round.evaluations, challenge);
        expected_r.push(challenge);
    }
    pc_verify(pp, &proof.hu_commitment, &expected_r, &proof.hu_at_r)?;
    let mut e_at_r = PaperField::from_int(0);
    for (worker_id, (opening, commitments)) in
        proof.worker_openings.iter().zip(commitments).enumerate()
    {
        let commitment = match relation {
            EncodingRelation::E1 => &commitments.e1,
            EncodingRelation::E2 => &commitments.e2,
        };
        if opening.worker_id != worker_id {
            return Err(Protocol11Error::InvalidProof(
                "Protocol 10 worker order mismatch",
            ));
        }
        pc_verify(pp, commitment, &expected_r, &opening.e_at_r)?;
        e_at_r += opening.e_at_r.value;
    }
    if claim != e_at_r * proof.hu_at_r.value {
        return Err(Protocol11Error::InvalidProof(
            "sumcheck terminal product failed",
        ));
    }
    transcript.absorb(
        b"protocol10-final-openings",
        &(
            &proof.hu_at_r,
            proof
                .worker_openings
                .iter()
                .map(|item| &item.e_at_r)
                .collect::<Vec<_>>(),
        ),
    )?;
    let expected_u_prime =
        transcript.challenge_fields(b"protocol10-u-prime", pp.layout.column_bits);
    let f_point = backend_point_msb(&expected_u_prime);
    let mut paper_e_point = expected_u_prime.clone();
    paper_e_point.push(PaperField::from_int(0));
    let e_point = backend_point_msb(&paper_e_point);
    let mut f_value = PaperField::from_int(0);
    let mut e_value = PaperField::from_int(0);
    for (opening, commitments) in proof.worker_openings.iter().zip(commitments) {
        let (e_commitment, f_commitment) = match relation {
            EncodingRelation::E1 => (&commitments.e1, &commitments.f1),
            EncodingRelation::E2 => (&commitments.e2, &commitments.f2),
        };
        pc_verify(pp, f_commitment, &f_point, &opening.f_at_u_prime)?;
        pc_verify(pp, e_commitment, &e_point, &opening.e_at_systematic)?;
        f_value += opening.f_at_u_prime.value;
        e_value += opening.e_at_systematic.value;
    }
    if f_value != e_value {
        return Err(Protocol11Error::InvalidProof(
            "systematic encoding equality failed",
        ));
    }
    transcript.absorb(b"protocol10-proof-tail", &proof.worker_openings)?;
    Ok(())
}

fn pc_commit(pp: &PublicParameters, values: &[PaperField], seed: [u8; 32]) -> Result<PcCommitment> {
    if values.is_empty() || !values.len().is_power_of_two() {
        return Err(Protocol11Error::InvalidLayout(
            "PCS vector must be a non-empty power of two",
        ));
    }
    let nv = values.len().trailing_zeros() as usize;
    let oracle = compact_codec::oracle_from_seed(seed, nv, pp.security.pcs_queries);
    let config = backend_config()?;
    let prover = prepare_prover(config, nv, mle_coefficients(values), &oracle);
    Ok(PcCommitment {
        nv,
        oracle_seed: seed,
        commitment: prover.commitment(),
    })
}

fn pc_open(
    pp: &PublicParameters,
    values: &[PaperField],
    commitment: &PcCommitment,
    point: &[PaperField],
) -> Result<PcOpening> {
    if point.len() != commitment.nv || values.len() != (1usize << commitment.nv) {
        return Err(Protocol11Error::InvalidProof(
            "PCS opening point/vector shape mismatch",
        ));
    }
    let oracle = compact_codec::oracle_from_seed(
        commitment.oracle_seed,
        commitment.nv,
        pp.security.pcs_queries,
    );
    let (proof, value) = open_polynomial(
        backend_config()?,
        commitment.nv,
        mle_coefficients(values),
        point,
        &commitment.commitment,
        &oracle,
    )?;
    Ok(PcOpening { value, proof })
}

fn pc_verify(
    pp: &PublicParameters,
    commitment: &PcCommitment,
    point: &[PaperField],
    opening: &PcOpening,
) -> Result<()> {
    if commitment.nv >= usize::BITS as usize
        || point.len() != commitment.nv
        || (1usize << commitment.nv) < pp.security.pcs_queries
    {
        return Err(Protocol11Error::InvalidProof(
            "PCS verifier point shape mismatch",
        ));
    }
    let oracle = compact_codec::oracle_from_seed(
        commitment.oracle_seed,
        commitment.nv,
        pp.security.pcs_queries,
    );
    verify_evaluation(
        backend_config()?,
        commitment.nv,
        &commitment.commitment,
        point,
        opening.value,
        &opening.proof,
        &oracle,
    )?;
    Ok(())
}

fn backend_config() -> Result<PaperDepcsConfig> {
    PaperDepcsConfig::new(PaperPcsBackend::DeepFold, 2).map_err(Protocol11Error::Backend)
}

fn encoded_column_tree(
    pp: &PublicParameters,
    worker_id: usize,
    encoded_rows: &[Vec<PaperField>],
) -> Result<MerkleTreeProver> {
    if encoded_rows.len() != pp.layout.rows_per_worker
        || encoded_rows
            .iter()
            .any(|row| row.len() != pp.layout.encoded_columns)
    {
        return Err(Protocol11Error::InvalidShard(
            "encoded matrix shape mismatch",
        ));
    }
    let leaves = (0..pp.layout.encoded_columns)
        .map(|column| {
            let values = encoded_rows
                .iter()
                .map(|row| row[column])
                .collect::<Vec<_>>();
            source_column_hash(pp.params_digest, worker_id, column, &values)
        })
        .collect::<Vec<_>>();
    Ok(MerkleTreeProver::from_leaf_hashes(
        leaves,
        pp.layout.encoded_columns,
    ))
}

fn open_source_columns(
    pp: &PublicParameters,
    worker: &WorkerProverState,
    indices: &[usize],
) -> Result<ColumnOpening> {
    let tree = encoded_column_tree(pp, worker.worker_id, &worker.encoded_rows)?;
    let columns = indices
        .iter()
        .map(|column| {
            worker
                .encoded_rows
                .iter()
                .map(|row| row[*column])
                .collect::<Vec<_>>()
        })
        .collect();
    Ok(ColumnOpening {
        indices: indices.to_vec(),
        columns,
        proof_bytes: tree.open(indices),
    })
}

fn verify_source_columns(
    pp: &PublicParameters,
    commitment: &WorkerCommitment,
    opening: &ColumnOpening,
) -> Result<()> {
    if opening.indices.len() != opening.columns.len()
        || !strictly_increasing_in_domain(&opening.indices, pp.layout.encoded_columns)
    {
        return Err(Protocol11Error::InvalidProof(
            "invalid source-column indices",
        ));
    }
    let hashes = opening
        .indices
        .iter()
        .zip(&opening.columns)
        .map(|(column, values)| {
            source_column_hash(pp.params_digest, commitment.worker_id, *column, values)
        })
        .collect::<Vec<_>>();
    let verifier = MerkleTreeVerifier::new(pp.layout.encoded_columns, &commitment.column_root);
    let valid = catch_unwind(AssertUnwindSafe(|| {
        verifier.verify_with_leaf_hashes(&opening.proof_bytes, &opening.indices, &hashes)
    }))
    .unwrap_or(false);
    if !valid {
        return Err(Protocol11Error::InvalidProof(
            "source-column Merkle proof failed",
        ));
    }
    Ok(())
}

fn vector_tree(
    params_digest: [u8; 32],
    label: &[u8],
    worker_id: usize,
    values: &[PaperField],
) -> (MerkleTreeProver, Vec<Vec<u8>>) {
    let leaves = values
        .iter()
        .enumerate()
        .map(|(index, value)| {
            vector_leaf_bytes(params_digest, label, worker_id, values.len(), index, *value)
        })
        .collect::<Vec<_>>();
    (MerkleTreeProver::new(leaves.clone()), leaves)
}

fn verify_vector_opening(
    params_digest: [u8; 32],
    root: MerkleHash,
    label: &[u8],
    worker_id: usize,
    domain: usize,
    opening: &VectorMerkleOpening,
) -> Result<()> {
    if opening.indices.len() != opening.values.len()
        || !strictly_increasing_in_domain(&opening.indices, domain)
    {
        return Err(Protocol11Error::InvalidProof(
            "invalid vector-opening indices",
        ));
    }
    let leaves = opening
        .indices
        .iter()
        .zip(&opening.values)
        .map(|(index, value)| {
            vector_leaf_bytes(params_digest, label, worker_id, domain, *index, *value)
        })
        .collect::<Vec<_>>();
    let verifier = MerkleTreeVerifier::new(domain, &root);
    let valid = catch_unwind(AssertUnwindSafe(|| {
        verifier.verify(&opening.proof_bytes, &opening.indices, &leaves)
    }))
    .unwrap_or(false);
    if !valid {
        return Err(Protocol11Error::InvalidProof("vector Merkle proof failed"));
    }
    Ok(())
}

fn vector_leaf_bytes(
    params_digest: [u8; 32],
    label: &[u8],
    worker_id: usize,
    domain: usize,
    index: usize,
    value: PaperField,
) -> Vec<u8> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&params_digest);
    push_bytes(&mut bytes, label);
    bytes.extend_from_slice(&(worker_id as u64).to_le_bytes());
    bytes.extend_from_slice(&(domain as u64).to_le_bytes());
    bytes.extend_from_slice(&(index as u64).to_le_bytes());
    bytes.extend_from_slice(&value.to_full_bytes());
    bytes
}

fn source_column_hash(
    params_digest: [u8; 32],
    worker_id: usize,
    column: usize,
    values: &[PaperField],
) -> MerkleHash {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&params_digest);
    bytes.extend_from_slice(&(worker_id as u64).to_le_bytes());
    bytes.extend_from_slice(&(column as u64).to_le_bytes());
    bytes.extend_from_slice(&(values.len() as u64).to_le_bytes());
    for value in values {
        bytes.extend_from_slice(&value.to_full_bytes());
    }
    domain_digest(b"protocol11-source-column", &bytes)
}

fn statement_transcript(
    pp: &PublicParameters,
    commitment: &Protocol11Commitment,
    point: &[PaperField],
    claimed_value: PaperField,
) -> Result<Transcript> {
    let mut transcript = Transcript::new();
    transcript.absorb(
        b"statement",
        &(
            pp.params_digest,
            commitment.root,
            point,
            claimed_value,
            PROTOCOL11_FIDELITY,
        ),
    )?;
    Ok(transcript)
}

fn validate_public_inputs(
    pp: &PublicParameters,
    commitment: &Protocol11Commitment,
    point: &[PaperField],
) -> Result<()> {
    let expected_pp = setup(pp.config, pp.setup_seed)?;
    if pp.protocol != PROTOCOL11_VERSION
        || pp.params_digest != expected_pp.params_digest
        || pp.layout != expected_pp.layout
        || pp.code != expected_pp.code
        || pp.security != expected_pp.security
        || commitment.protocol != PROTOCOL11_VERSION
        || commitment.params_digest != pp.params_digest
        || point.len() != pp.layout.nv
        || commitment.workers.len() != pp.layout.workers
    {
        return Err(Protocol11Error::InvalidStatement);
    }
    let expected = aggregate_commitments(pp, commitment.workers.clone())?;
    if expected.root != commitment.root {
        return Err(Protocol11Error::InvalidCommitment(
            "worker-set root mismatch",
        ));
    }
    Ok(())
}

fn validate_worker_states(
    pp: &PublicParameters,
    commitment: &Protocol11Commitment,
    workers: &[WorkerProverState],
) -> Result<()> {
    if workers.len() != pp.layout.workers {
        return Err(Protocol11Error::InvalidShard("worker-state count mismatch"));
    }
    for (worker_id, (worker, commitment)) in workers.iter().zip(&commitment.workers).enumerate() {
        if worker.worker_id != worker_id
            || worker.rows.len() != pp.layout.rows_per_worker
            || worker.encoded_rows.len() != pp.layout.rows_per_worker
        {
            return Err(Protocol11Error::InvalidShard(
                "worker-state order or shape mismatch",
            ));
        }
        let tree = encoded_column_tree(pp, worker_id, &worker.encoded_rows)?;
        if tree.commit() != commitment.column_root {
            return Err(Protocol11Error::InvalidCommitment(
                "worker state does not match root",
            ));
        }
    }
    Ok(())
}

fn evaluate_worker_rows(
    pp: &PublicParameters,
    workers: &[WorkerProverState],
    s1: &[PaperField],
    s2: &[PaperField],
) -> PaperField {
    let mut value = PaperField::from_int(0);
    for worker in workers {
        for (local_row, row) in worker.rows.iter().enumerate() {
            let global_row = worker.worker_id * pp.layout.rows_per_worker + local_row;
            let row_weight = eq_index_msb(s1, global_row);
            let row_value = row
                .iter()
                .enumerate()
                .fold(PaperField::from_int(0), |acc, (column, entry)| {
                    acc + *entry * eq_index_msb(s2, column)
                });
            value += row_weight * row_value;
        }
    }
    value
}

fn product_round_evaluations(left: &[PaperField], right: &[PaperField]) -> Result<[PaperField; 3]> {
    if left.len() != right.len() || left.len() < 2 || !left.len().is_power_of_two() {
        return Err(Protocol11Error::InvalidProof(
            "invalid sumcheck table shape",
        ));
    }
    let mut result = [PaperField::from_int(0); 3];
    for pair in 0..left.len() / 2 {
        let l0 = left[2 * pair];
        let l1 = left[2 * pair + 1];
        let r0 = right[2 * pair];
        let r1 = right[2 * pair + 1];
        result[0] += l0 * r0;
        result[1] += l1 * r1;
        let l2 = l0 + (l1 - l0) * PaperField::from_int(2);
        let r2 = r0 + (r1 - r0) * PaperField::from_int(2);
        result[2] += l2 * r2;
    }
    Ok(result)
}

fn fold_table(values: &[PaperField], challenge: PaperField) -> Result<Vec<PaperField>> {
    if values.len() < 2 || !values.len().is_power_of_two() {
        return Err(Protocol11Error::InvalidProof("invalid fold table shape"));
    }
    Ok(values
        .chunks_exact(2)
        .map(|pair| pair[0] + (pair[1] - pair[0]) * challenge)
        .collect())
}

fn quadratic_eval(values: [PaperField; 3], x: PaperField) -> PaperField {
    let inv2 = PaperField::inverse_2();
    let two = PaperField::from_int(2);
    let l0 = (x - PaperField::from_int(1)) * (x - two) * inv2;
    let l1 = -(x * (x - two));
    let l2 = x * (x - PaperField::from_int(1)) * inv2;
    values[0] * l0 + values[1] * l1 + values[2] * l2
}

fn backend_point_msb(point: &[PaperField]) -> Vec<PaperField> {
    point.iter().rev().copied().collect()
}

fn codeword_to_paper(pp: &PublicParameters, codeword: &[PaperField]) -> Result<Vec<PaperField>> {
    if codeword.len() != pp.layout.encoded_columns {
        return Err(Protocol11Error::InvalidLayout(
            "codeword permutation length mismatch",
        ));
    }
    let mut paper = vec![PaperField::from_int(0); codeword.len()];
    for (index, value) in codeword.iter().enumerate() {
        paper[pp.layout.codeword_to_paper_index(index)?] = *value;
    }
    Ok(paper)
}

/// Convert a Boolean-hypercube evaluation table into the multilinear monomial
/// coefficients expected by the vendored DeepFold implementation. Numeric
/// indices use the backend's low-bit-first variable order.
fn mle_coefficients(evaluations: &[PaperField]) -> Vec<PaperField> {
    let mut coefficients = evaluations.to_vec();
    let bits = evaluations.len().trailing_zeros() as usize;
    for bit in 0..bits {
        for mask in 0..coefficients.len() {
            if mask & (1 << bit) != 0 {
                let lower = coefficients[mask ^ (1 << bit)];
                coefficients[mask] -= lower;
            }
        }
    }
    coefficients
}

fn eq_index_msb(point: &[PaperField], index: usize) -> PaperField {
    point
        .iter()
        .enumerate()
        .fold(PaperField::from_int(1), |acc, (position, challenge)| {
            let bit = (index >> (point.len() - position - 1)) & 1;
            if bit == 0 {
                acc * (PaperField::from_int(1) - *challenge)
            } else {
                acc * *challenge
            }
        })
}

fn setup_block(
    seed: [u8; 32],
    label: &[u8],
    purpose: &[u8],
    level: usize,
    row: usize,
    edge: usize,
) -> [u8; 32] {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(b"pq-dpcs/protocol11/brakedown-setup/v2");
    bytes.extend_from_slice(&seed);
    push_bytes(&mut bytes, label);
    push_bytes(&mut bytes, purpose);
    bytes.extend_from_slice(&(level as u64).to_le_bytes());
    bytes.extend_from_slice(&(row as u64).to_le_bytes());
    bytes.extend_from_slice(&(edge as u64).to_le_bytes());
    sha256(&bytes)
}

fn pc_seed(base: [u8; 32], worker_id: usize, label: &[u8]) -> [u8; 32] {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&base);
    bytes.extend_from_slice(&(worker_id as u64).to_le_bytes());
    push_bytes(&mut bytes, label);
    domain_digest(b"protocol11-deepfold-oracle", &bytes)
}

fn verify_eval_commitment_seeds(
    pp: &PublicParameters,
    commitment: &Protocol11Commitment,
    point: &[PaperField],
    a: &[PaperField],
    commitments: &[WorkerEvalCommitments],
) -> Result<()> {
    let base = domain_digest(
        b"protocol11-pc-seed-base",
        &canonical_options()
            .serialize(&(pp.params_digest, commitment.root, point, a))
            .map_err(|_| Protocol11Error::Serialization)?,
    );
    for (worker_id, worker) in commitments.iter().enumerate() {
        let expected = [
            (&worker.e1, b"e1".as_slice(), pp.layout.column_bits + 1),
            (&worker.f1, b"f1".as_slice(), pp.layout.column_bits),
            (&worker.e2, b"e2".as_slice(), pp.layout.column_bits + 1),
            (&worker.f2, b"f2".as_slice(), pp.layout.column_bits),
        ];
        if worker.worker_id != worker_id
            || expected.iter().any(|(pc, label, nv)| {
                pc.nv != *nv || pc.oracle_seed != pc_seed(base, worker_id, label)
            })
        {
            return Err(Protocol11Error::InvalidProof(
                "DeepFold commitment oracle is not transcript-derived",
            ));
        }
    }
    Ok(())
}

fn canonical_options() -> impl Options {
    bincode::DefaultOptions::new().with_fixint_encoding()
}

fn domain_digest(label: &[u8], body: &[u8]) -> [u8; 32] {
    let mut bytes = Vec::new();
    push_bytes(&mut bytes, label);
    push_bytes(&mut bytes, body);
    sha256(&bytes)
}

fn push_bytes(out: &mut Vec<u8>, bytes: &[u8]) {
    out.extend_from_slice(&(bytes.len() as u64).to_le_bytes());
    out.extend_from_slice(bytes);
}

fn ceil_log2(value: usize) -> usize {
    if value <= 1 {
        0
    } else {
        usize::BITS as usize - (value - 1).leading_zeros() as usize
    }
}

fn strictly_increasing_in_domain(indices: &[usize], domain: usize) -> bool {
    indices.iter().all(|index| *index < domain)
        && indices.windows(2).all(|window| window[0] < window[1])
}

#[cfg(test)]
mod tests {
    use super::*;

    fn value(index: usize) -> PaperField {
        PaperField::from_parts(index as u64 * 17 + 3, index as u64 * 29 + 5)
    }

    fn test_config(nv: usize, workers: usize, queries: usize) -> Protocol11Config {
        Protocol11Config {
            original_len: 1 << nv,
            workers,
            security: SecurityProfile::TestOnly { queries },
        }
    }

    #[test]
    fn layout_uses_padded_rows_per_worker() {
        let layout = PaperLayout::derive(1 << 10, 4).unwrap();
        assert_eq!(layout.rows_per_worker, 8);
        assert_eq!(layout.rows, 32);
        assert_eq!(layout.columns, 32);
        assert_eq!(layout.encoded_columns, 64);
        for index in 0..layout.encoded_columns {
            let paper = layout.codeword_to_paper_index(index).unwrap();
            assert_eq!(layout.paper_to_codeword_index(paper).unwrap(), index);
        }
    }

    #[test]
    fn brakedown_code_is_systematic_and_has_zero_syndrome() {
        let pp = setup(test_config(8, 2, 2), [7_u8; 32]).unwrap();
        let message = (0..pp.layout.columns).map(value).collect::<Vec<_>>();
        let encoded = pp.code.encode(&message).unwrap();
        assert_eq!(&encoded[..message.len()], message.as_slice());
        assert!(pp.code.is_codeword(&encoded).unwrap());
        let mut tampered = encoded;
        tampered[pp.layout.columns] += PaperField::from_int(1);
        assert!(!pp.code.is_codeword(&tampered).unwrap());
    }

    #[test]
    fn brakedown_equation_degrees_are_pinned() {
        assert_eq!(brakedown_cn(4), 5);
        assert_eq!(brakedown_cn(64), 11);
        assert_eq!(brakedown_cn(1024), 10);
        assert_eq!(brakedown_dn(4), 2);
        assert_eq!(brakedown_dn(64), 14);
        assert_eq!(brakedown_dn(512), 21);

        let pp = setup(test_config(15, 2, 2), [8_u8; 32]).unwrap();
        let BrakedownLevel::Recursive {
            a_degree,
            b_degree,
            a_rows,
            b_rows,
            ..
        } = &pp.code.root
        else {
            panic!("expected recursive Brakedown code");
        };
        assert_eq!((*a_degree, *b_degree), (10, 21));
        assert!(a_rows.iter().all(|row| row.len() == *a_degree));
        assert!(b_rows.iter().all(|row| row.len() == *b_degree));
    }

    #[test]
    fn global_and_sharded_commitments_match() {
        let pp = setup(test_config(8, 2, 2), [9_u8; 32]).unwrap();
        let evaluations = (0..pp.layout.original_len).map(value).collect::<Vec<_>>();
        let (global, global_states) = commit_global(&pp, evaluations.clone()).unwrap();
        let rows = evaluations
            .chunks_exact(pp.layout.columns)
            .map(<[PaperField]>::to_vec)
            .collect::<Vec<_>>();
        let mut commitments = Vec::new();
        let mut sharded_states = Vec::new();
        for worker_id in 0..pp.layout.workers {
            let start = worker_id * pp.layout.rows_per_worker;
            let shard = WorkerShard {
                worker_id,
                rows: rows[start..start + pp.layout.rows_per_worker].to_vec(),
            };
            let (worker_commitment, state) = commit_worker(&pp, shard).unwrap();
            commitments.push(worker_commitment);
            sharded_states.push(state);
        }
        let sharded = aggregate_commitments(&pp, commitments).unwrap();
        assert_eq!(global.root, sharded.root);
        let point = vec![PaperField::from_parts(2, 7); pp.layout.nv];
        let (global_value, global_proof) = prove_fs(&pp, &global, global_states, &point).unwrap();
        let (sharded_value, sharded_proof) =
            prove_fs(&pp, &sharded, sharded_states, &point).unwrap();
        assert_eq!(global_value, sharded_value);
        assert_eq!(
            serialize_proof(&global_proof).unwrap(),
            serialize_proof(&sharded_proof).unwrap()
        );
    }

    #[test]
    fn protocol11_fs_roundtrip_and_statement_tamper() {
        let pp = setup(test_config(8, 2, 2), [11_u8; 32]).unwrap();
        let evaluations = (0..pp.layout.original_len).map(value).collect::<Vec<_>>();
        let (commitment, states) = commit_global(&pp, evaluations).unwrap();
        let point = (0..pp.layout.nv)
            .map(|index| PaperField::from_parts(index as u64 + 2, index as u64 + 13))
            .collect::<Vec<_>>();
        let (claimed_value, proof) = prove_fs(&pp, &commitment, states, &point).unwrap();
        verify_fs(&pp, &commitment, &point, claimed_value, &proof).unwrap();
        assert!(
            verify_fs(
                &pp,
                &commitment,
                &point,
                claimed_value + PaperField::from_int(1),
                &proof,
            )
            .is_err()
        );
        let mut other_point = point.clone();
        other_point[0] += PaperField::from_int(1);
        assert!(verify_fs(&pp, &commitment, &other_point, claimed_value, &proof).is_err());
    }

    #[test]
    fn protocol11_rejects_sumcheck_tamper() {
        let pp = setup(test_config(8, 2, 2), [13_u8; 32]).unwrap();
        let evaluations = (0..pp.layout.original_len).map(value).collect::<Vec<_>>();
        let (commitment, states) = commit_global(&pp, evaluations).unwrap();
        let point = (0..pp.layout.nv)
            .map(|index| PaperField::from_parts(index as u64 + 4, index as u64 + 19))
            .collect::<Vec<_>>();
        let (claimed_value, mut proof) = prove_fs(&pp, &commitment, states, &point).unwrap();
        proof.protocol10_e1.rounds[0].evaluations[0] += PaperField::from_int(1);
        assert!(verify_fs(&pp, &commitment, &point, claimed_value, &proof).is_err());
    }

    #[test]
    fn vector_merkle_binds_extension_image_component() {
        let a = PaperField::from_parts(5, 7);
        let b = PaperField::from_parts(5, 8);
        let (tree_a, _) = vector_tree([0_u8; 32], b"field-binding", 0, &[a, a]);
        let (tree_b, _) = vector_tree([0_u8; 32], b"field-binding", 0, &[b, a]);
        assert_ne!(tree_a.commit(), tree_b.commit());
    }

    #[test]
    fn field_deserializer_rejects_noncanonical_encoding() {
        let modulus_le = [
            0x01, 0x00, 0x00, 0x00, 0x00, 0xf2, 0xa4, 0x02, 0x30, 0x5f, 0x59, 0x86, 0x90, 0xc7,
            0x73, 0xef, 0x69, 0x59, 0x57, 0xb9, 0x04, 0xdf, 0xa9, 0xfd, 0x00, 0x29, 0x4d, 0x6e,
            0x9b, 0x79, 0x3c, 0x66,
        ];
        assert_eq!(PaperField::try_from_full_bytes(modulus_le), None);
        let bytes = bincode::serialize(&modulus_le).unwrap();
        let decoded = bincode::deserialize::<PaperField>(&bytes);
        assert!(
            decoded.is_err(),
            "decoded noncanonical field as {decoded:?}"
        );
    }

    #[test]
    fn proof_encoding_is_versioned_canonical_and_rejects_legacy() {
        let pp = setup(test_config(8, 2, 2), [17_u8; 32]).unwrap();
        let evaluations = (0..pp.layout.original_len).map(value).collect::<Vec<_>>();
        let (commitment, states) = commit_global(&pp, evaluations).unwrap();
        let point = vec![PaperField::from_parts(7, 9); pp.layout.nv];
        let (_, proof) = prove_fs(&pp, &commitment, states, &point).unwrap();
        let encoded = serialize_proof(&proof).unwrap();
        let decoded = deserialize_proof(&encoded).unwrap();
        assert_eq!(serialize_proof(&decoded).unwrap(), encoded);
        let encoded_commitment = serialize_commitment(&commitment).unwrap();
        let decoded_commitment = deserialize_commitment(&encoded_commitment).unwrap();
        assert_eq!(
            serialize_commitment(&decoded_commitment).unwrap(),
            encoded_commitment
        );
        let legacy = bincode::serialize(&proof).unwrap();
        assert!(matches!(
            deserialize_proof(&legacy),
            Err(Protocol11Error::UnsupportedLegacyProtocol)
        ));
        let mut trailing = encoded;
        trailing.push(0);
        assert!(deserialize_proof(&trailing).is_err());
    }

    #[test]
    fn verifier_rejects_prover_selected_oracle_and_bad_merkle_path() {
        let pp = setup(test_config(8, 2, 2), [19_u8; 32]).unwrap();
        let evaluations = (0..pp.layout.original_len).map(value).collect::<Vec<_>>();
        let (commitment, states) = commit_global(&pp, evaluations).unwrap();
        let point = vec![PaperField::from_parts(11, 13); pp.layout.nv];
        let (claimed_value, proof) = prove_fs(&pp, &commitment, states, &point).unwrap();

        let mut bad_seed = proof.clone();
        bad_seed.eval_commitments[0].e1.oracle_seed[0] ^= 1;
        assert!(verify_fs(&pp, &commitment, &point, claimed_value, &bad_seed).is_err());

        let mut bad_systematic = proof.clone();
        bad_systematic.protocol10_e2.worker_openings[0]
            .e_at_systematic
            .value += PaperField::from_int(1);
        assert!(verify_fs(&pp, &commitment, &point, claimed_value, &bad_systematic,).is_err());

        let mut bad_path = proof;
        bad_path.worker_openings[0].source_columns.proof_bytes[0] ^= 1;
        assert!(verify_fs(&pp, &commitment, &point, claimed_value, &bad_path).is_err());

        let (_, states) = commit_global(
            &pp,
            (0..pp.layout.original_len).map(value).collect::<Vec<_>>(),
        )
        .unwrap();
        let (_, mut bad_image) = prove_fs(&pp, &commitment, states, &point).unwrap();
        bad_image.worker_openings[0].f2_at_s2.value += PaperField::from_parts(0, 1);
        assert!(verify_fs(&pp, &commitment, &point, claimed_value, &bad_image).is_err());
    }

    #[test]
    fn interactive_verifier_enforces_message_order() {
        let pp = setup(test_config(8, 2, 2), [23_u8; 32]).unwrap();
        let evaluations = (0..pp.layout.original_len).map(value).collect::<Vec<_>>();
        let (commitment, states) = commit_global(&pp, evaluations).unwrap();
        let point = vec![PaperField::from_parts(3, 15); pp.layout.nv];
        let (_, fs_proof) = prove_fs(&pp, &commitment, states.clone(), &point).unwrap();
        let (claimed_value, proof) = Protocol11ProverSession::new(&pp, &commitment, &point)
            .unwrap()
            .prove(states)
            .unwrap();
        assert_eq!(
            serialize_proof(&fs_proof).unwrap(),
            serialize_proof(&proof).unwrap()
        );
        let mut verifier =
            Protocol11VerifierSession::new(&pp, &commitment, &point, claimed_value).unwrap();
        assert!(verifier.accept(Protocol11Event::ChallengeA).is_err());

        let mut verifier =
            Protocol11VerifierSession::new(&pp, &commitment, &point, claimed_value).unwrap();
        for event in PROTOCOL11_EVENT_ORDER {
            verifier.accept(event).unwrap();
        }
        verifier.finalize(&proof).unwrap();
    }

    #[test]
    fn setup_seed_and_worker_set_are_bound() {
        let config = test_config(8, 2, 2);
        let pp = setup(config, [29_u8; 32]).unwrap();
        let other_pp = setup(config, [31_u8; 32]).unwrap();
        assert_ne!(pp.params_digest, other_pp.params_digest);
        let evaluations = (0..pp.layout.original_len).map(value).collect::<Vec<_>>();
        let (commitment, states) = commit_global(&pp, evaluations).unwrap();
        let point = vec![PaperField::from_parts(5, 17); pp.layout.nv];
        let (claimed_value, mut proof) = prove_fs(&pp, &commitment, states, &point).unwrap();
        proof.worker_openings.pop();
        assert!(verify_fs(&pp, &commitment, &point, claimed_value, &proof).is_err());
    }

    #[test]
    fn paper100_full_protocol_smoke() {
        let config = Protocol11Config {
            original_len: 1 << 15,
            workers: 2,
            security: SecurityProfile::Paper100,
        };
        let pp = setup(config, [37_u8; 32]).unwrap();
        assert!(pp.security.effective_bits.is_some_and(|bits| bits >= 100));
        assert_eq!(pp.security.security_model, "classical-rom");
        assert_eq!(pp.security.soundness_regime, "deepfold-unique-decoding");
        assert_eq!(pp.security.pc_opening_count, 16);
        assert!(
            repeated_failure(
                3,
                4,
                pp.security.pcs_queries - 1,
                pp.security.pc_opening_count,
            ) > inverse_power_of_two(BRAKEDOWN_SETUP_BITS)
        );
        let evaluations = (0..pp.layout.original_len).map(value).collect::<Vec<_>>();
        let (commitment, states) = commit_global(&pp, evaluations).unwrap();
        let point = vec![PaperField::from_parts(7, 21); pp.layout.nv];
        let (claimed_value, proof) = prove_fs(&pp, &commitment, states, &point).unwrap();
        verify_fs(&pp, &commitment, &point, claimed_value, &proof).unwrap();
    }
}

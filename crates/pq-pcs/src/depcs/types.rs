use std::sync::Arc;

use paper_basefold::prover as basefold_prover;
use paper_deepfold::{self, prover as deepfold_prover};
use paper_util::{
    algebra::{field::mersenne61_ext::Mersenne61Ext, polynomial::Polynomial},
    merkle_tree::MERKLE_ROOT_SIZE,
    query_result::QueryResult,
    random_oracle::RandomOracle,
};
use serde::{Deserialize, Serialize};

use crate::depcs::backend::{
    PAPER_PCS_SECURITY_BITS, PaperPcsBackend, paper_query_count_for_code_rate,
};

use super::utils::round_up_to_step;

pub type PaperField = Mersenne61Ext;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PaperDepcsError {
    InvalidLength,
    InvalidWorker,
    InvalidBackend,
    InvalidCommitment,
    InvalidProof,
    InvalidEvaluation,
    Serialization,
    ArtifactPanic(String),
}

pub type PaperDepcsResult<T> = Result<T, PaperDepcsError>;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PaperDepcsConfig {
    pub backend: PaperPcsBackend,
    pub rate_inv: usize,
    pub security_bits: usize,
}

impl PaperDepcsConfig {
    pub fn new(backend: PaperPcsBackend, rate_inv: usize) -> PaperDepcsResult<Self> {
        let expected = match backend {
            PaperPcsBackend::BaseFold => 8,
            PaperPcsBackend::DeepFold => 2,
        };
        if rate_inv != expected || !rate_inv.is_power_of_two() {
            return Err(PaperDepcsError::InvalidBackend);
        }
        Ok(Self {
            backend,
            rate_inv,
            security_bits: PAPER_PCS_SECURITY_BITS,
        })
    }

    pub fn code_rate_log(self) -> usize {
        self.rate_inv.trailing_zeros() as usize
    }

    pub fn query_count(self) -> usize {
        paper_query_count_for_code_rate(self.backend, self.code_rate_log())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PaperProtocol11Commitment {
    pub config: PaperDepcsConfig,
    pub original_len: usize,
    pub nv: usize,
    pub workers: usize,
    pub worker_bits: usize,
    pub shard_len: usize,
    pub shard_nv: usize,
    pub artifact_nv: usize,
    pub workers_commitments: Vec<PaperProtocol11WorkerCommitment>,
    pub root: [u8; 32],
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PaperProtocol11WorkerCommitment {
    pub worker_id: usize,
    pub row_range: (usize, usize),
    pub oracle: RandomOracle<PaperField>,
    pub pcs_commitment: PaperPcsCommitment,
    pub leaf_digest: [u8; 32],
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum PaperPcsCommitment {
    BaseFold([u8; MERKLE_ROOT_SIZE]),
    DeepFold(paper_deepfold::Commit<PaperField>),
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PaperProtocol11Proof {
    pub config: PaperDepcsConfig,
    pub point: Vec<PaperField>,
    pub claimed_value: PaperField,
    pub query_count: usize,
    pub worker_openings: Vec<PaperProtocol11WorkerOpening>,
    pub encoding_batch: PaperProtocol10EncodingBatchProof,
    pub opening_batch: PaperProtocol10OpeningBatchProof,
    pub transcript_state: [u8; 32],
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PaperProtocol11WorkerOpening {
    pub worker_id: usize,
    pub worker_weight: PaperField,
    pub shard_point: Vec<PaperField>,
    pub value: PaperField,
    pub proof: PaperPcsOpeningProof,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum PaperPcsOpeningProof {
    BaseFold(PaperBaseFoldProof),
    DeepFold(paper_deepfold::Proof<PaperField>),
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PaperBaseFoldProof {
    pub evaluation: PaperField,
    pub folding_roots: Vec<(usize, [u8; MERKLE_ROOT_SIZE])>,
    pub sumcheck_values: Vec<(PaperField, PaperField, PaperField)>,
    pub final_poly: Polynomial<PaperField>,
    pub query_results: Vec<QueryResult<PaperField>>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PaperProtocol10EncodingBatchProof {
    pub relation_challenges: Vec<PaperField>,
    pub e1: PaperProtocol10RelationProof,
    pub e2: PaperProtocol10RelationProof,
    pub opening_batch_digest: [u8; 32],
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PaperProtocol10OpeningBatchProof {
    pub claims: Vec<PaperProtocol10OpeningClaim>,
    pub gammas: Vec<PaperField>,
    pub reduction_point: Vec<PaperField>,
    pub combined_value: PaperField,
    pub source_digest: [u8; 32],
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PaperProtocol10RelationProof {
    pub relation_index: usize,
    pub relation_kind: PaperProtocol10RelationKind,
    pub challenge: PaperField,
    pub opening_batch: PaperProtocol10OpeningBatchProof,
    pub relation_value: PaperField,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum PaperProtocol10RelationKind {
    E1,
    E2,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PaperProtocol10OpeningClaim {
    pub worker_id: usize,
    pub claim_kind: PaperProtocol10OpeningClaimKind,
    pub claimed_value: PaperField,
    pub weight: PaperField,
    pub point: Vec<PaperField>,
    pub source_digest: [u8; 32],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum PaperProtocol10OpeningClaimKind {
    ShardValue,
    WeightedShardValue,
    HuAtR,
    EAtR,
    FPadAtSystematic,
    EAtSystematic,
}

#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub struct PaperProtocol11OpenProfile {
    pub worker_eval_commit_ms: f64,
    pub column_open_ms: f64,
    pub f2_open_ms: f64,
    pub protocol10_e1_sumcheck_ms: f64,
    pub protocol10_e1_open_ms: f64,
    pub protocol10_e1_opening_batch_open_ms: f64,
    pub protocol10_e1_hu_open_ms: f64,
    pub protocol10_e1_e_at_r_open_ms: f64,
    pub protocol10_e1_f_at_u_prime_open_ms: f64,
    pub protocol10_e1_e_systematic_open_ms: f64,
    pub protocol10_e2_sumcheck_ms: f64,
    pub protocol10_e2_open_ms: f64,
    pub protocol10_e2_opening_batch_open_ms: f64,
    pub protocol10_e2_hu_open_ms: f64,
    pub protocol10_e2_e_at_r_open_ms: f64,
    pub protocol10_e2_f_at_u_prime_open_ms: f64,
    pub protocol10_e2_e_systematic_open_ms: f64,
}

#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub struct PaperProtocol11VerifyProfile {
    pub column_verify_ms: f64,
    pub f2_verify_ms: f64,
    pub protocol10_e1_verify_ms: f64,
    pub protocol10_e2_verify_ms: f64,
    pub paper_worker_verify_max_ms: f64,
    pub paper_worker_verify_sum_ms: f64,
    pub paper_master_verify_ms: f64,
    pub column_query_count: usize,
    pub pcs_query_count: usize,
    pub query_security_bits: usize,
    pub algebraic_security_bits: usize,
}

#[derive(Clone)]
pub struct PaperWorkerCache {
    pub original_len: usize,
    pub workers: usize,
    pub worker_id: usize,
    pub config: PaperDepcsConfig,
    pub commitment: PaperProtocol11WorkerCommitment,
    pub(crate) values: Arc<[PaperField]>,
    pub(crate) prepared: PreparedPaperProver,
}

#[derive(Clone)]
pub(crate) enum PreparedPaperProver {
    BaseFold(basefold_prover::Prover<PaperField>),
    DeepFold(deepfold_prover::Prover<PaperField>),
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct PaperLayout {
    pub(crate) nv: usize,
    pub(crate) worker_bits: usize,
    pub(crate) shard_len: usize,
    pub(crate) shard_nv: usize,
    pub(crate) artifact_nv: usize,
}

impl PaperLayout {
    pub(crate) fn new(original_len: usize, workers: usize) -> PaperDepcsResult<Self> {
        if original_len == 0
            || !original_len.is_power_of_two()
            || workers == 0
            || !workers.is_power_of_two()
            || !original_len.is_multiple_of(workers)
        {
            return Err(PaperDepcsError::InvalidLength);
        }
        let nv = original_len.trailing_zeros() as usize;
        let worker_bits = workers.trailing_zeros() as usize;
        if worker_bits >= nv {
            return Err(PaperDepcsError::InvalidLength);
        }
        let shard_len = original_len / workers;
        Ok(Self {
            nv,
            worker_bits,
            shard_len,
            shard_nv: shard_len.trailing_zeros() as usize,
            artifact_nv: round_up_to_step(shard_len.trailing_zeros() as usize),
        })
    }
}

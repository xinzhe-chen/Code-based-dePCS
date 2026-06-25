use pq_core::{
    FieldElement, SparseMatrix, eq_basis, eq_eval, eq_evaluations, evaluate_mle, log2_power_of_two,
};
use pq_sumcheck::{ProductSumcheckProof, QuadraticRoundPolynomial};
use pq_transcript::{Transcript, sha256};
use rayon::prelude::*;
use serde::{Deserialize, Serialize};
use std::time::Instant;

use super::deepfold;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PcsError {
    Empty,
    InvalidLength,
    InvalidWorker,
    InvalidProof,
    InvalidEncoding,
    InvalidCommitment,
    InvalidEvaluation,
    Sumcheck,
}

pub type PcsResult<T> = Result<T, PcsError>;

const CODE_RATE_INV: usize = 4;
const DEEPFOLD_RATE_INV: usize = CODE_RATE_INV;
const DEFAULT_SECURITY_BITS: usize = 128;
pub const GOLDILOCKS_ALGEBRAIC_SECURITY_BITS: usize = 64;

#[cfg(test)]
static BASEFOLD_COMMIT_CALLS: std::sync::atomic::AtomicUsize =
    std::sync::atomic::AtomicUsize::new(0);
#[cfg(test)]
static BASEFOLD_COMMIT_WITH_ADVICE_CALLS: std::sync::atomic::AtomicUsize =
    std::sync::atomic::AtomicUsize::new(0);
#[cfg(test)]
static BASEFOLD_COMMIT_COUNTER_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

#[derive(Copy, Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DistributedPcsParams {
    pub query_count: usize,
    pub security_bits: usize,
}

impl DistributedPcsParams {
    pub const DEFAULT_SECURITY_BITS: usize = DEFAULT_SECURITY_BITS;

    pub const fn new(query_count: usize) -> Self {
        Self {
            query_count,
            security_bits: DEFAULT_SECURITY_BITS,
        }
    }

    pub const fn for_security_bits(security_bits: usize) -> Self {
        Self {
            query_count: 0,
            security_bits,
        }
    }

    pub fn effective_query_count(self, len: usize) -> PcsResult<usize> {
        if len == 0 {
            return Err(PcsError::InvalidLength);
        }
        let security_queries = query_count_for_rate_inv(self.security_bits, CODE_RATE_INV)?;
        let requested = self.query_count.max(security_queries);
        Ok(requested.min(len))
    }
}

impl Default for DistributedPcsParams {
    fn default() -> Self {
        Self::for_security_bits(DEFAULT_SECURITY_BITS)
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum PcsBackendKind {
    BaseFold,
    DeepFold,
}

impl PcsBackendKind {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::BaseFold => "basefold",
            Self::DeepFold => "deepfold",
        }
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PcsBackendConfig {
    pub kind: PcsBackendKind,
    pub rate_inv: usize,
    pub security_bits: usize,
}

impl PcsBackendConfig {
    pub const fn basefold_default() -> Self {
        Self {
            kind: PcsBackendKind::BaseFold,
            rate_inv: CODE_RATE_INV,
            security_bits: DEFAULT_SECURITY_BITS,
        }
    }

    /// Compatibility alias for the current DeepFold default.
    ///
    /// This no longer configures rate-1/2; DeepFold is aligned with the
    /// repository rate-1/4 backend policy.
    pub const fn deepfold_rho_1_over_2() -> Self {
        Self::deepfold_default()
    }

    pub const fn deepfold_default() -> Self {
        Self {
            kind: PcsBackendKind::DeepFold,
            rate_inv: DEEPFOLD_RATE_INV,
            security_bits: DEFAULT_SECURITY_BITS,
        }
    }

    pub fn validate(self) -> PcsResult<()> {
        match self.kind {
            PcsBackendKind::BaseFold if self.rate_inv == CODE_RATE_INV => Ok(()),
            PcsBackendKind::DeepFold if self.rate_inv == DEEPFOLD_RATE_INV => Ok(()),
            _ => Err(PcsError::InvalidProof),
        }
    }

    pub const fn params(self, query_count: usize) -> DistributedPcsParams {
        DistributedPcsParams {
            query_count,
            security_bits: self.security_bits,
        }
    }
}

impl Default for PcsBackendConfig {
    fn default() -> Self {
        Self::basefold_default()
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Commitment {
    pub root: [u8; 32],
    pub len: usize,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OpeningProof {
    pub index: usize,
    pub value: FieldElement,
    pub path: Vec<([u8; 32], bool)>,
}

pub struct MerklePcs;

impl MerklePcs {
    pub fn commit(values: &[FieldElement]) -> PcsResult<Commitment> {
        Ok(MerkleTree::new(values)?.commitment())
    }

    pub fn open(values: &[FieldElement], index: usize) -> PcsResult<OpeningProof> {
        MerkleTree::new(values)?.open(index)
    }

    pub fn verify(commitment: &Commitment, proof: &OpeningProof) -> PcsResult<()> {
        if commitment.len == 0
            || !commitment.len.is_power_of_two()
            || proof.index >= commitment.len
            || proof.path.len() != commitment.len.trailing_zeros() as usize
        {
            return Err(PcsError::InvalidProof);
        }
        let mut node = leaf_hash(proof.value);
        let mut index = proof.index;
        for (sibling, sibling_is_right) in &proof.path {
            if *sibling_is_right != index.is_multiple_of(2) {
                return Err(PcsError::InvalidProof);
            }
            node = if *sibling_is_right {
                node_hash(&node, sibling)
            } else {
                node_hash(sibling, &node)
            };
            index /= 2;
        }
        if index == 0 && node == commitment.root {
            Ok(())
        } else {
            Err(PcsError::InvalidCommitment)
        }
    }
}

#[derive(Clone, Debug)]
pub(crate) struct MerkleTree {
    values: Vec<FieldElement>,
    levels: Vec<Vec<[u8; 32]>>,
}

impl MerkleTree {
    pub(crate) fn new(values: &[FieldElement]) -> PcsResult<Self> {
        if values.is_empty() || !values.len().is_power_of_two() {
            return Err(PcsError::InvalidLength);
        }
        let mut levels = Vec::new();
        let mut level = values
            .par_iter()
            .copied()
            .map(leaf_hash)
            .collect::<Vec<_>>();
        levels.push(level.clone());
        while level.len() > 1 {
            level = level
                .par_chunks_exact(2)
                .map(|pair| node_hash(&pair[0], &pair[1]))
                .collect();
            levels.push(level.clone());
        }
        Ok(Self {
            values: values.to_vec(),
            levels,
        })
    }

    pub(crate) fn commitment(&self) -> Commitment {
        Commitment {
            root: self.levels.last().expect("tree has a root")[0],
            len: self.values.len(),
        }
    }

    pub(crate) fn open(&self, index: usize) -> PcsResult<OpeningProof> {
        if index >= self.values.len() {
            return Err(PcsError::InvalidLength);
        }
        let mut idx = index;
        let mut path = Vec::new();
        for level in self.levels.iter().take(self.levels.len() - 1) {
            let sibling_on_right = idx.is_multiple_of(2);
            let sibling_idx = if sibling_on_right { idx + 1 } else { idx - 1 };
            path.push((level[sibling_idx], sibling_on_right));
            idx /= 2;
        }
        Ok(OpeningProof {
            index,
            value: self.values[index],
            path,
        })
    }
}

#[derive(Clone, Debug)]
pub struct BaseFoldCommitmentAdvice {
    commitment: BaseFoldPcCommitment,
    base_tree: MerkleTree,
    rs: deepfold::RsDeepFoldAdvice,
}

impl BaseFoldCommitmentAdvice {
    pub fn commitment(&self) -> &BaseFoldPcCommitment {
        &self.commitment
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BaseFoldPcCommitment {
    pub base: Commitment,
    pub rs: deepfold::RsDeepFoldCommitment,
    pub rate_inv: usize,
    pub codeword_len: usize,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeepFoldPcCommitment {
    pub base: Commitment,
    pub rs: deepfold::RsDeepFoldCommitment,
    pub rate_inv: usize,
    pub codeword_len: usize,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum PcCommitment {
    BaseFold(BaseFoldPcCommitment),
    DeepFold(DeepFoldPcCommitment),
}

impl PcCommitment {
    fn merkle_commitment(&self) -> &Commitment {
        match self {
            Self::BaseFold(commitment) => &commitment.base,
            Self::DeepFold(commitment) => &commitment.base,
        }
    }

    fn consistency_commitment(&self) -> &Commitment {
        match self {
            Self::BaseFold(commitment) => &commitment.rs.codeword,
            Self::DeepFold(commitment) => &commitment.rs.codeword,
        }
    }

    fn len(&self) -> usize {
        self.merkle_commitment().len
    }

    fn validate_for_backend(&self, backend: PcsBackendConfig) -> PcsResult<()> {
        match (backend.kind, self) {
            (PcsBackendKind::BaseFold, Self::BaseFold(commitment))
                if commitment.rate_inv == backend.rate_inv
                    && commitment.rs.rate_inv == backend.rate_inv
                    && commitment.rs.message_len == commitment.base.len
                    && commitment.rs.codeword_len == commitment.base.len * backend.rate_inv
                    && commitment.rs.codeword.len == commitment.rs.codeword_len
                    && commitment.codeword_len == commitment.base.len * backend.rate_inv =>
            {
                Ok(())
            }
            (PcsBackendKind::DeepFold, Self::DeepFold(commitment))
                if commitment.rate_inv == backend.rate_inv
                    && commitment.rs.rate_inv == backend.rate_inv
                    && commitment.rs.message_len == commitment.base.len
                    && commitment.rs.codeword_len == commitment.base.len * backend.rate_inv
                    && commitment.rs.codeword.len == commitment.rs.codeword_len
                    && commitment.codeword_len == commitment.base.len * backend.rate_inv =>
            {
                Ok(())
            }
            _ => Err(PcsError::InvalidCommitment),
        }
    }
}

#[derive(Clone, Debug)]
pub(crate) enum PcCommitmentAdvice {
    BaseFold(BaseFoldCommitmentAdvice),
    DeepFold {
        commitment: DeepFoldPcCommitment,
        base_tree: MerkleTree,
        rs: Box<deepfold::RsDeepFoldAdvice>,
    },
}

impl PcCommitmentAdvice {
    fn commitment(&self) -> PcCommitment {
        match self {
            Self::BaseFold(advice) => PcCommitment::BaseFold(advice.commitment().clone()),
            Self::DeepFold { commitment, .. } => PcCommitment::DeepFold(commitment.clone()),
        }
    }

    fn basefold(&self) -> &BaseFoldCommitmentAdvice {
        match self {
            Self::BaseFold(advice) => advice,
            Self::DeepFold { .. } => unreachable!("basefold advice requested for deepfold backend"),
        }
    }

    fn open_index(&self, index: usize) -> PcsResult<OpeningProof> {
        match self {
            Self::BaseFold(advice) => advice.base_tree.open(index),
            Self::DeepFold { base_tree, .. } => base_tree.open(index),
        }
    }

    fn open_consistency_index(&self, index: usize) -> PcsResult<OpeningProof> {
        match self {
            Self::BaseFold(advice) => advice.rs.tree.open(index),
            Self::DeepFold { rs, .. } => rs.tree.open(index),
        }
    }
}

fn commit_pc_with_advice(
    values: &[FieldElement],
    backend: PcsBackendConfig,
) -> PcsResult<(PcCommitment, PcCommitmentAdvice)> {
    match backend.kind {
        PcsBackendKind::BaseFold => {
            let (commitment, advice) = BaseFoldPc::commit_with_advice(values)?;
            Ok((
                PcCommitment::BaseFold(commitment),
                PcCommitmentAdvice::BaseFold(advice),
            ))
        }
        PcsBackendKind::DeepFold => {
            let base_tree = MerkleTree::new(values)?;
            let base = base_tree.commitment();
            let (rs_commitment, rs_advice) = deepfold::commit(values, backend.rate_inv)?;
            let commitment = DeepFoldPcCommitment {
                codeword_len: rs_commitment.codeword_len,
                rate_inv: backend.rate_inv,
                base,
                rs: rs_commitment,
            };
            Ok((
                PcCommitment::DeepFold(commitment.clone()),
                PcCommitmentAdvice::DeepFold {
                    commitment,
                    base_tree,
                    rs: Box::new(rs_advice),
                },
            ))
        }
    }
}

pub trait TransparentPc {
    type Commitment;
    type OpeningProof;

    fn commit(values: &[FieldElement]) -> PcsResult<Self::Commitment>;
    fn open<T: Transcript>(
        values: &[FieldElement],
        point: &[FieldElement],
        params: DistributedPcsParams,
        transcript: &mut T,
    ) -> PcsResult<Self::OpeningProof>;
    fn verify<T: Transcript>(
        commitment: &Self::Commitment,
        proof: &Self::OpeningProof,
        params: DistributedPcsParams,
        transcript: &mut T,
    ) -> PcsResult<()>;
    fn evaluate(values: &[FieldElement], point: &[FieldElement]) -> PcsResult<FieldElement>;
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BaseFoldOpeningProof {
    pub rate_inv: usize,
    pub query_count: usize,
    pub codeword_len: usize,
    pub value: FieldElement,
    pub rs_proof: deepfold::RsDeepFoldProof,
}

pub struct BaseFoldPc;

impl BaseFoldPc {
    pub fn commit_with_advice(
        values: &[FieldElement],
    ) -> PcsResult<(BaseFoldPcCommitment, BaseFoldCommitmentAdvice)> {
        #[cfg(test)]
        {
            let _guard = BASEFOLD_COMMIT_COUNTER_LOCK.lock().expect("counter lock");
            BASEFOLD_COMMIT_WITH_ADVICE_CALLS.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        }
        let base_tree = MerkleTree::new(values)?;
        let base = base_tree.commitment();
        let (rs, rs_advice) = deepfold::commit(values, CODE_RATE_INV)?;
        let commitment = BaseFoldPcCommitment {
            codeword_len: rs.codeword_len,
            rate_inv: CODE_RATE_INV,
            base,
            rs,
        };
        Ok((
            commitment.clone(),
            BaseFoldCommitmentAdvice {
                commitment,
                base_tree,
                rs: rs_advice,
            },
        ))
    }

    pub(crate) fn open_with_advice<T: Transcript>(
        values: &[FieldElement],
        advice: &BaseFoldCommitmentAdvice,
        point: &[FieldElement],
        params: DistributedPcsParams,
        transcript: &mut T,
    ) -> PcsResult<BaseFoldOpeningProof> {
        if values.len() != advice.commitment.base.len {
            return Err(PcsError::InvalidLength);
        }
        if advice.base_tree.values != values {
            return Err(PcsError::InvalidCommitment);
        }
        if point.len() != log2_power_of_two(values.len()).map_err(|_| PcsError::InvalidLength)? {
            return Err(PcsError::InvalidEvaluation);
        }
        let query_count = effective_query_count_for_backend(
            params,
            values.len(),
            PcsBackendConfig::basefold_default(),
        )?;
        absorb_basefold_opening_context(
            transcript,
            values.len(),
            point,
            advice.commitment.rate_inv,
            advice.commitment.codeword_len,
        );
        let rs_proof = deepfold::open(
            b"basefold-rs-core-v1",
            values,
            &advice.commitment.rs,
            &advice.rs,
            point,
            query_count,
            transcript,
        )?;
        Ok(BaseFoldOpeningProof {
            rate_inv: CODE_RATE_INV,
            query_count,
            codeword_len: advice.commitment.codeword_len,
            value: rs_proof.value,
            rs_proof,
        })
    }
}

fn verify_basefold_opening_inner<T: Transcript>(
    commitment: &BaseFoldPcCommitment,
    proof: &BaseFoldOpeningProof,
    params: DistributedPcsParams,
    transcript: &mut T,
    leaf_checker: Option<&dyn Fn(usize, FieldElement) -> PcsResult<()>>,
) -> PcsResult<()> {
    if proof.rate_inv != commitment.rate_inv
        || proof.codeword_len != commitment.rs.codeword_len
        || proof.value != proof.rs_proof.value
    {
        return Err(PcsError::InvalidProof);
    }
    let expected_query_count = effective_query_count_for_backend(
        params,
        commitment.base.len,
        PcsBackendConfig::basefold_default(),
    )?;
    if proof.query_count != expected_query_count {
        return Err(PcsError::InvalidProof);
    }
    absorb_basefold_opening_context(
        transcript,
        commitment.base.len,
        &proof.rs_proof.point,
        commitment.rate_inv,
        commitment.codeword_len,
    );
    deepfold::verify(
        b"basefold-rs-core-v1",
        &commitment.rs,
        &proof.rs_proof,
        &proof.rs_proof.point,
        expected_query_count,
        transcript,
    )?;
    if let Some(checker) = leaf_checker {
        let batched_proof = BatchedOpeningProof::BaseFold(proof.clone());
        for index in basefold_level_zero_indices(proof) {
            let value =
                batched_level_zero_value(&batched_proof, index).ok_or(PcsError::InvalidProof)?;
            checker(index, value)?;
        }
    }
    Ok(())
}

impl TransparentPc for BaseFoldPc {
    type Commitment = BaseFoldPcCommitment;
    type OpeningProof = BaseFoldOpeningProof;

    fn commit(values: &[FieldElement]) -> PcsResult<Self::Commitment> {
        #[cfg(test)]
        BASEFOLD_COMMIT_CALLS.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        Self::commit_with_advice(values).map(|(commitment, _)| commitment)
    }

    fn open<T: Transcript>(
        values: &[FieldElement],
        point: &[FieldElement],
        params: DistributedPcsParams,
        transcript: &mut T,
    ) -> PcsResult<Self::OpeningProof> {
        let (_, advice) = Self::commit_with_advice(values)?;
        Self::open_with_advice(values, &advice, point, params, transcript)
    }

    fn verify<T: Transcript>(
        commitment: &Self::Commitment,
        proof: &Self::OpeningProof,
        params: DistributedPcsParams,
        transcript: &mut T,
    ) -> PcsResult<()> {
        verify_basefold_opening_inner(commitment, proof, params, transcript, None)
    }

    fn evaluate(values: &[FieldElement], point: &[FieldElement]) -> PcsResult<FieldElement> {
        evaluate_mle(values, point).map_err(|_| PcsError::InvalidEvaluation)
    }
}

pub struct DeepFoldPc;

impl DeepFoldPc {
    pub(crate) fn open_with_advice<T: Transcript>(
        values: &[FieldElement],
        advice: &PcCommitmentAdvice,
        point: &[FieldElement],
        params: DistributedPcsParams,
        backend: PcsBackendConfig,
        transcript: &mut T,
    ) -> PcsResult<DeepFoldOpeningProof> {
        if backend.kind != PcsBackendKind::DeepFold || backend.rate_inv != DEEPFOLD_RATE_INV {
            return Err(PcsError::InvalidProof);
        }
        let PcCommitmentAdvice::DeepFold {
            commitment,
            base_tree,
            rs,
        } = advice
        else {
            return Err(PcsError::InvalidCommitment);
        };
        if values.len() != commitment.base.len || base_tree.commitment() != commitment.base {
            return Err(PcsError::InvalidCommitment);
        }
        if base_tree.values != values {
            return Err(PcsError::InvalidCommitment);
        }
        let query_count = effective_query_count_for_backend(params, values.len(), backend)?;
        absorb_deepfold_opening_context(transcript, values.len(), point, backend);
        let rs_proof = deepfold::open(
            b"deepfold-rs-core-v1",
            values,
            &commitment.rs,
            rs,
            point,
            query_count,
            transcript,
        )?;
        Ok(DeepFoldOpeningProof {
            rate_inv: backend.rate_inv,
            query_count,
            codeword_len: commitment.rs.codeword_len,
            value: rs_proof.value,
            rs_proof,
        })
    }

    pub fn verify<T: Transcript>(
        commitment: &DeepFoldPcCommitment,
        proof: &DeepFoldOpeningProof,
        point: &[FieldElement],
        params: DistributedPcsParams,
        backend: PcsBackendConfig,
        transcript: &mut T,
    ) -> PcsResult<()> {
        if backend.kind != PcsBackendKind::DeepFold
            || proof.rate_inv != backend.rate_inv
            || proof.codeword_len != commitment.rs.codeword_len
            || proof.rs_proof.point != point
            || proof.value != proof.rs_proof.value
        {
            return Err(PcsError::InvalidProof);
        }
        let expected_query_count =
            effective_query_count_for_backend(params, commitment.base.len, backend)?;
        if proof.query_count != expected_query_count {
            return Err(PcsError::InvalidProof);
        }
        absorb_deepfold_opening_context(transcript, commitment.base.len, point, backend);
        deepfold::verify(
            b"deepfold-rs-core-v1",
            &commitment.rs,
            &proof.rs_proof,
            point,
            expected_query_count,
            transcript,
        )
    }
}

pub fn effective_query_count_for_backend(
    params: DistributedPcsParams,
    len: usize,
    backend: PcsBackendConfig,
) -> PcsResult<usize> {
    if len == 0 {
        return Err(PcsError::InvalidLength);
    }
    backend.validate()?;
    let security_bits = backend.security_bits.max(params.security_bits).max(1);
    let security_queries = query_count_for_rate_inv(security_bits, backend.rate_inv)?;
    Ok(params
        .query_count
        .max(security_queries)
        .min(len.saturating_mul(backend.rate_inv)))
}

fn query_count_for_rate_inv(security_bits: usize, rate_inv: usize) -> PcsResult<usize> {
    if rate_inv < 2 || !rate_inv.is_power_of_two() {
        return Err(PcsError::InvalidProof);
    }
    let bits_per_query = rate_inv.trailing_zeros() as usize;
    Ok(security_bits.max(1).div_ceil(bits_per_query))
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BrakedownCodeSpec {
    pub message_len: usize,
    pub codeword_len: usize,
    pub rate_inv: usize,
}

impl BrakedownCodeSpec {
    pub fn new(message_len: usize) -> PcsResult<Self> {
        if message_len == 0 || !message_len.is_power_of_two() {
            return Err(PcsError::InvalidLength);
        }
        Ok(Self {
            message_len,
            codeword_len: message_len * CODE_RATE_INV,
            rate_inv: CODE_RATE_INV,
        })
    }

    pub fn encoded_vars(self) -> PcsResult<usize> {
        log2_power_of_two(self.codeword_len).map_err(|_| PcsError::InvalidLength)
    }

    pub fn message_vars(self) -> PcsResult<usize> {
        log2_power_of_two(self.message_len).map_err(|_| PcsError::InvalidLength)
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BrakedownParityShape {
    pub rows: usize,
    pub cols: usize,
    pub nnz: usize,
}

impl BrakedownParityShape {
    pub const fn from_spec(spec: BrakedownCodeSpec) -> Self {
        Self {
            rows: spec.codeword_len,
            cols: spec.codeword_len,
            nnz: 14 * spec.message_len,
        }
    }

    pub fn validate(self, rows: usize, cols: usize, nnz: usize) -> PcsResult<()> {
        if self.rows == rows && self.cols == cols && self.nnz == nnz {
            Ok(())
        } else {
            Err(PcsError::InvalidProof)
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Protocol11Commitment {
    pub backend: PcsBackendConfig,
    pub workers: Vec<Protocol11WorkerCommitment>,
    pub original_len: usize,
    pub matrix_rows: usize,
    pub row_axis_len: usize,
    pub rows_per_worker: usize,
    pub row_width: usize,
    pub encoded_width: usize,
    pub root: [u8; 32],
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Protocol11WorkerCommitment {
    pub worker_id: usize,
    pub row_range: (usize, usize),
    pub matrix_commitment: Commitment,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Protocol11Proof {
    pub backend: PcsBackendConfig,
    pub point: Vec<FieldElement>,
    pub claimed_value: FieldElement,
    pub query_indices: Vec<usize>,
    pub eval_commitments: Vec<Protocol11WorkerEvalCommitments>,
    pub merkle_roots: Vec<Protocol11WorkerMerkleRoots>,
    pub column_openings: Vec<Protocol11WorkerColumnProof>,
    pub y1: Vec<FieldElement>,
    pub y2: Vec<FieldElement>,
    pub f2_opening: BatchedDistributedPcOpening,
    pub encoding_batch: Protocol10EncodingBatchProof,
    pub transcript_state: [u8; 32],
}

#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub struct Protocol10OpenProfile {
    pub sumcheck_ms: f64,
    pub opening_ms: f64,
    pub opening_batch_open_ms: f64,
    pub hu_open_ms: f64,
    pub e_at_r_open_ms: f64,
    pub f_at_u_prime_open_ms: f64,
    pub e_systematic_open_ms: f64,
}

#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub struct Protocol11OpenProfile {
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
pub struct Protocol11VerifyProfile {
    pub column_verify_ms: f64,
    pub f2_verify_ms: f64,
    pub protocol10_e1_verify_ms: f64,
    pub protocol10_e2_verify_ms: f64,
    pub column_query_count: usize,
    pub pcs_query_count: usize,
    pub query_security_bits: usize,
    pub algebraic_security_bits: usize,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Protocol11WorkerEvalCommitments {
    pub worker_id: usize,
    pub f1: PcCommitment,
    pub e1: PcCommitment,
    pub f2: PcCommitment,
    pub e2: PcCommitment,
}

#[derive(Clone, Debug)]
struct Protocol11WorkerEvalAdvice {
    worker_id: usize,
    f1: PcCommitmentAdvice,
    e1: PcCommitmentAdvice,
    f2: PcCommitmentAdvice,
    e2: PcCommitmentAdvice,
}

#[derive(Clone, Debug)]
pub struct Protocol11PreparedOpen {
    payloads: Vec<Protocol11WorkerOpenPayload>,
    eval_commitments: Vec<Protocol11WorkerEvalCommitments>,
    merkle_roots: Vec<Protocol11WorkerMerkleRoots>,
    eval_advices: Vec<Protocol11WorkerEvalAdvice>,
    query_indices: Vec<usize>,
    worker_eval_commit_ms: f64,
}

impl Protocol11PreparedOpen {
    pub fn query_indices(&self) -> &[usize] {
        &self.query_indices
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Protocol11WorkerMerkleRoots {
    pub worker_id: usize,
    pub e1_root: PcCommitment,
    pub e2_root: PcCommitment,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Protocol11WorkerColumnProof {
    pub worker_id: usize,
    pub columns: Vec<Protocol11ColumnOpening>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Protocol11WorkerMatrixColumnProof {
    pub worker_id: usize,
    pub columns: Vec<Protocol11MatrixColumnOpening>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Protocol11WorkerOpenData {
    pub worker_id: usize,
    pub encoded_rows: Vec<Vec<FieldElement>>,
    pub f1: Vec<FieldElement>,
    pub f1_pad: Vec<FieldElement>,
    pub e1: Vec<FieldElement>,
    pub f2: Vec<FieldElement>,
    pub f2_pad: Vec<FieldElement>,
    pub e2: Vec<FieldElement>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Protocol11WorkerOpenPayload {
    pub worker_id: usize,
    pub f1_pad: Vec<FieldElement>,
    pub f2_pad: Vec<FieldElement>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Protocol11ColumnOpening {
    pub index: usize,
    pub encoded_row_values: Vec<FieldElement>,
    pub matrix_hash_value: FieldElement,
    pub matrix_opening: OpeningProof,
    pub e1_value: FieldElement,
    pub e1_opening: OpeningProof,
    pub e2_value: FieldElement,
    pub e2_opening: OpeningProof,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Protocol11MatrixColumnOpening {
    pub index: usize,
    pub encoded_row_values: Vec<FieldElement>,
    pub matrix_hash_value: FieldElement,
    pub matrix_opening: OpeningProof,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DistributedPcOpening {
    pub worker_id: usize,
    pub value: FieldElement,
    pub proof: BaseFoldOpeningProof,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum BatchedOpeningProof {
    BaseFold(BaseFoldOpeningProof),
    DeepFold(DeepFoldOpeningProof),
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeepFoldOpeningProof {
    pub rate_inv: usize,
    pub query_count: usize,
    pub codeword_len: usize,
    pub value: FieldElement,
    pub rs_proof: deepfold::RsDeepFoldProof,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BatchedDistributedPcOpening {
    pub backend: PcsBackendConfig,
    pub point: Vec<FieldElement>,
    pub aggregate_value: FieldElement,
    pub combined_commitment: PcCommitment,
    pub proof: BatchedOpeningProof,
    pub consistency: Vec<BatchedLeafConsistency>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BatchedLeafConsistency {
    pub index: usize,
    pub combined_value: FieldElement,
    pub worker_openings: Vec<OpeningProof>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WeightedSourceLeafConsistency {
    pub index: usize,
    pub combined_value: FieldElement,
    pub source_openings: Vec<OpeningProof>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WeightedSourceBatchOpening {
    pub backend: PcsBackendConfig,
    pub point: Vec<FieldElement>,
    pub aggregate_value: FieldElement,
    pub combined_commitment: PcCommitment,
    pub proof: BatchedOpeningProof,
    pub consistency: Vec<WeightedSourceLeafConsistency>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Protocol10OpeningClaimKind {
    HuAtR,
    EAtR,
    FPadAtSystematic,
    EAtSystematic,
}

impl Protocol10OpeningClaimKind {
    fn as_str(self) -> &'static str {
        match self {
            Self::HuAtR => "hu-at-r",
            Self::EAtR => "e-at-r",
            Self::FPadAtSystematic => "f-pad-at-systematic",
            Self::EAtSystematic => "e-at-systematic",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Protocol10OpeningClaim {
    pub relation_index: usize,
    pub claim_kind: Protocol10OpeningClaimKind,
    pub label: Vec<u8>,
    pub source_commitments: Vec<PcCommitment>,
    pub point: Vec<FieldElement>,
    pub claimed_value: FieldElement,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MultiPointBatchReductionProof {
    pub gammas: Vec<FieldElement>,
    pub product_sumcheck: ProductSumcheckProof,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Protocol10OpeningBatchProof {
    pub claims: Vec<Protocol10OpeningClaim>,
    pub reduction: MultiPointBatchReductionProof,
    pub combined_opening: WeightedSourceBatchOpening,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Protocol10EncodingProof {
    pub code_spec: BrakedownCodeSpec,
    pub f_commitments: Vec<PcCommitment>,
    pub e_commitments: Vec<PcCommitment>,
    pub parity_check_rows: usize,
    pub parity_check_cols: usize,
    pub parity_check_nnz: usize,
    pub u: Vec<FieldElement>,
    pub hu_commitment: PcCommitment,
    pub opening_batch: Protocol10OpeningBatchProof,
    pub e_at_r: FieldElement,
    pub hu_at_r: FieldElement,
    pub u_prime: Vec<FieldElement>,
    pub f_at_u_prime: FieldElement,
    pub e_at_systematic: FieldElement,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Protocol10EncodingBatchProof {
    pub relation_challenges: Vec<FieldElement>,
    pub product_sumcheck: ProductSumcheckProof,
    pub encodings: Vec<Protocol10EncodingProof>,
}

pub struct DistributedBrakedown;

impl DistributedBrakedown {
    pub fn commit(evaluations: &[FieldElement], workers: usize) -> PcsResult<Protocol11Commitment> {
        Self::commit_with_config(evaluations, workers, PcsBackendConfig::basefold_default())
    }

    pub fn commit_with_config(
        evaluations: &[FieldElement],
        workers: usize,
        backend: PcsBackendConfig,
    ) -> PcsResult<Protocol11Commitment> {
        backend.validate()?;
        let layout = Protocol11Layout::new(evaluations.len(), workers)?;
        let worker_commitments = (0..workers)
            .into_par_iter()
            .map(|worker_id| {
                let rows = worker_rows(evaluations, &layout, worker_id)?;
                let encoded_rows = encode_rows(&rows)?;
                let hashes = column_hashes(&encoded_rows);
                Ok(Protocol11WorkerCommitment {
                    worker_id,
                    row_range: worker_row_range(&layout, worker_id),
                    matrix_commitment: MerklePcs::commit(&hashes)?,
                })
            })
            .collect::<PcsResult<Vec<_>>>()?;
        let root = aggregate_worker_commitments(&worker_commitments);
        Ok(Protocol11Commitment {
            backend,
            workers: worker_commitments,
            original_len: evaluations.len(),
            matrix_rows: layout.matrix_rows,
            row_axis_len: layout.row_axis_len,
            rows_per_worker: layout.rows_per_worker,
            row_width: layout.row_width,
            encoded_width: layout.encoded_width,
            root,
        })
    }

    pub fn open<T: Transcript>(
        evaluations: &[FieldElement],
        commitment: &Protocol11Commitment,
        point: &[FieldElement],
        params: DistributedPcsParams,
        transcript: &mut T,
    ) -> PcsResult<Protocol11Proof> {
        Self::open_profiled(evaluations, commitment, point, params, transcript)
            .map(|(proof, _)| proof)
    }

    pub fn open_with_config<T: Transcript>(
        evaluations: &[FieldElement],
        commitment: &Protocol11Commitment,
        point: &[FieldElement],
        params: DistributedPcsParams,
        backend: PcsBackendConfig,
        transcript: &mut T,
    ) -> PcsResult<Protocol11Proof> {
        Self::open_profiled_with_config(evaluations, commitment, point, params, backend, transcript)
            .map(|(proof, _)| proof)
    }

    pub fn open_profiled<T: Transcript>(
        evaluations: &[FieldElement],
        commitment: &Protocol11Commitment,
        point: &[FieldElement],
        params: DistributedPcsParams,
        transcript: &mut T,
    ) -> PcsResult<(Protocol11Proof, Protocol11OpenProfile)> {
        Self::open_profiled_with_config(
            evaluations,
            commitment,
            point,
            params,
            commitment.backend,
            transcript,
        )
    }

    pub fn open_profiled_with_config<T: Transcript>(
        evaluations: &[FieldElement],
        commitment: &Protocol11Commitment,
        point: &[FieldElement],
        params: DistributedPcsParams,
        backend: PcsBackendConfig,
        transcript: &mut T,
    ) -> PcsResult<(Protocol11Proof, Protocol11OpenProfile)> {
        backend.validate()?;
        if commitment.backend != backend {
            return Err(PcsError::InvalidCommitment);
        }
        let mut profile = Protocol11OpenProfile::default();
        validate_commitment(commitment)?;
        if evaluations.len() != commitment.original_len {
            return Err(PcsError::InvalidLength);
        }
        let layout = Protocol11Layout::from_commitment(commitment)?;
        let row_vars =
            log2_power_of_two(layout.row_axis_len).map_err(|_| PcsError::InvalidLength)?;
        let col_vars = log2_power_of_two(layout.row_width).map_err(|_| PcsError::InvalidLength)?;
        if point.len() != row_vars + col_vars {
            return Err(PcsError::InvalidEvaluation);
        }
        let (s1, s2) = point.split_at(row_vars);
        absorb_protocol11_commitment(transcript, commitment);
        transcript.absorb_domain(b"protocol-11-eval");
        for coordinate in point {
            transcript.absorb_field(b"point", *coordinate);
        }
        let a = (0..layout.matrix_rows)
            .map(|_| transcript.challenge_field::<FieldElement>(b"protocol-11-a"))
            .collect::<Vec<_>>();
        let beta = (0..layout.matrix_rows)
            .map(|row| eq_basis(s1, row).map_err(|_| PcsError::InvalidEvaluation))
            .collect::<PcsResult<Vec<_>>>()?;

        let stage_start = Instant::now();
        let worker_data = (0..commitment.workers.len())
            .into_par_iter()
            .map(|worker_id| build_worker_eval_data(evaluations, &layout, worker_id, &a, &beta))
            .collect::<PcsResult<Vec<_>>>()?;
        let eval_commitment_advice = worker_data
            .par_iter()
            .map(|data| {
                let (f1, f1_advice) = commit_pc_with_advice(&data.f1_pad, backend)?;
                let (e1, e1_advice) = commit_pc_with_advice(&data.e1, backend)?;
                let (f2, f2_advice) = commit_pc_with_advice(&data.f2_pad, backend)?;
                let (e2, e2_advice) = commit_pc_with_advice(&data.e2, backend)?;
                Ok((
                    Protocol11WorkerEvalCommitments {
                        worker_id: data.worker_id,
                        f1,
                        e1,
                        f2,
                        e2,
                    },
                    Protocol11WorkerEvalAdvice {
                        worker_id: data.worker_id,
                        f1: f1_advice,
                        e1: e1_advice,
                        f2: f2_advice,
                        e2: e2_advice,
                    },
                ))
            })
            .collect::<PcsResult<Vec<_>>>()?;
        let eval_commitments = eval_commitment_advice
            .iter()
            .map(|(commitment, _)| commitment.clone())
            .collect::<Vec<_>>();
        let eval_advices = eval_commitment_advice
            .iter()
            .map(|(_, advice)| advice.clone())
            .collect::<Vec<_>>();
        let merkle_roots = eval_advices
            .par_iter()
            .map(|advice| Protocol11WorkerMerkleRoots {
                worker_id: advice.worker_id,
                e1_root: advice.e1.commitment(),
                e2_root: advice.e2.commitment(),
            })
            .collect::<Vec<_>>();
        profile.worker_eval_commit_ms = elapsed_ms(stage_start);
        absorb_protocol11_eval_commitments(transcript, &eval_commitments, &merkle_roots);

        let query_count = params.effective_query_count(layout.encoded_width)?;
        let query_indices =
            transcript.challenge_indices(b"protocol-11-columns", query_count, layout.encoded_width);
        let stage_start = Instant::now();
        let column_openings = worker_data
            .par_iter()
            .zip(eval_advices.par_iter())
            .map(|(data, advice)| worker_column_proof(data, advice, commitment, &query_indices))
            .collect::<PcsResult<Vec<_>>>()?;
        profile.column_open_ms = elapsed_ms(stage_start);
        let (y1, y2) = aggregate_column_claims(&column_openings, &a, &beta, &layout)?;

        let stage_start = Instant::now();
        let mut f2_systematic_point = s2.to_vec();
        f2_systematic_point.extend([FieldElement::ZERO, FieldElement::ZERO]);
        let f2_values = worker_data
            .iter()
            .map(|data| data.f2_pad.clone())
            .collect::<Vec<_>>();
        let f2_commitments = eval_commitments
            .iter()
            .map(|commitment| commitment.f2.clone())
            .collect::<Vec<_>>();
        let f2_advices = eval_advices
            .iter()
            .map(|advice| &advice.f2)
            .collect::<Vec<_>>();
        let f2_opening = open_distributed(
            DistributedOpenRequest {
                label: b"protocol-11-f2",
                values: &f2_values,
                commitments: &f2_commitments,
                advices: &f2_advices,
                point: &f2_systematic_point,
                params,
                backend,
            },
            transcript,
        )?;
        profile.f2_open_ms = elapsed_ms(stage_start);
        let claimed_value = f2_opening.aggregate_value;

        let f1_locals = worker_data
            .iter()
            .map(|data| data.f1.clone())
            .collect::<Vec<_>>();
        let f1_pad_locals = worker_data
            .iter()
            .map(|data| data.f1_pad.clone())
            .collect::<Vec<_>>();
        let e1_locals = worker_data
            .iter()
            .map(|data| data.e1.clone())
            .collect::<Vec<_>>();
        let f2_locals = worker_data
            .iter()
            .map(|data| data.f2.clone())
            .collect::<Vec<_>>();
        let f2_pad_locals = worker_data
            .iter()
            .map(|data| data.f2_pad.clone())
            .collect::<Vec<_>>();
        let e2_locals = worker_data
            .iter()
            .map(|data| data.e2.clone())
            .collect::<Vec<_>>();
        let f_commitments_e1 = eval_commitments
            .iter()
            .map(|commitment| commitment.f1.clone())
            .collect::<Vec<_>>();
        let e_commitments_e1 = eval_commitments
            .iter()
            .map(|commitment| commitment.e1.clone())
            .collect::<Vec<_>>();
        let f_commitments_e2 = eval_commitments
            .iter()
            .map(|commitment| commitment.f2.clone())
            .collect::<Vec<_>>();
        let e_commitments_e2 = eval_commitments
            .iter()
            .map(|commitment| commitment.e2.clone())
            .collect::<Vec<_>>();
        let f1_advices = eval_advices
            .iter()
            .map(|advice| &advice.f1)
            .collect::<Vec<_>>();
        let e1_advices = eval_advices
            .iter()
            .map(|advice| &advice.e1)
            .collect::<Vec<_>>();
        let f2_advices = eval_advices
            .iter()
            .map(|advice| &advice.f2)
            .collect::<Vec<_>>();
        let e2_advices = eval_advices
            .iter()
            .map(|advice| &advice.e2)
            .collect::<Vec<_>>();
        let encoding_relations = [
            Protocol10EncodingProverInput {
                f_locals: &f1_locals,
                f_pad_locals: &f1_pad_locals,
                e_locals: &e1_locals,
                f_commitments: &f_commitments_e1,
                e_commitments: &e_commitments_e1,
                f_advices: &f1_advices,
                e_advices: &e1_advices,
            },
            Protocol10EncodingProverInput {
                f_locals: &f2_locals,
                f_pad_locals: &f2_pad_locals,
                e_locals: &e2_locals,
                f_commitments: &f_commitments_e2,
                e_commitments: &e_commitments_e2,
                f_advices: &f2_advices,
                e_advices: &e2_advices,
            },
        ];
        let (encoding_batch, encoding_profiles) = prove_protocol10_encoding_batch_profiled(
            &encoding_relations,
            params,
            backend,
            transcript,
        )?;
        let profile_e1 = encoding_profiles[0];
        profile.protocol10_e1_sumcheck_ms = profile_e1.sumcheck_ms;
        profile.protocol10_e1_open_ms = profile_e1.opening_ms;
        profile.protocol10_e1_opening_batch_open_ms = profile_e1.opening_batch_open_ms;
        profile.protocol10_e1_hu_open_ms = profile_e1.hu_open_ms;
        profile.protocol10_e1_e_at_r_open_ms = profile_e1.e_at_r_open_ms;
        profile.protocol10_e1_f_at_u_prime_open_ms = profile_e1.f_at_u_prime_open_ms;
        profile.protocol10_e1_e_systematic_open_ms = profile_e1.e_systematic_open_ms;
        let profile_e2 = encoding_profiles[1];
        profile.protocol10_e2_sumcheck_ms = profile_e2.sumcheck_ms;
        profile.protocol10_e2_open_ms = profile_e2.opening_ms;
        profile.protocol10_e2_opening_batch_open_ms = profile_e2.opening_batch_open_ms;
        profile.protocol10_e2_hu_open_ms = profile_e2.hu_open_ms;
        profile.protocol10_e2_e_at_r_open_ms = profile_e2.e_at_r_open_ms;
        profile.protocol10_e2_f_at_u_prime_open_ms = profile_e2.f_at_u_prime_open_ms;
        profile.protocol10_e2_e_systematic_open_ms = profile_e2.e_systematic_open_ms;
        transcript.absorb_field(b"protocol-11-claimed-value", claimed_value);

        Ok((
            Protocol11Proof {
                backend,
                point: point.to_vec(),
                claimed_value,
                query_indices,
                eval_commitments,
                merkle_roots,
                column_openings,
                y1,
                y2,
                f2_opening,
                encoding_batch,
                transcript_state: transcript.state(),
            },
            profile,
        ))
    }

    pub fn worker_rows_for_commit(
        evaluations: &[FieldElement],
        workers: usize,
        worker_id: usize,
    ) -> PcsResult<Vec<Vec<FieldElement>>> {
        let layout = Protocol11Layout::new(evaluations.len(), workers)?;
        worker_rows(evaluations, &layout, worker_id)
    }

    pub fn worker_rows_for_commit_from_fn<F>(
        original_len: usize,
        workers: usize,
        worker_id: usize,
        value_at: F,
    ) -> PcsResult<Vec<Vec<FieldElement>>>
    where
        F: Fn(usize) -> FieldElement,
    {
        let layout = Protocol11Layout::new(original_len, workers)?;
        worker_rows_from_fn(original_len, &layout, worker_id, value_at)
    }

    pub fn commit_worker_rows_with_config(
        original_len: usize,
        workers: usize,
        worker_id: usize,
        rows: &[Vec<FieldElement>],
        backend: PcsBackendConfig,
    ) -> PcsResult<Protocol11WorkerCommitment> {
        backend.validate()?;
        let layout = Protocol11Layout::new(original_len, workers)?;
        if rows.len() != layout.rows_per_worker
            || rows.iter().any(|row| row.len() != layout.row_width)
        {
            return Err(PcsError::InvalidLength);
        }
        let encoded_rows = encode_rows(rows)?;
        let hashes = column_hashes(&encoded_rows);
        Ok(Protocol11WorkerCommitment {
            worker_id,
            row_range: worker_row_range(&layout, worker_id),
            matrix_commitment: MerklePcs::commit(&hashes)?,
        })
    }

    pub fn commit_from_worker_commitments_with_config(
        original_len: usize,
        workers: usize,
        backend: PcsBackendConfig,
        mut worker_commitments: Vec<Protocol11WorkerCommitment>,
    ) -> PcsResult<Protocol11Commitment> {
        backend.validate()?;
        let layout = Protocol11Layout::new(original_len, workers)?;
        if worker_commitments.len() != workers {
            return Err(PcsError::InvalidWorker);
        }
        worker_commitments.sort_by_key(|commitment| commitment.worker_id);
        for (worker_id, worker_commitment) in worker_commitments.iter().enumerate() {
            if worker_commitment.worker_id != worker_id
                || worker_commitment.row_range != worker_row_range(&layout, worker_id)
            {
                return Err(PcsError::InvalidWorker);
            }
        }
        let root = aggregate_worker_commitments(&worker_commitments);
        Ok(Protocol11Commitment {
            backend,
            workers: worker_commitments,
            original_len,
            matrix_rows: layout.matrix_rows,
            row_axis_len: layout.row_axis_len,
            rows_per_worker: layout.rows_per_worker,
            row_width: layout.row_width,
            encoded_width: layout.encoded_width,
            root,
        })
    }

    pub fn open_worker_data_from_rows_with_config(
        original_len: usize,
        workers: usize,
        worker_id: usize,
        rows: &[Vec<FieldElement>],
        a: &[FieldElement],
        beta: &[FieldElement],
        backend: PcsBackendConfig,
    ) -> PcsResult<Protocol11WorkerOpenData> {
        backend.validate()?;
        let layout = Protocol11Layout::new(original_len, workers)?;
        if rows.len() != layout.rows_per_worker
            || rows.iter().any(|row| row.len() != layout.row_width)
            || a.len() != layout.matrix_rows
            || beta.len() != layout.matrix_rows
        {
            return Err(PcsError::InvalidLength);
        }
        build_worker_eval_data_from_rows(rows, &layout, worker_id, a, beta)
    }

    pub fn open_worker_payload_from_data_with_config(
        data: &Protocol11WorkerOpenData,
        backend: PcsBackendConfig,
    ) -> PcsResult<Protocol11WorkerOpenPayload> {
        backend.validate()?;
        Ok(Protocol11WorkerOpenPayload {
            worker_id: data.worker_id,
            f1_pad: data.f1_pad.clone(),
            f2_pad: data.f2_pad.clone(),
        })
    }

    pub fn open_worker_column_proof_from_data_with_config(
        data: &Protocol11WorkerOpenData,
        commitment: &Protocol11Commitment,
        query_indices: &[usize],
        backend: PcsBackendConfig,
    ) -> PcsResult<Protocol11WorkerColumnProof> {
        backend.validate()?;
        if commitment.backend != backend {
            return Err(PcsError::InvalidCommitment);
        }
        let (_, _, _, advice) = worker_open_payload_and_advice(data, backend)?;
        worker_column_proof(data, &advice, commitment, query_indices)
    }

    pub fn open_worker_matrix_column_proof_from_data(
        data: &Protocol11WorkerOpenData,
        commitment: &Protocol11Commitment,
        query_indices: &[usize],
    ) -> PcsResult<Protocol11WorkerMatrixColumnProof> {
        worker_matrix_column_proof(data, commitment, query_indices)
    }

    pub fn open_column_queries_from_worker_payloads<T: Transcript>(
        commitment: &Protocol11Commitment,
        params: DistributedPcsParams,
        transcript: &mut T,
        payloads: &[Protocol11WorkerOpenPayload],
    ) -> PcsResult<Vec<usize>> {
        let prepared = prepare_open_from_worker_payloads(
            commitment,
            params,
            commitment.backend,
            transcript,
            payloads,
        )?;
        Ok(prepared.query_indices().to_vec())
    }

    pub fn prepare_open_worker_payloads<T: Transcript>(
        commitment: &Protocol11Commitment,
        params: DistributedPcsParams,
        backend: PcsBackendConfig,
        transcript: &mut T,
        payloads: &[Protocol11WorkerOpenPayload],
    ) -> PcsResult<Protocol11PreparedOpen> {
        prepare_open_from_worker_payloads(commitment, params, backend, transcript, payloads)
    }

    pub fn open_profiled_with_worker_data<T: Transcript>(
        commitment: &Protocol11Commitment,
        point: &[FieldElement],
        params: DistributedPcsParams,
        backend: PcsBackendConfig,
        transcript: &mut T,
        worker_data: &[Protocol11WorkerOpenData],
    ) -> PcsResult<(Protocol11Proof, Protocol11OpenProfile)> {
        open_profiled_from_worker_data(commitment, point, params, backend, transcript, worker_data)
    }

    pub fn open_profiled_with_worker_payloads<T: Transcript>(
        commitment: &Protocol11Commitment,
        point: &[FieldElement],
        params: DistributedPcsParams,
        backend: PcsBackendConfig,
        transcript: &mut T,
        payloads: &[Protocol11WorkerOpenPayload],
        column_openings: &[Protocol11WorkerColumnProof],
    ) -> PcsResult<(Protocol11Proof, Protocol11OpenProfile)> {
        open_profiled_from_worker_payloads(
            commitment,
            point,
            params,
            backend,
            transcript,
            payloads,
            column_openings,
        )
    }

    pub fn open_profiled_with_prepared_worker_payloads<T: Transcript>(
        commitment: &Protocol11Commitment,
        point: &[FieldElement],
        params: DistributedPcsParams,
        backend: PcsBackendConfig,
        transcript: &mut T,
        prepared: Protocol11PreparedOpen,
        column_openings: &[Protocol11WorkerColumnProof],
        a: &[FieldElement],
        beta: &[FieldElement],
    ) -> PcsResult<(Protocol11Proof, Protocol11OpenProfile)> {
        open_profiled_from_prepared_worker_payloads(
            commitment,
            point,
            params,
            backend,
            transcript,
            prepared,
            column_openings,
            a,
            beta,
        )
    }

    pub fn open_profiled_with_prepared_worker_matrix_columns<T: Transcript>(
        commitment: &Protocol11Commitment,
        point: &[FieldElement],
        params: DistributedPcsParams,
        backend: PcsBackendConfig,
        transcript: &mut T,
        prepared: Protocol11PreparedOpen,
        matrix_column_openings: &[Protocol11WorkerMatrixColumnProof],
        a: &[FieldElement],
        beta: &[FieldElement],
    ) -> PcsResult<(Protocol11Proof, Protocol11OpenProfile)> {
        let column_openings = complete_matrix_column_proofs(&prepared, matrix_column_openings)?;
        open_profiled_from_prepared_worker_payloads(
            commitment,
            point,
            params,
            backend,
            transcript,
            prepared,
            &column_openings,
            a,
            beta,
        )
    }

    pub fn open_worker_challenges<T: Transcript>(
        commitment: &Protocol11Commitment,
        point: &[FieldElement],
        transcript: &mut T,
    ) -> PcsResult<(Vec<FieldElement>, Vec<FieldElement>)> {
        validate_commitment(commitment)?;
        let layout = Protocol11Layout::from_commitment(commitment)?;
        let row_vars =
            log2_power_of_two(layout.row_axis_len).map_err(|_| PcsError::InvalidLength)?;
        let col_vars = log2_power_of_two(layout.row_width).map_err(|_| PcsError::InvalidLength)?;
        if point.len() != row_vars + col_vars {
            return Err(PcsError::InvalidEvaluation);
        }
        let (s1, _) = point.split_at(row_vars);
        absorb_protocol11_commitment(transcript, commitment);
        transcript.absorb_domain(b"protocol-11-eval");
        for coordinate in point {
            transcript.absorb_field(b"point", *coordinate);
        }
        let a = (0..layout.matrix_rows)
            .map(|_| transcript.challenge_field::<FieldElement>(b"protocol-11-a"))
            .collect::<Vec<_>>();
        let beta = (0..layout.matrix_rows)
            .map(|row| eq_basis(s1, row).map_err(|_| PcsError::InvalidEvaluation))
            .collect::<PcsResult<Vec<_>>>()?;
        Ok((a, beta))
    }

    pub fn verify<T: Transcript>(
        commitment: &Protocol11Commitment,
        proof: &Protocol11Proof,
        params: DistributedPcsParams,
        transcript: &mut T,
    ) -> PcsResult<()> {
        Self::verify_profiled(commitment, proof, params, transcript).map(|_| ())
    }

    pub fn verify_with_config<T: Transcript>(
        commitment: &Protocol11Commitment,
        proof: &Protocol11Proof,
        params: DistributedPcsParams,
        backend: PcsBackendConfig,
        transcript: &mut T,
    ) -> PcsResult<()> {
        Self::verify_profiled_with_config(commitment, proof, params, backend, transcript)
            .map(|_| ())
    }

    pub fn verify_profiled<T: Transcript>(
        commitment: &Protocol11Commitment,
        proof: &Protocol11Proof,
        params: DistributedPcsParams,
        transcript: &mut T,
    ) -> PcsResult<Protocol11VerifyProfile> {
        Self::verify_profiled_with_config(commitment, proof, params, commitment.backend, transcript)
    }

    pub fn verify_profiled_with_config<T: Transcript>(
        commitment: &Protocol11Commitment,
        proof: &Protocol11Proof,
        params: DistributedPcsParams,
        backend: PcsBackendConfig,
        transcript: &mut T,
    ) -> PcsResult<Protocol11VerifyProfile> {
        backend.validate()?;
        if commitment.backend != backend || proof.backend != backend {
            return Err(PcsError::InvalidProof);
        }
        let mut profile = Protocol11VerifyProfile::default();
        validate_commitment(commitment)?;
        let layout = Protocol11Layout::from_commitment(commitment)?;
        let row_vars =
            log2_power_of_two(layout.row_axis_len).map_err(|_| PcsError::InvalidLength)?;
        let col_vars = log2_power_of_two(layout.row_width).map_err(|_| PcsError::InvalidLength)?;
        if proof.point.len() != row_vars + col_vars
            || proof.eval_commitments.len() != commitment.workers.len()
            || proof.merkle_roots.len() != commitment.workers.len()
            || proof.column_openings.len() != commitment.workers.len()
        {
            return Err(PcsError::InvalidProof);
        }
        let (s1, s2) = proof.point.split_at(row_vars);
        absorb_protocol11_commitment(transcript, commitment);
        transcript.absorb_domain(b"protocol-11-eval");
        for coordinate in &proof.point {
            transcript.absorb_field(b"point", *coordinate);
        }
        let expected_a = (0..layout.matrix_rows)
            .map(|_| transcript.challenge_field::<FieldElement>(b"protocol-11-a"))
            .collect::<Vec<_>>();
        let expected_beta = (0..layout.matrix_rows)
            .map(|row| eq_basis(s1, row).map_err(|_| PcsError::InvalidEvaluation))
            .collect::<PcsResult<Vec<_>>>()?;
        validate_eval_commitments(commitment, &proof.eval_commitments, &proof.merkle_roots)?;
        absorb_protocol11_eval_commitments(
            transcript,
            &proof.eval_commitments,
            &proof.merkle_roots,
        );
        let query_count = params.effective_query_count(layout.encoded_width)?;
        profile.column_query_count = query_count;
        profile.query_security_bits = backend.security_bits.max(params.security_bits).max(1);
        profile.algebraic_security_bits = GOLDILOCKS_ALGEBRAIC_SECURITY_BITS;
        let expected_queries =
            transcript.challenge_indices(b"protocol-11-columns", query_count, layout.encoded_width);
        if expected_queries != proof.query_indices {
            return Err(PcsError::InvalidProof);
        }
        let stage_start = Instant::now();
        verify_column_proofs(commitment, proof, &layout)?;
        profile.column_verify_ms = elapsed_ms(stage_start);
        let (y1, y2) =
            aggregate_column_claims(&proof.column_openings, &expected_a, &expected_beta, &layout)?;
        if y1 != proof.y1 || y2 != proof.y2 {
            return Err(PcsError::InvalidEvaluation);
        }
        let stage_start = Instant::now();
        let mut f2_systematic_point = s2.to_vec();
        f2_systematic_point.extend([FieldElement::ZERO, FieldElement::ZERO]);
        verify_f2_openings(
            &proof.eval_commitments,
            &proof.f2_opening,
            &f2_systematic_point,
            params,
            backend,
            transcript,
        )?;
        profile.pcs_query_count = batched_opening_query_count(&proof.f2_opening.proof);
        profile.f2_verify_ms = elapsed_ms(stage_start);
        if proof.f2_opening.aggregate_value != proof.claimed_value {
            return Err(PcsError::InvalidEvaluation);
        }
        let f1_commitments = proof
            .eval_commitments
            .iter()
            .map(|commitment| commitment.f1.clone())
            .collect::<Vec<_>>();
        let e1_commitments = proof
            .eval_commitments
            .iter()
            .map(|commitment| commitment.e1.clone())
            .collect::<Vec<_>>();
        let f2_commitments = proof
            .eval_commitments
            .iter()
            .map(|commitment| commitment.f2.clone())
            .collect::<Vec<_>>();
        let e2_commitments = proof
            .eval_commitments
            .iter()
            .map(|commitment| commitment.e2.clone())
            .collect::<Vec<_>>();
        let encoding_relations = [
            Protocol10EncodingVerifierInput {
                f_commitments: &f1_commitments,
                e_commitments: &e1_commitments,
            },
            Protocol10EncodingVerifierInput {
                f_commitments: &f2_commitments,
                e_commitments: &e2_commitments,
            },
        ];
        let encoding_verify_ms = verify_protocol10_encoding_batch_profiled(
            &encoding_relations,
            &proof.encoding_batch,
            params,
            backend,
            transcript,
        )?;
        profile.protocol10_e1_verify_ms = encoding_verify_ms[0];
        profile.protocol10_e2_verify_ms = encoding_verify_ms[1];
        transcript.absorb_field(b"protocol-11-claimed-value", proof.claimed_value);
        if transcript.state() != proof.transcript_state {
            return Err(PcsError::InvalidProof);
        }
        Ok(profile)
    }
}

fn worker_open_payload_and_advice(
    data: &Protocol11WorkerOpenData,
    backend: PcsBackendConfig,
) -> PcsResult<(
    Protocol11WorkerOpenPayload,
    Protocol11WorkerEvalCommitments,
    Protocol11WorkerMerkleRoots,
    Protocol11WorkerEvalAdvice,
)> {
    let (f1, f1_advice) = commit_pc_with_advice(&data.f1_pad, backend)?;
    let (e1, e1_advice) = commit_pc_with_advice(&data.e1, backend)?;
    let (f2, f2_advice) = commit_pc_with_advice(&data.f2_pad, backend)?;
    let (e2, e2_advice) = commit_pc_with_advice(&data.e2, backend)?;
    let eval_commitments = Protocol11WorkerEvalCommitments {
        worker_id: data.worker_id,
        f1,
        e1,
        f2,
        e2,
    };
    let advice = Protocol11WorkerEvalAdvice {
        worker_id: data.worker_id,
        f1: f1_advice,
        e1: e1_advice,
        f2: f2_advice,
        e2: e2_advice,
    };
    let merkle_roots = Protocol11WorkerMerkleRoots {
        worker_id: data.worker_id,
        e1_root: advice.e1.commitment(),
        e2_root: advice.e2.commitment(),
    };
    Ok((
        Protocol11WorkerOpenPayload {
            worker_id: data.worker_id,
            f1_pad: data.f1_pad.clone(),
            f2_pad: data.f2_pad.clone(),
        },
        eval_commitments,
        merkle_roots,
        advice,
    ))
}

fn validate_worker_open_payloads(
    commitment: &Protocol11Commitment,
    layout: &Protocol11Layout,
    payloads: &mut [Protocol11WorkerOpenPayload],
) -> PcsResult<()> {
    if payloads.len() != commitment.workers.len() {
        return Err(PcsError::InvalidWorker);
    }
    payloads.sort_by_key(|payload| payload.worker_id);
    for (worker_id, payload) in payloads.iter().enumerate() {
        if payload.worker_id != worker_id
            || payload.f1_pad.len() != layout.encoded_width
            || payload.f2_pad.len() != layout.encoded_width
        {
            return Err(PcsError::InvalidLength);
        }
    }
    Ok(())
}

fn prepare_open_from_worker_payloads<T: Transcript>(
    commitment: &Protocol11Commitment,
    params: DistributedPcsParams,
    backend: PcsBackendConfig,
    transcript: &mut T,
    payloads: &[Protocol11WorkerOpenPayload],
) -> PcsResult<Protocol11PreparedOpen> {
    backend.validate()?;
    if commitment.backend != backend {
        return Err(PcsError::InvalidCommitment);
    }
    validate_commitment(commitment)?;
    let layout = Protocol11Layout::from_commitment(commitment)?;
    let mut payloads = payloads.to_vec();
    validate_worker_open_payloads(commitment, &layout, &mut payloads)?;
    let stage_start = Instant::now();
    let eval_commitment_advice = payloads
        .par_iter()
        .map(|payload| {
            let f1 = payload.f1_pad[..layout.row_width].to_vec();
            let f2 = payload.f2_pad[..layout.row_width].to_vec();
            let e1 = brakedown_encode(&f1)?;
            let e2 = brakedown_encode(&f2)?;
            let data = Protocol11WorkerOpenData {
                worker_id: payload.worker_id,
                encoded_rows: Vec::new(),
                f1,
                f1_pad: payload.f1_pad.clone(),
                e1,
                f2,
                f2_pad: payload.f2_pad.clone(),
                e2,
            };
            worker_open_payload_and_advice(&data, backend)
        })
        .collect::<PcsResult<Vec<_>>>()?;
    let eval_commitments = eval_commitment_advice
        .iter()
        .zip(&payloads)
        .map(
            |((computed_payload, commitments, _, _), expected_payload)| {
                if computed_payload != expected_payload {
                    return Err(PcsError::InvalidCommitment);
                }
                Ok(commitments.clone())
            },
        )
        .collect::<PcsResult<Vec<_>>>()?;
    let merkle_roots = eval_commitment_advice
        .iter()
        .map(|(_, _, roots, _)| roots.clone())
        .collect::<Vec<_>>();
    let eval_advices = eval_commitment_advice
        .into_iter()
        .map(|(_, _, _, advice)| advice)
        .collect::<Vec<_>>();
    let worker_eval_commit_ms = elapsed_ms(stage_start);
    absorb_protocol11_eval_commitments(transcript, &eval_commitments, &merkle_roots);
    let query_count = params.effective_query_count(layout.encoded_width)?;
    let query_indices =
        transcript.challenge_indices(b"protocol-11-columns", query_count, layout.encoded_width);
    Ok(Protocol11PreparedOpen {
        payloads,
        eval_commitments,
        merkle_roots,
        eval_advices,
        query_indices,
        worker_eval_commit_ms,
    })
}

fn open_profiled_from_worker_data<T: Transcript>(
    commitment: &Protocol11Commitment,
    point: &[FieldElement],
    params: DistributedPcsParams,
    backend: PcsBackendConfig,
    transcript: &mut T,
    worker_data: &[Protocol11WorkerOpenData],
) -> PcsResult<(Protocol11Proof, Protocol11OpenProfile)> {
    backend.validate()?;
    if commitment.backend != backend {
        return Err(PcsError::InvalidCommitment);
    }
    let mut profile = Protocol11OpenProfile::default();
    validate_commitment(commitment)?;
    let layout = Protocol11Layout::from_commitment(commitment)?;
    if worker_data.len() != commitment.workers.len() {
        return Err(PcsError::InvalidWorker);
    }
    let mut worker_data = worker_data.to_vec();
    worker_data.sort_by_key(|data| data.worker_id);
    for (worker_id, data) in worker_data.iter().enumerate() {
        if data.worker_id != worker_id
            || data.encoded_rows.len() != layout.rows_per_worker
            || data
                .encoded_rows
                .iter()
                .any(|row| row.len() != layout.encoded_width)
            || data.f1.len() != layout.row_width
            || data.f2.len() != layout.row_width
            || data.f1_pad.len() != layout.encoded_width
            || data.f2_pad.len() != layout.encoded_width
            || data.e1.len() != layout.encoded_width
            || data.e2.len() != layout.encoded_width
        {
            return Err(PcsError::InvalidLength);
        }
    }
    let row_vars = log2_power_of_two(layout.row_axis_len).map_err(|_| PcsError::InvalidLength)?;
    let col_vars = log2_power_of_two(layout.row_width).map_err(|_| PcsError::InvalidLength)?;
    if point.len() != row_vars + col_vars {
        return Err(PcsError::InvalidEvaluation);
    }
    let (_s1, s2) = point.split_at(row_vars);
    absorb_protocol11_commitment(transcript, commitment);
    transcript.absorb_domain(b"protocol-11-eval");
    for coordinate in point {
        transcript.absorb_field(b"point", *coordinate);
    }
    let a = (0..layout.matrix_rows)
        .map(|_| transcript.challenge_field::<FieldElement>(b"protocol-11-a"))
        .collect::<Vec<_>>();
    let beta = (0..layout.matrix_rows)
        .map(|row| eq_basis(&point[..row_vars], row).map_err(|_| PcsError::InvalidEvaluation))
        .collect::<PcsResult<Vec<_>>>()?;

    let stage_start = Instant::now();
    for data in &worker_data {
        let (start, _) = worker_row_range(&layout, data.worker_id);
        for slot in 0..layout.row_width {
            let expected_f1 = data
                .encoded_rows
                .iter()
                .enumerate()
                .map(|(local_row, row)| row[slot] * a[start + local_row])
                .sum::<FieldElement>();
            let expected_f2 = data
                .encoded_rows
                .iter()
                .enumerate()
                .map(|(local_row, row)| row[slot] * beta[start + local_row])
                .sum::<FieldElement>();
            if data.e1[slot] != expected_f1 || data.e2[slot] != expected_f2 {
                return Err(PcsError::InvalidEvaluation);
            }
        }
    }
    let eval_commitment_advice = worker_data
        .par_iter()
        .map(|data| {
            let (f1, f1_advice) = commit_pc_with_advice(&data.f1_pad, backend)?;
            let (e1, e1_advice) = commit_pc_with_advice(&data.e1, backend)?;
            let (f2, f2_advice) = commit_pc_with_advice(&data.f2_pad, backend)?;
            let (e2, e2_advice) = commit_pc_with_advice(&data.e2, backend)?;
            Ok((
                Protocol11WorkerEvalCommitments {
                    worker_id: data.worker_id,
                    f1,
                    e1,
                    f2,
                    e2,
                },
                Protocol11WorkerEvalAdvice {
                    worker_id: data.worker_id,
                    f1: f1_advice,
                    e1: e1_advice,
                    f2: f2_advice,
                    e2: e2_advice,
                },
            ))
        })
        .collect::<PcsResult<Vec<_>>>()?;
    let eval_commitments = eval_commitment_advice
        .iter()
        .map(|(commitment, _)| commitment.clone())
        .collect::<Vec<_>>();
    let eval_advices = eval_commitment_advice
        .iter()
        .map(|(_, advice)| advice.clone())
        .collect::<Vec<_>>();
    let merkle_roots = eval_advices
        .par_iter()
        .map(|advice| Protocol11WorkerMerkleRoots {
            worker_id: advice.worker_id,
            e1_root: advice.e1.commitment(),
            e2_root: advice.e2.commitment(),
        })
        .collect::<Vec<_>>();
    profile.worker_eval_commit_ms = elapsed_ms(stage_start);
    absorb_protocol11_eval_commitments(transcript, &eval_commitments, &merkle_roots);

    let query_count = params.effective_query_count(layout.encoded_width)?;
    let query_indices =
        transcript.challenge_indices(b"protocol-11-columns", query_count, layout.encoded_width);
    let stage_start = Instant::now();
    let column_openings = worker_data
        .par_iter()
        .zip(eval_advices.par_iter())
        .map(|(data, advice)| worker_column_proof(data, advice, commitment, &query_indices))
        .collect::<PcsResult<Vec<_>>>()?;
    profile.column_open_ms = elapsed_ms(stage_start);
    let (y1, y2) = aggregate_column_claims(&column_openings, &a, &beta, &layout)?;

    let stage_start = Instant::now();
    let mut f2_systematic_point = s2.to_vec();
    f2_systematic_point.extend([FieldElement::ZERO, FieldElement::ZERO]);
    let f2_values = worker_data
        .iter()
        .map(|data| data.f2_pad.clone())
        .collect::<Vec<_>>();
    let f2_commitments = eval_commitments
        .iter()
        .map(|commitment| commitment.f2.clone())
        .collect::<Vec<_>>();
    let f2_advices = eval_advices
        .iter()
        .map(|advice| &advice.f2)
        .collect::<Vec<_>>();
    let f2_opening = open_distributed(
        DistributedOpenRequest {
            label: b"protocol-11-f2",
            values: &f2_values,
            commitments: &f2_commitments,
            advices: &f2_advices,
            point: &f2_systematic_point,
            params,
            backend,
        },
        transcript,
    )?;
    profile.f2_open_ms = elapsed_ms(stage_start);
    let claimed_value = f2_opening.aggregate_value;

    let f1_locals = worker_data
        .iter()
        .map(|data| data.f1.clone())
        .collect::<Vec<_>>();
    let f1_pad_locals = worker_data
        .iter()
        .map(|data| data.f1_pad.clone())
        .collect::<Vec<_>>();
    let e1_locals = worker_data
        .iter()
        .map(|data| data.e1.clone())
        .collect::<Vec<_>>();
    let f2_locals = worker_data
        .iter()
        .map(|data| data.f2.clone())
        .collect::<Vec<_>>();
    let f2_pad_locals = worker_data
        .iter()
        .map(|data| data.f2_pad.clone())
        .collect::<Vec<_>>();
    let e2_locals = worker_data
        .iter()
        .map(|data| data.e2.clone())
        .collect::<Vec<_>>();
    let f_commitments_e1 = eval_commitments
        .iter()
        .map(|commitment| commitment.f1.clone())
        .collect::<Vec<_>>();
    let e_commitments_e1 = eval_commitments
        .iter()
        .map(|commitment| commitment.e1.clone())
        .collect::<Vec<_>>();
    let f_commitments_e2 = eval_commitments
        .iter()
        .map(|commitment| commitment.f2.clone())
        .collect::<Vec<_>>();
    let e_commitments_e2 = eval_commitments
        .iter()
        .map(|commitment| commitment.e2.clone())
        .collect::<Vec<_>>();
    let f1_advices = eval_advices
        .iter()
        .map(|advice| &advice.f1)
        .collect::<Vec<_>>();
    let e1_advices = eval_advices
        .iter()
        .map(|advice| &advice.e1)
        .collect::<Vec<_>>();
    let f2_advices = eval_advices
        .iter()
        .map(|advice| &advice.f2)
        .collect::<Vec<_>>();
    let e2_advices = eval_advices
        .iter()
        .map(|advice| &advice.e2)
        .collect::<Vec<_>>();
    let encoding_relations = [
        Protocol10EncodingProverInput {
            f_locals: &f1_locals,
            f_pad_locals: &f1_pad_locals,
            e_locals: &e1_locals,
            f_commitments: &f_commitments_e1,
            e_commitments: &e_commitments_e1,
            f_advices: &f1_advices,
            e_advices: &e1_advices,
        },
        Protocol10EncodingProverInput {
            f_locals: &f2_locals,
            f_pad_locals: &f2_pad_locals,
            e_locals: &e2_locals,
            f_commitments: &f_commitments_e2,
            e_commitments: &e_commitments_e2,
            f_advices: &f2_advices,
            e_advices: &e2_advices,
        },
    ];
    let (encoding_batch, encoding_profiles) =
        prove_protocol10_encoding_batch_profiled(&encoding_relations, params, backend, transcript)?;
    let profile_e1 = encoding_profiles[0];
    profile.protocol10_e1_sumcheck_ms = profile_e1.sumcheck_ms;
    profile.protocol10_e1_open_ms = profile_e1.opening_ms;
    profile.protocol10_e1_opening_batch_open_ms = profile_e1.opening_batch_open_ms;
    profile.protocol10_e1_hu_open_ms = profile_e1.hu_open_ms;
    profile.protocol10_e1_e_at_r_open_ms = profile_e1.e_at_r_open_ms;
    profile.protocol10_e1_f_at_u_prime_open_ms = profile_e1.f_at_u_prime_open_ms;
    profile.protocol10_e1_e_systematic_open_ms = profile_e1.e_systematic_open_ms;
    let profile_e2 = encoding_profiles[1];
    profile.protocol10_e2_sumcheck_ms = profile_e2.sumcheck_ms;
    profile.protocol10_e2_open_ms = profile_e2.opening_ms;
    profile.protocol10_e2_opening_batch_open_ms = profile_e2.opening_batch_open_ms;
    profile.protocol10_e2_hu_open_ms = profile_e2.hu_open_ms;
    profile.protocol10_e2_e_at_r_open_ms = profile_e2.e_at_r_open_ms;
    profile.protocol10_e2_f_at_u_prime_open_ms = profile_e2.f_at_u_prime_open_ms;
    profile.protocol10_e2_e_systematic_open_ms = profile_e2.e_systematic_open_ms;
    transcript.absorb_field(b"protocol-11-claimed-value", claimed_value);

    Ok((
        Protocol11Proof {
            backend,
            point: point.to_vec(),
            claimed_value,
            query_indices,
            eval_commitments,
            merkle_roots,
            column_openings,
            y1,
            y2,
            f2_opening,
            encoding_batch,
            transcript_state: transcript.state(),
        },
        profile,
    ))
}

fn open_profiled_from_worker_payloads<T: Transcript>(
    commitment: &Protocol11Commitment,
    point: &[FieldElement],
    params: DistributedPcsParams,
    backend: PcsBackendConfig,
    transcript: &mut T,
    payloads: &[Protocol11WorkerOpenPayload],
    column_openings: &[Protocol11WorkerColumnProof],
) -> PcsResult<(Protocol11Proof, Protocol11OpenProfile)> {
    backend.validate()?;
    if commitment.backend != backend {
        return Err(PcsError::InvalidCommitment);
    }
    let mut profile = Protocol11OpenProfile::default();
    validate_commitment(commitment)?;
    let layout = Protocol11Layout::from_commitment(commitment)?;
    let mut payloads = payloads.to_vec();
    validate_worker_open_payloads(commitment, &layout, &mut payloads)?;
    let row_vars = log2_power_of_two(layout.row_axis_len).map_err(|_| PcsError::InvalidLength)?;
    let col_vars = log2_power_of_two(layout.row_width).map_err(|_| PcsError::InvalidLength)?;
    if point.len() != row_vars + col_vars {
        return Err(PcsError::InvalidEvaluation);
    }
    let (_s1, s2) = point.split_at(row_vars);
    absorb_protocol11_commitment(transcript, commitment);
    transcript.absorb_domain(b"protocol-11-eval");
    for coordinate in point {
        transcript.absorb_field(b"point", *coordinate);
    }
    let a = (0..layout.matrix_rows)
        .map(|_| transcript.challenge_field::<FieldElement>(b"protocol-11-a"))
        .collect::<Vec<_>>();
    let beta = (0..layout.matrix_rows)
        .map(|row| eq_basis(&point[..row_vars], row).map_err(|_| PcsError::InvalidEvaluation))
        .collect::<PcsResult<Vec<_>>>()?;

    let stage_start = Instant::now();
    let eval_commitment_advice = payloads
        .par_iter()
        .map(|payload| {
            let f1 = payload.f1_pad[..layout.row_width].to_vec();
            let f2 = payload.f2_pad[..layout.row_width].to_vec();
            let e1 = brakedown_encode(&f1)?;
            let e2 = brakedown_encode(&f2)?;
            let data = Protocol11WorkerOpenData {
                worker_id: payload.worker_id,
                encoded_rows: Vec::new(),
                f1,
                f1_pad: payload.f1_pad.clone(),
                e1,
                f2,
                f2_pad: payload.f2_pad.clone(),
                e2,
            };
            worker_open_payload_and_advice(&data, backend)
        })
        .collect::<PcsResult<Vec<_>>>()?;
    let eval_commitments = eval_commitment_advice
        .iter()
        .zip(&payloads)
        .map(
            |((computed_payload, commitments, _, _), expected_payload)| {
                if computed_payload != expected_payload {
                    return Err(PcsError::InvalidCommitment);
                }
                Ok(commitments.clone())
            },
        )
        .collect::<PcsResult<Vec<_>>>()?;
    let merkle_roots = eval_commitment_advice
        .iter()
        .map(|(_, _, roots, _)| roots.clone())
        .collect::<Vec<_>>();
    let eval_advices = eval_commitment_advice
        .iter()
        .map(|(_, _, _, advice)| advice.clone())
        .collect::<Vec<_>>();
    profile.worker_eval_commit_ms = elapsed_ms(stage_start);
    absorb_protocol11_eval_commitments(transcript, &eval_commitments, &merkle_roots);

    let query_count = params.effective_query_count(layout.encoded_width)?;
    let query_indices =
        transcript.challenge_indices(b"protocol-11-columns", query_count, layout.encoded_width);
    let stage_start = Instant::now();
    let mut column_openings = column_openings.to_vec();
    if column_openings.len() != payloads.len() {
        return Err(PcsError::InvalidProof);
    }
    column_openings.sort_by_key(|opening| opening.worker_id);
    for (worker_id, worker_opening) in column_openings.iter().enumerate() {
        if worker_opening.worker_id != worker_id
            || worker_opening.columns.len() != query_indices.len()
            || worker_opening
                .columns
                .iter()
                .zip(&query_indices)
                .any(|(column, expected)| column.index != *expected)
        {
            return Err(PcsError::InvalidProof);
        }
    }
    let (y1, y2) = aggregate_column_claims(&column_openings, &a, &beta, &layout)?;
    profile.column_open_ms = elapsed_ms(stage_start);

    let stage_start = Instant::now();
    let mut f2_systematic_point = s2.to_vec();
    f2_systematic_point.extend([FieldElement::ZERO, FieldElement::ZERO]);
    let f2_values = payloads
        .iter()
        .map(|payload| payload.f2_pad.clone())
        .collect::<Vec<_>>();
    let f2_commitments = eval_commitments
        .iter()
        .map(|commitment| commitment.f2.clone())
        .collect::<Vec<_>>();
    let f2_advices = eval_advices
        .iter()
        .map(|advice| &advice.f2)
        .collect::<Vec<_>>();
    let f2_opening = open_distributed(
        DistributedOpenRequest {
            label: b"protocol-11-f2",
            values: &f2_values,
            commitments: &f2_commitments,
            advices: &f2_advices,
            point: &f2_systematic_point,
            params,
            backend,
        },
        transcript,
    )?;
    profile.f2_open_ms = elapsed_ms(stage_start);
    let claimed_value = f2_opening.aggregate_value;

    let f1_locals = payloads
        .iter()
        .map(|payload| payload.f1_pad[..layout.row_width].to_vec())
        .collect::<Vec<_>>();
    let f1_pad_locals = payloads
        .iter()
        .map(|payload| payload.f1_pad.clone())
        .collect::<Vec<_>>();
    let e1_locals = payloads
        .iter()
        .map(|payload| brakedown_encode(&payload.f1_pad[..layout.row_width]))
        .collect::<PcsResult<Vec<_>>>()?;
    let f2_locals = payloads
        .iter()
        .map(|payload| payload.f2_pad[..layout.row_width].to_vec())
        .collect::<Vec<_>>();
    let f2_pad_locals = payloads
        .iter()
        .map(|payload| payload.f2_pad.clone())
        .collect::<Vec<_>>();
    let e2_locals = payloads
        .iter()
        .map(|payload| brakedown_encode(&payload.f2_pad[..layout.row_width]))
        .collect::<PcsResult<Vec<_>>>()?;
    let f_commitments_e1 = eval_commitments
        .iter()
        .map(|commitment| commitment.f1.clone())
        .collect::<Vec<_>>();
    let e_commitments_e1 = eval_commitments
        .iter()
        .map(|commitment| commitment.e1.clone())
        .collect::<Vec<_>>();
    let f_commitments_e2 = eval_commitments
        .iter()
        .map(|commitment| commitment.f2.clone())
        .collect::<Vec<_>>();
    let e_commitments_e2 = eval_commitments
        .iter()
        .map(|commitment| commitment.e2.clone())
        .collect::<Vec<_>>();
    let f1_advices = eval_advices
        .iter()
        .map(|advice| &advice.f1)
        .collect::<Vec<_>>();
    let e1_advices = eval_advices
        .iter()
        .map(|advice| &advice.e1)
        .collect::<Vec<_>>();
    let f2_advices = eval_advices
        .iter()
        .map(|advice| &advice.f2)
        .collect::<Vec<_>>();
    let e2_advices = eval_advices
        .iter()
        .map(|advice| &advice.e2)
        .collect::<Vec<_>>();
    let encoding_relations = [
        Protocol10EncodingProverInput {
            f_locals: &f1_locals,
            f_pad_locals: &f1_pad_locals,
            e_locals: &e1_locals,
            f_commitments: &f_commitments_e1,
            e_commitments: &e_commitments_e1,
            f_advices: &f1_advices,
            e_advices: &e1_advices,
        },
        Protocol10EncodingProverInput {
            f_locals: &f2_locals,
            f_pad_locals: &f2_pad_locals,
            e_locals: &e2_locals,
            f_commitments: &f_commitments_e2,
            e_commitments: &e_commitments_e2,
            f_advices: &f2_advices,
            e_advices: &e2_advices,
        },
    ];
    let (encoding_batch, encoding_profiles) =
        prove_protocol10_encoding_batch_profiled(&encoding_relations, params, backend, transcript)?;
    let profile_e1 = encoding_profiles[0];
    profile.protocol10_e1_sumcheck_ms = profile_e1.sumcheck_ms;
    profile.protocol10_e1_open_ms = profile_e1.opening_ms;
    profile.protocol10_e1_opening_batch_open_ms = profile_e1.opening_batch_open_ms;
    profile.protocol10_e1_hu_open_ms = profile_e1.hu_open_ms;
    profile.protocol10_e1_e_at_r_open_ms = profile_e1.e_at_r_open_ms;
    profile.protocol10_e1_f_at_u_prime_open_ms = profile_e1.f_at_u_prime_open_ms;
    profile.protocol10_e1_e_systematic_open_ms = profile_e1.e_systematic_open_ms;
    let profile_e2 = encoding_profiles[1];
    profile.protocol10_e2_sumcheck_ms = profile_e2.sumcheck_ms;
    profile.protocol10_e2_open_ms = profile_e2.opening_ms;
    profile.protocol10_e2_opening_batch_open_ms = profile_e2.opening_batch_open_ms;
    profile.protocol10_e2_hu_open_ms = profile_e2.hu_open_ms;
    profile.protocol10_e2_e_at_r_open_ms = profile_e2.e_at_r_open_ms;
    profile.protocol10_e2_f_at_u_prime_open_ms = profile_e2.f_at_u_prime_open_ms;
    profile.protocol10_e2_e_systematic_open_ms = profile_e2.e_systematic_open_ms;
    transcript.absorb_field(b"protocol-11-claimed-value", claimed_value);

    Ok((
        Protocol11Proof {
            backend,
            point: point.to_vec(),
            claimed_value,
            query_indices,
            eval_commitments,
            merkle_roots,
            column_openings,
            y1,
            y2,
            f2_opening,
            encoding_batch,
            transcript_state: transcript.state(),
        },
        profile,
    ))
}

fn open_profiled_from_prepared_worker_payloads<T: Transcript>(
    commitment: &Protocol11Commitment,
    point: &[FieldElement],
    params: DistributedPcsParams,
    backend: PcsBackendConfig,
    transcript: &mut T,
    prepared: Protocol11PreparedOpen,
    column_openings: &[Protocol11WorkerColumnProof],
    a: &[FieldElement],
    beta: &[FieldElement],
) -> PcsResult<(Protocol11Proof, Protocol11OpenProfile)> {
    backend.validate()?;
    if commitment.backend != backend {
        return Err(PcsError::InvalidCommitment);
    }
    validate_commitment(commitment)?;
    let layout = Protocol11Layout::from_commitment(commitment)?;
    let row_vars = log2_power_of_two(layout.row_axis_len).map_err(|_| PcsError::InvalidLength)?;
    let col_vars = log2_power_of_two(layout.row_width).map_err(|_| PcsError::InvalidLength)?;
    if point.len() != row_vars + col_vars
        || a.len() != layout.matrix_rows
        || beta.len() != layout.matrix_rows
    {
        return Err(PcsError::InvalidEvaluation);
    }
    let (_, s2) = point.split_at(row_vars);
    let Protocol11PreparedOpen {
        payloads,
        eval_commitments,
        merkle_roots,
        eval_advices,
        query_indices,
        worker_eval_commit_ms,
    } = prepared;
    if payloads.len() != commitment.workers.len()
        || eval_commitments.len() != payloads.len()
        || merkle_roots.len() != payloads.len()
        || eval_advices.len() != payloads.len()
    {
        return Err(PcsError::InvalidWorker);
    }
    let mut profile = Protocol11OpenProfile {
        worker_eval_commit_ms,
        ..Protocol11OpenProfile::default()
    };

    let stage_start = Instant::now();
    let mut column_openings = column_openings.to_vec();
    if column_openings.len() != payloads.len() {
        return Err(PcsError::InvalidProof);
    }
    column_openings.sort_by_key(|opening| opening.worker_id);
    for (worker_id, worker_opening) in column_openings.iter().enumerate() {
        if worker_opening.worker_id != worker_id
            || worker_opening.columns.len() != query_indices.len()
            || worker_opening
                .columns
                .iter()
                .zip(&query_indices)
                .any(|(column, expected)| column.index != *expected)
        {
            return Err(PcsError::InvalidProof);
        }
    }
    let (y1, y2) = aggregate_column_claims(&column_openings, a, beta, &layout)?;
    profile.column_open_ms = elapsed_ms(stage_start);

    let stage_start = Instant::now();
    let mut f2_systematic_point = s2.to_vec();
    f2_systematic_point.extend([FieldElement::ZERO, FieldElement::ZERO]);
    let f2_values = payloads
        .iter()
        .map(|payload| payload.f2_pad.clone())
        .collect::<Vec<_>>();
    let f2_commitments = eval_commitments
        .iter()
        .map(|commitment| commitment.f2.clone())
        .collect::<Vec<_>>();
    let f2_advices = eval_advices
        .iter()
        .map(|advice| &advice.f2)
        .collect::<Vec<_>>();
    let f2_opening = open_distributed(
        DistributedOpenRequest {
            label: b"protocol-11-f2",
            values: &f2_values,
            commitments: &f2_commitments,
            advices: &f2_advices,
            point: &f2_systematic_point,
            params,
            backend,
        },
        transcript,
    )?;
    profile.f2_open_ms = elapsed_ms(stage_start);
    let claimed_value = f2_opening.aggregate_value;

    let f1_locals = payloads
        .iter()
        .map(|payload| payload.f1_pad[..layout.row_width].to_vec())
        .collect::<Vec<_>>();
    let f1_pad_locals = payloads
        .iter()
        .map(|payload| payload.f1_pad.clone())
        .collect::<Vec<_>>();
    let e1_locals = payloads
        .iter()
        .map(|payload| brakedown_encode(&payload.f1_pad[..layout.row_width]))
        .collect::<PcsResult<Vec<_>>>()?;
    let f2_locals = payloads
        .iter()
        .map(|payload| payload.f2_pad[..layout.row_width].to_vec())
        .collect::<Vec<_>>();
    let f2_pad_locals = payloads
        .iter()
        .map(|payload| payload.f2_pad.clone())
        .collect::<Vec<_>>();
    let e2_locals = payloads
        .iter()
        .map(|payload| brakedown_encode(&payload.f2_pad[..layout.row_width]))
        .collect::<PcsResult<Vec<_>>>()?;
    let f_commitments_e1 = eval_commitments
        .iter()
        .map(|commitment| commitment.f1.clone())
        .collect::<Vec<_>>();
    let e_commitments_e1 = eval_commitments
        .iter()
        .map(|commitment| commitment.e1.clone())
        .collect::<Vec<_>>();
    let f_commitments_e2 = eval_commitments
        .iter()
        .map(|commitment| commitment.f2.clone())
        .collect::<Vec<_>>();
    let e_commitments_e2 = eval_commitments
        .iter()
        .map(|commitment| commitment.e2.clone())
        .collect::<Vec<_>>();
    let f1_advices = eval_advices
        .iter()
        .map(|advice| &advice.f1)
        .collect::<Vec<_>>();
    let e1_advices = eval_advices
        .iter()
        .map(|advice| &advice.e1)
        .collect::<Vec<_>>();
    let f2_advices = eval_advices
        .iter()
        .map(|advice| &advice.f2)
        .collect::<Vec<_>>();
    let e2_advices = eval_advices
        .iter()
        .map(|advice| &advice.e2)
        .collect::<Vec<_>>();
    let encoding_relations = [
        Protocol10EncodingProverInput {
            f_locals: &f1_locals,
            f_pad_locals: &f1_pad_locals,
            e_locals: &e1_locals,
            f_commitments: &f_commitments_e1,
            e_commitments: &e_commitments_e1,
            f_advices: &f1_advices,
            e_advices: &e1_advices,
        },
        Protocol10EncodingProverInput {
            f_locals: &f2_locals,
            f_pad_locals: &f2_pad_locals,
            e_locals: &e2_locals,
            f_commitments: &f_commitments_e2,
            e_commitments: &e_commitments_e2,
            f_advices: &f2_advices,
            e_advices: &e2_advices,
        },
    ];
    let (encoding_batch, encoding_profiles) =
        prove_protocol10_encoding_batch_profiled(&encoding_relations, params, backend, transcript)?;
    let profile_e1 = encoding_profiles[0];
    profile.protocol10_e1_sumcheck_ms = profile_e1.sumcheck_ms;
    profile.protocol10_e1_open_ms = profile_e1.opening_ms;
    profile.protocol10_e1_opening_batch_open_ms = profile_e1.opening_batch_open_ms;
    profile.protocol10_e1_hu_open_ms = profile_e1.hu_open_ms;
    profile.protocol10_e1_e_at_r_open_ms = profile_e1.e_at_r_open_ms;
    profile.protocol10_e1_f_at_u_prime_open_ms = profile_e1.f_at_u_prime_open_ms;
    profile.protocol10_e1_e_systematic_open_ms = profile_e1.e_systematic_open_ms;
    let profile_e2 = encoding_profiles[1];
    profile.protocol10_e2_sumcheck_ms = profile_e2.sumcheck_ms;
    profile.protocol10_e2_open_ms = profile_e2.opening_ms;
    profile.protocol10_e2_opening_batch_open_ms = profile_e2.opening_batch_open_ms;
    profile.protocol10_e2_hu_open_ms = profile_e2.hu_open_ms;
    profile.protocol10_e2_e_at_r_open_ms = profile_e2.e_at_r_open_ms;
    profile.protocol10_e2_f_at_u_prime_open_ms = profile_e2.f_at_u_prime_open_ms;
    profile.protocol10_e2_e_systematic_open_ms = profile_e2.e_systematic_open_ms;
    transcript.absorb_field(b"protocol-11-claimed-value", claimed_value);

    Ok((
        Protocol11Proof {
            backend,
            point: point.to_vec(),
            claimed_value,
            query_indices,
            eval_commitments,
            merkle_roots,
            column_openings,
            y1,
            y2,
            f2_opening,
            encoding_batch,
            transcript_state: transcript.state(),
        },
        profile,
    ))
}

pub fn encode_systematic(message: &[FieldElement]) -> PcsResult<Vec<FieldElement>> {
    BrakedownCodeSpec::new(message.len())?;
    brakedown_encode(message)
}

pub fn brakedown_parity_check_matrix(message_len: usize) -> PcsResult<SparseMatrix> {
    let spec = BrakedownCodeSpec::new(message_len)?;
    let n = spec.message_len;
    let mut matrix = SparseMatrix::new(spec.codeword_len, spec.codeword_len);
    for idx in 0..n {
        add_constraint(&mut matrix, idx, n + idx, expander_terms_block1(n, idx))?;
        add_constraint(
            &mut matrix,
            n + idx,
            2 * n + idx,
            expander_terms_block2(n, idx),
        )?;
        let terms = vec![
            (n + idx, FieldElement::ONE),
            (2 * n + idx, FieldElement::ONE),
            ((13 * idx + 17) % n, FieldElement::from(5_u64)),
        ];
        add_constraint(&mut matrix, 2 * n + idx, 3 * n + idx, terms)?;
    }
    Ok(matrix)
}

pub fn protocol11_proof_size_bytes(proof: &Protocol11Proof) -> usize {
    protocol11_proof_size_breakdown(proof).total_bytes()
}

pub fn protocol11_communication_bytes(proof: &Protocol11Proof) -> usize {
    protocol11_proof_size_bytes(proof)
}

pub fn protocol11_commitment_size_bytes(commitment: &Protocol11Commitment) -> usize {
    8 * 5
        + 32
        + commitment
            .workers
            .iter()
            .map(|worker| 8 + 8 + 8 + commitment_size_bytes(&worker.matrix_commitment))
            .sum::<usize>()
}

pub fn protocol11_evaluation_domain_len(commitment: &Protocol11Commitment) -> usize {
    commitment.row_axis_len * commitment.row_width
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Protocol10ProofSizeBreakdown {
    pub commitments_bytes: usize,
    pub public_scalars_bytes: usize,
    pub opening_batch_bytes: usize,
    pub hu_opening_bytes: usize,
    pub sumcheck_bytes: usize,
    pub e_at_r_openings_bytes: usize,
    pub f_at_u_prime_openings_bytes: usize,
    pub e_systematic_openings_bytes: usize,
}

impl Protocol10ProofSizeBreakdown {
    pub fn total_bytes(self) -> usize {
        let opening_bytes = if self.opening_batch_bytes > 0 {
            self.opening_batch_bytes
        } else {
            self.hu_opening_bytes
                + self.e_at_r_openings_bytes
                + self.f_at_u_prime_openings_bytes
                + self.e_systematic_openings_bytes
        };
        self.commitments_bytes + self.public_scalars_bytes + self.sumcheck_bytes + opening_bytes
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Protocol11ProofSizeBreakdown {
    pub point_query_public_bytes: usize,
    pub eval_commitments_bytes: usize,
    pub merkle_roots_bytes: usize,
    pub column_openings_bytes: usize,
    pub f2_openings_bytes: usize,
    pub protocol10_e1_bytes: usize,
    pub protocol10_e2_bytes: usize,
    pub transcript_overhead_bytes: usize,
    pub protocol10_e1: Protocol10ProofSizeBreakdown,
    pub protocol10_e2: Protocol10ProofSizeBreakdown,
}

impl Protocol11ProofSizeBreakdown {
    pub fn total_bytes(self) -> usize {
        self.point_query_public_bytes
            + self.eval_commitments_bytes
            + self.merkle_roots_bytes
            + self.column_openings_bytes
            + self.f2_openings_bytes
            + self.protocol10_e1_bytes
            + self.protocol10_e2_bytes
            + self.transcript_overhead_bytes
    }
}

pub fn protocol11_proof_size_breakdown(proof: &Protocol11Proof) -> Protocol11ProofSizeBreakdown {
    let mut protocol10_e1 = proof
        .encoding_batch
        .encodings
        .first()
        .map(protocol10_proof_size_breakdown)
        .unwrap_or_default();
    let protocol10_e2 = proof
        .encoding_batch
        .encodings
        .get(1)
        .map(protocol10_proof_size_breakdown)
        .unwrap_or_default();
    protocol10_e1.sumcheck_bytes =
        product_sumcheck_size_bytes(&proof.encoding_batch.product_sumcheck);
    Protocol11ProofSizeBreakdown {
        point_query_public_bytes: field_vec_size(&proof.point)
            + 8
            + usize_vec_size(&proof.query_indices)
            + field_vec_size(&proof.y1)
            + field_vec_size(&proof.y2),
        eval_commitments_bytes: proof
            .eval_commitments
            .iter()
            .map(protocol11_eval_commitments_size_bytes)
            .sum::<usize>(),
        merkle_roots_bytes: proof
            .merkle_roots
            .iter()
            .map(protocol11_merkle_roots_size_bytes)
            .sum::<usize>(),
        column_openings_bytes: proof
            .column_openings
            .iter()
            .map(protocol11_column_proof_size_bytes)
            .sum::<usize>(),
        f2_openings_bytes: batched_distributed_pc_opening_size_bytes(&proof.f2_opening),
        protocol10_e1_bytes: protocol10_e1.total_bytes(),
        protocol10_e2_bytes: protocol10_e2.total_bytes(),
        transcript_overhead_bytes: 32
            + 8
            + field_vec_size(&proof.encoding_batch.relation_challenges),
        protocol10_e1,
        protocol10_e2,
    }
}

pub fn protocol10_proof_size_breakdown(
    proof: &Protocol10EncodingProof,
) -> Protocol10ProofSizeBreakdown {
    let opening_batch_bytes = protocol10_opening_batch_size_bytes(&proof.opening_batch);
    let split = opening_batch_bytes / 4;
    let remainder = opening_batch_bytes - split * 4;
    Protocol10ProofSizeBreakdown {
        commitments_bytes: proof
            .f_commitments
            .iter()
            .map(pc_commitment_size_bytes)
            .sum::<usize>()
            + proof
                .e_commitments
                .iter()
                .map(pc_commitment_size_bytes)
                .sum::<usize>(),
        public_scalars_bytes: 8 * 6
            + field_vec_size(&proof.u)
            + pc_commitment_size_bytes(&proof.hu_commitment)
            + 8
            + 8
            + field_vec_size(&proof.u_prime)
            + 8
            + 8,
        opening_batch_bytes,
        hu_opening_bytes: split + remainder,
        sumcheck_bytes: 0,
        e_at_r_openings_bytes: split,
        f_at_u_prime_openings_bytes: split,
        e_systematic_openings_bytes: split,
    }
}

struct Protocol10EncodingProverInput<'a> {
    f_locals: &'a [Vec<FieldElement>],
    f_pad_locals: &'a [Vec<FieldElement>],
    e_locals: &'a [Vec<FieldElement>],
    f_commitments: &'a [PcCommitment],
    e_commitments: &'a [PcCommitment],
    f_advices: &'a [&'a PcCommitmentAdvice],
    e_advices: &'a [&'a PcCommitmentAdvice],
}

struct Protocol10EncodingVerifierInput<'a> {
    f_commitments: &'a [PcCommitment],
    e_commitments: &'a [PcCommitment],
}

struct Protocol10OpeningBatchProverInput<'a> {
    claim: Protocol10OpeningClaim,
    source_values: Vec<&'a [FieldElement]>,
    source_advices: Vec<&'a PcCommitmentAdvice>,
}

fn prove_protocol10_opening_batch<T: Transcript>(
    relation_index: usize,
    inputs: &[Protocol10OpeningBatchProverInput<'_>],
    params: DistributedPcsParams,
    backend: PcsBackendConfig,
    transcript: &mut T,
) -> PcsResult<Protocol10OpeningBatchProof> {
    if inputs.is_empty() {
        return Err(PcsError::InvalidLength);
    }
    let len = inputs[0]
        .source_values
        .first()
        .map(|values| values.len())
        .ok_or(PcsError::InvalidLength)?;
    if len == 0 || !len.is_power_of_two() {
        return Err(PcsError::InvalidLength);
    }
    absorb_protocol10_opening_batch_context(
        transcript,
        relation_index,
        backend,
        inputs.iter().map(|input| &input.claim),
    );
    let gammas = (0..inputs.len())
        .map(|_| transcript.challenge_field::<FieldElement>(b"protocol-10-opening-batch-gamma"))
        .collect::<Vec<_>>();
    for gamma in &gammas {
        transcript.absorb_field(b"protocol-10-opening-batch-gamma", *gamma);
    }

    let mut left_storage = Vec::with_capacity(inputs.len());
    let mut right_storage = Vec::with_capacity(inputs.len());
    for input in inputs {
        if input.claim.relation_index != relation_index
            || input.source_values.len() != input.claim.source_commitments.len()
            || input.source_advices.len() != input.claim.source_commitments.len()
            || input.claim.point.len()
                != log2_power_of_two(len).map_err(|_| PcsError::InvalidLength)?
            || input.source_values.iter().any(|values| values.len() != len)
        {
            return Err(PcsError::InvalidLength);
        }
        for ((commitment, advice), values) in input
            .claim
            .source_commitments
            .iter()
            .zip(&input.source_advices)
            .zip(&input.source_values)
        {
            commitment.validate_for_backend(backend)?;
            if advice.commitment() != *commitment || commitment.len() != values.len() {
                return Err(PcsError::InvalidCommitment);
            }
        }
        let aggregate_value = input
            .source_values
            .iter()
            .map(|values| evaluate_mle(values, &input.claim.point))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| PcsError::InvalidEvaluation)?
            .into_iter()
            .sum::<FieldElement>();
        if aggregate_value != input.claim.claimed_value {
            return Err(PcsError::InvalidEvaluation);
        }
        left_storage.push(
            input
                .source_values
                .iter()
                .map(|values| values.to_vec())
                .collect::<Vec<_>>(),
        );
        right_storage
            .push(eq_evaluations(&input.claim.point).map_err(|_| PcsError::InvalidEvaluation)?);
    }
    let product_inputs = left_storage
        .iter()
        .zip(&right_storage)
        .zip(&gammas)
        .map(|((left_locals, right), gamma)| MultiProductInput {
            weight: *gamma,
            left_locals,
            right,
        })
        .collect::<Vec<_>>();
    let claimed_sum = inputs
        .iter()
        .zip(&gammas)
        .map(|(input, gamma)| input.claim.claimed_value * *gamma)
        .sum::<FieldElement>();
    let (product_sumcheck, _, _) =
        prove_distributed_multi_product_sumcheck(&product_inputs, claimed_sum, transcript)?;
    let zeta = product_sumcheck.challenges.clone();
    let claim_weights = inputs
        .iter()
        .zip(&gammas)
        .map(|(input, gamma)| {
            eq_eval(&input.claim.point, &zeta)
                .map(|eq| eq * *gamma)
                .map_err(|_| PcsError::InvalidEvaluation)
        })
        .collect::<PcsResult<Vec<_>>>()?;
    let mut weighted_sources = Vec::new();
    for (input, claim_weight) in inputs.iter().zip(&claim_weights) {
        for ((values, commitment), advice) in input
            .source_values
            .iter()
            .zip(&input.claim.source_commitments)
            .zip(&input.source_advices)
        {
            weighted_sources.push(WeightedOpeningSource {
                values,
                commitment,
                advice,
                weight: *claim_weight,
            });
        }
    }
    let weighted_sources = coalesce_weighted_opening_sources(&weighted_sources)?;
    let combined_opening = open_weighted_sources(
        b"protocol-10-opening-batch",
        &weighted_sources,
        &zeta,
        params,
        backend,
        transcript,
    )?;
    if combined_opening.aggregate_value != product_sumcheck.final_evaluation {
        return Err(PcsError::InvalidEvaluation);
    }
    Ok(Protocol10OpeningBatchProof {
        claims: inputs.iter().map(|input| input.claim.clone()).collect(),
        reduction: MultiPointBatchReductionProof {
            gammas,
            product_sumcheck,
        },
        combined_opening,
    })
}

fn verify_protocol10_opening_batch<T: Transcript>(
    relation_index: usize,
    expected_claims: &[Protocol10OpeningClaim],
    proof: &Protocol10OpeningBatchProof,
    params: DistributedPcsParams,
    backend: PcsBackendConfig,
    transcript: &mut T,
) -> PcsResult<()> {
    if expected_claims.is_empty() || proof.claims != expected_claims {
        return Err(PcsError::InvalidProof);
    }
    let num_vars = expected_claims[0].point.len();
    if expected_claims
        .iter()
        .any(|claim| claim.relation_index != relation_index || claim.point.len() != num_vars)
    {
        return Err(PcsError::InvalidProof);
    }
    absorb_protocol10_opening_batch_context(
        transcript,
        relation_index,
        backend,
        expected_claims.iter(),
    );
    let expected_gammas = (0..expected_claims.len())
        .map(|_| transcript.challenge_field::<FieldElement>(b"protocol-10-opening-batch-gamma"))
        .collect::<Vec<_>>();
    if proof.reduction.gammas != expected_gammas {
        return Err(PcsError::InvalidProof);
    }
    for gamma in &expected_gammas {
        transcript.absorb_field(b"protocol-10-opening-batch-gamma", *gamma);
    }
    let claimed_sum = expected_claims
        .iter()
        .zip(&expected_gammas)
        .map(|(claim, gamma)| claim.claimed_value * *gamma)
        .sum::<FieldElement>();
    verify_multi_product_sumcheck_rounds(
        num_vars,
        claimed_sum,
        &expected_gammas,
        &proof.reduction.product_sumcheck,
        transcript,
    )?;
    let zeta = &proof.reduction.product_sumcheck.challenges;
    let claim_weights = expected_claims
        .iter()
        .zip(&expected_gammas)
        .map(|(claim, gamma)| {
            eq_eval(&claim.point, zeta)
                .map(|eq| eq * *gamma)
                .map_err(|_| PcsError::InvalidEvaluation)
        })
        .collect::<PcsResult<Vec<_>>>()?;
    let mut commitments = Vec::new();
    let mut weights = Vec::new();
    for (claim, claim_weight) in expected_claims.iter().zip(&claim_weights) {
        for commitment in &claim.source_commitments {
            commitments.push(commitment.clone());
            weights.push(*claim_weight);
        }
    }
    let (commitments, weights) = coalesce_commitment_weights(&commitments, &weights)?;
    verify_weighted_source_opening(
        WeightedSourceVerifyRequest {
            label: b"protocol-10-opening-batch",
            commitments: &commitments,
            weights: &weights,
            opening: &proof.combined_opening,
            point: zeta,
            params,
            backend,
        },
        transcript,
    )?;
    if proof.combined_opening.aggregate_value != proof.reduction.product_sumcheck.final_evaluation {
        return Err(PcsError::InvalidEvaluation);
    }
    Ok(())
}

fn absorb_protocol10_opening_batch_context<'a, T: Transcript>(
    transcript: &mut T,
    relation_index: usize,
    backend: PcsBackendConfig,
    claims: impl IntoIterator<Item = &'a Protocol10OpeningClaim>,
) {
    transcript.absorb_domain(b"protocol-10-opening-batch-v1");
    absorb_backend_config(transcript, backend);
    transcript.absorb_public(b"relation-index", &(relation_index as u64).to_le_bytes());
    let claims = claims.into_iter().collect::<Vec<_>>();
    transcript.absorb_public(b"claim-count", &(claims.len() as u64).to_le_bytes());
    for (claim_index, claim) in claims.iter().enumerate() {
        transcript.absorb_public(b"claim-index", &(claim_index as u64).to_le_bytes());
        transcript.absorb_public(
            b"claim-relation-index",
            &(claim.relation_index as u64).to_le_bytes(),
        );
        transcript.absorb_public(b"claim-kind", claim.claim_kind.as_str().as_bytes());
        transcript.absorb_public(b"claim-label", &claim.label);
        transcript.absorb_field(b"claim-value", claim.claimed_value);
        transcript.absorb_public(
            b"claim-point-len",
            &(claim.point.len() as u64).to_le_bytes(),
        );
        for coordinate in &claim.point {
            transcript.absorb_field(b"claim-point", *coordinate);
        }
        transcript.absorb_public(
            b"claim-source-count",
            &(claim.source_commitments.len() as u64).to_le_bytes(),
        );
        for commitment in &claim.source_commitments {
            absorb_pc_commitment(transcript, b"claim-source-commitment", commitment);
        }
    }
}

fn prove_protocol10_encoding_batch_profiled<T: Transcript>(
    relations: &[Protocol10EncodingProverInput<'_>],
    params: DistributedPcsParams,
    backend: PcsBackendConfig,
    transcript: &mut T,
) -> PcsResult<(Protocol10EncodingBatchProof, Vec<Protocol10OpenProfile>)> {
    if relations.is_empty() {
        return Err(PcsError::InvalidLength);
    }
    absorb_protocol10_encoding_batch_header(transcript, relations.len());
    let mut relation_challenges = Vec::with_capacity(relations.len());
    let mut prepared = Vec::with_capacity(relations.len());
    for (index, relation) in relations.iter().enumerate() {
        absorb_protocol10_encoding_batch_relation(
            transcript,
            index,
            relation.f_commitments,
            relation.e_commitments,
        );
        let rho = transcript.challenge_field::<FieldElement>(b"protocol-10-encoding-batch-rho");
        relation_challenges.push(rho);
        transcript.absorb_field(b"protocol-10-encoding-batch-rho", rho);
        prepared.push(prepare_protocol10_encoding_relation(
            relation, backend, transcript,
        )?);
    }
    let mut profiles = vec![Protocol10OpenProfile::default(); prepared.len()];
    let stage_start = Instant::now();
    let multi_inputs = prepared
        .iter()
        .zip(&relation_challenges)
        .map(|(prepared, rho)| MultiProductInput {
            weight: *rho,
            left_locals: prepared.input.e_locals,
            right: &prepared.hu,
        })
        .collect::<Vec<_>>();
    let (product_sumcheck, e_at_r_values, hu_at_r_values) =
        prove_distributed_multi_product_sumcheck(&multi_inputs, FieldElement::ZERO, transcript)?;
    if let Some(first) = profiles.first_mut() {
        first.sumcheck_ms = elapsed_ms(stage_start);
    }
    let r = product_sumcheck.challenges.clone();
    let mut encodings = Vec::with_capacity(prepared.len());
    for (index, prepared) in prepared.into_iter().enumerate() {
        let mut profile = profiles[index];
        let stage_start = Instant::now();
        let e_at_r = e_at_r_values[index];
        let hu_at_r = hu_at_r_values[index];

        let u_prime = (0..prepared.spec.message_vars()?)
            .map(|_| transcript.challenge_field::<FieldElement>(b"protocol-10-u-prime"))
            .collect::<Vec<_>>();
        let mut systematic_point = u_prime.clone();
        systematic_point.extend([FieldElement::ZERO, FieldElement::ZERO]);
        let f_at_u_prime = prepared
            .input
            .f_pad_locals
            .iter()
            .map(|values| evaluate_mle(values, &systematic_point))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| PcsError::InvalidEvaluation)?
            .into_iter()
            .sum::<FieldElement>();
        let e_at_systematic = prepared
            .input
            .e_locals
            .iter()
            .map(|values| evaluate_mle(values, &systematic_point))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| PcsError::InvalidEvaluation)?
            .into_iter()
            .sum::<FieldElement>();
        transcript.absorb_field(b"protocol-10-f-u-prime", f_at_u_prime);
        transcript.absorb_field(b"protocol-10-e-systematic", e_at_systematic);
        if f_at_u_prime != e_at_systematic {
            return Err(PcsError::InvalidEncoding);
        }
        let opening_inputs = vec![
            Protocol10OpeningBatchProverInput {
                claim: Protocol10OpeningClaim {
                    relation_index: index,
                    claim_kind: Protocol10OpeningClaimKind::HuAtR,
                    label: b"protocol-10-hu-at-r".to_vec(),
                    source_commitments: vec![prepared.hu_commitment.clone()],
                    point: r.clone(),
                    claimed_value: hu_at_r,
                },
                source_values: vec![prepared.hu.as_slice()],
                source_advices: vec![&prepared.hu_advice],
            },
            Protocol10OpeningBatchProverInput {
                claim: Protocol10OpeningClaim {
                    relation_index: index,
                    claim_kind: Protocol10OpeningClaimKind::EAtR,
                    label: b"protocol-10-e-at-r".to_vec(),
                    source_commitments: prepared.input.e_commitments.to_vec(),
                    point: r.clone(),
                    claimed_value: e_at_r,
                },
                source_values: prepared.input.e_locals.iter().map(Vec::as_slice).collect(),
                source_advices: prepared.input.e_advices.to_vec(),
            },
            Protocol10OpeningBatchProverInput {
                claim: Protocol10OpeningClaim {
                    relation_index: index,
                    claim_kind: Protocol10OpeningClaimKind::FPadAtSystematic,
                    label: b"protocol-10-f-pad-systematic".to_vec(),
                    source_commitments: prepared.input.f_commitments.to_vec(),
                    point: systematic_point.clone(),
                    claimed_value: f_at_u_prime,
                },
                source_values: prepared
                    .input
                    .f_pad_locals
                    .iter()
                    .map(Vec::as_slice)
                    .collect(),
                source_advices: prepared.input.f_advices.to_vec(),
            },
            Protocol10OpeningBatchProverInput {
                claim: Protocol10OpeningClaim {
                    relation_index: index,
                    claim_kind: Protocol10OpeningClaimKind::EAtSystematic,
                    label: b"protocol-10-e-systematic".to_vec(),
                    source_commitments: prepared.input.e_commitments.to_vec(),
                    point: systematic_point,
                    claimed_value: e_at_systematic,
                },
                source_values: prepared.input.e_locals.iter().map(Vec::as_slice).collect(),
                source_advices: prepared.input.e_advices.to_vec(),
            },
        ];
        let opening_batch =
            prove_protocol10_opening_batch(index, &opening_inputs, params, backend, transcript)?;
        profile.opening_batch_open_ms = elapsed_ms(stage_start);
        profile.opening_ms = profile.opening_batch_open_ms;
        profile.hu_open_ms = profile.opening_batch_open_ms / 4.0;
        profile.e_at_r_open_ms = profile.opening_batch_open_ms / 4.0;
        profile.f_at_u_prime_open_ms = profile.opening_batch_open_ms / 4.0;
        profile.e_systematic_open_ms = profile.opening_batch_open_ms / 4.0;
        profiles[index] = profile;
        encodings.push(Protocol10EncodingProof {
            code_spec: prepared.spec,
            f_commitments: prepared.input.f_commitments.to_vec(),
            e_commitments: prepared.input.e_commitments.to_vec(),
            parity_check_rows: prepared.parity_shape.rows,
            parity_check_cols: prepared.parity_shape.cols,
            parity_check_nnz: prepared.parity_shape.nnz,
            u: prepared.u,
            hu_commitment: prepared.hu_commitment,
            opening_batch,
            e_at_r,
            hu_at_r,
            u_prime,
            f_at_u_prime,
            e_at_systematic,
        });
    }
    Ok((
        Protocol10EncodingBatchProof {
            relation_challenges,
            product_sumcheck,
            encodings,
        },
        profiles,
    ))
}

fn verify_protocol10_encoding_batch_profiled<T: Transcript>(
    relations: &[Protocol10EncodingVerifierInput<'_>],
    proof: &Protocol10EncodingBatchProof,
    params: DistributedPcsParams,
    backend: PcsBackendConfig,
    transcript: &mut T,
) -> PcsResult<Vec<f64>> {
    if relations.is_empty()
        || proof.encodings.len() != relations.len()
        || proof.relation_challenges.len() != relations.len()
    {
        return Err(PcsError::InvalidProof);
    }
    absorb_protocol10_encoding_batch_header(transcript, relations.len());
    let mut prepared = Vec::with_capacity(relations.len());
    let mut verify_ms = Vec::with_capacity(relations.len());
    for (index, (relation, encoding)) in relations.iter().zip(&proof.encodings).enumerate() {
        absorb_protocol10_encoding_batch_relation(
            transcript,
            index,
            relation.f_commitments,
            relation.e_commitments,
        );
        let expected_rho =
            transcript.challenge_field::<FieldElement>(b"protocol-10-encoding-batch-rho");
        if proof.relation_challenges[index] != expected_rho {
            return Err(PcsError::InvalidProof);
        }
        transcript.absorb_field(b"protocol-10-encoding-batch-rho", expected_rho);
        prepared.push(verify_protocol10_encoding_relation_header(
            relation, encoding, backend, transcript,
        )?);
    }
    verify_multi_product_sumcheck_rounds(
        prepared[0].spec.encoded_vars()?,
        FieldElement::ZERO,
        &proof.relation_challenges,
        &proof.product_sumcheck,
        transcript,
    )?;
    let r = &proof.product_sumcheck.challenges;
    if r.len() != prepared[0].spec.encoded_vars()? {
        return Err(PcsError::InvalidProof);
    }
    let mut final_evaluation = FieldElement::ZERO;
    for (index, (relation, encoding)) in relations.iter().zip(&proof.encodings).enumerate() {
        let stage_start = Instant::now();
        let prepared = &prepared[index];
        final_evaluation += proof.relation_challenges[index] * encoding.e_at_r * encoding.hu_at_r;

        let expected_u_prime = (0..prepared.spec.message_vars()?)
            .map(|_| transcript.challenge_field::<FieldElement>(b"protocol-10-u-prime"))
            .collect::<Vec<_>>();
        if expected_u_prime != encoding.u_prime {
            return Err(PcsError::InvalidProof);
        }
        let mut systematic_point = encoding.u_prime.clone();
        systematic_point.extend([FieldElement::ZERO, FieldElement::ZERO]);
        transcript.absorb_field(b"protocol-10-f-u-prime", encoding.f_at_u_prime);
        transcript.absorb_field(b"protocol-10-e-systematic", encoding.e_at_systematic);
        let expected_claims = vec![
            Protocol10OpeningClaim {
                relation_index: index,
                claim_kind: Protocol10OpeningClaimKind::HuAtR,
                label: b"protocol-10-hu-at-r".to_vec(),
                source_commitments: vec![encoding.hu_commitment.clone()],
                point: r.clone(),
                claimed_value: encoding.hu_at_r,
            },
            Protocol10OpeningClaim {
                relation_index: index,
                claim_kind: Protocol10OpeningClaimKind::EAtR,
                label: b"protocol-10-e-at-r".to_vec(),
                source_commitments: relation.e_commitments.to_vec(),
                point: r.clone(),
                claimed_value: encoding.e_at_r,
            },
            Protocol10OpeningClaim {
                relation_index: index,
                claim_kind: Protocol10OpeningClaimKind::FPadAtSystematic,
                label: b"protocol-10-f-pad-systematic".to_vec(),
                source_commitments: relation.f_commitments.to_vec(),
                point: systematic_point.clone(),
                claimed_value: encoding.f_at_u_prime,
            },
            Protocol10OpeningClaim {
                relation_index: index,
                claim_kind: Protocol10OpeningClaimKind::EAtSystematic,
                label: b"protocol-10-e-systematic".to_vec(),
                source_commitments: relation.e_commitments.to_vec(),
                point: systematic_point,
                claimed_value: encoding.e_at_systematic,
            },
        ];
        verify_protocol10_opening_batch(
            index,
            &expected_claims,
            &encoding.opening_batch,
            params,
            backend,
            transcript,
        )?;
        if encoding.f_at_u_prime != encoding.e_at_systematic {
            return Err(PcsError::InvalidEvaluation);
        }
        verify_ms.push(elapsed_ms(stage_start));
    }
    if proof.product_sumcheck.final_evaluation != final_evaluation {
        return Err(PcsError::InvalidEvaluation);
    }
    Ok(verify_ms)
}

fn absorb_protocol10_encoding_batch_header<T: Transcript>(
    transcript: &mut T,
    relation_count: usize,
) {
    transcript.absorb_domain(b"protocol-10-encoding-batch");
    transcript.absorb_public(
        b"protocol-10-encoding-batch-count",
        &(relation_count as u64).to_le_bytes(),
    );
}

fn absorb_protocol10_encoding_batch_relation<T: Transcript>(
    transcript: &mut T,
    index: usize,
    f_commitments: &[PcCommitment],
    e_commitments: &[PcCommitment],
) {
    transcript.absorb_public(
        b"protocol-10-encoding-batch-index",
        &(index as u64).to_le_bytes(),
    );
    absorb_pc_commitment_vec(transcript, b"batch-f", f_commitments);
    absorb_pc_commitment_vec(transcript, b"batch-e", e_commitments);
}

struct PreparedProtocol10EncodingRelation<'a> {
    input: &'a Protocol10EncodingProverInput<'a>,
    spec: BrakedownCodeSpec,
    parity_shape: BrakedownParityShape,
    u: Vec<FieldElement>,
    hu: Vec<FieldElement>,
    hu_commitment: PcCommitment,
    hu_advice: PcCommitmentAdvice,
}

struct VerifiedProtocol10EncodingRelation {
    spec: BrakedownCodeSpec,
}

fn prepare_protocol10_encoding_relation<'a, T: Transcript>(
    relation: &'a Protocol10EncodingProverInput<'a>,
    backend: PcsBackendConfig,
    transcript: &mut T,
) -> PcsResult<PreparedProtocol10EncodingRelation<'a>> {
    if relation.f_locals.is_empty()
        || relation.f_locals.len() != relation.e_locals.len()
        || relation.f_locals.len() != relation.f_pad_locals.len()
        || relation.f_locals.len() != relation.f_commitments.len()
        || relation.e_locals.len() != relation.e_commitments.len()
        || relation.f_locals.len() != relation.f_advices.len()
        || relation.e_locals.len() != relation.e_advices.len()
    {
        return Err(PcsError::InvalidLength);
    }
    let spec = BrakedownCodeSpec::new(relation.f_locals[0].len())?;
    if relation
        .f_locals
        .iter()
        .any(|values| values.len() != spec.message_len)
        || relation
            .f_pad_locals
            .iter()
            .any(|values| values.len() != spec.codeword_len)
        || relation
            .e_locals
            .iter()
            .any(|values| values.len() != spec.codeword_len)
    {
        return Err(PcsError::InvalidLength);
    }
    for ((((f, _f_pad), e), (f_commitment, e_commitment)), (f_advice, e_advice)) in relation
        .f_locals
        .iter()
        .zip(relation.f_pad_locals)
        .zip(relation.e_locals)
        .zip(relation.f_commitments.iter().zip(relation.e_commitments))
        .zip(relation.f_advices.iter().zip(relation.e_advices))
    {
        f_commitment.validate_for_backend(backend)?;
        e_commitment.validate_for_backend(backend)?;
        if f_advice.commitment() != *f_commitment || e_advice.commitment() != *e_commitment {
            return Err(PcsError::InvalidCommitment);
        }
        #[cfg(debug_assertions)]
        {
            let expected_f_pad = pad_message_to_systematic_domain(f)?;
            if expected_f_pad != *_f_pad {
                return Err(PcsError::InvalidEncoding);
            }
            let (expected_f, _) = commit_pc_with_advice(_f_pad, backend)?;
            let (expected_e, _) = commit_pc_with_advice(e, backend)?;
            if expected_f != *f_commitment || expected_e != *e_commitment {
                return Err(PcsError::InvalidCommitment);
            }
        }
        if brakedown_encode(f)? != *e {
            return Err(PcsError::InvalidEncoding);
        }
    }

    let parity_check = brakedown_parity_check_matrix(spec.message_len)?;
    let parity_shape = BrakedownParityShape::from_spec(spec);
    parity_shape.validate(parity_check.rows(), parity_check.cols(), parity_check.nnz())?;
    transcript.absorb_domain(b"protocol-10-encoding-relation");
    absorb_code_spec(transcript, spec);
    absorb_pc_commitment_vec(transcript, b"f", relation.f_commitments);
    absorb_pc_commitment_vec(transcript, b"e", relation.e_commitments);
    absorb_parity_shape(transcript, parity_shape);
    let u = (0..spec.encoded_vars()?)
        .map(|_| transcript.challenge_field::<FieldElement>(b"protocol-10-u"))
        .collect::<Vec<_>>();
    let hu = compute_hu_vector(&parity_check, &u)?;
    let (hu_commitment, hu_advice) = commit_pc_with_advice(&hu, backend)?;
    absorb_pc_commitment(transcript, b"hu", &hu_commitment);
    Ok(PreparedProtocol10EncodingRelation {
        input: relation,
        spec,
        parity_shape,
        u,
        hu,
        hu_commitment,
        hu_advice,
    })
}

fn verify_protocol10_encoding_relation_header<T: Transcript>(
    relation: &Protocol10EncodingVerifierInput<'_>,
    proof: &Protocol10EncodingProof,
    backend: PcsBackendConfig,
    transcript: &mut T,
) -> PcsResult<VerifiedProtocol10EncodingRelation> {
    let spec = BrakedownCodeSpec::new(proof.code_spec.message_len)?;
    if proof.code_spec != spec
        || proof.f_commitments != relation.f_commitments
        || proof.e_commitments != relation.e_commitments
        || relation.f_commitments.len() != relation.e_commitments.len()
    {
        return Err(PcsError::InvalidProof);
    }
    if relation.f_commitments.iter().any(|commitment| {
        commitment.validate_for_backend(backend).is_err() || commitment.len() != spec.codeword_len
    }) || relation.e_commitments.iter().any(|commitment| {
        commitment.validate_for_backend(backend).is_err() || commitment.len() != spec.codeword_len
    }) {
        return Err(PcsError::InvalidCommitment);
    }
    let parity_shape = verify_protocol10_parity_shape(
        spec,
        proof.parity_check_rows,
        proof.parity_check_cols,
        proof.parity_check_nnz,
    )?;
    if proof.u.len() != spec.encoded_vars()? {
        return Err(PcsError::InvalidProof);
    }
    transcript.absorb_domain(b"protocol-10-encoding-relation");
    absorb_code_spec(transcript, spec);
    absorb_pc_commitment_vec(transcript, b"f", relation.f_commitments);
    absorb_pc_commitment_vec(transcript, b"e", relation.e_commitments);
    absorb_parity_shape(transcript, parity_shape);
    let expected_u = (0..spec.encoded_vars()?)
        .map(|_| transcript.challenge_field::<FieldElement>(b"protocol-10-u"))
        .collect::<Vec<_>>();
    if expected_u != proof.u {
        return Err(PcsError::InvalidProof);
    }
    proof.hu_commitment.validate_for_backend(backend)?;
    let parity_check = brakedown_parity_check_matrix(spec.message_len)?;
    let hu = compute_hu_vector(&parity_check, &proof.u)?;
    let (expected_hu_commitment, _) = commit_pc_with_advice(&hu, backend)?;
    if expected_hu_commitment != proof.hu_commitment {
        return Err(PcsError::InvalidCommitment);
    }
    absorb_pc_commitment(transcript, b"hu", &proof.hu_commitment);
    Ok(VerifiedProtocol10EncodingRelation { spec })
}

fn verify_protocol10_parity_shape(
    spec: BrakedownCodeSpec,
    rows: usize,
    cols: usize,
    nnz: usize,
) -> PcsResult<BrakedownParityShape> {
    let shape = BrakedownParityShape::from_spec(spec);
    shape.validate(rows, cols, nnz)?;
    Ok(shape)
}

struct MultiProductInput<'a> {
    weight: FieldElement,
    left_locals: &'a [Vec<FieldElement>],
    right: &'a [FieldElement],
}

fn prove_distributed_multi_product_sumcheck<T: Transcript>(
    inputs: &[MultiProductInput<'_>],
    claimed_sum: FieldElement,
    transcript: &mut T,
) -> PcsResult<(ProductSumcheckProof, Vec<FieldElement>, Vec<FieldElement>)> {
    if inputs.is_empty() {
        return Err(PcsError::InvalidLength);
    }
    let len = inputs[0].right.len();
    if len == 0 || !len.is_power_of_two() {
        return Err(PcsError::InvalidLength);
    }
    if inputs.iter().any(|input| {
        input.left_locals.is_empty()
            || input.right.len() != len
            || input.left_locals.iter().any(|local| local.len() != len)
    }) {
        return Err(PcsError::InvalidLength);
    }
    let num_vars = log2_power_of_two(len).map_err(|_| PcsError::InvalidLength)?;
    transcript.absorb_domain(b"multi-product-sumcheck-v1");
    transcript.absorb_public(b"num-vars", &(num_vars as u64).to_le_bytes());
    transcript.absorb_public(b"eval-len", &(len as u64).to_le_bytes());
    transcript.absorb_public(b"relation-count", &(inputs.len() as u64).to_le_bytes());
    transcript.absorb_field(b"claimed-sum", claimed_sum);
    for (index, input) in inputs.iter().enumerate() {
        transcript.absorb_public(b"relation-index", &(index as u64).to_le_bytes());
        transcript.absorb_field(b"relation-weight", input.weight);
    }

    let actual_claim = inputs
        .par_iter()
        .map(|input| {
            input.weight
                * input
                    .left_locals
                    .par_iter()
                    .map(|local| inner_product_slice(local, input.right))
                    .reduce(|| FieldElement::ZERO, |left, right| left + right)
        })
        .reduce(|| FieldElement::ZERO, |left, right| left + right);
    if actual_claim != claimed_sum {
        return Err(PcsError::InvalidEvaluation);
    }

    let mut current_left = inputs
        .iter()
        .map(|input| input.left_locals.to_vec())
        .collect::<Vec<_>>();
    let mut current_right = inputs
        .iter()
        .map(|input| input.right.to_vec())
        .collect::<Vec<_>>();
    let weights = inputs.iter().map(|input| input.weight).collect::<Vec<_>>();
    let mut rounds = Vec::with_capacity(num_vars);
    let mut challenges = Vec::with_capacity(num_vars);
    for round in 0..num_vars {
        let round_poly = current_left
            .par_iter()
            .zip(current_right.par_iter())
            .zip(weights.par_iter().copied())
            .map(|((left_locals, right), weight)| {
                let relation_round = left_locals
                    .par_iter()
                    .map(|local| product_round_polynomial_from_slices(local, right))
                    .reduce(zero_quadratic_round, add_quadratic_round);
                scale_quadratic_round(relation_round, weight)
            })
            .reduce(zero_quadratic_round, add_quadratic_round);
        transcript.absorb_field(b"round-0", round_poly.eval_at_0);
        transcript.absorb_field(b"round-1", round_poly.eval_at_1);
        transcript.absorb_field(b"round-2", round_poly.eval_at_2);
        transcript.absorb_public(b"round-index", &(round as u64).to_le_bytes());
        let challenge = transcript.challenge_field::<FieldElement>(b"product-sumcheck-round");
        current_left = current_left
            .into_par_iter()
            .map(|left_locals| {
                left_locals
                    .into_par_iter()
                    .map(|local| fold_first_variable_vec(&local, challenge))
                    .collect::<PcsResult<Vec<_>>>()
            })
            .collect::<PcsResult<Vec<_>>>()?;
        current_right = current_right
            .into_par_iter()
            .map(|right| fold_first_variable_vec(&right, challenge))
            .collect::<PcsResult<Vec<_>>>()?;
        rounds.push(round_poly);
        challenges.push(challenge);
    }
    let e_at_r = current_left
        .iter()
        .map(|left_locals| {
            left_locals
                .iter()
                .map(|local| local[0])
                .sum::<FieldElement>()
        })
        .collect::<Vec<_>>();
    let hu_at_r = current_right
        .iter()
        .map(|right| right[0])
        .collect::<Vec<_>>();
    let final_evaluation = weights
        .iter()
        .copied()
        .zip(e_at_r.iter().copied().zip(hu_at_r.iter().copied()))
        .map(|(weight, (left, right))| weight * left * right)
        .sum::<FieldElement>();
    transcript.absorb_field(b"final-eval", final_evaluation);

    Ok((
        ProductSumcheckProof {
            claimed_sum,
            rounds,
            challenges,
            final_evaluation,
        },
        e_at_r,
        hu_at_r,
    ))
}

fn verify_multi_product_sumcheck_rounds<T: Transcript>(
    num_vars: usize,
    claimed_sum: FieldElement,
    relation_weights: &[FieldElement],
    proof: &ProductSumcheckProof,
    transcript: &mut T,
) -> PcsResult<()> {
    if proof.rounds.len() != num_vars
        || proof.challenges.len() != num_vars
        || relation_weights.is_empty()
    {
        return Err(PcsError::InvalidProof);
    }
    transcript.absorb_domain(b"multi-product-sumcheck-v1");
    transcript.absorb_public(b"num-vars", &(num_vars as u64).to_le_bytes());
    let eval_len = 1_usize
        .checked_shl(num_vars as u32)
        .ok_or(PcsError::InvalidLength)?;
    transcript.absorb_public(b"eval-len", &(eval_len as u64).to_le_bytes());
    transcript.absorb_public(
        b"relation-count",
        &(relation_weights.len() as u64).to_le_bytes(),
    );
    transcript.absorb_field(b"claimed-sum", proof.claimed_sum);
    if proof.claimed_sum != claimed_sum {
        return Err(PcsError::Sumcheck);
    }
    for (index, weight) in relation_weights.iter().copied().enumerate() {
        transcript.absorb_public(b"relation-index", &(index as u64).to_le_bytes());
        transcript.absorb_field(b"relation-weight", weight);
    }

    let mut expected = proof.claimed_sum;
    for (round, round_poly) in proof.rounds.iter().enumerate() {
        if expected != round_poly.eval_at_0 + round_poly.eval_at_1 {
            return Err(PcsError::Sumcheck);
        }
        transcript.absorb_field(b"round-0", round_poly.eval_at_0);
        transcript.absorb_field(b"round-1", round_poly.eval_at_1);
        transcript.absorb_field(b"round-2", round_poly.eval_at_2);
        transcript.absorb_public(b"round-index", &(round as u64).to_le_bytes());
        let challenge = transcript.challenge_field::<FieldElement>(b"product-sumcheck-round");
        if proof.challenges[round] != challenge {
            return Err(PcsError::Sumcheck);
        }
        expected = round_poly.evaluate(challenge);
    }
    if expected != proof.final_evaluation {
        return Err(PcsError::Sumcheck);
    }
    transcript.absorb_field(b"final-eval", proof.final_evaluation);
    Ok(())
}

#[cfg(test)]
fn prove_distributed_product_sumcheck<T: Transcript>(
    e_locals: &[Vec<FieldElement>],
    hu: &[FieldElement],
    claimed_sum: FieldElement,
    transcript: &mut T,
) -> PcsResult<(ProductSumcheckProof, FieldElement, FieldElement)> {
    if e_locals.is_empty()
        || hu.is_empty()
        || !hu.len().is_power_of_two()
        || e_locals.iter().any(|local| local.len() != hu.len())
    {
        return Err(PcsError::InvalidLength);
    }
    let num_vars = log2_power_of_two(hu.len()).map_err(|_| PcsError::InvalidLength)?;
    transcript.absorb_domain(b"product-sumcheck-v1");
    transcript.absorb_public(b"num-vars", &(num_vars as u64).to_le_bytes());
    transcript.absorb_public(b"eval-len", &(hu.len() as u64).to_le_bytes());
    transcript.absorb_field(b"claimed-sum", claimed_sum);

    let actual_claim = e_locals
        .par_iter()
        .map(|local| inner_product_slice(local, hu))
        .reduce(|| FieldElement::ZERO, |left, right| left + right);
    if actual_claim != claimed_sum {
        return Err(PcsError::InvalidEvaluation);
    }

    let mut current_e = e_locals.to_vec();
    let mut current_hu = hu.to_vec();
    let mut rounds = Vec::with_capacity(num_vars);
    let mut challenges = Vec::with_capacity(num_vars);
    for round in 0..num_vars {
        let round_poly = current_e
            .par_iter()
            .map(|local| product_round_polynomial_from_slices(local, &current_hu))
            .reduce(zero_quadratic_round, add_quadratic_round);
        transcript.absorb_field(b"round-0", round_poly.eval_at_0);
        transcript.absorb_field(b"round-1", round_poly.eval_at_1);
        transcript.absorb_field(b"round-2", round_poly.eval_at_2);
        transcript.absorb_public(b"round-index", &(round as u64).to_le_bytes());
        let challenge = transcript.challenge_field::<FieldElement>(b"product-sumcheck-round");
        current_e = current_e
            .into_par_iter()
            .map(|local| fold_first_variable_vec(&local, challenge))
            .collect::<PcsResult<Vec<_>>>()?;
        current_hu = fold_first_variable_vec(&current_hu, challenge)?;
        rounds.push(round_poly);
        challenges.push(challenge);
    }
    let e_at_r = current_e.iter().map(|local| local[0]).sum::<FieldElement>();
    let hu_at_r = current_hu[0];
    let final_evaluation = e_at_r * hu_at_r;
    transcript.absorb_field(b"final-eval", final_evaluation);

    Ok((
        ProductSumcheckProof {
            claimed_sum,
            rounds,
            challenges,
            final_evaluation,
        },
        e_at_r,
        hu_at_r,
    ))
}

fn inner_product_slice(left: &[FieldElement], right: &[FieldElement]) -> FieldElement {
    left.par_iter()
        .copied()
        .zip(right.par_iter().copied())
        .map(|(left, right)| left * right)
        .reduce(|| FieldElement::ZERO, |left, right| left + right)
}

fn product_round_polynomial_from_slices(
    left: &[FieldElement],
    right: &[FieldElement],
) -> QuadraticRoundPolynomial {
    let two = FieldElement::from(2_u64);
    left.par_chunks_exact(2)
        .zip(right.par_chunks_exact(2))
        .map(|(left_pair, right_pair)| {
            let left_at_2 = (FieldElement::ZERO - left_pair[0]) + left_pair[1] * two;
            let right_at_2 = (FieldElement::ZERO - right_pair[0]) + right_pair[1] * two;
            QuadraticRoundPolynomial {
                eval_at_0: left_pair[0] * right_pair[0],
                eval_at_1: left_pair[1] * right_pair[1],
                eval_at_2: left_at_2 * right_at_2,
            }
        })
        .reduce(zero_quadratic_round, add_quadratic_round)
}

fn zero_quadratic_round() -> QuadraticRoundPolynomial {
    QuadraticRoundPolynomial {
        eval_at_0: FieldElement::ZERO,
        eval_at_1: FieldElement::ZERO,
        eval_at_2: FieldElement::ZERO,
    }
}

fn add_quadratic_round(
    left: QuadraticRoundPolynomial,
    right: QuadraticRoundPolynomial,
) -> QuadraticRoundPolynomial {
    QuadraticRoundPolynomial {
        eval_at_0: left.eval_at_0 + right.eval_at_0,
        eval_at_1: left.eval_at_1 + right.eval_at_1,
        eval_at_2: left.eval_at_2 + right.eval_at_2,
    }
}

fn scale_quadratic_round(
    round: QuadraticRoundPolynomial,
    scalar: FieldElement,
) -> QuadraticRoundPolynomial {
    QuadraticRoundPolynomial {
        eval_at_0: round.eval_at_0 * scalar,
        eval_at_1: round.eval_at_1 * scalar,
        eval_at_2: round.eval_at_2 * scalar,
    }
}

fn fold_first_variable_vec(
    values: &[FieldElement],
    challenge: FieldElement,
) -> PcsResult<Vec<FieldElement>> {
    if values.len() <= 1 || !values.len().is_power_of_two() {
        return Err(PcsError::InvalidLength);
    }
    let one_minus = FieldElement::ONE - challenge;
    Ok(values
        .par_chunks_exact(2)
        .map(|pair| pair[0] * one_minus + pair[1] * challenge)
        .collect())
}

#[derive(Clone, Debug)]
struct Protocol11Layout {
    matrix_rows: usize,
    row_axis_len: usize,
    rows_per_worker: usize,
    row_width: usize,
    encoded_width: usize,
}

impl Protocol11Layout {
    fn new(len: usize, workers: usize) -> PcsResult<Self> {
        if len == 0 || !len.is_power_of_two() || workers == 0 {
            return Err(PcsError::InvalidLength);
        }
        let base_rows_per_worker = log2_power_of_two(len)
            .map_err(|_| PcsError::InvalidLength)?
            .saturating_sub(log2_floor(workers))
            .max(1);
        let rows_per_worker = base_rows_per_worker;
        let matrix_rows = workers * rows_per_worker;
        let row_axis_len = matrix_rows.next_power_of_two();
        let row_width = len.div_ceil(matrix_rows).max(1).next_power_of_two();
        let encoded_width = row_width * CODE_RATE_INV;
        Ok(Self {
            matrix_rows,
            row_axis_len,
            rows_per_worker,
            row_width,
            encoded_width,
        })
    }

    fn from_commitment(commitment: &Protocol11Commitment) -> PcsResult<Self> {
        Ok(Self {
            matrix_rows: commitment.matrix_rows,
            row_axis_len: commitment.row_axis_len,
            rows_per_worker: commitment.rows_per_worker,
            row_width: commitment.row_width,
            encoded_width: commitment.encoded_width,
        })
    }
}

type WorkerEvalData = Protocol11WorkerOpenData;

fn build_worker_eval_data(
    evaluations: &[FieldElement],
    layout: &Protocol11Layout,
    worker_id: usize,
    a: &[FieldElement],
    beta: &[FieldElement],
) -> PcsResult<WorkerEvalData> {
    let rows = worker_rows(evaluations, layout, worker_id)?;
    build_worker_eval_data_from_rows(&rows, layout, worker_id, a, beta)
}

fn build_worker_eval_data_from_rows(
    rows: &[Vec<FieldElement>],
    layout: &Protocol11Layout,
    worker_id: usize,
    a: &[FieldElement],
    beta: &[FieldElement],
) -> PcsResult<WorkerEvalData> {
    let encoded_rows = encode_rows(&rows)?;
    let (start, _) = worker_row_range(layout, worker_id);
    let mut f1 = vec![FieldElement::ZERO; layout.row_width];
    let mut f2 = vec![FieldElement::ZERO; layout.row_width];
    for (local_row, row) in rows.iter().enumerate() {
        let global_row = start + local_row;
        for (slot, value) in row.iter().copied().enumerate() {
            f1[slot] += value * a[global_row];
            f2[slot] += value * beta[global_row];
        }
    }
    let e1 = brakedown_encode(&f1)?;
    let e2 = brakedown_encode(&f2)?;
    let f1_pad = pad_message_to_systematic_domain(&f1)?;
    let f2_pad = pad_message_to_systematic_domain(&f2)?;
    Ok(WorkerEvalData {
        worker_id,
        encoded_rows,
        f1,
        f1_pad,
        e1,
        f2,
        f2_pad,
        e2,
    })
}

fn worker_rows(
    evaluations: &[FieldElement],
    layout: &Protocol11Layout,
    worker_id: usize,
) -> PcsResult<Vec<Vec<FieldElement>>> {
    worker_rows_from_fn(evaluations.len(), layout, worker_id, |index| {
        evaluations[index]
    })
}

fn worker_rows_from_fn<F>(
    original_len: usize,
    layout: &Protocol11Layout,
    worker_id: usize,
    value_at: F,
) -> PcsResult<Vec<Vec<FieldElement>>>
where
    F: Fn(usize) -> FieldElement,
{
    let (start_row, end_row) = worker_row_range(layout, worker_id);
    let mut rows = Vec::with_capacity(end_row - start_row);
    for row_idx in start_row..end_row {
        let mut row = vec![FieldElement::ZERO; layout.row_width];
        let start = row_idx * layout.row_width;
        if start < original_len {
            let end = (start + layout.row_width).min(original_len);
            for (slot, index) in (start..end).enumerate() {
                row[slot] = value_at(index);
            }
        }
        rows.push(row);
    }
    Ok(rows)
}

fn worker_row_range(layout: &Protocol11Layout, worker_id: usize) -> (usize, usize) {
    let start = worker_id * layout.rows_per_worker;
    (start, start + layout.rows_per_worker)
}

fn encode_rows(rows: &[Vec<FieldElement>]) -> PcsResult<Vec<Vec<FieldElement>>> {
    rows.iter().map(|row| brakedown_encode(row)).collect()
}

fn worker_column_proof(
    data: &WorkerEvalData,
    advice: &Protocol11WorkerEvalAdvice,
    commitment: &Protocol11Commitment,
    query_indices: &[usize],
) -> PcsResult<Protocol11WorkerColumnProof> {
    if data.worker_id != advice.worker_id {
        return Err(PcsError::InvalidWorker);
    }
    let worker_commitment = commitment
        .workers
        .get(data.worker_id)
        .ok_or(PcsError::InvalidWorker)?;
    let matrix_hashes = column_hashes(&data.encoded_rows);
    let matrix_tree = MerkleTree::new(&matrix_hashes)?;
    let columns = query_indices
        .iter()
        .copied()
        .map(|index| {
            let encoded_row_values = data
                .encoded_rows
                .iter()
                .map(|row| row[index])
                .collect::<Vec<_>>();
            let matrix_hash_value = hash_column_to_field(&encoded_row_values);
            Ok(Protocol11ColumnOpening {
                index,
                encoded_row_values,
                matrix_hash_value,
                matrix_opening: matrix_tree.open(index)?,
                e1_value: data.e1[index],
                e1_opening: advice.e1.open_index(index)?,
                e2_value: data.e2[index],
                e2_opening: advice.e2.open_index(index)?,
            })
        })
        .collect::<PcsResult<Vec<_>>>()?;
    if matrix_tree.commitment() != worker_commitment.matrix_commitment {
        return Err(PcsError::InvalidCommitment);
    }
    Ok(Protocol11WorkerColumnProof {
        worker_id: data.worker_id,
        columns,
    })
}

fn worker_matrix_column_proof(
    data: &WorkerEvalData,
    commitment: &Protocol11Commitment,
    query_indices: &[usize],
) -> PcsResult<Protocol11WorkerMatrixColumnProof> {
    let worker_commitment = commitment
        .workers
        .get(data.worker_id)
        .ok_or(PcsError::InvalidWorker)?;
    let matrix_hashes = column_hashes(&data.encoded_rows);
    let matrix_tree = MerkleTree::new(&matrix_hashes)?;
    let columns = query_indices
        .iter()
        .copied()
        .map(|index| {
            let encoded_row_values = data
                .encoded_rows
                .iter()
                .map(|row| row[index])
                .collect::<Vec<_>>();
            let matrix_hash_value = hash_column_to_field(&encoded_row_values);
            Ok(Protocol11MatrixColumnOpening {
                index,
                encoded_row_values,
                matrix_hash_value,
                matrix_opening: matrix_tree.open(index)?,
            })
        })
        .collect::<PcsResult<Vec<_>>>()?;
    if matrix_tree.commitment() != worker_commitment.matrix_commitment {
        return Err(PcsError::InvalidCommitment);
    }
    Ok(Protocol11WorkerMatrixColumnProof {
        worker_id: data.worker_id,
        columns,
    })
}

fn complete_matrix_column_proofs(
    prepared: &Protocol11PreparedOpen,
    matrix_column_openings: &[Protocol11WorkerMatrixColumnProof],
) -> PcsResult<Vec<Protocol11WorkerColumnProof>> {
    let mut matrix_column_openings = matrix_column_openings.to_vec();
    matrix_column_openings.sort_by_key(|opening| opening.worker_id);
    if matrix_column_openings.len() != prepared.eval_advices.len() {
        return Err(PcsError::InvalidProof);
    }
    matrix_column_openings
        .iter()
        .zip(&prepared.eval_advices)
        .enumerate()
        .map(|(worker_id, (matrix_proof, advice))| {
            if matrix_proof.worker_id != worker_id || advice.worker_id != worker_id {
                return Err(PcsError::InvalidWorker);
            }
            let columns = matrix_proof
                .columns
                .iter()
                .map(|column| {
                    let e1_opening = advice.e1.open_index(column.index)?;
                    let e2_opening = advice.e2.open_index(column.index)?;
                    Ok(Protocol11ColumnOpening {
                        index: column.index,
                        encoded_row_values: column.encoded_row_values.clone(),
                        matrix_hash_value: column.matrix_hash_value,
                        matrix_opening: column.matrix_opening.clone(),
                        e1_value: e1_opening.value,
                        e1_opening,
                        e2_value: e2_opening.value,
                        e2_opening,
                    })
                })
                .collect::<PcsResult<Vec<_>>>()?;
            Ok(Protocol11WorkerColumnProof { worker_id, columns })
        })
        .collect()
}

fn verify_column_proofs(
    commitment: &Protocol11Commitment,
    proof: &Protocol11Proof,
    layout: &Protocol11Layout,
) -> PcsResult<()> {
    proof
        .column_openings
        .par_iter()
        .try_for_each(|worker_proof| {
            let worker_commitment = commitment
                .workers
                .get(worker_proof.worker_id)
                .ok_or(PcsError::InvalidWorker)?;
            let roots = proof
                .merkle_roots
                .iter()
                .find(|roots| roots.worker_id == worker_proof.worker_id)
                .ok_or(PcsError::InvalidWorker)?;
            if worker_proof.columns.len() != proof.query_indices.len() {
                return Err(PcsError::InvalidProof);
            }
            proof
                .query_indices
                .par_iter()
                .copied()
                .zip(worker_proof.columns.par_iter())
                .try_for_each(|(expected_index, column)| {
                    if column.index != expected_index
                        || column.encoded_row_values.len() != layout.rows_per_worker
                        || column.matrix_hash_value
                            != hash_column_to_field(&column.encoded_row_values)
                        || column.matrix_opening.index != expected_index
                        || column.matrix_opening.value != column.matrix_hash_value
                        || column.e1_opening.index != expected_index
                        || column.e1_opening.value != column.e1_value
                        || column.e2_opening.index != expected_index
                        || column.e2_opening.value != column.e2_value
                    {
                        return Err(PcsError::InvalidProof);
                    }
                    MerklePcs::verify(
                        &worker_commitment.matrix_commitment,
                        &column.matrix_opening,
                    )?;
                    MerklePcs::verify(roots.e1_root.merkle_commitment(), &column.e1_opening)?;
                    MerklePcs::verify(roots.e2_root.merkle_commitment(), &column.e2_opening)?;
                    Ok(())
                })
        })
}

fn aggregate_column_claims(
    column_proofs: &[Protocol11WorkerColumnProof],
    a: &[FieldElement],
    beta: &[FieldElement],
    layout: &Protocol11Layout,
) -> PcsResult<(Vec<FieldElement>, Vec<FieldElement>)> {
    let query_count = column_proofs
        .first()
        .map(|worker| worker.columns.len())
        .ok_or(PcsError::InvalidProof)?;
    let mut y1 = vec![FieldElement::ZERO; query_count];
    let mut y2 = vec![FieldElement::ZERO; query_count];
    for worker in column_proofs {
        let (row_start, _) = worker_row_range(layout, worker.worker_id);
        for (query_slot, column) in worker.columns.iter().enumerate() {
            for (local_row, value) in column.encoded_row_values.iter().copied().enumerate() {
                let global_row = row_start + local_row;
                y1[query_slot] += value * a[global_row];
                y2[query_slot] += value * beta[global_row];
            }
            let e1_sum = column.e1_value;
            let e2_sum = column.e2_value;
            if column
                .encoded_row_values
                .iter()
                .copied()
                .enumerate()
                .map(|(local_row, value)| value * a[row_start + local_row])
                .sum::<FieldElement>()
                != e1_sum
                || column
                    .encoded_row_values
                    .iter()
                    .copied()
                    .enumerate()
                    .map(|(local_row, value)| value * beta[row_start + local_row])
                    .sum::<FieldElement>()
                    != e2_sum
            {
                return Err(PcsError::InvalidEvaluation);
            }
        }
    }
    Ok((y1, y2))
}

fn verify_f2_openings<T: Transcript>(
    commitments: &[Protocol11WorkerEvalCommitments],
    opening: &BatchedDistributedPcOpening,
    point: &[FieldElement],
    params: DistributedPcsParams,
    backend: PcsBackendConfig,
    transcript: &mut T,
) -> PcsResult<()> {
    let f2_commitments = commitments
        .iter()
        .map(|commitment| commitment.f2.clone())
        .collect::<Vec<_>>();
    verify_distributed_openings(
        b"protocol-11-f2",
        &f2_commitments,
        opening,
        point,
        params,
        backend,
        transcript,
    )
}

fn validate_eval_commitments(
    commitment: &Protocol11Commitment,
    eval_commitments: &[Protocol11WorkerEvalCommitments],
    merkle_roots: &[Protocol11WorkerMerkleRoots],
) -> PcsResult<()> {
    for expected in &commitment.workers {
        let eval = eval_commitments
            .iter()
            .find(|item| item.worker_id == expected.worker_id)
            .ok_or(PcsError::InvalidWorker)?;
        let roots = merkle_roots
            .iter()
            .find(|item| item.worker_id == expected.worker_id)
            .ok_or(PcsError::InvalidWorker)?;
        if eval.f1.validate_for_backend(commitment.backend).is_err()
            || eval.e1.validate_for_backend(commitment.backend).is_err()
            || eval.f2.validate_for_backend(commitment.backend).is_err()
            || eval.e2.validate_for_backend(commitment.backend).is_err()
            || roots
                .e1_root
                .validate_for_backend(commitment.backend)
                .is_err()
            || roots
                .e2_root
                .validate_for_backend(commitment.backend)
                .is_err()
            || eval.f1.len() != commitment.encoded_width
            || eval.f2.len() != commitment.encoded_width
            || eval.e1.len() != commitment.encoded_width
            || eval.e2.len() != commitment.encoded_width
            || roots.e1_root.len() != commitment.encoded_width
            || roots.e2_root.len() != commitment.encoded_width
        {
            return Err(PcsError::InvalidCommitment);
        }
    }
    Ok(())
}

struct DistributedOpenRequest<'a> {
    label: &'static [u8],
    values: &'a [Vec<FieldElement>],
    commitments: &'a [PcCommitment],
    advices: &'a [&'a PcCommitmentAdvice],
    point: &'a [FieldElement],
    params: DistributedPcsParams,
    backend: PcsBackendConfig,
}

struct WeightedOpeningSource<'a> {
    values: &'a [FieldElement],
    commitment: &'a PcCommitment,
    advice: &'a PcCommitmentAdvice,
    weight: FieldElement,
}

fn coalesce_weighted_opening_sources<'a>(
    sources: &[WeightedOpeningSource<'a>],
) -> PcsResult<Vec<WeightedOpeningSource<'a>>> {
    let mut coalesced: Vec<WeightedOpeningSource<'a>> = Vec::new();
    for source in sources {
        if let Some(existing) = coalesced
            .iter_mut()
            .find(|existing| existing.commitment == source.commitment)
        {
            if existing.values != source.values
                || existing.advice.commitment() != source.advice.commitment()
            {
                return Err(PcsError::InvalidCommitment);
            }
            existing.weight += source.weight;
        } else {
            coalesced.push(WeightedOpeningSource {
                values: source.values,
                commitment: source.commitment,
                advice: source.advice,
                weight: source.weight,
            });
        }
    }
    Ok(coalesced)
}

fn coalesce_commitment_weights(
    commitments: &[PcCommitment],
    weights: &[FieldElement],
) -> PcsResult<(Vec<PcCommitment>, Vec<FieldElement>)> {
    if commitments.len() != weights.len() {
        return Err(PcsError::InvalidLength);
    }
    let mut coalesced_commitments = Vec::<PcCommitment>::new();
    let mut coalesced_weights = Vec::<FieldElement>::new();
    for (commitment, weight) in commitments.iter().zip(weights) {
        if let Some(index) = coalesced_commitments
            .iter()
            .position(|existing| existing == commitment)
        {
            coalesced_weights[index] += *weight;
        } else {
            coalesced_commitments.push(commitment.clone());
            coalesced_weights.push(*weight);
        }
    }
    Ok((coalesced_commitments, coalesced_weights))
}

struct WeightedSourceVerifyRequest<'a> {
    label: &'static [u8],
    commitments: &'a [PcCommitment],
    weights: &'a [FieldElement],
    opening: &'a WeightedSourceBatchOpening,
    point: &'a [FieldElement],
    params: DistributedPcsParams,
    backend: PcsBackendConfig,
}

fn verify_local_pc<T: Transcript>(
    commitment: &PcCommitment,
    proof: &BatchedOpeningProof,
    point: &[FieldElement],
    params: DistributedPcsParams,
    backend: PcsBackendConfig,
    transcript: &mut T,
    consistency_checker: Option<&dyn Fn(usize, FieldElement) -> PcsResult<()>>,
) -> PcsResult<()> {
    backend.validate()?;
    commitment.validate_for_backend(backend)?;
    match (backend.kind, commitment, proof) {
        (
            PcsBackendKind::BaseFold,
            PcCommitment::BaseFold(base),
            BatchedOpeningProof::BaseFold(basefold),
        ) => {
            if basefold.rs_proof.point != point {
                return Err(PcsError::InvalidProof);
            }
            BaseFoldPc::verify(base, basefold, params, transcript)?;
        }
        (
            PcsBackendKind::DeepFold,
            PcCommitment::DeepFold(deepfold),
            BatchedOpeningProof::DeepFold(deepfold_proof),
        ) => {
            DeepFoldPc::verify(deepfold, deepfold_proof, point, params, backend, transcript)?;
        }
        _ => return Err(PcsError::InvalidProof),
    }
    if let Some(checker) = consistency_checker {
        for index in batched_level_zero_indices(proof) {
            let value = batched_level_zero_value(proof, index).ok_or(PcsError::InvalidProof)?;
            checker(index, value)?;
        }
    }
    Ok(())
}

fn open_distributed<T: Transcript>(
    request: DistributedOpenRequest<'_>,
    transcript: &mut T,
) -> PcsResult<BatchedDistributedPcOpening> {
    request.backend.validate()?;
    if request.values.len() != request.commitments.len()
        || request.values.len() != request.advices.len()
    {
        return Err(PcsError::InvalidLength);
    }
    if request.values.is_empty() {
        return Err(PcsError::InvalidLength);
    }
    let len = request.values[0].len();
    if len == 0
        || !len.is_power_of_two()
        || request
            .values
            .iter()
            .any(|worker_values| worker_values.len() != len)
        || request
            .commitments
            .iter()
            .any(|commitment| commitment.len() != len)
        || request.point.len() != log2_power_of_two(len).map_err(|_| PcsError::InvalidLength)?
    {
        return Err(PcsError::InvalidLength);
    }
    for (commitment, advice) in request.commitments.iter().zip(request.advices) {
        commitment.validate_for_backend(request.backend)?;
        if advice.commitment() != *commitment {
            return Err(PcsError::InvalidCommitment);
        }
    }
    let combined_values = combine_worker_values(request.values)?;
    let (combined_commitment, combined_advice) =
        commit_pc_with_advice(&combined_values, request.backend)?;
    absorb_batched_opening_context(
        transcript,
        request.label,
        request.backend,
        request.commitments,
        request.point,
        &combined_commitment,
    );
    let proof = match request.backend.kind {
        PcsBackendKind::BaseFold => {
            let basefold = BaseFoldPc::open_with_advice(
                &combined_values,
                combined_advice.basefold(),
                request.point,
                request.params,
                transcript,
            )?;
            BatchedOpeningProof::BaseFold(basefold)
        }
        PcsBackendKind::DeepFold => {
            let deepfold = DeepFoldPc::open_with_advice(
                &combined_values,
                &combined_advice,
                request.point,
                request.params,
                request.backend,
                transcript,
            )?;
            BatchedOpeningProof::DeepFold(deepfold)
        }
    };
    let aggregate_value = batched_opening_value(&proof);
    let consistency_indices = batched_level_zero_indices(&proof);
    let consistency = consistency_indices
        .into_iter()
        .map(|index| {
            let combined_opening = combined_advice.open_consistency_index(index)?;
            let worker_openings = request
                .advices
                .iter()
                .map(|advice| advice.open_consistency_index(index))
                .collect::<PcsResult<Vec<_>>>()?;
            Ok(BatchedLeafConsistency {
                index,
                combined_value: combined_opening.value,
                worker_openings,
            })
        })
        .collect::<PcsResult<Vec<_>>>()?;
    Ok(BatchedDistributedPcOpening {
        backend: request.backend,
        point: request.point.to_vec(),
        aggregate_value,
        combined_commitment,
        proof,
        consistency,
    })
}

fn open_weighted_sources<T: Transcript>(
    label: &'static [u8],
    sources: &[WeightedOpeningSource<'_>],
    point: &[FieldElement],
    params: DistributedPcsParams,
    backend: PcsBackendConfig,
    transcript: &mut T,
) -> PcsResult<WeightedSourceBatchOpening> {
    backend.validate()?;
    let len = sources
        .first()
        .map(|source| source.values.len())
        .ok_or(PcsError::InvalidLength)?;
    if len == 0
        || !len.is_power_of_two()
        || point.len() != log2_power_of_two(len).map_err(|_| PcsError::InvalidLength)?
        || sources
            .iter()
            .any(|source| source.values.len() != len || source.commitment.len() != len)
    {
        return Err(PcsError::InvalidLength);
    }
    for source in sources {
        source.commitment.validate_for_backend(backend)?;
        if source.advice.commitment() != *source.commitment {
            return Err(PcsError::InvalidCommitment);
        }
    }
    let combined_values = combine_weighted_source_values(sources, len)?;
    let (combined_commitment, combined_advice) = commit_pc_with_advice(&combined_values, backend)?;
    absorb_weighted_source_opening_context(
        transcript,
        label,
        backend,
        sources,
        point,
        &combined_commitment,
    );
    let proof = match backend.kind {
        PcsBackendKind::BaseFold => BatchedOpeningProof::BaseFold(BaseFoldPc::open_with_advice(
            &combined_values,
            combined_advice.basefold(),
            point,
            params,
            transcript,
        )?),
        PcsBackendKind::DeepFold => BatchedOpeningProof::DeepFold(DeepFoldPc::open_with_advice(
            &combined_values,
            &combined_advice,
            point,
            params,
            backend,
            transcript,
        )?),
    };
    let aggregate_value = batched_opening_value(&proof);
    let consistency = batched_level_zero_indices(&proof)
        .into_iter()
        .map(|index| {
            let combined_opening = combined_advice.open_consistency_index(index)?;
            let source_openings = sources
                .iter()
                .map(|source| source.advice.open_consistency_index(index))
                .collect::<PcsResult<Vec<_>>>()?;
            Ok(WeightedSourceLeafConsistency {
                index,
                combined_value: combined_opening.value,
                source_openings,
            })
        })
        .collect::<PcsResult<Vec<_>>>()?;
    Ok(WeightedSourceBatchOpening {
        backend,
        point: point.to_vec(),
        aggregate_value,
        combined_commitment,
        proof,
        consistency,
    })
}

fn verify_weighted_source_opening<T: Transcript>(
    request: WeightedSourceVerifyRequest<'_>,
    transcript: &mut T,
) -> PcsResult<()> {
    let WeightedSourceVerifyRequest {
        label,
        commitments,
        weights,
        opening,
        point,
        params,
        backend,
    } = request;
    backend.validate()?;
    if commitments.is_empty()
        || commitments.len() != weights.len()
        || opening.backend != backend
        || opening.point != point
        || commitments
            .iter()
            .any(|commitment| commitment.len() != opening.combined_commitment.len())
    {
        return Err(PcsError::InvalidProof);
    }
    opening.combined_commitment.validate_for_backend(backend)?;
    for commitment in commitments {
        commitment.validate_for_backend(backend)?;
    }
    absorb_weighted_source_verify_context(
        transcript,
        label,
        backend,
        commitments,
        weights,
        point,
        &opening.combined_commitment,
    );
    verify_local_pc(
        &opening.combined_commitment,
        &opening.proof,
        point,
        params,
        backend,
        transcript,
        None,
    )?;
    if opening.aggregate_value != batched_opening_value(&opening.proof) {
        return Err(PcsError::InvalidEvaluation);
    }
    let expected_indices = batched_level_zero_indices(&opening.proof);
    if opening.consistency.len() != expected_indices.len() {
        return Err(PcsError::InvalidProof);
    }
    expected_indices
        .par_iter()
        .copied()
        .zip(opening.consistency.par_iter())
        .try_for_each(|(expected_index, consistency)| {
            if consistency.index != expected_index
                || consistency.source_openings.len() != commitments.len()
            {
                return Err(PcsError::InvalidProof);
            }
            commitments
                .par_iter()
                .zip(consistency.source_openings.par_iter())
                .try_for_each(|(commitment, source_opening)| {
                    if source_opening.index != expected_index {
                        return Err(PcsError::InvalidProof);
                    }
                    MerklePcs::verify(commitment.consistency_commitment(), source_opening)
                })?;
            if batched_level_zero_value(&opening.proof, expected_index)
                != Some(consistency.combined_value)
            {
                return Err(PcsError::InvalidEvaluation);
            }
            let aggregate = consistency
                .source_openings
                .iter()
                .zip(weights)
                .map(|(source_opening, weight)| source_opening.value * *weight)
                .sum::<FieldElement>();
            if aggregate != consistency.combined_value {
                return Err(PcsError::InvalidEvaluation);
            }
            Ok(())
        })?;
    Ok(())
}

fn verify_distributed_openings<T: Transcript>(
    label: &'static [u8],
    commitments: &[PcCommitment],
    opening: &BatchedDistributedPcOpening,
    point: &[FieldElement],
    params: DistributedPcsParams,
    backend: PcsBackendConfig,
    transcript: &mut T,
) -> PcsResult<()> {
    backend.validate()?;
    if commitments.is_empty()
        || opening.backend != backend
        || opening.point != point
        || commitments
            .iter()
            .any(|commitment| commitment.len() != opening.combined_commitment.len())
    {
        return Err(PcsError::InvalidProof);
    }
    opening.combined_commitment.validate_for_backend(backend)?;
    for commitment in commitments {
        commitment.validate_for_backend(backend)?;
    }
    absorb_batched_opening_context(
        transcript,
        label,
        backend,
        commitments,
        point,
        &opening.combined_commitment,
    );
    match &opening.proof {
        BatchedOpeningProof::BaseFold(basefold_proof) => {
            if backend.kind != PcsBackendKind::BaseFold {
                return Err(PcsError::InvalidProof);
            }
            let PcCommitment::BaseFold(basefold_commitment) = &opening.combined_commitment else {
                return Err(PcsError::InvalidCommitment);
            };
            BaseFoldPc::verify(basefold_commitment, basefold_proof, params, transcript)?;
        }
        BatchedOpeningProof::DeepFold(deepfold_proof) => {
            if backend.kind != PcsBackendKind::DeepFold {
                return Err(PcsError::InvalidProof);
            }
            let PcCommitment::DeepFold(deepfold_commitment) = &opening.combined_commitment else {
                return Err(PcsError::InvalidCommitment);
            };
            DeepFoldPc::verify(
                deepfold_commitment,
                deepfold_proof,
                point,
                params,
                backend,
                transcript,
            )?;
        }
    };
    if opening.aggregate_value != batched_opening_value(&opening.proof) {
        return Err(PcsError::InvalidEvaluation);
    }
    let expected_indices = batched_level_zero_indices(&opening.proof);
    if opening.consistency.len() != expected_indices.len() {
        return Err(PcsError::InvalidProof);
    }
    expected_indices
        .par_iter()
        .copied()
        .zip(opening.consistency.par_iter())
        .try_for_each(|(expected_index, consistency)| {
            if consistency.index != expected_index
                || consistency.worker_openings.len() != commitments.len()
                || consistency
                    .worker_openings
                    .iter()
                    .any(|worker_opening| worker_opening.index != expected_index)
            {
                return Err(PcsError::InvalidProof);
            }
            commitments
                .par_iter()
                .zip(consistency.worker_openings.par_iter())
                .try_for_each(|(commitment, worker_opening)| {
                    MerklePcs::verify(commitment.consistency_commitment(), worker_opening)
                })?;
            if batched_level_zero_value(&opening.proof, expected_index)
                != Some(consistency.combined_value)
            {
                return Err(PcsError::InvalidEvaluation);
            }
            let aggregate = consistency
                .worker_openings
                .iter()
                .map(|worker_opening| worker_opening.value)
                .sum::<FieldElement>();
            if aggregate != consistency.combined_value {
                return Err(PcsError::InvalidEvaluation);
            }
            Ok(())
        })?;
    Ok(())
}

fn combine_worker_values(values: &[Vec<FieldElement>]) -> PcsResult<Vec<FieldElement>> {
    let len = values
        .first()
        .map(Vec::len)
        .ok_or(PcsError::InvalidLength)?;
    let mut combined = vec![FieldElement::ZERO; len];
    for worker_values in values {
        if worker_values.len() != len {
            return Err(PcsError::InvalidLength);
        }
        for (combined_value, worker_value) in combined.iter_mut().zip(worker_values) {
            *combined_value += *worker_value;
        }
    }
    Ok(combined)
}

fn combine_weighted_source_values(
    sources: &[WeightedOpeningSource<'_>],
    len: usize,
) -> PcsResult<Vec<FieldElement>> {
    let mut combined = vec![FieldElement::ZERO; len];
    for source in sources {
        if source.values.len() != len {
            return Err(PcsError::InvalidLength);
        }
        for (combined_value, source_value) in combined.iter_mut().zip(source.values) {
            *combined_value += *source_value * source.weight;
        }
    }
    Ok(combined)
}

fn basefold_level_zero_indices(proof: &BaseFoldOpeningProof) -> Vec<usize> {
    deepfold::level_zero_indices(&proof.rs_proof)
}

fn batched_opening_value(proof: &BatchedOpeningProof) -> FieldElement {
    match proof {
        BatchedOpeningProof::BaseFold(proof) => proof.value,
        BatchedOpeningProof::DeepFold(proof) => proof.value,
    }
}

fn batched_opening_query_count(proof: &BatchedOpeningProof) -> usize {
    match proof {
        BatchedOpeningProof::BaseFold(proof) => proof.query_count,
        BatchedOpeningProof::DeepFold(proof) => proof.query_count,
    }
}

fn batched_level_zero_indices(proof: &BatchedOpeningProof) -> Vec<usize> {
    match proof {
        BatchedOpeningProof::BaseFold(proof) => basefold_level_zero_indices(proof),
        BatchedOpeningProof::DeepFold(proof) => deepfold::level_zero_indices(&proof.rs_proof),
    }
}

fn batched_level_zero_value(proof: &BatchedOpeningProof, index: usize) -> Option<FieldElement> {
    match proof {
        BatchedOpeningProof::BaseFold(proof) => proof.rs_proof.queries.iter().find_map(|rounds| {
            rounds.first().and_then(|query| {
                if query.beta_opening.index == index {
                    Some(query.beta_opening.value)
                } else if query.conjugate_opening.index == index {
                    Some(query.conjugate_opening.value)
                } else {
                    None
                }
            })
        }),
        BatchedOpeningProof::DeepFold(proof) => proof.rs_proof.queries.iter().find_map(|rounds| {
            rounds.first().and_then(|query| {
                if query.beta_opening.index == index {
                    Some(query.beta_opening.value)
                } else if query.conjugate_opening.index == index {
                    Some(query.conjugate_opening.value)
                } else {
                    None
                }
            })
        }),
    }
}

fn absorb_batched_opening_context<T: Transcript>(
    transcript: &mut T,
    label: &[u8],
    backend: PcsBackendConfig,
    commitments: &[PcCommitment],
    point: &[FieldElement],
    combined_commitment: &PcCommitment,
) {
    transcript.absorb_domain(b"distributed-batched-opening");
    transcript.absorb_public(b"label", label);
    absorb_backend_config(transcript, backend);
    transcript.absorb_public(b"workers", &(commitments.len() as u64).to_le_bytes());
    for commitment in commitments {
        absorb_pc_commitment(transcript, b"worker-commitment", commitment);
    }
    transcript.absorb_public(b"point-len", &(point.len() as u64).to_le_bytes());
    for coordinate in point {
        transcript.absorb_field(b"point", *coordinate);
    }
    absorb_pc_commitment(transcript, b"combined", combined_commitment);
}

fn absorb_weighted_source_opening_context<T: Transcript>(
    transcript: &mut T,
    label: &[u8],
    backend: PcsBackendConfig,
    sources: &[WeightedOpeningSource<'_>],
    point: &[FieldElement],
    combined_commitment: &PcCommitment,
) {
    transcript.absorb_domain(b"weighted-source-batch-opening");
    transcript.absorb_public(b"label", label);
    absorb_backend_config(transcript, backend);
    transcript.absorb_public(b"sources", &(sources.len() as u64).to_le_bytes());
    for source in sources {
        absorb_pc_commitment(transcript, b"source-commitment", source.commitment);
        transcript.absorb_field(b"source-weight", source.weight);
    }
    transcript.absorb_public(b"point-len", &(point.len() as u64).to_le_bytes());
    for coordinate in point {
        transcript.absorb_field(b"point", *coordinate);
    }
    absorb_pc_commitment(transcript, b"combined", combined_commitment);
}

fn absorb_weighted_source_verify_context<T: Transcript>(
    transcript: &mut T,
    label: &[u8],
    backend: PcsBackendConfig,
    commitments: &[PcCommitment],
    weights: &[FieldElement],
    point: &[FieldElement],
    combined_commitment: &PcCommitment,
) {
    transcript.absorb_domain(b"weighted-source-batch-opening");
    transcript.absorb_public(b"label", label);
    absorb_backend_config(transcript, backend);
    transcript.absorb_public(b"sources", &(commitments.len() as u64).to_le_bytes());
    for (commitment, weight) in commitments.iter().zip(weights) {
        absorb_pc_commitment(transcript, b"source-commitment", commitment);
        transcript.absorb_field(b"source-weight", *weight);
    }
    transcript.absorb_public(b"point-len", &(point.len() as u64).to_le_bytes());
    for coordinate in point {
        transcript.absorb_field(b"point", *coordinate);
    }
    absorb_pc_commitment(transcript, b"combined", combined_commitment);
}

fn absorb_backend_config<T: Transcript>(transcript: &mut T, backend: PcsBackendConfig) {
    transcript.absorb_public(b"backend-kind", backend.kind.as_str().as_bytes());
    transcript.absorb_public(
        b"backend-rate-inv",
        &(backend.rate_inv as u64).to_le_bytes(),
    );
    transcript.absorb_public(
        b"backend-security-bits",
        &(backend.security_bits as u64).to_le_bytes(),
    );
}

fn absorb_deepfold_opening_context<T: Transcript>(
    transcript: &mut T,
    base_len: usize,
    point: &[FieldElement],
    backend: PcsBackendConfig,
) {
    transcript.absorb_domain(b"deepfold-rs-rate-half-open");
    absorb_backend_config(transcript, backend);
    transcript.absorb_public(b"base-len", &(base_len as u64).to_le_bytes());
    transcript.absorb_public(
        b"codeword-len",
        &((base_len * backend.rate_inv) as u64).to_le_bytes(),
    );
    for coordinate in point {
        transcript.absorb_field(b"point", *coordinate);
    }
}

fn brakedown_encode(message: &[FieldElement]) -> PcsResult<Vec<FieldElement>> {
    BrakedownCodeSpec::new(message.len())?;
    let n = message.len();
    let p1 = parallel_field_section(n, |idx| {
        expander_terms_block1(n, idx)
            .into_iter()
            .map(|(col, coeff)| message[col] * coeff)
            .sum()
    });
    let p2 = parallel_field_section(n, |idx| {
        expander_terms_block2(n, idx)
            .into_iter()
            .map(|(col, coeff)| message[col] * coeff)
            .sum()
    });
    let p3 = parallel_field_section(n, |idx| {
        p1[idx] + p2[idx] + message[(13 * idx + 17) % n] * FieldElement::from(5_u64)
    });
    let mut out = Vec::with_capacity(n * CODE_RATE_INV);
    out.extend_from_slice(message);
    out.extend(p1);
    out.extend(p2);
    out.extend(p3);
    Ok(out)
}

fn pad_message_to_systematic_domain(message: &[FieldElement]) -> PcsResult<Vec<FieldElement>> {
    let spec = BrakedownCodeSpec::new(message.len())?;
    let mut padded = vec![FieldElement::ZERO; spec.codeword_len];
    padded[..message.len()].copy_from_slice(message);
    Ok(padded)
}

fn expander_terms_block1(n: usize, idx: usize) -> Vec<(usize, FieldElement)> {
    vec![
        (idx, FieldElement::ONE),
        ((idx + 1) % n, FieldElement::ONE),
        ((3 * idx + 1) % n, FieldElement::from(2_u64)),
        ((5 * idx + 7) % n, FieldElement::from(3_u64)),
    ]
}

fn expander_terms_block2(n: usize, idx: usize) -> Vec<(usize, FieldElement)> {
    vec![
        (idx, FieldElement::ONE),
        ((idx + 3) % n, FieldElement::from(2_u64)),
        ((7 * idx + 5) % n, FieldElement::ONE),
        ((11 * idx + 13) % n, FieldElement::from(3_u64)),
    ]
}

fn add_constraint(
    matrix: &mut SparseMatrix,
    row: usize,
    parity_col: usize,
    terms: Vec<(usize, FieldElement)>,
) -> PcsResult<()> {
    matrix
        .add_entry(row, parity_col, FieldElement::ONE)
        .map_err(|_| PcsError::InvalidEncoding)?;
    for (col, coeff) in terms {
        matrix
            .add_entry(row, col, -coeff)
            .map_err(|_| PcsError::InvalidEncoding)?;
    }
    Ok(())
}

fn compute_hu_vector(
    parity_check: &SparseMatrix,
    u: &[FieldElement],
) -> PcsResult<Vec<FieldElement>> {
    if parity_check.rows() != (1_usize << u.len()) {
        return Err(PcsError::InvalidLength);
    }
    let eqs = eq_evaluations(u).map_err(|_| PcsError::InvalidEvaluation)?;
    let mut out = vec![FieldElement::ZERO; parity_check.cols()];
    for entry in parity_check.entries() {
        out[entry.col] += entry.value * eqs[entry.row];
    }
    Ok(out)
}

#[cfg(test)]
fn lazy_hu_at_index(
    spec: BrakedownCodeSpec,
    u: &[FieldElement],
    index: usize,
) -> PcsResult<FieldElement> {
    if index >= spec.codeword_len || u.len() != spec.encoded_vars()? {
        return Err(PcsError::InvalidLength);
    }
    let mut out = FieldElement::ZERO;
    for (row, value) in parity_column_entries(spec, index)? {
        out += eq_basis(u, row).map_err(|_| PcsError::InvalidEvaluation)? * value;
    }
    Ok(out)
}

#[cfg(test)]
fn parity_column_entries(
    spec: BrakedownCodeSpec,
    index: usize,
) -> PcsResult<Vec<(usize, FieldElement)>> {
    if index >= spec.codeword_len {
        return Err(PcsError::InvalidLength);
    }
    let n = spec.message_len;
    let mut out = Vec::new();
    if index < n {
        let col = index;
        push_column_entry(&mut out, col, -FieldElement::ONE);
        push_column_entry(&mut out, mod_sub(col, 1, n), -FieldElement::ONE);
        push_column_entry(
            &mut out,
            odd_linear_preimage(col, 3, 1, n),
            -FieldElement::from(2_u64),
        );
        push_column_entry(
            &mut out,
            odd_linear_preimage(col, 5, 7, n),
            -FieldElement::from(3_u64),
        );
        push_column_entry(&mut out, n + col, -FieldElement::ONE);
        push_column_entry(&mut out, n + mod_sub(col, 3, n), -FieldElement::from(2_u64));
        push_column_entry(
            &mut out,
            n + odd_linear_preimage(col, 7, 5, n),
            -FieldElement::ONE,
        );
        push_column_entry(
            &mut out,
            n + odd_linear_preimage(col, 11, 13, n),
            -FieldElement::from(3_u64),
        );
        push_column_entry(
            &mut out,
            2 * n + odd_linear_preimage(col, 13, 17, n),
            -FieldElement::from(5_u64),
        );
    } else if index < 2 * n {
        let col = index - n;
        push_column_entry(&mut out, col, FieldElement::ONE);
        push_column_entry(&mut out, 2 * n + col, -FieldElement::ONE);
    } else if index < 3 * n {
        let col = index - 2 * n;
        push_column_entry(&mut out, n + col, FieldElement::ONE);
        push_column_entry(&mut out, 2 * n + col, -FieldElement::ONE);
    } else {
        let col = index - 3 * n;
        push_column_entry(&mut out, 2 * n + col, FieldElement::ONE);
    }
    Ok(out)
}

#[cfg(test)]
fn push_column_entry(out: &mut Vec<(usize, FieldElement)>, row: usize, value: FieldElement) {
    if let Some((_, existing)) = out
        .iter_mut()
        .find(|(existing_row, _)| *existing_row == row)
    {
        *existing += value;
    } else if !value.is_zero() {
        out.push((row, value));
    }
}

#[cfg(test)]
fn odd_linear_preimage(target: usize, multiplier: usize, offset: usize, modulus: usize) -> usize {
    if modulus == 1 {
        return 0;
    }
    (mod_sub(target, offset % modulus, modulus) * odd_mod_inverse(multiplier, modulus)) % modulus
}

#[cfg(test)]
fn odd_mod_inverse(value: usize, modulus: usize) -> usize {
    debug_assert!(modulus.is_power_of_two());
    debug_assert!(value % 2 == 1);
    if modulus == 1 {
        return 0;
    }
    let mut inverse = 1usize;
    let mut bits = 1usize;
    while bits < usize::BITS as usize && (1usize << bits) < modulus {
        inverse = inverse.wrapping_mul(2usize.wrapping_sub(value.wrapping_mul(inverse)));
        bits *= 2;
    }
    inverse & (modulus - 1)
}

#[cfg(test)]
fn mod_sub(left: usize, right: usize, modulus: usize) -> usize {
    (left + modulus - (right % modulus)) % modulus
}

fn column_hashes(encoded_rows: &[Vec<FieldElement>]) -> Vec<FieldElement> {
    if encoded_rows.is_empty() {
        return vec![FieldElement::ZERO];
    }
    let width = encoded_rows[0].len();
    (0..width)
        .into_par_iter()
        .map(|column| {
            let values = encoded_rows
                .iter()
                .map(|row| row[column])
                .collect::<Vec<_>>();
            hash_column_to_field(&values)
        })
        .collect()
}

fn hash_column_to_field(values: &[FieldElement]) -> FieldElement {
    let mut input = Vec::with_capacity(16 + values.len() * 8);
    input.extend_from_slice(b"protocol-11-column");
    input.extend_from_slice(&(values.len() as u64).to_le_bytes());
    for value in values {
        input.extend_from_slice(&value.to_le_bytes());
    }
    let digest = sha256(&input);
    let mut bytes = [0_u8; 8];
    bytes.copy_from_slice(&digest[..8]);
    FieldElement::from_le_bytes(bytes)
}

fn validate_commitment(commitment: &Protocol11Commitment) -> PcsResult<()> {
    commitment.backend.validate()?;
    let layout = Protocol11Layout::new(commitment.original_len, commitment.workers.len())?;
    if commitment.matrix_rows != layout.matrix_rows
        || commitment.row_axis_len != layout.row_axis_len
        || commitment.rows_per_worker != layout.rows_per_worker
        || commitment.row_width != layout.row_width
        || commitment.encoded_width != layout.encoded_width
    {
        return Err(PcsError::InvalidLength);
    }
    for (expected, worker) in commitment.workers.iter().enumerate() {
        if worker.worker_id != expected
            || worker.row_range != worker_row_range(&layout, expected)
            || worker.matrix_commitment.len != layout.encoded_width
        {
            return Err(PcsError::InvalidWorker);
        }
    }
    if aggregate_worker_commitments(&commitment.workers) != commitment.root {
        return Err(PcsError::InvalidCommitment);
    }
    Ok(())
}

fn log2_floor(value: usize) -> usize {
    usize::BITS as usize - 1 - value.leading_zeros() as usize
}

fn elapsed_ms(start: Instant) -> f64 {
    start.elapsed().as_secs_f64() * 1000.0
}

fn parallel_field_section<F>(len: usize, f: F) -> Vec<FieldElement>
where
    F: Fn(usize) -> FieldElement + Sync + Send,
{
    (0..len).into_par_iter().map(f).collect()
}

fn leaf_hash(value: FieldElement) -> [u8; 32] {
    let mut input = Vec::with_capacity(9);
    input.push(0);
    input.extend_from_slice(&value.to_le_bytes());
    sha256(&input)
}

fn node_hash(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut input = Vec::with_capacity(65);
    input.push(1);
    input.extend_from_slice(left);
    input.extend_from_slice(right);
    sha256(&input)
}

fn aggregate_worker_commitments(workers: &[Protocol11WorkerCommitment]) -> [u8; 32] {
    let mut input = Vec::new();
    input.extend_from_slice(b"protocol-11-worker-commitments");
    for worker in workers {
        input.extend_from_slice(&(worker.worker_id as u64).to_le_bytes());
        input.extend_from_slice(&(worker.row_range.0 as u64).to_le_bytes());
        input.extend_from_slice(&(worker.row_range.1 as u64).to_le_bytes());
        input.extend_from_slice(&worker.matrix_commitment.root);
    }
    sha256(&input)
}

fn absorb_protocol11_commitment<T: Transcript>(
    transcript: &mut T,
    commitment: &Protocol11Commitment,
) {
    transcript.absorb_domain(b"protocol-11-commitment");
    absorb_backend_config(transcript, commitment.backend);
    transcript.absorb_public(
        b"original-len",
        &(commitment.original_len as u64).to_le_bytes(),
    );
    transcript.absorb_public(
        b"matrix-rows",
        &(commitment.matrix_rows as u64).to_le_bytes(),
    );
    transcript.absorb_public(
        b"row-axis-len",
        &(commitment.row_axis_len as u64).to_le_bytes(),
    );
    transcript.absorb_public(
        b"rows-per-worker",
        &(commitment.rows_per_worker as u64).to_le_bytes(),
    );
    transcript.absorb_public(b"row-width", &(commitment.row_width as u64).to_le_bytes());
    transcript.absorb_public(
        b"encoded-width",
        &(commitment.encoded_width as u64).to_le_bytes(),
    );
    transcript.absorb_public(b"workers", &(commitment.workers.len() as u64).to_le_bytes());
    transcript.absorb_commitment(b"root", &commitment.root);
    for worker in &commitment.workers {
        transcript.absorb_public(b"worker-id", &(worker.worker_id as u64).to_le_bytes());
        transcript.absorb_public(b"worker-start", &(worker.row_range.0 as u64).to_le_bytes());
        transcript.absorb_public(b"worker-end", &(worker.row_range.1 as u64).to_le_bytes());
        absorb_commitment(transcript, b"worker-matrix", &worker.matrix_commitment);
    }
}

fn absorb_protocol11_eval_commitments<T: Transcript>(
    transcript: &mut T,
    eval_commitments: &[Protocol11WorkerEvalCommitments],
    merkle_roots: &[Protocol11WorkerMerkleRoots],
) {
    transcript.absorb_domain(b"protocol-11-eval-commitments");
    for eval in eval_commitments {
        transcript.absorb_public(b"worker-id", &(eval.worker_id as u64).to_le_bytes());
        absorb_pc_commitment(transcript, b"f1", &eval.f1);
        absorb_pc_commitment(transcript, b"e1", &eval.e1);
        absorb_pc_commitment(transcript, b"f2", &eval.f2);
        absorb_pc_commitment(transcript, b"e2", &eval.e2);
        let roots = merkle_roots
            .iter()
            .find(|roots| roots.worker_id == eval.worker_id)
            .expect("validated by caller");
        absorb_pc_commitment(transcript, b"rt-e1", &roots.e1_root);
        absorb_pc_commitment(transcript, b"rt-e2", &roots.e2_root);
    }
}

fn absorb_basefold_opening_context<T: Transcript>(
    transcript: &mut T,
    base_len: usize,
    point: &[FieldElement],
    rate_inv: usize,
    codeword_len: usize,
) {
    transcript.absorb_domain(b"basefold-pc-open");
    transcript.absorb_public(b"base-len", &(base_len as u64).to_le_bytes());
    transcript.absorb_public(b"rate-inv", &(rate_inv as u64).to_le_bytes());
    transcript.absorb_public(b"codeword-len", &(codeword_len as u64).to_le_bytes());
    for coordinate in point {
        transcript.absorb_field(b"point", *coordinate);
    }
}

fn absorb_code_spec<T: Transcript>(transcript: &mut T, spec: BrakedownCodeSpec) {
    transcript.absorb_public(b"message-len", &(spec.message_len as u64).to_le_bytes());
    transcript.absorb_public(b"codeword-len", &(spec.codeword_len as u64).to_le_bytes());
    transcript.absorb_public(b"rate-inv", &(spec.rate_inv as u64).to_le_bytes());
}

fn absorb_parity_shape<T: Transcript>(transcript: &mut T, shape: BrakedownParityShape) {
    transcript.absorb_public(b"parity-rows", &(shape.rows as u64).to_le_bytes());
    transcript.absorb_public(b"parity-cols", &(shape.cols as u64).to_le_bytes());
    transcript.absorb_public(b"parity-nnz", &(shape.nnz as u64).to_le_bytes());
}

fn absorb_pc_commitment_vec<T: Transcript>(
    transcript: &mut T,
    label: &[u8],
    commitments: &[PcCommitment],
) {
    transcript.absorb_public(label, &(commitments.len() as u64).to_le_bytes());
    for commitment in commitments {
        absorb_pc_commitment(transcript, label, commitment);
    }
}

fn absorb_pc_commitment<T: Transcript>(
    transcript: &mut T,
    label: &[u8],
    commitment: &PcCommitment,
) {
    match commitment {
        PcCommitment::BaseFold(base) => {
            transcript.absorb_public(label, b"basefold");
            transcript.absorb_public(label, &(base.rate_inv as u64).to_le_bytes());
            transcript.absorb_public(label, &(base.codeword_len as u64).to_le_bytes());
            absorb_commitment(transcript, label, &base.base);
            absorb_commitment(transcript, label, &base.rs.codeword);
        }
        PcCommitment::DeepFold(deepfold) => {
            transcript.absorb_public(label, b"deepfold");
            transcript.absorb_public(label, &(deepfold.rate_inv as u64).to_le_bytes());
            transcript.absorb_public(label, &(deepfold.codeword_len as u64).to_le_bytes());
            absorb_commitment(transcript, label, &deepfold.base);
            absorb_commitment(transcript, label, &deepfold.rs.codeword);
        }
    }
}

fn absorb_commitment<T: Transcript>(transcript: &mut T, label: &[u8], commitment: &Commitment) {
    transcript.absorb_public(label, &(commitment.len as u64).to_le_bytes());
    transcript.absorb_commitment(label, &commitment.root);
}

fn protocol11_eval_commitments_size_bytes(commitments: &Protocol11WorkerEvalCommitments) -> usize {
    8 + pc_commitment_size_bytes(&commitments.f1)
        + pc_commitment_size_bytes(&commitments.e1)
        + pc_commitment_size_bytes(&commitments.f2)
        + pc_commitment_size_bytes(&commitments.e2)
}

fn protocol11_merkle_roots_size_bytes(roots: &Protocol11WorkerMerkleRoots) -> usize {
    8 + pc_commitment_size_bytes(&roots.e1_root) + pc_commitment_size_bytes(&roots.e2_root)
}

fn protocol11_column_proof_size_bytes(proof: &Protocol11WorkerColumnProof) -> usize {
    8 + proof
        .columns
        .iter()
        .map(|column| {
            8 + field_vec_size(&column.encoded_row_values)
                + 8
                + opening_proof_size_bytes(&column.matrix_opening)
                + 8
                + opening_proof_size_bytes(&column.e1_opening)
                + 8
                + opening_proof_size_bytes(&column.e2_opening)
        })
        .sum::<usize>()
}

fn batched_distributed_pc_opening_size_bytes(opening: &BatchedDistributedPcOpening) -> usize {
    8 + field_vec_size(&opening.point)
        + 8
        + pc_commitment_size_bytes(&opening.combined_commitment)
        + batched_opening_proof_size_bytes(&opening.proof)
        + opening
            .consistency
            .iter()
            .map(|consistency| {
                8 + 8
                    + consistency
                        .worker_openings
                        .iter()
                        .map(opening_proof_size_bytes)
                        .sum::<usize>()
            })
            .sum::<usize>()
}

fn protocol10_opening_batch_size_bytes(proof: &Protocol10OpeningBatchProof) -> usize {
    proof
        .claims
        .iter()
        .map(|claim| {
            8 + 8
                + claim.label.len()
                + field_vec_size(&claim.point)
                + 8
                + claim
                    .source_commitments
                    .iter()
                    .map(pc_commitment_size_bytes)
                    .sum::<usize>()
        })
        .sum::<usize>()
        + field_vec_size(&proof.reduction.gammas)
        + product_sumcheck_size_bytes(&proof.reduction.product_sumcheck)
        + weighted_source_batch_opening_size_bytes(&proof.combined_opening)
}

fn weighted_source_batch_opening_size_bytes(opening: &WeightedSourceBatchOpening) -> usize {
    8 + field_vec_size(&opening.point)
        + 8
        + pc_commitment_size_bytes(&opening.combined_commitment)
        + batched_opening_proof_size_bytes(&opening.proof)
        + opening
            .consistency
            .iter()
            .map(|consistency| {
                8 + 8
                    + consistency
                        .source_openings
                        .iter()
                        .map(opening_proof_size_bytes)
                        .sum::<usize>()
            })
            .sum::<usize>()
}

fn batched_opening_proof_size_bytes(proof: &BatchedOpeningProof) -> usize {
    match proof {
        BatchedOpeningProof::BaseFold(proof) => 8 + basefold_opening_size_bytes(proof),
        BatchedOpeningProof::DeepFold(proof) => {
            8 + 8 + 8 + 8 + deepfold::proof_size_bytes(&proof.rs_proof)
        }
    }
}

fn basefold_opening_size_bytes(proof: &BaseFoldOpeningProof) -> usize {
    8 + 8 + 8 + 8 + deepfold::proof_size_bytes(&proof.rs_proof)
}

fn product_sumcheck_size_bytes(proof: &ProductSumcheckProof) -> usize {
    8 + proof.rounds.len() * 24 + field_vec_size(&proof.challenges) + 8
}

fn commitment_size_bytes(_commitment: &Commitment) -> usize {
    32 + 8
}

fn pc_commitment_size_bytes(commitment: &PcCommitment) -> usize {
    match commitment {
        PcCommitment::BaseFold(base) => {
            8 + 8 + 8 + commitment_size_bytes(&base.base) + commitment_size_bytes(&base.rs.codeword)
        }
        PcCommitment::DeepFold(deepfold) => {
            8 + 8
                + 8
                + commitment_size_bytes(&deepfold.base)
                + commitment_size_bytes(&deepfold.rs.codeword)
        }
    }
}

fn opening_proof_size_bytes(proof: &OpeningProof) -> usize {
    8 + 8 + 8 + proof.path.len() * 33
}

fn field_vec_size(values: &[FieldElement]) -> usize {
    8 + values.len() * 8
}

fn usize_vec_size(values: &[usize]) -> usize {
    8 + values.len() * 8
}

#[cfg(test)]
mod tests {
    use super::*;
    use pq_core::MultilinearPolynomial;
    use pq_transcript::HashTranscript;

    fn sample_values(size: usize) -> Vec<FieldElement> {
        (0..size)
            .map(|idx| FieldElement::from((idx as u64 + 3) * 17))
            .collect()
    }

    fn sample_deepfold_batch_opening(
        transcript_label: &'static [u8],
    ) -> (
        Vec<PcCommitment>,
        BatchedDistributedPcOpening,
        Vec<FieldElement>,
        PcsBackendConfig,
        DistributedPcsParams,
    ) {
        let values_a = sample_values(32);
        let values_b = (0..32)
            .map(|idx| FieldElement::from((idx as u64 + 11) * 23))
            .collect::<Vec<_>>();
        let point = (0..5)
            .map(|idx| FieldElement::from((idx as u64 + 5) * 19))
            .collect::<Vec<_>>();
        let backend = PcsBackendConfig {
            security_bits: 8,
            ..PcsBackendConfig::deepfold_default()
        };
        let params = DistributedPcsParams {
            query_count: 2,
            security_bits: 8,
        };
        let (commitment_a, advice_a) = commit_pc_with_advice(&values_a, backend).expect("a");
        let (commitment_b, advice_b) = commit_pc_with_advice(&values_b, backend).expect("b");
        let values = vec![values_a, values_b];
        let commitments = vec![commitment_a, commitment_b];
        let advices = vec![&advice_a, &advice_b];
        let mut prover_tr = HashTranscript::new(transcript_label);
        let opening = open_distributed(
            DistributedOpenRequest {
                label: b"batch-test",
                values: &values,
                commitments: &commitments,
                advices: &advices,
                point: &point,
                params,
                backend,
            },
            &mut prover_tr,
        )
        .expect("open");
        (commitments, opening, point, backend, params)
    }

    fn sample_protocol11_proof_with_backend(
        transcript_label: &'static [u8],
        backend: PcsBackendConfig,
    ) -> (
        Protocol11Commitment,
        Protocol11Proof,
        Vec<FieldElement>,
        DistributedPcsParams,
    ) {
        let values = sample_values(128);
        let commitment =
            DistributedBrakedown::commit_with_config(&values, 2, backend).expect("commit");
        let point = (0..log2_power_of_two(protocol11_evaluation_domain_len(&commitment))
            .expect("domain length is power of two"))
            .map(|idx| FieldElement::from((idx as u64 + 29) * 7))
            .collect::<Vec<_>>();
        let params = DistributedPcsParams {
            query_count: 2,
            security_bits: backend.security_bits.min(8),
        };
        let mut prover_tr = HashTranscript::new(transcript_label);
        let proof =
            DistributedBrakedown::open(&values, &commitment, &point, params, &mut prover_tr)
                .expect("open");
        (commitment, proof, point, params)
    }

    fn verify_protocol11_sample(
        transcript_label: &'static [u8],
        commitment: &Protocol11Commitment,
        proof: &Protocol11Proof,
        params: DistributedPcsParams,
        backend: PcsBackendConfig,
    ) -> PcsResult<()> {
        let mut verifier_tr = HashTranscript::new(transcript_label);
        DistributedBrakedown::verify_with_config(
            commitment,
            proof,
            params,
            backend,
            &mut verifier_tr,
        )
    }

    #[test]
    fn brakedown_code_is_systematic_and_satisfies_sparse_h() {
        let f = sample_values(16);
        let e = encode_systematic(&f).expect("encode");
        assert_eq!(&e[..f.len()], f.as_slice());
        let h = brakedown_parity_check_matrix(f.len()).expect("h");
        let residual = h.mul_vec(&e).expect("mul");
        assert!(residual.iter().all(|value| value.is_zero()));
    }

    #[test]
    fn brakedown_parity_shape_matches_materialized_matrix() {
        for message_len in [1, 2, 4, 8, 16, 64, 256] {
            let spec = BrakedownCodeSpec::new(message_len).expect("spec");
            let shape = BrakedownParityShape::from_spec(spec);
            let matrix = brakedown_parity_check_matrix(message_len).expect("matrix");
            assert_eq!(shape.rows, matrix.rows());
            assert_eq!(shape.cols, matrix.cols());
            assert_eq!(shape.nnz, matrix.nnz());
            assert_eq!(shape.nnz, 14 * message_len);
        }
    }

    #[test]
    fn protocol10_verify_shape_is_o1_and_rejects_bad_shape() {
        let spec = BrakedownCodeSpec::new(1 << 20).expect("spec");
        let shape = BrakedownParityShape::from_spec(spec);
        assert_eq!(
            verify_protocol10_parity_shape(spec, shape.rows, shape.cols, shape.nnz).expect("shape"),
            shape
        );
        assert!(
            verify_protocol10_parity_shape(spec, shape.rows, shape.cols, shape.nnz + 1).is_err()
        );
    }

    #[test]
    fn lazy_hu_matches_materialized_sparse_hu() {
        let spec = BrakedownCodeSpec::new(16).expect("spec");
        let h = brakedown_parity_check_matrix(spec.message_len).expect("h");
        let u = (0..spec.encoded_vars().expect("vars"))
            .map(|idx| FieldElement::from((idx as u64 + 11) * 23))
            .collect::<Vec<_>>();
        let materialized = compute_hu_vector(&h, &u).expect("hu");
        for (idx, expected) in materialized.iter().copied().enumerate() {
            assert_eq!(lazy_hu_at_index(spec, &u, idx).expect("lazy"), expected);
        }
    }

    #[test]
    fn odd_mod_inverse_matches_power_of_two_inverse() {
        for modulus in [2usize, 4, 8, 16, 256, 1024, 1 << 20] {
            for value in [3usize, 5, 7, 11, 13] {
                let inverse = odd_mod_inverse(value, modulus);
                assert_eq!((value * inverse) % modulus, 1 % modulus);
            }
        }
    }

    #[test]
    fn protocol11_layout_uses_unpadded_rows_per_worker() {
        let layout = Protocol11Layout::new(1 << 14, 8).expect("layout");
        assert_eq!(layout.rows_per_worker, 11);
        assert_eq!(layout.matrix_rows, 88);
        assert!(layout.row_axis_len.is_power_of_two());
        assert!(layout.row_width.is_power_of_two());
    }

    #[test]
    fn cached_merkle_opening_matches_public_merkle_api() {
        let values = sample_values(64);
        let tree = MerkleTree::new(&values).expect("tree");
        assert_eq!(
            tree.commitment(),
            MerklePcs::commit(&values).expect("commit")
        );
        for index in [0usize, 1, 17, 63] {
            assert_eq!(
                tree.open(index).expect("cached opening"),
                MerklePcs::open(&values, index).expect("public opening")
            );
        }
    }

    #[test]
    fn basefold_open_with_advice_matches_open() {
        let values = sample_values(32);
        let point = (0..5)
            .map(|idx| FieldElement::from((idx as u64 + 5) * 19))
            .collect::<Vec<_>>();
        let (commitment, advice) = BaseFoldPc::commit_with_advice(&values).expect("advice");
        assert_eq!(commitment, *advice.commitment());
        let mut direct_tr = HashTranscript::new(b"basefold-advice-test");
        let direct = BaseFoldPc::open(
            &values,
            &point,
            DistributedPcsParams::new(2),
            &mut direct_tr,
        )
        .expect("direct open");
        let mut advice_tr = HashTranscript::new(b"basefold-advice-test");
        let advised = BaseFoldPc::open_with_advice(
            &values,
            &advice,
            &point,
            DistributedPcsParams::new(2),
            &mut advice_tr,
        )
        .expect("advised open");
        assert_eq!(direct, advised);
    }

    #[test]
    fn basefold_open_with_advice_rejects_wrong_advice_or_commitment() {
        let values = sample_values(32);
        let other_values = (0..32)
            .map(|idx| FieldElement::from((idx as u64 + 17) * 29))
            .collect::<Vec<_>>();
        let point = (0..5)
            .map(|idx| FieldElement::from((idx as u64 + 5) * 19))
            .collect::<Vec<_>>();
        let (_, wrong_advice) = BaseFoldPc::commit_with_advice(&other_values).expect("advice");
        let mut transcript = HashTranscript::new(b"wrong-advice");
        assert!(
            BaseFoldPc::open_with_advice(
                &values,
                &wrong_advice,
                &point,
                DistributedPcsParams::new(2),
                &mut transcript,
            )
            .is_err()
        );

        let (commitment, advice) = BaseFoldPc::commit_with_advice(&values).expect("advice");
        let mut bad_commitment = commitment.clone();
        bad_commitment.base.root = [7; 32];
        let bad_commitment = PcCommitment::BaseFold(bad_commitment);
        let advice = PcCommitmentAdvice::BaseFold(advice);
        let before = BASEFOLD_COMMIT_CALLS.load(std::sync::atomic::Ordering::SeqCst);
        let mut transcript = HashTranscript::new(b"open-distributed-advice");
        assert!(
            open_distributed(
                DistributedOpenRequest {
                    label: b"advice-test",
                    values: std::slice::from_ref(&values),
                    commitments: &[bad_commitment],
                    advices: &[&advice],
                    point: &point,
                    params: DistributedPcsParams::new(2),
                    backend: PcsBackendConfig::basefold_default(),
                },
                &mut transcript,
            )
            .is_err()
        );
        let after = BASEFOLD_COMMIT_CALLS.load(std::sync::atomic::Ordering::SeqCst);
        assert_eq!(before, after);
    }

    #[test]
    fn protocol11_proof_size_breakdown_total_matches_legacy_size() {
        let values = sample_values(64);
        let commitment = DistributedBrakedown::commit(&values, 2).expect("commit");
        let point = (0..log2_power_of_two(protocol11_evaluation_domain_len(&commitment))
            .expect("domain length is power of two"))
            .map(|idx| FieldElement::from((idx as u64 + 3) * 17))
            .collect::<Vec<_>>();
        let mut transcript = HashTranscript::new(b"size-breakdown");
        let proof = DistributedBrakedown::open(
            &values,
            &commitment,
            &point,
            DistributedPcsParams::new(2),
            &mut transcript,
        )
        .expect("open");
        let breakdown = protocol11_proof_size_breakdown(&proof);
        assert_eq!(breakdown.total_bytes(), protocol11_proof_size_bytes(&proof));
        assert_eq!(
            breakdown.protocol10_e1_bytes,
            protocol10_proof_size_breakdown(&proof.encoding_batch.encodings[0]).total_bytes()
                + product_sumcheck_size_bytes(&proof.encoding_batch.product_sumcheck)
        );
        assert_eq!(
            breakdown.protocol10_e2_bytes,
            protocol10_proof_size_breakdown(&proof.encoding_batch.encodings[1]).total_bytes()
        );
    }

    #[test]
    fn protocol10_opening_batch_coalesces_duplicate_source_commitments() {
        let values = sample_values(64);
        let workers = 2;
        let commitment = DistributedBrakedown::commit(&values, workers).expect("commit");
        let point = (0..log2_power_of_two(protocol11_evaluation_domain_len(&commitment))
            .expect("domain length is power of two"))
            .map(|idx| FieldElement::from((idx as u64 + 11) * 23))
            .collect::<Vec<_>>();
        let mut transcript = HashTranscript::new(b"protocol10-source-coalesce");
        let proof = DistributedBrakedown::open(
            &values,
            &commitment,
            &point,
            DistributedPcsParams::new(2),
            &mut transcript,
        )
        .expect("open");

        for encoding in &proof.encoding_batch.encodings {
            for consistency in &encoding.opening_batch.combined_opening.consistency {
                assert_eq!(consistency.source_openings.len(), 1 + 2 * workers);
            }
        }
    }

    #[test]
    fn distributed_product_sumcheck_matches_full_aggregate_rounds() {
        let left_a = sample_values(16);
        let left_b = (0..16)
            .map(|idx| FieldElement::from((idx as u64 + 9) * 31))
            .collect::<Vec<_>>();
        let right = (0..16)
            .map(|idx| FieldElement::from((idx as u64 + 2) * 7))
            .collect::<Vec<_>>();
        let locals = vec![left_a.clone(), left_b.clone()];
        let aggregate = left_a
            .iter()
            .copied()
            .zip(left_b.iter().copied())
            .map(|(left, right)| left + right)
            .collect::<Vec<_>>();
        let claim = inner_product_slice(&aggregate, &right);
        let mut distributed_tr = HashTranscript::new(b"distributed-product-test");
        let (distributed, e_at_r, hu_at_r) =
            prove_distributed_product_sumcheck(&locals, &right, claim, &mut distributed_tr)
                .expect("distributed proof");
        let aggregate_poly = MultilinearPolynomial::new(aggregate).expect("aggregate poly");
        let right_poly = MultilinearPolynomial::new(right).expect("right poly");
        let mut full_tr = HashTranscript::new(b"distributed-product-test");
        let full =
            pq_sumcheck::prove_product_sumcheck(&aggregate_poly, &right_poly, claim, &mut full_tr)
                .expect("full proof");
        assert_eq!(distributed.rounds, full.rounds);
        assert_eq!(distributed.challenges, full.challenges);
        assert_eq!(distributed.final_evaluation, full.final_evaluation);
        assert_eq!(distributed.final_evaluation, e_at_r * hu_at_r);
    }

    #[test]
    fn basefold_pc_rejects_tampered_opening() {
        let values = sample_values(32);
        let point = (0..5)
            .map(|idx| FieldElement::from((idx as u64 + 5) * 19))
            .collect::<Vec<_>>();
        let commitment = BaseFoldPc::commit(&values).expect("commit");
        let mut prover_tr = HashTranscript::new(b"basefold-test");
        let mut proof = BaseFoldPc::open(
            &values,
            &point,
            DistributedPcsParams::new(2),
            &mut prover_tr,
        )
        .expect("open");
        let mut verifier_tr = HashTranscript::new(b"basefold-test");
        BaseFoldPc::verify(
            &commitment,
            &proof,
            DistributedPcsParams::new(2),
            &mut verifier_tr,
        )
        .expect("verify");
        proof.rs_proof.queries[0][0].beta_opening.value += FieldElement::ONE;
        let mut verifier_tr = HashTranscript::new(b"basefold-test");
        assert!(
            BaseFoldPc::verify(
                &commitment,
                &proof,
                DistributedPcsParams::new(2),
                &mut verifier_tr,
            )
            .is_err()
        );
    }

    #[test]
    fn basefold_batch_opening_accepts_valid_proof() {
        let values_a = sample_values(32);
        let values_b = (0..32)
            .map(|idx| FieldElement::from((idx as u64 + 11) * 23))
            .collect::<Vec<_>>();
        let point = (0..5)
            .map(|idx| FieldElement::from((idx as u64 + 5) * 19))
            .collect::<Vec<_>>();
        let (commitment_a, advice_a) = BaseFoldPc::commit_with_advice(&values_a).expect("a");
        let (commitment_b, advice_b) = BaseFoldPc::commit_with_advice(&values_b).expect("b");
        let commitment_a = PcCommitment::BaseFold(commitment_a);
        let commitment_b = PcCommitment::BaseFold(commitment_b);
        let advice_a = PcCommitmentAdvice::BaseFold(advice_a);
        let advice_b = PcCommitmentAdvice::BaseFold(advice_b);
        let values = vec![values_a, values_b];
        let commitments = vec![commitment_a, commitment_b];
        let advices = vec![&advice_a, &advice_b];
        let mut prover_tr = HashTranscript::new(b"batch-open-test");
        let opening = open_distributed(
            DistributedOpenRequest {
                label: b"batch-test",
                values: &values,
                commitments: &commitments,
                advices: &advices,
                point: &point,
                params: DistributedPcsParams::new(2),
                backend: PcsBackendConfig::basefold_default(),
            },
            &mut prover_tr,
        )
        .expect("open");
        let mut verifier_tr = HashTranscript::new(b"batch-open-test");
        verify_distributed_openings(
            b"batch-test",
            &commitments,
            &opening,
            &point,
            DistributedPcsParams::new(2),
            PcsBackendConfig::basefold_default(),
            &mut verifier_tr,
        )
        .expect("verify");
    }

    #[test]
    fn basefold_batch_opening_rejects_tampered_claim() {
        let values_a = sample_values(32);
        let values_b = (0..32)
            .map(|idx| FieldElement::from((idx as u64 + 11) * 23))
            .collect::<Vec<_>>();
        let point = (0..5)
            .map(|idx| FieldElement::from((idx as u64 + 5) * 19))
            .collect::<Vec<_>>();
        let (commitment_a, advice_a) = BaseFoldPc::commit_with_advice(&values_a).expect("a");
        let (commitment_b, advice_b) = BaseFoldPc::commit_with_advice(&values_b).expect("b");
        let commitment_a = PcCommitment::BaseFold(commitment_a);
        let commitment_b = PcCommitment::BaseFold(commitment_b);
        let advice_a = PcCommitmentAdvice::BaseFold(advice_a);
        let advice_b = PcCommitmentAdvice::BaseFold(advice_b);
        let values = vec![values_a, values_b];
        let commitments = vec![commitment_a, commitment_b];
        let advices = vec![&advice_a, &advice_b];
        let mut prover_tr = HashTranscript::new(b"batch-open-tamper");
        let mut opening = open_distributed(
            DistributedOpenRequest {
                label: b"batch-test",
                values: &values,
                commitments: &commitments,
                advices: &advices,
                point: &point,
                params: DistributedPcsParams::new(2),
                backend: PcsBackendConfig::basefold_default(),
            },
            &mut prover_tr,
        )
        .expect("open");
        opening.consistency[0].worker_openings[0].value += FieldElement::ONE;
        let mut verifier_tr = HashTranscript::new(b"batch-open-tamper");
        assert!(
            verify_distributed_openings(
                b"batch-test",
                &commitments,
                &opening,
                &point,
                DistributedPcsParams::new(2),
                PcsBackendConfig::basefold_default(),
                &mut verifier_tr,
            )
            .is_err()
        );
    }

    #[test]
    fn deepfold_batch_opening_rejects_wrong_rate_inv() {
        assert!(
            PcsBackendConfig {
                kind: PcsBackendKind::DeepFold,
                rate_inv: 2,
                security_bits: DEFAULT_SECURITY_BITS,
            }
            .validate()
            .is_err()
        );
    }

    #[test]
    fn deepfold_commit_does_not_build_basefold_advice() {
        let values = sample_values(32);
        let _guard = BASEFOLD_COMMIT_COUNTER_LOCK.lock().expect("counter lock");
        let before = BASEFOLD_COMMIT_WITH_ADVICE_CALLS.load(std::sync::atomic::Ordering::SeqCst);
        let (commitment, advice) =
            commit_pc_with_advice(&values, PcsBackendConfig::deepfold_default()).expect("commit");
        let after = BASEFOLD_COMMIT_WITH_ADVICE_CALLS.load(std::sync::atomic::Ordering::SeqCst);
        assert_eq!(before, after);
        assert!(matches!(commitment, PcCommitment::DeepFold(_)));
        assert!(matches!(advice, PcCommitmentAdvice::DeepFold { .. }));
    }

    #[test]
    fn deepfold_open_rejects_wrong_raw_or_rs_advice() {
        let values = sample_values(32);
        let other_values = (0..32)
            .map(|idx| FieldElement::from((idx as u64 + 17) * 29))
            .collect::<Vec<_>>();
        let point = (0..5)
            .map(|idx| FieldElement::from((idx as u64 + 5) * 19))
            .collect::<Vec<_>>();
        let backend = PcsBackendConfig {
            security_bits: 8,
            ..PcsBackendConfig::deepfold_default()
        };
        let params = DistributedPcsParams {
            query_count: 2,
            security_bits: 8,
        };
        let (commitment, advice) = commit_pc_with_advice(&values, backend).expect("commit");
        let (_, wrong_advice) = commit_pc_with_advice(&other_values, backend).expect("wrong");

        let mut transcript = HashTranscript::new(b"deepfold-wrong-raw-advice");
        assert!(
            open_distributed(
                DistributedOpenRequest {
                    label: b"wrong-raw",
                    values: std::slice::from_ref(&values),
                    commitments: std::slice::from_ref(&commitment),
                    advices: &[&wrong_advice],
                    point: &point,
                    params,
                    backend,
                },
                &mut transcript,
            )
            .is_err()
        );

        let PcCommitmentAdvice::DeepFold {
            commitment: advice_commitment,
            base_tree,
            ..
        } = advice
        else {
            panic!("deepfold advice expected");
        };
        let PcCommitmentAdvice::DeepFold { rs: wrong_rs, .. } = wrong_advice else {
            panic!("deepfold advice expected");
        };
        let mismatched_rs_advice = PcCommitmentAdvice::DeepFold {
            commitment: advice_commitment,
            base_tree,
            rs: wrong_rs,
        };
        let mut transcript = HashTranscript::new(b"deepfold-wrong-rs-advice");
        assert!(
            DeepFoldPc::open_with_advice(
                &values,
                &mismatched_rs_advice,
                &point,
                params,
                backend,
                &mut transcript,
            )
            .is_err()
        );
    }

    #[test]
    fn deepfold_batch_opening_accepts_valid_proof() {
        let (commitments, opening, point, backend, params) =
            sample_deepfold_batch_opening(b"deepfold-batch-open-test");
        assert!(matches!(opening.proof, BatchedOpeningProof::DeepFold(_)));
        let mut verifier_tr = HashTranscript::new(b"deepfold-batch-open-test");
        verify_distributed_openings(
            b"batch-test",
            &commitments,
            &opening,
            &point,
            params,
            backend,
            &mut verifier_tr,
        )
        .expect("verify");
    }

    #[test]
    fn deepfold_batch_opening_rejects_tampered_fold() {
        let (commitments, mut opening, point, backend, params) =
            sample_deepfold_batch_opening(b"deepfold-batch-tamper");
        let BatchedOpeningProof::DeepFold(proof) = &mut opening.proof else {
            panic!("deepfold proof expected");
        };
        proof.rs_proof.final_value += FieldElement::ONE;
        let mut verifier_tr = HashTranscript::new(b"deepfold-batch-tamper");
        assert!(
            verify_distributed_openings(
                b"batch-test",
                &commitments,
                &opening,
                &point,
                params,
                backend,
                &mut verifier_tr,
            )
            .is_err()
        );
    }

    #[test]
    fn deepfold_batch_opening_rejects_tampered_point() {
        let (commitments, opening, mut point, backend, params) =
            sample_deepfold_batch_opening(b"deepfold-point-tamper");
        point[0] += FieldElement::ONE;
        let mut verifier_tr = HashTranscript::new(b"deepfold-point-tamper");
        assert!(
            verify_distributed_openings(
                b"batch-test",
                &commitments,
                &opening,
                &point,
                params,
                backend,
                &mut verifier_tr,
            )
            .is_err()
        );
    }

    #[test]
    fn deepfold_batch_opening_rejects_tampered_commitment_root() {
        let (mut commitments, opening, point, backend, params) =
            sample_deepfold_batch_opening(b"deepfold-root-tamper");
        match &mut commitments[0] {
            PcCommitment::DeepFold(commitment) => commitment.base.root[0] ^= 1,
            PcCommitment::BaseFold(_) => panic!("deepfold commitment expected"),
        }
        let mut verifier_tr = HashTranscript::new(b"deepfold-root-tamper");
        assert!(
            verify_distributed_openings(
                b"batch-test",
                &commitments,
                &opening,
                &point,
                params,
                backend,
                &mut verifier_tr,
            )
            .is_err()
        );
    }

    #[test]
    fn deepfold_batch_opening_rejects_tampered_rs_commitment_root() {
        let (mut commitments, opening, point, backend, params) =
            sample_deepfold_batch_opening(b"deepfold-rs-root-tamper");
        match &mut commitments[0] {
            PcCommitment::DeepFold(commitment) => commitment.rs.codeword.root[0] ^= 1,
            PcCommitment::BaseFold(_) => panic!("deepfold commitment expected"),
        }
        let mut verifier_tr = HashTranscript::new(b"deepfold-rs-root-tamper");
        assert!(
            verify_distributed_openings(
                b"batch-test",
                &commitments,
                &opening,
                &point,
                params,
                backend,
                &mut verifier_tr,
            )
            .is_err()
        );
    }

    #[test]
    fn deepfold_batch_opening_rejects_tampered_backend_tag() {
        let (commitments, mut opening, point, backend, params) =
            sample_deepfold_batch_opening(b"deepfold-backend-tamper");
        opening.backend = PcsBackendConfig::basefold_default();
        let mut verifier_tr = HashTranscript::new(b"deepfold-backend-tamper");
        assert!(
            verify_distributed_openings(
                b"batch-test",
                &commitments,
                &opening,
                &point,
                params,
                backend,
                &mut verifier_tr,
            )
            .is_err()
        );
    }

    #[test]
    fn deepfold_batch_opening_rejects_tampered_merkle_path() {
        let (commitments, mut opening, point, backend, params) =
            sample_deepfold_batch_opening(b"deepfold-merkle-path-tamper");
        opening.consistency[0].worker_openings[0].path[0].0[0] ^= 1;
        let mut verifier_tr = HashTranscript::new(b"deepfold-merkle-path-tamper");
        assert!(
            verify_distributed_openings(
                b"batch-test",
                &commitments,
                &opening,
                &point,
                params,
                backend,
                &mut verifier_tr,
            )
            .is_err()
        );
    }

    #[test]
    fn deepfold_batch_opening_rejects_tampered_query_count_metadata() {
        let (commitments, mut opening, point, backend, params) =
            sample_deepfold_batch_opening(b"deepfold-query-count-tamper");
        let BatchedOpeningProof::DeepFold(proof) = &mut opening.proof else {
            panic!("deepfold proof expected");
        };
        proof.query_count = proof.query_count.saturating_sub(1);
        let mut verifier_tr = HashTranscript::new(b"deepfold-query-count-tamper");
        assert!(
            verify_distributed_openings(
                b"batch-test",
                &commitments,
                &opening,
                &point,
                params,
                backend,
                &mut verifier_tr,
            )
            .is_err()
        );
    }

    #[test]
    fn deepfold_batch_opening_rejects_batch_order_tamper() {
        let (commitments, mut opening, point, backend, params) =
            sample_deepfold_batch_opening(b"deepfold-batch-order-tamper");
        assert!(opening.consistency.len() > 1);
        opening.consistency.swap(0, 1);
        let mut verifier_tr = HashTranscript::new(b"deepfold-batch-order-tamper");
        assert!(
            verify_distributed_openings(
                b"batch-test",
                &commitments,
                &opening,
                &point,
                params,
                backend,
                &mut verifier_tr,
            )
            .is_err()
        );
    }

    #[test]
    fn encoded_backend_query_policy_uses_code_rate() {
        let values = sample_values(64);
        assert_eq!(
            effective_query_count_for_backend(
                DistributedPcsParams::new(1),
                values.len(),
                PcsBackendConfig::basefold_default(),
            )
            .expect("basefold queries"),
            64
        );
        assert_eq!(
            effective_query_count_for_backend(
                DistributedPcsParams::new(1),
                values.len(),
                PcsBackendConfig::deepfold_default(),
            )
            .expect("deepfold queries"),
            64
        );
    }

    #[test]
    fn protocol_11_verifies_and_rejects_tampering() {
        let values = sample_values(64);
        let commitment = DistributedBrakedown::commit(&values, 2).expect("commit");
        let domain_len = protocol11_evaluation_domain_len(&commitment);
        let point = (0..log2_power_of_two(domain_len).expect("vars"))
            .map(|idx| FieldElement::from((idx as u64 + 3) * 17))
            .collect::<Vec<_>>();
        let mut prover_tr = HashTranscript::new(b"protocol11-test");
        let proof = DistributedBrakedown::open(
            &values,
            &commitment,
            &point,
            DistributedPcsParams::new(2),
            &mut prover_tr,
        )
        .expect("open");
        let mut verifier_tr = HashTranscript::new(b"protocol11-test");
        DistributedBrakedown::verify(
            &commitment,
            &proof,
            DistributedPcsParams::new(2),
            &mut verifier_tr,
        )
        .expect("verify");

        let mut bad = proof.clone();
        bad.column_openings[0].columns[0].encoded_row_values[0] += FieldElement::ONE;
        let mut verifier_tr = HashTranscript::new(b"protocol11-test");
        assert!(
            DistributedBrakedown::verify(
                &commitment,
                &bad,
                DistributedPcsParams::new(2),
                &mut verifier_tr,
            )
            .is_err()
        );
    }

    #[test]
    fn protocol11_with_cached_advice_verifies_and_rejects_tampering() {
        let values = sample_values(128);
        let commitment = DistributedBrakedown::commit(&values, 4).expect("commit");
        let point = (0..log2_power_of_two(protocol11_evaluation_domain_len(&commitment))
            .expect("domain length is power of two"))
            .map(|idx| FieldElement::from((idx as u64 + 13) * 11))
            .collect::<Vec<_>>();
        let mut prover_tr = HashTranscript::new(b"protocol11-cached-advice");
        let proof = DistributedBrakedown::open(
            &values,
            &commitment,
            &point,
            DistributedPcsParams::new(2),
            &mut prover_tr,
        )
        .expect("open");
        let mut verifier_tr = HashTranscript::new(b"protocol11-cached-advice");
        DistributedBrakedown::verify(
            &commitment,
            &proof,
            DistributedPcsParams::new(2),
            &mut verifier_tr,
        )
        .expect("verify");

        let mut bad = proof.clone();
        let BatchedOpeningProof::BaseFold(proof) = &mut bad.encoding_batch.encodings[0]
            .opening_batch
            .combined_opening
            .proof
        else {
            panic!("basefold batch proof expected");
        };
        proof.value += FieldElement::ONE;
        let mut verifier_tr = HashTranscript::new(b"protocol11-cached-advice");
        assert!(
            DistributedBrakedown::verify(
                &commitment,
                &bad,
                DistributedPcsParams::new(2),
                &mut verifier_tr,
            )
            .is_err()
        );
    }

    #[test]
    fn protocol11_encoding_batch_rejects_tampered_relation_challenge() {
        let values = sample_values(128);
        let commitment = DistributedBrakedown::commit(&values, 2).expect("commit");
        let point = (0..log2_power_of_two(protocol11_evaluation_domain_len(&commitment))
            .expect("domain length is power of two"))
            .map(|idx| FieldElement::from((idx as u64 + 17) * 13))
            .collect::<Vec<_>>();
        let mut prover_tr = HashTranscript::new(b"protocol11-batch-rho");
        let proof = DistributedBrakedown::open(
            &values,
            &commitment,
            &point,
            DistributedPcsParams::new(2),
            &mut prover_tr,
        )
        .expect("open");

        let mut bad = proof.clone();
        bad.encoding_batch.relation_challenges[0] += FieldElement::ONE;
        let mut verifier_tr = HashTranscript::new(b"protocol11-batch-rho");
        assert!(
            DistributedBrakedown::verify(
                &commitment,
                &bad,
                DistributedPcsParams::new(2),
                &mut verifier_tr,
            )
            .is_err()
        );
    }

    #[test]
    fn protocol10_opening_batch_accepts_valid_basefold() {
        let backend = PcsBackendConfig {
            security_bits: 8,
            ..PcsBackendConfig::basefold_default()
        };
        let (commitment, proof, _, params) =
            sample_protocol11_proof_with_backend(b"p10-opening-batch-basefold", backend);
        assert_eq!(
            proof.encoding_batch.encodings[0].opening_batch.claims.len(),
            4
        );
        assert!(matches!(
            proof.encoding_batch.encodings[0]
                .opening_batch
                .combined_opening
                .proof,
            BatchedOpeningProof::BaseFold(_)
        ));
        verify_protocol11_sample(
            b"p10-opening-batch-basefold",
            &commitment,
            &proof,
            params,
            backend,
        )
        .expect("verify");
    }

    #[test]
    fn protocol10_opening_batch_accepts_valid_deepfold() {
        let backend = PcsBackendConfig {
            security_bits: 8,
            ..PcsBackendConfig::deepfold_default()
        };
        let (commitment, proof, _, params) =
            sample_protocol11_proof_with_backend(b"p10-opening-batch-deepfold", backend);
        assert_eq!(
            proof.encoding_batch.encodings[0].opening_batch.claims.len(),
            4
        );
        assert!(matches!(
            proof.encoding_batch.encodings[0]
                .opening_batch
                .combined_opening
                .proof,
            BatchedOpeningProof::DeepFold(_)
        ));
        verify_protocol11_sample(
            b"p10-opening-batch-deepfold",
            &commitment,
            &proof,
            params,
            backend,
        )
        .expect("verify");
    }

    #[test]
    fn protocol10_opening_batch_rejects_tampered_hu_at_r() {
        let backend = PcsBackendConfig {
            security_bits: 8,
            ..PcsBackendConfig::basefold_default()
        };
        let (commitment, mut proof, _, params) =
            sample_protocol11_proof_with_backend(b"p10-hu-claim-tamper", backend);
        proof.encoding_batch.encodings[0].opening_batch.claims[0].claimed_value +=
            FieldElement::ONE;
        assert!(
            verify_protocol11_sample(b"p10-hu-claim-tamper", &commitment, &proof, params, backend)
                .is_err()
        );
    }

    #[test]
    fn protocol10_opening_batch_rejects_tampered_e_at_r() {
        let backend = PcsBackendConfig {
            security_bits: 8,
            ..PcsBackendConfig::basefold_default()
        };
        let (commitment, mut proof, _, params) =
            sample_protocol11_proof_with_backend(b"p10-e-at-r-claim-tamper", backend);
        proof.encoding_batch.encodings[0].opening_batch.claims[1].claimed_value +=
            FieldElement::ONE;
        assert!(
            verify_protocol11_sample(
                b"p10-e-at-r-claim-tamper",
                &commitment,
                &proof,
                params,
                backend,
            )
            .is_err()
        );
    }

    #[test]
    fn protocol10_batch_rejects_tampered_f_at_u_prime() {
        let values = sample_values(128);
        let commitment = DistributedBrakedown::commit(&values, 2).expect("commit");
        let point = (0..log2_power_of_two(protocol11_evaluation_domain_len(&commitment))
            .expect("domain length is power of two"))
            .map(|idx| FieldElement::from((idx as u64 + 29) * 7))
            .collect::<Vec<_>>();
        let mut prover_tr = HashTranscript::new(b"protocol10-f-u-prime-tamper");
        let proof = DistributedBrakedown::open(
            &values,
            &commitment,
            &point,
            DistributedPcsParams::new(2),
            &mut prover_tr,
        )
        .expect("open");

        let mut bad = proof.clone();
        bad.encoding_batch.encodings[0].opening_batch.claims[2].claimed_value += FieldElement::ONE;
        let mut verifier_tr = HashTranscript::new(b"protocol10-f-u-prime-tamper");
        assert!(
            DistributedBrakedown::verify(
                &commitment,
                &bad,
                DistributedPcsParams::new(2),
                &mut verifier_tr,
            )
            .is_err()
        );
    }

    #[test]
    fn protocol10_opening_batch_rejects_tampered_f_pad_systematic_claim() {
        let backend = PcsBackendConfig {
            security_bits: 8,
            ..PcsBackendConfig::basefold_default()
        };
        let (commitment, mut proof, _, params) =
            sample_protocol11_proof_with_backend(b"p10-f-pad-claim-tamper", backend);
        proof.encoding_batch.encodings[0].opening_batch.claims[2].claimed_value +=
            FieldElement::ONE;
        assert!(
            verify_protocol11_sample(
                b"p10-f-pad-claim-tamper",
                &commitment,
                &proof,
                params,
                backend,
            )
            .is_err()
        );
    }

    #[test]
    fn protocol10_opening_batch_rejects_tampered_e_systematic_claim() {
        let backend = PcsBackendConfig {
            security_bits: 8,
            ..PcsBackendConfig::basefold_default()
        };
        let (commitment, mut proof, _, params) =
            sample_protocol11_proof_with_backend(b"p10-e-systematic-claim-tamper", backend);
        proof.encoding_batch.encodings[0].opening_batch.claims[3].claimed_value +=
            FieldElement::ONE;
        assert!(
            verify_protocol11_sample(
                b"p10-e-systematic-claim-tamper",
                &commitment,
                &proof,
                params,
                backend,
            )
            .is_err()
        );
    }

    #[test]
    fn protocol10_opening_batch_rejects_tampered_point() {
        let backend = PcsBackendConfig {
            security_bits: 8,
            ..PcsBackendConfig::basefold_default()
        };
        let (commitment, mut proof, _, params) =
            sample_protocol11_proof_with_backend(b"p10-point-tamper", backend);
        proof.encoding_batch.encodings[0].opening_batch.claims[1].point[0] += FieldElement::ONE;
        assert!(
            verify_protocol11_sample(b"p10-point-tamper", &commitment, &proof, params, backend)
                .is_err()
        );
    }

    #[test]
    fn protocol10_opening_batch_rejects_batch_order() {
        let backend = PcsBackendConfig {
            security_bits: 8,
            ..PcsBackendConfig::basefold_default()
        };
        let (commitment, mut proof, _, params) =
            sample_protocol11_proof_with_backend(b"p10-opening-batch-order", backend);
        proof.encoding_batch.encodings[0]
            .opening_batch
            .claims
            .swap(0, 1);
        assert!(
            verify_protocol11_sample(
                b"p10-opening-batch-order",
                &commitment,
                &proof,
                params,
                backend,
            )
            .is_err()
        );
    }

    #[test]
    fn protocol10_opening_batch_rejects_reduction_final_claim() {
        let backend = PcsBackendConfig {
            security_bits: 8,
            ..PcsBackendConfig::basefold_default()
        };
        let (commitment, mut proof, _, params) =
            sample_protocol11_proof_with_backend(b"p10-reduction-final-tamper", backend);
        proof.encoding_batch.encodings[0]
            .opening_batch
            .reduction
            .product_sumcheck
            .final_evaluation += FieldElement::ONE;
        assert!(
            verify_protocol11_sample(
                b"p10-reduction-final-tamper",
                &commitment,
                &proof,
                params,
                backend,
            )
            .is_err()
        );
    }

    #[test]
    fn protocol10_opening_batch_rejects_tampered_combined_opening_value() {
        let backend = PcsBackendConfig {
            security_bits: 8,
            ..PcsBackendConfig::basefold_default()
        };
        let (commitment, mut proof, _, params) =
            sample_protocol11_proof_with_backend(b"p10-combined-value-tamper", backend);
        proof.encoding_batch.encodings[0]
            .opening_batch
            .combined_opening
            .aggregate_value += FieldElement::ONE;
        assert!(
            verify_protocol11_sample(
                b"p10-combined-value-tamper",
                &commitment,
                &proof,
                params,
                backend,
            )
            .is_err()
        );
    }

    #[test]
    fn protocol10_opening_batch_rejects_tampered_sampled_source_leaf() {
        let backend = PcsBackendConfig {
            security_bits: 8,
            ..PcsBackendConfig::basefold_default()
        };
        let (commitment, mut proof, _, params) =
            sample_protocol11_proof_with_backend(b"p10-source-leaf-tamper", backend);
        proof.encoding_batch.encodings[0]
            .opening_batch
            .combined_opening
            .consistency[0]
            .source_openings[0]
            .value += FieldElement::ONE;
        assert!(
            verify_protocol11_sample(
                b"p10-source-leaf-tamper",
                &commitment,
                &proof,
                params,
                backend,
            )
            .is_err()
        );
    }

    #[test]
    fn protocol10_batch_rejects_tampered_systematic_claim() {
        let values = sample_values(128);
        let commitment = DistributedBrakedown::commit(&values, 2).expect("commit");
        let point = (0..log2_power_of_two(protocol11_evaluation_domain_len(&commitment))
            .expect("domain length is power of two"))
            .map(|idx| FieldElement::from((idx as u64 + 31) * 7))
            .collect::<Vec<_>>();
        let mut prover_tr = HashTranscript::new(b"protocol10-systematic-claim-tamper");
        let proof = DistributedBrakedown::open(
            &values,
            &commitment,
            &point,
            DistributedPcsParams::new(2),
            &mut prover_tr,
        )
        .expect("open");

        let mut bad = proof.clone();
        bad.encoding_batch.encodings[0].e_at_systematic += FieldElement::ONE;
        let mut verifier_tr = HashTranscript::new(b"protocol10-systematic-claim-tamper");
        assert!(
            DistributedBrakedown::verify(
                &commitment,
                &bad,
                DistributedPcsParams::new(2),
                &mut verifier_tr,
            )
            .is_err()
        );
    }

    #[test]
    fn protocol11_encoding_batch_rejects_tampered_sumcheck_final_claim() {
        let values = sample_values(128);
        let commitment = DistributedBrakedown::commit(&values, 2).expect("commit");
        let point = (0..log2_power_of_two(protocol11_evaluation_domain_len(&commitment))
            .expect("domain length is power of two"))
            .map(|idx| FieldElement::from((idx as u64 + 23) * 13))
            .collect::<Vec<_>>();
        let mut prover_tr = HashTranscript::new(b"protocol11-batch-final");
        let proof = DistributedBrakedown::open(
            &values,
            &commitment,
            &point,
            DistributedPcsParams::new(2),
            &mut prover_tr,
        )
        .expect("open");

        let mut bad = proof.clone();
        bad.encoding_batch.product_sumcheck.final_evaluation += FieldElement::ONE;
        let mut verifier_tr = HashTranscript::new(b"protocol11-batch-final");
        assert!(
            DistributedBrakedown::verify(
                &commitment,
                &bad,
                DistributedPcsParams::new(2),
                &mut verifier_tr,
            )
            .is_err()
        );
    }

    #[test]
    fn protocol11_batched_e1_e2_rejects_single_e1_relation_tamper() {
        let values = sample_values(128);
        let commitment = DistributedBrakedown::commit(&values, 2).expect("commit");
        let point = (0..log2_power_of_two(protocol11_evaluation_domain_len(&commitment))
            .expect("domain length is power of two"))
            .map(|idx| FieldElement::from((idx as u64 + 37) * 7))
            .collect::<Vec<_>>();
        let mut prover_tr = HashTranscript::new(b"protocol11-e1-relation-tamper");
        let proof = DistributedBrakedown::open(
            &values,
            &commitment,
            &point,
            DistributedPcsParams::new(2),
            &mut prover_tr,
        )
        .expect("open");

        let mut bad = proof.clone();
        bad.encoding_batch.encodings[0].e_at_r += FieldElement::ONE;
        let mut verifier_tr = HashTranscript::new(b"protocol11-e1-relation-tamper");
        assert!(
            DistributedBrakedown::verify(
                &commitment,
                &bad,
                DistributedPcsParams::new(2),
                &mut verifier_tr,
            )
            .is_err()
        );
    }

    #[test]
    fn protocol11_batched_e1_e2_rejects_single_e2_relation_tamper() {
        let values = sample_values(128);
        let commitment = DistributedBrakedown::commit(&values, 2).expect("commit");
        let point = (0..log2_power_of_two(protocol11_evaluation_domain_len(&commitment))
            .expect("domain length is power of two"))
            .map(|idx| FieldElement::from((idx as u64 + 41) * 7))
            .collect::<Vec<_>>();
        let mut prover_tr = HashTranscript::new(b"protocol11-e2-relation-tamper");
        let proof = DistributedBrakedown::open(
            &values,
            &commitment,
            &point,
            DistributedPcsParams::new(2),
            &mut prover_tr,
        )
        .expect("open");

        let mut bad = proof.clone();
        bad.encoding_batch.encodings[1].e_at_r += FieldElement::ONE;
        let mut verifier_tr = HashTranscript::new(b"protocol11-e2-relation-tamper");
        assert!(
            DistributedBrakedown::verify(
                &commitment,
                &bad,
                DistributedPcsParams::new(2),
                &mut verifier_tr,
            )
            .is_err()
        );
    }

    #[test]
    fn protocol11_deepfold_encoding_batch_rejects_tampered_hu_opening() {
        let values = sample_values(128);
        let backend = PcsBackendConfig::deepfold_default();
        let commitment =
            DistributedBrakedown::commit_with_config(&values, 2, backend).expect("commit");
        let point = (0..log2_power_of_two(protocol11_evaluation_domain_len(&commitment))
            .expect("domain length is power of two"))
            .map(|idx| FieldElement::from((idx as u64 + 23) * 17))
            .collect::<Vec<_>>();
        let params = DistributedPcsParams {
            query_count: 1,
            security_bits: 32,
        };
        let mut prover_tr = HashTranscript::new(b"protocol11-deepfold-hu");
        let proof =
            DistributedBrakedown::open(&values, &commitment, &point, params, &mut prover_tr)
                .expect("open");
        assert!(matches!(
            proof.encoding_batch.encodings[0]
                .opening_batch
                .combined_opening
                .proof,
            BatchedOpeningProof::DeepFold(_)
        ));

        let mut bad = proof.clone();
        let BatchedOpeningProof::DeepFold(hu_proof) = &mut bad.encoding_batch.encodings[0]
            .opening_batch
            .combined_opening
            .proof
        else {
            panic!("deepfold hu proof expected");
        };
        hu_proof.rs_proof.queries[0][0].beta_opening.value += FieldElement::ONE;
        let mut verifier_tr = HashTranscript::new(b"protocol11-deepfold-hu");
        assert!(
            DistributedBrakedown::verify_with_config(
                &commitment,
                &bad,
                params,
                backend,
                &mut verifier_tr,
            )
            .is_err()
        );
    }

    #[test]
    fn protocol11_encoding_batch_rejects_relation_order_tamper() {
        let values = sample_values(128);
        let commitment = DistributedBrakedown::commit(&values, 2).expect("commit");
        let point = (0..log2_power_of_two(protocol11_evaluation_domain_len(&commitment))
            .expect("domain length is power of two"))
            .map(|idx| FieldElement::from((idx as u64 + 19) * 11))
            .collect::<Vec<_>>();
        let mut prover_tr = HashTranscript::new(b"protocol11-batch-order");
        let proof = DistributedBrakedown::open(
            &values,
            &commitment,
            &point,
            DistributedPcsParams::new(2),
            &mut prover_tr,
        )
        .expect("open");

        let mut bad = proof.clone();
        bad.encoding_batch.encodings.swap(0, 1);
        let mut verifier_tr = HashTranscript::new(b"protocol11-batch-order");
        assert!(
            DistributedBrakedown::verify(
                &commitment,
                &bad,
                DistributedPcsParams::new(2),
                &mut verifier_tr,
            )
            .is_err()
        );
    }

    #[test]
    fn protocol_11_supports_non_power_of_two_workers_with_padding() {
        let values = sample_values(64);
        let commitment = DistributedBrakedown::commit(&values, 3).expect("commit");
        assert_eq!(commitment.workers.len(), 3);
        assert!(commitment.row_axis_len.is_power_of_two());
        let domain_len = protocol11_evaluation_domain_len(&commitment);
        let point = (0..log2_power_of_two(domain_len).expect("vars"))
            .map(|idx| FieldElement::from((idx as u64 + 7) * 13))
            .collect::<Vec<_>>();
        let mut prover_tr = HashTranscript::new(b"protocol11-padding-test");
        let proof = DistributedBrakedown::open(
            &values,
            &commitment,
            &point,
            DistributedPcsParams::new(2),
            &mut prover_tr,
        )
        .expect("open");
        let mut verifier_tr = HashTranscript::new(b"protocol11-padding-test");
        DistributedBrakedown::verify(
            &commitment,
            &proof,
            DistributedPcsParams::new(2),
            &mut verifier_tr,
        )
        .expect("verify");
    }

    #[test]
    fn proof_size_is_sublinear_in_witness_vectors() {
        let small = sample_values(64);
        let large = sample_values(256);
        let small_commitment = DistributedBrakedown::commit(&small, 2).expect("small commit");
        let large_commitment = DistributedBrakedown::commit(&large, 2).expect("large commit");
        let small_point =
            (0..log2_power_of_two(protocol11_evaluation_domain_len(&small_commitment))
                .expect("small domain length is power of two"))
                .map(|idx| FieldElement::from((idx as u64 + 3) * 17))
                .collect::<Vec<_>>();
        let large_point =
            (0..log2_power_of_two(protocol11_evaluation_domain_len(&large_commitment))
                .expect("large domain length is power of two"))
                .map(|idx| FieldElement::from((idx as u64 + 3) * 17))
                .collect::<Vec<_>>();
        let size_params = DistributedPcsParams {
            query_count: 1,
            security_bits: 1,
        };
        let mut small_tr = HashTranscript::new(b"size-test");
        let mut large_tr = HashTranscript::new(b"size-test");
        let small_proof = DistributedBrakedown::open(
            &small,
            &small_commitment,
            &small_point,
            size_params,
            &mut small_tr,
        )
        .expect("small open");
        let large_proof = DistributedBrakedown::open(
            &large,
            &large_commitment,
            &large_point,
            size_params,
            &mut large_tr,
        )
        .expect("large open");
        assert!(
            protocol11_proof_size_bytes(&large_proof)
                < protocol11_proof_size_bytes(&small_proof) * 4
        );
    }
}

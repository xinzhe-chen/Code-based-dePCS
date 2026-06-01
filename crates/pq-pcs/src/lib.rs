use std::thread;

use pq_core::{FieldElement, PartitionPlan, eq_basis, evaluate_mle, log2_power_of_two};
use pq_transcript::{Transcript, sha256};

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PcsError {
    Empty,
    InvalidLength,
    InvalidWorker,
    InvalidProof,
    InvalidEncoding,
    InvalidCommitment,
    InvalidEvaluation,
}

pub type PcsResult<T> = Result<T, PcsError>;

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct DistributedPcsParams {
    pub query_count: usize,
}

impl DistributedPcsParams {
    pub const DEFAULT_QUERY_COUNT: usize = 32;

    pub const fn new(query_count: usize) -> Self {
        Self { query_count }
    }

    pub fn effective_query_count(self, col_len: usize) -> PcsResult<usize> {
        if self.query_count == 0 || col_len == 0 {
            return Err(PcsError::InvalidLength);
        }
        Ok(self.query_count.min(col_len))
    }
}

impl Default for DistributedPcsParams {
    fn default() -> Self {
        Self::new(Self::DEFAULT_QUERY_COUNT)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Commitment {
    pub root: [u8; 32],
    pub len: usize,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct PcsSetup {
    pub max_len: usize,
}

impl PcsSetup {
    pub fn new(max_len: usize) -> PcsResult<Self> {
        if max_len == 0 || !max_len.is_power_of_two() {
            return Err(PcsError::InvalidLength);
        }
        Ok(Self { max_len })
    }

    pub fn validate_len(self, len: usize) -> PcsResult<()> {
        if len == 0 || !len.is_power_of_two() || len > self.max_len {
            return Err(PcsError::InvalidLength);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OpeningProof {
    pub index: usize,
    pub value: FieldElement,
    pub path: Vec<([u8; 32], bool)>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BatchOpeningProof {
    pub proofs: Vec<OpeningProof>,
}

pub trait PolynomialCommitment {
    fn setup(max_len: usize) -> PcsResult<PcsSetup> {
        PcsSetup::new(max_len)
    }
    fn commit(evaluations: &[FieldElement]) -> PcsResult<Commitment>;
    fn commit_with_setup(setup: &PcsSetup, evaluations: &[FieldElement]) -> PcsResult<Commitment> {
        setup.validate_len(evaluations.len())?;
        Self::commit(evaluations)
    }
    fn open(evaluations: &[FieldElement], index: usize) -> PcsResult<OpeningProof>;
    fn open_with_setup(
        setup: &PcsSetup,
        evaluations: &[FieldElement],
        index: usize,
    ) -> PcsResult<OpeningProof> {
        setup.validate_len(evaluations.len())?;
        Self::open(evaluations, index)
    }
    fn verify(commitment: &Commitment, proof: &OpeningProof) -> PcsResult<()>;
    fn batch_open(evaluations: &[FieldElement], indices: &[usize]) -> PcsResult<BatchOpeningProof> {
        if indices.is_empty() {
            return Err(PcsError::Empty);
        }
        let proofs = indices
            .iter()
            .map(|index| Self::open(evaluations, *index))
            .collect::<PcsResult<Vec<_>>>()?;
        Ok(BatchOpeningProof { proofs })
    }
    fn batch_open_with_setup(
        setup: &PcsSetup,
        evaluations: &[FieldElement],
        indices: &[usize],
    ) -> PcsResult<BatchOpeningProof> {
        setup.validate_len(evaluations.len())?;
        Self::batch_open(evaluations, indices)
    }
    fn batch_verify(commitment: &Commitment, proof: &BatchOpeningProof) -> PcsResult<()> {
        if proof.proofs.is_empty() {
            return Err(PcsError::Empty);
        }
        for opening in &proof.proofs {
            Self::verify(commitment, opening)?;
        }
        Ok(())
    }
}

pub struct MerklePcs;

impl PolynomialCommitment for MerklePcs {
    fn commit(evaluations: &[FieldElement]) -> PcsResult<Commitment> {
        Ok(Commitment {
            root: merkle_root(evaluations)?,
            len: evaluations.len(),
        })
    }

    fn open(evaluations: &[FieldElement], index: usize) -> PcsResult<OpeningProof> {
        merkle_open(evaluations, index)
    }

    fn verify(commitment: &Commitment, proof: &OpeningProof) -> PcsResult<()> {
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
            let mut input = Vec::with_capacity(65);
            input.push(1);
            if *sibling_is_right {
                input.extend_from_slice(&node);
                input.extend_from_slice(sibling);
            } else {
                input.extend_from_slice(sibling);
                input.extend_from_slice(&node);
            }
            node = sha256(&input);
            index /= 2;
        }
        if node == commitment.root && index == 0 {
            Ok(())
        } else {
            Err(PcsError::InvalidCommitment)
        }
    }
}

pub fn encode_systematic(message: &[FieldElement]) -> PcsResult<Vec<FieldElement>> {
    if message.is_empty() || !message.len().is_power_of_two() {
        return Err(PcsError::InvalidLength);
    }
    let len = message.len();
    let stride = if len > 1 { len / 2 } else { 0 };
    let mut out = Vec::with_capacity(len * 4);
    out.extend_from_slice(message);
    for idx in 0..len {
        out.push(message[idx] + message[(idx + 1) % len]);
    }
    for idx in 0..len {
        out.push(message[idx] + message[(idx + stride) % len]);
    }
    for idx in 0..len {
        let adjacent = message[idx] + message[(idx + 1) % len];
        let strided = message[idx] + message[(idx + stride) % len];
        out.push(adjacent + strided);
    }
    Ok(out)
}

pub fn verify_systematic_encoding(
    message: &[FieldElement],
    codeword: &[FieldElement],
) -> PcsResult<()> {
    if codeword.len() != message.len() * 4 {
        return Err(PcsError::InvalidEncoding);
    }
    let expected = encode_systematic(message)?;
    if expected == codeword {
        Ok(())
    } else {
        Err(PcsError::InvalidEncoding)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WorkerCommitment {
    pub worker_id: usize,
    pub range: (usize, usize),
    pub encoded_commitment: Commitment,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DistributedCommitment {
    pub workers: Vec<WorkerCommitment>,
    pub original_len: usize,
    pub root: [u8; 32],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WorkerOpening {
    pub worker_id: usize,
    pub range: (usize, usize),
    pub queries: Vec<QueryOpening>,
}

#[derive(Copy, Clone, Debug)]
pub struct WorkerOpeningRequest<'a> {
    pub worker: &'a WorkerCommitment,
    pub row: &'a [FieldElement],
    pub query_indices: &'a [usize],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QueryOpening {
    pub query_index: usize,
    pub systematic: OpeningProof,
    pub systematic_next: OpeningProof,
    pub systematic_stride: OpeningProof,
    pub adjacent_parity: OpeningProof,
    pub stride_parity: OpeningProof,
    pub blend_parity: OpeningProof,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DistributedOpening {
    pub point: Vec<FieldElement>,
    pub claimed_value: FieldElement,
    pub combined_column: Vec<FieldElement>,
    pub combined_codeword: Vec<FieldElement>,
    pub folding_proof: MleFoldingProof,
    pub composition_proof: MleFoldingProof,
    pub sampled_folding_proof: SampledMleFoldingProof,
    pub sampled_composition_proof: SampledMleFoldingProof,
    pub query_count: usize,
    pub query_indices: Vec<usize>,
    pub workers: Vec<WorkerOpening>,
    pub transcript_state: [u8; 32],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CompactDistributedOpening {
    pub point: Vec<FieldElement>,
    pub claimed_value: FieldElement,
    pub combined_commitment: Commitment,
    pub codeword_commitment: Commitment,
    pub sampled_folding_proof: SampledMleFoldingProof,
    pub sampled_composition_proof: SampledMleFoldingProof,
    pub query_count: usize,
    pub composition_query_indices: Vec<usize>,
    pub composition_queries: Vec<CompactQueryOpening>,
    pub query_indices: Vec<usize>,
    pub combined_queries: Vec<CompactQueryOpening>,
    pub workers: Vec<WorkerOpening>,
    pub transcript_state: [u8; 32],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CompactQueryOpening {
    pub query_index: usize,
    pub column: OpeningProof,
    pub column_next: OpeningProof,
    pub column_stride: OpeningProof,
    pub codeword_systematic: OpeningProof,
    pub codeword_next: OpeningProof,
    pub codeword_stride: OpeningProof,
    pub adjacent_parity: OpeningProof,
    pub stride_parity: OpeningProof,
    pub blend_parity: OpeningProof,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MleFoldingProof {
    pub input_commitment: Commitment,
    pub layers: Vec<FoldLayerProof>,
    pub final_value: FieldElement,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FoldLayerProof {
    pub challenge: FieldElement,
    pub values: Vec<FieldElement>,
    pub commitment: Commitment,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SampledMleFoldingProof {
    pub input_commitment: Commitment,
    pub input_len: usize,
    pub query_count: usize,
    pub rounds: Vec<SampledFoldRoundProof>,
    pub final_opening: OpeningProof,
    pub final_value: FieldElement,
    pub transcript_state: [u8; 32],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SampledFoldRoundProof {
    pub challenge: FieldElement,
    pub input_len: usize,
    pub folded_commitment: Commitment,
    pub checks: Vec<SampledFoldCheck>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SampledFoldCheck {
    pub folded_index: usize,
    pub left: OpeningProof,
    pub right: OpeningProof,
    pub folded: OpeningProof,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DistributedIndexOpening {
    pub global_index: usize,
    pub worker_id: usize,
    pub local_index: usize,
    pub proof: OpeningProof,
}

pub trait DistributedPcs {
    fn partition(evaluations: &[FieldElement], workers: usize) -> PcsResult<PartitionPlan>;
    fn worker_commit(
        worker_id: usize,
        start: usize,
        evaluations: &[FieldElement],
    ) -> PcsResult<WorkerCommitment>;
    fn worker_open(
        worker_id: usize,
        start: usize,
        evaluations: &[FieldElement],
        query_indices: &[usize],
    ) -> PcsResult<WorkerOpening>;
    fn master_commit<T: Transcript>(
        workers: Vec<WorkerCommitment>,
        original_len: usize,
        transcript: &mut T,
    ) -> PcsResult<DistributedCommitment>;
    fn commit<T: Transcript>(
        evaluations: &[FieldElement],
        workers: usize,
        transcript: &mut T,
    ) -> PcsResult<DistributedCommitment>;
    fn open_at<T: Transcript>(
        evaluations: &[FieldElement],
        commitment: &DistributedCommitment,
        point: &[FieldElement],
        transcript: &mut T,
    ) -> PcsResult<DistributedOpening>;
    fn verify<T: Transcript>(
        commitment: &DistributedCommitment,
        opening: &DistributedOpening,
        transcript: &mut T,
    ) -> PcsResult<()>;
}

pub struct DistributedBrakedown;

impl DistributedBrakedown {
    pub fn commit_detached(
        evaluations: &[FieldElement],
        workers: usize,
    ) -> PcsResult<DistributedCommitment> {
        let plan = Self::partition(evaluations, workers)?;
        let worker_commitments = parallel_worker_commitments(evaluations, &plan)?;
        Self::commit_from_worker_commitments(worker_commitments, evaluations.len())
    }

    pub fn commit_from_worker_commitments(
        workers: Vec<WorkerCommitment>,
        original_len: usize,
    ) -> PcsResult<DistributedCommitment> {
        let root = aggregate_worker_commitments(&workers);
        let commitment = DistributedCommitment {
            workers,
            original_len,
            root,
        };
        validate_distributed_commitment(&commitment)?;
        Ok(commitment)
    }

    pub fn absorb_distributed_commitment<T: Transcript>(
        commitment: &DistributedCommitment,
        transcript: &mut T,
    ) {
        transcript.absorb_domain(b"distributed-brakedown-v1");
        transcript.absorb_public(b"workers", &(commitment.workers.len() as u64).to_le_bytes());
        transcript.absorb_public(b"len", &(commitment.original_len as u64).to_le_bytes());
        for worker in &commitment.workers {
            absorb_worker_commitment(transcript, worker);
        }
        transcript.absorb_commitment(b"distributed-root", &commitment.root);
    }

    pub fn verify_opening<T: Transcript>(
        commitment: &DistributedCommitment,
        opening: &DistributedOpening,
        transcript: &mut T,
    ) -> PcsResult<()> {
        Self::verify_opening_with_params(
            commitment,
            opening,
            DistributedPcsParams::default(),
            transcript,
        )
    }

    pub fn open_at_with_params<T: Transcript>(
        evaluations: &[FieldElement],
        commitment: &DistributedCommitment,
        point: &[FieldElement],
        params: DistributedPcsParams,
        transcript: &mut T,
    ) -> PcsResult<DistributedOpening> {
        Self::absorb_distributed_commitment(commitment, transcript);
        open_at_after_commitment(evaluations, commitment, point, params, transcript)
    }

    pub fn open_at_after_commitment_with_params<T: Transcript>(
        evaluations: &[FieldElement],
        commitment: &DistributedCommitment,
        point: &[FieldElement],
        params: DistributedPcsParams,
        transcript: &mut T,
    ) -> PcsResult<DistributedOpening> {
        open_at_after_commitment(evaluations, commitment, point, params, transcript)
    }

    pub fn open_at_after_commitment_with_worker_provider<T: Transcript, F>(
        evaluations: &[FieldElement],
        commitment: &DistributedCommitment,
        point: &[FieldElement],
        params: DistributedPcsParams,
        transcript: &mut T,
        provider: F,
    ) -> PcsResult<DistributedOpening>
    where
        F: FnMut(&WorkerCommitment, &[FieldElement], &[usize]) -> PcsResult<WorkerOpening>,
    {
        open_at_after_commitment_with_provider(
            evaluations,
            commitment,
            point,
            params,
            transcript,
            provider,
        )
    }

    pub fn open_at_after_commitment_with_batch_worker_provider<T: Transcript, F>(
        evaluations: &[FieldElement],
        commitment: &DistributedCommitment,
        point: &[FieldElement],
        params: DistributedPcsParams,
        transcript: &mut T,
        provider: F,
    ) -> PcsResult<DistributedOpening>
    where
        F: FnMut(&[WorkerOpeningRequest<'_>]) -> PcsResult<Vec<WorkerOpening>>,
    {
        open_at_after_commitment_with_batch_provider(
            evaluations,
            commitment,
            point,
            params,
            transcript,
            provider,
        )
    }

    pub fn open_compact_at_with_params<T: Transcript>(
        evaluations: &[FieldElement],
        commitment: &DistributedCommitment,
        point: &[FieldElement],
        params: DistributedPcsParams,
        transcript: &mut T,
    ) -> PcsResult<CompactDistributedOpening> {
        Self::absorb_distributed_commitment(commitment, transcript);
        open_compact_after_commitment(evaluations, commitment, point, params, transcript)
    }

    pub fn open_compact_at_after_commitment_with_params<T: Transcript>(
        evaluations: &[FieldElement],
        commitment: &DistributedCommitment,
        point: &[FieldElement],
        params: DistributedPcsParams,
        transcript: &mut T,
    ) -> PcsResult<CompactDistributedOpening> {
        open_compact_after_commitment(evaluations, commitment, point, params, transcript)
    }

    pub fn open_compact_at_after_commitment_with_worker_provider<T: Transcript, F>(
        evaluations: &[FieldElement],
        commitment: &DistributedCommitment,
        point: &[FieldElement],
        params: DistributedPcsParams,
        transcript: &mut T,
        provider: F,
    ) -> PcsResult<CompactDistributedOpening>
    where
        F: FnMut(&WorkerCommitment, &[FieldElement], &[usize]) -> PcsResult<WorkerOpening>,
    {
        open_compact_after_commitment_with_provider(
            evaluations,
            commitment,
            point,
            params,
            transcript,
            provider,
        )
    }

    pub fn open_compact_at_after_commitment_with_batch_worker_provider<T: Transcript, F>(
        evaluations: &[FieldElement],
        commitment: &DistributedCommitment,
        point: &[FieldElement],
        params: DistributedPcsParams,
        transcript: &mut T,
        provider: F,
    ) -> PcsResult<CompactDistributedOpening>
    where
        F: FnMut(&[WorkerOpeningRequest<'_>]) -> PcsResult<Vec<WorkerOpening>>,
    {
        open_compact_after_commitment_with_batch_provider(
            evaluations,
            commitment,
            point,
            params,
            transcript,
            provider,
        )
    }

    pub fn verify_opening_with_params<T: Transcript>(
        commitment: &DistributedCommitment,
        opening: &DistributedOpening,
        params: DistributedPcsParams,
        transcript: &mut T,
    ) -> PcsResult<()> {
        Self::absorb_distributed_commitment(commitment, transcript);
        verify_opening_after_commitment(commitment, opening, params, transcript)
    }

    pub fn verify_opening_after_commitment_with_params<T: Transcript>(
        commitment: &DistributedCommitment,
        opening: &DistributedOpening,
        params: DistributedPcsParams,
        transcript: &mut T,
    ) -> PcsResult<()> {
        verify_opening_after_commitment(commitment, opening, params, transcript)
    }

    pub fn verify_compact_with_params<T: Transcript>(
        commitment: &DistributedCommitment,
        opening: &CompactDistributedOpening,
        params: DistributedPcsParams,
        transcript: &mut T,
    ) -> PcsResult<()> {
        Self::absorb_distributed_commitment(commitment, transcript);
        verify_compact_after_commitment(commitment, opening, params, transcript)
    }

    pub fn verify_compact_after_commitment_with_params<T: Transcript>(
        commitment: &DistributedCommitment,
        opening: &CompactDistributedOpening,
        params: DistributedPcsParams,
        transcript: &mut T,
    ) -> PcsResult<()> {
        verify_compact_after_commitment(commitment, opening, params, transcript)
    }

    pub fn verify_with_params<T: Transcript>(
        commitment: &DistributedCommitment,
        opening: &DistributedOpening,
        params: DistributedPcsParams,
        transcript: &mut T,
    ) -> PcsResult<()> {
        Self::absorb_distributed_commitment(commitment, transcript);
        verify_opening_after_commitment(commitment, opening, params, transcript)
    }

    pub fn open_index(
        evaluations: &[FieldElement],
        commitment: &DistributedCommitment,
        global_index: usize,
    ) -> PcsResult<DistributedIndexOpening> {
        if evaluations.len() != commitment.original_len || global_index >= commitment.original_len {
            return Err(PcsError::InvalidLength);
        }
        let worker = commitment
            .workers
            .iter()
            .find(|worker| worker.range.0 <= global_index && global_index < worker.range.1)
            .ok_or(PcsError::InvalidWorker)?;
        let local_index = global_index - worker.range.0;
        let row = evaluations[worker.range.0..worker.range.1].to_vec();
        let codeword = encode_systematic(&row)?;
        let root = merkle_root(&codeword)?;
        if root != worker.encoded_commitment.root {
            return Err(PcsError::InvalidCommitment);
        }
        Ok(DistributedIndexOpening {
            global_index,
            worker_id: worker.worker_id,
            local_index,
            proof: MerklePcs::open(&codeword, local_index)?,
        })
    }

    pub fn verify_index(
        commitment: &DistributedCommitment,
        opening: &DistributedIndexOpening,
    ) -> PcsResult<FieldElement> {
        validate_distributed_commitment(commitment)?;
        if opening.global_index >= commitment.original_len {
            return Err(PcsError::InvalidLength);
        }
        let worker = commitment
            .workers
            .iter()
            .find(|worker| worker.worker_id == opening.worker_id)
            .ok_or(PcsError::InvalidWorker)?;
        if !(worker.range.0 <= opening.global_index && opening.global_index < worker.range.1) {
            return Err(PcsError::InvalidWorker);
        }
        let expected_local = opening.global_index - worker.range.0;
        if opening.local_index != expected_local || opening.proof.index != expected_local {
            return Err(PcsError::InvalidProof);
        }
        MerklePcs::verify(&worker.encoded_commitment, &opening.proof)?;
        Ok(opening.proof.value)
    }
}

impl DistributedPcs for DistributedBrakedown {
    fn partition(evaluations: &[FieldElement], workers: usize) -> PcsResult<PartitionPlan> {
        if log2_power_of_two(evaluations.len()).is_err() {
            return Err(PcsError::InvalidLength);
        }
        if workers == 0
            || !workers.is_power_of_two()
            || !evaluations.len().is_multiple_of(workers)
            || !(evaluations.len() / workers).is_power_of_two()
        {
            return Err(PcsError::InvalidLength);
        }
        PartitionPlan::balanced(evaluations.len(), workers).map_err(|_| PcsError::InvalidLength)
    }

    fn worker_commit(
        worker_id: usize,
        start: usize,
        evaluations: &[FieldElement],
    ) -> PcsResult<WorkerCommitment> {
        if evaluations.is_empty() || !evaluations.len().is_power_of_two() {
            return Err(PcsError::InvalidLength);
        }
        let codeword = encode_systematic(evaluations)?;
        let encoded_commitment = MerklePcs::commit(&codeword)?;
        Ok(WorkerCommitment {
            worker_id,
            range: (start, start + evaluations.len()),
            encoded_commitment,
        })
    }

    fn worker_open(
        worker_id: usize,
        start: usize,
        evaluations: &[FieldElement],
        query_indices: &[usize],
    ) -> PcsResult<WorkerOpening> {
        if evaluations.is_empty() || !evaluations.len().is_power_of_two() {
            return Err(PcsError::InvalidLength);
        }
        let codeword = encode_systematic(evaluations)?;
        let col_len = evaluations.len();
        let stride_offset = if col_len > 1 { col_len / 2 } else { 0 };
        let layers = merkle_layers(&codeword)?;
        let mut queries = Vec::with_capacity(query_indices.len());
        for query_index in query_indices {
            if *query_index >= col_len {
                return Err(PcsError::InvalidLength);
            }
            let next = (query_index + 1) % col_len;
            let stride = (query_index + stride_offset) % col_len;
            queries.push(QueryOpening {
                query_index: *query_index,
                systematic: merkle_open_from_layers(&codeword, &layers, *query_index)?,
                systematic_next: merkle_open_from_layers(&codeword, &layers, next)?,
                systematic_stride: merkle_open_from_layers(&codeword, &layers, stride)?,
                adjacent_parity: merkle_open_from_layers(
                    &codeword,
                    &layers,
                    col_len + *query_index,
                )?,
                stride_parity: merkle_open_from_layers(
                    &codeword,
                    &layers,
                    2 * col_len + *query_index,
                )?,
                blend_parity: merkle_open_from_layers(
                    &codeword,
                    &layers,
                    3 * col_len + *query_index,
                )?,
            });
        }
        Ok(WorkerOpening {
            worker_id,
            range: (start, start + evaluations.len()),
            queries,
        })
    }

    fn master_commit<T: Transcript>(
        workers: Vec<WorkerCommitment>,
        original_len: usize,
        transcript: &mut T,
    ) -> PcsResult<DistributedCommitment> {
        let commitment = Self::commit_from_worker_commitments(workers, original_len)?;
        Self::absorb_distributed_commitment(&commitment, transcript);
        Ok(commitment)
    }

    fn commit<T: Transcript>(
        evaluations: &[FieldElement],
        workers: usize,
        transcript: &mut T,
    ) -> PcsResult<DistributedCommitment> {
        let plan = Self::partition(evaluations, workers)?;
        let worker_commitments = parallel_worker_commitments(evaluations, &plan)?;
        Self::master_commit(worker_commitments, evaluations.len(), transcript)
    }

    fn open_at<T: Transcript>(
        evaluations: &[FieldElement],
        commitment: &DistributedCommitment,
        point: &[FieldElement],
        transcript: &mut T,
    ) -> PcsResult<DistributedOpening> {
        open_at_after_commitment(
            evaluations,
            commitment,
            point,
            DistributedPcsParams::default(),
            transcript,
        )
    }

    fn verify<T: Transcript>(
        commitment: &DistributedCommitment,
        opening: &DistributedOpening,
        transcript: &mut T,
    ) -> PcsResult<()> {
        Self::absorb_distributed_commitment(commitment, transcript);
        verify_opening_after_commitment(
            commitment,
            opening,
            DistributedPcsParams::default(),
            transcript,
        )
    }
}

fn parallel_worker_commitments(
    evaluations: &[FieldElement],
    plan: &PartitionPlan,
) -> PcsResult<Vec<WorkerCommitment>> {
    thread::scope(|scope| {
        let handles = plan
            .partitions()
            .iter()
            .copied()
            .enumerate()
            .map(|(ordinal, partition)| {
                scope.spawn(move || {
                    DistributedBrakedown::worker_commit(
                        partition.id,
                        partition.start,
                        &evaluations[partition.start..partition.end],
                    )
                    .map(|commitment| (ordinal, commitment))
                })
            })
            .collect::<Vec<_>>();

        let mut commitments = vec![None; plan.len()];
        for handle in handles {
            let (ordinal, commitment) = handle.join().map_err(|_| PcsError::InvalidProof)??;
            if ordinal >= commitments.len() {
                return Err(PcsError::InvalidWorker);
            }
            commitments[ordinal] = Some(commitment);
        }
        commitments
            .into_iter()
            .map(|commitment| commitment.ok_or(PcsError::InvalidWorker))
            .collect()
    })
}

pub fn merkle_root(values: &[FieldElement]) -> PcsResult<[u8; 32]> {
    if values.is_empty() || !values.len().is_power_of_two() {
        return Err(PcsError::InvalidLength);
    }
    let mut level = values.iter().copied().map(leaf_hash).collect::<Vec<_>>();
    while level.len() > 1 {
        level = level
            .chunks_exact(2)
            .map(|pair| internal_hash(pair[0], pair[1]))
            .collect();
    }
    Ok(level[0])
}

pub fn merkle_open(values: &[FieldElement], index: usize) -> PcsResult<OpeningProof> {
    if values.is_empty() || !values.len().is_power_of_two() || index >= values.len() {
        return Err(PcsError::InvalidLength);
    }
    merkle_open_from_layers(values, &merkle_layers(values)?, index)
}

fn merkle_layers(values: &[FieldElement]) -> PcsResult<Vec<Vec<[u8; 32]>>> {
    if values.is_empty() || !values.len().is_power_of_two() {
        return Err(PcsError::InvalidLength);
    }
    let mut layers = Vec::new();
    let mut level = values.iter().copied().map(leaf_hash).collect::<Vec<_>>();
    layers.push(level.clone());
    while level.len() > 1 {
        level = level
            .chunks_exact(2)
            .map(|pair| internal_hash(pair[0], pair[1]))
            .collect();
        layers.push(level.clone());
    }
    Ok(layers)
}

fn merkle_open_from_layers(
    values: &[FieldElement],
    layers: &[Vec<[u8; 32]>],
    index: usize,
) -> PcsResult<OpeningProof> {
    if values.is_empty()
        || !values.len().is_power_of_two()
        || index >= values.len()
        || layers.is_empty()
        || layers[0].len() != values.len()
    {
        return Err(PcsError::InvalidLength);
    }
    let mut path = Vec::new();
    let mut idx = index;
    for level in layers.iter().take(layers.len().saturating_sub(1)) {
        let sibling_on_right = idx.is_multiple_of(2);
        let sibling_idx = if sibling_on_right { idx + 1 } else { idx - 1 };
        if sibling_idx >= level.len() {
            return Err(PcsError::InvalidProof);
        }
        path.push((level[sibling_idx], sibling_on_right));
        idx /= 2;
    }
    Ok(OpeningProof {
        index,
        value: values[index],
        path,
    })
}

pub fn proof_size_bytes(opening: &DistributedOpening) -> usize {
    field_vec_size(&opening.point)
        + 8
        + field_vec_size(&opening.combined_column)
        + field_vec_size(&opening.combined_codeword)
        + folding_proof_size_bytes(&opening.folding_proof)
        + folding_proof_size_bytes(&opening.composition_proof)
        + sampled_mle_folding_proof_size_bytes(&opening.sampled_folding_proof)
        + sampled_mle_folding_proof_size_bytes(&opening.sampled_composition_proof)
        + 8
        + usize_vec_size(&opening.query_indices)
        + 8
        + opening
            .workers
            .iter()
            .map(worker_opening_size_bytes)
            .sum::<usize>()
        + 32
}

pub fn compact_proof_size_bytes(opening: &CompactDistributedOpening) -> usize {
    field_vec_size(&opening.point)
        + 8
        + commitment_size_bytes(&opening.combined_commitment)
        + commitment_size_bytes(&opening.codeword_commitment)
        + sampled_mle_folding_proof_size_bytes(&opening.sampled_folding_proof)
        + sampled_mle_folding_proof_size_bytes(&opening.sampled_composition_proof)
        + 8
        + usize_vec_size(&opening.composition_query_indices)
        + 8
        + opening
            .composition_queries
            .iter()
            .map(compact_query_opening_size_bytes)
            .sum::<usize>()
        + 8
        + usize_vec_size(&opening.query_indices)
        + 8
        + opening
            .combined_queries
            .iter()
            .map(compact_query_opening_size_bytes)
            .sum::<usize>()
        + 8
        + opening
            .workers
            .iter()
            .map(worker_opening_size_bytes)
            .sum::<usize>()
        + 32
}

pub fn communication_bytes(opening: &DistributedOpening) -> usize {
    proof_size_bytes(opening) + opening.workers.len() * 32
}

pub fn compact_communication_bytes(opening: &CompactDistributedOpening) -> usize {
    compact_proof_size_bytes(opening) + opening.workers.len() * 32
}

pub fn commitment_size_bytes(_commitment: &Commitment) -> usize {
    32 + 8
}

pub fn opening_proof_size_bytes(proof: &OpeningProof) -> usize {
    8 + 8 + 8 + proof.path.len() * 33
}

pub fn distributed_commitment_size_bytes(commitment: &DistributedCommitment) -> usize {
    8 + commitment
        .workers
        .iter()
        .map(worker_commitment_size_bytes)
        .sum::<usize>()
        + 8
        + 32
}

pub fn distributed_index_opening_size_bytes(opening: &DistributedIndexOpening) -> usize {
    8 + 8 + 8 + opening_proof_size_bytes(&opening.proof)
}

pub fn distributed_index_communication_bytes(opening: &DistributedIndexOpening) -> usize {
    distributed_index_opening_size_bytes(opening)
}

fn worker_commitment_size_bytes(worker: &WorkerCommitment) -> usize {
    8 + 16 + commitment_size_bytes(&worker.encoded_commitment)
}

fn worker_opening_size_bytes(worker: &WorkerOpening) -> usize {
    8 + 16
        + 8
        + worker
            .queries
            .iter()
            .map(query_opening_size_bytes)
            .sum::<usize>()
}

fn query_opening_size_bytes(query: &QueryOpening) -> usize {
    8 + opening_proof_size_bytes(&query.systematic)
        + opening_proof_size_bytes(&query.systematic_next)
        + opening_proof_size_bytes(&query.systematic_stride)
        + opening_proof_size_bytes(&query.adjacent_parity)
        + opening_proof_size_bytes(&query.stride_parity)
        + opening_proof_size_bytes(&query.blend_parity)
}

fn compact_query_opening_size_bytes(query: &CompactQueryOpening) -> usize {
    8 + opening_proof_size_bytes(&query.column)
        + opening_proof_size_bytes(&query.column_next)
        + opening_proof_size_bytes(&query.column_stride)
        + opening_proof_size_bytes(&query.codeword_systematic)
        + opening_proof_size_bytes(&query.codeword_next)
        + opening_proof_size_bytes(&query.codeword_stride)
        + opening_proof_size_bytes(&query.adjacent_parity)
        + opening_proof_size_bytes(&query.stride_parity)
        + opening_proof_size_bytes(&query.blend_parity)
}

fn folding_proof_size_bytes(proof: &MleFoldingProof) -> usize {
    commitment_size_bytes(&proof.input_commitment)
        + vec_len_prefix()
        + proof
            .layers
            .iter()
            .map(fold_layer_proof_size_bytes)
            .sum::<usize>()
        + 8
}

fn fold_layer_proof_size_bytes(layer: &FoldLayerProof) -> usize {
    8 + field_vec_size(&layer.values) + commitment_size_bytes(&layer.commitment)
}

pub fn sampled_mle_folding_proof_size_bytes(proof: &SampledMleFoldingProof) -> usize {
    commitment_size_bytes(&proof.input_commitment)
        + 8
        + 8
        + vec_len_prefix()
        + proof
            .rounds
            .iter()
            .map(sampled_fold_round_proof_size_bytes)
            .sum::<usize>()
        + opening_proof_size_bytes(&proof.final_opening)
        + 8
        + 32
}

fn sampled_fold_round_proof_size_bytes(round: &SampledFoldRoundProof) -> usize {
    8 + 8
        + commitment_size_bytes(&round.folded_commitment)
        + vec_len_prefix()
        + round
            .checks
            .iter()
            .map(sampled_fold_check_size_bytes)
            .sum::<usize>()
}

fn sampled_fold_check_size_bytes(check: &SampledFoldCheck) -> usize {
    8 + opening_proof_size_bytes(&check.left)
        + opening_proof_size_bytes(&check.right)
        + opening_proof_size_bytes(&check.folded)
}

fn field_vec_size(values: &[FieldElement]) -> usize {
    8 + values.len() * 8
}

fn usize_vec_size(values: &[usize]) -> usize {
    8 + values.len() * 8
}

fn vec_len_prefix() -> usize {
    8
}

fn leaf_hash(value: FieldElement) -> [u8; 32] {
    let mut input = Vec::with_capacity(9);
    input.push(0);
    input.extend_from_slice(&value.to_le_bytes());
    sha256(&input)
}

fn internal_hash(left: [u8; 32], right: [u8; 32]) -> [u8; 32] {
    let mut input = Vec::with_capacity(65);
    input.push(1);
    input.extend_from_slice(&left);
    input.extend_from_slice(&right);
    sha256(&input)
}

fn aggregate_worker_commitments(workers: &[WorkerCommitment]) -> [u8; 32] {
    let mut input = Vec::new();
    input.extend_from_slice(b"distributed-root");
    for worker in workers {
        input.extend_from_slice(&(worker.worker_id as u64).to_le_bytes());
        input.extend_from_slice(&(worker.range.0 as u64).to_le_bytes());
        input.extend_from_slice(&(worker.range.1 as u64).to_le_bytes());
        input.extend_from_slice(&(worker.encoded_commitment.len as u64).to_le_bytes());
        input.extend_from_slice(&worker.encoded_commitment.root);
    }
    sha256(&input)
}

fn validate_distributed_commitment(commitment: &DistributedCommitment) -> PcsResult<()> {
    if commitment.original_len == 0 || !commitment.original_len.is_power_of_two() {
        return Err(PcsError::InvalidLength);
    }
    let workers = commitment.workers.len();
    if workers == 0
        || !workers.is_power_of_two()
        || !commitment.original_len.is_multiple_of(workers)
    {
        return Err(PcsError::InvalidLength);
    }
    let col_len = commitment.original_len / workers;
    if !col_len.is_power_of_two() {
        return Err(PcsError::InvalidLength);
    }
    let mut expected_start = 0;
    for (ordinal, worker) in commitment.workers.iter().enumerate() {
        if worker.worker_id != ordinal
            || worker.range.0 != expected_start
            || worker.range.1 > commitment.original_len
            || worker.range.0 >= worker.range.1
        {
            return Err(PcsError::InvalidWorker);
        }
        let range_len = worker.range.1 - worker.range.0;
        if range_len != col_len || worker.encoded_commitment.len != col_len * 4 {
            return Err(PcsError::InvalidProof);
        }
        expected_start = worker.range.1;
    }
    if expected_start != commitment.original_len {
        return Err(PcsError::InvalidProof);
    }
    if aggregate_worker_commitments(&commitment.workers) != commitment.root {
        return Err(PcsError::InvalidCommitment);
    }
    Ok(())
}

fn absorb_worker_commitment<T: Transcript>(transcript: &mut T, worker: &WorkerCommitment) {
    transcript.absorb_public(b"worker-id", &(worker.worker_id as u64).to_le_bytes());
    transcript.absorb_public(b"worker-start", &(worker.range.0 as u64).to_le_bytes());
    transcript.absorb_public(b"worker-end", &(worker.range.1 as u64).to_le_bytes());
    transcript.absorb_public(
        b"worker-codeword-len",
        &(worker.encoded_commitment.len as u64).to_le_bytes(),
    );
    transcript.absorb_commitment(b"worker-root", &worker.encoded_commitment.root);
}

fn open_at_after_commitment<T: Transcript>(
    evaluations: &[FieldElement],
    commitment: &DistributedCommitment,
    point: &[FieldElement],
    params: DistributedPcsParams,
    transcript: &mut T,
) -> PcsResult<DistributedOpening> {
    open_at_after_commitment_with_batch_provider(
        evaluations,
        commitment,
        point,
        params,
        transcript,
        parallel_local_worker_openings,
    )
}

pub fn prove_mle_folding(
    evaluations: &[FieldElement],
    point: &[FieldElement],
) -> PcsResult<MleFoldingProof> {
    if evaluations.is_empty() || !evaluations.len().is_power_of_two() {
        return Err(PcsError::InvalidLength);
    }
    let expected_vars =
        log2_power_of_two(evaluations.len()).map_err(|_| PcsError::InvalidLength)?;
    if point.len() != expected_vars {
        return Err(PcsError::InvalidEvaluation);
    }
    let input_commitment = MerklePcs::commit(evaluations)?;
    let mut current = evaluations.to_vec();
    let mut layers = Vec::with_capacity(point.len());
    for challenge in point {
        let next = fold_once(&current, *challenge)?;
        let commitment = MerklePcs::commit(&next)?;
        layers.push(FoldLayerProof {
            challenge: *challenge,
            values: next.clone(),
            commitment,
        });
        current = next;
    }
    Ok(MleFoldingProof {
        input_commitment,
        final_value: current[0],
        layers,
    })
}

pub fn verify_mle_folding(
    evaluations: &[FieldElement],
    point: &[FieldElement],
    proof: &MleFoldingProof,
) -> PcsResult<FieldElement> {
    if evaluations.is_empty() || !evaluations.len().is_power_of_two() {
        return Err(PcsError::InvalidLength);
    }
    let expected_vars =
        log2_power_of_two(evaluations.len()).map_err(|_| PcsError::InvalidLength)?;
    if point.len() != expected_vars || proof.layers.len() != expected_vars {
        return Err(PcsError::InvalidEvaluation);
    }
    if MerklePcs::commit(evaluations)? != proof.input_commitment {
        return Err(PcsError::InvalidCommitment);
    }
    let mut current = evaluations.to_vec();
    for (round, (challenge, layer)) in point.iter().copied().zip(&proof.layers).enumerate() {
        if layer.challenge != challenge {
            return Err(PcsError::InvalidProof);
        }
        let expected = fold_once(&current, challenge)?;
        if expected != layer.values {
            return Err(PcsError::InvalidProof);
        }
        if MerklePcs::commit(&layer.values)? != layer.commitment {
            return Err(PcsError::InvalidCommitment);
        }
        if layer.values.len() != current.len() / 2
            || layer.values.len() != 1 << (expected_vars - round - 1)
        {
            return Err(PcsError::InvalidLength);
        }
        current = layer.values.clone();
    }
    if current.len() != 1 || proof.final_value != current[0] {
        return Err(PcsError::InvalidEvaluation);
    }
    Ok(proof.final_value)
}

pub fn prove_sampled_mle_folding<T: Transcript>(
    evaluations: &[FieldElement],
    point: &[FieldElement],
    query_count: usize,
    transcript: &mut T,
) -> PcsResult<SampledMleFoldingProof> {
    validate_sampled_folding_input(evaluations.len(), point, query_count)?;
    let input_commitment = MerklePcs::commit(evaluations)?;
    transcript.absorb_domain(b"sampled-mle-folding-v1");
    absorb_commitment(transcript, b"sampled-fold-input", &input_commitment);
    transcript.absorb_public(
        b"sampled-fold-input-len",
        &(evaluations.len() as u64).to_le_bytes(),
    );
    transcript.absorb_public(
        b"sampled-fold-query-count",
        &(query_count as u64).to_le_bytes(),
    );
    absorb_point(transcript, b"sampled-fold-point", point);

    let mut current = evaluations.to_vec();
    let mut current_commitment = input_commitment.clone();
    let mut rounds = Vec::with_capacity(point.len());
    for (round_index, challenge) in point.iter().copied().enumerate() {
        let folded = fold_once(&current, challenge)?;
        let folded_commitment = MerklePcs::commit(&folded)?;
        let checks = prove_sampled_fold_round(
            transcript,
            round_index,
            challenge,
            query_count,
            SampledFoldRoundWitness {
                current: &current,
                current_commitment: &current_commitment,
                folded: &folded,
                folded_commitment: &folded_commitment,
            },
        )?;
        rounds.push(SampledFoldRoundProof {
            challenge,
            input_len: current.len(),
            folded_commitment: folded_commitment.clone(),
            checks,
        });
        current = folded;
        current_commitment = folded_commitment;
    }

    let final_opening = MerklePcs::open(&current, 0)?;
    absorb_opening_proof(transcript, b"sampled-fold-final", &final_opening);
    let final_value = final_opening.value;
    transcript.absorb_field(b"sampled-fold-final-value", final_value);
    Ok(SampledMleFoldingProof {
        input_commitment,
        input_len: evaluations.len(),
        query_count,
        rounds,
        final_opening,
        final_value,
        transcript_state: transcript.state(),
    })
}

pub fn verify_sampled_mle_folding<T: Transcript>(
    input_commitment: &Commitment,
    point: &[FieldElement],
    proof: &SampledMleFoldingProof,
    transcript: &mut T,
) -> PcsResult<FieldElement> {
    validate_sampled_folding_input(proof.input_len, point, proof.query_count)?;
    if &proof.input_commitment != input_commitment || proof.rounds.len() != point.len() {
        return Err(PcsError::InvalidProof);
    }
    transcript.absorb_domain(b"sampled-mle-folding-v1");
    absorb_commitment(transcript, b"sampled-fold-input", input_commitment);
    transcript.absorb_public(
        b"sampled-fold-input-len",
        &(proof.input_len as u64).to_le_bytes(),
    );
    transcript.absorb_public(
        b"sampled-fold-query-count",
        &(proof.query_count as u64).to_le_bytes(),
    );
    absorb_point(transcript, b"sampled-fold-point", point);

    let mut current_commitment = input_commitment.clone();
    let mut current_len = proof.input_len;
    for (round_index, (challenge, round)) in point.iter().copied().zip(&proof.rounds).enumerate() {
        verify_sampled_fold_round(
            transcript,
            round_index,
            challenge,
            current_len,
            &current_commitment,
            round,
            proof.query_count,
        )?;
        current_len /= 2;
        current_commitment = round.folded_commitment.clone();
    }
    if current_len != 1
        || proof.final_opening.index != 0
        || proof.final_opening.value != proof.final_value
    {
        return Err(PcsError::InvalidProof);
    }
    MerklePcs::verify(&current_commitment, &proof.final_opening)?;
    absorb_opening_proof(transcript, b"sampled-fold-final", &proof.final_opening);
    transcript.absorb_field(b"sampled-fold-final-value", proof.final_value);
    if proof.transcript_state != transcript.state() {
        return Err(PcsError::InvalidProof);
    }
    Ok(proof.final_value)
}

struct SampledFoldRoundWitness<'a> {
    current: &'a [FieldElement],
    current_commitment: &'a Commitment,
    folded: &'a [FieldElement],
    folded_commitment: &'a Commitment,
}

fn prove_sampled_fold_round<T: Transcript>(
    transcript: &mut T,
    round_index: usize,
    challenge: FieldElement,
    query_count: usize,
    witness: SampledFoldRoundWitness<'_>,
) -> PcsResult<Vec<SampledFoldCheck>> {
    absorb_sampled_round_header(
        transcript,
        round_index,
        challenge,
        witness.current.len(),
        witness.current_commitment,
        witness.folded_commitment,
    );
    let round_query_count = query_count.min(witness.folded.len());
    let indices = transcript.challenge_indices(
        b"sampled-fold-query",
        round_query_count,
        witness.folded.len(),
    );
    indices
        .into_iter()
        .map(|folded_index| {
            let check = SampledFoldCheck {
                folded_index,
                left: MerklePcs::open(witness.current, folded_index * 2)?,
                right: MerklePcs::open(witness.current, folded_index * 2 + 1)?,
                folded: MerklePcs::open(witness.folded, folded_index)?,
            };
            absorb_sampled_fold_check(transcript, &check);
            Ok(check)
        })
        .collect()
}

fn verify_sampled_fold_round<T: Transcript>(
    transcript: &mut T,
    round_index: usize,
    challenge: FieldElement,
    current_len: usize,
    current_commitment: &Commitment,
    round: &SampledFoldRoundProof,
    query_count: usize,
) -> PcsResult<()> {
    if current_len <= 1 || !current_len.is_power_of_two() || round.input_len != current_len {
        return Err(PcsError::InvalidLength);
    }
    let folded_len = current_len / 2;
    if round.challenge != challenge || round.folded_commitment.len != folded_len {
        return Err(PcsError::InvalidProof);
    }
    absorb_sampled_round_header(
        transcript,
        round_index,
        challenge,
        current_len,
        current_commitment,
        &round.folded_commitment,
    );
    let round_query_count = query_count.min(folded_len);
    let expected_indices =
        transcript.challenge_indices(b"sampled-fold-query", round_query_count, folded_len);
    if round.checks.len() != expected_indices.len() {
        return Err(PcsError::InvalidProof);
    }
    for (expected_index, check) in expected_indices.iter().copied().zip(&round.checks) {
        if check.folded_index != expected_index
            || check.left.index != expected_index * 2
            || check.right.index != expected_index * 2 + 1
            || check.folded.index != expected_index
        {
            return Err(PcsError::InvalidProof);
        }
        MerklePcs::verify(current_commitment, &check.left)?;
        MerklePcs::verify(current_commitment, &check.right)?;
        MerklePcs::verify(&round.folded_commitment, &check.folded)?;
        let expected_folded =
            check.left.value * (FieldElement::ONE - challenge) + check.right.value * challenge;
        if check.folded.value != expected_folded {
            return Err(PcsError::InvalidEvaluation);
        }
        absorb_sampled_fold_check(transcript, check);
    }
    Ok(())
}

fn validate_sampled_folding_input(
    input_len: usize,
    point: &[FieldElement],
    query_count: usize,
) -> PcsResult<()> {
    if input_len == 0 || !input_len.is_power_of_two() || query_count == 0 {
        return Err(PcsError::InvalidLength);
    }
    let expected_vars = log2_power_of_two(input_len).map_err(|_| PcsError::InvalidLength)?;
    if point.len() != expected_vars {
        return Err(PcsError::InvalidEvaluation);
    }
    Ok(())
}

fn fold_once(values: &[FieldElement], challenge: FieldElement) -> PcsResult<Vec<FieldElement>> {
    if values.is_empty() || !values.len().is_power_of_two() {
        return Err(PcsError::InvalidLength);
    }
    if values.len() == 1 {
        return Err(PcsError::InvalidEvaluation);
    }
    let one_minus = FieldElement::ONE - challenge;
    Ok(values
        .chunks_exact(2)
        .map(|pair| pair[0] * one_minus + pair[1] * challenge)
        .collect())
}

fn absorb_folding_proof<T: Transcript>(transcript: &mut T, proof: &MleFoldingProof) {
    transcript.absorb_domain(b"mle-folding-proof-v1");
    absorb_commitment(transcript, b"fold-input", &proof.input_commitment);
    transcript.absorb_public(b"fold-layers", &(proof.layers.len() as u64).to_le_bytes());
    for (round, layer) in proof.layers.iter().enumerate() {
        transcript.absorb_public(b"fold-round", &(round as u64).to_le_bytes());
        transcript.absorb_field(b"fold-challenge", layer.challenge);
        transcript.absorb_public(b"fold-len", &(layer.values.len() as u64).to_le_bytes());
        absorb_commitment(transcript, b"fold-layer", &layer.commitment);
    }
    transcript.absorb_field(b"fold-final", proof.final_value);
}

fn absorb_point<T: Transcript>(transcript: &mut T, label: &'static [u8], point: &[FieldElement]) {
    transcript.absorb_public(label, &(point.len() as u64).to_le_bytes());
    for (index, coordinate) in point.iter().copied().enumerate() {
        transcript.absorb_public(b"point-index", &(index as u64).to_le_bytes());
        transcript.absorb_field(label, coordinate);
    }
}

fn absorb_sampled_round_header<T: Transcript>(
    transcript: &mut T,
    round_index: usize,
    challenge: FieldElement,
    input_len: usize,
    current_commitment: &Commitment,
    folded_commitment: &Commitment,
) {
    transcript.absorb_domain(b"sampled-mle-folding-round-v1");
    transcript.absorb_public(b"sampled-fold-round", &(round_index as u64).to_le_bytes());
    transcript.absorb_public(
        b"sampled-fold-round-input-len",
        &(input_len as u64).to_le_bytes(),
    );
    transcript.absorb_field(b"sampled-fold-round-challenge", challenge);
    absorb_commitment(transcript, b"sampled-fold-round-input", current_commitment);
    absorb_commitment(transcript, b"sampled-fold-round-output", folded_commitment);
}

fn absorb_sampled_fold_check<T: Transcript>(transcript: &mut T, check: &SampledFoldCheck) {
    transcript.absorb_domain(b"sampled-mle-folding-check-v1");
    transcript.absorb_public(
        b"sampled-fold-check-index",
        &(check.folded_index as u64).to_le_bytes(),
    );
    absorb_opening_proof(transcript, b"sampled-fold-check-left", &check.left);
    absorb_opening_proof(transcript, b"sampled-fold-check-right", &check.right);
    absorb_opening_proof(transcript, b"sampled-fold-check-folded", &check.folded);
}

fn absorb_opening_proof<T: Transcript>(
    transcript: &mut T,
    label: &'static [u8],
    proof: &OpeningProof,
) {
    transcript.absorb_domain(b"merkle-opening-proof-v1");
    transcript.absorb_public(label, &(proof.index as u64).to_le_bytes());
    transcript.absorb_field(label, proof.value);
    transcript.absorb_public(label, &(proof.path.len() as u64).to_le_bytes());
    for (level, (sibling, sibling_is_right)) in proof.path.iter().enumerate() {
        transcript.absorb_public(b"opening-level", &(level as u64).to_le_bytes());
        transcript.absorb_public(b"opening-sibling-side", &[*sibling_is_right as u8]);
        transcript.absorb_commitment(label, sibling);
    }
}

fn absorb_query_opening<T: Transcript>(transcript: &mut T, query: &QueryOpening) {
    transcript.absorb_domain(b"distributed-brakedown-worker-query-opening-v1");
    transcript.absorb_public(
        b"worker-query-index",
        &(query.query_index as u64).to_le_bytes(),
    );
    absorb_opening_proof(transcript, b"worker-query-systematic", &query.systematic);
    absorb_opening_proof(
        transcript,
        b"worker-query-systematic-next",
        &query.systematic_next,
    );
    absorb_opening_proof(
        transcript,
        b"worker-query-systematic-stride",
        &query.systematic_stride,
    );
    absorb_opening_proof(
        transcript,
        b"worker-query-adjacent-parity",
        &query.adjacent_parity,
    );
    absorb_opening_proof(
        transcript,
        b"worker-query-stride-parity",
        &query.stride_parity,
    );
    absorb_opening_proof(
        transcript,
        b"worker-query-blend-parity",
        &query.blend_parity,
    );
}

fn absorb_worker_openings<T: Transcript>(transcript: &mut T, openings: &[WorkerOpening]) {
    transcript.absorb_domain(b"distributed-brakedown-worker-openings-v1");
    transcript.absorb_public(
        b"worker-opening-count",
        &(openings.len() as u64).to_le_bytes(),
    );
    for opening in openings {
        transcript.absorb_public(
            b"worker-opening-id",
            &(opening.worker_id as u64).to_le_bytes(),
        );
        transcript.absorb_public(
            b"worker-opening-start",
            &(opening.range.0 as u64).to_le_bytes(),
        );
        transcript.absorb_public(
            b"worker-opening-end",
            &(opening.range.1 as u64).to_le_bytes(),
        );
        transcript.absorb_public(
            b"worker-opening-query-count",
            &(opening.queries.len() as u64).to_le_bytes(),
        );
        for query in &opening.queries {
            absorb_query_opening(transcript, query);
        }
    }
}

fn absorb_compact_query_opening<T: Transcript>(transcript: &mut T, query: &CompactQueryOpening) {
    transcript.absorb_domain(b"distributed-brakedown-compact-query-opening-v1");
    transcript.absorb_public(
        b"compact-query-index",
        &(query.query_index as u64).to_le_bytes(),
    );
    absorb_opening_proof(transcript, b"compact-query-column", &query.column);
    absorb_opening_proof(transcript, b"compact-query-column-next", &query.column_next);
    absorb_opening_proof(
        transcript,
        b"compact-query-column-stride",
        &query.column_stride,
    );
    absorb_opening_proof(
        transcript,
        b"compact-query-codeword-systematic",
        &query.codeword_systematic,
    );
    absorb_opening_proof(
        transcript,
        b"compact-query-codeword-next",
        &query.codeword_next,
    );
    absorb_opening_proof(
        transcript,
        b"compact-query-codeword-stride",
        &query.codeword_stride,
    );
    absorb_opening_proof(
        transcript,
        b"compact-query-adjacent-parity",
        &query.adjacent_parity,
    );
    absorb_opening_proof(
        transcript,
        b"compact-query-stride-parity",
        &query.stride_parity,
    );
    absorb_opening_proof(
        transcript,
        b"compact-query-blend-parity",
        &query.blend_parity,
    );
}

fn absorb_compact_query_openings<T: Transcript>(
    transcript: &mut T,
    queries: &[CompactQueryOpening],
) {
    absorb_labeled_compact_query_openings(
        transcript,
        b"distributed-brakedown-compact-query-openings-v1",
        b"compact-query-opening-count",
        queries,
    );
}

fn absorb_compact_composition_query_openings<T: Transcript>(
    transcript: &mut T,
    queries: &[CompactQueryOpening],
) {
    absorb_labeled_compact_query_openings(
        transcript,
        b"distributed-brakedown-compact-composition-query-openings-v1",
        b"compact-composition-query-opening-count",
        queries,
    );
}

fn absorb_labeled_compact_query_openings<T: Transcript>(
    transcript: &mut T,
    domain: &'static [u8],
    count_label: &'static [u8],
    queries: &[CompactQueryOpening],
) {
    transcript.absorb_domain(domain);
    transcript.absorb_public(count_label, &(queries.len() as u64).to_le_bytes());
    for query in queries {
        absorb_compact_query_opening(transcript, query);
    }
}

fn absorb_commitment<T: Transcript>(
    transcript: &mut T,
    label: &'static [u8],
    commitment: &Commitment,
) {
    transcript.absorb_public(label, &(commitment.len as u64).to_le_bytes());
    transcript.absorb_commitment(label, &commitment.root);
}

fn absorb_labeled_field_vec<T: Transcript>(
    transcript: &mut T,
    label: &'static [u8],
    values: &[FieldElement],
) {
    transcript.absorb_public(label, &(values.len() as u64).to_le_bytes());
    for (index, value) in values.iter().copied().enumerate() {
        transcript.absorb_public(b"field-vec-index", &(index as u64).to_le_bytes());
        transcript.absorb_field(label, value);
    }
}

fn challenge_composition_point<T: Transcript>(
    codeword_len: usize,
    transcript: &mut T,
) -> PcsResult<Vec<FieldElement>> {
    let vars = log2_power_of_two(codeword_len).map_err(|_| PcsError::InvalidLength)?;
    transcript.absorb_domain(b"distributed-brakedown-composition-fold-v1");
    transcript.absorb_public(b"composition-len", &(codeword_len as u64).to_le_bytes());
    Ok((0..vars)
        .map(|index| {
            transcript.absorb_public(b"composition-var", &(index as u64).to_le_bytes());
            transcript.challenge_field::<FieldElement>(b"composition-point")
        })
        .collect())
}

fn open_at_after_commitment_with_provider<T: Transcript, F>(
    evaluations: &[FieldElement],
    commitment: &DistributedCommitment,
    point: &[FieldElement],
    params: DistributedPcsParams,
    transcript: &mut T,
    mut provider: F,
) -> PcsResult<DistributedOpening>
where
    F: FnMut(&WorkerCommitment, &[FieldElement], &[usize]) -> PcsResult<WorkerOpening>,
{
    open_at_after_commitment_with_batch_provider(
        evaluations,
        commitment,
        point,
        params,
        transcript,
        |requests| {
            requests
                .iter()
                .map(|request| provider(request.worker, request.row, request.query_indices))
                .collect()
        },
    )
}

fn open_at_after_commitment_with_batch_provider<T: Transcript, F>(
    evaluations: &[FieldElement],
    commitment: &DistributedCommitment,
    point: &[FieldElement],
    params: DistributedPcsParams,
    transcript: &mut T,
    mut provider: F,
) -> PcsResult<DistributedOpening>
where
    F: FnMut(&[WorkerOpeningRequest<'_>]) -> PcsResult<Vec<WorkerOpening>>,
{
    if evaluations.len() != commitment.original_len {
        return Err(PcsError::InvalidLength);
    }
    validate_distributed_commitment(commitment)?;
    let workers = commitment.workers.len();
    if workers == 0 || !workers.is_power_of_two() {
        return Err(PcsError::InvalidLength);
    }
    let col_len = commitment.original_len / workers;
    let col_vars = log2_power_of_two(col_len).map_err(|_| PcsError::InvalidLength)?;
    let row_vars = log2_power_of_two(workers).map_err(|_| PcsError::InvalidLength)?;
    if point.len() != col_vars + row_vars {
        return Err(PcsError::InvalidEvaluation);
    }
    let query_count = params.effective_query_count(col_len)?;
    let value = evaluate_mle(evaluations, point).map_err(|_| PcsError::InvalidEvaluation)?;
    let row_point = &point[col_vars..];
    let mut combined_column = vec![FieldElement::ZERO; col_len];
    for worker in &commitment.workers {
        let row_weight =
            eq_basis(row_point, worker.worker_id).map_err(|_| PcsError::InvalidEvaluation)?;
        let row = &evaluations[worker.range.0..worker.range.1];
        for (out, value) in combined_column.iter_mut().zip(row) {
            *out += row_weight * *value;
        }
    }
    transcript.absorb_domain(b"distributed-brakedown-open-v1");
    transcript.absorb_public(
        b"requested-query-count",
        &(params.query_count as u64).to_le_bytes(),
    );
    transcript.absorb_public(b"query-count", &(query_count as u64).to_le_bytes());
    for coordinate in point {
        transcript.absorb_field(b"point", *coordinate);
    }
    transcript.absorb_field(b"value", value);
    transcript.absorb_public(
        b"combined-len",
        &(combined_column.len() as u64).to_le_bytes(),
    );
    for value in &combined_column {
        transcript.absorb_field(b"combined", *value);
    }
    let combined_codeword = encode_systematic(&combined_column)?;
    absorb_labeled_field_vec(transcript, b"combined-codeword", &combined_codeword);
    let folding_proof = prove_mle_folding(&combined_column, &point[..col_vars])?;
    absorb_folding_proof(transcript, &folding_proof);
    if folding_proof.final_value != value {
        return Err(PcsError::InvalidEvaluation);
    }
    let sampled_folding_proof = prove_sampled_mle_folding(
        &combined_column,
        &point[..col_vars],
        query_count,
        transcript,
    )?;
    if sampled_folding_proof.input_commitment != folding_proof.input_commitment
        || sampled_folding_proof.final_value != value
    {
        return Err(PcsError::InvalidEvaluation);
    }
    let composition_point = challenge_composition_point(combined_codeword.len(), transcript)?;
    let composition_proof = prove_mle_folding(&combined_codeword, &composition_point)?;
    absorb_folding_proof(transcript, &composition_proof);
    let sampled_composition_proof = prove_sampled_mle_folding(
        &combined_codeword,
        &composition_point,
        query_count,
        transcript,
    )?;
    if sampled_composition_proof.input_commitment != composition_proof.input_commitment
        || sampled_composition_proof.final_value != composition_proof.final_value
    {
        return Err(PcsError::InvalidEvaluation);
    }
    let query_indices = transcript.challenge_indices(b"brakedown-query", query_count, col_len);
    let requests = worker_opening_requests(evaluations, commitment, &query_indices);
    let openings = provider(&requests)?;
    validate_worker_opening_order(&openings, &requests)?;
    absorb_worker_openings(transcript, &openings);
    Ok(DistributedOpening {
        point: point.to_vec(),
        claimed_value: value,
        combined_column,
        combined_codeword,
        folding_proof,
        composition_proof,
        sampled_folding_proof,
        sampled_composition_proof,
        query_count: params.query_count,
        query_indices,
        workers: openings,
        transcript_state: transcript.state(),
    })
}

fn open_compact_after_commitment<T: Transcript>(
    evaluations: &[FieldElement],
    commitment: &DistributedCommitment,
    point: &[FieldElement],
    params: DistributedPcsParams,
    transcript: &mut T,
) -> PcsResult<CompactDistributedOpening> {
    open_compact_after_commitment_with_batch_provider(
        evaluations,
        commitment,
        point,
        params,
        transcript,
        parallel_local_worker_openings,
    )
}

fn open_compact_after_commitment_with_provider<T: Transcript, F>(
    evaluations: &[FieldElement],
    commitment: &DistributedCommitment,
    point: &[FieldElement],
    params: DistributedPcsParams,
    transcript: &mut T,
    mut provider: F,
) -> PcsResult<CompactDistributedOpening>
where
    F: FnMut(&WorkerCommitment, &[FieldElement], &[usize]) -> PcsResult<WorkerOpening>,
{
    open_compact_after_commitment_with_batch_provider(
        evaluations,
        commitment,
        point,
        params,
        transcript,
        |requests| {
            requests
                .iter()
                .map(|request| provider(request.worker, request.row, request.query_indices))
                .collect()
        },
    )
}

fn open_compact_after_commitment_with_batch_provider<T: Transcript, F>(
    evaluations: &[FieldElement],
    commitment: &DistributedCommitment,
    point: &[FieldElement],
    params: DistributedPcsParams,
    transcript: &mut T,
    mut provider: F,
) -> PcsResult<CompactDistributedOpening>
where
    F: FnMut(&[WorkerOpeningRequest<'_>]) -> PcsResult<Vec<WorkerOpening>>,
{
    if evaluations.len() != commitment.original_len {
        return Err(PcsError::InvalidLength);
    }
    validate_distributed_commitment(commitment)?;
    let workers = commitment.workers.len();
    if workers == 0 || !workers.is_power_of_two() {
        return Err(PcsError::InvalidLength);
    }
    let col_len = commitment.original_len / workers;
    let col_vars = log2_power_of_two(col_len).map_err(|_| PcsError::InvalidLength)?;
    let row_vars = log2_power_of_two(workers).map_err(|_| PcsError::InvalidLength)?;
    if point.len() != col_vars + row_vars {
        return Err(PcsError::InvalidEvaluation);
    }
    let query_count = params.effective_query_count(col_len)?;
    let claimed_value =
        evaluate_mle(evaluations, point).map_err(|_| PcsError::InvalidEvaluation)?;
    let combined_column = build_combined_column(evaluations, commitment, &point[col_vars..])?;
    let combined_codeword = encode_systematic(&combined_column)?;
    let combined_commitment = MerklePcs::commit(&combined_column)?;
    let codeword_commitment = MerklePcs::commit(&combined_codeword)?;

    absorb_compact_opening_header(
        transcript,
        params,
        query_count,
        point,
        claimed_value,
        combined_column.len(),
        &combined_commitment,
        &codeword_commitment,
    );
    let sampled_folding_proof = prove_sampled_mle_folding(
        &combined_column,
        &point[..col_vars],
        query_count,
        transcript,
    )?;
    if sampled_folding_proof.input_commitment != combined_commitment
        || sampled_folding_proof.final_value != claimed_value
    {
        return Err(PcsError::InvalidEvaluation);
    }
    let composition_point = challenge_composition_point(combined_codeword.len(), transcript)?;
    let sampled_composition_proof = prove_sampled_mle_folding(
        &combined_codeword,
        &composition_point,
        query_count,
        transcript,
    )?;
    if sampled_composition_proof.input_commitment != codeword_commitment {
        return Err(PcsError::InvalidEvaluation);
    }
    let composition_query_indices =
        transcript.challenge_indices(b"compact-composition-query", query_count, col_len);
    let composition_queries = composition_query_indices
        .iter()
        .copied()
        .map(|query_index| compact_query_opening(&combined_column, &combined_codeword, query_index))
        .collect::<PcsResult<Vec<_>>>()?;
    absorb_compact_composition_query_openings(transcript, &composition_queries);
    let query_indices =
        transcript.challenge_indices(b"compact-brakedown-query", query_count, col_len);
    let combined_queries = query_indices
        .iter()
        .copied()
        .map(|query_index| compact_query_opening(&combined_column, &combined_codeword, query_index))
        .collect::<PcsResult<Vec<_>>>()?;
    let requests = worker_opening_requests(evaluations, commitment, &query_indices);
    let openings = provider(&requests)?;
    validate_worker_opening_order(&openings, &requests)?;
    absorb_compact_query_openings(transcript, &combined_queries);
    absorb_worker_openings(transcript, &openings);
    Ok(CompactDistributedOpening {
        point: point.to_vec(),
        claimed_value,
        combined_commitment,
        codeword_commitment,
        sampled_folding_proof,
        sampled_composition_proof,
        query_count: params.query_count,
        composition_query_indices,
        composition_queries,
        query_indices,
        combined_queries,
        workers: openings,
        transcript_state: transcript.state(),
    })
}

fn build_combined_column(
    evaluations: &[FieldElement],
    commitment: &DistributedCommitment,
    row_point: &[FieldElement],
) -> PcsResult<Vec<FieldElement>> {
    let col_len = commitment.original_len / commitment.workers.len();
    let mut combined_column = vec![FieldElement::ZERO; col_len];
    for worker in &commitment.workers {
        let row_weight =
            eq_basis(row_point, worker.worker_id).map_err(|_| PcsError::InvalidEvaluation)?;
        let row = &evaluations[worker.range.0..worker.range.1];
        for (out, value) in combined_column.iter_mut().zip(row) {
            *out += row_weight * *value;
        }
    }
    Ok(combined_column)
}

fn compact_query_opening(
    combined_column: &[FieldElement],
    combined_codeword: &[FieldElement],
    query_index: usize,
) -> PcsResult<CompactQueryOpening> {
    let col_len = combined_column.len();
    if query_index >= col_len || combined_codeword.len() != col_len * 4 {
        return Err(PcsError::InvalidLength);
    }
    let next = (query_index + 1) % col_len;
    let stride_offset = if col_len > 1 { col_len / 2 } else { 0 };
    let stride = (query_index + stride_offset) % col_len;
    Ok(CompactQueryOpening {
        query_index,
        column: MerklePcs::open(combined_column, query_index)?,
        column_next: MerklePcs::open(combined_column, next)?,
        column_stride: MerklePcs::open(combined_column, stride)?,
        codeword_systematic: MerklePcs::open(combined_codeword, query_index)?,
        codeword_next: MerklePcs::open(combined_codeword, next)?,
        codeword_stride: MerklePcs::open(combined_codeword, stride)?,
        adjacent_parity: MerklePcs::open(combined_codeword, col_len + query_index)?,
        stride_parity: MerklePcs::open(combined_codeword, 2 * col_len + query_index)?,
        blend_parity: MerklePcs::open(combined_codeword, 3 * col_len + query_index)?,
    })
}

fn worker_opening_requests<'a>(
    evaluations: &'a [FieldElement],
    commitment: &'a DistributedCommitment,
    query_indices: &'a [usize],
) -> Vec<WorkerOpeningRequest<'a>> {
    commitment
        .workers
        .iter()
        .map(|worker| WorkerOpeningRequest {
            worker,
            row: &evaluations[worker.range.0..worker.range.1],
            query_indices,
        })
        .collect()
}

fn validate_worker_opening_order(
    openings: &[WorkerOpening],
    requests: &[WorkerOpeningRequest<'_>],
) -> PcsResult<()> {
    if openings.len() != requests.len() {
        return Err(PcsError::InvalidWorker);
    }
    for (opening, request) in openings.iter().zip(requests) {
        if opening.worker_id != request.worker.worker_id || opening.range != request.worker.range {
            return Err(PcsError::InvalidWorker);
        }
        validate_worker_query_order(opening, request.query_indices)?;
    }
    Ok(())
}

fn validate_worker_query_order(opening: &WorkerOpening, query_indices: &[usize]) -> PcsResult<()> {
    if opening.queries.len() != query_indices.len() {
        return Err(PcsError::InvalidProof);
    }
    for (query, expected_index) in opening.queries.iter().zip(query_indices.iter().copied()) {
        if query.query_index != expected_index {
            return Err(PcsError::InvalidProof);
        }
    }
    Ok(())
}

fn parallel_local_worker_openings(
    requests: &[WorkerOpeningRequest<'_>],
) -> PcsResult<Vec<WorkerOpening>> {
    thread::scope(|scope| {
        let handles = requests
            .iter()
            .copied()
            .enumerate()
            .map(|(ordinal, request)| {
                scope.spawn(move || {
                    local_worker_opening(request.worker, request.row, request.query_indices)
                        .map(|opening| (ordinal, opening))
                })
            })
            .collect::<Vec<_>>();

        let mut openings = vec![None; requests.len()];
        for handle in handles {
            let (ordinal, opening) = handle.join().map_err(|_| PcsError::InvalidProof)??;
            if ordinal >= openings.len() {
                return Err(PcsError::InvalidWorker);
            }
            openings[ordinal] = Some(opening);
        }
        openings
            .into_iter()
            .map(|opening| opening.ok_or(PcsError::InvalidWorker))
            .collect()
    })
}

fn local_worker_opening(
    worker: &WorkerCommitment,
    row: &[FieldElement],
    query_indices: &[usize],
) -> PcsResult<WorkerOpening> {
    let codeword = encode_systematic(row)?;
    let root = merkle_root(&codeword)?;
    if root != worker.encoded_commitment.root {
        return Err(PcsError::InvalidCommitment);
    }
    DistributedBrakedown::worker_open(worker.worker_id, worker.range.0, row, query_indices)
}

#[allow(clippy::too_many_arguments)]
fn absorb_compact_opening_header<T: Transcript>(
    transcript: &mut T,
    params: DistributedPcsParams,
    effective_query_count: usize,
    point: &[FieldElement],
    claimed_value: FieldElement,
    combined_len: usize,
    combined_commitment: &Commitment,
    codeword_commitment: &Commitment,
) {
    transcript.absorb_domain(b"distributed-brakedown-compact-open-v1");
    transcript.absorb_public(
        b"requested-query-count",
        &(params.query_count as u64).to_le_bytes(),
    );
    transcript.absorb_public(
        b"query-count",
        &(effective_query_count as u64).to_le_bytes(),
    );
    for coordinate in point {
        transcript.absorb_field(b"point", *coordinate);
    }
    transcript.absorb_field(b"value", claimed_value);
    transcript.absorb_public(b"combined-len", &(combined_len as u64).to_le_bytes());
    absorb_commitment(transcript, b"compact-combined", combined_commitment);
    absorb_commitment(transcript, b"compact-codeword", codeword_commitment);
}

fn verify_compact_after_commitment<T: Transcript>(
    commitment: &DistributedCommitment,
    opening: &CompactDistributedOpening,
    params: DistributedPcsParams,
    transcript: &mut T,
) -> PcsResult<()> {
    validate_distributed_commitment(commitment)?;
    if opening.workers.len() != commitment.workers.len()
        || opening.composition_queries.len() != opening.composition_query_indices.len()
        || opening.combined_queries.len() != opening.query_indices.len()
    {
        return Err(PcsError::InvalidProof);
    }
    if commitment.original_len == 0 || !commitment.original_len.is_power_of_two() {
        return Err(PcsError::InvalidLength);
    }
    let workers = commitment.workers.len();
    if workers == 0
        || !workers.is_power_of_two()
        || !commitment.original_len.is_multiple_of(workers)
    {
        return Err(PcsError::InvalidLength);
    }
    let col_len = commitment.original_len / workers;
    let query_count = params.effective_query_count(col_len)?;
    let col_vars = log2_power_of_two(col_len).map_err(|_| PcsError::InvalidLength)?;
    let row_vars = log2_power_of_two(workers).map_err(|_| PcsError::InvalidLength)?;
    if opening.point.len() != col_vars + row_vars
        || opening.combined_commitment.len != col_len
        || opening.codeword_commitment.len != col_len * 4
    {
        return Err(PcsError::InvalidEvaluation);
    }
    if opening.query_count != params.query_count
        || opening.composition_query_indices.len() != query_count
        || opening.query_indices.len() != query_count
        || opening.sampled_folding_proof.query_count != query_count
        || opening.sampled_composition_proof.query_count != query_count
        || opening.sampled_folding_proof.input_commitment != opening.combined_commitment
        || opening.sampled_composition_proof.input_commitment != opening.codeword_commitment
    {
        return Err(PcsError::InvalidProof);
    }
    let col_point = &opening.point[..col_vars];
    let row_point = &opening.point[col_vars..];
    verify_worker_opening_shape(
        commitment,
        &opening.workers,
        col_len,
        &opening.query_indices,
    )?;

    absorb_compact_opening_header(
        transcript,
        params,
        query_count,
        &opening.point,
        opening.claimed_value,
        col_len,
        &opening.combined_commitment,
        &opening.codeword_commitment,
    );
    let sampled_value = verify_sampled_mle_folding(
        &opening.combined_commitment,
        col_point,
        &opening.sampled_folding_proof,
        transcript,
    )?;
    if sampled_value != opening.claimed_value {
        return Err(PcsError::InvalidEvaluation);
    }
    let composition_point =
        challenge_composition_point(opening.codeword_commitment.len, transcript)?;
    verify_sampled_mle_folding(
        &opening.codeword_commitment,
        &composition_point,
        &opening.sampled_composition_proof,
        transcript,
    )?;
    let expected_composition_queries =
        transcript.challenge_indices(b"compact-composition-query", query_count, col_len);
    if expected_composition_queries != opening.composition_query_indices {
        return Err(PcsError::InvalidProof);
    }
    absorb_compact_composition_query_openings(transcript, &opening.composition_queries);
    let expected_queries =
        transcript.challenge_indices(b"compact-brakedown-query", query_count, col_len);
    if expected_queries != opening.query_indices {
        return Err(PcsError::InvalidProof);
    }
    absorb_compact_query_openings(transcript, &opening.combined_queries);
    absorb_worker_openings(transcript, &opening.workers);
    if opening.transcript_state != transcript.state() {
        return Err(PcsError::InvalidProof);
    }
    for (query_index, compact_query) in opening
        .composition_query_indices
        .iter()
        .copied()
        .zip(&opening.composition_queries)
    {
        verify_compact_query_encoding(
            &opening.combined_commitment,
            &opening.codeword_commitment,
            col_len,
            query_index,
            compact_query,
        )?;
    }
    for (query_index, compact_query) in opening
        .query_indices
        .iter()
        .copied()
        .zip(&opening.combined_queries)
    {
        verify_compact_query(
            commitment,
            &opening.combined_commitment,
            &opening.codeword_commitment,
            &opening.workers,
            row_point,
            col_len,
            query_index,
            compact_query,
        )?;
    }
    let root = aggregate_worker_commitments(&commitment.workers);
    if root == commitment.root {
        Ok(())
    } else {
        Err(PcsError::InvalidCommitment)
    }
}

fn verify_worker_opening_shape(
    commitment: &DistributedCommitment,
    openings: &[WorkerOpening],
    col_len: usize,
    query_indices: &[usize],
) -> PcsResult<()> {
    let mut expected_start = 0;
    for (expected, actual) in commitment.workers.iter().zip(openings) {
        if expected.worker_id != actual.worker_id || expected.range != actual.range {
            return Err(PcsError::InvalidWorker);
        }
        if expected.range.0 != expected_start
            || expected.range.1 > commitment.original_len
            || expected.range.0 >= expected.range.1
        {
            return Err(PcsError::InvalidProof);
        }
        let range_len = expected.range.1 - expected.range.0;
        if range_len != col_len {
            return Err(PcsError::InvalidProof);
        }
        validate_worker_query_order(actual, query_indices)?;
        expected_start = expected.range.1;
    }
    if expected_start == commitment.original_len {
        Ok(())
    } else {
        Err(PcsError::InvalidProof)
    }
}

#[allow(clippy::too_many_arguments)]
fn verify_compact_query(
    commitment: &DistributedCommitment,
    combined_commitment: &Commitment,
    codeword_commitment: &Commitment,
    worker_openings: &[WorkerOpening],
    row_point: &[FieldElement],
    col_len: usize,
    query_index: usize,
    compact_query: &CompactQueryOpening,
) -> PcsResult<()> {
    verify_compact_query_encoding(
        combined_commitment,
        codeword_commitment,
        col_len,
        query_index,
        compact_query,
    )?;

    let mut combined_query = FieldElement::ZERO;
    let mut combined_next = FieldElement::ZERO;
    let mut combined_stride = FieldElement::ZERO;
    let mut combined_adjacent_parity = FieldElement::ZERO;
    let mut combined_stride_parity = FieldElement::ZERO;
    let mut combined_blend_parity = FieldElement::ZERO;
    for (worker_commitment, worker_opening) in commitment.workers.iter().zip(worker_openings) {
        let query = worker_opening
            .queries
            .iter()
            .find(|query| query.query_index == query_index)
            .ok_or(PcsError::InvalidProof)?;
        verify_worker_query_opening(worker_commitment, col_len, query_index, query)?;
        let row_weight = eq_basis(row_point, worker_commitment.worker_id)
            .map_err(|_| PcsError::InvalidEvaluation)?;
        combined_query += row_weight * query.systematic.value;
        combined_next += row_weight * query.systematic_next.value;
        combined_stride += row_weight * query.systematic_stride.value;
        combined_adjacent_parity += row_weight * query.adjacent_parity.value;
        combined_stride_parity += row_weight * query.stride_parity.value;
        combined_blend_parity += row_weight * query.blend_parity.value;
    }
    if combined_query != compact_query.column.value
        || combined_next != compact_query.column_next.value
        || combined_stride != compact_query.column_stride.value
        || combined_query != compact_query.codeword_systematic.value
        || combined_next != compact_query.codeword_next.value
        || combined_stride != compact_query.codeword_stride.value
        || combined_adjacent_parity != compact_query.adjacent_parity.value
        || combined_stride_parity != compact_query.stride_parity.value
        || combined_blend_parity != compact_query.blend_parity.value
    {
        return Err(PcsError::InvalidProof);
    }
    Ok(())
}

fn verify_compact_query_encoding(
    combined_commitment: &Commitment,
    codeword_commitment: &Commitment,
    col_len: usize,
    query_index: usize,
    compact_query: &CompactQueryOpening,
) -> PcsResult<()> {
    let next = (query_index + 1) % col_len;
    let stride_offset = if col_len > 1 { col_len / 2 } else { 0 };
    let stride = (query_index + stride_offset) % col_len;
    if compact_query.query_index != query_index
        || compact_query.column.index != query_index
        || compact_query.column_next.index != next
        || compact_query.column_stride.index != stride
        || compact_query.codeword_systematic.index != query_index
        || compact_query.codeword_next.index != next
        || compact_query.codeword_stride.index != stride
        || compact_query.adjacent_parity.index != col_len + query_index
        || compact_query.stride_parity.index != 2 * col_len + query_index
        || compact_query.blend_parity.index != 3 * col_len + query_index
    {
        return Err(PcsError::InvalidProof);
    }
    MerklePcs::verify(combined_commitment, &compact_query.column)?;
    MerklePcs::verify(combined_commitment, &compact_query.column_next)?;
    MerklePcs::verify(combined_commitment, &compact_query.column_stride)?;
    MerklePcs::verify(codeword_commitment, &compact_query.codeword_systematic)?;
    MerklePcs::verify(codeword_commitment, &compact_query.codeword_next)?;
    MerklePcs::verify(codeword_commitment, &compact_query.codeword_stride)?;
    MerklePcs::verify(codeword_commitment, &compact_query.adjacent_parity)?;
    MerklePcs::verify(codeword_commitment, &compact_query.stride_parity)?;
    MerklePcs::verify(codeword_commitment, &compact_query.blend_parity)?;
    if compact_query.column.value != compact_query.codeword_systematic.value
        || compact_query.column_next.value != compact_query.codeword_next.value
        || compact_query.column_stride.value != compact_query.codeword_stride.value
        || compact_query.adjacent_parity.value
            != compact_query.codeword_systematic.value + compact_query.codeword_next.value
        || compact_query.stride_parity.value
            != compact_query.codeword_systematic.value + compact_query.codeword_stride.value
        || compact_query.blend_parity.value
            != compact_query.adjacent_parity.value + compact_query.stride_parity.value
    {
        return Err(PcsError::InvalidEncoding);
    }
    Ok(())
}

fn verify_worker_query_opening(
    worker_commitment: &WorkerCommitment,
    col_len: usize,
    query_index: usize,
    query: &QueryOpening,
) -> PcsResult<()> {
    let next = (query_index + 1) % col_len;
    let stride_offset = if col_len > 1 { col_len / 2 } else { 0 };
    let stride = (query_index + stride_offset) % col_len;
    if query.systematic.index != query_index
        || query.systematic_next.index != next
        || query.systematic_stride.index != stride
        || query.adjacent_parity.index != col_len + query_index
        || query.stride_parity.index != 2 * col_len + query_index
        || query.blend_parity.index != 3 * col_len + query_index
    {
        return Err(PcsError::InvalidProof);
    }
    MerklePcs::verify(&worker_commitment.encoded_commitment, &query.systematic)?;
    MerklePcs::verify(
        &worker_commitment.encoded_commitment,
        &query.systematic_next,
    )?;
    MerklePcs::verify(
        &worker_commitment.encoded_commitment,
        &query.systematic_stride,
    )?;
    MerklePcs::verify(
        &worker_commitment.encoded_commitment,
        &query.adjacent_parity,
    )?;
    MerklePcs::verify(&worker_commitment.encoded_commitment, &query.stride_parity)?;
    MerklePcs::verify(&worker_commitment.encoded_commitment, &query.blend_parity)?;
    if query.adjacent_parity.value != query.systematic.value + query.systematic_next.value
        || query.stride_parity.value != query.systematic.value + query.systematic_stride.value
        || query.blend_parity.value != query.adjacent_parity.value + query.stride_parity.value
    {
        return Err(PcsError::InvalidEncoding);
    }
    Ok(())
}

fn verify_opening_after_commitment<T: Transcript>(
    commitment: &DistributedCommitment,
    opening: &DistributedOpening,
    params: DistributedPcsParams,
    transcript: &mut T,
) -> PcsResult<()> {
    validate_distributed_commitment(commitment)?;
    if opening.workers.len() != commitment.workers.len() {
        return Err(PcsError::InvalidProof);
    }
    if commitment.original_len == 0 || !commitment.original_len.is_power_of_two() {
        return Err(PcsError::InvalidLength);
    }
    let workers = commitment.workers.len();
    if workers == 0
        || !workers.is_power_of_two()
        || !commitment.original_len.is_multiple_of(workers)
    {
        return Err(PcsError::InvalidLength);
    }
    let col_len = commitment.original_len / workers;
    let query_count = params.effective_query_count(col_len)?;
    let col_vars = log2_power_of_two(col_len).map_err(|_| PcsError::InvalidLength)?;
    let row_vars = log2_power_of_two(workers).map_err(|_| PcsError::InvalidLength)?;
    if opening.point.len() != col_vars + row_vars || opening.combined_column.len() != col_len {
        return Err(PcsError::InvalidEvaluation);
    }
    if opening.combined_codeword.len() != col_len * 4 {
        return Err(PcsError::InvalidEncoding);
    }
    verify_systematic_encoding(&opening.combined_column, &opening.combined_codeword)?;
    if opening.query_count != params.query_count || opening.query_indices.len() != query_count {
        return Err(PcsError::InvalidProof);
    }
    if opening.sampled_folding_proof.query_count != query_count
        || opening.sampled_composition_proof.query_count != query_count
    {
        return Err(PcsError::InvalidProof);
    }
    let col_point = &opening.point[..col_vars];
    let row_point = &opening.point[col_vars..];
    let mut expected_start = 0;
    for (expected, actual) in commitment.workers.iter().zip(&opening.workers) {
        if expected.worker_id != actual.worker_id || expected.range != actual.range {
            return Err(PcsError::InvalidWorker);
        }
        if expected.range.0 != expected_start
            || expected.range.1 > commitment.original_len
            || expected.range.0 >= expected.range.1
        {
            return Err(PcsError::InvalidProof);
        }
        let range_len = expected.range.1 - expected.range.0;
        if range_len != col_len || actual.queries.len() != opening.query_indices.len() {
            return Err(PcsError::InvalidProof);
        }
        validate_worker_query_order(actual, &opening.query_indices)?;
        expected_start = expected.range.1;
    }
    if expected_start != commitment.original_len {
        return Err(PcsError::InvalidProof);
    }
    transcript.absorb_domain(b"distributed-brakedown-open-v1");
    transcript.absorb_public(
        b"requested-query-count",
        &(params.query_count as u64).to_le_bytes(),
    );
    transcript.absorb_public(b"query-count", &(query_count as u64).to_le_bytes());
    for coordinate in &opening.point {
        transcript.absorb_field(b"point", *coordinate);
    }
    transcript.absorb_field(b"value", opening.claimed_value);
    transcript.absorb_public(
        b"combined-len",
        &(opening.combined_column.len() as u64).to_le_bytes(),
    );
    for value in &opening.combined_column {
        transcript.absorb_field(b"combined", *value);
    }
    absorb_labeled_field_vec(transcript, b"combined-codeword", &opening.combined_codeword);
    absorb_folding_proof(transcript, &opening.folding_proof);
    let sampled_value = verify_sampled_mle_folding(
        &opening.folding_proof.input_commitment,
        col_point,
        &opening.sampled_folding_proof,
        transcript,
    )?;
    if sampled_value != opening.claimed_value {
        return Err(PcsError::InvalidEvaluation);
    }
    let composition_point =
        challenge_composition_point(opening.combined_codeword.len(), transcript)?;
    absorb_folding_proof(transcript, &opening.composition_proof);
    let sampled_composition_value = verify_sampled_mle_folding(
        &opening.composition_proof.input_commitment,
        &composition_point,
        &opening.sampled_composition_proof,
        transcript,
    )?;
    if sampled_composition_value != opening.composition_proof.final_value {
        return Err(PcsError::InvalidEvaluation);
    }
    let expected_queries = transcript.challenge_indices(b"brakedown-query", query_count, col_len);
    if expected_queries != opening.query_indices {
        return Err(PcsError::InvalidProof);
    }
    absorb_worker_openings(transcript, &opening.workers);
    if opening.transcript_state != transcript.state() {
        return Err(PcsError::InvalidProof);
    }
    verify_mle_folding(&opening.combined_column, col_point, &opening.folding_proof)?;
    if opening.folding_proof.final_value != opening.claimed_value {
        return Err(PcsError::InvalidEvaluation);
    }
    verify_mle_folding(
        &opening.combined_codeword,
        &composition_point,
        &opening.composition_proof,
    )?;
    for query_index in &opening.query_indices {
        let next = (query_index + 1) % col_len;
        let stride_offset = if col_len > 1 { col_len / 2 } else { 0 };
        let stride = (query_index + stride_offset) % col_len;
        let mut combined_query = FieldElement::ZERO;
        let mut combined_next = FieldElement::ZERO;
        let mut combined_stride = FieldElement::ZERO;
        let mut combined_adjacent_parity = FieldElement::ZERO;
        let mut combined_stride_parity = FieldElement::ZERO;
        let mut combined_blend_parity = FieldElement::ZERO;
        for (worker_commitment, worker_opening) in commitment.workers.iter().zip(&opening.workers) {
            let query = worker_opening
                .queries
                .iter()
                .find(|query| query.query_index == *query_index)
                .ok_or(PcsError::InvalidProof)?;
            if query.systematic.index != *query_index
                || query.systematic_next.index != next
                || query.systematic_stride.index != stride
                || query.adjacent_parity.index != col_len + *query_index
                || query.stride_parity.index != 2 * col_len + *query_index
                || query.blend_parity.index != 3 * col_len + *query_index
            {
                return Err(PcsError::InvalidProof);
            }
            MerklePcs::verify(&worker_commitment.encoded_commitment, &query.systematic)?;
            MerklePcs::verify(
                &worker_commitment.encoded_commitment,
                &query.systematic_next,
            )?;
            MerklePcs::verify(
                &worker_commitment.encoded_commitment,
                &query.systematic_stride,
            )?;
            MerklePcs::verify(
                &worker_commitment.encoded_commitment,
                &query.adjacent_parity,
            )?;
            MerklePcs::verify(&worker_commitment.encoded_commitment, &query.stride_parity)?;
            MerklePcs::verify(&worker_commitment.encoded_commitment, &query.blend_parity)?;
            if query.adjacent_parity.value != query.systematic.value + query.systematic_next.value {
                return Err(PcsError::InvalidEncoding);
            }
            if query.stride_parity.value != query.systematic.value + query.systematic_stride.value {
                return Err(PcsError::InvalidEncoding);
            }
            if query.blend_parity.value != query.adjacent_parity.value + query.stride_parity.value {
                return Err(PcsError::InvalidEncoding);
            }
            let row_weight = eq_basis(row_point, worker_commitment.worker_id)
                .map_err(|_| PcsError::InvalidEvaluation)?;
            combined_query += row_weight * query.systematic.value;
            combined_next += row_weight * query.systematic_next.value;
            combined_stride += row_weight * query.systematic_stride.value;
            combined_adjacent_parity += row_weight * query.adjacent_parity.value;
            combined_stride_parity += row_weight * query.stride_parity.value;
            combined_blend_parity += row_weight * query.blend_parity.value;
        }
        if combined_query != opening.combined_column[*query_index]
            || combined_next != opening.combined_column[next]
            || combined_stride != opening.combined_column[stride]
            || combined_query != opening.combined_codeword[*query_index]
            || combined_next != opening.combined_codeword[next]
            || combined_stride != opening.combined_codeword[stride]
            || combined_adjacent_parity != opening.combined_codeword[col_len + *query_index]
            || combined_stride_parity != opening.combined_codeword[2 * col_len + *query_index]
            || combined_blend_parity != opening.combined_codeword[3 * col_len + *query_index]
        {
            return Err(PcsError::InvalidProof);
        }
    }
    let root = aggregate_worker_commitments(&commitment.workers);
    if root == commitment.root {
        Ok(())
    } else {
        Err(PcsError::InvalidCommitment)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pq_transcript::HashTranscript;

    #[test]
    fn merkle_opening_detects_tampering() {
        let values = vec![1_u64.into(), 2_u64.into(), 3_u64.into(), 4_u64.into()];
        let commitment = MerklePcs::commit(&values).expect("commit");
        let proof = MerklePcs::open(&values, 2).expect("open");
        assert!(MerklePcs::verify(&commitment, &proof).is_ok());
        assert_eq!(commitment_size_bytes(&commitment), 40);
        assert_eq!(opening_proof_size_bytes(&proof), 8 + 8 + 8 + 2 * 33);
        let mut wrong_index = proof.clone();
        wrong_index.index = 3;
        assert!(MerklePcs::verify(&commitment, &wrong_index).is_err());
        let mut bad = proof;
        bad.value = 9_u64.into();
        assert!(MerklePcs::verify(&commitment, &bad).is_err());
    }

    #[test]
    fn merkle_setup_and_batch_opening_api_verify_and_reject_tampering() {
        let setup = MerklePcs::setup(8).expect("setup");
        let values = (1_u64..=8).map(FieldElement::from).collect::<Vec<_>>();
        let commitment = MerklePcs::commit_with_setup(&setup, &values).expect("commit");
        let single = MerklePcs::open_with_setup(&setup, &values, 5).expect("single open");
        assert_eq!(single.value, 6_u64.into());
        assert!(MerklePcs::verify(&commitment, &single).is_ok());

        let batch =
            MerklePcs::batch_open_with_setup(&setup, &values, &[0, 3, 5]).expect("batch open");
        assert_eq!(
            batch
                .proofs
                .iter()
                .map(|proof| proof.index)
                .collect::<Vec<_>>(),
            vec![0, 3, 5]
        );
        assert!(MerklePcs::batch_verify(&commitment, &batch).is_ok());

        let mut tampered = batch.clone();
        tampered.proofs[1].value += FieldElement::ONE;
        assert!(MerklePcs::batch_verify(&commitment, &tampered).is_err());
        assert_eq!(MerklePcs::batch_open(&values, &[]), Err(PcsError::Empty));
        assert_eq!(
            MerklePcs::commit_with_setup(&MerklePcs::setup(4).expect("small setup"), &values),
            Err(PcsError::InvalidLength)
        );
    }

    #[test]
    fn encoding_relation_is_checked() {
        let message = vec![1_u64.into(), 2_u64.into(), 3_u64.into(), 4_u64.into()];
        let mut codeword = encode_systematic(&message).expect("enc");
        assert_eq!(codeword.len(), message.len() * 4);
        assert_eq!(codeword[4], 3_u64.into());
        assert_eq!(codeword[8], 4_u64.into());
        assert_eq!(codeword[12], 7_u64.into());
        assert!(verify_systematic_encoding(&message, &codeword).is_ok());
        codeword[5] += 1_u64.into();
        assert!(verify_systematic_encoding(&message, &codeword).is_err());
    }

    #[test]
    fn encoding_checks_all_parity_layers() {
        let message = vec![3_u64.into(), 5_u64.into(), 8_u64.into(), 13_u64.into()];
        let codeword = encode_systematic(&message).expect("enc");
        for tamper_index in [5, 10, 15] {
            let mut bad = codeword.clone();
            bad[tamper_index] += 1_u64.into();
            assert!(verify_systematic_encoding(&message, &bad).is_err());
        }
    }

    #[test]
    fn mle_folding_proof_verifies_and_rejects_tampering() {
        let values = vec![1_u64.into(), 2_u64.into(), 3_u64.into(), 4_u64.into()];
        let point = vec![2_u64.into(), 3_u64.into()];
        let proof = prove_mle_folding(&values, &point).expect("folding proof");
        let expected = evaluate_mle(&values, &point).expect("mle eval");
        assert_eq!(verify_mle_folding(&values, &point, &proof), Ok(expected));
        assert_eq!(proof.final_value, expected);

        let mut bad_layer = proof.clone();
        bad_layer.layers[0].values[0] += FieldElement::ONE;
        assert_eq!(
            verify_mle_folding(&values, &point, &bad_layer),
            Err(PcsError::InvalidProof)
        );

        let mut bad_commitment = proof.clone();
        bad_commitment.layers[0].commitment.root[0] ^= 1;
        assert_eq!(
            verify_mle_folding(&values, &point, &bad_commitment),
            Err(PcsError::InvalidCommitment)
        );

        let mut bad_challenge = proof;
        bad_challenge.layers[1].challenge += FieldElement::ONE;
        assert_eq!(
            verify_mle_folding(&values, &point, &bad_challenge),
            Err(PcsError::InvalidProof)
        );
    }

    #[test]
    fn sampled_mle_folding_proof_verifies_and_rejects_tampering() {
        let values = (1_u64..=8).map(FieldElement::from).collect::<Vec<_>>();
        let point = vec![3_u64.into(), 5_u64.into(), 7_u64.into()];
        let input_commitment = MerklePcs::commit(&values).expect("input commitment");
        let expected = evaluate_mle(&values, &point).expect("mle eval");

        let mut prover_tr = HashTranscript::new(b"sampled-fold");
        let proof =
            prove_sampled_mle_folding(&values, &point, 2, &mut prover_tr).expect("sampled proof");
        assert_eq!(proof.final_value, expected);
        assert_eq!(proof.input_commitment, input_commitment);
        assert_eq!(proof.rounds.len(), point.len());
        assert!(proof.rounds.iter().all(|round| !round.checks.is_empty()));

        let mut verifier_tr = HashTranscript::new(b"sampled-fold");
        assert_eq!(
            verify_sampled_mle_folding(&input_commitment, &point, &proof, &mut verifier_tr),
            Ok(expected)
        );

        let mut bad_value = proof.clone();
        bad_value.rounds[0].checks[0].left.value += FieldElement::ONE;
        let mut verifier_tr = HashTranscript::new(b"sampled-fold");
        assert!(
            verify_sampled_mle_folding(&input_commitment, &point, &bad_value, &mut verifier_tr)
                .is_err()
        );

        let mut bad_index = proof.clone();
        bad_index.rounds[0].checks[0].folded_index += 1;
        let mut verifier_tr = HashTranscript::new(b"sampled-fold");
        assert!(
            verify_sampled_mle_folding(&input_commitment, &point, &bad_index, &mut verifier_tr)
                .is_err()
        );

        let mut bad_final = proof;
        bad_final.final_value += FieldElement::ONE;
        let mut verifier_tr = HashTranscript::new(b"sampled-fold");
        assert!(
            verify_sampled_mle_folding(&input_commitment, &point, &bad_final, &mut verifier_tr)
                .is_err()
        );
    }

    #[test]
    fn distributed_opening_verifies_and_rejects_tamper() {
        let evaluations = vec![
            1_u64.into(),
            2_u64.into(),
            3_u64.into(),
            4_u64.into(),
            5_u64.into(),
            6_u64.into(),
            7_u64.into(),
            8_u64.into(),
        ];
        let point = vec![2_u64.into(), 3_u64.into(), 4_u64.into()];
        let mut open_tr = HashTranscript::new(b"pcs-flow");
        let commitment =
            DistributedBrakedown::commit(&evaluations, 2, &mut open_tr).expect("commit");
        let opening =
            DistributedBrakedown::open_at(&evaluations, &commitment, &point, &mut open_tr)
                .expect("open");
        assert!(distributed_commitment_size_bytes(&commitment) > 40);
        assert!(proof_size_bytes(&opening) > opening.combined_column.len() * 8);
        let mut verify_tr = HashTranscript::new(b"pcs-flow");
        assert!(DistributedBrakedown::verify(&commitment, &opening, &mut verify_tr).is_ok());
        assert_eq!(verify_tr.state(), opening.transcript_state);

        let mut worker_query_tr = HashTranscript::new(b"worker-query-binding");
        absorb_worker_openings(&mut worker_query_tr, &opening.workers);
        let mut tampered_workers = opening.workers.clone();
        tampered_workers[0].queries[0].systematic.path[0].0[0] ^= 1;
        let mut tampered_query_tr = HashTranscript::new(b"worker-query-binding");
        absorb_worker_openings(&mut tampered_query_tr, &tampered_workers);
        assert_ne!(worker_query_tr.state(), tampered_query_tr.state());

        let mut bad_state = opening.clone();
        bad_state.transcript_state[0] ^= 1;
        let mut verify_tr = HashTranscript::new(b"pcs-flow");
        assert!(DistributedBrakedown::verify(&commitment, &bad_state, &mut verify_tr).is_err());

        let mut bad = opening.clone();
        bad.workers[0].queries[0].systematic.value += 1_u64.into();
        let mut verify_tr = HashTranscript::new(b"pcs-flow");
        assert!(DistributedBrakedown::verify(&commitment, &bad, &mut verify_tr).is_err());

        let mut bad = opening.clone();
        bad.workers[0].queries[0].stride_parity.value += 1_u64.into();
        let mut verify_tr = HashTranscript::new(b"pcs-flow");
        assert!(DistributedBrakedown::verify(&commitment, &bad, &mut verify_tr).is_err());

        let mut bad = opening.clone();
        bad.workers[0].queries[0].blend_parity.value += 1_u64.into();
        let mut verify_tr = HashTranscript::new(b"pcs-flow");
        assert!(DistributedBrakedown::verify(&commitment, &bad, &mut verify_tr).is_err());

        let mut bad = opening.clone();
        bad.combined_codeword[bad.query_indices[0]] += FieldElement::ONE;
        let mut verify_tr = HashTranscript::new(b"pcs-flow");
        assert!(DistributedBrakedown::verify(&commitment, &bad, &mut verify_tr).is_err());

        let mut bad = opening.clone();
        bad.composition_proof.final_value += FieldElement::ONE;
        let mut verify_tr = HashTranscript::new(b"pcs-flow");
        assert!(DistributedBrakedown::verify(&commitment, &bad, &mut verify_tr).is_err());

        let mut bad = opening.clone();
        bad.sampled_folding_proof.rounds[0].checks[0].folded.value += FieldElement::ONE;
        let mut verify_tr = HashTranscript::new(b"pcs-flow");
        assert!(DistributedBrakedown::verify(&commitment, &bad, &mut verify_tr).is_err());

        let mut bad = opening.clone();
        bad.sampled_composition_proof.final_value += FieldElement::ONE;
        let mut verify_tr = HashTranscript::new(b"pcs-flow");
        assert!(DistributedBrakedown::verify(&commitment, &bad, &mut verify_tr).is_err());

        let mut bad = opening;
        bad.folding_proof.final_value += FieldElement::ONE;
        let mut verify_tr = HashTranscript::new(b"pcs-flow");
        assert!(DistributedBrakedown::verify(&commitment, &bad, &mut verify_tr).is_err());
    }

    #[test]
    fn compact_distributed_opening_verifies_and_rejects_tamper() {
        let evaluations = (1_u64..=256).map(FieldElement::from).collect::<Vec<_>>();
        let point = (2_u64..=9).map(FieldElement::from).collect::<Vec<_>>();
        let params = DistributedPcsParams::new(2);

        let mut compact_tr = HashTranscript::new(b"compact-pcs-flow");
        let commitment =
            DistributedBrakedown::commit(&evaluations, 2, &mut compact_tr).expect("commit");
        let opening = DistributedBrakedown::open_compact_at_after_commitment_with_params(
            &evaluations,
            &commitment,
            &point,
            params,
            &mut compact_tr,
        )
        .expect("compact open");
        assert!(opening.combined_queries.len() == opening.query_indices.len());
        assert!(opening.composition_queries.len() == opening.composition_query_indices.len());
        assert_eq!(opening.composition_query_indices.len(), 2);
        assert_eq!(opening.query_indices.len(), 2);
        let mut verify_tr = HashTranscript::new(b"compact-pcs-flow");
        assert!(
            DistributedBrakedown::verify_compact_with_params(
                &commitment,
                &opening,
                params,
                &mut verify_tr,
            )
            .is_ok()
        );
        assert_eq!(verify_tr.state(), opening.transcript_state);

        let mut bad_provider_tr = HashTranscript::new(b"compact-bad-worker-order");
        DistributedBrakedown::absorb_distributed_commitment(&commitment, &mut bad_provider_tr);
        let bad_provider =
            DistributedBrakedown::open_compact_at_after_commitment_with_worker_provider(
                &evaluations,
                &commitment,
                &point,
                params,
                &mut bad_provider_tr,
                |worker, row, query_indices| {
                    let mut opening = local_worker_opening(worker, row, query_indices)?;
                    opening.queries.reverse();
                    Ok(opening)
                },
            );
        assert_eq!(bad_provider, Err(PcsError::InvalidProof));

        let mut compact_query_tr = HashTranscript::new(b"compact-query-binding");
        absorb_compact_composition_query_openings(
            &mut compact_query_tr,
            &opening.composition_queries,
        );
        absorb_compact_query_openings(&mut compact_query_tr, &opening.combined_queries);
        absorb_worker_openings(&mut compact_query_tr, &opening.workers);
        let mut tampered_combined_queries = opening.combined_queries.clone();
        tampered_combined_queries[0].column.path[0].0[0] ^= 1;
        let mut tampered_query_tr = HashTranscript::new(b"compact-query-binding");
        absorb_compact_composition_query_openings(
            &mut tampered_query_tr,
            &opening.composition_queries,
        );
        absorb_compact_query_openings(&mut tampered_query_tr, &tampered_combined_queries);
        absorb_worker_openings(&mut tampered_query_tr, &opening.workers);
        assert_ne!(compact_query_tr.state(), tampered_query_tr.state());

        let mut bad_state = opening.clone();
        bad_state.transcript_state[0] ^= 1;
        let mut verify_tr = HashTranscript::new(b"compact-pcs-flow");
        assert!(
            DistributedBrakedown::verify_compact_with_params(
                &commitment,
                &bad_state,
                params,
                &mut verify_tr,
            )
            .is_err()
        );

        let mut full_tr = HashTranscript::new(b"full-pcs-flow");
        DistributedBrakedown::absorb_distributed_commitment(&commitment, &mut full_tr);
        let full_opening = DistributedBrakedown::open_at_after_commitment_with_params(
            &evaluations,
            &commitment,
            &point,
            params,
            &mut full_tr,
        )
        .expect("full open");
        assert!(compact_proof_size_bytes(&opening) < proof_size_bytes(&full_opening));

        let mut bad_combined = opening.clone();
        bad_combined.combined_queries[0].column.value += FieldElement::ONE;
        let mut verify_tr = HashTranscript::new(b"compact-pcs-flow");
        assert!(
            DistributedBrakedown::verify_compact_with_params(
                &commitment,
                &bad_combined,
                params,
                &mut verify_tr,
            )
            .is_err()
        );

        let mut bad_composition_query = opening.clone();
        bad_composition_query.composition_queries[0]
            .adjacent_parity
            .value += FieldElement::ONE;
        let mut verify_tr = HashTranscript::new(b"compact-pcs-flow");
        assert!(
            DistributedBrakedown::verify_compact_with_params(
                &commitment,
                &bad_composition_query,
                params,
                &mut verify_tr,
            )
            .is_err()
        );

        let mut bad_composition_indices = opening.clone();
        bad_composition_indices.composition_query_indices.reverse();
        let mut verify_tr = HashTranscript::new(b"compact-pcs-flow");
        assert!(
            DistributedBrakedown::verify_compact_with_params(
                &commitment,
                &bad_composition_indices,
                params,
                &mut verify_tr,
            )
            .is_err()
        );

        let mut bad_worker = opening.clone();
        bad_worker.workers[0].queries[0].blend_parity.value += FieldElement::ONE;
        let mut verify_tr = HashTranscript::new(b"compact-pcs-flow");
        assert!(
            DistributedBrakedown::verify_compact_with_params(
                &commitment,
                &bad_worker,
                params,
                &mut verify_tr,
            )
            .is_err()
        );

        let mut bad_sampled = opening.clone();
        bad_sampled.sampled_folding_proof.final_value += FieldElement::ONE;
        let mut verify_tr = HashTranscript::new(b"compact-pcs-flow");
        assert!(
            DistributedBrakedown::verify_compact_with_params(
                &commitment,
                &bad_sampled,
                params,
                &mut verify_tr,
            )
            .is_err()
        );

        let mut bad_queries = opening;
        bad_queries.query_indices.reverse();
        let mut verify_tr = HashTranscript::new(b"compact-pcs-flow");
        assert!(
            DistributedBrakedown::verify_compact_with_params(
                &commitment,
                &bad_queries,
                params,
                &mut verify_tr,
            )
            .is_err()
        );
    }

    #[test]
    fn compact_batch_worker_provider_matches_sequential_provider() {
        let evaluations = (1_u64..=256).map(FieldElement::from).collect::<Vec<_>>();
        let point = (2_u64..=9).map(FieldElement::from).collect::<Vec<_>>();
        let params = DistributedPcsParams::new(3);

        let mut sequential_tr = HashTranscript::new(b"compact-batch-provider");
        let sequential_commitment =
            DistributedBrakedown::commit(&evaluations, 4, &mut sequential_tr).expect("commit");
        let sequential = DistributedBrakedown::open_compact_at_after_commitment_with_params(
            &evaluations,
            &sequential_commitment,
            &point,
            params,
            &mut sequential_tr,
        )
        .expect("sequential compact open");

        let mut batch_tr = HashTranscript::new(b"compact-batch-provider");
        let batch_commitment =
            DistributedBrakedown::commit(&evaluations, 4, &mut batch_tr).expect("commit");
        assert_eq!(batch_commitment, sequential_commitment);
        let batch =
            DistributedBrakedown::open_compact_at_after_commitment_with_batch_worker_provider(
                &evaluations,
                &batch_commitment,
                &point,
                params,
                &mut batch_tr,
                |requests| {
                    requests
                        .iter()
                        .map(|request| {
                            local_worker_opening(request.worker, request.row, request.query_indices)
                        })
                        .collect()
                },
            )
            .expect("batch compact open");

        assert_eq!(batch, sequential);
        let mut verify_tr = HashTranscript::new(b"compact-batch-provider");
        assert!(
            DistributedBrakedown::verify_compact_with_params(
                &batch_commitment,
                &batch,
                params,
                &mut verify_tr,
            )
            .is_ok()
        );
    }

    #[test]
    fn distributed_opening_binds_combined_column_and_queries() {
        let evaluations = vec![
            1_u64.into(),
            2_u64.into(),
            3_u64.into(),
            4_u64.into(),
            5_u64.into(),
            6_u64.into(),
            7_u64.into(),
            8_u64.into(),
        ];
        let point = vec![2_u64.into(), 3_u64.into(), 4_u64.into()];
        let mut open_tr = HashTranscript::new(b"pcs-binding");
        let commitment =
            DistributedBrakedown::commit(&evaluations, 2, &mut open_tr).expect("commit");
        let opening =
            DistributedBrakedown::open_at(&evaluations, &commitment, &point, &mut open_tr)
                .expect("open");

        let mut bad_provider_tr = HashTranscript::new(b"pcs-binding-bad-worker-order");
        DistributedBrakedown::absorb_distributed_commitment(&commitment, &mut bad_provider_tr);
        let bad_provider = DistributedBrakedown::open_at_after_commitment_with_worker_provider(
            &evaluations,
            &commitment,
            &point,
            DistributedPcsParams::new(3),
            &mut bad_provider_tr,
            |worker, row, query_indices| {
                let mut opening = local_worker_opening(worker, row, query_indices)?;
                opening.queries.reverse();
                Ok(opening)
            },
        );
        assert_eq!(bad_provider, Err(PcsError::InvalidProof));

        let mut bad_combined = opening.clone();
        bad_combined.combined_column[bad_combined.query_indices[0]] += 1_u64.into();
        let mut verify_tr = HashTranscript::new(b"pcs-binding");
        assert!(DistributedBrakedown::verify(&commitment, &bad_combined, &mut verify_tr).is_err());

        let mut bad_composition = opening.clone();
        let idx = bad_composition.query_indices[0];
        bad_composition.combined_codeword[bad_composition.combined_column.len() + idx] +=
            FieldElement::ONE;
        let mut verify_tr = HashTranscript::new(b"pcs-binding");
        assert!(
            DistributedBrakedown::verify(&commitment, &bad_composition, &mut verify_tr).is_err()
        );

        let mut bad_query = opening;
        bad_query.query_indices.reverse();
        let mut verify_tr = HashTranscript::new(b"pcs-binding");
        assert!(DistributedBrakedown::verify(&commitment, &bad_query, &mut verify_tr).is_err());
    }

    #[test]
    fn distributed_opening_binds_query_security_parameter() {
        let evaluations = (1_u64..=16).map(FieldElement::from).collect::<Vec<_>>();
        let point = vec![2_u64.into(), 3_u64.into(), 4_u64.into(), 5_u64.into()];
        let params = DistributedPcsParams::new(3);
        let mut open_tr = HashTranscript::new(b"pcs-query-param");
        let commitment =
            DistributedBrakedown::commit(&evaluations, 2, &mut open_tr).expect("commit");
        let opening = DistributedBrakedown::open_at_after_commitment_with_params(
            &evaluations,
            &commitment,
            &point,
            params,
            &mut open_tr,
        )
        .expect("open");
        assert_eq!(opening.query_count, 3);
        assert_eq!(opening.query_indices.len(), 3);

        let mut verify_tr = HashTranscript::new(b"pcs-query-param");
        DistributedBrakedown::absorb_distributed_commitment(&commitment, &mut verify_tr);
        assert!(
            DistributedBrakedown::verify_opening_after_commitment_with_params(
                &commitment,
                &opening,
                params,
                &mut verify_tr,
            )
            .is_ok()
        );

        let mut wrong_param_tr = HashTranscript::new(b"pcs-query-param");
        DistributedBrakedown::absorb_distributed_commitment(&commitment, &mut wrong_param_tr);
        assert!(
            DistributedBrakedown::verify_opening_after_commitment_with_params(
                &commitment,
                &opening,
                DistributedPcsParams::new(4),
                &mut wrong_param_tr,
            )
            .is_err()
        );

        let mut tampered = opening;
        tampered.query_count = 1;
        let mut verify_tr = HashTranscript::new(b"pcs-query-param");
        DistributedBrakedown::absorb_distributed_commitment(&commitment, &mut verify_tr);
        assert!(
            DistributedBrakedown::verify_opening_after_commitment_with_params(
                &commitment,
                &tampered,
                params,
                &mut verify_tr,
            )
            .is_err()
        );
    }

    #[test]
    fn distributed_root_binds_worker_metadata() {
        let message = vec![1_u64.into(), 2_u64.into()];
        let codeword = encode_systematic(&message).expect("enc");
        let commitment = MerklePcs::commit(&codeword).expect("commit");
        let worker = WorkerCommitment {
            worker_id: 0,
            range: (0, 2),
            encoded_commitment: commitment,
        };
        let root = aggregate_worker_commitments(std::slice::from_ref(&worker));

        let mut changed_id = worker.clone();
        changed_id.worker_id = 1;
        assert_ne!(
            root,
            aggregate_worker_commitments(std::slice::from_ref(&changed_id))
        );

        let mut changed_range = worker;
        changed_range.range = (1, 3);
        assert_ne!(
            root,
            aggregate_worker_commitments(std::slice::from_ref(&changed_range))
        );
    }

    #[test]
    fn distributed_index_opening_binds_global_index() {
        let evaluations = vec![
            1_u64.into(),
            2_u64.into(),
            3_u64.into(),
            4_u64.into(),
            5_u64.into(),
            6_u64.into(),
            7_u64.into(),
            8_u64.into(),
        ];
        let commitment = DistributedBrakedown::commit_detached(&evaluations, 2).expect("commit");
        let opening = DistributedBrakedown::open_index(&evaluations, &commitment, 5).expect("open");
        assert_eq!(
            DistributedBrakedown::verify_index(&commitment, &opening),
            Ok(6_u64.into())
        );

        let mut bad = opening;
        bad.global_index = 4;
        assert!(DistributedBrakedown::verify_index(&commitment, &bad).is_err());

        let opening = DistributedBrakedown::open_index(&evaluations, &commitment, 5).expect("open");
        let mut bad_commitment = commitment;
        bad_commitment.root[0] ^= 1;
        assert!(DistributedBrakedown::verify_index(&bad_commitment, &opening).is_err());
    }

    #[test]
    fn split_opening_api_absorbs_commitment() {
        let evaluations = (1_u64..=16).map(FieldElement::from).collect::<Vec<_>>();
        let point = vec![2_u64.into(), 3_u64.into(), 4_u64.into(), 5_u64.into()];
        let params = DistributedPcsParams::new(3);
        let commitment = DistributedBrakedown::commit_detached(&evaluations, 2).expect("commit");
        let mut open_tr = HashTranscript::new(b"pcs-split-api");
        let opening = DistributedBrakedown::open_at_with_params(
            &evaluations,
            &commitment,
            &point,
            params,
            &mut open_tr,
        )
        .expect("open");

        let mut verify_tr = HashTranscript::new(b"pcs-split-api");
        assert!(
            DistributedBrakedown::verify_opening_with_params(
                &commitment,
                &opening,
                params,
                &mut verify_tr,
            )
            .is_ok()
        );

        let mut missing_commitment_tr = HashTranscript::new(b"pcs-split-api");
        assert!(
            DistributedBrakedown::verify_opening_after_commitment_with_params(
                &commitment,
                &opening,
                params,
                &mut missing_commitment_tr,
            )
            .is_err()
        );

        let mut bad_commitment = commitment;
        bad_commitment.root[0] ^= 1;
        let mut verify_tr = HashTranscript::new(b"pcs-split-api");
        assert!(
            DistributedBrakedown::verify_opening_with_params(
                &bad_commitment,
                &opening,
                params,
                &mut verify_tr,
            )
            .is_err()
        );
    }

    #[test]
    fn distributed_opening_rejects_malicious_worker_response() {
        let evaluations = (1_u64..=16).map(FieldElement::from).collect::<Vec<_>>();
        let point = vec![2_u64.into(), 3_u64.into(), 4_u64.into(), 5_u64.into()];
        let params = DistributedPcsParams::new(2);
        let commitment = DistributedBrakedown::commit_detached(&evaluations, 2).expect("commit");

        let mut honest_open_tr = HashTranscript::new(b"pcs-malicious-worker");
        DistributedBrakedown::absorb_distributed_commitment(&commitment, &mut honest_open_tr);
        let honest = DistributedBrakedown::open_at_after_commitment_with_worker_provider(
            &evaluations,
            &commitment,
            &point,
            params,
            &mut honest_open_tr,
            |worker, row, query_indices| {
                DistributedBrakedown::worker_open(
                    worker.worker_id,
                    worker.range.0,
                    row,
                    query_indices,
                )
            },
        )
        .expect("honest opening");
        let mut honest_verify_tr = HashTranscript::new(b"pcs-malicious-worker");
        assert!(
            DistributedBrakedown::verify_opening_with_params(
                &commitment,
                &honest,
                params,
                &mut honest_verify_tr,
            )
            .is_ok()
        );

        let mut malicious_open_tr = HashTranscript::new(b"pcs-malicious-worker");
        DistributedBrakedown::absorb_distributed_commitment(&commitment, &mut malicious_open_tr);
        let malicious = DistributedBrakedown::open_at_after_commitment_with_worker_provider(
            &evaluations,
            &commitment,
            &point,
            params,
            &mut malicious_open_tr,
            |worker, row, query_indices| {
                let mut opening = DistributedBrakedown::worker_open(
                    worker.worker_id,
                    worker.range.0,
                    row,
                    query_indices,
                )?;
                if worker.worker_id == 1 {
                    opening.queries[0].systematic.value += FieldElement::ONE;
                }
                Ok(opening)
            },
        )
        .expect("malicious opening is assembled before verification");

        let mut verify_tr = HashTranscript::new(b"pcs-malicious-worker");
        assert_eq!(
            DistributedBrakedown::verify_opening_with_params(
                &commitment,
                &malicious,
                params,
                &mut verify_tr,
            ),
            Err(PcsError::InvalidCommitment)
        );
    }

    #[test]
    fn worker_master_commit_api_matches_convenience_commit_and_rejects_bad_metadata() {
        let evaluations = (1_u64..=8).map(FieldElement::from).collect::<Vec<_>>();
        let worker_0 =
            DistributedBrakedown::worker_commit(0, 0, &evaluations[0..4]).expect("worker 0");
        let worker_1 =
            DistributedBrakedown::worker_commit(1, 4, &evaluations[4..8]).expect("worker 1");

        let mut split_tr = HashTranscript::new(b"pcs-worker-master");
        let split = DistributedBrakedown::master_commit(
            vec![worker_0.clone(), worker_1.clone()],
            evaluations.len(),
            &mut split_tr,
        )
        .expect("split commit");
        let mut direct_tr = HashTranscript::new(b"pcs-worker-master");
        let direct =
            DistributedBrakedown::commit(&evaluations, 2, &mut direct_tr).expect("direct commit");
        assert_eq!(split, direct);
        assert_eq!(split_tr.state(), direct_tr.state());

        let mut bad_order_tr = HashTranscript::new(b"pcs-worker-master");
        assert_eq!(
            DistributedBrakedown::master_commit(
                vec![worker_1.clone(), worker_0.clone()],
                evaluations.len(),
                &mut bad_order_tr,
            ),
            Err(PcsError::InvalidWorker)
        );

        let mut bad_range = worker_1;
        bad_range.range = (5, 9);
        bad_range.encoded_commitment.len = worker_0.encoded_commitment.len;
        let mut bad_range_tr = HashTranscript::new(b"pcs-worker-master");
        assert_eq!(
            DistributedBrakedown::master_commit(
                vec![worker_0, bad_range],
                evaluations.len(),
                &mut bad_range_tr,
            ),
            Err(PcsError::InvalidWorker)
        );
    }

    #[test]
    fn worker_open_api_checks_all_codeword_layers() {
        let evaluations = [5_u64.into(), 6_u64.into(), 7_u64.into(), 8_u64.into()];
        let opening =
            DistributedBrakedown::worker_open(3, 12, &evaluations, &[0, 2]).expect("worker open");
        assert_eq!(opening.worker_id, 3);
        assert_eq!(opening.range, (12, 16));
        assert_eq!(opening.queries.len(), 2);
        assert_eq!(opening.queries[0].systematic.value, evaluations[0]);
        assert_eq!(
            opening.queries[0].adjacent_parity.value,
            evaluations[0] + evaluations[1]
        );
        assert_eq!(
            opening.queries[0].stride_parity.value,
            evaluations[0] + evaluations[2]
        );
        assert_eq!(
            opening.queries[0].blend_parity.value,
            evaluations[0] + evaluations[1] + evaluations[0] + evaluations[2]
        );
        assert_eq!(
            DistributedBrakedown::worker_open(3, 12, &evaluations, &[4]),
            Err(PcsError::InvalidLength)
        );
    }

    #[test]
    fn distributed_commitment_requires_canonical_worker_ids() {
        let evaluations = (1_u64..=8).map(FieldElement::from).collect::<Vec<_>>();
        let mut commitment =
            DistributedBrakedown::commit_detached(&evaluations, 2).expect("commit");
        commitment.workers[1].worker_id = 0;
        commitment.root = aggregate_worker_commitments(&commitment.workers);

        let opening = DistributedIndexOpening {
            global_index: 1,
            worker_id: 0,
            local_index: 1,
            proof: MerklePcs::open(&encode_systematic(&evaluations[0..4]).expect("codeword"), 1)
                .expect("open"),
        };
        assert!(DistributedBrakedown::verify_index(&commitment, &opening).is_err());
    }

    #[test]
    fn distributed_verify_rejects_bad_range_lengths() {
        let message = vec![1_u64.into()];
        let codeword = encode_systematic(&message).expect("enc");
        let root = merkle_root(&codeword).expect("root");
        let worker = WorkerCommitment {
            worker_id: 0,
            range: (0, 2),
            encoded_commitment: Commitment {
                root,
                len: codeword.len(),
            },
        };
        let commitment = DistributedCommitment {
            workers: vec![worker.clone()],
            original_len: 4,
            root: aggregate_worker_commitments(&[worker]),
        };
        let combined_column = vec![
            FieldElement::ZERO,
            FieldElement::ZERO,
            FieldElement::ZERO,
            FieldElement::ZERO,
        ];
        let combined_codeword = encode_systematic(&combined_column).expect("combined codeword");
        let col_point = vec![FieldElement::ZERO, FieldElement::ZERO];
        let composition_point = vec![
            FieldElement::ZERO,
            FieldElement::ZERO,
            FieldElement::ZERO,
            FieldElement::ZERO,
        ];
        let folding_proof = prove_mle_folding(&combined_column, &col_point).expect("folding");
        let composition_proof =
            prove_mle_folding(&combined_codeword, &composition_point).expect("composition folding");
        let sampled_folding_proof = prove_sampled_mle_folding(
            &combined_column,
            &col_point,
            1,
            &mut HashTranscript::new(b"dummy-sampled-column"),
        )
        .expect("sampled folding");
        let sampled_composition_proof = prove_sampled_mle_folding(
            &combined_codeword,
            &composition_point,
            1,
            &mut HashTranscript::new(b"dummy-sampled-codeword"),
        )
        .expect("sampled composition");
        let opening = DistributedOpening {
            point: vec![FieldElement::ZERO, FieldElement::ZERO],
            claimed_value: FieldElement::ZERO,
            combined_column,
            combined_codeword,
            folding_proof,
            composition_proof,
            sampled_folding_proof,
            sampled_composition_proof,
            query_count: DistributedPcsParams::default().query_count,
            query_indices: Vec::new(),
            workers: vec![WorkerOpening {
                worker_id: 0,
                range: (0, 2),
                queries: Vec::new(),
            }],
            transcript_state: [0; 32],
        };
        let mut verify_tr = HashTranscript::new(b"pcs-flow");
        assert!(DistributedBrakedown::verify(&commitment, &opening, &mut verify_tr).is_err());
    }
}

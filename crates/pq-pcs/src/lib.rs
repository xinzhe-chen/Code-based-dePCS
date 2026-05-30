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

    fn effective_query_count(self, col_len: usize) -> PcsResult<usize> {
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

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OpeningProof {
    pub index: usize,
    pub value: FieldElement,
    pub path: Vec<([u8; 32], bool)>,
}

pub trait PolynomialCommitment {
    fn commit(evaluations: &[FieldElement]) -> PcsResult<Commitment>;
    fn open(evaluations: &[FieldElement], index: usize) -> PcsResult<OpeningProof>;
    fn verify(commitment: &Commitment, proof: &OpeningProof) -> PcsResult<()>;
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
    pub folding_proof: MleFoldingProof,
    pub query_count: usize,
    pub query_indices: Vec<usize>,
    pub workers: Vec<WorkerOpening>,
    pub transcript_state: [u8; 32],
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
pub struct DistributedIndexOpening {
    pub global_index: usize,
    pub worker_id: usize,
    pub local_index: usize,
    pub proof: OpeningProof,
}

pub trait DistributedPcs {
    fn partition(evaluations: &[FieldElement], workers: usize) -> PcsResult<PartitionPlan>;
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
        let mut worker_commitments = Vec::with_capacity(workers);
        for partition in plan.partitions() {
            let range = (partition.start, partition.end);
            let codeword = encode_systematic(&evaluations[range.0..range.1])?;
            let commitment = MerklePcs::commit(&codeword)?;
            worker_commitments.push(WorkerCommitment {
                worker_id: partition.id,
                range,
                encoded_commitment: commitment,
            });
        }
        let root = aggregate_worker_commitments(&worker_commitments);
        Ok(DistributedCommitment {
            workers: worker_commitments,
            original_len: evaluations.len(),
            root,
        })
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

    fn commit<T: Transcript>(
        evaluations: &[FieldElement],
        workers: usize,
        transcript: &mut T,
    ) -> PcsResult<DistributedCommitment> {
        let commitment = Self::commit_detached(evaluations, workers)?;
        Self::absorb_distributed_commitment(&commitment, transcript);
        Ok(commitment)
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
    let mut path = Vec::new();
    let mut idx = index;
    let mut level = values.iter().copied().map(leaf_hash).collect::<Vec<_>>();
    while level.len() > 1 {
        let sibling_on_right = idx.is_multiple_of(2);
        let sibling_idx = if sibling_on_right { idx + 1 } else { idx - 1 };
        path.push((level[sibling_idx], sibling_on_right));
        idx /= 2;
        level = level
            .chunks_exact(2)
            .map(|pair| internal_hash(pair[0], pair[1]))
            .collect();
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
        + folding_proof_size_bytes(&opening.folding_proof)
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

pub fn communication_bytes(opening: &DistributedOpening) -> usize {
    proof_size_bytes(opening) + opening.workers.len() * 32
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
    open_at_after_commitment_with_provider(
        evaluations,
        commitment,
        point,
        params,
        transcript,
        local_worker_opening,
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

fn absorb_commitment<T: Transcript>(
    transcript: &mut T,
    label: &'static [u8],
    commitment: &Commitment,
) {
    transcript.absorb_public(label, &(commitment.len as u64).to_le_bytes());
    transcript.absorb_commitment(label, &commitment.root);
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
    let folding_proof = prove_mle_folding(&combined_column, &point[..col_vars])?;
    absorb_folding_proof(transcript, &folding_proof);
    if folding_proof.final_value != value {
        return Err(PcsError::InvalidEvaluation);
    }
    let query_indices = transcript.challenge_indices(b"brakedown-query", query_count, col_len);
    let mut openings = Vec::with_capacity(commitment.workers.len());
    for worker in &commitment.workers {
        let row = &evaluations[worker.range.0..worker.range.1];
        openings.push(provider(worker, row, &query_indices)?);
    }
    Ok(DistributedOpening {
        point: point.to_vec(),
        claimed_value: value,
        combined_column,
        folding_proof,
        query_count: params.query_count,
        query_indices,
        workers: openings,
        transcript_state: transcript.state(),
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
    let col_len = row.len();
    let stride_offset = if col_len > 1 { col_len / 2 } else { 0 };
    let mut queries = Vec::with_capacity(query_indices.len());
    for query_index in query_indices {
        let next = (query_index + 1) % col_len;
        let stride = (query_index + stride_offset) % col_len;
        queries.push(QueryOpening {
            query_index: *query_index,
            systematic: MerklePcs::open(&codeword, *query_index)?,
            systematic_next: MerklePcs::open(&codeword, next)?,
            systematic_stride: MerklePcs::open(&codeword, stride)?,
            adjacent_parity: MerklePcs::open(&codeword, col_len + *query_index)?,
            stride_parity: MerklePcs::open(&codeword, 2 * col_len + *query_index)?,
            blend_parity: MerklePcs::open(&codeword, 3 * col_len + *query_index)?,
        });
    }
    Ok(WorkerOpening {
        worker_id: worker.worker_id,
        range: worker.range,
        queries,
    })
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
    if opening.query_count != params.query_count || opening.query_indices.len() != query_count {
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
    absorb_folding_proof(transcript, &opening.folding_proof);
    let expected_queries = transcript.challenge_indices(b"brakedown-query", query_count, col_len);
    if expected_queries != opening.query_indices {
        return Err(PcsError::InvalidProof);
    }
    if opening.transcript_state != transcript.state() {
        return Err(PcsError::InvalidProof);
    }
    verify_mle_folding(&opening.combined_column, col_point, &opening.folding_proof)?;
    if opening.folding_proof.final_value != opening.claimed_value {
        return Err(PcsError::InvalidEvaluation);
    }
    for query_index in &opening.query_indices {
        let next = (query_index + 1) % col_len;
        let stride_offset = if col_len > 1 { col_len / 2 } else { 0 };
        let stride = (query_index + stride_offset) % col_len;
        let mut combined_query = FieldElement::ZERO;
        let mut combined_next = FieldElement::ZERO;
        let mut combined_stride = FieldElement::ZERO;
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
        }
        if combined_query != opening.combined_column[*query_index]
            || combined_next != opening.combined_column[next]
            || combined_stride != opening.combined_column[stride]
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

        let mut bad = opening;
        bad.folding_proof.final_value += FieldElement::ONE;
        let mut verify_tr = HashTranscript::new(b"pcs-flow");
        assert!(DistributedBrakedown::verify(&commitment, &bad, &mut verify_tr).is_err());
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

        let mut bad_combined = opening.clone();
        bad_combined.combined_column[bad_combined.query_indices[0]] += 1_u64.into();
        let mut verify_tr = HashTranscript::new(b"pcs-binding");
        assert!(DistributedBrakedown::verify(&commitment, &bad_combined, &mut verify_tr).is_err());

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
        let opening = DistributedOpening {
            point: vec![FieldElement::ZERO, FieldElement::ZERO],
            claimed_value: FieldElement::ZERO,
            combined_column: vec![
                FieldElement::ZERO,
                FieldElement::ZERO,
                FieldElement::ZERO,
                FieldElement::ZERO,
            ],
            folding_proof: prove_mle_folding(
                &[
                    FieldElement::ZERO,
                    FieldElement::ZERO,
                    FieldElement::ZERO,
                    FieldElement::ZERO,
                ],
                &[FieldElement::ZERO, FieldElement::ZERO],
            )
            .expect("folding"),
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

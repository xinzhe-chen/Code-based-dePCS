use pq_core::{
    FieldElement, MultilinearPolynomial, Partition, PartitionPlan, R1csInstance, SparseEntry,
    SparseMatrix, eq_basis, evaluate_mle, log2_power_of_two, sample_r1cs,
};
use pq_pcs::{
    Commitment, CompactDistributedOpening, DistributedBrakedown, DistributedCommitment,
    DistributedIndexOpening, DistributedOpening, DistributedPcsParams, MerklePcs, OpeningProof,
    PolynomialCommitment, commitment_size_bytes, communication_bytes, compact_communication_bytes,
    compact_proof_size_bytes, distributed_commitment_size_bytes,
    distributed_index_communication_bytes, distributed_index_opening_size_bytes,
    opening_proof_size_bytes, proof_size_bytes as full_pcs_proof_size_bytes,
};
use pq_piop::Piop;
use pq_sumcheck::{
    CubicZerocheckProof, ProductMultisetEqualityProof, ProductSumcheckProof, RationalSumcheckProof,
    SumcheckProof, ZerocheckProof, cubic_zerocheck_final_evaluation, prove_cubic_zerocheck,
    prove_product_multiset_equality, prove_product_sumcheck, prove_zerocheck_proof,
    verify_cubic_zerocheck_rounds, verify_product_multiset_equality,
    verify_product_sumcheck_rounds, verify_zerocheck_rounds, zerocheck_final_evaluation,
};
use pq_transcript::{HashTranscript, Transcript};
use serde::{Deserialize, Serialize};
use std::time::{Duration, Instant};

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum R1csPiopError {
    Unsatisfied,
    InvalidProof,
    InvalidShape,
    Pcs,
    Sumcheck,
}

pub type R1csPiopResult<T> = Result<T, R1csPiopError>;

pub struct R1csPiop;

impl Piop for R1csPiop {
    type Statement = R1csInstance;
    type Witness = Vec<FieldElement>;
    type Proof = R1csPiopProof;
    type Metrics = R1csMetrics;
    type Error = R1csPiopError;

    fn prove_interactive<T: Transcript>(
        statement: &Self::Statement,
        witness: &Self::Witness,
        workers: usize,
        pcs_params: DistributedPcsParams,
        transcript: &mut T,
    ) -> Result<Self::Proof, Self::Error> {
        prove_r1cs_with_pcs_params(statement, witness, workers, pcs_params, transcript)
    }

    fn verify_interactive<T: Transcript>(
        statement: &Self::Statement,
        proof: &Self::Proof,
        pcs_params: DistributedPcsParams,
        transcript: &mut T,
    ) -> Result<Self::Metrics, Self::Error> {
        verify_r1cs_with_pcs_params(statement, proof, pcs_params, transcript)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DistributedSparkProof {
    pub tuple_challenge: FieldElement,
    pub matrix_challenge: FieldElement,
    pub row_challenge: FieldElement,
    pub col_challenge: FieldElement,
    pub value_challenge: FieldElement,
    pub total_entries: usize,
    pub linear_fingerprint: FieldElement,
    pub product_fingerprint: FieldElement,
    pub workers: Vec<SparkWorkerFingerprint>,
    pub combined_evaluation: FieldElement,
    pub matrix_evaluations: Vec<SparkMatrixEvaluationProof>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SparkWorkerFingerprint {
    pub worker_id: usize,
    pub range: (usize, usize),
    pub entry_count: usize,
    pub linear_fingerprint: FieldElement,
    pub product_fingerprint: FieldElement,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SparkWorkerEvaluation {
    pub matrix_id: usize,
    pub worker_id: usize,
    pub range: (usize, usize),
    pub entry_count: usize,
    pub evaluation: FieldElement,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SparkMatrixEvaluationProof {
    pub matrix_id: usize,
    pub evaluation: FieldElement,
    pub worker_evaluations: Vec<SparkWorkerEvaluation>,
    pub row_memory: SparkMemoryCheckProof,
    pub col_memory: SparkMemoryCheckProof,
    pub value_memory: SparkMemoryCheckProof,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SparkMemoryCheckProof {
    pub hash_challenge: FieldElement,
    pub domain_len: usize,
    pub access_count: usize,
    pub trace_commitments: SparkMemoryTraceCommitments,
    pub domain_queries: Vec<SparkMemoryDomainQuery>,
    pub access_queries: Vec<SparkMemoryAccessQuery>,
    pub worker_digests: Vec<SparkMemoryWorkerDigest>,
    pub multiset: ProductMultisetEqualityProof,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SparkMemoryTraceCommitments {
    pub init: Commitment,
    pub writes: Commitment,
    pub audit: Commitment,
    pub reads: Commitment,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SparkMemoryDomainQuery {
    pub index: usize,
    pub init: OpeningProof,
    pub audit: OpeningProof,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SparkMemoryAccessQuery {
    pub index: usize,
    pub address: usize,
    pub value: FieldElement,
    pub read_timestamp: FieldElement,
    pub write_timestamp: FieldElement,
    pub read: OpeningProof,
    pub write: OpeningProof,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SparkMemoryWorkerDigest {
    pub worker_id: usize,
    pub entry_range: (usize, usize),
    pub memory_range: (usize, usize),
    pub access_count: usize,
    pub init_product: FieldElement,
    pub read_product: FieldElement,
    pub write_product: FieldElement,
    pub audit_product: FieldElement,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SparkChallenges {
    pub tuple: FieldElement,
    pub matrix: FieldElement,
    pub row: FieldElement,
    pub col: FieldElement,
    pub value: FieldElement,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SparkWorkerShardClaim {
    pub fingerprint: SparkWorkerFingerprint,
    pub matrix_evaluations: Vec<SparkWorkerEvaluation>,
}

#[derive(Copy, Clone, Debug)]
pub struct SparkWorkerClaimRequest<'a> {
    pub partition: Partition,
    pub challenges: SparkChallenges,
    pub row_point: &'a [FieldElement],
    pub col_point: &'a [FieldElement],
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct R1csPiopProof {
    pub oracle_commitments: R1csOracleCommitments,
    pub outer_commitments: R1csOuterCommitments,
    pub outer_openings: R1csOuterOpenings,
    pub outer_sumcheck: CubicZerocheckProof,
    pub inner: R1csInnerProof,
    pub witness_consistency_queries: Vec<R1csWitnessConsistencyQuery>,
    pub residual_commitment: DistributedCommitment,
    pub residual_opening: R1csPcsOpening,
    pub sumcheck: ZerocheckProof,
    pub row_queries: Vec<R1csRowConsistencyQuery>,
    pub spark: DistributedSparkProof,
    pub workers: usize,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct R1csOracleCommitments {
    pub witness: Commitment,
    pub az: Commitment,
    pub bz: Commitment,
    pub cz: Commitment,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct R1csOuterCommitments {
    pub az: DistributedCommitment,
    pub bz: DistributedCommitment,
    pub cz: DistributedCommitment,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct R1csOuterOpenings {
    pub az: R1csPcsOpening,
    pub bz: R1csPcsOpening,
    pub cz: R1csPcsOpening,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct R1csInnerProof {
    pub matrix_challenges: [FieldElement; 3],
    pub witness_commitment: DistributedCommitment,
    pub sumcheck: ProductSumcheckProof,
    pub witness_opening: R1csPcsOpening,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum R1csPcsOpening {
    Full(DistributedOpening),
    Compact(CompactDistributedOpening),
}

impl R1csPcsOpening {
    pub fn point(&self) -> &[FieldElement] {
        match self {
            Self::Full(opening) => &opening.point,
            Self::Compact(opening) => &opening.point,
        }
    }

    pub fn point_mut(&mut self) -> &mut Vec<FieldElement> {
        match self {
            Self::Full(opening) => &mut opening.point,
            Self::Compact(opening) => &mut opening.point,
        }
    }

    pub fn claimed_value(&self) -> FieldElement {
        match self {
            Self::Full(opening) => opening.claimed_value,
            Self::Compact(opening) => opening.claimed_value,
        }
    }

    pub fn claimed_value_mut(&mut self) -> &mut FieldElement {
        match self {
            Self::Full(opening) => &mut opening.claimed_value,
            Self::Compact(opening) => &mut opening.claimed_value,
        }
    }

    fn verify_after_commitment<T: Transcript>(
        &self,
        commitment: &DistributedCommitment,
        params: DistributedPcsParams,
        transcript: &mut T,
    ) -> R1csPiopResult<()> {
        match self {
            Self::Full(opening) => {
                DistributedBrakedown::verify_opening_after_commitment_with_params(
                    commitment, opening, params, transcript,
                )
            }
            Self::Compact(opening) => {
                DistributedBrakedown::verify_compact_after_commitment_with_params(
                    commitment, opening, params, transcript,
                )
            }
        }
        .map_err(|_| R1csPiopError::Pcs)
    }

    pub fn proof_size_bytes(&self) -> usize {
        match self {
            Self::Full(opening) => full_pcs_proof_size_bytes(opening),
            Self::Compact(opening) => compact_proof_size_bytes(opening),
        }
    }

    pub fn communication_bytes(&self) -> usize {
        match self {
            Self::Full(opening) => communication_bytes(opening),
            Self::Compact(opening) => compact_communication_bytes(opening),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct R1csRowConsistencyQuery {
    pub row: usize,
    pub witness_openings: Vec<OpeningProof>,
    pub az_opening: OpeningProof,
    pub bz_opening: OpeningProof,
    pub cz_opening: OpeningProof,
    pub residual_opening: DistributedIndexOpening,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct R1csWitnessConsistencyQuery {
    pub index: usize,
    pub oracle_opening: OpeningProof,
    pub distributed_opening: DistributedIndexOpening,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct R1csMetrics {
    pub proof_bytes: usize,
    pub communication_bytes: usize,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct ConstraintVectors {
    witness: Vec<FieldElement>,
    az: Vec<FieldElement>,
    bz: Vec<FieldElement>,
    cz: Vec<FieldElement>,
    residual: Vec<FieldElement>,
}

#[derive(Copy, Clone)]
struct InnerLinearizationConfig {
    workers: usize,
    pcs_params: DistributedPcsParams,
}

pub struct R1csProverHooks<C, O, S> {
    pub commit_distributed: C,
    pub open_distributed: O,
    pub spark_worker_provider: S,
}

pub struct R1csBatchProverHooks<C, O, S> {
    pub commit_distributed: C,
    pub open_distributed: O,
    pub spark_worker_provider: S,
}

pub fn prove_r1cs<T: Transcript>(
    instance: &R1csInstance,
    witness: &[FieldElement],
    workers: usize,
    transcript: &mut T,
) -> R1csPiopResult<R1csPiopProof> {
    prove_r1cs_with_pcs_params(
        instance,
        witness,
        workers,
        DistributedPcsParams::default(),
        transcript,
    )
}

pub fn prove_r1cs_with_pcs_params<T: Transcript>(
    instance: &R1csInstance,
    witness: &[FieldElement],
    workers: usize,
    pcs_params: DistributedPcsParams,
    transcript: &mut T,
) -> R1csPiopResult<R1csPiopProof> {
    prove_r1cs_with_opening_hooks(
        instance,
        witness,
        workers,
        pcs_params,
        transcript,
        R1csProverHooks {
            commit_distributed: |evaluations: &[FieldElement], workers: usize| {
                DistributedBrakedown::commit_detached(evaluations, workers)
                    .map_err(|_| R1csPiopError::Pcs)
            },
            open_distributed: |evaluations: &[FieldElement],
                               commitment: &DistributedCommitment,
                               point: &[FieldElement],
                               params: DistributedPcsParams,
                               transcript: &mut T| {
                DistributedBrakedown::open_compact_at_after_commitment_with_params(
                    evaluations,
                    commitment,
                    point,
                    params,
                    transcript,
                )
                .map(R1csPcsOpening::Compact)
                .map_err(|_| R1csPiopError::Pcs)
            },
            spark_worker_provider: |partition: Partition,
                                    challenges: SparkChallenges,
                                    row_point: &[FieldElement],
                                    col_point: &[FieldElement]| {
                compute_spark_worker_shard_claim(
                    instance, partition, challenges, row_point, col_point,
                )
            },
        },
    )
}

pub fn prove_r1cs_with_pcs_hooks<T, C, O>(
    instance: &R1csInstance,
    witness: &[FieldElement],
    workers: usize,
    pcs_params: DistributedPcsParams,
    transcript: &mut T,
    commit_distributed: C,
    mut open_distributed: O,
) -> R1csPiopResult<R1csPiopProof>
where
    T: Transcript,
    C: FnMut(&[FieldElement], usize) -> R1csPiopResult<DistributedCommitment>,
    O: FnMut(
        &[FieldElement],
        &DistributedCommitment,
        &[FieldElement],
        DistributedPcsParams,
        &mut T,
    ) -> R1csPiopResult<DistributedOpening>,
{
    prove_r1cs_with_opening_hooks(
        instance,
        witness,
        workers,
        pcs_params,
        transcript,
        R1csProverHooks {
            commit_distributed,
            open_distributed: |evaluations: &[FieldElement],
                               commitment: &DistributedCommitment,
                               point: &[FieldElement],
                               params: DistributedPcsParams,
                               transcript: &mut T| {
                open_distributed(evaluations, commitment, point, params, transcript)
                    .map(R1csPcsOpening::Full)
            },
            spark_worker_provider: |partition: Partition,
                                    challenges: SparkChallenges,
                                    row_point: &[FieldElement],
                                    col_point: &[FieldElement]| {
                compute_spark_worker_shard_claim(
                    instance, partition, challenges, row_point, col_point,
                )
            },
        },
    )
}

pub fn prove_r1cs_with_pcs_opening_hooks<T, C, O>(
    instance: &R1csInstance,
    witness: &[FieldElement],
    workers: usize,
    pcs_params: DistributedPcsParams,
    transcript: &mut T,
    commit_distributed: C,
    open_distributed: O,
) -> R1csPiopResult<R1csPiopProof>
where
    T: Transcript,
    C: FnMut(&[FieldElement], usize) -> R1csPiopResult<DistributedCommitment>,
    O: FnMut(
        &[FieldElement],
        &DistributedCommitment,
        &[FieldElement],
        DistributedPcsParams,
        &mut T,
    ) -> R1csPiopResult<R1csPcsOpening>,
{
    prove_r1cs_with_opening_hooks(
        instance,
        witness,
        workers,
        pcs_params,
        transcript,
        R1csProverHooks {
            commit_distributed,
            open_distributed,
            spark_worker_provider: |partition: Partition,
                                    challenges: SparkChallenges,
                                    row_point: &[FieldElement],
                                    col_point: &[FieldElement]| {
                compute_spark_worker_shard_claim(
                    instance, partition, challenges, row_point, col_point,
                )
            },
        },
    )
}

pub fn prove_r1cs_with_pcs_and_spark_hooks<T, C, O, S>(
    instance: &R1csInstance,
    witness: &[FieldElement],
    workers: usize,
    pcs_params: DistributedPcsParams,
    transcript: &mut T,
    hooks: R1csProverHooks<C, O, S>,
) -> R1csPiopResult<R1csPiopProof>
where
    T: Transcript,
    C: FnMut(&[FieldElement], usize) -> R1csPiopResult<DistributedCommitment>,
    O: FnMut(
        &[FieldElement],
        &DistributedCommitment,
        &[FieldElement],
        DistributedPcsParams,
        &mut T,
    ) -> R1csPiopResult<R1csPcsOpening>,
    S: FnMut(
        Partition,
        SparkChallenges,
        &[FieldElement],
        &[FieldElement],
    ) -> R1csPiopResult<SparkWorkerShardClaim>,
{
    prove_r1cs_with_opening_hooks(instance, witness, workers, pcs_params, transcript, hooks)
}

pub fn prove_r1cs_with_pcs_and_spark_batch_hooks<T, C, O, S>(
    instance: &R1csInstance,
    witness: &[FieldElement],
    workers: usize,
    pcs_params: DistributedPcsParams,
    transcript: &mut T,
    hooks: R1csBatchProverHooks<C, O, S>,
) -> R1csPiopResult<R1csPiopProof>
where
    T: Transcript,
    C: FnMut(&[FieldElement], usize) -> R1csPiopResult<DistributedCommitment>,
    O: FnMut(
        &[FieldElement],
        &DistributedCommitment,
        &[FieldElement],
        DistributedPcsParams,
        &mut T,
    ) -> R1csPiopResult<R1csPcsOpening>,
    S: FnMut(&[SparkWorkerClaimRequest<'_>]) -> R1csPiopResult<Vec<SparkWorkerShardClaim>>,
{
    prove_r1cs_with_batch_opening_hooks(instance, witness, workers, pcs_params, transcript, hooks)
}

fn prove_r1cs_with_opening_hooks<T, C, O, S>(
    instance: &R1csInstance,
    witness: &[FieldElement],
    workers: usize,
    pcs_params: DistributedPcsParams,
    transcript: &mut T,
    hooks: R1csProverHooks<C, O, S>,
) -> R1csPiopResult<R1csPiopProof>
where
    T: Transcript,
    C: FnMut(&[FieldElement], usize) -> R1csPiopResult<DistributedCommitment>,
    O: FnMut(
        &[FieldElement],
        &DistributedCommitment,
        &[FieldElement],
        DistributedPcsParams,
        &mut T,
    ) -> R1csPiopResult<R1csPcsOpening>,
    S: FnMut(
        Partition,
        SparkChallenges,
        &[FieldElement],
        &[FieldElement],
    ) -> R1csPiopResult<SparkWorkerShardClaim>,
{
    let mut spark_worker_provider = hooks.spark_worker_provider;
    prove_r1cs_with_batch_opening_hooks(
        instance,
        witness,
        workers,
        pcs_params,
        transcript,
        R1csBatchProverHooks {
            commit_distributed: hooks.commit_distributed,
            open_distributed: hooks.open_distributed,
            spark_worker_provider: |requests: &[SparkWorkerClaimRequest<'_>]| {
                requests
                    .iter()
                    .map(|request| {
                        spark_worker_provider(
                            request.partition,
                            request.challenges,
                            request.row_point,
                            request.col_point,
                        )
                    })
                    .collect()
            },
        },
    )
}

fn prove_r1cs_with_batch_opening_hooks<T, C, O, S>(
    instance: &R1csInstance,
    witness: &[FieldElement],
    workers: usize,
    pcs_params: DistributedPcsParams,
    transcript: &mut T,
    mut hooks: R1csBatchProverHooks<C, O, S>,
) -> R1csPiopResult<R1csPiopProof>
where
    T: Transcript,
    C: FnMut(&[FieldElement], usize) -> R1csPiopResult<DistributedCommitment>,
    O: FnMut(
        &[FieldElement],
        &DistributedCommitment,
        &[FieldElement],
        DistributedPcsParams,
        &mut T,
    ) -> R1csPiopResult<R1csPcsOpening>,
    S: FnMut(&[SparkWorkerClaimRequest<'_>]) -> R1csPiopResult<Vec<SparkWorkerShardClaim>>,
{
    let trace = trace_r1cs_enabled();
    let phase = Instant::now();
    if !instance
        .is_satisfied(witness)
        .map_err(|_| R1csPiopError::Unsatisfied)?
    {
        return Err(R1csPiopError::Unsatisfied);
    }
    trace_r1cs_phase(trace, "prove/is_satisfied", phase.elapsed());
    let phase = Instant::now();
    let vectors = constraint_vectors(instance, witness)?;
    trace_r1cs_phase(trace, "prove/constraint_vectors", phase.elapsed());
    let phase = Instant::now();
    transcript.absorb_domain(b"r1cs-piop-v1");
    absorb_instance_shape(instance, workers, transcript);
    let oracle_commitments = commit_oracles(&vectors)?;
    absorb_oracle_commitments(&oracle_commitments, transcript);
    trace_r1cs_phase(trace, "prove/oracle_commitments", phase.elapsed());
    let phase = Instant::now();
    let outer_commitments =
        commit_outer_linearizations(&vectors, workers, &mut hooks.commit_distributed)?;
    absorb_outer_commitments(&outer_commitments, transcript);
    trace_r1cs_phase(trace, "prove/outer_commitments", phase.elapsed());
    let phase = Instant::now();
    let az_poly =
        MultilinearPolynomial::new(vectors.az.clone()).map_err(|_| R1csPiopError::InvalidShape)?;
    let bz_poly =
        MultilinearPolynomial::new(vectors.bz.clone()).map_err(|_| R1csPiopError::InvalidShape)?;
    let cz_poly =
        MultilinearPolynomial::new(vectors.cz.clone()).map_err(|_| R1csPiopError::InvalidShape)?;
    let outer_sumcheck = prove_cubic_zerocheck(&az_poly, &bz_poly, &cz_poly, transcript)
        .map_err(|_| R1csPiopError::Sumcheck)?;
    trace_r1cs_phase(trace, "prove/outer_sumcheck", phase.elapsed());
    let phase = Instant::now();
    let outer_openings = open_outer_linearizations(
        &vectors,
        &outer_commitments,
        &outer_sumcheck.challenges,
        pcs_params,
        transcript,
        &mut hooks.open_distributed,
    )?;
    trace_r1cs_phase(trace, "prove/outer_openings", phase.elapsed());
    let phase = Instant::now();
    let inner = prove_inner_linearization(
        instance,
        &vectors,
        &outer_openings,
        InnerLinearizationConfig {
            workers,
            pcs_params,
        },
        transcript,
        &mut hooks.commit_distributed,
        &mut hooks.open_distributed,
    )?;
    trace_r1cs_phase(trace, "prove/inner_linearization", phase.elapsed());
    let phase = Instant::now();
    let witness_consistency_indices = challenge_witness_consistency_indices(
        &oracle_commitments.witness,
        &inner.witness_commitment,
        pcs_params,
        transcript,
    )?;
    let witness_consistency_queries = open_witness_consistency_queries(
        &vectors,
        &oracle_commitments,
        &inner.witness_commitment,
        &witness_consistency_indices,
    )?;
    absorb_witness_consistency_queries(transcript, &witness_consistency_queries);
    trace_r1cs_phase(trace, "prove/witness_consistency", phase.elapsed());
    let phase = Instant::now();
    let residual_commitment = (hooks.commit_distributed)(&vectors.residual, workers)?;
    DistributedBrakedown::absorb_distributed_commitment(&residual_commitment, transcript);
    trace_r1cs_phase(trace, "prove/residual_commitment", phase.elapsed());
    let phase = Instant::now();
    let residual_poly = MultilinearPolynomial::new(vectors.residual.clone())
        .map_err(|_| R1csPiopError::InvalidShape)?;
    let sumcheck =
        prove_zerocheck_proof(&residual_poly, transcript).map_err(|_| R1csPiopError::Sumcheck)?;
    let point = sumcheck.challenges.clone();
    let residual_opening = (hooks.open_distributed)(
        &vectors.residual,
        &residual_commitment,
        &point,
        pcs_params,
        transcript,
    )?;
    trace_r1cs_phase(trace, "prove/residual_sumcheck_open", phase.elapsed());
    let phase = Instant::now();
    let row_indices = challenge_row_indices(instance, pcs_params, transcript)?;
    let row_queries = row_indices
        .iter()
        .copied()
        .map(|row| {
            open_row_query(
                instance,
                &vectors,
                &oracle_commitments,
                &residual_commitment,
                row,
            )
        })
        .collect::<R1csPiopResult<Vec<_>>>()?;
    absorb_row_consistency_queries(transcript, &row_queries);
    trace_r1cs_phase(trace, "prove/row_queries", phase.elapsed());
    let phase = Instant::now();
    let spark = prove_distributed_spark_with_batch_worker_provider(
        instance,
        workers,
        pcs_params,
        &outer_sumcheck.challenges,
        &inner.sumcheck.challenges,
        inner.matrix_challenges,
        transcript,
        &mut hooks.spark_worker_provider,
    )?;
    trace_r1cs_phase(trace, "prove/spark", phase.elapsed());
    let phase = Instant::now();
    verify_inner_spark_link(&inner, &spark)?;
    trace_r1cs_phase(trace, "prove/inner_spark_link", phase.elapsed());
    Ok(R1csPiopProof {
        oracle_commitments,
        outer_commitments,
        outer_openings,
        outer_sumcheck,
        inner,
        witness_consistency_queries,
        residual_commitment,
        residual_opening,
        sumcheck,
        row_queries,
        spark,
        workers,
    })
}

pub fn verify_r1cs<T: Transcript>(
    instance: &R1csInstance,
    proof: &R1csPiopProof,
    transcript: &mut T,
) -> R1csPiopResult<R1csMetrics> {
    verify_r1cs_with_pcs_params(instance, proof, DistributedPcsParams::default(), transcript)
}

pub fn verify_r1cs_with_pcs_params<T: Transcript>(
    instance: &R1csInstance,
    proof: &R1csPiopProof,
    pcs_params: DistributedPcsParams,
    transcript: &mut T,
) -> R1csPiopResult<R1csMetrics> {
    if proof.workers == 0 || proof.workers != proof.residual_commitment.workers.len() {
        return Err(R1csPiopError::InvalidShape);
    }
    validate_commitment_shape(instance, proof)?;
    transcript.absorb_domain(b"r1cs-piop-v1");
    absorb_instance_shape(instance, proof.workers, transcript);
    absorb_oracle_commitments(&proof.oracle_commitments, transcript);
    absorb_outer_commitments(&proof.outer_commitments, transcript);
    let row_vars = log2_power_of_two(proof.outer_commitments.az.original_len)
        .map_err(|_| R1csPiopError::InvalidShape)?;
    verify_cubic_zerocheck_rounds(row_vars, &proof.outer_sumcheck, transcript)
        .map_err(|_| R1csPiopError::Sumcheck)?;
    verify_outer_openings(
        &proof.outer_commitments,
        &proof.outer_openings,
        &proof.outer_sumcheck,
        pcs_params,
        transcript,
    )?;
    verify_inner_linearization(
        instance,
        &proof.inner,
        &proof.outer_openings,
        pcs_params,
        transcript,
    )?;
    let witness_consistency_indices = challenge_witness_consistency_indices(
        &proof.oracle_commitments.witness,
        &proof.inner.witness_commitment,
        pcs_params,
        transcript,
    )?;
    verify_witness_consistency_queries(
        &proof.oracle_commitments,
        &proof.inner.witness_commitment,
        &witness_consistency_indices,
        &proof.witness_consistency_queries,
    )?;
    absorb_witness_consistency_queries(transcript, &proof.witness_consistency_queries);
    DistributedBrakedown::absorb_distributed_commitment(&proof.residual_commitment, transcript);
    let num_vars = log2_power_of_two(proof.residual_commitment.original_len)
        .map_err(|_| R1csPiopError::InvalidShape)?;
    verify_zerocheck_rounds(num_vars, &proof.sumcheck, transcript)
        .map_err(|_| R1csPiopError::Sumcheck)?;
    if proof.residual_opening.point() != proof.sumcheck.challenges.as_slice() {
        return Err(R1csPiopError::InvalidProof);
    }
    let expected_final =
        zerocheck_final_evaluation(&proof.sumcheck, proof.residual_opening.claimed_value())
            .map_err(|_| R1csPiopError::InvalidProof)?;
    if expected_final != proof.sumcheck.final_evaluation {
        return Err(R1csPiopError::InvalidProof);
    }
    proof.residual_opening.verify_after_commitment(
        &proof.residual_commitment,
        pcs_params,
        transcript,
    )?;
    let row_indices = challenge_row_indices(instance, pcs_params, transcript)?;
    if row_indices.len() != proof.row_queries.len() {
        return Err(R1csPiopError::InvalidProof);
    }
    for (expected_row, query) in row_indices.iter().zip(&proof.row_queries) {
        if *expected_row != query.row {
            return Err(R1csPiopError::InvalidProof);
        }
        verify_row_query(
            instance,
            &proof.oracle_commitments,
            &proof.residual_commitment,
            query,
        )?;
    }
    absorb_row_consistency_queries(transcript, &proof.row_queries);
    verify_distributed_spark(
        instance,
        proof.workers,
        pcs_params,
        &proof.outer_sumcheck.challenges,
        &proof.inner.sumcheck.challenges,
        proof.inner.matrix_challenges,
        &proof.spark,
        transcript,
    )?;
    verify_inner_spark_link(&proof.inner, &proof.spark)?;
    Ok(R1csMetrics {
        proof_bytes: proof_size_bytes(proof),
        communication_bytes: proof_communication_bytes(proof),
    })
}

pub fn residual_evaluations(
    instance: &R1csInstance,
    witness: &[FieldElement],
) -> R1csPiopResult<Vec<FieldElement>> {
    let az = instance
        .a()
        .mul_vec(witness)
        .map_err(|_| R1csPiopError::InvalidShape)?;
    let bz = instance
        .b()
        .mul_vec(witness)
        .map_err(|_| R1csPiopError::InvalidShape)?;
    let cz = instance
        .c()
        .mul_vec(witness)
        .map_err(|_| R1csPiopError::InvalidShape)?;
    let mut out = az
        .iter()
        .zip(bz.iter())
        .zip(cz.iter())
        .map(|((a, b), c)| *a * *b - *c)
        .collect::<Vec<_>>();
    let next = out.len().next_power_of_two();
    out.resize(next, FieldElement::ZERO);
    let _ = log2_power_of_two(out.len()).map_err(|_| R1csPiopError::InvalidShape)?;
    Ok(out)
}

fn constraint_vectors(
    instance: &R1csInstance,
    witness: &[FieldElement],
) -> R1csPiopResult<ConstraintVectors> {
    let values = instance
        .constraint_values(witness)
        .map_err(|_| R1csPiopError::InvalidShape)?;
    let mut az = Vec::with_capacity(values.len());
    let mut bz = Vec::with_capacity(values.len());
    let mut cz = Vec::with_capacity(values.len());
    let mut residual = Vec::with_capacity(values.len());
    for (a, b, c) in values {
        az.push(a);
        bz.push(b);
        cz.push(c);
        residual.push(a * b - c);
    }
    let row_len = residual.len().max(1).next_power_of_two();
    az.resize(row_len, FieldElement::ZERO);
    bz.resize(row_len, FieldElement::ZERO);
    cz.resize(row_len, FieldElement::ZERO);
    residual.resize(row_len, FieldElement::ZERO);
    let mut witness = witness.to_vec();
    let witness_len = witness.len().max(1).next_power_of_two();
    witness.resize(witness_len, FieldElement::ZERO);
    Ok(ConstraintVectors {
        witness,
        az,
        bz,
        cz,
        residual,
    })
}

fn trace_r1cs_enabled() -> bool {
    std::env::var_os("PQ_DSNARK_TRACE_R1CS").is_some()
}

fn trace_r1cs_phase(enabled: bool, label: &str, elapsed: Duration) {
    if enabled {
        eprintln!(
            "[r1cs trace] {label}: {:.3} ms",
            elapsed.as_secs_f64() * 1000.0
        );
    }
}

fn commit_oracles(vectors: &ConstraintVectors) -> R1csPiopResult<R1csOracleCommitments> {
    Ok(R1csOracleCommitments {
        witness: MerklePcs::commit(&vectors.witness).map_err(|_| R1csPiopError::Pcs)?,
        az: MerklePcs::commit(&vectors.az).map_err(|_| R1csPiopError::Pcs)?,
        bz: MerklePcs::commit(&vectors.bz).map_err(|_| R1csPiopError::Pcs)?,
        cz: MerklePcs::commit(&vectors.cz).map_err(|_| R1csPiopError::Pcs)?,
    })
}

fn commit_outer_linearizations<C>(
    vectors: &ConstraintVectors,
    workers: usize,
    commit_distributed: &mut C,
) -> R1csPiopResult<R1csOuterCommitments>
where
    C: FnMut(&[FieldElement], usize) -> R1csPiopResult<DistributedCommitment>,
{
    Ok(R1csOuterCommitments {
        az: commit_distributed(&vectors.az, workers)?,
        bz: commit_distributed(&vectors.bz, workers)?,
        cz: commit_distributed(&vectors.cz, workers)?,
    })
}

fn open_outer_linearizations<T, O>(
    vectors: &ConstraintVectors,
    commitments: &R1csOuterCommitments,
    point: &[FieldElement],
    pcs_params: DistributedPcsParams,
    transcript: &mut T,
    open_distributed: &mut O,
) -> R1csPiopResult<R1csOuterOpenings>
where
    T: Transcript,
    O: FnMut(
        &[FieldElement],
        &DistributedCommitment,
        &[FieldElement],
        DistributedPcsParams,
        &mut T,
    ) -> R1csPiopResult<R1csPcsOpening>,
{
    Ok(R1csOuterOpenings {
        az: open_distributed(&vectors.az, &commitments.az, point, pcs_params, transcript)?,
        bz: open_distributed(&vectors.bz, &commitments.bz, point, pcs_params, transcript)?,
        cz: open_distributed(&vectors.cz, &commitments.cz, point, pcs_params, transcript)?,
    })
}

fn verify_outer_openings<T: Transcript>(
    commitments: &R1csOuterCommitments,
    openings: &R1csOuterOpenings,
    sumcheck: &CubicZerocheckProof,
    pcs_params: DistributedPcsParams,
    transcript: &mut T,
) -> R1csPiopResult<()> {
    for opening in [&openings.az, &openings.bz, &openings.cz] {
        if opening.point() != sumcheck.challenges.as_slice() {
            return Err(R1csPiopError::InvalidProof);
        }
    }
    openings
        .az
        .verify_after_commitment(&commitments.az, pcs_params, transcript)?;
    openings
        .bz
        .verify_after_commitment(&commitments.bz, pcs_params, transcript)?;
    openings
        .cz
        .verify_after_commitment(&commitments.cz, pcs_params, transcript)?;
    let expected_final = cubic_zerocheck_final_evaluation(
        sumcheck,
        openings.az.claimed_value(),
        openings.bz.claimed_value(),
        openings.cz.claimed_value(),
    )
    .map_err(|_| R1csPiopError::InvalidProof)?;
    if expected_final != sumcheck.final_evaluation {
        return Err(R1csPiopError::InvalidProof);
    }
    Ok(())
}

fn prove_inner_linearization<T, C, O>(
    instance: &R1csInstance,
    vectors: &ConstraintVectors,
    outer_openings: &R1csOuterOpenings,
    config: InnerLinearizationConfig,
    transcript: &mut T,
    commit_distributed: &mut C,
    open_distributed: &mut O,
) -> R1csPiopResult<R1csInnerProof>
where
    T: Transcript,
    C: FnMut(&[FieldElement], usize) -> R1csPiopResult<DistributedCommitment>,
    O: FnMut(
        &[FieldElement],
        &DistributedCommitment,
        &[FieldElement],
        DistributedPcsParams,
        &mut T,
    ) -> R1csPiopResult<R1csPcsOpening>,
{
    let witness_commitment = commit_distributed(&vectors.witness, config.workers)?;
    let matrix_challenges =
        derive_inner_matrix_challenges(outer_openings, &witness_commitment, transcript);
    let projected = projected_matrix_vector(
        instance,
        outer_openings.az.point(),
        matrix_challenges,
        vectors.witness.len(),
    )?;
    let projected_poly =
        MultilinearPolynomial::new(projected.clone()).map_err(|_| R1csPiopError::InvalidShape)?;
    let witness_poly = MultilinearPolynomial::new(vectors.witness.clone())
        .map_err(|_| R1csPiopError::InvalidShape)?;
    let claimed_sum = inner_linearization_claim(outer_openings, matrix_challenges);
    let sumcheck = prove_product_sumcheck(&projected_poly, &witness_poly, claimed_sum, transcript)
        .map_err(|_| R1csPiopError::Sumcheck)?;
    let witness_opening = open_distributed(
        &vectors.witness,
        &witness_commitment,
        &sumcheck.challenges,
        config.pcs_params,
        transcript,
    )?;
    let projected_eval =
        evaluate_mle(&projected, &sumcheck.challenges).map_err(|_| R1csPiopError::InvalidProof)?;
    if projected_eval * witness_opening.claimed_value() != sumcheck.final_evaluation {
        return Err(R1csPiopError::InvalidProof);
    }
    Ok(R1csInnerProof {
        matrix_challenges,
        witness_commitment,
        sumcheck,
        witness_opening,
    })
}

fn verify_inner_linearization<T: Transcript>(
    _instance: &R1csInstance,
    proof: &R1csInnerProof,
    outer_openings: &R1csOuterOpenings,
    pcs_params: DistributedPcsParams,
    transcript: &mut T,
) -> R1csPiopResult<()> {
    let matrix_challenges =
        derive_inner_matrix_challenges(outer_openings, &proof.witness_commitment, transcript);
    if proof.matrix_challenges != matrix_challenges {
        return Err(R1csPiopError::InvalidProof);
    }
    let witness_vars = log2_power_of_two(proof.witness_commitment.original_len)
        .map_err(|_| R1csPiopError::InvalidShape)?;
    let claimed_sum = inner_linearization_claim(outer_openings, matrix_challenges);
    verify_product_sumcheck_rounds(witness_vars, claimed_sum, &proof.sumcheck, transcript)
        .map_err(|_| R1csPiopError::Sumcheck)?;
    if proof.witness_opening.point() != proof.sumcheck.challenges.as_slice() {
        return Err(R1csPiopError::InvalidProof);
    }
    proof.witness_opening.verify_after_commitment(
        &proof.witness_commitment,
        pcs_params,
        transcript,
    )?;
    Ok(())
}

fn verify_inner_spark_link(
    inner: &R1csInnerProof,
    spark: &DistributedSparkProof,
) -> R1csPiopResult<()> {
    if spark.combined_evaluation * inner.witness_opening.claimed_value()
        != inner.sumcheck.final_evaluation
    {
        return Err(R1csPiopError::InvalidProof);
    }
    Ok(())
}

fn derive_inner_matrix_challenges<T: Transcript>(
    outer_openings: &R1csOuterOpenings,
    witness_commitment: &DistributedCommitment,
    transcript: &mut T,
) -> [FieldElement; 3] {
    DistributedBrakedown::absorb_distributed_commitment(witness_commitment, transcript);
    transcript.absorb_domain(b"r1cs-spartan-inner-linearization-v1");
    for coordinate in outer_openings.az.point() {
        transcript.absorb_field(b"outer-row-point", *coordinate);
    }
    transcript.absorb_field(b"outer-az", outer_openings.az.claimed_value());
    transcript.absorb_field(b"outer-bz", outer_openings.bz.claimed_value());
    transcript.absorb_field(b"outer-cz", outer_openings.cz.claimed_value());
    [
        transcript.challenge_field::<FieldElement>(b"inner-combine-a"),
        transcript.challenge_field::<FieldElement>(b"inner-combine-b"),
        transcript.challenge_field::<FieldElement>(b"inner-combine-c"),
    ]
}

fn projected_matrix_vector(
    instance: &R1csInstance,
    row_point: &[FieldElement],
    matrix_challenges: [FieldElement; 3],
    witness_len: usize,
) -> R1csPiopResult<Vec<FieldElement>> {
    if witness_len < instance.num_variables() || !witness_len.is_power_of_two() {
        return Err(R1csPiopError::InvalidShape);
    }
    let row_len = instance.num_constraints().max(1).next_power_of_two();
    let row_vars = log2_power_of_two(row_len).map_err(|_| R1csPiopError::InvalidShape)?;
    if row_point.len() != row_vars {
        return Err(R1csPiopError::InvalidProof);
    }
    let mut projected = vec![FieldElement::ZERO; witness_len];
    for (matrix, challenge) in [
        (instance.a(), matrix_challenges[0]),
        (instance.b(), matrix_challenges[1]),
        (instance.c(), matrix_challenges[2]),
    ] {
        for entry in matrix.entries() {
            let row_weight =
                eq_basis(row_point, entry.row).map_err(|_| R1csPiopError::InvalidProof)?;
            projected[entry.col] += challenge * row_weight * entry.value;
        }
    }
    Ok(projected)
}

fn inner_linearization_claim(
    outer_openings: &R1csOuterOpenings,
    matrix_challenges: [FieldElement; 3],
) -> FieldElement {
    matrix_challenges[0] * outer_openings.az.claimed_value()
        + matrix_challenges[1] * outer_openings.bz.claimed_value()
        + matrix_challenges[2] * outer_openings.cz.claimed_value()
}

fn validate_commitment_shape(instance: &R1csInstance, proof: &R1csPiopProof) -> R1csPiopResult<()> {
    let expected_witness_len = instance.num_variables().max(1).next_power_of_two();
    let expected_row_len = instance.num_constraints().max(1).next_power_of_two();
    if proof.oracle_commitments.witness.len != expected_witness_len
        || proof.oracle_commitments.az.len != expected_row_len
        || proof.oracle_commitments.bz.len != expected_row_len
        || proof.oracle_commitments.cz.len != expected_row_len
        || proof.outer_commitments.az.original_len != expected_row_len
        || proof.outer_commitments.bz.original_len != expected_row_len
        || proof.outer_commitments.cz.original_len != expected_row_len
        || proof.inner.witness_commitment.original_len != expected_witness_len
        || proof.inner.witness_commitment.workers.len() != proof.workers
        || proof.residual_commitment.original_len != expected_row_len
    {
        return Err(R1csPiopError::InvalidShape);
    }
    validate_row_domain_commitment(&proof.outer_commitments.az, expected_row_len, proof.workers)?;
    validate_row_domain_commitment(&proof.outer_commitments.bz, expected_row_len, proof.workers)?;
    validate_row_domain_commitment(&proof.outer_commitments.cz, expected_row_len, proof.workers)?;
    validate_row_domain_commitment(&proof.residual_commitment, expected_row_len, proof.workers)?;
    Ok(())
}

fn validate_row_domain_commitment(
    commitment: &DistributedCommitment,
    expected_row_len: usize,
    workers: usize,
) -> R1csPiopResult<()> {
    if commitment.original_len != expected_row_len || commitment.workers.len() != workers {
        return Err(R1csPiopError::InvalidShape);
    }
    let plan = PartitionPlan::balanced(expected_row_len, workers)
        .map_err(|_| R1csPiopError::InvalidShape)?;
    for (partition, worker) in plan.partitions().iter().zip(&commitment.workers) {
        if worker.worker_id != partition.id || worker.range != (partition.start, partition.end) {
            return Err(R1csPiopError::InvalidShape);
        }
    }
    Ok(())
}

fn challenge_witness_consistency_indices<T: Transcript>(
    oracle_commitment: &Commitment,
    distributed_commitment: &DistributedCommitment,
    pcs_params: DistributedPcsParams,
    transcript: &mut T,
) -> R1csPiopResult<Vec<usize>> {
    if oracle_commitment.len != distributed_commitment.original_len {
        return Err(R1csPiopError::InvalidShape);
    }
    let query_count = pcs_params
        .effective_query_count(oracle_commitment.len)
        .map_err(|_| R1csPiopError::InvalidShape)?;
    transcript.absorb_domain(b"r1cs-witness-commitment-consistency-v1");
    transcript.absorb_public(
        b"r1cs-witness-consistency-len",
        &(oracle_commitment.len as u64).to_le_bytes(),
    );
    transcript.absorb_public(
        b"r1cs-witness-consistency-requested-query-count",
        &(pcs_params.query_count as u64).to_le_bytes(),
    );
    transcript.absorb_public(
        b"r1cs-witness-consistency-query-count",
        &(query_count as u64).to_le_bytes(),
    );
    absorb_merkle_commitment(transcript, b"r1cs-witness-oracle", oracle_commitment);
    DistributedBrakedown::absorb_distributed_commitment(distributed_commitment, transcript);
    Ok(transcript.challenge_indices(
        b"r1cs-witness-consistency-query",
        query_count,
        oracle_commitment.len,
    ))
}

fn open_witness_consistency_queries(
    vectors: &ConstraintVectors,
    commitments: &R1csOracleCommitments,
    distributed_commitment: &DistributedCommitment,
    indices: &[usize],
) -> R1csPiopResult<Vec<R1csWitnessConsistencyQuery>> {
    indices
        .iter()
        .copied()
        .map(|index| {
            Ok(R1csWitnessConsistencyQuery {
                index,
                oracle_opening: MerklePcs::open(&vectors.witness, index)
                    .map_err(|_| R1csPiopError::Pcs)?,
                distributed_opening: DistributedBrakedown::open_index(
                    &vectors.witness,
                    distributed_commitment,
                    index,
                )
                .map_err(|_| R1csPiopError::Pcs)?,
            })
        })
        .collect::<R1csPiopResult<Vec<_>>>()
        .and_then(|queries| {
            for query in &queries {
                MerklePcs::verify(&commitments.witness, &query.oracle_opening)
                    .map_err(|_| R1csPiopError::Pcs)?;
            }
            Ok(queries)
        })
}

fn verify_witness_consistency_queries(
    commitments: &R1csOracleCommitments,
    distributed_commitment: &DistributedCommitment,
    expected_indices: &[usize],
    queries: &[R1csWitnessConsistencyQuery],
) -> R1csPiopResult<()> {
    if expected_indices.len() != queries.len() {
        return Err(R1csPiopError::InvalidProof);
    }
    for (expected, query) in expected_indices.iter().copied().zip(queries) {
        if query.index != expected
            || query.oracle_opening.index != expected
            || query.distributed_opening.global_index != expected
        {
            return Err(R1csPiopError::InvalidProof);
        }
        MerklePcs::verify(&commitments.witness, &query.oracle_opening)
            .map_err(|_| R1csPiopError::Pcs)?;
        let distributed_value =
            DistributedBrakedown::verify_index(distributed_commitment, &query.distributed_opening)
                .map_err(|_| R1csPiopError::Pcs)?;
        if query.oracle_opening.value != distributed_value {
            return Err(R1csPiopError::InvalidProof);
        }
    }
    Ok(())
}

fn open_row_query(
    instance: &R1csInstance,
    vectors: &ConstraintVectors,
    commitments: &R1csOracleCommitments,
    residual_commitment: &DistributedCommitment,
    row: usize,
) -> R1csPiopResult<R1csRowConsistencyQuery> {
    let columns = row_columns(instance, row);
    let witness_openings = columns
        .into_iter()
        .map(|column| MerklePcs::open(&vectors.witness, column).map_err(|_| R1csPiopError::Pcs))
        .collect::<R1csPiopResult<Vec<_>>>()?;
    let az_opening = MerklePcs::open(&vectors.az, row).map_err(|_| R1csPiopError::Pcs)?;
    let bz_opening = MerklePcs::open(&vectors.bz, row).map_err(|_| R1csPiopError::Pcs)?;
    let cz_opening = MerklePcs::open(&vectors.cz, row).map_err(|_| R1csPiopError::Pcs)?;
    if commitments.az.len <= row || commitments.bz.len <= row || commitments.cz.len <= row {
        return Err(R1csPiopError::InvalidShape);
    }
    let residual_opening =
        DistributedBrakedown::open_index(&vectors.residual, residual_commitment, row)
            .map_err(|_| R1csPiopError::Pcs)?;
    Ok(R1csRowConsistencyQuery {
        row,
        witness_openings,
        az_opening,
        bz_opening,
        cz_opening,
        residual_opening,
    })
}

fn verify_row_query(
    instance: &R1csInstance,
    commitments: &R1csOracleCommitments,
    residual_commitment: &DistributedCommitment,
    query: &R1csRowConsistencyQuery,
) -> R1csPiopResult<()> {
    if query.row >= instance.num_constraints() {
        return Err(R1csPiopError::InvalidProof);
    }
    let witness_values = verify_witness_openings(instance, commitments, query)?;
    verify_vector_opening(&commitments.az, &query.az_opening, query.row)?;
    verify_vector_opening(&commitments.bz, &query.bz_opening, query.row)?;
    verify_vector_opening(&commitments.cz, &query.cz_opening, query.row)?;
    let residual_value =
        DistributedBrakedown::verify_index(residual_commitment, &query.residual_opening)
            .map_err(|_| R1csPiopError::Pcs)?;
    if query.residual_opening.global_index != query.row {
        return Err(R1csPiopError::InvalidProof);
    }

    let az = row_dot_from_openings(instance.a(), query.row, &witness_values)?;
    let bz = row_dot_from_openings(instance.b(), query.row, &witness_values)?;
    let cz = row_dot_from_openings(instance.c(), query.row, &witness_values)?;
    if az != query.az_opening.value
        || bz != query.bz_opening.value
        || cz != query.cz_opening.value
        || az * bz - cz != residual_value
    {
        return Err(R1csPiopError::InvalidProof);
    }
    Ok(())
}

fn verify_witness_openings(
    instance: &R1csInstance,
    commitments: &R1csOracleCommitments,
    query: &R1csRowConsistencyQuery,
) -> R1csPiopResult<Vec<(usize, FieldElement)>> {
    let expected_columns = row_columns(instance, query.row);
    if expected_columns.len() != query.witness_openings.len() {
        return Err(R1csPiopError::InvalidProof);
    }
    let mut values = Vec::with_capacity(query.witness_openings.len());
    for (expected, opening) in expected_columns.iter().zip(&query.witness_openings) {
        if opening.index != *expected || opening.index >= instance.num_variables() {
            return Err(R1csPiopError::InvalidProof);
        }
        MerklePcs::verify(&commitments.witness, opening).map_err(|_| R1csPiopError::Pcs)?;
        values.push((opening.index, opening.value));
    }
    Ok(values)
}

fn verify_vector_opening(
    commitment: &Commitment,
    opening: &OpeningProof,
    expected_index: usize,
) -> R1csPiopResult<()> {
    if opening.index != expected_index {
        return Err(R1csPiopError::InvalidProof);
    }
    MerklePcs::verify(commitment, opening).map_err(|_| R1csPiopError::Pcs)
}

fn absorb_row_consistency_queries<T: Transcript>(
    transcript: &mut T,
    queries: &[R1csRowConsistencyQuery],
) {
    transcript.absorb_domain(b"r1cs-row-consistency-query-openings-v1");
    transcript.absorb_public(
        b"r1cs-row-query-count",
        &(queries.len() as u64).to_le_bytes(),
    );
    for query in queries {
        transcript.absorb_public(b"r1cs-row-query-row", &(query.row as u64).to_le_bytes());
        transcript.absorb_public(
            b"r1cs-row-query-witness-opening-count",
            &(query.witness_openings.len() as u64).to_le_bytes(),
        );
        for (position, opening) in query.witness_openings.iter().enumerate() {
            transcript.absorb_public(
                b"r1cs-row-query-witness-position",
                &(position as u64).to_le_bytes(),
            );
            absorb_opening_proof(transcript, b"r1cs-row-query-witness", opening);
        }
        absorb_opening_proof(transcript, b"r1cs-row-query-az", &query.az_opening);
        absorb_opening_proof(transcript, b"r1cs-row-query-bz", &query.bz_opening);
        absorb_opening_proof(transcript, b"r1cs-row-query-cz", &query.cz_opening);
        absorb_distributed_index_opening(
            transcript,
            b"r1cs-row-query-residual",
            &query.residual_opening,
        );
    }
}

fn absorb_distributed_index_opening<T: Transcript>(
    transcript: &mut T,
    label: &'static [u8],
    opening: &DistributedIndexOpening,
) {
    transcript.absorb_domain(b"r1cs-distributed-index-opening-v1");
    transcript.absorb_public(label, &(opening.global_index as u64).to_le_bytes());
    transcript.absorb_public(
        b"r1cs-distributed-index-worker",
        &(opening.worker_id as u64).to_le_bytes(),
    );
    transcript.absorb_public(
        b"r1cs-distributed-index-local",
        &(opening.local_index as u64).to_le_bytes(),
    );
    absorb_opening_proof(transcript, b"r1cs-distributed-index-proof", &opening.proof);
}

fn absorb_witness_consistency_queries<T: Transcript>(
    transcript: &mut T,
    queries: &[R1csWitnessConsistencyQuery],
) {
    transcript.absorb_domain(b"r1cs-witness-consistency-queries-v1");
    transcript.absorb_public(
        b"r1cs-witness-consistency-query-count",
        &(queries.len() as u64).to_le_bytes(),
    );
    for query in queries {
        transcript.absorb_public(
            b"r1cs-witness-consistency-index",
            &(query.index as u64).to_le_bytes(),
        );
        absorb_opening_proof(
            transcript,
            b"r1cs-witness-consistency-oracle",
            &query.oracle_opening,
        );
        absorb_distributed_index_opening(
            transcript,
            b"r1cs-witness-consistency-distributed",
            &query.distributed_opening,
        );
    }
}

fn row_dot_from_openings(
    matrix: &SparseMatrix,
    row: usize,
    witness_values: &[(usize, FieldElement)],
) -> R1csPiopResult<FieldElement> {
    let mut acc = FieldElement::ZERO;
    for entry in matrix.entries().iter().filter(|entry| entry.row == row) {
        let value = witness_values
            .iter()
            .find_map(|(column, value)| (*column == entry.col).then_some(*value))
            .ok_or(R1csPiopError::InvalidProof)?;
        acc += entry.value * value;
    }
    Ok(acc)
}

fn row_columns(instance: &R1csInstance, row: usize) -> Vec<usize> {
    let mut columns = Vec::new();
    for matrix in [instance.a(), instance.b(), instance.c()] {
        for entry in matrix.entries().iter().filter(|entry| entry.row == row) {
            columns.push(entry.col);
        }
    }
    columns.sort_unstable();
    columns.dedup();
    columns
}

fn challenge_row_indices<T: Transcript>(
    instance: &R1csInstance,
    pcs_params: DistributedPcsParams,
    transcript: &mut T,
) -> R1csPiopResult<Vec<usize>> {
    let rows = instance.num_constraints();
    let query_count = pcs_params
        .effective_query_count(rows)
        .map_err(|_| R1csPiopError::InvalidShape)?;
    transcript.absorb_domain(b"r1cs-row-consistency-sampled-v1");
    transcript.absorb_public(b"rows", &(rows as u64).to_le_bytes());
    transcript.absorb_public(
        b"requested-query-count",
        &(pcs_params.query_count as u64).to_le_bytes(),
    );
    transcript.absorb_public(b"query-count", &(query_count as u64).to_le_bytes());
    Ok(transcript.challenge_indices(b"r1cs-row-consistency-query", query_count, rows))
}

fn absorb_oracle_commitments<T: Transcript>(
    commitments: &R1csOracleCommitments,
    transcript: &mut T,
) {
    absorb_merkle_commitment(transcript, b"witness", &commitments.witness);
    absorb_merkle_commitment(transcript, b"az", &commitments.az);
    absorb_merkle_commitment(transcript, b"bz", &commitments.bz);
    absorb_merkle_commitment(transcript, b"cz", &commitments.cz);
}

fn absorb_outer_commitments<T: Transcript>(commitments: &R1csOuterCommitments, transcript: &mut T) {
    DistributedBrakedown::absorb_distributed_commitment(&commitments.az, transcript);
    DistributedBrakedown::absorb_distributed_commitment(&commitments.bz, transcript);
    DistributedBrakedown::absorb_distributed_commitment(&commitments.cz, transcript);
}

fn absorb_merkle_commitment<T: Transcript>(
    transcript: &mut T,
    label: &'static [u8],
    commitment: &Commitment,
) {
    transcript.absorb_public(label, &(commitment.len as u64).to_le_bytes());
    transcript.absorb_commitment(label, &commitment.root);
}

pub fn proof_size_bytes(proof: &R1csPiopProof) -> usize {
    commitment_size_bytes(&proof.oracle_commitments.witness)
        + commitment_size_bytes(&proof.oracle_commitments.az)
        + commitment_size_bytes(&proof.oracle_commitments.bz)
        + commitment_size_bytes(&proof.oracle_commitments.cz)
        + distributed_commitment_size_bytes(&proof.outer_commitments.az)
        + distributed_commitment_size_bytes(&proof.outer_commitments.bz)
        + distributed_commitment_size_bytes(&proof.outer_commitments.cz)
        + proof.outer_openings.az.proof_size_bytes()
        + proof.outer_openings.bz.proof_size_bytes()
        + proof.outer_openings.cz.proof_size_bytes()
        + cubic_zerocheck_proof_size_bytes(&proof.outer_sumcheck)
        + inner_proof_size_bytes(&proof.inner)
        + vec_len_prefix()
        + proof
            .witness_consistency_queries
            .iter()
            .map(witness_consistency_query_size_bytes)
            .sum::<usize>()
        + distributed_commitment_size_bytes(&proof.residual_commitment)
        + proof.residual_opening.proof_size_bytes()
        + zerocheck_proof_size_bytes(&proof.sumcheck)
        + vec_len_prefix()
        + proof
            .row_queries
            .iter()
            .map(row_query_size_bytes)
            .sum::<usize>()
        + spark_proof_size_bytes(&proof.spark)
        + 8
}

pub fn proof_communication_bytes(proof: &R1csPiopProof) -> usize {
    proof.outer_openings.az.communication_bytes()
        + proof.outer_openings.bz.communication_bytes()
        + proof.outer_openings.cz.communication_bytes()
        + proof.inner.witness_opening.communication_bytes()
        + proof.residual_opening.communication_bytes()
        + proof
            .witness_consistency_queries
            .iter()
            .map(witness_consistency_query_communication_bytes)
            .sum::<usize>()
        + proof
            .row_queries
            .iter()
            .map(row_query_communication_bytes)
            .sum::<usize>()
}

fn row_query_size_bytes(query: &R1csRowConsistencyQuery) -> usize {
    8 + vec_len_prefix()
        + query
            .witness_openings
            .iter()
            .map(opening_proof_size_bytes)
            .sum::<usize>()
        + opening_proof_size_bytes(&query.az_opening)
        + opening_proof_size_bytes(&query.bz_opening)
        + opening_proof_size_bytes(&query.cz_opening)
        + distributed_index_opening_size_bytes(&query.residual_opening)
}

fn row_query_communication_bytes(query: &R1csRowConsistencyQuery) -> usize {
    distributed_index_communication_bytes(&query.residual_opening)
}

fn zerocheck_proof_size_bytes(proof: &ZerocheckProof) -> usize {
    field_vec_size(&proof.eq_point)
        + 8
        + vec_len_prefix()
        + proof.rounds.len() * 24
        + field_vec_size(&proof.challenges)
        + 8
}

fn cubic_zerocheck_proof_size_bytes(proof: &CubicZerocheckProof) -> usize {
    field_vec_size(&proof.eq_point)
        + 8
        + vec_len_prefix()
        + proof.rounds.len() * 32
        + field_vec_size(&proof.challenges)
        + 8
}

fn product_sumcheck_proof_size_bytes(proof: &ProductSumcheckProof) -> usize {
    8 + vec_len_prefix() + proof.rounds.len() * 24 + field_vec_size(&proof.challenges) + 8
}

fn inner_proof_size_bytes(proof: &R1csInnerProof) -> usize {
    3 * 8
        + distributed_commitment_size_bytes(&proof.witness_commitment)
        + product_sumcheck_proof_size_bytes(&proof.sumcheck)
        + proof.witness_opening.proof_size_bytes()
}

fn spark_proof_size_bytes(proof: &DistributedSparkProof) -> usize {
    5 * 8
        + 8
        + 2 * 8
        + vec_len_prefix()
        + proof.workers.len() * spark_worker_fingerprint_size_bytes()
        + 8
        + vec_len_prefix()
        + proof
            .matrix_evaluations
            .iter()
            .map(spark_matrix_evaluation_size_bytes)
            .sum::<usize>()
}

fn spark_worker_fingerprint_size_bytes() -> usize {
    8 + 16 + 8 + 2 * 8
}

fn spark_matrix_evaluation_size_bytes(proof: &SparkMatrixEvaluationProof) -> usize {
    2 * 8
        + vec_len_prefix()
        + proof.worker_evaluations.len() * spark_worker_evaluation_size_bytes()
        + spark_memory_check_size_bytes(&proof.row_memory)
        + spark_memory_check_size_bytes(&proof.col_memory)
        + spark_memory_check_size_bytes(&proof.value_memory)
}

fn spark_worker_evaluation_size_bytes() -> usize {
    8 + 8 + 16 + 8 + 8
}

fn spark_memory_check_size_bytes(proof: &SparkMemoryCheckProof) -> usize {
    3 * 8
        + spark_memory_trace_commitments_size_bytes(&proof.trace_commitments)
        + vec_len_prefix()
        + proof
            .domain_queries
            .iter()
            .map(spark_memory_domain_query_size_bytes)
            .sum::<usize>()
        + vec_len_prefix()
        + proof
            .access_queries
            .iter()
            .map(spark_memory_access_query_size_bytes)
            .sum::<usize>()
        + vec_len_prefix()
        + proof.worker_digests.len() * spark_memory_worker_digest_size_bytes()
        + product_multiset_equality_proof_size_bytes(&proof.multiset)
}

fn spark_memory_trace_commitments_size_bytes(commitments: &SparkMemoryTraceCommitments) -> usize {
    commitment_size_bytes(&commitments.init)
        + commitment_size_bytes(&commitments.writes)
        + commitment_size_bytes(&commitments.audit)
        + commitment_size_bytes(&commitments.reads)
}

fn spark_memory_domain_query_size_bytes(query: &SparkMemoryDomainQuery) -> usize {
    8 + opening_proof_size_bytes(&query.init) + opening_proof_size_bytes(&query.audit)
}

fn spark_memory_access_query_size_bytes(query: &SparkMemoryAccessQuery) -> usize {
    8 + opening_proof_size_bytes(&query.read)
        + opening_proof_size_bytes(&query.write)
        + 8
        + 8
        + 8
        + 8
}

fn witness_consistency_query_size_bytes(query: &R1csWitnessConsistencyQuery) -> usize {
    8 + opening_proof_size_bytes(&query.oracle_opening)
        + distributed_index_opening_size_bytes(&query.distributed_opening)
}

fn witness_consistency_query_communication_bytes(query: &R1csWitnessConsistencyQuery) -> usize {
    distributed_index_communication_bytes(&query.distributed_opening)
}

fn spark_memory_worker_digest_size_bytes() -> usize {
    8 + 16 + 16 + 8 + 4 * 8
}

fn product_multiset_equality_proof_size_bytes(proof: &ProductMultisetEqualityProof) -> usize {
    7 * 8
        + rational_sumcheck_proof_size_bytes(&proof.left_log_derivative)
        + rational_sumcheck_proof_size_bytes(&proof.right_log_derivative)
}

fn rational_sumcheck_proof_size_bytes(proof: &RationalSumcheckProof) -> usize {
    3 * 8 + sumcheck_proof_size_bytes(&proof.sumcheck)
}

fn sumcheck_proof_size_bytes(proof: &SumcheckProof) -> usize {
    8 + vec_len_prefix()
        + proof.rounds.len() * 2 * 8
        + vec_len_prefix()
        + proof.challenges.len() * 8
        + 8
}

fn field_vec_size(values: &[FieldElement]) -> usize {
    vec_len_prefix() + values.len() * 8
}

fn vec_len_prefix() -> usize {
    8
}

pub fn prove_distributed_spark<T: Transcript>(
    instance: &R1csInstance,
    workers: usize,
    pcs_params: DistributedPcsParams,
    row_point: &[FieldElement],
    col_point: &[FieldElement],
    matrix_challenges: [FieldElement; 3],
    transcript: &mut T,
) -> R1csPiopResult<DistributedSparkProof> {
    prove_distributed_spark_with_worker_provider(
        instance,
        workers,
        pcs_params,
        row_point,
        col_point,
        matrix_challenges,
        transcript,
        |partition, challenges, row_point, col_point| {
            compute_spark_worker_shard_claim(instance, partition, challenges, row_point, col_point)
        },
    )
}

#[allow(clippy::too_many_arguments)]
pub fn prove_distributed_spark_with_worker_provider<T, P>(
    instance: &R1csInstance,
    workers: usize,
    pcs_params: DistributedPcsParams,
    row_point: &[FieldElement],
    col_point: &[FieldElement],
    matrix_challenges: [FieldElement; 3],
    transcript: &mut T,
    worker_provider: P,
) -> R1csPiopResult<DistributedSparkProof>
where
    T: Transcript,
    P: FnMut(
        Partition,
        SparkChallenges,
        &[FieldElement],
        &[FieldElement],
    ) -> R1csPiopResult<SparkWorkerShardClaim>,
{
    let mut worker_provider = worker_provider;
    prove_distributed_spark_with_batch_worker_provider(
        instance,
        workers,
        pcs_params,
        row_point,
        col_point,
        matrix_challenges,
        transcript,
        |requests| {
            requests
                .iter()
                .map(|request| {
                    worker_provider(
                        request.partition,
                        request.challenges,
                        request.row_point,
                        request.col_point,
                    )
                })
                .collect()
        },
    )
}

#[allow(clippy::too_many_arguments)]
pub fn prove_distributed_spark_with_batch_worker_provider<T, P>(
    instance: &R1csInstance,
    workers: usize,
    pcs_params: DistributedPcsParams,
    row_point: &[FieldElement],
    col_point: &[FieldElement],
    matrix_challenges: [FieldElement; 3],
    transcript: &mut T,
    mut worker_provider: P,
) -> R1csPiopResult<DistributedSparkProof>
where
    T: Transcript,
    P: FnMut(&[SparkWorkerClaimRequest<'_>]) -> R1csPiopResult<Vec<SparkWorkerShardClaim>>,
{
    let (plan, challenges) = derive_spark_challenges(instance, workers, transcript)?;
    let requests = plan
        .partitions()
        .iter()
        .copied()
        .map(|partition| SparkWorkerClaimRequest {
            partition,
            challenges,
            row_point,
            col_point,
        })
        .collect::<Vec<_>>();
    let worker_claims = worker_provider(&requests)?;
    validate_spark_worker_claims(&plan, &worker_claims, instance_matrices(instance).len())?;
    let worker_fingerprints = worker_claims
        .iter()
        .map(|claim| claim.fingerprint.clone())
        .collect::<Vec<_>>();
    let mut total_entries = 0_usize;
    let mut linear_fingerprint = FieldElement::ZERO;
    let mut product_fingerprint = FieldElement::ONE;
    for worker in &worker_fingerprints {
        total_entries += worker.entry_count;
        linear_fingerprint += worker.linear_fingerprint;
        product_fingerprint *= worker.product_fingerprint;
    }
    let matrix_evaluations = prove_spark_matrix_evaluations_from_worker_claims(
        instance,
        &plan,
        pcs_params,
        row_point,
        col_point,
        transcript,
        &worker_claims,
    )?;
    let combined_evaluation = combine_spark_matrix_evaluations(
        &matrix_evaluations,
        matrix_challenges,
        instance_matrices(instance).len(),
    )?;
    Ok(DistributedSparkProof {
        tuple_challenge: challenges.tuple,
        matrix_challenge: challenges.matrix,
        row_challenge: challenges.row,
        col_challenge: challenges.col,
        value_challenge: challenges.value,
        total_entries,
        linear_fingerprint,
        product_fingerprint,
        workers: worker_fingerprints,
        combined_evaluation,
        matrix_evaluations,
    })
}

#[allow(clippy::too_many_arguments)]
fn verify_distributed_spark<T: Transcript>(
    instance: &R1csInstance,
    workers: usize,
    pcs_params: DistributedPcsParams,
    row_point: &[FieldElement],
    col_point: &[FieldElement],
    matrix_challenges: [FieldElement; 3],
    proof: &DistributedSparkProof,
    transcript: &mut T,
) -> R1csPiopResult<()> {
    let (plan, challenges) = derive_spark_challenges(instance, workers, transcript)?;
    if proof.tuple_challenge != challenges.tuple
        || proof.matrix_challenge != challenges.matrix
        || proof.row_challenge != challenges.row
        || proof.col_challenge != challenges.col
        || proof.value_challenge != challenges.value
    {
        return Err(R1csPiopError::InvalidProof);
    }
    let expected_workers = compute_spark_worker_fingerprints(instance, &plan, challenges)?;
    if proof.workers != expected_workers {
        return Err(R1csPiopError::InvalidProof);
    }
    let mut total_entries = 0_usize;
    let mut linear_fingerprint = FieldElement::ZERO;
    let mut product_fingerprint = FieldElement::ONE;
    for worker in &proof.workers {
        total_entries += worker.entry_count;
        linear_fingerprint += worker.linear_fingerprint;
        product_fingerprint *= worker.product_fingerprint;
    }
    if proof.total_entries != total_entries
        || proof.linear_fingerprint != linear_fingerprint
        || proof.product_fingerprint != product_fingerprint
    {
        return Err(R1csPiopError::InvalidProof);
    }
    verify_spark_matrix_evaluations(
        instance, &plan, pcs_params, row_point, col_point, proof, transcript,
    )?;
    let combined_evaluation = combine_spark_matrix_evaluations(
        &proof.matrix_evaluations,
        matrix_challenges,
        instance_matrices(instance).len(),
    )?;
    if proof.combined_evaluation != combined_evaluation {
        return Err(R1csPiopError::InvalidProof);
    }
    Ok(())
}

fn derive_spark_challenges<T: Transcript>(
    instance: &R1csInstance,
    workers: usize,
    transcript: &mut T,
) -> R1csPiopResult<(PartitionPlan, SparkChallenges)> {
    let actual_rows = instance.num_constraints();
    let row_domain_len = actual_rows.max(1).next_power_of_two();
    if actual_rows == 0 || workers == 0 {
        return Err(R1csPiopError::InvalidShape);
    }
    let plan = PartitionPlan::balanced(row_domain_len, workers)
        .map_err(|_| R1csPiopError::InvalidShape)?;
    transcript.absorb_domain(b"r1cs-distributed-spark-fingerprint-v1");
    transcript.absorb_public(b"workers", &(workers as u64).to_le_bytes());
    transcript.absorb_public(b"rows", &(actual_rows as u64).to_le_bytes());
    transcript.absorb_public(b"row-domain-len", &(row_domain_len as u64).to_le_bytes());
    transcript.absorb_public(b"cols", &(instance.num_variables() as u64).to_le_bytes());
    transcript.absorb_public(b"matrices", &3_u64.to_le_bytes());
    for partition in plan.partitions() {
        transcript.absorb_public(b"worker-id", &(partition.id as u64).to_le_bytes());
        transcript.absorb_public(b"worker-start", &(partition.start as u64).to_le_bytes());
        transcript.absorb_public(b"worker-end", &(partition.end as u64).to_le_bytes());
    }
    Ok((
        plan,
        SparkChallenges {
            tuple: transcript.challenge_field::<FieldElement>(b"spark-tuple"),
            matrix: transcript.challenge_field::<FieldElement>(b"spark-matrix"),
            row: transcript.challenge_field::<FieldElement>(b"spark-row"),
            col: transcript.challenge_field::<FieldElement>(b"spark-col"),
            value: transcript.challenge_field::<FieldElement>(b"spark-value"),
        },
    ))
}

fn compute_spark_worker_fingerprints(
    instance: &R1csInstance,
    plan: &PartitionPlan,
    challenges: SparkChallenges,
) -> R1csPiopResult<Vec<SparkWorkerFingerprint>> {
    let mut workers = Vec::with_capacity(plan.len());
    for partition in plan.partitions() {
        let mut entry_count = 0_usize;
        let mut linear_fingerprint = FieldElement::ZERO;
        let mut product_fingerprint = FieldElement::ONE;
        for (matrix_id, matrix) in [instance.a(), instance.b(), instance.c()]
            .iter()
            .enumerate()
        {
            for entry in matrix
                .entries()
                .iter()
                .filter(|entry| partition.contains(entry.row))
            {
                let encoded = spark_entry_encoding(matrix_id, entry, challenges);
                entry_count += 1;
                linear_fingerprint += encoded;
                product_fingerprint *= challenges.tuple + encoded;
            }
        }
        workers.push(SparkWorkerFingerprint {
            worker_id: partition.id,
            range: (partition.start, partition.end),
            entry_count,
            linear_fingerprint,
            product_fingerprint,
        });
    }
    Ok(workers)
}

pub fn compute_spark_worker_shard_claim(
    instance: &R1csInstance,
    partition: Partition,
    challenges: SparkChallenges,
    row_point: &[FieldElement],
    col_point: &[FieldElement],
) -> R1csPiopResult<SparkWorkerShardClaim> {
    let fingerprint =
        compute_spark_worker_fingerprint_for_partition(instance, partition, challenges);
    let matrix_evaluations = instance_matrices(instance)
        .iter()
        .enumerate()
        .map(|(matrix_id, matrix)| {
            compute_spark_worker_evaluation_for_partition(
                matrix_id, matrix, partition, row_point, col_point,
            )
        })
        .collect::<R1csPiopResult<Vec<_>>>()?;
    Ok(SparkWorkerShardClaim {
        fingerprint,
        matrix_evaluations,
    })
}

fn compute_spark_worker_fingerprint_for_partition(
    instance: &R1csInstance,
    partition: Partition,
    challenges: SparkChallenges,
) -> SparkWorkerFingerprint {
    let mut entry_count = 0_usize;
    let mut linear_fingerprint = FieldElement::ZERO;
    let mut product_fingerprint = FieldElement::ONE;
    for (matrix_id, matrix) in [instance.a(), instance.b(), instance.c()]
        .iter()
        .enumerate()
    {
        for entry in matrix
            .entries()
            .iter()
            .filter(|entry| partition.contains(entry.row))
        {
            let encoded = spark_entry_encoding(matrix_id, entry, challenges);
            entry_count += 1;
            linear_fingerprint += encoded;
            product_fingerprint *= challenges.tuple + encoded;
        }
    }
    SparkWorkerFingerprint {
        worker_id: partition.id,
        range: (partition.start, partition.end),
        entry_count,
        linear_fingerprint,
        product_fingerprint,
    }
}

fn validate_spark_worker_claims(
    plan: &PartitionPlan,
    claims: &[SparkWorkerShardClaim],
    matrix_count: usize,
) -> R1csPiopResult<()> {
    if claims.len() != plan.len() {
        return Err(R1csPiopError::InvalidProof);
    }
    for (partition, claim) in plan.partitions().iter().zip(claims) {
        if claim.fingerprint.worker_id != partition.id
            || claim.fingerprint.range != (partition.start, partition.end)
            || claim.matrix_evaluations.len() != matrix_count
        {
            return Err(R1csPiopError::InvalidProof);
        }
        for (matrix_id, evaluation) in claim.matrix_evaluations.iter().enumerate() {
            if evaluation.matrix_id != matrix_id
                || evaluation.worker_id != partition.id
                || evaluation.range != (partition.start, partition.end)
            {
                return Err(R1csPiopError::InvalidProof);
            }
        }
    }
    Ok(())
}

fn prove_spark_matrix_evaluations_from_worker_claims<T: Transcript>(
    instance: &R1csInstance,
    plan: &PartitionPlan,
    pcs_params: DistributedPcsParams,
    row_point: &[FieldElement],
    col_point: &[FieldElement],
    transcript: &mut T,
    worker_claims: &[SparkWorkerShardClaim],
) -> R1csPiopResult<Vec<SparkMatrixEvaluationProof>> {
    instance_matrices(instance)
        .iter()
        .enumerate()
        .map(|(matrix_id, matrix)| {
            let worker_evaluations = worker_claims
                .iter()
                .map(|claim| claim.matrix_evaluations[matrix_id])
                .collect::<Vec<_>>();
            prove_spark_matrix_evaluation_with_worker_evaluations(
                matrix_id,
                matrix,
                plan,
                pcs_params,
                row_point,
                col_point,
                transcript,
                worker_evaluations,
            )
        })
        .collect()
}

fn verify_spark_matrix_evaluations<T: Transcript>(
    instance: &R1csInstance,
    plan: &PartitionPlan,
    pcs_params: DistributedPcsParams,
    row_point: &[FieldElement],
    col_point: &[FieldElement],
    proof: &DistributedSparkProof,
    transcript: &mut T,
) -> R1csPiopResult<()> {
    let matrices = instance_matrices(instance);
    if proof.matrix_evaluations.len() != matrices.len() {
        return Err(R1csPiopError::InvalidProof);
    }
    for (matrix_id, (matrix, matrix_proof)) in
        matrices.iter().zip(&proof.matrix_evaluations).enumerate()
    {
        verify_spark_matrix_evaluation(
            matrix_id,
            matrix,
            plan,
            pcs_params,
            row_point,
            col_point,
            matrix_proof,
            transcript,
        )?;
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn prove_spark_matrix_evaluation_with_worker_evaluations<T: Transcript>(
    matrix_id: usize,
    matrix: &SparseMatrix,
    plan: &PartitionPlan,
    pcs_params: DistributedPcsParams,
    row_point: &[FieldElement],
    col_point: &[FieldElement],
    transcript: &mut T,
    worker_evaluations: Vec<SparkWorkerEvaluation>,
) -> R1csPiopResult<SparkMatrixEvaluationProof> {
    let trace = trace_r1cs_enabled();
    let phase = Instant::now();
    absorb_spark_matrix_evaluation_statement(transcript, matrix_id, matrix, row_point, col_point);
    validate_spark_worker_evaluations(matrix_id, plan, &worker_evaluations)?;
    absorb_spark_worker_evaluations(transcript, &worker_evaluations);
    let evaluation = worker_evaluations
        .iter()
        .map(|worker| worker.evaluation)
        .sum();
    trace_r1cs_phase(
        trace,
        &format!("spark/matrix_{matrix_id}/statement"),
        phase.elapsed(),
    );
    let phase = Instant::now();
    let row_memory = prove_spark_memory_check(
        b"row",
        matrix_id,
        matrix.rows().max(1).next_power_of_two(),
        row_point,
        matrix.entries(),
        |entry| entry.row,
        plan,
        pcs_params,
        transcript,
    )?;
    trace_r1cs_phase(
        trace,
        &format!("spark/matrix_{matrix_id}/row_memory"),
        phase.elapsed(),
    );
    let phase = Instant::now();
    let col_memory = prove_spark_memory_check(
        b"col",
        matrix_id,
        matrix.cols().max(1).next_power_of_two(),
        col_point,
        matrix.entries(),
        |entry| entry.col,
        plan,
        pcs_params,
        transcript,
    )?;
    trace_r1cs_phase(
        trace,
        &format!("spark/matrix_{matrix_id}/col_memory"),
        phase.elapsed(),
    );
    let phase = Instant::now();
    let value_memory =
        prove_spark_value_memory_check(matrix_id, matrix.entries(), plan, pcs_params, transcript)?;
    trace_r1cs_phase(
        trace,
        &format!("spark/matrix_{matrix_id}/value_memory"),
        phase.elapsed(),
    );
    Ok(SparkMatrixEvaluationProof {
        matrix_id,
        evaluation,
        worker_evaluations,
        row_memory,
        col_memory,
        value_memory,
    })
}

#[allow(clippy::too_many_arguments)]
fn verify_spark_matrix_evaluation<T: Transcript>(
    matrix_id: usize,
    matrix: &SparseMatrix,
    plan: &PartitionPlan,
    pcs_params: DistributedPcsParams,
    row_point: &[FieldElement],
    col_point: &[FieldElement],
    proof: &SparkMatrixEvaluationProof,
    transcript: &mut T,
) -> R1csPiopResult<()> {
    if proof.matrix_id != matrix_id {
        return Err(R1csPiopError::InvalidProof);
    }
    absorb_spark_matrix_evaluation_statement(transcript, matrix_id, matrix, row_point, col_point);
    let expected_workers =
        compute_spark_worker_evaluations(matrix_id, matrix, plan, row_point, col_point)?;
    if proof.worker_evaluations != expected_workers {
        return Err(R1csPiopError::InvalidProof);
    }
    absorb_spark_worker_evaluations(transcript, &proof.worker_evaluations);
    let expected_evaluation = expected_workers
        .iter()
        .map(|worker| worker.evaluation)
        .sum::<FieldElement>();
    if proof.evaluation != expected_evaluation {
        return Err(R1csPiopError::InvalidProof);
    }
    verify_spark_memory_check(
        b"row",
        matrix_id,
        matrix.rows().max(1).next_power_of_two(),
        row_point,
        matrix.entries(),
        |entry| entry.row,
        plan,
        pcs_params,
        &proof.row_memory,
        transcript,
    )?;
    verify_spark_memory_check(
        b"col",
        matrix_id,
        matrix.cols().max(1).next_power_of_two(),
        col_point,
        matrix.entries(),
        |entry| entry.col,
        plan,
        pcs_params,
        &proof.col_memory,
        transcript,
    )?;
    verify_spark_value_memory_check(
        matrix_id,
        matrix.entries(),
        plan,
        pcs_params,
        &proof.value_memory,
        transcript,
    )
}

fn compute_spark_worker_evaluations(
    matrix_id: usize,
    matrix: &SparseMatrix,
    plan: &PartitionPlan,
    row_point: &[FieldElement],
    col_point: &[FieldElement],
) -> R1csPiopResult<Vec<SparkWorkerEvaluation>> {
    let row_len = matrix.rows().max(1).next_power_of_two();
    let col_len = matrix.cols().max(1).next_power_of_two();
    if row_point.len() != log2_power_of_two(row_len).map_err(|_| R1csPiopError::InvalidShape)?
        || col_point.len() != log2_power_of_two(col_len).map_err(|_| R1csPiopError::InvalidShape)?
    {
        return Err(R1csPiopError::InvalidProof);
    }
    let mut workers = Vec::with_capacity(plan.len());
    for partition in plan.partitions() {
        workers.push(compute_spark_worker_evaluation_for_partition(
            matrix_id, matrix, *partition, row_point, col_point,
        )?);
    }
    Ok(workers)
}

fn compute_spark_worker_evaluation_for_partition(
    matrix_id: usize,
    matrix: &SparseMatrix,
    partition: Partition,
    row_point: &[FieldElement],
    col_point: &[FieldElement],
) -> R1csPiopResult<SparkWorkerEvaluation> {
    validate_spark_evaluation_points(matrix, row_point, col_point)?;
    let mut entry_count = 0_usize;
    let mut evaluation = FieldElement::ZERO;
    for entry in matrix
        .entries()
        .iter()
        .filter(|entry| partition.contains(entry.row))
    {
        entry_count += 1;
        evaluation += sparse_entry_mle_term(entry, row_point, col_point)?;
    }
    Ok(SparkWorkerEvaluation {
        matrix_id,
        worker_id: partition.id,
        range: (partition.start, partition.end),
        entry_count,
        evaluation,
    })
}

fn validate_spark_evaluation_points(
    matrix: &SparseMatrix,
    row_point: &[FieldElement],
    col_point: &[FieldElement],
) -> R1csPiopResult<()> {
    let row_len = matrix.rows().max(1).next_power_of_two();
    let col_len = matrix.cols().max(1).next_power_of_two();
    if row_point.len() != log2_power_of_two(row_len).map_err(|_| R1csPiopError::InvalidShape)?
        || col_point.len() != log2_power_of_two(col_len).map_err(|_| R1csPiopError::InvalidShape)?
    {
        return Err(R1csPiopError::InvalidProof);
    }
    Ok(())
}

fn validate_spark_worker_evaluations(
    matrix_id: usize,
    plan: &PartitionPlan,
    evaluations: &[SparkWorkerEvaluation],
) -> R1csPiopResult<()> {
    if evaluations.len() != plan.len() {
        return Err(R1csPiopError::InvalidProof);
    }
    for (partition, evaluation) in plan.partitions().iter().zip(evaluations) {
        if evaluation.matrix_id != matrix_id
            || evaluation.worker_id != partition.id
            || evaluation.range != (partition.start, partition.end)
        {
            return Err(R1csPiopError::InvalidProof);
        }
    }
    Ok(())
}

fn sparse_entry_mle_term(
    entry: &SparseEntry,
    row_point: &[FieldElement],
    col_point: &[FieldElement],
) -> R1csPiopResult<FieldElement> {
    let row_weight = eq_basis(row_point, entry.row).map_err(|_| R1csPiopError::InvalidProof)?;
    let col_weight = eq_basis(col_point, entry.col).map_err(|_| R1csPiopError::InvalidProof)?;
    Ok(row_weight * col_weight * entry.value)
}

#[allow(clippy::too_many_arguments)]
fn prove_spark_memory_check<T, F>(
    label: &'static [u8],
    matrix_id: usize,
    domain_len: usize,
    point: &[FieldElement],
    entries: &[SparseEntry],
    access_index: F,
    plan: &PartitionPlan,
    pcs_params: DistributedPcsParams,
    transcript: &mut T,
) -> R1csPiopResult<SparkMemoryCheckProof>
where
    T: Transcript,
    F: Fn(&SparseEntry) -> usize + Copy,
{
    let trace_enabled = trace_r1cs_enabled();
    let phase = Instant::now();
    absorb_spark_memory_header(
        transcript,
        label,
        matrix_id,
        domain_len,
        entries.len(),
        plan,
    );
    let hash_challenge = transcript.challenge_field::<FieldElement>(b"spark-memory-hash");
    let memory_values = spark_eq_memory_values(domain_len, point)?;
    trace_r1cs_phase(trace_enabled, "spark/memory/eq_values", phase.elapsed());
    let phase = Instant::now();
    let access_indices = entries.iter().map(access_index).collect::<Vec<_>>();
    let trace = spark_memory_trace(domain_len, &memory_values, &access_indices, hash_challenge)?;
    trace_r1cs_phase(trace_enabled, "spark/memory/trace", phase.elapsed());
    let phase = Instant::now();
    let trace_commitments = commit_spark_memory_trace(&trace)?;
    trace_r1cs_phase(trace_enabled, "spark/memory/commitments", phase.elapsed());
    let phase = Instant::now();
    let (domain_indices, access_sample_indices) = challenge_spark_memory_trace_queries(
        transcript,
        label,
        matrix_id,
        domain_len,
        entries.len(),
        pcs_params,
        &trace_commitments,
    )?;
    let (domain_queries, access_queries) =
        open_spark_memory_trace_queries(&trace, &domain_indices, &access_sample_indices)?;
    absorb_spark_memory_trace_queries(transcript, &domain_queries, &access_queries);
    trace_r1cs_phase(trace_enabled, "spark/memory/queries", phase.elapsed());
    let phase = Instant::now();
    let worker_digests = compute_spark_memory_worker_digests(plan, entries, &trace)?;
    absorb_spark_memory_worker_digests(transcript, &worker_digests);
    trace_r1cs_phase(
        trace_enabled,
        "spark/memory/worker_digests",
        phase.elapsed(),
    );
    let phase = Instant::now();
    let multiset = prove_product_multiset_equality(
        &trace.init,
        &trace.writes,
        &trace.audit,
        &trace.reads,
        transcript,
    )
    .map_err(|_| R1csPiopError::Sumcheck)?;
    trace_r1cs_phase(trace_enabled, "spark/memory/multiset", phase.elapsed());
    Ok(SparkMemoryCheckProof {
        hash_challenge,
        domain_len,
        access_count: entries.len(),
        trace_commitments,
        domain_queries,
        access_queries,
        worker_digests,
        multiset,
    })
}

#[allow(clippy::too_many_arguments)]
fn verify_spark_memory_check<T, F>(
    label: &'static [u8],
    matrix_id: usize,
    domain_len: usize,
    point: &[FieldElement],
    entries: &[SparseEntry],
    access_index: F,
    plan: &PartitionPlan,
    pcs_params: DistributedPcsParams,
    proof: &SparkMemoryCheckProof,
    transcript: &mut T,
) -> R1csPiopResult<()>
where
    T: Transcript,
    F: Fn(&SparseEntry) -> usize + Copy,
{
    if proof.domain_len != domain_len || proof.access_count != entries.len() {
        return Err(R1csPiopError::InvalidProof);
    }
    absorb_spark_memory_header(
        transcript,
        label,
        matrix_id,
        domain_len,
        entries.len(),
        plan,
    );
    let hash_challenge = transcript.challenge_field::<FieldElement>(b"spark-memory-hash");
    if proof.hash_challenge != hash_challenge {
        return Err(R1csPiopError::InvalidProof);
    }
    let memory_values = spark_eq_memory_values(domain_len, point)?;
    let access_indices = entries.iter().map(access_index).collect::<Vec<_>>();
    let trace = spark_memory_trace(domain_len, &memory_values, &access_indices, hash_challenge)?;
    verify_spark_memory_trace_commitments(&trace, &proof.trace_commitments)?;
    let (domain_indices, access_sample_indices) = challenge_spark_memory_trace_queries(
        transcript,
        label,
        matrix_id,
        domain_len,
        entries.len(),
        pcs_params,
        &proof.trace_commitments,
    )?;
    verify_spark_memory_trace_queries(
        &trace,
        hash_challenge,
        &proof.trace_commitments,
        &domain_indices,
        &access_sample_indices,
        &proof.domain_queries,
        &proof.access_queries,
    )?;
    absorb_spark_memory_trace_queries(transcript, &proof.domain_queries, &proof.access_queries);
    let expected_worker_digests = compute_spark_memory_worker_digests(plan, entries, &trace)?;
    if proof.worker_digests != expected_worker_digests {
        return Err(R1csPiopError::InvalidProof);
    }
    absorb_spark_memory_worker_digests(transcript, &proof.worker_digests);
    verify_product_multiset_equality(
        &trace.init,
        &trace.writes,
        &trace.audit,
        &trace.reads,
        &proof.multiset,
        transcript,
    )
    .map_err(|_| R1csPiopError::Sumcheck)
}

fn prove_spark_value_memory_check<T: Transcript>(
    matrix_id: usize,
    entries: &[SparseEntry],
    plan: &PartitionPlan,
    pcs_params: DistributedPcsParams,
    transcript: &mut T,
) -> R1csPiopResult<SparkMemoryCheckProof> {
    let domain_len = entries.len().max(1).next_power_of_two();
    absorb_spark_memory_header(
        transcript,
        b"value",
        matrix_id,
        domain_len,
        entries.len(),
        plan,
    );
    let hash_challenge = transcript.challenge_field::<FieldElement>(b"spark-memory-hash");
    let memory_values = spark_value_memory_values(domain_len, entries)?;
    let access_indices = (0..entries.len()).collect::<Vec<_>>();
    let trace = spark_memory_trace(domain_len, &memory_values, &access_indices, hash_challenge)?;
    let trace_commitments = commit_spark_memory_trace(&trace)?;
    let (domain_indices, access_sample_indices) = challenge_spark_memory_trace_queries(
        transcript,
        b"value",
        matrix_id,
        domain_len,
        entries.len(),
        pcs_params,
        &trace_commitments,
    )?;
    let (domain_queries, access_queries) =
        open_spark_memory_trace_queries(&trace, &domain_indices, &access_sample_indices)?;
    absorb_spark_memory_trace_queries(transcript, &domain_queries, &access_queries);
    let worker_digests = compute_spark_memory_worker_digests(plan, entries, &trace)?;
    absorb_spark_memory_worker_digests(transcript, &worker_digests);
    let multiset = prove_product_multiset_equality(
        &trace.init,
        &trace.writes,
        &trace.audit,
        &trace.reads,
        transcript,
    )
    .map_err(|_| R1csPiopError::Sumcheck)?;
    Ok(SparkMemoryCheckProof {
        hash_challenge,
        domain_len,
        access_count: entries.len(),
        trace_commitments,
        domain_queries,
        access_queries,
        worker_digests,
        multiset,
    })
}

fn verify_spark_value_memory_check<T: Transcript>(
    matrix_id: usize,
    entries: &[SparseEntry],
    plan: &PartitionPlan,
    pcs_params: DistributedPcsParams,
    proof: &SparkMemoryCheckProof,
    transcript: &mut T,
) -> R1csPiopResult<()> {
    let domain_len = entries.len().max(1).next_power_of_two();
    if proof.domain_len != domain_len || proof.access_count != entries.len() {
        return Err(R1csPiopError::InvalidProof);
    }
    absorb_spark_memory_header(
        transcript,
        b"value",
        matrix_id,
        domain_len,
        entries.len(),
        plan,
    );
    let hash_challenge = transcript.challenge_field::<FieldElement>(b"spark-memory-hash");
    if proof.hash_challenge != hash_challenge {
        return Err(R1csPiopError::InvalidProof);
    }
    let memory_values = spark_value_memory_values(domain_len, entries)?;
    let access_indices = (0..entries.len()).collect::<Vec<_>>();
    let trace = spark_memory_trace(domain_len, &memory_values, &access_indices, hash_challenge)?;
    verify_spark_memory_trace_commitments(&trace, &proof.trace_commitments)?;
    let (domain_indices, access_sample_indices) = challenge_spark_memory_trace_queries(
        transcript,
        b"value",
        matrix_id,
        domain_len,
        entries.len(),
        pcs_params,
        &proof.trace_commitments,
    )?;
    verify_spark_memory_trace_queries(
        &trace,
        hash_challenge,
        &proof.trace_commitments,
        &domain_indices,
        &access_sample_indices,
        &proof.domain_queries,
        &proof.access_queries,
    )?;
    absorb_spark_memory_trace_queries(transcript, &proof.domain_queries, &proof.access_queries);
    let expected_worker_digests = compute_spark_memory_worker_digests(plan, entries, &trace)?;
    if proof.worker_digests != expected_worker_digests {
        return Err(R1csPiopError::InvalidProof);
    }
    absorb_spark_memory_worker_digests(transcript, &proof.worker_digests);
    verify_product_multiset_equality(
        &trace.init,
        &trace.writes,
        &trace.audit,
        &trace.reads,
        &proof.multiset,
        transcript,
    )
    .map_err(|_| R1csPiopError::Sumcheck)
}

struct SparkMemoryTrace {
    init: Vec<FieldElement>,
    writes: Vec<FieldElement>,
    audit: Vec<FieldElement>,
    reads: Vec<FieldElement>,
    read_addresses: Vec<usize>,
    read_values: Vec<FieldElement>,
    read_timestamps: Vec<FieldElement>,
    write_timestamps: Vec<FieldElement>,
}

fn commit_spark_memory_trace(
    trace: &SparkMemoryTrace,
) -> R1csPiopResult<SparkMemoryTraceCommitments> {
    Ok(SparkMemoryTraceCommitments {
        init: MerklePcs::commit(&trace.init).map_err(|_| R1csPiopError::Pcs)?,
        writes: MerklePcs::commit(&padded_trace_values(&trace.writes))
            .map_err(|_| R1csPiopError::Pcs)?,
        audit: MerklePcs::commit(&trace.audit).map_err(|_| R1csPiopError::Pcs)?,
        reads: MerklePcs::commit(&padded_trace_values(&trace.reads))
            .map_err(|_| R1csPiopError::Pcs)?,
    })
}

fn verify_spark_memory_trace_commitments(
    trace: &SparkMemoryTrace,
    commitments: &SparkMemoryTraceCommitments,
) -> R1csPiopResult<()> {
    let expected = commit_spark_memory_trace(trace)?;
    if commitments != &expected {
        return Err(R1csPiopError::InvalidProof);
    }
    Ok(())
}

fn padded_trace_values(values: &[FieldElement]) -> Vec<FieldElement> {
    let len = values.len().max(1).next_power_of_two();
    let mut padded = values.to_vec();
    padded.resize(len, FieldElement::ZERO);
    padded
}

fn challenge_spark_memory_trace_queries<T: Transcript>(
    transcript: &mut T,
    label: &'static [u8],
    matrix_id: usize,
    domain_len: usize,
    access_count: usize,
    pcs_params: DistributedPcsParams,
    commitments: &SparkMemoryTraceCommitments,
) -> R1csPiopResult<(Vec<usize>, Vec<usize>)> {
    let domain_query_count = pcs_params
        .effective_query_count(domain_len)
        .map_err(|_| R1csPiopError::InvalidShape)?;
    let access_query_count = if access_count == 0 {
        0
    } else {
        pcs_params
            .effective_query_count(access_count)
            .map_err(|_| R1csPiopError::InvalidShape)?
    };
    transcript.absorb_domain(b"r1cs-distributed-spark-memory-trace-sampled-v1");
    transcript.absorb_public(b"spark-memory-trace-label", label);
    transcript.absorb_public(
        b"spark-memory-trace-matrix-id",
        &(matrix_id as u64).to_le_bytes(),
    );
    transcript.absorb_public(
        b"spark-memory-trace-domain-len",
        &(domain_len as u64).to_le_bytes(),
    );
    transcript.absorb_public(
        b"spark-memory-trace-access-count",
        &(access_count as u64).to_le_bytes(),
    );
    transcript.absorb_public(
        b"spark-memory-trace-requested-query-count",
        &(pcs_params.query_count as u64).to_le_bytes(),
    );
    transcript.absorb_public(
        b"spark-memory-trace-domain-query-count",
        &(domain_query_count as u64).to_le_bytes(),
    );
    transcript.absorb_public(
        b"spark-memory-trace-access-query-count",
        &(access_query_count as u64).to_le_bytes(),
    );
    absorb_spark_memory_trace_commitments(transcript, commitments);
    let domain_indices = transcript.challenge_indices(
        b"spark-memory-trace-domain-query",
        domain_query_count,
        domain_len,
    );
    let access_indices = if access_query_count == 0 {
        Vec::new()
    } else {
        transcript.challenge_indices(
            b"spark-memory-trace-access-query",
            access_query_count,
            access_count,
        )
    };
    Ok((domain_indices, access_indices))
}

fn open_spark_memory_trace_queries(
    trace: &SparkMemoryTrace,
    domain_indices: &[usize],
    access_indices: &[usize],
) -> R1csPiopResult<(Vec<SparkMemoryDomainQuery>, Vec<SparkMemoryAccessQuery>)> {
    let padded_reads = padded_trace_values(&trace.reads);
    let padded_writes = padded_trace_values(&trace.writes);
    let domain_queries = domain_indices
        .iter()
        .copied()
        .map(|index| {
            if index >= trace.init.len() || index >= trace.audit.len() {
                return Err(R1csPiopError::InvalidProof);
            }
            Ok(SparkMemoryDomainQuery {
                index,
                init: MerklePcs::open(&trace.init, index).map_err(|_| R1csPiopError::Pcs)?,
                audit: MerklePcs::open(&trace.audit, index).map_err(|_| R1csPiopError::Pcs)?,
            })
        })
        .collect::<R1csPiopResult<Vec<_>>>()?;
    let access_queries = access_indices
        .iter()
        .copied()
        .map(|index| {
            if index >= trace.reads.len()
                || index >= trace.writes.len()
                || index >= trace.read_addresses.len()
                || index >= trace.read_values.len()
                || index >= trace.read_timestamps.len()
                || index >= trace.write_timestamps.len()
            {
                return Err(R1csPiopError::InvalidProof);
            }
            Ok(SparkMemoryAccessQuery {
                index,
                address: trace.read_addresses[index],
                value: trace.read_values[index],
                read_timestamp: trace.read_timestamps[index],
                write_timestamp: trace.write_timestamps[index],
                read: MerklePcs::open(&padded_reads, index).map_err(|_| R1csPiopError::Pcs)?,
                write: MerklePcs::open(&padded_writes, index).map_err(|_| R1csPiopError::Pcs)?,
            })
        })
        .collect::<R1csPiopResult<Vec<_>>>()?;
    Ok((domain_queries, access_queries))
}

fn verify_spark_memory_trace_queries(
    trace: &SparkMemoryTrace,
    hash_challenge: FieldElement,
    commitments: &SparkMemoryTraceCommitments,
    expected_domain_indices: &[usize],
    expected_access_indices: &[usize],
    domain_queries: &[SparkMemoryDomainQuery],
    access_queries: &[SparkMemoryAccessQuery],
) -> R1csPiopResult<()> {
    if domain_queries.len() != expected_domain_indices.len()
        || access_queries.len() != expected_access_indices.len()
        || trace.reads.len() != trace.writes.len()
        || trace.read_addresses.len() != trace.reads.len()
        || trace.read_values.len() != trace.reads.len()
        || trace.read_timestamps.len() != trace.reads.len()
        || trace.write_timestamps.len() != trace.writes.len()
    {
        return Err(R1csPiopError::InvalidProof);
    }
    for (expected, query) in expected_domain_indices.iter().zip(domain_queries) {
        if query.index != *expected
            || query.init.index != *expected
            || query.audit.index != *expected
            || query.init.value != trace.init[*expected]
            || query.audit.value != trace.audit[*expected]
        {
            return Err(R1csPiopError::InvalidProof);
        }
        MerklePcs::verify(&commitments.init, &query.init).map_err(|_| R1csPiopError::Pcs)?;
        MerklePcs::verify(&commitments.audit, &query.audit).map_err(|_| R1csPiopError::Pcs)?;
    }
    for (expected, query) in expected_access_indices.iter().zip(access_queries) {
        if query.index != *expected
            || query.read.index != *expected
            || query.write.index != *expected
            || query.read.value != trace.reads[*expected]
            || query.write.value != trace.writes[*expected]
            || query.address != trace.read_addresses[*expected]
            || query.value != trace.read_values[*expected]
            || query.read_timestamp != trace.read_timestamps[*expected]
            || query.write_timestamp != trace.write_timestamps[*expected]
        {
            return Err(R1csPiopError::InvalidProof);
        }
        let gamma_sq = hash_challenge * hash_challenge;
        if query.read.value
            != spark_memory_hash(
                query.address,
                query.value,
                query.read_timestamp,
                hash_challenge,
                gamma_sq,
            )
            || query.write.value
                != spark_memory_hash(
                    query.address,
                    query.value,
                    query.write_timestamp,
                    hash_challenge,
                    gamma_sq,
                )
        {
            return Err(R1csPiopError::InvalidProof);
        }
        MerklePcs::verify(&commitments.reads, &query.read).map_err(|_| R1csPiopError::Pcs)?;
        MerklePcs::verify(&commitments.writes, &query.write).map_err(|_| R1csPiopError::Pcs)?;
    }
    Ok(())
}

fn spark_memory_trace(
    domain_len: usize,
    memory_values: &[FieldElement],
    access_indices: &[usize],
    hash_challenge: FieldElement,
) -> R1csPiopResult<SparkMemoryTrace> {
    if domain_len == 0 || !domain_len.is_power_of_two() || memory_values.len() != domain_len {
        return Err(R1csPiopError::InvalidShape);
    }
    let gamma_sq = hash_challenge * hash_challenge;
    let mut timestamps = vec![FieldElement::ZERO; domain_len];
    let init = (0..domain_len)
        .map(|index| {
            spark_memory_hash(
                index,
                memory_values[index],
                FieldElement::ZERO,
                hash_challenge,
                gamma_sq,
            )
        })
        .collect::<Vec<_>>();
    let mut reads = Vec::with_capacity(access_indices.len());
    let mut writes = Vec::with_capacity(access_indices.len());
    let mut read_addresses = Vec::with_capacity(access_indices.len());
    let mut read_values = Vec::with_capacity(access_indices.len());
    let mut read_timestamps = Vec::with_capacity(access_indices.len());
    let mut write_timestamps = Vec::with_capacity(access_indices.len());
    let mut global_timestamp = FieldElement::ZERO;
    for &index in access_indices {
        if index >= domain_len {
            return Err(R1csPiopError::InvalidShape);
        }
        let value = memory_values[index];
        let read_timestamp = timestamps[index];
        reads.push(spark_memory_hash(
            index,
            value,
            read_timestamp,
            hash_challenge,
            gamma_sq,
        ));
        global_timestamp += FieldElement::ONE;
        timestamps[index] = global_timestamp;
        writes.push(spark_memory_hash(
            index,
            memory_values[index],
            timestamps[index],
            hash_challenge,
            gamma_sq,
        ));
        read_addresses.push(index);
        read_values.push(value);
        read_timestamps.push(read_timestamp);
        write_timestamps.push(global_timestamp);
    }
    let audit = (0..domain_len)
        .map(|index| {
            spark_memory_hash(
                index,
                memory_values[index],
                timestamps[index],
                hash_challenge,
                gamma_sq,
            )
        })
        .collect();
    Ok(SparkMemoryTrace {
        init,
        writes,
        audit,
        reads,
        read_addresses,
        read_values,
        read_timestamps,
        write_timestamps,
    })
}

fn compute_spark_memory_worker_digests(
    plan: &PartitionPlan,
    entries: &[SparseEntry],
    trace: &SparkMemoryTrace,
) -> R1csPiopResult<Vec<SparkMemoryWorkerDigest>> {
    let domain_plan = PartitionPlan::balanced(trace.init.len(), plan.len())
        .map_err(|_| R1csPiopError::InvalidShape)?;
    if trace.audit.len() != trace.init.len()
        || trace.reads.len() != entries.len()
        || trace.writes.len() != entries.len()
        || trace.read_addresses.len() != entries.len()
        || trace.read_values.len() != entries.len()
        || trace.read_timestamps.len() != entries.len()
        || trace.write_timestamps.len() != entries.len()
    {
        return Err(R1csPiopError::InvalidShape);
    }
    plan.partitions()
        .iter()
        .zip(domain_plan.partitions())
        .map(|(entry_partition, memory_partition)| {
            let mut access_count = 0_usize;
            let mut read_product = FieldElement::ONE;
            let mut write_product = FieldElement::ONE;
            for (index, entry) in entries.iter().enumerate() {
                if entry_partition.contains(entry.row) {
                    access_count += 1;
                    read_product *= trace.reads[index];
                    write_product *= trace.writes[index];
                }
            }
            let init_product = trace.init[memory_partition.start..memory_partition.end]
                .iter()
                .copied()
                .product();
            let audit_product = trace.audit[memory_partition.start..memory_partition.end]
                .iter()
                .copied()
                .product();
            Ok(SparkMemoryWorkerDigest {
                worker_id: entry_partition.id,
                entry_range: (entry_partition.start, entry_partition.end),
                memory_range: (memory_partition.start, memory_partition.end),
                access_count,
                init_product,
                read_product,
                write_product,
                audit_product,
            })
        })
        .collect()
}

fn spark_eq_memory_values(
    domain_len: usize,
    point: &[FieldElement],
) -> R1csPiopResult<Vec<FieldElement>> {
    if domain_len == 0
        || !domain_len.is_power_of_two()
        || point.len() != log2_power_of_two(domain_len).map_err(|_| R1csPiopError::InvalidShape)?
    {
        return Err(R1csPiopError::InvalidShape);
    }
    (0..domain_len)
        .map(|index| eq_basis(point, index).map_err(|_| R1csPiopError::InvalidProof))
        .collect()
}

fn spark_value_memory_values(
    domain_len: usize,
    entries: &[SparseEntry],
) -> R1csPiopResult<Vec<FieldElement>> {
    if domain_len == 0 || !domain_len.is_power_of_two() || entries.len() > domain_len {
        return Err(R1csPiopError::InvalidShape);
    }
    let mut values = vec![FieldElement::ZERO; domain_len];
    for (index, entry) in entries.iter().enumerate() {
        values[index] = entry.value;
    }
    Ok(values)
}

fn spark_memory_hash(
    address: usize,
    value: FieldElement,
    timestamp: FieldElement,
    gamma: FieldElement,
    gamma_sq: FieldElement,
) -> FieldElement {
    FieldElement::from(address) * gamma_sq + value * gamma + timestamp
}

fn combine_spark_matrix_evaluations(
    matrix_evaluations: &[SparkMatrixEvaluationProof],
    matrix_challenges: [FieldElement; 3],
    expected_len: usize,
) -> R1csPiopResult<FieldElement> {
    if matrix_evaluations.len() != expected_len || expected_len != matrix_challenges.len() {
        return Err(R1csPiopError::InvalidProof);
    }
    let mut combined = FieldElement::ZERO;
    for (expected_id, matrix_proof) in matrix_evaluations.iter().enumerate() {
        if matrix_proof.matrix_id != expected_id {
            return Err(R1csPiopError::InvalidProof);
        }
        combined += matrix_challenges[expected_id] * matrix_proof.evaluation;
    }
    Ok(combined)
}

fn instance_matrices(instance: &R1csInstance) -> [&SparseMatrix; 3] {
    [instance.a(), instance.b(), instance.c()]
}

fn spark_entry_encoding(
    matrix_id: usize,
    entry: &SparseEntry,
    challenges: SparkChallenges,
) -> FieldElement {
    challenges.matrix * FieldElement::from(matrix_id + 1)
        + challenges.row * FieldElement::from(entry.row)
        + challenges.col * FieldElement::from(entry.col)
        + challenges.value * entry.value
}

fn absorb_spark_matrix_evaluation_statement<T: Transcript>(
    transcript: &mut T,
    matrix_id: usize,
    matrix: &SparseMatrix,
    row_point: &[FieldElement],
    col_point: &[FieldElement],
) {
    transcript.absorb_domain(b"r1cs-distributed-spark-matrix-eval-v1");
    transcript.absorb_public(b"spark-matrix-id", &(matrix_id as u64).to_le_bytes());
    transcript.absorb_public(b"spark-matrix-rows", &(matrix.rows() as u64).to_le_bytes());
    transcript.absorb_public(b"spark-matrix-cols", &(matrix.cols() as u64).to_le_bytes());
    transcript.absorb_public(
        b"spark-matrix-nnz",
        &(matrix.entries().len() as u64).to_le_bytes(),
    );
    for (entry_index, entry) in matrix.entries().iter().enumerate() {
        transcript.absorb_public(
            b"spark-matrix-entry-index",
            &(entry_index as u64).to_le_bytes(),
        );
        transcript.absorb_public(b"spark-matrix-entry-row", &(entry.row as u64).to_le_bytes());
        transcript.absorb_public(b"spark-matrix-entry-col", &(entry.col as u64).to_le_bytes());
        transcript.absorb_field(b"spark-matrix-entry-value", entry.value);
    }
    for coordinate in row_point {
        transcript.absorb_field(b"spark-row-point", *coordinate);
    }
    for coordinate in col_point {
        transcript.absorb_field(b"spark-col-point", *coordinate);
    }
}

fn absorb_spark_worker_evaluations<T: Transcript>(
    transcript: &mut T,
    workers: &[SparkWorkerEvaluation],
) {
    transcript.absorb_domain(b"r1cs-distributed-spark-worker-evals-v1");
    transcript.absorb_public(
        b"spark-worker-eval-count",
        &(workers.len() as u64).to_le_bytes(),
    );
    for worker in workers {
        transcript.absorb_public(
            b"spark-worker-matrix-id",
            &(worker.matrix_id as u64).to_le_bytes(),
        );
        transcript.absorb_public(b"spark-worker-id", &(worker.worker_id as u64).to_le_bytes());
        transcript.absorb_public(
            b"spark-worker-start",
            &(worker.range.0 as u64).to_le_bytes(),
        );
        transcript.absorb_public(b"spark-worker-end", &(worker.range.1 as u64).to_le_bytes());
        transcript.absorb_public(
            b"spark-worker-entry-count",
            &(worker.entry_count as u64).to_le_bytes(),
        );
        transcript.absorb_field(b"spark-worker-evaluation", worker.evaluation);
    }
}

fn absorb_spark_memory_header<T: Transcript>(
    transcript: &mut T,
    label: &'static [u8],
    matrix_id: usize,
    domain_len: usize,
    access_count: usize,
    plan: &PartitionPlan,
) {
    transcript.absorb_domain(b"r1cs-distributed-spark-memory-v1");
    transcript.absorb_public(b"spark-memory-label", label);
    transcript.absorb_public(b"spark-memory-matrix-id", &(matrix_id as u64).to_le_bytes());
    transcript.absorb_public(
        b"spark-memory-domain-len",
        &(domain_len as u64).to_le_bytes(),
    );
    transcript.absorb_public(
        b"spark-memory-access-count",
        &(access_count as u64).to_le_bytes(),
    );
    transcript.absorb_public(
        b"spark-memory-worker-count",
        &(plan.partitions().len() as u64).to_le_bytes(),
    );
    for partition in plan.partitions() {
        transcript.absorb_public(
            b"spark-memory-worker-id",
            &(partition.id as u64).to_le_bytes(),
        );
        transcript.absorb_public(
            b"spark-memory-worker-start",
            &(partition.start as u64).to_le_bytes(),
        );
        transcript.absorb_public(
            b"spark-memory-worker-end",
            &(partition.end as u64).to_le_bytes(),
        );
    }
}

fn absorb_spark_memory_trace_commitments<T: Transcript>(
    transcript: &mut T,
    commitments: &SparkMemoryTraceCommitments,
) {
    transcript.absorb_domain(b"r1cs-distributed-spark-memory-trace-commitments-v1");
    absorb_merkle_commitment(transcript, b"spark-memory-init", &commitments.init);
    absorb_merkle_commitment(transcript, b"spark-memory-writes", &commitments.writes);
    absorb_merkle_commitment(transcript, b"spark-memory-audit", &commitments.audit);
    absorb_merkle_commitment(transcript, b"spark-memory-reads", &commitments.reads);
}

fn absorb_spark_memory_trace_queries<T: Transcript>(
    transcript: &mut T,
    domain_queries: &[SparkMemoryDomainQuery],
    access_queries: &[SparkMemoryAccessQuery],
) {
    transcript.absorb_domain(b"r1cs-distributed-spark-memory-trace-queries-v1");
    transcript.absorb_public(
        b"spark-memory-domain-query-count",
        &(domain_queries.len() as u64).to_le_bytes(),
    );
    for query in domain_queries {
        transcript.absorb_public(
            b"spark-memory-domain-query-index",
            &(query.index as u64).to_le_bytes(),
        );
        absorb_opening_proof(transcript, b"spark-memory-domain-init", &query.init);
        absorb_opening_proof(transcript, b"spark-memory-domain-audit", &query.audit);
    }
    transcript.absorb_public(
        b"spark-memory-access-query-count",
        &(access_queries.len() as u64).to_le_bytes(),
    );
    for query in access_queries {
        transcript.absorb_public(
            b"spark-memory-access-query-index",
            &(query.index as u64).to_le_bytes(),
        );
        transcript.absorb_public(
            b"spark-memory-access-address",
            &(query.address as u64).to_le_bytes(),
        );
        transcript.absorb_field(b"spark-memory-access-value", query.value);
        transcript.absorb_field(b"spark-memory-access-read-ts", query.read_timestamp);
        transcript.absorb_field(b"spark-memory-access-write-ts", query.write_timestamp);
        absorb_opening_proof(transcript, b"spark-memory-access-read", &query.read);
        absorb_opening_proof(transcript, b"spark-memory-access-write", &query.write);
    }
}

fn absorb_opening_proof<T: Transcript>(
    transcript: &mut T,
    label: &'static [u8],
    opening: &OpeningProof,
) {
    transcript.absorb_domain(b"r1cs-merkle-opening-proof-v1");
    transcript.absorb_public(b"r1cs-opening-label", label);
    transcript.absorb_public(b"r1cs-opening-index", &(opening.index as u64).to_le_bytes());
    transcript.absorb_field(b"r1cs-opening-value", opening.value);
    transcript.absorb_public(
        b"r1cs-opening-path-len",
        &(opening.path.len() as u64).to_le_bytes(),
    );
    for (level, (sibling, sibling_is_right)) in opening.path.iter().enumerate() {
        transcript.absorb_public(b"r1cs-opening-level", &(level as u64).to_le_bytes());
        transcript.absorb_public(b"r1cs-opening-sibling-side", &[*sibling_is_right as u8]);
        transcript.absorb_commitment(b"r1cs-opening-sibling", sibling);
    }
}

fn absorb_spark_memory_worker_digests<T: Transcript>(
    transcript: &mut T,
    worker_digests: &[SparkMemoryWorkerDigest],
) {
    transcript.absorb_domain(b"r1cs-distributed-spark-memory-worker-digests-v1");
    transcript.absorb_public(
        b"spark-memory-worker-digest-count",
        &(worker_digests.len() as u64).to_le_bytes(),
    );
    for worker in worker_digests {
        transcript.absorb_public(
            b"spark-memory-worker-id",
            &(worker.worker_id as u64).to_le_bytes(),
        );
        transcript.absorb_public(
            b"spark-memory-worker-entry-start",
            &(worker.entry_range.0 as u64).to_le_bytes(),
        );
        transcript.absorb_public(
            b"spark-memory-worker-entry-end",
            &(worker.entry_range.1 as u64).to_le_bytes(),
        );
        transcript.absorb_public(
            b"spark-memory-worker-memory-start",
            &(worker.memory_range.0 as u64).to_le_bytes(),
        );
        transcript.absorb_public(
            b"spark-memory-worker-memory-end",
            &(worker.memory_range.1 as u64).to_le_bytes(),
        );
        transcript.absorb_public(
            b"spark-memory-worker-access-count",
            &(worker.access_count as u64).to_le_bytes(),
        );
        transcript.absorb_field(b"spark-memory-worker-init-product", worker.init_product);
        transcript.absorb_field(b"spark-memory-worker-read-product", worker.read_product);
        transcript.absorb_field(b"spark-memory-worker-write-product", worker.write_product);
        transcript.absorb_field(b"spark-memory-worker-audit-product", worker.audit_product);
    }
}

fn absorb_instance_shape<T: Transcript>(
    instance: &R1csInstance,
    workers: usize,
    transcript: &mut T,
) {
    transcript.absorb_public(b"workers", &(workers as u64).to_le_bytes());
    transcript.absorb_public(b"rows", &(instance.a().rows() as u64).to_le_bytes());
    transcript.absorb_public(b"cols", &(instance.a().cols() as u64).to_le_bytes());
    for matrix in [instance.a(), instance.b(), instance.c()] {
        transcript.absorb_public(b"entries", &(matrix.entries().len() as u64).to_le_bytes());
        for entry in matrix.entries() {
            transcript.absorb_public(b"row", &(entry.row as u64).to_le_bytes());
            transcript.absorb_public(b"col", &(entry.col as u64).to_le_bytes());
            transcript.absorb_field(b"value", entry.value);
        }
    }
}

pub fn sample_proof(workers: usize) -> R1csPiopResult<R1csPiopProof> {
    let (instance, witness) = sample_r1cs();
    let mut transcript = HashTranscript::new(b"sample-r1cs");
    prove_r1cs(&instance, &witness, workers, &mut transcript)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn non_power_two_row_r1cs() -> (R1csInstance, Vec<FieldElement>) {
        let mut a = SparseMatrix::new(3, 4);
        let mut b = SparseMatrix::new(3, 4);
        let mut c = SparseMatrix::new(3, 4);
        a.add_entry(0, 1, FieldElement::ONE).expect("entry");
        b.add_entry(0, 2, FieldElement::ONE).expect("entry");
        c.add_entry(0, 3, FieldElement::ONE).expect("entry");
        a.add_entry(1, 3, FieldElement::ONE).expect("entry");
        b.add_entry(1, 0, FieldElement::ONE).expect("entry");
        c.add_entry(1, 3, FieldElement::ONE).expect("entry");
        a.add_entry(2, 0, FieldElement::ONE).expect("entry");
        b.add_entry(2, 0, FieldElement::ONE).expect("entry");
        c.add_entry(2, 0, FieldElement::ONE).expect("entry");
        (
            R1csInstance::new(a, b, c).expect("shape"),
            vec![
                FieldElement::ONE,
                FieldElement::from(3_u64),
                FieldElement::from(4_u64),
                FieldElement::from(12_u64),
            ],
        )
    }

    #[test]
    fn unified_piop_trait_drives_r1cs_route() {
        let (instance, witness) = sample_r1cs();
        let pcs_params = DistributedPcsParams::new(2);
        let mut prover_tr = HashTranscript::new(b"r1cs-piop-trait");
        let proof = R1csPiop::prove_interactive(&instance, &witness, 1, pcs_params, &mut prover_tr)
            .expect("trait proof");
        let mut verifier_tr = HashTranscript::new(b"r1cs-piop-trait");
        let metrics = R1csPiop::verify_interactive(&instance, &proof, pcs_params, &mut verifier_tr)
            .expect("trait verify");
        assert!(metrics.proof_bytes > 0);
        assert!(metrics.communication_bytes > 0);
    }

    #[test]
    fn r1cs_piop_accepts_and_rejects() {
        let (instance, witness) = sample_r1cs();
        let mut prover_tr = HashTranscript::new(b"r1cs-test");
        let proof = prove_r1cs(&instance, &witness, 1, &mut prover_tr).expect("proof");
        assert!(matches!(proof.residual_opening, R1csPcsOpening::Compact(_)));
        let mut verifier_tr = HashTranscript::new(b"r1cs-test");
        assert!(verify_r1cs(&instance, &proof, &mut verifier_tr).is_ok());

        let mut bad_proof = proof;
        bad_proof.row_queries[0].witness_openings[0].value += FieldElement::ONE;
        let mut verifier_tr = HashTranscript::new(b"r1cs-test");
        assert!(verify_r1cs(&instance, &bad_proof, &mut verifier_tr).is_err());
    }

    #[test]
    fn r1cs_hook_path_can_still_produce_full_pcs_openings() {
        let (instance, witness) = sample_r1cs();
        let mut prover_tr = HashTranscript::new(b"r1cs-full-hook");
        let proof = prove_r1cs_with_pcs_hooks(
            &instance,
            &witness,
            1,
            DistributedPcsParams::new(2),
            &mut prover_tr,
            |evaluations, workers| {
                DistributedBrakedown::commit_detached(evaluations, workers)
                    .map_err(|_| R1csPiopError::Pcs)
            },
            |evaluations, commitment, point, params, transcript| {
                DistributedBrakedown::open_at_after_commitment_with_params(
                    evaluations,
                    commitment,
                    point,
                    params,
                    transcript,
                )
                .map_err(|_| R1csPiopError::Pcs)
            },
        )
        .expect("full hook proof");
        assert!(matches!(proof.residual_opening, R1csPcsOpening::Full(_)));

        let mut verifier_tr = HashTranscript::new(b"r1cs-full-hook");
        assert!(
            verify_r1cs_with_pcs_params(
                &instance,
                &proof,
                DistributedPcsParams::new(2),
                &mut verifier_tr,
            )
            .is_ok()
        );
    }

    #[test]
    fn r1cs_opening_hook_path_can_produce_compact_pcs_openings() {
        let (instance, witness) = sample_r1cs();
        let params = DistributedPcsParams::new(2);
        let mut prover_tr = HashTranscript::new(b"r1cs-compact-hook");
        let proof = prove_r1cs_with_pcs_opening_hooks(
            &instance,
            &witness,
            2,
            params,
            &mut prover_tr,
            |evaluations, workers| {
                DistributedBrakedown::commit_detached(evaluations, workers)
                    .map_err(|_| R1csPiopError::Pcs)
            },
            |evaluations, commitment, point, params, transcript| {
                DistributedBrakedown::open_compact_at_after_commitment_with_params(
                    evaluations,
                    commitment,
                    point,
                    params,
                    transcript,
                )
                .map(R1csPcsOpening::Compact)
                .map_err(|_| R1csPiopError::Pcs)
            },
        )
        .expect("compact hook proof");

        assert!(matches!(proof.residual_opening, R1csPcsOpening::Compact(_)));
        assert!(matches!(
            proof.inner.witness_opening,
            R1csPcsOpening::Compact(_)
        ));

        let mut verifier_tr = HashTranscript::new(b"r1cs-compact-hook");
        verify_r1cs_with_pcs_params(&instance, &proof, params, &mut verifier_tr).expect("verify");
    }

    #[test]
    fn r1cs_row_domain_partitions_are_canonical_for_outer_spark_and_residual() {
        let (instance, witness) = non_power_two_row_r1cs();
        let params = DistributedPcsParams::new(2);
        let mut prover_tr = HashTranscript::new(b"r1cs-row-domain-partition");
        let proof = prove_r1cs_with_pcs_params(&instance, &witness, 2, params, &mut prover_tr)
            .expect("proof");
        let row_domain_len = instance.num_constraints().max(1).next_power_of_two();
        let plan = PartitionPlan::balanced(row_domain_len, 2).expect("plan");
        for (partition, worker) in plan
            .partitions()
            .iter()
            .zip(&proof.outer_commitments.az.workers)
        {
            assert_eq!(worker.worker_id, partition.id);
            assert_eq!(worker.range, (partition.start, partition.end));
        }
        for (partition, worker) in plan.partitions().iter().zip(&proof.spark.workers) {
            assert_eq!(worker.worker_id, partition.id);
            assert_eq!(worker.range, (partition.start, partition.end));
        }
        let mut verifier_tr = HashTranscript::new(b"r1cs-row-domain-partition");
        verify_r1cs_with_pcs_params(&instance, &proof, params, &mut verifier_tr).expect("verify");

        let mut commit_calls = 0_usize;
        let mut prover_tr = HashTranscript::new(b"r1cs-row-domain-partition-bad");
        let bad_proof = prove_r1cs_with_pcs_and_spark_batch_hooks(
            &instance,
            &witness,
            2,
            params,
            &mut prover_tr,
            R1csBatchProverHooks {
                commit_distributed: |evaluations: &[FieldElement], workers: usize| {
                    let actual_workers = if commit_calls < 3 { 1 } else { workers };
                    commit_calls += 1;
                    DistributedBrakedown::commit_detached(evaluations, actual_workers)
                        .map_err(|_| R1csPiopError::Pcs)
                },
                open_distributed:
                    |evaluations: &[FieldElement],
                     commitment: &DistributedCommitment,
                     point: &[FieldElement],
                     params: DistributedPcsParams,
                     transcript: &mut HashTranscript| {
                        DistributedBrakedown::open_compact_at_after_commitment_with_params(
                            evaluations,
                            commitment,
                            point,
                            params,
                            transcript,
                        )
                        .map(R1csPcsOpening::Compact)
                        .map_err(|_| R1csPiopError::Pcs)
                    },
                spark_worker_provider: |requests: &[SparkWorkerClaimRequest<'_>]| {
                    requests
                        .iter()
                        .map(|request| {
                            compute_spark_worker_shard_claim(
                                &instance,
                                request.partition,
                                request.challenges,
                                request.row_point,
                                request.col_point,
                            )
                        })
                        .collect()
                },
            },
        )
        .expect("bad-shape proof can be assembled");
        let mut verifier_tr = HashTranscript::new(b"r1cs-row-domain-partition-bad");
        assert_eq!(
            verify_r1cs_with_pcs_params(&instance, &bad_proof, params, &mut verifier_tr),
            Err(R1csPiopError::InvalidShape)
        );
    }

    #[test]
    fn r1cs_spark_worker_provider_feeds_prover_shard_claims() {
        let (instance, witness) = sample_r1cs();
        let params = DistributedPcsParams::new(2);
        let mut calls = Vec::new();
        let mut prover_tr = HashTranscript::new(b"r1cs-spark-worker-provider");
        let proof = prove_r1cs_with_pcs_and_spark_hooks(
            &instance,
            &witness,
            2,
            params,
            &mut prover_tr,
            R1csProverHooks {
                commit_distributed: |evaluations: &[FieldElement], workers: usize| {
                    DistributedBrakedown::commit_detached(evaluations, workers)
                        .map_err(|_| R1csPiopError::Pcs)
                },
                open_distributed:
                    |evaluations: &[FieldElement],
                     commitment: &DistributedCommitment,
                     point: &[FieldElement],
                     params: DistributedPcsParams,
                     transcript: &mut HashTranscript| {
                        DistributedBrakedown::open_compact_at_after_commitment_with_params(
                            evaluations,
                            commitment,
                            point,
                            params,
                            transcript,
                        )
                        .map(R1csPcsOpening::Compact)
                        .map_err(|_| R1csPiopError::Pcs)
                    },
                spark_worker_provider:
                    |partition: Partition,
                     challenges: SparkChallenges,
                     row_point: &[FieldElement],
                     col_point: &[FieldElement]| {
                        calls.push(partition.id);
                        compute_spark_worker_shard_claim(
                            &instance, partition, challenges, row_point, col_point,
                        )
                    },
            },
        )
        .expect("proof with Spark worker provider");

        assert_eq!(calls, vec![0, 1]);
        assert_eq!(proof.spark.workers.len(), 2);
        for matrix in &proof.spark.matrix_evaluations {
            assert_eq!(matrix.worker_evaluations.len(), 2);
        }
        let mut verifier_tr = HashTranscript::new(b"r1cs-spark-worker-provider");
        verify_r1cs_with_pcs_params(&instance, &proof, params, &mut verifier_tr)
            .expect("verify provider proof");
    }

    #[test]
    fn r1cs_spark_batch_worker_provider_matches_shard_claim_order() {
        let (instance, witness) = sample_r1cs();
        let params = DistributedPcsParams::new(2);
        let mut batch_calls = Vec::new();
        let mut prover_tr = HashTranscript::new(b"r1cs-spark-batch-worker-provider");
        let proof = prove_r1cs_with_pcs_and_spark_batch_hooks(
            &instance,
            &witness,
            2,
            params,
            &mut prover_tr,
            R1csBatchProverHooks {
                commit_distributed: |evaluations: &[FieldElement], workers: usize| {
                    DistributedBrakedown::commit_detached(evaluations, workers)
                        .map_err(|_| R1csPiopError::Pcs)
                },
                open_distributed:
                    |evaluations: &[FieldElement],
                     commitment: &DistributedCommitment,
                     point: &[FieldElement],
                     params: DistributedPcsParams,
                     transcript: &mut HashTranscript| {
                        DistributedBrakedown::open_compact_at_after_commitment_with_params(
                            evaluations,
                            commitment,
                            point,
                            params,
                            transcript,
                        )
                        .map(R1csPcsOpening::Compact)
                        .map_err(|_| R1csPiopError::Pcs)
                    },
                spark_worker_provider: |requests: &[SparkWorkerClaimRequest<'_>]| {
                    batch_calls.push(
                        requests
                            .iter()
                            .map(|request| request.partition.id)
                            .collect::<Vec<_>>(),
                    );
                    requests
                        .iter()
                        .map(|request| {
                            compute_spark_worker_shard_claim(
                                &instance,
                                request.partition,
                                request.challenges,
                                request.row_point,
                                request.col_point,
                            )
                        })
                        .collect()
                },
            },
        )
        .expect("proof with Spark batch worker provider");

        assert_eq!(batch_calls, vec![vec![0, 1]]);
        assert_eq!(proof.spark.workers.len(), 2);
        for matrix in &proof.spark.matrix_evaluations {
            assert_eq!(matrix.worker_evaluations.len(), 2);
        }
        let mut verifier_tr = HashTranscript::new(b"r1cs-spark-batch-worker-provider");
        verify_r1cs_with_pcs_params(&instance, &proof, params, &mut verifier_tr)
            .expect("verify batch provider proof");
    }

    #[test]
    fn r1cs_spark_worker_provider_rejects_malformed_claim_shape() {
        let (instance, witness) = sample_r1cs();
        let mut prover_tr = HashTranscript::new(b"r1cs-spark-worker-provider-bad");
        let err = prove_r1cs_with_pcs_and_spark_hooks(
            &instance,
            &witness,
            2,
            DistributedPcsParams::new(2),
            &mut prover_tr,
            R1csProverHooks {
                commit_distributed: |evaluations: &[FieldElement], workers: usize| {
                    DistributedBrakedown::commit_detached(evaluations, workers)
                        .map_err(|_| R1csPiopError::Pcs)
                },
                open_distributed:
                    |evaluations: &[FieldElement],
                     commitment: &DistributedCommitment,
                     point: &[FieldElement],
                     params: DistributedPcsParams,
                     transcript: &mut HashTranscript| {
                        DistributedBrakedown::open_compact_at_after_commitment_with_params(
                            evaluations,
                            commitment,
                            point,
                            params,
                            transcript,
                        )
                        .map(R1csPcsOpening::Compact)
                        .map_err(|_| R1csPiopError::Pcs)
                    },
                spark_worker_provider:
                    |partition: Partition,
                     challenges: SparkChallenges,
                     row_point: &[FieldElement],
                     col_point: &[FieldElement]| {
                        let mut claim = compute_spark_worker_shard_claim(
                            &instance, partition, challenges, row_point, col_point,
                        )?;
                        if partition.id == 0 {
                            claim.fingerprint.range.1 += 1;
                        }
                        Ok(claim)
                    },
            },
        )
        .expect_err("malformed Spark worker claim should be rejected");
        assert_eq!(err, R1csPiopError::InvalidProof);
    }

    #[test]
    fn spark_fingerprint_tampering_fails() {
        let (instance, witness) = sample_r1cs();
        let mut prover_tr = HashTranscript::new(b"r1cs-test-2");
        let mut proof = prove_r1cs(&instance, &witness, 1, &mut prover_tr).expect("proof");
        proof.spark.workers[0].linear_fingerprint += 1_u64.into();
        let mut verifier_tr = HashTranscript::new(b"r1cs-test-2");
        assert!(verify_r1cs(&instance, &proof, &mut verifier_tr).is_err());
    }

    #[test]
    fn spark_fingerprint_binds_partition_and_challenges() {
        let (instance, witness) = sample_r1cs();
        let mut prover_tr = HashTranscript::new(b"r1cs-spark-binding");
        let proof = prove_r1cs(&instance, &witness, 2, &mut prover_tr).expect("proof");
        assert_eq!(proof.spark.workers.len(), 2);
        assert_eq!(proof.spark.matrix_evaluations.len(), 3);

        let mut bad_range = proof.clone();
        bad_range.spark.workers[0].range.1 += 1;
        let mut verifier_tr = HashTranscript::new(b"r1cs-spark-binding");
        assert_eq!(
            verify_r1cs(&instance, &bad_range, &mut verifier_tr),
            Err(R1csPiopError::InvalidProof)
        );

        let mut bad_challenge = proof;
        bad_challenge.spark.row_challenge += FieldElement::ONE;
        let mut verifier_tr = HashTranscript::new(b"r1cs-spark-binding");
        assert_eq!(
            verify_r1cs(&instance, &bad_challenge, &mut verifier_tr),
            Err(R1csPiopError::InvalidProof)
        );
    }

    #[test]
    fn spark_memory_and_matrix_evaluation_tampering_fails() {
        let (instance, witness) = sample_r1cs();
        let mut prover_tr = HashTranscript::new(b"r1cs-spark-memory");
        let proof = prove_r1cs(&instance, &witness, 2, &mut prover_tr).expect("proof");
        assert_eq!(
            proof.spark.matrix_evaluations[0].row_memory.access_count,
            instance.a().entries().len()
        );
        assert_eq!(
            proof.spark.matrix_evaluations[0].value_memory.access_count,
            instance.a().entries().len()
        );
        assert_eq!(
            proof.spark.matrix_evaluations[0].value_memory.domain_len,
            instance.a().entries().len().max(1).next_power_of_two()
        );
        for (matrix_id, matrix_proof) in proof.spark.matrix_evaluations.iter().enumerate() {
            assert_eq!(matrix_proof.matrix_id, matrix_id);
            for worker_eval in &matrix_proof.worker_evaluations {
                assert_eq!(worker_eval.matrix_id, matrix_id);
            }
        }
        let row_memory = &proof.spark.matrix_evaluations[0].row_memory;
        assert_eq!(row_memory.trace_commitments.init.len, row_memory.domain_len);
        assert_eq!(
            row_memory.trace_commitments.audit.len,
            row_memory.domain_len
        );
        assert_eq!(
            row_memory.trace_commitments.reads.len,
            row_memory.access_count.max(1).next_power_of_two()
        );
        assert_eq!(
            row_memory.trace_commitments.writes.len,
            row_memory.access_count.max(1).next_power_of_two()
        );
        assert_eq!(
            row_memory.domain_queries.len(),
            DistributedPcsParams::default()
                .effective_query_count(row_memory.domain_len)
                .expect("domain query count")
        );
        assert_eq!(
            row_memory.access_queries.len(),
            DistributedPcsParams::default()
                .effective_query_count(row_memory.access_count)
                .expect("access query count")
        );

        let mut bad_matrix_eval = proof.clone();
        bad_matrix_eval.spark.matrix_evaluations[0].evaluation += FieldElement::ONE;
        let mut verifier_tr = HashTranscript::new(b"r1cs-spark-memory");
        assert_eq!(
            verify_r1cs(&instance, &bad_matrix_eval, &mut verifier_tr),
            Err(R1csPiopError::InvalidProof)
        );

        let mut bad_combined = proof.clone();
        bad_combined.spark.combined_evaluation += FieldElement::ONE;
        let mut verifier_tr = HashTranscript::new(b"r1cs-spark-memory");
        assert_eq!(
            verify_r1cs(&instance, &bad_combined, &mut verifier_tr),
            Err(R1csPiopError::InvalidProof)
        );

        let mut bad_worker_eval = proof.clone();
        bad_worker_eval.spark.matrix_evaluations[0].worker_evaluations[0].evaluation +=
            FieldElement::ONE;
        let mut verifier_tr = HashTranscript::new(b"r1cs-spark-memory");
        assert_eq!(
            verify_r1cs(&instance, &bad_worker_eval, &mut verifier_tr),
            Err(R1csPiopError::InvalidProof)
        );

        let mut bad_worker_eval_matrix = proof.clone();
        bad_worker_eval_matrix.spark.matrix_evaluations[0].worker_evaluations[0].matrix_id = 1;
        let mut verifier_tr = HashTranscript::new(b"r1cs-spark-memory");
        assert_eq!(
            verify_r1cs(&instance, &bad_worker_eval_matrix, &mut verifier_tr),
            Err(R1csPiopError::InvalidProof)
        );

        let mut bad_worker_digest = proof.clone();
        bad_worker_digest.spark.matrix_evaluations[0]
            .col_memory
            .worker_digests[0]
            .read_product += FieldElement::ONE;
        let mut verifier_tr = HashTranscript::new(b"r1cs-spark-memory");
        assert_eq!(
            verify_r1cs(&instance, &bad_worker_digest, &mut verifier_tr),
            Err(R1csPiopError::InvalidProof)
        );

        let mut bad_worker_digest_range = proof.clone();
        bad_worker_digest_range.spark.matrix_evaluations[0]
            .col_memory
            .worker_digests[0]
            .memory_range
            .1 += 1;
        let mut verifier_tr = HashTranscript::new(b"r1cs-spark-memory");
        assert_eq!(
            verify_r1cs(&instance, &bad_worker_digest_range, &mut verifier_tr),
            Err(R1csPiopError::InvalidProof)
        );

        let mut bad_domain_len = proof.clone();
        bad_domain_len.spark.matrix_evaluations[0]
            .row_memory
            .domain_len += 1;
        let mut verifier_tr = HashTranscript::new(b"r1cs-spark-memory");
        assert_eq!(
            verify_r1cs(&instance, &bad_domain_len, &mut verifier_tr),
            Err(R1csPiopError::InvalidProof)
        );

        let mut bad_access_count = proof.clone();
        bad_access_count.spark.matrix_evaluations[0]
            .row_memory
            .access_count += 1;
        let mut verifier_tr = HashTranscript::new(b"r1cs-spark-memory");
        assert_eq!(
            verify_r1cs(&instance, &bad_access_count, &mut verifier_tr),
            Err(R1csPiopError::InvalidProof)
        );

        let mut swapped_memory = proof.clone();
        {
            let matrix_eval = &mut swapped_memory.spark.matrix_evaluations[0];
            std::mem::swap(&mut matrix_eval.row_memory, &mut matrix_eval.col_memory);
        }
        let mut verifier_tr = HashTranscript::new(b"r1cs-spark-memory");
        assert!(verify_r1cs(&instance, &swapped_memory, &mut verifier_tr).is_err());

        let mut bad_trace_commitment = proof.clone();
        bad_trace_commitment.spark.matrix_evaluations[0]
            .row_memory
            .trace_commitments
            .init
            .root[0] ^= 1;
        let mut verifier_tr = HashTranscript::new(b"r1cs-spark-memory");
        assert_eq!(
            verify_r1cs(&instance, &bad_trace_commitment, &mut verifier_tr),
            Err(R1csPiopError::InvalidProof)
        );

        let mut bad_domain_query = proof.clone();
        bad_domain_query.spark.matrix_evaluations[0]
            .row_memory
            .domain_queries[0]
            .init
            .value += FieldElement::ONE;
        let mut verifier_tr = HashTranscript::new(b"r1cs-spark-memory");
        assert_eq!(
            verify_r1cs(&instance, &bad_domain_query, &mut verifier_tr),
            Err(R1csPiopError::InvalidProof)
        );

        let mut bad_access_query = proof.clone();
        bad_access_query.spark.matrix_evaluations[0]
            .row_memory
            .access_queries[0]
            .write
            .value += FieldElement::ONE;
        let mut verifier_tr = HashTranscript::new(b"r1cs-spark-memory");
        assert_eq!(
            verify_r1cs(&instance, &bad_access_query, &mut verifier_tr),
            Err(R1csPiopError::InvalidProof)
        );

        let mut bad_domain_path = proof.clone();
        bad_domain_path.spark.matrix_evaluations[0]
            .row_memory
            .domain_queries[0]
            .init
            .path[0]
            .0[0] ^= 1;
        let mut verifier_tr = HashTranscript::new(b"r1cs-spark-memory");
        assert!(verify_r1cs(&instance, &bad_domain_path, &mut verifier_tr).is_err());

        let mut missing_domain_query = proof.clone();
        missing_domain_query.spark.matrix_evaluations[0]
            .row_memory
            .domain_queries
            .pop();
        let mut verifier_tr = HashTranscript::new(b"r1cs-spark-memory");
        assert_eq!(
            verify_r1cs(&instance, &missing_domain_query, &mut verifier_tr),
            Err(R1csPiopError::InvalidProof)
        );

        let mut swapped_access_query = proof.clone();
        {
            let query = &mut swapped_access_query.spark.matrix_evaluations[0]
                .row_memory
                .access_queries[0];
            std::mem::swap(&mut query.read, &mut query.write);
        }
        let mut verifier_tr = HashTranscript::new(b"r1cs-spark-memory");
        assert!(verify_r1cs(&instance, &swapped_access_query, &mut verifier_tr).is_err());

        let mut bad_multiset = proof.clone();
        bad_multiset.spark.matrix_evaluations[0]
            .row_memory
            .multiset
            .left_product += FieldElement::ONE;
        let mut verifier_tr = HashTranscript::new(b"r1cs-spark-memory");
        assert!(verify_r1cs(&instance, &bad_multiset, &mut verifier_tr).is_err());

        let mut bad_multiset_log_derivative = proof.clone();
        bad_multiset_log_derivative.spark.matrix_evaluations[0]
            .row_memory
            .multiset
            .left_log_derivative
            .sumcheck
            .rounds[0]
            .eval_at_0 += FieldElement::ONE;
        let mut verifier_tr = HashTranscript::new(b"r1cs-spark-memory");
        assert!(verify_r1cs(&instance, &bad_multiset_log_derivative, &mut verifier_tr).is_err());

        let mut bad_multiset_gamma = proof.clone();
        bad_multiset_gamma.spark.matrix_evaluations[0]
            .row_memory
            .multiset
            .gamma += FieldElement::ONE;
        let mut verifier_tr = HashTranscript::new(b"r1cs-spark-memory");
        assert!(verify_r1cs(&instance, &bad_multiset_gamma, &mut verifier_tr).is_err());

        let mut bad_multiset_len = proof.clone();
        bad_multiset_len.spark.matrix_evaluations[0]
            .row_memory
            .multiset
            .f1_len += 1;
        let mut verifier_tr = HashTranscript::new(b"r1cs-spark-memory");
        assert!(verify_r1cs(&instance, &bad_multiset_len, &mut verifier_tr).is_err());

        let mut bad_value_worker_digest = proof.clone();
        bad_value_worker_digest.spark.matrix_evaluations[0]
            .value_memory
            .worker_digests[0]
            .read_product += FieldElement::ONE;
        let mut verifier_tr = HashTranscript::new(b"r1cs-spark-memory");
        assert_eq!(
            verify_r1cs(&instance, &bad_value_worker_digest, &mut verifier_tr),
            Err(R1csPiopError::InvalidProof)
        );

        let mut bad_value_multiset = proof.clone();
        bad_value_multiset.spark.matrix_evaluations[0]
            .value_memory
            .multiset
            .left_product += FieldElement::ONE;
        let mut verifier_tr = HashTranscript::new(b"r1cs-spark-memory");
        assert!(verify_r1cs(&instance, &bad_value_multiset, &mut verifier_tr).is_err());

        let mut bad_value_hash = proof.clone();
        bad_value_hash.spark.matrix_evaluations[0]
            .value_memory
            .hash_challenge += FieldElement::ONE;
        let mut verifier_tr = HashTranscript::new(b"r1cs-spark-memory");
        assert_eq!(
            verify_r1cs(&instance, &bad_value_hash, &mut verifier_tr),
            Err(R1csPiopError::InvalidProof)
        );

        let mut bad_memory_hash = proof;
        bad_memory_hash.spark.matrix_evaluations[0]
            .row_memory
            .hash_challenge += FieldElement::ONE;
        let mut verifier_tr = HashTranscript::new(b"r1cs-spark-memory");
        assert_eq!(
            verify_r1cs(&instance, &bad_memory_hash, &mut verifier_tr),
            Err(R1csPiopError::InvalidProof)
        );
    }

    #[test]
    fn spark_matrix_statement_absorbs_sparse_entries() {
        let (instance, _) = sample_r1cs();
        let row_point = vec![FieldElement::from(2_u64), FieldElement::from(3_u64)];
        let col_point = vec![FieldElement::from(5_u64), FieldElement::from(7_u64)];

        let mut original_tr = HashTranscript::new(b"spark-matrix-statement");
        absorb_spark_matrix_evaluation_statement(
            &mut original_tr,
            0,
            instance.a(),
            &row_point,
            &col_point,
        );
        let original_challenge = original_tr.challenge_field::<FieldElement>(b"statement-binding");

        let mut altered_entries = instance.a().entries().to_vec();
        altered_entries[0].value += FieldElement::ONE;
        let altered =
            SparseMatrix::from_entries(instance.a().rows(), instance.a().cols(), altered_entries)
                .expect("altered matrix");
        let mut altered_tr = HashTranscript::new(b"spark-matrix-statement");
        absorb_spark_matrix_evaluation_statement(
            &mut altered_tr,
            0,
            &altered,
            &row_point,
            &col_point,
        );
        let altered_challenge = altered_tr.challenge_field::<FieldElement>(b"statement-binding");

        assert_ne!(original_challenge, altered_challenge);

        let mut reordered_entries = instance.a().entries().to_vec();
        reordered_entries.swap(0, 1);
        let reordered =
            SparseMatrix::from_entries(instance.a().rows(), instance.a().cols(), reordered_entries)
                .expect("reordered matrix");
        let mut reordered_tr = HashTranscript::new(b"spark-matrix-statement");
        absorb_spark_matrix_evaluation_statement(
            &mut reordered_tr,
            0,
            &reordered,
            &row_point,
            &col_point,
        );
        let reordered_challenge =
            reordered_tr.challenge_field::<FieldElement>(b"statement-binding");
        assert_ne!(original_challenge, reordered_challenge);
    }

    #[test]
    fn spark_memory_trace_sampling_binds_commitments_and_openings() {
        let memory_values = vec![
            FieldElement::from(3_u64),
            FieldElement::from(5_u64),
            FieldElement::from(7_u64),
            FieldElement::from(11_u64),
        ];
        let access_indices = vec![0, 2, 0];
        let hash_challenge = FieldElement::from(13_u64);
        let trace =
            spark_memory_trace(4, &memory_values, &access_indices, hash_challenge).expect("trace");
        let commitments = commit_spark_memory_trace(&trace).expect("commit trace");
        let params = DistributedPcsParams::new(1);

        let mut transcript = HashTranscript::new(b"spark-trace-sampling");
        let (domain_indices, access_sample_indices) = challenge_spark_memory_trace_queries(
            &mut transcript,
            b"row",
            0,
            4,
            access_indices.len(),
            params,
            &commitments,
        )
        .expect("query indices");
        let (domain_queries, access_queries) =
            open_spark_memory_trace_queries(&trace, &domain_indices, &access_sample_indices)
                .expect("open trace queries");
        verify_spark_memory_trace_queries(
            &trace,
            hash_challenge,
            &commitments,
            &domain_indices,
            &access_sample_indices,
            &domain_queries,
            &access_queries,
        )
        .expect("verify trace queries");

        let mut bad_path = domain_queries.clone();
        bad_path[0].init.path[0].0[0] ^= 1;
        assert_eq!(
            verify_spark_memory_trace_queries(
                &trace,
                hash_challenge,
                &commitments,
                &domain_indices,
                &access_sample_indices,
                &bad_path,
                &access_queries,
            ),
            Err(R1csPiopError::Pcs)
        );

        let mut bad_access_preimage = access_queries.clone();
        if let Some(first) = bad_access_preimage.first_mut() {
            first.write_timestamp += FieldElement::ONE;
        }
        assert_eq!(
            verify_spark_memory_trace_queries(
                &trace,
                hash_challenge,
                &commitments,
                &domain_indices,
                &access_sample_indices,
                &domain_queries,
                &bad_access_preimage,
            ),
            Err(R1csPiopError::InvalidProof)
        );

        let mut commitment_transcript = HashTranscript::new(b"spark-trace-transcript");
        let _ = challenge_spark_memory_trace_queries(
            &mut commitment_transcript,
            b"row",
            0,
            4,
            access_indices.len(),
            params,
            &commitments,
        )
        .expect("query indices");
        let commitment_bound =
            commitment_transcript.challenge_field::<FieldElement>(b"post-commitment");
        let mut bad_commitments = commitments.clone();
        bad_commitments.reads.root[0] ^= 1;
        let mut bad_commitment_transcript = HashTranscript::new(b"spark-trace-transcript");
        let _ = challenge_spark_memory_trace_queries(
            &mut bad_commitment_transcript,
            b"row",
            0,
            4,
            access_indices.len(),
            params,
            &bad_commitments,
        )
        .expect("query indices");
        assert_ne!(
            commitment_bound,
            bad_commitment_transcript.challenge_field::<FieldElement>(b"post-commitment")
        );

        let mut opening_transcript = HashTranscript::new(b"spark-opening-transcript");
        absorb_spark_memory_trace_queries(
            &mut opening_transcript,
            &domain_queries,
            &access_queries,
        );
        let opening_bound = opening_transcript.challenge_field::<FieldElement>(b"post-opening");
        let mut bad_domain_queries = domain_queries.clone();
        bad_domain_queries[0].init.value += FieldElement::ONE;
        let mut bad_opening_transcript = HashTranscript::new(b"spark-opening-transcript");
        absorb_spark_memory_trace_queries(
            &mut bad_opening_transcript,
            &bad_domain_queries,
            &access_queries,
        );
        assert_ne!(
            opening_bound,
            bad_opening_transcript.challenge_field::<FieldElement>(b"post-opening")
        );
    }

    #[test]
    fn spark_memory_allows_empty_access_trace_without_sampling_reads() {
        let empty = SparseMatrix::new(1, 1);
        let instance = R1csInstance::new(empty.clone(), empty.clone(), empty).expect("zero r1cs");
        let witness = vec![FieldElement::ZERO];
        let params = DistributedPcsParams::new(3);
        let mut prover_tr = HashTranscript::new(b"r1cs-empty-spark-memory");
        let proof = prove_r1cs_with_pcs_params(&instance, &witness, 1, params, &mut prover_tr)
            .expect("proof");
        for matrix in &proof.spark.matrix_evaluations {
            for memory in [&matrix.row_memory, &matrix.col_memory, &matrix.value_memory] {
                assert_eq!(memory.access_count, 0);
                assert_eq!(memory.trace_commitments.reads.len, 1);
                assert_eq!(memory.trace_commitments.writes.len, 1);
                assert!(memory.access_queries.is_empty());
                assert_eq!(memory.domain_queries.len(), 1);
            }
        }
        let mut verifier_tr = HashTranscript::new(b"r1cs-empty-spark-memory");
        verify_r1cs_with_pcs_params(&instance, &proof, params, &mut verifier_tr).expect("verify");
    }

    #[test]
    fn pcs_opening_must_match_sumcheck_point_and_value() {
        let (instance, witness) = sample_r1cs();
        let mut prover_tr = HashTranscript::new(b"r1cs-binding");
        let proof = prove_r1cs(&instance, &witness, 1, &mut prover_tr).expect("proof");

        let mut bad_point = proof.clone();
        bad_point.residual_opening.point_mut()[0] += FieldElement::ONE;
        let mut verifier_tr = HashTranscript::new(b"r1cs-binding");
        assert_eq!(
            verify_r1cs(&instance, &bad_point, &mut verifier_tr),
            Err(R1csPiopError::InvalidProof)
        );

        let mut bad_value = proof;
        *bad_value.residual_opening.claimed_value_mut() += FieldElement::ONE;
        let mut verifier_tr = HashTranscript::new(b"r1cs-binding");
        assert_eq!(
            verify_r1cs(&instance, &bad_value, &mut verifier_tr),
            Err(R1csPiopError::InvalidProof)
        );
    }

    #[test]
    fn outer_sumcheck_binds_linearization_openings() {
        let (instance, witness) = sample_r1cs();
        let mut prover_tr = HashTranscript::new(b"r1cs-outer");
        let proof = prove_r1cs(&instance, &witness, 1, &mut prover_tr).expect("proof");

        let mut bad_round = proof.clone();
        bad_round.outer_sumcheck.rounds[0].eval_at_3 += FieldElement::ONE;
        let mut verifier_tr = HashTranscript::new(b"r1cs-outer");
        assert_eq!(
            verify_r1cs(&instance, &bad_round, &mut verifier_tr),
            Err(R1csPiopError::Sumcheck)
        );

        let mut bad_point = proof.clone();
        bad_point.outer_openings.az.point_mut()[0] += FieldElement::ONE;
        let mut verifier_tr = HashTranscript::new(b"r1cs-outer");
        assert_eq!(
            verify_r1cs(&instance, &bad_point, &mut verifier_tr),
            Err(R1csPiopError::InvalidProof)
        );

        let mut bad_value = proof;
        *bad_value.outer_openings.bz.claimed_value_mut() += FieldElement::ONE;
        let mut verifier_tr = HashTranscript::new(b"r1cs-outer");
        assert!(verify_r1cs(&instance, &bad_value, &mut verifier_tr).is_err());
    }

    #[test]
    fn inner_sumcheck_binds_witness_opening_and_matrix_projection() {
        let (instance, witness) = sample_r1cs();
        let mut prover_tr = HashTranscript::new(b"r1cs-inner");
        let proof = prove_r1cs(&instance, &witness, 1, &mut prover_tr).expect("proof");
        let projected = projected_matrix_vector(
            &instance,
            proof.outer_openings.az.point(),
            proof.inner.matrix_challenges,
            proof.inner.witness_commitment.original_len,
        )
        .expect("projected matrix");
        assert_eq!(
            evaluate_mle(&projected, &proof.inner.sumcheck.challenges).expect("projected eval")
                * proof.inner.witness_opening.claimed_value(),
            proof.inner.sumcheck.final_evaluation
        );
        assert_eq!(
            proof.witness_consistency_queries.len(),
            DistributedPcsParams::default()
                .effective_query_count(proof.inner.witness_commitment.original_len)
                .expect("witness consistency query count")
        );
        for query in &proof.witness_consistency_queries {
            assert_eq!(
                query.oracle_opening.value,
                query.distributed_opening.proof.value
            );
        }

        let mut bad_round = proof.clone();
        bad_round.inner.sumcheck.rounds[0].eval_at_2 += FieldElement::ONE;
        let mut verifier_tr = HashTranscript::new(b"r1cs-inner");
        assert!(verify_r1cs(&instance, &bad_round, &mut verifier_tr).is_err());

        let mut bad_challenge = proof.clone();
        bad_challenge.inner.matrix_challenges[0] += FieldElement::ONE;
        let mut verifier_tr = HashTranscript::new(b"r1cs-inner");
        assert!(verify_r1cs(&instance, &bad_challenge, &mut verifier_tr).is_err());

        let mut bad_point = proof.clone();
        bad_point.inner.witness_opening.point_mut()[0] += FieldElement::ONE;
        let mut verifier_tr = HashTranscript::new(b"r1cs-inner");
        assert!(verify_r1cs(&instance, &bad_point, &mut verifier_tr).is_err());

        let mut bad_value = proof;
        *bad_value.inner.witness_opening.claimed_value_mut() += FieldElement::ONE;
        let mut verifier_tr = HashTranscript::new(b"r1cs-inner");
        assert!(verify_r1cs(&instance, &bad_value, &mut verifier_tr).is_err());
    }

    #[test]
    fn witness_consistency_queries_bind_local_and_distributed_commitments() {
        let (instance, witness) = sample_r1cs();
        let params = DistributedPcsParams::new(2);
        let mut prover_tr = HashTranscript::new(b"r1cs-witness-consistency");
        let proof = prove_r1cs_with_pcs_params(&instance, &witness, 1, params, &mut prover_tr)
            .expect("proof");
        assert_eq!(proof.witness_consistency_queries.len(), 2);
        let mut verifier_tr = HashTranscript::new(b"r1cs-witness-consistency");
        verify_r1cs_with_pcs_params(&instance, &proof, params, &mut verifier_tr).expect("verify");
        assert_eq!(prover_tr.state(), verifier_tr.state());

        let mut bad_oracle_value = proof.clone();
        bad_oracle_value.witness_consistency_queries[0]
            .oracle_opening
            .value += FieldElement::ONE;
        let mut verifier_tr = HashTranscript::new(b"r1cs-witness-consistency");
        assert!(
            verify_r1cs_with_pcs_params(&instance, &bad_oracle_value, params, &mut verifier_tr)
                .is_err()
        );

        let mut bad_distributed_value = proof.clone();
        bad_distributed_value.witness_consistency_queries[0]
            .distributed_opening
            .proof
            .value += FieldElement::ONE;
        let mut verifier_tr = HashTranscript::new(b"r1cs-witness-consistency");
        assert!(
            verify_r1cs_with_pcs_params(
                &instance,
                &bad_distributed_value,
                params,
                &mut verifier_tr
            )
            .is_err()
        );

        let mut bad_index = proof;
        bad_index.witness_consistency_queries[0].index += 1;
        let mut verifier_tr = HashTranscript::new(b"r1cs-witness-consistency");
        assert!(
            verify_r1cs_with_pcs_params(&instance, &bad_index, params, &mut verifier_tr).is_err()
        );
    }

    #[test]
    fn communication_accounting_includes_sampled_distributed_index_openings() {
        let (instance, witness) = sample_r1cs();
        let params = DistributedPcsParams::new(2);
        let mut prover_tr = HashTranscript::new(b"r1cs-communication-accounting");
        let proof = prove_r1cs_with_pcs_params(&instance, &witness, 1, params, &mut prover_tr)
            .expect("proof");

        let main_openings = proof.outer_openings.az.communication_bytes()
            + proof.outer_openings.bz.communication_bytes()
            + proof.outer_openings.cz.communication_bytes()
            + proof.inner.witness_opening.communication_bytes()
            + proof.residual_opening.communication_bytes();
        let sampled_index_openings = proof
            .witness_consistency_queries
            .iter()
            .map(witness_consistency_query_communication_bytes)
            .sum::<usize>()
            + proof
                .row_queries
                .iter()
                .map(row_query_communication_bytes)
                .sum::<usize>();
        assert!(sampled_index_openings > 0);
        assert_eq!(
            proof_communication_bytes(&proof),
            main_openings + sampled_index_openings
        );

        let mut verifier_tr = HashTranscript::new(b"r1cs-communication-accounting");
        let metrics = verify_r1cs_with_pcs_params(&instance, &proof, params, &mut verifier_tr)
            .expect("verify");
        assert_eq!(
            metrics.communication_bytes,
            proof_communication_bytes(&proof)
        );
    }

    #[test]
    fn zerocheck_rejects_plain_sum_cancellation() {
        let canceling = MultilinearPolynomial::new(vec![FieldElement::ONE, -FieldElement::ONE])
            .expect("canceling polynomial");
        assert!(canceling.sum_over_boolean_hypercube().is_zero());
        let mut transcript = HashTranscript::new(b"r1cs-canceling-zerocheck");
        assert!(prove_zerocheck_proof(&canceling, &mut transcript).is_err());
    }

    #[test]
    fn row_consistency_queries_cover_all_constraints_when_query_count_is_large() {
        let (instance, witness) = sample_r1cs();
        let mut prover_tr = HashTranscript::new(b"r1cs-full-row-sample");
        let proof = prove_r1cs(&instance, &witness, 1, &mut prover_tr).expect("proof");
        let mut queried = proof
            .row_queries
            .iter()
            .map(|query| query.row)
            .collect::<Vec<_>>();
        queried.sort_unstable();
        assert_eq!(queried, (0..instance.num_constraints()).collect::<Vec<_>>());
    }

    #[test]
    fn row_consistency_queries_are_sampled_by_query_count() {
        let (instance, witness) = sample_r1cs();
        let params = DistributedPcsParams::new(2);
        let mut prover_tr = HashTranscript::new(b"r1cs-sampled-rows");
        let proof = prove_r1cs_with_pcs_params(&instance, &witness, 1, params, &mut prover_tr)
            .expect("proof");

        assert_eq!(proof.row_queries.len(), 2);
        let mut queried = proof
            .row_queries
            .iter()
            .map(|query| query.row)
            .collect::<Vec<_>>();
        queried.sort_unstable();
        queried.dedup();
        assert_eq!(queried.len(), 2);
        let row_memory = &proof.spark.matrix_evaluations[0].row_memory;
        assert_eq!(
            row_memory.domain_queries.len(),
            params
                .effective_query_count(row_memory.domain_len)
                .expect("domain query count")
        );
        assert_eq!(
            row_memory.access_queries.len(),
            params
                .effective_query_count(row_memory.access_count)
                .expect("access query count")
        );

        let mut verifier_tr = HashTranscript::new(b"r1cs-sampled-rows");
        verify_r1cs_with_pcs_params(&instance, &proof, params, &mut verifier_tr).expect("verify");
    }

    #[test]
    fn row_consistency_query_openings_bind_spark_challenges() {
        let (instance, witness) = sample_r1cs();
        let params = DistributedPcsParams::new(2);
        let mut prover_tr = HashTranscript::new(b"r1cs-row-query-binding");
        let proof = prove_r1cs_with_pcs_params(&instance, &witness, 1, params, &mut prover_tr)
            .expect("proof");

        let mut original_transcript = HashTranscript::new(b"r1cs-row-query-binding-helper");
        absorb_row_consistency_queries(&mut original_transcript, &proof.row_queries);
        let (_, original_challenges) =
            derive_spark_challenges(&instance, proof.workers, &mut original_transcript)
                .expect("original spark challenges");

        let mut tampered_queries = proof.row_queries.clone();
        tampered_queries[0].az_opening.value += FieldElement::ONE;
        let mut tampered_transcript = HashTranscript::new(b"r1cs-row-query-binding-helper");
        absorb_row_consistency_queries(&mut tampered_transcript, &tampered_queries);
        let (_, tampered_challenges) =
            derive_spark_challenges(&instance, proof.workers, &mut tampered_transcript)
                .expect("tampered spark challenges");

        assert_ne!(original_transcript.state(), tampered_transcript.state());
        assert_ne!(original_challenges, tampered_challenges);

        let mut verifier_tr = HashTranscript::new(b"r1cs-row-query-binding");
        verify_r1cs_with_pcs_params(&instance, &proof, params, &mut verifier_tr).expect("verify");
    }

    #[test]
    fn proof_size_accounting_includes_spark_fingerprints() {
        let (instance, witness) = sample_r1cs();
        let mut prover_tr = HashTranscript::new(b"r1cs-size-accounting");
        let mut proof = prove_r1cs(&instance, &witness, 1, &mut prover_tr).expect("proof");
        let original_size = proof_size_bytes(&proof);

        proof.spark.workers.push(SparkWorkerFingerprint {
            worker_id: 99,
            range: (0, 0),
            entry_count: 0,
            linear_fingerprint: FieldElement::ZERO,
            product_fingerprint: FieldElement::ONE,
        });
        assert_eq!(
            proof_size_bytes(&proof),
            original_size + spark_worker_fingerprint_size_bytes()
        );
    }

    #[test]
    fn proof_size_accounting_includes_compact_spark_memory_product_checks() {
        let (instance, witness) = sample_r1cs();
        let mut prover_tr = HashTranscript::new(b"r1cs-spark-memory-size-accounting");
        let proof = prove_r1cs(&instance, &witness, 1, &mut prover_tr).expect("proof");
        let row_memory = &proof.spark.matrix_evaluations[0].row_memory;
        assert_eq!(
            spark_memory_check_size_bytes(row_memory),
            3 * 8
                + spark_memory_trace_commitments_size_bytes(&row_memory.trace_commitments)
                + vec_len_prefix()
                + row_memory
                    .domain_queries
                    .iter()
                    .map(spark_memory_domain_query_size_bytes)
                    .sum::<usize>()
                + vec_len_prefix()
                + row_memory
                    .access_queries
                    .iter()
                    .map(spark_memory_access_query_size_bytes)
                    .sum::<usize>()
                + vec_len_prefix()
                + row_memory.worker_digests.len() * spark_memory_worker_digest_size_bytes()
                + product_multiset_equality_proof_size_bytes(&row_memory.multiset)
        );
        assert!(row_memory.multiset.left_product == row_memory.multiset.right_product);
        assert_eq!(
            row_memory.multiset.left_log_derivative.claimed_sum,
            row_memory.multiset.right_log_derivative.claimed_sum
        );

        let mut no_worker_digests = row_memory.clone();
        no_worker_digests.worker_digests.clear();
        assert_eq!(
            spark_memory_check_size_bytes(&no_worker_digests),
            3 * 8
                + spark_memory_trace_commitments_size_bytes(&row_memory.trace_commitments)
                + vec_len_prefix()
                + row_memory
                    .domain_queries
                    .iter()
                    .map(spark_memory_domain_query_size_bytes)
                    .sum::<usize>()
                + vec_len_prefix()
                + row_memory
                    .access_queries
                    .iter()
                    .map(spark_memory_access_query_size_bytes)
                    .sum::<usize>()
                + vec_len_prefix()
                + product_multiset_equality_proof_size_bytes(&row_memory.multiset)
        );
        assert!(
            proof.spark.matrix_evaluations[0]
                .row_memory
                .multiset
                .left_product
                == proof.spark.matrix_evaluations[0]
                    .row_memory
                    .multiset
                    .right_product
        );

        let value_memory = &proof.spark.matrix_evaluations[0].value_memory;
        assert_eq!(value_memory.access_count, instance.a().entries().len());
        assert_eq!(
            spark_memory_check_size_bytes(value_memory),
            3 * 8
                + spark_memory_trace_commitments_size_bytes(&value_memory.trace_commitments)
                + vec_len_prefix()
                + value_memory
                    .domain_queries
                    .iter()
                    .map(spark_memory_domain_query_size_bytes)
                    .sum::<usize>()
                + vec_len_prefix()
                + value_memory
                    .access_queries
                    .iter()
                    .map(spark_memory_access_query_size_bytes)
                    .sum::<usize>()
                + vec_len_prefix()
                + value_memory.worker_digests.len() * spark_memory_worker_digest_size_bytes()
                + product_multiset_equality_proof_size_bytes(&value_memory.multiset)
        );

        let mut without_domain_query = row_memory.clone();
        let removed_domain_query = without_domain_query
            .domain_queries
            .pop()
            .expect("domain query");
        assert_eq!(
            spark_memory_check_size_bytes(&without_domain_query),
            spark_memory_check_size_bytes(row_memory)
                - spark_memory_domain_query_size_bytes(&removed_domain_query)
        );

        let original_matrix_eval_size =
            spark_matrix_evaluation_size_bytes(&proof.spark.matrix_evaluations[0]);
        let mut without_value_digests = proof.spark.matrix_evaluations[0].clone();
        let removed_value_digest_bytes = without_value_digests.value_memory.worker_digests.len()
            * spark_memory_worker_digest_size_bytes();
        without_value_digests.value_memory.worker_digests.clear();
        assert_eq!(
            spark_matrix_evaluation_size_bytes(&without_value_digests),
            original_matrix_eval_size - removed_value_digest_bytes
        );
    }

    #[test]
    fn inner_final_check_depends_on_spark_combined_evaluation() {
        let (instance, witness) = sample_r1cs();
        let mut prover_tr = HashTranscript::new(b"r1cs-spark-inner-link");
        let proof = prove_r1cs(&instance, &witness, 1, &mut prover_tr).expect("proof");
        verify_inner_spark_link(&proof.inner, &proof.spark).expect("link");

        let mut bad_inner = proof.inner.clone();
        bad_inner.sumcheck.final_evaluation += FieldElement::ONE;
        assert_eq!(
            verify_inner_spark_link(&bad_inner, &proof.spark),
            Err(R1csPiopError::InvalidProof)
        );
    }

    #[test]
    fn row_consistency_queries_reject_bad_linearization() {
        let (instance, witness) = sample_r1cs();
        let mut prover_tr = HashTranscript::new(b"r1cs-row");
        let mut proof = prove_r1cs(&instance, &witness, 1, &mut prover_tr).expect("proof");
        proof.row_queries[0].az_opening.value += FieldElement::ONE;

        let mut verifier_tr = HashTranscript::new(b"r1cs-row");
        assert_eq!(
            verify_r1cs(&instance, &proof, &mut verifier_tr),
            Err(R1csPiopError::Pcs)
        );
    }

    #[test]
    fn worker_count_is_bound_to_commitment_shape() {
        let (instance, witness) = sample_r1cs();
        let mut prover_tr = HashTranscript::new(b"r1cs-workers");
        let mut proof = prove_r1cs(&instance, &witness, 1, &mut prover_tr).expect("proof");
        proof.workers = 2;

        let mut verifier_tr = HashTranscript::new(b"r1cs-workers");
        assert_eq!(
            verify_r1cs(&instance, &proof, &mut verifier_tr),
            Err(R1csPiopError::InvalidShape)
        );
    }

    #[test]
    fn oracle_lengths_are_bound_to_instance_shape() {
        let (instance, witness) = sample_r1cs();
        let mut prover_tr = HashTranscript::new(b"r1cs-shape");
        let proof = prove_r1cs(&instance, &witness, 1, &mut prover_tr).expect("proof");

        let mut bad_witness_len = proof.clone();
        bad_witness_len.oracle_commitments.witness.len *= 2;
        let mut verifier_tr = HashTranscript::new(b"r1cs-shape");
        assert_eq!(
            verify_r1cs(&instance, &bad_witness_len, &mut verifier_tr),
            Err(R1csPiopError::InvalidShape)
        );

        let mut bad_residual_len = proof;
        bad_residual_len.residual_commitment.original_len *= 2;
        let mut verifier_tr = HashTranscript::new(b"r1cs-shape");
        assert_eq!(
            verify_r1cs(&instance, &bad_residual_len, &mut verifier_tr),
            Err(R1csPiopError::InvalidShape)
        );
    }
}

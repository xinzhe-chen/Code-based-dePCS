use pq_core::{
    FieldElement, MultilinearPolynomial, PartitionPlan, R1csInstance, SparseEntry, SparseMatrix,
    eq_basis, evaluate_mle, log2_power_of_two, sample_r1cs,
};
use pq_pcs::{
    Commitment, DistributedBrakedown, DistributedCommitment, DistributedIndexOpening,
    DistributedOpening, DistributedPcsParams, MerklePcs, OpeningProof, PolynomialCommitment,
    commitment_size_bytes, communication_bytes, distributed_commitment_size_bytes,
    distributed_index_opening_size_bytes, opening_proof_size_bytes,
    proof_size_bytes as pcs_proof_size_bytes,
};
use pq_sumcheck::{
    CubicZerocheckProof, ProductSumcheckProof, ZerocheckProof, cubic_zerocheck_final_evaluation,
    prove_cubic_zerocheck, prove_product_sumcheck, prove_zerocheck_proof,
    verify_cubic_zerocheck_rounds, verify_product_sumcheck_rounds, verify_zerocheck_rounds,
    zerocheck_final_evaluation,
};
use pq_transcript::{HashTranscript, Transcript};

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum R1csPiopError {
    Unsatisfied,
    InvalidProof,
    InvalidShape,
    Pcs,
    Sumcheck,
}

pub type R1csPiopResult<T> = Result<T, R1csPiopError>;

#[derive(Clone, Debug, PartialEq, Eq)]
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
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SparkWorkerFingerprint {
    pub worker_id: usize,
    pub range: (usize, usize),
    pub entry_count: usize,
    pub linear_fingerprint: FieldElement,
    pub product_fingerprint: FieldElement,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
struct SparkChallenges {
    tuple: FieldElement,
    matrix: FieldElement,
    row: FieldElement,
    col: FieldElement,
    value: FieldElement,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct R1csPiopProof {
    pub oracle_commitments: R1csOracleCommitments,
    pub outer_commitments: R1csOuterCommitments,
    pub outer_openings: R1csOuterOpenings,
    pub outer_sumcheck: CubicZerocheckProof,
    pub inner: R1csInnerProof,
    pub residual_commitment: DistributedCommitment,
    pub residual_opening: DistributedOpening,
    pub sumcheck: ZerocheckProof,
    pub row_queries: Vec<R1csRowConsistencyQuery>,
    pub spark: DistributedSparkProof,
    pub workers: usize,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct R1csOracleCommitments {
    pub witness: Commitment,
    pub az: Commitment,
    pub bz: Commitment,
    pub cz: Commitment,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct R1csOuterCommitments {
    pub az: DistributedCommitment,
    pub bz: DistributedCommitment,
    pub cz: DistributedCommitment,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct R1csOuterOpenings {
    pub az: DistributedOpening,
    pub bz: DistributedOpening,
    pub cz: DistributedOpening,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct R1csInnerProof {
    pub matrix_challenges: [FieldElement; 3],
    pub witness_commitment: DistributedCommitment,
    pub sumcheck: ProductSumcheckProof,
    pub witness_opening: DistributedOpening,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct R1csRowConsistencyQuery {
    pub row: usize,
    pub witness_openings: Vec<OpeningProof>,
    pub az_opening: OpeningProof,
    pub bz_opening: OpeningProof,
    pub cz_opening: OpeningProof,
    pub residual_opening: DistributedIndexOpening,
}

#[derive(Clone, Debug, PartialEq, Eq)]
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
    prove_r1cs_with_pcs_hooks(
        instance,
        witness,
        workers,
        pcs_params,
        transcript,
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
}

pub fn prove_r1cs_with_pcs_hooks<T, C, O>(
    instance: &R1csInstance,
    witness: &[FieldElement],
    workers: usize,
    pcs_params: DistributedPcsParams,
    transcript: &mut T,
    mut commit_distributed: C,
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
    if !instance
        .is_satisfied(witness)
        .map_err(|_| R1csPiopError::Unsatisfied)?
    {
        return Err(R1csPiopError::Unsatisfied);
    }
    let vectors = constraint_vectors(instance, witness)?;
    transcript.absorb_domain(b"r1cs-piop-v1");
    absorb_instance_shape(instance, workers, transcript);
    let oracle_commitments = commit_oracles(&vectors)?;
    absorb_oracle_commitments(&oracle_commitments, transcript);
    let outer_commitments = commit_outer_linearizations(&vectors, workers)?;
    absorb_outer_commitments(&outer_commitments, transcript);
    let az_poly =
        MultilinearPolynomial::new(vectors.az.clone()).map_err(|_| R1csPiopError::InvalidShape)?;
    let bz_poly =
        MultilinearPolynomial::new(vectors.bz.clone()).map_err(|_| R1csPiopError::InvalidShape)?;
    let cz_poly =
        MultilinearPolynomial::new(vectors.cz.clone()).map_err(|_| R1csPiopError::InvalidShape)?;
    let outer_sumcheck = prove_cubic_zerocheck(&az_poly, &bz_poly, &cz_poly, transcript)
        .map_err(|_| R1csPiopError::Sumcheck)?;
    let outer_openings = open_outer_linearizations(
        &vectors,
        &outer_commitments,
        &outer_sumcheck.challenges,
        pcs_params,
        transcript,
    )?;
    let inner = prove_inner_linearization(
        instance,
        &vectors,
        &outer_openings,
        InnerLinearizationConfig {
            workers,
            pcs_params,
        },
        transcript,
        &mut commit_distributed,
        &mut open_distributed,
    )?;
    let residual_commitment = commit_distributed(&vectors.residual, workers)?;
    DistributedBrakedown::absorb_distributed_commitment(&residual_commitment, transcript);
    let residual_poly = MultilinearPolynomial::new(vectors.residual.clone())
        .map_err(|_| R1csPiopError::InvalidShape)?;
    let sumcheck =
        prove_zerocheck_proof(&residual_poly, transcript).map_err(|_| R1csPiopError::Sumcheck)?;
    let point = sumcheck.challenges.clone();
    let residual_opening = open_distributed(
        &vectors.residual,
        &residual_commitment,
        &point,
        pcs_params,
        transcript,
    )?;
    let row_indices = challenge_row_indices(instance, transcript);
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
    let spark = prove_distributed_spark(instance, workers, transcript)?;
    Ok(R1csPiopProof {
        oracle_commitments,
        outer_commitments,
        outer_openings,
        outer_sumcheck,
        inner,
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
    DistributedBrakedown::absorb_distributed_commitment(&proof.residual_commitment, transcript);
    let num_vars = log2_power_of_two(proof.residual_commitment.original_len)
        .map_err(|_| R1csPiopError::InvalidShape)?;
    verify_zerocheck_rounds(num_vars, &proof.sumcheck, transcript)
        .map_err(|_| R1csPiopError::Sumcheck)?;
    if proof.residual_opening.point != proof.sumcheck.challenges {
        return Err(R1csPiopError::InvalidProof);
    }
    let expected_final =
        zerocheck_final_evaluation(&proof.sumcheck, proof.residual_opening.claimed_value)
            .map_err(|_| R1csPiopError::InvalidProof)?;
    if expected_final != proof.sumcheck.final_evaluation {
        return Err(R1csPiopError::InvalidProof);
    }
    DistributedBrakedown::verify_opening_after_commitment_with_params(
        &proof.residual_commitment,
        &proof.residual_opening,
        pcs_params,
        transcript,
    )
    .map_err(|_| R1csPiopError::Pcs)?;
    let row_indices = challenge_row_indices(instance, transcript);
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
    verify_distributed_spark(instance, proof.workers, &proof.spark, transcript)?;
    Ok(R1csMetrics {
        proof_bytes: proof_size_bytes(proof),
        communication_bytes: communication_bytes(&proof.outer_openings.az)
            + communication_bytes(&proof.outer_openings.bz)
            + communication_bytes(&proof.outer_openings.cz)
            + communication_bytes(&proof.inner.witness_opening)
            + communication_bytes(&proof.residual_opening),
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

fn commit_oracles(vectors: &ConstraintVectors) -> R1csPiopResult<R1csOracleCommitments> {
    Ok(R1csOracleCommitments {
        witness: MerklePcs::commit(&vectors.witness).map_err(|_| R1csPiopError::Pcs)?,
        az: MerklePcs::commit(&vectors.az).map_err(|_| R1csPiopError::Pcs)?,
        bz: MerklePcs::commit(&vectors.bz).map_err(|_| R1csPiopError::Pcs)?,
        cz: MerklePcs::commit(&vectors.cz).map_err(|_| R1csPiopError::Pcs)?,
    })
}

fn commit_outer_linearizations(
    vectors: &ConstraintVectors,
    workers: usize,
) -> R1csPiopResult<R1csOuterCommitments> {
    Ok(R1csOuterCommitments {
        az: DistributedBrakedown::commit_detached(&vectors.az, workers)
            .map_err(|_| R1csPiopError::Pcs)?,
        bz: DistributedBrakedown::commit_detached(&vectors.bz, workers)
            .map_err(|_| R1csPiopError::Pcs)?,
        cz: DistributedBrakedown::commit_detached(&vectors.cz, workers)
            .map_err(|_| R1csPiopError::Pcs)?,
    })
}

fn open_outer_linearizations<T: Transcript>(
    vectors: &ConstraintVectors,
    commitments: &R1csOuterCommitments,
    point: &[FieldElement],
    pcs_params: DistributedPcsParams,
    transcript: &mut T,
) -> R1csPiopResult<R1csOuterOpenings> {
    Ok(R1csOuterOpenings {
        az: DistributedBrakedown::open_at_after_commitment_with_params(
            &vectors.az,
            &commitments.az,
            point,
            pcs_params,
            transcript,
        )
        .map_err(|_| R1csPiopError::Pcs)?,
        bz: DistributedBrakedown::open_at_after_commitment_with_params(
            &vectors.bz,
            &commitments.bz,
            point,
            pcs_params,
            transcript,
        )
        .map_err(|_| R1csPiopError::Pcs)?,
        cz: DistributedBrakedown::open_at_after_commitment_with_params(
            &vectors.cz,
            &commitments.cz,
            point,
            pcs_params,
            transcript,
        )
        .map_err(|_| R1csPiopError::Pcs)?,
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
        if opening.point != sumcheck.challenges {
            return Err(R1csPiopError::InvalidProof);
        }
    }
    DistributedBrakedown::verify_opening_after_commitment_with_params(
        &commitments.az,
        &openings.az,
        pcs_params,
        transcript,
    )
    .map_err(|_| R1csPiopError::Pcs)?;
    DistributedBrakedown::verify_opening_after_commitment_with_params(
        &commitments.bz,
        &openings.bz,
        pcs_params,
        transcript,
    )
    .map_err(|_| R1csPiopError::Pcs)?;
    DistributedBrakedown::verify_opening_after_commitment_with_params(
        &commitments.cz,
        &openings.cz,
        pcs_params,
        transcript,
    )
    .map_err(|_| R1csPiopError::Pcs)?;
    let expected_final = cubic_zerocheck_final_evaluation(
        sumcheck,
        openings.az.claimed_value,
        openings.bz.claimed_value,
        openings.cz.claimed_value,
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
    ) -> R1csPiopResult<DistributedOpening>,
{
    let witness_commitment = commit_distributed(&vectors.witness, config.workers)?;
    let matrix_challenges =
        derive_inner_matrix_challenges(outer_openings, &witness_commitment, transcript);
    let projected = projected_matrix_vector(
        instance,
        &outer_openings.az.point,
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
    if projected_eval * witness_opening.claimed_value != sumcheck.final_evaluation {
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
    instance: &R1csInstance,
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
    let projected = projected_matrix_vector(
        instance,
        &outer_openings.az.point,
        matrix_challenges,
        proof.witness_commitment.original_len,
    )?;
    let witness_vars = log2_power_of_two(proof.witness_commitment.original_len)
        .map_err(|_| R1csPiopError::InvalidShape)?;
    let claimed_sum = inner_linearization_claim(outer_openings, matrix_challenges);
    verify_product_sumcheck_rounds(witness_vars, claimed_sum, &proof.sumcheck, transcript)
        .map_err(|_| R1csPiopError::Sumcheck)?;
    if proof.witness_opening.point != proof.sumcheck.challenges {
        return Err(R1csPiopError::InvalidProof);
    }
    DistributedBrakedown::verify_opening_after_commitment_with_params(
        &proof.witness_commitment,
        &proof.witness_opening,
        pcs_params,
        transcript,
    )
    .map_err(|_| R1csPiopError::Pcs)?;
    let projected_eval = evaluate_mle(&projected, &proof.sumcheck.challenges)
        .map_err(|_| R1csPiopError::InvalidProof)?;
    if projected_eval * proof.witness_opening.claimed_value != proof.sumcheck.final_evaluation {
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
    for coordinate in &outer_openings.az.point {
        transcript.absorb_field(b"outer-row-point", *coordinate);
    }
    transcript.absorb_field(b"outer-az", outer_openings.az.claimed_value);
    transcript.absorb_field(b"outer-bz", outer_openings.bz.claimed_value);
    transcript.absorb_field(b"outer-cz", outer_openings.cz.claimed_value);
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
    matrix_challenges[0] * outer_openings.az.claimed_value
        + matrix_challenges[1] * outer_openings.bz.claimed_value
        + matrix_challenges[2] * outer_openings.cz.claimed_value
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

fn challenge_row_indices<T: Transcript>(instance: &R1csInstance, transcript: &mut T) -> Vec<usize> {
    let rows = instance.num_constraints();
    transcript.absorb_domain(b"r1cs-row-consistency-exhaustive-v1");
    transcript.absorb_public(b"rows", &(rows as u64).to_le_bytes());
    (0..rows).collect()
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
        + pcs_proof_size_bytes(&proof.outer_openings.az)
        + pcs_proof_size_bytes(&proof.outer_openings.bz)
        + pcs_proof_size_bytes(&proof.outer_openings.cz)
        + cubic_zerocheck_proof_size_bytes(&proof.outer_sumcheck)
        + inner_proof_size_bytes(&proof.inner)
        + distributed_commitment_size_bytes(&proof.residual_commitment)
        + pcs_proof_size_bytes(&proof.residual_opening)
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
        + pcs_proof_size_bytes(&proof.witness_opening)
}

fn spark_proof_size_bytes(proof: &DistributedSparkProof) -> usize {
    5 * 8
        + 8
        + 2 * 8
        + vec_len_prefix()
        + proof.workers.len() * spark_worker_fingerprint_size_bytes()
}

fn spark_worker_fingerprint_size_bytes() -> usize {
    8 + 16 + 8 + 2 * 8
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
    transcript: &mut T,
) -> R1csPiopResult<DistributedSparkProof> {
    let (plan, challenges) = derive_spark_challenges(instance, workers, transcript)?;
    let worker_fingerprints = compute_spark_worker_fingerprints(instance, &plan, challenges)?;
    let mut total_entries = 0_usize;
    let mut linear_fingerprint = FieldElement::ZERO;
    let mut product_fingerprint = FieldElement::ONE;
    for worker in &worker_fingerprints {
        total_entries += worker.entry_count;
        linear_fingerprint += worker.linear_fingerprint;
        product_fingerprint *= worker.product_fingerprint;
    }
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
    })
}

fn verify_distributed_spark<T: Transcript>(
    instance: &R1csInstance,
    workers: usize,
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
    Ok(())
}

fn derive_spark_challenges<T: Transcript>(
    instance: &R1csInstance,
    workers: usize,
    transcript: &mut T,
) -> R1csPiopResult<(PartitionPlan, SparkChallenges)> {
    let rows = instance.num_constraints();
    if rows == 0 || workers == 0 {
        return Err(R1csPiopError::InvalidShape);
    }
    let plan = PartitionPlan::balanced(rows, workers).map_err(|_| R1csPiopError::InvalidShape)?;
    transcript.absorb_domain(b"r1cs-distributed-spark-fingerprint-v1");
    transcript.absorb_public(b"workers", &(workers as u64).to_le_bytes());
    transcript.absorb_public(b"rows", &(rows as u64).to_le_bytes());
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

    #[test]
    fn r1cs_piop_accepts_and_rejects() {
        let (instance, witness) = sample_r1cs();
        let mut prover_tr = HashTranscript::new(b"r1cs-test");
        let proof = prove_r1cs(&instance, &witness, 1, &mut prover_tr).expect("proof");
        let mut verifier_tr = HashTranscript::new(b"r1cs-test");
        assert!(verify_r1cs(&instance, &proof, &mut verifier_tr).is_ok());

        let mut bad_proof = proof;
        bad_proof.row_queries[0].witness_openings[0].value += FieldElement::ONE;
        let mut verifier_tr = HashTranscript::new(b"r1cs-test");
        assert!(verify_r1cs(&instance, &bad_proof, &mut verifier_tr).is_err());
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
    fn pcs_opening_must_match_sumcheck_point_and_value() {
        let (instance, witness) = sample_r1cs();
        let mut prover_tr = HashTranscript::new(b"r1cs-binding");
        let proof = prove_r1cs(&instance, &witness, 1, &mut prover_tr).expect("proof");

        let mut bad_point = proof.clone();
        bad_point.residual_opening.point[0] += FieldElement::ONE;
        let mut verifier_tr = HashTranscript::new(b"r1cs-binding");
        assert_eq!(
            verify_r1cs(&instance, &bad_point, &mut verifier_tr),
            Err(R1csPiopError::InvalidProof)
        );

        let mut bad_value = proof;
        bad_value.residual_opening.claimed_value += FieldElement::ONE;
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
        bad_point.outer_openings.az.point[0] += FieldElement::ONE;
        let mut verifier_tr = HashTranscript::new(b"r1cs-outer");
        assert_eq!(
            verify_r1cs(&instance, &bad_point, &mut verifier_tr),
            Err(R1csPiopError::InvalidProof)
        );

        let mut bad_value = proof;
        bad_value.outer_openings.bz.claimed_value += FieldElement::ONE;
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
            &proof.outer_openings.az.point,
            proof.inner.matrix_challenges,
            proof.inner.witness_commitment.original_len,
        )
        .expect("projected matrix");
        assert_eq!(
            evaluate_mle(&projected, &proof.inner.sumcheck.challenges).expect("projected eval")
                * proof.inner.witness_opening.claimed_value,
            proof.inner.sumcheck.final_evaluation
        );

        let mut bad_round = proof.clone();
        bad_round.inner.sumcheck.rounds[0].eval_at_2 += FieldElement::ONE;
        let mut verifier_tr = HashTranscript::new(b"r1cs-inner");
        assert!(verify_r1cs(&instance, &bad_round, &mut verifier_tr).is_err());

        let mut bad_challenge = proof.clone();
        bad_challenge.inner.matrix_challenges[0] += FieldElement::ONE;
        let mut verifier_tr = HashTranscript::new(b"r1cs-inner");
        assert!(verify_r1cs(&instance, &bad_challenge, &mut verifier_tr).is_err());

        let mut bad_point = proof.clone();
        bad_point.inner.witness_opening.point[0] += FieldElement::ONE;
        let mut verifier_tr = HashTranscript::new(b"r1cs-inner");
        assert!(verify_r1cs(&instance, &bad_point, &mut verifier_tr).is_err());

        let mut bad_value = proof;
        bad_value.inner.witness_opening.claimed_value += FieldElement::ONE;
        let mut verifier_tr = HashTranscript::new(b"r1cs-inner");
        assert!(verify_r1cs(&instance, &bad_value, &mut verifier_tr).is_err());
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
    fn row_consistency_queries_cover_all_constraints() {
        let (instance, witness) = sample_r1cs();
        let mut prover_tr = HashTranscript::new(b"r1cs-exhaustive-rows");
        let proof = prove_r1cs(&instance, &witness, 1, &mut prover_tr).expect("proof");
        let queried = proof
            .row_queries
            .iter()
            .map(|query| query.row)
            .collect::<Vec<_>>();
        assert_eq!(queried, (0..instance.num_constraints()).collect::<Vec<_>>());
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

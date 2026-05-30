use pq_core::{CustomizedGate, FieldElement, PlonkishCircuit, PlonkishRow, log2_power_of_two};
use pq_pcs::{
    Commitment, DistributedBrakedown, DistributedCommitment, DistributedIndexOpening,
    DistributedOpening, DistributedPcsParams, FoldLayerProof, MerklePcs, MleFoldingProof,
    OpeningProof, PolynomialCommitment, commitment_size_bytes,
    communication_bytes as pcs_communication_bytes, distributed_commitment_size_bytes,
    distributed_index_opening_size_bytes, opening_proof_size_bytes,
    proof_size_bytes as pcs_proof_size_bytes, prove_mle_folding, verify_mle_folding,
};
use pq_sumcheck::{
    ZerocheckProof, prove_zerocheck_proof, verify_zerocheck_rounds, zerocheck_final_evaluation,
};
use pq_transcript::{HashTranscript, Transcript};

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PlonkishPiopError {
    Unsatisfied,
    InvalidShape,
    InvalidPermutation,
    InvalidProof,
}

pub type PlonkishPiopResult<T> = Result<T, PlonkishPiopError>;

#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub enum PlonkishColumn {
    A,
    B,
    C,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub struct PlonkishCell {
    pub row: usize,
    pub column: PlonkishColumn,
}

impl PlonkishCell {
    pub fn new(row: usize, column: PlonkishColumn) -> Self {
        Self { row, column }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PlonkishPermutation {
    mapping: Vec<usize>,
}

impl PlonkishPermutation {
    pub fn identity(row_count: usize) -> Self {
        let cell_count = row_count * 3;
        Self {
            mapping: (0..cell_count).collect(),
        }
    }

    pub fn from_mapping(mapping: Vec<usize>) -> PlonkishPiopResult<Self> {
        validate_permutation(&mapping)?;
        Ok(Self { mapping })
    }

    pub fn from_copy_constraints(
        row_count: usize,
        copies: &[(PlonkishCell, PlonkishCell)],
    ) -> PlonkishPiopResult<Self> {
        let cell_count = row_count * 3;
        let mut mapping = (0..cell_count).collect::<Vec<_>>();
        let mut touched = vec![false; cell_count];

        for (left, right) in copies {
            let left_index = cell_index(*left, row_count)?;
            let right_index = cell_index(*right, row_count)?;
            if touched[left_index] || touched[right_index] || left_index == right_index {
                return Err(PlonkishPiopError::InvalidPermutation);
            }
            mapping[left_index] = right_index;
            mapping[right_index] = left_index;
            touched[left_index] = true;
            touched[right_index] = true;
        }

        Self::from_mapping(mapping)
    }

    pub fn mapping(&self) -> &[usize] {
        &self.mapping
    }

    pub fn len(&self) -> usize {
        self.mapping.len()
    }

    pub fn is_empty(&self) -> bool {
        self.mapping.is_empty()
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PlonkishInstance {
    circuit: PlonkishCircuit,
    permutation: PlonkishPermutation,
}

impl PlonkishInstance {
    pub fn new(
        circuit: PlonkishCircuit,
        permutation: PlonkishPermutation,
    ) -> PlonkishPiopResult<Self> {
        if permutation.len() != circuit.len() * 3 {
            return Err(PlonkishPiopError::InvalidShape);
        }
        Ok(Self {
            circuit,
            permutation,
        })
    }

    pub fn with_identity_permutation(circuit: PlonkishCircuit) -> Self {
        let permutation = PlonkishPermutation::identity(circuit.len());
        Self {
            circuit,
            permutation,
        }
    }

    pub fn circuit(&self) -> &PlonkishCircuit {
        &self.circuit
    }

    pub fn permutation(&self) -> &PlonkishPermutation {
        &self.permutation
    }

    pub fn row_count(&self) -> usize {
        self.circuit.len()
    }

    pub fn permutation_check_count(&self) -> usize {
        self.permutation.len()
    }

    pub fn gate_residuals(&self) -> Vec<FieldElement> {
        self.circuit.row_evaluations()
    }

    pub fn permutation_residuals(&self) -> PlonkishPiopResult<Vec<FieldElement>> {
        let values = flattened_cell_values(&self.circuit);
        if values.len() != self.permutation.len() {
            return Err(PlonkishPiopError::InvalidShape);
        }

        self.permutation
            .mapping()
            .iter()
            .enumerate()
            .map(|(source, target)| {
                values
                    .get(*target)
                    .copied()
                    .map(|target_value| values[source] - target_value)
                    .ok_or(PlonkishPiopError::InvalidPermutation)
            })
            .collect()
    }

    pub fn constraint_residuals(&self) -> PlonkishPiopResult<Vec<FieldElement>> {
        let mut residuals = self.gate_residuals();
        residuals.extend(self.permutation_residuals()?);
        Ok(pad_to_power_of_two(residuals))
    }

    pub fn is_satisfied(&self) -> PlonkishPiopResult<bool> {
        Ok(self.circuit.is_satisfied()
            && self
                .permutation_residuals()?
                .iter()
                .all(|value| value.is_zero()))
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PlonkishPiopProof {
    pub oracle_commitments: PlonkishOracleCommitments,
    pub gate_subclaim: PlonkishGateSubclaimProof,
    pub permutation_accumulator: PlonkishPermutationAccumulatorProof,
    pub constraint_commitment: DistributedCommitment,
    pub constraint_opening: DistributedOpening,
    pub sumcheck: ZerocheckProof,
    pub gate_queries: Vec<PlonkishGateQuery>,
    pub permutation_queries: Vec<PlonkishPermutationQuery>,
    pub workers: usize,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PlonkishOracleCommitments {
    pub a: Commitment,
    pub b: Commitment,
    pub c: Commitment,
    pub q_l: Commitment,
    pub q_r: Commitment,
    pub q_o: Commitment,
    pub q_m: Commitment,
    pub q_c: Commitment,
    pub gate_residual: Commitment,
    pub permutation_residual: Commitment,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PlonkishGateSubclaimProof {
    pub point: Vec<FieldElement>,
    pub virtual_gate_value: FieldElement,
    pub a: PlonkishGateColumnSubclaim,
    pub b: PlonkishGateColumnSubclaim,
    pub c: PlonkishGateColumnSubclaim,
    pub q_l: PlonkishGateColumnSubclaim,
    pub q_r: PlonkishGateColumnSubclaim,
    pub q_o: PlonkishGateColumnSubclaim,
    pub q_m: PlonkishGateColumnSubclaim,
    pub q_c: PlonkishGateColumnSubclaim,
    pub gate_residual: PlonkishGateColumnSubclaim,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PlonkishGateColumnSubclaim {
    pub values: Vec<FieldElement>,
    pub folding: MleFoldingProof,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PlonkishGateQuery {
    pub row: usize,
    pub a: OpeningProof,
    pub b: OpeningProof,
    pub c: OpeningProof,
    pub gate_residual: OpeningProof,
    pub constraint_residual: DistributedIndexOpening,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PlonkishPermutationQuery {
    pub source: usize,
    pub target: usize,
    pub source_value: OpeningProof,
    pub target_value: OpeningProof,
    pub permutation_residual: OpeningProof,
    pub constraint_residual: DistributedIndexOpening,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PlonkishPermutationAccumulatorProof {
    pub beta: FieldElement,
    pub gamma: FieldElement,
    pub numerator_commitment: Commitment,
    pub denominator_commitment: Commitment,
    pub numerator_first: OpeningProof,
    pub numerator_last: OpeningProof,
    pub denominator_first: OpeningProof,
    pub denominator_last: OpeningProof,
    pub random_subclaim: PlonkishPermutationAccumulatorSubclaimProof,
    pub recurrence_queries: Vec<PlonkishPermutationAccumulatorQuery>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PlonkishPermutationAccumulatorSubclaimProof {
    pub point: Vec<FieldElement>,
    pub value: PlonkishGateColumnSubclaim,
    pub source_id: PlonkishGateColumnSubclaim,
    pub target_id: PlonkishGateColumnSubclaim,
    pub numerator_current: PlonkishGateColumnSubclaim,
    pub numerator_next: PlonkishGateColumnSubclaim,
    pub denominator_current: PlonkishGateColumnSubclaim,
    pub denominator_next: PlonkishGateColumnSubclaim,
    pub numerator_residual: MleFoldingProof,
    pub denominator_residual: MleFoldingProof,
}

struct PlonkishPermutationAccumulatorVectors {
    value: Vec<FieldElement>,
    source_id: Vec<FieldElement>,
    target_id: Vec<FieldElement>,
    numerator_current: Vec<FieldElement>,
    numerator_next: Vec<FieldElement>,
    denominator_current: Vec<FieldElement>,
    denominator_next: Vec<FieldElement>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PlonkishPermutationAccumulatorQuery {
    pub index: usize,
    pub value: OpeningProof,
    pub numerator_current: OpeningProof,
    pub numerator_next: OpeningProof,
    pub denominator_current: OpeningProof,
    pub denominator_next: OpeningProof,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PlonkishMetrics {
    pub proof_bytes: usize,
    pub communication_bytes: usize,
    pub rows: usize,
    pub constraints: usize,
    pub permutation_checks: usize,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct PlonkishOracles {
    a: Vec<FieldElement>,
    b: Vec<FieldElement>,
    c: Vec<FieldElement>,
    q_l: Vec<FieldElement>,
    q_r: Vec<FieldElement>,
    q_o: Vec<FieldElement>,
    q_m: Vec<FieldElement>,
    q_c: Vec<FieldElement>,
    gate_residuals: Vec<FieldElement>,
    permutation_residuals: Vec<FieldElement>,
    constraint_residuals: Vec<FieldElement>,
}

impl PlonkishOracles {
    fn from_instance(instance: &PlonkishInstance) -> PlonkishPiopResult<Self> {
        let rows = instance.circuit.rows();
        let mut a = rows.iter().map(|row| row.a).collect::<Vec<_>>();
        let mut b = rows.iter().map(|row| row.b).collect::<Vec<_>>();
        let mut c = rows.iter().map(|row| row.c).collect::<Vec<_>>();
        let mut q_l = rows.iter().map(|row| row.q_l).collect::<Vec<_>>();
        let mut q_r = rows.iter().map(|row| row.q_r).collect::<Vec<_>>();
        let mut q_o = rows.iter().map(|row| row.q_o).collect::<Vec<_>>();
        let mut q_m = rows.iter().map(|row| row.q_m).collect::<Vec<_>>();
        let mut q_c = rows.iter().map(|row| row.q_c).collect::<Vec<_>>();
        pad_to_power_of_two_in_place(&mut a);
        pad_to_power_of_two_in_place(&mut b);
        pad_to_power_of_two_in_place(&mut c);
        pad_to_power_of_two_in_place(&mut q_l);
        pad_to_power_of_two_in_place(&mut q_r);
        pad_to_power_of_two_in_place(&mut q_o);
        pad_to_power_of_two_in_place(&mut q_m);
        pad_to_power_of_two_in_place(&mut q_c);

        let mut gate_residuals = instance.gate_residuals();
        let permutation_residuals_unpadded = instance.permutation_residuals()?;
        let mut permutation_residuals = permutation_residuals_unpadded.clone();
        pad_to_power_of_two_in_place(&mut gate_residuals);
        pad_to_power_of_two_in_place(&mut permutation_residuals);

        let mut residuals = instance.gate_residuals();
        residuals.extend(permutation_residuals_unpadded);
        let constraint_residuals = pad_to_power_of_two(residuals);

        Ok(Self {
            a,
            b,
            c,
            q_l,
            q_r,
            q_o,
            q_m,
            q_c,
            gate_residuals,
            permutation_residuals,
            constraint_residuals,
        })
    }
}

pub fn prove_plonkish(
    instance: &PlonkishInstance,
    workers: usize,
    transcript: &mut HashTranscript,
) -> PlonkishPiopResult<PlonkishPiopProof> {
    prove_plonkish_with_pcs_params(
        instance,
        workers,
        DistributedPcsParams::default(),
        transcript,
    )
}

pub fn prove_plonkish_with_pcs_params(
    instance: &PlonkishInstance,
    workers: usize,
    pcs_params: DistributedPcsParams,
    transcript: &mut HashTranscript,
) -> PlonkishPiopResult<PlonkishPiopProof> {
    prove_plonkish_with_pcs_hooks(
        instance,
        workers,
        pcs_params,
        transcript,
        |evaluations, workers| {
            DistributedBrakedown::commit_detached(evaluations, workers)
                .map_err(|_| PlonkishPiopError::InvalidProof)
        },
        |evaluations, commitment, point, params, transcript| {
            DistributedBrakedown::open_at_after_commitment_with_params(
                evaluations,
                commitment,
                point,
                params,
                transcript,
            )
            .map_err(|_| PlonkishPiopError::InvalidProof)
        },
    )
}

pub fn prove_plonkish_with_pcs_hooks<C, O>(
    instance: &PlonkishInstance,
    workers: usize,
    pcs_params: DistributedPcsParams,
    transcript: &mut HashTranscript,
    mut commit_constraint: C,
    mut open_constraint: O,
) -> PlonkishPiopResult<PlonkishPiopProof>
where
    C: FnMut(&[FieldElement], usize) -> PlonkishPiopResult<DistributedCommitment>,
    O: FnMut(
        &[FieldElement],
        &DistributedCommitment,
        &[FieldElement],
        DistributedPcsParams,
        &mut HashTranscript,
    ) -> PlonkishPiopResult<DistributedOpening>,
{
    if workers == 0 {
        return Err(PlonkishPiopError::InvalidShape);
    }
    if !instance.is_satisfied()? {
        return Err(PlonkishPiopError::Unsatisfied);
    }

    transcript.absorb_domain(b"plonkish-piop-v1");
    absorb_circuit_statement(instance, workers, transcript);
    let oracles = PlonkishOracles::from_instance(instance)?;
    let oracle_commitments = commit_oracles(&oracles)?;
    absorb_oracle_commitments(&oracle_commitments, transcript);
    let gate_subclaim = prove_gate_subclaim(instance, &oracles, &oracle_commitments, transcript)?;
    let permutation_accumulator =
        prove_permutation_accumulator(instance, &oracles, &oracle_commitments, transcript)?;

    let constraint_commitment = commit_constraint(&oracles.constraint_residuals, workers)?;
    DistributedBrakedown::absorb_distributed_commitment(&constraint_commitment, transcript);
    let zerocheck_poly =
        pq_core::MultilinearExtension::from_evaluations(oracles.constraint_residuals.clone())
            .map_err(|_| PlonkishPiopError::InvalidShape)?;
    let sumcheck = prove_zerocheck_proof(&zerocheck_poly, transcript)
        .map_err(|_| PlonkishPiopError::InvalidProof)?;
    let constraint_opening = open_constraint(
        &oracles.constraint_residuals,
        &constraint_commitment,
        &sumcheck.challenges,
        pcs_params,
        transcript,
    )?;
    let gate_indices = challenge_gate_indices(instance, transcript);
    let permutation_indices = challenge_permutation_indices(instance, transcript);
    let gate_queries = gate_indices
        .iter()
        .copied()
        .map(|row| open_gate_query(&oracles, &oracle_commitments, &constraint_commitment, row))
        .collect::<PlonkishPiopResult<Vec<_>>>()?;
    let permutation_queries = permutation_indices
        .iter()
        .copied()
        .map(|source| {
            open_permutation_query(
                instance,
                &oracles,
                &oracle_commitments,
                &constraint_commitment,
                source,
            )
        })
        .collect::<PlonkishPiopResult<Vec<_>>>()?;

    Ok(PlonkishPiopProof {
        oracle_commitments,
        gate_subclaim,
        permutation_accumulator,
        constraint_commitment,
        constraint_opening,
        sumcheck,
        gate_queries,
        permutation_queries,
        workers,
    })
}

pub fn verify_plonkish(
    instance: &PlonkishInstance,
    proof: &PlonkishPiopProof,
    transcript: &mut HashTranscript,
) -> PlonkishPiopResult<PlonkishMetrics> {
    verify_plonkish_with_pcs_params(instance, proof, DistributedPcsParams::default(), transcript)
}

pub fn verify_plonkish_with_pcs_params(
    instance: &PlonkishInstance,
    proof: &PlonkishPiopProof,
    pcs_params: DistributedPcsParams,
    transcript: &mut HashTranscript,
) -> PlonkishPiopResult<PlonkishMetrics> {
    if proof.workers == 0 || proof.workers != proof.constraint_commitment.workers.len() {
        return Err(PlonkishPiopError::InvalidShape);
    }
    validate_commitment_shape(instance, proof)?;

    transcript.absorb_domain(b"plonkish-piop-v1");
    absorb_circuit_statement(instance, proof.workers, transcript);
    absorb_oracle_commitments(&proof.oracle_commitments, transcript);
    verify_gate_subclaim(
        instance,
        &proof.oracle_commitments,
        &proof.gate_subclaim,
        transcript,
    )?;
    verify_permutation_accumulator(
        instance,
        &proof.oracle_commitments,
        &proof.permutation_accumulator,
        transcript,
    )?;
    DistributedBrakedown::absorb_distributed_commitment(&proof.constraint_commitment, transcript);
    let num_vars = log2_power_of_two(proof.constraint_commitment.original_len)
        .map_err(|_| PlonkishPiopError::InvalidShape)?;
    verify_zerocheck_rounds(num_vars, &proof.sumcheck, transcript)
        .map_err(|_| PlonkishPiopError::InvalidProof)?;
    if proof.constraint_opening.point != proof.sumcheck.challenges {
        return Err(PlonkishPiopError::InvalidProof);
    }
    let expected_final =
        zerocheck_final_evaluation(&proof.sumcheck, proof.constraint_opening.claimed_value)
            .map_err(|_| PlonkishPiopError::InvalidProof)?;
    if expected_final != proof.sumcheck.final_evaluation {
        return Err(PlonkishPiopError::InvalidProof);
    }
    DistributedBrakedown::verify_opening_after_commitment_with_params(
        &proof.constraint_commitment,
        &proof.constraint_opening,
        pcs_params,
        transcript,
    )
    .map_err(|_| PlonkishPiopError::InvalidProof)?;
    let gate_indices = challenge_gate_indices(instance, transcript);
    let permutation_indices = challenge_permutation_indices(instance, transcript);
    if gate_indices.len() != proof.gate_queries.len()
        || permutation_indices.len() != proof.permutation_queries.len()
    {
        return Err(PlonkishPiopError::InvalidProof);
    }
    for (expected, query) in gate_indices.iter().zip(&proof.gate_queries) {
        if *expected != query.row {
            return Err(PlonkishPiopError::InvalidProof);
        }
        verify_gate_query(
            instance,
            &proof.oracle_commitments,
            &proof.constraint_commitment,
            query,
        )?;
    }
    for (expected, query) in permutation_indices.iter().zip(&proof.permutation_queries) {
        if *expected != query.source {
            return Err(PlonkishPiopError::InvalidProof);
        }
        verify_permutation_query(
            instance,
            &proof.oracle_commitments,
            &proof.constraint_commitment,
            query,
        )?;
    }

    Ok(PlonkishMetrics {
        proof_bytes: proof_size_bytes(proof),
        communication_bytes: communication_bytes(proof, proof.workers),
        rows: instance.row_count(),
        constraints: proof.constraint_commitment.original_len,
        permutation_checks: instance.permutation_check_count(),
    })
}

pub fn permutation_grand_product_delta(
    instance: &PlonkishInstance,
    beta: FieldElement,
    gamma: FieldElement,
) -> PlonkishPiopResult<FieldElement> {
    let values = flattened_cell_values(&instance.circuit);
    if values.len() != instance.permutation.len() {
        return Err(PlonkishPiopError::InvalidShape);
    }

    let mut left = FieldElement::ONE;
    let mut right = FieldElement::ONE;
    for (index, value) in values.iter().copied().enumerate() {
        let target = instance.permutation.mapping()[index];
        if target >= values.len() {
            return Err(PlonkishPiopError::InvalidPermutation);
        }
        left *= value + beta * FieldElement::from(index) + gamma;
        right *= value + beta * FieldElement::from(target) + gamma;
    }
    Ok(left - right)
}

pub fn sample_plonkish_instance(size: usize) -> PlonkishPiopResult<PlonkishInstance> {
    let row_count = size.max(1);
    let mut rows = Vec::with_capacity(row_count);
    let mut copies = Vec::with_capacity(row_count.saturating_sub(1));
    let mut current = FieldElement::from(2_u64);

    for row in 0..row_count {
        let factor = FieldElement::from((row as u64) + 3);
        let next = current * factor;
        rows.push(PlonkishRow::multiplication(current, factor, next));
        if row + 1 < row_count {
            copies.push((
                PlonkishCell::new(row, PlonkishColumn::C),
                PlonkishCell::new(row + 1, PlonkishColumn::A),
            ));
        }
        current = next;
    }

    let circuit = PlonkishCircuit::from_rows(rows);
    let permutation = PlonkishPermutation::from_copy_constraints(row_count, &copies)?;
    PlonkishInstance::new(circuit, permutation)
}

pub fn tamper_gate(instance: &PlonkishInstance) -> PlonkishInstance {
    let mut rows = instance.circuit().rows().to_vec();
    if let Some(first) = rows.first_mut() {
        first.c += FieldElement::ONE;
    }
    PlonkishInstance {
        circuit: PlonkishCircuit::from_rows(rows),
        permutation: instance.permutation().clone(),
    }
}

pub fn tamper_permutation_only(instance: &PlonkishInstance) -> PlonkishInstance {
    let mut rows = instance.circuit().rows().to_vec();
    if rows.len() > 1 {
        rows[1].a += FieldElement::ONE;
        rows[1].c = rows[1].a * rows[1].b;
    } else if let Some(first) = rows.first_mut() {
        first.a += FieldElement::ONE;
        first.c = first.a * first.b;
    }
    PlonkishInstance {
        circuit: PlonkishCircuit::from_rows(rows),
        permutation: instance.permutation().clone(),
    }
}

fn commit_oracles(oracles: &PlonkishOracles) -> PlonkishPiopResult<PlonkishOracleCommitments> {
    Ok(PlonkishOracleCommitments {
        a: MerklePcs::commit(&oracles.a).map_err(|_| PlonkishPiopError::InvalidProof)?,
        b: MerklePcs::commit(&oracles.b).map_err(|_| PlonkishPiopError::InvalidProof)?,
        c: MerklePcs::commit(&oracles.c).map_err(|_| PlonkishPiopError::InvalidProof)?,
        q_l: MerklePcs::commit(&oracles.q_l).map_err(|_| PlonkishPiopError::InvalidProof)?,
        q_r: MerklePcs::commit(&oracles.q_r).map_err(|_| PlonkishPiopError::InvalidProof)?,
        q_o: MerklePcs::commit(&oracles.q_o).map_err(|_| PlonkishPiopError::InvalidProof)?,
        q_m: MerklePcs::commit(&oracles.q_m).map_err(|_| PlonkishPiopError::InvalidProof)?,
        q_c: MerklePcs::commit(&oracles.q_c).map_err(|_| PlonkishPiopError::InvalidProof)?,
        gate_residual: MerklePcs::commit(&oracles.gate_residuals)
            .map_err(|_| PlonkishPiopError::InvalidProof)?,
        permutation_residual: MerklePcs::commit(&oracles.permutation_residuals)
            .map_err(|_| PlonkishPiopError::InvalidProof)?,
    })
}

fn validate_commitment_shape(
    instance: &PlonkishInstance,
    proof: &PlonkishPiopProof,
) -> PlonkishPiopResult<()> {
    let row_len = instance.row_count().max(1).next_power_of_two();
    let permutation_len = instance
        .permutation_check_count()
        .max(1)
        .next_power_of_two();
    let constraint_len = (instance.row_count() + instance.permutation_check_count())
        .max(1)
        .next_power_of_two();
    if proof.oracle_commitments.a.len != row_len
        || proof.oracle_commitments.b.len != row_len
        || proof.oracle_commitments.c.len != row_len
        || proof.oracle_commitments.q_l.len != row_len
        || proof.oracle_commitments.q_r.len != row_len
        || proof.oracle_commitments.q_o.len != row_len
        || proof.oracle_commitments.q_m.len != row_len
        || proof.oracle_commitments.q_c.len != row_len
        || proof.oracle_commitments.gate_residual.len != row_len
        || proof.oracle_commitments.permutation_residual.len != permutation_len
        || proof.constraint_commitment.original_len != constraint_len
    {
        return Err(PlonkishPiopError::InvalidShape);
    }
    Ok(())
}

fn prove_gate_subclaim(
    instance: &PlonkishInstance,
    oracles: &PlonkishOracles,
    commitments: &PlonkishOracleCommitments,
    transcript: &mut HashTranscript,
) -> PlonkishPiopResult<PlonkishGateSubclaimProof> {
    let point = challenge_gate_subclaim_point(instance, transcript)?;
    let a = prove_gate_column_subclaim(&oracles.a, &point)?;
    let b = prove_gate_column_subclaim(&oracles.b, &point)?;
    let c = prove_gate_column_subclaim(&oracles.c, &point)?;
    let q_l = prove_gate_column_subclaim(&oracles.q_l, &point)?;
    let q_r = prove_gate_column_subclaim(&oracles.q_r, &point)?;
    let q_o = prove_gate_column_subclaim(&oracles.q_o, &point)?;
    let q_m = prove_gate_column_subclaim(&oracles.q_m, &point)?;
    let q_c = prove_gate_column_subclaim(&oracles.q_c, &point)?;
    let virtual_gate_value = eval_gate_subclaim(&a, &b, &c, &q_l, &q_r, &q_o, &q_m, &q_c);
    let proof = PlonkishGateSubclaimProof {
        point: point.clone(),
        virtual_gate_value,
        a,
        b,
        c,
        q_l,
        q_r,
        q_o,
        q_m,
        q_c,
        gate_residual: prove_gate_column_subclaim(&oracles.gate_residuals, &point)?,
    };
    verify_gate_subclaim_commitments(commitments, &proof)?;
    absorb_gate_subclaim_proof(transcript, &proof);
    Ok(proof)
}

fn verify_gate_subclaim(
    instance: &PlonkishInstance,
    commitments: &PlonkishOracleCommitments,
    proof: &PlonkishGateSubclaimProof,
    transcript: &mut HashTranscript,
) -> PlonkishPiopResult<()> {
    let expected_point = challenge_gate_subclaim_point(instance, transcript)?;
    if proof.point != expected_point {
        return Err(PlonkishPiopError::InvalidProof);
    }
    verify_gate_subclaim_commitments(commitments, proof)?;
    for (commitment, column) in [
        (&commitments.a, &proof.a),
        (&commitments.b, &proof.b),
        (&commitments.c, &proof.c),
        (&commitments.q_l, &proof.q_l),
        (&commitments.q_r, &proof.q_r),
        (&commitments.q_o, &proof.q_o),
        (&commitments.q_m, &proof.q_m),
        (&commitments.q_c, &proof.q_c),
        (&commitments.gate_residual, &proof.gate_residual),
    ] {
        verify_gate_column_subclaim(commitment, &proof.point, column)?;
    }
    if eval_gate_subclaim(
        &proof.a, &proof.b, &proof.c, &proof.q_l, &proof.q_r, &proof.q_o, &proof.q_m, &proof.q_c,
    ) != proof.virtual_gate_value
    {
        return Err(PlonkishPiopError::InvalidProof);
    }
    absorb_gate_subclaim_proof(transcript, proof);
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn eval_gate_subclaim(
    a: &PlonkishGateColumnSubclaim,
    b: &PlonkishGateColumnSubclaim,
    c: &PlonkishGateColumnSubclaim,
    q_l: &PlonkishGateColumnSubclaim,
    q_r: &PlonkishGateColumnSubclaim,
    q_o: &PlonkishGateColumnSubclaim,
    q_m: &PlonkishGateColumnSubclaim,
    q_c: &PlonkishGateColumnSubclaim,
) -> FieldElement {
    let gate = CustomizedGate::vanilla_plonk_gate();
    let selector_evals = [
        q_l.folding.final_value,
        q_r.folding.final_value,
        q_o.folding.final_value,
        q_m.folding.final_value,
        q_c.folding.final_value,
    ];
    let witness_evals = [
        a.folding.final_value,
        b.folding.final_value,
        c.folding.final_value,
    ];
    gate.evaluate(&selector_evals, &witness_evals)
}

fn prove_gate_column_subclaim(
    values: &[FieldElement],
    point: &[FieldElement],
) -> PlonkishPiopResult<PlonkishGateColumnSubclaim> {
    Ok(PlonkishGateColumnSubclaim {
        values: values.to_vec(),
        folding: prove_mle_folding(values, point).map_err(|_| PlonkishPiopError::InvalidProof)?,
    })
}

fn verify_gate_column_subclaim(
    commitment: &Commitment,
    point: &[FieldElement],
    column: &PlonkishGateColumnSubclaim,
) -> PlonkishPiopResult<FieldElement> {
    if MerklePcs::commit(&column.values).map_err(|_| PlonkishPiopError::InvalidProof)?
        != *commitment
    {
        return Err(PlonkishPiopError::InvalidProof);
    }
    if column.folding.input_commitment != *commitment {
        return Err(PlonkishPiopError::InvalidProof);
    }
    verify_mle_folding(&column.values, point, &column.folding)
        .map_err(|_| PlonkishPiopError::InvalidProof)
}

fn gate_subclaim_columns(
    proof: &PlonkishGateSubclaimProof,
) -> [(&'static [u8], &PlonkishGateColumnSubclaim); 9] {
    [
        (b"a".as_ref(), &proof.a),
        (b"b".as_ref(), &proof.b),
        (b"c".as_ref(), &proof.c),
        (b"q-l".as_ref(), &proof.q_l),
        (b"q-r".as_ref(), &proof.q_r),
        (b"q-o".as_ref(), &proof.q_o),
        (b"q-m".as_ref(), &proof.q_m),
        (b"q-c".as_ref(), &proof.q_c),
        (b"gate-residual".as_ref(), &proof.gate_residual),
    ]
}

fn challenge_gate_subclaim_point(
    instance: &PlonkishInstance,
    transcript: &mut HashTranscript,
) -> PlonkishPiopResult<Vec<FieldElement>> {
    let row_len = instance.row_count().max(1).next_power_of_two();
    let row_vars = log2_power_of_two(row_len).map_err(|_| PlonkishPiopError::InvalidShape)?;
    transcript.absorb_domain(b"plonkish-gate-random-subclaim-v1");
    absorb_usize(transcript, b"row-len", row_len);
    Ok((0..row_vars)
        .map(|index| {
            absorb_usize(transcript, b"gate-subclaim-var", index);
            challenge_field(transcript, b"gate-subclaim-point")
        })
        .collect())
}

fn verify_gate_subclaim_commitments(
    commitments: &PlonkishOracleCommitments,
    proof: &PlonkishGateSubclaimProof,
) -> PlonkishPiopResult<()> {
    let expected = [
        (&proof.a.folding.input_commitment, &commitments.a),
        (&proof.b.folding.input_commitment, &commitments.b),
        (&proof.c.folding.input_commitment, &commitments.c),
        (&proof.q_l.folding.input_commitment, &commitments.q_l),
        (&proof.q_r.folding.input_commitment, &commitments.q_r),
        (&proof.q_o.folding.input_commitment, &commitments.q_o),
        (&proof.q_m.folding.input_commitment, &commitments.q_m),
        (&proof.q_c.folding.input_commitment, &commitments.q_c),
        (
            &proof.gate_residual.folding.input_commitment,
            &commitments.gate_residual,
        ),
    ];
    if expected
        .iter()
        .all(|(actual, expected)| *actual == *expected)
    {
        Ok(())
    } else {
        Err(PlonkishPiopError::InvalidProof)
    }
}

fn absorb_gate_subclaim_proof(transcript: &mut HashTranscript, proof: &PlonkishGateSubclaimProof) {
    transcript.absorb_domain(b"plonkish-gate-subclaim-proof-v1");
    absorb_usize(transcript, b"gate-subclaim-point-len", proof.point.len());
    for (index, coordinate) in proof.point.iter().copied().enumerate() {
        absorb_usize(transcript, b"gate-subclaim-point-index", index);
        absorb_field(transcript, b"gate-subclaim-point", coordinate);
    }
    absorb_field(
        transcript,
        b"gate-subclaim-virtual-value",
        proof.virtual_gate_value,
    );
    for (label, column) in gate_subclaim_columns(proof) {
        absorb_gate_column_subclaim(transcript, label, column);
    }
}

fn absorb_gate_column_subclaim(
    transcript: &mut HashTranscript,
    label: &'static [u8],
    column: &PlonkishGateColumnSubclaim,
) {
    transcript.absorb_domain(b"plonkish-gate-column-subclaim-v1");
    transcript.absorb_public(b"gate-column-label", label);
    absorb_usize(transcript, b"gate-column-values-len", column.values.len());
    for (index, value) in column.values.iter().copied().enumerate() {
        absorb_usize(transcript, b"gate-column-value-index", index);
        absorb_field(transcript, b"gate-column-value", value);
    }
    absorb_gate_folding_proof(transcript, &column.folding);
}

fn absorb_gate_folding_proof(transcript: &mut HashTranscript, proof: &MleFoldingProof) {
    transcript.absorb_domain(b"plonkish-gate-mle-folding-proof-v1");
    absorb_merkle_commitment(transcript, b"gate-fold-input", &proof.input_commitment);
    absorb_usize(transcript, b"gate-fold-layer-count", proof.layers.len());
    for (round, layer) in proof.layers.iter().enumerate() {
        absorb_usize(transcript, b"gate-fold-round", round);
        absorb_field(transcript, b"gate-fold-challenge", layer.challenge);
        absorb_usize(
            transcript,
            b"gate-fold-layer-values-len",
            layer.values.len(),
        );
        for (index, value) in layer.values.iter().copied().enumerate() {
            absorb_usize(transcript, b"gate-fold-layer-value-index", index);
            absorb_field(transcript, b"gate-fold-layer-value", value);
        }
        absorb_merkle_commitment(transcript, b"gate-fold-layer", &layer.commitment);
    }
    absorb_field(transcript, b"gate-fold-final", proof.final_value);
}

fn prove_permutation_accumulator(
    instance: &PlonkishInstance,
    oracles: &PlonkishOracles,
    commitments: &PlonkishOracleCommitments,
    transcript: &mut HashTranscript,
) -> PlonkishPiopResult<PlonkishPermutationAccumulatorProof> {
    transcript.absorb_domain(b"plonkish-permutation-accumulator-v1");
    absorb_usize(
        transcript,
        b"permutation-cells",
        instance.permutation_check_count(),
    );
    let beta = challenge_field(transcript, b"permutation-beta");
    let gamma = challenge_field(transcript, b"permutation-gamma");
    let (numerator_trace, denominator_trace) =
        build_permutation_accumulator_traces(instance, beta, gamma)?;
    let numerator_commitment =
        MerklePcs::commit(&numerator_trace).map_err(|_| PlonkishPiopError::InvalidProof)?;
    let denominator_commitment =
        MerklePcs::commit(&denominator_trace).map_err(|_| PlonkishPiopError::InvalidProof)?;
    absorb_merkle_commitment(transcript, b"permutation-numerator", &numerator_commitment);
    absorb_merkle_commitment(
        transcript,
        b"permutation-denominator",
        &denominator_commitment,
    );

    let terminal_index = instance.permutation_check_count();
    let numerator_first =
        MerklePcs::open(&numerator_trace, 0).map_err(|_| PlonkishPiopError::InvalidProof)?;
    let numerator_last = MerklePcs::open(&numerator_trace, terminal_index)
        .map_err(|_| PlonkishPiopError::InvalidProof)?;
    let denominator_first =
        MerklePcs::open(&denominator_trace, 0).map_err(|_| PlonkishPiopError::InvalidProof)?;
    let denominator_last = MerklePcs::open(&denominator_trace, terminal_index)
        .map_err(|_| PlonkishPiopError::InvalidProof)?;
    absorb_accumulator_boundaries(
        transcript,
        &numerator_first,
        &numerator_last,
        &denominator_first,
        &denominator_last,
    );

    let random_subclaim = prove_permutation_accumulator_subclaim(
        instance,
        commitments,
        &numerator_commitment,
        &denominator_commitment,
        &numerator_trace,
        &denominator_trace,
        beta,
        gamma,
        transcript,
    )?;

    let recurrence_indices = challenge_accumulator_indices(instance, transcript);
    let recurrence_queries = recurrence_indices
        .iter()
        .copied()
        .map(|index| {
            open_accumulator_query(
                oracles,
                commitments,
                &numerator_trace,
                &denominator_trace,
                index,
            )
        })
        .collect::<PlonkishPiopResult<Vec<_>>>()?;

    Ok(PlonkishPermutationAccumulatorProof {
        beta,
        gamma,
        numerator_commitment,
        denominator_commitment,
        numerator_first,
        numerator_last,
        denominator_first,
        denominator_last,
        random_subclaim,
        recurrence_queries,
    })
}

fn verify_permutation_accumulator(
    instance: &PlonkishInstance,
    commitments: &PlonkishOracleCommitments,
    proof: &PlonkishPermutationAccumulatorProof,
    transcript: &mut HashTranscript,
) -> PlonkishPiopResult<()> {
    transcript.absorb_domain(b"plonkish-permutation-accumulator-v1");
    absorb_usize(
        transcript,
        b"permutation-cells",
        instance.permutation_check_count(),
    );
    let beta = challenge_field(transcript, b"permutation-beta");
    let gamma = challenge_field(transcript, b"permutation-gamma");
    if proof.beta != beta || proof.gamma != gamma {
        return Err(PlonkishPiopError::InvalidProof);
    }

    let expected_trace_len = (instance.permutation_check_count() + 1)
        .max(1)
        .next_power_of_two();
    if proof.numerator_commitment.len != expected_trace_len
        || proof.denominator_commitment.len != expected_trace_len
    {
        return Err(PlonkishPiopError::InvalidProof);
    }
    absorb_merkle_commitment(
        transcript,
        b"permutation-numerator",
        &proof.numerator_commitment,
    );
    absorb_merkle_commitment(
        transcript,
        b"permutation-denominator",
        &proof.denominator_commitment,
    );

    let terminal_index = instance.permutation_check_count();
    verify_accumulator_boundary_opening(
        &proof.numerator_commitment,
        &proof.numerator_first,
        0,
        FieldElement::ONE,
    )?;
    verify_accumulator_boundary_opening(
        &proof.denominator_commitment,
        &proof.denominator_first,
        0,
        FieldElement::ONE,
    )?;
    verify_merkle_opening(
        &proof.numerator_commitment,
        &proof.numerator_last,
        terminal_index,
    )?;
    verify_merkle_opening(
        &proof.denominator_commitment,
        &proof.denominator_last,
        terminal_index,
    )?;
    if proof.numerator_last.value != proof.denominator_last.value {
        return Err(PlonkishPiopError::InvalidProof);
    }
    absorb_accumulator_boundaries(
        transcript,
        &proof.numerator_first,
        &proof.numerator_last,
        &proof.denominator_first,
        &proof.denominator_last,
    );
    verify_permutation_accumulator_subclaim(
        instance,
        commitments,
        &proof.numerator_commitment,
        &proof.denominator_commitment,
        beta,
        gamma,
        &proof.random_subclaim,
        transcript,
    )?;

    let recurrence_indices = challenge_accumulator_indices(instance, transcript);
    if recurrence_indices.len() != proof.recurrence_queries.len() {
        return Err(PlonkishPiopError::InvalidProof);
    }
    for (expected, query) in recurrence_indices
        .iter()
        .copied()
        .zip(&proof.recurrence_queries)
    {
        if expected != query.index {
            return Err(PlonkishPiopError::InvalidProof);
        }
        verify_accumulator_query(
            instance,
            commitments,
            &proof.numerator_commitment,
            &proof.denominator_commitment,
            beta,
            gamma,
            query,
        )?;
    }

    Ok(())
}

fn build_permutation_accumulator_traces(
    instance: &PlonkishInstance,
    beta: FieldElement,
    gamma: FieldElement,
) -> PlonkishPiopResult<(Vec<FieldElement>, Vec<FieldElement>)> {
    let values = flattened_cell_values(&instance.circuit);
    if values.len() != instance.permutation.len() {
        return Err(PlonkishPiopError::InvalidShape);
    }

    let mut numerator = Vec::with_capacity(values.len() + 1);
    let mut denominator = Vec::with_capacity(values.len() + 1);
    numerator.push(FieldElement::ONE);
    denominator.push(FieldElement::ONE);
    for (index, value) in values.iter().copied().enumerate() {
        let target = *instance
            .permutation
            .mapping()
            .get(index)
            .ok_or(PlonkishPiopError::InvalidPermutation)?;
        if target >= values.len() {
            return Err(PlonkishPiopError::InvalidPermutation);
        }
        let factors = hyperplonk_permutation_products(
            &[value],
            &[FieldElement::from(index)],
            &[FieldElement::from(target)],
            beta,
            gamma,
        )?;
        let numerator_next =
            *numerator.last().expect("non-empty accumulator") * factors.identity_product;
        let denominator_next =
            *denominator.last().expect("non-empty accumulator") * factors.permutation_product;
        numerator.push(numerator_next);
        denominator.push(denominator_next);
    }
    pad_to_power_of_two_in_place(&mut numerator);
    pad_to_power_of_two_in_place(&mut denominator);
    Ok((numerator, denominator))
}

#[allow(clippy::too_many_arguments)]
fn prove_permutation_accumulator_subclaim(
    instance: &PlonkishInstance,
    commitments: &PlonkishOracleCommitments,
    numerator_commitment: &Commitment,
    denominator_commitment: &Commitment,
    numerator_trace: &[FieldElement],
    denominator_trace: &[FieldElement],
    beta: FieldElement,
    gamma: FieldElement,
    transcript: &mut HashTranscript,
) -> PlonkishPiopResult<PlonkishPermutationAccumulatorSubclaimProof> {
    let point = challenge_accumulator_subclaim_point(instance, transcript)?;
    let vectors = permutation_accumulator_vectors(instance, numerator_trace, denominator_trace)?;
    let numerator_residual = numerator_recurrence_residual(&vectors, beta, gamma);
    let denominator_residual = denominator_recurrence_residual(&vectors, beta, gamma);
    if numerator_residual.iter().any(|value| !value.is_zero())
        || denominator_residual.iter().any(|value| !value.is_zero())
    {
        return Err(PlonkishPiopError::InvalidProof);
    }
    let proof = PlonkishPermutationAccumulatorSubclaimProof {
        point: point.clone(),
        value: prove_gate_column_subclaim(&vectors.value, &point)?,
        source_id: prove_gate_column_subclaim(&vectors.source_id, &point)?,
        target_id: prove_gate_column_subclaim(&vectors.target_id, &point)?,
        numerator_current: prove_gate_column_subclaim(&vectors.numerator_current, &point)?,
        numerator_next: prove_gate_column_subclaim(&vectors.numerator_next, &point)?,
        denominator_current: prove_gate_column_subclaim(&vectors.denominator_current, &point)?,
        denominator_next: prove_gate_column_subclaim(&vectors.denominator_next, &point)?,
        numerator_residual: prove_mle_folding(&numerator_residual, &point)
            .map_err(|_| PlonkishPiopError::InvalidProof)?,
        denominator_residual: prove_mle_folding(&denominator_residual, &point)
            .map_err(|_| PlonkishPiopError::InvalidProof)?,
    };
    verify_permutation_accumulator_subclaim(
        instance,
        commitments,
        numerator_commitment,
        denominator_commitment,
        beta,
        gamma,
        &proof,
        transcript,
    )?;
    Ok(proof)
}

#[allow(clippy::too_many_arguments)]
fn verify_permutation_accumulator_subclaim(
    instance: &PlonkishInstance,
    commitments: &PlonkishOracleCommitments,
    numerator_commitment: &Commitment,
    denominator_commitment: &Commitment,
    beta: FieldElement,
    gamma: FieldElement,
    proof: &PlonkishPermutationAccumulatorSubclaimProof,
    transcript: &mut HashTranscript,
) -> PlonkishPiopResult<()> {
    let expected_point = challenge_accumulator_subclaim_point(instance, transcript)?;
    if proof.point != expected_point {
        return Err(PlonkishPiopError::InvalidProof);
    }
    let expected = public_accumulator_vectors(instance, &proof.numerator_current.values)?;
    verify_accumulator_value_column(instance, commitments, &proof.value, &proof.point)?;
    verify_expected_accumulator_column(&expected.source_id, &proof.point, &proof.source_id)?;
    verify_expected_accumulator_column(&expected.target_id, &proof.point, &proof.target_id)?;
    verify_gate_column_subclaim(numerator_commitment, &proof.point, &proof.numerator_current)?;
    verify_gate_column_subclaim(
        denominator_commitment,
        &proof.point,
        &proof.denominator_current,
    )?;
    verify_shifted_accumulator_column(
        instance.permutation_check_count(),
        &proof.numerator_current,
        &proof.numerator_next,
        &proof.point,
    )?;
    verify_shifted_accumulator_column(
        instance.permutation_check_count(),
        &proof.denominator_current,
        &proof.denominator_next,
        &proof.point,
    )?;

    let vectors = PlonkishPermutationAccumulatorVectors {
        value: proof.value.values.clone(),
        source_id: proof.source_id.values.clone(),
        target_id: proof.target_id.values.clone(),
        numerator_current: proof.numerator_current.values.clone(),
        numerator_next: proof.numerator_next.values.clone(),
        denominator_current: proof.denominator_current.values.clone(),
        denominator_next: proof.denominator_next.values.clone(),
    };
    validate_accumulator_vector_lengths(instance, &vectors)?;
    let numerator_residual = numerator_recurrence_residual(&vectors, beta, gamma);
    let denominator_residual = denominator_recurrence_residual(&vectors, beta, gamma);
    if verify_mle_folding(&numerator_residual, &proof.point, &proof.numerator_residual)
        .map_err(|_| PlonkishPiopError::InvalidProof)?
        != FieldElement::ZERO
        || verify_mle_folding(&denominator_residual, &proof.point, &proof.denominator_residual)
            .map_err(|_| PlonkishPiopError::InvalidProof)?
            != FieldElement::ZERO
    {
        return Err(PlonkishPiopError::InvalidProof);
    }
    absorb_accumulator_subclaim_proof(transcript, proof);
    Ok(())
}

fn permutation_accumulator_vectors(
    instance: &PlonkishInstance,
    numerator_trace: &[FieldElement],
    denominator_trace: &[FieldElement],
) -> PlonkishPiopResult<PlonkishPermutationAccumulatorVectors> {
    let len = instance
        .permutation_check_count()
        .max(1)
        .next_power_of_two();
    if numerator_trace.len() != len || denominator_trace.len() != len {
        return Err(PlonkishPiopError::InvalidShape);
    }
    let mut public = public_accumulator_vectors(instance, numerator_trace)?;
    public.numerator_current.clone_from(&numerator_trace.to_vec());
    public.denominator_current.clone_from(&denominator_trace.to_vec());
    public.numerator_next = shifted_next_trace(instance.permutation_check_count(), numerator_trace)?;
    public.denominator_next =
        shifted_next_trace(instance.permutation_check_count(), denominator_trace)?;
    Ok(public)
}

fn public_accumulator_vectors(
    instance: &PlonkishInstance,
    current_trace_shape: &[FieldElement],
) -> PlonkishPiopResult<PlonkishPermutationAccumulatorVectors> {
    let len = current_trace_shape.len();
    if len == 0 || !len.is_power_of_two() {
        return Err(PlonkishPiopError::InvalidShape);
    }
    let cell_count = instance.permutation_check_count();
    let flat_values = flattened_cell_values(&instance.circuit);
    if flat_values.len() != cell_count || cell_count > len {
        return Err(PlonkishPiopError::InvalidShape);
    }
    let mut value = vec![FieldElement::ZERO; len];
    let mut source_id = vec![FieldElement::ZERO; len];
    let mut target_id = vec![FieldElement::ZERO; len];
    for source in 0..cell_count {
        let target = *instance
            .permutation
            .mapping()
            .get(source)
            .ok_or(PlonkishPiopError::InvalidPermutation)?;
        if target >= cell_count {
            return Err(PlonkishPiopError::InvalidPermutation);
        }
        value[source] = flat_values[source];
        source_id[source] = FieldElement::from(source);
        target_id[source] = FieldElement::from(target);
    }
    Ok(PlonkishPermutationAccumulatorVectors {
        value,
        source_id,
        target_id,
        numerator_current: vec![FieldElement::ZERO; len],
        numerator_next: vec![FieldElement::ZERO; len],
        denominator_current: vec![FieldElement::ZERO; len],
        denominator_next: vec![FieldElement::ZERO; len],
    })
}

fn shifted_next_trace(
    cell_count: usize,
    trace: &[FieldElement],
) -> PlonkishPiopResult<Vec<FieldElement>> {
    if cell_count >= trace.len() {
        return Err(PlonkishPiopError::InvalidShape);
    }
    let mut next = vec![FieldElement::ZERO; trace.len()];
    next[..cell_count].copy_from_slice(&trace[1..=cell_count]);
    Ok(next)
}

fn numerator_recurrence_residual(
    vectors: &PlonkishPermutationAccumulatorVectors,
    beta: FieldElement,
    gamma: FieldElement,
) -> Vec<FieldElement> {
    vectors
        .numerator_next
        .iter()
        .zip(&vectors.numerator_current)
        .zip(&vectors.value)
        .zip(&vectors.source_id)
        .map(|(((next, current), value), source)| *next - *current * (*value + beta * *source + gamma))
        .collect()
}

fn denominator_recurrence_residual(
    vectors: &PlonkishPermutationAccumulatorVectors,
    beta: FieldElement,
    gamma: FieldElement,
) -> Vec<FieldElement> {
    vectors
        .denominator_next
        .iter()
        .zip(&vectors.denominator_current)
        .zip(&vectors.value)
        .zip(&vectors.target_id)
        .map(|(((next, current), value), target)| *next - *current * (*value + beta * *target + gamma))
        .collect()
}

fn validate_accumulator_vector_lengths(
    instance: &PlonkishInstance,
    vectors: &PlonkishPermutationAccumulatorVectors,
) -> PlonkishPiopResult<()> {
    let len = instance
        .permutation_check_count()
        .max(1)
        .next_power_of_two();
    if [
        vectors.value.len(),
        vectors.source_id.len(),
        vectors.target_id.len(),
        vectors.numerator_current.len(),
        vectors.numerator_next.len(),
        vectors.denominator_current.len(),
        vectors.denominator_next.len(),
    ]
    .iter()
    .all(|actual| *actual == len)
    {
        Ok(())
    } else {
        Err(PlonkishPiopError::InvalidShape)
    }
}

fn challenge_accumulator_subclaim_point(
    instance: &PlonkishInstance,
    transcript: &mut HashTranscript,
) -> PlonkishPiopResult<Vec<FieldElement>> {
    let len = instance
        .permutation_check_count()
        .max(1)
        .next_power_of_two();
    let vars = log2_power_of_two(len).map_err(|_| PlonkishPiopError::InvalidShape)?;
    transcript.absorb_domain(b"plonkish-permutation-accumulator-random-subclaim-v1");
    absorb_usize(transcript, b"permutation-cells", instance.permutation_check_count());
    absorb_usize(transcript, b"accumulator-recurrence-len", len);
    Ok((0..vars)
        .map(|index| {
            absorb_usize(transcript, b"accumulator-subclaim-var", index);
            challenge_field(transcript, b"accumulator-subclaim-point")
        })
        .collect())
}

fn open_accumulator_query(
    oracles: &PlonkishOracles,
    commitments: &PlonkishOracleCommitments,
    numerator_trace: &[FieldElement],
    denominator_trace: &[FieldElement],
    index: usize,
) -> PlonkishPiopResult<PlonkishPermutationAccumulatorQuery> {
    Ok(PlonkishPermutationAccumulatorQuery {
        index,
        value: open_cell(oracles, commitments, index)?,
        numerator_current: MerklePcs::open(numerator_trace, index)
            .map_err(|_| PlonkishPiopError::InvalidProof)?,
        numerator_next: MerklePcs::open(numerator_trace, index + 1)
            .map_err(|_| PlonkishPiopError::InvalidProof)?,
        denominator_current: MerklePcs::open(denominator_trace, index)
            .map_err(|_| PlonkishPiopError::InvalidProof)?,
        denominator_next: MerklePcs::open(denominator_trace, index + 1)
            .map_err(|_| PlonkishPiopError::InvalidProof)?,
    })
}

fn verify_accumulator_query(
    instance: &PlonkishInstance,
    commitments: &PlonkishOracleCommitments,
    numerator_commitment: &Commitment,
    denominator_commitment: &Commitment,
    beta: FieldElement,
    gamma: FieldElement,
    query: &PlonkishPermutationAccumulatorQuery,
) -> PlonkishPiopResult<()> {
    let target = *instance
        .permutation
        .mapping()
        .get(query.index)
        .ok_or(PlonkishPiopError::InvalidPermutation)?;
    if target >= instance.permutation_check_count() {
        return Err(PlonkishPiopError::InvalidPermutation);
    }
    verify_cell(commitments, query.index, &query.value)?;
    verify_merkle_opening(numerator_commitment, &query.numerator_current, query.index)?;
    verify_merkle_opening(numerator_commitment, &query.numerator_next, query.index + 1)?;
    verify_merkle_opening(
        denominator_commitment,
        &query.denominator_current,
        query.index,
    )?;
    verify_merkle_opening(
        denominator_commitment,
        &query.denominator_next,
        query.index + 1,
    )?;

    let factors = hyperplonk_permutation_products(
        &[query.value.value],
        &[FieldElement::from(query.index)],
        &[FieldElement::from(target)],
        beta,
        gamma,
    )?;
    if query.numerator_next.value != query.numerator_current.value * factors.identity_product
        || query.denominator_next.value
            != query.denominator_current.value * factors.permutation_product
    {
        return Err(PlonkishPiopError::InvalidProof);
    }
    Ok(())
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
struct HyperPlonkPermutationProducts {
    identity_product: FieldElement,
    permutation_product: FieldElement,
}

fn hyperplonk_permutation_products(
    witness_perm_evals: &[FieldElement],
    id_evals: &[FieldElement],
    perm_evals: &[FieldElement],
    beta: FieldElement,
    gamma: FieldElement,
) -> PlonkishPiopResult<HyperPlonkPermutationProducts> {
    if witness_perm_evals.len() != id_evals.len() || witness_perm_evals.len() != perm_evals.len() {
        return Err(PlonkishPiopError::InvalidShape);
    }
    let mut identity_product = FieldElement::ONE;
    for (w_eval, id_eval) in witness_perm_evals.iter().zip(id_evals) {
        identity_product *= *w_eval + beta * *id_eval + gamma;
    }
    let mut permutation_product = FieldElement::ONE;
    for (w_eval, perm_eval) in witness_perm_evals.iter().zip(perm_evals) {
        permutation_product *= *w_eval + beta * *perm_eval + gamma;
    }
    Ok(HyperPlonkPermutationProducts {
        identity_product,
        permutation_product,
    })
}

#[allow(clippy::too_many_arguments)]
#[cfg(test)]
fn hyperplonk_eval_perm_gate(
    prod_evals: &[FieldElement],
    frac_evals: &[FieldElement],
    witness_perm_evals: &[FieldElement],
    id_evals: &[FieldElement],
    perm_evals: &[FieldElement],
    alpha: FieldElement,
    beta: FieldElement,
    gamma: FieldElement,
    x1: FieldElement,
) -> PlonkishPiopResult<FieldElement> {
    if prod_evals.len() < 3 || frac_evals.len() < 3 {
        return Err(PlonkishPiopError::InvalidShape);
    }
    let p1_eval = frac_evals[1] + x1 * (prod_evals[1] - frac_evals[1]);
    let p2_eval = frac_evals[2] + x1 * (prod_evals[2] - frac_evals[2]);
    let products =
        hyperplonk_permutation_products(witness_perm_evals, id_evals, perm_evals, beta, gamma)?;
    Ok(prod_evals[0] - p1_eval * p2_eval
        + alpha * (frac_evals[0] * products.permutation_product - products.identity_product))
}

fn verify_accumulator_boundary_opening(
    commitment: &Commitment,
    opening: &OpeningProof,
    expected_index: usize,
    expected_value: FieldElement,
) -> PlonkishPiopResult<()> {
    verify_merkle_opening(commitment, opening, expected_index)?;
    if opening.value == expected_value {
        Ok(())
    } else {
        Err(PlonkishPiopError::InvalidProof)
    }
}

fn open_gate_query(
    oracles: &PlonkishOracles,
    commitments: &PlonkishOracleCommitments,
    constraint_commitment: &DistributedCommitment,
    row: usize,
) -> PlonkishPiopResult<PlonkishGateQuery> {
    if row >= commitments.a.len
        || row >= commitments.b.len
        || row >= commitments.c.len
        || row >= commitments.gate_residual.len
    {
        return Err(PlonkishPiopError::InvalidShape);
    }
    Ok(PlonkishGateQuery {
        row,
        a: MerklePcs::open(&oracles.a, row).map_err(|_| PlonkishPiopError::InvalidProof)?,
        b: MerklePcs::open(&oracles.b, row).map_err(|_| PlonkishPiopError::InvalidProof)?,
        c: MerklePcs::open(&oracles.c, row).map_err(|_| PlonkishPiopError::InvalidProof)?,
        gate_residual: MerklePcs::open(&oracles.gate_residuals, row)
            .map_err(|_| PlonkishPiopError::InvalidProof)?,
        constraint_residual: DistributedBrakedown::open_index(
            &oracles.constraint_residuals,
            constraint_commitment,
            row,
        )
        .map_err(|_| PlonkishPiopError::InvalidProof)?,
    })
}

fn open_permutation_query(
    instance: &PlonkishInstance,
    oracles: &PlonkishOracles,
    commitments: &PlonkishOracleCommitments,
    constraint_commitment: &DistributedCommitment,
    source: usize,
) -> PlonkishPiopResult<PlonkishPermutationQuery> {
    let target = *instance
        .permutation
        .mapping()
        .get(source)
        .ok_or(PlonkishPiopError::InvalidPermutation)?;
    let residual_index = instance.row_count() + source;
    Ok(PlonkishPermutationQuery {
        source,
        target,
        source_value: open_cell(oracles, commitments, source)?,
        target_value: open_cell(oracles, commitments, target)?,
        permutation_residual: MerklePcs::open(&oracles.permutation_residuals, source)
            .map_err(|_| PlonkishPiopError::InvalidProof)?,
        constraint_residual: DistributedBrakedown::open_index(
            &oracles.constraint_residuals,
            constraint_commitment,
            residual_index,
        )
        .map_err(|_| PlonkishPiopError::InvalidProof)?,
    })
}

fn verify_gate_query(
    instance: &PlonkishInstance,
    commitments: &PlonkishOracleCommitments,
    constraint_commitment: &DistributedCommitment,
    query: &PlonkishGateQuery,
) -> PlonkishPiopResult<()> {
    let row = instance
        .circuit
        .rows()
        .get(query.row)
        .ok_or(PlonkishPiopError::InvalidProof)?;
    verify_merkle_opening(&commitments.a, &query.a, query.row)?;
    verify_merkle_opening(&commitments.b, &query.b, query.row)?;
    verify_merkle_opening(&commitments.c, &query.c, query.row)?;
    verify_merkle_opening(&commitments.gate_residual, &query.gate_residual, query.row)?;
    let committed_residual =
        DistributedBrakedown::verify_index(constraint_commitment, &query.constraint_residual)
            .map_err(|_| PlonkishPiopError::InvalidProof)?;
    if query.constraint_residual.global_index != query.row {
        return Err(PlonkishPiopError::InvalidProof);
    }
    let expected = CustomizedGate::vanilla_plonk_gate().evaluate(
        &[row.q_l, row.q_r, row.q_o, row.q_m, row.q_c],
        &[query.a.value, query.b.value, query.c.value],
    );
    if expected != query.gate_residual.value || committed_residual != query.gate_residual.value {
        return Err(PlonkishPiopError::InvalidProof);
    }
    Ok(())
}

fn verify_permutation_query(
    instance: &PlonkishInstance,
    commitments: &PlonkishOracleCommitments,
    constraint_commitment: &DistributedCommitment,
    query: &PlonkishPermutationQuery,
) -> PlonkishPiopResult<()> {
    let expected_target = *instance
        .permutation
        .mapping()
        .get(query.source)
        .ok_or(PlonkishPiopError::InvalidPermutation)?;
    if query.target != expected_target {
        return Err(PlonkishPiopError::InvalidProof);
    }
    verify_cell(commitments, query.source, &query.source_value)?;
    verify_cell(commitments, query.target, &query.target_value)?;
    verify_merkle_opening(
        &commitments.permutation_residual,
        &query.permutation_residual,
        query.source,
    )?;
    let residual_index = instance.row_count() + query.source;
    let committed_residual =
        DistributedBrakedown::verify_index(constraint_commitment, &query.constraint_residual)
            .map_err(|_| PlonkishPiopError::InvalidProof)?;
    if query.constraint_residual.global_index != residual_index {
        return Err(PlonkishPiopError::InvalidProof);
    }
    let expected = query.source_value.value - query.target_value.value;
    if expected != query.permutation_residual.value
        || committed_residual != query.permutation_residual.value
    {
        return Err(PlonkishPiopError::InvalidProof);
    }
    Ok(())
}

fn open_cell(
    oracles: &PlonkishOracles,
    commitments: &PlonkishOracleCommitments,
    cell: usize,
) -> PlonkishPiopResult<OpeningProof> {
    let row = cell / 3;
    match cell % 3 {
        0 if row < commitments.a.len => {
            MerklePcs::open(&oracles.a, row).map_err(|_| PlonkishPiopError::InvalidProof)
        }
        1 if row < commitments.b.len => {
            MerklePcs::open(&oracles.b, row).map_err(|_| PlonkishPiopError::InvalidProof)
        }
        2 if row < commitments.c.len => {
            MerklePcs::open(&oracles.c, row).map_err(|_| PlonkishPiopError::InvalidProof)
        }
        _ => Err(PlonkishPiopError::InvalidProof),
    }
}

fn verify_cell(
    commitments: &PlonkishOracleCommitments,
    cell: usize,
    opening: &OpeningProof,
) -> PlonkishPiopResult<()> {
    let row = cell / 3;
    match cell % 3 {
        0 => verify_merkle_opening(&commitments.a, opening, row),
        1 => verify_merkle_opening(&commitments.b, opening, row),
        2 => verify_merkle_opening(&commitments.c, opening, row),
        _ => Err(PlonkishPiopError::InvalidProof),
    }
}

fn verify_merkle_opening(
    commitment: &Commitment,
    opening: &OpeningProof,
    expected_index: usize,
) -> PlonkishPiopResult<()> {
    if opening.index != expected_index {
        return Err(PlonkishPiopError::InvalidProof);
    }
    MerklePcs::verify(commitment, opening).map_err(|_| PlonkishPiopError::InvalidProof)
}

pub fn proof_size_bytes(proof: &PlonkishPiopProof) -> usize {
    commitment_size_bytes(&proof.oracle_commitments.a)
        + commitment_size_bytes(&proof.oracle_commitments.b)
        + commitment_size_bytes(&proof.oracle_commitments.c)
        + commitment_size_bytes(&proof.oracle_commitments.q_l)
        + commitment_size_bytes(&proof.oracle_commitments.q_r)
        + commitment_size_bytes(&proof.oracle_commitments.q_o)
        + commitment_size_bytes(&proof.oracle_commitments.q_m)
        + commitment_size_bytes(&proof.oracle_commitments.q_c)
        + commitment_size_bytes(&proof.oracle_commitments.gate_residual)
        + commitment_size_bytes(&proof.oracle_commitments.permutation_residual)
        + gate_subclaim_size(&proof.gate_subclaim)
        + permutation_accumulator_size(&proof.permutation_accumulator)
        + distributed_commitment_size_bytes(&proof.constraint_commitment)
        + pcs_proof_size_bytes(&proof.constraint_opening)
        + zerocheck_proof_size_bytes(&proof.sumcheck)
        + vec_len_prefix()
        + proof
            .gate_queries
            .iter()
            .map(gate_query_size)
            .sum::<usize>()
        + vec_len_prefix()
        + proof
            .permutation_queries
            .iter()
            .map(permutation_query_size)
            .sum::<usize>()
        + 8
}

fn communication_bytes(proof: &PlonkishPiopProof, _workers: usize) -> usize {
    pcs_communication_bytes(&proof.constraint_opening)
}

fn gate_query_size(query: &PlonkishGateQuery) -> usize {
    8 + opening_proof_size_bytes(&query.a)
        + opening_proof_size_bytes(&query.b)
        + opening_proof_size_bytes(&query.c)
        + opening_proof_size_bytes(&query.gate_residual)
        + distributed_index_opening_size_bytes(&query.constraint_residual)
}

fn permutation_query_size(query: &PlonkishPermutationQuery) -> usize {
    16 + opening_proof_size_bytes(&query.source_value)
        + opening_proof_size_bytes(&query.target_value)
        + opening_proof_size_bytes(&query.permutation_residual)
        + distributed_index_opening_size_bytes(&query.constraint_residual)
}

fn permutation_accumulator_size(proof: &PlonkishPermutationAccumulatorProof) -> usize {
    2 * 8
        + commitment_size_bytes(&proof.numerator_commitment)
        + commitment_size_bytes(&proof.denominator_commitment)
        + opening_proof_size_bytes(&proof.numerator_first)
        + opening_proof_size_bytes(&proof.numerator_last)
        + opening_proof_size_bytes(&proof.denominator_first)
        + opening_proof_size_bytes(&proof.denominator_last)
        + vec_len_prefix()
        + proof
            .recurrence_queries
            .iter()
            .map(accumulator_query_size)
            .sum::<usize>()
}

fn accumulator_query_size(query: &PlonkishPermutationAccumulatorQuery) -> usize {
    8 + opening_proof_size_bytes(&query.value)
        + opening_proof_size_bytes(&query.numerator_current)
        + opening_proof_size_bytes(&query.numerator_next)
        + opening_proof_size_bytes(&query.denominator_current)
        + opening_proof_size_bytes(&query.denominator_next)
}

fn gate_subclaim_size(proof: &PlonkishGateSubclaimProof) -> usize {
    field_vec_size(&proof.point)
        + 8
        + gate_subclaim_columns(proof)
            .iter()
            .map(|(_, column)| gate_column_subclaim_size(column))
            .sum::<usize>()
}

fn gate_column_subclaim_size(column: &PlonkishGateColumnSubclaim) -> usize {
    field_vec_size(&column.values) + folding_proof_size(&column.folding)
}

fn folding_proof_size(proof: &MleFoldingProof) -> usize {
    commitment_size_bytes(&proof.input_commitment)
        + vec_len_prefix()
        + proof
            .layers
            .iter()
            .map(fold_layer_proof_size)
            .sum::<usize>()
        + 8
}

fn fold_layer_proof_size(layer: &FoldLayerProof) -> usize {
    8 + field_vec_size(&layer.values) + commitment_size_bytes(&layer.commitment)
}

fn zerocheck_proof_size_bytes(proof: &ZerocheckProof) -> usize {
    field_vec_size(&proof.eq_point)
        + 8
        + vec_len_prefix()
        + proof.rounds.len() * 24
        + field_vec_size(&proof.challenges)
        + 8
}

fn field_vec_size(values: &[FieldElement]) -> usize {
    vec_len_prefix() + values.len() * 8
}

fn vec_len_prefix() -> usize {
    8
}

fn absorb_circuit_statement(
    instance: &PlonkishInstance,
    workers: usize,
    transcript: &mut HashTranscript,
) {
    absorb_usize(transcript, b"workers", workers);
    absorb_usize(transcript, b"rows", instance.circuit.len());
    for (row_index, row) in instance.circuit.rows().iter().enumerate() {
        absorb_usize(transcript, b"row", row_index);
        for value in [row.q_l, row.q_r, row.q_o, row.q_m, row.q_c] {
            absorb_field(transcript, b"selector", value);
        }
    }
    for (source, target) in instance.permutation.mapping().iter().copied().enumerate() {
        absorb_usize(transcript, b"perm-source", source);
        absorb_usize(transcript, b"perm-target", target);
    }
}

fn absorb_oracle_commitments(
    commitments: &PlonkishOracleCommitments,
    transcript: &mut HashTranscript,
) {
    absorb_merkle_commitment(transcript, b"a", &commitments.a);
    absorb_merkle_commitment(transcript, b"b", &commitments.b);
    absorb_merkle_commitment(transcript, b"c", &commitments.c);
    absorb_merkle_commitment(transcript, b"q-l", &commitments.q_l);
    absorb_merkle_commitment(transcript, b"q-r", &commitments.q_r);
    absorb_merkle_commitment(transcript, b"q-o", &commitments.q_o);
    absorb_merkle_commitment(transcript, b"q-m", &commitments.q_m);
    absorb_merkle_commitment(transcript, b"q-c", &commitments.q_c);
    absorb_merkle_commitment(transcript, b"gate-residual", &commitments.gate_residual);
    absorb_merkle_commitment(
        transcript,
        b"permutation-residual",
        &commitments.permutation_residual,
    );
}

fn absorb_merkle_commitment(
    transcript: &mut HashTranscript,
    label: &'static [u8],
    commitment: &Commitment,
) {
    absorb_usize(transcript, label, commitment.len);
    transcript.absorb_commitment(label, &commitment.root);
}

fn absorb_accumulator_boundaries(
    transcript: &mut HashTranscript,
    numerator_first: &OpeningProof,
    numerator_last: &OpeningProof,
    denominator_first: &OpeningProof,
    denominator_last: &OpeningProof,
) {
    absorb_usize(
        transcript,
        b"permutation-numerator-first-index",
        numerator_first.index,
    );
    absorb_field(
        transcript,
        b"permutation-numerator-first",
        numerator_first.value,
    );
    absorb_usize(
        transcript,
        b"permutation-numerator-last-index",
        numerator_last.index,
    );
    absorb_field(
        transcript,
        b"permutation-numerator-last",
        numerator_last.value,
    );
    absorb_usize(
        transcript,
        b"permutation-denominator-first-index",
        denominator_first.index,
    );
    absorb_field(
        transcript,
        b"permutation-denominator-first",
        denominator_first.value,
    );
    absorb_usize(
        transcript,
        b"permutation-denominator-last-index",
        denominator_last.index,
    );
    absorb_field(
        transcript,
        b"permutation-denominator-last",
        denominator_last.value,
    );
}

fn challenge_accumulator_indices(
    instance: &PlonkishInstance,
    transcript: &mut HashTranscript,
) -> Vec<usize> {
    let len = instance.permutation_check_count();
    transcript.absorb_domain(b"plonkish-permutation-accumulator-exhaustive-v1");
    absorb_usize(transcript, b"permutation-cells", len);
    (0..len).collect()
}

fn challenge_gate_indices(
    instance: &PlonkishInstance,
    transcript: &mut HashTranscript,
) -> Vec<usize> {
    let rows = instance.row_count();
    transcript.absorb_domain(b"plonkish-gate-consistency-exhaustive-v1");
    absorb_usize(transcript, b"rows", rows);
    (0..rows).collect()
}

fn challenge_permutation_indices(
    instance: &PlonkishInstance,
    transcript: &mut HashTranscript,
) -> Vec<usize> {
    let len = instance.permutation_check_count();
    transcript.absorb_domain(b"plonkish-permutation-consistency-exhaustive-v1");
    absorb_usize(transcript, b"permutation-cells", len);
    (0..len).collect()
}

fn flattened_cell_values(circuit: &PlonkishCircuit) -> Vec<FieldElement> {
    circuit
        .rows()
        .iter()
        .flat_map(|row| [row.a, row.b, row.c])
        .collect()
}

fn cell_index(cell: PlonkishCell, row_count: usize) -> PlonkishPiopResult<usize> {
    if cell.row >= row_count {
        return Err(PlonkishPiopError::InvalidPermutation);
    }
    let column = match cell.column {
        PlonkishColumn::A => 0,
        PlonkishColumn::B => 1,
        PlonkishColumn::C => 2,
    };
    Ok(cell.row * 3 + column)
}

fn validate_permutation(mapping: &[usize]) -> PlonkishPiopResult<()> {
    let mut seen = vec![false; mapping.len()];
    for target in mapping {
        if *target >= mapping.len() || seen[*target] {
            return Err(PlonkishPiopError::InvalidPermutation);
        }
        seen[*target] = true;
    }
    Ok(())
}

fn pad_to_power_of_two(mut values: Vec<FieldElement>) -> Vec<FieldElement> {
    let len = values.len().max(1).next_power_of_two();
    values.resize(len, FieldElement::ZERO);
    values
}

fn pad_to_power_of_two_in_place(values: &mut Vec<FieldElement>) {
    let len = values.len().max(1).next_power_of_two();
    values.resize(len, FieldElement::ZERO);
}

fn challenge_field(transcript: &mut HashTranscript, label: &[u8]) -> FieldElement {
    FieldElement::from(transcript.challenge_u64(label, FieldElement::MODULUS))
}

fn absorb_field(transcript: &mut HashTranscript, label: &[u8], value: FieldElement) {
    transcript.absorb_public(label, &value.value().to_le_bytes());
}

fn absorb_usize(transcript: &mut HashTranscript, label: &[u8], value: usize) {
    transcript.absorb_public(label, &(value as u64).to_le_bytes());
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plonkish_piop_accepts_valid_gate_and_permutation() {
        let instance = sample_plonkish_instance(4).expect("sample");
        let mut prover_transcript = HashTranscript::new(b"plonkish-test");
        let proof = prove_plonkish(&instance, 2, &mut prover_transcript).expect("proof");

        let mut verifier_transcript = HashTranscript::new(b"plonkish-test");
        let metrics = verify_plonkish(&instance, &proof, &mut verifier_transcript).expect("verify");

        assert_eq!(metrics.rows, 4);
        assert!(metrics.proof_bytes > 0);
        assert_eq!(
            proof.permutation_accumulator.numerator_first.value,
            FieldElement::ONE
        );
        assert_eq!(
            proof.permutation_accumulator.denominator_first.value,
            FieldElement::ONE
        );
        assert_eq!(
            proof.permutation_accumulator.numerator_last.value,
            proof.permutation_accumulator.denominator_last.value
        );
        assert_eq!(
            permutation_grand_product_delta(
                &instance,
                proof.permutation_accumulator.beta,
                proof.permutation_accumulator.gamma
            )
            .expect("delta"),
            FieldElement::ZERO
        );
    }

    #[test]
    fn invalid_gate_is_rejected_before_proving() {
        let instance = sample_plonkish_instance(2).expect("sample");
        let bad = tamper_gate(&instance);
        let mut transcript = HashTranscript::new(b"plonkish-bad-gate");

        assert_eq!(
            prove_plonkish(&bad, 1, &mut transcript),
            Err(PlonkishPiopError::Unsatisfied)
        );
    }

    #[test]
    fn permutation_tampering_fails_verification() {
        let instance = sample_plonkish_instance(3).expect("sample");
        let mut prover_transcript = HashTranscript::new(b"plonkish-perm");
        let mut proof = prove_plonkish(&instance, 1, &mut prover_transcript).expect("proof");
        proof.permutation_queries[0].permutation_residual.value += FieldElement::ONE;

        let mut verifier_transcript = HashTranscript::new(b"plonkish-perm");
        assert_eq!(
            verify_plonkish(&instance, &proof, &mut verifier_transcript),
            Err(PlonkishPiopError::InvalidProof)
        );
    }

    #[test]
    fn permutation_accumulator_tampering_fails_verification() {
        let instance = sample_plonkish_instance(4).expect("sample");
        let mut prover_transcript = HashTranscript::new(b"plonkish-accumulator");
        let mut proof = prove_plonkish(&instance, 2, &mut prover_transcript).expect("proof");
        proof.permutation_accumulator.numerator_last.value += FieldElement::ONE;

        let mut verifier_transcript = HashTranscript::new(b"plonkish-accumulator");
        assert_eq!(
            verify_plonkish(&instance, &proof, &mut verifier_transcript),
            Err(PlonkishPiopError::InvalidProof)
        );
    }

    #[test]
    fn permutation_accumulator_challenge_tampering_fails_verification() {
        let instance = sample_plonkish_instance(4).expect("sample");
        let mut prover_transcript = HashTranscript::new(b"plonkish-accumulator-challenge");
        let mut proof = prove_plonkish(&instance, 2, &mut prover_transcript).expect("proof");
        proof.permutation_accumulator.beta += FieldElement::ONE;

        let mut verifier_transcript = HashTranscript::new(b"plonkish-accumulator-challenge");
        assert_eq!(
            verify_plonkish(&instance, &proof, &mut verifier_transcript),
            Err(PlonkishPiopError::InvalidProof)
        );
    }

    #[test]
    fn gate_random_point_subclaim_tampering_fails_verification() {
        let instance = sample_plonkish_instance(4).expect("sample");
        let mut prover_transcript = HashTranscript::new(b"plonkish-gate-subclaim");
        let proof = prove_plonkish(&instance, 2, &mut prover_transcript).expect("proof");

        let mut bad_values = proof.clone();
        bad_values.gate_subclaim.a.values[0] += FieldElement::ONE;
        let mut verifier_transcript = HashTranscript::new(b"plonkish-gate-subclaim");
        assert_eq!(
            verify_plonkish(&instance, &bad_values, &mut verifier_transcript),
            Err(PlonkishPiopError::InvalidProof)
        );

        let mut bad_final = proof.clone();
        bad_final.gate_subclaim.q_m.folding.final_value += FieldElement::ONE;
        let mut verifier_transcript = HashTranscript::new(b"plonkish-gate-subclaim");
        assert_eq!(
            verify_plonkish(&instance, &bad_final, &mut verifier_transcript),
            Err(PlonkishPiopError::InvalidProof)
        );

        let mut bad_virtual_value = proof.clone();
        bad_virtual_value.gate_subclaim.virtual_gate_value += FieldElement::ONE;
        let mut verifier_transcript = HashTranscript::new(b"plonkish-gate-subclaim");
        assert_eq!(
            verify_plonkish(&instance, &bad_virtual_value, &mut verifier_transcript),
            Err(PlonkishPiopError::InvalidProof)
        );

        let mut bad_selector_commitment = proof;
        bad_selector_commitment.oracle_commitments.q_l.root[0] ^= 1;
        let mut verifier_transcript = HashTranscript::new(b"plonkish-gate-subclaim");
        assert_eq!(
            verify_plonkish(
                &instance,
                &bad_selector_commitment,
                &mut verifier_transcript
            ),
            Err(PlonkishPiopError::InvalidProof)
        );
    }

    #[test]
    fn consistency_queries_cover_full_plonkish_domains() {
        let instance = sample_plonkish_instance(4).expect("sample");
        let mut prover_transcript = HashTranscript::new(b"plonkish-exhaustive-consistency");
        let proof = prove_plonkish(&instance, 2, &mut prover_transcript).expect("proof");

        assert_eq!(
            proof
                .gate_queries
                .iter()
                .map(|query| query.row)
                .collect::<Vec<_>>(),
            (0..instance.row_count()).collect::<Vec<_>>()
        );
        assert_eq!(
            proof
                .permutation_queries
                .iter()
                .map(|query| query.source)
                .collect::<Vec<_>>(),
            (0..instance.permutation_check_count()).collect::<Vec<_>>()
        );
        assert_eq!(
            proof
                .permutation_accumulator
                .recurrence_queries
                .iter()
                .map(|query| query.index)
                .collect::<Vec<_>>(),
            (0..instance.permutation_check_count()).collect::<Vec<_>>()
        );
    }

    #[test]
    fn proof_size_accounting_includes_accumulator_recurrence_queries() {
        let instance = sample_plonkish_instance(4).expect("sample");
        let mut prover_transcript = HashTranscript::new(b"plonkish-size-accounting");
        let mut proof = prove_plonkish(&instance, 2, &mut prover_transcript).expect("proof");
        let original_size = proof_size_bytes(&proof);
        let removed = proof
            .permutation_accumulator
            .recurrence_queries
            .pop()
            .expect("recurrence query");

        assert_eq!(
            proof_size_bytes(&proof),
            original_size - accumulator_query_size(&removed)
        );
    }

    #[test]
    fn proof_size_accounting_includes_gate_subclaim_values() {
        let instance = sample_plonkish_instance(4).expect("sample");
        let mut prover_transcript = HashTranscript::new(b"plonkish-gate-size-accounting");
        let mut proof = prove_plonkish(&instance, 2, &mut prover_transcript).expect("proof");
        let original_size = proof_size_bytes(&proof);
        proof
            .gate_subclaim
            .a
            .values
            .pop()
            .expect("gate subclaim value");

        assert_eq!(proof_size_bytes(&proof), original_size - 8);
    }

    #[test]
    fn hyperplonk_permutation_product_helper_matches_factor_semantics() {
        let beta = FieldElement::from(5_u64);
        let gamma = FieldElement::from(7_u64);
        let witness = [FieldElement::from(11_u64), FieldElement::from(13_u64)];
        let ids = [FieldElement::from(2_u64), FieldElement::from(3_u64)];
        let perms = [FieldElement::from(3_u64), FieldElement::from(2_u64)];

        let products =
            hyperplonk_permutation_products(&witness, &ids, &perms, beta, gamma).expect("products");
        assert_eq!(
            products.identity_product,
            (witness[0] + beta * ids[0] + gamma) * (witness[1] + beta * ids[1] + gamma)
        );
        assert_eq!(
            products.permutation_product,
            (witness[0] + beta * perms[0] + gamma) * (witness[1] + beta * perms[1] + gamma)
        );
    }

    #[test]
    fn hyperplonk_eval_perm_gate_accepts_constructed_zero_subclaim() {
        let alpha = FieldElement::from(3_u64);
        let beta = FieldElement::from(5_u64);
        let gamma = FieldElement::from(7_u64);
        let x1 = FieldElement::from(2_u64);
        let witness = [FieldElement::from(11_u64)];
        let ids = [FieldElement::from(13_u64)];
        let perms = [FieldElement::from(17_u64)];
        let products =
            hyperplonk_permutation_products(&witness, &ids, &perms, beta, gamma).expect("products");
        let frac0 = products.identity_product / products.permutation_product;
        let prod1 = FieldElement::from(19_u64);
        let frac1 = FieldElement::from(23_u64);
        let prod2 = FieldElement::from(29_u64);
        let frac2 = FieldElement::from(31_u64);
        let p1 = frac1 + x1 * (prod1 - frac1);
        let p2 = frac2 + x1 * (prod2 - frac2);
        let prod0 = p1 * p2;

        let eval = hyperplonk_eval_perm_gate(
            &[prod0, prod1, prod2],
            &[frac0, frac1, frac2],
            &witness,
            &ids,
            &perms,
            alpha,
            beta,
            gamma,
            x1,
        )
        .expect("eval");
        assert!(eval.is_zero());
    }

    #[test]
    fn permutation_mapping_must_be_bijection() {
        assert_eq!(
            PlonkishPermutation::from_mapping(vec![0, 0]),
            Err(PlonkishPiopError::InvalidPermutation)
        );
    }

    #[test]
    fn worker_count_is_bound_to_commitment_shape() {
        let instance = sample_plonkish_instance(2).expect("sample");
        let mut prover_transcript = HashTranscript::new(b"plonkish-workers");
        let mut proof = prove_plonkish(&instance, 1, &mut prover_transcript).expect("proof");
        proof.workers = 2;

        let mut verifier_transcript = HashTranscript::new(b"plonkish-workers");
        assert_eq!(
            verify_plonkish(&instance, &proof, &mut verifier_transcript),
            Err(PlonkishPiopError::InvalidShape)
        );
    }

    #[test]
    fn oracle_lengths_are_bound_to_instance_shape() {
        let instance = sample_plonkish_instance(4).expect("sample");
        let mut prover_transcript = HashTranscript::new(b"plonkish-shape");
        let proof = prove_plonkish(&instance, 2, &mut prover_transcript).expect("proof");

        let mut bad_oracle_len = proof.clone();
        bad_oracle_len.oracle_commitments.a.len *= 2;
        let mut verifier_transcript = HashTranscript::new(b"plonkish-shape");
        assert_eq!(
            verify_plonkish(&instance, &bad_oracle_len, &mut verifier_transcript),
            Err(PlonkishPiopError::InvalidShape)
        );

        let mut bad_constraint_len = proof;
        bad_constraint_len.constraint_commitment.original_len *= 2;
        let mut verifier_transcript = HashTranscript::new(b"plonkish-shape");
        assert_eq!(
            verify_plonkish(&instance, &bad_constraint_len, &mut verifier_transcript),
            Err(PlonkishPiopError::InvalidShape)
        );
    }
}

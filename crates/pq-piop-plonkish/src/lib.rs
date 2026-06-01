use pq_core::{
    CustomizedGate, FieldElement, MultilinearPolynomial, PlonkishCircuit, PlonkishRow,
    log2_power_of_two,
};
use pq_pcs::{
    Commitment, CompactDistributedOpening, DistributedBrakedown, DistributedCommitment,
    DistributedIndexOpening, DistributedOpening, DistributedPcsParams, MerklePcs, OpeningProof,
    PolynomialCommitment, SampledMleFoldingProof, commitment_size_bytes,
    communication_bytes as full_pcs_communication_bytes, compact_communication_bytes,
    compact_proof_size_bytes, distributed_commitment_size_bytes,
    distributed_index_communication_bytes, distributed_index_opening_size_bytes,
    opening_proof_size_bytes, proof_size_bytes as full_pcs_proof_size_bytes,
    prove_sampled_mle_folding, sampled_mle_folding_proof_size_bytes, verify_sampled_mle_folding,
};
use pq_piop::Piop;
use pq_sumcheck::{
    CubicZerocheckProof, ZerocheckProof, cubic_zerocheck_final_evaluation, prove_cubic_zerocheck,
    prove_zerocheck_proof, verify_cubic_zerocheck_rounds, verify_zerocheck_rounds,
    zerocheck_final_evaluation,
};
use pq_transcript::Transcript;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PlonkishPiopError {
    Unsatisfied,
    InvalidShape,
    InvalidPermutation,
    InvalidProof,
}

pub type PlonkishPiopResult<T> = Result<T, PlonkishPiopError>;

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct PlonkishWitnessRow {
    pub a: FieldElement,
    pub b: FieldElement,
    pub c: FieldElement,
}

impl PlonkishWitnessRow {
    pub fn new(a: FieldElement, b: FieldElement, c: FieldElement) -> Self {
        Self { a, b, c }
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PlonkishWitness {
    rows: Vec<PlonkishWitnessRow>,
}

impl PlonkishWitness {
    pub fn new(rows: Vec<PlonkishWitnessRow>) -> Self {
        Self { rows }
    }

    pub fn from_instance(instance: &PlonkishInstance) -> Self {
        Self {
            rows: instance
                .circuit
                .rows()
                .iter()
                .map(|row| PlonkishWitnessRow::new(row.a, row.b, row.c))
                .collect(),
        }
    }

    pub fn rows(&self) -> &[PlonkishWitnessRow] {
        &self.rows
    }

    pub fn rows_mut(&mut self) -> &mut [PlonkishWitnessRow] {
        &mut self.rows
    }
}

pub struct PlonkishPiop;

impl Piop for PlonkishPiop {
    type Statement = PlonkishInstance;
    type Witness = PlonkishWitness;
    type Proof = PlonkishPiopProof;
    type Metrics = PlonkishMetrics;
    type Error = PlonkishPiopError;

    fn prove_interactive<T: Transcript>(
        statement: &Self::Statement,
        witness: &Self::Witness,
        workers: usize,
        pcs_params: DistributedPcsParams,
        transcript: &mut T,
    ) -> Result<Self::Proof, Self::Error> {
        prove_plonkish_with_witness_and_pcs_params(
            statement, witness, workers, pcs_params, transcript,
        )
    }

    fn verify_interactive<T: Transcript>(
        statement: &Self::Statement,
        proof: &Self::Proof,
        pcs_params: DistributedPcsParams,
        transcript: &mut T,
    ) -> Result<Self::Metrics, Self::Error> {
        verify_plonkish_with_pcs_params(statement, proof, pcs_params, transcript)
    }
}

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

fn validate_plonkish_witness(
    instance: &PlonkishInstance,
    witness: &PlonkishWitness,
) -> PlonkishPiopResult<()> {
    let rows = instance.circuit.rows();
    if witness.rows().len() != rows.len() {
        return Err(PlonkishPiopError::InvalidShape);
    }
    for (statement_row, witness_row) in rows.iter().zip(witness.rows()) {
        if statement_row.a != witness_row.a
            || statement_row.b != witness_row.b
            || statement_row.c != witness_row.c
        {
            return Err(PlonkishPiopError::Unsatisfied);
        }
    }
    Ok(())
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PlonkishPiopProof {
    pub oracle_commitments: PlonkishOracleCommitments,
    pub gate_subclaim: PlonkishGateSubclaimProof,
    pub gate_cubic: PlonkishGateCubicProof,
    pub permutation_accumulator: PlonkishPermutationAccumulatorProof,
    pub constraint_commitment: DistributedCommitment,
    pub constraint_opening: PlonkishPcsOpening,
    pub sumcheck: ZerocheckProof,
    pub gate_queries: Vec<PlonkishGateQuery>,
    pub permutation_queries: Vec<PlonkishPermutationQuery>,
    pub workers: usize,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PlonkishPcsOpening {
    Full(DistributedOpening),
    Compact(CompactDistributedOpening),
}

impl PlonkishPcsOpening {
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
    ) -> PlonkishPiopResult<()> {
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
        .map_err(|_| PlonkishPiopError::InvalidProof)
    }

    pub fn proof_size_bytes(&self) -> usize {
        match self {
            Self::Full(opening) => full_pcs_proof_size_bytes(opening),
            Self::Compact(opening) => compact_proof_size_bytes(opening),
        }
    }

    pub fn communication_bytes(&self) -> usize {
        match self {
            Self::Full(opening) => full_pcs_communication_bytes(opening),
            Self::Compact(opening) => compact_communication_bytes(opening),
        }
    }
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
    pub gate_product_left: Commitment,
    pub gate_linear_output: Commitment,
    pub gate_residual: Commitment,
    pub permutation_residual: Commitment,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PlonkishGateSubclaimProof {
    pub point: Vec<FieldElement>,
    pub virtual_gate_value: FieldElement,
    pub a: PlonkishSampledGateColumnSubclaim,
    pub b: PlonkishSampledGateColumnSubclaim,
    pub c: PlonkishSampledGateColumnSubclaim,
    pub q_l: PlonkishSampledGateColumnSubclaim,
    pub q_r: PlonkishSampledGateColumnSubclaim,
    pub q_o: PlonkishSampledGateColumnSubclaim,
    pub q_m: PlonkishSampledGateColumnSubclaim,
    pub q_c: PlonkishSampledGateColumnSubclaim,
    pub gate_residual: PlonkishSampledGateColumnSubclaim,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PlonkishSampledGateColumnSubclaim {
    pub folding: SampledMleFoldingProof,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PlonkishGateCubicProof {
    pub sumcheck: CubicZerocheckProof,
    pub product_left: PlonkishSampledGateColumnSubclaim,
    pub b: PlonkishSampledGateColumnSubclaim,
    pub linear_output: PlonkishSampledGateColumnSubclaim,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PlonkishGateQuery {
    pub row: usize,
    pub a: OpeningProof,
    pub b: OpeningProof,
    pub c: OpeningProof,
    pub q_l: OpeningProof,
    pub q_r: OpeningProof,
    pub q_o: OpeningProof,
    pub q_m: OpeningProof,
    pub q_c: OpeningProof,
    pub gate_product_left: OpeningProof,
    pub gate_linear_output: OpeningProof,
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
    pub public_commitments: PlonkishPermutationAccumulatorPublicCommitments,
    pub numerator_next_commitment: Commitment,
    pub denominator_next_commitment: Commitment,
    pub value: PlonkishSampledGateColumnSubclaim,
    pub source_id: PlonkishSampledGateColumnSubclaim,
    pub target_id: PlonkishSampledGateColumnSubclaim,
    pub numerator_current: PlonkishSampledGateColumnSubclaim,
    pub numerator_next: PlonkishSampledGateColumnSubclaim,
    pub denominator_current: PlonkishSampledGateColumnSubclaim,
    pub denominator_next: PlonkishSampledGateColumnSubclaim,
    pub numerator_residual: PlonkishSampledGateColumnSubclaim,
    pub denominator_residual: PlonkishSampledGateColumnSubclaim,
    pub numerator_recurrence: PlonkishAccumulatorRecurrenceProof,
    pub denominator_recurrence: PlonkishAccumulatorRecurrenceProof,
    pub residual_queries: Vec<PlonkishAccumulatorResidualQuery>,
    pub numerator_shift_queries: Vec<PlonkishAccumulatorShiftQuery>,
    pub denominator_shift_queries: Vec<PlonkishAccumulatorShiftQuery>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PlonkishAccumulatorRecurrenceProof {
    pub sumcheck: CubicZerocheckProof,
    pub current: PlonkishSampledGateColumnSubclaim,
    pub value: PlonkishSampledGateColumnSubclaim,
    pub id: PlonkishSampledGateColumnSubclaim,
    pub active: PlonkishSampledGateColumnSubclaim,
    pub next: PlonkishSampledGateColumnSubclaim,
    pub residual: PlonkishSampledGateColumnSubclaim,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PlonkishAccumulatorShiftQuery {
    pub index: usize,
    pub current_at_next: OpeningProof,
    pub shifted_at_index: OpeningProof,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PlonkishAccumulatorResidualQuery {
    pub index: usize,
    pub value: OpeningProof,
    pub source_id: OpeningProof,
    pub target_id: OpeningProof,
    pub numerator_current: OpeningProof,
    pub numerator_next: OpeningProof,
    pub denominator_current: OpeningProof,
    pub denominator_next: OpeningProof,
    pub numerator_residual: OpeningProof,
    pub denominator_residual: OpeningProof,
}

struct PlonkishPermutationAccumulatorVectors {
    active: Vec<FieldElement>,
    value: Vec<FieldElement>,
    source_id: Vec<FieldElement>,
    target_id: Vec<FieldElement>,
    numerator_current: Vec<FieldElement>,
    numerator_next: Vec<FieldElement>,
    denominator_current: Vec<FieldElement>,
    denominator_next: Vec<FieldElement>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PlonkishPermutationAccumulatorPublicCommitments {
    pub active: Commitment,
    pub value: Commitment,
    pub source_id: Commitment,
    pub target_id: Commitment,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PlonkishPermutationAccumulatorQuery {
    pub index: usize,
    pub value: OpeningProof,
    pub public_value: OpeningProof,
    pub source_id: OpeningProof,
    pub target_id: OpeningProof,
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
    gate_product_left: Vec<FieldElement>,
    gate_linear_output: Vec<FieldElement>,
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
        let gate_product_left = q_m
            .iter()
            .zip(&a)
            .map(|(q_m, a)| *q_m * *a)
            .collect::<Vec<_>>();
        let gate_linear_output = q_l
            .iter()
            .zip(&a)
            .zip(&q_r)
            .zip(&b)
            .zip(&q_o)
            .zip(&c)
            .zip(&q_c)
            .map(|((((((q_l, a), q_r), b), q_o), c), q_c)| {
                -(*q_l * *a + *q_r * *b + *q_o * *c + *q_c)
            })
            .collect::<Vec<_>>();

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
            gate_product_left,
            gate_linear_output,
            gate_residuals,
            permutation_residuals,
            constraint_residuals,
        })
    }
}

pub fn prove_plonkish<T: Transcript>(
    instance: &PlonkishInstance,
    workers: usize,
    transcript: &mut T,
) -> PlonkishPiopResult<PlonkishPiopProof> {
    let witness = PlonkishWitness::from_instance(instance);
    prove_plonkish_with_witness(instance, &witness, workers, transcript)
}

pub fn prove_plonkish_with_witness<T: Transcript>(
    instance: &PlonkishInstance,
    witness: &PlonkishWitness,
    workers: usize,
    transcript: &mut T,
) -> PlonkishPiopResult<PlonkishPiopProof> {
    prove_plonkish_with_witness_and_pcs_params(
        instance,
        witness,
        workers,
        DistributedPcsParams::default(),
        transcript,
    )
}

pub fn prove_plonkish_with_witness_and_pcs_params<T: Transcript>(
    instance: &PlonkishInstance,
    witness: &PlonkishWitness,
    workers: usize,
    pcs_params: DistributedPcsParams,
    transcript: &mut T,
) -> PlonkishPiopResult<PlonkishPiopProof> {
    prove_plonkish_with_witness_and_pcs_hooks(
        instance,
        witness,
        workers,
        pcs_params,
        transcript,
        |evaluations, workers| {
            DistributedBrakedown::commit_detached(evaluations, workers)
                .map_err(|_| PlonkishPiopError::InvalidProof)
        },
        |evaluations, commitment, point, params, transcript| {
            DistributedBrakedown::open_compact_at_after_commitment_with_params(
                evaluations,
                commitment,
                point,
                params,
                transcript,
            )
            .map(PlonkishPcsOpening::Compact)
            .map_err(|_| PlonkishPiopError::InvalidProof)
        },
    )
}

pub fn prove_plonkish_with_pcs_params<T: Transcript>(
    instance: &PlonkishInstance,
    workers: usize,
    pcs_params: DistributedPcsParams,
    transcript: &mut T,
) -> PlonkishPiopResult<PlonkishPiopProof> {
    let witness = PlonkishWitness::from_instance(instance);
    prove_plonkish_with_witness_and_pcs_params(instance, &witness, workers, pcs_params, transcript)
}

pub fn prove_plonkish_with_pcs_hooks<T, C, O>(
    instance: &PlonkishInstance,
    workers: usize,
    pcs_params: DistributedPcsParams,
    transcript: &mut T,
    commit_constraint: C,
    open_constraint: O,
) -> PlonkishPiopResult<PlonkishPiopProof>
where
    T: Transcript,
    C: FnMut(&[FieldElement], usize) -> PlonkishPiopResult<DistributedCommitment>,
    O: FnMut(
        &[FieldElement],
        &DistributedCommitment,
        &[FieldElement],
        DistributedPcsParams,
        &mut T,
    ) -> PlonkishPiopResult<PlonkishPcsOpening>,
{
    let witness = PlonkishWitness::from_instance(instance);
    prove_plonkish_with_witness_and_pcs_hooks(
        instance,
        &witness,
        workers,
        pcs_params,
        transcript,
        commit_constraint,
        open_constraint,
    )
}

pub fn prove_plonkish_with_witness_and_pcs_hooks<T, C, O>(
    instance: &PlonkishInstance,
    witness: &PlonkishWitness,
    workers: usize,
    pcs_params: DistributedPcsParams,
    transcript: &mut T,
    mut commit_constraint: C,
    mut open_constraint: O,
) -> PlonkishPiopResult<PlonkishPiopProof>
where
    T: Transcript,
    C: FnMut(&[FieldElement], usize) -> PlonkishPiopResult<DistributedCommitment>,
    O: FnMut(
        &[FieldElement],
        &DistributedCommitment,
        &[FieldElement],
        DistributedPcsParams,
        &mut T,
    ) -> PlonkishPiopResult<PlonkishPcsOpening>,
{
    validate_plonkish_witness(instance, witness)?;
    prove_plonkish_core_with_pcs_hooks(
        instance,
        workers,
        pcs_params,
        transcript,
        &mut commit_constraint,
        &mut open_constraint,
    )
}

fn prove_plonkish_core_with_pcs_hooks<T, C, O>(
    instance: &PlonkishInstance,
    workers: usize,
    pcs_params: DistributedPcsParams,
    transcript: &mut T,
    mut commit_constraint: C,
    mut open_constraint: O,
) -> PlonkishPiopResult<PlonkishPiopProof>
where
    T: Transcript,
    C: FnMut(&[FieldElement], usize) -> PlonkishPiopResult<DistributedCommitment>,
    O: FnMut(
        &[FieldElement],
        &DistributedCommitment,
        &[FieldElement],
        DistributedPcsParams,
        &mut T,
    ) -> PlonkishPiopResult<PlonkishPcsOpening>,
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
    let gate_subclaim = prove_gate_subclaim(
        instance,
        &oracles,
        &oracle_commitments,
        pcs_params,
        transcript,
    )?;
    let gate_cubic = prove_gate_cubic(
        instance,
        &oracles,
        &oracle_commitments,
        pcs_params,
        transcript,
    )?;
    let permutation_accumulator = prove_permutation_accumulator(
        instance,
        &oracles,
        &oracle_commitments,
        pcs_params,
        transcript,
    )?;

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
    let gate_indices = challenge_gate_indices(instance, pcs_params, transcript)?;
    let permutation_indices = challenge_permutation_indices(instance, pcs_params, transcript)?;
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
    absorb_consistency_queries(transcript, &gate_queries, &permutation_queries);

    Ok(PlonkishPiopProof {
        oracle_commitments,
        gate_subclaim,
        gate_cubic,
        permutation_accumulator,
        constraint_commitment,
        constraint_opening,
        sumcheck,
        gate_queries,
        permutation_queries,
        workers,
    })
}

pub fn verify_plonkish<T: Transcript>(
    instance: &PlonkishInstance,
    proof: &PlonkishPiopProof,
    transcript: &mut T,
) -> PlonkishPiopResult<PlonkishMetrics> {
    verify_plonkish_with_pcs_params(instance, proof, DistributedPcsParams::default(), transcript)
}

pub fn verify_plonkish_with_pcs_params<T: Transcript>(
    instance: &PlonkishInstance,
    proof: &PlonkishPiopProof,
    pcs_params: DistributedPcsParams,
    transcript: &mut T,
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
        pcs_params,
        transcript,
    )?;
    verify_gate_cubic(
        instance,
        &proof.oracle_commitments,
        &proof.gate_cubic,
        pcs_params,
        transcript,
    )?;
    verify_permutation_accumulator(
        instance,
        &proof.oracle_commitments,
        &proof.permutation_accumulator,
        pcs_params,
        transcript,
    )?;
    DistributedBrakedown::absorb_distributed_commitment(&proof.constraint_commitment, transcript);
    let num_vars = log2_power_of_two(proof.constraint_commitment.original_len)
        .map_err(|_| PlonkishPiopError::InvalidShape)?;
    verify_zerocheck_rounds(num_vars, &proof.sumcheck, transcript)
        .map_err(|_| PlonkishPiopError::InvalidProof)?;
    if proof.constraint_opening.point() != proof.sumcheck.challenges.as_slice() {
        return Err(PlonkishPiopError::InvalidProof);
    }
    let expected_final =
        zerocheck_final_evaluation(&proof.sumcheck, proof.constraint_opening.claimed_value())
            .map_err(|_| PlonkishPiopError::InvalidProof)?;
    if expected_final != proof.sumcheck.final_evaluation {
        return Err(PlonkishPiopError::InvalidProof);
    }
    proof.constraint_opening.verify_after_commitment(
        &proof.constraint_commitment,
        pcs_params,
        transcript,
    )?;
    let gate_indices = challenge_gate_indices(instance, pcs_params, transcript)?;
    let permutation_indices = challenge_permutation_indices(instance, pcs_params, transcript)?;
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
    absorb_consistency_queries(transcript, &proof.gate_queries, &proof.permutation_queries);

    Ok(PlonkishMetrics {
        proof_bytes: proof_size_bytes(proof),
        communication_bytes: proof_communication_bytes(proof),
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
        gate_product_left: MerklePcs::commit(&oracles.gate_product_left)
            .map_err(|_| PlonkishPiopError::InvalidProof)?,
        gate_linear_output: MerklePcs::commit(&oracles.gate_linear_output)
            .map_err(|_| PlonkishPiopError::InvalidProof)?,
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
        || proof.oracle_commitments.gate_product_left.len != row_len
        || proof.oracle_commitments.gate_linear_output.len != row_len
        || proof.oracle_commitments.gate_residual.len != row_len
        || proof.oracle_commitments.permutation_residual.len != permutation_len
        || proof.constraint_commitment.original_len != constraint_len
    {
        return Err(PlonkishPiopError::InvalidShape);
    }
    Ok(())
}

fn prove_gate_subclaim<T: Transcript>(
    instance: &PlonkishInstance,
    oracles: &PlonkishOracles,
    commitments: &PlonkishOracleCommitments,
    pcs_params: DistributedPcsParams,
    transcript: &mut T,
) -> PlonkishPiopResult<PlonkishGateSubclaimProof> {
    let point = challenge_gate_subclaim_point(instance, transcript)?;
    let query_count = gate_subclaim_query_count(instance, pcs_params)?;
    let a = prove_sampled_gate_column_subclaim(b"a", &oracles.a, &point, query_count, transcript)?;
    let b = prove_sampled_gate_column_subclaim(b"b", &oracles.b, &point, query_count, transcript)?;
    let c = prove_sampled_gate_column_subclaim(b"c", &oracles.c, &point, query_count, transcript)?;
    let q_l =
        prove_sampled_gate_column_subclaim(b"q-l", &oracles.q_l, &point, query_count, transcript)?;
    let q_r =
        prove_sampled_gate_column_subclaim(b"q-r", &oracles.q_r, &point, query_count, transcript)?;
    let q_o =
        prove_sampled_gate_column_subclaim(b"q-o", &oracles.q_o, &point, query_count, transcript)?;
    let q_m =
        prove_sampled_gate_column_subclaim(b"q-m", &oracles.q_m, &point, query_count, transcript)?;
    let q_c =
        prove_sampled_gate_column_subclaim(b"q-c", &oracles.q_c, &point, query_count, transcript)?;
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
        gate_residual: prove_sampled_gate_column_subclaim(
            b"gate-residual",
            &oracles.gate_residuals,
            &point,
            query_count,
            transcript,
        )?,
    };
    verify_gate_subclaim_commitments(commitments, &proof)?;
    absorb_gate_subclaim_proof(transcript, &proof);
    Ok(proof)
}

fn verify_gate_subclaim<T: Transcript>(
    instance: &PlonkishInstance,
    commitments: &PlonkishOracleCommitments,
    proof: &PlonkishGateSubclaimProof,
    pcs_params: DistributedPcsParams,
    transcript: &mut T,
) -> PlonkishPiopResult<()> {
    let expected_point = challenge_gate_subclaim_point(instance, transcript)?;
    if proof.point != expected_point {
        return Err(PlonkishPiopError::InvalidProof);
    }
    let query_count = gate_subclaim_query_count(instance, pcs_params)?;
    verify_gate_subclaim_commitments(commitments, proof)?;
    for (label, commitment, column) in [
        (b"a".as_ref(), &commitments.a, &proof.a),
        (b"b".as_ref(), &commitments.b, &proof.b),
        (b"c".as_ref(), &commitments.c, &proof.c),
        (b"q-l".as_ref(), &commitments.q_l, &proof.q_l),
        (b"q-r".as_ref(), &commitments.q_r, &proof.q_r),
        (b"q-o".as_ref(), &commitments.q_o, &proof.q_o),
        (b"q-m".as_ref(), &commitments.q_m, &proof.q_m),
        (b"q-c".as_ref(), &commitments.q_c, &proof.q_c),
        (
            b"gate-residual".as_ref(),
            &commitments.gate_residual,
            &proof.gate_residual,
        ),
    ] {
        verify_sampled_gate_column_subclaim(
            label,
            commitment,
            &proof.point,
            column,
            query_count,
            transcript,
        )?;
    }
    if eval_gate_subclaim(
        &proof.a, &proof.b, &proof.c, &proof.q_l, &proof.q_r, &proof.q_o, &proof.q_m, &proof.q_c,
    ) != proof.virtual_gate_value
    {
        return Err(PlonkishPiopError::InvalidProof);
    }
    // This virtual gate polynomial is not equal to the MLE of the row residual
    // column away from Boolean rows. Row-level binding is checked by the final
    // sampled gate queries against the committed residual columns.
    absorb_gate_subclaim_proof(transcript, proof);
    Ok(())
}

fn prove_gate_cubic<T: Transcript>(
    instance: &PlonkishInstance,
    oracles: &PlonkishOracles,
    commitments: &PlonkishOracleCommitments,
    pcs_params: DistributedPcsParams,
    transcript: &mut T,
) -> PlonkishPiopResult<PlonkishGateCubicProof> {
    absorb_gate_cubic_statement(transcript, commitments);
    let left = MultilinearPolynomial::new(oracles.gate_product_left.clone())
        .map_err(|_| PlonkishPiopError::InvalidShape)?;
    let right = MultilinearPolynomial::new(oracles.b.clone())
        .map_err(|_| PlonkishPiopError::InvalidShape)?;
    let output = MultilinearPolynomial::new(oracles.gate_linear_output.clone())
        .map_err(|_| PlonkishPiopError::InvalidShape)?;
    let sumcheck = prove_cubic_zerocheck(&left, &right, &output, transcript)
        .map_err(|_| PlonkishPiopError::InvalidProof)?;
    let point = sumcheck.challenges.clone();
    let query_count = gate_subclaim_query_count(instance, pcs_params)?;
    let proof = PlonkishGateCubicProof {
        sumcheck,
        product_left: prove_sampled_gate_column_subclaim(
            b"gate-cubic-product-left",
            &oracles.gate_product_left,
            &point,
            query_count,
            transcript,
        )?,
        b: prove_sampled_gate_column_subclaim(
            b"gate-cubic-b",
            &oracles.b,
            &point,
            query_count,
            transcript,
        )?,
        linear_output: prove_sampled_gate_column_subclaim(
            b"gate-cubic-linear-output",
            &oracles.gate_linear_output,
            &point,
            query_count,
            transcript,
        )?,
    };
    ensure_gate_cubic_proof_commitments(&proof, commitments)?;
    let expected_final = cubic_zerocheck_final_evaluation(
        &proof.sumcheck,
        proof.product_left.folding.final_value,
        proof.b.folding.final_value,
        proof.linear_output.folding.final_value,
    )
    .map_err(|_| PlonkishPiopError::InvalidProof)?;
    if expected_final != proof.sumcheck.final_evaluation {
        return Err(PlonkishPiopError::InvalidProof);
    }
    absorb_gate_cubic_proof(transcript, &proof);
    Ok(proof)
}

fn verify_gate_cubic<T: Transcript>(
    instance: &PlonkishInstance,
    commitments: &PlonkishOracleCommitments,
    proof: &PlonkishGateCubicProof,
    pcs_params: DistributedPcsParams,
    transcript: &mut T,
) -> PlonkishPiopResult<()> {
    ensure_gate_cubic_proof_commitments(proof, commitments)?;
    absorb_gate_cubic_statement(transcript, commitments);
    let row_len = instance.row_count().max(1).next_power_of_two();
    let num_vars = log2_power_of_two(row_len).map_err(|_| PlonkishPiopError::InvalidShape)?;
    verify_cubic_zerocheck_rounds(num_vars, &proof.sumcheck, transcript)
        .map_err(|_| PlonkishPiopError::InvalidProof)?;
    let point = &proof.sumcheck.challenges;
    let query_count = gate_subclaim_query_count(instance, pcs_params)?;
    let product_left = verify_sampled_gate_column_subclaim(
        b"gate-cubic-product-left",
        &commitments.gate_product_left,
        point,
        &proof.product_left,
        query_count,
        transcript,
    )?;
    let b = verify_sampled_gate_column_subclaim(
        b"gate-cubic-b",
        &commitments.b,
        point,
        &proof.b,
        query_count,
        transcript,
    )?;
    let linear_output = verify_sampled_gate_column_subclaim(
        b"gate-cubic-linear-output",
        &commitments.gate_linear_output,
        point,
        &proof.linear_output,
        query_count,
        transcript,
    )?;
    let expected_final =
        cubic_zerocheck_final_evaluation(&proof.sumcheck, product_left, b, linear_output)
            .map_err(|_| PlonkishPiopError::InvalidProof)?;
    if expected_final != proof.sumcheck.final_evaluation {
        return Err(PlonkishPiopError::InvalidProof);
    }
    absorb_gate_cubic_proof(transcript, proof);
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn eval_gate_subclaim(
    a: &PlonkishSampledGateColumnSubclaim,
    b: &PlonkishSampledGateColumnSubclaim,
    c: &PlonkishSampledGateColumnSubclaim,
    q_l: &PlonkishSampledGateColumnSubclaim,
    q_r: &PlonkishSampledGateColumnSubclaim,
    q_o: &PlonkishSampledGateColumnSubclaim,
    q_m: &PlonkishSampledGateColumnSubclaim,
    q_c: &PlonkishSampledGateColumnSubclaim,
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

fn gate_subclaim_query_count(
    instance: &PlonkishInstance,
    pcs_params: DistributedPcsParams,
) -> PlonkishPiopResult<usize> {
    let row_len = instance.row_count().max(1).next_power_of_two();
    pcs_params
        .effective_query_count(row_len)
        .map_err(|_| PlonkishPiopError::InvalidShape)
}

fn accumulator_subclaim_query_count(
    instance: &PlonkishInstance,
    pcs_params: DistributedPcsParams,
) -> PlonkishPiopResult<usize> {
    let len = accumulator_trace_len(instance);
    pcs_params
        .effective_query_count(len)
        .map_err(|_| PlonkishPiopError::InvalidShape)
}

fn accumulator_shift_query_count(
    instance: &PlonkishInstance,
    pcs_params: DistributedPcsParams,
) -> PlonkishPiopResult<usize> {
    pcs_params
        .effective_query_count(instance.permutation_check_count())
        .map_err(|_| PlonkishPiopError::InvalidShape)
}

fn prove_sampled_gate_column_subclaim<T: Transcript>(
    label: &'static [u8],
    values: &[FieldElement],
    point: &[FieldElement],
    query_count: usize,
    transcript: &mut T,
) -> PlonkishPiopResult<PlonkishSampledGateColumnSubclaim> {
    transcript.absorb_domain(b"plonkish-sampled-gate-column-v1");
    transcript.absorb_public(b"sampled-gate-column-label", label);
    Ok(PlonkishSampledGateColumnSubclaim {
        folding: prove_sampled_mle_folding(values, point, query_count, transcript)
            .map_err(|_| PlonkishPiopError::InvalidProof)?,
    })
}

fn verify_sampled_gate_column_subclaim<T: Transcript>(
    label: &'static [u8],
    commitment: &Commitment,
    point: &[FieldElement],
    column: &PlonkishSampledGateColumnSubclaim,
    query_count: usize,
    transcript: &mut T,
) -> PlonkishPiopResult<FieldElement> {
    if column.folding.query_count != query_count {
        return Err(PlonkishPiopError::InvalidProof);
    }
    transcript.absorb_domain(b"plonkish-sampled-gate-column-v1");
    transcript.absorb_public(b"sampled-gate-column-label", label);
    verify_sampled_mle_folding(commitment, point, &column.folding, transcript)
        .map_err(|_| PlonkishPiopError::InvalidProof)
}

fn gate_subclaim_columns(
    proof: &PlonkishGateSubclaimProof,
) -> [(&'static [u8], &PlonkishSampledGateColumnSubclaim); 9] {
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

fn challenge_gate_subclaim_point<T: Transcript>(
    instance: &PlonkishInstance,
    transcript: &mut T,
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

fn ensure_gate_cubic_proof_commitments(
    proof: &PlonkishGateCubicProof,
    commitments: &PlonkishOracleCommitments,
) -> PlonkishPiopResult<()> {
    let expected = [
        (
            &proof.product_left.folding.input_commitment,
            &commitments.gate_product_left,
        ),
        (&proof.b.folding.input_commitment, &commitments.b),
        (
            &proof.linear_output.folding.input_commitment,
            &commitments.gate_linear_output,
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

fn absorb_gate_subclaim_proof<T: Transcript>(
    transcript: &mut T,
    proof: &PlonkishGateSubclaimProof,
) {
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

fn absorb_gate_cubic_statement<T: Transcript>(
    transcript: &mut T,
    commitments: &PlonkishOracleCommitments,
) {
    transcript.absorb_domain(b"plonkish-gate-cubic-statement-v1");
    absorb_merkle_commitment(
        transcript,
        b"gate-cubic-product-left",
        &commitments.gate_product_left,
    );
    absorb_merkle_commitment(transcript, b"gate-cubic-b", &commitments.b);
    absorb_merkle_commitment(
        transcript,
        b"gate-cubic-linear-output",
        &commitments.gate_linear_output,
    );
}

fn absorb_gate_cubic_proof<T: Transcript>(transcript: &mut T, proof: &PlonkishGateCubicProof) {
    transcript.absorb_domain(b"plonkish-gate-cubic-proof-v1");
    absorb_cubic_zerocheck_summary(transcript, b"gate-cubic", &proof.sumcheck);
    absorb_gate_column_subclaim(transcript, b"gate-cubic-product-left", &proof.product_left);
    absorb_gate_column_subclaim(transcript, b"gate-cubic-b", &proof.b);
    absorb_gate_column_subclaim(
        transcript,
        b"gate-cubic-linear-output",
        &proof.linear_output,
    );
}

fn absorb_cubic_zerocheck_summary<T: Transcript>(
    transcript: &mut T,
    label: &'static [u8],
    proof: &CubicZerocheckProof,
) {
    transcript.absorb_domain(b"plonkish-cubic-zerocheck-summary-v1");
    transcript.absorb_public(b"cubic-zerocheck-label", label);
    absorb_usize(transcript, b"cubic-zerocheck-rounds", proof.rounds.len());
    absorb_usize(transcript, b"cubic-zerocheck-eq-len", proof.eq_point.len());
    for (index, value) in proof.eq_point.iter().copied().enumerate() {
        absorb_usize(transcript, b"cubic-zerocheck-eq-index", index);
        absorb_field(transcript, b"cubic-zerocheck-eq-value", value);
    }
    absorb_field(
        transcript,
        b"cubic-zerocheck-claimed-sum",
        proof.claimed_sum,
    );
    absorb_field(
        transcript,
        b"cubic-zerocheck-final-eval",
        proof.final_evaluation,
    );
    absorb_usize(
        transcript,
        b"cubic-zerocheck-challenge-len",
        proof.challenges.len(),
    );
    for (index, value) in proof.challenges.iter().copied().enumerate() {
        absorb_usize(transcript, b"cubic-zerocheck-challenge-index", index);
        absorb_field(transcript, b"cubic-zerocheck-challenge-value", value);
    }
}

fn absorb_gate_column_subclaim<T: Transcript>(
    transcript: &mut T,
    label: &'static [u8],
    column: &PlonkishSampledGateColumnSubclaim,
) {
    transcript.absorb_domain(b"plonkish-sampled-gate-column-summary-v1");
    transcript.absorb_public(b"gate-column-label", label);
    absorb_usize(
        transcript,
        b"gate-column-input-len",
        column.folding.input_len,
    );
    absorb_usize(
        transcript,
        b"gate-column-query-count",
        column.folding.query_count,
    );
    absorb_merkle_commitment(
        transcript,
        b"gate-column-input",
        &column.folding.input_commitment,
    );
    absorb_field(
        transcript,
        b"gate-column-final-value",
        column.folding.final_value,
    );
    transcript.absorb_commitment(
        b"gate-column-sampled-state",
        &column.folding.transcript_state,
    );
}

fn prove_permutation_accumulator<T: Transcript>(
    instance: &PlonkishInstance,
    oracles: &PlonkishOracles,
    commitments: &PlonkishOracleCommitments,
    pcs_params: DistributedPcsParams,
    transcript: &mut T,
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
        pcs_params,
        beta,
        gamma,
        transcript,
    )?;

    let recurrence_indices = challenge_accumulator_indices(instance, pcs_params, transcript)?;
    let recurrence_queries = recurrence_indices
        .iter()
        .copied()
        .map(|index| {
            open_accumulator_query(
                instance,
                oracles,
                commitments,
                &numerator_trace,
                &denominator_trace,
                index,
            )
        })
        .collect::<PlonkishPiopResult<Vec<_>>>()?;
    for query in &recurrence_queries {
        absorb_accumulator_query(transcript, query);
    }

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

fn verify_permutation_accumulator<T: Transcript>(
    instance: &PlonkishInstance,
    commitments: &PlonkishOracleCommitments,
    proof: &PlonkishPermutationAccumulatorProof,
    pcs_params: DistributedPcsParams,
    transcript: &mut T,
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
        &proof.numerator_commitment,
        &proof.denominator_commitment,
        pcs_params,
        beta,
        gamma,
        &proof.random_subclaim,
        transcript,
    )?;

    let recurrence_indices = challenge_accumulator_indices(instance, pcs_params, transcript)?;
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
            AccumulatorQueryCommitments {
                oracle: commitments,
                public: &proof.random_subclaim.public_commitments,
                numerator: &proof.numerator_commitment,
                denominator: &proof.denominator_commitment,
            },
            beta,
            gamma,
            query,
        )?;
        absorb_accumulator_query(transcript, query);
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
fn prove_permutation_accumulator_subclaim<T: Transcript>(
    instance: &PlonkishInstance,
    commitments: &PlonkishOracleCommitments,
    numerator_commitment: &Commitment,
    denominator_commitment: &Commitment,
    numerator_trace: &[FieldElement],
    denominator_trace: &[FieldElement],
    pcs_params: DistributedPcsParams,
    beta: FieldElement,
    gamma: FieldElement,
    transcript: &mut T,
) -> PlonkishPiopResult<PlonkishPermutationAccumulatorSubclaimProof> {
    let vectors = permutation_accumulator_vectors(instance, numerator_trace, denominator_trace)?;
    let public_commitments = accumulator_public_commitments_from_vectors(&vectors)?;
    let numerator_next_commitment =
        MerklePcs::commit(&vectors.numerator_next).map_err(|_| PlonkishPiopError::InvalidProof)?;
    let denominator_next_commitment = MerklePcs::commit(&vectors.denominator_next)
        .map_err(|_| PlonkishPiopError::InvalidProof)?;
    let numerator_residual_values =
        numerator_recurrence_residual(&vectors, instance.permutation_check_count(), beta, gamma);
    let denominator_residual_values =
        denominator_recurrence_residual(&vectors, instance.permutation_check_count(), beta, gamma);
    if numerator_residual_values
        .iter()
        .any(|value| !value.is_zero())
        || denominator_residual_values
            .iter()
            .any(|value| !value.is_zero())
    {
        return Err(PlonkishPiopError::InvalidProof);
    }
    let numerator_residual_commitment = MerklePcs::commit(&numerator_residual_values)
        .map_err(|_| PlonkishPiopError::InvalidProof)?;
    let denominator_residual_commitment = MerklePcs::commit(&denominator_residual_values)
        .map_err(|_| PlonkishPiopError::InvalidProof)?;
    absorb_accumulator_subclaim_precommitments(
        transcript,
        &public_commitments,
        &numerator_next_commitment,
        &denominator_next_commitment,
        &numerator_residual_commitment,
        &denominator_residual_commitment,
    );
    let point = challenge_accumulator_subclaim_point(instance, transcript)?;
    let query_count = accumulator_subclaim_query_count(instance, pcs_params)?;
    let value = prove_sampled_gate_column_subclaim(
        b"accumulator-value",
        &vectors.value,
        &point,
        query_count,
        transcript,
    )?;
    let source_id = prove_sampled_gate_column_subclaim(
        b"accumulator-source-id",
        &vectors.source_id,
        &point,
        query_count,
        transcript,
    )?;
    let target_id = prove_sampled_gate_column_subclaim(
        b"accumulator-target-id",
        &vectors.target_id,
        &point,
        query_count,
        transcript,
    )?;
    let numerator_current = prove_sampled_gate_column_subclaim(
        b"accumulator-numerator-current",
        &vectors.numerator_current,
        &point,
        query_count,
        transcript,
    )?;
    let numerator_next = prove_sampled_gate_column_subclaim(
        b"accumulator-numerator-next",
        &vectors.numerator_next,
        &point,
        query_count,
        transcript,
    )?;
    let denominator_current = prove_sampled_gate_column_subclaim(
        b"accumulator-denominator-current",
        &vectors.denominator_current,
        &point,
        query_count,
        transcript,
    )?;
    let denominator_next = prove_sampled_gate_column_subclaim(
        b"accumulator-denominator-next",
        &vectors.denominator_next,
        &point,
        query_count,
        transcript,
    )?;
    let numerator_residual = prove_sampled_gate_column_subclaim(
        b"accumulator-numerator-residual",
        &numerator_residual_values,
        &point,
        query_count,
        transcript,
    )?;
    let denominator_residual = prove_sampled_gate_column_subclaim(
        b"accumulator-denominator-residual",
        &denominator_residual_values,
        &point,
        query_count,
        transcript,
    )?;
    if numerator_residual.folding.input_commitment != numerator_residual_commitment
        || denominator_residual.folding.input_commitment != denominator_residual_commitment
    {
        return Err(PlonkishPiopError::InvalidProof);
    }
    let numerator_recurrence = prove_accumulator_recurrence_sumcheck(
        ACCUMULATOR_NUMERATOR_RECURRENCE_LABELS,
        AccumulatorRecurrenceWitness {
            current: &vectors.numerator_current,
            value: &vectors.value,
            id: &vectors.source_id,
            active: &vectors.active,
            next: &vectors.numerator_next,
            residual: &numerator_residual_values,
        },
        AccumulatorRecurrenceCommitments {
            current: numerator_commitment,
            value: &public_commitments.value,
            id: &public_commitments.source_id,
            active: &public_commitments.active,
            next: &numerator_next_commitment,
            residual: &numerator_residual_commitment,
        },
        beta,
        gamma,
        query_count,
        transcript,
    )?;
    let denominator_recurrence = prove_accumulator_recurrence_sumcheck(
        ACCUMULATOR_DENOMINATOR_RECURRENCE_LABELS,
        AccumulatorRecurrenceWitness {
            current: &vectors.denominator_current,
            value: &vectors.value,
            id: &vectors.target_id,
            active: &vectors.active,
            next: &vectors.denominator_next,
            residual: &denominator_residual_values,
        },
        AccumulatorRecurrenceCommitments {
            current: denominator_commitment,
            value: &public_commitments.value,
            id: &public_commitments.target_id,
            active: &public_commitments.active,
            next: &denominator_next_commitment,
            residual: &denominator_residual_commitment,
        },
        beta,
        gamma,
        query_count,
        transcript,
    )?;
    let residual_indices =
        challenge_accumulator_residual_indices(instance, pcs_params, transcript)?;
    let residual_queries = prove_accumulator_residual_queries(
        &vectors,
        &numerator_residual_values,
        &denominator_residual_values,
        &residual_indices,
    )?;
    verify_accumulator_residual_queries(
        &public_commitments,
        numerator_commitment,
        denominator_commitment,
        &numerator_next_commitment,
        &denominator_next_commitment,
        &numerator_residual_commitment,
        &denominator_residual_commitment,
        beta,
        gamma,
        &residual_indices,
        &residual_queries,
        transcript,
    )?;
    let shift_indices = challenge_accumulator_shift_indices(instance, pcs_params, transcript)?;
    let numerator_shift_queries =
        prove_accumulator_shift_queries(numerator_trace, &vectors.numerator_next, &shift_indices)?;
    let denominator_shift_queries = prove_accumulator_shift_queries(
        denominator_trace,
        &vectors.denominator_next,
        &shift_indices,
    )?;
    verify_accumulator_shift_queries(
        numerator_commitment,
        &numerator_next_commitment,
        &shift_indices,
        &numerator_shift_queries,
        transcript,
        b"numerator",
    )?;
    verify_accumulator_shift_queries(
        denominator_commitment,
        &denominator_next_commitment,
        &shift_indices,
        &denominator_shift_queries,
        transcript,
        b"denominator",
    )?;
    let proof = PlonkishPermutationAccumulatorSubclaimProof {
        point: point.clone(),
        public_commitments: public_commitments.clone(),
        numerator_next_commitment,
        denominator_next_commitment,
        value,
        source_id,
        target_id,
        numerator_current,
        numerator_next,
        denominator_current,
        denominator_next,
        numerator_residual,
        denominator_residual,
        numerator_recurrence,
        denominator_recurrence,
        residual_queries,
        numerator_shift_queries,
        denominator_shift_queries,
    };
    ensure_flattened_value_commitment_matches_oracles(
        instance,
        commitments,
        &public_commitments.value,
    )?;
    if proof.value.folding.input_commitment != public_commitments.value
        || proof.source_id.folding.input_commitment != public_commitments.source_id
        || proof.target_id.folding.input_commitment != public_commitments.target_id
        || proof.numerator_current.folding.input_commitment != *numerator_commitment
        || proof.denominator_current.folding.input_commitment != *denominator_commitment
        || proof.numerator_next.folding.input_commitment != proof.numerator_next_commitment
        || proof.denominator_next.folding.input_commitment != proof.denominator_next_commitment
        || !proof.numerator_residual.folding.final_value.is_zero()
        || !proof.denominator_residual.folding.final_value.is_zero()
    {
        return Err(PlonkishPiopError::InvalidProof);
    }
    absorb_accumulator_subclaim_proof(transcript, &proof);
    Ok(proof)
}

#[allow(clippy::too_many_arguments)]
fn verify_permutation_accumulator_subclaim<T: Transcript>(
    instance: &PlonkishInstance,
    numerator_commitment: &Commitment,
    denominator_commitment: &Commitment,
    pcs_params: DistributedPcsParams,
    beta: FieldElement,
    gamma: FieldElement,
    proof: &PlonkishPermutationAccumulatorSubclaimProof,
    transcript: &mut T,
) -> PlonkishPiopResult<()> {
    let numerator_residual_commitment = proof.numerator_residual.folding.input_commitment.clone();
    let denominator_residual_commitment =
        proof.denominator_residual.folding.input_commitment.clone();
    absorb_accumulator_subclaim_precommitments(
        transcript,
        &proof.public_commitments,
        &proof.numerator_next_commitment,
        &proof.denominator_next_commitment,
        &numerator_residual_commitment,
        &denominator_residual_commitment,
    );
    let expected_point = challenge_accumulator_subclaim_point(instance, transcript)?;
    if proof.point != expected_point {
        return Err(PlonkishPiopError::InvalidProof);
    }
    let query_count = accumulator_subclaim_query_count(instance, pcs_params)?;
    let public_commitments = &proof.public_commitments;
    verify_accumulator_public_commitments(
        instance,
        accumulator_trace_len(instance),
        public_commitments,
    )?;
    for (label, commitment, column) in [
        (
            b"accumulator-value".as_ref(),
            &public_commitments.value,
            &proof.value,
        ),
        (
            b"accumulator-source-id".as_ref(),
            &public_commitments.source_id,
            &proof.source_id,
        ),
        (
            b"accumulator-target-id".as_ref(),
            &public_commitments.target_id,
            &proof.target_id,
        ),
        (
            b"accumulator-numerator-current".as_ref(),
            numerator_commitment,
            &proof.numerator_current,
        ),
        (
            b"accumulator-numerator-next".as_ref(),
            &proof.numerator_next_commitment,
            &proof.numerator_next,
        ),
        (
            b"accumulator-denominator-current".as_ref(),
            denominator_commitment,
            &proof.denominator_current,
        ),
        (
            b"accumulator-denominator-next".as_ref(),
            &proof.denominator_next_commitment,
            &proof.denominator_next,
        ),
    ] {
        verify_sampled_gate_column_subclaim(
            label,
            commitment,
            &proof.point,
            column,
            query_count,
            transcript,
        )?;
    }
    let numerator_residual = verify_sampled_gate_column_subclaim(
        b"accumulator-numerator-residual",
        &numerator_residual_commitment,
        &proof.point,
        &proof.numerator_residual,
        query_count,
        transcript,
    )?;
    let denominator_residual = verify_sampled_gate_column_subclaim(
        b"accumulator-denominator-residual",
        &denominator_residual_commitment,
        &proof.point,
        &proof.denominator_residual,
        query_count,
        transcript,
    )?;
    if !numerator_residual.is_zero() || !denominator_residual.is_zero() {
        return Err(PlonkishPiopError::InvalidProof);
    }
    verify_accumulator_recurrence_sumcheck(
        ACCUMULATOR_NUMERATOR_RECURRENCE_LABELS,
        AccumulatorRecurrenceCommitments {
            current: numerator_commitment,
            value: &public_commitments.value,
            id: &public_commitments.source_id,
            active: &public_commitments.active,
            next: &proof.numerator_next_commitment,
            residual: &numerator_residual_commitment,
        },
        beta,
        gamma,
        query_count,
        &proof.numerator_recurrence,
        transcript,
    )?;
    verify_accumulator_recurrence_sumcheck(
        ACCUMULATOR_DENOMINATOR_RECURRENCE_LABELS,
        AccumulatorRecurrenceCommitments {
            current: denominator_commitment,
            value: &public_commitments.value,
            id: &public_commitments.target_id,
            active: &public_commitments.active,
            next: &proof.denominator_next_commitment,
            residual: &denominator_residual_commitment,
        },
        beta,
        gamma,
        query_count,
        &proof.denominator_recurrence,
        transcript,
    )?;
    let residual_indices =
        challenge_accumulator_residual_indices(instance, pcs_params, transcript)?;
    verify_accumulator_residual_queries(
        public_commitments,
        numerator_commitment,
        denominator_commitment,
        &proof.numerator_next_commitment,
        &proof.denominator_next_commitment,
        &numerator_residual_commitment,
        &denominator_residual_commitment,
        beta,
        gamma,
        &residual_indices,
        &proof.residual_queries,
        transcript,
    )?;
    let shift_indices = challenge_accumulator_shift_indices(instance, pcs_params, transcript)?;
    verify_accumulator_shift_queries(
        numerator_commitment,
        &proof.numerator_next_commitment,
        &shift_indices,
        &proof.numerator_shift_queries,
        transcript,
        b"numerator",
    )?;
    verify_accumulator_shift_queries(
        denominator_commitment,
        &proof.denominator_next_commitment,
        &shift_indices,
        &proof.denominator_shift_queries,
        transcript,
        b"denominator",
    )?;
    absorb_accumulator_subclaim_proof(transcript, proof);
    Ok(())
}

fn permutation_accumulator_vectors(
    instance: &PlonkishInstance,
    numerator_trace: &[FieldElement],
    denominator_trace: &[FieldElement],
) -> PlonkishPiopResult<PlonkishPermutationAccumulatorVectors> {
    let len = accumulator_trace_len(instance);
    if numerator_trace.len() != len || denominator_trace.len() != len {
        return Err(PlonkishPiopError::InvalidShape);
    }
    let mut public = public_accumulator_vectors(instance, len)?;
    public.numerator_current = numerator_trace.to_vec();
    public.denominator_current = denominator_trace.to_vec();
    public.numerator_next =
        shifted_next_trace(instance.permutation_check_count(), numerator_trace)?;
    public.denominator_next =
        shifted_next_trace(instance.permutation_check_count(), denominator_trace)?;
    Ok(public)
}

fn public_accumulator_vectors(
    instance: &PlonkishInstance,
    len: usize,
) -> PlonkishPiopResult<PlonkishPermutationAccumulatorVectors> {
    if len == 0 || !len.is_power_of_two() {
        return Err(PlonkishPiopError::InvalidShape);
    }
    let cell_count = instance.permutation_check_count();
    let flat_values = flattened_cell_values(&instance.circuit);
    if flat_values.len() != cell_count || cell_count > len {
        return Err(PlonkishPiopError::InvalidShape);
    }
    let mut active = vec![FieldElement::ZERO; len];
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
        active[source] = FieldElement::ONE;
        value[source] = flat_values[source];
        source_id[source] = FieldElement::from(source);
        target_id[source] = FieldElement::from(target);
    }
    Ok(PlonkishPermutationAccumulatorVectors {
        active,
        value,
        source_id,
        target_id,
        numerator_current: vec![FieldElement::ZERO; len],
        numerator_next: vec![FieldElement::ZERO; len],
        denominator_current: vec![FieldElement::ZERO; len],
        denominator_next: vec![FieldElement::ZERO; len],
    })
}

fn accumulator_trace_len(instance: &PlonkishInstance) -> usize {
    (instance.permutation_check_count() + 1)
        .max(1)
        .next_power_of_two()
}

fn accumulator_public_commitments_from_vectors(
    public: &PlonkishPermutationAccumulatorVectors,
) -> PlonkishPiopResult<PlonkishPermutationAccumulatorPublicCommitments> {
    Ok(PlonkishPermutationAccumulatorPublicCommitments {
        active: MerklePcs::commit(&public.active).map_err(|_| PlonkishPiopError::InvalidProof)?,
        value: MerklePcs::commit(&public.value).map_err(|_| PlonkishPiopError::InvalidProof)?,
        source_id: MerklePcs::commit(&public.source_id)
            .map_err(|_| PlonkishPiopError::InvalidProof)?,
        target_id: MerklePcs::commit(&public.target_id)
            .map_err(|_| PlonkishPiopError::InvalidProof)?,
    })
}

fn verify_accumulator_public_commitments(
    instance: &PlonkishInstance,
    len: usize,
    commitments: &PlonkishPermutationAccumulatorPublicCommitments,
) -> PlonkishPiopResult<()> {
    if commitments.active.len != len
        || commitments.value.len != len
        || commitments.source_id.len != len
        || commitments.target_id.len != len
    {
        return Err(PlonkishPiopError::InvalidProof);
    }
    let cell_count = instance.permutation_check_count();
    if cell_count > len {
        return Err(PlonkishPiopError::InvalidShape);
    }
    let mut active = vec![FieldElement::ZERO; len];
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
        active[source] = FieldElement::ONE;
        source_id[source] = FieldElement::from(source);
        target_id[source] = FieldElement::from(target);
    }
    if MerklePcs::commit(&active).map_err(|_| PlonkishPiopError::InvalidProof)?
        != commitments.active
        || MerklePcs::commit(&source_id).map_err(|_| PlonkishPiopError::InvalidProof)?
            != commitments.source_id
        || MerklePcs::commit(&target_id).map_err(|_| PlonkishPiopError::InvalidProof)?
            != commitments.target_id
    {
        return Err(PlonkishPiopError::InvalidProof);
    }
    Ok(())
}

fn ensure_flattened_value_commitment_matches_oracles(
    instance: &PlonkishInstance,
    commitments: &PlonkishOracleCommitments,
    value_commitment: &Commitment,
) -> PlonkishPiopResult<()> {
    let len = accumulator_trace_len(instance);
    let public = public_accumulator_vectors(instance, len)?;
    if MerklePcs::commit(&public.value).map_err(|_| PlonkishPiopError::InvalidProof)?
        != *value_commitment
    {
        return Err(PlonkishPiopError::InvalidProof);
    }
    let row_len = instance.row_count().max(1).next_power_of_two();
    let mut a = vec![FieldElement::ZERO; row_len];
    let mut b = vec![FieldElement::ZERO; row_len];
    let mut c = vec![FieldElement::ZERO; row_len];
    for (cell, value) in public
        .value
        .iter()
        .copied()
        .take(instance.permutation_check_count())
        .enumerate()
    {
        let row = cell / 3;
        match cell % 3 {
            0 => a[row] = value,
            1 => b[row] = value,
            2 => c[row] = value,
            _ => return Err(PlonkishPiopError::InvalidProof),
        }
    }
    if MerklePcs::commit(&a).map_err(|_| PlonkishPiopError::InvalidProof)? != commitments.a
        || MerklePcs::commit(&b).map_err(|_| PlonkishPiopError::InvalidProof)? != commitments.b
        || MerklePcs::commit(&c).map_err(|_| PlonkishPiopError::InvalidProof)? != commitments.c
    {
        return Err(PlonkishPiopError::InvalidProof);
    }
    Ok(())
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
    cell_count: usize,
    beta: FieldElement,
    gamma: FieldElement,
) -> Vec<FieldElement> {
    vectors
        .numerator_next
        .iter()
        .zip(&vectors.numerator_current)
        .zip(&vectors.value)
        .zip(&vectors.source_id)
        .enumerate()
        .map(|(index, (((next, current), value), source))| {
            if index < cell_count {
                *next - *current * (*value + beta * *source + gamma)
            } else {
                FieldElement::ZERO
            }
        })
        .collect()
}

fn denominator_recurrence_residual(
    vectors: &PlonkishPermutationAccumulatorVectors,
    cell_count: usize,
    beta: FieldElement,
    gamma: FieldElement,
) -> Vec<FieldElement> {
    vectors
        .denominator_next
        .iter()
        .zip(&vectors.denominator_current)
        .zip(&vectors.value)
        .zip(&vectors.target_id)
        .enumerate()
        .map(|(index, (((next, current), value), target))| {
            if index < cell_count {
                *next - *current * (*value + beta * *target + gamma)
            } else {
                FieldElement::ZERO
            }
        })
        .collect()
}

#[derive(Copy, Clone)]
struct AccumulatorRecurrenceLabels {
    proof: &'static [u8],
    current: &'static [u8],
    value: &'static [u8],
    id: &'static [u8],
    active: &'static [u8],
    next: &'static [u8],
    residual: &'static [u8],
}

const ACCUMULATOR_NUMERATOR_RECURRENCE_LABELS: AccumulatorRecurrenceLabels =
    AccumulatorRecurrenceLabels {
        proof: b"numerator",
        current: b"accumulator-recurrence-numerator-current",
        value: b"accumulator-recurrence-numerator-value",
        id: b"accumulator-recurrence-source-id",
        active: b"accumulator-recurrence-numerator-active",
        next: b"accumulator-recurrence-numerator-next",
        residual: b"accumulator-recurrence-numerator-residual",
    };

const ACCUMULATOR_DENOMINATOR_RECURRENCE_LABELS: AccumulatorRecurrenceLabels =
    AccumulatorRecurrenceLabels {
        proof: b"denominator",
        current: b"accumulator-recurrence-denominator-current",
        value: b"accumulator-recurrence-denominator-value",
        id: b"accumulator-recurrence-target-id",
        active: b"accumulator-recurrence-denominator-active",
        next: b"accumulator-recurrence-denominator-next",
        residual: b"accumulator-recurrence-denominator-residual",
    };

#[derive(Copy, Clone)]
struct AccumulatorRecurrenceWitness<'a> {
    current: &'a [FieldElement],
    value: &'a [FieldElement],
    id: &'a [FieldElement],
    active: &'a [FieldElement],
    next: &'a [FieldElement],
    residual: &'a [FieldElement],
}

#[derive(Copy, Clone)]
struct AccumulatorRecurrenceCommitments<'a> {
    current: &'a Commitment,
    value: &'a Commitment,
    id: &'a Commitment,
    active: &'a Commitment,
    next: &'a Commitment,
    residual: &'a Commitment,
}

#[allow(clippy::too_many_arguments)]
fn prove_accumulator_recurrence_sumcheck<T: Transcript>(
    labels: AccumulatorRecurrenceLabels,
    witness: AccumulatorRecurrenceWitness<'_>,
    commitments: AccumulatorRecurrenceCommitments<'_>,
    beta: FieldElement,
    gamma: FieldElement,
    query_count: usize,
    transcript: &mut T,
) -> PlonkishPiopResult<PlonkishAccumulatorRecurrenceProof> {
    validate_accumulator_recurrence_shape(witness)?;
    ensure_accumulator_recurrence_commitments(witness, commitments)?;
    let factor = accumulator_recurrence_factor(witness, beta, gamma);
    let output = accumulator_recurrence_output(witness);
    if witness
        .current
        .iter()
        .zip(&factor)
        .zip(&output)
        .any(|((current, factor), output)| *current * *factor != *output)
    {
        return Err(PlonkishPiopError::InvalidProof);
    }

    absorb_accumulator_recurrence_statement(transcript, labels, commitments, beta, gamma);
    let current_poly = MultilinearPolynomial::new(witness.current.to_vec())
        .map_err(|_| PlonkishPiopError::InvalidShape)?;
    let factor_poly =
        MultilinearPolynomial::new(factor).map_err(|_| PlonkishPiopError::InvalidShape)?;
    let output_poly =
        MultilinearPolynomial::new(output).map_err(|_| PlonkishPiopError::InvalidShape)?;
    let sumcheck = prove_cubic_zerocheck(&current_poly, &factor_poly, &output_poly, transcript)
        .map_err(|_| PlonkishPiopError::InvalidProof)?;
    let point = sumcheck.challenges.clone();
    let proof = PlonkishAccumulatorRecurrenceProof {
        sumcheck,
        current: prove_sampled_gate_column_subclaim(
            labels.current,
            witness.current,
            &point,
            query_count,
            transcript,
        )?,
        value: prove_sampled_gate_column_subclaim(
            labels.value,
            witness.value,
            &point,
            query_count,
            transcript,
        )?,
        id: prove_sampled_gate_column_subclaim(
            labels.id,
            witness.id,
            &point,
            query_count,
            transcript,
        )?,
        active: prove_sampled_gate_column_subclaim(
            labels.active,
            witness.active,
            &point,
            query_count,
            transcript,
        )?,
        next: prove_sampled_gate_column_subclaim(
            labels.next,
            witness.next,
            &point,
            query_count,
            transcript,
        )?,
        residual: prove_sampled_gate_column_subclaim(
            labels.residual,
            witness.residual,
            &point,
            query_count,
            transcript,
        )?,
    };
    ensure_accumulator_recurrence_proof_commitments(&proof, commitments)?;
    Ok(proof)
}

fn verify_accumulator_recurrence_sumcheck<T: Transcript>(
    labels: AccumulatorRecurrenceLabels,
    commitments: AccumulatorRecurrenceCommitments<'_>,
    beta: FieldElement,
    gamma: FieldElement,
    query_count: usize,
    proof: &PlonkishAccumulatorRecurrenceProof,
    transcript: &mut T,
) -> PlonkishPiopResult<()> {
    let len = validate_accumulator_recurrence_commitment_shape(commitments)?;
    let num_vars = log2_power_of_two(len).map_err(|_| PlonkishPiopError::InvalidShape)?;
    absorb_accumulator_recurrence_statement(transcript, labels, commitments, beta, gamma);
    verify_cubic_zerocheck_rounds(num_vars, &proof.sumcheck, transcript)
        .map_err(|_| PlonkishPiopError::InvalidProof)?;
    let point = &proof.sumcheck.challenges;
    let current = verify_sampled_gate_column_subclaim(
        labels.current,
        commitments.current,
        point,
        &proof.current,
        query_count,
        transcript,
    )?;
    let value = verify_sampled_gate_column_subclaim(
        labels.value,
        commitments.value,
        point,
        &proof.value,
        query_count,
        transcript,
    )?;
    let id = verify_sampled_gate_column_subclaim(
        labels.id,
        commitments.id,
        point,
        &proof.id,
        query_count,
        transcript,
    )?;
    let active = verify_sampled_gate_column_subclaim(
        labels.active,
        commitments.active,
        point,
        &proof.active,
        query_count,
        transcript,
    )?;
    let next = verify_sampled_gate_column_subclaim(
        labels.next,
        commitments.next,
        point,
        &proof.next,
        query_count,
        transcript,
    )?;
    let residual = verify_sampled_gate_column_subclaim(
        labels.residual,
        commitments.residual,
        point,
        &proof.residual,
        query_count,
        transcript,
    )?;
    let factor = value + beta * id + gamma * active;
    let output = next - residual;
    let expected_final = cubic_zerocheck_final_evaluation(&proof.sumcheck, current, factor, output)
        .map_err(|_| PlonkishPiopError::InvalidProof)?;
    if expected_final != proof.sumcheck.final_evaluation {
        return Err(PlonkishPiopError::InvalidProof);
    }
    Ok(())
}

fn validate_accumulator_recurrence_shape(
    witness: AccumulatorRecurrenceWitness<'_>,
) -> PlonkishPiopResult<()> {
    let len = witness.current.len();
    if len == 0
        || !len.is_power_of_two()
        || witness.value.len() != len
        || witness.id.len() != len
        || witness.active.len() != len
        || witness.next.len() != len
        || witness.residual.len() != len
    {
        return Err(PlonkishPiopError::InvalidShape);
    }
    Ok(())
}

fn validate_accumulator_recurrence_commitment_shape(
    commitments: AccumulatorRecurrenceCommitments<'_>,
) -> PlonkishPiopResult<usize> {
    let len = commitments.current.len;
    if len == 0
        || !len.is_power_of_two()
        || commitments.value.len != len
        || commitments.id.len != len
        || commitments.active.len != len
        || commitments.next.len != len
        || commitments.residual.len != len
    {
        return Err(PlonkishPiopError::InvalidShape);
    }
    Ok(len)
}

fn ensure_accumulator_recurrence_commitments(
    witness: AccumulatorRecurrenceWitness<'_>,
    commitments: AccumulatorRecurrenceCommitments<'_>,
) -> PlonkishPiopResult<()> {
    let committed_current =
        MerklePcs::commit(witness.current).map_err(|_| PlonkishPiopError::InvalidProof)?;
    let committed_value =
        MerklePcs::commit(witness.value).map_err(|_| PlonkishPiopError::InvalidProof)?;
    let committed_id =
        MerklePcs::commit(witness.id).map_err(|_| PlonkishPiopError::InvalidProof)?;
    let committed_active =
        MerklePcs::commit(witness.active).map_err(|_| PlonkishPiopError::InvalidProof)?;
    let committed_next =
        MerklePcs::commit(witness.next).map_err(|_| PlonkishPiopError::InvalidProof)?;
    let committed_residual =
        MerklePcs::commit(witness.residual).map_err(|_| PlonkishPiopError::InvalidProof)?;
    if committed_current != *commitments.current
        || committed_value != *commitments.value
        || committed_id != *commitments.id
        || committed_active != *commitments.active
        || committed_next != *commitments.next
        || committed_residual != *commitments.residual
    {
        return Err(PlonkishPiopError::InvalidProof);
    }
    Ok(())
}

fn ensure_accumulator_recurrence_proof_commitments(
    proof: &PlonkishAccumulatorRecurrenceProof,
    commitments: AccumulatorRecurrenceCommitments<'_>,
) -> PlonkishPiopResult<()> {
    if proof.current.folding.input_commitment != *commitments.current
        || proof.value.folding.input_commitment != *commitments.value
        || proof.id.folding.input_commitment != *commitments.id
        || proof.active.folding.input_commitment != *commitments.active
        || proof.next.folding.input_commitment != *commitments.next
        || proof.residual.folding.input_commitment != *commitments.residual
    {
        return Err(PlonkishPiopError::InvalidProof);
    }
    Ok(())
}

fn accumulator_recurrence_factor(
    witness: AccumulatorRecurrenceWitness<'_>,
    beta: FieldElement,
    gamma: FieldElement,
) -> Vec<FieldElement> {
    witness
        .value
        .iter()
        .zip(witness.id)
        .zip(witness.active)
        .map(|((value, id), active)| *value + beta * *id + gamma * *active)
        .collect()
}

fn accumulator_recurrence_output(witness: AccumulatorRecurrenceWitness<'_>) -> Vec<FieldElement> {
    witness
        .next
        .iter()
        .zip(witness.residual)
        .map(|(next, residual)| *next - *residual)
        .collect()
}

fn absorb_accumulator_recurrence_statement<T: Transcript>(
    transcript: &mut T,
    labels: AccumulatorRecurrenceLabels,
    commitments: AccumulatorRecurrenceCommitments<'_>,
    beta: FieldElement,
    gamma: FieldElement,
) {
    transcript.absorb_domain(b"plonkish-accumulator-recurrence-sumcheck-v1");
    transcript.absorb_public(b"accumulator-recurrence-label", labels.proof);
    absorb_field(transcript, b"accumulator-recurrence-beta", beta);
    absorb_field(transcript, b"accumulator-recurrence-gamma", gamma);
    absorb_merkle_commitment(
        transcript,
        b"accumulator-recurrence-current",
        commitments.current,
    );
    absorb_merkle_commitment(
        transcript,
        b"accumulator-recurrence-value",
        commitments.value,
    );
    absorb_merkle_commitment(transcript, b"accumulator-recurrence-id", commitments.id);
    absorb_merkle_commitment(
        transcript,
        b"accumulator-recurrence-active",
        commitments.active,
    );
    absorb_merkle_commitment(transcript, b"accumulator-recurrence-next", commitments.next);
    absorb_merkle_commitment(
        transcript,
        b"accumulator-recurrence-residual",
        commitments.residual,
    );
}

fn challenge_accumulator_subclaim_point<T: Transcript>(
    instance: &PlonkishInstance,
    transcript: &mut T,
) -> PlonkishPiopResult<Vec<FieldElement>> {
    let len = accumulator_trace_len(instance);
    let vars = log2_power_of_two(len).map_err(|_| PlonkishPiopError::InvalidShape)?;
    transcript.absorb_domain(b"plonkish-permutation-accumulator-random-subclaim-v1");
    absorb_usize(
        transcript,
        b"permutation-cells",
        instance.permutation_check_count(),
    );
    absorb_usize(transcript, b"accumulator-recurrence-len", len);
    Ok((0..vars)
        .map(|index| {
            absorb_usize(transcript, b"accumulator-subclaim-var", index);
            challenge_field(transcript, b"accumulator-subclaim-point")
        })
        .collect())
}

fn challenge_accumulator_shift_indices<T: Transcript>(
    instance: &PlonkishInstance,
    pcs_params: DistributedPcsParams,
    transcript: &mut T,
) -> PlonkishPiopResult<Vec<usize>> {
    let cell_count = instance.permutation_check_count();
    let query_count = accumulator_shift_query_count(instance, pcs_params)?;
    transcript.absorb_domain(b"plonkish-accumulator-shift-consistency-sampled-v1");
    absorb_usize(transcript, b"permutation-cells", cell_count);
    absorb_usize(transcript, b"requested-query-count", pcs_params.query_count);
    absorb_usize(transcript, b"query-count", query_count);
    Ok(transcript.challenge_indices(b"plonkish-accumulator-shift-query", query_count, cell_count))
}

fn challenge_accumulator_residual_indices<T: Transcript>(
    instance: &PlonkishInstance,
    pcs_params: DistributedPcsParams,
    transcript: &mut T,
) -> PlonkishPiopResult<Vec<usize>> {
    let cell_count = instance.permutation_check_count();
    let query_count = accumulator_shift_query_count(instance, pcs_params)?;
    transcript.absorb_domain(b"plonkish-accumulator-residual-consistency-sampled-v1");
    absorb_usize(transcript, b"permutation-cells", cell_count);
    absorb_usize(transcript, b"requested-query-count", pcs_params.query_count);
    absorb_usize(transcript, b"query-count", query_count);
    Ok(transcript.challenge_indices(
        b"plonkish-accumulator-residual-query",
        query_count,
        cell_count,
    ))
}

fn prove_accumulator_residual_queries(
    vectors: &PlonkishPermutationAccumulatorVectors,
    numerator_residual: &[FieldElement],
    denominator_residual: &[FieldElement],
    indices: &[usize],
) -> PlonkishPiopResult<Vec<PlonkishAccumulatorResidualQuery>> {
    indices
        .iter()
        .copied()
        .map(|index| {
            Ok(PlonkishAccumulatorResidualQuery {
                index,
                value: MerklePcs::open(&vectors.value, index)
                    .map_err(|_| PlonkishPiopError::InvalidProof)?,
                source_id: MerklePcs::open(&vectors.source_id, index)
                    .map_err(|_| PlonkishPiopError::InvalidProof)?,
                target_id: MerklePcs::open(&vectors.target_id, index)
                    .map_err(|_| PlonkishPiopError::InvalidProof)?,
                numerator_current: MerklePcs::open(&vectors.numerator_current, index)
                    .map_err(|_| PlonkishPiopError::InvalidProof)?,
                numerator_next: MerklePcs::open(&vectors.numerator_next, index)
                    .map_err(|_| PlonkishPiopError::InvalidProof)?,
                denominator_current: MerklePcs::open(&vectors.denominator_current, index)
                    .map_err(|_| PlonkishPiopError::InvalidProof)?,
                denominator_next: MerklePcs::open(&vectors.denominator_next, index)
                    .map_err(|_| PlonkishPiopError::InvalidProof)?,
                numerator_residual: MerklePcs::open(numerator_residual, index)
                    .map_err(|_| PlonkishPiopError::InvalidProof)?,
                denominator_residual: MerklePcs::open(denominator_residual, index)
                    .map_err(|_| PlonkishPiopError::InvalidProof)?,
            })
        })
        .collect()
}

#[allow(clippy::too_many_arguments)]
fn verify_accumulator_residual_queries<T: Transcript>(
    public_commitments: &PlonkishPermutationAccumulatorPublicCommitments,
    numerator_commitment: &Commitment,
    denominator_commitment: &Commitment,
    numerator_next_commitment: &Commitment,
    denominator_next_commitment: &Commitment,
    numerator_residual_commitment: &Commitment,
    denominator_residual_commitment: &Commitment,
    beta: FieldElement,
    gamma: FieldElement,
    expected_indices: &[usize],
    queries: &[PlonkishAccumulatorResidualQuery],
    transcript: &mut T,
) -> PlonkishPiopResult<()> {
    if expected_indices.len() != queries.len() {
        return Err(PlonkishPiopError::InvalidProof);
    }
    for (expected, query) in expected_indices.iter().copied().zip(queries) {
        if query.index != expected
            || query.value.index != expected
            || query.source_id.index != expected
            || query.target_id.index != expected
            || query.numerator_current.index != expected
            || query.numerator_next.index != expected
            || query.denominator_current.index != expected
            || query.denominator_next.index != expected
            || query.numerator_residual.index != expected
            || query.denominator_residual.index != expected
        {
            return Err(PlonkishPiopError::InvalidProof);
        }
        MerklePcs::verify(&public_commitments.value, &query.value)
            .map_err(|_| PlonkishPiopError::InvalidProof)?;
        MerklePcs::verify(&public_commitments.source_id, &query.source_id)
            .map_err(|_| PlonkishPiopError::InvalidProof)?;
        MerklePcs::verify(&public_commitments.target_id, &query.target_id)
            .map_err(|_| PlonkishPiopError::InvalidProof)?;
        MerklePcs::verify(numerator_commitment, &query.numerator_current)
            .map_err(|_| PlonkishPiopError::InvalidProof)?;
        MerklePcs::verify(numerator_next_commitment, &query.numerator_next)
            .map_err(|_| PlonkishPiopError::InvalidProof)?;
        MerklePcs::verify(denominator_commitment, &query.denominator_current)
            .map_err(|_| PlonkishPiopError::InvalidProof)?;
        MerklePcs::verify(denominator_next_commitment, &query.denominator_next)
            .map_err(|_| PlonkishPiopError::InvalidProof)?;
        MerklePcs::verify(numerator_residual_commitment, &query.numerator_residual)
            .map_err(|_| PlonkishPiopError::InvalidProof)?;
        MerklePcs::verify(denominator_residual_commitment, &query.denominator_residual)
            .map_err(|_| PlonkishPiopError::InvalidProof)?;

        let expected_numerator = query.numerator_next.value
            - query.numerator_current.value
                * (query.value.value + beta * query.source_id.value + gamma);
        let expected_denominator = query.denominator_next.value
            - query.denominator_current.value
                * (query.value.value + beta * query.target_id.value + gamma);
        if query.numerator_residual.value != expected_numerator
            || query.denominator_residual.value != expected_denominator
        {
            return Err(PlonkishPiopError::InvalidProof);
        }
        absorb_accumulator_residual_query(transcript, query);
    }
    Ok(())
}

fn prove_accumulator_shift_queries(
    current_trace: &[FieldElement],
    shifted_trace: &[FieldElement],
    indices: &[usize],
) -> PlonkishPiopResult<Vec<PlonkishAccumulatorShiftQuery>> {
    if current_trace.len() != shifted_trace.len() {
        return Err(PlonkishPiopError::InvalidShape);
    }
    indices
        .iter()
        .copied()
        .map(|index| {
            if index + 1 >= current_trace.len() {
                return Err(PlonkishPiopError::InvalidShape);
            }
            Ok(PlonkishAccumulatorShiftQuery {
                index,
                current_at_next: MerklePcs::open(current_trace, index + 1)
                    .map_err(|_| PlonkishPiopError::InvalidProof)?,
                shifted_at_index: MerklePcs::open(shifted_trace, index)
                    .map_err(|_| PlonkishPiopError::InvalidProof)?,
            })
        })
        .collect()
}

fn verify_accumulator_shift_queries<T: Transcript>(
    current_commitment: &Commitment,
    shifted_commitment: &Commitment,
    expected_indices: &[usize],
    queries: &[PlonkishAccumulatorShiftQuery],
    transcript: &mut T,
    label: &'static [u8],
) -> PlonkishPiopResult<()> {
    if expected_indices.len() != queries.len() {
        return Err(PlonkishPiopError::InvalidProof);
    }
    for (expected, query) in expected_indices.iter().copied().zip(queries) {
        if query.index != expected
            || query.current_at_next.index != expected + 1
            || query.shifted_at_index.index != expected
            || query.current_at_next.value != query.shifted_at_index.value
        {
            return Err(PlonkishPiopError::InvalidProof);
        }
        MerklePcs::verify(current_commitment, &query.current_at_next)
            .map_err(|_| PlonkishPiopError::InvalidProof)?;
        MerklePcs::verify(shifted_commitment, &query.shifted_at_index)
            .map_err(|_| PlonkishPiopError::InvalidProof)?;
        absorb_accumulator_shift_query(transcript, label, query);
    }
    Ok(())
}

fn absorb_accumulator_subclaim_proof<T: Transcript>(
    transcript: &mut T,
    proof: &PlonkishPermutationAccumulatorSubclaimProof,
) {
    transcript.absorb_domain(b"plonkish-permutation-accumulator-subclaim-proof-v1");
    absorb_usize(
        transcript,
        b"accumulator-subclaim-point-len",
        proof.point.len(),
    );
    for (index, coordinate) in proof.point.iter().copied().enumerate() {
        absorb_usize(transcript, b"accumulator-subclaim-point-index", index);
        absorb_field(transcript, b"accumulator-subclaim-point", coordinate);
    }
    absorb_accumulator_subclaim_precommitments(
        transcript,
        &proof.public_commitments,
        &proof.numerator_next_commitment,
        &proof.denominator_next_commitment,
        &proof.numerator_residual.folding.input_commitment,
        &proof.denominator_residual.folding.input_commitment,
    );
    for (label, column) in accumulator_subclaim_columns(proof) {
        absorb_accumulator_column_subclaim(transcript, label, column);
    }
    absorb_accumulator_recurrence_proof_summary(
        transcript,
        ACCUMULATOR_NUMERATOR_RECURRENCE_LABELS.proof,
        &proof.numerator_recurrence,
    );
    absorb_accumulator_recurrence_proof_summary(
        transcript,
        ACCUMULATOR_DENOMINATOR_RECURRENCE_LABELS.proof,
        &proof.denominator_recurrence,
    );
    for query in &proof.residual_queries {
        absorb_accumulator_residual_query(transcript, query);
    }
    for query in &proof.numerator_shift_queries {
        absorb_accumulator_shift_query(transcript, b"numerator", query);
    }
    for query in &proof.denominator_shift_queries {
        absorb_accumulator_shift_query(transcript, b"denominator", query);
    }
}

fn absorb_accumulator_subclaim_precommitments<T: Transcript>(
    transcript: &mut T,
    public: &PlonkishPermutationAccumulatorPublicCommitments,
    numerator_next: &Commitment,
    denominator_next: &Commitment,
    numerator_residual: &Commitment,
    denominator_residual: &Commitment,
) {
    transcript.absorb_domain(b"plonkish-accumulator-subclaim-precommitments-v3");
    absorb_merkle_commitment(transcript, b"public-active", &public.active);
    absorb_merkle_commitment(transcript, b"public-value", &public.value);
    absorb_merkle_commitment(transcript, b"public-source-id", &public.source_id);
    absorb_merkle_commitment(transcript, b"public-target-id", &public.target_id);
    absorb_merkle_commitment(transcript, b"numerator-next", numerator_next);
    absorb_merkle_commitment(transcript, b"denominator-next", denominator_next);
    absorb_merkle_commitment(transcript, b"numerator-residual", numerator_residual);
    absorb_merkle_commitment(transcript, b"denominator-residual", denominator_residual);
}

fn absorb_accumulator_recurrence_proof_summary<T: Transcript>(
    transcript: &mut T,
    label: &'static [u8],
    proof: &PlonkishAccumulatorRecurrenceProof,
) {
    transcript.absorb_domain(b"plonkish-accumulator-recurrence-proof-summary-v1");
    transcript.absorb_public(b"accumulator-recurrence-summary-label", label);
    absorb_usize(
        transcript,
        b"accumulator-recurrence-rounds",
        proof.sumcheck.rounds.len(),
    );
    absorb_field(
        transcript,
        b"accumulator-recurrence-claimed-sum",
        proof.sumcheck.claimed_sum,
    );
    absorb_field(
        transcript,
        b"accumulator-recurrence-final-eval",
        proof.sumcheck.final_evaluation,
    );
    absorb_accumulator_column_subclaim(transcript, b"current", &proof.current);
    absorb_accumulator_column_subclaim(transcript, b"value", &proof.value);
    absorb_accumulator_column_subclaim(transcript, b"id", &proof.id);
    absorb_accumulator_column_subclaim(transcript, b"active", &proof.active);
    absorb_accumulator_column_subclaim(transcript, b"next", &proof.next);
    absorb_accumulator_column_subclaim(transcript, b"residual", &proof.residual);
}

fn accumulator_subclaim_columns(
    proof: &PlonkishPermutationAccumulatorSubclaimProof,
) -> [(&'static [u8], &PlonkishSampledGateColumnSubclaim); 9] {
    [
        (b"value".as_ref(), &proof.value),
        (b"source-id".as_ref(), &proof.source_id),
        (b"target-id".as_ref(), &proof.target_id),
        (b"numerator-current".as_ref(), &proof.numerator_current),
        (b"numerator-next".as_ref(), &proof.numerator_next),
        (b"denominator-current".as_ref(), &proof.denominator_current),
        (b"denominator-next".as_ref(), &proof.denominator_next),
        (b"numerator-residual".as_ref(), &proof.numerator_residual),
        (
            b"denominator-residual".as_ref(),
            &proof.denominator_residual,
        ),
    ]
}

fn absorb_accumulator_column_subclaim<T: Transcript>(
    transcript: &mut T,
    label: &'static [u8],
    column: &PlonkishSampledGateColumnSubclaim,
) {
    transcript.absorb_domain(b"plonkish-accumulator-column-subclaim-v1");
    transcript.absorb_public(b"accumulator-column-label", label);
    absorb_usize(
        transcript,
        b"accumulator-column-input-len",
        column.folding.input_len,
    );
    absorb_usize(
        transcript,
        b"accumulator-column-query-count",
        column.folding.query_count,
    );
    absorb_merkle_commitment(
        transcript,
        b"accumulator-column-input",
        &column.folding.input_commitment,
    );
    absorb_field(
        transcript,
        b"accumulator-column-final-value",
        column.folding.final_value,
    );
    transcript.absorb_commitment(
        b"accumulator-column-sampled-state",
        &column.folding.transcript_state,
    );
}

fn absorb_accumulator_query<T: Transcript>(
    transcript: &mut T,
    query: &PlonkishPermutationAccumulatorQuery,
) {
    transcript.absorb_domain(b"plonkish-permutation-accumulator-query-v1");
    absorb_usize(
        transcript,
        b"permutation-accumulator-query-index",
        query.index,
    );
    absorb_opening_summary(transcript, b"accumulator-query-value", &query.value);
    absorb_opening_summary(
        transcript,
        b"accumulator-query-public-value",
        &query.public_value,
    );
    absorb_opening_summary(transcript, b"accumulator-query-source-id", &query.source_id);
    absorb_opening_summary(transcript, b"accumulator-query-target-id", &query.target_id);
    absorb_opening_summary(
        transcript,
        b"accumulator-query-numerator-current",
        &query.numerator_current,
    );
    absorb_opening_summary(
        transcript,
        b"accumulator-query-numerator-next",
        &query.numerator_next,
    );
    absorb_opening_summary(
        transcript,
        b"accumulator-query-denominator-current",
        &query.denominator_current,
    );
    absorb_opening_summary(
        transcript,
        b"accumulator-query-denominator-next",
        &query.denominator_next,
    );
}

fn absorb_accumulator_residual_query<T: Transcript>(
    transcript: &mut T,
    query: &PlonkishAccumulatorResidualQuery,
) {
    transcript.absorb_domain(b"plonkish-accumulator-residual-query-v1");
    absorb_usize(transcript, b"accumulator-residual-index", query.index);
    absorb_opening_summary(transcript, b"accumulator-residual-value", &query.value);
    absorb_opening_summary(
        transcript,
        b"accumulator-residual-source-id",
        &query.source_id,
    );
    absorb_opening_summary(
        transcript,
        b"accumulator-residual-target-id",
        &query.target_id,
    );
    absorb_opening_summary(
        transcript,
        b"accumulator-residual-numerator-current",
        &query.numerator_current,
    );
    absorb_opening_summary(
        transcript,
        b"accumulator-residual-numerator-next",
        &query.numerator_next,
    );
    absorb_opening_summary(
        transcript,
        b"accumulator-residual-denominator-current",
        &query.denominator_current,
    );
    absorb_opening_summary(
        transcript,
        b"accumulator-residual-denominator-next",
        &query.denominator_next,
    );
    absorb_opening_summary(
        transcript,
        b"accumulator-residual-numerator",
        &query.numerator_residual,
    );
    absorb_opening_summary(
        transcript,
        b"accumulator-residual-denominator",
        &query.denominator_residual,
    );
}

fn absorb_accumulator_shift_query<T: Transcript>(
    transcript: &mut T,
    label: &'static [u8],
    query: &PlonkishAccumulatorShiftQuery,
) {
    transcript.absorb_domain(b"plonkish-accumulator-shift-query-v1");
    transcript.absorb_public(b"accumulator-shift-label", label);
    absorb_usize(transcript, b"accumulator-shift-index", query.index);
    absorb_opening_summary(
        transcript,
        b"accumulator-current-at-next",
        &query.current_at_next,
    );
    absorb_opening_summary(
        transcript,
        b"accumulator-shifted-at-index",
        &query.shifted_at_index,
    );
}

fn open_accumulator_query(
    instance: &PlonkishInstance,
    oracles: &PlonkishOracles,
    commitments: &PlonkishOracleCommitments,
    numerator_trace: &[FieldElement],
    denominator_trace: &[FieldElement],
    index: usize,
) -> PlonkishPiopResult<PlonkishPermutationAccumulatorQuery> {
    let public = public_accumulator_vectors(instance, accumulator_trace_len(instance))?;
    Ok(PlonkishPermutationAccumulatorQuery {
        index,
        value: open_cell(oracles, commitments, index)?,
        public_value: MerklePcs::open(&public.value, index)
            .map_err(|_| PlonkishPiopError::InvalidProof)?,
        source_id: MerklePcs::open(&public.source_id, index)
            .map_err(|_| PlonkishPiopError::InvalidProof)?,
        target_id: MerklePcs::open(&public.target_id, index)
            .map_err(|_| PlonkishPiopError::InvalidProof)?,
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

struct AccumulatorQueryCommitments<'a> {
    oracle: &'a PlonkishOracleCommitments,
    public: &'a PlonkishPermutationAccumulatorPublicCommitments,
    numerator: &'a Commitment,
    denominator: &'a Commitment,
}

fn verify_accumulator_query(
    instance: &PlonkishInstance,
    commitments: AccumulatorQueryCommitments<'_>,
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
    verify_cell(commitments.oracle, query.index, &query.value)?;
    verify_merkle_opening(&commitments.public.value, &query.public_value, query.index)?;
    verify_merkle_opening(&commitments.public.source_id, &query.source_id, query.index)?;
    verify_merkle_opening(&commitments.public.target_id, &query.target_id, query.index)?;
    verify_merkle_opening(commitments.numerator, &query.numerator_current, query.index)?;
    verify_merkle_opening(
        commitments.numerator,
        &query.numerator_next,
        query.index + 1,
    )?;
    verify_merkle_opening(
        commitments.denominator,
        &query.denominator_current,
        query.index,
    )?;
    verify_merkle_opening(
        commitments.denominator,
        &query.denominator_next,
        query.index + 1,
    )?;
    if query.public_value.value != query.value.value
        || query.source_id.value != FieldElement::from(query.index)
        || query.target_id.value != FieldElement::from(target)
    {
        return Err(PlonkishPiopError::InvalidProof);
    }

    let factors = hyperplonk_permutation_products(
        &[query.value.value],
        &[query.source_id.value],
        &[query.target_id.value],
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
        || row >= commitments.q_l.len
        || row >= commitments.q_r.len
        || row >= commitments.q_o.len
        || row >= commitments.q_m.len
        || row >= commitments.q_c.len
        || row >= commitments.gate_product_left.len
        || row >= commitments.gate_linear_output.len
        || row >= commitments.gate_residual.len
    {
        return Err(PlonkishPiopError::InvalidShape);
    }
    Ok(PlonkishGateQuery {
        row,
        a: MerklePcs::open(&oracles.a, row).map_err(|_| PlonkishPiopError::InvalidProof)?,
        b: MerklePcs::open(&oracles.b, row).map_err(|_| PlonkishPiopError::InvalidProof)?,
        c: MerklePcs::open(&oracles.c, row).map_err(|_| PlonkishPiopError::InvalidProof)?,
        q_l: MerklePcs::open(&oracles.q_l, row).map_err(|_| PlonkishPiopError::InvalidProof)?,
        q_r: MerklePcs::open(&oracles.q_r, row).map_err(|_| PlonkishPiopError::InvalidProof)?,
        q_o: MerklePcs::open(&oracles.q_o, row).map_err(|_| PlonkishPiopError::InvalidProof)?,
        q_m: MerklePcs::open(&oracles.q_m, row).map_err(|_| PlonkishPiopError::InvalidProof)?,
        q_c: MerklePcs::open(&oracles.q_c, row).map_err(|_| PlonkishPiopError::InvalidProof)?,
        gate_product_left: MerklePcs::open(&oracles.gate_product_left, row)
            .map_err(|_| PlonkishPiopError::InvalidProof)?,
        gate_linear_output: MerklePcs::open(&oracles.gate_linear_output, row)
            .map_err(|_| PlonkishPiopError::InvalidProof)?,
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
    verify_merkle_opening(&commitments.q_l, &query.q_l, query.row)?;
    verify_merkle_opening(&commitments.q_r, &query.q_r, query.row)?;
    verify_merkle_opening(&commitments.q_o, &query.q_o, query.row)?;
    verify_merkle_opening(&commitments.q_m, &query.q_m, query.row)?;
    verify_merkle_opening(&commitments.q_c, &query.q_c, query.row)?;
    verify_merkle_opening(
        &commitments.gate_product_left,
        &query.gate_product_left,
        query.row,
    )?;
    verify_merkle_opening(
        &commitments.gate_linear_output,
        &query.gate_linear_output,
        query.row,
    )?;
    verify_merkle_opening(&commitments.gate_residual, &query.gate_residual, query.row)?;
    let committed_residual =
        DistributedBrakedown::verify_index(constraint_commitment, &query.constraint_residual)
            .map_err(|_| PlonkishPiopError::InvalidProof)?;
    if query.constraint_residual.global_index != query.row {
        return Err(PlonkishPiopError::InvalidProof);
    }
    if query.q_l.value != row.q_l
        || query.q_r.value != row.q_r
        || query.q_o.value != row.q_o
        || query.q_m.value != row.q_m
        || query.q_c.value != row.q_c
    {
        return Err(PlonkishPiopError::InvalidProof);
    }
    let expected_product_left = query.q_m.value * query.a.value;
    let expected_linear_output = -(query.q_l.value * query.a.value
        + query.q_r.value * query.b.value
        + query.q_o.value * query.c.value
        + query.q_c.value);
    let expected = query.gate_product_left.value * query.b.value - query.gate_linear_output.value;
    if expected != query.gate_residual.value || committed_residual != query.gate_residual.value {
        return Err(PlonkishPiopError::InvalidProof);
    }
    if expected_product_left != query.gate_product_left.value
        || expected_linear_output != query.gate_linear_output.value
    {
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
        + commitment_size_bytes(&proof.oracle_commitments.gate_product_left)
        + commitment_size_bytes(&proof.oracle_commitments.gate_linear_output)
        + commitment_size_bytes(&proof.oracle_commitments.gate_residual)
        + commitment_size_bytes(&proof.oracle_commitments.permutation_residual)
        + gate_subclaim_size(&proof.gate_subclaim)
        + gate_cubic_size(&proof.gate_cubic)
        + permutation_accumulator_size(&proof.permutation_accumulator)
        + distributed_commitment_size_bytes(&proof.constraint_commitment)
        + proof.constraint_opening.proof_size_bytes()
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

pub fn proof_communication_bytes(proof: &PlonkishPiopProof) -> usize {
    proof.constraint_opening.communication_bytes()
        + proof
            .gate_queries
            .iter()
            .map(gate_query_communication_bytes)
            .sum::<usize>()
        + proof
            .permutation_queries
            .iter()
            .map(permutation_query_communication_bytes)
            .sum::<usize>()
}

fn gate_query_size(query: &PlonkishGateQuery) -> usize {
    8 + opening_proof_size_bytes(&query.a)
        + opening_proof_size_bytes(&query.b)
        + opening_proof_size_bytes(&query.c)
        + opening_proof_size_bytes(&query.q_l)
        + opening_proof_size_bytes(&query.q_r)
        + opening_proof_size_bytes(&query.q_o)
        + opening_proof_size_bytes(&query.q_m)
        + opening_proof_size_bytes(&query.q_c)
        + opening_proof_size_bytes(&query.gate_product_left)
        + opening_proof_size_bytes(&query.gate_linear_output)
        + opening_proof_size_bytes(&query.gate_residual)
        + distributed_index_opening_size_bytes(&query.constraint_residual)
}

fn gate_query_communication_bytes(query: &PlonkishGateQuery) -> usize {
    distributed_index_communication_bytes(&query.constraint_residual)
}

fn permutation_query_size(query: &PlonkishPermutationQuery) -> usize {
    16 + opening_proof_size_bytes(&query.source_value)
        + opening_proof_size_bytes(&query.target_value)
        + opening_proof_size_bytes(&query.permutation_residual)
        + distributed_index_opening_size_bytes(&query.constraint_residual)
}

fn permutation_query_communication_bytes(query: &PlonkishPermutationQuery) -> usize {
    distributed_index_communication_bytes(&query.constraint_residual)
}

fn permutation_accumulator_size(proof: &PlonkishPermutationAccumulatorProof) -> usize {
    2 * 8
        + commitment_size_bytes(&proof.numerator_commitment)
        + commitment_size_bytes(&proof.denominator_commitment)
        + opening_proof_size_bytes(&proof.numerator_first)
        + opening_proof_size_bytes(&proof.numerator_last)
        + opening_proof_size_bytes(&proof.denominator_first)
        + opening_proof_size_bytes(&proof.denominator_last)
        + accumulator_subclaim_size(&proof.random_subclaim)
        + vec_len_prefix()
        + proof
            .recurrence_queries
            .iter()
            .map(accumulator_query_size)
            .sum::<usize>()
}

fn accumulator_query_size(query: &PlonkishPermutationAccumulatorQuery) -> usize {
    8 + opening_proof_size_bytes(&query.value)
        + opening_proof_size_bytes(&query.public_value)
        + opening_proof_size_bytes(&query.source_id)
        + opening_proof_size_bytes(&query.target_id)
        + opening_proof_size_bytes(&query.numerator_current)
        + opening_proof_size_bytes(&query.numerator_next)
        + opening_proof_size_bytes(&query.denominator_current)
        + opening_proof_size_bytes(&query.denominator_next)
}

fn accumulator_subclaim_size(proof: &PlonkishPermutationAccumulatorSubclaimProof) -> usize {
    field_vec_size(&proof.point)
        + accumulator_public_commitments_size(&proof.public_commitments)
        + commitment_size_bytes(&proof.numerator_next_commitment)
        + commitment_size_bytes(&proof.denominator_next_commitment)
        + accumulator_subclaim_columns(proof)
            .iter()
            .map(|(_, column)| sampled_gate_column_subclaim_size(column))
            .sum::<usize>()
        + accumulator_recurrence_proof_size(&proof.numerator_recurrence)
        + accumulator_recurrence_proof_size(&proof.denominator_recurrence)
        + vec_len_prefix()
        + proof
            .residual_queries
            .iter()
            .map(accumulator_residual_query_size)
            .sum::<usize>()
        + vec_len_prefix()
        + proof
            .numerator_shift_queries
            .iter()
            .map(accumulator_shift_query_size)
            .sum::<usize>()
        + vec_len_prefix()
        + proof
            .denominator_shift_queries
            .iter()
            .map(accumulator_shift_query_size)
            .sum::<usize>()
}

fn accumulator_public_commitments_size(
    commitments: &PlonkishPermutationAccumulatorPublicCommitments,
) -> usize {
    commitment_size_bytes(&commitments.active)
        + commitment_size_bytes(&commitments.value)
        + commitment_size_bytes(&commitments.source_id)
        + commitment_size_bytes(&commitments.target_id)
}

fn gate_subclaim_size(proof: &PlonkishGateSubclaimProof) -> usize {
    field_vec_size(&proof.point)
        + 8
        + gate_subclaim_columns(proof)
            .iter()
            .map(|(_, column)| sampled_gate_column_subclaim_size(column))
            .sum::<usize>()
}

fn gate_cubic_size(proof: &PlonkishGateCubicProof) -> usize {
    cubic_zerocheck_proof_size_bytes(&proof.sumcheck)
        + sampled_gate_column_subclaim_size(&proof.product_left)
        + sampled_gate_column_subclaim_size(&proof.b)
        + sampled_gate_column_subclaim_size(&proof.linear_output)
}

fn sampled_gate_column_subclaim_size(column: &PlonkishSampledGateColumnSubclaim) -> usize {
    sampled_mle_folding_proof_size_bytes(&column.folding)
}

fn accumulator_recurrence_proof_size(proof: &PlonkishAccumulatorRecurrenceProof) -> usize {
    cubic_zerocheck_proof_size_bytes(&proof.sumcheck)
        + sampled_gate_column_subclaim_size(&proof.current)
        + sampled_gate_column_subclaim_size(&proof.value)
        + sampled_gate_column_subclaim_size(&proof.id)
        + sampled_gate_column_subclaim_size(&proof.active)
        + sampled_gate_column_subclaim_size(&proof.next)
        + sampled_gate_column_subclaim_size(&proof.residual)
}

fn accumulator_shift_query_size(query: &PlonkishAccumulatorShiftQuery) -> usize {
    8 + opening_proof_size_bytes(&query.current_at_next)
        + opening_proof_size_bytes(&query.shifted_at_index)
}

fn accumulator_residual_query_size(query: &PlonkishAccumulatorResidualQuery) -> usize {
    8 + opening_proof_size_bytes(&query.value)
        + opening_proof_size_bytes(&query.source_id)
        + opening_proof_size_bytes(&query.target_id)
        + opening_proof_size_bytes(&query.numerator_current)
        + opening_proof_size_bytes(&query.numerator_next)
        + opening_proof_size_bytes(&query.denominator_current)
        + opening_proof_size_bytes(&query.denominator_next)
        + opening_proof_size_bytes(&query.numerator_residual)
        + opening_proof_size_bytes(&query.denominator_residual)
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

fn field_vec_size(values: &[FieldElement]) -> usize {
    vec_len_prefix() + values.len() * 8
}

fn vec_len_prefix() -> usize {
    8
}

fn absorb_circuit_statement<T: Transcript>(
    instance: &PlonkishInstance,
    workers: usize,
    transcript: &mut T,
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

fn absorb_oracle_commitments<T: Transcript>(
    commitments: &PlonkishOracleCommitments,
    transcript: &mut T,
) {
    absorb_merkle_commitment(transcript, b"a", &commitments.a);
    absorb_merkle_commitment(transcript, b"b", &commitments.b);
    absorb_merkle_commitment(transcript, b"c", &commitments.c);
    absorb_merkle_commitment(transcript, b"q-l", &commitments.q_l);
    absorb_merkle_commitment(transcript, b"q-r", &commitments.q_r);
    absorb_merkle_commitment(transcript, b"q-o", &commitments.q_o);
    absorb_merkle_commitment(transcript, b"q-m", &commitments.q_m);
    absorb_merkle_commitment(transcript, b"q-c", &commitments.q_c);
    absorb_merkle_commitment(
        transcript,
        b"gate-product-left",
        &commitments.gate_product_left,
    );
    absorb_merkle_commitment(
        transcript,
        b"gate-linear-output",
        &commitments.gate_linear_output,
    );
    absorb_merkle_commitment(transcript, b"gate-residual", &commitments.gate_residual);
    absorb_merkle_commitment(
        transcript,
        b"permutation-residual",
        &commitments.permutation_residual,
    );
}

fn absorb_merkle_commitment<T: Transcript>(
    transcript: &mut T,
    label: &'static [u8],
    commitment: &Commitment,
) {
    absorb_usize(transcript, label, commitment.len);
    transcript.absorb_commitment(label, &commitment.root);
}

fn absorb_opening_summary<T: Transcript>(
    transcript: &mut T,
    label: &'static [u8],
    opening: &OpeningProof,
) {
    transcript.absorb_domain(b"plonkish-merkle-opening-summary-v1");
    transcript.absorb_public(b"opening-label", label);
    absorb_usize(transcript, b"opening-index", opening.index);
    absorb_field(transcript, b"opening-value", opening.value);
    absorb_usize(transcript, b"opening-path-len", opening.path.len());
    for (level, (sibling, sibling_is_right)) in opening.path.iter().enumerate() {
        absorb_usize(transcript, b"opening-path-level", level);
        transcript.absorb_public(b"opening-sibling-side", &[*sibling_is_right as u8]);
        transcript.absorb_commitment(b"opening-sibling", sibling);
    }
}

fn absorb_distributed_index_opening_summary<T: Transcript>(
    transcript: &mut T,
    label: &'static [u8],
    opening: &DistributedIndexOpening,
) {
    transcript.absorb_domain(b"plonkish-distributed-index-opening-summary-v1");
    transcript.absorb_public(b"distributed-index-label", label);
    absorb_usize(
        transcript,
        b"distributed-index-global",
        opening.global_index,
    );
    absorb_usize(transcript, b"distributed-index-worker", opening.worker_id);
    absorb_usize(transcript, b"distributed-index-local", opening.local_index);
    absorb_opening_summary(transcript, b"distributed-index-proof", &opening.proof);
}

fn absorb_gate_query<T: Transcript>(transcript: &mut T, query: &PlonkishGateQuery) {
    transcript.absorb_domain(b"plonkish-gate-consistency-query-opening-v1");
    absorb_usize(transcript, b"gate-query-row", query.row);
    absorb_opening_summary(transcript, b"gate-query-a", &query.a);
    absorb_opening_summary(transcript, b"gate-query-b", &query.b);
    absorb_opening_summary(transcript, b"gate-query-c", &query.c);
    absorb_opening_summary(transcript, b"gate-query-q-l", &query.q_l);
    absorb_opening_summary(transcript, b"gate-query-q-r", &query.q_r);
    absorb_opening_summary(transcript, b"gate-query-q-o", &query.q_o);
    absorb_opening_summary(transcript, b"gate-query-q-m", &query.q_m);
    absorb_opening_summary(transcript, b"gate-query-q-c", &query.q_c);
    absorb_opening_summary(
        transcript,
        b"gate-query-product-left",
        &query.gate_product_left,
    );
    absorb_opening_summary(
        transcript,
        b"gate-query-linear-output",
        &query.gate_linear_output,
    );
    absorb_opening_summary(transcript, b"gate-query-residual", &query.gate_residual);
    absorb_distributed_index_opening_summary(
        transcript,
        b"gate-query-constraint-residual",
        &query.constraint_residual,
    );
}

fn absorb_permutation_query<T: Transcript>(transcript: &mut T, query: &PlonkishPermutationQuery) {
    transcript.absorb_domain(b"plonkish-permutation-consistency-query-opening-v1");
    absorb_usize(transcript, b"permutation-query-source", query.source);
    absorb_usize(transcript, b"permutation-query-target", query.target);
    absorb_opening_summary(
        transcript,
        b"permutation-query-source-value",
        &query.source_value,
    );
    absorb_opening_summary(
        transcript,
        b"permutation-query-target-value",
        &query.target_value,
    );
    absorb_opening_summary(
        transcript,
        b"permutation-query-residual",
        &query.permutation_residual,
    );
    absorb_distributed_index_opening_summary(
        transcript,
        b"permutation-query-constraint-residual",
        &query.constraint_residual,
    );
}

fn absorb_consistency_queries<T: Transcript>(
    transcript: &mut T,
    gate_queries: &[PlonkishGateQuery],
    permutation_queries: &[PlonkishPermutationQuery],
) {
    transcript.absorb_domain(b"plonkish-final-consistency-query-openings-v1");
    absorb_usize(transcript, b"gate-query-count", gate_queries.len());
    for query in gate_queries {
        absorb_gate_query(transcript, query);
    }
    absorb_usize(
        transcript,
        b"permutation-query-count",
        permutation_queries.len(),
    );
    for query in permutation_queries {
        absorb_permutation_query(transcript, query);
    }
}

fn absorb_accumulator_boundaries<T: Transcript>(
    transcript: &mut T,
    numerator_first: &OpeningProof,
    numerator_last: &OpeningProof,
    denominator_first: &OpeningProof,
    denominator_last: &OpeningProof,
) {
    transcript.absorb_domain(b"plonkish-accumulator-boundary-openings-v2");
    absorb_opening_summary(transcript, b"permutation-numerator-first", numerator_first);
    absorb_opening_summary(transcript, b"permutation-numerator-last", numerator_last);
    absorb_opening_summary(
        transcript,
        b"permutation-denominator-first",
        denominator_first,
    );
    absorb_opening_summary(
        transcript,
        b"permutation-denominator-last",
        denominator_last,
    );
}

fn challenge_accumulator_indices<T: Transcript>(
    instance: &PlonkishInstance,
    pcs_params: DistributedPcsParams,
    transcript: &mut T,
) -> PlonkishPiopResult<Vec<usize>> {
    let len = instance.permutation_check_count();
    let query_count = consistency_query_count(pcs_params, len)?;
    transcript.absorb_domain(b"plonkish-permutation-accumulator-sampled-v1");
    absorb_usize(transcript, b"permutation-cells", len);
    absorb_usize(transcript, b"requested-query-count", pcs_params.query_count);
    absorb_usize(transcript, b"query-count", query_count);
    Ok(transcript.challenge_indices(b"plonkish-permutation-accumulator-query", query_count, len))
}

fn challenge_gate_indices<T: Transcript>(
    instance: &PlonkishInstance,
    pcs_params: DistributedPcsParams,
    transcript: &mut T,
) -> PlonkishPiopResult<Vec<usize>> {
    let rows = instance.row_count();
    let query_count = consistency_query_count(pcs_params, rows)?;
    transcript.absorb_domain(b"plonkish-gate-consistency-sampled-v1");
    absorb_usize(transcript, b"rows", rows);
    absorb_usize(transcript, b"requested-query-count", pcs_params.query_count);
    absorb_usize(transcript, b"query-count", query_count);
    Ok(transcript.challenge_indices(b"plonkish-gate-consistency-query", query_count, rows))
}

fn challenge_permutation_indices<T: Transcript>(
    instance: &PlonkishInstance,
    pcs_params: DistributedPcsParams,
    transcript: &mut T,
) -> PlonkishPiopResult<Vec<usize>> {
    let len = instance.permutation_check_count();
    let query_count = consistency_query_count(pcs_params, len)?;
    transcript.absorb_domain(b"plonkish-permutation-consistency-sampled-v1");
    absorb_usize(transcript, b"permutation-cells", len);
    absorb_usize(transcript, b"requested-query-count", pcs_params.query_count);
    absorb_usize(transcript, b"query-count", query_count);
    Ok(transcript.challenge_indices(b"plonkish-permutation-consistency-query", query_count, len))
}

fn consistency_query_count(
    pcs_params: DistributedPcsParams,
    domain_len: usize,
) -> PlonkishPiopResult<usize> {
    pcs_params
        .effective_query_count(domain_len)
        .map_err(|_| PlonkishPiopError::InvalidShape)
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

fn challenge_field<T: Transcript>(transcript: &mut T, label: &[u8]) -> FieldElement {
    transcript.challenge_field::<FieldElement>(label)
}

fn absorb_field<T: Transcript>(transcript: &mut T, label: &[u8], value: FieldElement) {
    transcript.absorb_field(label, value);
}

fn absorb_usize<T: Transcript>(transcript: &mut T, label: &[u8], value: usize) {
    transcript.absorb_public(label, &(value as u64).to_le_bytes());
}

#[cfg(test)]
mod tests {
    use super::*;
    use pq_transcript::HashTranscript;

    #[test]
    fn unified_piop_trait_drives_plonkish_route() {
        let instance = sample_plonkish_instance(4).expect("sample");
        let witness = PlonkishWitness::from_instance(&instance);
        let pcs_params = DistributedPcsParams::new(2);
        let mut prover_transcript = HashTranscript::new(b"plonkish-piop-trait");
        let proof = PlonkishPiop::prove_interactive(
            &instance,
            &witness,
            2,
            pcs_params,
            &mut prover_transcript,
        )
        .expect("trait proof");

        let mut verifier_transcript = HashTranscript::new(b"plonkish-piop-trait");
        let metrics = PlonkishPiop::verify_interactive(
            &instance,
            &proof,
            pcs_params,
            &mut verifier_transcript,
        )
        .expect("trait verify");
        assert_eq!(metrics.rows, instance.row_count());
        assert!(metrics.proof_bytes > 0);
    }

    #[test]
    fn plonkish_piop_trait_rejects_mismatched_witness() {
        let instance = sample_plonkish_instance(4).expect("sample");
        let mut witness = PlonkishWitness::from_instance(&instance);
        witness.rows_mut()[0].a += FieldElement::ONE;
        let mut transcript = HashTranscript::new(b"plonkish-bad-witness");

        let result = PlonkishPiop::prove_interactive(
            &instance,
            &witness,
            2,
            DistributedPcsParams::new(2),
            &mut transcript,
        );

        assert_eq!(result, Err(PlonkishPiopError::Unsatisfied));
    }

    #[test]
    fn plonkish_piop_trait_rejects_wrong_witness_shape() {
        let instance = sample_plonkish_instance(4).expect("sample");
        let witness = PlonkishWitness::new(vec![]);
        let mut transcript = HashTranscript::new(b"plonkish-bad-witness-shape");

        let result = PlonkishPiop::prove_interactive(
            &instance,
            &witness,
            2,
            DistributedPcsParams::new(2),
            &mut transcript,
        );

        assert_eq!(result, Err(PlonkishPiopError::InvalidShape));
    }

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
        assert!(matches!(
            proof.constraint_opening,
            PlonkishPcsOpening::Compact(_)
        ));
    }

    #[test]
    fn plonkish_hook_path_can_still_produce_full_pcs_opening() {
        let instance = sample_plonkish_instance(4).expect("sample");
        let pcs_params = DistributedPcsParams::new(2);
        let mut prover_transcript = HashTranscript::new(b"plonkish-full-opening-hook");
        let proof = prove_plonkish_with_pcs_hooks(
            &instance,
            2,
            pcs_params,
            &mut prover_transcript,
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
                .map(PlonkishPcsOpening::Full)
                .map_err(|_| PlonkishPiopError::InvalidProof)
            },
        )
        .expect("proof");

        assert!(matches!(
            proof.constraint_opening,
            PlonkishPcsOpening::Full(_)
        ));
        let mut verifier_transcript = HashTranscript::new(b"plonkish-full-opening-hook");
        verify_plonkish_with_pcs_params(&instance, &proof, pcs_params, &mut verifier_transcript)
            .expect("verify");
    }

    #[test]
    fn compact_constraint_opening_tampering_fails_verification() {
        let instance = sample_plonkish_instance(4).expect("sample");
        let mut prover_transcript = HashTranscript::new(b"plonkish-compact-opening-tamper");
        let proof = prove_plonkish(&instance, 2, &mut prover_transcript).expect("proof");
        assert!(matches!(
            proof.constraint_opening,
            PlonkishPcsOpening::Compact(_)
        ));

        let mut bad = proof.clone();
        match &mut bad.constraint_opening {
            PlonkishPcsOpening::Compact(opening) => {
                opening.combined_queries[0].column.value += FieldElement::ONE;
            }
            PlonkishPcsOpening::Full(_) => panic!("default Plonkish opening should be compact"),
        }
        let mut verifier_transcript = HashTranscript::new(b"plonkish-compact-opening-tamper");
        assert_eq!(
            verify_plonkish(&instance, &bad, &mut verifier_transcript),
            Err(PlonkishPiopError::InvalidProof)
        );
    }

    #[test]
    fn plonkish_opening_accounting_distinguishes_full_and_compact() {
        let instance = sample_plonkish_instance(4).expect("sample");
        let pcs_params = DistributedPcsParams::new(2);
        let mut compact_transcript = HashTranscript::new(b"plonkish-opening-size-compact");
        let compact =
            prove_plonkish_with_pcs_params(&instance, 2, pcs_params, &mut compact_transcript)
                .expect("compact proof");
        let mut full_transcript = HashTranscript::new(b"plonkish-opening-size-full");
        let full = prove_plonkish_with_pcs_hooks(
            &instance,
            2,
            pcs_params,
            &mut full_transcript,
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
                .map(PlonkishPcsOpening::Full)
                .map_err(|_| PlonkishPiopError::InvalidProof)
            },
        )
        .expect("full proof");

        assert!(matches!(
            compact.constraint_opening,
            PlonkishPcsOpening::Compact(_)
        ));
        assert!(matches!(
            full.constraint_opening,
            PlonkishPcsOpening::Full(_)
        ));
        assert_ne!(
            compact.constraint_opening.proof_size_bytes(),
            full.constraint_opening.proof_size_bytes()
        );
        assert_ne!(
            compact.constraint_opening.communication_bytes(),
            full.constraint_opening.communication_bytes()
        );
        let compact_index_openings = compact
            .gate_queries
            .iter()
            .map(gate_query_communication_bytes)
            .sum::<usize>()
            + compact
                .permutation_queries
                .iter()
                .map(permutation_query_communication_bytes)
                .sum::<usize>();
        assert!(compact_index_openings > 0);
        assert_eq!(
            proof_communication_bytes(&compact),
            compact.constraint_opening.communication_bytes() + compact_index_openings
        );
        let mut verifier_transcript = HashTranscript::new(b"plonkish-opening-size-compact");
        let metrics = verify_plonkish_with_pcs_params(
            &instance,
            &compact,
            pcs_params,
            &mut verifier_transcript,
        )
        .expect("verify compact");
        assert_eq!(
            metrics.communication_bytes,
            proof_communication_bytes(&compact)
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
        let proof = prove_plonkish(&instance, 2, &mut prover_transcript).expect("proof");

        let mut bad_value = proof.clone();
        bad_value.permutation_accumulator.numerator_last.value += FieldElement::ONE;
        let mut verifier_transcript = HashTranscript::new(b"plonkish-accumulator");
        assert_eq!(
            verify_plonkish(&instance, &bad_value, &mut verifier_transcript),
            Err(PlonkishPiopError::InvalidProof)
        );

        let mut bad_path = proof.clone();
        bad_path.permutation_accumulator.numerator_last.path[0].0[0] ^= 1;
        let mut verifier_transcript = HashTranscript::new(b"plonkish-accumulator");
        assert_eq!(
            verify_plonkish(&instance, &bad_path, &mut verifier_transcript),
            Err(PlonkishPiopError::InvalidProof)
        );

        let mut good_boundary_transcript = HashTranscript::new(b"plonkish-boundary-binding");
        absorb_accumulator_boundaries(
            &mut good_boundary_transcript,
            &proof.permutation_accumulator.numerator_first,
            &proof.permutation_accumulator.numerator_last,
            &proof.permutation_accumulator.denominator_first,
            &proof.permutation_accumulator.denominator_last,
        );
        let good_challenge =
            good_boundary_transcript.challenge_field::<FieldElement>(b"after-boundary");

        let mut tampered_boundary = proof.permutation_accumulator.numerator_last.clone();
        tampered_boundary.path[0].0[0] ^= 1;
        let mut bad_boundary_transcript = HashTranscript::new(b"plonkish-boundary-binding");
        absorb_accumulator_boundaries(
            &mut bad_boundary_transcript,
            &proof.permutation_accumulator.numerator_first,
            &tampered_boundary,
            &proof.permutation_accumulator.denominator_first,
            &proof.permutation_accumulator.denominator_last,
        );
        assert_ne!(
            good_challenge,
            bad_boundary_transcript.challenge_field::<FieldElement>(b"after-boundary")
        );

        let mut bad_recurrence_query = proof.clone();
        bad_recurrence_query
            .permutation_accumulator
            .recurrence_queries[0]
            .numerator_next
            .value += FieldElement::ONE;
        let mut verifier_transcript = HashTranscript::new(b"plonkish-accumulator");
        assert_eq!(
            verify_plonkish(&instance, &bad_recurrence_query, &mut verifier_transcript),
            Err(PlonkishPiopError::InvalidProof)
        );

        let mut good_query_transcript = HashTranscript::new(b"plonkish-acc-query-binding");
        absorb_accumulator_query(
            &mut good_query_transcript,
            &proof.permutation_accumulator.recurrence_queries[0],
        );
        let good_query_challenge =
            good_query_transcript.challenge_field::<FieldElement>(b"after-acc-query");
        let mut tampered_query = proof.permutation_accumulator.recurrence_queries[0].clone();
        tampered_query.denominator_current.path[0].0[0] ^= 1;
        let mut bad_query_transcript = HashTranscript::new(b"plonkish-acc-query-binding");
        absorb_accumulator_query(&mut bad_query_transcript, &tampered_query);
        assert_ne!(
            good_query_challenge,
            bad_query_transcript.challenge_field::<FieldElement>(b"after-acc-query")
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
    fn permutation_accumulator_recurrence_queries_bind_public_values_and_ids() {
        let instance = sample_plonkish_instance(4).expect("sample");
        let mut prover_transcript = HashTranscript::new(b"plonkish-accumulator-query-ids");
        let proof = prove_plonkish(&instance, 2, &mut prover_transcript).expect("proof");

        let mut bad_source_id = proof.clone();
        bad_source_id.permutation_accumulator.recurrence_queries[0]
            .source_id
            .value += FieldElement::ONE;
        let mut verifier_transcript = HashTranscript::new(b"plonkish-accumulator-query-ids");
        assert_eq!(
            verify_plonkish(&instance, &bad_source_id, &mut verifier_transcript),
            Err(PlonkishPiopError::InvalidProof)
        );

        let mut bad_public_value = proof.clone();
        bad_public_value.permutation_accumulator.recurrence_queries[0]
            .public_value
            .value += FieldElement::ONE;
        let mut verifier_transcript = HashTranscript::new(b"plonkish-accumulator-query-ids");
        assert_eq!(
            verify_plonkish(&instance, &bad_public_value, &mut verifier_transcript),
            Err(PlonkishPiopError::InvalidProof)
        );

        let mut bad_public_commitment = proof.clone();
        bad_public_commitment
            .permutation_accumulator
            .random_subclaim
            .public_commitments
            .value
            .root[0] ^= 1;
        let mut verifier_transcript = HashTranscript::new(b"plonkish-accumulator-query-ids");
        assert_eq!(
            verify_plonkish(&instance, &bad_public_commitment, &mut verifier_transcript),
            Err(PlonkishPiopError::InvalidProof)
        );

        let mut bad_target_path = proof;
        bad_target_path.permutation_accumulator.recurrence_queries[0]
            .target_id
            .path[0]
            .0[0] ^= 1;
        let mut verifier_transcript = HashTranscript::new(b"plonkish-accumulator-query-ids");
        assert_eq!(
            verify_plonkish(&instance, &bad_target_path, &mut verifier_transcript),
            Err(PlonkishPiopError::InvalidProof)
        );
    }

    #[test]
    fn plonkish_statement_excludes_wire_values_until_oracle_commitments() {
        let instance = sample_plonkish_instance(1).expect("sample");
        let mut changed_rows = instance.circuit().rows().to_vec();
        changed_rows[0].a += FieldElement::ONE;
        changed_rows[0].c = changed_rows[0].a * changed_rows[0].b;
        let changed =
            PlonkishInstance::with_identity_permutation(PlonkishCircuit::from_rows(changed_rows));

        let mut original_transcript = HashTranscript::new(b"plonkish-statement-wires");
        absorb_circuit_statement(&instance, 1, &mut original_transcript);
        let original_challenge =
            original_transcript.challenge_field::<FieldElement>(b"after-statement");

        let mut changed_transcript = HashTranscript::new(b"plonkish-statement-wires");
        absorb_circuit_statement(&changed, 1, &mut changed_transcript);
        let changed_challenge =
            changed_transcript.challenge_field::<FieldElement>(b"after-statement");

        assert_eq!(original_challenge, changed_challenge);

        let original_commitments =
            commit_oracles(&PlonkishOracles::from_instance(&instance).expect("oracles"))
                .expect("commit original");
        let changed_commitments =
            commit_oracles(&PlonkishOracles::from_instance(&changed).expect("changed oracles"))
                .expect("commit changed");
        assert_ne!(original_commitments.a, changed_commitments.a);
        assert_ne!(original_commitments.c, changed_commitments.c);

        let mut original_transcript = HashTranscript::new(b"plonkish-statement-wires");
        absorb_circuit_statement(&instance, 1, &mut original_transcript);
        absorb_oracle_commitments(&original_commitments, &mut original_transcript);
        let original_challenge =
            original_transcript.challenge_field::<FieldElement>(b"after-commitments");

        let mut changed_transcript = HashTranscript::new(b"plonkish-statement-wires");
        absorb_circuit_statement(&changed, 1, &mut changed_transcript);
        absorb_oracle_commitments(&changed_commitments, &mut changed_transcript);
        let changed_challenge =
            changed_transcript.challenge_field::<FieldElement>(b"after-commitments");

        assert_ne!(original_challenge, changed_challenge);
    }

    #[test]
    fn plonkish_verifier_binds_selectors_but_not_statement_wire_values() {
        let instance = sample_plonkish_instance(4).expect("sample");
        let mut prover_transcript = HashTranscript::new(b"plonkish-public-boundary");
        let proof = prove_plonkish(&instance, 2, &mut prover_transcript).expect("proof");

        let mut wire_changed_rows = instance.circuit().rows().to_vec();
        for (index, row) in wire_changed_rows.iter_mut().enumerate() {
            row.a += FieldElement::from(index + 7);
            row.b += FieldElement::from(index + 11);
            row.c += FieldElement::from(index + 13);
        }
        let wire_changed = PlonkishInstance::new(
            PlonkishCircuit::from_rows(wire_changed_rows),
            instance.permutation().clone(),
        )
        .expect("same public shape");
        let mut verifier_transcript = HashTranscript::new(b"plonkish-public-boundary");
        verify_plonkish(&wire_changed, &proof, &mut verifier_transcript)
            .expect("wire values are bound by oracle commitments, not the pre-oracle statement");

        let mut selector_changed_rows = instance.circuit().rows().to_vec();
        selector_changed_rows[0].q_c += FieldElement::ONE;
        let selector_changed = PlonkishInstance::new(
            PlonkishCircuit::from_rows(selector_changed_rows),
            instance.permutation().clone(),
        )
        .expect("selector change keeps shape");
        let mut verifier_transcript = HashTranscript::new(b"plonkish-public-boundary");
        assert_eq!(
            verify_plonkish(&selector_changed, &proof, &mut verifier_transcript),
            Err(PlonkishPiopError::InvalidProof)
        );
    }

    #[test]
    fn permutation_accumulator_random_subclaim_tampering_fails_verification() {
        let instance = sample_plonkish_instance(4).expect("sample");
        let mut prover_transcript = HashTranscript::new(b"plonkish-accumulator-subclaim");
        let proof = prove_plonkish(&instance, 2, &mut prover_transcript).expect("proof");

        let mut bad_shift = proof.clone();
        bad_shift
            .permutation_accumulator
            .random_subclaim
            .numerator_shift_queries[0]
            .shifted_at_index
            .value += FieldElement::ONE;
        let mut verifier_transcript = HashTranscript::new(b"plonkish-accumulator-subclaim");
        assert_eq!(
            verify_plonkish(&instance, &bad_shift, &mut verifier_transcript),
            Err(PlonkishPiopError::InvalidProof)
        );

        let mut bad_next_eval = proof.clone();
        bad_next_eval
            .permutation_accumulator
            .random_subclaim
            .denominator_next
            .folding
            .final_value += FieldElement::ONE;
        let mut verifier_transcript = HashTranscript::new(b"plonkish-accumulator-subclaim");
        assert_eq!(
            verify_plonkish(&instance, &bad_next_eval, &mut verifier_transcript),
            Err(PlonkishPiopError::InvalidProof)
        );

        let mut bad_next_commitment = proof.clone();
        bad_next_commitment
            .permutation_accumulator
            .random_subclaim
            .denominator_next_commitment
            .root[0] ^= 1;
        let mut verifier_transcript = HashTranscript::new(b"plonkish-accumulator-subclaim");
        assert_eq!(
            verify_plonkish(&instance, &bad_next_commitment, &mut verifier_transcript),
            Err(PlonkishPiopError::InvalidProof)
        );

        let mut bad_residual_query = proof.clone();
        bad_residual_query
            .permutation_accumulator
            .random_subclaim
            .residual_queries[0]
            .numerator_residual
            .value += FieldElement::ONE;
        let mut verifier_transcript = HashTranscript::new(b"plonkish-accumulator-subclaim");
        assert_eq!(
            verify_plonkish(&instance, &bad_residual_query, &mut verifier_transcript),
            Err(PlonkishPiopError::InvalidProof)
        );

        let mut bad_recurrence_round = proof.clone();
        bad_recurrence_round
            .permutation_accumulator
            .random_subclaim
            .numerator_recurrence
            .sumcheck
            .rounds[0]
            .eval_at_2 += FieldElement::ONE;
        let mut verifier_transcript = HashTranscript::new(b"plonkish-accumulator-subclaim");
        assert_eq!(
            verify_plonkish(&instance, &bad_recurrence_round, &mut verifier_transcript),
            Err(PlonkishPiopError::InvalidProof)
        );

        let mut bad_recurrence_opening = proof.clone();
        bad_recurrence_opening
            .permutation_accumulator
            .random_subclaim
            .numerator_recurrence
            .active
            .folding
            .final_value += FieldElement::ONE;
        let mut verifier_transcript = HashTranscript::new(b"plonkish-accumulator-subclaim");
        assert_eq!(
            verify_plonkish(&instance, &bad_recurrence_opening, &mut verifier_transcript),
            Err(PlonkishPiopError::InvalidProof)
        );

        let mut bad_value = proof.clone();
        bad_value
            .permutation_accumulator
            .random_subclaim
            .value
            .folding
            .rounds[0]
            .checks[0]
            .folded
            .value += FieldElement::ONE;
        let mut verifier_transcript = HashTranscript::new(b"plonkish-accumulator-subclaim");
        assert_eq!(
            verify_plonkish(&instance, &bad_value, &mut verifier_transcript),
            Err(PlonkishPiopError::InvalidProof)
        );

        let mut bad_point = proof;
        bad_point.permutation_accumulator.random_subclaim.point[0] += FieldElement::ONE;
        let mut verifier_transcript = HashTranscript::new(b"plonkish-accumulator-subclaim");
        assert_eq!(
            verify_plonkish(&instance, &bad_point, &mut verifier_transcript),
            Err(PlonkishPiopError::InvalidProof)
        );
    }

    #[test]
    fn gate_random_point_subclaim_tampering_fails_verification() {
        let instance = sample_plonkish_instance(4).expect("sample");
        let mut prover_transcript = HashTranscript::new(b"plonkish-gate-subclaim");
        let proof = prove_plonkish(&instance, 2, &mut prover_transcript).expect("proof");

        let mut bad_values = proof.clone();
        bad_values.gate_subclaim.a.folding.rounds[0].checks[0]
            .folded
            .value += FieldElement::ONE;
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

        let mut bad_gate_residual_binding = proof.clone();
        bad_gate_residual_binding
            .gate_subclaim
            .gate_residual
            .folding
            .final_value += FieldElement::ONE;
        let mut verifier_transcript = HashTranscript::new(b"plonkish-gate-subclaim");
        assert_eq!(
            verify_plonkish(
                &instance,
                &bad_gate_residual_binding,
                &mut verifier_transcript
            ),
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
    fn gate_cubic_zerocheck_tampering_fails_verification() {
        let instance = sample_plonkish_instance(4).expect("sample");
        let mut prover_transcript = HashTranscript::new(b"plonkish-gate-cubic");
        let proof = prove_plonkish(&instance, 2, &mut prover_transcript).expect("proof");

        let mut bad_sumcheck = proof.clone();
        bad_sumcheck.gate_cubic.sumcheck.final_evaluation += FieldElement::ONE;
        let mut verifier_transcript = HashTranscript::new(b"plonkish-gate-cubic");
        assert_eq!(
            verify_plonkish(&instance, &bad_sumcheck, &mut verifier_transcript),
            Err(PlonkishPiopError::InvalidProof)
        );

        let mut bad_product_opening = proof.clone();
        bad_product_opening
            .gate_cubic
            .product_left
            .folding
            .final_value += FieldElement::ONE;
        let mut verifier_transcript = HashTranscript::new(b"plonkish-gate-cubic");
        assert_eq!(
            verify_plonkish(&instance, &bad_product_opening, &mut verifier_transcript),
            Err(PlonkishPiopError::InvalidProof)
        );

        let mut bad_derived_commitment = proof.clone();
        bad_derived_commitment
            .oracle_commitments
            .gate_product_left
            .root[0] ^= 1;
        let mut verifier_transcript = HashTranscript::new(b"plonkish-gate-cubic");
        assert_eq!(
            verify_plonkish(&instance, &bad_derived_commitment, &mut verifier_transcript),
            Err(PlonkishPiopError::InvalidProof)
        );

        let mut bad_gate_query_relation = proof;
        bad_gate_query_relation.gate_queries[0]
            .gate_linear_output
            .value += FieldElement::ONE;
        let mut verifier_transcript = HashTranscript::new(b"plonkish-gate-cubic");
        assert_eq!(
            verify_plonkish(
                &instance,
                &bad_gate_query_relation,
                &mut verifier_transcript
            ),
            Err(PlonkishPiopError::InvalidProof)
        );
    }

    #[test]
    fn consistency_queries_cover_full_plonkish_domains_when_query_count_is_large() {
        let instance = sample_plonkish_instance(4).expect("sample");
        let mut prover_transcript = HashTranscript::new(b"plonkish-full-consistency-sample");
        let proof = prove_plonkish(&instance, 2, &mut prover_transcript).expect("proof");

        let mut gate_rows = proof
            .gate_queries
            .iter()
            .map(|query| query.row)
            .collect::<Vec<_>>();
        gate_rows.sort_unstable();
        assert_eq!(gate_rows, (0..instance.row_count()).collect::<Vec<_>>());
        let mut permutation_sources = proof
            .permutation_queries
            .iter()
            .map(|query| query.source)
            .collect::<Vec<_>>();
        permutation_sources.sort_unstable();
        assert_eq!(
            permutation_sources,
            (0..instance.permutation_check_count()).collect::<Vec<_>>()
        );
        let mut recurrence_indices = proof
            .permutation_accumulator
            .recurrence_queries
            .iter()
            .map(|query| query.index)
            .collect::<Vec<_>>();
        recurrence_indices.sort_unstable();
        assert_eq!(
            recurrence_indices,
            (0..instance.permutation_check_count()).collect::<Vec<_>>()
        );
    }

    #[test]
    fn consistency_queries_are_sampled_by_query_count() {
        let instance = sample_plonkish_instance(8).expect("sample");
        let params = DistributedPcsParams::new(2);
        let mut prover_transcript = HashTranscript::new(b"plonkish-sampled-consistency");
        let proof = prove_plonkish_with_pcs_params(&instance, 2, params, &mut prover_transcript)
            .expect("proof");

        assert_eq!(proof.gate_queries.len(), 2);
        assert_eq!(proof.permutation_queries.len(), 2);
        assert_eq!(proof.permutation_accumulator.recurrence_queries.len(), 2);

        let mut gate_rows = proof
            .gate_queries
            .iter()
            .map(|query| query.row)
            .collect::<Vec<_>>();
        gate_rows.sort_unstable();
        gate_rows.dedup();
        assert_eq!(gate_rows.len(), 2);

        let mut permutation_sources = proof
            .permutation_queries
            .iter()
            .map(|query| query.source)
            .collect::<Vec<_>>();
        permutation_sources.sort_unstable();
        permutation_sources.dedup();
        assert_eq!(permutation_sources.len(), 2);

        let mut recurrence_indices = proof
            .permutation_accumulator
            .recurrence_queries
            .iter()
            .map(|query| query.index)
            .collect::<Vec<_>>();
        recurrence_indices.sort_unstable();
        recurrence_indices.dedup();
        assert_eq!(recurrence_indices.len(), 2);

        let mut verifier_transcript = HashTranscript::new(b"plonkish-sampled-consistency");
        verify_plonkish_with_pcs_params(&instance, &proof, params, &mut verifier_transcript)
            .expect("verify");
    }

    #[test]
    fn consistency_query_openings_bind_final_transcript_state() {
        let instance = sample_plonkish_instance(4).expect("sample");
        let params = DistributedPcsParams::new(2);
        let mut prover_transcript = HashTranscript::new(b"plonkish-final-query-binding");
        let proof = prove_plonkish_with_pcs_params(&instance, 2, params, &mut prover_transcript)
            .expect("proof");
        let mut verifier_transcript = HashTranscript::new(b"plonkish-final-query-binding");
        verify_plonkish_with_pcs_params(&instance, &proof, params, &mut verifier_transcript)
            .expect("verify");
        assert_eq!(prover_transcript.state(), verifier_transcript.state());

        let mut good_transcript = HashTranscript::new(b"plonkish-final-query-helper");
        absorb_consistency_queries(
            &mut good_transcript,
            &proof.gate_queries,
            &proof.permutation_queries,
        );
        let good_challenge =
            good_transcript.challenge_field::<FieldElement>(b"after-final-queries");

        let mut bad_gate_queries = proof.gate_queries.clone();
        bad_gate_queries[0].a.path[0].0[0] ^= 1;
        let mut bad_gate_transcript = HashTranscript::new(b"plonkish-final-query-helper");
        absorb_consistency_queries(
            &mut bad_gate_transcript,
            &bad_gate_queries,
            &proof.permutation_queries,
        );
        assert_ne!(
            good_challenge,
            bad_gate_transcript.challenge_field::<FieldElement>(b"after-final-queries")
        );

        let mut bad_permutation_queries = proof.permutation_queries.clone();
        bad_permutation_queries[0].target_value.value += FieldElement::ONE;
        let mut bad_permutation_transcript = HashTranscript::new(b"plonkish-final-query-helper");
        absorb_consistency_queries(
            &mut bad_permutation_transcript,
            &proof.gate_queries,
            &bad_permutation_queries,
        );
        assert_ne!(
            good_challenge,
            bad_permutation_transcript.challenge_field::<FieldElement>(b"after-final-queries")
        );

        let mut bad_proof = proof.clone();
        bad_proof.gate_queries[0].a.path[0].0[0] ^= 1;
        let mut verifier_transcript = HashTranscript::new(b"plonkish-final-query-binding");
        assert_eq!(
            verify_plonkish_with_pcs_params(
                &instance,
                &bad_proof,
                params,
                &mut verifier_transcript
            ),
            Err(PlonkishPiopError::InvalidProof)
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
    fn proof_size_accounting_includes_gate_subclaim_sampled_openings() {
        let instance = sample_plonkish_instance(4).expect("sample");
        let mut prover_transcript = HashTranscript::new(b"plonkish-gate-size-accounting");
        let mut proof = prove_plonkish(&instance, 2, &mut prover_transcript).expect("proof");
        let original_size = proof_size_bytes(&proof);
        proof.gate_subclaim.a.folding.rounds[0]
            .checks
            .pop()
            .expect("sampled gate opening");

        assert!(proof_size_bytes(&proof) < original_size);
    }

    #[test]
    fn proof_size_accounting_includes_gate_cubic_proof() {
        let instance = sample_plonkish_instance(4).expect("sample");
        let mut prover_transcript = HashTranscript::new(b"plonkish-gate-cubic-size-accounting");
        let mut proof = prove_plonkish(&instance, 2, &mut prover_transcript).expect("proof");
        let original_size = proof_size_bytes(&proof);
        proof.gate_cubic.product_left.folding.rounds[0]
            .checks
            .pop()
            .expect("gate cubic sampled opening");

        assert!(proof_size_bytes(&proof) < original_size);
    }

    #[test]
    fn proof_size_accounting_includes_accumulator_subclaim_sampled_openings() {
        let instance = sample_plonkish_instance(4).expect("sample");
        let mut prover_transcript = HashTranscript::new(b"plonkish-acc-size-accounting");
        let mut proof = prove_plonkish(&instance, 2, &mut prover_transcript).expect("proof");
        let original_size = proof_size_bytes(&proof);
        proof
            .permutation_accumulator
            .random_subclaim
            .value
            .folding
            .rounds[0]
            .checks
            .pop()
            .expect("accumulator sampled opening");

        assert!(proof_size_bytes(&proof) < original_size);
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

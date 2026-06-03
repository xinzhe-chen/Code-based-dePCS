//! Core math and circuit data structures for pq_dSNARK.

pub mod error;
pub mod field;
pub mod matrix;
pub mod mle;
pub mod partition;
pub mod plonkish;
pub mod polynomial;
pub mod r1cs;

pub use error::{CoreError, Result};
pub use field::{FieldElement, GOLDILOCKS_MODULUS};
pub use matrix::{PrecomputedSparseMatrix, PrecomputedSparseStats, SparseEntry, SparseMatrix};
pub use mle::{
    MultilinearExtension, eq_basis, eq_eval, eq_evaluations, evaluate_mle, log2_power_of_two,
};
pub use partition::{Partition, PartitionPlan};
pub use plonkish::{CustomizedGate, Gate, GateMonomial, PlonkishCircuit, PlonkishRow};
pub use polynomial::{DensePolynomial, inner_product, lagrange_interpolate, powers};
pub use r1cs::R1CS;

pub type MultilinearPolynomial = MultilinearExtension;
pub type R1csInstance = R1CS;

pub fn sample_r1cs() -> (R1CS, Vec<FieldElement>) {
    let mut a = SparseMatrix::new(2, 4);
    let mut b = SparseMatrix::new(2, 4);
    let mut c = SparseMatrix::new(2, 4);
    a.add_entry(0, 1, FieldElement::ONE).expect("sample entry");
    b.add_entry(0, 2, FieldElement::ONE).expect("sample entry");
    c.add_entry(0, 3, FieldElement::ONE).expect("sample entry");
    a.add_entry(1, 3, FieldElement::ONE).expect("sample entry");
    b.add_entry(1, 0, FieldElement::ONE).expect("sample entry");
    c.add_entry(1, 3, FieldElement::ONE).expect("sample entry");
    (
        R1CS::new(a, b, c).expect("sample r1cs shape"),
        vec![
            FieldElement::ONE,
            FieldElement::from(3_u64),
            FieldElement::from(4_u64),
            FieldElement::from(12_u64),
        ],
    )
}

pub fn sample_plonkish() -> (PlonkishCircuit, Vec<FieldElement>) {
    PlonkishCircuit::sample_gate_permutation()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fe(value: u64) -> FieldElement {
        FieldElement::from(value)
    }

    #[test]
    fn mle_evaluation_matches_naive_eq_basis_sum() {
        let evaluations = vec![fe(3), fe(5), fe(7), fe(11), fe(13), fe(17), fe(19), fe(23)];
        let mle = MultilinearExtension::from_evaluations(evaluations.clone())
            .expect("power-of-two MLE evaluations should construct");
        let point = vec![fe(2), fe(3), fe(5)];

        let fast = mle
            .evaluate(&point)
            .expect("point length should match MLE variables");
        let naive = evaluations
            .iter()
            .enumerate()
            .map(|(index, value)| {
                *value * eq_basis(&point, index).expect("basis index should be in range")
            })
            .sum::<FieldElement>();

        assert_eq!(fast, naive);
        assert_eq!(
            fast,
            mle.evaluate_naive(&point)
                .expect("naive MLE evaluation should succeed")
        );
    }

    #[test]
    fn parallel_eq_evaluations_match_basis_order() {
        let point = (1_u64..=12).map(fe).collect::<Vec<_>>();
        let evals = eq_evaluations(&point).expect("eq evals");
        assert_eq!(evals.len(), 1 << point.len());
        for index in [0, 1, 2, 3, 17, 255, 1023, 2048, 4095] {
            assert_eq!(
                evals[index],
                eq_basis(&point, index).expect("basis index"),
                "eq evaluation order changed at index {index}"
            );
        }
        assert_eq!(
            evals.iter().copied().sum::<FieldElement>(),
            FieldElement::ONE
        );
    }

    #[test]
    fn parallel_mle_evaluation_matches_naive_at_medium_size() {
        let evaluations = (0..4096)
            .map(|index| fe((index as u64).wrapping_mul(17).wrapping_add(5)))
            .collect::<Vec<_>>();
        let mle = MultilinearExtension::from_evaluations(evaluations).expect("mle");
        let point = (2_u64..=13).map(fe).collect::<Vec<_>>();

        assert_eq!(
            mle.evaluate(&point).expect("parallel fold evaluation"),
            mle.evaluate_naive(&point).expect("eq-basis evaluation")
        );
    }

    #[test]
    fn mle_rejects_wrong_length_and_oversized_dimensions() {
        let mle = MultilinearExtension::from_evaluations(vec![fe(1), fe(2)])
            .expect("two evaluations should define one variable");

        assert_eq!(
            mle.evaluate_naive(&[fe(3), fe(4)]),
            Err(CoreError::PointLength {
                expected: 1,
                actual: 2,
            })
        );
        assert_eq!(
            MultilinearExtension::try_from_fn(MultilinearExtension::MAX_NUM_VARS + 1, |_| {
                FieldElement::ONE
            },),
            Err(CoreError::VectorLength {
                expected: MultilinearExtension::MAX_ALLOCATING_NUM_VARS,
                actual: MultilinearExtension::MAX_NUM_VARS + 1,
            })
        );
    }

    #[test]
    fn r1cs_accepts_valid_witness_and_rejects_invalid_witness() {
        let mut a = SparseMatrix::new(1, 4);
        let mut b = SparseMatrix::new(1, 4);
        let mut c = SparseMatrix::new(1, 4);

        a.add_entry(0, 1, FieldElement::ONE)
            .expect("A entry should be in bounds");
        b.add_entry(0, 2, FieldElement::ONE)
            .expect("B entry should be in bounds");
        c.add_entry(0, 3, FieldElement::ONE)
            .expect("C entry should be in bounds");

        let r1cs = R1CS::new(a, b, c).expect("R1CS matrices should have matching shapes");
        let valid = vec![FieldElement::ONE, fe(3), fe(4), fe(12)];
        let invalid = vec![FieldElement::ONE, fe(3), fe(4), fe(13)];

        assert!(
            r1cs.is_satisfied(&valid)
                .expect("valid witness length should match")
        );
        assert!(
            !r1cs
                .is_satisfied(&invalid)
                .expect("invalid witness length should match")
        );
    }

    #[test]
    fn partition_plan_checks_complete_non_overlapping_coverage() {
        let plan = PartitionPlan::balanced(10, 3).expect("balanced plan should be valid");

        assert_eq!(
            plan.partitions(),
            &[
                Partition::new(0, 0, 4),
                Partition::new(1, 4, 7),
                Partition::new(2, 7, 10),
            ]
        );
        assert!(plan.validate_coverage().is_ok());
        assert_eq!(plan.owner_of(0), Some(0));
        assert_eq!(plan.owner_of(4), Some(1));
        assert_eq!(plan.owner_of(9), Some(2));
        assert_eq!(plan.owner_of(10), None);

        let gap = PartitionPlan::new(5, vec![Partition::new(0, 0, 2), Partition::new(1, 3, 5)]);
        assert!(gap.is_err());

        let overlap = PartitionPlan::new(5, vec![Partition::new(0, 0, 3), Partition::new(1, 2, 5)]);
        assert!(overlap.is_err());
    }

    #[test]
    fn plonkish_multiplication_gate_checks_row_constraint() {
        let ok = PlonkishRow::multiplication(fe(6), fe(7), fe(42));
        let bad = PlonkishRow::multiplication(fe(6), fe(7), fe(41));
        let circuit = PlonkishCircuit::from_rows(vec![ok]);

        assert!(ok.is_satisfied());
        assert!(!bad.is_satisfied());
        assert!(circuit.is_satisfied());
    }

    #[test]
    fn hyperplonk_vanilla_gate_shape_evaluates_rows() {
        let gate = CustomizedGate::vanilla_plonk_gate();
        assert_eq!(gate.degree(), 3);
        assert_eq!(gate.num_selector_columns(), 5);
        assert_eq!(gate.num_witness_columns(), 3);
        assert_eq!(gate.monomials().len(), 5);

        let row = PlonkishRow::multiplication(fe(6), fe(7), fe(42));
        assert_eq!(
            gate.evaluate(&row.selectors(), &row.witnesses()),
            row.evaluate()
        );

        let linear = PlonkishRow::linear(fe(3), fe(4), fe(9), fe(2), fe(5), -fe(4), fe(1));
        let direct = linear.q_l * linear.a
            + linear.q_r * linear.b
            + linear.q_o * linear.c
            + linear.q_m * linear.a * linear.b
            + linear.q_c;
        assert_eq!(linear.evaluate(), direct);
    }

    #[test]
    fn plonkish_gate_permutation_constructor_rejects_bad_indices() {
        let bad_gate = PlonkishCircuit::from_gate_permutation(
            2,
            vec![Gate::Mul {
                left: 0,
                right: 1,
                out: 2,
            }],
            vec![0, 1],
        );
        assert!(matches!(bad_gate, Err(CoreError::IndexOutOfBounds { .. })));

        let non_bijection = PlonkishCircuit::from_gate_permutation(2, Vec::new(), vec![0, 0]);
        assert!(matches!(
            non_bijection,
            Err(CoreError::InvalidPartition { .. })
        ));
    }

    #[test]
    fn plonkish_gate_permutation_sample_requires_explicit_witness_check() {
        let (circuit, witness) = sample_plonkish();

        assert!(!circuit.is_empty());
        assert_eq!(circuit.len(), 4);
        assert!(!circuit.is_satisfied());
        assert!(
            circuit
                .is_satisfied_with_witness(&witness)
                .expect("sample witness length should match")
        );
    }
}

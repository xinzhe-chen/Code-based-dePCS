//! Core math and circuit data structures for pq_dSNARK.

pub mod error;
pub mod field;
pub mod matrix;
pub mod mle;
pub mod partition;
pub mod polynomial;

pub use error::{CoreError, Result};
pub use field::{FieldElement, GOLDILOCKS_MODULUS};
pub use matrix::{PrecomputedSparseMatrix, PrecomputedSparseStats, SparseEntry, SparseMatrix};
pub use mle::{
    MultilinearExtension, eq_basis, eq_eval, eq_evaluations, evaluate_mle, log2_power_of_two,
};
pub use partition::{Partition, PartitionPlan};
pub use polynomial::{DensePolynomial, inner_product, lagrange_interpolate, powers};

pub type MultilinearPolynomial = MultilinearExtension;

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
}

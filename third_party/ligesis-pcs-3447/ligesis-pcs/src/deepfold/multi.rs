//! DeepFold multi-commit helper functions
//!
//! Provides helper functions for splitting large polynomials into chunks
//! and committing each chunk separately.

use crate::{errors::PCSError, types::HasQuadraticExtension, utils::*};
use ark_ff::{Field, PrimeField};
use ark_poly::DenseMultilinearExtension;
use ark_std::{sync::Arc, vec::Vec};

use super::{
    DeepFoldCommitment, DeepFoldProverCommitmentAdvice, DeepFoldProverParam,
    deepfold_commit, deepfold_d_commit_full_poly_v2,
};
use deNetwork::{DeMultiNet as Net, DeNet};

/// Split a polynomial into chunks of size 2^base_mu
///
/// Returns (chunk_polys, num_chunks_log2)
/// - chunk_polys: Vec of chunk polynomials, each with base_mu variables
/// - num_chunks_log2: log2 of number of chunks (num_vars - base_mu, or 0 if no split)
pub fn split_polynomial<F: PrimeField>(
    poly: &Arc<DenseMultilinearExtension<F>>,
    base_mu: usize,
) -> (Vec<Arc<DenseMultilinearExtension<F>>>, usize) {
    let num_vars = poly.num_vars;

    if num_vars <= base_mu {
        // No split needed, just pad
        let padded_evals = resize_eval(&poly.evaluations, base_mu);
        let padded_poly = evals_to_arcpoly(&padded_evals);
        (vec![padded_poly], 0)
    } else {
        // Split into chunks
        let num_chunks_log2 = num_vars - base_mu;
        let num_chunks = 1 << num_chunks_log2;
        let chunk_size = 1 << base_mu;

        let chunk_polys: Vec<Arc<DenseMultilinearExtension<F>>> = (0..num_chunks)
            .map(|chunk_idx| {
                let chunk_evals: Vec<F> = (0..chunk_size)
                    .map(|i| poly.evaluations[i + chunk_idx * chunk_size])
                    .collect();
                evals_to_arcpoly(&chunk_evals)
            })
            .collect();

        (chunk_polys, num_chunks_log2)
    }
}

/// Commit a polynomial, splitting into chunks if needed
///
/// Returns (commitments, advices, num_chunks_log2)
pub fn multi_commit<F: PrimeField>(
    prover_param: &DeepFoldProverParam<F>,
    poly: &Arc<DenseMultilinearExtension<F>>,
) -> Result<(Vec<DeepFoldCommitment>, Vec<DeepFoldProverCommitmentAdvice<F>>, usize), PCSError> {
    let base_mu = prover_param.max_mu;
    let (chunk_polys, num_chunks_log2) = split_polynomial(poly, base_mu);

    let mut commitments = Vec::with_capacity(chunk_polys.len());
    let mut advices = Vec::with_capacity(chunk_polys.len());

    for chunk_poly in chunk_polys {
        let (com, advice) = deepfold_commit(prover_param, &chunk_poly)?;
        commitments.push(com);
        advices.push(advice);
    }

    Ok((commitments, advices, num_chunks_log2))
}

/// Distributed commit v2 for a polynomial that ALL parties already have (e.g., mat_h)
/// using the new column-based distribution protocol.
///
/// The polynomial is split into chunks if needed, then each chunk is committed
/// using deepfold_d_commit_full_poly_v2.
///
/// Returns (Option<commitments>, advices, num_chunks_log2)
/// - commitments: Some for master, contents are commitments for workers
/// - advices: local advices for each party
/// - num_chunks_log2: log2 of number of chunks
pub fn d_multi_commit_v2<F: PrimeField>(
    prover_param: &DeepFoldProverParam<F>,
    poly: &Arc<DenseMultilinearExtension<F>>,
) -> Result<(Vec<Option<DeepFoldCommitment>>, Vec<DeepFoldProverCommitmentAdvice<F>>, usize), PCSError> {
    let base_mu = prover_param.max_mu;
    let (chunk_polys, num_chunks_log2) = split_polynomial(poly, base_mu);

    let mut commitments = Vec::with_capacity(chunk_polys.len());
    let mut advices = Vec::with_capacity(chunk_polys.len());

    for chunk_poly in chunk_polys {
        let (com_opt, advice) = deepfold_d_commit_full_poly_v2(prover_param, &chunk_poly)?;
        commitments.push(com_opt);
        advices.push(advice);
    }

    Ok((commitments, advices, num_chunks_log2))
}

/// Compute eq(b, point) where b is the binary representation of chunk_idx
pub fn compute_eq_at_chunk<F: PrimeField>(chunk_idx: usize, point: &[F]) -> F {
    let mut result = F::ONE;
    for (i, &pi) in point.iter().enumerate() {
        let bit = (chunk_idx >> i) & 1;
        if bit == 1 {
            result *= pi;
        } else {
            result *= F::ONE - pi;
        }
    }
    result
}

/// Combine chunk values into original polynomial value
/// f(x_low, x_high) = Σ_b f_b(x_low) · eq(b, x_high)
pub fn combine_chunk_values<F: PrimeField>(
    chunk_values: &[F],
    high_point: &[F],
) -> F {
    let mut result = F::ZERO;
    for (chunk_idx, &val) in chunk_values.iter().enumerate() {
        let eq_coeff = compute_eq_at_chunk(chunk_idx, high_point);
        result += eq_coeff * val;
    }
    result
}

/// Split a full point into (low_point, high_point) for chunked polynomial evaluation
///
/// For a polynomial with full_num_vars variables split at base_mu:
/// - low_point: first base_mu variables (used for evaluating each chunk)
/// - high_point: remaining variables (used for combining chunk values with eq)
///
/// Returns (low_point, high_point)
pub fn split_point_for_chunks<F: Clone>(
    point: &[F],
    base_mu: usize,
) -> (Vec<F>, Vec<F>) {
    if point.len() <= base_mu {
        (point.to_vec(), vec![])
    } else {
        (point[..base_mu].to_vec(), point[base_mu..].to_vec())
    }
}

/// Expand chunk polynomials, advices, and points for batch_open
///
/// Takes the output of multi_commit along with the full opening point,
/// and returns vectors suitable for batch_open.
///
/// For a polynomial f(x_low, x_high) split into chunks f_0, f_1, ..., f_{2^k-1}:
/// - Each chunk f_b is opened at x_low
/// - After batch_open, combine values using combine_chunk_values(vals, x_high)
///
/// Returns (chunk_polys, chunk_advices, chunk_points)
pub fn expand_for_batch_open<F: PrimeField>(
    chunk_polys: &[Arc<DenseMultilinearExtension<F>>],
    chunk_advices: &[DeepFoldProverCommitmentAdvice<F>],
    full_point: &[F],
    base_mu: usize,
) -> (
    Vec<Arc<DenseMultilinearExtension<F>>>,
    Vec<DeepFoldProverCommitmentAdvice<F>>,
    Vec<Vec<F>>,
) {
    let (low_point, _high_point) = split_point_for_chunks(full_point, base_mu);

    // Pad low_point to base_mu if needed
    let padded_low_point = resize_point(&low_point, base_mu);

    let num_chunks = chunk_polys.len();
    let polys: Vec<_> = chunk_polys.iter().cloned().collect();
    let advices: Vec<_> = chunk_advices.iter().cloned().collect();
    let points: Vec<_> = (0..num_chunks)
        .map(|_| padded_low_point.clone())
        .collect();

    (polys, advices, points)
}

// =============================================================================
// Extension field versions for Ligesis
// =============================================================================

/// Compute eq(b, point) for extension field point
pub fn compute_eq_at_chunk_ext<F: PrimeField + HasQuadraticExtension>(
    chunk_idx: usize,
    point: &[F::Extension],
) -> F::Extension {
    let mut result = F::Extension::ONE;
    for (i, &pi) in point.iter().enumerate() {
        let bit = (chunk_idx >> i) & 1;
        if bit == 1 {
            result *= pi;
        } else {
            result *= F::Extension::ONE - pi;
        }
    }
    result
}

/// Combine chunk values (extension field) using extension field eq coefficients
/// f(x_low, x_high) = Σ_b f_b(x_low) · eq(b, x_high)
pub fn combine_chunk_values_ext<F: PrimeField + HasQuadraticExtension>(
    chunk_values: &[F::Extension],
    high_point: &[F::Extension],
) -> F::Extension {
    let mut result = F::Extension::ZERO;
    for (chunk_idx, &val) in chunk_values.iter().enumerate() {
        let eq_coeff = compute_eq_at_chunk_ext::<F>(chunk_idx, high_point);
        result += eq_coeff * val;
    }
    result
}

/// Expand chunk polynomials, advices, and points for batch_open at extension field points
///
/// Returns (chunk_polys, chunk_advices, chunk_points_ext)
pub fn expand_for_batch_open_ext<F: PrimeField + HasQuadraticExtension>(
    chunk_polys: &[Arc<DenseMultilinearExtension<F>>],
    chunk_advices: &[DeepFoldProverCommitmentAdvice<F>],
    full_point: &[F::Extension],
    base_mu: usize,
) -> (
    Vec<Arc<DenseMultilinearExtension<F>>>,
    Vec<DeepFoldProverCommitmentAdvice<F>>,
    Vec<Vec<F::Extension>>,
) {
    let (low_point, _high_point) = split_point_for_chunks(full_point, base_mu);

    // Pad low_point to base_mu if needed
    let padded_low_point = resize_point_ext::<F>(&low_point, base_mu);

    let num_chunks = chunk_polys.len();
    let polys: Vec<_> = chunk_polys.iter().cloned().collect();
    let advices: Vec<_> = chunk_advices.iter().cloned().collect();
    let points: Vec<_> = (0..num_chunks)
        .map(|_| padded_low_point.clone())
        .collect();

    (polys, advices, points)
}

/// Helper to resize extension field point
fn resize_point_ext<F: PrimeField + HasQuadraticExtension>(
    point: &[F::Extension],
    target_len: usize,
) -> Vec<F::Extension> {
    let mut result = point.to_vec();
    while result.len() < target_len {
        result.push(F::Extension::ZERO);
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::FGoldilocks as F;

    #[test]
    fn test_split_small_poly() {
        let base_mu = 4;
        let evals: Vec<F> = (0..8).map(|i| F::from(i as u64)).collect();
        let poly = evals_to_arcpoly(&evals);

        let (chunks, num_chunks_log2) = split_polynomial(&poly, base_mu);

        assert_eq!(chunks.len(), 1);
        assert_eq!(num_chunks_log2, 0);
        assert_eq!(chunks[0].num_vars, base_mu);
    }

    #[test]
    fn test_split_large_poly() {
        let base_mu = 4;
        let evals: Vec<F> = (0..64).map(|i| F::from(i as u64)).collect();
        let poly = evals_to_arcpoly(&evals);

        let (chunks, num_chunks_log2) = split_polynomial(&poly, base_mu);

        // 64 = 2^6, base_mu = 4, so 2^(6-4) = 4 chunks
        assert_eq!(chunks.len(), 4);
        assert_eq!(num_chunks_log2, 2);

        // Verify chunk contents
        for (chunk_idx, chunk) in chunks.iter().enumerate() {
            assert_eq!(chunk.num_vars, base_mu);
            for i in 0..16 {
                assert_eq!(
                    chunk.evaluations[i],
                    F::from((chunk_idx * 16 + i) as u64)
                );
            }
        }
    }

    #[test]
    fn test_combine_chunk_values() {
        // 2 chunks (1 high variable)
        let chunk_values = vec![F::from(3u64), F::from(7u64)];
        let high_point = vec![F::from(2u64)];

        // f(x) = f0 * (1-x) + f1 * x = 3 * (1-2) + 7 * 2 = -3 + 14 = 11
        let result = combine_chunk_values(&chunk_values, &high_point);
        assert_eq!(result, F::from(11u64));
    }

    #[test]
    fn test_combine_chunk_values_4_chunks() {
        // 4 chunks (2 high variables)
        // f(x0, x1) = f00*(1-x0)*(1-x1) + f01*x0*(1-x1) + f10*(1-x0)*x1 + f11*x0*x1
        let chunk_values = vec![
            F::from(1u64),  // f00
            F::from(2u64),  // f01
            F::from(3u64),  // f10
            F::from(4u64),  // f11
        ];
        let high_point = vec![F::from(1u64), F::from(1u64)]; // x0=1, x1=1

        // At (1,1): only f11 contributes = 4
        let result = combine_chunk_values(&chunk_values, &high_point);
        assert_eq!(result, F::from(4u64));

        // At (0,0): only f00 contributes = 1
        let high_point_00 = vec![F::from(0u64), F::from(0u64)];
        let result_00 = combine_chunk_values(&chunk_values, &high_point_00);
        assert_eq!(result_00, F::from(1u64));
    }
}

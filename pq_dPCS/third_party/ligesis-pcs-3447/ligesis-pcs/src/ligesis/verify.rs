//! Ligesis verify functions
//!
//! This module contains the verify implementations for Ligesis PCS:
//! - `ligesis_verify`: Extension field verification with 128-bit security

use crate::{
    deepfold::{multi_chunked_batch_verify_at_ext_point, *},
    errors::PCSError,
    ext_sumcheck::ext_sumcheck_verify,
    types::{FieldExtension, HasQuadraticExtension},
    utils::*,
};
use ark_ff::PrimeField;
use ark_std::{borrow::Borrow, vec::Vec, Zero};
use transcript::IOPTranscript;

use super::{ExtSumCheckWithReductionProof, LigeSISCommitment, LigeSISProof, LigeSISVerifierParam};

/// Ligesis verify with extension field SumCheck (128-bit security)
/// Uses extension field SumCheck and direct extension field opening in DeepFold
#[allow(non_snake_case)]
pub fn ligesis_verify<F: PrimeField + HasQuadraticExtension>(
    verifier_param: &LigeSISVerifierParam<F>,
    com: &LigeSISCommitment<F>,
    point: &[F],
    value: &F,
    proof: &LigeSISProof<F>,
    transcript: &mut IOPTranscript<F>,
) -> Result<bool, PCSError> {
    // trim parameters
    let LigeSISVerifierParam {
        eta,
        s_lambda,
        mu,
        log_m,
        log_n,
        rs_len,
        c,
        g,
        com_mat_a,
        deepfold_verifier_param,
    } = verifier_param.borrow().clone();
    let LigeSISCommitment {
        num_vars: _,
        com_mat_h,
        _marker: _,
    } = com.clone();
    let (m, n) = (1 << log_m, 1 << log_n);
    let log_rs_len = rs_len.ilog2() as usize;

    // Pad point if needed
    let point = resize_point(&point.to_vec(), mu);

    let LigeSISProof {
        com_a_bI_rsa,
        bI_check_proof,
        alpha2_a_bI_r2_check_proof,
        v_bI_r2_check_proof,
        rs_a_check_proof,
        mat_g_check_proofs,
        deepfold_batched_proof,
    } = proof.clone();
    // Extension field evaluations from multi-chunked batch proof
    // claimed_values[point_idx][poly_idx] structure
    let claimed_values = &deepfold_batched_proof.claimed_values;

    // Step 1: Split point into z1 (for row selection) and z2 (for column selection)
    let (z1, z2): (Vec<F>, Vec<F>) = (point[log_n..].to_vec(), point[..log_n].to_vec());

    // Step 3: Get challenge indices (needed to keep transcript in sync with prover)
    let _ = transcript.get_and_append_challenge_indices(b"I", s_lambda, 2 * n)?;

    // Step 5: Get challenges
    let alpha1 = transcript
        .get_and_append_challenge_vectors(b"alpha1", (m * eta * s_lambda).ilog2() as usize)?;
    let alpha2 = transcript.get_and_append_challenge_vectors(b"alpha2", c.ilog2() as usize)?;
    let alpha3 = transcript.get_and_append_challenge_vectors(b"alpha3", rs_len.ilog2() as usize)?;

    // Point indices for claimed_values:
    // With combined com_a_bI_rsa (3 polys: a=0, bI=1, rs_a=2):
    // 0: a(z2) -> [0][0], 1: a(r6) -> [1][0], 2: bI(r1) -> [2][1],
    // 3: bI(r2,r4) -> [3][1], 4: bI(r2,r5) -> [4][1]
    // 5: rs_a(r3) -> [5][2], 6: rs_a(alpha3) -> [6][2]
    // 7: mat_h(r3,alpha2) -> [7][0], 8: mat_a(r4,alpha2) -> [8][0]

    // Step 6: Verify extension field SumCheck for bI check
    // This proves: sum_x bI(x) * (bI(x) - 1) * tensor_alpha1(x) = 0
    let bI_num_vars = (m * eta * s_lambda).ilog2() as usize;
    let (r1_ext, bI_check_expected, bI_check_claimed_sum) = verify_ext_sumcheck_with_subclaim::<F>(
        &bI_check_proof,
        bI_num_vars,
        3, // max_degree = 3 (product of 3 polynomials)
        transcript,
    )?;

    // Verify bI_check claimed_sum = 0 (bI must be binary, so bI*(bI-1) = 0 for all
    // points)
    if !bI_check_claimed_sum.is_zero() {
        return Ok(false);
    }

    // Verify bI_check subclaim: bI(r1) * (bI(r1) - 1) * tensor_alpha1(r1) =
    // expected claimed_values[2] = bI(r1) (point 2 targets bI)
    let bI_r1 = claimed_values[2];
    let tensor_alpha1_r1 = eval_tensor_at_ext_point::<F>(&alpha1, &r1_ext);
    let bI_check_computed = bI_r1 * (bI_r1 - F::Extension::from_base(F::ONE)) * tensor_alpha1_r1;
    if bI_check_computed != bI_check_expected {
        return Ok(false);
    }

    // Step 7.1: Verify extension field SumCheck for rs_a check
    // This proves: sum_x alpha3_mat_g_n(x) * a(x) = rs_a(alpha3)
    let (r6_ext, rs_a_check_expected, rs_a_check_claimed_sum) =
        verify_ext_sumcheck_with_subclaim::<F>(
            &rs_a_check_proof,
            log_n,
            2, // max_degree = 2
            transcript,
        )?;

    // Verify rs_a_check claimed_sum = rs_a(alpha3) = claimed_values[6]
    // This ensures the RS encoding is correct: sum_x alpha3_mat_g_n(x) * a(x)
    // should equal rs_a(alpha3)
    if rs_a_check_claimed_sum != claimed_values[6] {
        return Ok(false);
    }

    // Note: The RS encoding identity states that for RS codeword c = RS(a):
    // sum_x alpha3_mat_g_n(x) * a(x) = c(alpha3)
    // where alpha3_mat_g_n encodes the generator matrix evaluation.

    // Verify rs_a_check subclaim: alpha3_mat_g_n(r6) * a(r6) = expected
    // claimed_values[1] = a(r6) (point 1 targets a)
    let a_r6 = claimed_values[1];
    let alpha3_mat_g = compute_alpha_mat_g(log_rs_len, log_n, &g, &alpha3);
    let alpha3_mat_g_n_r6 =
        eval_vec_at_ext_point::<F>(&alpha3_mat_g[log_rs_len][..n].to_vec(), &r6_ext);
    let rs_a_check_computed = alpha3_mat_g_n_r6 * a_r6;
    if rs_a_check_computed != rs_a_check_expected {
        return Ok(false);
    }

    // Get base field version for subsequent computations
    let r6: Vec<F> = r6_ext.iter().map(|x| F::ext_real(x)).collect();

    // Step 7.2: Verify mat_g checks
    let mut cur_p = vec![r6.clone(), vec![F::ZERO; log_rs_len - log_n]].concat();
    for i in (2..=log_rs_len).rev() {
        let mat_g_check_proof = &mat_g_check_proofs[log_rs_len - i];

        // Verify extension field SumCheck
        let (mat_g_point_ext, mat_g_expected, _mat_g_claimed_sum) =
            verify_ext_sumcheck_with_subclaim::<F>(
                mat_g_check_proof,
                i - 1,
                3, // max_degree = 3
                transcript,
            )?;

        // Verify mat_g subclaim: tensor_x(mat_g_point) * alpha3_mat_g[i-1](mat_g_point)
        // * w(mat_g_point) = expected
        let (x, b) = (cur_p[..i - 1].to_vec(), cur_p[i - 1]);
        let gi = g.pow([1u64 << (log_rs_len - i)]);
        let w: Vec<F> = (0..1 << (i - 1))
            .map(|z| {
                F::ONE - alpha3[log_rs_len - i]
                    + alpha3[log_rs_len - i]
                        * (gi.pow([z]) * (F::ONE - b) + gi.pow([z + (1 << (i - 1))]) * b)
            })
            .collect();

        let tensor_x_eval = eval_tensor_at_ext_point::<F>(&x, &mat_g_point_ext);
        let alpha3_mat_g_eval = eval_vec_at_ext_point::<F>(&alpha3_mat_g[i - 1], &mat_g_point_ext);
        let w_eval = eval_vec_at_ext_point::<F>(&w, &mat_g_point_ext);
        let mat_g_computed = tensor_x_eval * alpha3_mat_g_eval * w_eval;
        if mat_g_computed != mat_g_expected {
            return Ok(false);
        }

        // Use real part of extension field point for next iteration
        cur_p = mat_g_check_proof
            .ext_proof
            .point
            .iter()
            .map(|x| F::ext_real(x))
            .collect();
    }

    // Step 8: Get r2, r3
    let r2 = transcript.get_and_append_challenge_vectors(b"r2", s_lambda.ilog2() as usize)?;
    let r3 = transcript.get_and_append_challenge_vectors(b"r3", (2 * n).ilog2() as usize)?;

    // Convert r2 to extension field early (needed for bI chunk combining)
    let r2_ext: Vec<F::Extension> = r2.iter().map(|&x| F::Extension::from_base(x)).collect();

    // Step 9: Verify extension field SumCheck for alpha2_a_bI_r2 check
    // This proves: sum_x alpha2_a(x) * bI_r2(x) = <alpha2, H * r2_on_I>
    let (r4_ext, alpha2_a_bI_r2_expected, _alpha2_a_bI_r2_claimed_sum) =
        verify_ext_sumcheck_with_subclaim::<F>(
            &alpha2_a_bI_r2_check_proof,
            (m * eta).ilog2() as usize,
            2, // max_degree = 2
            transcript,
        )?;

    // Verify alpha2_a_bI_r2 subclaim: alpha2_a(r4) * bI_r2(r4) = expected
    // claimed_values[8] = mat_a(r4, alpha2) = alpha2_a(r4) (point 8 targets mat_a)
    // claimed_values[3] = bI(r2, r4) = bI_r2(r4) (point 3 targets bI)
    let alpha2_a_r4 = claimed_values[8];
    let bI_r2_r4 = claimed_values[3];
    let alpha2_a_bI_r2_computed = alpha2_a_r4 * bI_r2_r4;
    if alpha2_a_bI_r2_computed != alpha2_a_bI_r2_expected {
        return Ok(false);
    }

    // Step 10: Verify extension field SumCheck for v_bI_r2 check
    // This proves: sum_x v(x) * bI_r2(x) = <v, F'[:,I] * r2>
    let (r5_ext, v_bI_r2_expected, _v_bI_r2_claimed_sum) = verify_ext_sumcheck_with_subclaim::<F>(
        &v_bI_r2_check_proof,
        (m * eta).ilog2() as usize,
        2,
        transcript,
    )?;

    // Verify v_bI_r2 subclaim: v(r5) * bI_r2(r5) = expected
    // v = tensor(z1) ⊗ [1, 2, 4, ..., 2^(eta-1)]
    // v(r5) can be computed from z1
    // claimed_values[4] = bI(r2, r5) = bI_r2(r5) (point 4 targets bI)
    let v: Vec<F> = otimes(
        &get_tensor(&z1),
        &(0..eta)
            .map(|i| F::from(2u64).pow([i as u64]))
            .collect::<Vec<_>>(),
    );
    let v_r5 = eval_vec_at_ext_point::<F>(&v, &r5_ext);
    let bI_r2_r5 = claimed_values[4];
    let v_bI_r2_computed = v_r5 * bI_r2_r5;
    if v_bI_r2_computed != v_bI_r2_expected {
        return Ok(false);
    }

    // Step 11: Multi-chunked batch verify at extension field points
    // Convert base field points to extension field
    let z2_ext: Vec<F::Extension> = z2.iter().map(|&x| F::Extension::from_base(x)).collect();
    let r3_ext: Vec<F::Extension> = r3.iter().map(|&x| F::Extension::from_base(x)).collect();
    let alpha2_ext: Vec<F::Extension> =
        alpha2.iter().map(|&x| F::Extension::from_base(x)).collect();
    let alpha3_ext: Vec<F::Extension> =
        alpha3.iter().map(|&x| F::Extension::from_base(x)).collect();

    // Build commitments vector (combined com_a_bI_rsa, then mat_h, mat_a)
    let commitments: Vec<&DeepFoldBatchMultiCommitment> =
        vec![&com_a_bI_rsa, &com_mat_h, &com_mat_a];

    // Build points in extension field matching open order
    let bI_r2_r4_point: Vec<F::Extension> = vec![r2_ext.clone(), r4_ext.clone()].concat();
    let bI_r2_r5_point: Vec<F::Extension> = vec![r2_ext.clone(), r5_ext.clone()].concat();
    let mat_h_full_point_ext: Vec<F::Extension> = vec![r3_ext.clone(), alpha2_ext.clone()].concat();
    let mat_a_point_ext: Vec<F::Extension> = vec![r4_ext.clone(), alpha2_ext.clone()].concat();

    let points_ext: Vec<Vec<F::Extension>> = vec![
        z2_ext.clone(),       // point 0 -> com_a_bI_rsa
        r6_ext.clone(),       // point 1 -> com_a_bI_rsa
        r1_ext.clone(),       // point 2 -> com_a_bI_rsa
        bI_r2_r4_point,       // point 3 -> com_a_bI_rsa
        bI_r2_r5_point,       // point 4 -> com_a_bI_rsa
        r3_ext.clone(),       // point 5 -> com_a_bI_rsa
        alpha3_ext.clone(),   // point 6 -> com_a_bI_rsa
        mat_h_full_point_ext, // point 7 -> mat_h
        mat_a_point_ext,      // point 8 -> mat_a
    ];

    // Check that the first evaluation (a at z2) equals the claimed value in
    // extension field claimed_values[0] = a(z2) (point 0 targets a)
    if F::ext_real(&claimed_values[0]) != *value {
        return Ok(false);
    }

    if !multi_chunked_batch_verify_at_ext_point(
        &deepfold_verifier_param,
        &commitments,
        &points_ext,
        &deepfold_batched_proof,
        transcript,
    )? {
        return Ok(false);
    }

    Ok(true)
}

/// Helper to verify extension field SumCheck and return subclaim
/// Returns (extension field point, expected evaluation at that point,
/// claimed_sum)
#[allow(non_snake_case)]
fn verify_ext_sumcheck_with_subclaim<F: PrimeField + HasQuadraticExtension>(
    proof: &ExtSumCheckWithReductionProof<F>,
    num_vars: usize,
    max_degree: usize,
    transcript: &mut IOPTranscript<F>,
) -> Result<(Vec<F::Extension>, F::Extension, F::Extension), PCSError> {
    // Extract the claimed sum from the proof
    let claimed_sum = if !proof.ext_proof.proofs.is_empty() {
        proof.ext_proof.proofs[0][0] + proof.ext_proof.proofs[0][1]
    } else {
        F::Extension::default()
    };

    // Verify extension field SumCheck and get subclaim
    let ext_subclaim = ext_sumcheck_verify::<F, F::Extension>(
        claimed_sum,
        &proof.ext_proof,
        num_vars,
        max_degree,
        transcript,
    )?;

    // Return the extension field point, the expected evaluation, and the claimed
    // sum
    Ok((
        proof.ext_proof.point.clone(),
        ext_subclaim.expected_evaluation,
        claimed_sum,
    ))
}

/// Helper to resize extension field point
fn resize_point_ext<F: PrimeField + HasQuadraticExtension>(
    point: &[F::Extension],
    target_len: usize,
) -> Vec<F::Extension> {
    let mut result = point.to_vec();
    while result.len() < target_len {
        result.push(F::Extension::from_base(F::ZERO));
    }
    result
}

/// Evaluate tensor product polynomial at extension field point
fn eval_tensor_at_ext_point<F: PrimeField + HasQuadraticExtension>(
    vars: &[F],
    point: &[F::Extension],
) -> F::Extension {
    let tensor = get_tensor(&vars.to_vec());
    eval_vec_at_ext_point::<F>(&tensor, point)
}

/// Evaluate a vector (as MLE) at extension field point
fn eval_vec_at_ext_point<F: PrimeField + HasQuadraticExtension>(
    evals: &[F],
    point: &[F::Extension],
) -> F::Extension {
    let n = point.len();
    if n == 0 {
        return F::Extension::from_base(evals[0]);
    }

    // Compute tensor product of (1-x_i, x_i) for all coordinates
    let mut tensor = vec![F::Extension::from_base(F::ONE); 1 << n];
    for (i, &pi) in point.iter().enumerate() {
        let half = 1 << i;
        for j in 0..half {
            tensor[j + half] = tensor[j] * pi;
            tensor[j] = tensor[j] * (F::Extension::from_base(F::ONE) - pi);
        }
    }

    // Dot product
    let mut result = F::Extension::default();
    for (i, &eval) in evals.iter().enumerate() {
        if i < tensor.len() {
            result = result + tensor[i] * F::Extension::from_base(eval);
        }
    }
    result
}

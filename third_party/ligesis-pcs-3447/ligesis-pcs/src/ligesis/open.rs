//! Ligesis open functions
//!
//! This module contains the open implementations for Ligesis PCS:
//! - `ligesis_open`: Extension field SumCheck with 128-bit security
//! - `ligesis_d_open`: Distributed open with 128-bit security

use crate::{
    deepfold::{
        chunked_batch_commit, d_chunked_batch_commit, d_multi_chunked_batch_open_at_ext_point,
        multi_chunked_batch_open_at_ext_point, DeepFoldBatchMultiCommitment,
        DeepFoldBatchMultiProverAdvice, *,
    },
    errors::PCSError,
    ext_sumcheck::ExtSumCheckBuilder,
    rscode::*,
    types::{FieldExtension, HasQuadraticExtension},
    utils::*,
    PolynomialCommitmentScheme,
};
use arithmetic::math::Math;
use ark_ff::PrimeField;
use ark_poly::DenseMultilinearExtension;
use ark_std::{end_timer, start_timer, sync::Arc, vec::Vec};
use transcript::IOPTranscript;

use deNetwork::{DeMultiNet as Net, DeNet, DeSerNet};

use super::{
    ExtSumCheckWithReductionProof, LigeSISProof, LigeSISProverCommitmentAdvice, LigeSISProverParam,
};

/// Ligesis open with extension field SumCheck (128-bit security)
/// Uses extension field SumCheck and multi-chunked batch opening in DeepFold
#[allow(non_snake_case)]
pub fn ligesis_open<F: PrimeField + HasQuadraticExtension>(
    prover_param: &LigeSISProverParam<F>,
    poly: &Arc<DenseMultilinearExtension<F>>,
    advice: &LigeSISProverCommitmentAdvice<F>,
    point: &[F],
    transcript: &mut IOPTranscript<F>,
) -> Result<LigeSISProof<F>, PCSError> {
    let LigeSISProverParam {
        eta,
        s_lambda,
        mu,
        log_m,
        log_n,
        c,
        ref rs,
        ref mat_a,
        ref mat_a_pad,
        ref mat_a_advice,
        ref deepfold_prover_param,
    } = *prover_param;
    let _ = mat_a_pad; // Suppress unused warnings
    let (m, n) = (1 << log_m, 1 << log_n);
    let rs_len = rs.get_k();
    let log_rs_len = rs_len.ilog2() as usize;

    assert_eq!(mu, log_m + log_n);
    assert!(poly.num_vars <= mu);

    // Pad polynomial and point if needed
    let poly_evals = if poly.num_vars < mu {
        resize_eval(&poly.evaluations, mu)
    } else {
        poly.evaluations.clone()
    };
    let point = resize_point(&point.to_vec(), mu);

    let mat_f = reshape(&poly_evals, m, n);

    let LigeSISProverCommitmentAdvice {
        mat_f_prime,
        mat_h: _,
        ref mat_h_advice,
    } = advice;

    // Step 1
    let (z1, z2) = (point[log_n..].to_vec(), point[..log_n].to_vec());
    let eq_z1 = get_tensor(&z1);

    // Step 2: Compute a
    let a: Vec<F> = (0..n)
        .map(|j| (0..m).map(|i| eq_z1[i] * mat_f[i][j]).sum())
        .collect();
    let a_poly = evals_to_arcpoly(&a);

    // Step 3: Get challenge indices I
    let I = transcript.get_and_append_challenge_indices(b"I", s_lambda, 2 * n)?;

    // Step 4: Compute bI
    let mat_f_prime_trans = transposition(mat_f_prime);
    let mat_bI = transposition(
        &I.iter()
            .map(|&i| decompose_vector(&mat_f_prime_trans[i]))
            .collect::<Vec<_>>(),
    );
    let bI_field = bool_vec_to_field_vec(&mat_bI.concat());
    let bI_poly = evals_to_arcpoly(&bI_field);

    // Step 5: Get challenges
    let alpha1 = transcript
        .get_and_append_challenge_vectors(b"alpha1", (m * eta * s_lambda).ilog2() as usize)?;
    let alpha2 = transcript.get_and_append_challenge_vectors(b"alpha2", c.ilog2() as usize)?;
    let alpha3 = transcript.get_and_append_challenge_vectors(b"alpha3", log_rs_len)?;

    // Step 6: Compute rs_a
    let rs_a = rs.encode(&a);
    let g = rs.get_generator();
    let rs_a_poly = evals_to_arcpoly(&rs_a);

    // Step 7: Combined commit for a, bI, rs_a (single Merkle tree)
    let timer = start_timer!(|| "Ligesis.Open.CombinedCommit");
    let (com_a_bI_rsa, com_a_bI_rsa_advice) = chunked_batch_commit(
        deepfold_prover_param,
        &[a_poly.clone(), bI_poly.clone(), rs_a_poly.clone()],
    )?;
    end_timer!(timer);

    // Step 8: Extension field SumCheck for bI check (moved after commit)
    let timer = start_timer!(|| "Ligesis.Open.ExtSumchecks");
    let bI_field_minus_one: Vec<F> = bI_field.iter().map(|&x| x - F::ONE).collect();
    let tensor_alpha1 = get_tensor(&alpha1);

    let bI_check_proof = run_ext_sumcheck::<F>(
        bI_field.len().ilog2() as usize,
        vec![&bI_field[..], &bI_field_minus_one[..], &tensor_alpha1[..]],
        F::ONE,
        transcript,
    )?;
    let r1_ext = bI_check_proof.ext_proof.point.clone();

    // Step 7.1: Extension field SumCheck for rs_a check
    let alpha3_mat_g = compute_alpha_mat_g(log_rs_len, log_n, &g, &alpha3);
    let alpha3_mat_g_n = alpha3_mat_g[log_rs_len][..n].to_vec();

    let rs_a_check_proof =
        run_ext_sumcheck::<F>(log_n, vec![&alpha3_mat_g_n[..], &a[..]], F::ONE, transcript)?;
    let r6_ext = rs_a_check_proof.ext_proof.point.clone();
    // Get base field version for subsequent computations
    let r6: Vec<F> = r6_ext.iter().map(|x| F::ext_real(x)).collect();

    // Step 7.2: Extension field SumChecks for mat_g checks
    let mut cur_p = vec![r6.clone(), vec![F::ZERO; log_rs_len - log_n]].concat();
    let mut mat_g_check_proofs = Vec::new();
    for i in (2..=log_rs_len).rev() {
        let (x, b) = (cur_p[..i - 1].to_vec(), cur_p[i - 1]);
        let gi = g.pow([1u64 << (log_rs_len - i)]);
        let w: Vec<F> = (0..1 << (i - 1))
            .map(|z| {
                F::ONE - alpha3[log_rs_len - i]
                    + alpha3[log_rs_len - i]
                        * (gi.pow([z]) * (F::ONE - b) + gi.pow([z + (1 << (i - 1))]) * b)
            })
            .collect();
        let tensor_x = get_tensor(&x);

        let mat_g_check_proof = run_ext_sumcheck::<F>(
            i - 1,
            vec![&tensor_x[..], &alpha3_mat_g[i - 1][..], &w[..]],
            F::ONE,
            transcript,
        )?;

        // Use real part of extension field point for next iteration
        cur_p = mat_g_check_proof
            .ext_proof
            .point
            .iter()
            .map(|x| F::ext_real(x))
            .collect();
        mat_g_check_proofs.push(mat_g_check_proof);
    }

    // Step 8
    let v = otimes(
        &get_tensor(&z1),
        &(0..eta)
            .map(|i| F::from(2u64).pow([i as u64]))
            .collect::<Vec<_>>(),
    );

    let r2 = transcript.get_and_append_challenge_vectors(b"r2", s_lambda.ilog2() as usize)?;
    let r3 = transcript.get_and_append_challenge_vectors(b"r3", (2 * n).ilog2() as usize)?;

    // Step 9: Extension field SumCheck for alpha2_a_bI_r2 check
    let alpha2_a = mat_mul(&vec![get_tensor(&alpha2)], mat_a)[0].clone();
    let bI_r2 = field_mat_mul_bool_mat(&vec![get_tensor(&r2)], &transposition(&mat_bI))[0].clone();

    let alpha2_a_bI_r2_check_proof = run_ext_sumcheck::<F>(
        mat_bI.len().ilog2() as usize,
        vec![&alpha2_a[..], &bI_r2[..]],
        F::ONE,
        transcript,
    )?;
    let r4_ext = alpha2_a_bI_r2_check_proof.ext_proof.point.clone();

    // Step 10: Extension field SumCheck for v_bI_r2 check
    let v_bI_r2_check_proof = run_ext_sumcheck::<F>(
        v.len().ilog2() as usize,
        vec![&v[..], &bI_r2[..]],
        F::ONE,
        transcript,
    )?;
    let r5_ext = v_bI_r2_check_proof.ext_proof.point.clone();
    end_timer!(timer);

    // Step 11: Multi-chunked batch open at extension field points
    // Convert base field points to extension field
    let z2_ext: Vec<F::Extension> = z2.iter().map(|&x| F::Extension::from_base(x)).collect();
    let r3_ext: Vec<F::Extension> = r3.iter().map(|&x| F::Extension::from_base(x)).collect();
    let alpha2_ext: Vec<F::Extension> =
        alpha2.iter().map(|&x| F::Extension::from_base(x)).collect();
    let alpha3_ext: Vec<F::Extension> =
        alpha3.iter().map(|&x| F::Extension::from_base(x)).collect();
    let r2_ext: Vec<F::Extension> = r2.iter().map(|&x| F::Extension::from_base(x)).collect();

    // Build advices and points for multi_chunked_batch_open_at_ext_point
    // Commitments are (in order): com_a_bI_rsa (3 polys: a=0, bI=1, rs_a=2), mat_h,
    // mat_a Points mapping:
    //   0: z2 -> com_a_bI_rsa (index 0), evaluates a[0], bI[1], rs_a[2]
    //   1: r6 -> com_a_bI_rsa (index 0), evaluates a[0], bI[1], rs_a[2]
    //   2: r1 -> com_a_bI_rsa (index 0), evaluates a[0], bI[1], rs_a[2]
    //   3: (r2, r4) -> com_a_bI_rsa (index 0), evaluates a[0], bI[1], rs_a[2]
    //   4: (r2, r5) -> com_a_bI_rsa (index 0), evaluates a[0], bI[1], rs_a[2]
    //   5: r3 -> com_a_bI_rsa (index 0), evaluates a[0], bI[1], rs_a[2]
    //   6: alpha3 -> com_a_bI_rsa (index 0), evaluates a[0], bI[1], rs_a[2]
    //   7: (r3, alpha2) -> mat_h (index 1)
    //   8: (r4, alpha2) -> mat_a (index 2)

    // Use mat_a_advice from setup (no need to re-commit)
    let advices: Vec<&DeepFoldBatchMultiProverAdvice<F>> =
        vec![&com_a_bI_rsa_advice, mat_h_advice, mat_a_advice];

    // Build points in extension field
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

    // All first 7 points go to combined commit (index 0), mat_h to index 1, mat_a
    // to index 2
    let point_to_commit: Vec<usize> = vec![0, 0, 0, 0, 0, 0, 0, 1, 2];
    // Which polynomial within each commitment: a=0, bI=1, rs_a=2 for commit 0;
    // single poly (0) for commits 1,2 Point 0,1: a; Point 2,3,4: bI; Point 5,6:
    // rs_a; Point 7: mat_h; Point 8: mat_a
    let point_to_poly: Vec<usize> = vec![0, 0, 1, 1, 1, 2, 2, 0, 0];

    let timer = start_timer!(|| "Ligesis.Open.DeepFold");
    let deepfold_batched_proof = multi_chunked_batch_open_at_ext_point(
        deepfold_prover_param,
        &advices,
        &points_ext,
        &point_to_commit,
        &point_to_poly,
        transcript,
    )?;
    end_timer!(timer);

    Ok(LigeSISProof {
        com_a_bI_rsa,
        bI_check_proof,
        alpha2_a_bI_r2_check_proof,
        v_bI_r2_check_proof,
        rs_a_check_proof,
        mat_g_check_proofs,
        deepfold_batched_proof,
    })
}

/// Helper function to run extension field SumCheck (no reduction needed)
#[allow(non_snake_case)]
fn run_ext_sumcheck<F: PrimeField + HasQuadraticExtension>(
    num_vars: usize,
    evals_list: Vec<&[F]>,
    coeff: F,
    transcript: &mut IOPTranscript<F>,
) -> Result<ExtSumCheckWithReductionProof<F>, PCSError> {
    // Build and run extension field SumCheck
    let mut builder = ExtSumCheckBuilder::<F, F::Extension>::new(num_vars);
    let mles: Vec<Arc<DenseMultilinearExtension<F>>> = evals_list
        .iter()
        .map(|evals| evals_to_arcpoly(&evals.to_vec()))
        .collect();
    builder = builder.add_mle_list(mles, coeff)?;
    let ext_proof = builder.prove(transcript)?;

    Ok(ExtSumCheckWithReductionProof { ext_proof })
}

/// Distributed helper function to run extension field SumCheck
/// Each party provides their local portion of the evaluations.
/// Returns Some(proof) on master, None on workers.
#[allow(non_snake_case)]
fn d_run_ext_sumcheck<F: PrimeField + HasQuadraticExtension>(
    local_num_vars: usize,
    evals_list: Vec<&[F]>,
    coeff: F,
    transcript: &mut IOPTranscript<F>,
) -> Result<Option<ExtSumCheckWithReductionProof<F>>, PCSError> {
    // Build and run distributed extension field SumCheck
    let mut builder = ExtSumCheckBuilder::<F, F::Extension>::new(local_num_vars);
    let mles: Vec<Arc<DenseMultilinearExtension<F>>> = evals_list
        .iter()
        .map(|evals| evals_to_arcpoly(&evals.to_vec()))
        .collect();
    builder = builder.add_mle_list(mles, coeff)?;
    let ext_proof_opt = builder.d_prove(transcript)?;

    Ok(ext_proof_opt.map(|ext_proof| ExtSumCheckWithReductionProof { ext_proof }))
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

/// Compute the local portion of tensor for distributed sumcheck.
/// For party k, computes: tensor_local[b_low] = get_tensor(alpha_low)[b_low] *
/// eq(k, alpha_high) where alpha is split into alpha_low (local variables) and
/// alpha_high (party selection variables).
fn compute_local_tensor<F: PrimeField>(
    alpha: &[F],
    local_num_vars: usize,
    party_id: usize,
) -> Vec<F> {
    let alpha_low: Vec<F> = alpha[..local_num_vars].to_vec();
    let alpha_high = &alpha[local_num_vars..];

    // Compute base tensor for local variables
    let tensor_low = get_tensor(&alpha_low);

    // Compute eq(party_id, alpha_high) = prod_i ((1-k_i)(1-alpha_high_i) +
    // k_i*alpha_high_i)
    let mut eq_factor = F::ONE;
    for (i, &alpha_i) in alpha_high.iter().enumerate() {
        let k_i = ((party_id >> i) & 1) as u64;
        if k_i == 0 {
            eq_factor *= F::ONE - alpha_i;
        } else {
            eq_factor *= alpha_i;
        }
    }

    // Scale the tensor by eq_factor
    tensor_low.into_iter().map(|t| t * eq_factor).collect()
}

/// Distributed Ligesis open with 128-bit security
/// Uses extension field SumCheck and direct extension field opening in DeepFold
#[allow(non_snake_case)]
pub fn ligesis_d_open<F: PrimeField + HasQuadraticExtension>(
    prover_param: &LigeSISProverParam<F>,
    poly: &Arc<DenseMultilinearExtension<F>>,
    advice: &LigeSISProverCommitmentAdvice<F>,
    point: &[F],
    transcript: &mut IOPTranscript<F>,
) -> Result<Option<LigeSISProof<F>>, PCSError> {
    let &LigeSISProverParam {
        eta,
        s_lambda,
        mu,
        log_m,
        log_n,
        c,
        ref rs,
        ref mat_a,
        ref mat_a_pad,
        ref mat_a_advice,
        ref deepfold_prover_param,
    } = prover_param;
    let _ = mat_a_pad; // Suppress unused warnings
    let num_party = Net::n_parties();
    let num_party_vars = Net::n_parties().log_2() as usize;
    let (m, n) = (1 << log_m, 1 << log_n);
    let rs_len = rs.get_k();
    let log_rs_len = rs_len.ilog2() as usize;
    let _local_poly_size = (1 << deepfold_prover_param.max_mu) / num_party;

    assert_eq!(mu, log_m + log_n);
    assert!(poly.num_vars <= mu - num_party_vars);

    // Pad point if needed
    let point = resize_point(&point.to_vec(), mu);

    let mat_f = reshape(&poly.evaluations, m / num_party, n);

    let LigeSISProverCommitmentAdvice {
        mat_f_prime,
        mat_h: _,
        ref mat_h_advice,
    } = advice;

    // Step 1
    let (z1, z2) = (point[log_n..].to_vec(), point[..log_n].to_vec());
    let (z1_0, z1_1) = (
        z1[log_m - num_party_vars..].to_vec(),
        z1[..log_m - num_party_vars].to_vec(),
    );
    let eq_z1_1 = get_tensor(&z1_1);
    let eq_z1_0 = get_tensor(&z1_0);

    // Step 2: Compute a (gather, then split and distribute for commit)
    Net::barrier();
    let timer = start_timer!(|| "DLigesis.Open.ComputeA");
    let a_k = (0..n)
        .map(|j| (0..m / num_party).map(|i| eq_z1_1[i] * mat_f[i][j]).sum())
        .collect::<Vec<F>>();
    let a_k_list = Net::send_to_master(&a_k);

    // Master computes full a (kept for later sumchecks)
    let a_full: Vec<F> = if Net::am_master() {
        let a_k_list = a_k_list.ok_or(PCSError::UnexpectedNone("a_k_list".into()))?;
        (0..n)
            .map(|j| (0..num_party).map(|k| eq_z1_0[k] * a_k_list[k][j]).sum())
            .collect()
    } else {
        vec![]
    };

    // Split and distribute a to all parties (each gets 1/num_party portion)
    let a_local: Vec<F> = if Net::am_master() {
        let portion_size = n / num_party;
        let portions: Vec<Vec<F>> = (0..num_party)
            .map(|k| a_full[k * portion_size..(k + 1) * portion_size].to_vec())
            .collect();
        Net::recv_from_master(Some(portions))
    } else {
        Net::recv_from_master(None)
    };
    let a_poly = evals_to_arcpoly(&a_local);
    end_timer!(timer);

    // Step 3: receive challenge indices
    let I = if Net::am_master() {
        let I = transcript.get_and_append_challenge_indices(b"I", s_lambda, 2 * n)?;
        Net::recv_from_master_uniform(Some(I.clone()));
        I
    } else {
        Net::recv_from_master_uniform(None)
    };

    // Step 4: Compute bI (gather, then split and distribute for commit)
    Net::barrier();
    let timer = start_timer!(|| "DLigesis.Open.ComputeBI");
    let mat_bI_k = {
        let mat_f_prime_trans = transposition(&mat_f_prime);
        transposition(
            &I.iter()
                .map(|&i| decompose_vector(&mat_f_prime_trans[i]))
                .collect::<Vec<_>>(),
        )
    };
    let mat_bI_k_list = Net::send_to_master(&mat_bI_k);

    // On master: compute full bI (kept for later sumchecks)
    let mat_bI_full: Vec<Vec<bool>> = if Net::am_master() {
        let mat_bI_k_list =
            mat_bI_k_list.ok_or(PCSError::UnexpectedNone("mat_bI_k_list".into()))?;
        mat_bI_k_list.concat()
    } else {
        vec![]
    };

    // Split and distribute bI to all parties
    // bI has shape (m * eta) x s_lambda, flattened size = m * eta * s_lambda
    let bI_field_full: Vec<F> = if Net::am_master() {
        bool_vec_to_field_vec(&mat_bI_full.concat())
    } else {
        vec![]
    };
    let bI_local: Vec<F> = if Net::am_master() {
        let bI_size = bI_field_full.len();
        let portion_size = bI_size / num_party;
        let portions: Vec<Vec<F>> = (0..num_party)
            .map(|k| bI_field_full[k * portion_size..(k + 1) * portion_size].to_vec())
            .collect();
        Net::recv_from_master(Some(portions))
    } else {
        Net::recv_from_master(None)
    };
    let bI_poly = evals_to_arcpoly(&bI_local);
    end_timer!(timer);

    // Step 5: receive challenge vectors
    let (alpha1, alpha2, alpha3) = if Net::am_master() {
        let alpha1 = transcript
            .get_and_append_challenge_vectors(b"alpha1", (m * eta * s_lambda).ilog2() as usize)?;
        let alpha2 = transcript.get_and_append_challenge_vectors(b"alpha2", c.ilog2() as usize)?;
        let alpha3 = transcript.get_and_append_challenge_vectors(b"alpha3", log_rs_len)?;
        Net::recv_from_master_uniform(Some((alpha1.clone(), alpha2.clone(), alpha3.clone())));
        (alpha1, alpha2, alpha3)
    } else {
        Net::recv_from_master_uniform(None)
    };

    // Step 6: Compute rs_a (split and distribute for commit)
    Net::barrier();
    let timer = start_timer!(|| "DLigesis.Open.ComputeRSA");
    let rs_a_full: Vec<F> = if Net::am_master() {
        rs.encode(&a_full)
    } else {
        vec![]
    };
    // Split and distribute rs_a to all parties
    let rs_a_local: Vec<F> = if Net::am_master() {
        let rs_a_size = rs_a_full.len();
        let portion_size = rs_a_size / num_party;
        let portions: Vec<Vec<F>> = (0..num_party)
            .map(|k| rs_a_full[k * portion_size..(k + 1) * portion_size].to_vec())
            .collect();
        Net::recv_from_master(Some(portions))
    } else {
        Net::recv_from_master(None)
    };
    let rs_a_poly = evals_to_arcpoly(&rs_a_local);
    end_timer!(timer);

    // Step 7: Combined d_chunked_batch_commit for a, bI, rs_a (single Merkle tree)
    Net::barrier();
    let timer = start_timer!(|| "DLigesis.Open.CombinedCommit");
    let (com_a_bI_rsa_opt, com_a_bI_rsa_advice) = d_chunked_batch_commit(
        deepfold_prover_param,
        &[a_poly.clone(), bI_poly.clone(), rs_a_poly.clone()],
    )?;
    let com_a_bI_rsa = if Net::am_master() {
        com_a_bI_rsa_opt.unwrap()
    } else {
        DeepFoldBatchMultiCommitment::default()
    };
    end_timer!(timer);

    // Step 8: Extension field SumCheck for bI check (distributed)
    Net::barrier();
    let timer = start_timer!(|| "DLigesis.Open.ExtSumchecks");

    // bI check sumcheck: sum_{x} bI(x) * (bI(x) - 1) * eq(x, alpha1) = 0
    // Each party has bI_local and can compute their local portion of the sumcheck
    let local_bI_num_vars = bI_local.len().ilog2() as usize;
    let bI_local_minus_one: Vec<F> = bI_local.iter().map(|&x| x - F::ONE).collect();
    let tensor_alpha1_local = compute_local_tensor(&alpha1, local_bI_num_vars, Net::party_id());

    let bI_check_proof_opt = d_run_ext_sumcheck::<F>(
        local_bI_num_vars,
        vec![
            &bI_local[..],
            &bI_local_minus_one[..],
            &tensor_alpha1_local[..],
        ],
        F::ONE,
        transcript,
    )?;

    let (bI_check_proof, r1_ext) = if Net::am_master() {
        let proof = bI_check_proof_opt.unwrap();
        let r1 = proof.ext_proof.point.clone();
        Net::recv_from_master_uniform(Some(r1.clone()));
        (proof, r1)
    } else {
        let r1: Vec<F::Extension> = Net::recv_from_master_uniform(None);
        (
            ExtSumCheckWithReductionProof {
                ext_proof: crate::ext_sumcheck::ExtSumCheckProof::default(),
            },
            r1,
        )
    };

    // Step 9: Extension field SumChecks for rs_a and mat_g checks (on master)
    let g = rs.get_generator();
    let (rs_a_check_proof, r6_ext, mat_g_check_proofs) = if Net::am_master() {
        // Step 9.1: Extension field SumCheck for rs_a check
        let alpha3_mat_g = compute_alpha_mat_g(log_rs_len as usize, log_n, &g, &alpha3);
        let alpha3_mat_g_n = alpha3_mat_g[log_rs_len][..n].to_vec();
        let rs_a_check_proof = run_ext_sumcheck::<F>(
            log_n,
            vec![&alpha3_mat_g_n[..], &a_full[..]],
            F::ONE,
            transcript,
        )?;
        let r6_ext = rs_a_check_proof.ext_proof.point.clone();
        let r6: Vec<F> = r6_ext.iter().map(|x| F::ext_real(x)).collect();

        // Step 9.2: Extension field SumChecks for mat_g checks
        let mut cur_p = vec![r6.clone(), vec![F::ZERO; log_rs_len - log_n]].concat();
        let mut mat_g_check_proofs = Vec::new();
        for i in (2..=log_rs_len).rev() {
            let (x, b) = (cur_p[..i - 1].to_vec(), cur_p[i - 1]);
            let gi = g.pow([1u64 << (log_rs_len - i)]);
            let w: Vec<F> = (0..1 << (i - 1))
                .map(|z| {
                    F::ONE - alpha3[log_rs_len - i]
                        + alpha3[log_rs_len - i]
                            * (gi.pow([z]) * (F::ONE - b) + gi.pow([z + (1 << (i - 1))]) * b)
                })
                .collect();
            let tensor_x = get_tensor(&x);
            let mat_g_check_proof = run_ext_sumcheck::<F>(
                i - 1,
                vec![&tensor_x[..], &alpha3_mat_g[i - 1][..], &w[..]],
                F::ONE,
                transcript,
            )?;
            cur_p = mat_g_check_proof
                .ext_proof
                .point
                .iter()
                .map(|x| F::ext_real(x))
                .collect();
            mat_g_check_proofs.push(mat_g_check_proof);
        }

        (rs_a_check_proof, r6_ext, mat_g_check_proofs)
    } else {
        (
            ExtSumCheckWithReductionProof {
                ext_proof: crate::ext_sumcheck::ExtSumCheckProof::default(),
            },
            vec![],
            vec![],
        )
    };
    end_timer!(timer);

    // Step 8
    let (r2, r3, v, alpha2_a_bI_r2_check_proof, r4_ext, v_bI_r2_check_proof, r5_ext) =
        if Net::am_master() {
            let v = otimes(
                &get_tensor(&z1),
                &(0..eta)
                    .map(|i| F::from(2u64).pow([i as u64]))
                    .collect::<Vec<_>>(),
            );
            let r2 =
                transcript.get_and_append_challenge_vectors(b"r2", s_lambda.ilog2() as usize)?;
            let r3 =
                transcript.get_and_append_challenge_vectors(b"r3", (2 * n).ilog2() as usize)?;

            // Step 9: Extension field SumCheck for alpha2_a_bI_r2 check
            let alpha2_a = mat_mul(&vec![get_tensor(&alpha2)], &mat_a)[0].clone();
            let bI_r2 =
                field_mat_mul_bool_mat(&vec![get_tensor(&r2)], &transposition(&mat_bI_full))[0]
                    .clone();
            let alpha2_a_bI_r2_check_proof = run_ext_sumcheck::<F>(
                mat_bI_full.len().ilog2() as usize,
                vec![&alpha2_a[..], &bI_r2[..]],
                F::ONE,
                transcript,
            )?;
            let r4_ext = alpha2_a_bI_r2_check_proof.ext_proof.point.clone();

            // Step 10: Extension field SumCheck for v_bI_r2 check
            let v_bI_r2_check_proof = run_ext_sumcheck::<F>(
                v.len().ilog2() as usize,
                vec![&v[..], &bI_r2[..]],
                F::ONE,
                transcript,
            )?;
            let r5_ext = v_bI_r2_check_proof.ext_proof.point.clone();

            (
                r2,
                r3,
                v,
                alpha2_a_bI_r2_check_proof,
                r4_ext,
                v_bI_r2_check_proof,
                r5_ext,
            )
        } else {
            (
                vec![],
                vec![],
                vec![],
                ExtSumCheckWithReductionProof {
                    ext_proof: crate::ext_sumcheck::ExtSumCheckProof::default(),
                },
                vec![],
                ExtSumCheckWithReductionProof {
                    ext_proof: crate::ext_sumcheck::ExtSumCheckProof::default(),
                },
                vec![],
            )
        };

    // Use mat_a_advice from setup (no need to re-commit)
    // Advices: com_a_bI_rsa (3 polys: a=0, bI=1, rs_a=2), mat_h, mat_a
    let advices: Vec<&DeepFoldBatchMultiProverAdvice<F>> =
        vec![&com_a_bI_rsa_advice, mat_h_advice, mat_a_advice];

    // Convert base field points to extension field
    let z2_ext: Vec<F::Extension> = z2.iter().map(|&x| F::Extension::from_base(x)).collect();
    let r3_ext: Vec<F::Extension> = r3.iter().map(|&x| F::Extension::from_base(x)).collect();
    let alpha2_ext: Vec<F::Extension> =
        alpha2.iter().map(|&x| F::Extension::from_base(x)).collect();
    let alpha3_ext: Vec<F::Extension> =
        alpha3.iter().map(|&x| F::Extension::from_base(x)).collect();
    let r2_ext: Vec<F::Extension> = r2.iter().map(|&x| F::Extension::from_base(x)).collect();

    // Build points in extension field
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

    // All first 7 points go to combined commit (index 0), mat_h to index 1, mat_a
    // to index 2
    let point_to_commit: Vec<usize> = vec![0, 0, 0, 0, 0, 0, 0, 1, 2];
    // Which polynomial within each commitment: a=0, bI=1, rs_a=2 for commit 0;
    // single poly (0) for commits 1,2 Point 0,1: a; Point 2,3,4: bI; Point 5,6:
    // rs_a; Point 7: mat_h; Point 8: mat_a
    let point_to_poly: Vec<usize> = vec![0, 0, 1, 1, 1, 2, 2, 0, 0];

    // Broadcast points to all parties
    let points_ext: Vec<Vec<F::Extension>> = if Net::am_master() {
        Net::recv_from_master_uniform(Some(points_ext.clone()));
        points_ext
    } else {
        Net::recv_from_master_uniform(None)
    };
    let point_to_commit: Vec<usize> = if Net::am_master() {
        Net::recv_from_master_uniform(Some(point_to_commit.clone()));
        point_to_commit
    } else {
        Net::recv_from_master_uniform(None)
    };
    let point_to_poly: Vec<usize> = if Net::am_master() {
        Net::recv_from_master_uniform(Some(point_to_poly.clone()));
        point_to_poly
    } else {
        Net::recv_from_master_uniform(None)
    };

    // Step 12: d_multi_chunked_batch_open at extension field points
    Net::barrier();
    let timer = start_timer!(|| "DLigesis.Open.DeepFold");

    let deepfold_batched_proof_opt = d_multi_chunked_batch_open_at_ext_point(
        deepfold_prover_param,
        &advices,
        &points_ext,
        &point_to_commit,
        &point_to_poly,
        transcript,
    )?;
    end_timer!(timer);

    if Net::am_master() {
        Ok(Some(LigeSISProof {
            com_a_bI_rsa,
            bI_check_proof,
            alpha2_a_bI_r2_check_proof,
            v_bI_r2_check_proof,
            rs_a_check_proof,
            mat_g_check_proofs,
            deepfold_batched_proof: deepfold_batched_proof_opt.unwrap(),
        }))
    } else {
        Ok(None)
    }
}

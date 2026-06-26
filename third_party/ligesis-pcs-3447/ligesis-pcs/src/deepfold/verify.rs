//! DeepFold verify functions
//!
//! This module contains the verify implementations for DeepFold PCS:
//! - `deepfold_verify`: Standard verify
//! - `deepfold_batch_verify`: Batched verify

use crate::{
    errors::PCSError, hash::*, utils::*,
    IOPProof, PolyIOP,
    sumcheck::SumCheck,
};
use arithmetic::VPAuxInfo;
use ark_ff::PrimeField;
use ark_std::{marker::PhantomData, vec::Vec};
use transcript::IOPTranscript;

use super::{
    DeepFoldBatchedProof, DeepFoldCommitment, DeepFoldProof, DeepFoldVerifierParam,
    utils::verify_merkle_tree_at_conjugate_points,
};

/// Standard DeepFold verify
#[allow(non_snake_case)]
pub fn deepfold_verify<F: PrimeField>(
    verifier_param: &DeepFoldVerifierParam<F>,
    com: &DeepFoldCommitment,
    point: &[F],
    value: &F,
    proof: &DeepFoldProof<F>,
    transcript: &mut IOPTranscript<F>,
) -> Result<bool, PCSError> {
    let DeepFoldVerifierParam {
        max_mu,
        len_l0,
        g,
        s,
    } = verifier_param.clone();
    let DeepFoldCommitment { mu, rt0 } = com.clone();
    assert!(mu <= max_mu);
    let DeepFoldProof {
        linear_polys,
        mt_roots,
        f_mu,
        mt_proofs,
    } = proof.clone();

    if rt0 != mt_roots[0] {
        eprintln!("VERIFY FAIL: rt0 != mt_roots[0]");
        return Ok(false);
    }

    let mut alpha = vec![F::ZERO];
    let mut r = vec![F::ZERO];

    for _ in 1..mu + 1 {
        alpha.push(transcript.get_and_append_challenge(b"alpha")?);
        r.push(transcript.get_and_append_challenge(b"r")?);
    }

    if eval_linear_poly(&linear_polys[0][0], &point[0]) != *value
        || eval_linear_poly(&linear_polys[mu - 1][0], &r[mu]) != f_mu
    {
        eprintln!("VERIFY FAIL: linear poly check");
        eprintln!(
            "  eval_linear_poly(&linear_polys[0][0], &point[0])={:?}",
            eval_linear_poly(&linear_polys[0][0], &point[0])
        );
        eprintln!("  value={:?}", value);
        eprintln!(
            "  eval_linear_poly(&linear_polys[mu - 1][0], &r[mu])={:?}",
            eval_linear_poly(&linear_polys[mu - 1][0], &r[mu])
        );
        eprintln!("  f_mu={:?}", f_mu);
        return Ok(false);
    }

    for i in 1..mu {
        for j in 0..linear_polys[i - 1].len() {
            let k = if i < mu - 1 { j } else { 0 };
            let w1 = if j == 0 {
                point[i]
            } else {
                alpha[j].pow([1 << (i + 1 - j) as u64])
            };
            if eval_linear_poly(&linear_polys[i - 1][j], &r[i])
                != eval_linear_poly(&linear_polys[i][k], &w1)
            {
                eprintln!(
                    "VERIFY FAIL: linear poly consistency check at i={}, j={}",
                    i, j
                );
                return Ok(false);
            }
        }
    }

    for t in 0..s {
        let mut beta = transcript.get_and_append_challenge_indices(b"beta", 1, len_l0)?[0];
        let mut beta_point = g.pow([beta as u64]);
        for i in 0..mu {
            let offset = len_l0 >> (i + 1);
            if !verify_merkle_tree_at_conjugate_points(
                len_l0 >> i,
                &mt_roots[i],
                beta,
                &mt_proofs[t][i].1,
                &mt_proofs[t][i].2,
                &mt_proofs[t][i].3,
            ) {
                eprintln!(
                    "VERIFY FAIL: merkle proof at t={}, i={}, beta={}",
                    t, i, beta
                );
                return Ok(false);
            }

            let next_beta = if beta >= offset { beta - offset } else { beta };
            let val = if i < mu - 1 {
                mt_proofs[t][i + 1].1.0
            } else {
                f_mu
            };

            if !is_collinear(
                (beta_point, mt_proofs[t][i].1.0),
                (-beta_point, mt_proofs[t][i].1.1),
                (r[i + 1], val),
            ) {
                eprintln!("VERIFY FAIL: collinear check at t={}, i={}", t, i);
                return Ok(false);
            }

            beta = next_beta;
            beta_point *= beta_point;
        }
    }

    Ok(true)
}

/// Batched DeepFold verify
#[allow(non_snake_case)]
pub fn deepfold_batch_verify<F: PrimeField>(
    verifier_param: &DeepFoldVerifierParam<F>,
    commitments: &[DeepFoldCommitment],
    points: &[Vec<F>],
    batch_proof: &DeepFoldBatchedProof<F>,
    transcript: &mut IOPTranscript<F>,
) -> Result<bool, PCSError> {
    let DeepFoldVerifierParam {
        max_mu,
        len_l0,
        g,
        s,
    } = verifier_param.clone();
    let mu = max_mu;
    assert!(commitments.iter().all(|com| com.mu == mu));
    let num_poly = commitments.len();
    assert!(points.iter().all(|point| point.len() == mu));
    assert!(points.len() == num_poly);
    let DeepFoldBatchedProof {
        deepfold_proof,
        sum_check_proof,
        mt_proofs_for_mt0,
        evals,
        sum_check_evals,
    } = batch_proof.clone();

    let DeepFoldProof {
        ref linear_polys,
        ref mt_roots,
        f_mu,
        ref mt_proofs,
    } = deepfold_proof;

    // Sumcheck Phase
    let r_batch = transcript.get_and_append_challenge(b"batched_sumcheck")?;
    let sum_check_sum = <PolyIOP<F> as SumCheck<F>>::extract_sum(&sum_check_proof);
    if sum_check_sum
        != (0..num_poly)
            .map(|k| r_batch.pow([k as u64]) * evals[k])
            .sum::<F>()
    {
        return Ok(false);
    }
    let sum_check_claim = <PolyIOP<F> as SumCheck<F>>::verify(
        sum_check_sum,
        &sum_check_proof,
        &VPAuxInfo {
            max_degree: 2,
            num_variables: mu,
            phantom: PhantomData::<F>::default(),
        },
        transcript,
    )
    .map_err(|e| PCSError::SumCheckError(format!("{:?}", e)))?;
    let point = sum_check_proof.point.clone();
    if sum_check_claim.expected_evaluation
        != (0..num_poly)
            .map(|k| r_batch.pow([k as u64]) * eval_mle_eq(&point, &points[k]) * sum_check_evals[k])
            .sum::<F>()
    {
        return Ok(false);
    }

    // Batched Open Phase
    let gamma = transcript.get_and_append_challenge_vectors(b"gamma", num_poly)?;
    let value: F = (0..num_poly).map(|k| gamma[k] * sum_check_evals[k]).sum();

    // Get challenges (same as verify())
    let mut alpha = vec![F::ZERO];
    let mut r = vec![F::ZERO];
    for _ in 1..mu + 1 {
        alpha.push(transcript.get_and_append_challenge(b"alpha")?);
        r.push(transcript.get_and_append_challenge(b"r")?);
    }

    // Verify linear polynomial relationships
    if eval_linear_poly(&linear_polys[0][0], &point[0]) != value
        || eval_linear_poly(&linear_polys[mu - 1][0], &r[mu]) != f_mu
    {
        return Ok(false);
    }

    for i in 1..mu {
        for j in 0..linear_polys[i - 1].len() {
            let k = if i < mu - 1 { j } else { 0 };
            let w1 = if j == 0 {
                point[i]
            } else {
                alpha[j].pow([1 << (i + 1 - j) as u64])
            };
            if eval_linear_poly(&linear_polys[i - 1][j], &r[i])
                != eval_linear_poly(&linear_polys[i][k], &w1)
            {
                return Ok(false);
            }
        }
    }

    // Verify merkle proofs and collinearity (skip mt0 merkle verification)
    for t in 0..s {
        let mut beta = transcript.get_and_append_challenge_indices(b"beta", 1, len_l0)?[0];
        let mut beta_point = g.pow([beta as u64]);

        for i in 0..mu {
            let offset = len_l0 >> (i + 1);

            // For i=0: skip merkle verification (will be checked via linear combination)
            // For i>=1: verify merkle proof using mt_roots[i-1]
            if i > 0 {
                if !verify_merkle_tree_at_conjugate_points(
                    len_l0 >> i,
                    &mt_roots[i - 1], // mt_roots shifted by 1
                    beta,
                    &mt_proofs[t][i].1,
                    &mt_proofs[t][i].2,
                    &mt_proofs[t][i].3,
                ) {
                    return Ok(false);
                }
            }

            let next_beta = if beta >= offset { beta - offset } else { beta };
            let val = if i < mu - 1 {
                mt_proofs[t][i + 1].1.0
            } else {
                f_mu
            };

            if !is_collinear(
                (beta_point, mt_proofs[t][i].1.0),
                (-beta_point, mt_proofs[t][i].1.1),
                (r[i + 1], val),
            ) {
                return Ok(false);
            }

            beta = next_beta;
            beta_point *= beta_point;
        }
    }

    // Additional checks for individual mt0s via linear combination
    let idx = (0..num_poly)
        .filter(|&i| (0..i).all(|j| commitments[i] != commitments[j]))
        .collect::<Vec<_>>();
    let mut flag = vec![];
    let mut cnt = 0;
    for i in 0..num_poly {
        for j in 0..=i {
            if i == j {
                flag.push(cnt);
                cnt += 1;
            } else if commitments[i] == commitments[j] {
                flag.push(flag[j]);
                break;
            }
        }
    }
    for t in 0..s {
        let mut sum = F::ZERO;
        let x = mt_proofs[t][0].0;
        for (ki, &k) in idx.iter().enumerate() {
            let leaf_size = mt_proofs_for_mt0[t][ki].0.len();
            let step = len_l0 / leaf_size;
            if !MerkleTree::verify(
                &commitments[k].rt0,
                x % step,
                &compute_sha256_row(&mt_proofs_for_mt0[t][ki].0),
                &mt_proofs_for_mt0[t][ki].1,
            ) {
                return Ok(false);
            }
        }
        // Use the first proof's leaf_size for the sum computation
        let leaf_size = mt_proofs_for_mt0[t][0].0.len();
        let step = len_l0 / leaf_size;
        for (k, &ki) in flag.iter().enumerate() {
            sum += gamma[k] * mt_proofs_for_mt0[t][ki].0[x / step];
        }
        if sum != mt_proofs[t][0].1.0 {
            return Ok(false);
        }
    }

    Ok(true)
}

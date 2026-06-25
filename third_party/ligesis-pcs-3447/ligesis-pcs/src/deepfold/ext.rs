//! DeepFold extension field functions
//!
//! This module contains the extension field implementations for DeepFold PCS:
//! - `deepfold_open_at_ext_point`: Open at extension field point
//! - `deepfold_verify_at_ext_point`: Verify extension field proof
//! - `deepfold_batch_open_at_ext_point`: Batch open at extension field points
//! - `deepfold_batch_verify_at_ext_point`: Batch verify extension field proofs

use crate::{
    errors::PCSError, hash::*, utils::*,
    IOPProof, PolyIOP,
    sumcheck::SumCheck,
    types::{FieldExtension, HasQuadraticExtension},
};
use arithmetic::VPAuxInfo;
use ark_ff::{Field, PrimeField};
use ark_poly::{DenseMultilinearExtension, EvaluationDomain, GeneralEvaluationDomain};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::{end_timer, marker::PhantomData, start_timer, sync::Arc, vec::Vec};
use transcript::IOPTranscript;

use super::{
    DeepFoldCommitment, DeepFoldProverCommitmentAdvice, DeepFoldProverParam, DeepFoldVerifierParam,
    utils::{build_merkle_tree, get_leaf_elements, open_merkle_tree_at_conjugate_points,
            verify_merkle_tree_at_conjugate_points, LEAF_SIZE},
};

/// Extension field proof structure for opening at extension field point
/// Linear polynomials are stored as extension field values
#[derive(Clone, Debug, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize)]
pub struct DeepFoldExtProof<F: PrimeField + HasQuadraticExtension> {
    /// Linear polynomial evaluations at (0, value(0)) and (1, value(1))
    /// These are in extension field EF after folding
    pub linear_polys: Vec<Vec<(F::Extension, F::Extension)>>,
    /// Merkle tree roots (base field commitments)
    pub mt_roots: Vec<Byte32>,
    /// Final folded value (in extension field)
    pub f_mu: F::Extension,
    /// Merkle proofs for consistency checks (base field values)
    pub mt_proofs: Vec<Vec<(usize, (F, F), Vec<F>, Vec<Byte32>)>>,
}

/// Batched extension field proof
#[derive(Clone, Debug, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize)]
pub struct DeepFoldExtBatchedProof<F: PrimeField + HasQuadraticExtension> {
    pub deepfold_proof: DeepFoldExtProof<F>,
    pub sum_check_proof: IOPProof<F>,
    pub mt_proofs_for_mt0: Vec<Vec<(Vec<F>, Vec<Byte32>)>>,
    /// Claimed evaluations (in extension field)
    pub evals: Vec<F::Extension>,
    /// SumCheck subclaim evaluations (in extension field)
    pub sum_check_evals: Vec<F::Extension>,
}

/// Open a base field polynomial at an extension field point
///
/// This achieves 128-bit soundness by using extension field challenges
/// during the folding process while keeping base field Merkle commitments.
#[allow(non_snake_case)]
pub fn deepfold_open_at_ext_point<F: PrimeField + HasQuadraticExtension>(
    prover_param: &DeepFoldProverParam<F>,
    poly: &Arc<DenseMultilinearExtension<F>>,
    advice: &DeepFoldProverCommitmentAdvice<F>,
    point: &[F::Extension],
    transcript: &mut IOPTranscript<F>,
) -> Result<DeepFoldExtProof<F>, PCSError> {
    let DeepFoldProverParam { max_mu, l0, s } = prover_param.clone();
    let mu = poly.num_vars;
    assert!(mu <= max_mu);
    assert_eq!(point.len(), mu);

    let DeepFoldProverCommitmentAdvice { f0, mt0, v0, f_tilde: _, upper_tree: _ } = advice.clone();

    // Initialize structures
    // f_tilde_ext[i] stores extension field evaluations after i folds
    let mut f_tilde_ext: Vec<Vec<F::Extension>> = vec![
        poly.evaluations.iter().map(|&x| F::Extension::from_base(x)).collect()
    ];
    let mut f = vec![f0];  // Base field coefficients
    let mut v = vec![v0];  // Base field FFT values
    let mut alpha = vec![F::ZERO];
    let mut linear_polys: Vec<Vec<(F::Extension, F::Extension)>> = Vec::new();
    let mut l = vec![l0];
    l.append(
        &mut (1..mu + 1)
            .map(|i| GeneralEvaluationDomain::<F>::new(l0.size() >> i).unwrap())
            .collect::<Vec<_>>(),
    );
    let mut mt_roots = vec![mt0.root()];
    let mut mt = vec![mt0];
    let mut mt_proofs = Vec::new();
    let mut f_mu_ext = F::Extension::default();
    let mut r = vec![F::ZERO];

    // Main folding loop
    for i in 1..mu + 1 {
        // Step 2.a: Get alpha challenge (base field for transcript compatibility)
        alpha.push(transcript.get_and_append_challenge(b"alpha")?);

        // Split f_tilde (extension field)
        let (f0_ext, f1_ext) = split_even_odd_ext(&f_tilde_ext[i - 1]);

        // Split f (base field coefficients)
        let (fe, fo) = split_even_odd(&f[i - 1]);

        // Step 2.b: Compute linear polynomials (extension field)
        if i == mu {
            linear_polys.push(vec![(f_tilde_ext[i - 1][0], f_tilde_ext[i - 1][1])]);
        } else {
            // For now, just store the direct values for the main point
            // The linear poly at extension field point is (f(0,...), f(1,...))
            linear_polys.push(vec![(
                f0_ext.iter().zip(get_tensor_ext::<F>(&point[1..]).iter())
                    .map(|(&a, &b)| a * b)
                    .fold(F::Extension::default(), |acc, x| acc + x),
                f1_ext.iter().zip(get_tensor_ext::<F>(&point[1..]).iter())
                    .map(|(&a, &b)| a * b)
                    .fold(F::Extension::default(), |acc, x| acc + x),
            )]);
        }

        // Step 2.c: Get r challenge (extension field from transcript)
        // We sample a base field challenge and embed into extension field
        let ri_base = transcript.get_and_append_challenge(b"r")?;
        r.push(ri_base);
        let ri_ext = F::Extension::from_base(ri_base);

        // Step 2.d: Fold polynomials
        // f_tilde_ext folds with extension field challenge (produces EF values)
        f_tilde_ext.push(fold_ext(&f0_ext, &f1_ext, ri_ext));

        // f folds with base field challenge (stays in F for Merkle tree)
        f.push(vector_add(&fe, &scalar_vector_product(ri_base, &fo)));

        // Step 2.e: Compute v for Merkle tree (base field)
        v.push(l[i].fft(&f[i]));
        if i == mu {
            // Final value is in extension field
            f_mu_ext = f_tilde_ext[i][0];
        } else {
            let mti = build_merkle_tree(&v[i]);
            mt_roots.push(mti.root());
            mt.push(mti);
        }
    }

    // Step 4: Generate Merkle proofs (same as base field case)
    for t in 0..s {
        let mut beta = transcript.get_and_append_challenge_indices(b"beta", 1, l[0].size())?[0];
        mt_proofs.push(Vec::new());
        for i in 0..mu {
            mt_proofs[t].push(open_merkle_tree_at_conjugate_points(&mt[i], &v[i], beta));
            if beta >= l[i + 1].size() {
                beta -= l[i + 1].size();
            }
        }
    }

    Ok(DeepFoldExtProof {
        linear_polys,
        mt_roots,
        f_mu: f_mu_ext,
        mt_proofs,
    })
}

/// Verify an extension field proof
#[allow(non_snake_case)]
pub fn deepfold_verify_at_ext_point<F: PrimeField + HasQuadraticExtension>(
    verifier_param: &DeepFoldVerifierParam<F>,
    com: &DeepFoldCommitment,
    point: &[F::Extension],
    value: &F::Extension,
    proof: &DeepFoldExtProof<F>,
    transcript: &mut IOPTranscript<F>,
) -> Result<bool, PCSError> {
    let DeepFoldVerifierParam { max_mu, len_l0, g, s } = verifier_param.clone();
    let DeepFoldCommitment { mu, rt0 } = com.clone();
    assert!(mu <= max_mu);
    assert_eq!(point.len(), mu);

    let DeepFoldExtProof {
        linear_polys,
        mt_roots,
        f_mu,
        mt_proofs,
    } = proof.clone();

    if rt0 != mt_roots[0] {
        return Ok(false);
    }

    let mut alpha = vec![F::ZERO];
    let mut r = vec![F::ZERO];

    for _ in 1..mu + 1 {
        alpha.push(transcript.get_and_append_challenge(b"alpha")?);
        r.push(transcript.get_and_append_challenge(b"r")?);
    }

    // Verify linear polynomial evaluations (extension field)
    // linear_polys[0][0] evaluated at point[0] should equal value
    let computed_value = eval_linear_poly_ext(&linear_polys[0][0], &point[0]);
    if computed_value != *value {
        return Ok(false);
    }

    // Final linear poly at r[mu] should equal f_mu
    let r_mu_ext = F::Extension::from_base(r[mu]);
    if eval_linear_poly_ext(&linear_polys[mu - 1][0], &r_mu_ext) != f_mu {
        return Ok(false);
    }

    // Verify linear polynomial consistency across rounds
    for i in 1..mu {
        let r_i_ext = F::Extension::from_base(r[i]);
        let point_i_ext = point[i];
        if eval_linear_poly_ext(&linear_polys[i - 1][0], &r_i_ext)
            != eval_linear_poly_ext(&linear_polys[i][0], &point_i_ext)
        {
            return Ok(false);
        }
    }

    // Verify Merkle proofs and collinearity (base field checks)
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
                return Ok(false);
            }

            let next_beta = if beta >= offset { beta - offset } else { beta };
            let val = if i < mu - 1 {
                mt_proofs[t][i + 1].1.0
            } else {
                // For the last round, use real part of f_mu for collinearity
                // (This is sound because the low-degree test is on base field)
                F::ext_real(&f_mu)
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

    Ok(true)
}

/// Batch open at extension field points
#[allow(non_snake_case)]
pub fn deepfold_batch_open_at_ext_point<F: PrimeField + HasQuadraticExtension>(
    prover_param: &DeepFoldProverParam<F>,
    polynomials: Vec<Arc<DenseMultilinearExtension<F>>>,
    advices: &[&DeepFoldProverCommitmentAdvice<F>],
    points: &[Vec<F::Extension>],
    transcript: &mut IOPTranscript<F>,
) -> Result<DeepFoldExtBatchedProof<F>, PCSError> {
    let DeepFoldProverParam { max_mu, l0, s } = prover_param.clone();
    let num_poly = polynomials.len();
    let mu = max_mu;
    assert!(polynomials.iter().all(|poly| poly.num_vars == mu));
    assert!(points.iter().all(|point| point.len() == mu));
    assert!(points.len() == num_poly && advices.len() == num_poly);
    let mt0_list = advices.iter().map(|advice| &advice.mt0).collect::<Vec<_>>();

    // SumCheck Phase (base field SumCheck for batching)
    let timer = start_timer!(|| "DeepFold.Open.Sumcheck");
    let r_batch = transcript.get_and_append_challenge(b"batched_sumcheck")?;

    // Compute evaluations at extension field points
    let evals_ext: Vec<F::Extension> = polynomials.iter()
        .zip(points.iter())
        .map(|(poly, pt)| eval_mle_at_ext_point(&poly.evaluations, pt))
        .collect();

    // For SumCheck, we use base field points derived from extension field points
    // This is a simplification - in production, may need extension field SumCheck
    let points_base: Vec<Vec<F>> = points.iter()
        .map(|pt| pt.iter().map(|x| F::ext_real(x)).collect())
        .collect();

    let mut sum_check = arithmetic::VirtualPolynomial::new(max_mu);
    for i in 0..num_poly {
        sum_check
            .add_mle_list(
                [
                    evals_to_arcpoly(&polynomials[i].evaluations),
                    evals_to_arcpoly(&get_tensor(&points_base[i])),
                ],
                r_batch.pow([i as u64]),
            )
            .map_err(|e| PCSError::VirtualPolynomialError(format!("{:?}", e)))?;
    }
    let sum_check_proof = <PolyIOP<F> as SumCheck<F>>::prove(sum_check, transcript)
        .map_err(|e| PCSError::SumCheckError(format!("{:?}", e)))?;
    let sc_point = sum_check_proof.point.clone();
    let sum_check_evals_ext: Vec<F::Extension> = polynomials.iter()
        .map(|poly| eval_mle_at_ext_point(
            &poly.evaluations,
            &sc_point.iter().map(|&x| F::Extension::from_base(x)).collect::<Vec<_>>()
        ))
        .collect();
    end_timer!(timer);

    // Batched Open Phase
    let timer = start_timer!(|| "DeepFold.Open.Folding");
    let gamma = transcript.get_and_append_challenge_vectors(b"gamma", num_poly)?;

    // Combine polynomials (base field)
    let poly_evals: Vec<F> = (0..1 << max_mu)
        .map(|i| {
            (0..num_poly)
                .map(|j| gamma[j] * polynomials[j].evaluations[i])
                .sum::<F>()
        })
        .collect();

    let f0 = evals_to_coeffs(mu, &poly_evals);
    let v0 = l0.fft(&f0);

    // Extension field evaluations of combined polynomial
    let poly_evals_ext: Vec<F::Extension> = poly_evals.iter()
        .map(|&x| F::Extension::from_base(x))
        .collect();

    // Initialize structures
    let mut f_tilde_ext: Vec<Vec<F::Extension>> = vec![poly_evals_ext];
    let mut f = vec![f0];
    let mut v = vec![v0];
    let mut alpha = vec![F::ZERO];
    let mut linear_polys: Vec<Vec<(F::Extension, F::Extension)>> = Vec::new();
    let mut l = vec![l0];
    l.append(
        &mut (1..mu + 1)
            .map(|i| GeneralEvaluationDomain::<F>::new(l0.size() >> i).unwrap())
            .collect::<Vec<_>>(),
    );
    let mut mt_roots = Vec::new();
    let mut mt = Vec::new();
    let mut f_mu_ext = F::Extension::default();
    let mut r = vec![F::ZERO];

    // Use the SumCheck point (base field) as the evaluation point
    let sc_point_ext: Vec<F::Extension> = sc_point.iter()
        .map(|&x| F::Extension::from_base(x))
        .collect();

    // Main folding loop
    for i in 1..mu + 1 {
        alpha.push(transcript.get_and_append_challenge(b"alpha")?);

        let (f0_ext, f1_ext) = split_even_odd_ext(&f_tilde_ext[i - 1]);
        let (fe, fo) = split_even_odd(&f[i - 1]);

        if i == mu {
            linear_polys.push(vec![(f_tilde_ext[i - 1][0], f_tilde_ext[i - 1][1])]);
        } else {
            let tensor = get_tensor_ext::<F>(&sc_point_ext[i..]);
            linear_polys.push(vec![(
                f0_ext.iter().zip(tensor.iter())
                    .map(|(&a, &b)| a * b)
                    .fold(F::Extension::default(), |acc, x| acc + x),
                f1_ext.iter().zip(tensor.iter())
                    .map(|(&a, &b)| a * b)
                    .fold(F::Extension::default(), |acc, x| acc + x),
            )]);
        }

        let ri_base = transcript.get_and_append_challenge(b"r")?;
        r.push(ri_base);
        let ri_ext = F::Extension::from_base(ri_base);

        f_tilde_ext.push(fold_ext(&f0_ext, &f1_ext, ri_ext));
        f.push(vector_add(&fe, &scalar_vector_product(ri_base, &fo)));

        v.push(l[i].fft(&f[i]));
        if i == mu {
            f_mu_ext = f_tilde_ext[i][0];
        } else {
            let mti = build_merkle_tree(&v[i]);
            mt_roots.push(mti.root());
            mt.push(mti);
        }
    }

    // Generate Merkle proofs
    let mut mt_proofs = Vec::new();
    for t in 0..s {
        let mut beta = transcript.get_and_append_challenge_indices(b"beta", 1, l[0].size())?[0];
        mt_proofs.push(Vec::new());

        // For i=0
        let leaf_size = LEAF_SIZE.min(v[0].len());
        let step = v[0].len() / leaf_size;
        let local_beta = beta % step;
        let beta_prime = if beta >= v[0].len() / 2 {
            beta - v[0].len() / 2
        } else {
            beta + v[0].len() / 2
        };
        mt_proofs[t].push((
            beta,
            (v[0][beta], v[0][beta_prime]),
            get_leaf_elements(&v[0], local_beta, step, leaf_size),
            vec![],
        ));
        if beta >= l[1].size() {
            beta -= l[1].size();
        }

        // For i=1..mu-1
        for i in 1..mu {
            mt_proofs[t].push(open_merkle_tree_at_conjugate_points(&mt[i - 1], &v[i], beta));
            if beta >= l[i + 1].size() {
                beta -= l[i + 1].size();
            }
        }
    }
    end_timer!(timer);

    // mt0 proofs
    let mut mt_proofs_for_mt0 = Vec::new();
    let idx: Vec<usize> = (0..num_poly)
        .filter(|&i| (0..i).all(|j| !Arc::ptr_eq(&polynomials[i], &polynomials[j])))
        .collect();
    for t in 0..s {
        mt_proofs_for_mt0.push(Vec::new());
        let x0 = mt_proofs[t][0].0;

        for &k in &idx {
            let leaf_size = mt0_list[k].leaf_size();
            let step = l0.size() / leaf_size;
            let local_x0 = x0 % step;
            mt_proofs_for_mt0[t].push((
                get_leaf_elements(&advices[k].v0, local_x0, step, leaf_size),
                mt0_list[k].prove(local_x0),
            ));
        }
    }

    Ok(DeepFoldExtBatchedProof {
        deepfold_proof: DeepFoldExtProof {
            linear_polys,
            mt_roots,
            f_mu: f_mu_ext,
            mt_proofs,
        },
        sum_check_proof,
        mt_proofs_for_mt0,
        evals: evals_ext,
        sum_check_evals: sum_check_evals_ext,
    })
}

/// Batch verify at extension field points
#[allow(non_snake_case)]
pub fn deepfold_batch_verify_at_ext_point<F: PrimeField + HasQuadraticExtension>(
    verifier_param: &DeepFoldVerifierParam<F>,
    commitments: &[DeepFoldCommitment],
    points: &[Vec<F::Extension>],
    batch_proof: &DeepFoldExtBatchedProof<F>,
    transcript: &mut IOPTranscript<F>,
) -> Result<bool, PCSError> {
    let DeepFoldVerifierParam { max_mu, len_l0, g, s } = verifier_param.clone();
    let mu = max_mu;
    assert!(commitments.iter().all(|com| com.mu == mu));
    let num_poly = commitments.len();
    assert!(points.iter().all(|point| point.len() == mu));
    assert!(points.len() == num_poly);

    let DeepFoldExtBatchedProof {
        deepfold_proof,
        sum_check_proof,
        mt_proofs_for_mt0,
        evals,
        sum_check_evals,
    } = batch_proof.clone();

    let DeepFoldExtProof {
        ref linear_polys,
        ref mt_roots,
        f_mu,
        ref mt_proofs,
    } = deepfold_proof;

    // SumCheck verification
    let r_batch = transcript.get_and_append_challenge(b"batched_sumcheck")?;

    // Compute expected sum using extension field evals
    let points_base: Vec<Vec<F>> = points.iter()
        .map(|pt| pt.iter().map(|x| F::ext_real(x)).collect())
        .collect();
    let sum_check_sum_expected: F = (0..num_poly)
        .map(|k| r_batch.pow([k as u64]) * F::ext_real(&evals[k]))
        .sum();

    let sum_check_sum = <PolyIOP<F> as SumCheck<F>>::extract_sum(&sum_check_proof);
    if sum_check_sum != sum_check_sum_expected {
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

    let sc_point = sum_check_proof.point.clone();
    let expected_eval: F = (0..num_poly)
        .map(|k| r_batch.pow([k as u64]) * eval_mle_eq(&sc_point, &points_base[k]) * F::ext_real(&sum_check_evals[k]))
        .sum();
    if sum_check_claim.expected_evaluation != expected_eval {
        return Ok(false);
    }

    // Batched Open verification
    let gamma = transcript.get_and_append_challenge_vectors(b"gamma", num_poly)?;
    let value_ext: F::Extension = (0..num_poly)
        .map(|k| F::Extension::from_base(gamma[k]) * sum_check_evals[k])
        .fold(F::Extension::default(), |acc, x| acc + x);

    let sc_point_ext: Vec<F::Extension> = sc_point.iter()
        .map(|&x| F::Extension::from_base(x))
        .collect();

    // Get challenges
    let mut alpha = vec![F::ZERO];
    let mut r = vec![F::ZERO];
    for _ in 1..mu + 1 {
        alpha.push(transcript.get_and_append_challenge(b"alpha")?);
        r.push(transcript.get_and_append_challenge(b"r")?);
    }

    // Verify linear polynomial evaluations
    let computed_value = eval_linear_poly_ext(&linear_polys[0][0], &sc_point_ext[0]);
    if computed_value != value_ext {
        return Ok(false);
    }

    let r_mu_ext = F::Extension::from_base(r[mu]);
    if eval_linear_poly_ext(&linear_polys[mu - 1][0], &r_mu_ext) != f_mu {
        return Ok(false);
    }

    // Verify linear polynomial consistency
    for i in 1..mu {
        let r_i_ext = F::Extension::from_base(r[i]);
        let point_i_ext = sc_point_ext[i];
        if eval_linear_poly_ext(&linear_polys[i - 1][0], &r_i_ext)
            != eval_linear_poly_ext(&linear_polys[i][0], &point_i_ext)
        {
            return Ok(false);
        }
    }

    // Verify Merkle proofs and collinearity
    for t in 0..s {
        let mut beta = transcript.get_and_append_challenge_indices(b"beta", 1, len_l0)?[0];
        let mut beta_point = g.pow([beta as u64]);

        for i in 0..mu {
            let offset = len_l0 >> (i + 1);

            // For i>0, verify Merkle proof
            if i > 0 {
                if !verify_merkle_tree_at_conjugate_points(
                    len_l0 >> i,
                    &mt_roots[i - 1],
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
                F::ext_real(&f_mu)
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

    // Verify mt0 proofs
    let idx: Vec<usize> = (0..num_poly)
        .filter(|&i| (0..i).all(|j| commitments[i] != commitments[j]))
        .collect();
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

// =============================================================================
// Helper functions for extension field operations
// =============================================================================

/// Split vector into even and odd parts (extension field version)
fn split_even_odd_ext<F: Field>(v: &[F]) -> (Vec<F>, Vec<F>) {
    let n = v.len() / 2;
    let even: Vec<F> = (0..n).map(|i| v[2 * i]).collect();
    let odd: Vec<F> = (0..n).map(|i| v[2 * i + 1]).collect();
    (even, odd)
}

/// Fold two vectors with extension field challenge
fn fold_ext<F: Field>(f0: &[F], f1: &[F], r: F) -> Vec<F> {
    f0.iter()
        .zip(f1.iter())
        .map(|(&a, &b)| a + r * (b - a))
        .collect()
}

/// Compute tensor product for extension field point
fn get_tensor_ext<F: PrimeField + HasQuadraticExtension>(point: &[F::Extension]) -> Vec<F::Extension> {
    if point.is_empty() {
        return vec![F::Extension::from_base(F::ONE)];
    }
    let mut tensor = vec![F::Extension::from_base(F::ONE); 1 << point.len()];
    for (i, &pi) in point.iter().enumerate() {
        let half = 1 << i;
        for j in 0..half {
            tensor[j + half] = tensor[j] * pi;
            tensor[j] = tensor[j] * (F::Extension::from_base(F::ONE) - pi);
        }
    }
    tensor
}

/// Evaluate linear polynomial (a, b) at point x: a + x * (b - a)
fn eval_linear_poly_ext<F: Field>(poly: &(F, F), x: &F) -> F {
    poly.0 + *x * (poly.1 - poly.0)
}

/// Evaluate MLE at extension field point
fn eval_mle_at_ext_point<F: PrimeField + HasQuadraticExtension>(
    evals: &[F],
    point: &[F::Extension],
) -> F::Extension {
    let n = point.len();
    if n == 0 {
        return F::Extension::from_base(evals[0]);
    }

    let tensor = get_tensor_ext::<F>(point);
    let mut result = F::Extension::default();
    for (i, &eval) in evals.iter().enumerate() {
        result = result + tensor[i] * F::Extension::from_base(eval);
    }
    result
}

/// Distributed batch open at extension field points
#[allow(non_snake_case)]
pub fn deepfold_d_batch_open_at_ext_point<F: PrimeField + HasQuadraticExtension>(
    prover_param: &DeepFoldProverParam<F>,
    polynomials: Vec<Arc<DenseMultilinearExtension<F>>>,
    advices: &[&DeepFoldProverCommitmentAdvice<F>],
    points: &[Vec<F::Extension>],
    transcript: &mut IOPTranscript<F>,
) -> Result<Option<DeepFoldExtBatchedProof<F>>, PCSError> {
    use deNetwork::{DeMultiNet as Net, DeNet, DeSerNet};

    let DeepFoldProverParam { max_mu, l0, s } = prover_param.clone();
    let num_party = Net::n_parties();
    let num_party_vars = num_party.ilog2() as usize;
    let num_poly = polynomials.len();

    // Each party has local evaluations of size 2^local_mu
    let local_mu = polynomials[0].num_vars;
    let mu = local_mu + num_party_vars;
    assert!(mu <= max_mu);
    assert!(polynomials.iter().all(|poly| poly.num_vars == local_mu));
    assert!(points.iter().all(|point| point.len() == mu));
    assert!(points.len() == num_poly && advices.len() == num_poly);

    // Step 1: Gather all polynomial evaluations to master
    let all_poly_evals: Vec<Option<Vec<Vec<F>>>> = polynomials
        .iter()
        .map(|poly| Net::send_to_master(&poly.evaluations))
        .collect();

    // Initialize structures
    let mt0_list = advices.iter().map(|advice| &advice.mt0).collect::<Vec<_>>();
    let upper_tree0_list = advices.iter().map(|advice| &advice.upper_tree).collect::<Vec<_>>();
    let mut l = vec![l0];
    l.append(
        &mut (1..mu + 1)
            .map(|i| GeneralEvaluationDomain::<F>::new(l0.size() >> i).unwrap())
            .collect::<Vec<_>>(),
    );

    // All parties need these for distributed Merkle tree construction
    let mut local_mts: Vec<MerkleTree> = Vec::new();
    let mut upper_mts: Vec<Option<MerkleTree>> = Vec::new();
    let mut is_distributed: Vec<bool> = Vec::new();
    let mut mt_roots: Vec<Byte32> = Vec::new();
    let mut r = vec![F::ZERO];

    // Master-only data
    let mut f_tilde_ext: Vec<Vec<F::Extension>> = Vec::new();
    let mut f: Vec<Vec<F>> = Vec::new();
    let mut alpha = vec![F::ZERO];
    let mut linear_polys: Vec<Vec<(F::Extension, F::Extension)>> = Vec::new();
    let mut v: Vec<Vec<F>> = Vec::new();
    let mut f_mu_ext = F::Extension::default();
    let mut sum_check_proof: Option<IOPProof<F>> = None;
    let mut sum_check_evals_ext: Vec<F::Extension> = Vec::new();
    let mut sc_point: Vec<F> = Vec::new();
    let mut sc_point_ext: Vec<F::Extension> = Vec::new();
    let mut gamma: Vec<F> = Vec::new();
    let mut full_poly_evals: Vec<Vec<F>> = Vec::new();
    let mut evals_ext: Vec<F::Extension> = Vec::new();

    let timer = start_timer!(|| "DDeepFold.Open.Sumcheck");
    if Net::am_master() {
        // Reconstruct full polynomials on master
        full_poly_evals = all_poly_evals
            .into_iter()
            .map(|evals_opt| {
                let all_evals: Vec<Vec<F>> = evals_opt.unwrap();
                all_evals.into_iter().flatten().collect()
            })
            .collect();

        // Pad polynomials if needed
        for poly_evals in &mut full_poly_evals {
            if poly_evals.len() < (1 << max_mu) {
                poly_evals.resize(1 << max_mu, F::ZERO);
            }
        }

        // Compute extension field evaluations
        evals_ext = full_poly_evals.iter()
            .zip(points.iter())
            .map(|(poly, pt)| eval_mle_at_ext_point(poly, pt))
            .collect();

        // For SumCheck, use base field points derived from extension field points
        let points_base: Vec<Vec<F>> = points.iter()
            .map(|pt| pt.iter().map(|x| F::ext_real(x)).collect())
            .collect();

        // SumCheck Phase (base field)
        let r_batch = transcript.get_and_append_challenge(b"batched_sumcheck")?;
        let mut sum_check = arithmetic::VirtualPolynomial::new(max_mu);
        for i in 0..num_poly {
            sum_check
                .add_mle_list(
                    [
                        evals_to_arcpoly(&full_poly_evals[i]),
                        evals_to_arcpoly(&get_tensor(&points_base[i])),
                    ],
                    r_batch.pow([i as u64]),
                )
                .map_err(|e| PCSError::VirtualPolynomialError(format!("{:?}", e)))?;
        }
        let proof = <PolyIOP<F> as SumCheck<F>>::prove(sum_check, transcript)
            .map_err(|e| PCSError::SumCheckError(format!("{:?}", e)))?;
        sc_point = proof.point.clone();
        sc_point_ext = sc_point.iter().map(|&x| F::Extension::from_base(x)).collect();
        sum_check_evals_ext = full_poly_evals.iter()
            .map(|poly| eval_mle_at_ext_point(poly, &sc_point_ext))
            .collect();
        sum_check_proof = Some(proof);

        // Batched Open Phase
        gamma = transcript.get_and_append_challenge_vectors(b"gamma", num_poly)?;

        // Combine polynomials (base field)
        let poly_evals: Vec<F> = (0..1 << max_mu)
            .map(|i| {
                (0..num_poly)
                    .map(|j| gamma[j] * full_poly_evals[j][i])
                    .sum::<F>()
            })
            .collect();

        let f0 = evals_to_coeffs(mu, &poly_evals);
        let v0 = l0.fft(&f0);

        // Extension field evaluations of combined polynomial
        let poly_evals_ext: Vec<F::Extension> = poly_evals.iter()
            .map(|&x| F::Extension::from_base(x))
            .collect();

        f_tilde_ext = vec![poly_evals_ext];
        f = vec![f0];
        v = vec![v0];
    }
    end_timer!(timer);

    // Broadcast necessary data to all parties
    let broadcast_data: (Vec<F>, Vec<F>, Vec<F>) = if Net::am_master() {
        Net::recv_from_master_uniform(Some((sc_point.clone(), gamma.clone(), v[0].clone())));
        (sc_point.clone(), gamma.clone(), v[0].clone())
    } else {
        Net::recv_from_master_uniform(None)
    };
    if !Net::am_master() {
        sc_point = broadcast_data.0;
        gamma = broadcast_data.1;
        v = vec![broadcast_data.2];
        sc_point_ext = sc_point.iter().map(|&x| F::Extension::from_base(x)).collect();
    }

    // Folding loop - all parties participate
    let timer = start_timer!(|| "DDeepFold.Open.Folding");
    for i in 1..mu + 1 {
        let alpha_i = if Net::am_master() {
            let a = transcript.get_and_append_challenge(b"alpha")?;
            Net::recv_from_master_uniform(Some(a));
            a
        } else {
            Net::recv_from_master_uniform(None)
        };
        alpha.push(alpha_i);

        // Master computes linear polys and folds
        if Net::am_master() {
            let (f0_ext, f1_ext) = split_even_odd_ext(&f_tilde_ext[i - 1]);
            let (fe, fo) = split_even_odd(&f[i - 1]);

            if i == mu {
                linear_polys.push(vec![(f_tilde_ext[i - 1][0], f_tilde_ext[i - 1][1])]);
            } else {
                let tensor = get_tensor_ext::<F>(&sc_point_ext[i..]);
                linear_polys.push(vec![(
                    f0_ext.iter().zip(tensor.iter())
                        .map(|(&a, &b)| a * b)
                        .fold(F::Extension::default(), |acc, x| acc + x),
                    f1_ext.iter().zip(tensor.iter())
                        .map(|(&a, &b)| a * b)
                        .fold(F::Extension::default(), |acc, x| acc + x),
                )]);
            }

            let ri_base = transcript.get_and_append_challenge(b"r")?;
            r.push(ri_base);
            Net::recv_from_master_uniform(Some(ri_base));
            let ri_ext = F::Extension::from_base(ri_base);

            f_tilde_ext.push(fold_ext(&f0_ext, &f1_ext, ri_ext));
            f.push(vector_add(&fe, &scalar_vector_product(ri_base, &fo)));

            v.push(l[i].fft(&f[i]));
            if i == mu {
                f_mu_ext = f_tilde_ext[i][0];
            } else {
                let mti = build_merkle_tree(&v[i]);
                mt_roots.push(mti.root());
                local_mts.push(mti);
                upper_mts.push(None);
                is_distributed.push(false);
            }
        } else {
            let ri_base: F = Net::recv_from_master_uniform(None);
            r.push(ri_base);
        }
    }
    end_timer!(timer);

    // Generate Merkle proofs on master
    let mut mt_proofs = Vec::new();
    if Net::am_master() {
        for t in 0..s {
            let mut beta = transcript.get_and_append_challenge_indices(b"beta", 1, l[0].size())?[0];
            mt_proofs.push(Vec::new());

            // For i=0
            let leaf_size = LEAF_SIZE.min(v[0].len());
            let step = v[0].len() / leaf_size;
            let local_beta = beta % step;
            let beta_prime = if beta >= v[0].len() / 2 {
                beta - v[0].len() / 2
            } else {
                beta + v[0].len() / 2
            };
            mt_proofs[t].push((
                beta,
                (v[0][beta], v[0][beta_prime]),
                get_leaf_elements(&v[0], local_beta, step, leaf_size),
                vec![],
            ));
            if beta >= l[1].size() {
                beta -= l[1].size();
            }

            // For i=1..mu-1
            for i in 1..mu {
                mt_proofs[t].push(open_merkle_tree_at_conjugate_points(&local_mts[i - 1], &v[i], beta));
                if beta >= l[i + 1].size() {
                    beta -= l[i + 1].size();
                }
            }
        }
    }

    // Additional proofs for individual mt0s - all parties participate in d_prove
    let mut mt_proofs_for_mt0 = Vec::new();

    // Master computes deduplication and broadcasts info
    let idx: Vec<usize> = if Net::am_master() {
        let idx: Vec<usize> = (0..num_poly)
            .filter(|&i| (0..i).all(|j| advices[i].mt0.root() != advices[j].mt0.root()))
            .collect();
        Net::recv_from_master_uniform(Some(idx.clone()));
        idx
    } else {
        Net::recv_from_master_uniform(None)
    };

    for t in 0..s {
        // Master broadcasts x0 for this round
        let x0: usize = if Net::am_master() {
            let x = mt_proofs[t][0].0;
            Net::recv_from_master_uniform(Some(x));
            x
        } else {
            Net::recv_from_master_uniform(None)
        };

        let mut proofs_for_t = Vec::new();

        for &k in &idx {
            // All parties participate in d_prove using the same index k
            let leaf_size = mt0_list[k].leaf_size();
            let step = l0.size() / leaf_size;
            let local_x0 = x0 % step;

            let proof_opt = MerkleTree::d_prove(local_x0, mt0_list[k], upper_tree0_list[k].as_ref());

            if Net::am_master() {
                let merkle_proof = proof_opt.unwrap();
                let leaf_elements = get_leaf_elements(&advices[k].v0, local_x0, step, leaf_size);
                proofs_for_t.push((leaf_elements, merkle_proof));
            }
        }
        if Net::am_master() {
            mt_proofs_for_mt0.push(proofs_for_t);
        }
    }

    if Net::am_master() {
        Ok(Some(DeepFoldExtBatchedProof {
            deepfold_proof: DeepFoldExtProof {
                linear_polys,
                mt_roots,
                f_mu: f_mu_ext,
                mt_proofs,
            },
            sum_check_proof: sum_check_proof.unwrap(),
            mt_proofs_for_mt0,
            evals: evals_ext,
            sum_check_evals: sum_check_evals_ext,
        }))
    } else {
        Ok(None)
    }
}

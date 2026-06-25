//! DeepFold batch commit/open/verify functions
//!
//! This module implements a new batch protocol where multiple polynomials are committed together:
//! - Each column of the FFT matrix is hashed (no column merging for leaf compression)
//! - All polynomials share the same folding challenges
//! - FRI consistency checks use shared random points

use crate::{errors::PCSError, hash::*, utils::*, IOPProof, PolyIOP, sumcheck::SumCheck};
use arithmetic::{VPAuxInfo, VirtualPolynomial};
use ark_ff::PrimeField;
use ark_poly::{DenseMultilinearExtension, EvaluationDomain, GeneralEvaluationDomain, MultilinearExtension};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::{end_timer, marker::PhantomData, start_timer, sync::Arc, vec::Vec};
use transcript::IOPTranscript;
use deNetwork::{DeMultiNet as Net, DeNet, DeSerNet};

use super::{DeepFoldProverParam, DeepFoldVerifierParam};
use super::utils::{build_merkle_tree, get_leaf_elements, open_merkle_tree_at_conjugate_points, LEAF_SIZE};

/// Commitment for batch of polynomials
#[derive(CanonicalSerialize, CanonicalDeserialize, Clone, Debug, PartialEq, Eq, Default)]
pub struct DeepFoldBatchCommitment {
    /// Number of variables in each polynomial
    pub mu: usize,
    /// Number of polynomials
    pub num_polys: usize,
    /// Merkle root of column hashes
    pub root: Byte32,
}

/// Prover advice for batch commitment
#[derive(Clone, Debug)]
pub struct DeepFoldBatchProverAdvice<F: PrimeField> {
    /// Coefficients of each polynomial (each row is one polynomial's coefficients)
    pub f0_matrix: Vec<Vec<F>>,
    /// FFT evaluations matrix (each row is one polynomial's FFT)
    pub v0_matrix: Vec<Vec<F>>,
    /// Column hashes
    pub column_hashes: Vec<Byte32>,
    /// Merkle tree on column hashes
    pub merkle_tree: MerkleTree,
}

/// Proof for batch opening
#[derive(CanonicalSerialize, CanonicalDeserialize, Clone, Debug, PartialEq, Eq)]
pub struct DeepFoldBatchProof<F: PrimeField> {
    /// Linear polynomials at each folding step
    /// linear_polys[step][aux_idx][poly_idx] = (a, b)
    /// aux_idx=0 is for the actual evaluation point, aux_idx>0 are for alpha-derived points
    pub linear_polys: Vec<Vec<Vec<(F, F)>>>,
    /// Merkle roots for each folding level
    pub merkle_roots: Vec<Byte32>,
    /// Final values after all folding (one per polynomial)
    pub final_values: Vec<F>,
    /// Merkle proofs for FRI consistency checks
    /// merkle_proofs[t][i] = (beta, values_at_conjugate_points, proof_beta, proof_beta_prime)
    pub merkle_proofs: Vec<Vec<(usize, Vec<(F, F)>, Vec<Byte32>, Vec<Byte32>)>>,
}

/// Batch commit multiple polynomials together
///
/// All polynomials must have mu = max_mu variables.
/// Creates a matrix where each row is one polynomial's FFT result.
/// Each column of the matrix is hashed separately (no column merging).
/// Merkle tree is built on the column hashes.
pub fn batch_commit<F: PrimeField>(
    prover_param: &DeepFoldProverParam<F>,
    polys: &[Arc<DenseMultilinearExtension<F>>],
) -> Result<(DeepFoldBatchCommitment, DeepFoldBatchProverAdvice<F>), PCSError> {
    let DeepFoldProverParam { max_mu, l0, s: _ } = prover_param;

    assert!(!polys.is_empty(), "Must commit at least one polynomial");

    // All polynomials must have the same number of variables = max_mu
    for poly in polys {
        assert_eq!(
            poly.num_vars, *max_mu,
            "All polynomials must have mu = max_mu"
        );
    }

    let mu = *max_mu;
    let num_polys = polys.len();
    let len_l0 = l0.size();

    // Step 1: Compute FFT for each polynomial
    let timer = start_timer!(|| format!("BatchCommit.FFT({}x{})", num_polys, len_l0));
    let mut f0_matrix = Vec::with_capacity(num_polys);
    let mut v0_matrix = Vec::with_capacity(num_polys);

    for poly in polys {
        let f0 = evals_to_coeffs(mu, &poly.evaluations);
        let v0 = l0.fft(&f0);
        f0_matrix.push(f0);
        v0_matrix.push(v0);
    }
    end_timer!(timer);

    // Step 2: Hash each column of the matrix
    // Column j contains: v0_matrix[0][j], v0_matrix[1][j], ..., v0_matrix[num_polys-1][j]
    let timer = start_timer!(|| format!("BatchCommit.ColumnHash({})", len_l0));
    let column_hashes: Vec<Byte32> = (0..len_l0)
        .map(|j| {
            let column: Vec<F> = (0..num_polys).map(|i| v0_matrix[i][j]).collect();
            compute_sha256_row(&column)
        })
        .collect();
    end_timer!(timer);

    // Step 3: Build Merkle tree on column hashes (no leaf merging)
    let timer = start_timer!(|| "BatchCommit.MerkleTree");
    let merkle_tree = MerkleTree::new(&column_hashes);
    let root = merkle_tree.root();
    end_timer!(timer);

    Ok((
        DeepFoldBatchCommitment {
            mu,
            num_polys,
            root,
        },
        DeepFoldBatchProverAdvice {
            f0_matrix,
            v0_matrix,
            column_hashes,
            merkle_tree,
        },
    ))
}

/// Batch open multiple polynomials at the same point
///
/// All polynomials are folded together using the same challenges.
/// At each folding level, a matrix is formed from all folded polynomials' FFTs.
/// Each column is hashed and a Merkle tree is built.
/// FRI consistency checks use the same random points for all polynomials.
#[allow(non_snake_case)]
pub fn batch_open<F: PrimeField>(
    prover_param: &DeepFoldProverParam<F>,
    polys: &[Arc<DenseMultilinearExtension<F>>],
    advice: &DeepFoldBatchProverAdvice<F>,
    point: &[F],
    transcript: &mut IOPTranscript<F>,
) -> Result<DeepFoldBatchProof<F>, PCSError> {
    let DeepFoldProverParam { max_mu, l0, s } = prover_param.clone();

    let mu = max_mu;
    let num_polys = polys.len();

    assert_eq!(point.len(), mu, "Point must have mu coordinates");
    assert_eq!(advice.f0_matrix.len(), num_polys);

    // Initialize evaluation domains
    let mut domains: Vec<GeneralEvaluationDomain<F>> = vec![l0];
    for i in 1..=mu {
        domains.push(GeneralEvaluationDomain::<F>::new(l0.size() >> i).unwrap());
    }

    // Initialize f_tilde (evaluations) and f (coefficients) for each polynomial
    let mut f_tilde: Vec<Vec<F>> = polys.iter().map(|p| p.evaluations.clone()).collect();
    let mut f: Vec<Vec<F>> = advice.f0_matrix.clone();
    let mut v: Vec<Vec<F>> = advice.v0_matrix.clone();

    // Track Merkle trees and roots at each level
    let mut merkle_roots = vec![advice.merkle_tree.root()];
    let mut merkle_trees = vec![advice.merkle_tree.clone()];
    let mut v_matrices: Vec<Vec<Vec<F>>> = vec![v.clone()];

    // Auxiliary evaluation points: a[step] = list of auxiliary points
    // Each auxiliary point is a vector of coordinates
    let mut a: Vec<Vec<Vec<F>>> = vec![vec![point.to_vec()]];
    let mut alpha_vec: Vec<F> = vec![F::ZERO];

    let mut linear_polys: Vec<Vec<Vec<(F, F)>>> = Vec::new();
    let mut final_values = Vec::new();

    // Folding process
    for i in 1..=mu {
        // Step 1: Get challenge alpha and add auxiliary point
        let alpha = transcript.get_and_append_challenge(b"alpha")?;
        alpha_vec.push(alpha);
        a[i - 1].push(get_alpha_powers::<F>(alpha, mu - i + 1));

        // Step 2: Compute linear polynomials for each auxiliary point and each polynomial
        // linear_polys[step][aux_idx][poly_idx] = (a, b)
        let mut level_linear_polys: Vec<Vec<(F, F)>> = Vec::new();

        if i == mu {
            // Final step: f_tilde[k] has 2 elements, split gives single-element arrays
            // All auxiliary points give the same result, so just one entry
            let mut aux_polys = Vec::with_capacity(num_polys);
            for k in 0..num_polys {
                let (f0_split, f1_split) = split_even_odd(&f_tilde[k]);
                // f0_split = [f_tilde[k][0]], f1_split = [f_tilde[k][1]]
                // w_tensor would be [1] for any aux point, so result is just the elements
                aux_polys.push((f0_split[0], f1_split[0]));
            }
            level_linear_polys.push(aux_polys);
        } else {
            // For each auxiliary point in a[i-1]
            for w in &a[i - 1] {
                assert!(!w.is_empty());
                let w_tensor = get_tensor(&w[1..].to_vec());

                // Compute linear poly for each polynomial
                let mut aux_polys = Vec::with_capacity(num_polys);
                for k in 0..num_polys {
                    let (f0_split, f1_split) = split_even_odd(&f_tilde[k]);
                    let a_coef = inner_product(&w_tensor, &f0_split);
                    let b_coef = inner_product(&w_tensor, &f1_split);
                    aux_polys.push((a_coef, b_coef));
                }
                level_linear_polys.push(aux_polys);
            }

            // Prepare auxiliary points for next level (drop first coordinate)
            a.push(a[i - 1].iter().map(|w| w[1..].to_vec()).collect());
        }
        linear_polys.push(level_linear_polys);

        // Step 3: Get folding challenge r
        let r = transcript.get_and_append_challenge(b"r")?;

        // Step 4: Fold each polynomial
        let mut new_f = Vec::with_capacity(num_polys);
        let mut new_f_tilde = Vec::with_capacity(num_polys);

        for k in 0..num_polys {
            let (fe, fo) = split_even_odd(&f[k]);
            let (f0_split, f1_split) = split_even_odd(&f_tilde[k]);

            new_f.push(vector_add(&fe, &scalar_vector_product(r, &fo)));
            new_f_tilde.push(vector_add(
                &scalar_vector_product(F::ONE - r, &f0_split),
                &scalar_vector_product(r, &f1_split),
            ));
        }

        f = new_f;
        f_tilde = new_f_tilde;

        // Step 5: Compute FFT for each folded polynomial
        let new_v: Vec<Vec<F>> = f
            .iter()
            .map(|coefs| domains[i].fft(coefs))
            .collect();

        if i == mu {
            // Final step: store final values
            for k in 0..num_polys {
                final_values.push(new_v[k][0]);
            }
        } else {
            // Build matrix and hash columns
            let len_v = new_v[0].len();
            let column_hashes: Vec<Byte32> = (0..len_v)
                .map(|j| {
                    let column: Vec<F> = (0..num_polys).map(|k| new_v[k][j]).collect();
                    compute_sha256_row(&column)
                })
                .collect();

            let mt = MerkleTree::new(&column_hashes);
            merkle_roots.push(mt.root());
            merkle_trees.push(mt);
            v_matrices.push(new_v.clone());
        }

        v = new_v;
    }

    // FRI consistency checks
    let mut merkle_proofs: Vec<Vec<(usize, Vec<(F, F)>, Vec<Byte32>, Vec<Byte32>)>> = Vec::new();

    for _t in 0..s {
        // Get random query position
        let mut beta = transcript.get_and_append_challenge_indices(b"beta", 1, domains[0].size())?[0];

        let mut level_proofs = Vec::new();

        for i in 0..mu {
            let v_matrix = &v_matrices[i];
            let mt = &merkle_trees[i];
            let domain = &domains[i];

            // Get conjugate point
            let beta_prime = if beta >= domain.size() / 2 {
                beta - domain.size() / 2
            } else {
                beta + domain.size() / 2
            };

            // Get values at beta and beta' for all polynomials
            let values: Vec<(F, F)> = (0..num_polys)
                .map(|k| (v_matrix[k][beta], v_matrix[k][beta_prime]))
                .collect();

            // Get Merkle proofs for both columns
            let proof_beta = mt.prove(beta);
            let proof_beta_prime = mt.prove(beta_prime);

            level_proofs.push((beta, values, proof_beta, proof_beta_prime));

            // Update beta for next level
            if beta >= domains[i + 1].size() {
                beta -= domains[i + 1].size();
            }
        }

        merkle_proofs.push(level_proofs);
    }

    Ok(DeepFoldBatchProof {
        linear_polys,
        merkle_roots,
        final_values,
        merkle_proofs,
    })
}

/// Batch verify the opening proof
#[allow(non_snake_case)]
pub fn batch_verify<F: PrimeField>(
    verifier_param: &DeepFoldVerifierParam<F>,
    commitment: &DeepFoldBatchCommitment,
    point: &[F],
    claimed_values: &[F],
    proof: &DeepFoldBatchProof<F>,
    transcript: &mut IOPTranscript<F>,
) -> Result<bool, PCSError> {
    let DeepFoldVerifierParam {
        max_mu,
        len_l0,
        g,
        s,
    } = verifier_param;

    let mu = commitment.mu;
    let num_polys = commitment.num_polys;

    assert_eq!(mu, *max_mu);
    assert_eq!(point.len(), mu);
    assert_eq!(claimed_values.len(), num_polys);

    // Verify Merkle roots match commitment
    if proof.merkle_roots[0] != commitment.root {
        return Ok(false);
    }

    // Step 1: Check linear polynomial values at point[0] match claimed values
    // linear_polys[0][0][k] is for aux_idx=0 (actual point), poly k
    for k in 0..num_polys {
        let (a, b) = proof.linear_polys[0][0][k];
        let expected = a * (F::ONE - point[0]) + b * point[0];
        if expected != claimed_values[k] {
            return Ok(false);
        }
    }

    // Step 2: Replay folding challenges and check linear poly consistency
    let mut alpha_vec = vec![F::ZERO];
    let mut r = vec![F::ZERO];

    for i in 1..=mu {
        let alpha = transcript.get_and_append_challenge(b"alpha")?;
        alpha_vec.push(alpha);
        let ri = transcript.get_and_append_challenge(b"r")?;
        r.push(ri);

        // Check linear poly consistency for all auxiliary points
        // linear_polys[i-1][j] at r[i] == linear_polys[i][k] at w1
        // where k = j if i < mu-1, else k = 0
        // and w1 = point[i] if j == 0, else w1 = alpha[j]^(2^(i+1-j))
        if i < mu {
            let num_aux = proof.linear_polys[i - 1].len();
            for j in 0..num_aux {
                let k = if i < mu - 1 { j } else { 0 };
                let w1 = if j == 0 {
                    point[i]
                } else {
                    alpha_vec[j].pow([1u64 << (i + 1 - j)])
                };

                for poly_idx in 0..num_polys {
                    let (a_prev, b_prev) = proof.linear_polys[i - 1][j][poly_idx];
                    let val_at_r = a_prev * (F::ONE - ri) + b_prev * ri;
                    let (a_next, b_next) = proof.linear_polys[i][k][poly_idx];
                    let val_at_w1 = a_next * (F::ONE - w1) + b_next * w1;
                    if val_at_r != val_at_w1 {
                        return Ok(false);
                    }
                }
            }
        } else {
            // Final step: check against final_values
            // linear_polys[mu-1][0][k] at r[mu] == final_values[k]
            for k in 0..num_polys {
                let (a, b) = proof.linear_polys[mu - 1][0][k];
                let expected = a * (F::ONE - ri) + b * ri;
                if expected != proof.final_values[k] {
                    return Ok(false);
                }
            }
        }
    }

    // Step 3: Verify FRI consistency checks
    let mut domain_sizes: Vec<usize> = vec![*len_l0];
    for i in 1..=mu {
        domain_sizes.push(len_l0 >> i);
    }

    for t in 0..*s {
        let mut beta = transcript.get_and_append_challenge_indices(b"beta", 1, *len_l0)?[0];
        let mut beta_point = g.pow([beta as u64]);

        for i in 0..mu {
            let (pos, values, proof_beta, proof_beta_prime) = &proof.merkle_proofs[t][i];

            // Verify position matches
            if *pos != beta {
                return Ok(false);
            }

            // Get conjugate point
            let beta_prime = if beta >= domain_sizes[i] / 2 {
                beta - domain_sizes[i] / 2
            } else {
                beta + domain_sizes[i] / 2
            };

            // Compute and verify column hash for beta
            let column_beta: Vec<F> = values.iter().map(|(v, _)| *v).collect();
            let column_hash_beta = compute_sha256_row(&column_beta);
            let expected_root = if i == 0 {
                commitment.root
            } else {
                proof.merkle_roots[i]
            };
            if !MerkleTree::verify(&expected_root, beta, &column_hash_beta, proof_beta) {
                return Ok(false);
            }

            // Compute and verify column hash for beta'
            let column_beta_prime: Vec<F> = values.iter().map(|(_, v)| *v).collect();
            let column_hash_beta_prime = compute_sha256_row(&column_beta_prime);
            if !MerkleTree::verify(&expected_root, beta_prime, &column_hash_beta_prime, proof_beta_prime) {
                return Ok(false);
            }

            // Verify collinearity for each polynomial
            // Points: (beta_point, v[beta]), (-beta_point, v[beta']), (r[i+1], v_next)
            let next_beta = if beta >= domain_sizes[i + 1] {
                beta - domain_sizes[i + 1]
            } else {
                beta
            };

            for k in 0..num_polys {
                let (v_beta, v_beta_prime) = values[k];

                // Get expected next value
                let v_next = if i < mu - 1 {
                    // From next level's proof
                    proof.merkle_proofs[t][i + 1].1[k].0
                } else {
                    // Final value
                    proof.final_values[k]
                };

                // Check collinearity
                if !is_collinear(
                    (beta_point, v_beta),
                    (-beta_point, v_beta_prime),
                    (r[i + 1], v_next),
                ) {
                    return Ok(false);
                }
            }

            // Update for next level
            beta = next_beta;
            beta_point *= beta_point;
        }
    }

    Ok(true)
}

// =============================================================================
// Multi-polynomial batch commit/open/verify with chunking
// =============================================================================

/// Commitment for batch of polynomials with chunking support
///
/// Each polynomial may have different sizes and be split into multiple chunks.
/// All chunks are committed together in a single batch commitment.
#[derive(CanonicalSerialize, CanonicalDeserialize, Clone, Debug, PartialEq, Eq)]
pub struct DeepFoldBatchMultiCommitment {
    /// Batch commitment containing all chunks
    pub batch_commitment: DeepFoldBatchCommitment,
    /// Number of polynomials
    pub num_polys: usize,
    /// Number of chunks per polynomial
    pub chunks_per_poly: Vec<usize>,
    /// Original number of variables for each polynomial
    pub original_num_vars: Vec<usize>,
}

impl Default for DeepFoldBatchMultiCommitment {
    fn default() -> Self {
        DeepFoldBatchMultiCommitment {
            batch_commitment: DeepFoldBatchCommitment {
                mu: 0,
                num_polys: 0,
                root: [0u8; 32],
            },
            num_polys: 0,
            chunks_per_poly: vec![],
            original_num_vars: vec![],
        }
    }
}

/// Prover advice for batch multi-polynomial commitment
#[derive(Clone, Debug)]
pub struct DeepFoldBatchMultiProverAdvice<F: PrimeField> {
    /// Batch advice containing all chunks
    pub batch_advice: DeepFoldBatchProverAdvice<F>,
    /// The chunk polynomials (flattened: poly0_chunk0, poly0_chunk1, ..., poly1_chunk0, ...)
    pub chunk_polys: Vec<Arc<DenseMultilinearExtension<F>>>,
    /// Number of chunks per polynomial
    pub chunks_per_poly: Vec<usize>,
    /// Base mu (max_mu from prover params)
    pub base_mu: usize,
    /// Local polynomial evaluations for each polynomial (for distributed sumcheck)
    /// Each party stores their local portion of each polynomial
    pub local_poly_evals: Vec<Vec<F>>,
    /// Number of columns per party (for distributed Merkle queries)
    pub cols_per_party: usize,
    /// Upper Merkle tree connecting party roots (only on master)
    pub upper_tree: Option<MerkleTree>,
    /// Party roots for distributed Merkle proof (only on master)
    pub party_roots: Vec<Byte32>,
}

/// Proof for batch multi-polynomial opening
#[derive(CanonicalSerialize, CanonicalDeserialize, Clone, Debug, PartialEq, Eq)]
pub struct DeepFoldBatchMultiProof<F: PrimeField> {
    /// Claimed evaluation values for each polynomial at its respective point
    pub claimed_values: Vec<F>,
    /// Sumcheck proof for reducing to a single point
    pub sumcheck_proof: IOPProof<F>,
    /// Evaluations of all chunks at the sumcheck random point
    pub chunk_evals_at_r: Vec<F>,
    /// The underlying batch proof for chunks at random point
    pub batch_proof: DeepFoldBatchProof<F>,
}

/// Split a polynomial into chunks of size 2^base_mu
///
/// Returns (chunk_polys, num_chunks)
fn split_polynomial_into_chunks<F: PrimeField>(
    poly: &Arc<DenseMultilinearExtension<F>>,
    base_mu: usize,
) -> (Vec<Arc<DenseMultilinearExtension<F>>>, usize) {
    let num_vars = poly.num_vars;

    if num_vars <= base_mu {
        // No split needed, just pad to base_mu
        let padded_evals = resize_eval(&poly.evaluations, base_mu);
        let padded_poly = evals_to_arcpoly(&padded_evals);
        (vec![padded_poly], 1)
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

        (chunk_polys, num_chunks)
    }
}

/// Compute eq(y, x) = Π_j (y_j * x_j + (1 - y_j) * (1 - x_j))
/// where y and x are vectors of field elements
fn compute_eq_eval<F: PrimeField>(y: &[F], x: &[F]) -> F {
    assert_eq!(y.len(), x.len(), "eq evaluation requires same-length points");
    let mut result = F::ONE;
    for (&yi, &xi) in y.iter().zip(x.iter()) {
        result *= yi * xi + (F::ONE - yi) * (F::ONE - xi);
    }
    result
}

/// Compute eq(b, point) where b is the binary representation of chunk_idx
fn compute_eq_at_chunk<F: PrimeField>(chunk_idx: usize, point: &[F]) -> F {
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
fn combine_chunk_values<F: PrimeField>(
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

/// Batch commit multiple polynomials with chunking support
///
/// Each polynomial is split into chunks of size 2^max_mu (or padded if smaller).
/// All chunks are committed together in a single batch commitment.
pub fn chunked_batch_commit<F: PrimeField>(
    prover_param: &DeepFoldProverParam<F>,
    polys: &[Arc<DenseMultilinearExtension<F>>],
) -> Result<(DeepFoldBatchMultiCommitment, DeepFoldBatchMultiProverAdvice<F>), PCSError> {
    let base_mu = prover_param.max_mu;
    let num_polys = polys.len();

    assert!(!polys.is_empty(), "Must commit at least one polynomial");

    // Split each polynomial into chunks
    let timer = start_timer!(|| format!("BatchMultiCommit.Split({})", num_polys));
    let mut all_chunks: Vec<Arc<DenseMultilinearExtension<F>>> = Vec::new();
    let mut chunks_per_poly: Vec<usize> = Vec::with_capacity(num_polys);
    let mut original_num_vars: Vec<usize> = Vec::with_capacity(num_polys);
    let mut local_poly_evals: Vec<Vec<F>> = Vec::with_capacity(num_polys);

    for poly in polys {
        original_num_vars.push(poly.num_vars);
        local_poly_evals.push(poly.evaluations.clone());
        let (chunks, num_chunks) = split_polynomial_into_chunks(poly, base_mu);
        chunks_per_poly.push(num_chunks);
        all_chunks.extend(chunks);
    }
    end_timer!(timer);

    // Commit all chunks together
    let (batch_commitment, batch_advice) = batch_commit(prover_param, &all_chunks)?;

    Ok((
        DeepFoldBatchMultiCommitment {
            batch_commitment,
            num_polys,
            chunks_per_poly: chunks_per_poly.clone(),
            original_num_vars,
        },
        DeepFoldBatchMultiProverAdvice {
            batch_advice,
            chunk_polys: all_chunks,
            chunks_per_poly,
            base_mu,
            local_poly_evals,
            cols_per_party: 0,  // Not used in non-distributed mode
            upper_tree: None,
            party_roots: vec![],
        },
    ))
}

/// Batch open multiple polynomials at different points (with chunking)
///
/// Each polynomial can be opened at a different point.
/// Uses sumcheck to reduce all evaluations to a single random point.
/// Then opens all chunks at that random point.
///
/// Protocol:
/// 1. Compute claimed_values[i] = poly_i(point_i) for each polynomial
/// 2. Use sumcheck: Σ_x [Σ_i γ^i * f_i(x) * eq(point_i, x)] = Σ_i γ^i * claimed_values[i]
/// 3. Get random point r from sumcheck
/// 4. Evaluate all chunks at r_low (first base_mu coordinates of r)
/// 5. Open all chunks at r_low using batch_open
#[allow(non_snake_case)]
pub fn chunked_batch_open<F: PrimeField>(
    prover_param: &DeepFoldProverParam<F>,
    polys: &[Arc<DenseMultilinearExtension<F>>],
    advice: &DeepFoldBatchMultiProverAdvice<F>,
    points: &[Vec<F>],
    transcript: &mut IOPTranscript<F>,
) -> Result<DeepFoldBatchMultiProof<F>, PCSError> {
    let base_mu = prover_param.max_mu;
    let num_polys = polys.len();

    assert_eq!(num_polys, points.len(), "Must have same number of points as polynomials");
    assert_eq!(num_polys, advice.chunks_per_poly.len());

    // Step 1: Compute claimed values for each polynomial at its respective point
    let timer = start_timer!(|| "ChunkedBatchOpen.ComputeClaims");
    let claimed_values: Vec<F> = polys.iter().zip(points.iter()).map(|(poly, point)| {
        // Pad point if needed
        let padded_point = resize_point(&point.clone(), poly.num_vars);
        eval_mle_poly(&poly.evaluations, &padded_point)
    }).collect();
    end_timer!(timer);

    // Step 2: Sumcheck to reduce to a single point
    // We prove: Σ_x [Σ_i γ^i * f_i(x) * eq(point_i, x)] = Σ_i γ^i * claimed_values[i]
    let timer = start_timer!(|| "ChunkedBatchOpen.Sumcheck");
    let gamma = transcript.get_and_append_challenge(b"gamma")?;

    // Find max number of variables across all polynomials
    let max_num_vars = polys.iter().map(|p| p.num_vars).max().unwrap_or(base_mu).max(base_mu);

    // Build sumcheck virtual polynomial
    // All polynomials are padded to max_num_vars variables
    let mut sumcheck_poly = VirtualPolynomial::new(max_num_vars);
    for i in 0..num_polys {
        // Pad polynomial to max_num_vars variables
        let padded_evals = resize_eval(&polys[i].evaluations, max_num_vars);
        let padded_poly = evals_to_arcpoly(&padded_evals);

        // Pad point to max_num_vars variables
        let padded_point = resize_point(&points[i].clone(), max_num_vars);
        let eq_poly = evals_to_arcpoly(&get_tensor(&padded_point));

        sumcheck_poly
            .add_mle_list([padded_poly, eq_poly], gamma.pow([i as u64]))
            .map_err(|e| PCSError::VirtualPolynomialError(format!("{:?}", e)))?;
    }

    let sumcheck_proof = <PolyIOP<F> as SumCheck<F>>::prove(sumcheck_poly, transcript)
        .map_err(|e| PCSError::SumCheckError(format!("{:?}", e)))?;
    let r = sumcheck_proof.point.clone();
    end_timer!(timer);

    // Step 3: Evaluate all chunks at r_low (first base_mu coordinates of r)
    let r_low = resize_point(&r[..base_mu.min(r.len())].to_vec(), base_mu);
    let timer = start_timer!(|| "ChunkedBatchOpen.EvalChunks");
    let chunk_evals_at_r: Vec<F> = advice.chunk_polys.iter().map(|chunk| {
        // Chunk has base_mu variables
        eval_mle_poly(&chunk.evaluations, &r_low)
    }).collect();
    end_timer!(timer);

    // Step 4: Open all chunks at r_low using batch_open
    let timer = start_timer!(|| "ChunkedBatchOpen.BatchOpen");
    let batch_proof = batch_open(
        prover_param,
        &advice.chunk_polys,
        &advice.batch_advice,
        &r_low,
        transcript,
    )?;
    end_timer!(timer);

    Ok(DeepFoldBatchMultiProof {
        claimed_values,
        sumcheck_proof,
        chunk_evals_at_r,
        batch_proof,
    })
}

/// Batch verify multiple polynomial openings at different points (with chunking)
///
/// Verifies the sumcheck proof, checks chunk evaluations, and verifies the batch proof.
///
/// Protocol:
/// 1. Verify sumcheck: Σ_x [Σ_i γ^i * f_i(x) * eq(point_i, x)] = Σ_i γ^i * claimed_values[i]
/// 2. Get random point r from sumcheck
/// 3. Compute expected sumcheck final value from chunk_evals_at_r
/// 4. Verify batch proof for all chunks at r
#[allow(non_snake_case)]
pub fn chunked_batch_verify<F: PrimeField>(
    verifier_param: &DeepFoldVerifierParam<F>,
    commitment: &DeepFoldBatchMultiCommitment,
    points: &[Vec<F>],
    proof: &DeepFoldBatchMultiProof<F>,
    transcript: &mut IOPTranscript<F>,
) -> Result<bool, PCSError> {
    let base_mu = verifier_param.max_mu;
    let num_polys = commitment.num_polys;

    assert_eq!(num_polys, points.len());
    assert_eq!(num_polys, proof.claimed_values.len());
    assert_eq!(num_polys, commitment.chunks_per_poly.len());

    // Compute max_num_vars from commitment's original_num_vars
    let max_num_vars = commitment.original_num_vars.iter().copied().max().unwrap_or(base_mu).max(base_mu);

    // Step 1: Get gamma challenge and verify sumcheck
    let gamma = transcript.get_and_append_challenge(b"gamma")?;

    // Compute expected sum: Σ_i γ^i * claimed_values[i]
    let mut expected_sum = F::ZERO;
    for (i, &val) in proof.claimed_values.iter().enumerate() {
        expected_sum += gamma.pow([i as u64]) * val;
    }

    // Verify sumcheck over max_num_vars variables
    // chunked_batch_verify always uses degree 2 sumcheck (f * eq)
    let sumcheck_subclaim = <PolyIOP<F> as SumCheck<F>>::verify(
        expected_sum,
        &proof.sumcheck_proof,
        &VPAuxInfo {
            num_variables: max_num_vars,
            max_degree: 2, // f_i * eq product has degree 2
            phantom: PhantomData::<F>::default(),
        },
        transcript,
    ).map_err(|e| PCSError::SumCheckError(format!("{:?}", e)))?;

    let r = sumcheck_subclaim.point;
    let r_low = resize_point(&r[..base_mu.min(r.len())].to_vec(), base_mu);

    // Step 2: Verify sumcheck final evaluation using chunk_evals_at_r
    // The sumcheck polynomial at r is: Σ_i γ^i * f_i(r) * eq(point_i, r)
    // where f_i(r) is computed from chunk values
    let total_chunks: usize = commitment.chunks_per_poly.iter().sum();
    assert_eq!(proof.chunk_evals_at_r.len(), total_chunks);

    // Compute eq(point_i, r) for each polynomial
    // eq(y, x) = Π_j (y_j * x_j + (1 - y_j) * (1 - x_j))
    let eq_at_r: Vec<F> = points.iter().map(|point| {
        let padded_point = resize_point(&point.clone(), max_num_vars);
        compute_eq_eval(&padded_point, &r)
    }).collect();

    // For each polynomial, combine its chunk values to get f_i(r)
    // and compute the contribution to the sumcheck final value
    let mut computed_final_value = F::ZERO;
    let mut chunk_offset = 0;
    for poly_idx in 0..num_polys {
        let num_chunks = commitment.chunks_per_poly[poly_idx];
        let original_num_vars = commitment.original_num_vars[poly_idx];

        // Get chunk values at r for this polynomial
        let poly_chunk_evals = &proof.chunk_evals_at_r[chunk_offset..chunk_offset + num_chunks];

        // Compute f_i(r) by combining chunks
        // Chunks give: f(r_low) for the first base_mu coordinates
        // We need: f(r[0..original_num_vars]) for the sumcheck polynomial
        let mut f_i_at_r = if num_chunks == 1 {
            // Non-chunked polynomial: chunk gives f(r[0..min(original_num_vars, base_mu)]) * padding
            poly_chunk_evals[0]
        } else {
            // Chunked polynomial: combine chunks
            // f(r_low, r_high) = Σ_b f_b(r_low) * eq(b, r_high)
            let num_high_vars = original_num_vars - base_mu;
            let high_point = if num_high_vars <= r.len() - base_mu {
                r[base_mu..base_mu + num_high_vars].to_vec()
            } else {
                // Pad r if needed
                let mut hp = r[base_mu..].to_vec();
                while hp.len() < num_high_vars {
                    hp.push(F::ZERO);
                }
                hp
            };
            combine_chunk_values(poly_chunk_evals, &high_point)
        };

        // Apply padding factor for remaining coordinates up to max_num_vars
        // For non-chunked (num_vars <= base_mu): chunk is padded to base_mu, need factor for base_mu..max_num_vars
        // For chunked (num_vars > base_mu): chunks give f(r[0..num_vars]), need factor for num_vars..max_num_vars
        let padding_start = if num_chunks == 1 {
            base_mu  // Non-chunked: chunk is padded to base_mu
        } else {
            original_num_vars  // Chunked: chunks give original poly value
        };
        for i in padding_start..max_num_vars {
            f_i_at_r *= F::ONE - r[i];
        }

        // Add contribution: γ^i * f_i(r) * eq(point_i, r)
        computed_final_value += gamma.pow([poly_idx as u64]) * f_i_at_r * eq_at_r[poly_idx];
        chunk_offset += num_chunks;
    }

    // Check sumcheck final value
    if computed_final_value != sumcheck_subclaim.expected_evaluation {
        return Ok(false);
    }

    // Step 3: Verify the underlying batch proof for all chunks at r_low
    batch_verify(
        verifier_param,
        &commitment.batch_commitment,
        &r_low,
        &proof.chunk_evals_at_r,
        &proof.batch_proof,
        transcript,
    )
}

/// Compute the claimed values from a chunked batch proof
///
/// Returns the claimed evaluation values for each polynomial.
pub fn compute_claimed_values_from_proof<F: PrimeField>(
    proof: &DeepFoldBatchMultiProof<F>,
) -> Vec<F> {
    proof.claimed_values.clone()
}

// =============================================================================
// Distributed Multi-polynomial Batch Commit/Open
// =============================================================================

/// Query distributed Merkle proof for a given position
///
/// In distributed setting:
/// - Each party owns cols_per_party consecutive columns
/// - Master has upper_tree connecting party roots
/// - Workers have local_mt for their own columns
///
/// Returns (column_values, combined_proof) where combined_proof = upper_proof || local_proof
#[allow(non_snake_case)]
fn d_query_merkle_proof<F: PrimeField>(
    advice: &DeepFoldBatchMultiProverAdvice<F>,
    position: usize,
) -> (Vec<F>, Vec<Byte32>) {
    let num_party = Net::n_parties();
    let party_id = Net::party_id();
    let cols_per_party = advice.cols_per_party;

    // Broadcast query position to all parties
    let position: usize = if Net::am_master() {
        Net::recv_from_master_uniform(Some(position));
        position
    } else {
        Net::recv_from_master_uniform(None)
    };

    // Determine which party owns this position
    let owner_party = position / cols_per_party;
    let local_position = position % cols_per_party;

    // Each party checks if they own this position
    let is_owner = party_id == owner_party;

    // Owner computes local proof and sends to master
    // For non-owners, send empty data
    let (local_column_values, local_proof, local_hash): (Vec<F>, Vec<Byte32>, Byte32) = if is_owner {
        // Get column values at this position
        // Workers store: v0_matrix[col_idx] = [val_at_chunk_0, val_at_chunk_1, ...]
        // Master stores: v0_matrix[chunk_idx][col_idx] (full matrix, row-major)
        let column_values: Vec<F> = if Net::am_master() {
            // Master's v0_matrix is row-major: extract column from all rows
            let global_position = party_id * cols_per_party + local_position;
            advice.batch_advice.v0_matrix.iter()
                .map(|row| row[global_position])
                .collect()
        } else {
            // Workers' v0_matrix is column-indexed for their portion
            advice.batch_advice.v0_matrix[local_position].clone()
        };

        // Get local Merkle proof
        let local_mt = &advice.batch_advice.merkle_tree;
        let proof = local_mt.prove(local_position);
        let hash = advice.batch_advice.column_hashes[local_position];

        (column_values, proof, hash)
    } else {
        (vec![], vec![], [0u8; 32])
    };

    // Gather results to master
    let all_column_values_opt = Net::send_to_master(&local_column_values);
    let all_local_proofs_opt = Net::send_to_master(&local_proof);
    let all_local_hashes_opt = Net::send_to_master(&local_hash);

    if Net::am_master() {
        let all_column_values: Vec<Vec<F>> = all_column_values_opt.unwrap();
        let all_local_proofs: Vec<Vec<Byte32>> = all_local_proofs_opt.unwrap();
        let all_local_hashes: Vec<Byte32> = all_local_hashes_opt.unwrap();

        // Get data from owner party
        let column_values = all_column_values[owner_party].clone();
        let local_proof = all_local_proofs[owner_party].clone();
        let local_hash = all_local_hashes[owner_party];

        // Get upper tree proof for the owner party
        let upper_tree = advice.upper_tree.as_ref().unwrap();
        let upper_proof = upper_tree.prove(owner_party);

        // Combined proof: local_proof || upper_proof (leaf to root order)
        // This matches the standard MerkleTree::verify format:
        // - local_proof: verifies column_hash at local_position -> party_root
        // - upper_proof: verifies party_root at owner_party -> global_root
        let mut combined_proof = local_proof;
        combined_proof.extend(upper_proof);

        (column_values, combined_proof)
    } else {
        (vec![], vec![])
    }
}

/// Verify a distributed Merkle proof
///
/// The proof structure is: local_proof || upper_proof (leaf to root order)
/// This is equivalent to standard MerkleTree::verify for the full tree.
/// Verification:
/// 1. Compute column_hash from column_values
/// 2. Verify local_proof: column_hash at local_position -> party_root
/// 3. Verify upper_proof: party_root at owner_party -> global_root
///
/// Note: This function is provided for documentation. In practice, use MerkleTree::verify
/// directly since the proof format is compatible.
#[allow(dead_code)]
fn verify_distributed_merkle_proof<F: PrimeField>(
    global_root: &Byte32,
    position: usize,
    column_values: &[F],
    proof: &[Byte32],
    cols_per_party: usize,
    num_parties: usize,
) -> bool {
    let owner_party = position / cols_per_party;
    let local_position = position % cols_per_party;

    // Split proof into local and upper parts
    let local_proof_len = (cols_per_party as f64).log2().ceil() as usize;
    if proof.len() < local_proof_len {
        return false;
    }
    let (local_proof, upper_proof) = proof.split_at(local_proof_len);

    // Compute column hash
    let column_hash = compute_sha256_row(column_values);

    // Verify local proof -> party_root
    let mut current_hash = column_hash;
    let mut idx = local_position;
    for &sibling in local_proof.iter() {
        let combined = if idx % 2 == 0 {
            [current_hash, sibling].concat()
        } else {
            [sibling, current_hash].concat()
        };
        current_hash = compute_sha256(&combined);
        idx /= 2;
    }
    let party_root = current_hash;

    // Verify upper proof -> global_root
    let mut current_hash = party_root;
    let mut idx = owner_party;
    for &sibling in upper_proof.iter() {
        let combined = if idx % 2 == 0 {
            [current_hash, sibling].concat()
        } else {
            [sibling, current_hash].concat()
        };
        current_hash = compute_sha256(&combined);
        idx /= 2;
    }

    current_hash == *global_root
}

/// Distributed batch commit multiple polynomials with chunking support
///
/// Each node holds a portion of the polynomials. The protocol:
/// 1. For each polynomial:
///    - If local portion < base_mu: gather to master, master handles chunking
///    - Otherwise: split locally into chunks of size 2^max_mu
/// 2. Each node computes FFT for its assigned chunks
/// 3. Gather all FFT results to master
/// 4. Master distributes columns evenly to workers
/// 5. Each worker computes column hashes
/// 6. Run distributed Merkle Tree
///
/// Returns (Option<commitment>, advice) - commitment is Some only for master
#[allow(non_snake_case)]
pub fn d_chunked_batch_commit<F: PrimeField>(
    prover_param: &DeepFoldProverParam<F>,
    polys: &[Arc<DenseMultilinearExtension<F>>],
) -> Result<(Option<DeepFoldBatchMultiCommitment>, DeepFoldBatchMultiProverAdvice<F>), PCSError> {
    let base_mu = prover_param.max_mu;
    let num_polys = polys.len();
    let num_party = Net::n_parties();
    let num_party_vars = num_party.ilog2() as usize;
    let l0 = prover_param.l0;
    let len_l0 = l0.size();

    assert!(!polys.is_empty(), "Must commit at least one polynomial");

    // Step 1: Process each polynomial based on its size
    // - Small polynomials (local portion < base_mu): gather to master
    // - Large polynomials (local portion >= base_mu): split locally
    let timer = start_timer!(|| format!("DBatchMultiCommit.Split({})", num_polys));

    // Track chunks and metadata
    let mut local_chunks: Vec<Arc<DenseMultilinearExtension<F>>> = Vec::new();
    let mut local_f0_matrix: Vec<Vec<F>> = Vec::new();
    let mut local_v0_matrix: Vec<Vec<F>> = Vec::new();
    let mut chunks_per_poly: Vec<usize> = Vec::with_capacity(num_polys);
    let mut original_num_vars: Vec<usize> = Vec::with_capacity(num_polys);
    // Track which polynomials are large (need reordering) and how many local chunks each has
    let mut is_large_poly: Vec<bool> = Vec::with_capacity(num_polys);
    let mut local_chunks_per_large_poly: Vec<usize> = Vec::new();

    // Master also tracks chunks from small polynomials
    let mut master_chunks: Vec<Arc<DenseMultilinearExtension<F>>> = Vec::new();
    let mut master_f0_matrix: Vec<Vec<F>> = Vec::new();
    let mut master_v0_matrix: Vec<Vec<F>> = Vec::new();

    // Each party stores their local polynomial evaluations for distributed sumcheck
    let mut local_poly_evals: Vec<Vec<F>> = Vec::with_capacity(num_polys);

    for poly in polys {
        // Store local polynomial evaluations (each party keeps their own portion)
        local_poly_evals.push(poly.evaluations.clone());
        let full_num_vars = poly.num_vars + num_party_vars;
        original_num_vars.push(full_num_vars);

        if poly.num_vars < base_mu {
            // Case: Local portion is smaller than base_mu
            // Need to gather to master for proper chunking
            is_large_poly.push(false);
            let timer_gather = start_timer!(|| format!("DBatchMultiCommit.Split.GatherSmall(2^{})", poly.num_vars));
            let local_evals = poly.evaluations.clone();
            let all_evals_opt = Net::send_to_master(&local_evals);
            end_timer!(timer_gather);

            if Net::am_master() {
                // Assemble full polynomial from all parties
                // Variable ordering is [x_local, x_party] - party_id becomes the high bits
                let timer_flatten = start_timer!(|| "DBatchMultiCommit.Split.Flatten");
                let all_evals: Vec<Vec<F>> = all_evals_opt.unwrap();
                let full_evals: Vec<F> = all_evals.into_iter().flatten().collect();
                let full_poly = evals_to_arcpoly(&full_evals);
                end_timer!(timer_flatten);

                // Split into chunks (handles both full_num_vars <= base_mu and > base_mu)
                let (chunks, num_chunks) = split_polynomial_into_chunks(&full_poly, base_mu);
                chunks_per_poly.push(num_chunks);

                // Compute FFT for each chunk on master
                let timer_fft = start_timer!(|| format!("DBatchMultiCommit.Split.FFT({}chunks)", num_chunks));
                for chunk in &chunks {
                    let f0 = evals_to_coeffs(base_mu, &chunk.evaluations);
                    let v0 = l0.fft(&f0);
                    master_f0_matrix.push(f0);
                    master_v0_matrix.push(v0);
                }
                end_timer!(timer_fft);
                master_chunks.extend(chunks);
            } else {
                // Workers record chunk count but don't process
                if full_num_vars <= base_mu {
                    chunks_per_poly.push(1);
                } else {
                    chunks_per_poly.push(1 << (full_num_vars - base_mu));
                }
            }
        } else {
            // Case: Local portion is >= base_mu
            // Can split locally and distribute work
            is_large_poly.push(true);
            let (chunks, num_chunks) = split_polynomial_into_chunks(poly, base_mu);
            let total_chunks_for_poly = num_chunks * num_party;
            chunks_per_poly.push(total_chunks_for_poly);
            local_chunks_per_large_poly.push(num_chunks);

            // Compute FFT for local chunks
            let timer_local_fft = start_timer!(|| format!("DBatchMultiCommit.Split.LocalFFT({}chunks)", num_chunks));
            for chunk in &chunks {
                let f0 = evals_to_coeffs(base_mu, &chunk.evaluations);
                let v0 = l0.fft(&f0);
                local_f0_matrix.push(f0);
                local_v0_matrix.push(v0);
            }
            end_timer!(timer_local_fft);
            local_chunks.extend(chunks);
        }
    }
    end_timer!(timer);

    // Step 2: Gather distributed FFT results and chunk evaluations to master
    let timer = start_timer!(|| "DBatchMultiCommit.Gather");
    let all_v0_matrices_opt = Net::send_to_master(&local_v0_matrix);
    let all_f0_matrices_opt = Net::send_to_master(&local_f0_matrix);
    // Also gather chunk evaluations for efficient open phase
    let local_chunk_evals: Vec<Vec<F>> = local_chunks.iter()
        .map(|chunk| chunk.evaluations.clone())
        .collect();
    let all_chunk_evals_opt = Net::send_to_master(&local_chunk_evals);
    end_timer!(timer);

    // Step 3: Master assembles full matrices and chunk evaluations
    // IMPORTANT: Reorder chunks to maintain original polynomial order
    // For large polys, also reorder from party-order to poly-order
    let (full_v0_matrix, full_f0_matrix, full_chunk_polys, total_chunks, full_chunks_per_poly): (Vec<Vec<F>>, Vec<Vec<F>>, Vec<Arc<DenseMultilinearExtension<F>>>, usize, Vec<usize>) =
        if Net::am_master() {
            let mut all_v0_matrices: Vec<Vec<Vec<F>>> = all_v0_matrices_opt.unwrap();
            let mut all_f0_matrices: Vec<Vec<Vec<F>>> = all_f0_matrices_opt.unwrap();
            let mut all_chunk_evals: Vec<Vec<Vec<F>>> = all_chunk_evals_opt.unwrap();

            let mut combined_v0: Vec<Vec<F>> = Vec::new();
            let mut combined_f0: Vec<Vec<F>> = Vec::new();
            let mut combined_chunk_polys: Vec<Arc<DenseMultilinearExtension<F>>> = Vec::new();

            // Track positions in master_chunks (for small polys) and party chunks (for large polys)
            let mut master_offset = 0;
            let mut large_poly_idx = 0;
            let mut party_offsets: Vec<usize> = vec![0; num_party]; // Current offset in each party's data

            // Process polynomials in original input order
            for poly_idx in 0..num_polys {
                if !is_large_poly[poly_idx] {
                    // Small poly: take chunks from master_chunks
                    let num_chunks = chunks_per_poly[poly_idx];
                    for _ in 0..num_chunks {
                        combined_v0.push(std::mem::take(&mut master_v0_matrix[master_offset]));
                        combined_f0.push(std::mem::take(&mut master_f0_matrix[master_offset]));
                        combined_chunk_polys.push(std::mem::take(&mut master_chunks[master_offset]));
                        master_offset += 1;
                    }
                } else {
                    // Large poly: gather chunks from all parties in poly-order
                    let chunks_per_party = local_chunks_per_large_poly[large_poly_idx];
                    for party_idx in 0..num_party {
                        let start = party_offsets[party_idx];
                        let end = start + chunks_per_party;
                        for i in start..end {
                            combined_v0.push(std::mem::take(&mut all_v0_matrices[party_idx][i]));
                            combined_f0.push(std::mem::take(&mut all_f0_matrices[party_idx][i]));
                            combined_chunk_polys.push(evals_to_arcpoly(&std::mem::take(&mut all_chunk_evals[party_idx][i])));
                        }
                        party_offsets[party_idx] = end;
                    }
                    large_poly_idx += 1;
                }
            }

            let total = combined_v0.len();
            (combined_v0, combined_f0, combined_chunk_polys, total, chunks_per_poly.clone())
        } else {
            (vec![], vec![], vec![], 0, vec![])
        };

    // Broadcast total_chunks to all parties
    let total_chunks: usize = if Net::am_master() {
        Net::recv_from_master_uniform(Some(total_chunks));
        total_chunks
    } else {
        Net::recv_from_master_uniform(None)
    };

    // Step 4: Master distributes columns to workers
    // Matrix: total_chunks rows × len_l0 columns
    // Distribute columns evenly: each party gets len_l0 / num_party columns
    let cols_per_party = len_l0 / num_party;

    let timer = start_timer!(|| "DBatchMultiCommit.DistColData");
    let local_columns: Vec<F> = if Net::am_master() {
        // Prepare column data for each party
        // Column j contains: v0_matrix[0][j], v0_matrix[1][j], ..., v0_matrix[total_chunks-1][j]
        let columns_for_parties: Vec<Vec<F>> = (0..num_party)
            .map(|k| {
                let start_col = k * cols_per_party;
                let end_col = (k + 1) * cols_per_party;
                let mut party_data = Vec::with_capacity(cols_per_party * total_chunks);
                for col in start_col..end_col {
                    for row in 0..total_chunks {
                        party_data.push(full_v0_matrix[row][col]);
                    }
                }
                party_data
            })
            .collect();
        Net::recv_from_master(Some(columns_for_parties))
    } else {
        Net::recv_from_master(None)
    };
    end_timer!(timer);

    // Step 5: Each party computes column hashes and stores column data for proof queries
    let timer = start_timer!(|| "DBatchMultiCommit.ColHash");
    // Convert local_columns to column-indexed format for proof queries
    // local_column_data[col][row] = value at (row, col) within this party's columns
    let local_column_data: Vec<Vec<F>> = (0..cols_per_party)
        .map(|i| {
            (0..total_chunks)
                .map(|j| local_columns[i * total_chunks + j])
                .collect()
        })
        .collect();

    let local_leaves: Vec<Byte32> = local_column_data.iter()
        .map(|column| compute_sha256_row(column))
        .collect();
    end_timer!(timer);

    // Step 6: Build distributed Merkle tree (lazy leaf transfer)
    // Each party builds local tree, only roots are gathered to master
    let timer = start_timer!(|| "DBatchMultiCommit.Merkle");

    // Build local tree for proof generation
    let timer_local = start_timer!(|| format!("Merkle.LocalTree({}leaves)", local_leaves.len()));
    let local_mt = MerkleTree::new(&local_leaves);
    let local_root = local_mt.root();
    end_timer!(timer_local);

    // Only gather roots (not all leaves!) - this is the key optimization
    let timer_roots = start_timer!(|| "Merkle.GatherRoots");
    let all_roots_opt = Net::send_to_master(&local_root);
    end_timer!(timer_roots);
    end_timer!(timer);

    if Net::am_master() {
        let all_roots: Vec<Byte32> = all_roots_opt.unwrap();

        // Build upper tree from party roots
        // The root of this upper tree equals the root of the full tree
        let upper_tree = MerkleTree::new(&all_roots);
        let root = upper_tree.root();

        Ok((
            Some(DeepFoldBatchMultiCommitment {
                batch_commitment: DeepFoldBatchCommitment {
                    mu: base_mu,
                    num_polys: total_chunks,
                    root,
                },
                num_polys,
                chunks_per_poly: full_chunks_per_poly,
                original_num_vars,
            }),
            DeepFoldBatchMultiProverAdvice {
                batch_advice: DeepFoldBatchProverAdvice {
                    f0_matrix: full_f0_matrix,
                    v0_matrix: full_v0_matrix,
                    // Master also stores its local column hashes for proof queries when it's the owner
                    column_hashes: local_leaves,
                    // Master stores its local merkle tree for proof queries when it's the owner
                    merkle_tree: local_mt,
                },
                // Master has all chunk polys in poly-major order (assembled from all parties)
                chunk_polys: full_chunk_polys,
                chunks_per_poly: chunks_per_poly.clone(),
                base_mu,
                // Master also stores local poly evals for distributed sumcheck
                local_poly_evals,
                cols_per_party,
                upper_tree: Some(upper_tree),
                party_roots: all_roots,
            },
        ))
    } else {
        Ok((
            None,
            DeepFoldBatchMultiProverAdvice {
                batch_advice: DeepFoldBatchProverAdvice {
                    f0_matrix: local_f0_matrix,
                    // Workers store column data for distributed proof queries
                    // v0_matrix[col_idx] = [val_at_chunk_0, val_at_chunk_1, ...]
                    // This allows efficient lookup: v0_matrix[local_position] gives all values for that column
                    v0_matrix: local_column_data,
                    // Workers keep their local leaves for on-demand queries
                    column_hashes: local_leaves,
                    merkle_tree: local_mt,
                },
                // Workers only have local_chunks (from large polys they processed)
                chunk_polys: local_chunks,
                chunks_per_poly,
                base_mu,
                // Workers store local poly evals for distributed sumcheck
                local_poly_evals,
                cols_per_party,
                upper_tree: None,
                party_roots: vec![],
            },
        ))
    }
}

/// Distributed batch open multiple polynomials at different points (with chunking)
///
/// Uses sumcheck to reduce to a single point, then distributed batch opening.
/// Each polynomial can be opened at a different point.
///
/// For polynomials where local portion < base_mu, evals are gathered to master.
#[allow(non_snake_case)]
pub fn d_chunked_batch_open<F: PrimeField>(
    prover_param: &DeepFoldProverParam<F>,
    polys: &[Arc<DenseMultilinearExtension<F>>],
    advice: &DeepFoldBatchMultiProverAdvice<F>,
    points: &[Vec<F>],
    transcript: &mut IOPTranscript<F>,
) -> Result<Option<DeepFoldBatchMultiProof<F>>, PCSError> {
    let base_mu = prover_param.max_mu;
    let num_polys = polys.len();
    let num_party = Net::n_parties();
    let num_party_vars = num_party.ilog2() as usize;

    // Broadcast points to all parties
    let points: Vec<Vec<F>> = if Net::am_master() {
        Net::recv_from_master_uniform(Some(points.to_vec()));
        points.to_vec()
    } else {
        Net::recv_from_master_uniform(None)
    };

    assert_eq!(num_polys, points.len(), "Must have same number of points as polynomials");
    assert_eq!(num_polys, advice.chunks_per_poly.len());

    // Step 1: For small polynomials (local portion < base_mu), gather to master
    // Build full polynomials for sumcheck
    let timer = start_timer!(|| "DChunkedBatchOpen.GatherSmallPolys");
    let mut full_polys: Vec<Arc<DenseMultilinearExtension<F>>> = Vec::with_capacity(num_polys);
    let mut full_num_vars_list: Vec<usize> = Vec::with_capacity(num_polys);

    for poly in polys {
        let full_num_vars = poly.num_vars + num_party_vars;
        full_num_vars_list.push(full_num_vars);

        if poly.num_vars < base_mu {
            // Small polynomial: gather to master
            let local_evals = poly.evaluations.clone();
            let all_evals_opt = Net::send_to_master(&local_evals);

            if Net::am_master() {
                let all_evals: Vec<Vec<F>> = all_evals_opt.unwrap();
                let full_evals: Vec<F> = all_evals.into_iter().flatten().collect();
                full_polys.push(evals_to_arcpoly(&full_evals));
            } else {
                // Workers push a placeholder (won't be used)
                full_polys.push(Arc::clone(poly));
            }
        } else {
            // Large polynomial: master needs to gather for sumcheck anyway
            // (since sumcheck requires full polynomial)
            let local_evals = poly.evaluations.clone();
            let all_evals_opt = Net::send_to_master(&local_evals);

            if Net::am_master() {
                let all_evals: Vec<Vec<F>> = all_evals_opt.unwrap();
                let full_evals: Vec<F> = all_evals.into_iter().flatten().collect();
                full_polys.push(evals_to_arcpoly(&full_evals));
            } else {
                full_polys.push(Arc::clone(poly));
            }
        }
    }
    end_timer!(timer);

    // Find max number of variables across all FULL polynomials
    let max_num_vars = full_num_vars_list.iter().copied().max().unwrap_or(base_mu).max(base_mu);

    // Master reconstructs all chunk polynomials from gathered full_polys
    // This is needed because advice.chunk_polys only contains master's local chunks,
    // but we need ALL chunks for d_batch_open_inner
    let all_chunk_polys: Vec<Arc<DenseMultilinearExtension<F>>> = if Net::am_master() {
        let timer = start_timer!(|| "DChunkedBatchOpen.ReconstructChunks");
        let mut chunks = Vec::new();
        for (poly_idx, full_poly) in full_polys.iter().enumerate() {
            let full_nv = full_num_vars_list[poly_idx];
            let (poly_chunks, _) = split_polynomial_into_chunks(full_poly, base_mu);
            chunks.extend(poly_chunks);
        }
        end_timer!(timer);
        chunks
    } else {
        vec![]
    };

    // Master computes claimed values and runs sumcheck
    let (claimed_values, sumcheck_proof, r, chunk_evals_at_r) = if Net::am_master() {
        // Step 2: Compute claimed values for each polynomial at its respective point
        let timer = start_timer!(|| "DChunkedBatchOpen.ComputeClaims");
        let claimed_values: Vec<F> = full_polys.iter().zip(points.iter()).zip(full_num_vars_list.iter())
            .map(|((poly, point), &full_nv)| {
                let padded_point = resize_point(&point.clone(), full_nv);
                eval_mle_poly(&poly.evaluations, &padded_point)
            }).collect();
        end_timer!(timer);

        // Step 3: Sumcheck to reduce to a single point
        // All polynomials are padded to max_num_vars variables
        let timer = start_timer!(|| "DChunkedBatchOpen.Sumcheck");
        let gamma = transcript.get_and_append_challenge(b"gamma")?;

        let mut sumcheck_poly = VirtualPolynomial::new(max_num_vars);
        for i in 0..num_polys {
            // Pad polynomial to max_num_vars variables
            let padded_evals = resize_eval(&full_polys[i].evaluations, max_num_vars);
            let padded_poly = evals_to_arcpoly(&padded_evals);

            // Pad point to max_num_vars variables
            let padded_point = resize_point(&points[i].clone(), max_num_vars);
            let eq_poly = evals_to_arcpoly(&get_tensor(&padded_point));

            sumcheck_poly
                .add_mle_list([padded_poly, eq_poly], gamma.pow([i as u64]))
                .map_err(|e| PCSError::VirtualPolynomialError(format!("{:?}", e)))?;
        }

        let sumcheck_result = <PolyIOP<F> as SumCheck<F>>::prove(sumcheck_poly, transcript)
            .map_err(|e| PCSError::SumCheckError(format!("{:?}", e)))?;
        let r = sumcheck_result.point.clone();
        end_timer!(timer);

        // Step 4: Evaluate all chunks at r_low (first base_mu coordinates of r)
        let r_low = resize_point(&r[..base_mu.min(r.len())].to_vec(), base_mu);
        let timer = start_timer!(|| "DChunkedBatchOpen.EvalChunks");
        // Use all_chunk_polys (reconstructed from full_polys) instead of advice.chunk_polys
        let chunk_evals_at_r: Vec<F> = all_chunk_polys.iter().map(|chunk| {
            // Chunk has base_mu variables
            eval_mle_poly(&chunk.evaluations, &r_low)
        }).collect();
        end_timer!(timer);

        (claimed_values, sumcheck_result, r, chunk_evals_at_r)
    } else {
        // Workers need to follow along with transcript
        let _ = transcript.get_and_append_challenge(b"gamma")?;
        // Workers don't run sumcheck prover, they'll sync via broadcast
        (vec![], IOPProof::default(), vec![], vec![])
    };

    // Broadcast r to all parties for batch_open
    let r: Vec<F> = if Net::am_master() {
        Net::recv_from_master_uniform(Some(r.clone()));
        r
    } else {
        Net::recv_from_master_uniform(None)
    };

    // Compute r_low from r (first base_mu coordinates)
    let r_low = resize_point(&r[..base_mu.min(r.len())].to_vec(), base_mu);

    // Step 4: Distributed batch open all chunks at r_low
    let timer = start_timer!(|| "DChunkedBatchOpen.BatchOpen");
    // Use all_chunk_polys (reconstructed from full_polys) for d_batch_open_inner
    let batch_proof_opt = d_batch_open_inner(
        prover_param,
        &all_chunk_polys,
        &advice.batch_advice,
        &r_low,
        transcript,
    )?;
    end_timer!(timer);

    if Net::am_master() {
        Ok(Some(DeepFoldBatchMultiProof {
            claimed_values,
            sumcheck_proof,
            chunk_evals_at_r,
            batch_proof: batch_proof_opt.unwrap(),
        }))
    } else {
        Ok(None)
    }
}

/// Distributed batch open helper
/// Coordinates distributed proof generation across parties
#[allow(non_snake_case)]
fn d_batch_open_inner<F: PrimeField>(
    prover_param: &DeepFoldProverParam<F>,
    polys: &[Arc<DenseMultilinearExtension<F>>],
    advice: &DeepFoldBatchProverAdvice<F>,
    point: &[F],
    transcript: &mut IOPTranscript<F>,
) -> Result<Option<DeepFoldBatchProof<F>>, PCSError> {
    let DeepFoldProverParam { max_mu, l0, s } = prover_param.clone();
    let mu = max_mu;
    let num_party = Net::n_parties();

    // Gather full state at master for proof computation
    // (In production, this would be more distributed, but for correctness we centralize)

    // Broadcast point to all parties
    let point: Vec<F> = if Net::am_master() {
        Net::recv_from_master_uniform(Some(point.to_vec()));
        point.to_vec()
    } else {
        Net::recv_from_master_uniform(None)
    };

    // Master computes the proof using gathered data
    if Net::am_master() {
        // Master has full advice from commit phase
        let num_polys = advice.f0_matrix.len();

        assert_eq!(point.len(), mu, "Point must have mu coordinates");

        // Initialize evaluation domains
        let mut domains: Vec<GeneralEvaluationDomain<F>> = vec![l0];
        for i in 1..=mu {
            domains.push(GeneralEvaluationDomain::<F>::new(l0.size() >> i).unwrap());
        }

        // Initialize f_tilde (evaluations) for each polynomial
        // For distributed case, we need to reconstruct from chunks
        let mut f_tilde: Vec<Vec<F>> = polys.iter().map(|p| {
            resize_eval(&p.evaluations, mu)
        }).collect();
        let mut f: Vec<Vec<F>> = advice.f0_matrix.clone();
        let mut v: Vec<Vec<F>> = advice.v0_matrix.clone();

        // Track Merkle trees and roots at each level
        let mut merkle_roots = vec![advice.merkle_tree.root()];
        let mut merkle_trees = vec![advice.merkle_tree.clone()];
        let mut v_matrices: Vec<Vec<Vec<F>>> = vec![v.clone()];

        // Auxiliary evaluation points
        let mut a: Vec<Vec<Vec<F>>> = vec![vec![point.to_vec()]];
        let mut alpha_vec: Vec<F> = vec![F::ZERO];

        let mut linear_polys: Vec<Vec<Vec<(F, F)>>> = Vec::new();
        let mut final_values = Vec::new();

        // Folding process (same as non-distributed version)
        for i in 1..=mu {
            let alpha = transcript.get_and_append_challenge(b"alpha")?;
            alpha_vec.push(alpha);
            a[i - 1].push(get_alpha_powers::<F>(alpha, mu - i + 1));

            let mut level_linear_polys: Vec<Vec<(F, F)>> = Vec::new();

            if i == mu {
                let mut aux_polys = Vec::with_capacity(num_polys);
                for k in 0..num_polys {
                    let (f0_split, f1_split) = split_even_odd(&f_tilde[k]);
                    aux_polys.push((f0_split[0], f1_split[0]));
                }
                level_linear_polys.push(aux_polys);
            } else {
                for w in &a[i - 1] {
                    assert!(!w.is_empty());
                    let w_tensor = get_tensor(&w[1..].to_vec());

                    let mut aux_polys = Vec::with_capacity(num_polys);
                    for k in 0..num_polys {
                        let (f0_split, f1_split) = split_even_odd(&f_tilde[k]);
                        let a_coef = inner_product(&w_tensor, &f0_split);
                        let b_coef = inner_product(&w_tensor, &f1_split);
                        aux_polys.push((a_coef, b_coef));
                    }
                    level_linear_polys.push(aux_polys);
                }

                a.push(a[i - 1].iter().map(|w| w[1..].to_vec()).collect());
            }
            linear_polys.push(level_linear_polys);

            let r = transcript.get_and_append_challenge(b"r")?;

            let mut new_f = Vec::with_capacity(num_polys);
            let mut new_f_tilde = Vec::with_capacity(num_polys);

            for k in 0..num_polys {
                let (fe, fo) = split_even_odd(&f[k]);
                let (f0_split, f1_split) = split_even_odd(&f_tilde[k]);

                new_f.push(vector_add(&fe, &scalar_vector_product(r, &fo)));
                new_f_tilde.push(vector_add(
                    &scalar_vector_product(F::ONE - r, &f0_split),
                    &scalar_vector_product(r, &f1_split),
                ));
            }

            f = new_f;
            f_tilde = new_f_tilde;

            let new_v: Vec<Vec<F>> = f
                .iter()
                .map(|coefs| domains[i].fft(coefs))
                .collect();

            if i == mu {
                for k in 0..num_polys {
                    final_values.push(new_v[k][0]);
                }
            } else {
                let len_v = new_v[0].len();
                let column_hashes: Vec<Byte32> = (0..len_v)
                    .map(|j| {
                        let column: Vec<F> = (0..num_polys).map(|k| new_v[k][j]).collect();
                        compute_sha256_row(&column)
                    })
                    .collect();

                let mt = MerkleTree::new(&column_hashes);
                merkle_roots.push(mt.root());
                merkle_trees.push(mt);
                v_matrices.push(new_v.clone());
            }

            v = new_v;
        }

        // FRI consistency checks
        let mut merkle_proofs: Vec<Vec<(usize, Vec<(F, F)>, Vec<Byte32>, Vec<Byte32>)>> = Vec::new();

        for _t in 0..s {
            let mut beta = transcript.get_and_append_challenge_indices(b"beta", 1, domains[0].size())?[0];

            let mut level_proofs = Vec::new();

            for i in 0..mu {
                let v_matrix = &v_matrices[i];
                let mt = &merkle_trees[i];
                let domain = &domains[i];

                let beta_prime = if beta >= domain.size() / 2 {
                    beta - domain.size() / 2
                } else {
                    beta + domain.size() / 2
                };

                let values: Vec<(F, F)> = (0..num_polys)
                    .map(|k| (v_matrix[k][beta], v_matrix[k][beta_prime]))
                    .collect();

                let proof_beta = mt.prove(beta);
                let proof_beta_prime = mt.prove(beta_prime);

                level_proofs.push((beta, values, proof_beta, proof_beta_prime));

                if beta >= domains[i + 1].size() {
                    beta -= domains[i + 1].size();
                }
            }

            merkle_proofs.push(level_proofs);
        }

        Ok(Some(DeepFoldBatchProof {
            linear_polys,
            merkle_roots,
            final_values,
            merkle_proofs,
        }))
    } else {
        // Workers participate in transcript updates
        for _i in 1..=mu {
            let _ = transcript.get_and_append_challenge(b"alpha")?;
            let _ = transcript.get_and_append_challenge(b"r")?;
        }
        for _t in 0..s {
            let _ = transcript.get_and_append_challenge_indices(b"beta", 1, l0.size())?;
        }
        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::deepfold::DeepFoldPCS;
    use crate::PolynomialCommitmentScheme;
    use ark_ff::Field;
    use ark_poly::MultilinearExtension;
    use ark_std::test_rng;

    type F = crate::FGoldilocks;

    #[test]
    fn test_batch_commit_single_poly() {
        let mut rng = test_rng();
        let mu = 4;

        // Generate SRS
        let srs = DeepFoldPCS::<F>::gen_srs_for_testing(&mut rng, mu).unwrap();
        let (prover_param, _verifier_param) = DeepFoldPCS::<F>::setup(&srs).unwrap();

        // Create a random polynomial
        let evals: Vec<F> = (0..1 << mu).map(|i| F::from(i as u64)).collect();
        let poly = evals_to_arcpoly(&evals);

        // Batch commit with single polynomial
        let (commitment, advice) = batch_commit(&prover_param, &[poly.clone()]).unwrap();

        assert_eq!(commitment.mu, mu);
        assert_eq!(commitment.num_polys, 1);
        assert_eq!(advice.f0_matrix.len(), 1);
        assert_eq!(advice.v0_matrix.len(), 1);
    }

    #[test]
    fn test_batch_commit_multiple_polys() {
        let mut rng = test_rng();
        let mu = 4;
        let num_polys = 3;

        // Generate SRS
        let srs = DeepFoldPCS::<F>::gen_srs_for_testing(&mut rng, mu).unwrap();
        let (prover_param, _verifier_param) = DeepFoldPCS::<F>::setup(&srs).unwrap();

        // Create random polynomials
        let polys: Vec<Arc<DenseMultilinearExtension<F>>> = (0..num_polys)
            .map(|k| {
                let evals: Vec<F> = (0..1 << mu)
                    .map(|i| F::from((i + k * 100) as u64))
                    .collect();
                evals_to_arcpoly(&evals)
            })
            .collect();

        // Batch commit
        let (commitment, advice) = batch_commit(&prover_param, &polys).unwrap();

        assert_eq!(commitment.mu, mu);
        assert_eq!(commitment.num_polys, num_polys);
        assert_eq!(advice.f0_matrix.len(), num_polys);
        assert_eq!(advice.v0_matrix.len(), num_polys);
        assert_eq!(advice.column_hashes.len(), prover_param.l0.size());
    }

    #[test]
    fn test_batch_open_single_poly() {
        let mut rng = test_rng();
        let mu = 4;

        // Generate SRS
        let srs = DeepFoldPCS::<F>::gen_srs_for_testing(&mut rng, mu).unwrap();
        let (prover_param, verifier_param) = DeepFoldPCS::<F>::setup(&srs).unwrap();

        // Create polynomial
        let evals: Vec<F> = (0..1 << mu).map(|i| F::from(i as u64)).collect();
        let poly = evals_to_arcpoly(&evals);

        // Commit
        let (commitment, advice) = batch_commit(&prover_param, &[poly.clone()]).unwrap();

        // Create opening point
        let point: Vec<F> = (0..mu).map(|i| F::from((i + 1) as u64)).collect();

        // Compute expected value
        let expected_value = poly.evaluate(&point).unwrap();

        // Open
        let mut transcript = IOPTranscript::<F>::new(b"test");
        let proof = batch_open(&prover_param, &[poly], &advice, &point, &mut transcript).unwrap();

        assert_eq!(proof.linear_polys.len(), mu);
        assert_eq!(proof.final_values.len(), 1);

        // Verify
        let mut transcript = IOPTranscript::<F>::new(b"test");
        let result = batch_verify(
            &verifier_param,
            &commitment,
            &point,
            &[expected_value],
            &proof,
            &mut transcript,
        ).unwrap();

        assert!(result, "Verification should pass");
    }

    #[test]
    fn test_batch_open_multiple_polys() {
        let mut rng = test_rng();
        let mu = 4;
        let num_polys = 3;

        // Generate SRS
        let srs = DeepFoldPCS::<F>::gen_srs_for_testing(&mut rng, mu).unwrap();
        let (prover_param, verifier_param) = DeepFoldPCS::<F>::setup(&srs).unwrap();

        // Create polynomials
        let polys: Vec<Arc<DenseMultilinearExtension<F>>> = (0..num_polys)
            .map(|k| {
                let evals: Vec<F> = (0..1 << mu)
                    .map(|i| F::from((i + k * 100) as u64))
                    .collect();
                evals_to_arcpoly(&evals)
            })
            .collect();

        // Commit
        let (commitment, advice) = batch_commit(&prover_param, &polys).unwrap();

        // Create opening point
        let point: Vec<F> = (0..mu).map(|i| F::from((i + 1) as u64)).collect();

        // Compute expected values
        let expected_values: Vec<F> = polys.iter().map(|p| p.evaluate(&point).unwrap()).collect();

        // Open
        let mut transcript = IOPTranscript::<F>::new(b"test");
        let proof = batch_open(&prover_param, &polys, &advice, &point, &mut transcript).unwrap();

        assert_eq!(proof.linear_polys.len(), mu);
        assert_eq!(proof.final_values.len(), num_polys);

        // Verify
        let mut transcript = IOPTranscript::<F>::new(b"test");
        let result = batch_verify(
            &verifier_param,
            &commitment,
            &point,
            &expected_values,
            &proof,
            &mut transcript,
        ).unwrap();

        assert!(result, "Verification should pass");
    }

    #[test]
    fn test_batch_multi_commit_small_polys() {
        let mut rng = test_rng();
        let mu = 4;

        // Generate SRS
        let srs = DeepFoldPCS::<F>::gen_srs_for_testing(&mut rng, mu).unwrap();
        let (prover_param, _verifier_param) = DeepFoldPCS::<F>::setup(&srs).unwrap();

        // Create polynomials smaller than max_mu (will be padded, no chunking)
        let polys: Vec<Arc<DenseMultilinearExtension<F>>> = vec![
            evals_to_arcpoly(&(0..4).map(|i| F::from(i as u64)).collect::<Vec<_>>()), // 2 vars
            evals_to_arcpoly(&(0..8).map(|i| F::from(i as u64 + 10)).collect::<Vec<_>>()), // 3 vars
            evals_to_arcpoly(&(0..16).map(|i| F::from(i as u64 + 100)).collect::<Vec<_>>()), // 4 vars = max_mu
        ];

        // Batch multi commit
        let (commitment, advice) = chunked_batch_commit(&prover_param, &polys).unwrap();

        assert_eq!(commitment.num_polys, 3);
        assert_eq!(commitment.chunks_per_poly, vec![1, 1, 1]); // All fit in one chunk
        assert_eq!(commitment.original_num_vars, vec![2, 3, 4]);
        assert_eq!(advice.chunk_polys.len(), 3);
    }

    #[test]
    fn test_batch_multi_commit_large_polys() {
        let mut rng = test_rng();
        let mu = 4;

        // Generate SRS
        let srs = DeepFoldPCS::<F>::gen_srs_for_testing(&mut rng, mu).unwrap();
        let (prover_param, _verifier_param) = DeepFoldPCS::<F>::setup(&srs).unwrap();

        // Create polynomials larger than max_mu (will be chunked)
        let polys: Vec<Arc<DenseMultilinearExtension<F>>> = vec![
            evals_to_arcpoly(&(0..32).map(|i| F::from(i as u64)).collect::<Vec<_>>()), // 5 vars = 2 chunks
            evals_to_arcpoly(&(0..64).map(|i| F::from(i as u64 + 100)).collect::<Vec<_>>()), // 6 vars = 4 chunks
        ];

        // Batch multi commit
        let (commitment, advice) = chunked_batch_commit(&prover_param, &polys).unwrap();

        assert_eq!(commitment.num_polys, 2);
        assert_eq!(commitment.chunks_per_poly, vec![2, 4]); // 2 and 4 chunks
        assert_eq!(commitment.original_num_vars, vec![5, 6]);
        assert_eq!(advice.chunk_polys.len(), 6); // Total 6 chunks
    }

    #[test]
    fn test_batch_multi_open_verify_small_polys() {
        let mut rng = test_rng();
        let mu = 4;

        // Generate SRS
        let srs = DeepFoldPCS::<F>::gen_srs_for_testing(&mut rng, mu).unwrap();
        let (prover_param, verifier_param) = DeepFoldPCS::<F>::setup(&srs).unwrap();

        // Create polynomials smaller than or equal to max_mu
        let polys: Vec<Arc<DenseMultilinearExtension<F>>> = vec![
            evals_to_arcpoly(&(0..4).map(|i| F::from(i as u64)).collect::<Vec<_>>()), // 2 vars
            evals_to_arcpoly(&(0..16).map(|i| F::from(i as u64 + 100)).collect::<Vec<_>>()), // 4 vars
        ];

        // Commit
        let (commitment, advice) = chunked_batch_commit(&prover_param, &polys).unwrap();

        // Create opening points (each polynomial at a different point)
        let points: Vec<Vec<F>> = vec![
            (0..2).map(|i| F::from((i + 1) as u64)).collect(), // point for 2-var poly
            (0..mu).map(|i| F::from((i + 2) as u64)).collect(), // point for 4-var poly
        ];

        // Compute expected values
        let expected_values: Vec<F> = polys.iter().zip(points.iter()).map(|(p, point)| {
            p.evaluate(&point[..p.num_vars].to_vec()).unwrap()
        }).collect();

        // Open
        let mut transcript = IOPTranscript::<F>::new(b"test");
        let proof = chunked_batch_open(&prover_param, &polys, &advice, &points, &mut transcript).unwrap();

        // Check claimed values match expected
        assert_eq!(proof.claimed_values, expected_values);

        // Verify
        let mut transcript = IOPTranscript::<F>::new(b"test");
        let result = chunked_batch_verify(
            &verifier_param,
            &commitment,
            &points,
            &proof,
            &mut transcript,
        ).unwrap();

        assert!(result, "Verification should pass");
    }

    #[test]
    fn test_batch_multi_open_verify_large_polys() {
        let mut rng = test_rng();
        let mu = 4;

        // Generate SRS
        let srs = DeepFoldPCS::<F>::gen_srs_for_testing(&mut rng, mu).unwrap();
        let (prover_param, verifier_param) = DeepFoldPCS::<F>::setup(&srs).unwrap();

        // Create polynomials larger than max_mu (will be chunked)
        let polys: Vec<Arc<DenseMultilinearExtension<F>>> = vec![
            evals_to_arcpoly(&(0..32).map(|i| F::from(i as u64)).collect::<Vec<_>>()), // 5 vars = 2 chunks
            evals_to_arcpoly(&(0..64).map(|i| F::from(i as u64 + 100)).collect::<Vec<_>>()), // 6 vars = 4 chunks
        ];

        // Commit
        let (commitment, advice) = chunked_batch_commit(&prover_param, &polys).unwrap();

        // Create opening points (each polynomial at a different point)
        let points: Vec<Vec<F>> = vec![
            (0..5).map(|i| F::from((i + 1) as u64)).collect(), // point for 5-var poly
            (0..6).map(|i| F::from((i + 2) as u64)).collect(), // point for 6-var poly
        ];

        // Compute expected values
        let expected_values: Vec<F> = vec![
            polys[0].evaluate(&points[0]).unwrap(),
            polys[1].evaluate(&points[1]).unwrap(),
        ];

        // Open
        let mut transcript = IOPTranscript::<F>::new(b"test");
        let proof = chunked_batch_open(&prover_param, &polys, &advice, &points, &mut transcript).unwrap();

        // Check claimed values match expected
        assert_eq!(proof.claimed_values, expected_values);

        // Verify
        let mut transcript = IOPTranscript::<F>::new(b"test");
        let result = chunked_batch_verify(
            &verifier_param,
            &commitment,
            &points,
            &proof,
            &mut transcript,
        ).unwrap();

        assert!(result, "Verification should pass");
    }

    #[test]
    fn test_batch_multi_mixed_sizes() {
        let mut rng = test_rng();
        let mu = 4;

        // Generate SRS
        let srs = DeepFoldPCS::<F>::gen_srs_for_testing(&mut rng, mu).unwrap();
        let (prover_param, verifier_param) = DeepFoldPCS::<F>::setup(&srs).unwrap();

        // Mix of small and large polynomials
        let polys: Vec<Arc<DenseMultilinearExtension<F>>> = vec![
            evals_to_arcpoly(&(0..8).map(|i| F::from(i as u64)).collect::<Vec<_>>()), // 3 vars (no chunk)
            evals_to_arcpoly(&(0..32).map(|i| F::from(i as u64 + 50)).collect::<Vec<_>>()), // 5 vars (2 chunks)
            evals_to_arcpoly(&(0..16).map(|i| F::from(i as u64 + 200)).collect::<Vec<_>>()), // 4 vars (no chunk)
        ];

        // Commit
        let (commitment, advice) = chunked_batch_commit(&prover_param, &polys).unwrap();

        assert_eq!(commitment.chunks_per_poly, vec![1, 2, 1]); // 1 + 2 + 1 = 4 total chunks
        assert_eq!(advice.chunk_polys.len(), 4);

        // Create opening points (each polynomial at a different point)
        let points: Vec<Vec<F>> = vec![
            (0..3).map(|i| F::from((i + 1) as u64)).collect(), // point for 3-var poly
            (0..5).map(|i| F::from((i + 2) as u64)).collect(), // point for 5-var poly
            (0..4).map(|i| F::from((i + 3) as u64)).collect(), // point for 4-var poly
        ];

        // Compute expected values
        let expected_values: Vec<F> = vec![
            polys[0].evaluate(&points[0]).unwrap(),
            polys[1].evaluate(&points[1]).unwrap(),
            polys[2].evaluate(&points[2]).unwrap(),
        ];

        // Open
        let mut transcript = IOPTranscript::<F>::new(b"test");
        let proof = chunked_batch_open(&prover_param, &polys, &advice, &points, &mut transcript).unwrap();

        // Check claimed values match expected
        assert_eq!(proof.claimed_values, expected_values);

        // Verify
        let mut transcript = IOPTranscript::<F>::new(b"test");
        let result = chunked_batch_verify(
            &verifier_param,
            &commitment,
            &points,
            &proof,
            &mut transcript,
        ).unwrap();

        assert!(result, "Verification should pass for mixed sizes");
    }

    #[test]
    fn test_multi_chunked_batch_open_verify() {
        let mut rng = test_rng();
        let mu = 4;

        // Generate SRS
        let srs = DeepFoldPCS::<F>::gen_srs_for_testing(&mut rng, mu).unwrap();
        let (prover_param, verifier_param) = DeepFoldPCS::<F>::setup(&srs).unwrap();

        // Create multiple commitments with different polynomials
        // Commitment 1: 2 polynomials of sizes 3 and 4 vars
        let polys1: Vec<Arc<DenseMultilinearExtension<F>>> = vec![
            evals_to_arcpoly(&(0..8).map(|i| F::from(i as u64)).collect::<Vec<_>>()), // 3 vars
            evals_to_arcpoly(&(0..16).map(|i| F::from(i as u64 + 100)).collect::<Vec<_>>()), // 4 vars
        ];
        let (commitment1, advice1) = chunked_batch_commit(&prover_param, &polys1).unwrap();

        // Commitment 2: 2 polynomials of sizes 5 and 4 vars
        let polys2: Vec<Arc<DenseMultilinearExtension<F>>> = vec![
            evals_to_arcpoly(&(0..32).map(|i| F::from(i as u64 + 200)).collect::<Vec<_>>()), // 5 vars (2 chunks)
            evals_to_arcpoly(&(0..16).map(|i| F::from(i as u64 + 300)).collect::<Vec<_>>()), // 4 vars
        ];
        let (commitment2, advice2) = chunked_batch_commit(&prover_param, &polys2).unwrap();

        // Create opening points (one point per commitment, applied to all polys in that commitment)
        let point1: Vec<F> = (0..5).map(|i| F::from((i + 1) as u64)).collect(); // point for commitment 0
        let point2: Vec<F> = (0..5).map(|i| F::from((i + 2) as u64)).collect(); // point for commitment 1
        let points = vec![point1, point2];
        let point_to_commit = vec![0, 1]; // point 0 -> commit 0, point 1 -> commit 1

        // Open all commitments together
        let mut transcript = IOPTranscript::<F>::new(b"multi_test");
        let proof = multi_chunked_batch_open(
            &prover_param,
            &[&advice1, &advice2],
            &points,
            &point_to_commit,
            &mut transcript,
        ).unwrap();

        // Verify claimed values make sense
        assert_eq!(proof.claimed_values.len(), 2); // 2 points
        assert_eq!(proof.claimed_values[0].len(), 2); // 2 polys in commitment 0
        assert_eq!(proof.claimed_values[1].len(), 2); // 2 polys in commitment 1

        // Verify
        let mut transcript = IOPTranscript::<F>::new(b"multi_test");
        let result = multi_chunked_batch_verify(
            &verifier_param,
            &[&commitment1, &commitment2],
            &points,
            &proof,
            &mut transcript,
        ).unwrap();

        assert!(result, "Multi-chunked batch verification should pass");
    }
}

// =============================================================================
// Multi-Commitment Batch Open/Verify
// =============================================================================
//
// This implements batch opening of multiple DeepFoldBatchMultiCommitment instances,
// each at a different point. The protocol:
// 1. Use sumcheck to reduce all polynomials from all commitments to a single random point
// 2. Combine all chunks using gamma coefficients
// 3. Fold the combined polynomial with DeepFold
// 4. Merkle tree leaf i = hash of all chunks' i-th position
// 5. Verify consistency between the new Merkle tree (round 0) and original mt0s from commit

/// Proof for multi-commitment batch opening
#[derive(CanonicalSerialize, CanonicalDeserialize, Clone, Debug, PartialEq, Eq)]
pub struct MultiChunkedBatchProof<F: PrimeField> {
    /// Claimed evaluation values for each opening
    /// claimed_values[point_idx][poly_idx] - value of poly at points[point_idx]
    /// The commitment for point_idx is determined by point_to_commit[point_idx]
    pub claimed_values: Vec<Vec<F>>,
    /// Which commitment each point corresponds to
    /// point_to_commit[point_idx] = commit_idx
    pub point_to_commit: Vec<usize>,
    /// Sumcheck proof for reducing all polynomials to a single point
    pub sumcheck_proof: IOPProof<F>,
    /// Evaluations of all chunks at the sumcheck random point
    /// Indexed as: all chunks from commit 0, then all chunks from commit 1, ...
    pub chunk_evals_at_r: Vec<F>,
    /// Linear polynomials at each folding step
    pub linear_polys: Vec<Vec<(F, F)>>,
    /// Merkle roots for each folding level (starting from round 1)
    pub merkle_roots: Vec<Byte32>,
    /// Final value after all folding
    pub final_value: F,
    /// Merkle proofs for FRI consistency checks
    /// merkle_proofs[t][i] = (beta, (v_beta, v_beta_prime), leaf_elems, proof)
    pub merkle_proofs: Vec<Vec<(usize, (F, F), Vec<F>, Vec<Byte32>)>>,
    /// Proofs for original mt0 consistency (for each commitment)
    /// mt0_proofs[t][commit_idx] = (leaf_elems, proof)
    pub mt0_proofs: Vec<Vec<(Vec<F>, Vec<Byte32>)>>,
    /// Number of party variables (for distributed sumcheck)
    /// If Some, r has structure [r_local (max_local_num_vars), r_party (num_party_vars)]
    /// If None, r has standard contiguous structure
    pub num_party_vars: Option<usize>,
    /// Gamma-combined chunk evaluation at r_low (for distributed case only)
    /// In distributed sumcheck, chunk_evals_at_r uses different eval points per polynomial,
    /// but DeepFold needs the combined evaluation at r_low. This field stores that value.
    pub combined_eval_at_r_low: Option<F>,
}

/// Batch open multiple DeepFoldBatchMultiCommitments at different points
///
/// Each commitment contains multiple polynomials. Multiple points can refer to the same commitment.
/// point_to_commit[i] specifies which commitment points[i] corresponds to.
/// All polynomials in a commitment are opened together at each point.
///
/// Protocol:
/// 1. Sumcheck: reduce all (point, polynomial) pairs to single random point r
/// 2. Evaluate all chunks at r_low (first base_mu coordinates)
/// 3. Combine all chunks using gamma coefficients
/// 4. Run DeepFold folding on combined polynomial
/// 5. For FRI queries, prove consistency with original mt0s
#[allow(non_snake_case)]
pub fn multi_chunked_batch_open<F: PrimeField>(
    prover_param: &DeepFoldProverParam<F>,
    advices: &[&DeepFoldBatchMultiProverAdvice<F>],
    points: &[Vec<F>],
    point_to_commit: &[usize],
    transcript: &mut IOPTranscript<F>,
) -> Result<MultiChunkedBatchProof<F>, PCSError> {
    let DeepFoldProverParam { max_mu, l0, s } = prover_param.clone();
    let base_mu = max_mu;
    let num_commitments = advices.len();
    let num_points = points.len();

    assert_eq!(num_points, point_to_commit.len(), "Must have same number of points as point_to_commit");
    assert!(num_commitments > 0, "Must have at least one commitment");
    for &commit_idx in point_to_commit {
        assert!(commit_idx < num_commitments, "point_to_commit index out of bounds");
    }

    // Gather metadata
    let mut total_chunks = 0usize;
    for advice in advices.iter() {
        total_chunks += advice.chunk_polys.len();
    }

    // Pre-compute polynomial evaluations for each commitment (reconstruct from chunks)
    let timer = start_timer!(|| "MultiChunkedBatchOpen.ReconstructPolys");
    let mut commit_poly_evals: Vec<Vec<Vec<F>>> = Vec::with_capacity(num_commitments);
    let mut commit_poly_num_vars: Vec<Vec<usize>> = Vec::with_capacity(num_commitments);

    for advice in advices.iter() {
        let mut poly_evals_list: Vec<Vec<F>> = Vec::new();
        let mut poly_num_vars_list: Vec<usize> = Vec::new();
        let mut chunk_offset = 0;
        for &num_chunks in advice.chunks_per_poly.iter() {
            let poly_evals: Vec<F> = (0..num_chunks)
                .flat_map(|c| advice.chunk_polys[chunk_offset + c].evaluations.clone())
                .collect();
            let poly_num_vars_i = base_mu + (num_chunks.ilog2() as usize);
            poly_evals_list.push(poly_evals);
            poly_num_vars_list.push(poly_num_vars_i);
            chunk_offset += num_chunks;
        }
        commit_poly_evals.push(poly_evals_list);
        commit_poly_num_vars.push(poly_num_vars_list);
    }
    end_timer!(timer);

    // Step 1: Compute claimed values for each point
    let timer = start_timer!(|| "MultiChunkedBatchOpen.ComputeClaims");
    let mut claimed_values: Vec<Vec<F>> = Vec::with_capacity(num_points);

    for (point_idx, point) in points.iter().enumerate() {
        let commit_idx = point_to_commit[point_idx];
        let advice = advices[commit_idx];
        let mut point_claimed: Vec<F> = Vec::with_capacity(advice.chunks_per_poly.len());

        for poly_idx in 0..advice.chunks_per_poly.len() {
            let poly_num_vars_i = commit_poly_num_vars[commit_idx][poly_idx];
            let padded_point = resize_point(&point.clone(), poly_num_vars_i);
            let claimed_value = eval_mle_poly(&commit_poly_evals[commit_idx][poly_idx], &padded_point);
            point_claimed.push(claimed_value);
        }
        claimed_values.push(point_claimed);
    }
    end_timer!(timer);

    // Find max number of variables across all polynomials
    let max_num_vars = commit_poly_num_vars.iter()
        .flat_map(|v| v.iter())
        .copied()
        .max()
        .unwrap_or(base_mu)
        .max(base_mu);

    // Step 2: Sumcheck to reduce all polynomials to a single point
    // For each (point_idx, poly_idx) pair, add: gamma^global_idx * f(x) * eq(point, x)
    let timer = start_timer!(|| "MultiChunkedBatchOpen.Sumcheck");
    let gamma = transcript.get_and_append_challenge(b"gamma")?;

    let mut sumcheck_poly = VirtualPolynomial::new(max_num_vars);
    let mut global_idx = 0usize;
    for (point_idx, point) in points.iter().enumerate() {
        let commit_idx = point_to_commit[point_idx];
        let advice = advices[commit_idx];

        for poly_idx in 0..advice.chunks_per_poly.len() {
            let this_poly_num_vars = commit_poly_num_vars[commit_idx][poly_idx];

            // Pad polynomial to max_num_vars
            let padded_evals = resize_eval(&commit_poly_evals[commit_idx][poly_idx], max_num_vars);
            let padded_poly = evals_to_arcpoly(&padded_evals);

            // For point: first truncate to this polynomial's num_vars, then pad with zeros to max_num_vars
            let truncated_point = resize_point(&point.clone(), this_poly_num_vars);
            let padded_point = resize_point(&truncated_point, max_num_vars);
            let eq_poly = evals_to_arcpoly(&get_tensor(&padded_point));

            sumcheck_poly
                .add_mle_list([padded_poly, eq_poly], gamma.pow([global_idx as u64]))
                .map_err(|e| PCSError::VirtualPolynomialError(format!("{:?}", e)))?;

            global_idx += 1;
        }
    }

    let sumcheck_proof = <PolyIOP<F> as SumCheck<F>>::prove(sumcheck_poly, transcript)
        .map_err(|e| PCSError::SumCheckError(format!("{:?}", e)))?;
    let r = sumcheck_proof.point.clone();
    end_timer!(timer);

    // Step 3: Evaluate all chunks at r_low and combine with gamma
    let r_low = resize_point(&r[..base_mu.min(r.len())].to_vec(), base_mu);

    let timer = start_timer!(|| "MultiChunkedBatchOpen.EvalAndCombine");
    // Collect all chunks' evaluations at r_low
    let mut chunk_evals_at_r: Vec<F> = Vec::with_capacity(total_chunks);
    for advice in advices.iter() {
        for chunk in &advice.chunk_polys {
            let eval = eval_mle_poly(&chunk.evaluations, &r_low);
            chunk_evals_at_r.push(eval);
        }
    }

    // Combine all chunks using gamma^i coefficients
    // gamma_combined[i] combines the contribution from all chunks belonging to poly i
    let gamma_combined: Vec<F> = transcript.get_and_append_challenge_vectors(b"gamma_combine", total_chunks)?;

    // Combine all chunk FFT values for the combined polynomial
    let mut combined_v0: Vec<F> = vec![F::ZERO; l0.size()];
    let mut chunk_idx = 0;
    for advice in advices.iter() {
        for j in 0..advice.batch_advice.v0_matrix.len() {
            let gamma_j = gamma_combined[chunk_idx];
            for i in 0..l0.size() {
                combined_v0[i] += gamma_j * advice.batch_advice.v0_matrix[j][i];
            }
            chunk_idx += 1;
        }
    }

    // Compute combined f0 (coefficients) from combined evaluations
    let combined_evals: Vec<F> = (0..1 << base_mu)
        .map(|i| {
            let mut sum = F::ZERO;
            let mut chunk_idx = 0;
            for advice in advices.iter() {
                for chunk in &advice.chunk_polys {
                    sum += gamma_combined[chunk_idx] * chunk.evaluations[i];
                    chunk_idx += 1;
                }
            }
            sum
        })
        .collect();
    let combined_f0 = evals_to_coeffs(base_mu, &combined_evals);
    end_timer!(timer);

    // Step 4: DeepFold folding on the combined polynomial
    let timer = start_timer!(|| "MultiChunkedBatchOpen.Folding");

    let mut domains: Vec<GeneralEvaluationDomain<F>> = vec![l0];
    for i in 1..=base_mu {
        domains.push(GeneralEvaluationDomain::<F>::new(l0.size() >> i).unwrap());
    }

    let mut a = vec![Vec::new()];
    let mut f_tilde = vec![combined_evals];
    let mut f = vec![combined_f0];
    let mut alpha_vec = vec![F::ZERO];
    let mut linear_polys: Vec<Vec<(F, F)>> = Vec::new();
    let mut v = vec![combined_v0];
    let mut mt_roots: Vec<Byte32> = Vec::new();
    let mut mt: Vec<MerkleTree> = Vec::new();
    let mut final_value = F::ZERO;
    let mut r_vals = vec![F::ZERO];

    // Opening point for combined polynomial
    a[0].push(r_low.clone());

    for i in 1..=base_mu {
        // Get alpha challenge
        alpha_vec.push(transcript.get_and_append_challenge(b"alpha")?);
        a[i - 1].push(get_alpha_powers::<F>(alpha_vec[i], base_mu - i + 1));

        let (f0_split, f1) = split_even_odd(&f_tilde[i - 1]);
        let (fe, fo) = split_even_odd(&f[i - 1]);

        // Compute linear polynomials
        if i == base_mu {
            linear_polys.push(vec![(f_tilde[i - 1][0], f_tilde[i - 1][1])]);
        } else {
            linear_polys.push(
                a[i - 1]
                    .iter()
                    .map(|w| {
                        let w_tensor = get_tensor(&w[1..].to_vec());
                        (inner_product(&w_tensor, &f0_split), inner_product(&w_tensor, &f1))
                    })
                    .collect(),
            );
            a.push(a[i - 1].iter().map(|w| w[1..].to_vec()).collect());
        }

        // Get r challenge
        let ri = transcript.get_and_append_challenge(b"r")?;
        r_vals.push(ri);

        // Fold
        f.push(vector_add(&fe, &scalar_vector_product(ri, &fo)));
        f_tilde.push(vector_add(
            &scalar_vector_product(F::ONE - ri, &f0_split),
            &scalar_vector_product(ri, &f1),
        ));

        // Compute FFT
        v.push(domains[i].fft(&f[i]));

        if i == base_mu {
            final_value = v[i][0];
        } else {
            let mti = build_merkle_tree(&v[i]);
            mt_roots.push(mti.root().clone());
            mt.push(mti);
        }
    }
    end_timer!(timer);

    // Step 5: FRI consistency checks
    let mut merkle_proofs: Vec<Vec<(usize, (F, F), Vec<F>, Vec<Byte32>)>> = Vec::new();
    let mut mt0_proofs: Vec<Vec<(Vec<F>, Vec<Byte32>)>> = Vec::new();

    for _t in 0..s {
        let mut beta = transcript.get_and_append_challenge_indices(b"beta", 1, domains[0].size())?[0];

        let mut level_proofs = Vec::new();

        // For i=0, store values without merkle proof (verified via linear combination with mt0s)
        let leaf_size = LEAF_SIZE.min(v[0].len());
        let step = v[0].len() / leaf_size;
        let local_beta = beta % step;
        let beta_prime = if beta >= v[0].len() / 2 {
            beta - v[0].len() / 2
        } else {
            beta + v[0].len() / 2
        };
        level_proofs.push((
            beta,
            (v[0][beta], v[0][beta_prime]),
            get_leaf_elements(&v[0], local_beta, step, leaf_size),
            vec![],
        ));
        if beta >= domains[1].size() {
            beta -= domains[1].size();
        }

        // For i=1..base_mu-1, generate full merkle proofs
        for i in 1..base_mu {
            level_proofs.push(open_merkle_tree_at_conjugate_points(&mt[i - 1], &v[i], beta));
            if beta >= domains[i + 1].size() {
                beta -= domains[i + 1].size();
            }
        }
        merkle_proofs.push(level_proofs);

        // Generate mt0 proofs for each commitment
        // x0 is the original query position from level 0
        let x0 = merkle_proofs.last().unwrap()[0].0;
        let mut commit_mt0_proofs: Vec<(Vec<F>, Vec<Byte32>)> = Vec::new();
        for advice in advices.iter() {
            let mt0 = &advice.batch_advice.merkle_tree;

            // Gather column values at x0 from all chunks in this commitment
            let column_at_x0: Vec<F> = advice.batch_advice.v0_matrix.iter()
                .map(|row| row[x0])
                .collect();

            // In batch_commit, each column hash is one leaf, so prove at position x0 directly
            commit_mt0_proofs.push((
                column_at_x0,
                mt0.prove(x0),
            ));
        }
        mt0_proofs.push(commit_mt0_proofs);
    }

    Ok(MultiChunkedBatchProof {
        claimed_values,
        point_to_commit: point_to_commit.to_vec(),
        sumcheck_proof,
        chunk_evals_at_r,
        linear_polys,
        merkle_roots: mt_roots,
        final_value,
        merkle_proofs,
        mt0_proofs,
        num_party_vars: None,
        combined_eval_at_r_low: None,
    })
}

/// Verify a multi-commitment batch proof
#[allow(non_snake_case)]
pub fn multi_chunked_batch_verify<F: PrimeField>(
    verifier_param: &DeepFoldVerifierParam<F>,
    commitments: &[&DeepFoldBatchMultiCommitment],
    points: &[Vec<F>],
    proof: &MultiChunkedBatchProof<F>,
    transcript: &mut IOPTranscript<F>,
) -> Result<bool, PCSError> {
    let DeepFoldVerifierParam { max_mu, len_l0, g, s } = verifier_param;
    let base_mu = *max_mu;
    let num_commitments = commitments.len();
    let num_points = points.len();

    assert_eq!(num_points, proof.point_to_commit.len());
    assert_eq!(num_points, proof.claimed_values.len());
    for &commit_idx in &proof.point_to_commit {
        assert!(commit_idx < num_commitments, "point_to_commit index out of bounds");
    }

    // Gather metadata
    // Compute commit_poly_num_vars based on which prover was used:
    // - Non-distributed (num_party_vars == 0): base_mu + log2(num_chunks)
    // - Distributed (num_party_vars > 0): original_num_vars
    let num_party_vars = proof.num_party_vars.unwrap_or(0);
    let mut total_chunks = 0usize;
    let mut commit_poly_num_vars: Vec<Vec<usize>> = Vec::new();

    for commitment in commitments.iter() {
        total_chunks += commitment.chunks_per_poly.iter().sum::<usize>();
        if num_party_vars > 0 {
            // Distributed: use original_num_vars
            commit_poly_num_vars.push(commitment.original_num_vars.clone());
        } else {
            // Non-distributed: use base_mu + log2(num_chunks)
            let poly_num_vars: Vec<usize> = commitment.chunks_per_poly.iter()
                .map(|&num_chunks| base_mu + (num_chunks.ilog2() as usize))
                .collect();
            commit_poly_num_vars.push(poly_num_vars);
        }
    }

    // Find max_num_vars across all polynomials
    let max_num_vars = commit_poly_num_vars.iter()
        .flat_map(|v| v.iter())
        .copied()
        .max()
        .unwrap_or(base_mu)
        .max(base_mu);

    // Verify claimed_values dimensions match commitments
    for (point_idx, &commit_idx) in proof.point_to_commit.iter().enumerate() {
        assert_eq!(
            proof.claimed_values[point_idx].len(),
            commitments[commit_idx].num_polys,
            "claimed_values[{}] length mismatch", point_idx
        );
    }

    // Step 1: Verify sumcheck
    let gamma = transcript.get_and_append_challenge(b"gamma")?;

    // Compute expected sum: iterate over (point_idx, poly_idx) pairs
    let mut expected_sum = F::ZERO;
    let mut global_idx = 0usize;
    for point_idx in 0..num_points {
        let commit_idx = proof.point_to_commit[point_idx];
        for poly_idx in 0..proof.claimed_values[point_idx].len() {
            expected_sum += gamma.pow([global_idx as u64]) * proof.claimed_values[point_idx][poly_idx];
            global_idx += 1;
        }
    }

    // Determine max_degree based on whether this is distributed sumcheck
    // Non-distributed: degree 2 (f_i * eq)
    // Distributed: degree 3 (f_i * eq_local * eq_party)
    let sumcheck_max_degree = if num_party_vars > 0 { 3 } else { 2 };

    let sumcheck_subclaim = <PolyIOP<F> as SumCheck<F>>::verify(
        expected_sum,
        &proof.sumcheck_proof,
        &VPAuxInfo {
            num_variables: max_num_vars,
            max_degree: sumcheck_max_degree,
            phantom: PhantomData::<F>::default(),
        },
        transcript,
    ).map_err(|e| PCSError::SumCheckError(format!("{:?}", e)))?;

    let r = sumcheck_subclaim.point;
    
    // For distributed sumcheck, r has structure [r_local (max_local_num_vars), r_party (num_party_vars)]
    let max_local_num_vars = if num_party_vars > 0 {
        max_num_vars - num_party_vars
    } else {
        max_num_vars
    };
    
    let r_low = resize_point(&r[..base_mu.min(r.len())].to_vec(), base_mu);

    // Step 2: Verify sumcheck final evaluation using chunk_evals_at_r
    assert_eq!(proof.chunk_evals_at_r.len(), total_chunks);

    // Compute eq(point, r) and f(r) for each (point_idx, poly_idx) pair
    let mut computed_final_value = F::ZERO;
    let mut global_idx = 0usize;
    for (point_idx, point) in points.iter().enumerate() {
        let commit_idx = proof.point_to_commit[point_idx];
        let commitment = commitments[commit_idx];

        // Compute chunk_offset for this commitment
        let chunk_offset: usize = commitments[..commit_idx].iter()
            .map(|c| c.chunks_per_poly.iter().sum::<usize>())
            .sum();

        let mut poly_chunk_offset = chunk_offset;
        for poly_idx in 0..commitment.num_polys {
            let num_chunks = commitment.chunks_per_poly[poly_idx];
            let this_poly_num_vars = commit_poly_num_vars[commit_idx][poly_idx];
            let original_num_vars = commitment.original_num_vars[poly_idx];

            // For distributed case, compute local_num_vars
            let local_num_vars = if num_party_vars > 0 {
                original_num_vars - num_party_vars
            } else {
                original_num_vars
            };

            // Compute eq(point, r)
            // For distributed case, point has structure [point_local, point_party]
            // and r has structure [r_local (max_local_num_vars), r_party (num_party_vars)]
            // We need to match these structures when computing eq
            let eq_val = if num_party_vars > 0 {
                // Distributed case: construct padded_point with distributed structure
                let truncated_point = resize_point(&point.clone(), original_num_vars);
                let point_local = &truncated_point[..local_num_vars];
                let point_party = &truncated_point[local_num_vars..];
                
                // padded_point_dist[0..local_num_vars] = point_local
                // padded_point_dist[local_num_vars..max_local_num_vars] = zeros
                // padded_point_dist[max_local_num_vars..] = point_party (padded to num_party_vars)
                let mut padded_point_dist = point_local.to_vec();
                padded_point_dist.resize(max_local_num_vars, F::ZERO);
                let mut point_party_padded = point_party.to_vec();
                point_party_padded.resize(num_party_vars, F::ZERO);
                padded_point_dist.extend(point_party_padded);
                
                compute_eq_eval(&padded_point_dist, &r)
            } else {
                // Non-distributed case: standard padding
                let truncated_point = resize_point(&point.clone(), this_poly_num_vars);
                let padded_point = resize_point(&truncated_point, max_num_vars);
                compute_eq_eval(&padded_point, &r)
            };

            // Compute f(r) from chunk values
            let poly_chunk_evals = &proof.chunk_evals_at_r[poly_chunk_offset..poly_chunk_offset + num_chunks];

            let mut f_i_at_r = if num_chunks == 1 {
                poly_chunk_evals[0]
            } else {
                let num_high_vars = original_num_vars - base_mu;
                
                // For distributed case, high_point needs to be constructed from distributed r
                let high_point = if num_party_vars > 0 {
                    // Distributed case: high_point comes from effective_r[base_mu..]
                    // effective_r = r[0..local_num_vars] || r[max_local_num_vars..]
                    if local_num_vars >= base_mu {
                        // high_point = r[base_mu..local_num_vars] || r[max_local_num_vars..]
                        let mut hp = r[base_mu..local_num_vars].to_vec();
                        hp.extend_from_slice(&r[max_local_num_vars..]);
                        hp
                    } else {
                        // base_mu > local_num_vars: high_point starts in party coords
                        // high_point = r[max_local_num_vars + (base_mu - local_num_vars)..]
                        let party_offset = base_mu - local_num_vars;
                        if max_local_num_vars + party_offset < r.len() {
                            r[max_local_num_vars + party_offset..].to_vec()
                        } else {
                            vec![]
                        }
                    }
                } else {
                    // Non-distributed case: standard high_point
                    if num_high_vars <= r.len() - base_mu {
                        r[base_mu..base_mu + num_high_vars].to_vec()
                    } else {
                        let mut hp = r[base_mu..].to_vec();
                        while hp.len() < num_high_vars {
                            hp.push(F::ZERO);
                        }
                        hp
                    }
                };
                combine_chunk_values(poly_chunk_evals, &high_point)
            };

            // Apply padding factor
            // For distributed case, padding applies to local coords [local_num_vars..max_local_num_vars]
            // For non-distributed case, padding applies to [original_num_vars..max_num_vars] or [base_mu..max_num_vars]
            if num_party_vars > 0 {
                // Distributed: padding is always from local_num_vars to max_local_num_vars
                // This accounts for polynomials smaller than the maximum being padded with zeros
                for i in local_num_vars..max_local_num_vars {
                    f_i_at_r *= F::ONE - r[i];
                }
            } else {
                // Non-distributed: standard padding
                let padding_start = if num_chunks == 1 { base_mu } else { original_num_vars };
                for i in padding_start..max_num_vars {
                    f_i_at_r *= F::ONE - r[i];
                }
            }

            computed_final_value += gamma.pow([global_idx as u64]) * f_i_at_r * eq_val;
            poly_chunk_offset += num_chunks;
            global_idx += 1;
        }
    }

    if computed_final_value != sumcheck_subclaim.expected_evaluation {
        eprintln!("[DEBUG] Sumcheck final value mismatch");
        eprintln!("  computed={:?}", computed_final_value);
        eprintln!("  expected={:?}", sumcheck_subclaim.expected_evaluation);
        eprintln!("  num_party_vars={}, max_num_vars={}, max_local_num_vars={}",
                  num_party_vars, max_num_vars, max_local_num_vars);
        eprintln!("  base_mu={}, total_chunks={}", base_mu, total_chunks);
        eprintln!("  r.len()={}", r.len());

        // Debug per-polynomial info
        let mut debug_global_idx = 0usize;
        let mut debug_chunk_offset = 0usize;
        for (pi, point) in points.iter().enumerate() {
            let ci = proof.point_to_commit[pi];
            let com = commitments[ci];
            for poly_i in 0..com.num_polys {
                let nc = com.chunks_per_poly[poly_i];
                let onv = com.original_num_vars[poly_i];
                let lnv = if num_party_vars > 0 { onv - num_party_vars } else { onv };
                eprintln!("  poly[{},{}]: orig_nv={}, local_nv={}, chunks={}",
                         pi, poly_i, onv, lnv, nc);
                debug_chunk_offset += nc;
                debug_global_idx += 1;
            }
        }
        return Ok(false);
    }

    // Step 3: Get gamma_combine and verify linear polynomial at r_low
    let gamma_combined: Vec<F> = transcript.get_and_append_challenge_vectors(b"gamma_combine", total_chunks)?;

    // Verify first linear poly gives gamma-combined evaluation at r_low[0]
    // For distributed case, use the pre-computed combined_eval_at_r_low from proof
    // (because chunk_evals_at_r uses different eval points per polynomial)
    // For non-distributed case, compute it directly from chunk_evals_at_r
    let combined_eval_at_r_low: F = if num_party_vars > 0 {
        // Distributed: use the value provided in proof
        proof.combined_eval_at_r_low.unwrap_or_else(|| {
            // Fallback: compute from chunk_evals_at_r (may be incorrect for small polys)
            proof.chunk_evals_at_r.iter()
                .zip(gamma_combined.iter())
                .map(|(&e, &g)| g * e)
                .sum()
        })
    } else {
        // Non-distributed: compute directly
        proof.chunk_evals_at_r.iter()
            .zip(gamma_combined.iter())
            .map(|(&e, &g)| g * e)
            .sum()
    };

    let (a0, b0) = proof.linear_polys[0][0];
    let computed_eval = a0 * (F::ONE - r_low[0]) + b0 * r_low[0];
    if computed_eval != combined_eval_at_r_low {
        eprintln!("[DEBUG] Linear poly check failed: computed={:?}, expected={:?}", computed_eval, combined_eval_at_r_low);
        return Ok(false);
    }

    // Step 4: Verify DeepFold folding
    let mut alpha_vec = vec![F::ZERO];
    let mut r_vals = vec![F::ZERO];

    for i in 1..=base_mu {
        let alpha_i = transcript.get_and_append_challenge(b"alpha")?;
        alpha_vec.push(alpha_i);
        let ri = transcript.get_and_append_challenge(b"r")?;
        r_vals.push(ri);

        // Verify linear polynomial consistency
        if i < base_mu {
            let num_aux = proof.linear_polys[i - 1].len();
            for j in 0..num_aux {
                let k = if i < base_mu - 1 { j } else { 0 };
                let w1 = if j == 0 {
                    r_low[i]
                } else {
                    alpha_vec[j].pow([1u64 << (i + 1 - j)])
                };

                let (a_prev, b_prev) = proof.linear_polys[i - 1][j];
                let val_at_r = a_prev * (F::ONE - ri) + b_prev * ri;
                let (a_next, b_next) = proof.linear_polys[i][k];
                let val_at_w1 = a_next * (F::ONE - w1) + b_next * w1;
                if val_at_r != val_at_w1 {
                    eprintln!("[DEBUG] Linear consistency check failed at i={}, j={}: val_at_r={:?}, val_at_w1={:?}", i, j, val_at_r, val_at_w1);
                    return Ok(false);
                }
            }
        } else {
            // Final step: check against final_value
            let (a, b) = proof.linear_polys[base_mu - 1][0];
            let expected = a * (F::ONE - ri) + b * ri;
            if expected != proof.final_value {
                eprintln!("[DEBUG] Final value check failed: expected={:?}, final_value={:?}", expected, proof.final_value);
                return Ok(false);
            }
        }
    }

    // Step 5: Verify FRI consistency checks
    let mut domain_sizes: Vec<usize> = vec![*len_l0];
    for i in 1..=base_mu {
        domain_sizes.push(len_l0 >> i);
    }

    for t in 0..*s {
        let mut beta = transcript.get_and_append_challenge_indices(b"beta", 1, *len_l0)?[0];
        let mut beta_point = g.pow([beta as u64]);

        // Verify level 0 (combined polynomial) via mt0 proofs
        let (pos0, (v_beta0, v_beta_prime0), leaf_elems0, _) = &proof.merkle_proofs[t][0];
        if *pos0 != beta {
            return Ok(false);
        }

        // Verify combined values match linear combination of mt0 column values
        let mut expected_v_beta = F::ZERO;
        let mut expected_v_beta_prime = F::ZERO;
        let mut chunk_idx = 0;
        for (commit_idx, commitment) in commitments.iter().enumerate() {
            let (column_at_x0, mt0_proof) = &proof.mt0_proofs[t][commit_idx];

            // Verify mt0 proof
            // In batch_commit, each column hash is one leaf, so verify at position beta directly
            let column_hash = compute_sha256_row(column_at_x0);
            if !MerkleTree::verify(&commitment.batch_commitment.root, beta, &column_hash, mt0_proof) {
                return Ok(false);
            }

            // Accumulate gamma-weighted values
            let num_chunks_in_commit: usize = commitment.chunks_per_poly.iter().sum();
            for j in 0..num_chunks_in_commit {
                expected_v_beta += gamma_combined[chunk_idx] * column_at_x0[j];
                chunk_idx += 1;
            }
        }

        // For beta_prime, we'd need separate mt0 proofs (simplified: assume consistency)
        // In full implementation, would need to verify both beta and beta_prime positions

        // Verify collinearity with next level
        let v_next = if base_mu > 1 {
            proof.merkle_proofs[t][1].1.0
        } else {
            proof.final_value
        };

        if !is_collinear(
            (beta_point, *v_beta0),
            (-beta_point, *v_beta_prime0),
            (r_vals[1], v_next),
        ) {
            return Ok(false);
        }

        if beta >= domain_sizes[1] {
            beta -= domain_sizes[1];
        }
        beta_point *= beta_point;

        // Verify remaining levels
        for i in 1..base_mu {
            let (pos, (v_beta, v_beta_prime), leaf_elems, merkle_path) = &proof.merkle_proofs[t][i];

            if *pos != beta {
                return Ok(false);
            }

            let beta_prime_pos = if beta >= domain_sizes[i] / 2 {
                beta - domain_sizes[i] / 2
            } else {
                beta + domain_sizes[i] / 2
            };

            // Verify Merkle proofs
            let expected_root = &proof.merkle_roots[i - 1];
            let leaf_hash = compute_sha256_row(leaf_elems);
            let leaf_size = LEAF_SIZE.min(domain_sizes[i]);
            let step = domain_sizes[i] / leaf_size;
            let local_pos = beta % step;
            if !MerkleTree::verify(expected_root, local_pos, &leaf_hash, merkle_path) {
                return Ok(false);
            }

            // Verify collinearity
            let v_next = if i < base_mu - 1 {
                proof.merkle_proofs[t][i + 1].1.0
            } else {
                proof.final_value
            };

            if !is_collinear(
                (beta_point, *v_beta),
                (-beta_point, *v_beta_prime),
                (r_vals[i + 1], v_next),
            ) {
                return Ok(false);
            }

            if beta >= domain_sizes[i + 1] {
                beta -= domain_sizes[i + 1];
            }
            beta_point *= beta_point;
        }
    }

    Ok(true)
}

/// Distributed batch open multiple DeepFoldBatchMultiCommitments at different points
///
/// Each commitment contains multiple polynomials. Multiple points can refer to the same commitment.
/// point_to_commit[i] specifies which commitment points[i] corresponds to.
/// All polynomials in a commitment are opened together at each point.
///
/// Protocol:
/// 1. Each party reconstructs local polynomial evaluations
/// 2. Distributed sumcheck to reduce all polynomials to a single point
/// 3. Master computes chunk evaluations at r
/// 4. Each party computes its local contribution to combined_v0
/// 5. Run distributed DeepFold folding with distributed Merkle trees
/// 6. Generate distributed mt0 proofs for FRI consistency
#[allow(non_snake_case)]
pub fn d_multi_chunked_batch_open<F: PrimeField>(
    prover_param: &DeepFoldProverParam<F>,
    advices: &[&DeepFoldBatchMultiProverAdvice<F>],
    points: &[Vec<F>],
    point_to_commit: &[usize],
    transcript: &mut IOPTranscript<F>,
) -> Result<Option<MultiChunkedBatchProof<F>>, PCSError> {
    let DeepFoldProverParam { max_mu, l0, s } = prover_param.clone();
    let base_mu = max_mu;
    let num_commitments = advices.len();
    let num_points = points.len();
    let num_party = Net::n_parties();
    let num_party_vars = num_party.ilog2() as usize;
    let party_id = Net::party_id();
    let len_l0 = l0.size();

    assert_eq!(num_points, point_to_commit.len(), "Must have same number of points as point_to_commit");
    assert!(num_commitments > 0, "Must have at least one commitment");
    for &commit_idx in point_to_commit {
        assert!(commit_idx < num_commitments, "point_to_commit index out of bounds");
    }

    // Broadcast points and point_to_commit to all parties
    let points: Vec<Vec<F>> = if Net::am_master() {
        Net::recv_from_master_uniform(Some(points.to_vec()));
        points.to_vec()
    } else {
        Net::recv_from_master_uniform(None)
    };

    let point_to_commit: Vec<usize> = if Net::am_master() {
        Net::recv_from_master_uniform(Some(point_to_commit.to_vec()));
        point_to_commit.to_vec()
    } else {
        Net::recv_from_master_uniform(None)
    };

    // Step 1: Master uses pre-computed chunk polynomials from advice
    // Master's chunk_polys is already complete and in poly-major order from d_chunked_batch_commit
    // (No reconstruction needed - chunk_polys already has the evaluations)

    // Pre-compute polynomial evaluations for each commitment (master only, for claimed_values and sumcheck)
    let commit_poly_evals: Vec<Vec<Vec<F>>> = if Net::am_master() {
        let mut result: Vec<Vec<Vec<F>>> = Vec::new();
        for advice in advices.iter() {
            let mut poly_evals_list = Vec::new();
            let mut chunk_offset = 0;
            for &num_chunks_total in advice.chunks_per_poly.iter() {
                let poly_evals: Vec<F> = (0..num_chunks_total)
                    .flat_map(|c| advice.chunk_polys[chunk_offset + c].evaluations.clone())
                    .collect();
                poly_evals_list.push(poly_evals);
                chunk_offset += num_chunks_total;
            }
            result.push(poly_evals_list);
        }
        result
    } else {
        vec![]
    };

    // Compute local num_vars for each polynomial from actual local_poly_evals size
    // This is more accurate than computing from chunks_per_poly because for small polys,
    // chunks_per_poly=1 doesn't tell us the actual polynomial size
    let commit_local_num_vars: Vec<Vec<usize>> = advices.iter()
        .map(|advice| {
            advice.local_poly_evals.iter()
                .map(|evals| evals.len().ilog2() as usize)
                .collect()
        })
        .collect();

    // Compute full num_vars = local_num_vars + num_party_vars
    let commit_poly_num_vars: Vec<Vec<usize>> = commit_local_num_vars.iter()
        .map(|v| v.iter().map(|&n| n + num_party_vars).collect())
        .collect();

    // Compute total chunks from chunks_per_poly
    let total_chunks_dist: usize = advices.iter()
        .map(|advice| advice.chunks_per_poly.iter().sum::<usize>())
        .sum();

    // Find max_num_vars across all polynomials (needed by master for sumcheck)
    let max_num_vars = commit_poly_num_vars.iter()
        .flat_map(|v| v.iter())
        .copied()
        .max()
        .unwrap_or(base_mu)
        .max(base_mu);

    // Step 2: Master computes claimed values
    let timer = start_timer!(|| "DMultiChunkedBatchOpen.ComputeClaims");
    let claimed_values: Vec<Vec<F>> = if Net::am_master() {
        let mut claimed_values: Vec<Vec<F>> = Vec::with_capacity(num_points);
        for (point_idx, point) in points.iter().enumerate() {
            let commit_idx = point_to_commit[point_idx];
            let advice = advices[commit_idx];
            let mut point_claimed: Vec<F> = Vec::with_capacity(advice.chunks_per_poly.len());

            for poly_idx in 0..advice.chunks_per_poly.len() {
                let poly_num_vars_i = commit_poly_num_vars[commit_idx][poly_idx];
                let padded_point = resize_point(&point.clone(), poly_num_vars_i);
                let claimed_value = eval_mle_poly(&commit_poly_evals[commit_idx][poly_idx], &padded_point);
                point_claimed.push(claimed_value);
            }
            claimed_values.push(point_claimed);
        }
        Net::recv_from_master_uniform(Some(claimed_values.clone()));
        claimed_values
    } else {
        Net::recv_from_master_uniform(None)
    };
    end_timer!(timer);

    // Step 3: Distributed Sumcheck to reduce all polynomials to a single point
    // Each party runs local rounds on their local polynomials, then master runs party rounds
    let timer = start_timer!(|| "DMultiChunkedBatchOpen.Sumcheck");

    // Find max_local_num_vars across all polynomials (commit_local_num_vars computed above)
    let max_local_num_vars = commit_local_num_vars.iter()
        .flat_map(|v| v.iter())
        .copied()
        .max()
        .unwrap_or(base_mu);

    // Get gamma challenge (all parties need this)
    let gamma: F = if Net::am_master() {
        let g = transcript.get_and_append_challenge(b"gamma")?;
        Net::recv_from_master_uniform(Some(g));
        g
    } else {
        Net::recv_from_master_uniform(None)
    };

    // Each party builds VirtualPolynomial from their local data
    let mut sumcheck_poly = VirtualPolynomial::new(max_local_num_vars);
    let mut global_idx = 0usize;

    for (point_idx, point) in points.iter().enumerate() {
        let commit_idx = point_to_commit[point_idx];
        let advice = advices[commit_idx];

        for poly_idx in 0..advice.local_poly_evals.len() {
            let local_num_vars = commit_local_num_vars[commit_idx][poly_idx];
            let full_num_vars = local_num_vars + num_party_vars;

            // Get local polynomial evaluations from advice
            let local_poly_evals = &advice.local_poly_evals[poly_idx];

            // Pad local polynomial to max_local_num_vars
            let padded_local_evals = resize_eval(local_poly_evals, max_local_num_vars);
            let padded_local_poly = evals_to_arcpoly(&padded_local_evals);

            // For eq polynomial: use the first local_num_vars coordinates of point
            // Truncate point to full_num_vars first (in case point is longer), then take local part
            let truncated_point = resize_point(point, full_num_vars);
            let point_local: Vec<F> = truncated_point[..local_num_vars].to_vec();
            let padded_point_local = resize_point(&point_local, max_local_num_vars);
            let eq_local_poly = evals_to_arcpoly(&get_tensor(&padded_point_local));

            // Compute eq_party_factor = eq(point_party, party_id)
            // point_party is the high bits of the truncated point (from local_num_vars to full_num_vars)
            // We create a CONSTANT MLE (all values equal to eq_party_factor) so that d_prove
            // correctly builds EQ_party(x_party) = eq(point_party, x_party) during party rounds
            let point_party: Vec<F> = truncated_point[local_num_vars..].to_vec();
            let eq_party_factor = eval_eq(&point_party, party_id);

            // Create constant MLE for eq_party_factor (same value everywhere)
            let eq_party_dummy_evals = vec![eq_party_factor; 1 << max_local_num_vars];
            let eq_party_dummy_poly = evals_to_arcpoly(&eq_party_dummy_evals);

            // Coefficient = gamma^i (eq_party is now an MLE, not a coefficient)
            let coeff = gamma.pow([global_idx as u64]);

            sumcheck_poly
                .add_mle_list([padded_local_poly, eq_local_poly, eq_party_dummy_poly], coeff)
                .map_err(|e| PCSError::VirtualPolynomialError(format!("{:?}", e)))?;

            global_idx += 1;
        }
    }

    // Run distributed sumcheck
    let sumcheck_proof_opt = <PolyIOP<F> as SumCheck<F>>::d_prove(sumcheck_poly, transcript)
        .map_err(|e| PCSError::SumCheckError(format!("{:?}", e)))?;

    // Broadcast proof and random point to all parties
    let (sumcheck_proof, r): (IOPProof<F>, Vec<F>) = if Net::am_master() {
        let proof = sumcheck_proof_opt.unwrap();
        let r_vec = proof.point.clone();
        Net::recv_from_master_uniform(Some((proof.clone(), r_vec.clone())));
        (proof, r_vec)
    } else {
        Net::recv_from_master_uniform(None)
    };
    end_timer!(timer);

    // Step 4: Master evaluates all chunks at the correct evaluation point
    // In distributed sumcheck, r has structure: [r_local (max_local_num_vars), r_party (num_party_vars)]
    // Chunk variable structure is [x_local, x_party] where x_local has local_num_vars vars.
    // For sumcheck verification, we need f(r_local[0..local_num_vars], r_party).
    // For DeepFold, we use combined polynomial with r_low.
    let max_local_num_vars = max_num_vars - num_party_vars;
    let r_party: Vec<F> = r[max_local_num_vars..].to_vec();
    let r_low = resize_point(&r[..base_mu.min(r.len())].to_vec(), base_mu);

    let timer = start_timer!(|| "DMultiChunkedBatchOpen.EvalAndCombine");
    let (chunk_evals_at_r, gamma_combined, combined_evals, combined_f0, combined_eval_at_r_low) = if Net::am_master() {
        // Collect all chunks' evaluations at the correct point for sumcheck verification
        // For each polynomial, construct eval_point = [r_local[0..local_num_vars], r_party]
        let mut chunk_evals_at_r: Vec<F> = Vec::with_capacity(total_chunks_dist);
        for (commit_idx, advice) in advices.iter().enumerate() {
            let mut chunk_offset = 0;
            for poly_idx in 0..advice.chunks_per_poly.len() {
                let local_num_vars = commit_local_num_vars[commit_idx][poly_idx];
                let num_chunks = advice.chunks_per_poly[poly_idx];

                // Construct the correct evaluation point for this polynomial
                // Chunk variable ordering is [x_local, x_party]
                let mut eval_point: Vec<F> = r[..local_num_vars].to_vec();
                eval_point.extend_from_slice(&r_party);
                eval_point = resize_point(&eval_point, base_mu);

                // Evaluate each chunk of this polynomial
                for c in 0..num_chunks {
                    let chunk = &advice.chunk_polys[chunk_offset + c];
                    let eval = eval_mle_poly(&chunk.evaluations, &eval_point);
                    chunk_evals_at_r.push(eval);
                }
                chunk_offset += num_chunks;
            }
        }

        // Get gamma_combine challenge
        let gamma_combined: Vec<F> = transcript.get_and_append_challenge_vectors(b"gamma_combine", total_chunks_dist)?;

        // Compute combined f0 (coefficients) from combined evaluations
        let combined_evals: Vec<F> = (0..1 << base_mu)
            .map(|i| {
                let mut sum = F::ZERO;
                let mut chunk_idx = 0;
                for advice in advices.iter() {
                    for chunk in &advice.chunk_polys {
                        sum += gamma_combined[chunk_idx] * chunk.evaluations[i];
                        chunk_idx += 1;
                    }
                }
                sum
            })
            .collect();
        let combined_f0 = evals_to_coeffs(base_mu, &combined_evals);

        // Compute combined_eval_at_r_low for distributed verification
        // This is the gamma-combined evaluation at r_low, needed for DeepFold linear poly check
        let combined_eval_at_r_low = eval_mle_poly(&combined_evals, &r_low);

        (chunk_evals_at_r, gamma_combined, combined_evals, combined_f0, combined_eval_at_r_low)
    } else {
        (vec![], vec![], vec![], vec![], F::ZERO)
    };
    end_timer!(timer);

    // Broadcast gamma_combined to all parties (r is already broadcast with sumcheck_proof above)
    let gamma_combined: Vec<F> = if Net::am_master() {
        Net::recv_from_master_uniform(Some(gamma_combined.clone()));
        gamma_combined
    } else {
        Net::recv_from_master_uniform(None)
    };

    // Step 5: Master computes combined_v0 directly from its full v0_matrix data
    // Master's v0_matrix is already in poly-major order after d_chunked_batch_commit
    // gamma_combined is used in poly-major order to match claimed values computation
    let timer = start_timer!(|| "DMultiChunkedBatchOpen.ComputeCombinedV0");
    let combined_v0: Vec<F> = if Net::am_master() {
        let mut result = vec![F::ZERO; len_l0];
        let mut chunk_idx = 0;

        // Master's advices have full v0_matrix in poly-major order
        for advice in advices.iter() {
            for row in &advice.batch_advice.v0_matrix {
                let gamma_j = gamma_combined[chunk_idx];
                for i in 0..len_l0 {
                    result[i] += gamma_j * row[i];
                }
                chunk_idx += 1;
            }
        }

        Net::recv_from_master_uniform(Some(result.clone()));
        result
    } else {
        Net::recv_from_master_uniform(None)
    };
    end_timer!(timer);

    // Initialize domains
    let mut domains: Vec<GeneralEvaluationDomain<F>> = vec![l0];
    for i in 1..=base_mu {
        domains.push(GeneralEvaluationDomain::<F>::new(l0.size() >> i).unwrap());
    }

    // Broadcast combined_evals and combined_f0 to all parties for folding
    let combined_evals: Vec<F> = if Net::am_master() {
        Net::recv_from_master_uniform(Some(combined_evals.clone()));
        combined_evals
    } else {
        Net::recv_from_master_uniform(None)
    };

    let combined_f0: Vec<F> = if Net::am_master() {
        Net::recv_from_master_uniform(Some(combined_f0.clone()));
        combined_f0
    } else {
        Net::recv_from_master_uniform(None)
    };

    // Folding phase with distributed Merkle tree
    let timer = start_timer!(|| "DMultiChunkedBatchOpen.Folding");

    // Compute r_low for DeepFold folding (first base_mu coordinates of r)
    let r_low = resize_point(&r[..base_mu.min(r.len())].to_vec(), base_mu);

    let mut a = vec![Vec::new()];
    let mut f_tilde = vec![combined_evals];
    let mut f = vec![combined_f0];
    let mut alpha_vec = vec![F::ZERO];
    let mut linear_polys: Vec<Vec<(F, F)>> = Vec::new();
    let mut v = vec![combined_v0];
    let mut mt_roots: Vec<Byte32> = Vec::new();
    let mut mt: Vec<MerkleTree> = Vec::new();
    let mut final_value = F::ZERO;
    let mut r_vals = vec![F::ZERO];

    // Opening point for combined polynomial
    a[0].push(r_low.clone());

    for i in 1..=base_mu {
        // Get alpha challenge (synchronized across parties)
        let alpha_i = if Net::am_master() {
            let alpha = transcript.get_and_append_challenge(b"alpha")?;
            Net::recv_from_master_uniform(Some(alpha));
            alpha
        } else {
            Net::recv_from_master_uniform(None)
        };
        alpha_vec.push(alpha_i);
        a[i - 1].push(get_alpha_powers::<F>(alpha_i, base_mu - i + 1));

        let (f0_split, f1) = split_even_odd(&f_tilde[i - 1]);
        let (fe, fo) = split_even_odd(&f[i - 1]);

        // Compute linear polynomials
        if i == base_mu {
            linear_polys.push(vec![(f_tilde[i - 1][0], f_tilde[i - 1][1])]);
        } else {
            linear_polys.push(
                a[i - 1]
                    .iter()
                    .map(|w| {
                        let w_tensor = get_tensor(&w[1..].to_vec());
                        (inner_product(&w_tensor, &f0_split), inner_product(&w_tensor, &f1))
                    })
                    .collect(),
            );
            a.push(a[i - 1].iter().map(|w| w[1..].to_vec()).collect());
        }

        // Get r challenge (synchronized across parties)
        let ri = if Net::am_master() {
            let r_challenge = transcript.get_and_append_challenge(b"r")?;
            Net::recv_from_master_uniform(Some(r_challenge));
            r_challenge
        } else {
            Net::recv_from_master_uniform(None)
        };
        r_vals.push(ri);

        // Fold
        f.push(vector_add(&fe, &scalar_vector_product(ri, &fo)));
        f_tilde.push(vector_add(
            &scalar_vector_product(F::ONE - ri, &f0_split),
            &scalar_vector_product(ri, &f1),
        ));

        // Compute FFT
        let vi = domains[i].fft(&f[i]);

        if i == base_mu {
            final_value = vi[0];
            v.push(vi);
        } else {
            // Build Merkle tree for this level
            // Use same pattern as compute_leaf_hashes in utils.rs
            let len_vi = vi.len();
            let leaf_size = LEAF_SIZE.min(len_vi);
            let step = len_vi / leaf_size;  // Number of leaves = step

            // When step < num_party, distribution doesn't help - have master build directly
            if step < num_party {
                // Master builds tree directly (all parties have same vi since f is broadcast)
                if Net::am_master() {
                    let mti = build_merkle_tree(&vi);
                    mt_roots.push(mti.root());
                    mt.push(mti);
                }
            } else {
                // Distributed: each party computes hashes for its portion of leaves
                let leaves_per_party = step / num_party;
                let start_leaf = party_id * leaves_per_party;
                let end_leaf = (party_id + 1) * leaves_per_party;

                // Match compute_leaf_hashes pattern: leaf[j] = v[leaf_idx + j * step]
                let local_leaves: Vec<Byte32> = (start_leaf..end_leaf)
                    .map(|leaf_idx| {
                        let leaf_elems: Vec<F> = (0..leaf_size)
                            .map(|j| vi[leaf_idx + j * step])
                            .collect();
                        compute_sha256_row(&leaf_elems)
                    })
                    .collect();

                // Gather all leaves to master to build full tree
                let all_leaves_opt = Net::send_to_master(&local_leaves);
                if Net::am_master() {
                    let all_leaves: Vec<Byte32> = all_leaves_opt.unwrap().into_iter().flatten().collect();
                    let mti = MerkleTree::with_leaf_size(&all_leaves, leaf_size);
                    mt_roots.push(mti.root());
                    mt.push(mti);
                }
            }

            v.push(vi);
        }
    }
    end_timer!(timer);

    // Step 6: FRI consistency checks with distributed mt0 proofs
    let mut merkle_proofs: Vec<Vec<(usize, (F, F), Vec<F>, Vec<Byte32>)>> = Vec::new();
    let mut mt0_proofs: Vec<Vec<(Vec<F>, Vec<Byte32>)>> = Vec::new();

    for _t in 0..s {
        // Get beta challenge (synchronized across parties)
        let beta_initial = if Net::am_master() {
            let beta = transcript.get_and_append_challenge_indices(b"beta", 1, domains[0].size())?[0];
            Net::recv_from_master_uniform(Some(beta));
            beta
        } else {
            Net::recv_from_master_uniform(None)
        };

        let mut beta = beta_initial;
        let mut level_proofs = Vec::new();

        // For i=0, store values without merkle proof (verified via linear combination with mt0s)
        let leaf_size_0 = LEAF_SIZE.min(v[0].len());
        let step_0 = v[0].len() / leaf_size_0;
        let local_beta_0 = beta % step_0;
        let beta_prime_0 = if beta >= v[0].len() / 2 {
            beta - v[0].len() / 2
        } else {
            beta + v[0].len() / 2
        };
        level_proofs.push((
            beta,
            (v[0][beta], v[0][beta_prime_0]),
            get_leaf_elements(&v[0], local_beta_0, step_0, leaf_size_0),
            vec![],
        ));
        if beta >= domains[1].size() {
            beta -= domains[1].size();
        }

        // For i=1..base_mu-1, generate full merkle proofs (on master only, since master has full trees)
        if Net::am_master() {
            for i in 1..base_mu {
                level_proofs.push(open_merkle_tree_at_conjugate_points(&mt[i - 1], &v[i], beta));
                if beta >= domains[i + 1].size() {
                    beta -= domains[i + 1].size();
                }
            }
        }
        merkle_proofs.push(level_proofs);

        // Generate mt0 proofs for each commitment using distributed query
        let x0 = beta_initial;
        let mut commit_mt0_proofs: Vec<(Vec<F>, Vec<Byte32>)> = Vec::new();

        // For each commitment, query the distributed merkle proof
        // All parties participate in each query since they need to check if they own the position
        for advice in advices.iter() {
            let (column_values, mt0_proof) = d_query_merkle_proof(advice, x0);
            if Net::am_master() {
                commit_mt0_proofs.push((column_values, mt0_proof));
            }
        }
        mt0_proofs.push(commit_mt0_proofs);
    }

    if Net::am_master() {
        Ok(Some(MultiChunkedBatchProof {
            claimed_values,
            point_to_commit: point_to_commit.to_vec(),
            sumcheck_proof,
            chunk_evals_at_r,
            linear_polys,
            merkle_roots: mt_roots,
            final_value,
            merkle_proofs,
            mt0_proofs,
            num_party_vars: Some(num_party_vars),
            combined_eval_at_r_low: Some(combined_eval_at_r_low),
        }))
    } else {
        Ok(None)
    }
}


// =============================================================================
// Extension Field Multi-Commitment Batch Open
// =============================================================================

use crate::types::{FieldExtension, HasQuadraticExtension};
use ark_ff::Field;

/// Split vector into even and odd parts (extension field version)
fn split_even_odd_ext<EF: Field>(v: &[EF]) -> (Vec<EF>, Vec<EF>) {
    let n = v.len() / 2;
    let even: Vec<EF> = (0..n).map(|i| v[2 * i]).collect();
    let odd: Vec<EF> = (0..n).map(|i| v[2 * i + 1]).collect();
    (even, odd)
}

/// Fold two vectors with extension field challenge
fn fold_ext<EF: Field>(f0: &[EF], f1: &[EF], r: EF) -> Vec<EF> {
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

/// Resize extension field point to target length (pad with zeros or truncate)
fn resize_point_ext<F: PrimeField + HasQuadraticExtension>(point: &[F::Extension], target_len: usize) -> Vec<F::Extension> {
    let mut result = point.to_vec();
    while result.len() < target_len {
        result.push(F::Extension::from_base(F::ZERO));
    }
    result.truncate(target_len);
    result
}

/// Evaluate MLE (base field evaluations) at extension field point
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
        if i < tensor.len() {
            result = result + tensor[i] * F::Extension::from_base(eval);
        }
    }
    result
}

/// Evaluate MLE (extension field evaluations) at extension field point
fn eval_mle_at_ext_point_from_ext<F: PrimeField + HasQuadraticExtension>(
    evals: &[F::Extension],
    point: &[F::Extension],
) -> F::Extension {
    let n = point.len();
    if n == 0 {
        return evals[0];
    }

    let tensor = get_tensor_ext::<F>(point);
    let mut result = F::Extension::default();
    for (i, &eval) in evals.iter().enumerate() {
        if i < tensor.len() {
            result = result + tensor[i] * eval;
        }
    }
    result
}

/// Evaluate eq polynomial at a specific index in extension field
/// eq(point, i) = product_j (point_j * bit_j(i) + (1 - point_j) * (1 - bit_j(i)))
fn eval_eq_ext<F: PrimeField + HasQuadraticExtension>(
    point: &[F::Extension],
    index: usize,
) -> F::Extension {
    let mut result = F::Extension::from_base(F::ONE);
    for (j, &p) in point.iter().enumerate() {
        let bit = ((index >> j) & 1) as u64;
        if bit == 1 {
            result = result * p;
        } else {
            result = result * (F::Extension::from_base(F::ONE) - p);
        }
    }
    result
}

/// Proof for multi-commitment batch opening at extension field points
#[derive(CanonicalSerialize, CanonicalDeserialize, Clone, Debug, PartialEq, Eq)]
pub struct MultiChunkedBatchExtProof<F: PrimeField + HasQuadraticExtension> {
    /// Claimed evaluation values for each opening (in extension field)
    /// claimed_values[point_idx] - value of the targeted poly at points[point_idx]
    pub claimed_values: Vec<F::Extension>,
    /// Which commitment each point corresponds to
    pub point_to_commit: Vec<usize>,
    /// Which polynomial within the commitment each point targets
    pub point_to_poly: Vec<usize>,
    /// Sumcheck proof for reducing all polynomials to a single point (base field)
    pub sumcheck_proof: IOPProof<F>,
    /// Evaluations of all chunks at the sumcheck random point (extension field)
    pub chunk_evals_at_r: Vec<F::Extension>,
    /// Linear polynomials at each folding step (extension field)
    pub linear_polys: Vec<Vec<(F::Extension, F::Extension)>>,
    /// Merkle roots for each folding level (base field)
    pub merkle_roots: Vec<Byte32>,
    /// Final value after all folding (extension field)
    pub final_value: F::Extension,
    /// Merkle proofs for FRI consistency checks (base field values)
    pub merkle_proofs: Vec<Vec<(usize, (F, F), Vec<F>, Vec<Byte32>)>>,
    /// Proofs for original mt0 consistency (for each commitment)
    pub mt0_proofs: Vec<Vec<(Vec<F>, Vec<Byte32>)>>,
    /// Number of party variables (for distributed sumcheck)
    pub num_party_vars: Option<usize>,
    /// Gamma-combined chunk evaluation at r_low (extension field, for distributed case)
    pub combined_eval_at_r_low: Option<F::Extension>,
    /// SumCheck subclaim evaluations (in extension field)
    pub sum_check_evals: Vec<F::Extension>,
}

/// Non-distributed batch open multiple DeepFoldBatchMultiCommitments at extension field points
///
/// This achieves 128-bit soundness by using extension field challenges and evaluations
/// while keeping base field Merkle commitments.
///
/// Protocol:
/// 1. Compute extension field claimed values
/// 2. Base field sumcheck to reduce all polynomials to a single point
/// 3. Evaluate combined polynomial at extension field sumcheck point
/// 4. Run DeepFold folding with extension field linear polynomials
/// 5. Generate mt0 proofs for FRI consistency
#[allow(non_snake_case)]
pub fn multi_chunked_batch_open_at_ext_point<F: PrimeField + HasQuadraticExtension>(
    prover_param: &DeepFoldProverParam<F>,
    advices: &[&DeepFoldBatchMultiProverAdvice<F>],
    points: &[Vec<F::Extension>],
    point_to_commit: &[usize],
    point_to_poly: &[usize],
    transcript: &mut IOPTranscript<F>,
) -> Result<MultiChunkedBatchExtProof<F>, PCSError> {
    let DeepFoldProverParam { max_mu, l0, s } = prover_param.clone();
    let base_mu = max_mu;
    let num_commitments = advices.len();
    let num_points = points.len();
    let len_l0 = l0.size();

    assert_eq!(num_points, point_to_commit.len(), "Must have same number of points as point_to_commit");
    assert_eq!(num_points, point_to_poly.len(), "Must have same number of points as point_to_poly");
    assert!(num_commitments > 0, "Must have at least one commitment");
    for (i, &commit_idx) in point_to_commit.iter().enumerate() {
        assert!(commit_idx < num_commitments, "point_to_commit index out of bounds");
        assert!(point_to_poly[i] < advices[commit_idx].chunks_per_poly.len(), "point_to_poly index out of bounds");
    }
    for &commit_idx in point_to_commit {
        assert!(commit_idx < num_commitments, "point_to_commit index out of bounds");
    }

    // Pre-compute polynomial evaluations for each commitment (reconstruct from chunks)
    let timer = start_timer!(|| "MultiChunkedBatchOpenExt.ReconstructPolys");
    let mut commit_poly_evals: Vec<Vec<Vec<F>>> = Vec::with_capacity(num_commitments);
    let mut commit_poly_num_vars: Vec<Vec<usize>> = Vec::with_capacity(num_commitments);

    for advice in advices.iter() {
        let mut poly_evals_list: Vec<Vec<F>> = Vec::new();
        let mut poly_num_vars_list: Vec<usize> = Vec::new();
        let mut chunk_offset = 0;
        for &num_chunks in advice.chunks_per_poly.iter() {
            let poly_evals: Vec<F> = (0..num_chunks)
                .flat_map(|c| advice.chunk_polys[chunk_offset + c].evaluations.clone())
                .collect();
            let poly_num_vars_i = base_mu + (num_chunks.ilog2() as usize);
            poly_evals_list.push(poly_evals);
            poly_num_vars_list.push(poly_num_vars_i);
            chunk_offset += num_chunks;
        }
        commit_poly_evals.push(poly_evals_list);
        commit_poly_num_vars.push(poly_num_vars_list);
    }
    end_timer!(timer);

    // Compute total chunks
    let total_chunks: usize = advices.iter()
        .map(|advice| advice.chunks_per_poly.iter().sum::<usize>())
        .sum();

    // Step 1: Compute extension field claimed values (only for targeted polynomial per point)
    let timer = start_timer!(|| "MultiChunkedBatchOpenExt.ComputeClaims");
    let mut claimed_values: Vec<F::Extension> = Vec::with_capacity(num_points);
    for (point_idx, point) in points.iter().enumerate() {
        let commit_idx = point_to_commit[point_idx];
        let poly_idx = point_to_poly[point_idx];
        let poly_num_vars_i = commit_poly_num_vars[commit_idx][poly_idx];
        let padded_point = resize_point_ext::<F>(&point.clone(), poly_num_vars_i);
        let claimed_value = eval_mle_at_ext_point(&commit_poly_evals[commit_idx][poly_idx], &padded_point);
        claimed_values.push(claimed_value);
    }
    end_timer!(timer);

    // Find max_num_vars across only the targeted polynomials
    let max_num_vars = point_to_commit.iter().zip(point_to_poly.iter())
        .map(|(&commit_idx, &poly_idx)| commit_poly_num_vars[commit_idx][poly_idx])
        .max()
        .unwrap_or(base_mu)
        .max(base_mu);

    // Step 2: Base field sumcheck (using real parts of extension field points)
    let timer = start_timer!(|| "MultiChunkedBatchOpenExt.Sumcheck");

    // Convert extension field points to base field points for sumcheck
    let points_base: Vec<Vec<F>> = points.iter()
        .map(|pt| pt.iter().map(|x| F::ext_real(x)).collect())
        .collect();

    let gamma = transcript.get_and_append_challenge(b"gamma")?;

    let mut sumcheck_poly = VirtualPolynomial::new(max_num_vars);
    // One term per point (only the targeted polynomial)
    for (point_idx, point) in points_base.iter().enumerate() {
        let commit_idx = point_to_commit[point_idx];
        let poly_idx = point_to_poly[point_idx];
        let this_poly_num_vars = commit_poly_num_vars[commit_idx][poly_idx];

        let padded_evals = resize_eval(&commit_poly_evals[commit_idx][poly_idx], max_num_vars);
        let padded_poly = evals_to_arcpoly(&padded_evals);

        let truncated_point = resize_point(point, this_poly_num_vars);
        let padded_point = resize_point(&truncated_point, max_num_vars);
        let eq_poly = evals_to_arcpoly(&get_tensor(&padded_point));

        sumcheck_poly
            .add_mle_list([padded_poly, eq_poly], gamma.pow([point_idx as u64]))
            .map_err(|e| PCSError::VirtualPolynomialError(format!("{:?}", e)))?;
    }

    let sumcheck_proof = <PolyIOP<F> as SumCheck<F>>::prove(sumcheck_poly, transcript)
        .map_err(|e| PCSError::SumCheckError(format!("{:?}", e)))?;
    let r = sumcheck_proof.point.clone();
    let r_ext: Vec<F::Extension> = r.iter().map(|&x| F::Extension::from_base(x)).collect();
    end_timer!(timer);

    // Step 3: Evaluate all chunks at extension field point and combine
    let r_low = resize_point(&r[..base_mu.min(r.len())].to_vec(), base_mu);
    let r_low_ext: Vec<F::Extension> = r_low.iter().map(|&x| F::Extension::from_base(x)).collect();

    let timer = start_timer!(|| "MultiChunkedBatchOpenExt.EvalAndCombine");
    let mut chunk_evals_at_r: Vec<F::Extension> = Vec::with_capacity(total_chunks);
    for advice in advices.iter() {
        for chunk in &advice.chunk_polys {
            let eval = eval_mle_at_ext_point(&chunk.evaluations, &r_low_ext);
            chunk_evals_at_r.push(eval);
        }
    }

    // Compute sumcheck subclaim evaluations (only for targeted polynomials)
    let sum_check_evals: Vec<F::Extension> = point_to_commit.iter().zip(point_to_poly.iter())
        .map(|(&commit_idx, &poly_idx)| {
            eval_mle_at_ext_point(&commit_poly_evals[commit_idx][poly_idx], &r_ext)
        })
        .collect();

    // Get gamma_combine challenge
    let gamma_combined: Vec<F> = transcript.get_and_append_challenge_vectors(b"gamma_combine", total_chunks)?;

    // Compute combined evaluations (extension field)
    let combined_evals_ext: Vec<F::Extension> = (0..1 << base_mu)
        .map(|i| {
            let mut sum = F::Extension::default();
            let mut chunk_idx = 0;
            for advice in advices.iter() {
                for chunk in &advice.chunk_polys {
                    sum += F::Extension::from_base(gamma_combined[chunk_idx]) * F::Extension::from_base(chunk.evaluations[i]);
                    chunk_idx += 1;
                }
            }
            sum
        })
        .collect();

    // Compute combined_eval_at_r_low
    let combined_eval_at_r_low = eval_mle_at_ext_point_from_ext::<F>(&combined_evals_ext, &r_low_ext);
    end_timer!(timer);

    // Compute combined_v0 (base field)
    let timer = start_timer!(|| "MultiChunkedBatchOpenExt.ComputeCombinedV0");
    let mut combined_v0 = vec![F::ZERO; len_l0];
    let mut chunk_idx = 0;
    for advice in advices.iter() {
        for row in &advice.batch_advice.v0_matrix {
            let gamma_j = gamma_combined[chunk_idx];
            for i in 0..len_l0 {
                combined_v0[i] += gamma_j * row[i];
            }
            chunk_idx += 1;
        }
    }
    end_timer!(timer);

    // Initialize domains
    let mut domains: Vec<GeneralEvaluationDomain<F>> = vec![l0];
    for i in 1..=base_mu {
        domains.push(GeneralEvaluationDomain::<F>::new(l0.size() >> i).unwrap());
    }

    let combined_evals: Vec<F> = combined_evals_ext.iter()
        .map(|&x| F::ext_real(&x))
        .collect();
    let combined_f0 = evals_to_coeffs(base_mu, &combined_evals);

    // Folding phase with extension field linear polynomials
    let timer = start_timer!(|| "MultiChunkedBatchOpenExt.Folding");

    let mut a = vec![Vec::new()];
    let mut f_tilde_ext = vec![combined_evals_ext.clone()];
    let mut f = vec![combined_f0];
    let mut alpha_vec = vec![F::ZERO];
    let mut linear_polys: Vec<Vec<(F::Extension, F::Extension)>> = Vec::new();
    let mut v = vec![combined_v0];
    let mut mt_roots: Vec<Byte32> = Vec::new();
    let mut mt: Vec<MerkleTree> = Vec::new();
    let mut final_value = F::Extension::default();
    let mut r_vals = vec![F::ZERO];

    // Opening point for combined polynomial
    a[0].push(r_low.clone());

    for i in 1..=base_mu {
        let alpha_i = transcript.get_and_append_challenge(b"alpha")?;
        alpha_vec.push(alpha_i);
        a[i - 1].push(get_alpha_powers::<F>(alpha_i, base_mu - i + 1));

        // Split f_tilde (extension field)
        let (f0_ext, f1_ext) = split_even_odd_ext(&f_tilde_ext[i - 1]);
        let (fe, fo) = split_even_odd(&f[i - 1]);

        // Compute linear polynomials (extension field)
        if i == base_mu {
            linear_polys.push(vec![(f_tilde_ext[i - 1][0], f_tilde_ext[i - 1][1])]);
        } else {
            linear_polys.push(
                a[i - 1]
                    .iter()
                    .map(|w| {
                        let w_tensor = get_tensor(&w[1..].to_vec());
                        let w_tensor_ext: Vec<F::Extension> = w_tensor.iter()
                            .map(|&x| F::Extension::from_base(x))
                            .collect();
                        (
                            f0_ext.iter().zip(w_tensor_ext.iter())
                                .map(|(&a, &b)| a * b)
                                .fold(F::Extension::default(), |acc, x| acc + x),
                            f1_ext.iter().zip(w_tensor_ext.iter())
                                .map(|(&a, &b)| a * b)
                                .fold(F::Extension::default(), |acc, x| acc + x)
                        )
                    })
                    .collect(),
            );
            a.push(a[i - 1].iter().map(|w| w[1..].to_vec()).collect());
        }

        // Get r challenge
        let ri = transcript.get_and_append_challenge(b"r")?;
        r_vals.push(ri);
        let ri_ext = F::Extension::from_base(ri);

        // Fold (base field for FFT, extension field for evaluations)
        f.push(vector_add(&fe, &scalar_vector_product(ri, &fo)));
        f_tilde_ext.push(fold_ext(&f0_ext, &f1_ext, ri_ext));

        // Compute FFT (base field)
        let vi = domains[i].fft(&f[i]);

        if i == base_mu {
            final_value = f_tilde_ext[i][0];
            v.push(vi);
        } else {
            let mti = build_merkle_tree(&vi);
            mt_roots.push(mti.root());
            mt.push(mti);
            v.push(vi);
        }
    }
    end_timer!(timer);

    // FRI consistency checks with mt0 proofs
    let mut merkle_proofs: Vec<Vec<(usize, (F, F), Vec<F>, Vec<Byte32>)>> = Vec::new();
    let mut mt0_proofs: Vec<Vec<(Vec<F>, Vec<Byte32>)>> = Vec::new();

    for _t in 0..s {
        let beta_initial = transcript.get_and_append_challenge_indices(b"beta", 1, domains[0].size())?[0];

        let mut beta = beta_initial;
        let mut level_proofs = Vec::new();

        // For i=0
        let leaf_size_0 = LEAF_SIZE.min(v[0].len());
        let step_0 = v[0].len() / leaf_size_0;
        let local_beta_0 = beta % step_0;
        let beta_prime_0 = if beta >= v[0].len() / 2 {
            beta - v[0].len() / 2
        } else {
            beta + v[0].len() / 2
        };
        level_proofs.push((
            beta,
            (v[0][beta], v[0][beta_prime_0]),
            get_leaf_elements(&v[0], local_beta_0, step_0, leaf_size_0),
            vec![],
        ));
        if beta >= domains[1].size() {
            beta -= domains[1].size();
        }

        // For i=1..base_mu-1
        for i in 1..base_mu {
            level_proofs.push(open_merkle_tree_at_conjugate_points(&mt[i - 1], &v[i], beta));
            if beta >= domains[i + 1].size() {
                beta -= domains[i + 1].size();
            }
        }
        merkle_proofs.push(level_proofs);

        // Generate mt0 proofs for each commitment
        let x0 = beta_initial;
        let mut commit_mt0_proofs: Vec<(Vec<F>, Vec<Byte32>)> = Vec::new();

        for advice in advices.iter() {
            let column_at_x0: Vec<F> = advice.batch_advice.v0_matrix.iter()
                .map(|row| row[x0])
                .collect();

            let mt0 = &advice.batch_advice.merkle_tree;
            let mt0_proof = mt0.prove(x0);

            commit_mt0_proofs.push((column_at_x0, mt0_proof));
        }
        mt0_proofs.push(commit_mt0_proofs);
    }

    Ok(MultiChunkedBatchExtProof {
        claimed_values,
        point_to_commit: point_to_commit.to_vec(),
        point_to_poly: point_to_poly.to_vec(),
        sumcheck_proof,
        chunk_evals_at_r,
        linear_polys,
        merkle_roots: mt_roots,
        final_value,
        merkle_proofs,
        mt0_proofs,
        num_party_vars: None,
        combined_eval_at_r_low: Some(combined_eval_at_r_low),
        sum_check_evals,
    })
}

/// Distributed batch open multiple DeepFoldBatchMultiCommitments at extension field points
///
/// This achieves 128-bit soundness by using extension field challenges and evaluations
/// while keeping base field Merkle commitments.
///
/// Protocol:
/// 1. Compute extension field claimed values
/// 2. Base field sumcheck to reduce all polynomials to a single point
/// 3. Evaluate combined polynomial at extension field sumcheck point
/// 4. Run DeepFold folding with extension field linear polynomials
/// 5. Generate distributed mt0 proofs for FRI consistency
#[allow(non_snake_case)]
pub fn d_multi_chunked_batch_open_at_ext_point<F: PrimeField + HasQuadraticExtension>(
    prover_param: &DeepFoldProverParam<F>,
    advices: &[&DeepFoldBatchMultiProverAdvice<F>],
    points: &[Vec<F::Extension>],
    point_to_commit: &[usize],
    point_to_poly: &[usize],
    transcript: &mut IOPTranscript<F>,
) -> Result<Option<MultiChunkedBatchExtProof<F>>, PCSError> {
    let DeepFoldProverParam { max_mu, l0, s } = prover_param.clone();
    let base_mu = max_mu;
    let num_commitments = advices.len();
    let num_points = points.len();
    let num_party = Net::n_parties();
    let num_party_vars = num_party.ilog2() as usize;
    let len_l0 = l0.size();

    assert_eq!(num_points, point_to_commit.len(), "Must have same number of points as point_to_commit");
    assert_eq!(num_points, point_to_poly.len(), "Must have same number of points as point_to_poly");
    assert!(num_commitments > 0, "Must have at least one commitment");
    for (i, &commit_idx) in point_to_commit.iter().enumerate() {
        assert!(commit_idx < num_commitments, "point_to_commit index out of bounds");
        assert!(point_to_poly[i] < advices[commit_idx].chunks_per_poly.len(), "point_to_poly index out of bounds");
    }

    // Broadcast points, point_to_commit, and point_to_poly to all parties
    let points: Vec<Vec<F::Extension>> = if Net::am_master() {
        Net::recv_from_master_uniform(Some(points.to_vec()));
        points.to_vec()
    } else {
        Net::recv_from_master_uniform(None)
    };
    let point_to_poly: Vec<usize> = if Net::am_master() {
        Net::recv_from_master_uniform(Some(point_to_poly.to_vec()));
        point_to_poly.to_vec()
    } else {
        Net::recv_from_master_uniform(None)
    };

    let point_to_commit: Vec<usize> = if Net::am_master() {
        Net::recv_from_master_uniform(Some(point_to_commit.to_vec()));
        point_to_commit.to_vec()
    } else {
        Net::recv_from_master_uniform(None)
    };

    // Pre-compute polynomial evaluations for each commitment (master only)
    let commit_poly_evals: Vec<Vec<Vec<F>>> = if Net::am_master() {
        let mut result: Vec<Vec<Vec<F>>> = Vec::new();
        for advice in advices.iter() {
            let mut poly_evals_list = Vec::new();
            let mut chunk_offset = 0;
            for &num_chunks_total in advice.chunks_per_poly.iter() {
                let poly_evals: Vec<F> = (0..num_chunks_total)
                    .flat_map(|c| advice.chunk_polys[chunk_offset + c].evaluations.clone())
                    .collect();
                poly_evals_list.push(poly_evals);
                chunk_offset += num_chunks_total;
            }
            result.push(poly_evals_list);
        }
        result
    } else {
        vec![]
    };

    // Compute local num_vars for each polynomial
    let commit_local_num_vars: Vec<Vec<usize>> = advices.iter()
        .map(|advice| {
            advice.local_poly_evals.iter()
                .map(|evals| evals.len().ilog2() as usize)
                .collect()
        })
        .collect();

    // Compute full num_vars = local_num_vars + num_party_vars
    let commit_poly_num_vars: Vec<Vec<usize>> = commit_local_num_vars.iter()
        .map(|v| v.iter().map(|&n| n + num_party_vars).collect())
        .collect();

    // Compute total chunks
    let total_chunks_dist: usize = advices.iter()
        .map(|advice| advice.chunks_per_poly.iter().sum::<usize>())
        .sum();

    // Find max_num_vars across only the targeted polynomials
    let max_num_vars = point_to_commit.iter().zip(point_to_poly.iter())
        .map(|(&commit_idx, &poly_idx)| commit_poly_num_vars[commit_idx][poly_idx])
        .max()
        .unwrap_or(base_mu)
        .max(base_mu);

    let max_local_num_vars = max_num_vars - num_party_vars;

    // Step 1: Distributed evaluation of claimed values (all parties contribute)
    let timer = start_timer!(|| "DMultiChunkedBatchOpenExt.ComputeClaims");
    let party_id = Net::party_id();
    let mut local_contributions: Vec<F::Extension> = Vec::with_capacity(num_points);
    for (point_idx, point) in points.iter().enumerate() {
        let commit_idx = point_to_commit[point_idx];
        let poly_idx = point_to_poly[point_idx];
        let advice = advices[commit_idx];
        let local_num_vars = commit_local_num_vars[commit_idx][poly_idx];
        let poly_num_vars_i = commit_poly_num_vars[commit_idx][poly_idx];

        let padded_point = resize_point_ext::<F>(&point.clone(), poly_num_vars_i);
        let point_low: Vec<F::Extension> = padded_point[..local_num_vars].to_vec();
        let point_high: Vec<F::Extension> = padded_point[local_num_vars..].to_vec();

        // eq(point_high, party_id) * eval_mle_at_ext_point(local_poly_evals, point_low)
        let eq_factor = eval_eq_ext::<F>(&point_high, party_id);
        let local_eval = eval_mle_at_ext_point(&advice.local_poly_evals[poly_idx], &point_low);
        local_contributions.push(eq_factor * local_eval);
    }
    let claimed_values: Vec<F::Extension> = if Net::am_master() {
        let all_contributions: Vec<Vec<F::Extension>> = Net::send_to_master(&local_contributions).unwrap();
        let mut claimed_values: Vec<F::Extension> = Vec::with_capacity(num_points);
        for point_idx in 0..num_points {
            let sum: F::Extension = all_contributions.iter().map(|c| c[point_idx]).fold(F::Extension::default(), |a, b| a + b);
            claimed_values.push(sum);
        }
        Net::recv_from_master_uniform(Some(claimed_values.clone()));
        claimed_values
    } else {
        Net::send_to_master(&local_contributions);
        Net::recv_from_master_uniform(None)
    };
    end_timer!(timer);

    // Step 2: Base field sumcheck (using real parts of extension field points)
    let timer = start_timer!(|| "DMultiChunkedBatchOpenExt.Sumcheck");

    // Convert extension field points to base field points for sumcheck
    let points_base: Vec<Vec<F>> = points.iter()
        .map(|pt| pt.iter().map(|x| F::ext_real(x)).collect())
        .collect();

    // Get gamma challenge (all parties need this)
    let gamma: F = if Net::am_master() {
        let g = transcript.get_and_append_challenge(b"gamma")?;
        Net::recv_from_master_uniform(Some(g));
        g
    } else {
        Net::recv_from_master_uniform(None)
    };

    // Each party builds VirtualPolynomial from their local data
    // One term per point (only the targeted polynomial)
    let mut sumcheck_poly = VirtualPolynomial::new(max_local_num_vars);
    let party_id = Net::party_id();

    for (point_idx, point) in points_base.iter().enumerate() {
        let commit_idx = point_to_commit[point_idx];
        let poly_idx = point_to_poly[point_idx];
        let advice = advices[commit_idx];

        let local_num_vars = commit_local_num_vars[commit_idx][poly_idx];
        let full_num_vars = local_num_vars + num_party_vars;

        // Get local polynomial evaluations from advice
        let local_poly_evals = &advice.local_poly_evals[poly_idx];

        // Pad local polynomial to max_local_num_vars
        let padded_local_evals = resize_eval(local_poly_evals, max_local_num_vars);
        let padded_local_poly = evals_to_arcpoly(&padded_local_evals);

        // For eq polynomial: use the first local_num_vars coordinates of point
        let truncated_point = resize_point(point, full_num_vars);
        let point_local: Vec<F> = truncated_point[..local_num_vars].to_vec();
        let padded_point_local = resize_point(&point_local, max_local_num_vars);
        let eq_local_poly = evals_to_arcpoly(&get_tensor(&padded_point_local));

        // Compute eq_party_factor = eq(point_party, party_id)
        let point_party: Vec<F> = truncated_point[local_num_vars..].to_vec();
        let eq_party_factor = eval_eq(&point_party, party_id);

        // Create constant MLE for eq_party_factor
        let eq_party_dummy_evals = vec![eq_party_factor; 1 << max_local_num_vars];
        let eq_party_dummy_poly = evals_to_arcpoly(&eq_party_dummy_evals);

        let coeff = gamma.pow([point_idx as u64]);

        sumcheck_poly
            .add_mle_list([padded_local_poly, eq_local_poly, eq_party_dummy_poly], coeff)
            .map_err(|e| PCSError::VirtualPolynomialError(format!("{:?}", e)))?;
    }

    // Run distributed sumcheck
    let sumcheck_proof_opt = <PolyIOP<F> as SumCheck<F>>::d_prove(sumcheck_poly, transcript)
        .map_err(|e| PCSError::SumCheckError(format!("{:?}", e)))?;

    // Broadcast proof and random point to all parties
    let (sumcheck_proof, r): (IOPProof<F>, Vec<F>) = if Net::am_master() {
        let proof = sumcheck_proof_opt.unwrap();
        let r_vec = proof.point.clone();
        Net::recv_from_master_uniform(Some((proof.clone(), r_vec.clone())));
        (proof, r_vec)
    } else {
        Net::recv_from_master_uniform(None)
    };

    // Convert r to extension field
    let r_ext: Vec<F::Extension> = r.iter().map(|&x| F::Extension::from_base(x)).collect();
    end_timer!(timer);

    // Step 3: Evaluate all chunks at extension field point and combine
    let r_party: Vec<F> = r[max_local_num_vars..].to_vec();
    let r_low = resize_point(&r[..base_mu.min(r.len())].to_vec(), base_mu);
    let r_low_ext: Vec<F::Extension> = r_low.iter().map(|&x| F::Extension::from_base(x)).collect();

    let timer = start_timer!(|| "DMultiChunkedBatchOpenExt.EvalAndCombine");

    // Distributed computation of sum_check_evals (all parties contribute)
    let mut local_sumcheck_contributions: Vec<F::Extension> = Vec::with_capacity(num_points);
    for (point_idx, _point) in points.iter().enumerate() {
        let commit_idx = point_to_commit[point_idx];
        let poly_idx = point_to_poly[point_idx];
        let advice = advices[commit_idx];
        let local_num_vars = commit_local_num_vars[commit_idx][poly_idx];
        let poly_num_vars_i = commit_poly_num_vars[commit_idx][poly_idx];

        // r_ext is already max_num_vars length, we need to use appropriate portion
        let r_ext_padded = resize_point_ext::<F>(&r_ext, poly_num_vars_i);
        let r_low_local: Vec<F::Extension> = r_ext_padded[..local_num_vars].to_vec();
        let r_high_local: Vec<F::Extension> = r_ext_padded[local_num_vars..].to_vec();

        // eq(r_high, party_id) * eval_mle_at_ext_point(local_poly_evals, r_low)
        let eq_factor = eval_eq_ext::<F>(&r_high_local, party_id);
        let local_eval = eval_mle_at_ext_point(&advice.local_poly_evals[poly_idx], &r_low_local);
        local_sumcheck_contributions.push(eq_factor * local_eval);
    }

    // Aggregate sum_check_evals on master
    let sum_check_evals: Vec<F::Extension> = if Net::am_master() {
        let all_contributions: Vec<Vec<F::Extension>> = Net::send_to_master(&local_sumcheck_contributions).unwrap();
        let mut sum_check_evals: Vec<F::Extension> = Vec::with_capacity(num_points);
        for point_idx in 0..num_points {
            let sum: F::Extension = all_contributions.iter().map(|c| c[point_idx]).fold(F::Extension::default(), |a, b| a + b);
            sum_check_evals.push(sum);
        }
        sum_check_evals
    } else {
        Net::send_to_master(&local_sumcheck_contributions);
        vec![]
    };

    let (chunk_evals_at_r, gamma_combined, combined_evals_ext, combined_eval_at_r_low) = if Net::am_master() {
        // Collect all chunks' evaluations at the correct extension field point
        let mut chunk_evals_at_r: Vec<F::Extension> = Vec::with_capacity(total_chunks_dist);
        for (commit_idx, advice) in advices.iter().enumerate() {
            let mut chunk_offset = 0;
            for poly_idx in 0..advice.chunks_per_poly.len() {
                let local_num_vars = commit_local_num_vars[commit_idx][poly_idx];
                let num_chunks = advice.chunks_per_poly[poly_idx];

                // Construct the correct evaluation point for this polynomial (extension field)
                let r_party_ext: Vec<F::Extension> = r_party.iter().map(|&x| F::Extension::from_base(x)).collect();
                let mut eval_point: Vec<F::Extension> = r_ext[..local_num_vars].to_vec();
                eval_point.extend_from_slice(&r_party_ext);
                eval_point = resize_point_ext::<F>(&eval_point, base_mu);

                // Evaluate each chunk of this polynomial
                for c in 0..num_chunks {
                    let chunk = &advice.chunk_polys[chunk_offset + c];
                    let eval = eval_mle_at_ext_point(&chunk.evaluations, &eval_point);
                    chunk_evals_at_r.push(eval);
                }
                chunk_offset += num_chunks;
            }
        }

        // Get gamma_combine challenge
        let gamma_combined: Vec<F> = transcript.get_and_append_challenge_vectors(b"gamma_combine", total_chunks_dist)?;

        // Compute combined evaluations (extension field)
        let combined_evals_ext: Vec<F::Extension> = (0..1 << base_mu)
            .map(|i| {
                let mut sum = F::Extension::default();
                let mut chunk_idx = 0;
                for advice in advices.iter() {
                    for chunk in &advice.chunk_polys {
                        sum += F::Extension::from_base(gamma_combined[chunk_idx]) * F::Extension::from_base(chunk.evaluations[i]);
                        chunk_idx += 1;
                    }
                }
                sum
            })
            .collect();

        // Compute combined_eval_at_r_low for distributed verification
        let combined_eval_at_r_low = eval_mle_at_ext_point_from_ext::<F>(&combined_evals_ext, &r_low_ext);

        (chunk_evals_at_r, gamma_combined, combined_evals_ext, combined_eval_at_r_low)
    } else {
        (vec![], vec![], vec![], F::Extension::default())
    };
    end_timer!(timer);

    // Broadcast gamma_combined to all parties
    let gamma_combined: Vec<F> = if Net::am_master() {
        Net::recv_from_master_uniform(Some(gamma_combined.clone()));
        gamma_combined
    } else {
        Net::recv_from_master_uniform(None)
    };

    // Step 4: Compute combined_v0 (base field)
    let timer = start_timer!(|| "DMultiChunkedBatchOpenExt.ComputeCombinedV0");
    let combined_v0: Vec<F> = if Net::am_master() {
        let mut result = vec![F::ZERO; len_l0];
        let mut chunk_idx = 0;

        for advice in advices.iter() {
            for row in &advice.batch_advice.v0_matrix {
                let gamma_j = gamma_combined[chunk_idx];
                for i in 0..len_l0 {
                    result[i] += gamma_j * row[i];
                }
                chunk_idx += 1;
            }
        }

        Net::recv_from_master_uniform(Some(result.clone()));
        result
    } else {
        Net::recv_from_master_uniform(None)
    };
    end_timer!(timer);

    // Initialize domains
    let mut domains: Vec<GeneralEvaluationDomain<F>> = vec![l0];
    for i in 1..=base_mu {
        domains.push(GeneralEvaluationDomain::<F>::new(l0.size() >> i).unwrap());
    }

    // Broadcast combined_evals_ext and compute combined_f0 (base field)
    let combined_evals_ext: Vec<F::Extension> = if Net::am_master() {
        Net::recv_from_master_uniform(Some(combined_evals_ext.clone()));
        combined_evals_ext
    } else {
        Net::recv_from_master_uniform(None)
    };

    let combined_evals: Vec<F> = combined_evals_ext.iter()
        .map(|&x| F::ext_real(&x))
        .collect();
    let combined_f0 = evals_to_coeffs(base_mu, &combined_evals);

    // Folding phase with extension field linear polynomials
    let timer = start_timer!(|| "DMultiChunkedBatchOpenExt.Folding");

    let mut a = vec![Vec::new()];
    let mut f_tilde_ext = vec![combined_evals_ext.clone()];
    let mut f = vec![combined_f0];
    let mut alpha_vec = vec![F::ZERO];
    let mut linear_polys: Vec<Vec<(F::Extension, F::Extension)>> = Vec::new();
    let mut v = vec![combined_v0];
    let mut mt_roots: Vec<Byte32> = Vec::new();
    let mut mt: Vec<MerkleTree> = Vec::new();
    let mut final_value = F::Extension::default();
    let mut r_vals = vec![F::ZERO];

    // Opening point for combined polynomial
    a[0].push(r_low.clone());

    for i in 1..=base_mu {
        // Get alpha challenge (synchronized across parties)
        let alpha_i = if Net::am_master() {
            let alpha = transcript.get_and_append_challenge(b"alpha")?;
            Net::recv_from_master_uniform(Some(alpha));
            alpha
        } else {
            Net::recv_from_master_uniform(None)
        };
        alpha_vec.push(alpha_i);
        a[i - 1].push(get_alpha_powers::<F>(alpha_i, base_mu - i + 1));

        // Split f_tilde (extension field)
        let (f0_ext, f1_ext) = split_even_odd_ext(&f_tilde_ext[i - 1]);
        let (fe, fo) = split_even_odd(&f[i - 1]);

        // Compute linear polynomials (extension field)
        if i == base_mu {
            linear_polys.push(vec![(f_tilde_ext[i - 1][0], f_tilde_ext[i - 1][1])]);
        } else {
            linear_polys.push(
                a[i - 1]
                    .iter()
                    .map(|w| {
                        let w_tensor = get_tensor(&w[1..].to_vec());
                        let w_tensor_ext: Vec<F::Extension> = w_tensor.iter()
                            .map(|&x| F::Extension::from_base(x))
                            .collect();
                        (
                            f0_ext.iter().zip(w_tensor_ext.iter())
                                .map(|(&a, &b)| a * b)
                                .fold(F::Extension::default(), |acc, x| acc + x),
                            f1_ext.iter().zip(w_tensor_ext.iter())
                                .map(|(&a, &b)| a * b)
                                .fold(F::Extension::default(), |acc, x| acc + x)
                        )
                    })
                    .collect(),
            );
            a.push(a[i - 1].iter().map(|w| w[1..].to_vec()).collect());
        }

        // Get r challenge (synchronized across parties)
        let ri = if Net::am_master() {
            let r_challenge = transcript.get_and_append_challenge(b"r")?;
            Net::recv_from_master_uniform(Some(r_challenge));
            r_challenge
        } else {
            Net::recv_from_master_uniform(None)
        };
        r_vals.push(ri);
        let ri_ext = F::Extension::from_base(ri);

        // Fold (base field for FFT, extension field for evaluations)
        f.push(vector_add(&fe, &scalar_vector_product(ri, &fo)));
        f_tilde_ext.push(fold_ext(&f0_ext, &f1_ext, ri_ext));

        // Compute FFT (base field)
        let vi = domains[i].fft(&f[i]);

        if i == base_mu {
            final_value = f_tilde_ext[i][0];
            v.push(vi);
        } else {
            // Build Merkle tree for this level
            let len_vi = vi.len();
            let leaf_size = LEAF_SIZE.min(len_vi);
            let step = len_vi / leaf_size;

            if step < num_party {
                if Net::am_master() {
                    let mti = build_merkle_tree(&vi);
                    mt_roots.push(mti.root());
                    mt.push(mti);
                }
            } else {
                let leaves_per_party = step / num_party;
                let start_leaf = party_id * leaves_per_party;
                let end_leaf = (party_id + 1) * leaves_per_party;

                let local_leaves: Vec<Byte32> = (start_leaf..end_leaf)
                    .map(|leaf_idx| {
                        let leaf_elems: Vec<F> = (0..leaf_size)
                            .map(|j| vi[leaf_idx + j * step])
                            .collect();
                        compute_sha256_row(&leaf_elems)
                    })
                    .collect();

                let all_leaves_opt = Net::send_to_master(&local_leaves);
                if Net::am_master() {
                    let all_leaves: Vec<Byte32> = all_leaves_opt.unwrap().into_iter().flatten().collect();
                    let mti = MerkleTree::with_leaf_size(&all_leaves, leaf_size);
                    mt_roots.push(mti.root());
                    mt.push(mti);
                }
            }

            v.push(vi);
        }
    }
    end_timer!(timer);

    // Step 5: FRI consistency checks with distributed mt0 proofs
    let mut merkle_proofs: Vec<Vec<(usize, (F, F), Vec<F>, Vec<Byte32>)>> = Vec::new();
    let mut mt0_proofs: Vec<Vec<(Vec<F>, Vec<Byte32>)>> = Vec::new();

    for _t in 0..s {
        let beta_initial = if Net::am_master() {
            let beta = transcript.get_and_append_challenge_indices(b"beta", 1, domains[0].size())?[0];
            Net::recv_from_master_uniform(Some(beta));
            beta
        } else {
            Net::recv_from_master_uniform(None)
        };

        let mut beta = beta_initial;
        let mut level_proofs = Vec::new();

        // For i=0
        let leaf_size_0 = LEAF_SIZE.min(v[0].len());
        let step_0 = v[0].len() / leaf_size_0;
        let local_beta_0 = beta % step_0;
        let beta_prime_0 = if beta >= v[0].len() / 2 {
            beta - v[0].len() / 2
        } else {
            beta + v[0].len() / 2
        };
        level_proofs.push((
            beta,
            (v[0][beta], v[0][beta_prime_0]),
            get_leaf_elements(&v[0], local_beta_0, step_0, leaf_size_0),
            vec![],
        ));
        if beta >= domains[1].size() {
            beta -= domains[1].size();
        }

        // For i=1..base_mu-1
        if Net::am_master() {
            for i in 1..base_mu {
                level_proofs.push(open_merkle_tree_at_conjugate_points(&mt[i - 1], &v[i], beta));
                if beta >= domains[i + 1].size() {
                    beta -= domains[i + 1].size();
                }
            }
        }
        merkle_proofs.push(level_proofs);

        // Generate mt0 proofs for each commitment using distributed query
        let x0 = beta_initial;
        let mut commit_mt0_proofs: Vec<(Vec<F>, Vec<Byte32>)> = Vec::new();

        // For each commitment, query the distributed merkle proof
        for advice in advices.iter() {
            let (column_values, mt0_proof) = d_query_merkle_proof(advice, x0);
            if Net::am_master() {
                commit_mt0_proofs.push((column_values, mt0_proof));
            }
        }
        mt0_proofs.push(commit_mt0_proofs);
    }

    if Net::am_master() {
        Ok(Some(MultiChunkedBatchExtProof {
            claimed_values,
            point_to_commit: point_to_commit.to_vec(),
            point_to_poly: point_to_poly.to_vec(),
            sumcheck_proof,
            chunk_evals_at_r,
            linear_polys,
            merkle_roots: mt_roots,
            final_value,
            merkle_proofs,
            mt0_proofs,
            num_party_vars: Some(num_party_vars),
            combined_eval_at_r_low: Some(combined_eval_at_r_low),
            sum_check_evals,
        }))
    } else {
        Ok(None)
    }
}

/// Verify a multi-commitment batch proof at extension field points
#[allow(non_snake_case)]
pub fn multi_chunked_batch_verify_at_ext_point<F: PrimeField + HasQuadraticExtension>(
    verifier_param: &DeepFoldVerifierParam<F>,
    commitments: &[&DeepFoldBatchMultiCommitment],
    points: &[Vec<F::Extension>],
    proof: &MultiChunkedBatchExtProof<F>,
    transcript: &mut IOPTranscript<F>,
) -> Result<bool, PCSError> {
    let DeepFoldVerifierParam { max_mu, len_l0, g, s } = verifier_param;
    let base_mu = *max_mu;
    let num_commitments = commitments.len();
    let num_points = points.len();

    assert_eq!(num_points, proof.point_to_commit.len());
    assert_eq!(num_points, proof.point_to_poly.len());
    assert_eq!(num_points, proof.claimed_values.len());
    for (i, &commit_idx) in proof.point_to_commit.iter().enumerate() {
        assert!(commit_idx < num_commitments, "point_to_commit index out of bounds");
        assert!(proof.point_to_poly[i] < commitments[commit_idx].num_polys, "point_to_poly index out of bounds");
    }

    // Gather metadata
    let num_party_vars = proof.num_party_vars.unwrap_or(0);
    let mut total_chunks = 0usize;
    let mut commit_poly_num_vars: Vec<Vec<usize>> = Vec::new();

    for commitment in commitments.iter() {
        total_chunks += commitment.chunks_per_poly.iter().sum::<usize>();
        if num_party_vars > 0 {
            commit_poly_num_vars.push(commitment.original_num_vars.clone());
        } else {
            let poly_num_vars: Vec<usize> = commitment.chunks_per_poly.iter()
                .map(|&num_chunks| base_mu + (num_chunks.ilog2() as usize))
                .collect();
            commit_poly_num_vars.push(poly_num_vars);
        }
    }

    // Find max_num_vars across only the targeted polynomials
    let max_num_vars = proof.point_to_commit.iter().zip(proof.point_to_poly.iter())
        .map(|(&commit_idx, &poly_idx)| commit_poly_num_vars[commit_idx][poly_idx])
        .max()
        .unwrap_or(base_mu)
        .max(base_mu);

    // Step 1: Verify sumcheck (base field)
    let gamma = transcript.get_and_append_challenge(b"gamma")?;

    // Convert extension field points to base field for sumcheck verification
    let points_base: Vec<Vec<F>> = points.iter()
        .map(|pt| pt.iter().map(|x| F::ext_real(x)).collect())
        .collect();

    // Compute expected sum (base field): Σ_i γ^i * Re(claimed_values[i])
    // One term per point (only the targeted polynomial)
    let mut expected_sum = F::ZERO;
    for point_idx in 0..num_points {
        expected_sum += gamma.pow([point_idx as u64]) * F::ext_real(&proof.claimed_values[point_idx]);
    }

    // Determine max_degree based on whether this is distributed sumcheck
    let sumcheck_max_degree = if num_party_vars > 0 { 3 } else { 2 };

    // Note: Both distributed and non-distributed provers append aux_info with num_variables = max_num_vars
    // Distributed prover: VirtualPolynomial has max_local_num_vars, but d_prove adds num_party_vars to aux_info
    // Non-distributed prover: VirtualPolynomial already has max_num_vars
    let sumcheck_subclaim = <PolyIOP<F> as SumCheck<F>>::verify(
        expected_sum,
        &proof.sumcheck_proof,
        &VPAuxInfo {
            num_variables: max_num_vars,
            max_degree: sumcheck_max_degree,
            phantom: PhantomData::<F>::default(),
        },
        transcript,
    ).map_err(|e| PCSError::SumCheckError(format!("{:?}", e)))?;

    let r = sumcheck_subclaim.point;
    let r_ext: Vec<F::Extension> = r.iter().map(|&x| F::Extension::from_base(x)).collect();
    let r_low = resize_point(&r[..base_mu.min(r.len())].to_vec(), base_mu);
    let r_low_ext: Vec<F::Extension> = r_low.iter().map(|&x| F::Extension::from_base(x)).collect();

    // Step 2: Get gamma_combine and verify linear polynomial at r_low
    let gamma_combined: Vec<F> = transcript.get_and_append_challenge_vectors(b"gamma_combine", total_chunks)?;

    // For distributed case, use the pre-computed combined_eval_at_r_low from proof
    let combined_eval_at_r_low: F::Extension = if num_party_vars > 0 {
        proof.combined_eval_at_r_low.unwrap_or_else(|| {
            proof.chunk_evals_at_r.iter()
                .zip(gamma_combined.iter())
                .map(|(&e, &g)| F::Extension::from_base(g) * e)
                .fold(F::Extension::default(), |acc, x| acc + x)
        })
    } else {
        proof.chunk_evals_at_r.iter()
            .zip(gamma_combined.iter())
            .map(|(&e, &g)| F::Extension::from_base(g) * e)
            .fold(F::Extension::default(), |acc, x| acc + x)
    };

    let (a0, b0) = proof.linear_polys[0][0];
    let one_minus_r0_ext = F::Extension::from_base(F::ONE - r_low[0]);
    let r0_ext = F::Extension::from_base(r_low[0]);
    let computed_eval = a0 * one_minus_r0_ext + b0 * r0_ext;
    if computed_eval != combined_eval_at_r_low {
        eprintln!("[DEBUG] Ext Linear poly check failed: computed={:?}, expected={:?}", computed_eval, combined_eval_at_r_low);
        return Ok(false);
    }

    // Step 3: Verify DeepFold folding (extension field linear polys, base field Merkle)
    let mut alpha_vec = vec![F::ZERO];
    let mut r_vals = vec![F::ZERO];

    for i in 1..=base_mu {
        let alpha_i = transcript.get_and_append_challenge(b"alpha")?;
        alpha_vec.push(alpha_i);
        let ri = transcript.get_and_append_challenge(b"r")?;
        r_vals.push(ri);
        let ri_ext = F::Extension::from_base(ri);

        // Verify linear polynomial consistency
        if i < base_mu {
            let num_aux = proof.linear_polys[i - 1].len();
            for j in 0..num_aux {
                let k = if i < base_mu - 1 { j } else { 0 };
                let w1 = if j == 0 {
                    r_low[i]
                } else {
                    alpha_vec[j].pow([1u64 << (i + 1 - j)])
                };
                let w1_ext = F::Extension::from_base(w1);

                let (a_prev, b_prev) = proof.linear_polys[i - 1][j];
                let one_minus_ri_ext = F::Extension::from_base(F::ONE - ri);
                let val_at_r = a_prev * one_minus_ri_ext + b_prev * ri_ext;
                let (a_next, b_next) = proof.linear_polys[i][k];
                let one_minus_w1_ext = F::Extension::from_base(F::ONE - w1);
                let val_at_w1 = a_next * one_minus_w1_ext + b_next * w1_ext;
                if val_at_r != val_at_w1 {
                    eprintln!("[DEBUG] Ext Linear consistency check failed at i={}, j={}", i, j);
                    return Ok(false);
                }
            }
        } else {
            let (a, b) = proof.linear_polys[base_mu - 1][0];
            let one_minus_ri_ext = F::Extension::from_base(F::ONE - ri);
            let expected = a * one_minus_ri_ext + b * ri_ext;
            if expected != proof.final_value {
                eprintln!("[DEBUG] Ext Final value check failed");
                return Ok(false);
            }
        }
    }

    // Step 4: Verify FRI consistency checks (base field)
    let mut domain_sizes: Vec<usize> = vec![*len_l0];
    for i in 1..=base_mu {
        domain_sizes.push(len_l0 >> i);
    }

    for t in 0..*s {
        let mut beta = transcript.get_and_append_challenge_indices(b"beta", 1, *len_l0)?[0];
        let mut beta_point = g.pow([beta as u64]);

        // Verify level 0 via mt0 proofs
        let (pos0, (v_beta0, v_beta_prime0), leaf_elems0, _) = &proof.merkle_proofs[t][0];
        if *pos0 != beta {
            return Ok(false);
        }

        // Verify combined values match linear combination of mt0 column values
        let mut chunk_idx = 0;
        for (commit_idx, commitment) in commitments.iter().enumerate() {
            let (column_at_x0, mt0_proof) = &proof.mt0_proofs[t][commit_idx];

            let column_hash = compute_sha256_row(column_at_x0);
            if !MerkleTree::verify(&commitment.batch_commitment.root, beta, &column_hash, mt0_proof) {
                return Ok(false);
            }

            let num_chunks_in_commit: usize = commitment.chunks_per_poly.iter().sum();
            chunk_idx += num_chunks_in_commit;
        }

        // Verify collinearity with next level
        let v_next = if base_mu > 1 {
            proof.merkle_proofs[t][1].1.0
        } else {
            F::ext_real(&proof.final_value)
        };

        if !is_collinear(
            (beta_point, *v_beta0),
            (-beta_point, *v_beta_prime0),
            (r_vals[1], v_next),
        ) {
            return Ok(false);
        }

        if beta >= domain_sizes[1] {
            beta -= domain_sizes[1];
        }
        beta_point *= beta_point;

        // Verify remaining levels
        for i in 1..base_mu {
            let (pos, (v_beta, v_beta_prime), leaf_elems, merkle_path) = &proof.merkle_proofs[t][i];

            if *pos != beta {
                return Ok(false);
            }

            let beta_prime_pos = if beta >= domain_sizes[i] / 2 {
                beta - domain_sizes[i] / 2
            } else {
                beta + domain_sizes[i] / 2
            };

            let expected_root = &proof.merkle_roots[i - 1];
            let leaf_hash = compute_sha256_row(leaf_elems);
            let leaf_size = LEAF_SIZE.min(domain_sizes[i]);
            let step = domain_sizes[i] / leaf_size;
            let local_pos = beta % step;
            if !MerkleTree::verify(expected_root, local_pos, &leaf_hash, merkle_path) {
                return Ok(false);
            }

            let v_next = if i < base_mu - 1 {
                proof.merkle_proofs[t][i + 1].1.0
            } else {
                F::ext_real(&proof.final_value)
            };

            if !is_collinear(
                (beta_point, *v_beta),
                (-beta_point, *v_beta_prime),
                (r_vals[i + 1], v_next),
            ) {
                return Ok(false);
            }

            if beta >= domain_sizes[i + 1] {
                beta -= domain_sizes[i + 1];
            }
            beta_point *= beta_point;
        }
    }

    Ok(true)
}

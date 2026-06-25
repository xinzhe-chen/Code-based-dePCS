//! DeepFold commit functions
//!
//! This module contains the commit implementations for DeepFold PCS:
//! - `deepfold_commit`: Standard commit
//! - `deepfold_d_commit`: Distributed commit (original)
//! - `deepfold_d_commit_v2`: New distributed commit with column-based distribution

use crate::{errors::PCSError, hash::*, utils::*};
use ark_ff::PrimeField;
use ark_poly::{EvaluationDomain, GeneralEvaluationDomain};
use ark_std::{end_timer, start_timer, sync::Arc, vec::Vec};
use deNetwork::{DeMultiNet as Net, DeNet, DeSerNet};

use super::{
    DeepFoldCommitment, DeepFoldProverCommitmentAdvice, DeepFoldProverParam,
    utils::{build_merkle_tree, compute_leaf_hashes},
};

/// Standard DeepFold commit
pub fn deepfold_commit<F: PrimeField>(
    prover_param: &DeepFoldProverParam<F>,
    poly: &Arc<ark_poly::DenseMultilinearExtension<F>>,
) -> Result<(DeepFoldCommitment, DeepFoldProverCommitmentAdvice<F>), PCSError> {
    let DeepFoldProverParam { max_mu, l0, s: _ } = prover_param;
    let mu = poly.num_vars;
    assert!(mu <= *max_mu);

    let f0 = evals_to_coeffs(mu, &poly.evaluations);
    let v0 = l0.fft(&f0);

    let mt0 = build_merkle_tree(&v0);

    let rt0 = mt0.root();
    Ok((
        DeepFoldCommitment { mu, rt0 },
        DeepFoldProverCommitmentAdvice {
            f0,
            mt0,
            v0,
            f_tilde: poly.evaluations.clone(),
            upper_tree: None,
        },
    ))
}

/// Distributed commit: each party has local polynomial evaluations
/// Each party builds local subtree, master builds upper tree from collected roots
/// Returns (Option<Commitment>, Advice) - commitment is Some only for master
pub fn deepfold_d_commit<F: PrimeField>(
    prover_param: &DeepFoldProverParam<F>,
    poly: &Arc<ark_poly::DenseMultilinearExtension<F>>,
) -> Result<(Option<DeepFoldCommitment>, DeepFoldProverCommitmentAdvice<F>), PCSError> {
    let DeepFoldProverParam { max_mu, l0, s: _ } = prover_param;
    let num_party = Net::n_parties();
    let num_party_vars = num_party.ilog2() as usize;

    // Each party has local evaluations of size 2^local_mu
    let local_mu = poly.num_vars;
    let mu = local_mu + num_party_vars;
    assert!(mu <= *max_mu);

    // Step 1: Gather all evaluations to master
    let all_evals_opt = Net::send_to_master(&poly.evaluations);

    // Step 2: Master computes full f0, v0
    let (f0, v0, f_tilde): (Vec<F>, Vec<F>, Vec<F>) = if Net::am_master() {
        let all_evals: Vec<Vec<F>> = all_evals_opt.unwrap();
        let full_evals: Vec<F> = all_evals.into_iter().flatten().collect();

        // Compute full coefficients and FFT
        let timer = start_timer!(|| "DDeepFold.Commit.FFT");
        let f0 = evals_to_coeffs(mu, &full_evals);
        let v0 = l0.fft(&f0);
        end_timer!(timer);

        (f0, v0, full_evals)
    } else {
        (vec![], vec![], vec![])
    };

    // Step 3: Master distributes v0 data to workers for parallel leaf hash computation
    // Leaf structure: leaf i contains v0[i], v0[i+step], ..., v0[i+(leaf_size-1)*step]
    // where step = v0.len() / leaf_size
    // We distribute so each worker computes a contiguous range of leaves
    let (local_v0_data, leaf_size, leaves_per_party): (Vec<F>, usize, usize) = if Net::am_master() {
        use super::utils::LEAF_SIZE;
        let leaf_size = LEAF_SIZE.min(v0.len());
        let step = v0.len() / leaf_size;  // number of leaves
        let leaves_per_party = step / num_party;

        // Reorganize v0 for distribution: for each worker, collect the elements needed for their leaves
        // Worker k computes leaves [k*leaves_per_party, (k+1)*leaves_per_party)
        // For leaf i, elements are at positions: i, i+step, i+2*step, ..., i+(leaf_size-1)*step
        let v0_chunks: Vec<Vec<F>> = (0..num_party)
            .map(|k| {
                let start_leaf = k * leaves_per_party;
                let end_leaf = (k + 1) * leaves_per_party;
                // Collect elements for this worker's leaves
                let mut chunk = Vec::with_capacity(leaves_per_party * leaf_size);
                for leaf_idx in start_leaf..end_leaf {
                    for j in 0..leaf_size {
                        chunk.push(v0[leaf_idx + j * step]);
                    }
                }
                chunk
            })
            .collect();

        let local_data: Vec<F> = Net::recv_from_master(Some(v0_chunks));
        Net::recv_from_master_uniform(Some((leaf_size, leaves_per_party)));
        (local_data, leaf_size, leaves_per_party)
    } else {
        let local_data: Vec<F> = Net::recv_from_master(None);
        let (leaf_size, leaves_per_party): (usize, usize) = Net::recv_from_master_uniform(None);
        (local_data, leaf_size, leaves_per_party)
    };

    // Step 4: Each party computes leaf hashes and builds local subtree
    let timer = start_timer!(|| "DDeepFold.Commit.LeafHash");
    // Compute leaf hashes from local v0 data (already organized by leaves)
    let local_leaves: Vec<Byte32> = (0..leaves_per_party)
        .map(|i| {
            let leaf: Vec<F> = (0..leaf_size)
                .map(|j| local_v0_data[i * leaf_size + j])
                .collect();
            compute_sha256_row(&leaf)
        })
        .collect();
    end_timer!(timer);

    let timer = start_timer!(|| "DDeepFold.Commit.Merkle");
    let local_mt0 = MerkleTree::with_leaf_size(&local_leaves, leaf_size);
    let local_root = local_mt0.root();
    // Gather all local roots to master to build upper tree
    let all_roots_opt = Net::send_to_master(&local_root);
    end_timer!(timer);

    if Net::am_master() {
        let all_roots: Vec<Byte32> = all_roots_opt.unwrap();

        // Build upper tree from all party roots
        let upper_tree = MerkleTree::with_leaf_size(&all_roots, leaf_size);
        let rt0 = upper_tree.root();

        Ok((
            Some(DeepFoldCommitment { mu, rt0 }),
            DeepFoldProverCommitmentAdvice {
                f0,
                mt0: local_mt0,
                v0,
                f_tilde,
                upper_tree: Some(upper_tree),
            },
        ))
    } else {
        Ok((
            None,
            DeepFoldProverCommitmentAdvice {
                f0: vec![],
                mt0: local_mt0,
                v0: vec![],
                f_tilde: vec![],
                upper_tree: None,
            },
        ))
    }
}

/// New distributed commit protocol (v2):
/// 1. Workers send their data to master
/// 2. Master computes RS code (FFT)
/// 3. Master distributes RS columns to workers
/// 4. Each party computes column hashes
/// 5. Run distributed merkle tree
///
/// Column-based distribution:
/// - RS codeword v0 is organized as matrix: num_leaves rows × leaf_size columns
/// - Each party gets leaf_size / num_party columns
/// - Each column (containing num_leaves elements) is hashed to produce a leaf
/// - Distributed merkle tree is built from all leaf hashes
pub fn deepfold_d_commit_v2<F: PrimeField>(
    prover_param: &DeepFoldProverParam<F>,
    poly: &Arc<ark_poly::DenseMultilinearExtension<F>>,
) -> Result<(Option<DeepFoldCommitment>, DeepFoldProverCommitmentAdvice<F>), PCSError> {
    let DeepFoldProverParam { max_mu, l0, s: _ } = prover_param;
    let num_party = Net::n_parties();
    let num_party_vars = num_party.ilog2() as usize;

    // Each party has local evaluations of size 2^local_mu
    let local_mu = poly.num_vars;
    let mu = local_mu + num_party_vars;
    assert!(mu <= *max_mu);

    // Step 1: Gather all evaluations to master
    let timer = start_timer!(|| "DDeepFold.CommitV2.Gather");
    let all_evals_opt = Net::send_to_master(&poly.evaluations);
    end_timer!(timer);

    // Step 2: Master computes full f0, v0 (RS code via FFT)
    let (f0, v0, f_tilde): (Vec<F>, Vec<F>, Vec<F>) = if Net::am_master() {
        let all_evals: Vec<Vec<F>> = all_evals_opt.unwrap();
        let full_evals: Vec<F> = all_evals.into_iter().flatten().collect();

        let timer = start_timer!(|| "DDeepFold.CommitV2.FFT");
        let f0 = evals_to_coeffs(mu, &full_evals);
        let v0 = l0.fft(&f0);
        end_timer!(timer);

        (f0, v0, full_evals)
    } else {
        (vec![], vec![], vec![])
    };

    // Step 3: Master distributes columns to workers
    // Matrix organization:
    // - v0 has len_rs = l0.size() elements
    // - Organize as: num_leaves rows × leaf_size columns
    // - Where num_leaves = len_rs / leaf_size
    // - Column j contains: v0[j], v0[j + leaf_size], v0[j + 2*leaf_size], ...
    // - Each party gets leaf_size / num_party columns
    let timer = start_timer!(|| "DDeepFold.CommitV2.DistCols");
    use super::utils::LEAF_SIZE;
    let len_rs = l0.size();
    let leaf_size = LEAF_SIZE.min(len_rs);
    let num_leaves = len_rs / leaf_size;
    let cols_per_party = leaf_size / num_party;

    // Distribute columns to parties
    // Party k gets columns [k * cols_per_party, (k+1) * cols_per_party)
    let (local_columns, local_v0_indices): (Vec<F>, Vec<usize>) = if Net::am_master() {
        let columns_for_parties: Vec<Vec<F>> = (0..num_party)
            .map(|k| {
                let start_col = k * cols_per_party;
                let end_col = (k + 1) * cols_per_party;
                let mut party_data = Vec::with_capacity(cols_per_party * num_leaves);
                for col in start_col..end_col {
                    for row in 0..num_leaves {
                        party_data.push(v0[col + row * leaf_size]);
                    }
                }
                party_data
            })
            .collect();
        let local_data: Vec<F> = Net::recv_from_master(Some(columns_for_parties));

        // Compute indices for master's columns
        let start_col = 0;
        let end_col = cols_per_party;
        let indices: Vec<usize> = (start_col..end_col)
            .flat_map(|col| (0..num_leaves).map(move |row| col + row * leaf_size))
            .collect();

        Net::recv_from_master_uniform(Some((leaf_size, num_leaves, cols_per_party)));
        (local_data, indices)
    } else {
        let local_data: Vec<F> = Net::recv_from_master(None);
        let (leaf_size_recv, num_leaves_recv, cols_per_party_recv): (usize, usize, usize) =
            Net::recv_from_master_uniform(None);

        // Compute indices for this party's columns
        let party_id = Net::party_id();
        let start_col = party_id * cols_per_party_recv;
        let indices: Vec<usize> = (start_col..start_col + cols_per_party_recv)
            .flat_map(|col| (0..num_leaves_recv).map(move |row| col + row * leaf_size_recv))
            .collect();

        (local_data, indices)
    };
    end_timer!(timer);

    // Step 4: Each party computes column hashes
    // Each column has num_leaves elements, hash to produce one leaf
    let timer = start_timer!(|| "DDeepFold.CommitV2.ColHash");
    let local_leaves: Vec<Byte32> = (0..cols_per_party)
        .map(|i| {
            let column: Vec<F> = (0..num_leaves)
                .map(|j| local_columns[i * num_leaves + j])
                .collect();
            compute_sha256_row(&column)
        })
        .collect();
    end_timer!(timer);

    // Step 5: Distributed merkle tree
    // Gather all local leaves to master and build tree
    let timer = start_timer!(|| "DDeepFold.CommitV2.Merkle");
    let all_leaves_opt = Net::send_to_master(&local_leaves);

    // Build local subtree for proof generation
    let local_mt0 = MerkleTree::with_leaf_size(&local_leaves, leaf_size);
    let local_root = local_mt0.root();

    // Gather roots for upper tree
    let all_roots_opt = Net::send_to_master(&local_root);
    end_timer!(timer);

    if Net::am_master() {
        // Build full leaf list and tree for verification data
        let all_leaves: Vec<Byte32> = all_leaves_opt.unwrap().into_iter().flatten().collect();
        let all_roots: Vec<Byte32> = all_roots_opt.unwrap();

        // Build upper tree from party roots
        let upper_tree = MerkleTree::with_leaf_size(&all_roots, leaf_size);
        let rt0 = upper_tree.root();

        Ok((
            Some(DeepFoldCommitment { mu, rt0 }),
            DeepFoldProverCommitmentAdvice {
                f0,
                mt0: local_mt0,
                v0,
                f_tilde,
                upper_tree: Some(upper_tree),
            },
        ))
    } else {
        Ok((
            None,
            DeepFoldProverCommitmentAdvice {
                f0: vec![],
                mt0: local_mt0,
                v0: local_columns, // Store local columns for proof generation
                f_tilde: vec![],
                upper_tree: None,
            },
        ))
    }
}

/// Batch distributed commit v2: commit multiple polynomials together
/// All polynomials are combined into a single RS codeword before distribution
pub fn deepfold_batch_d_commit_v2<F: PrimeField>(
    prover_param: &DeepFoldProverParam<F>,
    polys: &[Arc<ark_poly::DenseMultilinearExtension<F>>],
) -> Result<(Vec<Option<DeepFoldCommitment>>, Vec<DeepFoldProverCommitmentAdvice<F>>), PCSError> {
    // For now, commit each polynomial separately using v2 protocol
    // Future optimization: batch RS encoding and column distribution
    let mut commitments = Vec::with_capacity(polys.len());
    let mut advices = Vec::with_capacity(polys.len());

    for poly in polys {
        let (com, advice) = deepfold_d_commit_v2(prover_param, poly)?;
        commitments.push(com);
        advices.push(advice);
    }

    Ok((commitments, advices))
}

/// Distributed commit v2 for a polynomial that ALL parties already have
/// (e.g., mat_a from shared SRS)
///
/// Unlike d_commit_v2 which gathers local polynomials from workers,
/// this version assumes all parties have the full polynomial and only
/// master performs RS encoding, then distributes columns for merkle tree.
pub fn deepfold_d_commit_full_poly_v2<F: PrimeField>(
    prover_param: &DeepFoldProverParam<F>,
    poly: &Arc<ark_poly::DenseMultilinearExtension<F>>,
) -> Result<(Option<DeepFoldCommitment>, DeepFoldProverCommitmentAdvice<F>), PCSError> {
    let DeepFoldProverParam { max_mu, l0, s: _ } = prover_param;
    let num_party = Net::n_parties();

    let mu = poly.num_vars;
    assert!(mu <= *max_mu);

    // Step 1: Master computes RS code (all parties have full poly, but only master does FFT)
    let (f0, v0): (Vec<F>, Vec<F>) = if Net::am_master() {
        let timer = start_timer!(|| "DDeepFold.CommitFullPoly.FFT");
        let f0 = evals_to_coeffs(mu, &poly.evaluations);
        let v0 = l0.fft(&f0);
        end_timer!(timer);
        (f0, v0)
    } else {
        (vec![], vec![])
    };

    // Step 2: Master distributes columns to workers
    use super::utils::LEAF_SIZE;
    let len_rs = l0.size();
    let leaf_size = LEAF_SIZE.min(len_rs);
    let num_leaves = len_rs / leaf_size;
    let cols_per_party = leaf_size / num_party;

    let timer = start_timer!(|| "DDeepFold.CommitFullPoly.DistCols");
    let local_columns: Vec<F> = if Net::am_master() {
        let columns_for_parties: Vec<Vec<F>> = (0..num_party)
            .map(|k| {
                let start_col = k * cols_per_party;
                let end_col = (k + 1) * cols_per_party;
                let mut party_data = Vec::with_capacity(cols_per_party * num_leaves);
                for col in start_col..end_col {
                    for row in 0..num_leaves {
                        party_data.push(v0[col + row * leaf_size]);
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

    // Step 3: Each party computes column hashes
    let timer = start_timer!(|| "DDeepFold.CommitFullPoly.ColHash");
    let local_leaves: Vec<Byte32> = (0..cols_per_party)
        .map(|i| {
            let column: Vec<F> = (0..num_leaves)
                .map(|j| local_columns[i * num_leaves + j])
                .collect();
            compute_sha256_row(&column)
        })
        .collect();
    end_timer!(timer);

    // Step 4: Distributed merkle tree
    let timer = start_timer!(|| "DDeepFold.CommitFullPoly.Merkle");
    let local_mt0 = MerkleTree::with_leaf_size(&local_leaves, leaf_size);
    let local_root = local_mt0.root();
    let all_roots_opt = Net::send_to_master(&local_root);
    end_timer!(timer);

    if Net::am_master() {
        let all_roots: Vec<Byte32> = all_roots_opt.unwrap();
        let upper_tree = MerkleTree::with_leaf_size(&all_roots, leaf_size);
        let rt0 = upper_tree.root();

        Ok((
            Some(DeepFoldCommitment { mu, rt0 }),
            DeepFoldProverCommitmentAdvice {
                f0,
                mt0: local_mt0,
                v0,
                f_tilde: poly.evaluations.clone(),
                upper_tree: Some(upper_tree),
            },
        ))
    } else {
        Ok((
            None,
            DeepFoldProverCommitmentAdvice {
                f0: vec![],
                mt0: local_mt0,
                v0: local_columns,
                f_tilde: vec![],
                upper_tree: None,
            },
        ))
    }
}

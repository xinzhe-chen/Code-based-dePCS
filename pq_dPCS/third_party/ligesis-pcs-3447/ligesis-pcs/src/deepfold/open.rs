//! DeepFold open functions
//!
//! This module contains the open implementations for DeepFold PCS:
//! - `deepfold_open`: Standard open
//! - `deepfold_d_open`: Distributed open
//! - `deepfold_batch_open`: Batched open
//! - `deepfold_d_batch_open`: Distributed batched open

use crate::{
    errors::PCSError, hash::*, utils::*,
    IOPProof, PolyIOP,
    sumcheck::SumCheck,
};
use arithmetic::VirtualPolynomial;
use ark_ff::PrimeField;
use ark_poly::{DenseMultilinearExtension, EvaluationDomain, GeneralEvaluationDomain};
use ark_std::{end_timer, start_timer, sync::Arc, vec::Vec};
use deNetwork::{DeMultiNet as Net, DeNet, DeSerNet};
use transcript::IOPTranscript;

use super::{
    DeepFoldBatchedProof, DeepFoldProof, DeepFoldProverCommitmentAdvice, DeepFoldProverParam,
    utils::{build_merkle_tree, compute_leaf_hashes, get_leaf_elements,
            open_merkle_tree_at_conjugate_points, LEAF_SIZE},
};

/// Standard DeepFold open
#[allow(non_snake_case)]
pub fn deepfold_open<F: PrimeField>(
    prover_param: &DeepFoldProverParam<F>,
    poly: &Arc<DenseMultilinearExtension<F>>,
    advice: &DeepFoldProverCommitmentAdvice<F>,
    point: &[F],
    transcript: &mut IOPTranscript<F>,
) -> Result<DeepFoldProof<F>, PCSError> {
    let DeepFoldProverParam { max_mu, l0, s } = prover_param.clone();

    let mu = poly.num_vars;

    assert!(mu <= max_mu);

    let DeepFoldProverCommitmentAdvice { f0, mt0, v0, f_tilde: _, upper_tree: _ } = advice.clone();
    let mut a = vec![Vec::new()];
    let mut f_tilde = vec![poly.evaluations.clone()];
    let mut f = vec![f0];
    let mut alpha = vec![F::ZERO];
    let mut linear_polys = Vec::new();
    let mut l = vec![l0];
    l.append(
        &mut (1..mu + 1)
            .map(|i| GeneralEvaluationDomain::<F>::new(l0.size() >> i).unwrap())
            .collect::<Vec<_>>(),
    );
    let mut v = vec![v0];
    let mut mt_roots = vec![mt0.root().clone()];
    let mut mt = vec![mt0];
    let mut mt_proofs = Vec::new();
    let mut f_mu = F::ZERO;
    let mut r = vec![F::ZERO];

    // Step 1
    a[0].push(point.to_vec());

    // Step 2
    for i in 1..mu + 1 {
        // Step 2.a
        alpha.push(transcript.get_and_append_challenge(b"alpha")?);
        a[i - 1].push(get_alpha_powers::<F>(alpha[i], mu - i + 1));
        let (f0_split, f1) = split_even_odd(&f_tilde[i - 1]);
        let (fe, fo) = split_even_odd(&f[i - 1]);
        // Step 2.b
        if i == mu {
            linear_polys.push(vec![(f_tilde[i - 1][0], f_tilde[i - 1][1])]);
        } else {
            linear_polys.push(
                a[i - 1]
                    .iter()
                    .map(|w| {
                        assert!(!w.is_empty());
                        let w_tensor = get_tensor(&w[1..].to_vec());
                        (inner_product(&w_tensor, &f0_split), inner_product(&w_tensor, &f1))
                    })
                    .collect::<Vec<_>>(),
            );

            a.push(a[i - 1].iter().map(|w| w[1..].to_vec()).collect::<Vec<_>>());
        }
        // Step 2.c
        let ri = transcript.get_and_append_challenge(b"r")?;
        r.push(ri);
        // Step 2.d
        f.push(vector_add(&fe, &scalar_vector_product(ri, &fo)));
        f_tilde.push(vector_add(
            &scalar_vector_product(F::ONE - ri, &f0_split),
            &scalar_vector_product(ri, &f1),
        ));
        // Step 2.e
        v.push(l[i].fft(&f[i]));
        if i == mu {
            f_mu = v[i][0];
        } else {
            let mti = build_merkle_tree(&v[i]);
            mt_roots.push(mti.root().clone());
            mt.push(mti);
        }
    }
    // Step 4
    for t in 0..s {
        // Step 4.a
        let mut beta = transcript.get_and_append_challenge_indices(b"beta", 1, l[0].size())?[0];
        // Step 4.b
        mt_proofs.push(Vec::new());
        for i in 0..mu {
            mt_proofs[t].push(open_merkle_tree_at_conjugate_points(&mt[i], &v[i], beta));
            if beta >= l[i + 1].size() {
                beta -= l[i + 1].size();
            }
        }
    }
    Ok(DeepFoldProof {
        linear_polys,
        mt_roots,
        f_mu,
        mt_proofs,
    })
}

/// Distributed DeepFold open
#[allow(non_snake_case)]
pub fn deepfold_d_open<F: PrimeField>(
    prover_param: &DeepFoldProverParam<F>,
    poly: &Arc<DenseMultilinearExtension<F>>,
    advice: &DeepFoldProverCommitmentAdvice<F>,
    point: &[F],
    transcript: &mut IOPTranscript<F>,
) -> Result<Option<DeepFoldProof<F>>, PCSError> {
    let DeepFoldProverParam { max_mu, l0, s } = prover_param.clone();
    let num_party = Net::n_parties();
    let num_party_vars = num_party.ilog2() as usize;

    // Each party has local evaluations of size 2^local_mu
    let local_mu = poly.num_vars;
    let mu = local_mu + num_party_vars;
    assert!(mu <= max_mu);

    // Initialize structures - use f0, v0, mt0, f_tilde, upper_tree from advice (computed in d_commit)
    let DeepFoldProverCommitmentAdvice { f0, mt0, v0, f_tilde: advice_f_tilde, upper_tree } = advice.clone();
    let mut l = vec![l0];
    l.append(
        &mut (1..mu + 1)
            .map(|i| GeneralEvaluationDomain::<F>::new(l0.size() >> i).unwrap())
            .collect::<Vec<_>>(),
    );

    let timer = start_timer!(|| "DDeepFold.Open.Folding");

    // Each party stores local subtrees, master also stores upper trees
    let mut local_mts: Vec<MerkleTree> = vec![mt0.clone()];
    let mut upper_mts: Vec<Option<MerkleTree>> = vec![upper_tree.clone()];
    let mut is_distributed: Vec<bool> = vec![true]; // Track which rounds use distributed Merkle
    let mut mt_roots: Vec<Byte32> = vec![];

    // Get mt_roots[0] from upper_tree (master) or placeholder (workers)
    if Net::am_master() {
        mt_roots.push(upper_tree.as_ref().unwrap().root());
    } else {
        mt_roots.push(Byte32::default());
    }

    // Master-only data for polynomial computation
    let mut a = vec![Vec::new()];
    let mut f_tilde: Vec<Vec<F>> = if Net::am_master() {
        vec![advice_f_tilde]  // Use f_tilde from advice (computed in d_commit)
    } else {
        Vec::new()
    };
    let mut f = vec![f0.clone()];
    let mut alpha = vec![F::ZERO];
    let mut linear_polys = Vec::new();
    let mut v = vec![v0.clone()];
    let mut f_mu = F::ZERO;
    let mut r = vec![F::ZERO];

    // Step 1
    a[0].push(point.to_vec());

    // Step 2: Main loop - all parties participate in building distributed Merkle trees
    for i in 1..mu + 1 {
        // Step 2.a: Get alpha challenge - master generates and broadcasts to workers
        let alpha_i = if Net::am_master() {
            let a = transcript.get_and_append_challenge(b"alpha")?;
            Net::recv_from_master_uniform(Some(a));
            a
        } else {
            Net::recv_from_master_uniform(None)
        };
        alpha.push(alpha_i);

        if Net::am_master() {
            a[i - 1].push(get_alpha_powers::<F>(alpha[i], mu - i + 1));
            let (f0_split, f1) = split_even_odd(&f_tilde[i - 1]);
            let (fe, fo) = split_even_odd(&f[i - 1]);

            // Step 2.b: Compute linear_polys (master only)
            if i == mu {
                linear_polys.push(vec![(f_tilde[i - 1][0], f_tilde[i - 1][1])]);
            } else {
                linear_polys.push(
                    a[i - 1]
                        .iter()
                        .map(|w| {
                            assert!(!w.is_empty());
                            let w_tensor = get_tensor(&w[1..].to_vec());
                            (inner_product(&w_tensor, &f0_split), inner_product(&w_tensor, &f1))
                        })
                        .collect::<Vec<_>>(),
                );
                a.push(a[i - 1].iter().map(|w| w[1..].to_vec()).collect::<Vec<_>>());
            }

            // Step 2.c: Get r challenge - master generates and broadcasts to workers
            let ri = transcript.get_and_append_challenge(b"r")?;
            Net::recv_from_master_uniform(Some(ri));

            // Step 2.d: Compute f[i] and f_tilde[i]
            r.push(ri);
            f.push(vector_add(&fe, &scalar_vector_product(ri, &fo)));
            f_tilde.push(vector_add(
                &scalar_vector_product(F::ONE - ri, &f0_split),
                &scalar_vector_product(ri, &f1),
            ));

            // Step 2.e: Compute v[i] = FFT(f[i])
            let vi = l[i].fft(&f[i]);
            v.push(vi.clone());

            if i == mu {
                f_mu = v[i][0];
            } else {
                // Check if we can use distributed Merkle tree
                let (all_leaves, leaf_size) = compute_leaf_hashes(&vi);
                let can_distribute = all_leaves.len() >= num_party;

                // First broadcast can_distribute flag so workers know what to expect
                Net::recv_from_master_uniform(Some(can_distribute));

                if can_distribute {
                    // Distribute leaf hashes for distributed Merkle tree
                    let chunk_size = all_leaves.len() / num_party;
                    let leaf_chunks: Vec<Vec<Byte32>> = (0..num_party)
                        .map(|j| all_leaves[j * chunk_size..(j + 1) * chunk_size].to_vec())
                        .collect();

                    let local_leaves: Vec<Byte32> = Net::recv_from_master(Some(leaf_chunks));
                    Net::recv_from_master_uniform(Some(leaf_size));

                    // Build local Merkle tree
                    let local_mt = MerkleTree::with_leaf_size(&local_leaves, leaf_size);
                    let local_root = local_mt.root();
                    local_mts.push(local_mt);

                    // Gather local roots to build upper tree
                    let all_roots: Vec<Byte32> = Net::send_to_master(&local_root).unwrap();
                    let upper_tree = MerkleTree::with_leaf_size(&all_roots, leaf_size);
                    mt_roots.push(upper_tree.root());
                    upper_mts.push(Some(upper_tree));
                    is_distributed.push(true);
                } else {
                    // Too few leaves for distribution - master builds full tree alone
                    let full_mt = MerkleTree::with_leaf_size(&all_leaves, leaf_size);
                    mt_roots.push(full_mt.root());
                    local_mts.push(full_mt);
                    upper_mts.push(None);
                    is_distributed.push(false);
                }
            }
        } else {
            // Workers: receive r challenge from master
            let ri: F = Net::recv_from_master_uniform(None);
            r.push(ri);

            // Workers: participate in distributed Merkle tree construction
            if i != mu {
                // First receive can_distribute flag
                let can_distribute: bool = Net::recv_from_master_uniform(None);

                if can_distribute {
                    // Receive leaf hashes for distributed Merkle tree
                    let local_leaves: Vec<Byte32> = Net::recv_from_master(None);
                    let leaf_size: usize = Net::recv_from_master_uniform(None);

                    // Build local Merkle tree
                    let local_mt = MerkleTree::with_leaf_size(&local_leaves, leaf_size);
                    let local_root = local_mt.root();
                    local_mts.push(local_mt);

                    // Send local root to master
                    Net::send_to_master(&local_root);

                    // Workers don't have upper trees
                    upper_mts.push(None);
                    is_distributed.push(true);
                } else {
                    // Non-distributed mode: workers just push placeholders
                    local_mts.push(MerkleTree::default());
                    upper_mts.push(None);
                    is_distributed.push(false);
                }
            }
        }
    }
    end_timer!(timer);

    // Step 4: Generate merkle proofs
    let mut mt_proofs = Vec::new();
    for t in 0..s {
        // All parties need to participate in transcript to get beta
        let mut beta = if Net::am_master() {
            let b = transcript.get_and_append_challenge_indices(b"beta", 1, l[0].size())?[0];
            Net::recv_from_master_uniform(Some(b));
            b
        } else {
            Net::recv_from_master_uniform(None)
        };

        let mut proofs_for_t = Vec::new();
        for i in 0..mu {
            let vi_len = l[i].size();
            let leaf_size = local_mts[i].leaf_size();
            let step = vi_len / leaf_size;
            let local_beta = beta % step;

            if is_distributed[i] {
                // Use d_prove for distributed proof generation
                let proof_opt = MerkleTree::d_prove(local_beta, &local_mts[i], upper_mts[i].as_ref());

                if Net::am_master() {
                    let merkle_proof = proof_opt.unwrap();
                    let beta_prime = if beta >= vi_len / 2 {
                        beta - vi_len / 2
                    } else {
                        beta + vi_len / 2
                    };
                    let leaf_elements = get_leaf_elements(&v[i], local_beta, step, leaf_size);
                    proofs_for_t.push((beta, (v[i][beta], v[i][beta_prime]), leaf_elements, merkle_proof));
                }
            } else if Net::am_master() {
                // Non-distributed: master uses regular prove
                let merkle_proof = local_mts[i].prove(local_beta);
                let beta_prime = if beta >= vi_len / 2 {
                    beta - vi_len / 2
                } else {
                    beta + vi_len / 2
                };
                let leaf_elements = get_leaf_elements(&v[i], local_beta, step, leaf_size);
                proofs_for_t.push((beta, (v[i][beta], v[i][beta_prime]), leaf_elements, merkle_proof));
            }

            if beta >= l[i + 1].size() {
                beta -= l[i + 1].size();
            }
        }
        if Net::am_master() {
            mt_proofs.push(proofs_for_t);
        }
    }

    if Net::am_master() {
        Ok(Some(DeepFoldProof {
            linear_polys,
            mt_roots,
            f_mu,
            mt_proofs,
        }))
    } else {
        Ok(None)
    }
}

/// Batched DeepFold open
#[allow(non_snake_case)]
pub fn deepfold_batch_open<F: PrimeField>(
    prover_param: &DeepFoldProverParam<F>,
    polynomials: Vec<Arc<DenseMultilinearExtension<F>>>,
    advices: &[&DeepFoldProverCommitmentAdvice<F>],
    points: &[Vec<F>],
    transcript: &mut IOPTranscript<F>,
) -> Result<DeepFoldBatchedProof<F>, PCSError> {
    let DeepFoldProverParam { max_mu, l0, s } = prover_param.clone();
    let num_poly = polynomials.len();
    let mu = max_mu;
    assert!(polynomials.iter().all(|poly| poly.num_vars == mu));
    assert!(points.iter().all(|point| point.len() == mu));
    assert!(points.len() == num_poly && advices.len() == num_poly);
    let mt0_list = advices.iter().map(|advice| &advice.mt0).collect::<Vec<_>>();

    // SumCheck Phase
    let timer = start_timer!(|| "DeepFold.Sumcheck");
    let r = transcript.get_and_append_challenge(b"batched_sumcheck")?;
    let mut sum_check = VirtualPolynomial::new(max_mu);
    for i in 0..num_poly {
        sum_check
            .add_mle_list(
                [
                    evals_to_arcpoly(&polynomials[i].evaluations),
                    evals_to_arcpoly(&get_tensor(&points[i])),
                ],
                r.pow([i as u64]),
            )
            .map_err(|e| PCSError::VirtualPolynomialError(format!("{:?}", e)))?;
    }
    let sum_check_proof = <PolyIOP<F> as SumCheck<F>>::prove(sum_check, transcript)
        .map_err(|e| PCSError::SumCheckError(format!("{:?}", e)))?;
    let point = sum_check_proof.point.clone();
    let sum_check_evals = polynomials
        .iter()
        .map(|poly| eval_mle_poly(&poly.evaluations, &point))
        .collect::<Vec<_>>();
    end_timer!(timer);

    // Batched Open Phase - Compute combined polynomial WITHOUT building mt0
    let timer = start_timer!(|| "DeepFold.BatchedOpen");
    let gamma = transcript.get_and_append_challenge_vectors(b"gamma", num_poly)?;
    let poly_evals: Vec<F> = (0..1 << max_mu)
        .map(|i| {
            (0..num_poly)
                .map(|j| gamma[j] * polynomials[j].evaluations[i])
                .sum::<F>()
        })
        .collect();

    // Compute f0 and v0 for combined polynomial (needed for subsequent rounds)
    let f0 = evals_to_coeffs(mu, &poly_evals);
    let v0 = l0.fft(&f0);

    // Initialize structures - NO mt0 needed
    let mut a = vec![Vec::new()];
    let mut f_tilde = vec![poly_evals];
    let mut f = vec![f0];
    let mut alpha = vec![F::ZERO];
    let mut linear_polys = Vec::new();
    let mut l = vec![l0];
    l.append(
        &mut (1..mu + 1)
            .map(|i| GeneralEvaluationDomain::<F>::new(l0.size() >> i).unwrap())
            .collect::<Vec<_>>(),
    );
    let mut v = vec![v0];
    let mut mt_roots = Vec::new(); // Will be filled starting from round 1
    let mut mt = Vec::new();
    let mut f_mu = F::ZERO;
    let mut r_vals = vec![F::ZERO];

    // Step 1
    a[0].push(point.clone());

    // Step 2
    for i in 1..mu + 1 {
        // Step 2.a
        alpha.push(transcript.get_and_append_challenge(b"alpha")?);
        a[i - 1].push(get_alpha_powers::<F>(alpha[i], mu - i + 1));
        let (f0_split, f1) = split_even_odd(&f_tilde[i - 1]);
        let (fe, fo) = split_even_odd(&f[i - 1]);
        // Step 2.b
        if i == mu {
            linear_polys.push(vec![(f_tilde[i - 1][0], f_tilde[i - 1][1])]);
        } else {
            linear_polys.push(
                a[i - 1]
                    .iter()
                    .map(|w| {
                        assert!(!w.is_empty());
                        let w_tensor = get_tensor(&w[1..].to_vec());
                        (inner_product(&w_tensor, &f0_split), inner_product(&w_tensor, &f1))
                    })
                    .collect::<Vec<_>>(),
            );

            a.push(a[i - 1].iter().map(|w| w[1..].to_vec()).collect::<Vec<_>>());
        }
        // Step 2.c
        let ri = transcript.get_and_append_challenge(b"r")?;
        r_vals.push(ri);
        // Step 2.d
        f.push(vector_add(&fe, &scalar_vector_product(ri, &fo)));
        f_tilde.push(vector_add(
            &scalar_vector_product(F::ONE - ri, &f0_split),
            &scalar_vector_product(ri, &f1),
        ));
        // Step 2.e
        v.push(l[i].fft(&f[i]));
        if i == mu {
            f_mu = v[i][0];
        } else {
            // Build merkle trees starting from i=1 (skip mt0)
            let mti = build_merkle_tree(&v[i]);
            mt_roots.push(mti.root().clone());
            mt.push(mti);
        }
    }

    // Step 4: Generate merkle proofs (starting from index 1)
    let mut mt_proofs = Vec::new();
    for t in 0..s {
        let mut beta = transcript.get_and_append_challenge_indices(b"beta", 1, l[0].size())?[0];
        mt_proofs.push(Vec::new());

        // For i=0, just store the values without merkle proof (will be verified via linear combination)
        let leaf_size = LEAF_SIZE.min(v[0].len());
        let step = v[0].len() / leaf_size;
        let local_beta = beta % step;
        let beta_prime = if beta >= v[0].len() / 2 {
            beta - v[0].len() / 2
        } else {
            beta + v[0].len() / 2
        };
        mt_proofs[t].push((
            beta, // Store original position
            (v[0][beta], v[0][beta_prime]),
            get_leaf_elements(&v[0], local_beta, step, leaf_size),
            vec![], // No merkle path needed
        ));
        if beta >= l[1].size() {
            beta -= l[1].size();
        }

        // For i=1..mu-1, generate full merkle proofs
        for i in 1..mu {
            mt_proofs[t].push(open_merkle_tree_at_conjugate_points(&mt[i - 1], &v[i], beta));
            if beta >= l[i + 1].size() {
                beta -= l[i + 1].size();
            }
        }
    }
    end_timer!(timer);

    // Additional proofs for individual mt0s
    let timer = start_timer!(|| "DeepFold.Mt0Proofs");
    let mut mt_proofs_for_mt0 = Vec::new();
    let idx = (0..num_poly)
        .filter(|&i| (0..i).all(|j| polynomials[i] != polynomials[j]))
        .collect::<Vec<_>>();
    for t in 0..s {
        mt_proofs_for_mt0.push(Vec::new());
        let x0 = mt_proofs[t][0].0;

        for (_, &k) in idx.iter().enumerate() {
            let leaf_size = mt0_list[k].leaf_size();
            let step = l0.size() / leaf_size;
            let local_x0 = x0 % step;
            mt_proofs_for_mt0[t].push((
                get_leaf_elements(&advices[k].v0, local_x0, step, leaf_size),
                mt0_list[k].prove(local_x0),
            ));
        }
    }

    let evals = polynomials
        .iter()
        .zip(points.iter())
        .map(|(poly, point)| eval_mle_poly(&poly.evaluations, point))
        .collect::<Vec<_>>();
    end_timer!(timer);

    Ok(DeepFoldBatchedProof {
        deepfold_proof: DeepFoldProof {
            linear_polys,
            mt_roots,
            f_mu,
            mt_proofs,
        },
        sum_check_proof,
        mt_proofs_for_mt0,
        evals,
        sum_check_evals,
    })
}

/// Distributed batched DeepFold open
#[allow(non_snake_case)]
pub fn deepfold_d_batch_open<F: PrimeField>(
    prover_param: &DeepFoldProverParam<F>,
    polynomials: Vec<Arc<DenseMultilinearExtension<F>>>,
    advices: &[&DeepFoldProverCommitmentAdvice<F>],
    points: &[Vec<F>],
    transcript: &mut IOPTranscript<F>,
) -> Result<Option<DeepFoldBatchedProof<F>>, PCSError> {
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

    // Step 1: Gather all polynomial evaluations to master for SumCheck
    let timer = start_timer!(|| "DBatchOpen.GatherEvals");
    let all_poly_evals: Vec<Option<Vec<Vec<F>>>> = polynomials
        .iter()
        .map(|poly| Net::send_to_master(&poly.evaluations))
        .collect();
    end_timer!(timer);

    // Initialize structures for all parties
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
    let mut a = vec![Vec::new()];
    let mut f_tilde: Vec<Vec<F>> = Vec::new();
    let mut f: Vec<Vec<F>> = Vec::new();
    let mut alpha = vec![F::ZERO];
    let mut linear_polys = Vec::new();
    let mut v: Vec<Vec<F>> = Vec::new();
    let mut f_mu = F::ZERO;
    let mut sum_check_proof: Option<IOPProof<F>> = None;
    let mut sum_check_evals: Vec<F> = Vec::new();
    let mut point: Vec<F> = Vec::new();
    let mut gamma: Vec<F> = Vec::new();
    let mut full_poly_evals: Vec<Vec<F>> = Vec::new(); // Save for evals computation

    let timer = start_timer!(|| "DBatchOpen.Compute");
    if Net::am_master() {
        // Reconstruct full polynomials on master
        full_poly_evals = all_poly_evals
            .into_iter()
            .map(|evals_opt| {
                let all_evals: Vec<Vec<F>> = evals_opt.unwrap();
                all_evals.into_iter().flatten().collect()
            })
            .collect();

        // SumCheck Phase
        let r_batch = transcript.get_and_append_challenge(b"batched_sumcheck")?;
        let mut sum_check = VirtualPolynomial::new(mu);
        for i in 0..num_poly {
            sum_check
                .add_mle_list(
                    [
                        evals_to_arcpoly(&full_poly_evals[i]),
                        evals_to_arcpoly(&get_tensor(&points[i])),
                    ],
                    r_batch.pow([i as u64]),
                )
                .map_err(|e| PCSError::VirtualPolynomialError(format!("{:?}", e)))?;
        }
        let sc_proof = <PolyIOP<F> as SumCheck<F>>::prove(sum_check, transcript)
            .map_err(|e| PCSError::SumCheckError(format!("{:?}", e)))?;
        point = sc_proof.point.clone();
        sum_check_evals = full_poly_evals
            .iter()
            .map(|evals| eval_mle_poly(evals, &point))
            .collect();
        sum_check_proof = Some(sc_proof);

        // Batched Open Phase
        gamma = transcript.get_and_append_challenge_vectors(b"gamma", num_poly)?;
        let poly_evals: Vec<F> = (0..1 << mu)
            .map(|i| {
                (0..num_poly)
                    .map(|j| gamma[j] * full_poly_evals[j][i])
                    .sum::<F>()
            })
            .collect();

        // Compute f0 and v0 for combined polynomial
        let f0 = evals_to_coeffs(mu, &poly_evals);
        let v0 = l0.fft(&f0);

        f_tilde.push(poly_evals);
        f.push(f0);
        v.push(v0);
        a[0].push(point.clone());
    }

    // Step 2: Main loop - all parties participate in distributed Merkle tree
    for i in 1..mu + 1 {
        // Step 2.a: Get alpha challenge - master generates and broadcasts
        let alpha_i = if Net::am_master() {
            let a = transcript.get_and_append_challenge(b"alpha")?;
            Net::recv_from_master_uniform(Some(a));
            a
        } else {
            Net::recv_from_master_uniform(None)
        };
        alpha.push(alpha_i);

        if Net::am_master() {
            a[i - 1].push(get_alpha_powers::<F>(alpha[i], mu - i + 1));
            let (f0_split, f1) = split_even_odd(&f_tilde[i - 1]);
            let (fe, fo) = split_even_odd(&f[i - 1]);

            // Compute linear_polys
            if i == mu {
                linear_polys.push(vec![(f_tilde[i - 1][0], f_tilde[i - 1][1])]);
            } else {
                linear_polys.push(
                    a[i - 1]
                        .iter()
                        .map(|w| {
                            assert!(!w.is_empty());
                            let w_tensor = get_tensor(&w[1..].to_vec());
                            (inner_product(&w_tensor, &f0_split), inner_product(&w_tensor, &f1))
                        })
                        .collect::<Vec<_>>(),
                );
                a.push(a[i - 1].iter().map(|w| w[1..].to_vec()).collect::<Vec<_>>());
            }

            // Get r challenge - master generates and broadcasts
            let ri = transcript.get_and_append_challenge(b"r")?;
            Net::recv_from_master_uniform(Some(ri));
            r.push(ri);

            // Compute f[i] and f_tilde[i]
            f.push(vector_add(&fe, &scalar_vector_product(ri, &fo)));
            f_tilde.push(vector_add(
                &scalar_vector_product(F::ONE - ri, &f0_split),
                &scalar_vector_product(ri, &f1),
            ));

            // Compute v[i] = FFT(f[i])
            let vi = l[i].fft(&f[i]);
            v.push(vi.clone());

            if i == mu {
                f_mu = v[i][0];
            } else {
                // Check if we can use distributed Merkle tree
                let (all_leaves, leaf_size) = compute_leaf_hashes(&vi);
                let can_distribute = all_leaves.len() >= num_party;

                // First broadcast can_distribute flag
                Net::recv_from_master_uniform(Some(can_distribute));

                if can_distribute {
                    // Distribute leaf hashes for distributed Merkle tree
                    let chunk_size = all_leaves.len() / num_party;
                    let leaf_chunks: Vec<Vec<Byte32>> = (0..num_party)
                        .map(|j| all_leaves[j * chunk_size..(j + 1) * chunk_size].to_vec())
                        .collect();

                    let local_leaves: Vec<Byte32> = Net::recv_from_master(Some(leaf_chunks));
                    Net::recv_from_master_uniform(Some(leaf_size));

                    // Build local Merkle tree
                    let local_mt = MerkleTree::with_leaf_size(&local_leaves, leaf_size);
                    let local_root = local_mt.root();
                    local_mts.push(local_mt);

                    // Gather local roots to build upper tree
                    let all_roots: Vec<Byte32> = Net::send_to_master(&local_root).unwrap();
                    let upper_tree = MerkleTree::with_leaf_size(&all_roots, leaf_size);
                    mt_roots.push(upper_tree.root());
                    upper_mts.push(Some(upper_tree));
                    is_distributed.push(true);
                } else {
                    // Too few leaves for distribution - master builds full tree alone
                    let full_mt = MerkleTree::with_leaf_size(&all_leaves, leaf_size);
                    mt_roots.push(full_mt.root());
                    local_mts.push(full_mt);
                    upper_mts.push(None);
                    is_distributed.push(false);
                }
            }
        } else {
            // Workers: receive r challenge from master
            let ri: F = Net::recv_from_master_uniform(None);
            r.push(ri);

            // Workers: participate in distributed Merkle tree construction
            if i != mu {
                // First receive can_distribute flag
                let can_distribute: bool = Net::recv_from_master_uniform(None);

                if can_distribute {
                    // Receive leaf hashes for distributed Merkle tree
                    let local_leaves: Vec<Byte32> = Net::recv_from_master(None);
                    let leaf_size: usize = Net::recv_from_master_uniform(None);

                    // Build local Merkle tree
                    let local_mt = MerkleTree::with_leaf_size(&local_leaves, leaf_size);
                    let local_root = local_mt.root();
                    local_mts.push(local_mt);

                    // Send local root to master
                    Net::send_to_master(&local_root);

                    // Workers don't have upper trees
                    upper_mts.push(None);
                    is_distributed.push(true);
                } else {
                    // Non-distributed mode: workers just push placeholders
                    local_mts.push(MerkleTree::default());
                    upper_mts.push(None);
                    is_distributed.push(false);
                }
            }
        }
    }
    end_timer!(timer);

    // Step 4: Generate merkle proofs - all parties participate in d_prove
    let timer = start_timer!(|| "DBatchOpen.GenProofs");
    let mut mt_proofs = Vec::new();
    for t in 0..s {
        // All parties sync on beta challenge
        let mut beta = if Net::am_master() {
            let b = transcript.get_and_append_challenge_indices(b"beta", 1, l[0].size())?[0];
            Net::recv_from_master_uniform(Some(b));
            b
        } else {
            Net::recv_from_master_uniform(None)
        };

        let mut proofs_for_t = Vec::new();

        // For i=0, no merkle proof needed (handled by mt0 proofs)
        if Net::am_master() {
            let leaf_size = LEAF_SIZE.min(v[0].len());
            let step = v[0].len() / leaf_size;
            let local_beta = beta % step;
            let beta_prime = if beta >= v[0].len() / 2 {
                beta - v[0].len() / 2
            } else {
                beta + v[0].len() / 2
            };
            proofs_for_t.push((
                beta,
                (v[0][beta], v[0][beta_prime]),
                get_leaf_elements(&v[0], local_beta, step, leaf_size),
                vec![],
            ));
        }
        if beta >= l[1].size() {
            beta -= l[1].size();
        }

        // For i=1..mu, use distributed proof generation
        for i in 1..mu {
            let vi_len = l[i].size();
            let leaf_size = local_mts[i - 1].leaf_size();
            let step = vi_len / leaf_size;
            let local_beta = beta % step;

            if is_distributed[i - 1] {
                // Use d_prove for distributed proof generation
                let proof_opt = MerkleTree::d_prove(local_beta, &local_mts[i - 1], upper_mts[i - 1].as_ref());

                if Net::am_master() {
                    let merkle_proof = proof_opt.unwrap();
                    let beta_prime = if beta >= vi_len / 2 {
                        beta - vi_len / 2
                    } else {
                        beta + vi_len / 2
                    };
                    let leaf_elements = get_leaf_elements(&v[i], local_beta, step, leaf_size);
                    proofs_for_t.push((beta, (v[i][beta], v[i][beta_prime]), leaf_elements, merkle_proof));
                }
            } else if Net::am_master() {
                // Non-distributed: master uses regular prove
                let merkle_proof = local_mts[i - 1].prove(local_beta);
                let beta_prime = if beta >= vi_len / 2 {
                    beta - vi_len / 2
                } else {
                    beta + vi_len / 2
                };
                let leaf_elements = get_leaf_elements(&v[i], local_beta, step, leaf_size);
                proofs_for_t.push((beta, (v[i][beta], v[i][beta_prime]), leaf_elements, merkle_proof));
            }

            if beta >= l[i + 1].size() {
                beta -= l[i + 1].size();
            }
        }
        if Net::am_master() {
            mt_proofs.push(proofs_for_t);
        }
    }
    end_timer!(timer);

    // Additional proofs for individual mt0s - all parties participate in d_prove
    let timer = start_timer!(|| "DBatchOpen.Mt0Proofs");
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
    end_timer!(timer);

    // Non-master parties return after participating in all d_prove calls
    if !Net::am_master() {
        return Ok(None);
    }

    // Compute evals: evaluation of each polynomial at its corresponding point
    let evals: Vec<F> = full_poly_evals
        .iter()
        .zip(points.iter())
        .map(|(poly_evals, pt)| eval_mle_poly(poly_evals, pt))
        .collect();

    Ok(Some(DeepFoldBatchedProof {
        deepfold_proof: DeepFoldProof {
            linear_polys,
            mt_roots,
            f_mu,
            mt_proofs,
        },
        sum_check_proof: sum_check_proof.unwrap(),
        mt_proofs_for_mt0,
        evals,
        sum_check_evals,
    }))
}

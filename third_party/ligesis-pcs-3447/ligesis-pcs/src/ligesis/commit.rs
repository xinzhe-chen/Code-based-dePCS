//! Ligesis commit functions
//!
//! This module contains the commit implementations for Ligesis PCS:
//! - `ligesis_commit`: Standard commit
//! - `ligesis_d_commit`: Distributed commit

use crate::{
    deepfold::{chunked_batch_commit, d_chunked_batch_commit, *},
    errors::PCSError,
    rscode::*,
    utils::*,
    PolynomialCommitmentScheme,
};
use arithmetic::math::Math;
use ark_ff::PrimeField;
use ark_poly::DenseMultilinearExtension;
use ark_std::{end_timer, start_timer, sync::Arc, vec::Vec};

use deNetwork::{DeMultiNet as Net, DeNet, DeSerNet};

use super::{
    compute_sis_hash, LigeSISCommitment, LigeSISProverCommitmentAdvice, LigeSISProverParam,
};

/// Standard Ligesis commit
#[allow(non_snake_case)]
pub fn ligesis_commit<F: PrimeField>(
    prover_param: &LigeSISProverParam<F>,
    poly: &Arc<DenseMultilinearExtension<F>>,
) -> Result<(LigeSISCommitment<F>, LigeSISProverCommitmentAdvice<F>), PCSError> {
    let &LigeSISProverParam {
        eta,
        s_lambda: _,
        mu,
        log_m,
        log_n,
        c: _,
        ref rs,
        ref mat_a,
        ref mat_a_pad,
        ref mat_a_advice,
        ref deepfold_prover_param,
    } = prover_param;
    let _ = (mat_a_pad, mat_a_advice); // Suppress unused warnings
    let (m, n) = (1 << log_m, 1 << log_n);

    // Record original num_vars and pad if needed
    let num_vars = poly.num_vars;
    let poly_evals = if num_vars < mu {
        resize_eval(&poly.evaluations, mu)
    } else {
        poly.evaluations.clone()
    };
    let mat_f = reshape(&poly_evals, m, n);

    // encode `F`
    let timer = start_timer!(|| format!("Ligesis.Commit.RSEncode({}x{})", m, n));
    let mat_f_prime = mat_f.iter().map(|row| rs.encode(row)).collect::<Vec<_>>();
    end_timer!(timer);

    // compute `H`
    let timer = start_timer!(|| "Ligesis.Commit.SISHash");
    let mat_h = compute_sis_hash(mat_a, &mat_f_prime, eta, m);
    end_timer!(timer);

    // compute com(H) using chunked_batch_commit
    let timer = start_timer!(|| "Ligesis.Commit.DeepFold");
    let mat_h_poly = evals_to_arcpoly(&mat_h.concat());
    let (com_mat_h, mat_h_advice) = chunked_batch_commit(deepfold_prover_param, &[mat_h_poly])?;
    end_timer!(timer);

    Ok((
        LigeSISCommitment {
            num_vars,
            com_mat_h,
            _marker: std::marker::PhantomData,
        },
        LigeSISProverCommitmentAdvice {
            mat_f_prime,
            mat_h,
            mat_h_advice,
        },
    ))
}

/// Distributed Ligesis commit using multi-chunked batch protocol
#[allow(non_snake_case)]
pub fn ligesis_d_commit<F: PrimeField>(
    prover_param: &LigeSISProverParam<F>,
    poly: &Arc<DenseMultilinearExtension<F>>,
) -> Result<
    (
        Option<LigeSISCommitment<F>>,
        LigeSISProverCommitmentAdvice<F>,
    ),
    PCSError,
> {
    let num_party = Net::n_parties();
    let num_party_vars = Net::n_parties().log_2() as usize;
    let party_id = Net::party_id();

    let &LigeSISProverParam {
        eta,
        s_lambda: _,
        mu: _,
        log_m,
        log_n,
        c,
        ref rs,
        ref mat_a,
        ref mat_a_pad,
        ref mat_a_advice,
        ref deepfold_prover_param,
    } = prover_param;
    let _ = (mat_a_pad, mat_a_advice); // Suppress unused warnings
    let (m, n) = (1 << log_m, 1 << log_n);

    // Record original num_vars (for distributed case, actual num_vars =
    // poly.num_vars + num_party_vars)
    let num_vars = poly.num_vars + num_party_vars;
    let mat_f = reshape(&poly.evaluations, m / num_party, n);

    // encode `F`
    Net::barrier();
    let timer = start_timer!(|| format!("DLigesis.Commit.RSEncode({}x{})", m / num_party, n));
    let mat_f_prime = mat_f.iter().map(|row| rs.encode(row)).collect::<Vec<_>>();
    end_timer!(timer);

    // compute `H` locally (each party computes their portion)
    let mat_a_k: Vec<Vec<F>> = mat_a
        .iter()
        .map(|row| {
            row[party_id * eta * m / num_party..(party_id + 1) * eta * m / num_party].to_vec()
        })
        .collect();

    Net::barrier();
    let timer =
        start_timer!(|| format!("DLigesis.Commit.SISHash({}x{}x{})", c, m / num_party, n * 2));
    let mat_h_i = compute_sis_hash(&mat_a_k, &mat_f_prime, eta, m / num_party);
    end_timer!(timer);

    // Gather mat_h to master (flatten before sending for efficient serialization)
    let mat_h_i_flat: Vec<F> = mat_h_i.concat();
    let mat_h_bytes = mat_h_i_flat.len() * 8;
    Net::barrier();
    let timer =
        start_timer!(|| format!("DLigesis.Commit.GatherMatH({}MB)", mat_h_bytes / 1_000_000));
    let all_mat_h_flat = Net::send_to_master(&mat_h_i_flat);
    end_timer!(timer);

    // Master computes full mat_h, then splits and distributes to parties
    let timer = start_timer!(|| "DLigesis.Commit.AssembleAndDistribute");
    let mat_h_local: Vec<F> = if Net::am_master() {
        let all_mat_h_flat =
            all_mat_h_flat.ok_or(PCSError::UnexpectedNone("all_mat_h_flat".into()))?;
        // Each party sent c * 2 * n elements, sum element-wise
        let total_size = c * 2 * n;
        let mat_h_flat: Vec<F> = (0..total_size)
            .map(|i| (0..num_party).map(|k| all_mat_h_flat[k][i]).sum::<F>())
            .collect();

        let portion_size = total_size / num_party;
        let portions: Vec<Vec<F>> = (0..num_party)
            .map(|k| mat_h_flat[k * portion_size..(k + 1) * portion_size].to_vec())
            .collect();

        Net::recv_from_master(Some(portions))
    } else {
        Net::recv_from_master(None)
    };

    end_timer!(timer);

    // Each party now has their portion of mat_h
    // d_chunked_batch_commit will use "large polynomial" path if local size >=
    // base_mu
    let timer = start_timer!(|| "DLigesis.Commit.DeepFoldChunkedBatch");
    let mat_h_local_poly = evals_to_arcpoly(&mat_h_local);
    let (com_mat_h_opt, mat_h_advice) =
        d_chunked_batch_commit(deepfold_prover_param, &[mat_h_local_poly])?;
    end_timer!(timer);

    // For the advice, store empty mat_h since we don't need it in open
    // (open.rs ignores mat_h field with `mat_h: _`)
    let mat_h: Vec<Vec<F>> = vec![];

    if Net::am_master() {
        Ok((
            Some(LigeSISCommitment {
                num_vars,
                com_mat_h: com_mat_h_opt.unwrap(),
                _marker: std::marker::PhantomData,
            }),
            LigeSISProverCommitmentAdvice {
                mat_f_prime,
                mat_h,
                mat_h_advice,
            },
        ))
    } else {
        Ok((
            None,
            LigeSISProverCommitmentAdvice {
                mat_f_prime,
                mat_h,
                mat_h_advice,
            },
        ))
    }
}

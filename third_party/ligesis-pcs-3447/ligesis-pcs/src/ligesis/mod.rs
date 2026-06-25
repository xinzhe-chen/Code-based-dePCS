mod commit;
mod open;
mod verify;

pub use commit::{ligesis_commit, ligesis_d_commit};
pub use open::{ligesis_d_open, ligesis_open};
pub use verify::ligesis_verify;

use crate::{
    deepfold::*,
    errors::PCSError,
    ext_sumcheck::ExtSumCheckProof,
    hash::MerkleTree,
    rand::*,
    rscode::*,
    types::{FieldExtension, HasQuadraticExtension},
    utils::*,
    PolynomialCommitmentScheme,
};
use ark_ff::{BigInteger, Field, PrimeField};
use ark_poly::DenseMultilinearExtension;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::{
    borrow::Borrow,
    cmp::{max, min},
    marker::PhantomData,
    rand::Rng,
    sync::Arc,
    vec::Vec,
};
use transcript::IOPTranscript;

pub use crate::FGoldilocks;

/// Compute the SIS hash matrix H = A' * B where B is the byte decomposition of
/// F'.
///
/// Parameters:
/// - `mat_a`: The A matrix of shape `c x (eta * m_rows)`
/// - `mat_f_prime`: The RS-encoded F' matrix of shape `m_rows x cols`
/// - `eta`: The eta parameter (bit length)
/// - `m_rows`: Number of rows in mat_f_prime (can be m or m/num_party for
///   distributed)
///
/// Returns `mat_h` of shape `c x cols`
///
/// Optimized using:
/// - Fixed-size array [u64; 8] for lookup table entries (cache-friendly)
/// - Direct byte extraction from u64 (avoids to_bytes_le() allocation)
/// - Row-first iteration for better memory access patterns
fn compute_sis_hash<F: PrimeField>(
    mat_a: &[Vec<F>],
    mat_f_prime: &[Vec<F>],
    eta: usize,
    m_rows: usize,
) -> Vec<Vec<F>> {
    let c = mat_a.len();
    let cols = mat_f_prime[0].len();
    let num_bytes = eta / 8; // 8 bytes for 64-bit field

    // Precompute lookup table: a[byte_position * 256 + byte_value] -> [u64; 8]
    // All c values stored together for cache locality when accessed
    let a: Vec<[u64; 8]> = (0..m_rows * num_bytes * 256)
        .map(|idx| {
            let byte_position = idx / 256;
            let byte_val = idx % 256;
            let i = byte_position / num_bytes;
            let byte_idx = byte_position % num_bytes;

            let mut result = [0u64; 8];
            for (c_idx, row) in mat_a.iter().enumerate().take(8) {
                let elem_base = i * num_bytes * 8 + byte_idx * 8;
                let mut sum = 0u64;
                for bit in 0..8 {
                    if (byte_val >> bit) & 1 == 1 {
                        sum += row[elem_base + bit].into_bigint().as_ref()[0];
                    }
                }
                result[c_idx] = sum;
            }
            result
        })
        .collect();

    // Get modulus for final reduction
    let modulus = F::MODULUS.as_ref()[0];

    // Compute H: process row by row, all columns at once
    let mut hashes: Vec<[u64; 8]> = vec![[0u64; 8]; cols];

    for i in 0..m_rows {
        let base_cnt = i * num_bytes * 256;
        let row = &mat_f_prime[i];
        for j in 0..cols {
            // Get raw u64 value directly (faster than to_bytes_le())
            let val = row[j].into_bigint().as_ref()[0];
            // Extract bytes manually
            let b0 = (val & 0xFF) as usize;
            let b1 = ((val >> 8) & 0xFF) as usize;
            let b2 = ((val >> 16) & 0xFF) as usize;
            let b3 = ((val >> 24) & 0xFF) as usize;
            let b4 = ((val >> 32) & 0xFF) as usize;
            let b5 = ((val >> 40) & 0xFF) as usize;
            let b6 = ((val >> 48) & 0xFF) as usize;
            let b7 = ((val >> 56) & 0xFF) as usize;

            let h = &mut hashes[j];
            let l0 = &a[base_cnt + b0];
            let l1 = &a[base_cnt + 256 + b1];
            let l2 = &a[base_cnt + 512 + b2];
            let l3 = &a[base_cnt + 768 + b3];
            let l4 = &a[base_cnt + 1024 + b4];
            let l5 = &a[base_cnt + 1280 + b5];
            let l6 = &a[base_cnt + 1536 + b6];
            let l7 = &a[base_cnt + 1792 + b7];

            h[0] += l0[0] + l1[0] + l2[0] + l3[0] + l4[0] + l5[0] + l6[0] + l7[0];
            h[1] += l0[1] + l1[1] + l2[1] + l3[1] + l4[1] + l5[1] + l6[1] + l7[1];
            h[2] += l0[2] + l1[2] + l2[2] + l3[2] + l4[2] + l5[2] + l6[2] + l7[2];
            h[3] += l0[3] + l1[3] + l2[3] + l3[3] + l4[3] + l5[3] + l6[3] + l7[3];
            h[4] += l0[4] + l1[4] + l2[4] + l3[4] + l4[4] + l5[4] + l6[4] + l7[4];
            h[5] += l0[5] + l1[5] + l2[5] + l3[5] + l4[5] + l5[5] + l6[5] + l7[5];
            h[6] += l0[6] + l1[6] + l2[6] + l3[6] + l4[6] + l5[6] + l6[6] + l7[6];
            h[7] += l0[7] + l1[7] + l2[7] + l3[7] + l4[7] + l5[7] + l6[7] + l7[7];
        }
    }

    // Convert to field elements with modular reduction
    let mut mat_h: Vec<Vec<F>> = vec![vec![F::ZERO; cols]; c];
    for j in 0..cols {
        for k in 0..c {
            mat_h[k][j] = F::from(hashes[j][k] % modulus);
        }
    }

    mat_h
}

// TODO: Lookup code is currently incorrect, commented out for now
// #[derive(CanonicalSerialize, CanonicalDeserialize, Clone, Debug, PartialEq,
// Eq)] /// proof of lookup
// pub struct LigeSISLookupProof<F: PrimeField> {
//     pub sumcheck_proof: IOPProof<F>,
// }

#[cfg(test)]
mod tests;

/// LigeSIS Polynomial Commitment Scheme
pub struct LigeSISPCS<F: PrimeField> {
    #[doc(hidden)]
    phantom: PhantomData<F>,
}

impl<F: PrimeField + HasQuadraticExtension> LigeSISPCS<F> {
    pub fn compute_value_from_proof(_log_n: usize, _point: &Vec<F>, proof: &LigeSISProof<F>) -> F {
        // claimed_values[0] = a(z2) (point 0 targets polynomial a)
        F::ext_real(&proof.deepfold_batched_proof.claimed_values[0])
    }

    /// Distributed setup for LigeSIS
    /// Returns (ProverParam, Option<VerifierParam>) where VerifierParam is only
    /// present on master
    pub fn d_setup(
        srs: impl Borrow<LigeSISSRS<F>>,
    ) -> Result<(LigeSISProverParam<F>, Option<LigeSISVerifierParam<F>>), PCSError> {
        use deNetwork::{DeMultiNet as Net, DeNet};

        let LigeSISSRS {
            eta,
            lambda,
            mu,
            log_m,
            rs_len,
            c,
            mat_a,
            deepfold_srs,
        } = srs.borrow().clone();
        let log_n = mu - log_m;
        let n = 1 << log_n;
        let s_lambda = min(lambda, rs_len);
        let (deepfold_prover_param, deepfold_verifier_param) =
            DeepFoldPCS::<F>::setup(deepfold_srs)?;

        // mat_a size = c * eta * 2^log_m = 2^(log_c + log_eta + log_m) = 2^(3 + 6 +
        // log_m) = 2^(log_m + 9) Use actual mat_a size, not deepfold_srs.max_mu
        // (which may be smaller for optimization)
        let mat_a_num_vars = log_m + 9;
        let mat_a_pad = evals_to_arcpoly(&resize_eval(&mat_a.concat(), mat_a_num_vars));

        // Distributed mode: use d_chunked_batch_commit for mat_a (done once in setup)
        let (com_mat_a_opt, mat_a_advice) =
            d_chunked_batch_commit(&deepfold_prover_param, &[mat_a_pad.clone()])?;

        let rs = ReedSolomon::<F>::new(n, rs_len);
        let g = rs.get_generator();

        let prover_param = LigeSISProverParam {
            eta,
            s_lambda,
            mu,
            log_m,
            log_n,
            c,
            rs,
            mat_a,
            mat_a_pad,
            mat_a_advice,
            deepfold_prover_param,
        };

        if Net::am_master() {
            let verifier_param = LigeSISVerifierParam {
                eta,
                s_lambda,
                mu,
                log_m,
                log_n,
                rs_len,
                c,
                g,
                com_mat_a: com_mat_a_opt.unwrap(),
                deepfold_verifier_param,
            };
            Ok((prover_param, Some(verifier_param)))
        } else {
            Ok((prover_param, None))
        }
    }
}

#[derive(CanonicalSerialize, CanonicalDeserialize, Clone, Debug, Default)]
pub struct LigeSISSRS<F: PrimeField> {
    lambda: usize,
    eta: usize,
    pub mu: usize,
    log_m: usize,
    rs_len: usize,
    c: usize,
    mat_a: Vec<Vec<F>>,
    deepfold_srs: DeepFoldSRS<F>,
}

impl<F: PrimeField> LigeSISSRS<F> {
    /// Generate SRS with custom base_mu and code_rate parameters.
    ///
    /// - `mu`: Total polynomial size (number of variables)
    /// - `base_mu`: DeepFold SRS max_mu (default: log_m + 9)
    /// - `code_rate`: Code rate multiplier (default: 4 for 1/4 rate)
    pub fn gen_with_params<R: Rng>(
        rng: &mut R,
        mu: usize,
        base_mu: Option<usize>,
        code_rate: Option<usize>,
    ) -> Result<Self, PCSError> {
        Self::gen_with_layout_params(rng, mu, None, base_mu, code_rate)
    }

    pub fn gen_with_layout_params<R: Rng>(
        rng: &mut R,
        mu: usize,
        log_m_override: Option<usize>,
        base_mu: Option<usize>,
        code_rate: Option<usize>,
    ) -> Result<Self, PCSError> {
        let eta = F::ONE.into_bigint().to_bits_be().len();
        let lambda = 128usize;
        let log_m = log_m_override.unwrap_or_else(|| if mu < 4 { 0 } else { (mu - 8) / 2 });
        if log_m > mu {
            return Err(PCSError::InvalidParameters(
                "log_m must be <= mu".to_owned(),
            ));
        }
        let rs_len = (1 << (mu - log_m)) * 2;
        let log_c = 3;
        let c = 1 << log_c;

        // Generate mat_a with values in [0, 2^40) to avoid overflow in SIS hash
        let mat_a_bound = 1u64 << 40;
        let mat_a: Vec<Vec<F>> = (0..c)
            .map(|_| {
                (0..eta * (1 << log_m))
                    .map(|_| F::from(rng.gen::<u64>() % mat_a_bound))
                    .collect()
            })
            .collect();

        let default_base_mu = log_m + 9;
        let actual_base_mu = base_mu.unwrap_or(default_base_mu);
        let actual_rate = code_rate.unwrap_or(4); // default to 1/4 rate

        let deepfold_srs = DeepFoldPCS::<F>::gen_srs_with_rate(rng, actual_base_mu, actual_rate)?;

        Ok(LigeSISSRS {
            eta,
            lambda,
            mu,
            log_m,
            rs_len,
            c,
            mat_a,
            deepfold_srs,
        })
    }
}

#[derive(Clone)]
pub struct LigeSISProverParam<F: PrimeField> {
    eta: usize,
    s_lambda: usize,
    mu: usize,
    log_m: usize,
    log_n: usize,
    c: usize,
    rs: ReedSolomon<F>,
    mat_a: Vec<Vec<F>>,
    mat_a_pad: Arc<DenseMultilinearExtension<F>>,
    mat_a_advice: DeepFoldBatchMultiProverAdvice<F>,
    deepfold_prover_param: DeepFoldProverParam<F>,
}

#[derive(Clone, CanonicalSerialize, CanonicalDeserialize)]
pub struct LigeSISVerifierParam<F: PrimeField> {
    eta: usize,
    s_lambda: usize,
    mu: usize,
    log_m: usize,
    log_n: usize,
    rs_len: usize,
    c: usize,
    g: F,
    com_mat_a: DeepFoldBatchMultiCommitment,
    deepfold_verifier_param: DeepFoldVerifierParam<F>,
}

/// Extension field SumCheck proof (direct, no reduction needed)
/// Used with direct extension field opening in DeepFold (128-bit soundness)
#[derive(Clone, Debug, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize)]
pub struct ExtSumCheckWithReductionProof<F: PrimeField + HasQuadraticExtension> {
    /// Extension field SumCheck proof (contains the extension field point)
    pub ext_proof: ExtSumCheckProof<F::Extension>,
}

/// Proof for Ligesis - provides 128-bit soundness
/// Uses extension field SumCheck and multi-chunked batch opening in DeepFold
#[derive(Clone, Debug, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize)]
pub struct LigeSISProof<F: PrimeField + HasQuadraticExtension> {
    /// Combined commitment for a, bI, rs_a polynomials (3 polynomials in one
    /// commitment)
    pub com_a_bI_rsa: DeepFoldBatchMultiCommitment,

    /// Extension field SumCheck proofs (no reduction needed)
    pub bI_check_proof: ExtSumCheckWithReductionProof<F>,
    pub alpha2_a_bI_r2_check_proof: ExtSumCheckWithReductionProof<F>,
    pub v_bI_r2_check_proof: ExtSumCheckWithReductionProof<F>,
    pub rs_a_check_proof: ExtSumCheckWithReductionProof<F>,
    pub mat_g_check_proofs: Vec<ExtSumCheckWithReductionProof<F>>,

    /// Extension field multi-chunked batch proof (combines all polynomial
    /// openings)
    pub deepfold_batched_proof: MultiChunkedBatchExtProof<F>,
}

/// Prover advice for LigeSIS commitment
/// Uses DeepFoldBatchMultiProverAdvice for mat_h commitment
#[derive(Debug)]
pub struct LigeSISProverCommitmentAdvice<F: PrimeField> {
    pub mat_f_prime: Vec<Vec<F>>,
    pub mat_h: Vec<Vec<F>>,
    /// Combined advice for mat_h commitment using multi-chunked batch
    pub mat_h_advice: DeepFoldBatchMultiProverAdvice<F>,
}

impl<F: PrimeField> Clone for LigeSISProverCommitmentAdvice<F> {
    fn clone(&self) -> Self {
        LigeSISProverCommitmentAdvice {
            mat_f_prime: self.mat_f_prime.clone(),
            mat_h: self.mat_h.clone(),
            mat_h_advice: self.mat_h_advice.clone(),
        }
    }
}

impl<F: PrimeField> Default for LigeSISProverCommitmentAdvice<F> {
    fn default() -> Self {
        LigeSISProverCommitmentAdvice {
            mat_f_prime: vec![],
            mat_h: vec![],
            mat_h_advice: DeepFoldBatchMultiProverAdvice {
                batch_advice: DeepFoldBatchProverAdvice {
                    f0_matrix: vec![],
                    v0_matrix: vec![],
                    column_hashes: vec![],
                    merkle_tree: MerkleTree::default(),
                },
                chunk_polys: vec![],
                chunks_per_poly: vec![],
                base_mu: 0,
                local_poly_evals: vec![],
                cols_per_party: 0,
                upper_tree: None,
                party_roots: vec![],
            },
        }
    }
}

/// Commitment for LigeSIS using multi-chunked batch commitment
#[derive(CanonicalSerialize, CanonicalDeserialize, Clone, Debug, PartialEq, Eq)]
pub struct LigeSISCommitment<F: PrimeField> {
    pub num_vars: usize,
    /// Combined commitment for mat_h using multi-chunked batch
    pub com_mat_h: DeepFoldBatchMultiCommitment,
    #[doc(hidden)]
    pub _marker: PhantomData<F>,
}

impl<F: PrimeField> Default for LigeSISCommitment<F> {
    fn default() -> Self {
        LigeSISCommitment {
            num_vars: 0,
            com_mat_h: DeepFoldBatchMultiCommitment {
                batch_commitment: DeepFoldBatchCommitment {
                    mu: 0,
                    num_polys: 0,
                    root: [0u8; 32],
                },
                num_polys: 0,
                chunks_per_poly: vec![],
                original_num_vars: vec![],
            },
            _marker: PhantomData,
        }
    }
}

impl<F: PrimeField + HasQuadraticExtension> PolynomialCommitmentScheme<F> for LigeSISPCS<F> {
    // Parameters
    type ProverParam = LigeSISProverParam<F>;
    type VerifierParam = LigeSISVerifierParam<F>;
    type SRS = LigeSISSRS<F>;
    // Polynomial and its associated types
    type Polynomial = Arc<DenseMultilinearExtension<F>>;
    type ProverCommitmentAdvice = LigeSISProverCommitmentAdvice<F>;
    type Point = Vec<F>;
    type Evaluation = F;
    // Commitments and proofs
    type Commitment = LigeSISCommitment<F>;
    type Proof = LigeSISProof<F>;
    type BatchProof = ();

    fn gen_srs_for_testing<R: Rng>(rng: &mut R, log_size: usize) -> Result<Self::SRS, PCSError> {
        let eta = F::ONE.into_bigint().to_bits_be().len();
        let lambda = 128usize;
        let mu = log_size;
        let log_m = if log_size < 4 { 0 } else { (log_size - 8) / 2 };
        let rs_len = (1 << (mu - log_m)) * 2;
        let log_c = 3;
        let c = 1 << log_c;
        let log_eta = eta.ilog2() as usize;
        let log_n = mu - log_m;
        let log_s_lambda = lambda.ilog2() as usize;

        // Generate mat_a with values in [0, 2^40) to avoid overflow in SIS hash
        let mat_a_bound = 1u64 << 40;
        let mat_a: Vec<Vec<F>> = (0..c)
            .map(|_| {
                (0..eta * (1 << log_m))
                    .map(|_| F::from(rng.gen::<u64>() % mat_a_bound))
                    .collect()
            })
            .collect();

        let deepfold_srs = DeepFoldPCS::<F>::gen_srs_for_testing(rng, log_m + 7)?;
        Ok(LigeSISSRS {
            eta,
            lambda,
            mu,
            log_m,
            rs_len,
            c,
            mat_a,
            deepfold_srs,
        })
    }

    fn setup(
        srs: impl Borrow<Self::SRS>,
    ) -> Result<(Self::ProverParam, Self::VerifierParam), PCSError> {
        let LigeSISSRS {
            eta,
            lambda,
            mu,
            log_m,
            rs_len,
            c,
            mat_a,
            deepfold_srs,
        } = srs.borrow().clone();
        let log_n = mu - log_m;
        let n = 1 << log_n;
        let s_lambda = min(lambda, rs_len);
        let (deepfold_prover_param, deepfold_verifier_param) =
            DeepFoldPCS::<F>::setup(deepfold_srs)?;

        // mat_a size = c * eta * 2^log_m = 2^(log_c + log_eta + log_m) = 2^(3 + 6 +
        // log_m) = 2^(log_m + 9) Use actual mat_a size, not deepfold_srs.max_mu
        // (which may be smaller for optimization)
        let mat_a_num_vars = log_m + 9;
        let mat_a_pad = evals_to_arcpoly(&resize_eval(&mat_a.concat(), mat_a_num_vars));

        // Non-distributed mode: use chunked_batch_commit for mat_a (done once in setup)
        let (com_mat_a, mat_a_advice) =
            chunked_batch_commit(&deepfold_prover_param, &[mat_a_pad.clone()])?;

        let rs = ReedSolomon::<F>::new(n, rs_len);
        let g = rs.get_generator();

        let prover_param = LigeSISProverParam {
            eta,
            s_lambda,
            mu,
            log_m,
            log_n,
            c,
            rs,
            mat_a,
            mat_a_pad,
            mat_a_advice,
            deepfold_prover_param,
        };
        let verifier_param = LigeSISVerifierParam {
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
        };
        Ok((prover_param, verifier_param))
    }

    fn commit(
        prover_param: impl Borrow<Self::ProverParam>,
        poly: &Self::Polynomial,
    ) -> Result<(Self::Commitment, Self::ProverCommitmentAdvice), PCSError> {
        ligesis_commit(prover_param.borrow(), poly)
    }

    fn d_commit(
        prover_param: impl Borrow<Self::ProverParam>,
        poly: &Self::Polynomial,
    ) -> Result<(Option<Self::Commitment>, Self::ProverCommitmentAdvice), PCSError> {
        ligesis_d_commit(prover_param.borrow(), poly)
    }

    fn open(
        prover_param: impl Borrow<Self::ProverParam>,
        poly: &Self::Polynomial,
        advice: &Self::ProverCommitmentAdvice,
        point: &Self::Point,
        transcript: &mut IOPTranscript<F>,
    ) -> Result<Self::Proof, PCSError> {
        ligesis_open(prover_param.borrow(), poly, advice, point, transcript)
    }

    fn d_open(
        prover_param: impl Borrow<Self::ProverParam>,
        poly: &Self::Polynomial,
        advice: &Self::ProverCommitmentAdvice,
        point: &Self::Point,
        transcript: &mut IOPTranscript<F>,
    ) -> Result<Option<Self::Proof>, PCSError> {
        ligesis_d_open(prover_param.borrow(), poly, advice, point, transcript)
    }

    fn verify(
        verifier_param: &Self::VerifierParam,
        com: &Self::Commitment,
        point: &Self::Point,
        value: &F,
        proof: &Self::Proof,
        transcript: &mut IOPTranscript<F>,
    ) -> Result<bool, PCSError> {
        ligesis_verify(verifier_param, com, point, value, proof, transcript)
    }
}

use crate::{errors::PCSError, hash::*, rand::*, rscode::*, utils::*, PolynomialCommitmentScheme};
use ark_ff::PrimeField;
use ark_poly::DenseMultilinearExtension;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::{borrow::Borrow, cmp::min, marker::PhantomData, rand::Rng, sync::Arc, vec, vec::Vec};
use transcript::IOPTranscript;

/// Ligero Polynomial Commitment Scheme
pub struct LigeroPCS<F: PrimeField> {
    #[doc(hidden)]
    phantom: PhantomData<F>,
}

#[derive(CanonicalSerialize, CanonicalDeserialize, Clone, Debug, PartialEq, Eq, Default)]
pub struct LigeroCommitment {
    pub num_vars: usize,
    pub root: Byte32,
}

#[derive(CanonicalSerialize, CanonicalDeserialize, Clone, Debug, PartialEq, Eq)]
/// proof of opening
pub struct LigeroProof<F: PrimeField> {
    pub f0: Vec<F>, // r^T * A
    pub f1: Vec<F>, // u0^T * A
    pub mt_proofs: Vec<Vec<Byte32>>,
    pub cols: Vec<Vec<F>>,
}

impl<F: PrimeField> LigeroPCS<F> {
    pub fn compute_value_from_proof(log_m0: usize, point: &Vec<F>, proof: &LigeroProof<F>) -> F {
        let u1 = get_tensor(&point[log_m0..].to_vec());
        (0..u1.len()).map(|i| proof.f1[i] * u1[i]).sum::<F>()
    }
}

impl<F: PrimeField> PolynomialCommitmentScheme<F> for LigeroPCS<F> {
    // Parameters
    type ProverParam = (usize, usize, usize); // (num of variables, num of variables in one side, length of RS code)
    type VerifierParam = (usize, usize, usize);
    type SRS = (usize, usize, usize); // (num of variables, length of RS code)
                                      // Polynomial and its associated types
    type Polynomial = Arc<DenseMultilinearExtension<F>>;
    type ProverCommitmentAdvice = MerkleTree; // merkle tree structure
    type Point = Vec<F>;
    type Evaluation = F;
    // Commitments and proofs
    type Commitment = LigeroCommitment; // merkle tree root with num_vars
    type Proof = LigeroProof<F>; // merkle tree paths, columes of `E`
    type BatchProof = (); //

    fn gen_srs_for_testing<R: Rng>(_rng: &mut R, log_size: usize) -> Result<Self::SRS, PCSError> {
        // MultilinearUniversalParams::<E>::gen_srs_for_testing(rng, log_size)
        let log_n = log_size;
        let log_m = log_n / 2;
        let rs_len = (1 << log_m) * 2;
        Ok((log_n, log_m, rs_len))
    }

    fn setup(
        srs: impl Borrow<Self::SRS>,
    ) -> Result<(Self::ProverParam, Self::VerifierParam), PCSError> {
        Ok((srs.borrow().clone(), srs.borrow().clone()))
    }

    fn commit(
        prover_param: impl Borrow<Self::ProverParam>,
        poly: &Self::Polynomial,
    ) -> Result<(Self::Commitment, Self::ProverCommitmentAdvice), PCSError> {
        // trim parameters
        let &(log_n, log_m0, rs_len) = prover_param.borrow();
        let log_m1 = log_n - log_m0;
        let (n, m0, m1) = (1 << log_n, 1 << log_m0, 1 << log_m1);

        // Record original num_vars and pad if needed
        let num_vars = poly.num_vars;
        assert!(num_vars <= log_n);
        let poly_evals = if num_vars < log_n {
            resize_eval(&poly.evaluations, log_n)
        } else {
            poly.evaluations.clone()
        };
        let mat_a = reshape(&poly_evals, m0, m1);

        // encode `A`
        let rs = ReedSolomon::new(m1, rs_len);
        let mat_e = mat_a.iter().map(|row| rs.encode(row)).collect::<Vec<_>>();

        // build merkle tree on columes
        let hash_cols = (0..(m1 << 1))
            .map(|j| compute_sha256_row(&((0..m0).map(|i| mat_e[i][j]).collect::<Vec<_>>())))
            .collect::<Vec<_>>();
        let mt = MerkleTree::new(&hash_cols);

        Ok((LigeroCommitment { num_vars, root: mt.root().clone() }, mt))
    }

    fn open(
        prover_param: impl Borrow<Self::ProverParam>,
        poly: &Self::Polynomial,
        advice: &Self::ProverCommitmentAdvice,
        point: &Self::Point,
        transcript: &mut IOPTranscript<F>,
    ) -> Result<Self::Proof, PCSError> {
        // trim parameters
        let &(log_n, log_m0, rs_len) = prover_param.borrow();
        let log_m1 = log_n - log_m0;
        let (n, m0, m1) = (1 << log_n, 1 << log_m0, 1 << log_m1);

        assert!(poly.num_vars <= log_n);
        // Pad polynomial and point if needed
        let poly_evals = if poly.num_vars < log_n {
            resize_eval(&poly.evaluations, log_n)
        } else {
            poly.evaluations.clone()
        };
        let point = resize_point(point, log_n);
        let mat_a = reshape(&poly_evals, m0, m1);

        // encode `A`
        let rs = ReedSolomon::new(m1, rs_len);
        let mat_e = mat_a.iter().map(|row| rs.encode(row)).collect::<Vec<_>>();

        // generate `r` and compute the tensor vector `u0`
        let r = transcript.get_and_append_challenge_vectors(b"r", m0)?;
        let u0 = get_tensor(&point[..log_m0].to_vec());

        // compute `rA` and `u0A` and compute msg
        let f0: Vec<F> = (0..m1)
            .map(|j| (0..m0).map(|i| r[i] * mat_a[i][j]).sum())
            .collect::<Vec<_>>();
        let f1: Vec<F> = (0..m1)
            .map(|j| (0..m0).map(|i| u0[i] * mat_a[i][j]).sum())
            .collect::<Vec<_>>();
        // let msg: Vec<F> = { let mut f = f0.clone(); f.append(&mut f1.clone()); f };

        // get merkle tree on columes
        let mt = advice;

        // generate lambda indices and alpha
        let idx: Vec<usize> =
            transcript.get_and_append_challenge_indices(b"idx", min(128, m1 << 1), m1 << 1)?;
        let _alpha: F = transcript.get_and_append_challenge(b"alpha")?;

        // trim all needed columes and compute merkle paths
        let cols = idx
            .iter()
            .map(|&i| mat_e.iter().map(|row| row[i]).collect::<Vec<_>>())
            .collect::<Vec<_>>();
        let mt_proofs = idx.iter().map(|&i| mt.prove(i)).collect::<Vec<_>>();

        Ok(LigeroProof {
            f0,
            f1,
            cols,
            mt_proofs,
        })
    }

    fn verify(
        verifier_param: &Self::VerifierParam,
        com: &Self::Commitment,
        point: &Self::Point,
        value: &F,
        proof: &Self::Proof,
        transcript: &mut IOPTranscript<F>,
    ) -> Result<bool, PCSError> {
        // trim parameters
        let &(log_n, log_m0, rs_len) = verifier_param;
        let log_m1 = log_n - log_m0;
        let (n, m0, m1) = (1 << log_n, 1 << log_m0, 1 << log_m1);

        // Extract num_vars and root from commitment
        let LigeroCommitment { num_vars, root } = com.clone();

        // Pad point if needed
        let point = resize_point(point, log_n);

        let f0 = proof.f0.clone();
        let f1 = proof.f1.clone();

        // generate the challenge and compuate the tensor vector
        let r = transcript.get_and_append_challenge_vectors(b"r", m0)?;
        let (u0, u1) = (
            get_tensor(&point[..log_m0].to_vec()),
            get_tensor(&point[log_m0..].to_vec()),
        );

        // check if the final value is correctly computed
        if (0..m1).map(|i| f1[i] * u1[i]).sum::<F>() != *value {
            return Ok(false);
        }

        // choose lambda columes
        // generate a random value alpha and batch `f0 + alpha * f1`
        let idx: Vec<usize> =
            transcript.get_and_append_challenge_indices(b"idx", min(128, m1 << 1), m1 << 1)?;
        let alpha: F = transcript.get_and_append_challenge(b"alpha")?;
        let f = (0..m1).map(|i| f0[i] + alpha * f1[i]).collect();

        // encode `f`
        let rs = ReedSolomon::<F>::new(m1, rs_len);
        let enc = rs.encode(&f);
        let enc_i = idx.iter().map(|&i| enc[i]).collect::<Vec<_>>();

        // check if `Enc(f)` and `(r + alpha * u0)^T E` meet at lambda points
        let cmp_i = (0..idx.len())
            .map(|i| {
                (0..m0)
                    .map(|j| proof.cols[i][j] * (r[j] + alpha * u0[j]))
                    .sum::<F>()
            })
            .collect::<Vec<_>>();
        if cmp_i != enc_i {
            return Ok(false);
        }

        // check merkle paths
        for i in 0..idx.len() {
            if !MerkleTree::verify(
                &root,
                idx[i],
                &compute_sha256_row(&proof.cols[i]),
                &proof.mt_proofs[i],
            ) {
                return Ok(false);
            }
        }

        return Ok(true);
    }
}

#[cfg(test)]
mod tests;

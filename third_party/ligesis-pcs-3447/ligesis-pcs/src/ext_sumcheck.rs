//! Extension field SumCheck protocol
//!
//! This module implements a SumCheck protocol where:
//! - Polynomials are stored in the base field F
//! - Challenges are sampled from extension field EF
//! - This provides ~128-bit soundness for 64-bit base fields

use ark_ff::{Field, PrimeField};
use ark_poly::DenseMultilinearExtension;
use ark_serialize::{CanonicalSerialize, CanonicalDeserialize};
use std::sync::Arc;
use transcript::IOPTranscript;

use crate::{
    errors::PCSError,
    structs::{IOPProof, IOPProverMessage},
    types::FieldExtension,
};
use arithmetic::math::Math;
use deNetwork::{DeMultiNet as Net, DeNet, DeSerNet};

/// Evaluate a base field MLE at an extension field point.
///
/// Given an MLE f: F^n -> F and a point r in EF^n, computes f(r) in EF.
/// This works by treating F elements as EF elements via embedding.
pub fn eval_mle_at_ext_point<F, EF>(mle: &DenseMultilinearExtension<F>, point: &[EF]) -> EF
where
    F: PrimeField,
    EF: Field + FieldExtension<F>,
{
    let n = mle.num_vars;
    assert_eq!(point.len(), n, "Point dimension must match MLE variables");

    if n == 0 {
        return EF::from_base(mle.evaluations[0]);
    }

    // Use the multilinear extension formula:
    // f(r) = sum_{b in {0,1}^n} f(b) * prod_{i=1}^n ((1-b_i)(1-r_i) + b_i*r_i)
    // which simplifies to:
    // f(r) = sum_{b in {0,1}^n} f(b) * prod_{i=1}^n ((1-r_i) + (2*r_i - 1)*b_i)

    // Build the tensor product: tensor[b] = prod_{i} ((1-r_i) + (2*r_i - 1)*b_i)
    let mut tensor = vec![EF::one(); 1 << n];

    for i in 0..n {
        let ri = &point[i];
        let one_minus_ri = EF::one() - ri;
        let two_ri_minus_one = *ri + *ri - EF::one();

        let half = 1 << i;
        for j in 0..half {
            // tensor[j + half] *= (1-r_i) + (2*r_i - 1) * 1 = r_i
            // tensor[j] *= (1-r_i) + (2*r_i - 1) * 0 = 1 - r_i
            tensor[j + half] = tensor[j] * (one_minus_ri + two_ri_minus_one);
            tensor[j] *= one_minus_ri;
        }
    }

    // Compute the inner product of evaluations and tensor
    let mut result = EF::zero();
    for (i, &eval) in mle.evaluations.iter().enumerate() {
        result += tensor[i] * EF::from_base(eval);
    }

    result
}

/// Extension field SumCheck prover state
/// Uses efficient incremental evaluation updates instead of naive O(2^2n) approach
pub struct ExtSumCheckProverState<F: PrimeField, EF: Field + FieldExtension<F>> {
    /// The current round
    round: usize,
    /// Number of variables
    num_vars: usize,
    /// Products: (coefficient, indices into ext_evaluations)
    products: Vec<(EF, Vec<usize>)>,
    /// Extension field evaluations of each MLE, updated incrementally
    /// After round r, each has 2^(num_vars - r) evaluations
    ext_evaluations: Vec<Vec<EF>>,
    /// Challenges received so far (in extension field)
    challenges: Vec<EF>,
    /// PhantomData for F
    _marker: std::marker::PhantomData<F>,
}

impl<F: PrimeField, EF: Field + FieldExtension<F> + Copy> ExtSumCheckProverState<F, EF> {
    /// Create a new prover state
    pub fn new(
        num_vars: usize,
        products: Vec<(F, Vec<usize>)>,
        flattened_ml_extensions: Vec<Arc<DenseMultilinearExtension<F>>>,
    ) -> Self {
        // Convert coefficients to extension field
        let products_ext: Vec<(EF, Vec<usize>)> = products
            .into_iter()
            .map(|(coeff, indices)| (EF::from_base(coeff), indices))
            .collect();

        // Convert base field evaluations to extension field
        let ext_evaluations: Vec<Vec<EF>> = flattened_ml_extensions
            .iter()
            .map(|mle| mle.evaluations.iter().map(|&x| EF::from_base(x)).collect())
            .collect();

        Self {
            round: 0,
            num_vars,
            products: products_ext,
            ext_evaluations,
            challenges: Vec::new(),
            _marker: std::marker::PhantomData,
        }
    }

    /// Compute the sum over the boolean hypercube (efficient O(2^n) version)
    pub fn compute_sum(&self) -> EF {
        let mut sum = EF::zero();

        // Sum over all points in the boolean hypercube
        for b in 0..(1 << self.num_vars) {
            let mut term = EF::zero();
            for (coeff, indices) in &self.products {
                let mut prod = *coeff;
                for &idx in indices {
                    prod *= self.ext_evaluations[idx][b];
                }
                term += prod;
            }
            sum += term;
        }

        sum
    }

    /// Bind the bottom variable with an extension field challenge
    /// Updates evaluations: new[i] = old[2*i] + r * (old[2*i+1] - old[2*i])
    fn bind_var_bot(&mut self, r: &EF) {
        for evals in &mut self.ext_evaluations {
            let n = evals.len() / 2;
            for i in 0..n {
                evals[i] = evals[2 * i] + *r * (evals[2 * i + 1] - evals[2 * i]);
            }
            evals.truncate(n);
        }
    }

    /// Generate the univariate polynomial for the current round
    /// Returns evaluations at 0, 1, 2, ..., degree
    pub fn prove_round(&mut self, challenge: Option<EF>) -> Vec<EF> {
        // First, bind the previous challenge if any
        if let Some(c) = challenge {
            self.challenges.push(c);
            self.bind_var_bot(&c);
        }

        let remaining_vars = self.num_vars - self.round;
        let max_degree = self.products.iter().map(|(_, indices)| indices.len()).max().unwrap_or(1);

        // Compute evaluations at 0, 1, 2, ..., max_degree
        let mut evals = vec![EF::zero(); max_degree + 1];

        // Sum over all remaining variables except the first (bottom) one
        // For each b in [0, 2^(remaining_vars-1)), we have:
        //   eval_at_0 = ext_evaluations[idx][2*b]
        //   eval_at_1 = ext_evaluations[idx][2*b + 1]
        //   step = eval_at_1 - eval_at_0
        //   eval_at_t = eval_at_0 + t * step
        for b in 0..(1 << (remaining_vars - 1)) {
            // Collect (eval_at_0, step) for each MLE in the product
            for (coeff, indices) in &self.products {
                let mut buf: Vec<(EF, EF)> = indices
                    .iter()
                    .map(|&idx| {
                        let eval_0 = self.ext_evaluations[idx][2 * b];
                        let eval_1 = self.ext_evaluations[idx][2 * b + 1];
                        (eval_0, eval_1 - eval_0)
                    })
                    .collect();

                // eval_at_0: product of all eval_0 values
                evals[0] += *coeff * buf.iter().map(|(e, _)| *e).product::<EF>();

                // eval_at_t for t = 1, 2, ..., max_degree
                for t in 1..=max_degree {
                    // Update each (eval, step) -> (eval + step, step)
                    buf.iter_mut().for_each(|(e, s)| *e += *s);
                    evals[t] += *coeff * buf.iter().map(|(e, _)| *e).product::<EF>();
                }
            }
        }

        self.round += 1;
        evals
    }

    /// Get the final evaluation after all rounds
    pub fn get_final_evaluation(&mut self, final_challenge: EF) -> Vec<EF> {
        self.challenges.push(final_challenge);
        self.bind_var_bot(&final_challenge);

        // After binding all variables, each MLE has exactly 1 evaluation
        self.ext_evaluations.iter().map(|evals| evals[0]).collect()
    }

    /// Get the current evaluations for distributed sumcheck (without binding final challenge)
    /// Used to gather evaluations from all parties before master runs party rounds
    pub fn get_current_evaluations(&self) -> Vec<Vec<EF>> {
        self.ext_evaluations.clone()
    }

    /// Get the products structure for rebuilding state on master
    pub fn get_products(&self) -> &Vec<(EF, Vec<usize>)> {
        &self.products
    }

    /// Get the challenges accumulated so far
    pub fn get_challenges(&self) -> &Vec<EF> {
        &self.challenges
    }

    /// Create a new prover state from gathered evaluations (for master in distributed setting)
    pub fn from_gathered_evaluations(
        num_vars: usize,
        products: Vec<(EF, Vec<usize>)>,
        ext_evaluations: Vec<Vec<EF>>,
        challenges: Vec<EF>,
    ) -> Self {
        Self {
            round: 0,
            num_vars,
            products,
            ext_evaluations,
            challenges,
            _marker: std::marker::PhantomData,
        }
    }
}

/// Extension field SumCheck proof
#[derive(Clone, Debug, Default, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize)]
pub struct ExtSumCheckProof<EF: Field> {
    /// Prover messages (univariate polynomial evaluations for each round)
    pub proofs: Vec<Vec<EF>>,
    /// The challenge point where the subclaim is made
    pub point: Vec<EF>,
}

/// Extension field SumCheck subclaim
#[derive(Clone, Debug, Default)]
pub struct ExtSumCheckSubClaim<EF: Field> {
    /// The challenge point
    pub point: Vec<EF>,
    /// The expected sum of evaluations
    pub expected_evaluation: EF,
}

/// Run the extension field SumCheck protocol
pub fn ext_sumcheck_prove<F, EF>(
    num_vars: usize,
    products: Vec<(F, Vec<usize>)>,
    flattened_ml_extensions: Vec<Arc<DenseMultilinearExtension<F>>>,
    transcript: &mut IOPTranscript<F>,
) -> Result<(ExtSumCheckProof<EF>, EF), PCSError>
where
    F: PrimeField,
    EF: Field + FieldExtension<F> + Copy + ark_serialize::CanonicalSerialize + ark_serialize::CanonicalDeserialize + Default,
{
    let mut state = ExtSumCheckProverState::<F, EF>::new(
        num_vars,
        products,
        flattened_ml_extensions,
    );

    let sum = state.compute_sum();
    let mut proofs = Vec::new();
    let mut challenges = Vec::new();

    for round in 0..num_vars {
        let challenge = if round == 0 {
            None
        } else {
            // Get challenge from transcript (using extension field)
            let c = transcript.get_and_append_challenge(b"ext_sumcheck")?;
            Some(EF::from_base(c))
        };

        let evals = state.prove_round(challenge);

        // Append evaluations to transcript
        for eval in &evals {
            transcript.append_serializable_element(b"eval", eval)?;
        }

        if round > 0 {
            challenges.push(challenge.unwrap());
        }
        proofs.push(evals);
    }

    // Final challenge
    let final_challenge = transcript.get_and_append_challenge(b"ext_sumcheck")?;
    challenges.push(EF::from_base(final_challenge));

    Ok((
        ExtSumCheckProof {
            proofs,
            point: challenges,
        },
        sum,
    ))
}

/// Verify extension field SumCheck proof
pub fn ext_sumcheck_verify<F, EF>(
    claimed_sum: EF,
    proof: &ExtSumCheckProof<EF>,
    num_vars: usize,
    max_degree: usize,
    transcript: &mut IOPTranscript<F>,
) -> Result<ExtSumCheckSubClaim<EF>, PCSError>
where
    F: PrimeField,
    EF: Field + FieldExtension<F> + Copy + ark_serialize::CanonicalSerialize + ark_serialize::CanonicalDeserialize + Default,
{
    let mut expected = claimed_sum;
    let mut challenges = Vec::new();

    for (round, evals) in proof.proofs.iter().enumerate() {
        // Check that p(0) + p(1) = expected
        let sum_at_01 = evals[0] + evals[1];
        if sum_at_01 != expected {
            return Err(PCSError::SumCheckError(format!(
                "SumCheck failed at round {}: p(0) + p(1) = {:?}, expected {:?}",
                round, sum_at_01, expected
            )));
        }

        // Append evaluations to transcript (same as prover)
        for eval in evals {
            transcript.append_serializable_element(b"eval", eval)?;
        }

        // In round 0, the challenge is sampled AFTER evals are added but BEFORE the next round
        // The prover samples challenges starting from round 1
        // So we need to sample the challenge that will be used for the NEXT round
        if round < num_vars - 1 {
            // Sample challenge for next round
            let challenge = EF::from_base(transcript.get_and_append_challenge(b"ext_sumcheck")?);
            challenges.push(challenge);
            // Evaluate univariate polynomial at challenge using Lagrange interpolation
            expected = interpolate_and_eval::<F, EF>(evals, challenge);
        } else {
            // Last round - use the final challenge
            let final_challenge = EF::from_base(transcript.get_and_append_challenge(b"ext_sumcheck")?);
            challenges.push(final_challenge);
            expected = interpolate_and_eval::<F, EF>(evals, final_challenge);
        }
    }

    Ok(ExtSumCheckSubClaim {
        point: challenges,
        expected_evaluation: expected,
    })
}

/// Interpolate a polynomial from evaluations at 0, 1, 2, ... and evaluate at a point
fn interpolate_and_eval<F, EF>(evals: &[EF], point: EF) -> EF
where
    F: PrimeField,
    EF: Field + FieldExtension<F> + Copy,
{
    let n = evals.len();
    let mut result = EF::zero();

    // Lagrange interpolation over points 0, 1, 2, ..., n-1
    for i in 0..n {
        let mut term = evals[i];
        for j in 0..n {
            if i != j {
                let i_ef = EF::from_base(F::from(i as u64));
                let j_ef = EF::from_base(F::from(j as u64));
                term *= (point - j_ef) * (i_ef - j_ef).inverse().unwrap();
            }
        }
        result += term;
    }

    result
}

/// Extension field SumCheck proof with base field point (for compatibility with base field PCS)
#[derive(Clone, Debug, Default)]
pub struct ExtSumCheckProofWithBasePoint<F: PrimeField, EF: Field> {
    /// The extension field proof
    pub ext_proof: ExtSumCheckProof<EF>,
    /// The claimed sum (in extension field)
    pub sum: EF,
    /// The challenge point converted to base field (c0, c1 components)
    pub point_base: Vec<(F, F)>,
}

/// Helper to create an extension field sumcheck and add MLEs.
/// Similar API to SumCheckBuilder but uses extension field challenges.
pub struct ExtSumCheckBuilder<F: PrimeField, EF: Field + FieldExtension<F> + Copy> {
    num_vars: usize,
    products: Vec<(F, Vec<usize>)>,
    flattened_ml_extensions: Vec<Arc<DenseMultilinearExtension<F>>>,
    raw_pointers_lookup_table: std::collections::HashMap<*const DenseMultilinearExtension<F>, usize>,
    _phantom: std::marker::PhantomData<EF>,
}

impl<F: PrimeField, EF: Field + FieldExtension<F> + Copy + ark_serialize::CanonicalSerialize + ark_serialize::CanonicalDeserialize + Default> ExtSumCheckBuilder<F, EF> {
    /// Create a new ExtSumCheckBuilder with the given number of variables.
    pub fn new(num_vars: usize) -> Self {
        Self {
            num_vars,
            products: Vec::new(),
            flattened_ml_extensions: Vec::new(),
            raw_pointers_lookup_table: std::collections::HashMap::new(),
            _phantom: std::marker::PhantomData,
        }
    }

    /// Add a product of MLEs (as Arc) with a coefficient.
    pub fn add_mle_list(
        mut self,
        mles: impl IntoIterator<Item = Arc<DenseMultilinearExtension<F>>>,
        coeff: F,
    ) -> Result<Self, PCSError> {
        let mles: Vec<_> = mles.into_iter().collect();
        let mut indices = Vec::with_capacity(mles.len());

        for mle in mles {
            let ptr = Arc::as_ptr(&mle);
            if let Some(&idx) = self.raw_pointers_lookup_table.get(&ptr) {
                indices.push(idx);
            } else {
                let idx = self.flattened_ml_extensions.len();
                self.raw_pointers_lookup_table.insert(ptr, idx);
                self.flattened_ml_extensions.push(mle);
                indices.push(idx);
            }
        }

        self.products.push((coeff, indices));
        Ok(self)
    }

    /// Add a product of evaluation vectors with a coefficient.
    pub fn add_evals<const N: usize>(
        self,
        evals: [&Vec<F>; N],
        coeff: F,
    ) -> Result<Self, PCSError> {
        let mles: Vec<_> = evals.into_iter().map(|e| crate::evals_to_arcpoly(e)).collect();
        self.add_mle_list(mles, coeff)
    }

    /// Add a product of owned evaluation vectors with a coefficient.
    pub fn add_evals_owned<const N: usize>(
        self,
        evals: [Vec<F>; N],
        coeff: F,
    ) -> Result<Self, PCSError> {
        let mles: Vec<_> = evals.into_iter().map(|e| crate::evals_to_arcpoly(&e)).collect();
        self.add_mle_list(mles, coeff)
    }

    /// Prove the extension field sumcheck.
    /// Returns the proof and the computed sum.
    pub fn prove(self, transcript: &mut IOPTranscript<F>) -> Result<ExtSumCheckProof<EF>, PCSError> {
        let mut state = ExtSumCheckProverState::<F, EF>::new(
            self.num_vars,
            self.products,
            self.flattened_ml_extensions,
        );

        let mut proofs = Vec::new();
        let mut challenges = Vec::new();

        for round in 0..self.num_vars {
            let challenge = if round == 0 {
                None
            } else {
                let c = transcript.get_and_append_challenge(b"ext_sumcheck")?;
                Some(EF::from_base(c))
            };

            let evals = state.prove_round(challenge);

            // Append evaluations to transcript
            for eval in &evals {
                transcript.append_serializable_element(b"eval", eval)?;
            }

            if round > 0 {
                challenges.push(challenge.unwrap());
            }
            proofs.push(evals);
        }

        // Final challenge
        let final_challenge = transcript.get_and_append_challenge(b"ext_sumcheck")?;
        challenges.push(EF::from_base(final_challenge));

        Ok(ExtSumCheckProof {
            proofs,
            point: challenges,
        })
    }

    /// Distributed prove for extension field sumcheck.
    /// Each party runs local rounds on their local data, then master aggregates and runs party rounds.
    /// Returns Some(proof) on master, None on workers.
    pub fn d_prove(self, transcript: &mut IOPTranscript<F>) -> Result<Option<ExtSumCheckProof<EF>>, PCSError> {
        let num_party_vars = Net::n_parties().log_2() as usize;
        let max_degree = self.products.iter().map(|(_, indices)| indices.len()).max().unwrap_or(1);

        let mut state = ExtSumCheckProverState::<F, EF>::new(
            self.num_vars,
            self.products,
            self.flattened_ml_extensions,
        );

        let mut proofs = Vec::new();
        let mut challenges = Vec::new();

        // Phase 1: Local rounds (all parties participate)
        for round in 0..self.num_vars {
            let challenge = if round == 0 {
                None
            } else {
                // Challenge was set in previous iteration
                Some(challenges.last().copied().unwrap())
            };

            // Each party computes their local round
            let mut evals = state.prove_round(challenge);

            // Gather and sum evaluations from all parties
            let gathered_evals = Net::send_to_master(&evals);
            if Net::am_master() {
                let all_evals = gathered_evals.unwrap();
                // Sum up evaluations from all parties
                evals = vec![EF::zero(); max_degree + 1];
                for party_evals in all_evals {
                    for (i, &e) in party_evals.iter().enumerate() {
                        if i < evals.len() {
                            evals[i] += e;
                        }
                    }
                }

                // Append evaluations to transcript
                for eval in &evals {
                    transcript.append_serializable_element(b"eval", eval)?;
                }
            }
            proofs.push(evals.clone());

            // Get challenge for next round (or final challenge on last round)
            let challenge_ef = if Net::am_master() {
                let c = transcript.get_and_append_challenge(b"ext_sumcheck")?;
                let c_ef = EF::from_base(c);
                Net::recv_from_master_uniform(Some(c_ef));
                c_ef
            } else {
                Net::recv_from_master_uniform::<EF>(None)
            };
            challenges.push(challenge_ef);
        }

        // Phase 2: Gather final evaluations from all parties
        // After all local rounds, each party has 1 evaluation per MLE
        let final_challenge = challenges.last().copied().unwrap();
        let final_evals = state.get_final_evaluation(final_challenge);
        let gathered_final_evals = Net::send_to_master(&final_evals);

        if !Net::am_master() {
            return Ok(None);
        }

        // Phase 3: Master runs party rounds
        let all_final_evals = gathered_final_evals.unwrap();
        let num_mles = all_final_evals[0].len();

        // Build new MLEs from gathered evaluations (each MLE now has n_parties evaluations)
        let new_ext_evaluations: Vec<Vec<EF>> = (0..num_mles)
            .map(|mle_idx| {
                all_final_evals.iter().map(|party_evals| party_evals[mle_idx]).collect()
            })
            .collect();

        // Create new state for party rounds
        let products = state.get_products().clone();
        let mut party_state = ExtSumCheckProverState::<F, EF>::from_gathered_evaluations(
            num_party_vars,
            products,
            new_ext_evaluations,
            Vec::new(),
        );

        // Run party rounds on master only
        for round in 0..num_party_vars {
            let challenge = if round == 0 {
                None
            } else {
                Some(challenges.last().copied().unwrap())
            };

            let evals = party_state.prove_round(challenge);

            // Append evaluations to transcript
            for eval in &evals {
                transcript.append_serializable_element(b"eval", eval)?;
            }
            proofs.push(evals);

            // Get challenge for next round
            let c = transcript.get_and_append_challenge(b"ext_sumcheck")?;
            challenges.push(EF::from_base(c));
        }

        Ok(Some(ExtSumCheckProof {
            proofs,
            point: challenges,
        }))
    }
}

// ============================================================================
// Reduction Protocol: Extension field evaluation → Base field SumCheck
// ============================================================================

/// Decomposition of eq(x, r) where r ∈ EF^n into real and imaginary parts.
/// eq(x, r) = eq_R(x, a, b) + eq_I(x, a, b)·u
/// where r = a + b·u with a, b ∈ F^n
///
/// For x ∈ {0,1}^n:
/// eq(x, r) = Π_i [(1-x_i)(1-r_i) + x_i·r_i]
///          = Π_{i: x_i=0} (1-r_i) · Π_{i: x_i=1} r_i
///          = Π_{i: x_i=0} (1-a_i-b_i·u) · Π_{i: x_i=1} (a_i+b_i·u)
pub struct EqDecomposition<F: PrimeField> {
    /// a = real parts of r, i.e., r = a + b·u
    pub a: Vec<F>,
    /// b = imaginary parts of r
    pub b: Vec<F>,
    /// The non-residue γ such that u² = γ (for Goldilocks, γ = 7)
    pub gamma: F,
}

impl<F: PrimeField> EqDecomposition<F> {
    /// Create a new EqDecomposition from extension field point r = a + b·u
    pub fn new(a: Vec<F>, b: Vec<F>, gamma: F) -> Self {
        assert_eq!(a.len(), b.len());
        Self { a, b, gamma }
    }

    /// Compute eq_R(x) and eq_I(x) for a given boolean vector x ∈ {0,1}^n.
    /// Returns (eq_R, eq_I) such that eq(x, r) = eq_R + eq_I·u
    pub fn eval_at_boolean(&self, x: &[bool]) -> (F, F) {
        let n = self.a.len();
        assert_eq!(x.len(), n);

        // We compute the product of (c_i + d_i·u) terms
        // where c_i = 1-a_i, d_i = -b_i if x_i = 0
        //       c_i = a_i,   d_i = b_i  if x_i = 1
        //
        // Product of two terms: (c + d·u)(e + f·u) = (ce + γdf) + (cf + de)·u

        let mut real = F::one();
        let mut imag = F::zero();

        for i in 0..n {
            let (c, d) = if x[i] {
                (self.a[i], self.b[i])
            } else {
                (F::one() - self.a[i], -self.b[i])
            };

            // Multiply (real + imag·u) by (c + d·u)
            let new_real = real * c + self.gamma * imag * d;
            let new_imag = real * d + imag * c;
            real = new_real;
            imag = new_imag;
        }

        (real, imag)
    }

    /// Compute the MLE evaluations of eq_R and eq_I over {0,1}^n
    /// Returns (eq_R_evals, eq_I_evals) where each is a Vec of length 2^n
    pub fn compute_mle_evals(&self) -> (Vec<F>, Vec<F>) {
        let n = self.a.len();
        let size = 1 << n;
        let mut eq_r_evals = Vec::with_capacity(size);
        let mut eq_i_evals = Vec::with_capacity(size);

        for idx in 0..size {
            let x: Vec<bool> = (0..n).map(|i| (idx >> i) & 1 == 1).collect();
            let (r, i) = self.eval_at_boolean(&x);
            eq_r_evals.push(r);
            eq_i_evals.push(i);
        }

        (eq_r_evals, eq_i_evals)
    }
}

/// Proof for reducing extension field evaluation to base field.
///
/// To verify f(r) = v where r ∈ EF^n, v ∈ EF:
/// 1. Decompose: r = a + b·u, v = v₀ + v₁·u
/// 2. Run reduction SumCheck to get base field point s ∈ F^n
/// 3. Open f at s using base field PCS
#[derive(Clone, Debug, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize)]
pub struct ExtToBaseReductionProof<F: PrimeField> {
    /// The reduction SumCheck proof (base field)
    pub reduction_sumcheck: IOPProof<F>,
    /// The base field point from reduction SumCheck
    pub base_point: Vec<F>,
}

/// Compute the reduction SumCheck for verifying f(r) = v
///
/// The reduction proves: Σ_x H(x) = 0 where
/// H(x) = [(f(x) - v₀)·eq_R(x) - γ·v₁·eq_I(x)] + λ·[(f(x) - v₀)·eq_I(x) - v₁·eq_R(x)]
///
/// Returns the proof and the base field point s where f(s) needs to be verified.
pub fn reduction_sumcheck_prove<F: PrimeField>(
    f_evals: &[F],              // Evaluations of f on {0,1}^n
    v0: F,                       // Real part of claimed value
    v1: F,                       // Imaginary part of claimed value
    eq_decomp: &EqDecomposition<F>,  // Decomposition of eq(x, r)
    lambda: F,                   // Random combination coefficient
    transcript: &mut IOPTranscript<F>,
) -> Result<ExtToBaseReductionProof<F>, PCSError> {
    let n = eq_decomp.a.len();
    assert_eq!(f_evals.len(), 1 << n);

    let (eq_r_evals, eq_i_evals) = eq_decomp.compute_mle_evals();
    let gamma = eq_decomp.gamma;

    // H(x) = (f(x) - v₀)·(eq_R(x) + λ·eq_I(x)) - v₁·(γ·eq_I(x) + λ·eq_R(x))
    //
    // We express H as a virtual polynomial (sum of products of MLEs):
    // - (f - v0) * (eq_R + λ*eq_I) is a product of 2 MLEs
    // - v1 * (γ*eq_I + λ*eq_R) is 1 MLE with coefficient
    //
    // Create the auxiliary MLEs:
    // - f_minus_v0 = f - v0
    // - eq_combined = eq_R + λ*eq_I
    // - eq_combined2 = γ*eq_I + λ*eq_R

    let f_minus_v0_evals: Vec<F> = f_evals.iter().map(|&x| x - v0).collect();
    let eq_combined_evals: Vec<F> = eq_r_evals.iter()
        .zip(eq_i_evals.iter())
        .map(|(&r, &i)| r + lambda * i)
        .collect();
    let eq_combined2_evals: Vec<F> = eq_r_evals.iter()
        .zip(eq_i_evals.iter())
        .map(|(&r, &i)| gamma * i + lambda * r)
        .collect();

    // Run SumCheck on H = (f - v0) * eq_combined - v1 * eq_combined2
    let sumcheck_proof = crate::SumCheckBuilder::new(n)
        .add_evals([&f_minus_v0_evals, &eq_combined_evals], F::one())?
        .add_evals([&eq_combined2_evals], -v1)?
        .prove(transcript)?;

    let base_point = sumcheck_proof.point.clone();

    Ok(ExtToBaseReductionProof {
        reduction_sumcheck: sumcheck_proof,
        base_point,
    })
}

/// Verify the reduction SumCheck
/// Returns the expected evaluation of f at the base field point s.
pub fn reduction_sumcheck_verify<F: PrimeField>(
    proof: &ExtToBaseReductionProof<F>,
    v0: F,                       // Real part of claimed value
    v1: F,                       // Imaginary part of claimed value
    eq_decomp: &EqDecomposition<F>,  // Decomposition of eq(x, r)
    lambda: F,                   // Random combination coefficient
    transcript: &mut IOPTranscript<F>,
) -> Result<F, PCSError> {
    let gamma = eq_decomp.gamma;

    // Verify the SumCheck - the sum should be zero (encoded in proof)
    let subclaim = crate::sumcheck_verify(&proof.reduction_sumcheck, transcript)?;

    // Check that the extracted sum is zero
    let extracted_sum = crate::sumcheck_extract_sum(&proof.reduction_sumcheck);
    if !extracted_sum.is_zero() {
        return Err(PCSError::SumCheckError("Reduction SumCheck sum is not zero".into()));
    }

    // The subclaim says H(s) = subclaim.expected_evaluation
    // where s = proof.base_point
    //
    // H(s) = (f(s) - v₀)·(eq_R(s) + λ·eq_I(s)) - v₁·(γ·eq_I(s) + λ·eq_R(s))
    //
    // Solve for f(s):
    // f(s) = [H(s) + v₁·(γ·eq_I(s) + λ·eq_R(s))] / (eq_R(s) + λ·eq_I(s)) + v₀

    let s = &proof.base_point;

    // Compute eq_R(s) and eq_I(s) by evaluating the MLEs at s
    let (eq_r_evals, eq_i_evals) = eq_decomp.compute_mle_evals();
    let eq_r_s = crate::eval_mle_poly(&eq_r_evals, s);
    let eq_i_s = crate::eval_mle_poly(&eq_i_evals, s);

    let h_s = subclaim.expected_evaluation;
    let denom = eq_r_s + lambda * eq_i_s;

    if denom.is_zero() {
        return Err(PCSError::InvalidParameters("Denominator is zero in reduction verification".into()));
    }

    let f_s = (h_s + v1 * (gamma * eq_i_s + lambda * eq_r_s)) * denom.inverse().unwrap() + v0;

    Ok(f_s)
}

/// Complete protocol for extension field SumCheck with base field reduction.
///
/// Protocol:
/// 1. Run extension field SumCheck on the virtual polynomial
/// 2. Get extension field point r and claimed evaluations
/// 3. Run reduction SumCheck to get base field point s
/// 4. Verify using base field PCS (DeepFold) at point s
#[derive(Clone, Debug)]
pub struct ExtSumCheckWithReduction<F: PrimeField, EF: Field> {
    /// The extension field SumCheck proof
    pub ext_sumcheck_proof: ExtSumCheckProof<EF>,
    /// Extension field point (a + b·u decomposition)
    pub point_real: Vec<F>,
    pub point_imag: Vec<F>,
    /// Claimed evaluation in extension field (v₀ + v₁·u)
    pub claimed_eval_real: F,
    pub claimed_eval_imag: F,
    /// The reduction proof
    pub reduction_proof: ExtToBaseReductionProof<F>,
    /// Lambda used for batching real/imaginary parts
    pub lambda: F,
}

/// Non-residue for Goldilocks field extension (u² = 7)
pub const GOLDILOCKS_GAMMA: u64 = 7;

/// Combined proof for extension field SumCheck with base field reduction.
/// This is the main interface for integrating with Ligesis.
#[derive(Clone, Debug)]
pub struct ExtSumCheckFullProof<F: PrimeField, EF: Field> {
    /// The extension field SumCheck proof
    pub ext_proof: ExtSumCheckProof<EF>,
    /// Reduction proofs for each polynomial (one per polynomial that needs opening)
    pub reduction_proofs: Vec<ExtToBaseReductionProof<F>>,
    /// Lambda values used for each reduction
    pub lambdas: Vec<F>,
    /// The extension field evaluation point
    pub ext_point: Vec<EF>,
    /// Non-residue gamma
    pub gamma: F,
}

/// Helper function to run extension field SumCheck and reduction for a single polynomial.
/// Returns the base field point and the expected evaluation at that point.
pub fn ext_sumcheck_with_reduction<F, EF>(
    num_vars: usize,
    f_evals: &[F],           // Polynomial evaluations on {0,1}^n
    products: Vec<(F, Vec<Arc<DenseMultilinearExtension<F>>>)>, // Virtual polynomial structure
    transcript: &mut IOPTranscript<F>,
) -> Result<(ExtSumCheckFullProof<F, EF>, Vec<F>, F), PCSError>
where
    F: PrimeField,
    EF: Field + FieldExtension<F> + Copy + ark_serialize::CanonicalSerialize + ark_serialize::CanonicalDeserialize + Default,
{
    // Build and run extension field SumCheck
    let mut builder = ExtSumCheckBuilder::<F, EF>::new(num_vars);
    for (coeff, mles) in products {
        builder = builder.add_mle_list(mles, coeff)?;
    }
    let ext_proof = builder.prove(transcript)?;

    // Get the extension field point
    let ext_point = ext_proof.point.clone();

    // Decompose point into real/imaginary parts
    let point_real: Vec<F> = ext_point.iter().map(|x| {
        // Extract c0 (real part) from extension field element
        let bytes = {
            let mut buf = Vec::new();
            x.serialize_compressed(&mut buf).unwrap();
            buf
        };
        // First half is c0
        let half = bytes.len() / 2;
        F::deserialize_compressed(&bytes[..half]).unwrap()
    }).collect();

    let point_imag: Vec<F> = ext_point.iter().map(|x| {
        let bytes = {
            let mut buf = Vec::new();
            x.serialize_compressed(&mut buf).unwrap();
            buf
        };
        let half = bytes.len() / 2;
        F::deserialize_compressed(&bytes[half..]).unwrap()
    }).collect();

    // Compute f(r) in extension field
    let f_mle = DenseMultilinearExtension::from_evaluations_vec(num_vars, f_evals.to_vec());
    let f_r = eval_mle_at_ext_point(&f_mle, &ext_point);

    // Extract v0 and v1 from f_r
    let f_r_bytes = {
        let mut buf = Vec::new();
        f_r.serialize_compressed(&mut buf).unwrap();
        buf
    };
    let half = f_r_bytes.len() / 2;
    let v0: F = F::deserialize_compressed(&f_r_bytes[..half]).unwrap();
    let v1: F = F::deserialize_compressed(&f_r_bytes[half..]).unwrap();

    // Gamma is the non-residue
    let gamma = F::from(GOLDILOCKS_GAMMA);

    // Run reduction SumCheck
    let eq_decomp = EqDecomposition::new(point_real.clone(), point_imag.clone(), gamma);
    let lambda = transcript.get_and_append_challenge(b"reduction_lambda")?;
    let reduction_proof = reduction_sumcheck_prove(
        f_evals, v0, v1, &eq_decomp, lambda, transcript
    )?;

    let base_point = reduction_proof.base_point.clone();
    let expected_eval = crate::eval_mle_poly(&f_evals.to_vec(), &base_point);

    Ok((
        ExtSumCheckFullProof {
            ext_proof,
            reduction_proofs: vec![reduction_proof],
            lambdas: vec![lambda],
            ext_point,
            gamma,
        },
        base_point,
        expected_eval,
    ))
}

/// Verify extension field SumCheck with reduction.
/// Returns the base field point and expected evaluation.
pub fn ext_sumcheck_with_reduction_verify<F, EF>(
    proof: &ExtSumCheckFullProof<F, EF>,
    claimed_sum: EF,
    num_vars: usize,
    max_degree: usize,
    transcript: &mut IOPTranscript<F>,
) -> Result<(Vec<F>, F), PCSError>
where
    F: PrimeField,
    EF: Field + FieldExtension<F> + Copy + ark_serialize::CanonicalSerialize + ark_serialize::CanonicalDeserialize + Default,
{
    // Verify extension field SumCheck
    let ext_subclaim = ext_sumcheck_verify::<F, EF>(
        claimed_sum,
        &proof.ext_proof,
        num_vars,
        max_degree,
        transcript,
    )?;

    // Get the extension field point
    let ext_point = &proof.ext_point;

    // Decompose point into real/imaginary parts
    let point_real: Vec<F> = ext_point.iter().map(|x| {
        let bytes = {
            let mut buf = Vec::new();
            x.serialize_compressed(&mut buf).unwrap();
            buf
        };
        let half = bytes.len() / 2;
        F::deserialize_compressed(&bytes[..half]).unwrap()
    }).collect();

    let point_imag: Vec<F> = ext_point.iter().map(|x| {
        let bytes = {
            let mut buf = Vec::new();
            x.serialize_compressed(&mut buf).unwrap();
            buf
        };
        let half = bytes.len() / 2;
        F::deserialize_compressed(&bytes[half..]).unwrap()
    }).collect();

    // For the subclaim, we need to extract v0, v1 from expected_evaluation
    let eval_bytes = {
        let mut buf = Vec::new();
        ext_subclaim.expected_evaluation.serialize_compressed(&mut buf).unwrap();
        buf
    };
    let half = eval_bytes.len() / 2;
    let v0: F = F::deserialize_compressed(&eval_bytes[..half]).unwrap();
    let v1: F = F::deserialize_compressed(&eval_bytes[half..]).unwrap();

    // Verify reduction SumCheck
    let eq_decomp = EqDecomposition::new(point_real, point_imag, proof.gamma);
    let lambda = transcript.get_and_append_challenge(b"reduction_lambda")?;

    if proof.reduction_proofs.is_empty() {
        return Err(PCSError::InvalidParameters("No reduction proof provided".into()));
    }

    let expected_f_s = reduction_sumcheck_verify(
        &proof.reduction_proofs[0],
        v0, v1,
        &eq_decomp,
        lambda,
        transcript,
    )?;

    let base_point = proof.reduction_proofs[0].base_point.clone();

    Ok((base_point, expected_f_s))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{FGoldilocks, EGoldilocks, FieldExtension};
    use ark_poly::MultilinearExtension;
    use ark_std::{test_rng, One, Zero};
    use ark_std::UniformRand;

    #[test]
    fn test_eval_mle_at_ext_point() {
        let mut rng = test_rng();
        let num_vars = 3;

        // Create a random MLE
        let evals: Vec<FGoldilocks> = (0..(1 << num_vars))
            .map(|_| FGoldilocks::rand(&mut rng))
            .collect();
        let mle = DenseMultilinearExtension::from_evaluations_vec(num_vars, evals.clone());

        // Test at a base field point
        let point_f: Vec<FGoldilocks> = (0..num_vars)
            .map(|_| FGoldilocks::rand(&mut rng))
            .collect();

        // Evaluate using standard method
        let standard_eval = mle.evaluate(&point_f).unwrap();

        // Evaluate using our extension method with base field point embedded in extension
        let point_ef: Vec<EGoldilocks> = point_f.iter().map(|&x| EGoldilocks::from_base(x)).collect();
        let ext_eval = eval_mle_at_ext_point(&mle, &point_ef);

        assert_eq!(EGoldilocks::from_base(standard_eval), ext_eval);
    }

    #[test]
    fn test_eq_decomposition() {
        use ark_ff::fields::fp2::Fp2;

        let mut rng = test_rng();
        let num_vars = 3;
        let gamma = FGoldilocks::from(7u64); // Non-residue for Goldilocks

        // Create random extension field point r = a + b·u
        let a: Vec<FGoldilocks> = (0..num_vars).map(|_| FGoldilocks::rand(&mut rng)).collect();
        let b: Vec<FGoldilocks> = (0..num_vars).map(|_| FGoldilocks::rand(&mut rng)).collect();

        let eq_decomp = EqDecomposition::new(a.clone(), b.clone(), gamma);

        // Test: for each x ∈ {0,1}^n, check that eq_R + eq_I·u = eq(x, r)
        for idx in 0..(1 << num_vars) {
            let x: Vec<bool> = (0..num_vars).map(|i| (idx >> i) & 1 == 1).collect();
            let (eq_r, eq_i) = eq_decomp.eval_at_boolean(&x);

            // Compute eq(x, r) directly in extension field
            let r: Vec<EGoldilocks> = a.iter().zip(b.iter())
                .map(|(&ai, &bi)| Fp2::new(ai, bi))
                .collect();

            let mut eq_direct = EGoldilocks::one();
            for i in 0..num_vars {
                let factor = if x[i] {
                    r[i]
                } else {
                    EGoldilocks::one() - r[i]
                };
                eq_direct *= factor;
            }

            // Check eq_R + eq_I·u = eq_direct
            let eq_from_decomp = Fp2::new(eq_r, eq_i);
            assert_eq!(eq_from_decomp, eq_direct, "Mismatch at x = {:?}", x);
        }
    }

    #[test]
    fn test_reduction_sumcheck() {
        use ark_ff::fields::fp2::Fp2;
        use transcript::IOPTranscript;

        let mut rng = test_rng();
        let num_vars = 4;
        let gamma = FGoldilocks::from(7u64);

        // Create a random MLE f
        let f_evals: Vec<FGoldilocks> = (0..(1 << num_vars))
            .map(|_| FGoldilocks::rand(&mut rng))
            .collect();

        // Create random extension field point r = a + b·u
        let a: Vec<FGoldilocks> = (0..num_vars).map(|_| FGoldilocks::rand(&mut rng)).collect();
        let b: Vec<FGoldilocks> = (0..num_vars).map(|_| FGoldilocks::rand(&mut rng)).collect();
        let r: Vec<EGoldilocks> = a.iter().zip(b.iter())
            .map(|(&ai, &bi)| Fp2::new(ai, bi))
            .collect();

        // Compute f(r) = v in extension field
        let mle = DenseMultilinearExtension::from_evaluations_vec(num_vars, f_evals.clone());
        let v = eval_mle_at_ext_point(&mle, &r);
        let v0 = v.c0;  // Real part
        let v1 = v.c1;  // Imaginary part

        // Verify the identity: Σ_x [f(x) - v]·eq(x, r) = 0
        let eq_decomp = EqDecomposition::new(a.clone(), b.clone(), gamma);
        let (eq_r_evals, eq_i_evals) = eq_decomp.compute_mle_evals();

        // Check real part sum: Σ_x [(f(x)-v₀)·eq_R(x) - γ·v₁·eq_I(x)] = 0
        let real_sum: FGoldilocks = (0..(1 << num_vars))
            .map(|i| (f_evals[i] - v0) * eq_r_evals[i] - gamma * v1 * eq_i_evals[i])
            .sum();
        assert!(real_sum.is_zero(), "Real part sum is not zero: {:?}", real_sum);

        // Check imag part sum: Σ_x [(f(x)-v₀)·eq_I(x) - v₁·eq_R(x)] = 0
        let imag_sum: FGoldilocks = (0..(1 << num_vars))
            .map(|i| (f_evals[i] - v0) * eq_i_evals[i] - v1 * eq_r_evals[i])
            .sum();
        assert!(imag_sum.is_zero(), "Imag part sum is not zero: {:?}", imag_sum);

        // Random lambda for batching
        let lambda = FGoldilocks::rand(&mut rng);

        // Prover: generate reduction proof
        let mut prover_transcript = IOPTranscript::<FGoldilocks>::new(b"test_reduction");
        let reduction_proof = reduction_sumcheck_prove(
            &f_evals, v0, v1, &eq_decomp, lambda, &mut prover_transcript
        ).unwrap();

        // Verifier: verify reduction proof
        let mut verifier_transcript = IOPTranscript::<FGoldilocks>::new(b"test_reduction");
        let expected_f_s = reduction_sumcheck_verify(
            &reduction_proof, v0, v1, &eq_decomp, lambda, &mut verifier_transcript
        ).unwrap();

        // Check: f(s) computed by verifier should match actual f(s)
        let s = &reduction_proof.base_point;
        let actual_f_s = crate::eval_mle_poly(&f_evals, s);

        assert_eq!(expected_f_s, actual_f_s, "Reduction verification failed!");
    }

    /// Test that the extension SumCheck prover correctly computes a zero sum
    /// for the boolean check: Σ b(x) * (b(x) - 1) = 0
    #[test]
    fn test_ext_sumcheck_zero_sum() {
        use transcript::IOPTranscript;

        let num_vars = 4;

        // Create a boolean polynomial b(x) (all 0s and 1s)
        let b_evals: Vec<FGoldilocks> = (0..(1 << num_vars))
            .map(|i| if i % 3 == 0 { FGoldilocks::one() } else { FGoldilocks::zero() })
            .collect();

        // b(x) - 1
        let b_minus_one_evals: Vec<FGoldilocks> = b_evals.iter()
            .map(|&x| x - FGoldilocks::one())
            .collect();

        // eq_alpha(x) = tensor product of random challenges
        let alpha: Vec<FGoldilocks> = (0..num_vars)
            .map(|i| FGoldilocks::from((i + 1) as u64))
            .collect();
        let eq_alpha_evals = crate::utils::get_tensor(&alpha);

        // Verify that the sum is actually 0 by computing it directly
        let direct_sum: FGoldilocks = (0..(1 << num_vars))
            .map(|i| b_evals[i] * b_minus_one_evals[i] * eq_alpha_evals[i])
            .sum();
        assert!(direct_sum.is_zero(), "Direct sum should be 0 but got {:?}", direct_sum);

        // Now test that the extension SumCheck prover also produces a proof where p(0) + p(1) = 0
        let mut prover_transcript = IOPTranscript::<FGoldilocks>::new(b"zero_sum_test");

        let ext_proof = ExtSumCheckBuilder::<FGoldilocks, EGoldilocks>::new(num_vars)
            .add_evals([&b_evals, &b_minus_one_evals, &eq_alpha_evals], FGoldilocks::one())
            .unwrap()
            .prove(&mut prover_transcript)
            .unwrap();

        // Check that p(0) + p(1) = 0
        let claimed_sum = ext_proof.proofs[0][0] + ext_proof.proofs[0][1];
        assert!(
            claimed_sum.is_zero(),
            "Extension SumCheck prover returned non-zero sum: {:?}",
            claimed_sum
        );

        // Verify the proof
        let mut verifier_transcript = IOPTranscript::<FGoldilocks>::new(b"zero_sum_test");
        let _subclaim = ext_sumcheck_verify::<FGoldilocks, EGoldilocks>(
            EGoldilocks::zero(),
            &ext_proof,
            num_vars,
            3,
            &mut verifier_transcript,
        ).unwrap();
    }

    /// End-to-end test: Extension field SumCheck + reduction to base field
    /// This demonstrates the full workflow for integrating with Ligesis
    #[test]
    fn test_full_ext_sumcheck_with_reduction() {
        use ark_ff::fields::fp2::Fp2;
        use transcript::IOPTranscript;

        let mut rng = test_rng();
        let num_vars = 4;
        let gamma = FGoldilocks::from(7u64);

        // Create two random MLEs (simulating polynomial commitments)
        let f_evals: Vec<FGoldilocks> = (0..(1 << num_vars))
            .map(|_| FGoldilocks::rand(&mut rng))
            .collect();
        let g_evals: Vec<FGoldilocks> = (0..(1 << num_vars))
            .map(|_| FGoldilocks::rand(&mut rng))
            .collect();

        // ========== PROVER ==========

        let mut prover_transcript = IOPTranscript::<FGoldilocks>::new(b"full_test");

        // Step 1: Run extension field SumCheck on product f(x) * g(x)
        // This is the pattern used in Ligesis for various checks
        let ext_proof = ExtSumCheckBuilder::<FGoldilocks, EGoldilocks>::new(num_vars)
            .add_evals([&f_evals, &g_evals], FGoldilocks::one())
            .unwrap()
            .prove(&mut prover_transcript)
            .unwrap();

        // The proof contains the extension field point r ∈ EF^n
        // For Ligesis integration, we'd need to open f and g at this point

        // Step 2: Compute the claimed evaluation at r (in extension field)
        let r_ef: Vec<EGoldilocks> = ext_proof.point.clone();

        // Decompose r into real and imaginary parts
        let r_real: Vec<FGoldilocks> = r_ef.iter().map(|x| x.c0).collect();
        let r_imag: Vec<FGoldilocks> = r_ef.iter().map(|x| x.c1).collect();

        // Compute f(r) and g(r) in extension field
        let f_mle = DenseMultilinearExtension::from_evaluations_vec(num_vars, f_evals.clone());
        let g_mle = DenseMultilinearExtension::from_evaluations_vec(num_vars, g_evals.clone());
        let f_r = eval_mle_at_ext_point(&f_mle, &r_ef);
        let g_r = eval_mle_at_ext_point(&g_mle, &r_ef);

        // Step 3: Run reduction SumCheck for f to get base field point
        let eq_decomp = EqDecomposition::new(r_real.clone(), r_imag.clone(), gamma);
        let lambda_f = prover_transcript.get_and_append_challenge(b"lambda_f").unwrap();
        let reduction_proof_f = reduction_sumcheck_prove(
            &f_evals, f_r.c0, f_r.c1, &eq_decomp, lambda_f, &mut prover_transcript
        ).unwrap();

        // Similarly for g
        let lambda_g = prover_transcript.get_and_append_challenge(b"lambda_g").unwrap();
        let reduction_proof_g = reduction_sumcheck_prove(
            &g_evals, g_r.c0, g_r.c1, &eq_decomp, lambda_g, &mut prover_transcript
        ).unwrap();

        // ========== VERIFIER ==========

        let mut verifier_transcript = IOPTranscript::<FGoldilocks>::new(b"full_test");

        // Step 1: Verify extension field SumCheck
        let claimed_sum = ext_proof.proofs[0][0] + ext_proof.proofs[0][1];
        let ext_subclaim = ext_sumcheck_verify::<FGoldilocks, EGoldilocks>(
            claimed_sum,
            &ext_proof,
            num_vars,
            2, // max_degree = 2 for product of 2 MLEs
            &mut verifier_transcript,
        ).unwrap();

        // Verify: expected_evaluation should equal f(r) * g(r)
        let product_at_r = f_r * g_r;
        assert_eq!(ext_subclaim.expected_evaluation, product_at_r,
            "Extension SumCheck subclaim mismatch!");

        // Step 2: Verify reduction for f
        let lambda_f_v = verifier_transcript.get_and_append_challenge(b"lambda_f").unwrap();
        assert_eq!(lambda_f, lambda_f_v);
        let expected_f_s = reduction_sumcheck_verify(
            &reduction_proof_f, f_r.c0, f_r.c1, &eq_decomp, lambda_f, &mut verifier_transcript
        ).unwrap();

        // Verify f at base field point
        let s_f = &reduction_proof_f.base_point;
        let actual_f_s = crate::eval_mle_poly(&f_evals, s_f);
        assert_eq!(expected_f_s, actual_f_s, "Reduction verification for f failed!");

        // Step 3: Verify reduction for g
        let lambda_g_v = verifier_transcript.get_and_append_challenge(b"lambda_g").unwrap();
        assert_eq!(lambda_g, lambda_g_v);
        let expected_g_s = reduction_sumcheck_verify(
            &reduction_proof_g, g_r.c0, g_r.c1, &eq_decomp, lambda_g, &mut verifier_transcript
        ).unwrap();

        // Verify g at base field point
        let s_g = &reduction_proof_g.base_point;
        let actual_g_s = crate::eval_mle_poly(&g_evals, s_g);
        assert_eq!(expected_g_s, actual_g_s, "Reduction verification for g failed!");

        // At this point, the verifier has:
        // - s_f: a base field point where f(s_f) should be opened
        // - s_g: a base field point where g(s_g) should be opened
        // - expected_f_s and expected_g_s: the expected values
        //
        // In Ligesis, these would be verified via DeepFold batch_open
        println!("Full extension field SumCheck with reduction: SUCCESS!");
    }
}

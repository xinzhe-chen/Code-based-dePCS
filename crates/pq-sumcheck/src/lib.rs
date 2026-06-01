use pq_core::{CoreError, FieldElement, MultilinearPolynomial, eq_eval, eq_evaluations};
use pq_transcript::{HashTranscript, Transcript};

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SumcheckError {
    Core(CoreError),
    InvalidClaim,
    InvalidProof,
    ZeroDenominator,
    LengthMismatch,
}

impl From<CoreError> for SumcheckError {
    fn from(value: CoreError) -> Self {
        Self::Core(value)
    }
}

pub type SumcheckResult<T> = Result<T, SumcheckError>;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RoundPolynomial {
    pub eval_at_0: FieldElement,
    pub eval_at_1: FieldElement,
}

impl RoundPolynomial {
    pub fn evaluate(&self, x: FieldElement) -> FieldElement {
        self.eval_at_0 * (FieldElement::ONE - x) + self.eval_at_1 * x
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SumcheckProof {
    pub claimed_sum: FieldElement,
    pub rounds: Vec<RoundPolynomial>,
    pub challenges: Vec<FieldElement>,
    pub final_evaluation: FieldElement,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QuadraticRoundPolynomial {
    pub eval_at_0: FieldElement,
    pub eval_at_1: FieldElement,
    pub eval_at_2: FieldElement,
}

impl QuadraticRoundPolynomial {
    pub fn evaluate(&self, x: FieldElement) -> FieldElement {
        let two = FieldElement::from(2_u64);
        let two_inv = two.inverse().expect("two is non-zero in Goldilocks");
        let l0 = (x - FieldElement::ONE) * (x - two) * two_inv;
        let l1 = FieldElement::ZERO - x * (x - two);
        let l2 = x * (x - FieldElement::ONE) * two_inv;
        self.eval_at_0 * l0 + self.eval_at_1 * l1 + self.eval_at_2 * l2
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CubicRoundPolynomial {
    pub eval_at_0: FieldElement,
    pub eval_at_1: FieldElement,
    pub eval_at_2: FieldElement,
    pub eval_at_3: FieldElement,
}

impl CubicRoundPolynomial {
    pub fn evaluate(&self, x: FieldElement) -> FieldElement {
        lagrange_eval_small_domain(
            x,
            &[
                self.eval_at_0,
                self.eval_at_1,
                self.eval_at_2,
                self.eval_at_3,
            ],
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CubicZerocheckProof {
    pub eq_point: Vec<FieldElement>,
    pub claimed_sum: FieldElement,
    pub rounds: Vec<CubicRoundPolynomial>,
    pub challenges: Vec<FieldElement>,
    pub final_evaluation: FieldElement,
}

pub fn prove_sumcheck<T: Transcript>(
    poly: &MultilinearPolynomial,
    transcript: &mut T,
) -> SumcheckResult<SumcheckProof> {
    transcript.absorb_domain(b"sumcheck-v1");
    absorb_polynomial(poly, transcript);
    let claimed_sum = poly.sum_over_boolean_hypercube();
    transcript.absorb_field(b"claimed-sum", claimed_sum);

    let mut current = poly.clone();
    let mut rounds = Vec::with_capacity(poly.num_vars());
    let mut challenges = Vec::with_capacity(poly.num_vars());
    for round in 0..poly.num_vars() {
        let mut eval_at_0 = FieldElement::ZERO;
        let mut eval_at_1 = FieldElement::ZERO;
        for pair in current.evaluations().chunks_exact(2) {
            eval_at_0 += pair[0];
            eval_at_1 += pair[1];
        }
        let round_poly = RoundPolynomial {
            eval_at_0,
            eval_at_1,
        };
        transcript.absorb_field(b"round-0", round_poly.eval_at_0);
        transcript.absorb_field(b"round-1", round_poly.eval_at_1);
        transcript.absorb_public(b"round-index", &(round as u64).to_le_bytes());
        let challenge = transcript.challenge_field::<FieldElement>(b"sumcheck-round");
        current = current.fix_first_variable(challenge)?;
        rounds.push(round_poly);
        challenges.push(challenge);
    }
    let final_evaluation = current.evaluations()[0];
    transcript.absorb_field(b"final-eval", final_evaluation);
    Ok(SumcheckProof {
        claimed_sum,
        rounds,
        challenges,
        final_evaluation,
    })
}

pub fn verify_sumcheck<T: Transcript>(
    poly: &MultilinearPolynomial,
    proof: &SumcheckProof,
    transcript: &mut T,
) -> SumcheckResult<()> {
    if proof.rounds.len() != poly.num_vars() || proof.challenges.len() != poly.num_vars() {
        return Err(SumcheckError::InvalidProof);
    }
    transcript.absorb_domain(b"sumcheck-v1");
    absorb_polynomial(poly, transcript);
    transcript.absorb_field(b"claimed-sum", proof.claimed_sum);
    if proof.claimed_sum != poly.sum_over_boolean_hypercube() {
        return Err(SumcheckError::InvalidClaim);
    }

    let mut expected = proof.claimed_sum;
    let mut verifier_challenges = Vec::with_capacity(poly.num_vars());
    for (round, round_poly) in proof.rounds.iter().enumerate() {
        if expected != round_poly.eval_at_0 + round_poly.eval_at_1 {
            return Err(SumcheckError::InvalidProof);
        }
        transcript.absorb_field(b"round-0", round_poly.eval_at_0);
        transcript.absorb_field(b"round-1", round_poly.eval_at_1);
        transcript.absorb_public(b"round-index", &(round as u64).to_le_bytes());
        let challenge = transcript.challenge_field::<FieldElement>(b"sumcheck-round");
        if proof.challenges[round] != challenge {
            return Err(SumcheckError::InvalidProof);
        }
        expected = round_poly.evaluate(challenge);
        verifier_challenges.push(challenge);
    }
    let direct = poly.evaluate(&verifier_challenges)?;
    if expected != proof.final_evaluation || direct != proof.final_evaluation {
        return Err(SumcheckError::InvalidProof);
    }
    transcript.absorb_field(b"final-eval", proof.final_evaluation);
    Ok(())
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DistributedSumcheckProof {
    pub workers: usize,
    pub local_sums: Vec<FieldElement>,
    pub aggregate: SumcheckProof,
}

pub fn prove_distributed_sumcheck<T: Transcript>(
    partitions: &[MultilinearPolynomial],
    transcript: &mut T,
) -> SumcheckResult<DistributedSumcheckProof> {
    if partitions.is_empty() {
        return Err(SumcheckError::LengthMismatch);
    }
    let len = partitions[0].evaluations().len();
    if partitions.iter().any(|p| p.evaluations().len() != len) {
        return Err(SumcheckError::LengthMismatch);
    }
    let mut aggregate = vec![FieldElement::ZERO; len];
    let mut local_sums = Vec::with_capacity(partitions.len());
    for partition in partitions {
        local_sums.push(partition.sum_over_boolean_hypercube());
        for (idx, value) in partition.evaluations().iter().copied().enumerate() {
            aggregate[idx] += value;
        }
    }
    transcript.absorb_domain(b"distributed-sumcheck-v1");
    transcript.absorb_public(b"workers", &(partitions.len() as u64).to_le_bytes());
    let aggregate_poly = MultilinearPolynomial::new(aggregate)?;
    let proof = prove_sumcheck(&aggregate_poly, transcript)?;
    Ok(DistributedSumcheckProof {
        workers: partitions.len(),
        local_sums,
        aggregate: proof,
    })
}

pub fn verify_distributed_sumcheck<T: Transcript>(
    partitions: &[MultilinearPolynomial],
    proof: &DistributedSumcheckProof,
    transcript: &mut T,
) -> SumcheckResult<()> {
    if proof.workers != partitions.len() || proof.local_sums.len() != partitions.len() {
        return Err(SumcheckError::InvalidProof);
    }
    let len = partitions
        .first()
        .ok_or(SumcheckError::LengthMismatch)?
        .evaluations()
        .len();
    let mut aggregate = vec![FieldElement::ZERO; len];
    let mut sum = FieldElement::ZERO;
    for (idx, partition) in partitions.iter().enumerate() {
        if partition.evaluations().len() != len {
            return Err(SumcheckError::LengthMismatch);
        }
        let local = partition.sum_over_boolean_hypercube();
        if proof.local_sums[idx] != local {
            return Err(SumcheckError::InvalidProof);
        }
        sum += local;
        for (item, value) in aggregate.iter_mut().zip(partition.evaluations()) {
            *item += *value;
        }
    }
    if sum != proof.aggregate.claimed_sum {
        return Err(SumcheckError::InvalidClaim);
    }
    transcript.absorb_domain(b"distributed-sumcheck-v1");
    transcript.absorb_public(b"workers", &(partitions.len() as u64).to_le_bytes());
    let aggregate_poly = MultilinearPolynomial::new(aggregate)?;
    verify_sumcheck(&aggregate_poly, &proof.aggregate, transcript)
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ZerocheckProof {
    pub eq_point: Vec<FieldElement>,
    pub claimed_sum: FieldElement,
    pub rounds: Vec<QuadraticRoundPolynomial>,
    pub challenges: Vec<FieldElement>,
    pub final_evaluation: FieldElement,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProductSumcheckProof {
    pub claimed_sum: FieldElement,
    pub rounds: Vec<QuadraticRoundPolynomial>,
    pub challenges: Vec<FieldElement>,
    pub final_evaluation: FieldElement,
}

pub fn prove_product_sumcheck<T: Transcript>(
    left: &MultilinearPolynomial,
    right: &MultilinearPolynomial,
    claimed_sum: FieldElement,
    transcript: &mut T,
) -> SumcheckResult<ProductSumcheckProof> {
    validate_pair_shape(left, right)?;
    transcript.absorb_domain(b"product-sumcheck-v1");
    transcript.absorb_public(b"num-vars", &(left.num_vars() as u64).to_le_bytes());
    transcript.absorb_public(
        b"eval-len",
        &(left.evaluations().len() as u64).to_le_bytes(),
    );
    transcript.absorb_field(b"claimed-sum", claimed_sum);
    if inner_product(left.evaluations(), right.evaluations()) != claimed_sum {
        return Err(SumcheckError::InvalidClaim);
    }

    let mut current_left = left.clone();
    let mut current_right = right.clone();
    let mut rounds = Vec::with_capacity(left.num_vars());
    let mut challenges = Vec::with_capacity(left.num_vars());
    for round in 0..left.num_vars() {
        let round_poly = product_round_polynomial(&current_left, &current_right);
        transcript.absorb_field(b"round-0", round_poly.eval_at_0);
        transcript.absorb_field(b"round-1", round_poly.eval_at_1);
        transcript.absorb_field(b"round-2", round_poly.eval_at_2);
        transcript.absorb_public(b"round-index", &(round as u64).to_le_bytes());
        let challenge = transcript.challenge_field::<FieldElement>(b"product-sumcheck-round");
        current_left = current_left.fix_first_variable(challenge)?;
        current_right = current_right.fix_first_variable(challenge)?;
        rounds.push(round_poly);
        challenges.push(challenge);
    }
    let final_evaluation = current_left.evaluations()[0] * current_right.evaluations()[0];
    transcript.absorb_field(b"final-eval", final_evaluation);

    Ok(ProductSumcheckProof {
        claimed_sum,
        rounds,
        challenges,
        final_evaluation,
    })
}

pub fn verify_product_sumcheck_rounds<T: Transcript>(
    num_vars: usize,
    claimed_sum: FieldElement,
    proof: &ProductSumcheckProof,
    transcript: &mut T,
) -> SumcheckResult<()> {
    if proof.rounds.len() != num_vars || proof.challenges.len() != num_vars {
        return Err(SumcheckError::InvalidProof);
    }
    transcript.absorb_domain(b"product-sumcheck-v1");
    transcript.absorb_public(b"num-vars", &(num_vars as u64).to_le_bytes());
    let eval_len = 1_usize
        .checked_shl(num_vars as u32)
        .ok_or(SumcheckError::LengthMismatch)?;
    transcript.absorb_public(b"eval-len", &(eval_len as u64).to_le_bytes());
    transcript.absorb_field(b"claimed-sum", proof.claimed_sum);
    if proof.claimed_sum != claimed_sum {
        return Err(SumcheckError::InvalidClaim);
    }

    let mut expected = proof.claimed_sum;
    for (round, round_poly) in proof.rounds.iter().enumerate() {
        if expected != round_poly.eval_at_0 + round_poly.eval_at_1 {
            return Err(SumcheckError::InvalidProof);
        }
        transcript.absorb_field(b"round-0", round_poly.eval_at_0);
        transcript.absorb_field(b"round-1", round_poly.eval_at_1);
        transcript.absorb_field(b"round-2", round_poly.eval_at_2);
        transcript.absorb_public(b"round-index", &(round as u64).to_le_bytes());
        let challenge = transcript.challenge_field::<FieldElement>(b"product-sumcheck-round");
        if proof.challenges[round] != challenge {
            return Err(SumcheckError::InvalidProof);
        }
        expected = round_poly.evaluate(challenge);
    }
    if expected != proof.final_evaluation {
        return Err(SumcheckError::InvalidProof);
    }
    transcript.absorb_field(b"final-eval", proof.final_evaluation);
    Ok(())
}

pub fn prove_zerocheck(poly: &MultilinearPolynomial) -> SumcheckResult<()> {
    if poly.evaluations().iter().all(|value| value.is_zero()) {
        Ok(())
    } else {
        Err(SumcheckError::InvalidClaim)
    }
}

pub fn prove_zerocheck_proof<T: Transcript>(
    poly: &MultilinearPolynomial,
    transcript: &mut T,
) -> SumcheckResult<ZerocheckProof> {
    transcript.absorb_domain(b"zerocheck-v2");
    transcript.absorb_public(b"num-vars", &(poly.num_vars() as u64).to_le_bytes());
    let eq_point = challenge_point(poly.num_vars(), transcript);
    let eqs = eq_evaluations(&eq_point)?;
    let claimed_sum = inner_product(poly.evaluations(), &eqs);
    transcript.absorb_field(b"claimed-sum", claimed_sum);
    if !claimed_sum.is_zero() {
        return Err(SumcheckError::InvalidClaim);
    }

    let eq_poly = MultilinearPolynomial::new(eqs)?;
    let mut current_poly = poly.clone();
    let mut current_eq = eq_poly;
    let mut rounds = Vec::with_capacity(poly.num_vars());
    let mut challenges = Vec::with_capacity(poly.num_vars());
    for round in 0..poly.num_vars() {
        let round_poly = product_round_polynomial(&current_poly, &current_eq);
        transcript.absorb_field(b"round-0", round_poly.eval_at_0);
        transcript.absorb_field(b"round-1", round_poly.eval_at_1);
        transcript.absorb_field(b"round-2", round_poly.eval_at_2);
        transcript.absorb_public(b"round-index", &(round as u64).to_le_bytes());
        let challenge = transcript.challenge_field::<FieldElement>(b"zerocheck-round");
        current_poly = current_poly.fix_first_variable(challenge)?;
        current_eq = current_eq.fix_first_variable(challenge)?;
        rounds.push(round_poly);
        challenges.push(challenge);
    }
    let final_evaluation = current_poly.evaluations()[0] * current_eq.evaluations()[0];
    transcript.absorb_field(b"final-eval", final_evaluation);

    Ok(ZerocheckProof {
        eq_point,
        claimed_sum,
        rounds,
        challenges,
        final_evaluation,
    })
}

pub fn verify_zerocheck_proof<T: Transcript>(
    poly: &MultilinearPolynomial,
    proof: &ZerocheckProof,
    transcript: &mut T,
) -> SumcheckResult<()> {
    verify_zerocheck_rounds(poly.num_vars(), proof, transcript)?;
    let opened_value = poly.evaluate(&proof.challenges)?;
    let expected_final = zerocheck_final_evaluation(proof, opened_value)?;
    if expected_final == proof.final_evaluation {
        Ok(())
    } else {
        Err(SumcheckError::InvalidProof)
    }
}

pub fn verify_zerocheck_rounds<T: Transcript>(
    num_vars: usize,
    proof: &ZerocheckProof,
    transcript: &mut T,
) -> SumcheckResult<()> {
    if proof.eq_point.len() != num_vars
        || proof.rounds.len() != num_vars
        || proof.challenges.len() != num_vars
    {
        return Err(SumcheckError::InvalidProof);
    }
    transcript.absorb_domain(b"zerocheck-v2");
    transcript.absorb_public(b"num-vars", &(num_vars as u64).to_le_bytes());
    let expected_eq_point = challenge_point(num_vars, transcript);
    if proof.eq_point != expected_eq_point {
        return Err(SumcheckError::InvalidProof);
    }
    transcript.absorb_field(b"claimed-sum", proof.claimed_sum);
    if !proof.claimed_sum.is_zero() {
        return Err(SumcheckError::InvalidClaim);
    }

    let mut expected = proof.claimed_sum;
    for (round, round_poly) in proof.rounds.iter().enumerate() {
        if expected != round_poly.eval_at_0 + round_poly.eval_at_1 {
            return Err(SumcheckError::InvalidProof);
        }
        transcript.absorb_field(b"round-0", round_poly.eval_at_0);
        transcript.absorb_field(b"round-1", round_poly.eval_at_1);
        transcript.absorb_field(b"round-2", round_poly.eval_at_2);
        transcript.absorb_public(b"round-index", &(round as u64).to_le_bytes());
        let challenge = transcript.challenge_field::<FieldElement>(b"zerocheck-round");
        if proof.challenges[round] != challenge {
            return Err(SumcheckError::InvalidProof);
        }
        expected = round_poly.evaluate(challenge);
    }
    if expected != proof.final_evaluation {
        return Err(SumcheckError::InvalidProof);
    }
    transcript.absorb_field(b"final-eval", proof.final_evaluation);
    Ok(())
}

pub fn zerocheck_final_evaluation(
    proof: &ZerocheckProof,
    opened_value: FieldElement,
) -> SumcheckResult<FieldElement> {
    Ok(opened_value * eq_eval(&proof.eq_point, &proof.challenges)?)
}

pub fn prove_cubic_zerocheck<T: Transcript>(
    left: &MultilinearPolynomial,
    right: &MultilinearPolynomial,
    output: &MultilinearPolynomial,
    transcript: &mut T,
) -> SumcheckResult<CubicZerocheckProof> {
    validate_same_shape(left, right, output)?;
    transcript.absorb_domain(b"cubic-zerocheck-v1");
    transcript.absorb_public(b"num-vars", &(left.num_vars() as u64).to_le_bytes());
    transcript.absorb_public(
        b"eval-len",
        &(left.evaluations().len() as u64).to_le_bytes(),
    );
    let eq_point = challenge_point_with_labels(
        left.num_vars(),
        transcript,
        b"cubic-eq-index",
        b"cubic-zerocheck-eq",
    );
    let eqs = eq_evaluations(&eq_point)?;
    let claimed_sum = left
        .evaluations()
        .iter()
        .zip(right.evaluations())
        .zip(output.evaluations())
        .zip(&eqs)
        .map(|(((left, right), output), eq)| *eq * (*left * *right - *output))
        .sum::<FieldElement>();
    transcript.absorb_field(b"claimed-sum", claimed_sum);
    if !claimed_sum.is_zero() {
        return Err(SumcheckError::InvalidClaim);
    }

    let mut current_left = left.clone();
    let mut current_right = right.clone();
    let mut current_output = output.clone();
    let mut current_eq = MultilinearPolynomial::new(eqs)?;
    let mut rounds = Vec::with_capacity(left.num_vars());
    let mut challenges = Vec::with_capacity(left.num_vars());
    for round in 0..left.num_vars() {
        let round_poly = cubic_relation_round_polynomial(
            &current_left,
            &current_right,
            &current_output,
            &current_eq,
        );
        transcript.absorb_field(b"round-0", round_poly.eval_at_0);
        transcript.absorb_field(b"round-1", round_poly.eval_at_1);
        transcript.absorb_field(b"round-2", round_poly.eval_at_2);
        transcript.absorb_field(b"round-3", round_poly.eval_at_3);
        transcript.absorb_public(b"round-index", &(round as u64).to_le_bytes());
        let challenge = transcript.challenge_field::<FieldElement>(b"cubic-zerocheck-round");
        current_left = current_left.fix_first_variable(challenge)?;
        current_right = current_right.fix_first_variable(challenge)?;
        current_output = current_output.fix_first_variable(challenge)?;
        current_eq = current_eq.fix_first_variable(challenge)?;
        rounds.push(round_poly);
        challenges.push(challenge);
    }
    let final_evaluation = current_eq.evaluations()[0]
        * (current_left.evaluations()[0] * current_right.evaluations()[0]
            - current_output.evaluations()[0]);
    transcript.absorb_field(b"final-eval", final_evaluation);

    Ok(CubicZerocheckProof {
        eq_point,
        claimed_sum,
        rounds,
        challenges,
        final_evaluation,
    })
}

pub fn verify_cubic_zerocheck_rounds<T: Transcript>(
    num_vars: usize,
    proof: &CubicZerocheckProof,
    transcript: &mut T,
) -> SumcheckResult<()> {
    if proof.eq_point.len() != num_vars
        || proof.rounds.len() != num_vars
        || proof.challenges.len() != num_vars
    {
        return Err(SumcheckError::InvalidProof);
    }
    transcript.absorb_domain(b"cubic-zerocheck-v1");
    transcript.absorb_public(b"num-vars", &(num_vars as u64).to_le_bytes());
    let eval_len = 1_usize
        .checked_shl(num_vars as u32)
        .ok_or(SumcheckError::LengthMismatch)?;
    transcript.absorb_public(b"eval-len", &(eval_len as u64).to_le_bytes());
    let expected_eq_point = challenge_point_with_labels(
        num_vars,
        transcript,
        b"cubic-eq-index",
        b"cubic-zerocheck-eq",
    );
    if proof.eq_point != expected_eq_point {
        return Err(SumcheckError::InvalidProof);
    }
    transcript.absorb_field(b"claimed-sum", proof.claimed_sum);
    if !proof.claimed_sum.is_zero() {
        return Err(SumcheckError::InvalidClaim);
    }
    let mut expected = proof.claimed_sum;
    for (round, round_poly) in proof.rounds.iter().enumerate() {
        if expected != round_poly.eval_at_0 + round_poly.eval_at_1 {
            return Err(SumcheckError::InvalidProof);
        }
        transcript.absorb_field(b"round-0", round_poly.eval_at_0);
        transcript.absorb_field(b"round-1", round_poly.eval_at_1);
        transcript.absorb_field(b"round-2", round_poly.eval_at_2);
        transcript.absorb_field(b"round-3", round_poly.eval_at_3);
        transcript.absorb_public(b"round-index", &(round as u64).to_le_bytes());
        let challenge = transcript.challenge_field::<FieldElement>(b"cubic-zerocheck-round");
        if proof.challenges[round] != challenge {
            return Err(SumcheckError::InvalidProof);
        }
        expected = round_poly.evaluate(challenge);
    }
    if expected != proof.final_evaluation {
        return Err(SumcheckError::InvalidProof);
    }
    transcript.absorb_field(b"final-eval", proof.final_evaluation);
    Ok(())
}

pub fn cubic_zerocheck_final_evaluation(
    proof: &CubicZerocheckProof,
    left_opened: FieldElement,
    right_opened: FieldElement,
    output_opened: FieldElement,
) -> SumcheckResult<FieldElement> {
    Ok(eq_eval(&proof.eq_point, &proof.challenges)? * (left_opened * right_opened - output_opened))
}

pub fn rational_sum(
    numerator: &[FieldElement],
    denominator: &[FieldElement],
) -> SumcheckResult<FieldElement> {
    if numerator.len() != denominator.len() {
        return Err(SumcheckError::LengthMismatch);
    }
    let mut sum = FieldElement::ZERO;
    for (p, q) in numerator.iter().zip(denominator) {
        let inv = q.inverse().ok_or(SumcheckError::ZeroDenominator)?;
        sum += *p * inv;
    }
    Ok(sum)
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RationalSumcheckProof {
    pub claimed_sum: FieldElement,
    pub len: usize,
    pub sumcheck: SumcheckProof,
    pub binding_challenge: FieldElement,
}

pub fn prove_rational_sumcheck(
    numerator: Vec<FieldElement>,
    denominator: Vec<FieldElement>,
) -> SumcheckResult<RationalSumcheckProof> {
    let mut transcript = HashTranscript::new(b"rational-sumcheck");
    prove_rational_sumcheck_with_transcript(&numerator, &denominator, &mut transcript)
}

pub fn prove_rational_sumcheck_with_transcript<T: Transcript>(
    numerator: &[FieldElement],
    denominator: &[FieldElement],
    transcript: &mut T,
) -> SumcheckResult<RationalSumcheckProof> {
    let len = numerator.len();
    let rational_evaluations = rational_evaluations(numerator, denominator)?;
    let rational_poly = MultilinearPolynomial::new(rational_evaluations)?;
    absorb_rational_statement(numerator, denominator, transcript);
    let sumcheck = prove_sumcheck(&rational_poly, transcript)?;
    let claimed_sum = sumcheck.claimed_sum;
    let binding_challenge = transcript.challenge_field::<FieldElement>(b"rational-binding");
    Ok(RationalSumcheckProof {
        claimed_sum,
        len,
        sumcheck,
        binding_challenge,
    })
}

pub fn verify_rational_sumcheck(
    numerator: &[FieldElement],
    denominator: &[FieldElement],
    claimed_sum: FieldElement,
    proof: &RationalSumcheckProof,
) -> SumcheckResult<()> {
    let mut transcript = HashTranscript::new(b"rational-sumcheck");
    verify_rational_sumcheck_with_transcript(
        numerator,
        denominator,
        claimed_sum,
        proof,
        &mut transcript,
    )
}

pub fn verify_rational_sumcheck_with_transcript<T: Transcript>(
    numerator: &[FieldElement],
    denominator: &[FieldElement],
    claimed_sum: FieldElement,
    proof: &RationalSumcheckProof,
    transcript: &mut T,
) -> SumcheckResult<()> {
    if proof.len != numerator.len()
        || proof.len != denominator.len()
        || proof.claimed_sum != claimed_sum
        || proof.sumcheck.claimed_sum != claimed_sum
    {
        return Err(SumcheckError::InvalidProof);
    }
    let rational_evaluations = rational_evaluations(numerator, denominator)?;
    let rational_poly = MultilinearPolynomial::new(rational_evaluations)?;
    absorb_rational_statement(numerator, denominator, transcript);
    verify_sumcheck(&rational_poly, &proof.sumcheck, transcript)?;
    let binding_challenge = transcript.challenge_field::<FieldElement>(b"rational-binding");
    if binding_challenge == proof.binding_challenge {
        Ok(())
    } else {
        Err(SumcheckError::InvalidProof)
    }
}

fn rational_evaluations(
    numerator: &[FieldElement],
    denominator: &[FieldElement],
) -> SumcheckResult<Vec<FieldElement>> {
    if numerator.len() != denominator.len() {
        return Err(SumcheckError::LengthMismatch);
    }
    let mut evaluations = Vec::with_capacity(numerator.len().max(1).next_power_of_two());
    for (p, q) in numerator.iter().zip(denominator) {
        let inv = q.inverse().ok_or(SumcheckError::ZeroDenominator)?;
        evaluations.push(*p * inv);
    }
    evaluations.resize(
        evaluations.len().max(1).next_power_of_two(),
        FieldElement::ZERO,
    );
    Ok(evaluations)
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MultisetEqualityProof {
    pub gamma: FieldElement,
    pub f1_len: usize,
    pub f2_len: usize,
    pub g1_len: usize,
    pub g2_len: usize,
    pub left_sum: FieldElement,
    pub right_sum: FieldElement,
}

pub fn prove_multiset_equality<T: Transcript>(
    f1: &[FieldElement],
    f2: &[FieldElement],
    g1: &[FieldElement],
    g2: &[FieldElement],
    transcript: &mut T,
) -> SumcheckResult<MultisetEqualityProof> {
    transcript.absorb_domain(b"multiset-equality-v1");
    absorb_multiset_statement(f1, f2, g1, g2, transcript);
    let gamma = transcript.challenge_field::<FieldElement>(b"gamma");
    let left = f1.iter().chain(f2).copied().collect::<Vec<FieldElement>>();
    let right = g1.iter().chain(g2).copied().collect::<Vec<FieldElement>>();
    let left_sum = log_derivative_sum(&left, gamma)?;
    let right_sum = log_derivative_sum(&right, gamma)?;
    Ok(MultisetEqualityProof {
        gamma,
        f1_len: f1.len(),
        f2_len: f2.len(),
        g1_len: g1.len(),
        g2_len: g2.len(),
        left_sum,
        right_sum,
    })
}

pub fn verify_multiset_equality<T: Transcript>(
    f1: &[FieldElement],
    f2: &[FieldElement],
    g1: &[FieldElement],
    g2: &[FieldElement],
    proof: &MultisetEqualityProof,
    transcript: &mut T,
) -> SumcheckResult<()> {
    if proof.f1_len != f1.len()
        || proof.f2_len != f2.len()
        || proof.g1_len != g1.len()
        || proof.g2_len != g2.len()
    {
        return Err(SumcheckError::InvalidProof);
    }
    transcript.absorb_domain(b"multiset-equality-v1");
    absorb_multiset_statement(f1, f2, g1, g2, transcript);
    let gamma = transcript.challenge_field::<FieldElement>(b"gamma");
    if gamma != proof.gamma {
        return Err(SumcheckError::InvalidProof);
    }
    let expected_left = f1.iter().chain(f2).copied().collect::<Vec<FieldElement>>();
    let expected_right = g1.iter().chain(g2).copied().collect::<Vec<FieldElement>>();
    let left_sum = log_derivative_sum(&expected_left, gamma)?;
    let right_sum = log_derivative_sum(&expected_right, gamma)?;
    if proof.left_sum == left_sum && proof.right_sum == right_sum && left_sum == right_sum {
        Ok(())
    } else {
        Err(SumcheckError::InvalidProof)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProductMultisetEqualityProof {
    pub gamma: FieldElement,
    pub f1_len: usize,
    pub f2_len: usize,
    pub g1_len: usize,
    pub g2_len: usize,
    pub left_product: FieldElement,
    pub right_product: FieldElement,
    pub left_log_derivative: RationalSumcheckProof,
    pub right_log_derivative: RationalSumcheckProof,
}

pub fn prove_product_multiset_equality<T: Transcript>(
    f1: &[FieldElement],
    f2: &[FieldElement],
    g1: &[FieldElement],
    g2: &[FieldElement],
    transcript: &mut T,
) -> SumcheckResult<ProductMultisetEqualityProof> {
    transcript.absorb_domain(b"product-multiset-equality-v1");
    absorb_multiset_statement(f1, f2, g1, g2, transcript);
    let gamma = transcript.challenge_field::<FieldElement>(b"gamma");
    let left = f1.iter().chain(f2).copied().collect::<Vec<FieldElement>>();
    let right = g1.iter().chain(g2).copied().collect::<Vec<FieldElement>>();
    let left_product = multiset_product(&[&left], gamma);
    let right_product = multiset_product(&[&right], gamma);
    let left_denominator = log_derivative_denominators(&left, gamma);
    let right_denominator = log_derivative_denominators(&right, gamma);
    let left_numerator = vec![FieldElement::ONE; left_denominator.len()];
    let right_numerator = vec![FieldElement::ONE; right_denominator.len()];
    let left_log_derivative =
        prove_rational_sumcheck_with_transcript(&left_numerator, &left_denominator, transcript)?;
    let right_log_derivative =
        prove_rational_sumcheck_with_transcript(&right_numerator, &right_denominator, transcript)?;
    Ok(ProductMultisetEqualityProof {
        gamma,
        f1_len: f1.len(),
        f2_len: f2.len(),
        g1_len: g1.len(),
        g2_len: g2.len(),
        left_product,
        right_product,
        left_log_derivative,
        right_log_derivative,
    })
}

pub fn verify_product_multiset_equality<T: Transcript>(
    f1: &[FieldElement],
    f2: &[FieldElement],
    g1: &[FieldElement],
    g2: &[FieldElement],
    proof: &ProductMultisetEqualityProof,
    transcript: &mut T,
) -> SumcheckResult<()> {
    if proof.f1_len != f1.len()
        || proof.f2_len != f2.len()
        || proof.g1_len != g1.len()
        || proof.g2_len != g2.len()
    {
        return Err(SumcheckError::InvalidProof);
    }
    transcript.absorb_domain(b"product-multiset-equality-v1");
    absorb_multiset_statement(f1, f2, g1, g2, transcript);
    let gamma = transcript.challenge_field::<FieldElement>(b"gamma");
    if gamma != proof.gamma {
        return Err(SumcheckError::InvalidProof);
    }
    let left = f1.iter().chain(f2).copied().collect::<Vec<FieldElement>>();
    let right = g1.iter().chain(g2).copied().collect::<Vec<FieldElement>>();
    let left_product = multiset_product(&[&left], gamma);
    let right_product = multiset_product(&[&right], gamma);
    let left_denominator = log_derivative_denominators(&left, gamma);
    let right_denominator = log_derivative_denominators(&right, gamma);
    let left_numerator = vec![FieldElement::ONE; left_denominator.len()];
    let right_numerator = vec![FieldElement::ONE; right_denominator.len()];
    verify_rational_sumcheck_with_transcript(
        &left_numerator,
        &left_denominator,
        proof.left_log_derivative.claimed_sum,
        &proof.left_log_derivative,
        transcript,
    )?;
    verify_rational_sumcheck_with_transcript(
        &right_numerator,
        &right_denominator,
        proof.right_log_derivative.claimed_sum,
        &proof.right_log_derivative,
        transcript,
    )?;
    if proof.left_product == left_product
        && proof.right_product == right_product
        && left_product == right_product
        && proof.left_log_derivative.claimed_sum == proof.right_log_derivative.claimed_sum
    {
        Ok(())
    } else {
        Err(SumcheckError::InvalidProof)
    }
}

pub fn verify_multiset_by_sort(
    left: &[FieldElement],
    right: &[FieldElement],
) -> SumcheckResult<()> {
    let mut l = left.to_vec();
    let mut r = right.to_vec();
    l.sort();
    r.sort();
    if l == r {
        Ok(())
    } else {
        Err(SumcheckError::InvalidProof)
    }
}

fn log_derivative_sum(
    values: &[FieldElement],
    gamma: FieldElement,
) -> SumcheckResult<FieldElement> {
    let mut sum = FieldElement::ZERO;
    for value in values {
        let denom = gamma + *value;
        let inv = denom.inverse().ok_or(SumcheckError::ZeroDenominator)?;
        sum += inv;
    }
    Ok(sum)
}

fn log_derivative_denominators(values: &[FieldElement], gamma: FieldElement) -> Vec<FieldElement> {
    values.iter().map(|value| gamma + *value).collect()
}

fn multiset_product(chunks: &[&[FieldElement]], gamma: FieldElement) -> FieldElement {
    let mut product = FieldElement::ONE;
    for chunk in chunks {
        for value in *chunk {
            product *= gamma + *value;
        }
    }
    product
}

fn absorb_polynomial<T: Transcript>(poly: &MultilinearPolynomial, transcript: &mut T) {
    transcript.absorb_public(b"num-vars", &(poly.num_vars() as u64).to_le_bytes());
    transcript.absorb_public(
        b"eval-len",
        &(poly.evaluations().len() as u64).to_le_bytes(),
    );
    for (index, value) in poly.evaluations().iter().copied().enumerate() {
        transcript.absorb_public(b"eval-index", &(index as u64).to_le_bytes());
        transcript.absorb_field(b"eval", value);
    }
}

fn absorb_labeled_values<T: Transcript>(
    transcript: &mut T,
    label: &'static [u8],
    values: &[FieldElement],
) {
    transcript.absorb_public(label, &(values.len() as u64).to_le_bytes());
    for (index, value) in values.iter().copied().enumerate() {
        transcript.absorb_public(b"multiset-index", &(index as u64).to_le_bytes());
        transcript.absorb_field(label, value);
    }
}

fn absorb_multiset_statement<T: Transcript>(
    f1: &[FieldElement],
    f2: &[FieldElement],
    g1: &[FieldElement],
    g2: &[FieldElement],
    transcript: &mut T,
) {
    absorb_labeled_values(transcript, b"f1", f1);
    absorb_labeled_values(transcript, b"f2", f2);
    absorb_labeled_values(transcript, b"g1", g1);
    absorb_labeled_values(transcript, b"g2", g2);
}

fn absorb_rational_statement<T: Transcript>(
    numerator: &[FieldElement],
    denominator: &[FieldElement],
    transcript: &mut T,
) {
    transcript.absorb_domain(b"rational-sumcheck-v1");
    absorb_labeled_values(transcript, b"rational-numerator", numerator);
    absorb_labeled_values(transcript, b"rational-denominator", denominator);
}

fn inner_product(left: &[FieldElement], right: &[FieldElement]) -> FieldElement {
    left.iter()
        .zip(right)
        .map(|(left, right)| *left * *right)
        .sum()
}

fn challenge_point<T: Transcript>(num_vars: usize, transcript: &mut T) -> Vec<FieldElement> {
    challenge_point_with_labels(num_vars, transcript, b"eq-index", b"zerocheck-eq")
}

fn challenge_point_with_labels<T: Transcript>(
    num_vars: usize,
    transcript: &mut T,
    index_label: &'static [u8],
    challenge_label: &'static [u8],
) -> Vec<FieldElement> {
    (0..num_vars)
        .map(|index| {
            transcript.absorb_public(index_label, &(index as u64).to_le_bytes());
            transcript.challenge_field::<FieldElement>(challenge_label)
        })
        .collect()
}

fn validate_same_shape(
    left: &MultilinearPolynomial,
    right: &MultilinearPolynomial,
    output: &MultilinearPolynomial,
) -> SumcheckResult<()> {
    validate_pair_shape(left, right)?;
    if left.num_vars() != output.num_vars()
        || left.evaluations().len() != output.evaluations().len()
    {
        return Err(SumcheckError::LengthMismatch);
    }
    Ok(())
}

fn validate_pair_shape(
    left: &MultilinearPolynomial,
    right: &MultilinearPolynomial,
) -> SumcheckResult<()> {
    if left.num_vars() != right.num_vars() || left.evaluations().len() != right.evaluations().len()
    {
        return Err(SumcheckError::LengthMismatch);
    }
    Ok(())
}

fn product_round_polynomial(
    current_poly: &MultilinearPolynomial,
    current_eq: &MultilinearPolynomial,
) -> QuadraticRoundPolynomial {
    let two = FieldElement::from(2_u64);
    let mut eval_at_0 = FieldElement::ZERO;
    let mut eval_at_1 = FieldElement::ZERO;
    let mut eval_at_2 = FieldElement::ZERO;
    for (poly_pair, eq_pair) in current_poly
        .evaluations()
        .chunks_exact(2)
        .zip(current_eq.evaluations().chunks_exact(2))
    {
        eval_at_0 += poly_pair[0] * eq_pair[0];
        eval_at_1 += poly_pair[1] * eq_pair[1];
        let poly_at_2 = (FieldElement::ZERO - poly_pair[0]) + poly_pair[1] * two;
        let eq_at_2 = (FieldElement::ZERO - eq_pair[0]) + eq_pair[1] * two;
        eval_at_2 += poly_at_2 * eq_at_2;
    }
    QuadraticRoundPolynomial {
        eval_at_0,
        eval_at_1,
        eval_at_2,
    }
}

fn cubic_relation_round_polynomial(
    current_left: &MultilinearPolynomial,
    current_right: &MultilinearPolynomial,
    current_output: &MultilinearPolynomial,
    current_eq: &MultilinearPolynomial,
) -> CubicRoundPolynomial {
    let points = [
        FieldElement::ZERO,
        FieldElement::ONE,
        FieldElement::from(2_u64),
        FieldElement::from(3_u64),
    ];
    let mut evals = [FieldElement::ZERO; 4];
    for (((left_pair, right_pair), output_pair), eq_pair) in current_left
        .evaluations()
        .chunks_exact(2)
        .zip(current_right.evaluations().chunks_exact(2))
        .zip(current_output.evaluations().chunks_exact(2))
        .zip(current_eq.evaluations().chunks_exact(2))
    {
        for (idx, point) in points.iter().copied().enumerate() {
            let left = line_at(left_pair, point);
            let right = line_at(right_pair, point);
            let output = line_at(output_pair, point);
            let eq = line_at(eq_pair, point);
            evals[idx] += eq * (left * right - output);
        }
    }
    CubicRoundPolynomial {
        eval_at_0: evals[0],
        eval_at_1: evals[1],
        eval_at_2: evals[2],
        eval_at_3: evals[3],
    }
}

fn line_at(pair: &[FieldElement], x: FieldElement) -> FieldElement {
    pair[0] * (FieldElement::ONE - x) + pair[1] * x
}

fn lagrange_eval_small_domain(x: FieldElement, values: &[FieldElement]) -> FieldElement {
    let mut out = FieldElement::ZERO;
    for (i, value) in values.iter().copied().enumerate() {
        let xi = FieldElement::from(i);
        let mut numerator = FieldElement::ONE;
        let mut denominator = FieldElement::ONE;
        for j in 0..values.len() {
            if i == j {
                continue;
            }
            let xj = FieldElement::from(j);
            numerator *= x - xj;
            denominator *= xi - xj;
        }
        out += value * numerator * denominator.inverse().expect("distinct small domain points");
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use pq_transcript::HashTranscript;

    fn sample_poly() -> MultilinearPolynomial {
        MultilinearPolynomial::new(vec![1_u64.into(), 3_u64.into(), 5_u64.into(), 7_u64.into()])
            .expect("poly")
    }

    #[test]
    fn sumcheck_accepts_and_rejects_tampering() {
        let poly = sample_poly();
        let mut prover_tr = HashTranscript::new(b"sum");
        let proof = prove_sumcheck(&poly, &mut prover_tr).expect("proof");
        let mut verifier_tr = HashTranscript::new(b"sum");
        assert!(verify_sumcheck(&poly, &proof, &mut verifier_tr).is_ok());
        let mut bad = proof;
        bad.rounds[0].eval_at_0 += 1_u64.into();
        let mut verifier_tr = HashTranscript::new(b"sum");
        assert!(verify_sumcheck(&poly, &bad, &mut verifier_tr).is_err());

        let mut prover_tr = HashTranscript::new(b"sum-claim");
        let mut bad_claim = prove_sumcheck(&poly, &mut prover_tr).expect("proof");
        bad_claim.claimed_sum += 1_u64.into();
        let mut verifier_tr = HashTranscript::new(b"sum-claim");
        assert_eq!(
            verify_sumcheck(&poly, &bad_claim, &mut verifier_tr),
            Err(SumcheckError::InvalidClaim)
        );
    }

    #[test]
    fn distributed_matches_single_aggregate() {
        let p0 = MultilinearPolynomial::new(vec![1_u64.into(), 2_u64.into()]).expect("p0");
        let p1 = MultilinearPolynomial::new(vec![3_u64.into(), 4_u64.into()]).expect("p1");
        let partitions = vec![p0, p1];
        let mut prover_tr = HashTranscript::new(b"dist");
        let proof = prove_distributed_sumcheck(&partitions, &mut prover_tr).expect("proof");
        let mut verifier_tr = HashTranscript::new(b"dist");
        assert!(verify_distributed_sumcheck(&partitions, &proof, &mut verifier_tr).is_ok());
    }

    #[test]
    fn product_sumcheck_accepts_and_rejects_tampering() {
        let left = MultilinearPolynomial::new(vec![
            1_u64.into(),
            2_u64.into(),
            3_u64.into(),
            4_u64.into(),
        ])
        .expect("left");
        let right = MultilinearPolynomial::new(vec![
            5_u64.into(),
            6_u64.into(),
            7_u64.into(),
            8_u64.into(),
        ])
        .expect("right");
        let claim = inner_product(left.evaluations(), right.evaluations());
        let mut prover_tr = HashTranscript::new(b"product");
        let proof = prove_product_sumcheck(&left, &right, claim, &mut prover_tr).expect("proof");

        let mut verifier_tr = HashTranscript::new(b"product");
        assert!(
            verify_product_sumcheck_rounds(left.num_vars(), claim, &proof, &mut verifier_tr)
                .is_ok()
        );
        assert_eq!(
            left.evaluate(&proof.challenges).expect("left")
                * right.evaluate(&proof.challenges).expect("right"),
            proof.final_evaluation
        );

        let mut bad_round = proof.clone();
        bad_round.rounds[0].eval_at_2 += FieldElement::ONE;
        let mut verifier_tr = HashTranscript::new(b"product");
        assert_eq!(
            verify_product_sumcheck_rounds(left.num_vars(), claim, &bad_round, &mut verifier_tr),
            Err(SumcheckError::InvalidProof)
        );

        let mut bad_claim_tr = HashTranscript::new(b"product-bad-claim");
        assert_eq!(
            prove_product_sumcheck(&left, &right, claim + FieldElement::ONE, &mut bad_claim_tr),
            Err(SumcheckError::InvalidClaim)
        );
    }

    #[test]
    fn cubic_zerocheck_accepts_and_rejects_tampering() {
        let left = MultilinearPolynomial::new(vec![
            1_u64.into(),
            2_u64.into(),
            3_u64.into(),
            4_u64.into(),
        ])
        .expect("left");
        let right = MultilinearPolynomial::new(vec![
            5_u64.into(),
            6_u64.into(),
            7_u64.into(),
            8_u64.into(),
        ])
        .expect("right");
        let output = MultilinearPolynomial::new(vec![
            5_u64.into(),
            12_u64.into(),
            21_u64.into(),
            32_u64.into(),
        ])
        .expect("output");
        let mut prover_tr = HashTranscript::new(b"cubic");
        let proof = prove_cubic_zerocheck(&left, &right, &output, &mut prover_tr).expect("proof");
        let mut verifier_tr = HashTranscript::new(b"cubic");
        assert!(verify_cubic_zerocheck_rounds(left.num_vars(), &proof, &mut verifier_tr).is_ok());
        assert_eq!(
            cubic_zerocheck_final_evaluation(
                &proof,
                left.evaluate(&proof.challenges).expect("left eval"),
                right.evaluate(&proof.challenges).expect("right eval"),
                output.evaluate(&proof.challenges).expect("output eval"),
            )
            .expect("final"),
            proof.final_evaluation
        );

        let mut bad_round = proof.clone();
        bad_round.rounds[0].eval_at_2 += FieldElement::ONE;
        let mut verifier_tr = HashTranscript::new(b"cubic");
        assert_eq!(
            verify_cubic_zerocheck_rounds(left.num_vars(), &bad_round, &mut verifier_tr),
            Err(SumcheckError::InvalidProof)
        );

        let mut bad_final = proof;
        bad_final.final_evaluation += FieldElement::ONE;
        let mut verifier_tr = HashTranscript::new(b"cubic");
        assert_eq!(
            verify_cubic_zerocheck_rounds(left.num_vars(), &bad_final, &mut verifier_tr),
            Err(SumcheckError::InvalidProof)
        );
    }

    #[test]
    fn zerocheck_rejects_nonzero() {
        let zero =
            MultilinearPolynomial::new(vec![FieldElement::ZERO, FieldElement::ZERO]).expect("zero");
        assert!(prove_zerocheck(&zero).is_ok());
        let mut prover_tr = HashTranscript::new(b"zero-proof");
        let proof = prove_zerocheck_proof(&zero, &mut prover_tr).expect("zero proof");
        let mut verifier_tr = HashTranscript::new(b"zero-proof");
        assert!(verify_zerocheck_proof(&zero, &proof, &mut verifier_tr).is_ok());

        let mut bad = proof;
        bad.final_evaluation += FieldElement::ONE;
        let mut verifier_tr = HashTranscript::new(b"zero-proof");
        assert_eq!(
            verify_zerocheck_proof(&zero, &bad, &mut verifier_tr),
            Err(SumcheckError::InvalidProof)
        );

        let nonzero = MultilinearPolynomial::new(vec![FieldElement::ZERO, FieldElement::ONE])
            .expect("nonzero");
        assert!(prove_zerocheck(&nonzero).is_err());
        let mut prover_tr = HashTranscript::new(b"zero-proof-nonzero");
        assert_eq!(
            prove_zerocheck_proof(&nonzero, &mut prover_tr),
            Err(SumcheckError::InvalidClaim)
        );

        let canceling_plain_sum =
            MultilinearPolynomial::new(vec![FieldElement::ONE, -FieldElement::ONE])
                .expect("canceling plain sum");
        assert!(canceling_plain_sum.sum_over_boolean_hypercube().is_zero());
        let mut prover_tr = HashTranscript::new(b"zero-proof-canceling");
        assert_eq!(
            prove_zerocheck_proof(&canceling_plain_sum, &mut prover_tr),
            Err(SumcheckError::InvalidClaim)
        );
    }

    #[test]
    fn rational_sum_rejects_zero_denominator() {
        let numerator = vec![1_u64.into(), 2_u64.into()];
        let denominator = vec![1_u64.into(), 4_u64.into()];
        let proof = prove_rational_sumcheck(numerator.clone(), denominator.clone()).expect("proof");
        assert_eq!(proof.len, numerator.len());
        assert_eq!(proof.sumcheck.claimed_sum, proof.claimed_sum);
        assert_eq!(proof.sumcheck.rounds.len(), 1);
        assert!(
            verify_rational_sumcheck(&numerator, &denominator, proof.claimed_sum, &proof).is_ok()
        );
        let forged_public = vec![9_u64.into(), 2_u64.into()];
        assert!(
            verify_rational_sumcheck(&forged_public, &denominator, proof.claimed_sum, &proof)
                .is_err()
        );
        let mut bad_len = proof;
        bad_len.len += 1;
        assert!(
            verify_rational_sumcheck(&numerator, &denominator, bad_len.claimed_sum, &bad_len)
                .is_err()
        );
        assert!(prove_rational_sumcheck(vec![1_u64.into()], vec![FieldElement::ZERO]).is_err());
    }

    #[test]
    fn rational_sumcheck_binds_transcript_and_public_inputs() {
        let numerator = vec![1_u64.into(), 2_u64.into(), 5_u64.into(), 7_u64.into()];
        let denominator = vec![1_u64.into(), 3_u64.into(), 4_u64.into(), 9_u64.into()];
        let mut prover_tr = HashTranscript::new(b"rational-fs");
        let proof =
            prove_rational_sumcheck_with_transcript(&numerator, &denominator, &mut prover_tr)
                .expect("proof");
        let mut verifier_tr = HashTranscript::new(b"rational-fs");
        verify_rational_sumcheck_with_transcript(
            &numerator,
            &denominator,
            proof.claimed_sum,
            &proof,
            &mut verifier_tr,
        )
        .expect("verify");
        assert_eq!(prover_tr.state(), verifier_tr.state());

        let mut bad_challenge = proof.clone();
        bad_challenge.binding_challenge += FieldElement::ONE;
        let mut verifier_tr = HashTranscript::new(b"rational-fs");
        assert_eq!(
            verify_rational_sumcheck_with_transcript(
                &numerator,
                &denominator,
                bad_challenge.claimed_sum,
                &bad_challenge,
                &mut verifier_tr,
            ),
            Err(SumcheckError::InvalidProof)
        );

        let mut bad_round = proof.clone();
        bad_round.sumcheck.rounds[0].eval_at_0 += FieldElement::ONE;
        let mut verifier_tr = HashTranscript::new(b"rational-fs");
        assert_eq!(
            verify_rational_sumcheck_with_transcript(
                &numerator,
                &denominator,
                bad_round.claimed_sum,
                &bad_round,
                &mut verifier_tr,
            ),
            Err(SumcheckError::InvalidProof)
        );

        let mut changed_numerator = numerator.clone();
        changed_numerator[0] += FieldElement::ONE;
        let mut changed_tr = HashTranscript::new(b"rational-fs");
        let changed_proof = prove_rational_sumcheck_with_transcript(
            &changed_numerator,
            &denominator,
            &mut changed_tr,
        )
        .expect("changed proof");
        assert_ne!(proof.binding_challenge, changed_proof.binding_challenge);
        assert_ne!(prover_tr.state(), changed_tr.state());
    }

    #[test]
    fn multiset_checks_bind_public_inputs() {
        let f1 = vec![1_u64.into(), 2_u64.into()];
        let f2 = vec![3_u64.into()];
        let g1 = vec![3_u64.into()];
        let g2 = vec![2_u64.into(), 1_u64.into()];
        let mut prover_tr = HashTranscript::new(b"mset");
        let proof = prove_multiset_equality(&f1, &f2, &g1, &g2, &mut prover_tr).expect("proof");
        assert_eq!(proof.f1_len, f1.len());
        assert_eq!(proof.f2_len, f2.len());
        assert_eq!(proof.g1_len, g1.len());
        assert_eq!(proof.g2_len, g2.len());
        let mut different_statement_tr = HashTranscript::new(b"mset");
        let different = prove_multiset_equality(
            &[9_u64.into(), 2_u64.into()],
            &f2,
            &g1,
            &g2,
            &mut different_statement_tr,
        )
        .expect("proof");
        assert_ne!(proof.gamma, different.gamma);
        let mut verifier_tr = HashTranscript::new(b"mset");
        assert!(verify_multiset_equality(&f1, &f2, &g1, &g2, &proof, &mut verifier_tr).is_ok());
        let forged_f1 = vec![9_u64.into(), 2_u64.into()];
        let mut verifier_tr = HashTranscript::new(b"mset");
        assert!(
            verify_multiset_equality(&forged_f1, &f2, &g1, &g2, &proof, &mut verifier_tr).is_err()
        );
        let mut bad_length = proof.clone();
        bad_length.g2_len += 1;
        let mut verifier_tr = HashTranscript::new(b"mset");
        assert!(
            verify_multiset_equality(&f1, &f2, &g1, &g2, &bad_length, &mut verifier_tr).is_err()
        );
        let mut bad_sum = proof;
        bad_sum.left_sum += FieldElement::ONE;
        let mut verifier_tr = HashTranscript::new(b"mset");
        assert!(verify_multiset_equality(&f1, &f2, &g1, &g2, &bad_sum, &mut verifier_tr).is_err());

        let left = vec![1_u64.into(), 2_u64.into(), 3_u64.into()];
        let right = vec![3_u64.into(), 1_u64.into(), 2_u64.into()];
        assert!(verify_multiset_by_sort(&left, &right).is_ok());
    }

    #[test]
    fn product_multiset_checks_do_not_carry_input_vectors() {
        let f1 = vec![1_u64.into(), 2_u64.into()];
        let f2 = vec![3_u64.into()];
        let g1 = vec![3_u64.into()];
        let g2 = vec![2_u64.into(), 1_u64.into()];
        let mut prover_tr = HashTranscript::new(b"product-mset");
        let proof =
            prove_product_multiset_equality(&f1, &f2, &g1, &g2, &mut prover_tr).expect("proof");
        assert_eq!(proof.f1_len, 2);
        assert_eq!(proof.f2_len, 1);
        assert_eq!(proof.g1_len, 1);
        assert_eq!(proof.g2_len, 2);
        assert_eq!(proof.left_product, proof.right_product);
        assert_eq!(
            proof.left_log_derivative.claimed_sum,
            proof.right_log_derivative.claimed_sum
        );
        assert!(!proof.left_log_derivative.sumcheck.rounds.is_empty());

        let mut verifier_tr = HashTranscript::new(b"product-mset");
        verify_product_multiset_equality(&f1, &f2, &g1, &g2, &proof, &mut verifier_tr)
            .expect("verify");
        assert_eq!(prover_tr.state(), verifier_tr.state());

        let forged_f1 = vec![9_u64.into(), 2_u64.into()];
        let mut verifier_tr = HashTranscript::new(b"product-mset");
        assert!(
            verify_product_multiset_equality(&forged_f1, &f2, &g1, &g2, &proof, &mut verifier_tr)
                .is_err()
        );

        let mut bad_product = proof.clone();
        bad_product.left_product += FieldElement::ONE;
        let mut verifier_tr = HashTranscript::new(b"product-mset");
        assert!(
            verify_product_multiset_equality(&f1, &f2, &g1, &g2, &bad_product, &mut verifier_tr)
                .is_err()
        );

        let mut bad_log_derivative = proof.clone();
        bad_log_derivative.left_log_derivative.sumcheck.rounds[0].eval_at_0 += FieldElement::ONE;
        let mut verifier_tr = HashTranscript::new(b"product-mset");
        assert!(
            verify_product_multiset_equality(
                &f1,
                &f2,
                &g1,
                &g2,
                &bad_log_derivative,
                &mut verifier_tr
            )
            .is_err()
        );
    }
}

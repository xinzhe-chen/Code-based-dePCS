#![allow(non_local_definitions)]

use ark_ff::{MontBackend, MontConfig, PrimeField};
use ark_poly::{EvaluationDomain, GeneralEvaluationDomain};
use pq_core::{FieldElement, GOLDILOCKS_MODULUS};
use pq_transcript::Transcript;
use serde::{Deserialize, Serialize};

use crate::{Commitment, MerklePcs, MerkleTree, OpeningProof, PcsError, PcsResult};

#[derive(MontConfig)]
#[modulus = "18446744069414584321"]
#[generator = "7"]
pub struct FGoldilocksConfig;

pub type FGoldilocks = ark_ff::Fp64<MontBackend<FGoldilocksConfig, 1>>;

pub fn field_to_ark(value: FieldElement) -> FGoldilocks {
    FGoldilocks::from(value.value())
}

pub fn ark_to_field(value: FGoldilocks) -> PcsResult<FieldElement> {
    let bigint = value.into_bigint();
    let limbs = bigint.as_ref();
    let value = limbs.first().copied().ok_or(PcsError::InvalidEvaluation)?;
    if value >= GOLDILOCKS_MODULUS {
        return Err(PcsError::InvalidEvaluation);
    }
    Ok(FieldElement::from(value))
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RsDeepFoldCommitment {
    pub codeword: Commitment,
    pub message_len: usize,
    pub codeword_len: usize,
    pub rate_inv: usize,
}

#[derive(Clone, Debug)]
pub struct RsDeepFoldAdvice {
    pub(crate) coeffs: Vec<FieldElement>,
    pub(crate) codeword: Vec<FieldElement>,
    pub(crate) tree: MerkleTree,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RsDeepFoldProof {
    pub point: Vec<FieldElement>,
    pub value: FieldElement,
    pub rate_inv: usize,
    pub query_count: usize,
    pub codeword_len: usize,
    pub layer_commitments: Vec<Commitment>,
    pub linear_polys: Vec<Vec<LinearPolynomial>>,
    pub final_value: FieldElement,
    pub queries: Vec<Vec<RsDeepFoldQuery>>,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LinearPolynomial {
    pub at_zero: FieldElement,
    pub at_one: FieldElement,
}

impl LinearPolynomial {
    fn evaluate(self, point: FieldElement) -> FieldElement {
        self.at_zero * (FieldElement::ONE - point) + self.at_one * point
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RsDeepFoldQuery {
    pub beta: usize,
    pub beta_opening: OpeningProof,
    pub conjugate_opening: OpeningProof,
}

pub(crate) fn commit(
    values: &[FieldElement],
    rate_inv: usize,
) -> PcsResult<(RsDeepFoldCommitment, RsDeepFoldAdvice)> {
    if values.is_empty() || !values.len().is_power_of_two() || !matches!(rate_inv, 2 | 4) {
        return Err(PcsError::InvalidLength);
    }
    let coeffs = evals_to_coeffs(values)?;
    let codeword = codeword_from_coeffs(&coeffs, values.len(), rate_inv)?;
    let codeword_len = codeword.len();
    let tree = MerkleTree::new(&codeword)?;
    let codeword_commitment = tree.commitment();
    Ok((
        RsDeepFoldCommitment {
            codeword: codeword_commitment,
            message_len: values.len(),
            codeword_len,
            rate_inv,
        },
        RsDeepFoldAdvice {
            coeffs,
            codeword,
            tree,
        },
    ))
}

pub(crate) fn open<T: Transcript>(
    domain: &'static [u8],
    values: &[FieldElement],
    commitment: &RsDeepFoldCommitment,
    advice: &RsDeepFoldAdvice,
    point: &[FieldElement],
    query_count: usize,
    transcript: &mut T,
) -> PcsResult<RsDeepFoldProof> {
    validate_commitment_shape(commitment)?;
    if !matches!(commitment.rate_inv, 2 | 4)
        || values.len() != commitment.message_len
        || advice.coeffs.len() != commitment.message_len
        || advice.codeword.len() != commitment.codeword_len
        || advice.tree.commitment() != commitment.codeword
        || point.is_empty()
        || point.len() != log2_power_of_two(commitment.message_len)?
    {
        return Err(PcsError::InvalidProof);
    }
    #[cfg(debug_assertions)]
    {
        let expected_coeffs = evals_to_coeffs(values)?;
        if expected_coeffs != advice.coeffs {
            return Err(PcsError::InvalidCommitment);
        }
        let expected_codeword =
            codeword_from_coeffs(&advice.coeffs, commitment.message_len, commitment.rate_inv)?;
        if expected_codeword != advice.codeword {
            return Err(PcsError::InvalidCommitment);
        }
    }
    if advice.tree.commitment() != commitment.codeword {
        return Err(PcsError::InvalidCommitment);
    }
    let query_count = query_count.max(1).min(commitment.codeword_len);
    let value = evaluate_mle(values, point)?;

    let mut a = vec![Vec::<Vec<FieldElement>>::new()];
    a[0].push(point.to_vec());
    let mut f_tilde = vec![values.to_vec()];
    let mut coeff_layers = vec![advice.coeffs.clone()];
    let mut codeword_layers = vec![advice.codeword.clone()];
    let mut trees = vec![advice.tree.clone()];
    let mut layer_commitments = vec![commitment.codeword.clone()];
    let mut linear_polys = Vec::with_capacity(point.len());
    let mut final_value = FieldElement::ZERO;

    absorb_opening_header(transcript, domain, commitment, point, value);
    for round in 0..point.len() {
        let alpha = transcript.challenge_field::<FieldElement>(b"deepfold-alpha");
        let remaining_vars = point.len() - round;
        a[round].push(alpha_powers(alpha, remaining_vars));

        let (f_tilde_zero, f_tilde_one) = split_even_odd(&f_tilde[round])?;
        let (coeff_even, coeff_odd) = split_even_odd(&coeff_layers[round])?;
        let round_polys = if round + 1 == point.len() {
            vec![LinearPolynomial {
                at_zero: f_tilde[round][0],
                at_one: f_tilde[round][1],
            }]
        } else {
            let polys = a[round]
                .iter()
                .map(|w| {
                    let tensor = tensor(&w[1..]);
                    Ok(LinearPolynomial {
                        at_zero: inner_product(&tensor, &f_tilde_zero)?,
                        at_one: inner_product(&tensor, &f_tilde_one)?,
                    })
                })
                .collect::<PcsResult<Vec<_>>>()?;
            a.push(a[round].iter().map(|w| w[1..].to_vec()).collect());
            polys
        };
        absorb_linear_polys(transcript, &round_polys);
        linear_polys.push(round_polys);

        let r = transcript.challenge_field::<FieldElement>(b"deepfold-r");
        let next_coeffs = coeff_even
            .iter()
            .zip(&coeff_odd)
            .map(|(even, odd)| *even + r * *odd)
            .collect::<Vec<_>>();
        let next_tilde = f_tilde_zero
            .iter()
            .zip(&f_tilde_one)
            .map(|(zero, one)| *zero * (FieldElement::ONE - r) + *one * r)
            .collect::<Vec<_>>();
        let next_domain_len = commitment.codeword_len >> (round + 1);
        let next_codeword = fft_coeffs(&next_coeffs, next_domain_len)?;
        coeff_layers.push(next_coeffs);
        f_tilde.push(next_tilde);
        codeword_layers.push(next_codeword.clone());
        if round + 1 == point.len() {
            final_value = *next_codeword.first().ok_or(PcsError::InvalidEvaluation)?;
            transcript.absorb_field(b"deepfold-final-value", final_value);
        } else {
            let tree = MerkleTree::new(&next_codeword)?;
            let commitment = tree.commitment();
            absorb_codeword_commitment(transcript, b"deepfold-layer", &commitment);
            layer_commitments.push(commitment);
            trees.push(tree);
        }
    }

    let beta_queries =
        transcript.challenge_indices(b"encoded-fold-beta", query_count, commitment.codeword_len);
    let queries = beta_queries
        .into_iter()
        .map(|mut beta| {
            (0..point.len())
                .map(|round| {
                    let domain_len = commitment.codeword_len >> round;
                    let offset = domain_len / 2;
                    let conjugate = if beta < offset {
                        beta + offset
                    } else {
                        beta - offset
                    };
                    let query = RsDeepFoldQuery {
                        beta,
                        beta_opening: trees[round].open(beta)?,
                        conjugate_opening: trees[round].open(conjugate)?,
                    };
                    beta %= offset;
                    Ok(query)
                })
                .collect::<PcsResult<Vec<_>>>()
        })
        .collect::<PcsResult<Vec<_>>>()?;

    Ok(RsDeepFoldProof {
        point: point.to_vec(),
        value,
        rate_inv: commitment.rate_inv,
        query_count,
        codeword_len: commitment.codeword_len,
        layer_commitments,
        linear_polys,
        final_value,
        queries,
    })
}

pub(crate) fn verify<T: Transcript>(
    domain: &'static [u8],
    commitment: &RsDeepFoldCommitment,
    proof: &RsDeepFoldProof,
    point: &[FieldElement],
    expected_query_count: usize,
    transcript: &mut T,
) -> PcsResult<()> {
    validate_commitment_shape(commitment)?;
    let mu = log2_power_of_two(commitment.message_len)?;
    if point.is_empty()
        || proof.point != point
        || point.len() != mu
        || proof.rate_inv != commitment.rate_inv
        || proof.query_count != expected_query_count.max(1).min(commitment.codeword_len)
        || proof.codeword_len != commitment.codeword_len
        || proof.layer_commitments.len() != mu
        || proof.layer_commitments.first() != Some(&commitment.codeword)
        || proof.linear_polys.len() != mu
        || proof.queries.len() != proof.query_count
    {
        return Err(PcsError::InvalidProof);
    }

    absorb_opening_header(transcript, domain, commitment, point, proof.value);
    let mut alphas = Vec::with_capacity(mu);
    let mut rs = Vec::with_capacity(mu);
    for round in 0..mu {
        let alpha = transcript.challenge_field::<FieldElement>(b"deepfold-alpha");
        alphas.push(alpha);
        let expected_len = if round + 1 == mu { 1 } else { round + 2 };
        if proof.linear_polys[round].len() != expected_len {
            return Err(PcsError::InvalidProof);
        }
        absorb_linear_polys(transcript, &proof.linear_polys[round]);
        let r = transcript.challenge_field::<FieldElement>(b"deepfold-r");
        rs.push(r);
        if round + 1 == mu {
            transcript.absorb_field(b"deepfold-final-value", proof.final_value);
        } else {
            let next = &proof.layer_commitments[round + 1];
            if next.len != commitment.codeword_len >> (round + 1) {
                return Err(PcsError::InvalidCommitment);
            }
            absorb_codeword_commitment(transcript, b"deepfold-layer", next);
        }
    }

    if proof.linear_polys[0][0].evaluate(point[0]) != proof.value {
        return Err(PcsError::InvalidEvaluation);
    }
    if proof.linear_polys[mu - 1][0].evaluate(rs[mu - 1]) != proof.final_value {
        return Err(PcsError::InvalidEvaluation);
    }
    for current_round in 1..mu {
        for previous_poly_index in 0..proof.linear_polys[current_round - 1].len() {
            let next_poly_index = if current_round + 1 < mu {
                previous_poly_index
            } else {
                0
            };
            let transition_point = if previous_poly_index == 0 {
                point[current_round]
            } else {
                let exponent = 1_u128 << (current_round + 1 - previous_poly_index);
                alphas[previous_poly_index - 1].pow(exponent)
            };
            if proof.linear_polys[current_round - 1][previous_poly_index]
                .evaluate(rs[current_round - 1])
                != proof.linear_polys[current_round][next_poly_index].evaluate(transition_point)
            {
                return Err(PcsError::InvalidEvaluation);
            }
        }
    }

    let domain = GeneralEvaluationDomain::<FGoldilocks>::new(commitment.codeword_len)
        .ok_or(PcsError::InvalidLength)?;
    let generator = ark_to_field(domain.element(1))?;
    for query_rounds in &proof.queries {
        if query_rounds.len() != mu {
            return Err(PcsError::InvalidProof);
        }
    }
    let expected_betas = transcript.challenge_indices(
        b"encoded-fold-beta",
        proof.query_count,
        commitment.codeword_len,
    );
    for (query_rounds, expected_beta) in proof.queries.iter().zip(expected_betas) {
        if query_rounds[0].beta != expected_beta {
            return Err(PcsError::InvalidProof);
        }
        let mut beta_point = generator.pow(expected_beta as u128);
        for round in 0..mu {
            let domain_len = commitment.codeword_len >> round;
            let offset = domain_len / 2;
            let layer_commitment = &proof.layer_commitments[round];
            let query = &query_rounds[round];
            if query.beta >= domain_len {
                return Err(PcsError::InvalidProof);
            }
            let conjugate = if query.beta < offset {
                query.beta + offset
            } else {
                query.beta - offset
            };
            if query.beta_opening.index != query.beta
                || query.conjugate_opening.index != conjugate
                || query.beta_opening.index == query.conjugate_opening.index
            {
                return Err(PcsError::InvalidProof);
            }
            MerklePcs::verify(layer_commitment, &query.beta_opening)?;
            MerklePcs::verify(layer_commitment, &query.conjugate_opening)?;
            let next_value = if round + 1 == mu {
                proof.final_value
            } else {
                query_rounds[round + 1].beta_opening.value
            };
            if !is_collinear(
                (beta_point, query.beta_opening.value),
                (-beta_point, query.conjugate_opening.value),
                (rs[round], next_value),
            ) {
                return Err(PcsError::InvalidEvaluation);
            }
            if round + 1 < mu && query_rounds[round + 1].beta != query.beta % offset {
                return Err(PcsError::InvalidProof);
            }
            beta_point *= beta_point;
        }
    }
    Ok(())
}

pub(crate) fn level_zero_indices(proof: &RsDeepFoldProof) -> Vec<usize> {
    let mut indices = proof
        .queries
        .iter()
        .flat_map(|rounds| {
            rounds
                .first()
                .into_iter()
                .flat_map(|query| [query.beta_opening.index, query.conjugate_opening.index])
        })
        .collect::<Vec<_>>();
    indices.sort_unstable();
    indices.dedup();
    indices
}

pub(crate) fn proof_size_bytes(proof: &RsDeepFoldProof) -> usize {
    let commitment_bytes = proof.layer_commitments.len() * (32 + 8);
    let linear_bytes = proof
        .linear_polys
        .iter()
        .map(|round| round.len() * 16)
        .sum::<usize>();
    let query_bytes = proof
        .queries
        .iter()
        .flatten()
        .map(|query| {
            opening_size_bytes(&query.beta_opening)
                + opening_size_bytes(&query.conjugate_opening)
                + 8
        })
        .sum::<usize>();
    8 * 4 + 8 + commitment_bytes + linear_bytes + query_bytes
}

fn opening_size_bytes(opening: &OpeningProof) -> usize {
    8 + 8 + opening.path.len() * (32 + 1)
}

fn validate_commitment_shape(commitment: &RsDeepFoldCommitment) -> PcsResult<()> {
    if !matches!(commitment.rate_inv, 2 | 4)
        || commitment.message_len == 0
        || !commitment.message_len.is_power_of_two()
        || commitment.codeword_len != commitment.message_len * commitment.rate_inv
        || commitment.codeword.len != commitment.codeword_len
    {
        return Err(PcsError::InvalidCommitment);
    }
    Ok(())
}

fn fft_coeffs(coeffs: &[FieldElement], domain_len: usize) -> PcsResult<Vec<FieldElement>> {
    if domain_len == 0 || !domain_len.is_power_of_two() || coeffs.len() > domain_len {
        return Err(PcsError::InvalidLength);
    }
    let domain =
        GeneralEvaluationDomain::<FGoldilocks>::new(domain_len).ok_or(PcsError::InvalidLength)?;
    domain
        .fft(&coeffs.iter().copied().map(field_to_ark).collect::<Vec<_>>())
        .into_iter()
        .map(ark_to_field)
        .collect()
}

fn codeword_from_coeffs(
    coeffs: &[FieldElement],
    message_len: usize,
    rate_inv: usize,
) -> PcsResult<Vec<FieldElement>> {
    if message_len == 0 || !message_len.is_power_of_two() || !matches!(rate_inv, 2 | 4) {
        return Err(PcsError::InvalidLength);
    }
    let codeword_len = message_len
        .checked_mul(rate_inv)
        .ok_or(PcsError::InvalidLength)?;
    fft_coeffs(coeffs, codeword_len)
}

fn evals_to_coeffs(values: &[FieldElement]) -> PcsResult<Vec<FieldElement>> {
    if values.is_empty() || !values.len().is_power_of_two() {
        return Err(PcsError::InvalidLength);
    }
    let mu = log2_power_of_two(values.len())?;
    let mut coeffs = values.to_vec();
    for bit in 0..mu {
        for index in 0..values.len() {
            if index & (1 << bit) != 0 {
                coeffs[index] = coeffs[index] - coeffs[index ^ (1 << bit)];
            }
        }
    }
    Ok(coeffs)
}

fn evaluate_mle(values: &[FieldElement], point: &[FieldElement]) -> PcsResult<FieldElement> {
    if point.len() != log2_power_of_two(values.len())? {
        return Err(PcsError::InvalidEvaluation);
    }
    let mut current = values.to_vec();
    for challenge in point {
        current = current
            .chunks_exact(2)
            .map(|pair| pair[0] * (FieldElement::ONE - *challenge) + pair[1] * *challenge)
            .collect();
    }
    current.first().copied().ok_or(PcsError::InvalidEvaluation)
}

fn split_even_odd(values: &[FieldElement]) -> PcsResult<(Vec<FieldElement>, Vec<FieldElement>)> {
    if values.len() < 2 || !values.len().is_multiple_of(2) {
        return Err(PcsError::InvalidLength);
    }
    let mut even = Vec::with_capacity(values.len() / 2);
    let mut odd = Vec::with_capacity(values.len() / 2);
    for pair in values.chunks_exact(2) {
        even.push(pair[0]);
        odd.push(pair[1]);
    }
    Ok((even, odd))
}

fn tensor(point: &[FieldElement]) -> Vec<FieldElement> {
    let mut values = vec![FieldElement::ONE];
    for coordinate in point {
        let mut next = Vec::with_capacity(values.len() * 2);
        for value in &values {
            next.push(*value * (FieldElement::ONE - *coordinate));
        }
        for value in &values {
            next.push(*value * *coordinate);
        }
        values = next;
    }
    values
}

fn inner_product(left: &[FieldElement], right: &[FieldElement]) -> PcsResult<FieldElement> {
    if left.len() != right.len() {
        return Err(PcsError::InvalidLength);
    }
    Ok(left
        .iter()
        .zip(right)
        .map(|(left, right)| *left * *right)
        .sum())
}

fn alpha_powers(alpha: FieldElement, count: usize) -> Vec<FieldElement> {
    let mut powers = Vec::with_capacity(count);
    let mut current = alpha;
    for _ in 0..count {
        powers.push(current);
        current *= current;
    }
    powers
}

fn is_collinear(
    p0: (FieldElement, FieldElement),
    p1: (FieldElement, FieldElement),
    p2: (FieldElement, FieldElement),
) -> bool {
    (p1.1 - p0.1) * (p2.0 - p1.0) == (p2.1 - p1.1) * (p1.0 - p0.0)
}

fn absorb_opening_header<T: Transcript>(
    transcript: &mut T,
    domain: &'static [u8],
    commitment: &RsDeepFoldCommitment,
    point: &[FieldElement],
    value: FieldElement,
) {
    transcript.absorb_domain(domain);
    absorb_codeword_commitment(transcript, b"deepfold-codeword", &commitment.codeword);
    transcript.absorb_public(
        b"deepfold-message-len",
        &(commitment.message_len as u64).to_le_bytes(),
    );
    transcript.absorb_public(
        b"deepfold-codeword-len",
        &(commitment.codeword_len as u64).to_le_bytes(),
    );
    transcript.absorb_public(
        b"deepfold-rate-inv",
        &(commitment.rate_inv as u64).to_le_bytes(),
    );
    transcript.absorb_public(b"deepfold-point-len", &(point.len() as u64).to_le_bytes());
    for coordinate in point {
        transcript.absorb_field(b"deepfold-point", *coordinate);
    }
    transcript.absorb_field(b"deepfold-value", value);
}

fn absorb_linear_polys<T: Transcript>(transcript: &mut T, polys: &[LinearPolynomial]) {
    transcript.absorb_public(
        b"deepfold-linear-count",
        &(polys.len() as u64).to_le_bytes(),
    );
    for poly in polys {
        transcript.absorb_field(b"deepfold-linear-zero", poly.at_zero);
        transcript.absorb_field(b"deepfold-linear-one", poly.at_one);
    }
}

fn absorb_codeword_commitment<T: Transcript>(
    transcript: &mut T,
    label: &[u8],
    commitment: &Commitment,
) {
    transcript.absorb_public(label, &commitment.root);
    transcript.absorb_public(label, &(commitment.len as u64).to_le_bytes());
}

fn log2_power_of_two(len: usize) -> PcsResult<usize> {
    if len == 0 || !len.is_power_of_two() {
        return Err(PcsError::InvalidLength);
    }
    Ok(len.trailing_zeros() as usize)
}

#[cfg(test)]
mod tests {
    use super::*;
    use pq_transcript::HashTranscript;

    #[test]
    fn field_bridge_roundtrips_canonical_values() {
        let values = [
            0,
            1,
            2,
            7,
            1 << 32,
            GOLDILOCKS_MODULUS - 2,
            GOLDILOCKS_MODULUS - 1,
        ];
        for value in values {
            let field = FieldElement::from(value);
            assert_eq!(ark_to_field(field_to_ark(field)).expect("roundtrip"), field);
        }
    }

    #[test]
    fn field_bridge_matches_arithmetic() {
        let left = FieldElement::from(123_456_789_u64);
        let right = FieldElement::from(987_654_321_u64);
        let ark_sum = field_to_ark(left) + field_to_ark(right);
        let ark_product = field_to_ark(left) * field_to_ark(right);
        assert_eq!(ark_to_field(ark_sum).expect("sum"), left + right);
        assert_eq!(ark_to_field(ark_product).expect("product"), left * right);
    }

    fn sample_values() -> Vec<FieldElement> {
        (0..16)
            .map(|index| FieldElement::from((index * 17 + 5) as u64))
            .collect()
    }

    const TEST_DOMAIN: &[u8] = b"rs-deepfold-test-core";

    #[test]
    fn rs_deepfold_accepts_valid_proof() {
        let values = sample_values();
        let point = vec![
            FieldElement::from(2_u64),
            FieldElement::from(3_u64),
            FieldElement::from(5_u64),
            FieldElement::from(7_u64),
        ];
        let (commitment, advice) = commit(&values, 2).expect("commit");
        let mut prover_tr = HashTranscript::new(b"rs-deepfold-valid");
        let proof = open(
            TEST_DOMAIN,
            &values,
            &commitment,
            &advice,
            &point,
            8,
            &mut prover_tr,
        )
        .expect("open");
        let mut verifier_tr = HashTranscript::new(b"rs-deepfold-valid");
        verify(
            TEST_DOMAIN,
            &commitment,
            &proof,
            &point,
            8,
            &mut verifier_tr,
        )
        .expect("verify");
    }

    #[test]
    fn rs_deepfold_rejects_tampered_value() {
        let values = sample_values();
        let point = vec![
            FieldElement::from(2_u64),
            FieldElement::from(3_u64),
            FieldElement::from(5_u64),
            FieldElement::from(7_u64),
        ];
        let (commitment, advice) = commit(&values, 2).expect("commit");
        let mut prover_tr = HashTranscript::new(b"rs-deepfold-value");
        let mut proof = open(
            TEST_DOMAIN,
            &values,
            &commitment,
            &advice,
            &point,
            8,
            &mut prover_tr,
        )
        .expect("open");
        proof.value += FieldElement::ONE;
        let mut verifier_tr = HashTranscript::new(b"rs-deepfold-value");
        assert!(
            verify(
                TEST_DOMAIN,
                &commitment,
                &proof,
                &point,
                8,
                &mut verifier_tr
            )
            .is_err()
        );
    }

    #[test]
    fn rs_deepfold_rejects_tampered_query_path() {
        let values = sample_values();
        let point = vec![
            FieldElement::from(2_u64),
            FieldElement::from(3_u64),
            FieldElement::from(5_u64),
            FieldElement::from(7_u64),
        ];
        let (commitment, advice) = commit(&values, 2).expect("commit");
        let mut prover_tr = HashTranscript::new(b"rs-deepfold-path");
        let mut proof = open(
            TEST_DOMAIN,
            &values,
            &commitment,
            &advice,
            &point,
            8,
            &mut prover_tr,
        )
        .expect("open");
        proof.queries[0][0].beta_opening.path[0].0[0] ^= 1;
        let mut verifier_tr = HashTranscript::new(b"rs-deepfold-path");
        assert!(
            verify(
                TEST_DOMAIN,
                &commitment,
                &proof,
                &point,
                8,
                &mut verifier_tr
            )
            .is_err()
        );
    }

    #[test]
    fn rs_deepfold_rejects_tampered_fold_query() {
        let values = sample_values();
        let point = vec![
            FieldElement::from(2_u64),
            FieldElement::from(3_u64),
            FieldElement::from(5_u64),
            FieldElement::from(7_u64),
        ];
        let (commitment, advice) = commit(&values, 2).expect("commit");
        let mut prover_tr = HashTranscript::new(b"rs-deepfold-fold");
        let mut proof = open(
            TEST_DOMAIN,
            &values,
            &commitment,
            &advice,
            &point,
            8,
            &mut prover_tr,
        )
        .expect("open");
        proof.queries[0][1].beta_opening.value += FieldElement::ONE;
        let mut verifier_tr = HashTranscript::new(b"rs-deepfold-fold");
        assert!(
            verify(
                TEST_DOMAIN,
                &commitment,
                &proof,
                &point,
                8,
                &mut verifier_tr
            )
            .is_err()
        );
    }

    #[test]
    fn rs_deepfold_rejects_tampered_beta_challenge() {
        let values = sample_values();
        let point = vec![
            FieldElement::from(2_u64),
            FieldElement::from(3_u64),
            FieldElement::from(5_u64),
            FieldElement::from(7_u64),
        ];
        let (commitment, advice) = commit(&values, 2).expect("commit");
        let mut prover_tr = HashTranscript::new(b"rs-deepfold-beta");
        let mut proof = open(
            TEST_DOMAIN,
            &values,
            &commitment,
            &advice,
            &point,
            8,
            &mut prover_tr,
        )
        .expect("open");
        proof.queries[0][0].beta ^= 1;
        let mut verifier_tr = HashTranscript::new(b"rs-deepfold-beta");
        assert!(
            verify(
                TEST_DOMAIN,
                &commitment,
                &proof,
                &point,
                8,
                &mut verifier_tr
            )
            .is_err()
        );
    }

    #[test]
    fn rs_deepfold_beta_queries_are_unique() {
        let values = sample_values();
        let point = vec![
            FieldElement::from(2_u64),
            FieldElement::from(3_u64),
            FieldElement::from(5_u64),
            FieldElement::from(7_u64),
        ];
        let (commitment, advice) = commit(&values, 2).expect("commit");
        let mut prover_tr = HashTranscript::new(b"rs-deepfold-unique-beta");
        let proof = open(
            TEST_DOMAIN,
            &values,
            &commitment,
            &advice,
            &point,
            8,
            &mut prover_tr,
        )
        .expect("open");
        let mut betas = proof
            .queries
            .iter()
            .map(|rounds| rounds[0].beta)
            .collect::<Vec<_>>();
        betas.sort_unstable();
        betas.dedup();
        assert_eq!(betas.len(), proof.queries.len());
    }
}

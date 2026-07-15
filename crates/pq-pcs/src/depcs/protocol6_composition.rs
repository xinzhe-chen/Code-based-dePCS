//! Protocol 6: Brakedown with Proof Composition.
//!
//! Paper role: Protocol 6 is the single-prover Brakedown composition that
//! reduces the multilinear claim `f(s) = v` to commitments/openings for
//! `E1 = Enc(F1)`, `F1`, `E2 = Enc(F2)`, and `F2`, plus the relation proof
//! checked later by Protocol 10.
//!
//! Symbol mapping: the global claim `f(s) = v` is represented by
//! `PaperProtocol11Proof::claimed_value`; `s = s1 || s2` maps to the
//! worker-prefix challenge (`s1`) and shard-local suffix (`s2`) of
//! `PaperProtocol11Proof::point`.
//!
//! Code mapping:
//! - Protocol 6 Eval steps 2, 7, and 9 are orchestrated by Protocol 11 and
//!   Protocol 10 in this crate.
//! - This module owns the composition equation used by Protocol 6 step 10(c):
//!   the master accepts `v` only when it equals the sum of worker-local `F2`
//!   evaluations weighted by `eq(s1, worker_id)`.
//! - `prove_composed_claim` is the prover-side construction of that sum.
//! - `check_composed_claim`/`verify_composed_claim` are the verifier-side
//!   checks that the worker openings are in canonical order and match `s`.

use paper_util::algebra::field::MyField;

use super::protocol9_f_commitments::validate_worker_opening_metadata;
use super::types::*;

pub(crate) struct Protocol6CompositionClaim {
    pub(crate) claimed_value: PaperField,
}

pub(crate) struct Protocol6ClaimCheck {
    pub(crate) expected_claim: PaperField,
}

pub(crate) fn prove_composed_claim(
    commitment: &PaperProtocol11Commitment,
    point: &[PaperField],
    worker_openings: &mut [PaperProtocol11WorkerOpening],
) -> PaperDepcsResult<Protocol6CompositionClaim> {
    if worker_openings.len() != commitment.workers {
        return Err(PaperDepcsError::InvalidProof);
    }
    // Protocol 6 uses a single global claim `f(s) = v`. Protocol 11 obtains it
    // by partitioning `s = s1 || s2`: each worker opens its local shard at
    // `s2`, and the master combines those values with `eq(s1, worker_id)`.
    // Canonical order is part of the transcript/proof layout.
    worker_openings.sort_by_key(|opening| opening.worker_id);
    let claimed_value = composed_claim_value(commitment, point, worker_openings)?;
    Ok(Protocol6CompositionClaim { claimed_value })
}

#[cfg(test)]
pub(crate) fn verify_composed_claim(
    commitment: &PaperProtocol11Commitment,
    proof: &PaperProtocol11Proof,
) -> PaperDepcsResult<Protocol6ClaimCheck> {
    let check = check_composed_claim(commitment, proof)?;
    if check.expected_claim != proof.claimed_value {
        return Err(PaperDepcsError::InvalidEvaluation);
    }
    Ok(check)
}

pub(crate) fn check_composed_claim(
    commitment: &PaperProtocol11Commitment,
    proof: &PaperProtocol11Proof,
) -> PaperDepcsResult<Protocol6ClaimCheck> {
    if proof.worker_openings.len() != commitment.workers {
        return Err(PaperDepcsError::InvalidProof);
    }
    let expected_claim = composed_claim_value(commitment, &proof.point, &proof.worker_openings)?;
    Ok(Protocol6ClaimCheck { expected_claim })
}

fn composed_claim_value(
    commitment: &PaperProtocol11Commitment,
    point: &[PaperField],
    worker_openings: &[PaperProtocol11WorkerOpening],
) -> PaperDepcsResult<PaperField> {
    let mut claimed_value = PaperField::from_int(0);
    for (worker_id, opening) in worker_openings.iter().enumerate() {
        // Paper equation: v = sum_i beta^(i) * v_F2^(i), where
        // beta^(i) = eq(s1, bin(worker_id)). Protocol 9 validates beta and the
        // local point `s2`; this function only performs the Protocol 6 sum.
        validate_worker_opening_metadata(commitment, point, worker_id, opening)?;
        claimed_value += opening.worker_weight * opening.value;
    }
    Ok(claimed_value)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::depcs::backend::PaperPcsBackend;
    use crate::depcs::{
        PaperDepcsConfig, assemble_opening, commit_from_worker_commitments, commit_worker,
        open_worker, sample_point,
    };

    #[test]
    fn protocol6_composes_worker_claims() {
        let config = PaperDepcsConfig::new(PaperPcsBackend::DeepFold, 2).unwrap();
        let workers = 2;
        let original_len = 1 << 6;
        let commitments = (0..workers)
            .map(|worker_id| commit_worker(original_len, workers, worker_id, config).unwrap())
            .collect();
        let commitment =
            commit_from_worker_commitments(original_len, workers, config, commitments).unwrap();
        let point = sample_point(commitment.nv);
        let mut openings = (0..workers)
            .rev()
            .map(|worker_id| open_worker(&commitment, worker_id, &point).unwrap())
            .collect::<Vec<_>>();
        let claim = prove_composed_claim(&commitment, &point, &mut openings).unwrap();
        let (proof, _) = assemble_opening(&commitment, point, openings).unwrap();
        assert_eq!(claim.claimed_value, proof.claimed_value);
        assert!(verify_composed_claim(&commitment, &proof).is_ok());
    }

    #[test]
    fn protocol6_rejects_tampered_worker_weight() {
        let config = PaperDepcsConfig::new(PaperPcsBackend::DeepFold, 2).unwrap();
        let workers = 2;
        let original_len = 1 << 6;
        let commitments = (0..workers)
            .map(|worker_id| commit_worker(original_len, workers, worker_id, config).unwrap())
            .collect();
        let commitment =
            commit_from_worker_commitments(original_len, workers, config, commitments).unwrap();
        let point = sample_point(commitment.nv);
        let openings = (0..workers)
            .map(|worker_id| open_worker(&commitment, worker_id, &point).unwrap())
            .collect::<Vec<_>>();
        let (mut proof, _) = assemble_opening(&commitment, point, openings).unwrap();
        proof.worker_openings[0].worker_weight += PaperField::from_int(1);
        assert!(verify_composed_claim(&commitment, &proof).is_err());
    }
}

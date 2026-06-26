//! Protocol 8: Distributed Polynomial Commitments to E1 and E2.
//!
//! Paper role: worker `P_i` commits to `E1^(i) = Enc(F1^(i))` and
//! `E2^(i) = Enc(F2^(i))`, then proves evaluations at verifier-chosen points.
//! The verifier checks all per-worker PCS openings and the aggregate equations
//! `v_E1 = sum_i v_E1^(i)` and `v_E2 = sum_i v_E2^(i)`.
//!
//! Code mapping:
//! - Protocol 8 commit phase is represented by the worker PCS commitment stored
//!   in `PaperProtocol11WorkerCommitment`.
//! - Protocol 8 eval phase appears in Protocol 10 as two logical opening
//!   claims: `EAtR` for the random relation point `r`, and `EAtSystematic` for
//!   the systematic point `(u', 0^log c)`.
//! - This module constructs those claims only; artifact PCS opening bytes and
//!   verification stay in `pcs_backend` so backend rate/query policy is not
//!   changed by this structural split.

use paper_util::algebra::field::MyField;

use super::types::*;

pub(crate) struct Protocol8EClaim {
    pub(crate) opening_claim: PaperProtocol10OpeningClaim,
}

pub(crate) fn relation_weight(
    relation_kind: PaperProtocol10RelationKind,
    opening: &PaperProtocol11WorkerOpening,
) -> PaperField {
    // Protocol 11 defines E1 from the random vector `a`, and E2 from
    // `beta^(i)=eq(s1, bin(i))`. For E1 the local relation is unweighted; for
    // E2 it carries the worker's beta weight.
    match relation_kind {
        PaperProtocol10RelationKind::E1 => PaperField::from_int(1),
        PaperProtocol10RelationKind::E2 => opening.worker_weight,
    }
}

pub(crate) fn systematic_value(
    relation_kind: PaperProtocol10RelationKind,
    opening: &PaperProtocol11WorkerOpening,
) -> PaperField {
    // Protocol 10 step 5 checks `E(u', 0^log c) = F(u')`. For E2 the code path
    // carries the weighted F2 value, matching Protocol 11's beta-weighted sum.
    match relation_kind {
        PaperProtocol10RelationKind::E1 => opening.value,
        PaperProtocol10RelationKind::E2 => opening.worker_weight * opening.value,
    }
}

pub(crate) fn e_at_r_claim(
    opening: &PaperProtocol11WorkerOpening,
    relation_weight: PaperField,
    relation_point: Vec<PaperField>,
    source_digest: [u8; 32],
) -> Protocol8EClaim {
    // Protocol 10 step 4, `E(r) = q'_2`: this is the distributed Protocol 8
    // evaluation of the encoded vector at the relation point `r`.
    Protocol8EClaim {
        opening_claim: PaperProtocol10OpeningClaim {
            worker_id: opening.worker_id,
            claim_kind: PaperProtocol10OpeningClaimKind::EAtR,
            claimed_value: relation_weight * opening.value,
            weight: relation_weight,
            point: relation_point,
            source_digest,
        },
    }
}

pub(crate) fn e_at_systematic_claim(
    relation_kind: PaperProtocol10RelationKind,
    opening: &PaperProtocol11WorkerOpening,
    relation_weight: PaperField,
    source_digest: [u8; 32],
) -> Protocol8EClaim {
    // Protocol 10 step 5, `E(u', 0^log c)`: the systematic opening that must
    // agree with the corresponding Protocol 9 `F(u')` claim.
    Protocol8EClaim {
        opening_claim: PaperProtocol10OpeningClaim {
            worker_id: opening.worker_id,
            claim_kind: PaperProtocol10OpeningClaimKind::EAtSystematic,
            claimed_value: systematic_value(relation_kind, opening),
            weight: relation_weight,
            point: opening.shard_point.clone(),
            source_digest,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::depcs::backend::PaperPcsBackend;
    use crate::depcs::{
        PaperDepcsConfig, commit_from_worker_commitments, commit_worker, open_worker, sample_point,
    };

    #[test]
    fn protocol8_constructs_e1_and_e2_claims() {
        let config = PaperDepcsConfig::new(PaperPcsBackend::DeepFold, 2).unwrap();
        let worker_commitments = (0..2)
            .map(|worker_id| commit_worker(1 << 6, 2, worker_id, config).unwrap())
            .collect();
        let commitment =
            commit_from_worker_commitments(1 << 6, 2, config, worker_commitments).unwrap();
        let point = sample_point(commitment.nv);
        let opening = open_worker(&commitment, 0, &point).unwrap();
        let source_digest = [7_u8; 32];
        let relation_point = opening.shard_point.clone();

        let e1_weight = relation_weight(PaperProtocol10RelationKind::E1, &opening);
        let e1 =
            e_at_r_claim(&opening, e1_weight, relation_point.clone(), source_digest).opening_claim;
        assert_eq!(e1.claim_kind, PaperProtocol10OpeningClaimKind::EAtR);
        assert_eq!(e1.claimed_value, opening.value);
        assert_eq!(e1.weight, PaperField::from_int(1));

        let e2_weight = relation_weight(PaperProtocol10RelationKind::E2, &opening);
        let e2 = e_at_systematic_claim(
            PaperProtocol10RelationKind::E2,
            &opening,
            e2_weight,
            source_digest,
        )
        .opening_claim;
        assert_eq!(
            e2.claim_kind,
            PaperProtocol10OpeningClaimKind::EAtSystematic
        );
        assert_eq!(e2.claimed_value, opening.worker_weight * opening.value);
    }
}

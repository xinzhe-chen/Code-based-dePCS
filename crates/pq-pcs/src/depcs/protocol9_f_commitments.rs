//! Protocol 9: Distributed Polynomial Commitments to F1 and F2.
//!
//! Paper role: worker `P_i` commits to `F1^(i)` and `F2^(i)`, where
//! `F1^(i)` is the random linear combination from Protocol 11 step 1 and
//! `F2^(i)` is weighted by `beta^(i)=eq(s1, bin(i))`. During evaluation, each
//! worker proves `F1^(i)(x)`/`F2^(i)(x)`, and the verifier checks aggregate
//! sums over workers.
//!
//! Code mapping:
//! - `worker_weight` computes the paper's `beta^(i)`.
//! - `prepare_*_worker_opening_input` computes the local `F2^(i)(s2)` value and
//!   the artifact point used by DeepFold.
//! - `f_pad_systematic_claim` is Protocol 10 step 5's `F(u')` claim, paired
//!   with Protocol 8's `E(u', 0^log c)` claim.

use paper_util::algebra::field::MyField;

use super::protocol7_merkle_commitments::worker_commitment_digest;
use super::types::*;
use super::utils::{artifact_point, deterministic_value};

#[cfg(test)]
pub(crate) struct Protocol9FClaim {
    pub(crate) opening_claim: PaperProtocol10OpeningClaim,
}

pub(crate) struct Protocol9WorkerOpeningInput {
    pub(crate) worker_id: usize,
    pub(crate) worker_weight: PaperField,
    pub(crate) shard_point: Vec<PaperField>,
}

pub(crate) struct Protocol9UncachedWorkerOpeningInput {
    pub(crate) opening: Protocol9WorkerOpeningInput,
    pub(crate) coefficients: Vec<PaperField>,
}

pub(crate) fn worker_weight(
    worker_id: usize,
    worker_bits: usize,
    point: &[PaperField],
) -> PaperDepcsResult<PaperField> {
    // Paper notation: beta^(i)[k] = eq(s1, bin(ib+k)). In this path the shard
    // owner is selected by the worker-id prefix, so the per-worker coefficient
    // is exactly eq(s1, bin(worker_id)).
    if point.len() < worker_bits {
        return Err(PaperDepcsError::InvalidProof);
    }
    let mut weight = PaperField::from_int(1);
    for (bit_idx, challenge) in point.iter().take(worker_bits).enumerate() {
        let bit = (worker_id >> (worker_bits - bit_idx - 1)) & 1;
        weight *= if bit == 0 {
            PaperField::from_int(1) - *challenge
        } else {
            *challenge
        };
    }
    Ok(weight)
}

pub(crate) fn worker_coefficients(
    original_len: usize,
    workers: usize,
    worker_id: usize,
) -> PaperDepcsResult<Vec<PaperField>> {
    // Protocol 11 setup: worker P_i holds rows `M_f^(i)[k] = M_f[ib+k]`.
    // The benchmark uses deterministic witness values; this helper materializes
    // precisely the rows owned by `worker_id`.
    let layout = PaperLayout::new(original_len, workers)?;
    if worker_id >= workers {
        return Err(PaperDepcsError::InvalidWorker);
    }
    let start = worker_id * layout.shard_len;
    Ok((0..layout.shard_len)
        .map(|offset| deterministic_value(start + offset))
        .collect())
}

pub(crate) fn prepare_worker_opening_input(
    commitment: &PaperProtocol11Commitment,
    worker_id: usize,
    point: &[PaperField],
) -> PaperDepcsResult<Protocol9UncachedWorkerOpeningInput> {
    // Protocol 9 eval phase, non-cached worker path: materialize the worker's
    // shard for the backend PCS proof and return the public opening metadata.
    // The opened value is read back from the artifact proof evaluation, avoiding
    // a second multilinear evaluation before proving.
    if point.len() != commitment.nv || worker_id >= commitment.workers {
        return Err(PaperDepcsError::InvalidProof);
    }
    let coefficients = worker_coefficients(commitment.original_len, commitment.workers, worker_id)?;
    let opening = worker_opening_input_from_point(
        worker_id,
        commitment.worker_bits,
        commitment.artifact_nv,
        point,
    )?;
    Ok(Protocol9UncachedWorkerOpeningInput {
        opening,
        coefficients,
    })
}

pub(crate) fn prepare_cached_worker_opening_input(
    cache: &PaperWorkerCache,
    commitment: &PaperProtocol11Commitment,
    point: &[PaperField],
) -> PaperDepcsResult<Protocol9WorkerOpeningInput> {
    // Same Protocol 9 eval phase as above, but using the Protocol 11 prepared
    // worker cache. The metadata checks are fail-closed: a cache can only open
    // the exact commitment/config/root it was prepared for.
    if point.len() != commitment.nv
        || cache.worker_id >= commitment.workers
        || cache.original_len != commitment.original_len
        || cache.workers != commitment.workers
        || cache.config != commitment.config
        || cache.commitment.worker_id != cache.worker_id
        || cache.commitment.row_range
            != (
                cache.worker_id * commitment.shard_len,
                (cache.worker_id + 1) * commitment.shard_len,
            )
        || commitment.workers_commitments[cache.worker_id].leaf_digest
            != cache.commitment.leaf_digest
        || commitment.workers_commitments[cache.worker_id].leaf_digest
            != worker_commitment_digest(&cache.commitment)?
    {
        return Err(PaperDepcsError::InvalidCommitment);
    }
    worker_opening_input_from_point(
        cache.worker_id,
        commitment.worker_bits,
        commitment.artifact_nv,
        point,
    )
}

pub(crate) fn validate_worker_opening_metadata(
    commitment: &PaperProtocol11Commitment,
    point: &[PaperField],
    worker_id: usize,
    opening: &PaperProtocol11WorkerOpening,
) -> PaperDepcsResult<()> {
    // Verifier-side metadata check for Protocol 9: the opening must come from
    // the expected worker, at the shared shard-local point `s2`, with the beta
    // weight determined by the worker prefix `s1`.
    if opening.worker_id != worker_id
        || opening.shard_point
            != artifact_point(&point[commitment.worker_bits..], commitment.artifact_nv)
        || opening.worker_weight != worker_weight(worker_id, commitment.worker_bits, point)?
    {
        return Err(PaperDepcsError::InvalidProof);
    }
    Ok(())
}

#[cfg(test)]
pub(crate) fn f_pad_systematic_claim(
    opening: &PaperProtocol11WorkerOpening,
    source_digest: [u8; 32],
) -> Protocol9FClaim {
    // Protocol 10 step 5, `F(u')`: this claim is intentionally unweighted in
    // the batch equation; E2's beta factor has already been folded into the
    // worker opening value used by Protocol 6/11.
    Protocol9FClaim {
        opening_claim: PaperProtocol10OpeningClaim {
            worker_id: opening.worker_id,
            claim_kind: PaperProtocol10OpeningClaimKind::FPadAtSystematic,
            claimed_value: opening.value,
            weight: PaperField::from_int(1),
            point: opening.shard_point.clone(),
            source_digest,
        },
    }
}

fn worker_opening_input_from_point(
    worker_id: usize,
    worker_bits: usize,
    artifact_nv: usize,
    point: &[PaperField],
) -> PaperDepcsResult<Protocol9WorkerOpeningInput> {
    // Split `s=s1||s2`, compute beta=eq(s1, worker_id), and pad `s2` to the
    // vendored PCS arity without changing the logical claim. The opened value
    // is filled from DeepFold's returned evaluation after proof generation.
    let worker_weight = worker_weight(worker_id, worker_bits, point)?;
    let shard_point = point[worker_bits..].to_vec();
    let shard_point = artifact_point(&shard_point, artifact_nv);
    Ok(Protocol9WorkerOpeningInput {
        worker_id,
        worker_weight,
        shard_point,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::depcs::backend::PaperPcsBackend;
    use crate::depcs::{
        PaperDepcsConfig, commit_from_worker_commitments, commit_worker, open_worker, sample_point,
    };

    #[test]
    fn protocol9_worker_weight_and_f_claim_are_stable() {
        let point = vec![PaperField::from_int(3), PaperField::from_int(7)];
        let w0 = worker_weight(0, 1, &point).unwrap();
        let w1 = worker_weight(1, 1, &point).unwrap();
        assert_eq!(w0, PaperField::from_int(1) - point[0]);
        assert_eq!(w1, point[0]);

        let config = PaperDepcsConfig::new(PaperPcsBackend::DeepFold, 2).unwrap();
        let worker_commitments = (0..2)
            .map(|worker_id| commit_worker(1 << 6, 2, worker_id, config).unwrap())
            .collect();
        let commitment =
            commit_from_worker_commitments(1 << 6, 2, config, worker_commitments).unwrap();
        let point = sample_point(commitment.nv);
        let opening = open_worker(&commitment, 1, &point).unwrap();
        let claim = f_pad_systematic_claim(&opening, [9_u8; 32]).opening_claim;
        assert_eq!(
            claim.claim_kind,
            PaperProtocol10OpeningClaimKind::FPadAtSystematic
        );
        assert_eq!(claim.claimed_value, opening.value);
        assert_eq!(claim.weight, PaperField::from_int(1));
    }
}

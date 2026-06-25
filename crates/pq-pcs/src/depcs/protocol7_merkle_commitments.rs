//! Protocol 7: Distributed Merkle Commitments to E1 and E2.
//!
//! Paper role: each worker `P_i` commits to its encoded linear combinations
//! `E1^(i)` and `E2^(i)`, sends the roots to the master `P0`, later opens
//! selected columns, and the verifier checks both per-worker Merkle proofs and
//! the aggregate equations `e1 = sum_i e1^(i)`, `e2 = sum_i e2^(i)`.
//!
//! Artifact-backed mapping:
//! - The vendored BaseFold/DeepFold PCS already contains its own oracle/root
//!   material, so this module records the Protocol 7 worker leaf as a digest of
//!   `(worker_id, row_range, oracle, pcs_commitment)`.
//! - `aggregate_worker_commitments` is Protocol 7 commit phase step 2/3:
//!   worker leaves are sorted by worker id and committed into the master root.
//! - `verify_commitment_root` is the master/verifier side of Protocol 7 root
//!   checking before Protocol 11 evaluates openings.
//!
//! Existing source-commitment coalescing is a semantics-preserving optimization:
//! only linearly equivalent openings with the same source commitment are merged.

use paper_util::random_oracle::RandomOracle;

use super::types::*;
use super::utils::digest_serialized;

pub(crate) struct Protocol7WorkerCommitmentInput {
    pub(crate) worker_id: usize,
    pub(crate) row_range: (usize, usize),
    pub(crate) oracle: RandomOracle<PaperField>,
    pub(crate) pcs_commitment: PaperPcsCommitment,
}

pub(crate) struct Protocol7CommitmentSet {
    pub(crate) commitment: PaperProtocol11Commitment,
}

pub(crate) fn worker_commitment_digest(
    commitment: &PaperProtocol11WorkerCommitment,
) -> PaperDepcsResult<[u8; 32]> {
    // Protocol 7 leaf binding. The digest is the artifact-native analogue of a
    // per-worker Merkle commitment root: it binds which worker produced the
    // leaf, which rows it owns, and the PCS oracle/commitment used later by
    // Protocol 8/9 openings.
    digest_serialized(&(
        commitment.worker_id,
        commitment.row_range,
        &commitment.oracle,
        &commitment.pcs_commitment,
    ))
}

pub(crate) fn build_worker_commitment(
    input: Protocol7WorkerCommitmentInput,
) -> PaperDepcsResult<PaperProtocol11WorkerCommitment> {
    // Protocol 7 commit phase, worker side: build the worker leaf first with an
    // empty digest, then compute the digest over the public metadata.
    let mut commitment = PaperProtocol11WorkerCommitment {
        worker_id: input.worker_id,
        row_range: input.row_range,
        oracle: input.oracle,
        pcs_commitment: input.pcs_commitment,
        leaf_digest: [0_u8; 32],
    };
    commitment.leaf_digest = worker_commitment_digest(&commitment)?;
    Ok(commitment)
}

pub(crate) fn validate_worker_commitment(
    layout: PaperLayout,
    worker_id: usize,
    commitment: &PaperProtocol11WorkerCommitment,
) -> PaperDepcsResult<()> {
    // Protocol 7 commit phase, master/verifier side: worker leaves must be in
    // the expected row partition and must re-hash to their advertised digest.
    if commitment.worker_id != worker_id
        || commitment.row_range
            != (
                worker_id * layout.shard_len,
                (worker_id + 1) * layout.shard_len,
            )
        || commitment.leaf_digest != worker_commitment_digest(commitment)?
    {
        return Err(PaperDepcsError::InvalidCommitment);
    }
    Ok(())
}

pub(crate) fn aggregate_worker_commitments(
    original_len: usize,
    workers: usize,
    config: PaperDepcsConfig,
    mut worker_commitments: Vec<PaperProtocol11WorkerCommitment>,
) -> PaperDepcsResult<Protocol7CommitmentSet> {
    let layout = PaperLayout::new(original_len, workers)?;
    if worker_commitments.len() != workers {
        return Err(PaperDepcsError::InvalidCommitment);
    }
    // Protocol 7 outputs the set of worker roots `{rt_E1^(i), rt_E2^(i)}`.
    // This artifact path uses one canonical master root over worker leaves so
    // Protocol 11 can transcript-bind the same public commitment set.
    worker_commitments.sort_by_key(|commitment| commitment.worker_id);
    for (worker_id, commitment) in worker_commitments.iter().enumerate() {
        validate_worker_commitment(layout, worker_id, commitment)?;
    }
    let root = digest_serialized(&worker_commitments)?;
    Ok(Protocol7CommitmentSet {
        commitment: PaperProtocol11Commitment {
            config,
            original_len,
            nv: layout.nv,
            workers,
            worker_bits: layout.worker_bits,
            shard_len: layout.shard_len,
            shard_nv: layout.shard_nv,
            artifact_nv: layout.artifact_nv,
            workers_commitments: worker_commitments,
            root,
        },
    })
}

pub(crate) fn verify_commitment_root(
    commitment: &PaperProtocol11Commitment,
) -> PaperDepcsResult<()> {
    // Protocol 7 verify phase, root consistency: recompute the master root from
    // the ordered worker leaves before accepting any later opening proof.
    if commitment.root != digest_serialized(&commitment.workers_commitments)? {
        return Err(PaperDepcsError::InvalidCommitment);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::artifact::PaperPcsBackend;

    #[test]
    fn protocol7_aggregates_and_checks_root() {
        let config = PaperDepcsConfig::new(PaperPcsBackend::DeepFold, 2).unwrap();
        let workers = 2;
        let original_len = 1 << 6;
        let commitments = (0..workers)
            .map(|worker_id| {
                crate::depcs::commit_worker(original_len, workers, worker_id, config).unwrap()
            })
            .collect::<Vec<_>>();
        let commitment = aggregate_worker_commitments(original_len, workers, config, commitments)
            .unwrap()
            .commitment;
        verify_commitment_root(&commitment).unwrap();

        let mut tampered = commitment;
        tampered.root[0] ^= 1;
        assert!(verify_commitment_root(&tampered).is_err());
    }
}

//! Shared deterministic helpers for artifact-backed dePCS.
//!
//! These helpers are implementation/accounting utilities. They do not define new
//! protocol steps and must not change transcript labels, serialization, or field
//! encodings without an explicit benchmark-compatibility migration.

use serde::Serialize;

use paper_util::algebra::field::MyField;

use paper_util::STEP;
use paper_util::algebra::polynomial::MultilinearPolynomial;
use pq_transcript::sha256;

use super::types::*;

pub(crate) fn deterministic_value(index: usize) -> PaperField {
    PaperField::from_parts(
        ((index as u64 + 3) * 17) & ((1_u64 << 61) - 1),
        ((index as u64 + 11) * 23) & ((1_u64 << 61) - 1),
    )
}

pub(crate) fn round_up_to_step(nv: usize) -> usize {
    let rem = nv % STEP;
    if rem == 0 { nv } else { nv + (STEP - rem) }
}

pub(crate) fn pad_values(mut values: Vec<PaperField>, artifact_nv: usize) -> Vec<PaperField> {
    let target_len = 1_usize << artifact_nv;
    values.resize(target_len, PaperField::from_int(0));
    values
}

pub(crate) fn artifact_point(point: &[PaperField], artifact_nv: usize) -> Vec<PaperField> {
    let mut padded = point.to_vec();
    padded.resize(artifact_nv, PaperField::from_int(0));
    padded
}

pub(crate) fn evaluate_multilinear_slice(
    values: &[PaperField],
    point: &[PaperField],
) -> PaperField {
    MultilinearPolynomial::new(values.to_vec()).evaluate(&point.to_vec())
}

pub(crate) fn digest_serialized<T: Serialize>(value: &T) -> PaperDepcsResult<[u8; 32]> {
    Ok(sha256(
        &bincode::serialize(value).map_err(|_| PaperDepcsError::Serialization)?,
    ))
}

pub(crate) fn serialized_size<T: Serialize>(value: &T) -> usize {
    bincode::serialized_size(value).unwrap_or(0) as usize
}

pub(crate) fn panic_message(error: Box<dyn std::any::Any + Send>) -> String {
    if let Some(message) = error.downcast_ref::<&str>() {
        (*message).to_owned()
    } else if let Some(message) = error.downcast_ref::<String>() {
        message.clone()
    } else {
        "paper PCS verifier panicked".to_owned()
    }
}

//! Shared deterministic helpers for artifact-backed dePCS.
//!
//! These helpers are implementation/accounting utilities. They do not define new
//! protocol steps and must not change transcript labels, serialization, or field
//! encodings without an explicit benchmark-compatibility migration.

use paper_util::STEP;
use paper_util::algebra::field::MyField;

use super::types::*;

pub(crate) fn deterministic_value(index: usize) -> PaperField {
    PaperField::from_parts(
        ((index as u64 + 3) * 17) & ((1_u64 << 61) - 1),
        ((index as u64 + 11) * 23) & ((1_u64 << 61) - 1),
    )
}

// STEP is a compile-time constant (currently 1); keeping the modulo makes the
// rounding correct if STEP ever changes, so clippy's modulo_one is expected.
#[allow(clippy::modulo_one)]
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

pub(crate) fn panic_message(error: Box<dyn std::any::Any + Send>) -> String {
    if let Some(message) = error.downcast_ref::<&str>() {
        (*message).to_owned()
    } else if let Some(message) = error.downcast_ref::<String>() {
        message.clone()
    } else {
        "paper PCS verifier panicked".to_owned()
    }
}

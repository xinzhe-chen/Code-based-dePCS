//! Legacy Goldilocks/local PCS backends.
//!
//! These modules preserve the repository-local compatibility implementation used
//! by `legacy-protocol11`. They are not the paper artifact BaseFold/DeepFold
//! backend used by the active dePCS `protocol11` runner.

pub mod basefold;
pub mod deepfold;
pub mod protocol11_local;

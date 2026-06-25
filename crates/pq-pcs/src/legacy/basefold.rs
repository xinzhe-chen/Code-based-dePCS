//! Legacy local BaseFold boundary.
//!
//! The historical Goldilocks `PcsBackendKind::BaseFold` path is implemented in
//! `crate::lib` on top of the repository-local transparent Merkle folding code.
//! This marker module exists so the legacy tree exposes both backend names
//! explicitly; artifact-backed BaseFold lives under `crate::artifact` and
//! `crate::depcs`.

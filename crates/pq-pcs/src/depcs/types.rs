use paper_deepfold::{self, prover as deepfold_prover};
use paper_util::algebra::field::ft255::Ft255;
use serde::{Deserialize, Serialize};

use crate::depcs::backend::{PAPER_PCS_SECURITY_BITS, PaperPcsBackend};

/// The release profile uses the 255-bit prime field already supported by the
/// vendored DeepFold implementation.  The former 122-bit extension field is
/// retained only in the vendored artifact's own regression tests.
pub type PaperField = Ft255;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PaperDepcsError {
    InvalidBackend,
    InvalidProof,
    ArtifactPanic(String),
}

pub type PaperDepcsResult<T> = Result<T, PaperDepcsError>;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PaperDepcsConfig {
    pub backend: PaperPcsBackend,
    pub rate_inv: usize,
    pub security_bits: usize,
}

impl PaperDepcsConfig {
    pub fn new(backend: PaperPcsBackend, rate_inv: usize) -> PaperDepcsResult<Self> {
        if !matches!(backend, PaperPcsBackend::DeepFold) || rate_inv != 2 {
            return Err(PaperDepcsError::InvalidBackend);
        }
        Ok(Self {
            backend,
            rate_inv,
            security_bits: PAPER_PCS_SECURITY_BITS,
        })
    }

    pub fn code_rate_log(self) -> usize {
        self.rate_inv.trailing_zeros() as usize
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum PaperPcsCommitment {
    DeepFold(paper_deepfold::Commit<PaperField>),
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum PaperPcsOpeningProof {
    DeepFold(paper_deepfold::Proof<PaperField>),
}

#[derive(Clone)]
pub(crate) enum PreparedPaperProver {
    DeepFold(deepfold_prover::Prover<PaperField>),
}

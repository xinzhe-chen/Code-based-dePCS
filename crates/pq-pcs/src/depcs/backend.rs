//! Paper-backed PCS backend descriptors for the artifact-backed dePCS path.
//!
//! These name the vendored DeepFold backend, its query policy, and the
//! source/security metadata the distributed dePCS commits to. (The older
//! single-machine "paper-native" runner that used to live alongside these types
//! was removed together with the non-distributed benchmark path.)

use paper_util::{CODE_RATE as DEFAULT_CODE_RATE, SECURITY_BITS};
use serde::{Deserialize, Serialize};

#[derive(Copy, Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum PaperPcsBackend {
    DeepFold,
}

impl PaperPcsBackend {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::DeepFold => "deepfold",
        }
    }

    pub const fn scheme_name(self) -> &'static str {
        match self {
            Self::DeepFold => "paper-depcs-deepfold",
        }
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum PaperQueryPolicy {
    ArtifactDefault,
    FixedMax,
}

impl PaperQueryPolicy {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ArtifactDefault => "artifact-default",
            Self::FixedMax => "fixed-max",
        }
    }
}

pub const PAPER_PCS_SOURCE_URL: &str = "https://github.com/paulguoyanpei/deepfold-bench";
pub const PAPER_PCS_SOURCE_REV: &str = "e4245da33690a9e2afe8f0c1e237b2edde88f6ba";
pub const PAPER_PCS_LICENSE: &str = "NO_LICENSE_FILE_IN_REPOSITORY";
pub const PAPER_PCS_HASH: &str = "Blake3";
pub const PAPER_PCS_SECURITY_BITS: usize = SECURITY_BITS;
pub const PAPER_PCS_DEFAULT_CODE_RATE_LOG: usize = DEFAULT_CODE_RATE;

pub fn paper_query_count(backend: PaperPcsBackend) -> usize {
    paper_query_count_for_code_rate(backend, PAPER_PCS_DEFAULT_CODE_RATE_LOG)
}

pub fn paper_query_count_for_code_rate(backend: PaperPcsBackend, code_rate_log: usize) -> usize {
    match backend {
        PaperPcsBackend::DeepFold => {
            let rate_inverse = 1usize << code_rate_log.max(1);
            let rho = 1.0 / rate_inverse as f64;
            let per_query_failure = (1.0 + rho) / 2.0;
            (SECURITY_BITS as f64 / -per_query_failure.log2()).ceil() as usize
        }
    }
}

pub fn paper_fair_query_count() -> usize {
    paper_query_count(PaperPcsBackend::DeepFold)
}

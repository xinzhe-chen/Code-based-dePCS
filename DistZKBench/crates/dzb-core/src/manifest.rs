use std::fs;
use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::config::ResolvedConfig;
use crate::platform::CapabilityReport;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Manifest {
    pub run_id: String,
    pub platform: String,
    pub isolation_tier: String,
    pub architecture: String,
    pub capability: CapabilityReport,
    pub notes: Vec<String>,
}

impl Manifest {
    pub fn from_resolved(config: &ResolvedConfig) -> Self {
        Self {
            run_id: config.run_id.clone(),
            platform: config.platform.as_str().to_owned(),
            isolation_tier: config.isolation_tier.as_str().to_owned(),
            architecture: config.capability.architecture.clone(),
            capability: config.capability.clone(),
            notes: config.capability.notes.clone(),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RunJson {
    pub run_id: String,
    pub experiment: String,
    pub platform: String,
    pub isolation_tier: String,
    pub status: String,
    pub prover_critical_path_ms: f64,
    pub prover_wall_controller_ms: f64,
    pub proof_size_bytes: usize,
    pub proof_sha256: String,
    pub total_protocol_bytes: u64,
    pub total_framed_bytes: u64,
    pub message_count: u64,
    pub verifier_median_ms: f64,
    pub rank_pids: Vec<u32>,
    pub verifier_pid: Option<u32>,
    pub communication_precision: String,
    pub platform_evidence: serde_json::Value,
    pub best_effort_warning: Option<String>,
}

pub fn write_json_pretty<T: Serialize>(path: &Path, value: &T) -> std::io::Result<()> {
    let text = serde_json::to_string_pretty(value)
        .map_err(|error| std::io::Error::other(error.to_string()))?;
    fs::write(path, text)
}

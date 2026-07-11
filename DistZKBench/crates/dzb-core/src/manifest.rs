use std::fs;
use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::config::ResolvedConfig;
use crate::platform::CapabilityReport;

#[derive(Clone, Copy, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RunStatus {
    Preparing,
    Running,
    Verifying,
    #[default]
    Ok,
    Failed,
    Timeout,
    Oom,
    Cancelled,
}

impl RunStatus {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Preparing => "preparing",
            Self::Running => "running",
            Self::Verifying => "verifying",
            Self::Ok => "ok",
            Self::Failed => "failed",
            Self::Timeout => "timeout",
            Self::Oom => "oom",
            Self::Cancelled => "cancelled",
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Manifest {
    pub schema_version: u32,
    pub run_id: String,
    pub platform: String,
    pub isolation_tier: String,
    pub architecture: String,
    pub capability: CapabilityReport,
    pub notes: Vec<String>,
    pub framework_commit: String,
    pub adapter_commit: String,
    pub dirty_state: bool,
    pub binary_sha256: String,
    pub toolchain: String,
    pub system: serde_json::Value,
    pub release_blockers: Vec<String>,
    #[serde(default)]
    pub config_hash: String,
    #[serde(default)]
    pub execution_fingerprint: String,
}

impl Manifest {
    pub fn from_resolved(config: &ResolvedConfig) -> Self {
        Self {
            schema_version: 2,
            run_id: config.run_id.clone(),
            platform: config.platform.as_str().to_owned(),
            isolation_tier: config.isolation_tier.as_str().to_owned(),
            architecture: config.capability.architecture.clone(),
            capability: config.capability.clone(),
            notes: config.capability.notes.clone(),
            framework_commit: command_output("git", &["rev-parse", "HEAD"]),
            adapter_commit: command_output("git", &["rev-parse", "HEAD"]),
            dirty_state: !command_output("git", &["status", "--porcelain"]).is_empty(),
            binary_sha256: std::env::current_exe()
                .ok()
                .map(|path| command_output("shasum", &["-a", "256", &path.to_string_lossy()]))
                .unwrap_or_else(|| "unavailable".to_owned()),
            toolchain: command_output("rustc", &["--version"]),
            system: serde_json::json!({
                "kernel": command_output("uname", &["-a"]),
                "cpu_topology": command_output("lscpu", &["--json"]),
                "numa": command_output("lscpu", &["-e=cpu,node,socket,core"]),
                "governor": read_glob_value("/sys/devices/system/cpu/cpu0/cpufreq/scaling_governor"),
                "turbo": read_glob_value("/sys/devices/system/cpu/intel_pstate/no_turbo"),
                "transparent_huge_pages": read_glob_value("/sys/kernel/mm/transparent_hugepage/enabled"),
            }),
            release_blockers: vec![
                "vendored DeepFold redistribution permission is not recorded; internal validation only"
                    .to_owned(),
            ],
            config_hash: config.config_hash.clone(),
            execution_fingerprint: config.execution_fingerprint.clone(),
        }
    }
}

fn command_output(command: &str, args: &[&str]) -> String {
    std::process::Command::new(command)
        .args(args)
        .output()
        .ok()
        .filter(|output| output.status.success())
        .map(|output| String::from_utf8_lossy(&output.stdout).trim().to_owned())
        .filter(|output| !output.is_empty())
        .unwrap_or_else(|| "unavailable".to_owned())
}

fn read_glob_value(path: &str) -> String {
    fs::read_to_string(path)
        .map(|value| value.trim().to_owned())
        .unwrap_or_else(|_| "unavailable".to_owned())
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RunJson {
    #[serde(default = "run_schema_v2")]
    pub schema_version: u32,
    pub run_id: String,
    pub experiment: String,
    pub platform: String,
    pub isolation_tier: String,
    pub status: String,
    pub prover_critical_path_ms: f64,
    pub prover_wall_controller_ms: f64,
    pub proof_size_bytes: usize,
    pub proof_sha256: String,
    #[serde(default)]
    pub statement_size_bytes: usize,
    #[serde(default)]
    pub statement_sha256: Option<String>,
    pub total_protocol_bytes: u64,
    pub total_framed_bytes: u64,
    pub message_count: u64,
    pub verifier_median_ms: f64,
    pub rank_pids: Vec<u32>,
    pub verifier_pid: Option<u32>,
    pub communication_precision: String,
    pub platform_evidence: serde_json::Value,
    pub best_effort_warning: Option<String>,
    #[serde(default)]
    pub config_hash: String,
    #[serde(default)]
    pub execution_fingerprint: String,
}

const fn run_schema_v2() -> u32 {
    2
}

pub fn write_json_pretty<T: Serialize>(path: &Path, value: &T) -> std::io::Result<()> {
    let text = serde_json::to_string_pretty(value)
        .map_err(|error| std::io::Error::other(error.to_string()))?;
    fs::write(path, text)
}

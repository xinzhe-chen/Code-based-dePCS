use std::path::PathBuf;

use dzb_core::CapabilityReport;

pub type Pid = u32;
pub type RunId = String;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResolvedConfig {
    pub run_id: RunId,
    pub worker_threads: usize,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HostPlan {
    pub run_id: RunId,
    pub notes: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RankLaunchSpec {
    pub run_id: RunId,
    pub rank: usize,
    pub executable: PathBuf,
    pub args: Vec<String>,
    pub env: Vec<(String, String)>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifierLaunchSpec {
    pub run_id: RunId,
    pub executable: PathBuf,
    pub args: Vec<String>,
    pub env: Vec<(String, String)>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProcessHandle {
    pub pid: Pid,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RankHandle {
    pub rank: usize,
    pub process: ProcessHandle,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TopologyPlan {
    pub world_size: usize,
    pub base_port: u16,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NetworkPlan {
    pub listen_addrs: Vec<String>,
    pub notes: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MeasurementHandle {
    pub pids: Vec<Pid>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProcessSample {
    pub pid: Pid,
    pub resident_bytes: Option<u64>,
    pub virtual_bytes: Option<u64>,
    pub thread_count: Option<usize>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MeasurementReport {
    pub samples: Vec<ProcessSample>,
    pub notes: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PlatformError {
    message: String,
}

impl PlatformError {
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

impl std::fmt::Display for PlatformError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl std::error::Error for PlatformError {}

pub type PlatformResult<T> = Result<T, PlatformError>;

pub trait PlatformBackend {
    fn detect_capabilities(&self) -> PlatformResult<CapabilityReport>;

    fn prepare_host(&self, cfg: &ResolvedConfig) -> PlatformResult<HostPlan>;

    fn launch_rank(&self, spec: RankLaunchSpec) -> PlatformResult<RankHandle>;

    fn launch_verifier(&self, spec: VerifierLaunchSpec) -> PlatformResult<ProcessHandle>;

    fn setup_network(&self, plan: &TopologyPlan) -> PlatformResult<NetworkPlan>;

    fn start_measurement(&self, pids: &[Pid]) -> PlatformResult<MeasurementHandle>;

    fn sample_process(&self, pid: Pid) -> PlatformResult<ProcessSample>;

    fn stop_measurement(&self, handle: MeasurementHandle) -> PlatformResult<MeasurementReport>;

    fn cleanup(&self, run_id: &RunId) -> PlatformResult<()>;
}

pub fn standard_thread_budget_env(worker_threads: usize) -> Vec<(String, String)> {
    let value = worker_threads.to_string();
    [
        "RAYON_NUM_THREADS",
        "OMP_NUM_THREADS",
        "OPENBLAS_NUM_THREADS",
        "MKL_NUM_THREADS",
        "NUMEXPR_NUM_THREADS",
        "TOKIO_WORKER_THREADS",
    ]
    .into_iter()
    .map(|key| (key.to_owned(), value.clone()))
    .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn standard_env_sets_common_thread_pools() {
        let env = standard_thread_budget_env(1);
        assert!(env.contains(&("RAYON_NUM_THREADS".to_owned(), "1".to_owned())));
        assert!(env.contains(&("TOKIO_WORKER_THREADS".to_owned(), "1".to_owned())));
    }
}

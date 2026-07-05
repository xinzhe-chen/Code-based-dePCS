use std::fs;
use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::platform::{CapabilityReport, IsolationTier, Platform};
use crate::run_id::new_run_id;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConfigError(pub String);

impl std::fmt::Display for ConfigError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl std::error::Error for ConfigError {}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Config {
    pub experiment: ExperimentConfig,
    pub platform: PlatformConfig,
    pub roles: RolesConfig,
    pub topology: TopologyConfig,
    pub resources: ResourcesConfig,
    pub memory: MemoryConfig,
    pub cache: CacheConfig,
    pub network: NetworkConfig,
    pub metrics: MetricsConfig,
    pub protocol: ProtocolConfig,
    pub timeouts: TimeoutsConfig,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default)]
pub struct ExperimentConfig {
    pub name: String,
    pub run_id: String,
    pub repetitions: usize,
    pub warmups: usize,
    pub random_seed: u64,
    pub fail_on_warning: bool,
    pub output_dir: String,
}

impl Default for ExperimentConfig {
    fn default() -> Self {
        Self {
            name: "toy".to_owned(),
            run_id: "auto".to_owned(),
            repetitions: 1,
            warmups: 0,
            random_seed: 1,
            fail_on_warning: false,
            output_dir: "results".to_owned(),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum PlatformBackendName {
    Auto,
    Linux,
    Darwin,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default)]
pub struct PlatformConfig {
    pub backend: PlatformBackendName,
}

impl Default for PlatformConfig {
    fn default() -> Self {
        Self {
            backend: PlatformBackendName::Auto,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default)]
pub struct RolesConfig {
    pub prover_ranks: usize,
    pub master_rank: usize,
    pub master_participates: bool,
    pub master_has_local_shard: bool,
    pub verifier_enabled: bool,
}

impl Default for RolesConfig {
    fn default() -> Self {
        Self {
            prover_ranks: 2,
            master_rank: 0,
            master_participates: true,
            master_has_local_shard: true,
            verifier_enabled: true,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum TopologyKind {
    Star,
    FullMesh,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default)]
pub struct TopologyConfig {
    #[serde(rename = "type")]
    pub kind: TopologyKind,
    pub worker_to_worker: String,
    pub enforce_topology: bool,
}

impl Default for TopologyConfig {
    fn default() -> Self {
        Self {
            kind: TopologyKind::Star,
            worker_to_worker: "forbidden".to_owned(),
            enforce_topology: true,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default)]
pub struct ResourcesConfig {
    pub worker_threads: usize,
    pub verifier_threads: String,
    pub no_overcommit: bool,
    pub check_extra_threads: bool,
}

impl Default for ResourcesConfig {
    fn default() -> Self {
        Self {
            worker_threads: 1,
            verifier_threads: "same_as_worker".to_owned(),
            no_overcommit: true,
            check_extra_threads: true,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default)]
pub struct MemoryConfig {
    pub per_rank_limit: String,
    pub macos_sampling: String,
    pub macos_enforcement: String,
    pub cgroup: bool,
}

impl Default for MemoryConfig {
    fn default() -> Self {
        Self {
            per_rank_limit: "1GiB".to_owned(),
            macos_sampling: "phase_boundary".to_owned(),
            macos_enforcement: "watchdog".to_owned(),
            cgroup: false,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default)]
pub struct CacheConfig {
    pub mode: String,
    pub fail_if_unavailable: bool,
}

impl Default for CacheConfig {
    fn default() -> Self {
        Self {
            mode: "none".to_owned(),
            fail_if_unavailable: false,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default)]
pub struct NetworkConfig {
    pub transport: String,
    pub mode: String,
    pub base_port: u16,
    pub tcp_nodelay: bool,
    pub max_frame_payload: String,
    pub shaper: ShaperConfig,
}

impl Default for NetworkConfig {
    fn default() -> Self {
        Self {
            transport: "tcp".to_owned(),
            mode: "loopback".to_owned(),
            base_port: 39000,
            tcp_nodelay: true,
            max_frame_payload: "16MiB".to_owned(),
            shaper: ShaperConfig::default(),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default)]
pub struct ShaperConfig {
    pub bandwidth: String,
    pub latency: String,
    pub jitter: String,
    pub loss: String,
    pub per_edge: bool,
}

impl Default for ShaperConfig {
    fn default() -> Self {
        Self {
            bandwidth: "0".to_owned(),
            latency: "0ms".to_owned(),
            jitter: "0ms".to_owned(),
            loss: "0%".to_owned(),
            per_edge: true,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default)]
pub struct MetricsConfig {
    pub phase_tracing: bool,
    pub communication_breakdown: bool,
    pub chrome_trace: bool,
    pub collect_perf: bool,
    pub output_formats: Vec<String>,
}

impl Default for MetricsConfig {
    fn default() -> Self {
        Self {
            phase_tracing: true,
            communication_breakdown: true,
            chrome_trace: true,
            collect_perf: false,
            output_formats: vec!["json".to_owned(), "csv".to_owned(), "html".to_owned()],
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default)]
pub struct ProtocolConfig {
    pub adapter: String,
    pub mode: String,
    pub command: String,
    pub args: Vec<String>,
    pub toy: ToyProtocolConfig,
}

impl Default for ProtocolConfig {
    fn default() -> Self {
        Self {
            adapter: "toy-star-aggregate".to_owned(),
            mode: "sdk-binary".to_owned(),
            command: String::new(),
            args: Vec::new(),
            toy: ToyProtocolConfig::default(),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default)]
pub struct ToyProtocolConfig {
    pub message_bytes: usize,
}

impl Default for ToyProtocolConfig {
    fn default() -> Self {
        Self {
            message_bytes: 1024,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default)]
pub struct TimeoutsConfig {
    pub connection_setup_sec: u64,
    pub prove_sec: u64,
    pub verify_sec: u64,
}

impl Default for TimeoutsConfig {
    fn default() -> Self {
        Self {
            connection_setup_sec: 30,
            prove_sec: 3600,
            verify_sec: 300,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ResolvedConfig {
    pub original: Config,
    pub run_id: String,
    pub platform: Platform,
    pub isolation_tier: IsolationTier,
    pub result_dir: String,
    pub verifier_threads: usize,
    pub capability: CapabilityReport,
}

pub fn load_config(path: &Path) -> Result<Config, ConfigError> {
    let text = fs::read_to_string(path)
        .map_err(|error| ConfigError(format!("read config failed: {error}")))?;
    serde_yaml::from_str(&text).map_err(|error| ConfigError(format!("parse yaml failed: {error}")))
}

pub fn resolve_config(
    config: Config,
    capability: CapabilityReport,
) -> Result<ResolvedConfig, ConfigError> {
    let platform = match config.platform.backend {
        PlatformBackendName::Auto => Platform::host(),
        PlatformBackendName::Linux => Platform::Linux,
        PlatformBackendName::Darwin => Platform::Darwin,
    };
    if platform == Platform::Unsupported {
        return Err(ConfigError("unsupported host platform".to_owned()));
    }
    if platform != capability.platform {
        return Err(ConfigError(format!(
            "requested platform {platform} but capability report is for {}",
            capability.platform
        )));
    }
    if capability.isolation_tier == IsolationTier::Unsupported {
        return Err(ConfigError(format!(
            "requested platform {platform} is unsupported on this host"
        )));
    }
    if config.roles.prover_ranks == 0 {
        return Err(ConfigError(
            "roles.prover_ranks must be positive".to_owned(),
        ));
    }
    if config.roles.master_rank >= config.roles.prover_ranks {
        return Err(ConfigError("roles.master_rank out of range".to_owned()));
    }
    if config.cache.mode == "resctrl_cat" && !capability.resource_control.cache_isolation.supported
    {
        return Err(ConfigError(
            "resctrl CAT was requested but is unavailable on this platform".to_owned(),
        ));
    }
    if config.memory.cgroup && !capability.memory_control.hard_limit.supported {
        return Err(ConfigError(
            "memory.cgroup was requested but cgroup v2 hard memory limit is unavailable".to_owned(),
        ));
    }
    if platform == Platform::Darwin && config.network.mode == "netns_veth" {
        return Err(ConfigError(
            "network.mode=netns_veth is unavailable on macOS Darwin backend".to_owned(),
        ));
    }
    if platform == Platform::Linux
        && config.network.mode == "netns_veth"
        && (!capability.network_emulation.netns_or_equivalent.supported
            || !capability.network_emulation.kernel_shaper.supported)
    {
        return Err(ConfigError(
            "network.mode=netns_veth requires Linux ip netns and tc".to_owned(),
        ));
    }
    if config.metrics.collect_perf && !capability.perf_counters.linux_perf_equivalent.supported {
        return Err(ConfigError(
            "metrics.collect_perf requested but Linux-equivalent perf counters are unavailable"
                .to_owned(),
        ));
    }
    if config.experiment.fail_on_warning && !capability.unsupported_features.is_empty() {
        return Err(ConfigError(format!(
            "requested fail_on_warning but unsupported features are present: {:?}",
            capability.unsupported_features
        )));
    }
    let run_id = if config.experiment.run_id == "auto" {
        new_run_id(&config.experiment.name)
    } else {
        config.experiment.run_id.clone()
    };
    let verifier_threads = if config.resources.verifier_threads == "same_as_worker" {
        config.resources.worker_threads
    } else {
        config
            .resources
            .verifier_threads
            .parse::<usize>()
            .map_err(|_| ConfigError("invalid resources.verifier_threads".to_owned()))?
    };
    let result_dir = format!(
        "{}/{}/{}",
        config.experiment.output_dir, config.experiment.name, run_id
    );
    Ok(ResolvedConfig {
        original: config,
        run_id,
        platform,
        isolation_tier: capability.isolation_tier,
        result_dir,
        verifier_threads,
        capability,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::platform::{
        FeatureAvailability, MemoryControl, NetworkEmulation, PerfCounters, ResourceControl,
    };

    fn capability(platform: Platform, tier: IsolationTier) -> CapabilityReport {
        CapabilityReport {
            platform,
            architecture: "test".to_owned(),
            isolation_tier: tier,
            resource_control: ResourceControl {
                process_per_rank: FeatureAvailability::strict("process"),
                hard_cpu_affinity: FeatureAvailability::unsupported("none"),
                fixed_thread_budget: FeatureAvailability::strict("threads"),
                cache_isolation: FeatureAvailability::unsupported("none"),
                numa_binding: FeatureAvailability::unsupported("none"),
            },
            memory_control: MemoryControl {
                hard_limit: FeatureAvailability::unsupported("none"),
                peak_measurement: FeatureAvailability::best_effort("sample"),
                enforcement: "watchdog".to_owned(),
            },
            network_emulation: NetworkEmulation {
                tcp_data_plane: FeatureAvailability::strict("tcp"),
                loopback: FeatureAvailability::strict("loopback"),
                netns_or_equivalent: FeatureAvailability::unsupported("none"),
                kernel_shaper: FeatureAvailability::unsupported("none"),
                userspace_shaper: FeatureAvailability::best_effort("shape"),
            },
            perf_counters: PerfCounters {
                linux_perf_equivalent: FeatureAvailability::unsupported("none"),
                supplemental: FeatureAvailability::unsupported("none"),
            },
            thermal_monitoring: FeatureAvailability::best_effort("thermal"),
            unsupported_features: vec![],
            notes: vec![],
        }
    }

    #[test]
    fn resolves_auto_run_id() {
        let config = Config {
            platform: PlatformConfig {
                backend: PlatformBackendName::Darwin,
            },
            ..Config::default()
        };
        let resolved = resolve_config(
            config,
            capability(Platform::Darwin, IsolationTier::BestEffort),
        )
        .unwrap_or_else(|error| panic!("{error}"));
        assert!(resolved.run_id.starts_with("toy-"));
        assert_eq!(resolved.verifier_threads, 1);
    }

    #[test]
    fn darwin_resctrl_strict_fails() {
        let mut config = Config {
            platform: PlatformConfig {
                backend: PlatformBackendName::Darwin,
            },
            ..Config::default()
        };
        config.cache.mode = "resctrl_cat".to_owned();
        config.cache.fail_if_unavailable = true;
        assert!(
            resolve_config(
                config,
                capability(Platform::Darwin, IsolationTier::BestEffort)
            )
            .is_err()
        );
    }
}

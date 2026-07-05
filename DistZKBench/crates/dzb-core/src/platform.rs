use std::fmt::{Display, Formatter};

use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Platform {
    Linux,
    Darwin,
    Unsupported,
}

impl Platform {
    pub const fn host() -> Self {
        if cfg!(target_os = "linux") {
            Self::Linux
        } else if cfg!(target_os = "macos") {
            Self::Darwin
        } else {
            Self::Unsupported
        }
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Linux => "linux",
            Self::Darwin => "darwin",
            Self::Unsupported => "unsupported",
        }
    }
}

impl Display for Platform {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.as_str())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum IsolationTier {
    Strict,
    BestEffort,
    Unsupported,
}

impl IsolationTier {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Strict => "strict",
            Self::BestEffort => "best_effort",
            Self::Unsupported => "unsupported",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct FeatureAvailability {
    pub supported: bool,
    pub strict: bool,
    pub detail: String,
}

impl FeatureAvailability {
    pub fn strict(detail: impl Into<String>) -> Self {
        Self {
            supported: true,
            strict: true,
            detail: detail.into(),
        }
    }

    pub fn best_effort(detail: impl Into<String>) -> Self {
        Self {
            supported: true,
            strict: false,
            detail: detail.into(),
        }
    }

    pub fn unsupported(detail: impl Into<String>) -> Self {
        Self {
            supported: false,
            strict: false,
            detail: detail.into(),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ResourceControl {
    pub process_per_rank: FeatureAvailability,
    pub hard_cpu_affinity: FeatureAvailability,
    pub fixed_thread_budget: FeatureAvailability,
    pub cache_isolation: FeatureAvailability,
    pub numa_binding: FeatureAvailability,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct MemoryControl {
    pub hard_limit: FeatureAvailability,
    pub peak_measurement: FeatureAvailability,
    pub enforcement: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct NetworkEmulation {
    pub tcp_data_plane: FeatureAvailability,
    pub loopback: FeatureAvailability,
    pub netns_or_equivalent: FeatureAvailability,
    pub kernel_shaper: FeatureAvailability,
    pub userspace_shaper: FeatureAvailability,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct PerfCounters {
    pub linux_perf_equivalent: FeatureAvailability,
    pub supplemental: FeatureAvailability,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct CapabilityReport {
    pub platform: Platform,
    pub architecture: String,
    pub isolation_tier: IsolationTier,
    pub resource_control: ResourceControl,
    pub memory_control: MemoryControl,
    pub network_emulation: NetworkEmulation,
    pub perf_counters: PerfCounters,
    pub thermal_monitoring: FeatureAvailability,
    pub unsupported_features: Vec<String>,
    pub notes: Vec<String>,
}

impl CapabilityReport {
    pub fn requires_best_effort_warning(&self) -> bool {
        self.isolation_tier == IsolationTier::BestEffort
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_platform_is_known_or_explicitly_unsupported() {
        assert!(matches!(
            Platform::host(),
            Platform::Linux | Platform::Darwin | Platform::Unsupported
        ));
    }

    #[test]
    fn best_effort_reports_require_warning() {
        let report = CapabilityReport {
            platform: Platform::Darwin,
            architecture: "arm64".to_owned(),
            isolation_tier: IsolationTier::BestEffort,
            resource_control: ResourceControl {
                process_per_rank: FeatureAvailability::strict("os process"),
                hard_cpu_affinity: FeatureAvailability::unsupported("no hard affinity"),
                fixed_thread_budget: FeatureAvailability::strict("env guard"),
                cache_isolation: FeatureAvailability::unsupported("no CAT"),
                numa_binding: FeatureAvailability::unsupported("unified memory"),
            },
            memory_control: MemoryControl {
                hard_limit: FeatureAvailability::unsupported("no cgroup"),
                peak_measurement: FeatureAvailability::best_effort("Mach task_info"),
                enforcement: "watchdog".to_owned(),
            },
            network_emulation: NetworkEmulation {
                tcp_data_plane: FeatureAvailability::strict("TCP"),
                loopback: FeatureAvailability::strict("loopback"),
                netns_or_equivalent: FeatureAvailability::unsupported("no netns"),
                kernel_shaper: FeatureAvailability::unsupported("no tc"),
                userspace_shaper: FeatureAvailability::best_effort("token bucket"),
            },
            perf_counters: PerfCounters {
                linux_perf_equivalent: FeatureAvailability::unsupported("no perf_event_open"),
                supplemental: FeatureAvailability::best_effort("powermetrics"),
            },
            thermal_monitoring: FeatureAvailability::best_effort("ProcessInfo"),
            unsupported_features: vec!["resctrl_cat".to_owned()],
            notes: vec![],
        };

        assert!(report.requires_best_effort_warning());
    }
}

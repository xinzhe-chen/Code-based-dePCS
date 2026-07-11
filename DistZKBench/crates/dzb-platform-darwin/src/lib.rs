use std::process::Command;

use dzb_core::{
    CapabilityReport, FeatureAvailability, IsolationTier, MemoryControl, NetworkEmulation,
    PerfCounters, Platform, ResourceControl,
};
use dzb_platform::{
    HostPlan, MeasurementHandle, MeasurementReport, NetworkPlan, Pid, PlatformBackend,
    PlatformError, PlatformResult, ProcessHandle, ProcessSample, RankHandle, RankLaunchSpec,
    ResolvedConfig, RunId, TopologyPlan, VerifierLaunchSpec,
};

#[derive(Clone, Debug, Default)]
pub struct DarwinBackend;

impl DarwinBackend {
    pub fn new() -> Self {
        Self
    }
}

impl PlatformBackend for DarwinBackend {
    fn detect_capabilities(&self) -> PlatformResult<CapabilityReport> {
        Ok(darwin_capability_report())
    }

    fn prepare_host(&self, cfg: &ResolvedConfig) -> PlatformResult<HostPlan> {
        Ok(HostPlan {
            run_id: cfg.run_id.clone(),
            notes: vec![
                "Darwin backend is best-effort; hard CPU, cache, cgroup, netns, tc, and perf isolation are unavailable".to_owned(),
            ],
        })
    }

    fn launch_rank(&self, spec: RankLaunchSpec) -> PlatformResult<RankHandle> {
        let mut command = Command::new(&spec.executable);
        command.args(&spec.args);
        command.envs(spec.env);
        command.env("DZB_DARWIN_QOS", "user_initiated");
        let child = command
            .spawn()
            .map_err(|error| PlatformError::new(format!("launch Darwin rank failed: {error}")))?;
        Ok(RankHandle {
            rank: spec.rank,
            process: ProcessHandle { pid: child.id() },
        })
    }

    fn launch_verifier(&self, spec: VerifierLaunchSpec) -> PlatformResult<ProcessHandle> {
        let mut command = Command::new(&spec.executable);
        command.args(&spec.args);
        command.envs(spec.env);
        command.env("DZB_DARWIN_QOS", "user_initiated");
        let child = command.spawn().map_err(|error| {
            PlatformError::new(format!("launch Darwin verifier failed: {error}"))
        })?;
        Ok(ProcessHandle { pid: child.id() })
    }

    fn setup_network(&self, plan: &TopologyPlan) -> PlatformResult<NetworkPlan> {
        let listen_addrs = (0..plan.world_size)
            .map(|rank| format!("127.0.0.1:{}", plan.base_port as usize + rank))
            .collect();
        Ok(NetworkPlan {
            listen_addrs,
            notes: vec![
                "Darwin supports loopback TCP and userspace_shaper; netns/tc are unsupported"
                    .to_owned(),
            ],
        })
    }

    fn start_measurement(&self, pids: &[Pid]) -> PlatformResult<MeasurementHandle> {
        Ok(MeasurementHandle {
            pids: pids.to_vec(),
        })
    }

    fn sample_process(&self, pid: Pid) -> PlatformResult<ProcessSample> {
        sample_with_ps(pid)
    }

    fn stop_measurement(&self, handle: MeasurementHandle) -> PlatformResult<MeasurementReport> {
        let mut samples = Vec::with_capacity(handle.pids.len());
        for pid in handle.pids {
            if let Ok(sample) = self.sample_process(pid) {
                samples.push(sample);
            }
        }
        Ok(MeasurementReport {
            samples,
            notes: vec![
                "MVP sample uses ps as an external best-effort fallback; phase-boundary Mach task_info belongs in dzb-sdk".to_owned(),
            ],
        })
    }

    fn cleanup(&self, _run_id: &RunId) -> PlatformResult<()> {
        Ok(())
    }
}

pub fn darwin_capability_report() -> CapabilityReport {
    let is_darwin = cfg!(target_os = "macos");
    let powermetrics = is_darwin && command_available("powermetrics");
    let perflevels = detect_perflevels();

    let mut notes = vec![
        "macOS Apple Silicon backend is for portability and supplemental benchmarking".to_owned(),
        "hard affinity, cgroup memory, netns/tc, and perf_event_open are unavailable".to_owned(),
    ];
    if let Some(summary) = perflevels {
        notes.push(summary);
    }

    CapabilityReport {
        platform: Platform::Darwin,
        architecture: std::env::consts::ARCH.to_owned(),
        isolation_tier: if is_darwin {
            IsolationTier::BestEffort
        } else {
            IsolationTier::Unsupported
        },
        resource_control: ResourceControl {
            process_per_rank: FeatureAvailability::strict("independent OS processes"),
            hard_cpu_affinity: FeatureAvailability::unsupported(
                "macOS does not expose Linux-equivalent hard affinity",
            ),
            fixed_thread_budget: FeatureAvailability::strict("environment guards plus task checks"),
            cache_isolation: FeatureAvailability::unsupported(
                "LLC partitioning is intentionally not requested or collected",
            ),
            numa_binding: FeatureAvailability::unsupported(
                "not applicable to Apple Silicon unified memory",
            ),
        },
        memory_control: MemoryControl {
            hard_limit: FeatureAvailability::unsupported("no cgroup v2 memory.max equivalent"),
            peak_measurement: FeatureAvailability::best_effort(
                "Mach task_info phase-boundary sampling, ps fallback",
            ),
            enforcement: "watchdog_best_effort".to_owned(),
        },
        network_emulation: NetworkEmulation {
            tcp_data_plane: FeatureAvailability::strict("TCP"),
            loopback: FeatureAvailability::strict("loopback TCP"),
            netns_or_equivalent: FeatureAvailability::unsupported("network namespaces unavailable"),
            kernel_shaper: FeatureAvailability::unsupported("tc netem unavailable"),
            userspace_shaper: FeatureAvailability::best_effort("token-bucket frame pacing"),
        },
        perf_counters: PerfCounters {
            linux_perf_equivalent: FeatureAvailability::unsupported(
                "perf_event_open unavailable on macOS",
            ),
            supplemental: if powermetrics {
                FeatureAvailability::best_effort("powermetrics detected")
            } else {
                FeatureAvailability::unsupported("powermetrics unavailable or not on PATH")
            },
        },
        thermal_monitoring: FeatureAvailability::best_effort(
            "ProcessInfo thermal state / powermetrics when enabled",
        ),
        unsupported_features: vec![
            "hard_cpu_affinity".to_owned(),
            "cgroup_memory_limit".to_owned(),
            "netns_veth".to_owned(),
            "tc_netem".to_owned(),
            "perf_event_open".to_owned(),
            "numa_binding".to_owned(),
        ],
        notes,
    }
}

fn sample_with_ps(pid: Pid) -> PlatformResult<ProcessSample> {
    let output = Command::new("ps")
        .args(["-o", "rss=", "-o", "vsz=", "-o", "thcount=", "-p"])
        .arg(pid.to_string())
        .output()
        .map_err(|error| PlatformError::new(format!("run ps failed: {error}")))?;
    if !output.status.success() {
        return Err(PlatformError::new("ps did not return process sample"));
    }
    let stdout = String::from_utf8(output.stdout)
        .map_err(|error| PlatformError::new(format!("ps output was not utf8: {error}")))?;
    parse_ps_sample(pid, &stdout)
}

fn parse_ps_sample(pid: Pid, stdout: &str) -> PlatformResult<ProcessSample> {
    let Some(line) = stdout.lines().find(|line| !line.trim().is_empty()) else {
        return Err(PlatformError::new("empty ps output"));
    };
    let fields = line.split_whitespace().collect::<Vec<_>>();
    let resident_bytes = fields
        .first()
        .and_then(|value| value.parse::<u64>().ok())
        .map(|kib| kib * 1024);
    let virtual_bytes = fields
        .get(1)
        .and_then(|value| value.parse::<u64>().ok())
        .map(|kib| kib * 1024);
    let thread_count = fields.get(2).and_then(|value| value.parse::<usize>().ok());
    Ok(ProcessSample {
        pid,
        resident_bytes,
        virtual_bytes,
        thread_count,
    })
}

fn detect_perflevels() -> Option<String> {
    if !cfg!(target_os = "macos") {
        return None;
    }
    let output = Command::new("sysctl").arg("-a").output().ok()?;
    if !output.status.success() {
        return None;
    }
    let text = String::from_utf8(output.stdout).ok()?;
    let count = text
        .lines()
        .filter(|line| line.contains("perflevel"))
        .take(16)
        .count();
    (count > 0).then(|| format!("core_type_detection=sysctl_best_effort perflevel_keys={count}"))
}

fn command_available(command: &str) -> bool {
    let Some(path) = std::env::var_os("PATH") else {
        return false;
    };
    std::env::split_paths(&path).any(|dir| dir.join(command).is_file())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn darwin_report_is_best_effort_or_unsupported() {
        let report = darwin_capability_report();
        assert_eq!(report.platform, Platform::Darwin);
        assert!(matches!(
            report.isolation_tier,
            IsolationTier::BestEffort | IsolationTier::Unsupported
        ));
        assert!(report.requires_best_effort_warning() || !cfg!(target_os = "macos"));
    }

    #[test]
    fn parses_ps_sample() {
        let sample = match parse_ps_sample(7, "  1024  2048  3\n") {
            Ok(sample) => sample,
            Err(error) => panic!("sample should parse: {error}"),
        };
        assert_eq!(sample.resident_bytes, Some(1024 * 1024));
        assert_eq!(sample.virtual_bytes, Some(2048 * 1024));
        assert_eq!(sample.thread_count, Some(3));
    }
}

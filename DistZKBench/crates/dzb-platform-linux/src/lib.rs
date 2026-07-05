use std::fs;
use std::path::Path;
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
pub struct LinuxBackend;

impl LinuxBackend {
    pub fn new() -> Self {
        Self
    }
}

impl PlatformBackend for LinuxBackend {
    fn detect_capabilities(&self) -> PlatformResult<CapabilityReport> {
        Ok(linux_capability_report())
    }

    fn prepare_host(&self, cfg: &ResolvedConfig) -> PlatformResult<HostPlan> {
        Ok(HostPlan {
            run_id: cfg.run_id.clone(),
            notes: vec![
                "strict Linux host preparation is delegated to cgroup/cpuset/resctrl/netns modules"
                    .to_owned(),
            ],
        })
    }

    fn launch_rank(&self, spec: RankLaunchSpec) -> PlatformResult<RankHandle> {
        let mut command = Command::new(&spec.executable);
        command.args(&spec.args);
        command.envs(spec.env);
        let child = command
            .spawn()
            .map_err(|error| PlatformError::new(format!("launch rank failed: {error}")))?;
        Ok(RankHandle {
            rank: spec.rank,
            process: ProcessHandle { pid: child.id() },
        })
    }

    fn launch_verifier(&self, spec: VerifierLaunchSpec) -> PlatformResult<ProcessHandle> {
        let mut command = Command::new(&spec.executable);
        command.args(&spec.args);
        command.envs(spec.env);
        let child = command
            .spawn()
            .map_err(|error| PlatformError::new(format!("launch verifier failed: {error}")))?;
        Ok(ProcessHandle { pid: child.id() })
    }

    fn setup_network(&self, plan: &TopologyPlan) -> PlatformResult<NetworkPlan> {
        let listen_addrs = (0..plan.world_size)
            .map(|rank| format!("127.0.0.1:{}", plan.base_port as usize + rank))
            .collect();
        Ok(NetworkPlan {
            listen_addrs,
            notes: vec![
                "loopback plan only; netns/veth/tc setup is a strict Linux module".to_owned(),
            ],
        })
    }

    fn start_measurement(&self, pids: &[Pid]) -> PlatformResult<MeasurementHandle> {
        Ok(MeasurementHandle {
            pids: pids.to_vec(),
        })
    }

    fn sample_process(&self, pid: Pid) -> PlatformResult<ProcessSample> {
        sample_proc_status(pid)
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
            notes: vec!["Linux precise peak memory should prefer cgroup memory.peak".to_owned()],
        })
    }

    fn cleanup(&self, _run_id: &RunId) -> PlatformResult<()> {
        Ok(())
    }
}

pub fn linux_capability_report() -> CapabilityReport {
    let is_linux = cfg!(target_os = "linux");
    let cgroup_v2 = is_linux && Path::new("/sys/fs/cgroup/cgroup.controllers").exists();
    let resctrl = is_linux && Path::new("/sys/fs/resctrl").exists();
    let procfs = is_linux && Path::new("/proc").exists();
    let netns = is_linux && command_available("ip");
    let tc = is_linux && command_available("tc");
    let perf = is_linux && Path::new("/proc/sys/kernel/perf_event_paranoid").exists();

    let mut unsupported = Vec::new();
    if !cgroup_v2 {
        unsupported.push("cgroup_v2".to_owned());
    }
    if !resctrl {
        unsupported.push("resctrl_cat".to_owned());
    }
    if !netns {
        unsupported.push("network_namespace".to_owned());
    }
    if !tc {
        unsupported.push("tc_netem".to_owned());
    }
    if !perf {
        unsupported.push("perf_event_open".to_owned());
    }

    CapabilityReport {
        platform: Platform::Linux,
        architecture: std::env::consts::ARCH.to_owned(),
        isolation_tier: if is_linux {
            IsolationTier::Strict
        } else {
            IsolationTier::Unsupported
        },
        resource_control: ResourceControl {
            process_per_rank: FeatureAvailability::strict("independent OS processes"),
            hard_cpu_affinity: if is_linux {
                FeatureAvailability::strict("sched_setaffinity/cpuset")
            } else {
                FeatureAvailability::unsupported("not running on Linux")
            },
            fixed_thread_budget: FeatureAvailability::strict("environment guards plus task checks"),
            cache_isolation: if resctrl {
                FeatureAvailability::strict("resctrl CAT available")
            } else {
                FeatureAvailability::unsupported("resctrl CAT unavailable")
            },
            numa_binding: if is_linux {
                FeatureAvailability::strict("Linux NUMA policy")
            } else {
                FeatureAvailability::unsupported("not running on Linux")
            },
        },
        memory_control: MemoryControl {
            hard_limit: if cgroup_v2 {
                FeatureAvailability::strict("cgroup v2 memory.max")
            } else {
                FeatureAvailability::unsupported("cgroup v2 unavailable")
            },
            peak_measurement: if procfs {
                FeatureAvailability::strict("cgroup/procfs/rusage")
            } else {
                FeatureAvailability::unsupported("procfs unavailable")
            },
            enforcement: "cgroup_v2".to_owned(),
        },
        network_emulation: NetworkEmulation {
            tcp_data_plane: FeatureAvailability::strict("TCP"),
            loopback: FeatureAvailability::strict("loopback TCP"),
            netns_or_equivalent: if netns {
                FeatureAvailability::strict("ip netns")
            } else {
                FeatureAvailability::unsupported("ip netns unavailable")
            },
            kernel_shaper: if tc {
                FeatureAvailability::strict("tc netem/tbf")
            } else {
                FeatureAvailability::unsupported("tc unavailable")
            },
            userspace_shaper: FeatureAvailability::best_effort("portable token-bucket shaper"),
        },
        perf_counters: PerfCounters {
            linux_perf_equivalent: if perf {
                FeatureAvailability::strict("perf_event_open")
            } else {
                FeatureAvailability::unsupported("perf_event_open unavailable")
            },
            supplemental: FeatureAvailability::unsupported("no supplemental Linux counter source"),
        },
        thermal_monitoring: FeatureAvailability::best_effort("record governor/turbo/THP state"),
        unsupported_features: unsupported,
        notes: vec!["Linux backend is the only strict artifact backend".to_owned()],
    }
}

fn command_available(command: &str) -> bool {
    let Some(path) = std::env::var_os("PATH") else {
        return false;
    };
    std::env::split_paths(&path).any(|dir| dir.join(command).is_file())
}

fn sample_proc_status(pid: Pid) -> PlatformResult<ProcessSample> {
    let path = format!("/proc/{pid}/status");
    let text = fs::read_to_string(path)
        .map_err(|error| PlatformError::new(format!("read proc status failed: {error}")))?;
    let resident_bytes = parse_status_kib(&text, "VmRSS:");
    let virtual_bytes = parse_status_kib(&text, "VmSize:");
    let thread_count = parse_status_usize(&text, "Threads:");
    Ok(ProcessSample {
        pid,
        resident_bytes,
        virtual_bytes,
        thread_count,
    })
}

fn parse_status_kib(text: &str, key: &str) -> Option<u64> {
    text.lines()
        .find_map(|line| line.strip_prefix(key))
        .and_then(|value| value.split_whitespace().next())
        .and_then(|value| value.parse::<u64>().ok())
        .map(|kib| kib * 1024)
}

fn parse_status_usize(text: &str, key: &str) -> Option<usize> {
    text.lines()
        .find_map(|line| line.strip_prefix(key))
        .and_then(|value| value.split_whitespace().next())
        .and_then(|value| value.parse::<usize>().ok())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn linux_report_marks_strict_tier() {
        let report = linux_capability_report();
        assert_eq!(report.platform, Platform::Linux);
        if cfg!(target_os = "linux") {
            assert_eq!(report.isolation_tier, IsolationTier::Strict);
        } else {
            assert_eq!(report.isolation_tier, IsolationTier::Unsupported);
        }
    }

    #[test]
    fn parses_proc_status_units() {
        let text = "VmSize:\t100 kB\nVmRSS:\t42 kB\nThreads:\t3\n";
        assert_eq!(parse_status_kib(text, "VmRSS:"), Some(42 * 1024));
        assert_eq!(parse_status_usize(text, "Threads:"), Some(3));
    }
}

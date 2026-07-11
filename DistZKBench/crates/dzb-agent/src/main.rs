use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::process::{Child, Command, Stdio};
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use std::thread::JoinHandle;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum AgentRequest {
    Ping,
    PrepareRun {
        run_id: String,
    },
    SetupNetwork {
        run_id: String,
        world_size: usize,
        base_port: u16,
        topology: String,
        master_rank: usize,
        worker_to_worker: String,
        shaper: KernelShaper,
    },
    Launch {
        id: String,
        executable: String,
        args: Vec<String>,
        env: BTreeMap<String, String>,
        stdout_path: String,
        stderr_path: String,
        #[serde(default)]
        run_id: String,
        #[serde(default)]
        cpuset: Option<String>,
        #[serde(default)]
        memory_limit_bytes: Option<u64>,
        #[serde(default)]
        strict_linux: bool,
        #[serde(default)]
        namespace: Option<String>,
        #[serde(default)]
        sample_path: Option<String>,
        #[serde(default = "default_sampling_interval_ms")]
        sample_interval_ms: u64,
        #[serde(default)]
        role: String,
        #[serde(default)]
        rank: Option<usize>,
    },
    Wait {
        id: String,
        timeout_ms: u64,
    },
    WaitAll {
        ids: Vec<String>,
        timeout_ms: u64,
    },
    Terminate {
        id: String,
    },
    SampleStatus,
    Cleanup,
}

const fn default_sampling_interval_ms() -> u64 {
    100
}

#[derive(Clone, Debug, Default, Deserialize)]
struct KernelShaper {
    bandwidth_bps: Option<u64>,
    latency_ms: u64,
    jitter_ms: u64,
    loss_percent: String,
    #[serde(default)]
    edges: Vec<KernelEdgeShaper>,
}

#[derive(Clone, Debug, Default, Deserialize)]
struct KernelEdgeShaper {
    src: usize,
    dst: usize,
    bandwidth_bps: Option<u64>,
    latency_ms: u64,
    jitter_ms: u64,
    loss_percent: String,
}

#[derive(Debug, Serialize)]
struct AgentResponse {
    ok: bool,
    message: String,
    pid: Option<u32>,
    exit_code: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    listen_addrs: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    namespaces: Option<Vec<String>>,
}

struct NetworkResources {
    bridge: String,
    namespaces: Vec<String>,
    listen_addrs: Vec<String>,
}

struct Sampler {
    stop: Arc<AtomicBool>,
    handle: JoinHandle<Result<(), String>>,
}

fn main() {
    if std::env::args().nth(1).as_deref() != Some("serve") {
        eprintln!("usage: dzb-agent serve");
        std::process::exit(2);
    }
    if let Err(error) = serve() {
        eprintln!("{error}");
        std::process::exit(1);
    }
}

#[allow(clippy::map_entry)]
fn serve() -> Result<(), String> {
    let cancelled = Arc::new(AtomicBool::new(false));
    let signal_cancelled = Arc::clone(&cancelled);
    ctrlc::set_handler(move || signal_cancelled.store(true, Ordering::SeqCst))
        .map_err(|error| format!("install agent signal handler failed: {error}"))?;
    let mut children = BTreeMap::<String, Child>::new();
    let mut cgroups = BTreeMap::<String, String>::new();
    let mut networks = BTreeMap::<String, NetworkResources>::new();
    let mut samplers = BTreeMap::<String, Sampler>::new();
    let mut input = std::io::stdin().lock();
    let mut output = std::io::stdout().lock();
    loop {
        if cancelled.load(Ordering::SeqCst) {
            cleanup(&mut children);
            cleanup_samplers(&mut samplers);
            cleanup_cgroups(&mut cgroups);
            cleanup_networks(&mut networks);
            return Ok(());
        }
        let Some(request) = read_message::<AgentRequest>(&mut input)? else {
            cleanup(&mut children);
            cleanup_samplers(&mut samplers);
            cleanup_cgroups(&mut cgroups);
            cleanup_networks(&mut networks);
            return Ok(());
        };
        let response = match request {
            AgentRequest::Ping => response("pong"),
            AgentRequest::PrepareRun { run_id } => {
                cleanup_run_network(&run_id, &mut networks);
                response("run prepared")
            }
            AgentRequest::SetupNetwork {
                run_id,
                world_size,
                base_port,
                topology,
                master_rank,
                worker_to_worker,
                shaper,
            } => match setup_network(
                &run_id,
                world_size,
                base_port,
                &topology,
                master_rank,
                &worker_to_worker,
                &shaper,
            ) {
                Ok(resources) => {
                    let listen_addrs = resources.listen_addrs.clone();
                    let namespaces = resources.namespaces.clone();
                    networks.insert(run_id, resources);
                    AgentResponse {
                        ok: true,
                        message: "network ready".to_owned(),
                        pid: None,
                        exit_code: None,
                        listen_addrs: Some(listen_addrs),
                        namespaces: Some(namespaces),
                    }
                }
                Err(error) => failure(error),
            },
            AgentRequest::Launch {
                id,
                executable,
                args,
                env,
                stdout_path,
                stderr_path,
                run_id,
                cpuset,
                memory_limit_bytes,
                strict_linux,
                namespace,
                sample_path,
                sample_interval_ms,
                role,
                rank,
            } => {
                if children.contains_key(&id) {
                    failure(format!("process id '{id}' already exists"))
                } else {
                    let stdout = std::fs::File::create(stdout_path)
                        .map_err(|error| format!("create stdout log failed: {error}"))?;
                    let stderr = std::fs::File::create(stderr_path)
                        .map_err(|error| format!("create stderr log failed: {error}"))?;
                    let cgroup = prepare_cgroup(
                        &run_id,
                        &id,
                        cpuset.as_deref(),
                        memory_limit_bytes,
                        strict_linux,
                    );
                    let cgroup = match cgroup {
                        Ok(path) => path,
                        Err(error) => {
                            write_message(&mut output, &failure(error))?;
                            continue;
                        }
                    };
                    let namespaced = namespace.is_some();
                    let mut command = build_launch_command(
                        &executable,
                        &args,
                        cpuset.as_deref(),
                        namespace.as_deref(),
                    );
                    command
                        .envs(env)
                        .stdin(Stdio::null())
                        .stdout(Stdio::from(stdout))
                        .stderr(Stdio::from(stderr));
                    if !namespaced {
                        drop_privileges(&mut command);
                    }
                    match command.spawn() {
                        Ok(child) => {
                            let pid = child.id();
                            if let Some(path) = &cgroup {
                                if let Err(error) = std::fs::write(
                                    std::path::Path::new(path).join("cgroup.procs"),
                                    pid.to_string(),
                                ) {
                                    let mut child = child;
                                    let _ = child.kill();
                                    let _ = child.wait();
                                    let _ = std::fs::remove_dir(path);
                                    write_message(
                                        &mut output,
                                        &failure(format!("attach cgroup failed: {error}")),
                                    )?;
                                    continue;
                                }
                                cgroups.insert(id.clone(), path.clone());
                            }
                            if let Some(sample_path) = sample_path {
                                match start_sampler(
                                    pid,
                                    cgroup.as_deref(),
                                    &sample_path,
                                    sample_interval_ms,
                                    strict_linux,
                                    &role,
                                    rank,
                                ) {
                                    Ok(sampler) => {
                                        samplers.insert(id.clone(), sampler);
                                    }
                                    Err(error) => {
                                        let mut child = child;
                                        let _ = child.kill();
                                        let _ = child.wait();
                                        remove_cgroup(&mut cgroups, &id);
                                        write_message(&mut output, &failure(error))?;
                                        continue;
                                    }
                                }
                            }
                            children.insert(id, child);
                            AgentResponse {
                                ok: true,
                                message: "launched".to_owned(),
                                pid: Some(pid),
                                exit_code: None,
                                listen_addrs: None,
                                namespaces: None,
                            }
                        }
                        Err(error) => failure(format!("launch failed: {error}")),
                    }
                }
            }
            AgentRequest::Wait { id, timeout_ms } => match children.remove(&id) {
                Some(mut child) => match wait_child(&mut child, timeout_ms) {
                    Ok(Some(status)) => {
                        let oom = cgroups
                            .get(&id)
                            .and_then(|path| sample_cgroup(path).ok())
                            .is_some_and(|(_, _, oom)| oom);
                        let sample_result = stop_sampler(&mut samplers, &id);
                        remove_cgroup(&mut cgroups, &id);
                        if oom {
                            failure(format!("process '{id}' was terminated by cgroup OOM"))
                        } else if let Err(error) = sample_result {
                            failure(error)
                        } else {
                            AgentResponse {
                                ok: status.success(),
                                message: status.to_string(),
                                pid: Some(child.id()),
                                exit_code: status.code(),
                                listen_addrs: None,
                                namespaces: None,
                            }
                        }
                    }
                    Ok(None) => {
                        let _ = child.kill();
                        let _ = child.wait();
                        let _ = stop_sampler(&mut samplers, &id);
                        remove_cgroup(&mut cgroups, &id);
                        failure(format!("process '{id}' timed out after {timeout_ms} ms"))
                    }
                    Err(error) => failure(format!("wait failed: {error}")),
                },
                None => failure(format!("unknown process id '{id}'")),
            },
            AgentRequest::WaitAll { ids, timeout_ms } => {
                let mut failure_message = None;
                let mut remaining = ids;
                let deadline = std::time::Instant::now()
                    .checked_add(std::time::Duration::from_millis(timeout_ms));
                while !remaining.is_empty() && failure_message.is_none() {
                    if cancelled.load(Ordering::SeqCst) {
                        failure_message = Some("run cancelled by signal".to_owned());
                        break;
                    }
                    if deadline.is_some_and(|deadline| std::time::Instant::now() >= deadline) {
                        failure_message =
                            Some(format!("process group timed out after {timeout_ms} ms"));
                        break;
                    }
                    let mut completed = Vec::new();
                    for id in &remaining {
                        let Some(child) = children.get_mut(id) else {
                            failure_message = Some(format!("unknown process id '{id}'"));
                            break;
                        };
                        match child.try_wait() {
                            Ok(Some(status)) if status.success() => completed.push(id.clone()),
                            Ok(Some(status)) => {
                                let oom = cgroups
                                    .get(id)
                                    .and_then(|path| sample_cgroup(path).ok())
                                    .is_some_and(|(_, _, oom)| oom);
                                failure_message = Some(if oom {
                                    format!("process '{id}' was terminated by cgroup OOM")
                                } else {
                                    format!("process '{id}' exited with {status}")
                                });
                                break;
                            }
                            Ok(None) => {}
                            Err(error) => {
                                failure_message =
                                    Some(format!("poll process '{id}' failed: {error}"));
                                break;
                            }
                        }
                    }
                    for id in completed {
                        children.remove(&id);
                        if let Err(error) = stop_sampler(&mut samplers, &id) {
                            failure_message = Some(error);
                        }
                        remove_cgroup(&mut cgroups, &id);
                        remaining.retain(|candidate| candidate != &id);
                    }
                    if failure_message.is_none() && !remaining.is_empty() {
                        std::thread::sleep(std::time::Duration::from_millis(20));
                    }
                }
                if let Some(error) = failure_message {
                    cleanup(&mut children);
                    cleanup_samplers(&mut samplers);
                    cleanup_cgroups(&mut cgroups);
                    if cancelled.load(Ordering::SeqCst) {
                        cleanup_networks(&mut networks);
                    }
                    failure(error)
                } else {
                    response("all processes completed")
                }
            }
            AgentRequest::Terminate { id } => match children.remove(&id) {
                Some(mut child) => {
                    let _ = child.kill();
                    let status = child.wait().ok();
                    let _ = stop_sampler(&mut samplers, &id);
                    remove_cgroup(&mut cgroups, &id);
                    AgentResponse {
                        ok: true,
                        message: "terminated".to_owned(),
                        pid: Some(child.id()),
                        exit_code: status.and_then(|status| status.code()),
                        listen_addrs: None,
                        namespaces: None,
                    }
                }
                None => response("already absent"),
            },
            AgentRequest::SampleStatus => response(&format!("sampling_active={}", samplers.len())),
            AgentRequest::Cleanup => {
                cleanup(&mut children);
                cleanup_samplers(&mut samplers);
                cleanup_cgroups(&mut cgroups);
                cleanup_networks(&mut networks);
                response("cleaned")
            }
        };
        write_message(&mut output, &response)?;
    }
}

fn wait_child(
    child: &mut Child,
    timeout_ms: u64,
) -> std::io::Result<Option<std::process::ExitStatus>> {
    let deadline =
        std::time::Instant::now().checked_add(std::time::Duration::from_millis(timeout_ms));
    loop {
        if let Some(status) = child.try_wait()? {
            return Ok(Some(status));
        }
        if deadline.is_some_and(|deadline| std::time::Instant::now() >= deadline) {
            return Ok(None);
        }
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
}

fn build_launch_command(
    executable: &str,
    args: &[String],
    cpuset: Option<&str>,
    namespace: Option<&str>,
) -> Command {
    if cfg!(target_os = "linux")
        && let Some(namespace) = namespace
    {
        let uid = std::env::var("SUDO_UID").unwrap_or_else(|_| "0".to_owned());
        let gid = std::env::var("SUDO_GID").unwrap_or_else(|_| "0".to_owned());
        let mut command = Command::new("ip");
        command.args([
            "netns",
            "exec",
            namespace,
            "setpriv",
            "--reuid",
            &uid,
            "--regid",
            &gid,
            "--clear-groups",
        ]);
        if let Some(cpus) = cpuset {
            command.args(["taskset", "-c", cpus]);
        }
        command.arg(executable).args(args);
        return command;
    }
    if cfg!(target_os = "linux")
        && let Some(cpus) = cpuset
    {
        let mut command = Command::new("taskset");
        command.args(["-c", cpus, executable]).args(args);
        return command;
    }
    let mut command = Command::new(executable);
    command.args(args);
    command
}

#[allow(clippy::too_many_arguments)]
fn setup_network(
    run_id: &str,
    world_size: usize,
    base_port: u16,
    topology: &str,
    master_rank: usize,
    worker_to_worker: &str,
    shaper: &KernelShaper,
) -> Result<NetworkResources, String> {
    if !cfg!(target_os = "linux") {
        return Err("netns_veth is only supported on Linux".to_owned());
    }
    if world_size == 0 || world_size > 253 || master_rank >= world_size {
        return Err("netns_veth requires 1..=253 ranks and a valid master rank".to_owned());
    }
    let digest = stable_run_digest(run_id);
    let short = &digest[..6];
    let bridge = format!("dzb{short}");
    let subnet_a = 1 + u8::from_str_radix(&digest[0..2], 16).unwrap_or(1) % 253;
    let subnet_b = 1 + u8::from_str_radix(&digest[2..4], 16).unwrap_or(1) % 253;
    run_command("ip", &["link", "add", &bridge, "type", "bridge"])?;
    if let Err(error) = (|| {
        run_command(
            "ip",
            &[
                "addr",
                "add",
                &format!("10.{subnet_a}.{subnet_b}.1/24"),
                "dev",
                &bridge,
            ],
        )?;
        run_command("ip", &["link", "set", &bridge, "up"])?;
        Ok::<_, String>(())
    })() {
        let _ = run_command("ip", &["link", "del", &bridge]);
        return Err(error);
    }
    let mut namespaces = Vec::new();
    let mut listen_addrs = Vec::new();
    for rank in 0..world_size {
        let namespace = format!("dzb-{short}-r{rank}");
        let host_veth = format!("dh{short}{rank}");
        let peer_veth = format!("dn{short}{rank}");
        let ip = format!("10.{subnet_a}.{subnet_b}.{}", rank + 2);
        let setup = (|| {
            run_command("ip", &["netns", "add", &namespace])?;
            run_command(
                "ip",
                &[
                    "link", "add", &host_veth, "type", "veth", "peer", "name", &peer_veth,
                ],
            )?;
            run_command("ip", &["link", "set", &host_veth, "master", &bridge])?;
            run_command("ip", &["link", "set", &host_veth, "up"])?;
            run_command("ip", &["link", "set", &peer_veth, "netns", &namespace])?;
            run_command("ip", &["-n", &namespace, "link", "set", "lo", "up"])?;
            run_command(
                "ip",
                &["-n", &namespace, "link", "set", &peer_veth, "name", "eth0"],
            )?;
            run_command(
                "ip",
                &[
                    "-n",
                    &namespace,
                    "addr",
                    "add",
                    &format!("{ip}/24"),
                    "dev",
                    "eth0",
                ],
            )?;
            run_command("ip", &["-n", &namespace, "link", "set", "eth0", "up"])?;
            setup_tc(&namespace, rank, shaper, subnet_a, subnet_b)?;
            if topology == "star" && worker_to_worker != "allowed" && rank != master_rank {
                for peer in 0..world_size {
                    if peer != master_rank && peer != rank {
                        run_command(
                            "ip",
                            &[
                                "-n",
                                &namespace,
                                "route",
                                "add",
                                "unreachable",
                                &format!("10.{subnet_a}.{subnet_b}.{}/32", peer + 2),
                            ],
                        )?;
                    }
                }
            }
            Ok::<_, String>(())
        })();
        if let Err(error) = setup {
            let mut resources = NetworkResources {
                bridge,
                namespaces,
                listen_addrs,
            };
            resources.namespaces.push(namespace);
            cleanup_network(&resources);
            return Err(error);
        }
        namespaces.push(namespace);
        listen_addrs.push(format!("{ip}:{}", base_port as usize + rank));
    }
    Ok(NetworkResources {
        bridge,
        namespaces,
        listen_addrs,
    })
}

fn setup_tc(
    namespace: &str,
    rank: usize,
    shaper: &KernelShaper,
    subnet_a: u8,
    subnet_b: u8,
) -> Result<(), String> {
    let has_default = shaper.bandwidth_bps.is_some()
        || shaper.latency_ms > 0
        || shaper.jitter_ms > 0
        || parse_loss(&shaper.loss_percent) > 0.0;
    let edges = shaper
        .edges
        .iter()
        .filter(|edge| edge.src == rank)
        .collect::<Vec<_>>();
    if !has_default && edges.is_empty() {
        return Ok(());
    }
    run_command(
        "ip",
        &[
            "netns", "exec", namespace, "tc", "qdisc", "replace", "dev", "eth0", "root", "handle",
            "1:", "htb", "default", "10",
        ],
    )?;
    add_tc_class(
        namespace,
        "1:10",
        shaper.bandwidth_bps,
        shaper.latency_ms,
        shaper.jitter_ms,
        &shaper.loss_percent,
    )?;
    for edge in edges {
        let class = 20 + edge.dst;
        add_tc_class(
            namespace,
            &format!("1:{class}"),
            edge.bandwidth_bps,
            edge.latency_ms,
            edge.jitter_ms,
            &edge.loss_percent,
        )?;
        run_command(
            "ip",
            &[
                "netns",
                "exec",
                namespace,
                "tc",
                "filter",
                "replace",
                "dev",
                "eth0",
                "protocol",
                "ip",
                "parent",
                "1:",
                "prio",
                "1",
                "u32",
                "match",
                "ip",
                "dst",
                &format!("10.{subnet_a}.{subnet_b}.{}/32", edge.dst + 2),
                "flowid",
                &format!("1:{class}"),
            ],
        )?;
    }
    Ok(())
}

fn add_tc_class(
    namespace: &str,
    class: &str,
    bandwidth_bps: Option<u64>,
    latency_ms: u64,
    jitter_ms: u64,
    loss: &str,
) -> Result<(), String> {
    let rate = bandwidth_bps.unwrap_or(100_000_000_000).saturating_mul(8);
    run_command(
        "ip",
        &[
            "netns",
            "exec",
            namespace,
            "tc",
            "class",
            "replace",
            "dev",
            "eth0",
            "parent",
            "1:",
            "classid",
            class,
            "htb",
            "rate",
            &format!("{rate}bit"),
            "ceil",
            &format!("{rate}bit"),
        ],
    )?;
    if latency_ms > 0 || jitter_ms > 0 || parse_loss(loss) > 0.0 {
        let minor = class.split(':').nth(1).unwrap_or("10");
        let mut args = vec![
            "netns".to_owned(),
            "exec".to_owned(),
            namespace.to_owned(),
            "tc".to_owned(),
            "qdisc".to_owned(),
            "replace".to_owned(),
            "dev".to_owned(),
            "eth0".to_owned(),
            "parent".to_owned(),
            class.to_owned(),
            "handle".to_owned(),
            format!("{minor}0:"),
            "netem".to_owned(),
        ];
        if latency_ms > 0 || jitter_ms > 0 {
            args.extend(["delay".to_owned(), format!("{latency_ms}ms")]);
            if jitter_ms > 0 {
                args.push(format!("{jitter_ms}ms"));
            }
        }
        if parse_loss(loss) > 0.0 {
            args.extend(["loss".to_owned(), loss.to_owned()]);
        }
        let refs = args.iter().map(String::as_str).collect::<Vec<_>>();
        run_command("ip", &refs)?;
    }
    Ok(())
}

fn parse_loss(value: &str) -> f64 {
    value.trim_end_matches('%').parse::<f64>().unwrap_or(0.0)
}

fn stable_run_digest(run_id: &str) -> String {
    use std::hash::{Hash, Hasher};
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    run_id.hash(&mut hasher);
    format!("{:016x}", hasher.finish())
}

fn run_command(command: &str, args: &[&str]) -> Result<(), String> {
    let output = Command::new(command)
        .args(args)
        .output()
        .map_err(|error| format!("run {command} failed: {error}"))?;
    if output.status.success() {
        Ok(())
    } else {
        Err(format!(
            "{} {} failed: {}",
            command,
            args.join(" "),
            String::from_utf8_lossy(&output.stderr).trim()
        ))
    }
}

fn cleanup_network(network: &NetworkResources) {
    for namespace in network.namespaces.iter().rev() {
        let _ = run_command("ip", &["netns", "del", namespace]);
    }
    let _ = run_command("ip", &["link", "del", &network.bridge]);
}

fn cleanup_run_network(run_id: &str, networks: &mut BTreeMap<String, NetworkResources>) {
    if let Some(network) = networks.remove(run_id) {
        cleanup_network(&network);
    }
}

fn cleanup_networks(networks: &mut BTreeMap<String, NetworkResources>) {
    let values = std::mem::take(networks);
    for network in values.values() {
        cleanup_network(network);
    }
}

fn start_sampler(
    pid: u32,
    cgroup: Option<&str>,
    sample_path: &str,
    interval_ms: u64,
    strict: bool,
    role: &str,
    rank: Option<usize>,
) -> Result<Sampler, String> {
    let path = std::path::Path::new(sample_path);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|error| format!("create memory sample directory failed: {error}"))?;
    }
    let mut file = std::fs::File::create(path)
        .map_err(|error| format!("create memory sample file failed: {error}"))?;
    writeln!(file, "timestamp_ns,elapsed_ms,role,rank,pid,resident_bytes,virtual_bytes,cgroup_current_bytes,cgroup_peak_bytes,oom,source")
        .map_err(|error| error.to_string())?;
    let stop = Arc::new(AtomicBool::new(false));
    let thread_stop = Arc::clone(&stop);
    let cgroup = cgroup.map(str::to_owned);
    let role = role.to_owned();
    let handle = std::thread::spawn(move || {
        let started = Instant::now();
        let mut failures = 0_u8;
        while !thread_stop.load(Ordering::Relaxed) {
            let process = sample_proc(pid);
            let cgroup_sample = cgroup.as_deref().map(sample_cgroup).transpose();
            match (&process, &cgroup_sample) {
                (_, Err(error)) if strict => {
                    failures = failures.saturating_add(1);
                    if failures >= 3 {
                        return Err(format!(
                            "continuous cgroup sampling failed three times: {error}"
                        ));
                    }
                }
                _ => failures = 0,
            }
            let (current, peak, oom) = cgroup_sample.ok().flatten().unwrap_or_default();
            let (rss, virtual_bytes) = process.unwrap_or_default();
            let timestamp = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos();
            writeln!(
                file,
                "{timestamp},{:.3},{},{},{pid},{},{},{},{},{},{}",
                started.elapsed().as_secs_f64() * 1000.0,
                role,
                rank.map_or_else(String::new, |rank| rank.to_string()),
                rss.map_or_else(String::new, |value| value.to_string()),
                virtual_bytes.map_or_else(String::new, |value| value.to_string()),
                current.map_or_else(String::new, |value| value.to_string()),
                peak.map_or_else(String::new, |value| value.to_string()),
                oom,
                if cgroup.is_some() {
                    "cgroup_v2+procfs"
                } else {
                    "procfs_best_effort"
                },
            )
            .map_err(|error| error.to_string())?;
            file.flush().map_err(|error| error.to_string())?;
            std::thread::sleep(Duration::from_millis(interval_ms.max(1)));
        }
        Ok(())
    });
    Ok(Sampler { stop, handle })
}

type CgroupSample = (Option<u64>, Option<u64>, bool);

fn sample_cgroup(path: &str) -> Result<CgroupSample, String> {
    let path = std::path::Path::new(path);
    let read_u64 = |name: &str| -> Result<Option<u64>, String> {
        std::fs::read_to_string(path.join(name))
            .map_err(|error| format!("read {name} failed: {error}"))?
            .trim()
            .parse::<u64>()
            .map(Some)
            .map_err(|error| format!("parse {name} failed: {error}"))
    };
    let events = std::fs::read_to_string(path.join("memory.events"))
        .map_err(|error| format!("read memory.events failed: {error}"))?;
    let oom = events.lines().any(|line| {
        let mut parts = line.split_whitespace();
        matches!(parts.next(), Some("oom" | "oom_kill"))
            && parts
                .next()
                .and_then(|value| value.parse::<u64>().ok())
                .unwrap_or(0)
                > 0
    });
    Ok((read_u64("memory.current")?, read_u64("memory.peak")?, oom))
}

fn sample_proc(pid: u32) -> Option<(Option<u64>, Option<u64>)> {
    #[cfg(target_os = "linux")]
    {
        let text = std::fs::read_to_string(format!("/proc/{pid}/status")).ok()?;
        let value = |name: &str| {
            text.lines().find_map(|line| {
                let rest = line.strip_prefix(name)?.trim();
                rest.split_whitespace()
                    .next()?
                    .parse::<u64>()
                    .ok()
                    .map(|kb| kb * 1024)
            })
        };
        Some((value("VmRSS:"), value("VmSize:")))
    }
    #[cfg(target_os = "macos")]
    {
        let output = Command::new("ps")
            .args(["-o", "rss=,vsz=", "-p", &pid.to_string()])
            .output()
            .ok()?;
        let text = String::from_utf8_lossy(&output.stdout);
        let mut values = text
            .split_whitespace()
            .filter_map(|value| value.parse::<u64>().ok());
        Some((
            values.next().map(|kb| kb * 1024),
            values.next().map(|kb| kb * 1024),
        ))
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        let _ = pid;
        None
    }
}

fn stop_sampler(samplers: &mut BTreeMap<String, Sampler>, id: &str) -> Result<(), String> {
    let Some(sampler) = samplers.remove(id) else {
        return Ok(());
    };
    sampler.stop.store(true, Ordering::Relaxed);
    sampler
        .handle
        .join()
        .map_err(|_| format!("memory sampler for {id} panicked"))?
}

fn cleanup_samplers(samplers: &mut BTreeMap<String, Sampler>) {
    let ids = samplers.keys().cloned().collect::<Vec<_>>();
    for id in ids {
        let _ = stop_sampler(samplers, &id);
    }
}

fn cleanup(children: &mut BTreeMap<String, Child>) {
    for child in children.values_mut() {
        let _ = child.kill();
        let _ = child.wait();
    }
    children.clear();
}

fn prepare_cgroup(
    run_id: &str,
    id: &str,
    cpuset: Option<&str>,
    memory_limit_bytes: Option<u64>,
    strict: bool,
) -> Result<Option<String>, String> {
    if !cfg!(target_os = "linux") || (!strict && cpuset.is_none() && memory_limit_bytes.is_none()) {
        return Ok(None);
    }
    let root = std::path::Path::new("/sys/fs/cgroup");
    if !root.join("cgroup.controllers").exists() {
        return if strict {
            Err("cgroup v2 is required for strict Linux launch".to_owned())
        } else {
            Ok(None)
        };
    }
    let safe = |value: &str| {
        value
            .chars()
            .map(|ch| {
                if ch.is_ascii_alphanumeric() || ch == '-' {
                    ch
                } else {
                    '-'
                }
            })
            .collect::<String>()
    };
    let run = root.join(format!("dzb-{}", safe(run_id)));
    let path = run.join(safe(id));
    enable_controllers(root, "+cpuset +memory")?;
    std::fs::create_dir_all(&run)
        .map_err(|error| format!("create run cgroup {} failed: {error}", run.display()))?;
    let root_mems = std::fs::read_to_string(root.join("cpuset.mems.effective"))
        .unwrap_or_else(|_| "0".to_owned());
    let root_cpus = std::fs::read_to_string(root.join("cpuset.cpus.effective"))
        .map_err(|error| format!("read effective cpuset failed: {error}"))?;
    std::fs::write(run.join("cpuset.mems"), root_mems.trim())
        .map_err(|error| format!("initialize run cpuset.mems failed: {error}"))?;
    std::fs::write(run.join("cpuset.cpus"), root_cpus.trim())
        .map_err(|error| format!("initialize run cpuset.cpus failed: {error}"))?;
    enable_controllers(&run, "+cpuset +memory")?;
    std::fs::create_dir_all(&path)
        .map_err(|error| format!("create process cgroup {} failed: {error}", path.display()))?;
    if let Some(cpus) = cpuset {
        std::fs::write(path.join("cpuset.mems"), root_mems.trim())
            .map_err(|error| format!("write cpuset.mems failed: {error}"))?;
        std::fs::write(path.join("cpuset.cpus"), cpus)
            .map_err(|error| format!("write cpuset.cpus failed: {error}"))?;
    }
    if let Some(limit) = memory_limit_bytes {
        std::fs::write(path.join("memory.max"), limit.to_string())
            .map_err(|error| format!("write memory.max failed: {error}"))?;
    }
    Ok(Some(path.to_string_lossy().into_owned()))
}

fn enable_controllers(cgroup: &std::path::Path, controllers: &str) -> Result<(), String> {
    std::fs::write(cgroup.join("cgroup.subtree_control"), controllers)
        .map_err(|error| format!("enable controllers in {} failed: {error}", cgroup.display()))
}

#[cfg(unix)]
fn drop_privileges(command: &mut Command) {
    use std::os::unix::process::CommandExt;
    if let (Ok(uid), Ok(gid)) = (std::env::var("SUDO_UID"), std::env::var("SUDO_GID"))
        && let (Ok(uid), Ok(gid)) = (uid.parse::<u32>(), gid.parse::<u32>())
    {
        command.uid(uid).gid(gid);
    }
}

#[cfg(not(unix))]
fn drop_privileges(_command: &mut Command) {}

fn remove_cgroup(cgroups: &mut BTreeMap<String, String>, id: &str) {
    if let Some(path) = cgroups.remove(id) {
        let _ = std::fs::remove_dir(&path);
        if let Some(parent) = std::path::Path::new(&path).parent() {
            let _ = std::fs::remove_dir(parent);
        }
    }
}

fn cleanup_cgroups(cgroups: &mut BTreeMap<String, String>) {
    let ids = cgroups.keys().cloned().collect::<Vec<_>>();
    for id in ids {
        remove_cgroup(cgroups, &id);
    }
}

fn response(message: &str) -> AgentResponse {
    AgentResponse {
        ok: true,
        message: message.to_owned(),
        pid: None,
        exit_code: None,
        listen_addrs: None,
        namespaces: None,
    }
}

fn failure(message: String) -> AgentResponse {
    AgentResponse {
        ok: false,
        message,
        pid: None,
        exit_code: None,
        listen_addrs: None,
        namespaces: None,
    }
}

fn read_message<T: for<'de> Deserialize<'de>>(reader: &mut impl Read) -> Result<Option<T>, String> {
    let mut len = [0_u8; 4];
    match reader.read_exact(&mut len) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(error) => return Err(format!("read agent message length failed: {error}")),
    }
    let len = u32::from_le_bytes(len) as usize;
    if len > 16 * 1024 * 1024 {
        return Err("agent control message exceeds 16 MiB".to_owned());
    }
    let mut bytes = vec![0_u8; len];
    reader
        .read_exact(&mut bytes)
        .map_err(|error| format!("read agent message failed: {error}"))?;
    serde_json::from_slice(&bytes)
        .map(Some)
        .map_err(|error| format!("parse agent message failed: {error}"))
}

fn write_message<T: Serialize>(writer: &mut impl Write, value: &T) -> Result<(), String> {
    let bytes = serde_json::to_vec(value)
        .map_err(|error| format!("serialize agent response failed: {error}"))?;
    writer
        .write_all(&(bytes.len() as u32).to_le_bytes())
        .and_then(|_| writer.write_all(&bytes))
        .and_then(|_| writer.flush())
        .map_err(|error| format!("write agent response failed: {error}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn run_digest_is_stable_and_interface_safe() {
        let digest = stable_run_digest("example-run");
        assert_eq!(digest, stable_run_digest("example-run"));
        assert_eq!(digest.len(), 16);
        assert!(format!("dh{}{}", &digest[..6], 253).len() <= 15);
    }

    #[test]
    fn continuous_sampler_writes_multiple_rows() {
        let path = std::env::temp_dir().join(format!(
            "dzb-memory-sampler-{}-{}.csv",
            std::process::id(),
            stable_run_digest("sampler-test")
        ));
        let sampler = start_sampler(
            std::process::id(),
            None,
            path.to_string_lossy().as_ref(),
            10,
            false,
            "rank",
            Some(0),
        )
        .expect("start sampler");
        let mut samplers = BTreeMap::from([("rank-0".to_owned(), sampler)]);
        std::thread::sleep(Duration::from_millis(35));
        stop_sampler(&mut samplers, "rank-0").expect("stop sampler");
        let text = std::fs::read_to_string(&path).expect("read samples");
        assert!(text.lines().count() >= 3);
        let _ = std::fs::remove_file(path);
    }
}

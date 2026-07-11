use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::process::{Child, Command, Stdio};

use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum AgentRequest {
    Ping,
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
    Cleanup,
}

#[derive(Debug, Serialize)]
struct AgentResponse {
    ok: bool,
    message: String,
    pid: Option<u32>,
    exit_code: Option<i32>,
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
    let mut children = BTreeMap::<String, Child>::new();
    let mut cgroups = BTreeMap::<String, String>::new();
    let mut input = std::io::stdin().lock();
    let mut output = std::io::stdout().lock();
    loop {
        let Some(request) = read_message::<AgentRequest>(&mut input)? else {
            cleanup(&mut children);
            cleanup_cgroups(&mut cgroups);
            return Ok(());
        };
        let response = match request {
            AgentRequest::Ping => response("pong"),
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
                    let mut command = if cfg!(target_os = "linux") && cpuset.is_some() {
                        let mut command = Command::new("taskset");
                        command
                            .arg("-c")
                            .arg(cpuset.as_deref().unwrap_or_default())
                            .arg(executable);
                        command
                    } else {
                        Command::new(executable)
                    };
                    command
                        .args(args)
                        .envs(env)
                        .stdin(Stdio::null())
                        .stdout(Stdio::from(stdout))
                        .stderr(Stdio::from(stderr));
                    drop_privileges(&mut command);
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
                            children.insert(id, child);
                            AgentResponse {
                                ok: true,
                                message: "launched".to_owned(),
                                pid: Some(pid),
                                exit_code: None,
                            }
                        }
                        Err(error) => failure(format!("launch failed: {error}")),
                    }
                }
            }
            AgentRequest::Wait { id, timeout_ms } => match children.remove(&id) {
                Some(mut child) => match wait_child(&mut child, timeout_ms) {
                    Ok(Some(status)) => {
                        remove_cgroup(&mut cgroups, &id);
                        AgentResponse {
                            ok: status.success(),
                            message: status.to_string(),
                            pid: Some(child.id()),
                            exit_code: status.code(),
                        }
                    }
                    Ok(None) => {
                        let _ = child.kill();
                        let _ = child.wait();
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
                                failure_message =
                                    Some(format!("process '{id}' exited with {status}"));
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
                        remove_cgroup(&mut cgroups, &id);
                        remaining.retain(|candidate| candidate != &id);
                    }
                    if failure_message.is_none() && !remaining.is_empty() {
                        std::thread::sleep(std::time::Duration::from_millis(20));
                    }
                }
                if let Some(error) = failure_message {
                    cleanup(&mut children);
                    cleanup_cgroups(&mut cgroups);
                    failure(error)
                } else {
                    response("all processes completed")
                }
            }
            AgentRequest::Terminate { id } => match children.remove(&id) {
                Some(mut child) => {
                    let _ = child.kill();
                    let status = child.wait().ok();
                    remove_cgroup(&mut cgroups, &id);
                    AgentResponse {
                        ok: true,
                        message: "terminated".to_owned(),
                        pid: Some(child.id()),
                        exit_code: status.and_then(|status| status.code()),
                    }
                }
                None => response("already absent"),
            },
            AgentRequest::Cleanup => {
                cleanup(&mut children);
                cleanup_cgroups(&mut cgroups);
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
    }
}

fn failure(message: String) -> AgentResponse {
    AgentResponse {
        ok: false,
        message,
        pid: None,
        exit_code: None,
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

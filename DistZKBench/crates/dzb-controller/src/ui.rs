use std::collections::BTreeMap;
use std::fs::{self, File};
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicU64, Ordering},
};
use std::thread;
use std::time::{Duration, SystemTime};

use serde::{Deserialize, Serialize};
use serde_json::Value;

use dzb_core::{Config, TopologyKind};

const UI_HTML: &str = include_str!("ui.html");

#[derive(Clone)]
struct UiState {
    jobs: Arc<Mutex<BTreeMap<u64, JobState>>>,
    next_job: Arc<AtomicU64>,
    exe: PathBuf,
}

#[derive(Clone, Debug, Serialize)]
struct JobState {
    id: u64,
    kind: String,
    status: String,
    command: Vec<String>,
    log: String,
    exit_code: Option<i32>,
    result_dir: Option<String>,
}

#[derive(Clone, Debug, Serialize)]
struct EdgeSummary {
    src: usize,
    dst: usize,
    payload_bytes: u64,
    framed_bytes: u64,
    messages: u64,
}

#[derive(Clone, Debug, Serialize)]
struct RunSummary {
    found: bool,
    run_id: String,
    result_dir: String,
    report_url: String,
    status: String,
    platform: String,
    isolation_tier: String,
    proof_size_bytes: u64,
    verifier_ms: f64,
    communication_precision: String,
    network_ok: bool,
    feasible: bool,
    reason: String,
    edges: Vec<EdgeSummary>,
}

#[derive(Clone, Debug, Deserialize)]
struct ToyConfigRequest {
    shape: Option<String>,
    ranks: Option<usize>,
    message_bytes: Option<usize>,
    base_port: Option<u16>,
    worker_threads: Option<usize>,
    latency: Option<String>,
    bandwidth: Option<String>,
    adapter_command: Option<String>,
    mode: Option<String>,
}

pub fn cmd_ui(args: &[String]) -> Result<(), String> {
    let no_open = args.iter().any(|arg| arg == "--no-open");
    let once_smoke = args.iter().any(|arg| arg == "--once-smoke");
    let bind_addr = bind_listener()?;
    let url = format!(
        "http://{}",
        bind_addr.local_addr().map_err(|e| e.to_string())?
    );
    let state = UiState {
        jobs: Arc::new(Mutex::new(BTreeMap::new())),
        next_job: Arc::new(AtomicU64::new(1)),
        exe: std::env::current_exe().map_err(|error| error.to_string())?,
    };
    if once_smoke {
        let listener_addr = bind_addr.local_addr().map_err(|error| error.to_string())?;
        let state_ref = state.clone();
        let handle = thread::spawn(move || {
            if let Ok((stream, _)) = bind_addr.accept() {
                let _ = handle_connection(stream, &state_ref);
            }
        });
        let mut stream = TcpStream::connect(listener_addr)
            .map_err(|error| format!("ui smoke connect failed: {error}"))?;
        stream
            .write_all(b"GET / HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n")
            .map_err(|error| format!("ui smoke write failed: {error}"))?;
        let mut response = String::new();
        stream
            .read_to_string(&mut response)
            .map_err(|error| format!("ui smoke read failed: {error}"))?;
        handle
            .join()
            .map_err(|_| "ui smoke server thread panicked".to_owned())?;
        if response.contains("DistZKBench Integrated Console") {
            println!("{url}");
            return Ok(());
        }
        return Err("ui smoke did not return console html".to_owned());
    }
    println!("DistZKBench UI: {url}");
    if !no_open {
        let _ = open_url(&url);
    }
    for stream in bind_addr.incoming() {
        let stream = stream.map_err(|error| format!("ui accept failed: {error}"))?;
        let state_ref = state.clone();
        thread::spawn(move || {
            let _ = handle_connection(stream, &state_ref);
        });
    }
    Ok(())
}

fn bind_listener() -> Result<TcpListener, String> {
    for port in 38999..39050 {
        match TcpListener::bind(("127.0.0.1", port)) {
            Ok(listener) => return Ok(listener),
            Err(_) => continue,
        }
    }
    Err("could not bind DistZKBench UI on 127.0.0.1:38999..39049".to_owned())
}

fn handle_connection(mut stream: TcpStream, state: &UiState) -> Result<(), String> {
    let request = read_http_request(&mut stream)?;
    let response = route_request(&request, state);
    stream
        .write_all(&response)
        .map_err(|error| format!("write response failed: {error}"))
}

#[derive(Clone, Debug)]
struct HttpRequest {
    method: String,
    path: String,
    body: String,
}

fn read_http_request(stream: &mut TcpStream) -> Result<HttpRequest, String> {
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .map_err(|error| error.to_string())?;
    let mut buffer = Vec::new();
    let mut temp = [0_u8; 1024];
    loop {
        let read = stream
            .read(&mut temp)
            .map_err(|error| format!("read request failed: {error}"))?;
        if read == 0 {
            break;
        }
        buffer.extend_from_slice(&temp[..read]);
        if buffer.windows(4).any(|window| window == b"\r\n\r\n") {
            break;
        }
        if buffer.len() > 64 * 1024 {
            return Err("request header too large".to_owned());
        }
    }
    let header_end = buffer
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .map(|index| index + 4)
        .ok_or_else(|| "malformed HTTP request".to_owned())?;
    let header = String::from_utf8_lossy(&buffer[..header_end]).to_string();
    let mut lines = header.lines();
    let first = lines
        .next()
        .ok_or_else(|| "empty HTTP request".to_owned())?;
    let mut parts = first.split_whitespace();
    let method = parts.next().unwrap_or_default().to_owned();
    let path = parts.next().unwrap_or("/").to_owned();
    let content_len = lines
        .find_map(|line| {
            line.split_once(':').and_then(|(key, value)| {
                key.eq_ignore_ascii_case("content-length")
                    .then(|| value.trim().parse::<usize>().ok())
                    .flatten()
            })
        })
        .unwrap_or(0);
    while buffer.len() < header_end + content_len {
        let read = stream
            .read(&mut temp)
            .map_err(|error| format!("read request body failed: {error}"))?;
        if read == 0 {
            break;
        }
        buffer.extend_from_slice(&temp[..read]);
    }
    let body =
        String::from_utf8_lossy(&buffer[header_end..buffer.len().min(header_end + content_len)])
            .to_string();
    Ok(HttpRequest { method, path, body })
}

fn route_request(request: &HttpRequest, state: &UiState) -> Vec<u8> {
    let result = match (request.method.as_str(), request.path.as_str()) {
        ("GET", "/") => Ok(html(UI_HTML)),
        ("POST", "/api/toy-config") => handle_toy_config(&request.body).and_then(json_response),
        ("POST", "/api/preflight") => {
            handle_job_request("preflight", &request.body, state).and_then(json_response)
        }
        ("POST", "/api/run") => {
            handle_job_request("run", &request.body, state).and_then(json_response)
        }
        ("GET", "/api/runs/latest") => latest_run_summary().and_then(json_response),
        ("GET", path) if path.starts_with("/api/jobs/") => {
            handle_job_get(path, state).and_then(json_response)
        }
        ("GET", path) if path.starts_with("/api/runs/") && path.ends_with("/report") => {
            handle_report_get(path)
        }
        _ => Err(("not found".to_owned(), 404)),
    };
    match result {
        Ok(response) => response,
        Err((message, status)) => text_response(status, "text/plain; charset=utf-8", &message),
    }
}

fn html(body: &str) -> Vec<u8> {
    text_response(200, "text/html; charset=utf-8", body)
}

fn json_response<T: Serialize>(value: T) -> Result<Vec<u8>, (String, u16)> {
    serde_json::to_string(&value)
        .map(|body| text_response(200, "application/json; charset=utf-8", &body))
        .map_err(|error| (error.to_string(), 500))
}

fn text_response(status: u16, content_type: &str, body: &str) -> Vec<u8> {
    let reason = match status {
        200 => "OK",
        400 => "Bad Request",
        404 => "Not Found",
        500 => "Internal Server Error",
        _ => "OK",
    };
    format!(
        "HTTP/1.1 {status} {reason}\r\ncontent-type: {content_type}\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
        body.len()
    )
    .into_bytes()
}

fn handle_toy_config(body: &str) -> Result<Value, (String, u16)> {
    let req = serde_json::from_str::<ToyConfigRequest>(body)
        .map_err(|error| (format!("invalid toy config request: {error}"), 400))?;
    let shape = req.shape.unwrap_or_else(|| "star".to_owned());
    let mut config = Config::default();
    config.experiment.name = format!("ui_toy_{}", slugify(&shape));
    config.experiment.run_id = "auto".to_owned();
    config.experiment.output_dir = "results".to_owned();
    config.roles.prover_ranks = req.ranks.unwrap_or(if shape == "pingpong" { 2 } else { 4 });
    config.roles.master_rank = 0;
    config.roles.verifier_enabled = true;
    config.resources.worker_threads = req.worker_threads.unwrap_or(1);
    config.resources.verifier_threads = "same_as_worker".to_owned();
    config.network.mode = "loopback".to_owned();
    config.network.base_port = req.base_port.unwrap_or(39000);
    config.network.shaper.latency = req.latency.unwrap_or_else(|| "0ms".to_owned());
    config.network.shaper.bandwidth = req.bandwidth.unwrap_or_else(|| "0".to_owned());
    config.protocol.mode = req.mode.unwrap_or_else(|| "sdk-binary".to_owned());
    config.protocol.command = req.adapter_command.unwrap_or_default();
    config.protocol.toy.message_bytes = req.message_bytes.unwrap_or(1024);
    match shape.as_str() {
        "full-mesh" | "fullmesh" | "alltoall" => {
            config.topology.kind = TopologyKind::FullMesh;
            config.topology.worker_to_worker = "allowed".to_owned();
            config.protocol.adapter = "toy-alltoall".to_owned();
        }
        "pingpong" | "ping-pong" => {
            config.topology.kind = TopologyKind::FullMesh;
            config.topology.worker_to_worker = "allowed".to_owned();
            config.roles.prover_ranks = config.roles.prover_ranks.max(2);
            config.protocol.adapter = "toy-pingpong".to_owned();
        }
        "star" | "" => {
            config.topology.kind = TopologyKind::Star;
            config.topology.worker_to_worker = "forbidden".to_owned();
            config.protocol.adapter = "toy-star-aggregate".to_owned();
        }
        other => return Err((format!("unknown toy shape '{other}'"), 400)),
    }
    let dir = PathBuf::from("configs/generated");
    fs::create_dir_all(&dir).map_err(|error| (error.to_string(), 500))?;
    let path = dir.join(format!("{}_ui.yaml", config.experiment.name));
    let yaml = serde_yaml::to_string(&config).map_err(|error| (error.to_string(), 500))?;
    fs::write(&path, &yaml).map_err(|error| (error.to_string(), 500))?;
    Ok(serde_json::json!({
        "config_path": path,
        "yaml": yaml,
        "shape": shape,
        "ranks": config.roles.prover_ranks
    }))
}

fn handle_job_request(kind: &str, body: &str, state: &UiState) -> Result<Value, (String, u16)> {
    let body = serde_json::from_str::<Value>(body)
        .map_err(|error| (format!("invalid job request: {error}"), 400))?;
    let config_path = body
        .get("config_path")
        .and_then(Value::as_str)
        .ok_or_else(|| ("config_path is required".to_owned(), 400))?;
    let args = if kind == "preflight" {
        vec![
            "preflight".to_owned(),
            "--config".to_owned(),
            config_path.to_owned(),
        ]
    } else {
        vec!["run".to_owned(), config_path.to_owned()]
    };
    let id = spawn_job(kind, args, state).map_err(|error| (error, 500))?;
    Ok(serde_json::json!({"job_id": id}))
}

fn spawn_job(kind: &str, args: Vec<String>, state: &UiState) -> Result<u64, String> {
    let id = state.next_job.fetch_add(1, Ordering::Relaxed);
    let mut command_display = vec![state.exe.display().to_string()];
    command_display.extend(args.clone());
    let job = JobState {
        id,
        kind: kind.to_owned(),
        status: "running".to_owned(),
        command: command_display,
        log: String::new(),
        exit_code: None,
        result_dir: None,
    };
    state
        .jobs
        .lock()
        .map_err(|_| "job state poisoned".to_owned())?
        .insert(id, job);
    let jobs = Arc::clone(&state.jobs);
    let exe = state.exe.clone();
    let kind = kind.to_owned();
    thread::spawn(move || {
        let _ = run_job_thread(id, kind, exe, args, jobs);
    });
    Ok(id)
}

fn run_job_thread(
    id: u64,
    kind: String,
    exe: PathBuf,
    args: Vec<String>,
    jobs: Arc<Mutex<BTreeMap<u64, JobState>>>,
) -> Result<(), String> {
    append_job_log(
        &jobs,
        id,
        &format!("$ {} {}\n", exe.display(), args.join(" ")),
    );
    let mut child = Command::new(&exe)
        .args(&args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|error| {
            finish_job(&jobs, id, -1, None);
            error.to_string()
        })?;
    let stdout = child.stdout.take();
    let stderr = child.stderr.take();
    let jobs_out = Arc::clone(&jobs);
    let out_handle = stdout.map(|out| {
        thread::spawn(move || {
            read_pipe_to_job(out, &jobs_out, id);
        })
    });
    let jobs_err = Arc::clone(&jobs);
    let err_handle = stderr.map(|err| {
        thread::spawn(move || {
            read_pipe_to_job(err, &jobs_err, id);
        })
    });
    let status = child.wait().map_err(|error| error.to_string())?;
    if let Some(handle) = out_handle {
        let _ = handle.join();
    }
    if let Some(handle) = err_handle {
        let _ = handle.join();
    }
    let code = status.code().unwrap_or(-1);
    let result_dir = if kind == "run" {
        latest_run_dir().map(|path| path.display().to_string())
    } else {
        None
    };
    finish_job(&jobs, id, code, result_dir);
    Ok(())
}

fn read_pipe_to_job<R: Read>(reader: R, jobs: &Arc<Mutex<BTreeMap<u64, JobState>>>, id: u64) {
    for line in BufReader::new(reader).lines().map_while(Result::ok) {
        append_job_log(jobs, id, &format!("{line}\n"));
    }
}

fn append_job_log(jobs: &Arc<Mutex<BTreeMap<u64, JobState>>>, id: u64, text: &str) {
    if let Ok(mut guard) = jobs.lock()
        && let Some(job) = guard.get_mut(&id)
    {
        job.log.push_str(text);
        if job.log.len() > 128 * 1024 {
            let drain = job.log.len() - 128 * 1024;
            job.log.drain(..drain);
        }
        let _ = persist_job_log(job);
    }
}

fn finish_job(
    jobs: &Arc<Mutex<BTreeMap<u64, JobState>>>,
    id: u64,
    code: i32,
    result_dir: Option<String>,
) {
    if let Ok(mut guard) = jobs.lock()
        && let Some(job) = guard.get_mut(&id)
    {
        job.exit_code = Some(code);
        job.status = if code == 0 { "ok" } else { "failed" }.to_owned();
        job.result_dir = result_dir;
        let _ = persist_job_log(job);
    }
}

fn persist_job_log(job: &JobState) -> std::io::Result<()> {
    let dir = Path::new("results").join("ui").join("logs");
    fs::create_dir_all(&dir)?;
    let mut file = File::create(dir.join(format!("ui_job_{}.log", job.id)))?;
    file.write_all(job.log.as_bytes())
}

fn handle_job_get(path: &str, state: &UiState) -> Result<Value, (String, u16)> {
    let id = path
        .trim_start_matches("/api/jobs/")
        .parse::<u64>()
        .map_err(|_| ("invalid job id".to_owned(), 400))?;
    let guard = state
        .jobs
        .lock()
        .map_err(|_| ("job state poisoned".to_owned(), 500))?;
    let job = guard
        .get(&id)
        .ok_or_else(|| ("job not found".to_owned(), 404))?;
    serde_json::to_value(job).map_err(|error| (error.to_string(), 500))
}

fn latest_run_summary() -> Result<Value, (String, u16)> {
    let Some(dir) = latest_run_dir() else {
        return Ok(serde_json::json!({"found": false}));
    };
    let summary = summarize_run_dir(&dir).map_err(|error| (error, 500))?;
    serde_json::to_value(summary).map_err(|error| (error.to_string(), 500))
}

fn latest_run_dir() -> Option<PathBuf> {
    let mut candidates = Vec::new();
    collect_run_jsons(Path::new("results"), &mut candidates).ok()?;
    candidates
        .into_iter()
        .max_by_key(|(modified, _)| *modified)
        .and_then(|(_, path)| path.parent().map(Path::to_path_buf))
}

fn collect_run_jsons(dir: &Path, out: &mut Vec<(SystemTime, PathBuf)>) -> std::io::Result<()> {
    if !dir.exists() {
        return Ok(());
    }
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        let ty = entry.file_type()?;
        if ty.is_dir() {
            collect_run_jsons(&path, out)?;
        } else if ty.is_file() && path.file_name().is_some_and(|name| name == "run.json") {
            let modified = entry
                .metadata()
                .and_then(|metadata| metadata.modified())
                .unwrap_or(SystemTime::UNIX_EPOCH);
            out.push((modified, path));
        }
    }
    Ok(())
}

fn summarize_run_dir(dir: &Path) -> Result<RunSummary, String> {
    let run_json = read_json(&dir.join("run.json"))?;
    let run_id = run_json
        .get("run_id")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_owned();
    let status = run_json
        .get("status")
        .and_then(Value::as_str)
        .unwrap_or("unknown")
        .to_owned();
    let communication_precision = run_json
        .get("communication_precision")
        .and_then(Value::as_str)
        .unwrap_or("unknown")
        .to_owned();
    let edges = parse_comm_matrix(&dir.join("comm_matrix.csv"))?;
    let rank_count = parse_rank_count(&dir.join("per_rank.csv"))?;
    let verifier_ok = parse_verifier_ok(&dir.join("verifier.json")).unwrap_or(true);
    let total_messages = edges.iter().map(|edge| edge.messages).sum::<u64>();
    let total_payload = edges.iter().map(|edge| edge.payload_bytes).sum::<u64>();
    let proof_size = run_json
        .get("proof_size_bytes")
        .and_then(Value::as_u64)
        .unwrap_or(0);
    let communication_unavailable = communication_precision == "unavailable";
    let network_ok = total_messages > 0 && total_payload > 0;
    let feasible = status == "ok"
        && rank_count > 0
        && (communication_unavailable || network_ok)
        && proof_size > 0
        && verifier_ok;
    let reason = if feasible {
        "ok".to_owned()
    } else if status != "ok" {
        "run failed".to_owned()
    } else if !communication_unavailable && !network_ok {
        "no active TCP protocol edge".to_owned()
    } else if proof_size == 0 {
        "no proof/artifact bytes".to_owned()
    } else if !verifier_ok {
        "verifier failed".to_owned()
    } else {
        "incomplete run artifacts".to_owned()
    };
    Ok(RunSummary {
        found: true,
        run_id: run_id.clone(),
        result_dir: dir.display().to_string(),
        report_url: format!("/api/runs/{run_id}/report"),
        status,
        platform: run_json
            .get("platform")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_owned(),
        isolation_tier: run_json
            .get("isolation_tier")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_owned(),
        proof_size_bytes: proof_size,
        verifier_ms: run_json
            .get("verifier_median_ms")
            .and_then(Value::as_f64)
            .unwrap_or(0.0),
        communication_precision,
        network_ok,
        feasible,
        reason,
        edges,
    })
}

fn read_json(path: &Path) -> Result<Value, String> {
    let text = fs::read_to_string(path)
        .map_err(|error| format!("read {} failed: {error}", path.display()))?;
    serde_json::from_str(&text).map_err(|error| format!("parse {} failed: {error}", path.display()))
}

fn parse_comm_matrix(path: &Path) -> Result<Vec<EdgeSummary>, String> {
    let text =
        fs::read_to_string(path).map_err(|error| format!("read comm matrix failed: {error}"))?;
    let mut out = Vec::new();
    for line in text.lines().skip(1) {
        let cols = line.split(',').collect::<Vec<_>>();
        if cols.len() < 5 {
            continue;
        }
        out.push(EdgeSummary {
            src: cols[0].parse().unwrap_or(0),
            dst: cols[1].parse().unwrap_or(0),
            payload_bytes: cols[2].parse().unwrap_or(0),
            framed_bytes: cols[3].parse().unwrap_or(0),
            messages: cols[4].parse().unwrap_or(0),
        });
    }
    Ok(out)
}

fn parse_rank_count(path: &Path) -> Result<usize, String> {
    let text =
        fs::read_to_string(path).map_err(|error| format!("read per_rank failed: {error}"))?;
    Ok(text
        .lines()
        .skip(1)
        .filter(|line| !line.trim().is_empty())
        .count())
}

fn parse_verifier_ok(path: &Path) -> Option<bool> {
    let value = read_json(path).ok()?;
    value
        .pointer("/process_report/verified")
        .and_then(Value::as_bool)
        .or_else(|| {
            value
                .pointer("/process_report/verified")
                .is_none()
                .then_some(true)
        })
}

fn handle_report_get(path: &str) -> Result<Vec<u8>, (String, u16)> {
    let run_id = path
        .trim_start_matches("/api/runs/")
        .trim_end_matches("/report");
    let Some(dir) = find_run_dir(run_id) else {
        return Err(("run not found".to_owned(), 404));
    };
    let html = fs::read_to_string(dir.join("report.html"))
        .map_err(|error| (format!("read report failed: {error}"), 500))?;
    Ok(text_response(200, "text/html; charset=utf-8", &html))
}

fn find_run_dir(run_id: &str) -> Option<PathBuf> {
    let mut candidates = Vec::new();
    collect_run_jsons(Path::new("results"), &mut candidates).ok()?;
    candidates.into_iter().find_map(|(_, run_json)| {
        let dir = run_json.parent()?.to_path_buf();
        let value = read_json(&run_json).ok()?;
        (value.get("run_id").and_then(Value::as_str) == Some(run_id)).then_some(dir)
    })
}

fn open_url(url: &str) -> Result<(), String> {
    let opener = if cfg!(target_os = "macos") {
        "open"
    } else if cfg!(target_os = "linux") {
        "xdg-open"
    } else {
        return Ok(());
    };
    Command::new(opener)
        .arg(url)
        .status()
        .map_err(|error| format!("failed to open browser: {error}"))?;
    Ok(())
}

fn slugify(value: &str) -> String {
    let mut out = String::new();
    let mut previous_dash = false;
    for ch in value.chars() {
        if ch.is_ascii_alphanumeric() {
            out.push(ch.to_ascii_lowercase());
            previous_dash = false;
        } else if !previous_dash && !out.is_empty() {
            out.push('_');
            previous_dash = true;
        }
    }
    while out.ends_with('_') {
        out.pop();
    }
    if out.is_empty() {
        "distzkbench_ui".to_owned()
    } else {
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_comm_matrix_edges() {
        let path = std::env::temp_dir().join(format!("dzb-comm-{}.csv", std::process::id()));
        fs::write(
            &path,
            "src,dst,serialized_payload_bytes,framed_bytes,messages\n0,1,12,84,1\n",
        )
        .expect("write comm csv");
        let edges = parse_comm_matrix(&path).expect("parse comm csv");
        assert_eq!(edges.len(), 1);
        assert_eq!(edges[0].payload_bytes, 12);
        let _ = fs::remove_file(path);
    }

    #[test]
    fn job_log_buffer_caps() {
        let jobs = Arc::new(Mutex::new(BTreeMap::new()));
        jobs.lock().expect("lock").insert(
            1,
            JobState {
                id: 1,
                kind: "test".to_owned(),
                status: "running".to_owned(),
                command: vec![],
                log: String::new(),
                exit_code: None,
                result_dir: None,
            },
        );
        append_job_log(&jobs, 1, &"x".repeat(140 * 1024));
        let len = jobs.lock().expect("lock").get(&1).expect("job").log.len();
        assert!(len <= 128 * 1024);
    }
}

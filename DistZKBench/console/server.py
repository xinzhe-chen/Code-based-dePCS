#!/usr/bin/env python3
"""DistZKBench top-level HTML console.

This server intentionally uses only the Python standard library so the console
can start before Rust targets exist. It listens on localhost and dispatches
build/run/smoke commands requested by console/index.html.
"""

from __future__ import annotations

import argparse
import csv
import json
import os
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import urllib.request
import webbrowser
from dataclasses import asdict, dataclass, field
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
INDEX_HTML = ROOT / "console" / "index.html"
RESULTS = ROOT / "results"
GENERATED_CONFIGS = ROOT / "configs" / "generated"


@dataclass
class Job:
    id: int
    kind: str
    command: list[str]
    status: str = "running"
    log: str = ""
    exit_code: int | None = None
    result_dir: str | None = None


class ConsoleState:
    def __init__(self) -> None:
        self.jobs: dict[int, Job] = {}
        self.next_job = 1
        self.lock = threading.Lock()

    def create_job(self, kind: str, command: list[str]) -> Job:
        with self.lock:
            job = Job(id=self.next_job, kind=kind, command=command)
            self.jobs[job.id] = job
            self.next_job += 1
            return job

    def get_job(self, job_id: int) -> Job | None:
        with self.lock:
            return self.jobs.get(job_id)

    def append_log(self, job_id: int, text: str) -> None:
        with self.lock:
            job = self.jobs.get(job_id)
            if not job:
                return
            job.log += text
            if len(job.log) > 128 * 1024:
                job.log = job.log[-128 * 1024 :]
            persist_job_log(job)

    def finish(self, job_id: int, code: int, result_dir: str | None = None) -> None:
        with self.lock:
            job = self.jobs.get(job_id)
            if not job:
                return
            job.exit_code = code
            job.status = "ok" if code == 0 else "failed"
            job.result_dir = result_dir
            persist_job_log(job)


STATE = ConsoleState()


class Handler(BaseHTTPRequestHandler):
    server_version = "DistZKBenchConsole/1"

    def do_GET(self) -> None:
        try:
            if self.path == "/":
                self.send_html(INDEX_HTML.read_text())
            elif self.path == "/api/runs/latest":
                self.send_json(latest_run_summary())
            elif self.path.startswith("/api/jobs/"):
                self.handle_job_get()
            elif self.path.startswith("/api/runs/") and self.path.endswith("/report"):
                self.handle_report_get()
            else:
                self.send_error_text(HTTPStatus.NOT_FOUND, "not found")
        except Exception as exc:  # noqa: BLE001 - server boundary
            self.send_error_text(HTTPStatus.INTERNAL_SERVER_ERROR, str(exc))

    def do_POST(self) -> None:
        try:
            body = self.read_json_body()
            if self.path == "/api/build/rust-release":
                self.send_json({"job_id": spawn_command_job("build-rust-release", cargo_cmd(["build", "--workspace", "--release", "--locked"]))})
            elif self.path == "/api/build/rust-debug":
                self.send_json({"job_id": spawn_command_job("build-rust-debug", cargo_cmd(["build", "--workspace"]))})
            elif self.path == "/api/build/c-ffi":
                self.send_json({"job_id": spawn_sequence_job("build-c-ffi", c_ffi_build_steps())})
            elif self.path == "/api/clean/target":
                self.send_json({"job_id": spawn_python_job("clean-target", clean_target)})
            elif self.path == "/api/toy-config":
                self.send_json(handle_toy_config(body))
            elif self.path == "/api/preflight":
                self.send_json({"job_id": spawn_dzb_job("preflight", body)})
            elif self.path == "/api/run":
                self.send_json({"job_id": spawn_dzb_job("run", body)})
            elif self.path == "/api/smoke/c-ffi-pingpong":
                self.send_json({"job_id": spawn_python_job("c-ffi-pingpong", lambda job: run_c_ffi_pingpong(job, body))})
            else:
                self.send_error_text(HTTPStatus.NOT_FOUND, "not found")
        except ValueError as exc:
            self.send_error_text(HTTPStatus.BAD_REQUEST, str(exc))
        except Exception as exc:  # noqa: BLE001 - server boundary
            self.send_error_text(HTTPStatus.INTERNAL_SERVER_ERROR, str(exc))

    def read_json_body(self) -> dict[str, Any]:
        length = int(self.headers.get("content-length", "0"))
        if length == 0:
            return {}
        return json.loads(self.rfile.read(length).decode())

    def handle_job_get(self) -> None:
        raw = self.path.removeprefix("/api/jobs/")
        job = STATE.get_job(int(raw))
        if not job:
            self.send_error_text(HTTPStatus.NOT_FOUND, "job not found")
            return
        self.send_json(asdict(job))

    def handle_report_get(self) -> None:
        run_id = self.path.removeprefix("/api/runs/").removesuffix("/report")
        run_dir = find_run_dir(run_id)
        if not run_dir:
            self.send_error_text(HTTPStatus.NOT_FOUND, "run not found")
            return
        self.send_html((run_dir / "report.html").read_text())

    def send_json(self, value: Any) -> None:
        body = json.dumps(value).encode()
        self.send_response(HTTPStatus.OK)
        self.send_header("content-type", "application/json; charset=utf-8")
        self.send_header("content-length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def send_html(self, text: str) -> None:
        body = text.encode()
        self.send_response(HTTPStatus.OK)
        self.send_header("content-type", "text/html; charset=utf-8")
        self.send_header("content-length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def send_error_text(self, status: HTTPStatus, text: str) -> None:
        body = text.encode()
        self.send_response(status)
        self.send_header("content-type", "text/plain; charset=utf-8")
        self.send_header("content-length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, fmt: str, *args: Any) -> None:
        return


def cargo_cmd(args: list[str]) -> list[str]:
    cargo = find_tool("DZB_CARGO", "cargo")
    return [cargo, *args]


def cc_cmd() -> str:
    return find_tool("CC", "cc")


def find_tool(env_name: str, tool: str) -> str:
    override = os.environ.get(env_name)
    if override:
        return override
    found = shutil.which(tool)
    if found:
        return found
    candidates = [
        Path.home() / ".cargo" / "bin" / tool,
        ROOT.parent / "pq_dPCS" / ".codex-rust" / "cargo" / "bin" / tool,
    ]
    for candidate in candidates:
        if candidate.exists():
            return str(candidate)
    return tool


def bundled_rust_env() -> dict[str, str]:
    candidates = [
        ROOT / ".codex-rust",
        ROOT.parent / "pq_dPCS" / ".codex-rust",
    ]
    for base in candidates:
        cargo_home = base / "cargo"
        rustup_home = base / "rustup"
        cargo_bin = cargo_home / "bin"
        if (cargo_bin / "cargo").exists() and rustup_home.exists():
            return {
                "CARGO_HOME": str(cargo_home),
                "RUSTUP_HOME": str(rustup_home),
                "PATH": str(cargo_bin),
            }
    return {}


def dzb_release() -> Path:
    exe = ROOT / "target" / "release" / ("dzb.exe" if os.name == "nt" else "dzb")
    return exe


def fixture_binary() -> Path:
    return ROOT / "target" / "ffi" / ("dzb_ffi_pingpong.exe" if os.name == "nt" else "dzb_ffi_pingpong")


def lib_name() -> str:
    if sys.platform == "darwin":
        return "libdzb_sdk.dylib"
    if os.name == "nt":
        return "dzb_sdk.dll"
    return "libdzb_sdk.so"


def c_ffi_build_steps() -> list[list[str]]:
    out = fixture_binary()
    out.parent.mkdir(parents=True, exist_ok=True)
    return [
        cargo_cmd(["build", "-p", "dzb-sdk", "--release", "--locked"]),
        [
            cc_cmd(),
            "ffi-fixtures/pingpong.c",
            "-I",
            "include",
            "-L",
            "target/release",
            "-ldzb_sdk",
            "-o",
            str(out),
        ],
    ]


def spawn_command_job(kind: str, command: list[str]) -> int:
    return spawn_sequence_job(kind, [command])


def spawn_sequence_job(kind: str, commands: list[list[str]]) -> int:
    job = STATE.create_job(kind, commands[0] if commands else [])
    thread = threading.Thread(target=run_sequence, args=(job.id, commands), daemon=True)
    thread.start()
    return job.id


def spawn_python_job(kind: str, fn: Any) -> int:
    job = STATE.create_job(kind, [kind])
    thread = threading.Thread(target=lambda: run_python_job(job.id, fn), daemon=True)
    thread.start()
    return job.id


def run_python_job(job_id: int, fn: Any) -> None:
    try:
        code = fn(job_id)
    except Exception as exc:  # noqa: BLE001 - job boundary
        STATE.append_log(job_id, f"{exc}\n")
        code = 1
    STATE.finish(job_id, int(code), latest_run_dir_str())


def run_sequence(job_id: int, commands: list[list[str]]) -> None:
    code = 0
    try:
        for command in commands:
            code = run_subprocess(job_id, command)
            if code != 0:
                break
    except FileNotFoundError as exc:
        STATE.append_log(job_id, f"command not found: {exc.filename}\n")
        STATE.append_log(job_id, "If this is a build job, install Rust or set DZB_CARGO=/absolute/path/to/cargo.\n")
        code = 127
    except Exception as exc:  # noqa: BLE001 - job boundary
        STATE.append_log(job_id, f"job failed before process output: {exc}\n")
        code = 1
    STATE.finish(job_id, code, latest_run_dir_str())


def run_subprocess(job_id: int, command: list[str], env: dict[str, str] | None = None) -> int:
    STATE.append_log(job_id, "$ " + " ".join(command) + "\n")
    merged_env = os.environ.copy()
    rust_env = bundled_rust_env()
    for key, value in rust_env.items():
        if key == "PATH":
            merged_env[key] = value + os.pathsep + merged_env.get(key, "")
        else:
            merged_env.setdefault(key, value)
    if env:
        merged_env.update(env)
    process = subprocess.Popen(
        command,
        cwd=ROOT,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        env=merged_env,
    )
    assert process.stdout is not None
    for line in process.stdout:
        STATE.append_log(job_id, line)
    return process.wait()


def spawn_dzb_job(kind: str, body: dict[str, Any]) -> int:
    config_path = str(body.get("config_path", ""))
    if not config_path:
        raise ValueError("config_path is required")
    dzb = dzb_release()
    if not dzb.exists():
        return spawn_python_job(kind, lambda job: missing_dzb(job))
    if kind == "preflight":
        return spawn_command_job("preflight", [str(dzb), "preflight", "--config", config_path])
    return spawn_command_job("run", [str(dzb), "run", config_path])


def missing_dzb(job_id: int) -> int:
    STATE.append_log(job_id, "target/release/dzb is missing. Run Build Rust release first.\n")
    return 1


def clean_target(job_id: int) -> int:
    STATE.append_log(job_id, "$ rm -rf target\n")
    shutil.rmtree(ROOT / "target", ignore_errors=True)
    return 0


def handle_toy_config(body: dict[str, Any]) -> dict[str, Any]:
    shape = str(body.get("shape", "star"))
    ranks = int(body.get("ranks") or (2 if shape == "pingpong" else 4))
    if shape in {"pingpong", "ping-pong"}:
        ranks = max(ranks, 2)
    experiment = f"console_toy_{slugify(shape)}"
    topology_type = "star"
    worker_to_worker = "forbidden"
    adapter = "toy-star-aggregate"
    if shape in {"full-mesh", "fullmesh", "alltoall"}:
        topology_type = "full-mesh"
        worker_to_worker = "allowed"
        adapter = "toy-alltoall"
    elif shape in {"pingpong", "ping-pong"}:
        topology_type = "full-mesh"
        worker_to_worker = "allowed"
        adapter = "toy-pingpong"
    elif shape not in {"star", ""}:
        raise ValueError(f"unknown toy shape '{shape}'")
    config = {
        "experiment": {
            "name": experiment,
            "run_id": "auto",
            "output_dir": "results",
            "random_seed": 12345,
        },
        "platform": {"backend": "auto"},
        "roles": {
            "prover_ranks": ranks,
            "master_rank": 0,
            "verifier_enabled": True,
        },
        "topology": {
            "type": topology_type,
            "worker_to_worker": worker_to_worker,
            "enforce_topology": True,
        },
        "resources": {
            "worker_threads": int(body.get("worker_threads") or 1),
            "verifier_threads": "same_as_worker",
        },
        "network": {
            "transport": "tcp",
            "mode": "loopback",
            "base_port": int(body.get("base_port") or 39000),
            "max_frame_payload": "16MiB",
            "shaper": {
                "bandwidth": str(body.get("bandwidth") or "0"),
                "latency": str(body.get("latency") or "0ms"),
            },
        },
        "protocol": {
            "adapter": adapter,
            "mode": str(body.get("mode") or "sdk-binary"),
            "command": str(body.get("adapter_command") or ""),
            "toy": {"message_bytes": int(body.get("message_bytes") or 1024)},
        },
    }
    GENERATED_CONFIGS.mkdir(parents=True, exist_ok=True)
    path = GENERATED_CONFIGS / f"{experiment}_console.yaml"
    yaml = to_yaml(config)
    path.write_text(yaml)
    return {"config_path": str(path), "yaml": yaml, "shape": shape, "ranks": ranks}


def run_c_ffi_pingpong(job_id: int, body: dict[str, Any]) -> int:
    binary = fixture_binary()
    dylib = ROOT / "target" / "release" / lib_name()
    if not binary.exists() or not dylib.exists():
        STATE.append_log(job_id, "C FFI fixture or dzb-sdk library is missing. Run Build C FFI fixture first.\n")
        return 1
    base_port = int(body.get("base_port") or 39410)
    max_frame_payload = int(body.get("max_frame_payload") or 1048576)
    run_id = f"ffi-console-{int(time.time() * 1000)}"
    tmp = Path(tempfile.mkdtemp(prefix="dzb-ffi-console-"))
    out0 = tmp / "rank0.json"
    out1 = tmp / "rank1.json"
    cfg0 = tmp / "rank_0_config.json"
    cfg1 = tmp / "rank_1_config.json"
    common = {
        "run_id": run_id,
        "world_size": 2,
        "master_rank": 0,
        "adapter": "ffi-pingpong",
        "topology_kind": "full-mesh",
        "enforce_topology": True,
        "routed_star": False,
        "listen_addrs": [f"127.0.0.1:{base_port}", f"127.0.0.1:{base_port + 1}"],
        "message_bytes": 8,
        "random_seed": 1,
        "max_frame_payload": max_frame_payload,
        "thread_budget": 1,
        "shaper": {"bandwidth_bytes_per_sec": None, "latency_ms": 0, "edge_overrides": []},
        "memory_limit_bytes": None,
    }
    cfg0.write_text(json.dumps({**common, "rank": 0, "output_path": str(out0), "proof_path": None}))
    cfg1.write_text(json.dumps({**common, "rank": 1, "output_path": str(out1), "proof_path": None}))
    env0 = ffi_env(cfg0)
    env1 = ffi_env(cfg1)
    STATE.append_log(job_id, f"$ DZB_RANK_CONFIG={cfg0} {binary}\n")
    p0 = subprocess.Popen([str(binary)], cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, env=env0)
    time.sleep(0.1)
    STATE.append_log(job_id, f"$ DZB_RANK_CONFIG={cfg1} {binary}\n")
    p1 = subprocess.Popen([str(binary)], cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, env=env1)
    code = 0
    for proc in [p0, p1]:
        assert proc.stdout is not None
        for line in proc.stdout:
            STATE.append_log(job_id, line)
        code = max(code, proc.wait())
    if code != 0:
        return code
    outputs = [json.loads(out0.read_text()), json.loads(out1.read_text())]
    messages = sum(edge["messages"] for output in outputs for edge in output["communication"]["edges"])
    if messages != 2:
        STATE.append_log(job_id, f"expected 2 C FFI TCP messages, observed {messages}\n")
        return 1
    STATE.append_log(job_id, f"C FFI pingpong ok: messages={messages}, tmp={tmp}\n")
    return 0


def ffi_env(config_path: Path) -> dict[str, str]:
    env = os.environ.copy()
    env["DZB_RANK_CONFIG"] = str(config_path)
    lib_dir = str(ROOT / "target" / "release")
    if sys.platform == "darwin":
        env["DYLD_LIBRARY_PATH"] = lib_dir + os.pathsep + env.get("DYLD_LIBRARY_PATH", "")
    else:
        env["LD_LIBRARY_PATH"] = lib_dir + os.pathsep + env.get("LD_LIBRARY_PATH", "")
    return env


def latest_run_summary() -> dict[str, Any]:
    run_dir = latest_run_dir()
    if not run_dir:
        return {"found": False}
    return summarize_run_dir(run_dir)


def latest_run_dir_str() -> str | None:
    run_dir = latest_run_dir()
    return str(run_dir) if run_dir else None


def latest_run_dir() -> Path | None:
    if not RESULTS.exists():
        return None
    candidates = list(RESULTS.glob("**/run.json"))
    if not candidates:
        return None
    return max(candidates, key=lambda path: path.stat().st_mtime).parent


def find_run_dir(run_id: str) -> Path | None:
    if not RESULTS.exists():
        return None
    for run_json in RESULTS.glob("**/run.json"):
        try:
            value = json.loads(run_json.read_text())
        except json.JSONDecodeError:
            continue
        if value.get("run_id") == run_id:
            return run_json.parent
    return None


def summarize_run_dir(run_dir: Path) -> dict[str, Any]:
    run = json.loads((run_dir / "run.json").read_text())
    edges = parse_comm_matrix(run_dir / "comm_matrix.csv")
    rank_count = parse_rank_count(run_dir / "per_rank.csv")
    verifier_ok = parse_verifier_ok(run_dir / "verifier.json")
    communication_precision = str(run.get("communication_precision", "unknown"))
    communication_unavailable = communication_precision == "unavailable"
    total_messages = sum(edge["messages"] for edge in edges)
    total_payload = sum(edge["payload_bytes"] for edge in edges)
    network_ok = total_messages > 0 and total_payload > 0
    proof_size = int(run.get("proof_size_bytes") or 0)
    feasible = (
        run.get("status") == "ok"
        and rank_count > 0
        and (communication_unavailable or network_ok)
        and proof_size > 0
        and verifier_ok
    )
    if feasible:
        reason = "ok"
    elif run.get("status") != "ok":
        reason = "run failed"
    elif not communication_unavailable and not network_ok:
        reason = "no active TCP protocol edge"
    elif proof_size == 0:
        reason = "no proof/artifact bytes"
    elif not verifier_ok:
        reason = "verifier failed"
    else:
        reason = "incomplete run artifacts"
    run_id = str(run.get("run_id", ""))
    return {
        "found": True,
        "run_id": run_id,
        "result_dir": str(run_dir),
        "report_url": f"/api/runs/{run_id}/report",
        "status": str(run.get("status", "unknown")),
        "platform": str(run.get("platform", "")),
        "isolation_tier": str(run.get("isolation_tier", "")),
        "proof_size_bytes": proof_size,
        "verifier_ms": float(run.get("verifier_median_ms") or 0.0),
        "communication_precision": communication_precision,
        "network_ok": network_ok,
        "feasible": feasible,
        "reason": reason,
        "edges": edges,
    }


def parse_comm_matrix(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    with path.open(newline="") as handle:
        rows = csv.DictReader(handle)
        return [
            {
                "src": int(row["src"]),
                "dst": int(row["dst"]),
                "payload_bytes": int(row["serialized_payload_bytes"]),
                "framed_bytes": int(row["framed_bytes"]),
                "messages": int(row["messages"]),
            }
            for row in rows
        ]


def parse_rank_count(path: Path) -> int:
    if not path.exists():
        return 0
    with path.open(newline="") as handle:
        return sum(1 for _ in csv.DictReader(handle))


def parse_verifier_ok(path: Path) -> bool:
    if not path.exists():
        return True
    value = json.loads(path.read_text())
    verified = value.get("process_report", {}).get("verified")
    return True if verified is None else bool(verified)


def persist_job_log(job: Job) -> None:
    directory = RESULTS / "ui" / "logs"
    directory.mkdir(parents=True, exist_ok=True)
    (directory / f"ui_job_{job.id}.log").write_text(job.log)


def to_yaml(value: Any, indent: int = 0) -> str:
    lines: list[str] = []
    prefix = " " * indent
    if isinstance(value, dict):
        for key, item in value.items():
            if isinstance(item, dict):
                lines.append(f"{prefix}{key}:")
                lines.append(to_yaml(item, indent + 2).rstrip())
            elif isinstance(item, list):
                lines.append(f"{prefix}{key}:")
                for element in item:
                    lines.append(f"{prefix}  - {element}")
            else:
                lines.append(f"{prefix}{key}: {format_yaml_scalar(item)}")
    return "\n".join(lines) + "\n"


def format_yaml_scalar(value: Any) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    if value is None:
        return "null"
    if isinstance(value, (int, float)):
        return str(value)
    text = str(value)
    if text == "" or any(ch in text for ch in [":", "#", "'", '"']) or text in {"0", "true", "false"}:
        return json.dumps(text)
    return text


def slugify(value: str) -> str:
    out = []
    previous = False
    for char in value:
        if char.isalnum():
            out.append(char.lower())
            previous = False
        elif not previous and out:
            out.append("_")
            previous = True
    return "".join(out).strip("_") or "distzkbench"


def bind_server(port: int) -> ThreadingHTTPServer:
    last_error: OSError | None = None
    for candidate in range(port, port + 51):
        try:
            return ThreadingHTTPServer(("127.0.0.1", candidate), Handler)
        except OSError as exc:
            last_error = exc
    raise RuntimeError(f"could not bind localhost server: {last_error}")


def smoke(port: int) -> None:
    server = bind_server(port)
    url = f"http://{server.server_address[0]}:{server.server_address[1]}"
    thread = threading.Thread(target=server.handle_request, daemon=True)
    thread.start()
    body = urllib.request.urlopen(url, timeout=5).read().decode()
    server.server_close()
    if "DistZKBench Integrated Console" not in body:
        raise SystemExit("console smoke did not return HTML")
    print(url)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=38999)
    parser.add_argument("--no-open", action="store_true")
    parser.add_argument("--once-smoke", action="store_true")
    args = parser.parse_args()
    os.chdir(ROOT)
    if args.host != "127.0.0.1":
        raise SystemExit("DistZKBench console only supports 127.0.0.1")
    if args.once_smoke:
        smoke(args.port)
        return
    server = bind_server(args.port)
    url = f"http://{server.server_address[0]}:{server.server_address[1]}"
    print(f"DistZKBench console: {url}", flush=True)
    if not args.no_open:
        webbrowser.open(url)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()

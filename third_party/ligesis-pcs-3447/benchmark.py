#!/usr/bin/env python3
"""
PCS Benchmark (Remote Server)

Supported schemes:
  - Single-thread: LigeSIS, DeepFold, Ligero
  - Distributed: dLigeSIS, dDeepFold, dDeepFoldBatch, etc.

Usage:
    # Interactive mode
    python3 benchmark.py

    # Single command
    python3 benchmark.py status
    python3 benchmark.py set-n 4                    # Set num_party=4
    python3 benchmark.py run -s ligesis -m 24       # Single-thread test
    python3 benchmark.py run -s dligesis -m 28      # Distributed test
"""

import argparse
import json
import math
import os
import re
import readline  # Command line history and editing support
import shlex
import signal
import subprocess
import sys
import tempfile
import threading
import time
from dataclasses import dataclass, asdict
from datetime import datetime
from pathlib import Path
from typing import Optional

# Global flag for interrupt handling
_interrupted = False

# ============== Configuration ==============

WORKSPACE = Path(__file__).parent.resolve()
SERVERS_CONFIG = WORKSPACE / "ligesis-pcs" / "dTests" / "servers_16.json"
RESULTS_DIR = Path("bench_results")
ZONE = "us-central1-a"
REMOTE_DIR = "~/ligesis-pcs"

# Cache files
CACHE_DIR = WORKSPACE / ".benchmark_cache"
CONFIG_CACHE = CACHE_DIR / "config.json"
HISTORY_FILE = CACHE_DIR / "history"
HISTORY_LENGTH = 50

# Machine type configs: name -> (gcp_machine_type, description)
MACHINE_CONFIGS = {
    "8g":  ("e2-standard-2", "2 vCPU,  8GB"),
    "16g": ("e2-highmem-2",  "2 vCPU, 16GB"),
    "32g": ("e2-highmem-4",  "4 vCPU, 32GB"),
    "64g": ("e2-highmem-8",  "8 vCPU, 64GB"),
}

# ANSI colors for scheme names
# Use distinct 256-color codes so every known scheme has a unique color.
SCHEME_COLORS = {
    "ligesis": "\033[38;5;82m",         # green
    "dligesis": "\033[38;5;45m",        # cyan
    "deepfold": "\033[38;5;75m",        # blue
    "ddeepfold": "\033[38;5;69m",       # light blue
    "ddeepfoldbatch": "\033[38;5;33m",  # dark blue
    "ligero": "\033[38;5;220m",         # yellow
    "dpip-fri-pcs": "\033[38;5;201m",   # magenta
    "dmkzg-pcs": "\033[38;5;208m",      # orange
    "ddory-pcs": "\033[38;5;196m",      # red
    "dsumcheck3": "\033[38;5;178m",     # gold
    "dsumcheck4": "\033[38;5;81m",      # teal
    "dhyperpianist": "\033[38;5;129m",  # purple
    "dfrittata-pcs": "\033[38;5;214m",  # orange-yellow
}
COLOR_RESET = "\033[0m"


def colored_scheme(scheme: str, display_name: str) -> str:
    """Return colored scheme name"""
    color = SCHEME_COLORS.get(scheme, "")
    if color:
        return f"{color}{display_name}{COLOR_RESET}"
    return display_name


def result_sort_key(r: 'BenchResult'):
    """Sort with single-thread first, then distributed."""
    return (r.num_parties > 1, r.scheme, r.num_parties, r.mu)

# Current number of parties
NUM_PARTY = 4


# ============== Cache Functions ==============

def load_config_cache():
    """Load config cache"""
    global NUM_PARTY
    if CONFIG_CACHE.exists():
        try:
            with open(CONFIG_CACHE, 'r') as f:
                config = json.load(f)
                NUM_PARTY = config.get('num_party', NUM_PARTY)
        except (json.JSONDecodeError, IOError):
            pass


def save_config_cache():
    """Save config cache"""
    CACHE_DIR.mkdir(parents=True, exist_ok=True)
    with open(CONFIG_CACHE, 'w') as f:
        json.dump({'num_party': NUM_PARTY}, f)


def load_history():
    """Load command history"""
    if HISTORY_FILE.exists():
        try:
            readline.read_history_file(str(HISTORY_FILE))
        except (IOError, OSError):
            pass
    readline.set_history_length(HISTORY_LENGTH)


def save_history():
    """Save command history"""
    CACHE_DIR.mkdir(parents=True, exist_ok=True)
    try:
        readline.write_history_file(str(HISTORY_FILE))
    except (IOError, OSError):
        pass


# Single-thread schemes
SINGLE_SCHEMES = {
    "ligesis": {"bench_name": "ligesis_bench", "display_name": "LigeSIS"},
    "deepfold": {"bench_name": "deepfold_bench", "display_name": "DeepFold"},
    "ligero": {"bench_name": "ligero_bench", "display_name": "Ligero"},
}

# Distributed schemes (internal - ligesis-pcs examples)
DISTRIBUTED_SCHEMES = {
    "dligesis": {"example_name": "dLigesis", "display_name": "dLigeSIS"},
    "ddeepfold": {"example_name": "dDeepFold", "display_name": "dDeepFold"},
    "ddeepfoldbatch": {"example_name": "dDeepFoldBatch", "display_name": "dDeepFoldBatch"},
    "dmerkle": {"example_name": "dMerkle", "display_name": "dMerkle"},
    "dchunkedbatch": {"example_name": "dChunkedBatch", "display_name": "dChunkedBatch"},
    "dmultichunkedbatchbench": {"example_name": "dMultiChunkedBatchBench", "display_name": "dMultiChunkedBatchBench"},
    "dmultichunkedbatchprofile": {"example_name": "dMultiChunkedBatchProfile", "display_name": "dMultiChunkedBatchProfile"},
    "dsumcheck3": {"example_name": "dSumcheck", "display_name": "dSumcheck3", "extra_args": "--degree 3", "skip_base_mu": True},
    "dsumcheck4": {"example_name": "dSumcheck", "display_name": "dSumcheck4", "extra_args": "--degree 4", "skip_base_mu": True},
}

# External distributed schemes (from submodules in external/)
EXTERNAL_SCHEMES = {
    "dpip-fri-pcs": {
        "display_name": "dPIP-FRI-PCS",
        "local_dir": WORKSPACE / "external" / "PIP_FRI",
        "remote_dir": "~/pip_fri",
        "binary": "target/release/examples/de_pip_fri",
        "config_path": "de_pip_fri/data/network.conf",
        "port": 8000,
        "build_cmd": lambda mu: (
            f"source ~/.cargo/env && RUSTFLAGS='-Awarnings' cargo build --release --example de_pip_fri"
        ),
        "run_cmd": lambda i, remote_dir, config_path, mu, iterations: (
            f"RAYON_NUM_THREADS=1 bash -c 'cd {remote_dir}/de_pip_fri && {remote_dir}/{EXTERNAL_SCHEMES['dpip-fri-pcs']['binary']} {i} data/network.conf {mu} -i {iterations}' 2>&1"
        ),
    },
    "dmkzg-pcs": {
        "display_name": "dmKZG-PCS",
        "local_dir": WORKSPACE / "external" / "HyperPianist",
        "remote_dir": "~/HyperPianist",
        "binary": "target/release/examples/deMkzg_bench",
        "config_path": "hyperpianist/dTests/data/network.conf",
        "port": 18000,
        "build_cmd": lambda mu: (
            f"source ~/.cargo/env && RUSTFLAGS='-Awarnings -C target-cpu=native' "
            f"cargo build --release --example deMkzg_bench"
        ),
        "run_cmd": lambda i, remote_dir, config_path, mu, iterations: (
            f"{remote_dir}/{EXTERNAL_SCHEMES['dmkzg-pcs']['binary']} {i} {remote_dir}/{config_path} {mu} -i {iterations} 2>&1"
        ),
    },
    "ddory-pcs": {
        "display_name": "dDory-PCS",
        "local_dir": WORKSPACE / "external" / "HyperPianist",
        "remote_dir": "~/HyperPianist",
        "binary": "target/release/examples/deDory_bench",
        "config_path": "hyperpianist/dTests/data/network.conf",
        "port": 18000,
        "build_cmd": lambda mu: (
            f"source ~/.cargo/env && RUSTFLAGS='-Awarnings -C target-cpu=native' "
            f"cargo build --release --example deDory_bench"
        ),
        "run_cmd": lambda i, remote_dir, config_path, mu, iterations: (
            f"{remote_dir}/{EXTERNAL_SCHEMES['ddory-pcs']['binary']} {i} {remote_dir}/{config_path} {mu} -i {iterations} 2>&1"
        ),
    },
    "dhyperpianist": {
        "display_name": "dHyperPianist",
        "local_dir": WORKSPACE / "external" / "HyperPianist",
        "remote_dir": "~/HyperPianist",
        "binary": "target/release/examples/hyperpianist-bench",
        "config_path": "hyperpianist/dTests/data/network.conf",
        "port": 18000,
        "build_cmd": lambda mu: (
            f"source ~/.cargo/env && RUSTFLAGS='-Awarnings -C target-cpu=native' "
            f"cargo build --release --example hyperpianist-bench"
        ),
        "run_cmd": lambda i, remote_dir, config_path, mu, iterations: (
            f"{remote_dir}/{EXTERNAL_SCHEMES['dhyperpianist']['binary']} {i} {remote_dir}/{config_path} --jellyfish {mu} -i {iterations} 2>&1"
        ),
    },
    "dfrittata-pcs": {
        "display_name": "dFRIttata-PCS",
        "local_dir": WORKSPACE,
        "remote_dir": REMOTE_DIR,
        "binary": "target/release/examples/dFrittata",
        "config_path": "ligesis-pcs/dTests/data/network.conf",
        "port": 18000,
        "build_cmd": lambda mu: (
            f"source ~/.cargo/env && cd ligesis-pcs && RUSTFLAGS='-Awarnings' "
            f"cargo build --release --example dFrittata"
        ),
        "run_cmd": lambda i, remote_dir, config_path, mu, iterations: (
            f"RAYON_NUM_THREADS=1 {remote_dir}/{EXTERNAL_SCHEMES['dfrittata-pcs']['binary']} {i} {remote_dir}/{config_path} --mu {mu} -i {iterations} 2>&1"
        ),
    },
}

ALL_SCHEMES = {**SINGLE_SCHEMES, **DISTRIBUTED_SCHEMES, **EXTERNAL_SCHEMES}

DEFAULT_MUS = [24, 26, 28, 30]
DEFAULT_SINGLE_SCHEMES = ["ligesis", "deepfold", "ligero"]
DEFAULT_ITERATIONS = 1

# ============== Data Structures ==============

@dataclass
class BenchResult:
    scheme: str
    mu: int
    iteration: int
    timestamp: str
    success: bool
    num_parties: int = 1
    setup_time_ms: Optional[float] = None
    commit_time_ms: Optional[float] = None
    open_time_ms: Optional[float] = None
    verify_time_ms: Optional[float] = None
    prover_time_ms: Optional[float] = None
    total_time_ms: Optional[float] = None
    communication_bytes: Optional[int] = None
    proof_size_kb: Optional[float] = None
    # Per-iteration times (list of ms values)
    iter_commit_times: Optional[list[float]] = None
    iter_open_times: Optional[list[float]] = None
    iter_verify_times: Optional[list[float]] = None
    iter_prove_times: Optional[list[float]] = None
    # Machine type per node, e.g. {"node-1": "e2-highmem-4", ...}
    machine_types: Optional[dict[str, str]] = None
    raw_output: str = ""
    error: str = ""


# ============== Server Management ==============

def load_servers_config():
    with open(SERVERS_CONFIG) as f:
        return json.load(f)


def get_all_servers() -> list[dict]:
    config = load_servers_config()
    return config["servers"]


def get_active_servers() -> list[dict]:
    """Get server list for current NUM_PARTY"""
    all_servers = get_all_servers()
    return all_servers[:NUM_PARTY]


def get_server_name() -> str:
    """Get first server name (for single-thread tests)"""
    return get_active_servers()[0]["name"]


def get_user() -> str:
    config = load_servers_config()
    return config.get("user", "")


def get_zone() -> str:
    config = load_servers_config()
    return config.get("zone", ZONE)


def run_gcloud(args: list[str], timeout: int = 300) -> subprocess.CompletedProcess:
    cmd = ["gcloud"] + args
    return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)


def gcloud_ssh(instance: str, command: str, timeout: int = 3600, retries: int = 3) -> dict:
    """Execute command via gcloud ssh with IAP tunneling support"""
    user = get_user()
    zone = get_zone()

    cmd = ["gcloud", "compute", "ssh"]
    if user:
        cmd.append(f"{user}@{instance}")
    else:
        cmd.append(instance)

    cmd.extend([
        "--zone", zone,
        "--tunnel-through-iap",  # Explicitly use IAP tunneling
        "--quiet",  # Reduce output noise
    ])

    # Add SSH options
    cmd.extend([
        "--ssh-flag=-o ServerAliveInterval=30",
        "--ssh-flag=-o ServerAliveCountMax=3",
        "--ssh-flag=-o ConnectTimeout=30",
        "--", "-T", command
    ])

    last_error = ""
    for attempt in range(retries):
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
            stderr = result.stderr

            # Filter out IAP tunneling warnings and other noise
            stderr_lines = [
                line for line in stderr.split('\n')
                if not line.startswith("External IP address was not found")
                and not line.startswith("WARNING:")
                and "Connection closed by UNKNOWN" not in line
                and "increase the performance of the tunnel" not in line
                and "installing NumPy" not in line
                and "cloud.google.com/iap/docs" not in line
                and line.strip()
            ]
            filtered_stderr = '\n'.join(stderr_lines)

            # Check for IAP connection error (needs retry)
            if result.returncode != 0 and "Connection closed by UNKNOWN" in stderr:
                last_error = f"IAP connection failed (attempt {attempt + 1}/{retries})"
                if attempt < retries - 1:
                    time.sleep(2 * (attempt + 1))  # Exponential backoff
                    continue

            return {
                "stdout": result.stdout,
                "stderr": filtered_stderr,
                "returncode": result.returncode
            }
        except subprocess.TimeoutExpired:
            last_error = "Timeout"
            if attempt < retries - 1:
                continue
            return {"stdout": "", "stderr": "Timeout", "returncode": -1}
        except Exception as e:
            last_error = str(e)
            if attempt < retries - 1:
                time.sleep(1)
                continue
            return {"stdout": "", "stderr": str(e), "returncode": -1}

    return {"stdout": "", "stderr": last_error, "returncode": -1}


def gcloud_scp(local_path: str, instance: str, remote_path: str, retries: int = 3) -> bool:
    user = get_user()
    zone = get_zone()

    cmd = [
        "gcloud", "compute", "scp",
        "--zone", zone,
        "--tunnel-through-iap",  # Explicitly use IAP
        "--quiet",
    ]
    remote_spec = f"{user}@{instance}:{remote_path}" if user else f"{instance}:{remote_path}"
    cmd.extend([local_path, remote_spec])

    for attempt in range(retries):
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            if result.returncode == 0:
                return True
            # Retry on IAP connection error
            if "Connection closed by UNKNOWN" in result.stderr and attempt < retries - 1:
                time.sleep(2 * (attempt + 1))
                continue
            return False
        except subprocess.TimeoutExpired:
            if attempt < retries - 1:
                continue
            return False
        except Exception:
            if attempt < retries - 1:
                time.sleep(1)
                continue
            return False
    return False


def get_running_servers() -> list[str]:
    """Get all running node-* servers"""
    result = run_gcloud([
        "compute", "instances", "list",
        "--filter=name~'^node-' AND status=RUNNING",
        "--format=value(name)"
    ])
    if result.returncode != 0:
        return []
    return [s for s in result.stdout.strip().split('\n') if s]


def get_stopped_servers() -> list[str]:
    """Get all stopped node-* servers"""
    result = run_gcloud([
        "compute", "instances", "list",
        "--filter=name~'^node-' AND status=TERMINATED",
        "--format=value(name)"
    ])
    if result.returncode != 0:
        return []
    return [s for s in result.stdout.strip().split('\n') if s]


def get_machine_types(num_parties: int) -> Optional[dict[str, str]]:
    """Get machine types for node-1 to node-{num_parties}"""
    if num_parties <= 0:
        return None
    result = run_gcloud([
        "compute", "instances", "list",
        "--filter=name~'^node-'",
        "--format=value(name,machineType.basename())"
    ])
    if result.returncode != 0:
        return None
    types = {}
    for line in result.stdout.strip().split('\n'):
        parts = line.split()
        if len(parts) == 2:
            types[parts[0]] = parts[1]
    # Only keep nodes used in this run
    return {f"node-{i}": types.get(f"node-{i}", "unknown")
            for i in range(1, num_parties + 1)}


def auto_detect_num_party(force: bool = False) -> int:
    """Auto-detect NUM_PARTY based on running servers.

    If force=False and NUM_PARTY was loaded from cache, skip auto-detection.
    """
    global NUM_PARTY

    # Check if config was loaded from cache (file exists)
    if not force and CONFIG_CACHE.exists():
        # Config was cached, don't override
        running = get_running_servers()
        if running:
            print(f"Using cached NUM_PARTY = {NUM_PARTY} (detected {len(running)} running servers)")
        return NUM_PARTY

    running = get_running_servers()
    if not running:
        print("No running servers detected, keeping NUM_PARTY = {}".format(NUM_PARTY))
        return NUM_PARTY

    # Count consecutive node-1, node-2, ... that are running
    count = 0
    for i in range(1, len(running) + 1):
        if f"node-{i}" in running:
            count = i
        else:
            break

    # Round down to power of 2
    if count >= 1:
        power_of_2 = 1
        while power_of_2 * 2 <= count:
            power_of_2 *= 2
        NUM_PARTY = power_of_2
        print(f"Auto-detected {len(running)} running servers, set NUM_PARTY = {NUM_PARTY}")
    else:
        print(f"No consecutive node-* servers found, keeping NUM_PARTY = {NUM_PARTY}")

    return NUM_PARTY


def cmd_status(_args=None):
    global NUM_PARTY
    print(f"\nCurrent config: num_party = {NUM_PARTY}")
    print(f"Active servers: node-1 to node-{NUM_PARTY}\n")

    result = run_gcloud(["compute", "instances", "list", "--filter=name~'^node-'"])
    print(result.stdout)
    return 0


def cmd_set_n(args):
    global NUM_PARTY
    n = args.n

    # Verify n is power of 2
    if n < 1 or (n & (n - 1)) != 0:
        print(f"Error: num_party must be a power of 2, got {n}")
        return 1

    all_servers = get_all_servers()
    if n > len(all_servers):
        print(f"Error: num_party ({n}) exceeds available servers ({len(all_servers)})")
        return 1

    NUM_PARTY = n
    save_config_cache()
    print(f"Set num_party = {NUM_PARTY}")
    print(f"  Active servers: node-1 to node-{NUM_PARTY}")

    # Show current server status
    running = get_running_servers()
    needed = [f"node-{i}" for i in range(1, NUM_PARTY + 1)]
    extra = [s for s in running if s not in needed]

    if extra:
        print(f"\nWarning: Extra servers running: {', '.join(extra)}")
        print("  Use 'start' command to adjust server state")

    return 0


def cmd_start(_args=None):
    global NUM_PARTY

    needed = [f"node-{i}" for i in range(1, NUM_PARTY + 1)]
    running = get_running_servers()

    # Servers to start
    to_start = [s for s in needed if s not in running]
    # Servers to stop (extra ones)
    to_stop = [s for s in running if s not in needed]

    zone = get_zone()

    if to_stop:
        print(f"Stopping extra servers: {', '.join(to_stop)}")
        result = run_gcloud(["compute", "instances", "stop"] + to_stop + ["--zone", zone], timeout=180)
        if result.returncode != 0:
            print(f"Stop failed: {result.stderr}", file=sys.stderr)

    if to_start:
        print(f"Starting servers: {', '.join(to_start)}")
        result = run_gcloud(["compute", "instances", "start"] + to_start + ["--zone", zone], timeout=180)
        if result.returncode != 0:
            print(f"Start failed: {result.stderr}", file=sys.stderr)
            return 1

        print("Waiting for servers to be ready...")
        time.sleep(15)

    if not to_start and not to_stop:
        print(f"Servers ready: {', '.join(needed)} already running")
    else:
        print(f"Servers ready: {', '.join(needed)}")

    return 0


def cmd_stop(_args=None):
    running = get_running_servers()

    if not running:
        print("No running servers")
        return 0

    zone = get_zone()
    print(f"Stopping {len(running)} servers: {', '.join(running)}")
    run_gcloud(["compute", "instances", "stop"] + running + ["--zone", zone], timeout=180)
    print("Servers stopped")
    return 0


def sync_main_project() -> int:
    """Sync main ligesis-pcs code to all active servers (parallel)"""
    servers = get_active_servers()

    print(f"Syncing ligesis-pcs to {len(servers)} servers...", end="", flush=True)

    # Create tarball
    tar_path = f"/tmp/ligesis_sync_{datetime.now().strftime('%H%M%S')}.tar.gz"
    # Keep external/winterfell (needed for dFrittata), exclude other external subdirs
    exclude_args = [
        "--exclude=target", "--exclude=.git", "--exclude=bench_results", "--exclude=.claude",
        "--exclude=external/HyperFond", "--exclude=external/HyperPianist", "--exclude=external/PIP_FRI"
    ]

    tar_cmd = ["tar", "czf", tar_path] + exclude_args + ["-C", str(WORKSPACE), "."]
    result = subprocess.run(tar_cmd, capture_output=True, text=True)
    if result.returncode != 0:
        print(f" failed")
        print(f"Failed to create tarball: {result.stderr}")
        return 1

    # Parallel sync
    sync_results = {}

    def do_sync(idx: int, server: dict):
        instance = server["name"]
        # Upload
        if not gcloud_scp(tar_path, instance, "~/ligesis_sync.tar.gz"):
            sync_results[idx] = (False, "upload failed")
            return
        # Extract
        result = gcloud_ssh(
            instance,
            f"mkdir -p {REMOTE_DIR} && cd {REMOTE_DIR} && "
            f"find . -maxdepth 1 ! -name . ! -name target -exec rm -rf {{}} + && "
            f"tar xzf ~/ligesis_sync.tar.gz && rm ~/ligesis_sync.tar.gz",
            timeout=120
        )
        if result["returncode"] != 0:
            sync_results[idx] = (False, f"extract failed: {result['stderr']}")
            return
        sync_results[idx] = (True, "ok")

    threads = []
    for i, server in enumerate(servers):
        t = threading.Thread(target=do_sync, args=(i, server))
        threads.append(t)

    for t in threads:
        t.start()
    for t in threads:
        t.join()

    Path(tar_path).unlink(missing_ok=True)

    # Check results
    failed = [(i, sync_results[i][1]) for i in range(len(servers)) if not sync_results.get(i, (False, "unknown"))[0]]
    if failed:
        print(" failed")
        for i, err in failed:
            print(f"  x {servers[i]['name']}: {err}")
        return 1

    print(" done")
    return 0


def cmd_sync(_args=None):
    """Sync code to all active servers (parallel), including external schemes"""
    ret = sync_main_project()
    if ret != 0:
        return ret

    # Sync all external schemes that exist locally
    for scheme, config in EXTERNAL_SCHEMES.items():
        local_dir = config["local_dir"]
        if local_dir.exists():
            sync_external_scheme(scheme)
        else:
            print(f"  Skipping {scheme} (not found at {local_dir})")
    return 0


# ============== Parsers ==============

def parse_duration(s: str) -> Optional[float]:
    s = s.strip()
    # Extract a numeric token followed by a time unit to avoid matching dot leaders.
    m = re.search(r'([0-9]+(?:\.[0-9]+)?)\s*(s|ms|us|µs|ns)', s, re.IGNORECASE)
    if not m:
        return None
    value = float(m.group(1))
    unit = m.group(2).lower()
    if unit == "s":
        return value * 1000
    if unit == "ms":
        return value
    if unit in ("us", "µs"):
        return value / 1000
    if unit == "ns":
        return value / 1_000_000
    return None


def parse_benchmark_output(output: str) -> dict:
    result = {}
    # Capture the first duration token after the label (works for "avg", "xN", "excluding setup", etc.)
    time_token = r'([0-9]+(?:\.[0-9]+)?\s*(?:s|ms|us|µs|ns))'
    patterns = {
        "setup": [rf'Setup(?: \([^)]*\))?[:\s]+{time_token}'],
        "commit": [rf'Commit(?: \([^)]*\))?[:\s]+{time_token}'],
        "open": [rf'Open(?: \([^)]*\))?[:\s]+{time_token}'],
        "verify": [rf'Verify(?: \([^)]*\))?[:\s]+{time_token}'],
        "total": [rf'Total(?: \([^)]*\))?[:\s]+{time_token}'],
    }

    for key, pats in patterns.items():
        for pat in pats:
            m = re.search(pat, output, re.IGNORECASE)
            if m:
                duration = parse_duration(m.group(1))
                if duration is not None:
                    result[key] = duration
                    break

    # Parse machine-readable metrics (override human-readable if present)
    machine_patterns = {
        "prover": r'PROVER_TIME_MS:\s*([\d.]+)',
        "verify": r'VERIFY_TIME_MS:\s*([\d.]+)',
        "proof_size_kb": r'PROOF_SIZE_KB:\s*([\d.]+)',
    }
    for key, pat in machine_patterns.items():
        m = re.search(pat, output)
        if m:
            result[key] = float(m.group(1))

    # Parse communication stats (try BYTES first, then MB)
    comm_match = re.search(r'COMM_TOTAL_BYTES:\s*(\d+)', output)
    if comm_match:
        result["communication_bytes"] = int(comm_match.group(1))
    else:
        comm_mb_match = re.search(r'COMM_TOTAL_MB:\s*([\d.]+)', output)
        if comm_mb_match:
            result["communication_bytes"] = int(float(comm_mb_match.group(1)) * 1024 * 1024)

    # Parse per-iteration times (ITER_N_COMMIT_MS, ITER_N_OPEN_MS, ITER_N_VERIFY_MS, ITER_N_PROVE_MS)
    iter_commit = []
    iter_open = []
    iter_verify = []
    iter_prove = []
    for m in re.finditer(r'ITER_(\d+)_COMMIT_MS:\s*([\d.]+)', output):
        iter_num = int(m.group(1))
        while len(iter_commit) < iter_num:
            iter_commit.append(None)
        iter_commit[iter_num - 1] = float(m.group(2))
    for m in re.finditer(r'ITER_(\d+)_OPEN_MS:\s*([\d.]+)', output):
        iter_num = int(m.group(1))
        while len(iter_open) < iter_num:
            iter_open.append(None)
        iter_open[iter_num - 1] = float(m.group(2))
    for m in re.finditer(r'ITER_(\d+)_VERIFY_MS:\s*([\d.]+)', output):
        iter_num = int(m.group(1))
        while len(iter_verify) < iter_num:
            iter_verify.append(None)
        iter_verify[iter_num - 1] = float(m.group(2))
    for m in re.finditer(r'ITER_(\d+)_PROVE_MS:\s*([\d.]+)', output):
        iter_num = int(m.group(1))
        while len(iter_prove) < iter_num:
            iter_prove.append(None)
        iter_prove[iter_num - 1] = float(m.group(2))

    if iter_commit:
        result["iter_commit_times"] = iter_commit
    if iter_open:
        result["iter_open_times"] = iter_open
    if iter_verify:
        result["iter_verify_times"] = iter_verify
    if iter_prove:
        result["iter_prove_times"] = iter_prove

    return result


# ============== Single-thread Benchmark ==============

def check_bench_exists(scheme: str) -> bool:
    if scheme not in SINGLE_SCHEMES:
        return False
    bench_name = SINGLE_SCHEMES[scheme]["bench_name"]
    bench_path = WORKSPACE / "ligesis-pcs" / "benches" / f"{bench_name}.rs"
    return bench_path.exists()


def run_single_thread_benchmark(scheme: str, mu: int, iterations: int = 1) -> BenchResult:
    config = SINGLE_SCHEMES.get(scheme)
    if not config:
        return BenchResult(
            scheme=scheme, mu=mu, iteration=1,
            timestamp=datetime.now().isoformat(),
            success=False, error=f"Unknown scheme: {scheme}"
        )

    bench_name = config["bench_name"]
    instance = get_server_name()
    cmd = (
        f"cd {REMOTE_DIR} && source ~/.cargo/env && "
        f"cargo bench --package ligesis-pcs --bench {bench_name} "
        f"--features print-trace -- --mu {mu} --iterations {iterations} 2>&1"
    )

    print(f"  Running...", end="", flush=True)
    result = gcloud_ssh(instance, cmd, timeout=3600)
    output = result["stdout"] + result["stderr"]

    if result["returncode"] != 0:
        print(" failed")
        return BenchResult(
            scheme=scheme, mu=mu, iteration=iterations,
            timestamp=datetime.now().isoformat(),
            success=False, error=output[-500:], raw_output=output
        )

    parsed = parse_benchmark_output(output)
    if not parsed:
        print(" parse failed")
        return BenchResult(
            scheme=scheme, mu=mu, iteration=iterations,
            timestamp=datetime.now().isoformat(),
            success=False, error="Failed to parse output", raw_output=output
        )

    commit_ms = parsed.get("commit")
    open_ms = parsed.get("open")
    prover_ms = (commit_ms or 0) + (open_ms or 0) if commit_ms or open_ms else None

    print(" done")
    return BenchResult(
        scheme=scheme, mu=mu, iteration=iterations,
        timestamp=datetime.now().isoformat(),
        success=True,
        setup_time_ms=parsed.get("setup"),
        commit_time_ms=commit_ms,
        open_time_ms=open_ms,
        verify_time_ms=parsed.get("verify"),
        prover_time_ms=prover_ms,
        total_time_ms=parsed.get("total"),
        proof_size_kb=parsed.get("proof_size_kb"),
        communication_bytes=parsed.get("communication_bytes"),
        iter_commit_times=parsed.get("iter_commit_times"),
        iter_open_times=parsed.get("iter_open_times"),
        iter_verify_times=parsed.get("iter_verify_times"),
        iter_prove_times=parsed.get("iter_prove_times"),
        raw_output=output,
    )


# ============== Distributed Benchmark ==============

def compute_optimal_base_mu(mu: int, num_parties: int) -> int:
    log_parties = int(math.log2(num_parties))
    local_num_vars = mu - log_parties
    OPTIMAL_BASE_MU = 14
    return min(OPTIMAL_BASE_MU, local_num_vars)


def generate_network_config(hosts: list[str], base_port: int = 18000) -> str:
    """Generate network config (all nodes use same port)"""
    return "\n".join(f"{host}:{base_port}" for host in hosts)


def _run_gcloud_ssh_worker(instance: str, command: str, timeout: int, result_dict: dict, index: int):
    """Worker function for threaded gcloud ssh execution"""
    result_dict[index] = gcloud_ssh(instance, command, timeout=timeout)


def kill_remote_processes(binary_name: str, servers: list[dict]):
    """Kill leftover benchmark processes on all remote servers (parallel)"""
    results = {}
    threads = []
    kill_cmd = f"pkill -9 -f '{binary_name}' 2>/dev/null; true"
    for i, server in enumerate(servers):
        t = threading.Thread(
            target=_run_gcloud_ssh_worker,
            args=(server["name"], kill_cmd, 30, results, i)
        )
        threads.append(t)
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=35)


def check_servers_running() -> tuple[bool, list[str], list[str]]:
    """Check if required servers are running, returns (all_running, running_list, not_running_list)"""
    needed = [f"node-{i}" for i in range(1, NUM_PARTY + 1)]
    running = get_running_servers()
    not_running = [s for s in needed if s not in running]
    return len(not_running) == 0, [s for s in needed if s in running], not_running


def run_distributed_benchmark(
    scheme: str,
    mu: int,
    iterations: int = 1,
    trace: bool = True,
    build: bool = False,
    sync: bool = False,
    base_mu: Optional[int] = None,
) -> BenchResult:
    global NUM_PARTY

    # Check server status
    all_running, running, not_running = check_servers_running()
    if not all_running:
        return BenchResult(
            scheme=scheme, mu=mu, iteration=iterations,
            timestamp=datetime.now().isoformat(),
            success=False, num_parties=NUM_PARTY,
            error=f"Servers not running: {', '.join(not_running)}. Run 'start' first"
        )

    # Sync main project code to servers if requested
    if sync:
        ret = sync_main_project()
        if ret != 0:
            return BenchResult(
                scheme=scheme, mu=mu, iteration=iterations,
                timestamp=datetime.now().isoformat(),
                success=False, num_parties=NUM_PARTY,
                error="Code sync failed"
            )

    config = DISTRIBUTED_SCHEMES.get(scheme)
    if not config:
        return BenchResult(
            scheme=scheme, mu=mu, iteration=iterations,
            timestamp=datetime.now().isoformat(),
            success=False, num_parties=NUM_PARTY,
            error=f"Unknown distributed scheme: {scheme}"
        )

    example_name = config["example_name"]
    extra_args = config.get("extra_args", "")
    skip_base_mu = config.get("skip_base_mu", False)
    servers = get_active_servers()
    num_parties = len(servers)

    # Compute base_mu (skip for schemes that don't use it)
    actual_base_mu = None
    if not skip_base_mu:
        actual_base_mu = base_mu if base_mu is not None else compute_optimal_base_mu(mu, num_parties)

    # Generate network config
    server_config = load_servers_config()
    hosts = [s["host"] for s in servers]
    network_port = server_config.get("network_port", 18000)
    config_content = generate_network_config(hosts, network_port)

    if actual_base_mu is not None:
        print(f"  Nodes: {num_parties}, base_mu: {actual_base_mu}")
    else:
        print(f"  Nodes: {num_parties}")

    # Build if needed
    if build:
        print(f"  Building on remote servers...", end="", flush=True)
        build_cmd = (
            f"source ~/.cargo/env && cd {REMOTE_DIR}/ligesis-pcs && "
            f"RUSTFLAGS='-Awarnings' cargo build --example {example_name} --release"
        )
        if trace:
            build_cmd += " --features print-trace"
        build_cmd += " 2>&1"

        # Parallel build
        build_results = {}
        build_threads = []
        for i, server in enumerate(servers):
            t = threading.Thread(
                target=_run_gcloud_ssh_worker,
                args=(server["name"], build_cmd, 600, build_results, i)
            )
            build_threads.append(t)

        for t in build_threads:
            t.start()
        for t in build_threads:
            t.join()

        # Check build results
        build_failed = [i for i in range(num_parties) if build_results.get(i, {}).get("returncode", -1) != 0]
        if build_failed:
            print(" failed")
            return BenchResult(
                scheme=scheme, mu=mu, iteration=iterations,
                timestamp=datetime.now().isoformat(),
                success=False, num_parties=num_parties,
                error=f"Build failed on {', '.join(servers[i]['name'] for i in build_failed)}",
                raw_output=build_results.get(build_failed[0], {}).get("stdout", "")
            )
        print(" done")

    # Deploy network config (parallel)
    print(f"  Deploying network config...", end="", flush=True)
    config_cmd = f"cat > /tmp/ligesis_network.conf << 'EOF'\n{config_content}\nEOF"

    config_results = {}
    config_threads = []
    for i, server in enumerate(servers):
        t = threading.Thread(
            target=_run_gcloud_ssh_worker,
            args=(server["name"], config_cmd, 60, config_results, i)
        )
        config_threads.append(t)

    for t in config_threads:
        t.start()
    for t in config_threads:
        t.join()

    # Check config results
    config_failed = [i for i in range(num_parties) if config_results.get(i, {}).get("returncode", -1) != 0]
    if config_failed:
        print(" failed")
        return BenchResult(
            scheme=scheme, mu=mu, iteration=iterations,
            timestamp=datetime.now().isoformat(),
            success=False, num_parties=num_parties,
            error=f"Config deploy failed on {', '.join(servers[i]['name'] for i in config_failed)}"
        )
    print(" done")

    # Run test - needs concurrent execution (distributed protocol requires simultaneous run)
    print(f"  Running...", end="", flush=True)

    # Kill leftover processes from previous runs
    kill_remote_processes(example_name, servers)

    binary_path = f"{REMOTE_DIR}/target/release/examples/{example_name}"
    run_results = {}
    threads = []

    # Start all threads using separate worker function to avoid closure issues
    for i, server in enumerate(servers):
        base_mu_arg = "" if skip_base_mu else f"--base-mu {actual_base_mu}"
        run_cmd = (
            f"RUST_BACKTRACE=1 {binary_path} {i} /tmp/ligesis_network.conf "
            f"--mu {mu} {base_mu_arg} --iterations {iterations} {extra_args} 2>&1"
        )
        t = threading.Thread(
            target=_run_gcloud_ssh_worker,
            args=(server["name"], run_cmd, 1800, run_results, i)
        )
        threads.append(t)

    # Start all threads
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    # Check results
    failed = [i for i in range(num_parties) if run_results.get(i, {}).get("returncode", -1) != 0]
    if failed:
        print(" failed")
        errors = []
        for i in failed:
            # Check both stdout and stderr for error messages
            stdout = run_results.get(i, {}).get("stdout", "")
            stderr = run_results.get(i, {}).get("stderr", "")
            # Look for actual errors in stdout (since we use 2>&1)
            err_lines = [l for l in stdout.split('\n') if 'error' in l.lower() or 'No such file' in l or 'not found' in l.lower()]
            if err_lines:
                err = err_lines[0]
            elif stderr:
                err = stderr
            else:
                err = stdout[-200:] if stdout else "Unknown error"
            errors.append(f"Party {i}: {err[:200]}")
        return BenchResult(
            scheme=scheme, mu=mu, iteration=iterations,
            timestamp=datetime.now().isoformat(),
            success=False, num_parties=num_parties,
            error="\n".join(errors),
            raw_output=run_results.get(0, {}).get("stdout", "")
        )

    # Parse output (from party 0)
    output = run_results[0]["stdout"]
    parsed = parse_benchmark_output(output)

    print(" done")

    commit_ms = parsed.get("commit")
    open_ms = parsed.get("open")
    # Use direct PROVER_TIME_MS if available, otherwise sum commit+open
    prover_ms = parsed.get("prover")
    if prover_ms is None and (commit_ms or open_ms):
        prover_ms = (commit_ms or 0) + (open_ms or 0)

    return BenchResult(
        scheme=scheme, mu=mu, iteration=iterations,
        timestamp=datetime.now().isoformat(),
        success=True, num_parties=num_parties,
        setup_time_ms=parsed.get("setup"),
        commit_time_ms=commit_ms,
        open_time_ms=open_ms,
        verify_time_ms=parsed.get("verify"),
        prover_time_ms=prover_ms,
        total_time_ms=parsed.get("total"),
        communication_bytes=parsed.get("communication_bytes"),
        proof_size_kb=parsed.get("proof_size_kb"),
        iter_commit_times=parsed.get("iter_commit_times"),
        iter_open_times=parsed.get("iter_open_times"),
        iter_verify_times=parsed.get("iter_verify_times"),
        iter_prove_times=parsed.get("iter_prove_times"),
        raw_output=output,
    )


# ============== External Benchmark ==============

def sync_external_scheme(scheme: str) -> bool:
    """Sync external scheme code to all active servers"""
    if scheme not in EXTERNAL_SCHEMES:
        print(f"Unknown external scheme: {scheme}")
        return False

    config = EXTERNAL_SCHEMES[scheme]
    local_dir = config["local_dir"]
    remote_dir = config["remote_dir"]
    servers = get_active_servers()

    if not local_dir.exists():
        print(f"Local directory not found: {local_dir}")
        print(f"  Run: git submodule update --init --recursive")
        return False

    print(f"Syncing {scheme} to {len(servers)} servers...", end="", flush=True)

    # Create tarball
    tar_path = f"/tmp/{scheme}_sync_{os.getpid()}.tar.gz"
    exclude_args = ["--exclude=target", "--exclude=.git", "--exclude=bench_results"]
    tar_cmd = ["tar", "czf", tar_path] + exclude_args + ["-C", str(local_dir), "."]
    result = subprocess.run(tar_cmd, capture_output=True, text=True)
    if result.returncode != 0:
        print(f" failed (tar)")
        return False

    # Parallel sync
    sync_results = {}

    def do_sync(idx: int, server: dict):
        instance = server["name"]
        if not gcloud_scp(tar_path, instance, f"~/{scheme}_sync.tar.gz"):
            sync_results[idx] = (False, "upload failed")
            return
        result = gcloud_ssh(
            instance,
            f"mkdir -p {remote_dir} && cd {remote_dir} && "
            f"find . -maxdepth 1 ! -name . ! -name target -exec rm -rf {{}} + && "
            f"tar xzf ~/{scheme}_sync.tar.gz && rm ~/{scheme}_sync.tar.gz",
            timeout=120
        )
        if result["returncode"] != 0:
            sync_results[idx] = (False, f"extract failed")
            return
        sync_results[idx] = (True, "ok")

    threads = []
    for i, server in enumerate(servers):
        t = threading.Thread(target=do_sync, args=(i, server))
        threads.append(t)

    for t in threads:
        t.start()
    for t in threads:
        t.join()

    Path(tar_path).unlink(missing_ok=True)

    failed = [i for i in range(len(servers)) if not sync_results.get(i, (False,))[0]]
    if failed:
        print(" failed")
        return False

    print(" done")
    return True


def run_external_benchmark(
    scheme: str,
    mu: int,
    iterations: int = 1,
    build: bool = False,
    sync: bool = False,
) -> BenchResult:
    """Run benchmark for external schemes (pip_fri, mkzg, dory)"""
    global NUM_PARTY

    # Check server status
    all_running, running, not_running = check_servers_running()
    if not all_running:
        return BenchResult(
            scheme=scheme, mu=mu, iteration=iterations,
            timestamp=datetime.now().isoformat(),
            success=False, num_parties=NUM_PARTY,
            error=f"Servers not running: {', '.join(not_running)}. Run 'start' first"
        )

    config = EXTERNAL_SCHEMES.get(scheme)
    if not config:
        return BenchResult(
            scheme=scheme, mu=mu, iteration=iterations,
            timestamp=datetime.now().isoformat(),
            success=False, num_parties=NUM_PARTY,
            error=f"Unknown external scheme: {scheme}"
        )

    servers = get_active_servers()
    num_parties = len(servers)
    remote_dir = config["remote_dir"]

    print(f"  Nodes: {num_parties}")

    # Sync if requested
    if sync:
        if not sync_external_scheme(scheme):
            return BenchResult(
                scheme=scheme, mu=mu, iteration=iterations,
                timestamp=datetime.now().isoformat(),
                success=False, num_parties=num_parties,
                error="Sync failed"
            )

    # Build if requested
    if build:
        print(f"  Building...", end="", flush=True)
        build_cmd = f"cd {remote_dir} && set -o pipefail && {config['build_cmd'](mu)} 2>&1 | tail -20"

        build_results = {}
        build_threads = []
        for i, server in enumerate(servers):
            t = threading.Thread(
                target=_run_gcloud_ssh_worker,
                args=(server["name"], build_cmd, 900, build_results, i)
            )
            build_threads.append(t)

        for t in build_threads:
            t.start()
        for t in build_threads:
            t.join()

        build_failed = [i for i in range(num_parties) if build_results.get(i, {}).get("returncode", -1) != 0]
        if build_failed:
            print(" failed")
            return BenchResult(
                scheme=scheme, mu=mu, iteration=iterations,
                timestamp=datetime.now().isoformat(),
                success=False, num_parties=num_parties,
                error=f"Build failed on {', '.join(servers[i]['name'] for i in build_failed)}",
                raw_output=build_results.get(build_failed[0], {}).get("stdout", "")
            )
        print(" done")

    # Deploy network config
    print(f"  Deploying network config...", end="", flush=True)
    server_config = load_servers_config()
    hosts = [s["host"] for s in servers]
    port = config.get("port", 18000)
    network_conf = generate_network_config(hosts, port)
    config_path = f"{remote_dir}/{config['config_path']}"

    config_cmd = f"mkdir -p $(dirname {config_path}) && cat > {config_path} << 'EOF'\n{network_conf}\nEOF"

    config_results = {}
    config_threads = []
    for i, server in enumerate(servers):
        t = threading.Thread(
            target=_run_gcloud_ssh_worker,
            args=(server["name"], config_cmd, 60, config_results, i)
        )
        config_threads.append(t)

    for t in config_threads:
        t.start()
    for t in config_threads:
        t.join()

    config_failed = [i for i in range(num_parties) if config_results.get(i, {}).get("returncode", -1) != 0]
    if config_failed:
        print(" failed")
        return BenchResult(
            scheme=scheme, mu=mu, iteration=iterations,
            timestamp=datetime.now().isoformat(),
            success=False, num_parties=num_parties,
            error=f"Config deploy failed"
        )
    print(" done")

    # Run test - single call, let Rust handle iterations internally
    print(f"  Running...", end="", flush=True)

    # Kill leftover processes from previous runs
    binary_name = Path(config["binary"]).name
    kill_remote_processes(binary_name, servers)

    run_results = {}
    threads = []

    for i, server in enumerate(servers):
        run_cmd = config["run_cmd"](i, remote_dir, config["config_path"], mu, iterations)
        t = threading.Thread(
            target=_run_gcloud_ssh_worker,
            args=(server["name"], run_cmd, 1800, run_results, i)
        )
        threads.append(t)

    for t in threads:
        t.start()
    for t in threads:
        t.join()

    # Check results
    failed = [i for i in range(num_parties) if run_results.get(i, {}).get("returncode", -1) != 0]
    if failed:
        print(" failed")
        errors = []
        for i in failed:
            stdout = run_results.get(i, {}).get("stdout", "")
            stderr = run_results.get(i, {}).get("stderr", "")
            err = stderr if stderr else stdout[-200:]
            errors.append(f"Party {i}: {err[:100]}")
        return BenchResult(
            scheme=scheme, mu=mu, iteration=iterations,
            timestamp=datetime.now().isoformat(),
            success=False, num_parties=num_parties,
            error="\n".join(errors),
            raw_output=run_results.get(0, {}).get("stdout", "")
        )

    print(" done")

    # Parse output (from party 0)
    output = run_results[0]["stdout"]
    parsed = parse_external_output(output)

    # Also parse per-iteration times using the standard parser
    std_parsed = parse_benchmark_output(output)

    # Get averages from parsed output
    avg_commit = parsed.get("commit_time_ms")
    avg_open = parsed.get("open_time_ms")
    avg_verify = parsed.get("verify_time_ms")
    prover_ms = parsed.get("prover_time_ms")
    if prover_ms is None and (avg_commit or avg_open):
        prover_ms = (avg_commit or 0) + (avg_open or 0)

    comm_bytes = parsed.get("comm_total_bytes")
    comm_mb = parsed.get("comm_total_mb")

    return BenchResult(
        scheme=scheme, mu=mu, iteration=iterations,
        timestamp=datetime.now().isoformat(),
        success=True, num_parties=num_parties,
        commit_time_ms=avg_commit,
        open_time_ms=avg_open,
        verify_time_ms=avg_verify,
        prover_time_ms=prover_ms,
        communication_bytes=comm_bytes if comm_bytes else (int(comm_mb * 1024 * 1024) if comm_mb else None),
        proof_size_kb=parsed.get("proof_size_kb"),
        iter_commit_times=std_parsed.get("iter_commit_times"),
        iter_open_times=std_parsed.get("iter_open_times"),
        iter_verify_times=std_parsed.get("iter_verify_times"),
        iter_prove_times=std_parsed.get("iter_prove_times"),
        raw_output=output,
    )


def parse_duration_to_ms(duration_str: str) -> Optional[float]:
    """Parse Rust Duration debug output to milliseconds.

    Examples: "1.234567s", "123.456ms", "1234µs", "1234us"
    """
    duration_str = duration_str.strip()

    # Try seconds format: "1.234567s" or "1s"
    m = re.match(r'^([\d.]+)s$', duration_str)
    if m:
        return float(m.group(1)) * 1000

    # Try milliseconds format: "123.456ms"
    m = re.match(r'^([\d.]+)ms$', duration_str)
    if m:
        return float(m.group(1))

    # Try microseconds format: "1234µs" or "1234us"
    m = re.match(r'^([\d.]+)[µu]s$', duration_str)
    if m:
        return float(m.group(1)) / 1000

    # Try nanoseconds format: "1234ns"
    m = re.match(r'^([\d.]+)ns$', duration_str)
    if m:
        return float(m.group(1)) / 1000000

    return None


def parse_external_output(output: str) -> dict:
    """Parse output from external schemes (dpip-fri-pcs, dmkzg-pcs, etc.)"""
    result = {}

    # Standard patterns (machine-readable)
    patterns = {
        "commit_time_ms": r'COMMIT_TIME_MS:\s*([\d.]+)',
        "open_time_ms": r'OPEN_TIME_MS:\s*([\d.]+)',
        "verify_time_ms": r'VERIFY_TIME_MS:\s*([\d.]+)',
        "proof_size_kb": r'PROOF_SIZE_KB:\s*([\d.]+)',
        "comm_total_mb": r'COMM_TOTAL_MB:\s*([\d.]+)',
        "prover_time_ms": r'PROVER_TIME_MS:\s*([\d.]+)',  # Combined commit+open for proof systems
    }

    # Alternative patterns (older formats)
    alt_patterns = {
        "commit_time_ms": r'Commit time:\s*([\d.]+)\s*([µu]?s|ms)',
        "open_time_ms": r'Open time:\s*([\d.]+)\s*([µu]?s|ms|s)',
        "verify_time_ms": r'Verify time:\s*([\d.]+)\s*([µu]?s|ms)',
        "proof_size_kb": r'Proof size:\s*([\d.]+)\s*KB',
        "comm_total_mb": r'total[=:]\s*([\d.]+)\s*MB',
    }

    for key, pattern in patterns.items():
        m = re.search(pattern, output)
        if m:
            result[key] = float(m.group(1))

    # Try alternative patterns if not found
    for key, pattern in alt_patterns.items():
        if key not in result:
            m = re.search(pattern, output, re.IGNORECASE)
            if m:
                val = float(m.group(1))
                if len(m.groups()) > 1:
                    unit = m.group(2).lower()
                    if unit in ('µs', 'us'):
                        val /= 1000
                    elif unit == 's' and 'ms' not in unit:
                        val *= 1000
                result[key] = val

    # Parse communication stats (try BYTES first, then MB)
    comm_bytes_match = re.search(r'COMM_TOTAL_BYTES:\s*(\d+)', output)
    if comm_bytes_match:
        result["comm_total_bytes"] = int(comm_bytes_match.group(1))

    # HyperFond-specific patterns (Rust Duration format)
    # "proving for 24 variables: 1.234567s"
    if "prover_time_ms" not in result:
        m = re.search(r'proving for \d+ variables:\s*([\d.]+(?:s|ms|[µu]s|ns))', output)
        if m:
            ms = parse_duration_to_ms(m.group(1))
            if ms is not None:
                result["prover_time_ms"] = ms

    # "verifiy for 24 variables: 123.456ms" (note: typo in original code)
    if "verify_time_ms" not in result:
        m = re.search(r'verifi?y for \d+ variables:\s*([\d.]+(?:s|ms|[µu]s|ns))', output)
        if m:
            ms = parse_duration_to_ms(m.group(1))
            if ms is not None:
                result["verify_time_ms"] = ms

    # "proof length 1234." -> proof size in bytes
    if "proof_size_kb" not in result:
        m = re.search(r'proof length\s*(\d+)\.', output)
        if m:
            result["proof_size_kb"] = int(m.group(1)) / 1024

    return result


# ============== Result Management ==============

def save_result(result: BenchResult, batch_id: Optional[str] = None):
    # Auto-fill machine types for distributed runs
    if result.machine_types is None and result.num_parties >= 1:
        result.machine_types = get_machine_types(result.num_parties)

    if result.num_parties > 1:
        result_dir = RESULTS_DIR / f"distributed_n{result.num_parties}"
    else:
        result_dir = RESULTS_DIR / "single_thread"

    result_dir.mkdir(parents=True, exist_ok=True)

    if batch_id:
        result_file = result_dir / f"batch_{batch_id}.jsonl"
    else:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        result_file = result_dir / f"{result.scheme}_mu{result.mu}_{timestamp}.json"

    with open(result_file, 'a') as f:
        f.write(json.dumps(asdict(result)) + "\n")
    return result_file


def load_all_results(distributed: bool = False, num_parties: Optional[int] = None) -> list[BenchResult]:
    """Load all results from results directory"""
    results = []
    single_vm_cache: Optional[dict[str, str]] = None

    if distributed and num_parties:
        search_dirs = [RESULTS_DIR / f"distributed_n{num_parties}"]
    elif distributed:
        # Load all distributed results
        search_dirs = list(RESULTS_DIR.glob("distributed_n*"))
    else:
        search_dirs = [RESULTS_DIR / "single_thread"]

    for result_dir in search_dirs:
        if not result_dir.exists():
            continue
        for f in result_dir.glob("*.json*"):
            with open(f) as fp:
                for line in fp:
                    line = line.strip()
                    if line:
                        try:
                            data = json.loads(line)
                            r = BenchResult(**data)
                            # Backfill missing metrics from raw_output if available
                            if r.raw_output and (
                                r.proof_size_kb is None
                                or r.iter_commit_times is None
                                or r.iter_open_times is None
                                or r.iter_verify_times is None
                            ):
                                parsed = parse_benchmark_output(r.raw_output)
                                if r.proof_size_kb is None:
                                    r.proof_size_kb = parsed.get("proof_size_kb")
                                if r.iter_commit_times is None:
                                    r.iter_commit_times = parsed.get("iter_commit_times")
                                if r.iter_open_times is None:
                                    r.iter_open_times = parsed.get("iter_open_times")
                                if r.iter_verify_times is None:
                                    r.iter_verify_times = parsed.get("iter_verify_times")
                            if r.num_parties == 1 and r.machine_types is None:
                                if single_vm_cache is None:
                                    single_vm_cache = get_machine_types(1) or {"node-1": "unknown"}
                                r.machine_types = single_vm_cache
                            results.append(r)
                        except (json.JSONDecodeError, TypeError):
                            pass
    return results


def format_vm(machine_types: Optional[dict[str, str]], show_all: bool = False) -> str:
    """Format machine type info. Default shows master only."""
    if not machine_types:
        return "-"
    if show_all:
        # Group by type and show counts
        from collections import Counter
        counts = Counter(machine_types.values())
        return ", ".join(f"{v}x{c}" for v, c in sorted(counts.items()))
    # Master only
    return machine_types.get("node-1", "-")


def print_summary_table(results: list[BenchResult], show_vm: bool = False):
    """Print summary table of results, grouped by (scheme, mu, num_parties)"""
    is_distributed = any(r.num_parties > 1 for r in results)
    has_vm = any(r.machine_types for r in results)

    if is_distributed:
        header = f"{'Scheme':<14} {'mu':>4} {'n':>3} {'i':>2}"
        if has_vm:
            header += f" {'VM':<14}" if not show_vm else f" {'VM':<30}"
        header += f" | {'Commit':>10} {'Open':>10} {'Prover':>10} | {'Verify':>10} {'Proof':>10} {'Comm':>10} {'CV':>6} | {'Time':>16}"
    else:
        header = f"{'Scheme':<14} {'mu':>4} {'i':>2} | {'Commit':>10} {'Open':>10} {'Prover':>10} | {'Verify':>10} {'Proof':>10} {'CV':>6} | {'Time':>16}"
    print(header)
    print("-" * len(header))

    # Sort by (scheme, num_parties, mu) for better grouping
    sorted_results = sorted(results, key=result_sort_key)

    for r in sorted_results:
        display_name = ALL_SCHEMES.get(r.scheme, {}).get("display_name", r.scheme)
        # Apply color to scheme name (pad first, then color to preserve alignment)
        colored_name = colored_scheme(r.scheme, f"{display_name:<14}")
        # Get iteration count from available per-iteration data
        iters = len(r.iter_commit_times or r.iter_prove_times or r.iter_verify_times or []) or r.iteration or 1
        # Format timestamp: YYYY-MM-DD HH:MM
        ts = r.timestamp[:16].replace('T', ' ') if r.timestamp else "-"
        if is_distributed:
            line = f"{colored_name} {r.mu:>4} {r.num_parties:>3} {iters:>2}"
            if has_vm:
                vm_str = format_vm(r.machine_types, show_vm)
                width = 30 if show_vm else 14
                line += f" {vm_str:<{width}}"
            cv = calc_result_cv(r)
            line += (f" | {format_time(avg_time_ms(r, 'commit')):>10} "
                     f"{format_time(avg_time_ms(r, 'open')):>10} "
                     f"{format_time(avg_time_ms(r, 'prover')):>10} | "
                     f"{format_time(avg_time_ms(r, 'verify')):>10} "
                     f"{format_proof_size(r.proof_size_kb):>10} "
                     f"{format_bytes(r.communication_bytes):>10} "
                     f"{format_cv(cv):>6} | {ts:>16}")
            print(line)
        else:
            cv = calc_result_cv(r)
            print(f"{colored_name} {r.mu:>4} {iters:>2} | "
                  f"{format_time(avg_time_ms(r, 'commit')):>10} "
                  f"{format_time(avg_time_ms(r, 'open')):>10} "
                  f"{format_time(avg_time_ms(r, 'prover')):>10} | "
                  f"{format_time(avg_time_ms(r, 'verify')):>10} "
                  f"{format_proof_size(r.proof_size_kb):>10} "
                  f"{format_cv(cv):>6} | {ts:>16}")


def export_csv(results: list[BenchResult], filename: str):
    """Export results to CSV file"""
    import csv
    is_distributed = any(r.num_parties > 1 for r in results)
    has_vm = any(r.machine_types for r in results)

    with open(filename, 'w', newline='') as f:
        writer = csv.writer(f)
        # Header - match report output columns
        header = ["Scheme", "mu"]
        if is_distributed:
            header.extend(["Parties", "Iterations"])
            if has_vm:
                header.append("VM")
        else:
            header.append("Iterations")
        header.extend([
            "Commit (ms)", "Open (ms)", "Prover (ms)",
            "Verify (ms)", "Proof Size (KB)", "Comm (bytes)", "CV (%)", "Timestamp"
        ])
        writer.writerow(header)

        for r in results:
            display_name = ALL_SCHEMES.get(r.scheme, {}).get("display_name", r.scheme)
            iters = len(r.iter_commit_times or r.iter_prove_times or r.iter_verify_times or []) or r.iteration or 1
            cv = calc_result_cv(r)
            cv_str = f"{cv * 100:.1f}" if cv is not None else ""

            row = [display_name, r.mu]
            if is_distributed:
                row.extend([r.num_parties, iters])
                if has_vm:
                    row.append(format_vm(r.machine_types, False))
            else:
                row.append(iters)
            row.extend([
                f"{avg_time_ms(r, 'commit'):.2f}" if avg_time_ms(r, 'commit') else "",
                f"{avg_time_ms(r, 'open'):.2f}" if avg_time_ms(r, 'open') else "",
                f"{avg_time_ms(r, 'prover'):.2f}" if avg_time_ms(r, 'prover') else "",
                f"{avg_time_ms(r, 'verify'):.2f}" if avg_time_ms(r, 'verify') else "",
                f"{r.proof_size_kb:.2f}" if r.proof_size_kb else "",
                r.communication_bytes if r.communication_bytes else "",
                cv_str,
                r.timestamp[:16].replace('T', ' ') if r.timestamp else "",
            ])
            writer.writerow(row)


def format_time(ms: Optional[float]) -> str:
    if ms is None:
        return "-"
    if ms >= 1000:
        return f"{ms/1000:.2f}s"
    return f"{ms:.1f}ms"


def format_bytes(b: Optional[int]) -> str:
    if b is None:
        return "-"
    if b >= 1024 * 1024:
        return f"{b / (1024 * 1024):.2f}MB"
    if b >= 1024:
        return f"{b / 1024:.2f}KB"
    return f"{b}B"


def format_proof_size(kb: Optional[float]) -> str:
    if kb is None:
        return "-"
    if kb >= 1024:
        return f"{kb / 1024:.2f}MB"
    return f"{kb:.2f}KB"


def calc_cv(values: Optional[list[float]]) -> Optional[float]:
    """Calculate coefficient of variation (CV = std / mean)"""
    if not values or len(values) < 2:
        return None
    import statistics
    mean = statistics.mean(values)
    if mean == 0:
        return None
    std = statistics.stdev(values)
    return std / mean


def calc_result_cv(r: 'BenchResult') -> Optional[float]:
    """Calculate overall CV for a benchmark result based on prover times"""
    # Prefer prover times (commit + open combined)
    if r.iter_prove_times:
        return calc_cv(r.iter_prove_times)
    # Otherwise combine commit and open times
    if r.iter_commit_times and r.iter_open_times:
        combined = [c + o for c, o in zip(r.iter_commit_times, r.iter_open_times)]
        return calc_cv(combined)
    # Fall back to individual times
    if r.iter_commit_times:
        return calc_cv(r.iter_commit_times)
    if r.iter_open_times:
        return calc_cv(r.iter_open_times)
    return None


def format_cv(cv: Optional[float], sample_size: int = 0) -> str:
    """Format CV as reliability indicator: CV<10% good, 10-30% medium, >30% bad
    Also marks insufficient sample size (< 5) with '?'"""
    if cv is None:
        return "-"
    pct = cv * 100
    # Sample size indicator: ? means insufficient samples
    if sample_size > 0 and sample_size < 5:
        suffix = "?"
    elif pct < 10:
        suffix = ""
    elif pct < 30:
        suffix = "~"
    else:
        suffix = "!"
    return f"{pct:>4.0f}%{suffix}"


def _mean(values: Optional[list[float]]) -> Optional[float]:
    if not values:
        return None
    return sum(values) / len(values)


def avg_time_ms(r: 'BenchResult', kind: str) -> Optional[float]:
    """Return average time in ms for commit/open/verify/prover."""
    if kind == "commit":
        if r.iter_commit_times:
            return _mean(r.iter_commit_times)
        if r.commit_time_ms is not None and r.iteration and r.iteration > 1:
            return r.commit_time_ms / r.iteration
        return r.commit_time_ms
    if kind == "open":
        if r.iter_open_times:
            return _mean(r.iter_open_times)
        if r.open_time_ms is not None and r.iteration and r.iteration > 1:
            return r.open_time_ms / r.iteration
        return r.open_time_ms
    if kind == "verify":
        if r.iter_verify_times:
            return _mean(r.iter_verify_times)
        if r.verify_time_ms is not None and r.iteration and r.iteration > 1:
            return r.verify_time_ms / r.iteration
        return r.verify_time_ms
    if kind == "prover":
        if r.iter_prove_times:
            return _mean(r.iter_prove_times)
        if r.iter_commit_times and r.iter_open_times:
            combined = [c + o for c, o in zip(r.iter_commit_times, r.iter_open_times)]
            return _mean(combined)
        if r.prover_time_ms is not None and r.iteration and r.iteration > 1:
            return r.prover_time_ms / r.iteration
        return r.prover_time_ms
    return None


# ============== Command Handlers ==============

def cmd_run(args):
    global _interrupted
    _interrupted = False

    scheme = args.scheme.lower()
    mu = args.mu
    iterations = args.iterations
    build = getattr(args, 'build', False)
    sync = getattr(args, 'sync', False)

    if scheme not in ALL_SCHEMES:
        print(f"Unknown scheme: {scheme}")
        print(f"Available schemes: {', '.join(ALL_SCHEMES.keys())}")
        return 1

    is_distributed = scheme in DISTRIBUTED_SCHEMES
    is_external = scheme in EXTERNAL_SCHEMES
    display_name = ALL_SCHEMES[scheme]['display_name']

    print(f"\n{'='*60}")
    if is_distributed or is_external:
        print(f"Running: {display_name}, mu={mu}, nodes={NUM_PARTY}, iter={iterations}")
    else:
        print(f"Running: {display_name}, mu={mu}")
    print(f"{'='*60}\n")

    try:
        if sync and not (is_distributed or is_external):
            ret = sync_main_project()
            if ret != 0:
                return 1
        if is_external:
            result = run_external_benchmark(scheme, mu, iterations, build=build, sync=sync)
        elif is_distributed:
            result = run_distributed_benchmark(scheme, mu, iterations, build=build, sync=sync)
        else:
            result = run_single_thread_benchmark(scheme, mu, iterations)
    except KeyboardInterrupt:
        print("\n\n[Interrupted] Benchmark cancelled by user")
        result = BenchResult(
            scheme=scheme, mu=mu, iteration=iterations,
            timestamp=datetime.now().isoformat(),
            success=False, num_parties=NUM_PARTY if (is_distributed or is_external) else 1,
            error="Interrupted by user (Ctrl+C)"
        )

    if result.success:
        print(f"\nSuccess")
        if result.commit_time_ms or result.open_time_ms:
            print(f"  Setup:   {format_time(result.setup_time_ms)}")
            print(f"  Commit:  {format_time(result.commit_time_ms)}")
            print(f"  Open:    {format_time(result.open_time_ms)}")
            print(f"  Verify:  {format_time(result.verify_time_ms)}")
            print(f"  Prover:  {format_time(result.prover_time_ms)}")
        else:
            print(f"  Prover:  {format_time(result.prover_time_ms)}")
            print(f"  Verify:  {format_time(result.verify_time_ms)}")
        if result.proof_size_kb:
            print(f"  Proof:   {result.proof_size_kb:.2f} KB")
        if result.communication_bytes:
            print(f"  Comm:    {format_bytes(result.communication_bytes)}")
    else:
        print(f"\nFailed: {result.error[:300]}")

    result_file = save_result(result)
    print(f"\nResult saved to: {result_file}")
    return 0 if result.success else 1


def cmd_batch(args):
    schemes = [s.strip().lower() for s in args.schemes.split(',')] if args.schemes else DEFAULT_SINGLE_SCHEMES
    mus = [int(m.strip()) for m in args.mus.split(',')] if args.mus else DEFAULT_MUS
    iterations = args.iterations
    build = getattr(args, 'build', False)
    sync = getattr(args, 'sync', False)

    available_schemes = []
    for scheme in schemes:
        if scheme not in ALL_SCHEMES:
            print(f"Warning: Unknown scheme: {scheme}, skipping")
            continue
        if scheme in SINGLE_SCHEMES and not check_bench_exists(scheme):
            print(f"Warning: {scheme} benchmark not found, skipping")
            continue
        if scheme in EXTERNAL_SCHEMES:
            local_dir = EXTERNAL_SCHEMES[scheme]["local_dir"]
            if not local_dir.exists():
                print(f"Warning: {scheme} not found at {local_dir}, skipping")
                print(f"  Run: git submodule update --init --recursive")
                continue
        available_schemes.append(scheme)

    if not available_schemes:
        print("No available benchmarks")
        return 1

    tests = [(scheme, mu) for scheme in available_schemes for mu in mus]
    total = len(tests)

    print(f"\n{'='*60}")
    print(f"PCS Benchmark Batch")
    print(f"Schemes: {', '.join(available_schemes)}")
    print(f"mu: {', '.join(map(str, mus))}")
    print(f"Iterations: {iterations}")
    print(f"Total tests: {total}")
    print(f"{'='*60}\n")

    batch_id = datetime.now().strftime("%Y%m%d_%H%M%S")
    results = []
    interrupted = False

    # Track which schemes have been built/synced
    built_schemes = set()
    synced_schemes = set()

    # Sync once for single-thread schemes if requested
    if sync and any(s in SINGLE_SCHEMES for s, _ in tests):
        ret = sync_main_project()
        if ret != 0:
            return 1

    for i, (scheme, mu) in enumerate(tests, 1):
        display_name = ALL_SCHEMES[scheme]['display_name']
        is_distributed = scheme in DISTRIBUTED_SCHEMES
        is_external = scheme in EXTERNAL_SCHEMES

        if is_distributed or is_external:
            print(f"[{i}/{total}] {display_name} mu={mu} n={NUM_PARTY}")
        else:
            print(f"[{i}/{total}] {display_name} mu={mu}")

        try:
            if is_external:
                # Only sync/build each external scheme once
                should_sync = sync and scheme not in synced_schemes
                should_build = build and scheme not in built_schemes
                result = run_external_benchmark(scheme, mu, iterations, build=should_build, sync=should_sync)
                if should_sync:
                    synced_schemes.add(scheme)
                if should_build:
                    built_schemes.add(scheme)
            elif is_distributed:
                # Sync once for all distributed schemes (they share the same codebase)
                should_sync = sync and "distributed" not in synced_schemes
                should_build = build and scheme not in built_schemes
                result = run_distributed_benchmark(scheme, mu, iterations, build=should_build, sync=should_sync)
                if should_sync:
                    synced_schemes.add("distributed")
                if should_build:
                    built_schemes.add(scheme)
            else:
                result = run_single_thread_benchmark(scheme, mu, iterations)
        except KeyboardInterrupt:
            print("\n\n[Interrupted] Benchmark cancelled by user")
            result = BenchResult(
                scheme=scheme, mu=mu, iteration=iterations,
                timestamp=datetime.now().isoformat(),
                success=False, num_parties=NUM_PARTY if (is_distributed or is_external) else 1,
                error="Interrupted by user (Ctrl+C)"
            )
            interrupted = True

        results.append(result)
        save_result(result, batch_id)

        if result.success:
            extra = f", comm={format_bytes(result.communication_bytes)}" if result.communication_bytes else ""
            avg_commit = avg_time_ms(result, "commit")
            avg_open = avg_time_ms(result, "open")
            avg_verify = avg_time_ms(result, "verify")
            if avg_commit is not None or avg_open is not None:
                print(f"        commit={format_time(avg_commit)}, open={format_time(avg_open)}, verify={format_time(avg_verify)}{extra}\n")
            else:
                print(f"        prover={format_time(avg_time_ms(result, 'prover'))}, verify={format_time(avg_verify)}{extra}\n")
        else:
            print(f"        Error: {result.error[:80]}\n")

        if interrupted:
            print(f"\n[Interrupted] Stopping batch (completed {i}/{total} tests)")
            break

    print(f"\n{'='*60}")
    if interrupted:
        print(f"Batch interrupted! (completed {len(results)}/{total} tests)")
    else:
        print("Batch complete!")
    print(f"{'='*60}\n")

    # Print result file locations
    if results:
        saved_dirs = set()
        for r in results:
            if r.num_parties > 1:
                saved_dirs.add(RESULTS_DIR / f"distributed_n{r.num_parties}")
            else:
                saved_dirs.add(RESULTS_DIR / "single_thread")
        for d in saved_dirs:
            result_file = d / f"batch_{batch_id}.jsonl"
            print(f"Results saved to: {result_file}")

    return 0


def cmd_report(args):
    """Show/export benchmark results"""
    distributed = getattr(args, 'distributed', False)
    single_only = getattr(args, 'single', False)
    num_parties = getattr(args, 'n', None)
    show_all = getattr(args, 'all', False)
    show_detail = getattr(args, 'detail', False)
    scheme_filter = getattr(args, 'scheme', None)
    show_vm = getattr(args, 'vm', False)

    # Determine scope: default = both, -d = distributed only, -u = single only
    if distributed and not single_only:
        results = load_all_results(distributed=True, num_parties=num_parties)
    elif single_only and not distributed:
        results = load_all_results(distributed=False)
    else:
        results = load_all_results(distributed=True, num_parties=num_parties)
        results += load_all_results(distributed=False)
    if not results:
        print("No results found")
        return 1

    successful = [r for r in results if r.success]

    # Filter by scheme name (case-insensitive, partial match)
    if scheme_filter:
        tokens = [t.strip().lower() for t in scheme_filter.split(",") if t.strip()]
        if len(tokens) > 1:
            allowed = set(tokens)
            successful = [r for r in successful if r.scheme.lower() in allowed]
        else:
            sf = tokens[0] if tokens else scheme_filter.lower()
            successful = [r for r in successful if sf in r.scheme.lower()]

    if not successful:
        print("No successful test results")
        return 1

    if show_all:
        # Show all results, grouped by (scheme, mu, num_parties)
        results_list = sorted(successful, key=lambda x: (x.num_parties > 1, x.scheme, x.mu, x.num_parties, x.timestamp))
        print_all_results(results_list, show_detail, show_vm)
    else:
        # Get latest result for each (scheme, mu, num_parties) tuple
        latest = {}
        for r in sorted(successful, key=lambda x: x.timestamp):
            latest[(r.scheme, r.mu, r.num_parties)] = r

        results_list = sorted(latest.values(), key=result_sort_key)

        if show_detail:
            print_detail_results(results_list, show_vm)
        else:
            print_summary_table(results_list, show_vm)

    csv_file = getattr(args, 'csv', None)
    if csv_file:
        export_csv(results_list if not show_all else successful, csv_file)
        print(f"\nCSV exported to: {csv_file}")
    return 0


def print_all_results(results: list[BenchResult], show_detail: bool = False, show_vm: bool = False):
    """Print all historical results grouped by (scheme, mu, num_parties)"""
    from itertools import groupby

    for (scheme, mu, n), group in groupby(results, key=lambda x: (x.scheme, x.mu, x.num_parties)):
        group_list = list(group)
        display_name = ALL_SCHEMES.get(scheme, {}).get("display_name", scheme)
        colored_name = colored_scheme(scheme, display_name)

        print(f"\n{'='*60}")
        if n > 1:
            print(f"{colored_name} | mu={mu} | n={n} | {len(group_list)} runs")
        else:
            print(f"{colored_name} | mu={mu} | {len(group_list)} runs")
        print(f"{'='*60}")

        for i, r in enumerate(group_list, 1):
            ts = r.timestamp[:19].replace('T', ' ')  # Format timestamp
            iters = len(r.iter_commit_times or r.iter_prove_times or r.iter_verify_times or []) or r.iteration or 1
            vm_info = f" | VM: {format_vm(r.machine_types, show_vm)}" if r.machine_types else ""
            print(f"\n[{i}] {ts} ({iters} iters){vm_info}")
            if r.iter_prove_times and not r.iter_commit_times:
                # Sumcheck-style: show prover + verify
                print(f"    Prover: {format_time(r.prover_time_ms):>10}  Verify: {format_time(r.verify_time_ms):>10}")
            else:
                print(f"    Commit: {format_time(r.commit_time_ms):>10}  Open: {format_time(r.open_time_ms):>10}  "
                      f"Verify: {format_time(r.verify_time_ms):>10}")
            if r.communication_bytes:
                print(f"    Comm: {format_bytes(r.communication_bytes)}")
            if r.proof_size_kb:
                print(f"    Proof: {r.proof_size_kb:.2f} KB")

            if show_detail and (r.iter_commit_times or r.iter_prove_times):
                print(f"    Per-iteration times (ms):")
                if r.iter_prove_times and not r.iter_commit_times:
                    print(f"      {'Iter':<6} {'Prove':>12} {'Verify':>12}")
                    print(f"      {'-'*6} {'-'*12} {'-'*12}")
                    for j in range(len(r.iter_prove_times)):
                        p = r.iter_prove_times[j] if j < len(r.iter_prove_times) else None
                        v = r.iter_verify_times[j] if r.iter_verify_times and j < len(r.iter_verify_times) else None
                        print(f"      {j+1:<6} {p:>12.2f} {v:>12.2f}" if p is not None and v is not None else f"      {j+1:<6} -")
                else:
                    print(f"      {'Iter':<6} {'Commit':>12} {'Open':>12} {'Verify':>12}")
                    print(f"      {'-'*6} {'-'*12} {'-'*12} {'-'*12}")
                    for j in range(len(r.iter_commit_times)):
                        c = r.iter_commit_times[j] if r.iter_commit_times else None
                        o = r.iter_open_times[j] if r.iter_open_times and j < len(r.iter_open_times) else None
                        v = r.iter_verify_times[j] if r.iter_verify_times and j < len(r.iter_verify_times) else None
                        print(f"      {j+1:<6} {c:>12.2f} {o:>12.2f} {v:>12.2f}" if c and o and v else f"      {j+1:<6} -")


def print_detail_results(results: list[BenchResult], show_vm: bool = False):
    """Print results with per-iteration details"""
    for r in results:
        display_name = ALL_SCHEMES.get(r.scheme, {}).get("display_name", r.scheme)
        colored_name = colored_scheme(r.scheme, display_name)
        iters = len(r.iter_commit_times or r.iter_prove_times or r.iter_verify_times or []) or r.iteration or 1
        # Format timestamp
        ts = r.timestamp[:19].replace('T', ' ') if r.timestamp else "-"

        print(f"\n{'='*60}")
        vm_info = f" | VM: {format_vm(r.machine_types, show_vm)}" if r.machine_types else ""
        if r.num_parties > 1:
            print(f"{colored_name} | mu={r.mu} | n={r.num_parties} | {iters} iterations{vm_info}")
        else:
            print(f"{colored_name} | mu={r.mu} | {iters} iterations")
        print(f"Test time: {ts}")
        print(f"{'='*60}")

        print(f"Average:")
        if r.iter_prove_times and not r.iter_commit_times:
            # Sumcheck-style
            print(f"  Prover: {format_time(r.prover_time_ms):>10}  Verify: {format_time(r.verify_time_ms):>10}")
        else:
            print(f"  Commit: {format_time(r.commit_time_ms):>10}  Open: {format_time(r.open_time_ms):>10}  "
                  f"Verify: {format_time(r.verify_time_ms):>10}")
        if r.communication_bytes:
            print(f"  Comm: {format_bytes(r.communication_bytes)}")
        if r.proof_size_kb:
            print(f"  Proof: {r.proof_size_kb:.2f} KB")

        if r.iter_prove_times and not r.iter_commit_times:
            # Sumcheck-style per-iteration
            print(f"\nPer-iteration times (ms):")
            print(f"  {'Iter':<6} {'Prove':>12} {'Verify':>12}")
            print(f"  {'-'*6} {'-'*12} {'-'*12}")
            for j in range(len(r.iter_prove_times)):
                p = r.iter_prove_times[j] if j < len(r.iter_prove_times) else None
                v = r.iter_verify_times[j] if r.iter_verify_times and j < len(r.iter_verify_times) else None
                if p is not None and v is not None:
                    print(f"  {j+1:<6} {p:>12.2f} {v:>12.2f}")
                else:
                    print(f"  {j+1:<6} {'-':>12} {'-':>12}")

            if len(r.iter_prove_times) > 1:
                import statistics
                print(f"\nStatistics:")
                for name, times in [("Prove", r.iter_prove_times),
                                   ("Verify", r.iter_verify_times)]:
                    if times and len(times) > 1:
                        avg = statistics.mean(times)
                        std = statistics.stdev(times)
                        print(f"  {name:<8} avg={avg:>10.2f}ms  std={std:>8.2f}ms  ({std/avg*100:>5.1f}%)")

        elif r.iter_commit_times:
            print(f"\nPer-iteration times (ms):")
            print(f"  {'Iter':<6} {'Commit':>12} {'Open':>12} {'Verify':>12}")
            print(f"  {'-'*6} {'-'*12} {'-'*12} {'-'*12}")
            for j in range(len(r.iter_commit_times)):
                c = r.iter_commit_times[j] if r.iter_commit_times else None
                o = r.iter_open_times[j] if r.iter_open_times and j < len(r.iter_open_times) else None
                v = r.iter_verify_times[j] if r.iter_verify_times and j < len(r.iter_verify_times) else None
                if c is not None and o is not None and v is not None:
                    print(f"  {j+1:<6} {c:>12.2f} {o:>12.2f} {v:>12.2f}")
                else:
                    print(f"  {j+1:<6} {'-':>12} {'-':>12} {'-':>12}")

            # Statistics
            if len(r.iter_commit_times) > 1:
                import statistics
                print(f"\nStatistics:")
                for name, times in [("Commit", r.iter_commit_times),
                                   ("Open", r.iter_open_times),
                                   ("Verify", r.iter_verify_times)]:
                    if times and len(times) > 1:
                        avg = statistics.mean(times)
                        std = statistics.stdev(times)
                        print(f"  {name:<8} avg={avg:>10.2f}ms  std={std:>8.2f}ms  ({std/avg*100:>5.1f}%)")


def cmd_list(_args=None):
    print("\nAvailable Benchmarks:")
    print("-" * 50)
    print("\nSingle-thread:")
    for scheme, config in SINGLE_SCHEMES.items():
        exists = "+" if check_bench_exists(scheme) else "-"
        print(f"  {exists} {config['display_name']:<20} ({scheme})")

    print("\nDistributed (internal):")
    for scheme, config in DISTRIBUTED_SCHEMES.items():
        print(f"  + {config['display_name']:<20} ({scheme})")

    print("\nDistributed (external):")
    for scheme, config in EXTERNAL_SCHEMES.items():
        exists = "+" if config["local_dir"].exists() else "-"
        print(f"  {exists} {config['display_name']:<20} ({scheme})")
    print()
    return 0


def cmd_set_vm(args):
    """Resize server machine type"""
    node_range = args.range
    config = args.config.lower()

    # Parse node range
    match = re.match(r"(\d+)-(\d+)", node_range)
    if not match:
        print(f"Error: Invalid node range '{node_range}', format: start-end (e.g., 1-4)")
        return 1

    start, end = int(match.group(1)), int(match.group(2))
    if start > end or start < 1 or end > 16:
        print(f"Error: Invalid range {start}-{end} (must be within 1-16)")
        return 1

    if config not in MACHINE_CONFIGS:
        print(f"Error: Unknown config '{config}'")
        print(f"Available: {', '.join(MACHINE_CONFIGS.keys())}")
        return 1

    machine_type, desc = MACHINE_CONFIGS[config]
    nodes = [f"node-{i}" for i in range(start, end + 1)]

    # Check if any target nodes are running
    running = get_running_servers()
    running_targets = [n for n in nodes if n in running]
    if running_targets:
        print(f"Error: The following servers are still running:")
        for n in running_targets:
            print(f"  - {n}")
        print(f"\nPlease stop them first with: stop {start}-{end}")
        return 1

    print(f"Setting node-{start} to node-{end} to {config} ({desc})")
    print(f"Machine type: {machine_type}")
    print()

    # Change machine type
    print(f"Changing machine type...")
    for node in nodes:
        result = subprocess.run(
            f"gcloud compute instances set-machine-type {node} --zone={ZONE} --machine-type={machine_type}",
            shell=True, capture_output=True, text=True
        )
        if result.returncode != 0:
            print(f"Error: {result.stderr}")
            return 1
        print(f"  {node} -> {machine_type}")
    print("Done")

    print(f"\nTo start servers: start {start}-{end}")
    return 0


def cmd_clean(args):
    """Remove failed benchmark results"""
    dry_run = getattr(args, 'dry_run', False)

    total_removed = 0
    total_kept = 0
    files_modified = 0
    files_deleted = 0

    if not RESULTS_DIR.exists():
        print("No bench_results directory found")
        return 0

    for result_dir in sorted(RESULTS_DIR.iterdir()):
        if not result_dir.is_dir():
            continue

        for f in sorted(result_dir.glob("*.json*")):
            lines = []
            kept = []
            removed = []

            with open(f) as fp:
                for line in fp:
                    line = line.strip()
                    if not line:
                        continue
                    lines.append(line)
                    try:
                        data = json.loads(line)
                        if data.get("success", False):
                            kept.append(line)
                        else:
                            removed.append(data)
                    except (json.JSONDecodeError, TypeError):
                        removed.append({"error": "parse error"})

            if not removed and not kept:
                # Empty file, delete it
                if not dry_run:
                    f.unlink()
                    files_deleted += 1
                else:
                    print(f"  [DRY] Delete empty: {f.parent.name}/{f.name}")
                continue
            if not removed:
                total_kept += len(kept)
                continue

            # Show what will be removed
            for r in removed:
                scheme = r.get("scheme", "?")
                mu = r.get("mu", "?")
                err = r.get("error", "unknown")[:80]
                print(f"  {'[DRY] ' if dry_run else ''}Remove: {f.parent.name}/{f.name}  {scheme} mu={mu}  ({err})")

            total_removed += len(removed)
            total_kept += len(kept)

            if dry_run:
                continue

            if not kept:
                # All entries failed, delete the file
                f.unlink()
                files_deleted += 1
            else:
                # Rewrite file with only successful entries
                with open(f, 'w') as fp:
                    for line in kept:
                        fp.write(line + "\n")
                files_modified += 1

    print(f"\n{'[DRY RUN] ' if dry_run else ''}Results: {total_removed} failed removed, {total_kept} successful kept")
    if not dry_run:
        if files_deleted:
            print(f"  Files deleted:  {files_deleted}")
        if files_modified:
            print(f"  Files modified: {files_modified}")
    return 0


def cmd_help(_args=None):
    global NUM_PARTY
    print(f"""
Current config: num_party = {NUM_PARTY}

Commands:
  status              Show server status
  set-n <n>           Set num_party (must be power of 2)
  start               Start required servers (node-1 to node-{NUM_PARTY})
  stop                Stop all servers
  sync                Sync code to servers
  list                List available benchmarks

  run -s <scheme> -m <mu> [-i <iterations>] [--build] [--sync]
                      Run benchmark
                      Example: run -s ligesis -m 24            # single-thread
                      Example: run -s dligesis -m 28 --build   # distributed
                      Example: run -s dpip-fri-pcs -m 27 --sync --build  # external PCS

  batch [-s <schemes>] [-m <mus>] [-i <iterations>] [--build] [--sync]
                      Run batch benchmarks
                      Example: batch -s ligesis,deepfold -m 24,26,28
                      Example: batch -s dligesis -m 27,28 -i 5 --build
                      Example: batch -s dpip-fri-pcs,dmkzg-pcs -m 24 --sync --build

  External PCS: dpip-fri-pcs, dmkzg-pcs, ddory-pcs
  External SNARK: dhyperpianist
    --sync            Sync external code to servers before running
    --build           Build on remote servers before running

  report [-d|-u] [-s <scheme>] [-n <parties>] [-a] [--detail] [--vm] [--csv <file>]
                      Show/export results
                      -d, --distributed   Show distributed results only
                      -u, --single        Show single-thread results only
                      -s, --scheme <name> Filter by scheme (e.g., dligesis or ligesis,dligesis)
                      -n <parties>        Filter by num_parties
                      -a, --all           Show all historical results (not just latest)
                      --detail            Show per-iteration times with statistics
                      --vm                Show all node machine types (default: master only)
                      --csv <file>        Export to CSV file

  set-vm <i-j> <config>
                      Resize servers node-i to node-j
                      Configs: 8g (2C/8G), 16g (2C/16G), 32g (4C/32G), 64g (8C/64G)
                      Example: set-vm 1-4 32g   # set node-1~4 to 4C/32G
                      Example: set-vm 5-16 16g  # set node-5~16 to 2C/16G

  clean [--dry-run]   Remove failed benchmark results from bench_results/
                      --dry-run   Preview what would be removed without deleting

  help                Show this help
  exit, quit, q       Exit
""")
    return 0


# ============== Interactive Mode ==============

def create_parser():
    parser = argparse.ArgumentParser(prog="", add_help=False)
    subparsers = parser.add_subparsers(dest="command")

    subparsers.add_parser("status")
    subparsers.add_parser("start")
    subparsers.add_parser("stop")
    subparsers.add_parser("sync")
    subparsers.add_parser("list")
    subparsers.add_parser("help")

    p = subparsers.add_parser("set-n")
    p.add_argument("n", type=int, help="Number of parties")

    p = subparsers.add_parser("run")
    p.add_argument("--scheme", "-s", type=str, required=True)
    p.add_argument("--mu", "-m", type=int, default=24)
    p.add_argument("--iterations", "-i", type=int, default=1)
    p.add_argument("--build", "-b", action="store_true", help="Build on remote before running")
    p.add_argument("--sync", action="store_true", help="Sync external scheme code before running")

    p = subparsers.add_parser("batch")
    p.add_argument("--schemes", "-s", type=str, default=None)
    p.add_argument("--mus", "-m", type=str, default=None)
    p.add_argument("--iterations", "-i", type=int, default=DEFAULT_ITERATIONS)
    p.add_argument("--build", "-b", action="store_true", help="Build on remote before running")
    p.add_argument("--sync", action="store_true", help="Sync external scheme code before running")

    p = subparsers.add_parser("report")
    p.add_argument("--csv", type=str, default=None, help="Export to CSV file")
    p.add_argument("--distributed", "-d", action="store_true", help="Show distributed results")
    p.add_argument("--single", "-u", action="store_true", help="Show single-thread results")
    p.add_argument("--scheme", "-s", type=str, default=None, help="Filter by scheme name")
    p.add_argument("-n", type=int, default=None, help="Filter by num_parties")
    p.add_argument("--all", "-a", action="store_true", help="Show all historical results")
    p.add_argument("--detail", action="store_true", help="Show per-iteration times")
    p.add_argument("--vm", action="store_true", help="Show all node machine types")

    p = subparsers.add_parser("set-vm")
    p.add_argument("range", type=str, help="Node range (e.g., 1-4)")
    p.add_argument("config", type=str, help="Config: 8g, 16g, 32g, 64g")

    p = subparsers.add_parser("clean")
    p.add_argument("--dry-run", action="store_true", help="Show what would be removed without deleting")

    return parser


def interactive_mode():
    # Load cached config and history
    load_config_cache()
    load_history()

    print("=" * 60)
    print("PCS Benchmark - Interactive Mode")
    print("=" * 60)

    # Auto-detect running servers
    auto_detect_num_party()

    print("Type 'help' for commands, 'exit' to quit")

    parser = create_parser()
    cmd_map = {
        "status": cmd_status,
        "set-n": cmd_set_n,
        "start": cmd_start,
        "stop": cmd_stop,
        "sync": cmd_sync,
        "list": cmd_list,
        "help": cmd_help,
        "run": cmd_run,
        "batch": cmd_batch,
        "report": cmd_report,
        "set-vm": cmd_set_vm,
        "clean": cmd_clean,
    }

    while True:
        try:
            print(flush=True)  # newline before prompt, flush to fix readline display
            line = input("> ").strip()
        except EOFError:
            save_history()
            print("\nExit")
            break
        except KeyboardInterrupt:
            # Ctrl+C at prompt: just print newline and continue
            print("")
            continue

        if not line:
            continue

        if line.lower() in ("exit", "quit", "q"):
            save_history()
            print("Exit")
            break

        try:
            argv = shlex.split(line)
            args = parser.parse_args(argv)

            if args.command in cmd_map:
                cmd_map[args.command](args)
            else:
                print(f"Unknown command: {line}")
                cmd_help()

        except SystemExit:
            pass
        except KeyboardInterrupt:
            # Ctrl+C during command execution: already handled by the command
            print("\n[Returned to prompt]")
        except Exception as e:
            print(f"Error: {e}")


# ============== Main ==============

def main():
    global NUM_PARTY

    # Load cached config first
    load_config_cache()

    if len(sys.argv) == 1:
        interactive_mode()
        return 0

    # Auto-detect running servers for non-interactive mode
    auto_detect_num_party()

    parser = argparse.ArgumentParser(
        description="PCS Benchmark (Remote Server)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s                                         # Interactive mode
  %(prog)s status                                  # Show server status
  %(prog)s set-n 4                                 # Set num_party=4
  %(prog)s start                                   # Start servers
  %(prog)s sync                                    # Sync code
  %(prog)s run -s ligesis -m 24                    # Single-thread test
  %(prog)s run -s dligesis -m 28 --build           # Distributed test
        """
    )

    subparsers = parser.add_subparsers(dest="command", help="Commands")

    subparsers.add_parser("status", help="Show server status").set_defaults(func=cmd_status)
    subparsers.add_parser("start", help="Start servers").set_defaults(func=cmd_start)
    subparsers.add_parser("stop", help="Stop servers").set_defaults(func=cmd_stop)
    subparsers.add_parser("sync", help="Sync code to servers").set_defaults(func=cmd_sync)
    subparsers.add_parser("list", help="List available benchmarks").set_defaults(func=cmd_list)

    p = subparsers.add_parser("set-n", help="Set num_party")
    p.add_argument("n", type=int, help="Number of parties (must be power of 2)")
    p.set_defaults(func=cmd_set_n)

    p = subparsers.add_parser("set-vm", help="Resize server machine type")
    p.add_argument("range", type=str, help="Node range (e.g., 1-4)")
    p.add_argument("config", type=str, help="Machine config (8g, 16g, 32g)")
    p.set_defaults(func=cmd_set_vm)

    p = subparsers.add_parser("run", help="Run benchmark")
    p.add_argument("--scheme", "-s", type=str, required=True)
    p.add_argument("--mu", "-m", type=int, default=24)
    p.add_argument("--iterations", "-i", type=int, default=1)
    p.add_argument("--build", "-b", action="store_true", help="Build on remote before running")
    p.add_argument("--sync", action="store_true", help="Sync external scheme code before running")
    p.set_defaults(func=cmd_run)

    p = subparsers.add_parser("batch", help="Run batch benchmarks")
    p.add_argument("--schemes", "-s", type=str, default=None,
                   help=f"Comma-separated schemes (default: {','.join(DEFAULT_SINGLE_SCHEMES)})")
    p.add_argument("--mus", "-m", type=str, default=None,
                   help=f"Comma-separated mus (default: {','.join(map(str, DEFAULT_MUS))})")
    p.add_argument("--iterations", "-i", type=int, default=DEFAULT_ITERATIONS)
    p.add_argument("--build", "-b", action="store_true", help="Build on remote before running")
    p.add_argument("--sync", action="store_true", help="Sync external scheme code before running")
    p.set_defaults(func=cmd_batch)

    p = subparsers.add_parser("report", help="Show/export results")
    p.add_argument("--csv", type=str, default=None, help="Export to CSV file")
    p.add_argument("--distributed", "-d", action="store_true", help="Show distributed results")
    p.add_argument("--single", "-u", action="store_true", help="Show single-thread results")
    p.add_argument("--scheme", "-s", type=str, default=None, help="Filter by scheme name")
    p.add_argument("-n", type=int, default=None, help="Filter by num_parties")
    p.add_argument("--all", "-a", action="store_true", help="Show all historical results")
    p.add_argument("--detail", action="store_true", help="Show per-iteration times")
    p.add_argument("--vm", action="store_true", help="Show all node machine types")
    p.set_defaults(func=cmd_report)

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        return 1

    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())

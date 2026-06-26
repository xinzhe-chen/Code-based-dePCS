#!/usr/bin/env python3
"""
Distributed testing runner for ligesis-pcs using gcloud.

This script is similar to run.py but uses gcloud compute ssh/scp instead of direct SSH.
Designed for GCP VMs without public IPs.

Local mode:
    python3 run_gcloud.py dLigesis              # Run with default 4 parties locally
    python3 run_gcloud.py dLigesis -n 8         # Run with 8 parties locally

Remote mode (gcloud):
    python3 run_gcloud.py dLigesis --servers servers_gcloud.json --sync --build -m 24
    python3 run_gcloud.py dLigesis --servers servers_gcloud.json -m 24
    python3 run_gcloud.py dLigesis --servers servers_gcloud.json -m 24 --trace

servers_gcloud.json format:
    {
        "servers": [
            {"name": "node-1", "host": "10.128.0.48"},
            {"name": "node-2", "host": "10.128.0.49"},
            ...
            {"name": "node-16", "host": "10.128.0.63"}
        ],
        "zone": "us-central1-a",
        "project": "your-gcp-project",
        "user": "ubuntu",
        "remote_dir": "~/ligesis-pcs",
        "network_port": 18000
    }

    - name: GCP instance name (for gcloud ssh)
    - host: Internal IP for inter-node communication
    - zone: GCP zone (optional, uses default if not specified)
    - project: GCP project (optional, uses default if not specified)
    - user: SSH username
    - remote_dir: Code location on remote servers
    - network_port: Port for distributed protocol
"""

import argparse
import json
import os
import subprocess
import sys
import tempfile
import threading
from pathlib import Path
from typing import Optional
import math


def compute_optimal_base_mu(mu: int, num_parties: int) -> int:
    """Compute optimal base_mu for distributed LigeSIS."""
    log_parties = int(math.log2(num_parties))
    local_num_vars = mu - log_parties
    OPTIMAL_BASE_MU = 14
    return min(OPTIMAL_BASE_MU, local_num_vars)


def generate_config(hosts: list[str], base_port: int = 18000, use_different_ports: bool = True) -> str:
    """Generate network configuration."""
    if use_different_ports:
        lines = [f"{host}:{base_port + i}" for i, host in enumerate(hosts)]
    else:
        lines = [f"{host}:{base_port}" for host in hosts]
    return "\n".join(lines)


def build_example(example_name: str, release: bool = True, trace: bool = False) -> Path:
    """Build the example binary locally and return its path."""
    script_dir = Path(__file__).resolve().parent
    project_dir = script_dir.parent

    cmd = ["cargo", "build", "--example", example_name]
    if release:
        cmd.append("--release")
    if trace:
        cmd.extend(["--features", "print-trace"])

    env = os.environ.copy()
    env["RUSTFLAGS"] = "-Awarnings"

    print(f"Building {example_name}..." + (" (with print-trace)" if trace else ""))
    result = subprocess.run(cmd, cwd=project_dir, env=env)
    if result.returncode != 0:
        print(f"Build failed with code {result.returncode}")
        sys.exit(1)

    target_dir = "release" if release else "debug"
    binary_path = project_dir.parent / "target" / target_dir / "examples" / example_name

    if not binary_path.exists():
        print(f"Binary not found: {binary_path}")
        sys.exit(1)

    return binary_path


def run_local_test(
    example_name: str,
    num_parties: int = 4,
    release: bool = True,
    base_port: int = 18000,
    mu: int = 20,
    trace: bool = False,
    base_mu: Optional[int] = None,
    log_m: Optional[int] = None,
    code_rate: Optional[int] = None,
) -> int:
    """Run the distributed test locally with the specified number of parties."""
    binary_path = build_example(example_name, release, trace)

    hosts = ["127.0.0.1"] * num_parties
    config_content = generate_config(hosts, base_port)

    actual_base_mu = base_mu if base_mu is not None else compute_optimal_base_mu(mu, num_parties)

    with tempfile.NamedTemporaryFile(mode="w", suffix=".conf", delete=False) as f:
        f.write(config_content)
        config_path = f.name

    try:
        extra_params = [f"base_mu={actual_base_mu}"]
        if base_mu is None:
            extra_params[-1] += " (auto)"
        if log_m is not None:
            extra_params.append(f"log_m={log_m}")
        if code_rate is not None:
            extra_params.append(f"code_rate=1/{code_rate}")
        extra_str = f", {', '.join(extra_params)}" if extra_params else ""
        print(f"\nRunning {example_name} locally with {num_parties} parties, mu={mu}{extra_str}...\n")

        processes = []
        for party_id in range(num_parties):
            cmd = [str(binary_path), str(party_id), config_path, "--mu", str(mu)]
            cmd.extend(["--base-mu", str(actual_base_mu)])
            if log_m is not None:
                cmd.extend(["--log-m", str(log_m)])
            if code_rate is not None:
                cmd.extend(["--code-rate", str(code_rate)])
            proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
            )
            processes.append((party_id, proc))

        outputs = {}
        exit_codes = [None] * num_parties

        def collect_output(party_id: int, proc):
            stdout, _ = proc.communicate()
            outputs[party_id] = stdout
            exit_codes[party_id] = proc.returncode

        threads = []
        for party_id, proc in processes:
            t = threading.Thread(target=collect_output, args=(party_id, proc))
            t.start()
            threads.append(t)

        for t in threads:
            t.join()

        print_outputs(outputs)

        failed = [i for i, code in enumerate(exit_codes) if code != 0]
        if failed:
            print(f"FAILED: Parties {failed} exited with non-zero codes")
            return 1
        else:
            print("All parties completed successfully")
            return 0

    except KeyboardInterrupt:
        print("\nInterrupted, terminating all processes...")
        for _, proc in processes:
            proc.terminate()
        return 130

    finally:
        os.unlink(config_path)


def build_gcloud_ssh_cmd(
    instance_name: str,
    user: str,
    zone: Optional[str] = None,
    project: Optional[str] = None,
) -> list[str]:
    """Build the base gcloud compute ssh command."""
    cmd = ["gcloud", "compute", "ssh"]
    if user:
        cmd.append(f"{user}@{instance_name}")
    else:
        cmd.append(instance_name)
    if zone:
        cmd.extend(["--zone", zone])
    if project:
        cmd.extend(["--project", project])
    # Disable PTY allocation to avoid terminal control characters in output
    cmd.extend(["--", "-T"])
    return cmd


def run_gcloud_command(
    instance_name: str,
    user: str,
    command: str,
    party_id: int,
    results: dict,
    zone: Optional[str] = None,
    project: Optional[str] = None,
    timeout: int = 600,
):
    """Run command on remote server via gcloud compute ssh."""
    ssh_cmd = build_gcloud_ssh_cmd(instance_name, user, zone, project)
    ssh_cmd.append(command)

    try:
        result = subprocess.run(
            ssh_cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        results[party_id] = {
            "stdout": result.stdout,
            "stderr": result.stderr,
            "returncode": result.returncode,
        }
    except subprocess.TimeoutExpired:
        results[party_id] = {
            "stdout": "",
            "stderr": "gcloud ssh timeout",
            "returncode": -1,
        }
    except Exception as e:
        results[party_id] = {
            "stdout": "",
            "stderr": str(e),
            "returncode": -1,
        }


def gcloud_scp(
    local_path: str,
    instance_name: str,
    remote_path: str,
    user: str,
    zone: Optional[str] = None,
    project: Optional[str] = None,
) -> subprocess.CompletedProcess:
    """Copy file to remote server via gcloud compute scp."""
    cmd = ["gcloud", "compute", "scp"]
    if zone:
        cmd.extend(["--zone", zone])
    if project:
        cmd.extend(["--project", project])

    if user:
        remote_spec = f"{user}@{instance_name}:{remote_path}"
    else:
        remote_spec = f"{instance_name}:{remote_path}"

    cmd.extend([local_path, remote_spec])

    return subprocess.run(cmd, capture_output=True, text=True, timeout=300)


def run_remote_test(
    example_name: str,
    servers_config: str,
    mu: int = 20,
    trace: bool = False,
    build_remote: bool = False,
    release: bool = True,
    sync: bool = False,
    base_mu: Optional[int] = None,
    log_m: Optional[int] = None,
    measure_memory: bool = False,
    code_rate: Optional[int] = None,
) -> int:
    """Run the distributed test on remote servers via gcloud."""

    # Load server configuration
    with open(servers_config) as f:
        config = json.load(f)

    servers = config["servers"]
    remote_dir = config.get("remote_dir", "~/ligesis-pcs")
    network_port = config.get("network_port", 18000)
    default_user = config.get("user", "")
    zone = config.get("zone")
    project = config.get("project")
    num_parties = len(servers)

    def get_user(s):
        return s.get("user", default_user)

    if num_parties < 1 or (num_parties & (num_parties - 1)) != 0:
        print(f"Error: Number of servers must be a power of 2, got {num_parties}")
        return 1

    # Compute optimal base_mu if not specified
    actual_base_mu = base_mu if base_mu is not None else compute_optimal_base_mu(mu, num_parties)
    base_mu_info = f"base_mu={actual_base_mu}" + (" (auto)" if base_mu is None else "")

    # Get server IPs/hostnames for network config
    hosts = [s["host"] for s in servers]
    config_content = generate_config(hosts, network_port, use_different_ports=False)

    print(f"Remote distributed test (gcloud): {num_parties} servers, mu={mu}, {base_mu_info}")
    print(f"Instances: {', '.join(s['name'] for s in servers)}")
    print(f"Internal IPs: {', '.join(hosts)}")
    if zone:
        print(f"Zone: {zone}")
    if project:
        print(f"Project: {project}")
    print(f"Network config:\n{config_content}\n")

    # Sync code to remote servers if requested
    if sync:
        print("Syncing code to remote servers...")
        script_dir = Path(__file__).resolve().parent
        local_dir = str(script_dir.parent.parent)  # ligesis-pcs root

        # Create tarball once
        tar_path = f"/tmp/ligesis_sync_{os.getpid()}.tar.gz"
        tar_cmd = [
            "tar", "czf", tar_path,
            "--exclude=target", "--exclude=.git", "--exclude=.claude",
            "-C", local_dir, "."
        ]
        result = subprocess.run(tar_cmd, capture_output=True, text=True)
        if result.returncode != 0:
            print(f"Failed to create tarball: {result.stderr}")
            return 1

        sync_threads = []
        sync_results = {}

        def do_sync(i, server):
            instance_name = server["name"]
            user = get_user(server)

            # Upload tarball via gcloud scp
            result = gcloud_scp(
                tar_path,
                instance_name,
                "~/ligesis_sync.tar.gz",
                user,
                zone,
                project,
            )
            if result.returncode != 0:
                sync_results[i] = (False, f"Upload failed: {result.stderr}")
                return

            # Extract on remote
            extract_results = {}
            run_gcloud_command(
                instance_name,
                user,
                f"mkdir -p {remote_dir} && cd {remote_dir} && tar xzf ~/ligesis_sync.tar.gz && rm ~/ligesis_sync.tar.gz",
                0,
                extract_results,
                zone,
                project,
                timeout=120,
            )

            if extract_results[0]["returncode"] != 0:
                sync_results[i] = (False, f"Extract failed: {extract_results[0]['stderr']}")
                return

            sync_results[i] = (True, "OK")

        for i, server in enumerate(servers):
            t = threading.Thread(target=do_sync, args=(i, server))
            t.start()
            sync_threads.append(t)

        for t in sync_threads:
            t.join()

        # Clean up local tarball
        os.unlink(tar_path)

        # Check sync results
        for i, server in enumerate(servers):
            if not sync_results[i][0]:
                print(f"Sync failed on {server['name']}: {sync_results[i][1]}")
                return 1
        print("Sync completed.\n")

    # Build on remote servers if requested
    if build_remote:
        print("Building on remote servers...")
        build_threads = []
        build_results = {}

        build_cmd = f"source ~/.cargo/env && cd {remote_dir}/ligesis-pcs && RUSTFLAGS='-Awarnings' cargo build --example {example_name}"
        if release:
            build_cmd += " --release"
        if trace:
            build_cmd += " --features print-trace"
        build_cmd += " 2>&1"

        for i, server in enumerate(servers):
            t = threading.Thread(
                target=run_gcloud_command,
                args=(server["name"], get_user(server), build_cmd, i, build_results, zone, project),
            )
            t.start()
            build_threads.append(t)

        for t in build_threads:
            t.join()

        # Check build results
        for i, server in enumerate(servers):
            if build_results[i]["returncode"] != 0:
                print(f"Build failed on {server['name']}:")
                print(build_results[i]["stderr"])
                return 1
        print("Build completed on all servers.\n")

    # Create config file on all servers
    print("Deploying network config...")
    config_threads = []
    config_results = {}
    config_cmd = f"cat > /tmp/ligesis_network.conf << 'EOF'\n{config_content}\nEOF"

    for i, server in enumerate(servers):
        t = threading.Thread(
            target=run_gcloud_command,
            args=(server["name"], get_user(server), config_cmd, i, config_results, zone, project),
        )
        t.start()
        config_threads.append(t)

    for t in config_threads:
        t.join()

    # Run the test
    print(f"Starting distributed test...\n")

    target_dir = "release" if release else "debug"
    binary_path = f"{remote_dir}/target/{target_dir}/examples/{example_name}"

    run_threads = []
    run_results = {}

    for i, server in enumerate(servers):
        base_cmd = f"{binary_path} {i} /tmp/ligesis_network.conf --mu {mu} --base-mu {actual_base_mu}"
        if log_m is not None:
            base_cmd += f" --log-m {log_m}"
        if code_rate is not None:
            base_cmd += f" --code-rate {code_rate}"
        if measure_memory:
            run_cmd = f"command -v gtime >/dev/null && gtime -v {base_cmd} 2>&1 || (command -v /usr/bin/time >/dev/null && /usr/bin/time -v {base_cmd} 2>&1) || {base_cmd} 2>&1"
        else:
            run_cmd = f"RUST_BACKTRACE=1 {base_cmd} 2>&1"
        t = threading.Thread(
            target=run_gcloud_command,
            args=(server["name"], get_user(server), run_cmd, i, run_results, zone, project),
        )
        t.start()
        run_threads.append(t)

    for t in run_threads:
        t.join()

    # Collect outputs
    outputs = {i: run_results[i]["stdout"] for i in range(num_parties)}
    print_outputs(outputs)

    # Check results
    failed = [i for i in range(num_parties) if run_results[i]["returncode"] != 0]
    if failed:
        print(f"FAILED: Parties {failed} exited with non-zero codes")
        for i in failed:
            if run_results[i]["stderr"]:
                print(f"  Party {i} stderr: {run_results[i]['stderr']}")
        return 1
    else:
        print("All parties completed successfully")
        return 0


def clean_line(line: str) -> str:
    """Clean a line by removing carriage returns and extra whitespace."""
    # Remove carriage returns (common in gcloud ssh output)
    line = line.replace('\r', '')
    # Strip trailing whitespace but preserve leading whitespace for indentation
    return line.rstrip()


def print_outputs(outputs: dict):
    """Print formatted outputs from parties."""
    BLUE = "\033[34m"
    GREEN = "\033[32m"
    YELLOW = "\033[33m"
    RESET = "\033[0m"

    def should_skip(line: str) -> bool:
        stripped = line.strip()
        if stripped.startswith("deNetwork"):
            return True
        network_keywords = ["To master", "From master", "Connecting"]
        if any(kw in stripped for kw in network_keywords):
            return True
        if stripped.startswith("COMM_"):
            return True
        return False

    # Clean outputs first - remove \r characters
    cleaned_outputs = {}
    for party_id in outputs:
        if outputs[party_id]:
            cleaned_outputs[party_id] = "\n".join(
                clean_line(line) for line in outputs[party_id].split("\n")
            )
        else:
            cleaned_outputs[party_id] = ""

    # Extract communication statistics
    comm_bytes = None
    comm_mb = None
    for party_id in cleaned_outputs:
        if cleaned_outputs[party_id]:
            for line in cleaned_outputs[party_id].strip().split("\n"):
                if line.startswith("COMM_TOTAL_BYTES:"):
                    comm_bytes = int(line.split(":")[1].strip())
                elif line.startswith("COMM_TOTAL_MB:"):
                    comm_mb = float(line.split(":")[1].strip())

    for party_id in [0, 1]:
        if party_id in cleaned_outputs and cleaned_outputs[party_id]:
            color = BLUE if party_id == 0 else GREEN
            for line in cleaned_outputs[party_id].strip().split("\n"):
                if line and not should_skip(line):
                    if line.startswith(f"[P{party_id}]"):
                        print(f"{color}{line}{RESET}")
                    else:
                        print(line)

    # Print communication summary
    if comm_bytes is not None:
        print(f"\n{YELLOW}========================================{RESET}")
        print(f"{YELLOW}Total Communication (master side):{RESET}")
        print(f"{YELLOW}  {comm_bytes:,} bytes ({comm_mb:.2f} MB){RESET}")
        print(f"{YELLOW}========================================{RESET}")

    print()


def generate_servers_config(output_path: str, num_nodes: int = 16):
    """Generate a sample servers_gcloud.json config file."""
    servers = []
    for i in range(num_nodes):
        servers.append({
            "name": f"node-{i+1}",
            "host": f"10.128.0.{48+i}",
        })

    config = {
        "servers": servers,
        "zone": "us-central1-a",
        "project": "your-gcp-project",
        "user": "ubuntu",
        "remote_dir": "~/ligesis-pcs",
        "network_port": 18000,
    }

    with open(output_path, "w") as f:
        json.dump(config, f, indent=4)

    print(f"Generated sample config: {output_path}")
    print("Please update 'zone' and 'project' fields as needed.")


def main():
    parser = argparse.ArgumentParser(
        description="Run distributed tests for ligesis-pcs using gcloud"
    )
    parser.add_argument(
        "example",
        nargs="?",
        help="Name of the example to run (e.g., dLigesis)",
    )
    parser.add_argument(
        "-n", "--num-parties",
        type=int,
        default=4,
        help="Number of parties for local mode (default: 4, must be power of 2)",
    )
    parser.add_argument(
        "-m", "--mu",
        type=int,
        default=20,
        help="Number of polynomial variables (default: 20)",
    )
    parser.add_argument(
        "--trace",
        action="store_true",
        help="Enable internal timing output (print-trace feature)",
    )
    parser.add_argument(
        "--release",
        action="store_true",
        default=True,
        help="Build in release mode (default)",
    )
    parser.add_argument(
        "--debug",
        action="store_false",
        dest="release",
        help="Build in debug mode",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=18000,
        help="Base port for network communication (default: 18000)",
    )
    parser.add_argument(
        "--servers",
        type=str,
        help="Path to servers_gcloud.json config file for remote mode",
    )
    parser.add_argument(
        "--build",
        action="store_true",
        help="Build on remote servers before running (remote mode only)",
    )
    parser.add_argument(
        "--sync",
        action="store_true",
        help="Sync code to remote servers before building (remote mode only)",
    )
    parser.add_argument(
        "--base-mu",
        type=int,
        default=None,
        help="Override DeepFold base_mu (default: computed from mu)",
    )
    parser.add_argument(
        "--log-m",
        type=int,
        default=None,
        help="Override log_m (log_n = mu - log_m, default: (mu-8)/2)",
    )
    parser.add_argument(
        "--memory",
        action="store_true",
        help="Measure peak memory usage using /usr/bin/time -v (remote mode only)",
    )
    parser.add_argument(
        "--code-rate",
        type=int,
        default=None,
        help="Override code rate multiplier (e.g., 4 for 1/4 rate, 8 for 1/8 rate). Default: 4",
    )
    parser.add_argument(
        "--generate-config",
        type=str,
        metavar="OUTPUT_PATH",
        help="Generate a sample servers_gcloud.json config file",
    )
    parser.add_argument(
        "--num-nodes",
        type=int,
        default=16,
        help="Number of nodes for generated config (default: 16)",
    )

    args = parser.parse_args()

    # Handle config generation
    if args.generate_config:
        generate_servers_config(args.generate_config, args.num_nodes)
        return 0

    # Require example name for running tests
    if not args.example:
        parser.error("the following arguments are required: example")

    if args.servers:
        # Remote mode
        if not os.path.exists(args.servers):
            print(f"Error: Server config file not found: {args.servers}")
            sys.exit(1)
        sys.exit(run_remote_test(
            args.example,
            servers_config=args.servers,
            mu=args.mu,
            trace=args.trace,
            build_remote=args.build,
            release=args.release,
            sync=args.sync,
            base_mu=args.base_mu,
            log_m=args.log_m,
            measure_memory=args.memory,
            code_rate=args.code_rate,
        ))
    else:
        # Local mode
        if args.mu >= 26:
            print(f"Error: mu={args.mu} is too large for local testing (requires too much memory).")
            print(f"Use remote mode with --servers for mu >= 26.")
            sys.exit(1)

        if args.num_parties < 1 or (args.num_parties & (args.num_parties - 1)) != 0:
            print(f"Error: num-parties must be a power of 2, got {args.num_parties}")
            sys.exit(1)

        sys.exit(run_local_test(
            args.example,
            num_parties=args.num_parties,
            release=args.release,
            base_port=args.port,
            mu=args.mu,
            trace=args.trace,
            base_mu=args.base_mu,
            log_m=args.log_m,
            code_rate=args.code_rate,
        ))


if __name__ == "__main__":
    main()

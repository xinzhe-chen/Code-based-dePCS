#!/usr/bin/env python3
import json
import os
import struct
import subprocess
import sys


def request(proc, value):
    payload = json.dumps(value).encode()
    proc.stdin.write(struct.pack("<I", len(payload)) + payload)
    proc.stdin.flush()
    size = struct.unpack("<I", proc.stdout.read(4))[0]
    response = json.loads(proc.stdout.read(size))
    if not response.get("ok"):
        raise RuntimeError(response.get("message", "agent request failed"))
    return response


def run(*args, ok=True):
    completed = subprocess.run(args, text=True, capture_output=True)
    if ok and completed.returncode:
        raise RuntimeError(f"{' '.join(args)}: {completed.stderr}")
    if not ok and completed.returncode == 0:
        raise RuntimeError(f"command unexpectedly succeeded: {' '.join(args)}")
    return completed


def setup(proc, run_id, topology, worker_policy):
    request(proc, {"kind": "prepare_run", "run_id": run_id})
    return request(
        proc,
        {
            "kind": "setup_network",
            "run_id": run_id,
            "world_size": 4,
            "base_port": 39900,
            "topology": topology,
            "master_rank": 0,
            "worker_to_worker": worker_policy,
            "shaper": {
                "bandwidth_bps": None,
                "latency_ms": 1,
                "jitter_ms": 0,
                "loss_percent": "0%",
                "edges": [
                    {
                        "src": 1,
                        "dst": 0,
                        "bandwidth_bps": 125000000,
                        "latency_ms": 2,
                        "jitter_ms": 0,
                        "loss_percent": "0%",
                    }
                ],
            },
        },
    )


def main():
    agent = sys.argv[1] if len(sys.argv) > 1 else "target/release/dzb-agent"
    proc = subprocess.Popen(
        ["sudo", "-n", agent, "serve"],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    try:
        star = setup(proc, "agent-netns-star", "star", "forbidden")
        namespaces = star["namespaces"]
        addresses = [entry.rsplit(":", 1)[0] for entry in star["listen_addrs"]]
        run("sudo", "-n", "ip", "netns", "exec", namespaces[1], "ping", "-c", "1", "-W", "2", addresses[0])
        run("sudo", "-n", "ip", "netns", "exec", namespaces[1], "ping", "-c", "1", "-W", "1", addresses[2], ok=False)
        qdisc = run("sudo", "-n", "ip", "netns", "exec", namespaces[1], "tc", "qdisc", "show", "dev", "eth0").stdout
        if "htb" not in qdisc or "netem" not in qdisc:
            raise RuntimeError(f"missing Agent-managed tc hierarchy: {qdisc}")
        request(proc, {"kind": "cleanup"})

        mesh = setup(proc, "agent-netns-mesh", "full-mesh", "allowed")
        namespaces = mesh["namespaces"]
        addresses = [entry.rsplit(":", 1)[0] for entry in mesh["listen_addrs"]]
        run("sudo", "-n", "ip", "netns", "exec", namespaces[1], "ping", "-c", "1", "-W", "2", addresses[2])
        request(proc, {"kind": "cleanup"})

        leftovers = run("sudo", "-n", "ip", "netns", "list").stdout
        if "dzb-" in leftovers:
            raise RuntimeError(f"namespace leak after cleanup: {leftovers}")
        print("agent_netns_lifecycle=ok star_block=ok full_mesh=ok tc=ok cleanup=ok")
    finally:
        if proc.poll() is None:
            try:
                request(proc, {"kind": "cleanup"})
            except Exception:
                pass
            proc.stdin.close()
            proc.wait(timeout=10)
        if proc.returncode:
            sys.stderr.write(proc.stderr.read().decode())
            raise SystemExit(proc.returncode)


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
import json
import sys
from pathlib import Path

run_dir = Path(sys.argv[1]) if len(sys.argv) > 1 else None
if run_dir is None:
    raise SystemExit("usage: check_results.py <run-dir>")

run = json.loads((run_dir / "run.json").read_text())
required = [
    "manifest.json",
    "comm_matrix.csv",
    "per_rank.csv",
    "per_phase.csv",
    "memory_timeseries.csv",
    "proof.bin",
    "proof.sha256",
    "verifier.json",
    "chrome_trace.json",
    "report.html",
]
missing = [name for name in required if not (run_dir / name).exists()]
if missing:
    raise SystemExit(f"missing files: {missing}")
if run["status"] != "ok":
    raise SystemExit(f"run not ok: {run['status']}")
if run["proof_size_bytes"] <= 0:
    raise SystemExit("empty proof")
print("ok")


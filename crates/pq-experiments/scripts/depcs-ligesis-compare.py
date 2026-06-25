#!/usr/bin/env python3
"""Run and summarize pq_dSNARK dePCS versus the vendored LigeSIS benchmark.

The pq_dSNARK side uses the repository's verified `pcs-benchmark` path. The
LigeSIS side is best-effort because the vendored checkout may be incomplete;
when it cannot build or run, the report records the blocker instead of emitting
fake comparison rows.
"""

from __future__ import annotations

import argparse
import csv
import ctypes
import json
import math
import os
import queue
import re
import subprocess
import sys
import tempfile
import threading
import time
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Iterable

MAX_EXPERIMENT_SECONDS = 15 * 60


def find_repo_root(start: Path) -> Path:
    for candidate in [start, *start.parents]:
        if (candidate / "Cargo.toml").exists() and (candidate / "crates" / "pq-experiments").exists():
            return candidate
    raise RuntimeError("could not locate pq_dSNARK repository root")


ROOT = find_repo_root(Path(__file__).resolve())


@dataclass
class CommandResult:
    ok: bool
    command: list[str]
    stdout: str
    stderr: str
    returncode: int


@dataclass
class MetricRow:
    scheme: str
    backend: str
    backend_rate_inv: int
    runner: str
    opening: str
    workers: int
    nv: int
    polynomial_length: int
    commit_ms: float
    open_ms: float
    verify_ms: float
    prover_ms: float
    proof_kib: float
    communication_kib: float | None
    verifier_communication_kib: float | None
    scheme_reported_communication_kib: float | None
    communication_basis: str
    worker_local_compute_ms: float | None
    end_to_end_open_proof_ms: float | None
    worker_local_speedup: float | None
    end_to_end_open_speedup: float | None
    batch_claim_count: float | None
    batch_open_ms: float | None
    batch_verify_ms: float | None
    batch_proof_bytes: float | None
    effective_query_count: float | None
    column_query_count: float | None
    pcs_query_count: float | None
    query_security_bits: float | None
    algebraic_security_bits: float | None
    verified: str
    source: str
    query_count_semantics: str = ""
    query_count_target: int = 0
    host_logical_cores: int = 0
    max_workers: int = 0
    cores_per_worker: int = 0
    backend_source: str = ""
    field: str = ""
    hash: str = ""
    code_rate_log: int = 0
    security_target_bits: int = 0
    security_effective_bits: int = 0
    security_exact: str = ""
    source_rev: str = ""
    communication_bytes: float | None = None
    verifier_communication_bytes: float | None = None
    scheme_reported_communication_bytes: float | None = None
    network_commit_bytes: float | None = None
    network_open_bytes: float | None = None
    network_bytes: float | None = None
    paper_worker_commit_max_ms: float = 0.0
    paper_worker_commit_sum_ms: float = 0.0
    paper_worker_open_max_ms: float = 0.0
    paper_worker_open_sum_ms: float = 0.0
    paper_master_assemble_ms: float = 0.0
    paper_worker_verify_max_ms: float = 0.0
    paper_worker_verify_sum_ms: float = 0.0
    paper_master_verify_ms: float = 0.0
    paper_batch_claim_ms: float = 0.0
    paper_batch_sumcheck_ms: float = 0.0
    paper_batch_combined_open_ms: float = 0.0
    paper_batch_merkle_ms: float = 0.0
    paper_batch_verify_ms: float = 0.0
    paper_individual_worker_proof_count: float = 0.0
    paper_batched_proof_count: float = 0.0
    communication_cost_kib: float | None = None
    communication_cost_basis: str = ""
    failure_reason: str = ""


def run(cmd: list[str], cwd: Path, timeout: int, env: dict[str, str] | None = None) -> CommandResult:
    if timeout <= 0:
        return CommandResult(False, cmd, "", "experiment deadline expired", 124)
    child_env = os.environ.copy()
    if env:
        child_env.update(env)
    try:
        proc = subprocess.run(
            cmd,
            cwd=cwd,
            env=child_env,
            text=True,
            encoding="utf-8",
            errors="replace",
            capture_output=True,
            timeout=timeout,
        )
        return CommandResult(proc.returncode == 0, cmd, proc.stdout, proc.stderr, proc.returncode)
    except subprocess.TimeoutExpired as exc:
        return CommandResult(
            False,
            cmd,
            exc.stdout or "",
            (exc.stderr or "") + "\nexperiment command timed out",
            124,
        )


def deadline_expired(args: argparse.Namespace) -> bool:
    return time.monotonic() >= args.experiment_deadline


def deadline_timeout(args: argparse.Namespace, requested: int) -> int:
    if math.isinf(args.experiment_deadline):
        return requested
    remaining = int(args.experiment_deadline - time.monotonic())
    if remaining <= 0:
        return 0
    return max(1, min(requested, MAX_EXPERIMENT_SECONDS, remaining))


def command_text(cmd: Iterable[str]) -> str:
    return " ".join(str(part) for part in cmd)


def child_cpu_seconds(proc: subprocess.Popen) -> float | None:
    if proc.poll() is not None:
        return None
    if os.name == "nt":
        try:
            creation = ctypes.c_ulonglong()
            exit_time = ctypes.c_ulonglong()
            kernel = ctypes.c_ulonglong()
            user = ctypes.c_ulonglong()
            ok = ctypes.windll.kernel32.GetProcessTimes(
                ctypes.c_void_p(int(proc._handle)),  # type: ignore[attr-defined]
                ctypes.byref(creation),
                ctypes.byref(exit_time),
                ctypes.byref(kernel),
                ctypes.byref(user),
            )
            if not ok:
                return None
            return (kernel.value + user.value) / 10_000_000.0
        except Exception:
            return None
    return None


def stream_reader(index: int, proc: subprocess.Popen, events: "queue.Queue[tuple[int, str]]") -> None:
    if proc.stdout is None:
        return
    try:
        for line in proc.stdout:
            events.put((index, line))
    finally:
        try:
            proc.stdout.close()
        except Exception:
            pass


def newest_pcs_run(out_dir: Path) -> Path | None:
    if not out_dir.exists():
        return None
    runs = [path for path in out_dir.iterdir() if path.is_dir() and path.name.startswith("pcs-bench-")]
    return max(runs, key=lambda path: path.stat().st_mtime) if runs else None


def parse_pcs_worker_commit_means(run_dir: Path) -> dict[tuple[str, str, str, int, int], float]:
    source_path = run_dir / "source.csv"
    if not source_path.exists():
        return {}
    grouped: dict[tuple[str, str, str, int, int], list[float]] = {}
    with source_path.open(newline="", encoding="utf-8") as handle:
        for record in csv.DictReader(handle):
            nv = int(record.get("nv", record.get("variable_count", record.get("nv_power", 0))))
            key = (
                record.get("scheme", "pq_dSNARK dePCS"),
                record["runner"],
                record["opening"],
                int(record["workers"]),
                nv,
            )
            grouped.setdefault(key, []).append(float(record.get("worker_commit_ms", 0.0)))
    return {key: sum(values) / len(values) for key, values in grouped.items() if values}


def parse_pcs_source_batch_means(run_dir: Path) -> dict[tuple[str, str, str, int, int], dict[str, float]]:
    source_path = run_dir / "source.csv"
    if not source_path.exists():
        return {}
    fields = [
        "batch_claim_count",
        "batch_open_ms",
        "batch_verify_ms",
        "batch_proof_bytes",
        "effective_query_count",
        "column_query_count",
        "pcs_query_count",
        "query_security_bits",
        "algebraic_security_bits",
        "host_logical_cores",
        "cores_per_worker",
    ]
    grouped: dict[tuple[str, str, str, int, int], dict[str, list[float]]] = {}
    with source_path.open(newline="", encoding="utf-8") as handle:
        for record in csv.DictReader(handle):
            nv = int(record.get("nv", record.get("variable_count", record.get("nv_power", 0))))
            key = (
                record.get("scheme", "pq_dSNARK dePCS"),
                record["runner"],
                record["opening"],
                int(record["workers"]),
                nv,
            )
            bucket = grouped.setdefault(key, {field: [] for field in fields})
            for field in fields:
                value = record.get(field)
                if value not in (None, ""):
                    bucket[field].append(float(value))
    return {
        key: {
            field: sum(values) / len(values)
            for field, values in field_values.items()
            if values
        }
        for key, field_values in grouped.items()
    }


def parse_pcs_source_metadata(run_dir: Path) -> dict[tuple[str, str, str, int, int], dict[str, str]]:
    source_path = run_dir / "source.csv"
    if not source_path.exists():
        return {}
    fields = [
        "backend_source",
        "field",
        "hash",
        "code_rate_log",
        "security_target_bits",
        "security_effective_bits",
        "security_exact",
        "query_count_semantics",
        "source_rev",
        "communication_basis",
        "communication_bytes",
        "verifier_communication_bytes",
        "scheme_reported_communication_bytes",
        "network_commit_bytes",
        "network_open_bytes",
        "network_bytes",
        "paper_worker_commit_max_ms",
        "paper_worker_commit_sum_ms",
        "paper_worker_open_max_ms",
        "paper_worker_open_sum_ms",
        "paper_master_assemble_ms",
        "paper_worker_verify_max_ms",
        "paper_worker_verify_sum_ms",
        "paper_master_verify_ms",
        "paper_batch_claim_ms",
        "paper_batch_sumcheck_ms",
        "paper_batch_combined_open_ms",
        "paper_batch_merkle_ms",
        "paper_batch_verify_ms",
        "paper_individual_worker_proof_count",
        "paper_batched_proof_count",
    ]
    metadata: dict[tuple[str, str, str, int, int], dict[str, str]] = {}
    with source_path.open(newline="", encoding="utf-8") as handle:
        for record in csv.DictReader(handle):
            nv = int(record.get("nv", record.get("variable_count", record.get("nv_power", 0))))
            key = (
                record.get("scheme", "pq_dSNARK dePCS"),
                record["runner"],
                record["opening"],
                int(record["workers"]),
                nv,
            )
            metadata[key] = {field: record.get(field, "") for field in fields}
    return metadata


def parse_pcs_summary(run_dir: Path) -> list[MetricRow]:
    rows: list[MetricRow] = []
    worker_commit_means = parse_pcs_worker_commit_means(run_dir)
    batch_means = parse_pcs_source_batch_means(run_dir)
    source_metadata = parse_pcs_source_metadata(run_dir)
    with (run_dir / "summary_stats.csv").open(newline="", encoding="utf-8") as handle:
        for record in csv.DictReader(handle):
            commit_ms = float(record["commit_ms_mean"])
            open_ms = float(record["open_ms_mean"])
            verify_ms = float(record["verify_ms_mean"])
            nv = int(record.get("nv", record.get("variable_count", record.get("nv_power", 0))))
            polynomial_length = int(record.get("polynomial_length", record.get("size", 0)))
            scheme = record.get("scheme", "pq_dSNARK dePCS")
            backend = record.get("backend", "basefold")
            backend_rate_inv = int(record.get("backend_rate_inv", 4 if backend == "basefold" else 0))
            key = (scheme, record["runner"], record["opening"], int(record["workers"]), nv)
            worker_commit_ms = worker_commit_means.get(key)
            batch = batch_means.get(key, {})
            metadata = source_metadata.get(key, {})
            worker_eval_commit_ms = float(record.get("worker_eval_commit_ms_mean", 0.0))
            worker_local_compute_ms = (
                None
                if worker_commit_ms is None
                else worker_commit_ms + worker_eval_commit_ms
            )
            if record.get("proof_bytes_mean"):
                proof_bytes = float(record["proof_bytes_mean"])
            else:
                proof_bytes = float(record.get("commitment_bytes_mean", 0.0)) + float(
                    record.get(
                        "opening_proof_bytes_mean",
                        record.get("opening_proof_object_bytes_mean", 0.0),
                    )
                )
            rows.append(
                MetricRow(
                    scheme=scheme,
                    backend=backend,
                    backend_rate_inv=backend_rate_inv,
                    runner=record["runner"],
                    opening=record["opening"],
                    workers=int(record["workers"]),
                    nv=nv,
                    polynomial_length=polynomial_length,
                    commit_ms=commit_ms,
                    open_ms=open_ms,
                    verify_ms=verify_ms,
                    prover_ms=commit_ms + open_ms,
                    proof_kib=proof_bytes / 1024.0,
                    communication_kib=measured_communication_kib(record),
                    verifier_communication_kib=summary_bytes_kib(
                        record, "verifier_communication_bytes_mean"
                    ),
                    scheme_reported_communication_kib=summary_bytes_kib(
                        record, "scheme_reported_communication_bytes_mean"
                    ),
                    communication_basis=record.get(
                        "communication_basis", metadata.get("communication_basis", "")
                    )
                    or "unknown",
                    worker_local_compute_ms=worker_local_compute_ms,
                    end_to_end_open_proof_ms=open_ms,
                    worker_local_speedup=None,
                    end_to_end_open_speedup=None,
                    batch_claim_count=batch.get("batch_claim_count"),
                    batch_open_ms=batch.get("batch_open_ms", float(record.get("batch_open_ms_mean", 0.0))),
                    batch_verify_ms=batch.get("batch_verify_ms", float(record.get("batch_verify_ms_mean", 0.0))),
                    batch_proof_bytes=batch.get("batch_proof_bytes", float(record.get("batch_proof_bytes_mean", 0.0))),
                    effective_query_count=batch.get("effective_query_count", float(record.get("effective_query_count_mean", 0.0))),
                    column_query_count=batch.get("column_query_count", float(record.get("column_query_count_mean", 0.0))),
                    pcs_query_count=batch.get("pcs_query_count", float(record.get("pcs_query_count_mean", 0.0))),
                    query_security_bits=batch.get("query_security_bits", float(record.get("query_security_bits_mean", 0.0))),
                    algebraic_security_bits=batch.get("algebraic_security_bits", float(record.get("algebraic_security_bits_mean", 0.0))),
                    verified=record["verified_count"],
                    source=str(run_dir),
                    query_count_semantics=metadata.get("query_count_semantics") or "query-unified",
                    host_logical_cores=int(batch.get("host_logical_cores", 0)),
                    cores_per_worker=int(batch.get("cores_per_worker", 0)),
                    backend_source=metadata.get("backend_source", ""),
                    field=metadata.get("field", ""),
                    hash=metadata.get("hash", ""),
                    code_rate_log=int(metadata.get("code_rate_log") or 0),
                    security_target_bits=int(metadata.get("security_target_bits") or 0),
                    security_effective_bits=int(metadata.get("security_effective_bits") or 0),
                    security_exact=metadata.get("security_exact", ""),
                    source_rev=metadata.get("source_rev", ""),
                    communication_bytes=summary_bytes_with_metadata(
                        record, metadata, "communication_bytes"
                    ),
                    verifier_communication_bytes=summary_bytes_with_metadata(
                        record, metadata, "verifier_communication_bytes"
                    ),
                    scheme_reported_communication_bytes=summary_bytes_with_metadata(
                        record, metadata, "scheme_reported_communication_bytes"
                    ),
                    network_commit_bytes=summary_bytes_with_metadata(
                        record, metadata, "network_commit_bytes"
                    ),
                    network_open_bytes=summary_bytes_with_metadata(
                        record, metadata, "network_open_bytes"
                    ),
                    network_bytes=summary_bytes_with_metadata(record, metadata, "network_bytes"),
                    paper_worker_commit_max_ms=float(record.get("paper_worker_commit_max_ms_mean", 0.0) or 0.0),
                    paper_worker_commit_sum_ms=float(record.get("paper_worker_commit_sum_ms_mean", 0.0) or 0.0),
                    paper_worker_open_max_ms=float(record.get("paper_worker_open_max_ms_mean", 0.0) or 0.0),
                    paper_worker_open_sum_ms=float(record.get("paper_worker_open_sum_ms_mean", 0.0) or 0.0),
                    paper_master_assemble_ms=float(record.get("paper_master_assemble_ms_mean", 0.0) or 0.0),
                    paper_worker_verify_max_ms=float(record.get("paper_worker_verify_max_ms_mean", 0.0) or 0.0),
                    paper_worker_verify_sum_ms=float(record.get("paper_worker_verify_sum_ms_mean", 0.0) or 0.0),
                    paper_master_verify_ms=float(record.get("paper_master_verify_ms_mean", 0.0) or 0.0),
                    paper_batch_claim_ms=float(record.get("paper_batch_claim_ms_mean", 0.0) or 0.0),
                    paper_batch_sumcheck_ms=float(record.get("paper_batch_sumcheck_ms_mean", 0.0) or 0.0),
                    paper_batch_combined_open_ms=float(record.get("paper_batch_combined_open_ms_mean", 0.0) or 0.0),
                    paper_batch_merkle_ms=float(record.get("paper_batch_merkle_ms_mean", 0.0) or 0.0),
                    paper_batch_verify_ms=float(record.get("paper_batch_verify_ms_mean", 0.0) or 0.0),
                    paper_individual_worker_proof_count=float(record.get("paper_individual_worker_proof_count_mean", 0.0) or 0.0),
                    paper_batched_proof_count=float(record.get("paper_batched_proof_count_mean", 0.0) or 0.0),
                )
            )
    return rows


def measured_communication_kib(record: dict[str, str]) -> float | None:
    basis = record.get("communication_basis", "")
    if basis and basis != "master_worker_sent_recv":
        return None
    communication = float(record.get("communication_bytes_mean", 0.0) or 0.0) / 1024.0
    network = float(record.get("network_bytes_mean", 0.0) or 0.0) / 1024.0
    if network == 0.0:
        return None
    return communication


def summary_bytes_kib(record: dict[str, str], field: str) -> float | None:
    value = record.get(field)
    if value in (None, ""):
        return None
    parsed = float(value)
    if parsed == 0.0:
        return None
    return parsed / 1024.0


def summary_bytes_with_metadata(
    record: dict[str, str], metadata: dict[str, str], base_field: str
) -> float | None:
    value = record.get(f"{base_field}_mean")
    if value in (None, ""):
        value = metadata.get(base_field)
    if value in (None, ""):
        return None
    parsed = float(value)
    if parsed == 0.0:
        return None
    return parsed


def parse_ligesis_output(text: str, nv: int, parties: int, source: str) -> MetricRow | None:
    values: dict[str, float] = {}
    patterns = {
        "commit": r"COMMIT_TIME_MS:\s*([0-9.]+)",
        "open": r"OPEN_TIME_MS:\s*([0-9.]+)",
        "verify": r"VERIFY_TIME_MS:\s*([0-9.]+)",
        "commitment": r"COMMITMENT_SIZE_KB:\s*([0-9.]+)",
        "proof": r"PROOF_SIZE_KB:\s*([0-9.]+)",
        "comm": r"COMM_TOTAL_MB:\s*([0-9.]+)",
    }
    for key, pattern in patterns.items():
        match = re.search(pattern, text)
        if match:
            values[key] = float(match.group(1))
    if not {"commit", "open", "verify", "commitment", "proof"}.issubset(values):
        return None
    return MetricRow(
        scheme="LigeSIS dLigesis",
        backend="ligesis",
        backend_rate_inv=0,
        runner="local",
        opening="dligesis",
        workers=parties,
        nv=nv,
        polynomial_length=1 << nv if nv < 63 else 0,
        commit_ms=values["commit"],
        open_ms=values["open"],
        verify_ms=values["verify"],
        prover_ms=values["commit"] + values["open"],
        proof_kib=values["commitment"] + values["proof"],
        communication_kib=None,
        verifier_communication_kib=values["commitment"] + values["proof"],
        scheme_reported_communication_kib=values.get("comm", 0.0) * 1024.0,
        communication_basis="scheme_native_reported",
        worker_local_compute_ms=None,
        end_to_end_open_proof_ms=None,
        worker_local_speedup=None,
        end_to_end_open_speedup=None,
        batch_claim_count=None,
        batch_open_ms=None,
        batch_verify_ms=None,
        batch_proof_bytes=None,
        effective_query_count=None,
        column_query_count=None,
        pcs_query_count=None,
        query_security_bits=None,
        algebraic_security_bits=None,
        verified="1",
        source=source,
        query_count_semantics="scheme-native-ligesis",
        verifier_communication_bytes=(values["commitment"] + values["proof"]) * 1024.0,
        scheme_reported_communication_bytes=values.get("comm", 0.0) * 1024.0 * 1024.0,
    )


EXTERNAL_PCS_SPECS = {
    "dfrittata-pcs": {
        "scheme": "dFRIttata-PCS",
        "backend": "frittata",
        "opening": "dfrittata",
        "build_cwd": lambda root: root / "ligesis-pcs",
        "build_cmd": ["cargo", "build", "--release", "--example", "dFrittata"],
        "binary": lambda root: root / "target" / "release" / "examples" / "dFrittata",
        "run_cwd": lambda root: root / "ligesis-pcs",
        "port": 28000,
        "args": lambda party_id, config_path, nv, repeats, query_count: [
            str(party_id),
            str(config_path),
            "--mu",
            str(nv),
            "-i",
            str(repeats),
            *([] if query_count is None else ["--queries", str(query_count)]),
        ],
    },
    "dpip-fri-pcs": {
        "scheme": "dPIP-FRI-PCS",
        "backend": "pip-fri",
        "opening": "depipfri",
        "build_cwd": lambda root: root / "external" / "PIP_FRI",
        "build_cmd": ["cargo", "build", "--release", "--example", "de_pip_fri"],
        "binary": lambda root: root
        / "external"
        / "PIP_FRI"
        / "target"
        / "release"
        / "examples"
        / "de_pip_fri",
        "run_cwd": lambda root: root / "external" / "PIP_FRI" / "de_pip_fri",
        "port": 29000,
        "args": lambda party_id, config_path, nv, repeats, query_count: [
            str(party_id),
            str(config_path),
            str(nv),
            "-i",
            str(repeats),
            *([] if query_count is None else ["--queries", str(query_count)]),
        ],
    },
}


def external_binary_path(spec: dict, ligesis_root: Path) -> Path:
    binary = spec["binary"](ligesis_root)
    if os.name == "nt":
        binary = binary.with_suffix(".exe")
    return binary


def parse_external_pcs_output(
    text: str, scheme_key: str, nv: int, parties: int, source: str
) -> MetricRow | None:
    spec = EXTERNAL_PCS_SPECS[scheme_key]
    patterns = {
        "commit": r"COMMIT_TIME_MS:\s*([0-9.]+)",
        "open": r"OPEN_TIME_MS:\s*([0-9.]+)",
        "verify": r"VERIFY_TIME_MS:\s*([0-9.]+)",
        "proof": r"PROOF_SIZE_KB:\s*([0-9.]+)",
        "comm_mb": r"COMM_TOTAL_MB:\s*([0-9.]+)",
        "comm_bytes": r"COMM_TOTAL_BYTES:\s*([0-9]+)",
        "queries": r"QUERY_COUNT:\s*([0-9]+)",
    }
    values: dict[str, float] = {}
    for key, pattern in patterns.items():
        match = re.search(pattern, text)
        if match:
            values[key] = float(match.group(1))
    if not {"commit", "open", "verify", "proof"}.issubset(values):
        return None
    scheme_reported_communication_kib = None
    if "comm_bytes" in values:
        scheme_reported_communication_kib = values["comm_bytes"] / 1024.0
    elif "comm_mb" in values:
        scheme_reported_communication_kib = values["comm_mb"] * 1024.0
    return MetricRow(
        scheme=spec["scheme"],
        backend=spec["backend"],
        backend_rate_inv=0,
        runner="local",
        opening=spec["opening"],
        workers=parties,
        nv=nv,
        polynomial_length=1 << nv if nv < 63 else 0,
        commit_ms=values["commit"],
        open_ms=values["open"],
        verify_ms=values["verify"],
        prover_ms=values["commit"] + values["open"],
        proof_kib=values["proof"],
        communication_kib=None,
        verifier_communication_kib=values["proof"],
        scheme_reported_communication_kib=scheme_reported_communication_kib,
        communication_basis="scheme_native_reported",
        worker_local_compute_ms=None,
        end_to_end_open_proof_ms=None,
        worker_local_speedup=None,
        end_to_end_open_speedup=None,
        batch_claim_count=None,
        batch_open_ms=None,
        batch_verify_ms=None,
        batch_proof_bytes=None,
        effective_query_count=values.get("queries"),
        column_query_count=None,
        pcs_query_count=values.get("queries"),
        query_security_bits=None,
        algebraic_security_bits=None,
        verified="1",
        source=source,
        query_count_semantics="query-unified",
        verifier_communication_bytes=values["proof"] * 1024.0,
        scheme_reported_communication_bytes=(
            scheme_reported_communication_kib * 1024.0
            if scheme_reported_communication_kib is not None
            else None
        ),
    )


def winterfell_missing(ligesis_root: Path) -> bool:
    return not (ligesis_root / "external" / "winterfell" / "crypto" / "Cargo.toml").exists()


def ligesis_binary_path(ligesis_root: Path) -> Path:
    binary = ligesis_root / "target" / "release" / "examples" / "dLigesis"
    if os.name == "nt":
        binary = binary.with_suffix(".exe")
    return binary


def build_ligesis_once(args: argparse.Namespace, ligesis_root: Path) -> CommandResult:
    project_dir = ligesis_root / "ligesis-pcs"
    build_timeout = deadline_timeout(args, args.ligesis_timeout)
    if build_timeout <= 0:
        return CommandResult(
            False,
            ["cargo", "build", "--release", "--example", "dLigesis"],
            "",
            "experiment deadline expired before LigeSIS build",
            124,
        )
    return run(
        ["cargo", "build", "--release", "--example", "dLigesis"],
        project_dir,
        build_timeout,
    )


def compute_ligesis_base_mu(mu: int, parties: int) -> int:
    return compute_ligesis_log_m(mu, parties) + 9


def compute_ligesis_log_m(mu: int, parties: int) -> int:
    default_log_m = 0 if mu < 4 else (mu - 8) // 2
    party_log = int(math.log2(parties))
    if 1 << party_log != parties:
        raise ValueError("LigeSIS local parties must be a power of two")
    return max(default_log_m, party_log)


def parse_csv_ints(value: str) -> list[int]:
    values = []
    for part in value.split(","):
        part = part.strip()
        if not part:
            continue
        values.append(int(part))
    return values


def parse_backend_specs(value: str) -> list[tuple[str, int]]:
    specs: list[tuple[str, int]] = []
    for part in value.split(","):
        part = part.strip()
        if not part:
            continue
        if ":" not in part:
            raise SystemExit(f"invalid --depcs-backends entry '{part}', expected backend:rate_inv")
        backend, rate = part.split(":", 1)
        backend = backend.strip()
        rate_inv = int(rate.strip())
        if (backend, rate_inv) not in {
            ("basefold", 8),
            ("deepfold", 2),
            ("basefold", 4),
            ("deepfold", 4),
        }:
            raise SystemExit(
                "unsupported dePCS backend spec "
                f"'{part}', expected basefold:8/deepfold:2 for paper-backed protocol11 "
                "or basefold:4/deepfold:4 for legacy runs"
            )
        specs.append((backend, rate_inv))
    if not specs:
        raise SystemExit("--depcs-backends must not be empty")
    return specs


def parse_nv_range(value: str) -> list[int]:
    value = value.strip()
    if ".." in value:
        start_text, end_text = value.split("..", 1)
        start = int(start_text)
        end = int(end_text)
        if end < start:
            raise SystemExit(f"invalid nv range '{value}': end before start")
        return list(range(start, end + 1))
    return [int(value)]


def write_jsonl_event(path: Path, payload: dict) -> None:
    payload = dict(payload)
    payload.setdefault("timestamp", datetime.now().isoformat(timespec="seconds"))
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(payload, sort_keys=True) + "\n")


def command_tail(text: str, limit: int = 2000) -> str:
    text = text or ""
    return text[-limit:]


def kill_process_tree(proc: subprocess.Popen) -> None:
    if proc.poll() is not None:
        return
    if os.name == "nt":
        subprocess.run(
            ["taskkill", "/PID", str(proc.pid), "/T", "/F"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
    else:
        proc.kill()


def run_logged(
    cmd: list[str],
    cwd: Path,
    timeout: int,
    env: dict[str, str] | None,
    events_path: Path,
    row: dict | None,
    event_kind: str,
) -> CommandResult:
    if timeout <= 0:
        return CommandResult(False, cmd, "", "experiment deadline expired", 124)
    child_env = os.environ.copy()
    if env:
        child_env.update(env)
    started_at = datetime.now().isoformat(timespec="seconds")
    start = time.monotonic()
    proc = subprocess.Popen(
        cmd,
        cwd=cwd,
        env=child_env,
        text=True,
        encoding="utf-8",
        errors="replace",
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    write_jsonl_event(
        events_path,
        {
            "event": "start",
            "kind": event_kind,
            "row_index": row.get("index") if row else None,
            "scheme": row.get("scheme") if row else None,
            "nv": row.get("nv") if row else None,
            "workers": row.get("workers") if row else None,
            "command": command_text(cmd),
            "cwd": str(cwd),
            "pid": proc.pid,
            "pids": [proc.pid],
            "started_at": started_at,
        },
    )
    try:
        stdout, stderr = proc.communicate(timeout=timeout)
        returncode = proc.returncode
    except subprocess.TimeoutExpired as exc:
        kill_process_tree(proc)
        stdout, stderr = proc.communicate()
        stdout = stdout or exc.stdout or ""
        stderr = (stderr or exc.stderr or "") + "\nexperiment command timed out"
        returncode = 124
    elapsed = time.monotonic() - start
    status = "completed" if returncode == 0 else ("timeout" if returncode == 124 else "failed")
    write_jsonl_event(
        events_path,
        {
            "event": "end",
            "kind": event_kind,
            "row_index": row.get("index") if row else None,
            "scheme": row.get("scheme") if row else None,
            "nv": row.get("nv") if row else None,
            "workers": row.get("workers") if row else None,
            "command": command_text(cmd),
            "cwd": str(cwd),
            "pid": proc.pid,
            "pids": [proc.pid],
            "started_at": started_at,
            "finished_at": datetime.now().isoformat(timespec="seconds"),
            "elapsed_s": round(elapsed, 3),
            "status": status,
            "returncode": returncode,
            "stdout_tail": command_tail(stdout),
            "stderr_tail": command_tail(stderr),
        },
    )
    return CommandResult(returncode == 0, cmd, stdout, stderr, returncode)


def active_benchmark_processes() -> list[dict[str, str]]:
    target_names = {
        "cargo.exe",
        "pq-experiments.exe",
        "dfrittata.exe",
        "de_pip_fri.exe",
        "dligesis.exe",
    }
    if os.name == "nt":
        proc = subprocess.run(
            ["tasklist", "/fo", "csv", "/nh"],
            text=True,
            encoding="utf-8",
            errors="replace",
            capture_output=True,
        )
        if proc.returncode != 0:
            return []
        active: list[dict[str, str]] = []
        for record in csv.reader(proc.stdout.splitlines()):
            if len(record) < 2:
                continue
            image = record[0].strip()
            if image.lower() in target_names:
                active.append({"image": image, "pid": record[1].strip()})
        return active
    proc = subprocess.run(
        ["ps", "-eo", "pid=,comm=,args="],
        text=True,
        encoding="utf-8",
        errors="replace",
        capture_output=True,
    )
    active = []
    for line in proc.stdout.splitlines():
        lowered = line.lower()
        if any(name.replace(".exe", "") in lowered for name in target_names):
            active.append({"process": line.strip()})
    return active


def newest_pcs_run_after(out_dir: Path, before: set[Path], started_after: float) -> Path | None:
    if not out_dir.exists():
        return None
    candidates = [
        path
        for path in out_dir.iterdir()
        if path.is_dir()
        and path.name.startswith("pcs-bench-")
        and (path not in before or path.stat().st_mtime >= started_after)
    ]
    return max(candidates, key=lambda path: path.stat().st_mtime) if candidates else None


def build_fair_schedule(args: argparse.Namespace) -> list[dict]:
    depcs_nvs = parse_nv_range(args.depcs_nv_range)
    if args.ligesis_nvs != depcs_nvs:
        raise SystemExit("--ligesis-nvs must match --depcs-nv-range in --fair-sequential mode")
    if args.ligesis_parties_list != args.depcs_worker_values:
        raise SystemExit("--ligesis-parties-list must match --depcs-workers in --fair-sequential mode")
    backend_by_name = {backend: rate_inv for backend, rate_inv in args.depcs_backend_specs}
    rows: list[dict] = []
    index = 1
    fixed_scheme_order = [
        ("depcs", "depcs-deepfold-paper-protocol11", "deepfold", "protocol11"),
        ("depcs", "depcs-basefold-paper-protocol11", "basefold", "protocol11"),
        ("depcs", "depcs-deepfold-paper-protocol11-batch", "deepfold", "protocol11-batch"),
        ("depcs", "depcs-basefold-paper-protocol11-batch", "basefold", "protocol11-batch"),
        ("ligesis", "LigeSIS", None),
        ("external", "dFRIttata", "dfrittata-pcs"),
        ("external", "dPIP-FRI", "dpip-fri-pcs"),
    ]
    for entry in fixed_scheme_order:
        kind, scheme, backend_or_key = entry[:3]
        opening = entry[3] if len(entry) > 3 else ""
        if kind == "depcs" and backend_or_key not in backend_by_name:
            continue
        if kind == "depcs" and opening == "protocol11-batch" and not args.include_depcs_batch:
            continue
        if kind == "ligesis" and args.skip_ligesis:
            continue
        if kind == "external" and backend_or_key not in args.external_pcs_schemes:
            continue
        for nv in depcs_nvs:
            for workers in args.depcs_worker_values:
                if kind == "ligesis":
                    query_semantics = "scheme-native-ligesis"
                    query_count = ""
                elif kind == "external" and external_query_count_arg(args) is None:
                    query_semantics = "scheme-native-external"
                    query_count = ""
                else:
                    query_semantics = "query-unified"
                    query_count = args.query_count
                rows.append(
                    {
                        "index": index,
                        "kind": kind,
                        "scheme": scheme,
                        "backend": backend_or_key or "ligesis",
                        "opening": opening or args.depcs_opening,
                        "rate_inv": backend_by_name.get(backend_or_key, 0),
                        "nv": nv,
                        "workers": workers,
                        "query_count": query_count,
                        "query_count_semantics": query_semantics,
                        "cores_per_worker": args.cores_per_worker,
                        "total_thread_budget": workers * args.cores_per_worker,
                        "status": "pending",
                        "command": "",
                        "failure_reason": "",
                        "started_at": "",
                        "finished_at": "",
                        "elapsed_s": "",
                    }
                )
                index += 1
    return rows


def write_schedule_csv(path: Path, schedule: list[dict]) -> None:
    fieldnames = [
        "index",
        "kind",
        "scheme",
        "backend",
        "opening",
        "rate_inv",
        "nv",
        "workers",
        "query_count",
        "query_count_semantics",
        "cores_per_worker",
        "total_thread_budget",
        "status",
        "command",
        "failure_reason",
        "started_at",
        "finished_at",
        "elapsed_s",
    ]
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        for row in schedule:
            writer.writerow({field: row.get(field, "") for field in fieldnames})


def annotate_run_context(rows: list[MetricRow], args: argparse.Namespace) -> None:
    for row in rows:
        row.host_logical_cores = int(args.host_logical_cores)
        row.max_workers = int(args.max_workers)
        row.cores_per_worker = int(args.cores_per_worker)
        if not row.query_count_semantics:
            if row.scheme.startswith("LigeSIS"):
                row.query_count_semantics = "scheme-native-ligesis"
            elif row.scheme in {"dFRIttata-PCS", "dPIP-FRI-PCS"}:
                row.query_count_semantics = "scheme-native-external"
            elif "paper-protocol11" in row.scheme:
                row.query_count_semantics = "paper-backed-protocol11-artifact"
            else:
                row.query_count_semantics = "query-unified"
        row.query_count_target = (
            int(args.query_count)
            if row.query_count_semantics == "query-unified"
            else int(row.effective_query_count or 0)
        )
        if not row.backend_source:
            if row.scheme.startswith("depcs-"):
                row.backend_source = "deepfold-bench-v0.1-paper-artifact"
            elif row.scheme.startswith("LigeSIS"):
                row.backend_source = "vendored-ligesis-native"
            elif row.scheme == "dFRIttata-PCS":
                row.backend_source = "vendored-frittata-native"
            elif row.scheme == "dPIP-FRI-PCS":
                row.backend_source = "vendored-dpip-fri-native"
        if not row.security_target_bits:
            row.security_target_bits = 100 if row.scheme.startswith("depcs-") else 0
        if not row.security_effective_bits and row.query_security_bits:
            row.security_effective_bits = int(row.query_security_bits)
        if not row.security_exact:
            row.security_exact = (
                "true"
                if row.security_target_bits
                and row.security_effective_bits == row.security_target_bits
                else "unknown"
            )
        if not row.communication_basis:
            if row.scheme.startswith("depcs-"):
                row.communication_basis = "master_worker_sent_recv"
            elif row.scheme.startswith("LigeSIS") or row.scheme in {"dFRIttata-PCS", "dPIP-FRI-PCS"}:
                row.communication_basis = "scheme_native_reported"
            else:
                row.communication_basis = "unknown"
        if row.communication_kib is not None:
            row.communication_cost_kib = row.communication_kib
            row.communication_cost_basis = "master_worker_sent_recv"
        elif row.scheme_reported_communication_kib is not None:
            row.communication_cost_kib = row.scheme_reported_communication_kib
            row.communication_cost_basis = "scheme_native_reported"
        else:
            row.communication_cost_kib = None
            row.communication_cost_basis = "unknown"


def validate_no_overlapping_benchmark_rows(events_path: Path) -> None:
    active: set[int] = set()
    with events_path.open(encoding="utf-8") as handle:
        for line_no, line in enumerate(handle, start=1):
            event = json.loads(line)
            if event.get("kind") != "benchmark":
                continue
            row_index = event.get("row_index")
            if row_index is None:
                continue
            if event.get("event") == "start":
                if active:
                    raise RuntimeError(
                        f"benchmark row overlap before row {row_index}: active rows {sorted(active)}"
                    )
                active.add(int(row_index))
            elif event.get("event") == "end":
                active.discard(int(row_index))
    if active:
        raise RuntimeError(f"benchmark rows still active in events file: {sorted(active)}")


def run_ligesis_local(
    args: argparse.Namespace, ligesis_root: Path, mu: int, parties: int
) -> CommandResult:
    project_dir = ligesis_root / "ligesis-pcs"
    binary = ligesis_binary_path(ligesis_root)
    if not binary.exists():
        return CommandResult(
            False,
            [str(binary)],
            "",
            f"Binary not found: {binary}",
            1,
        )

    config = "\n".join(f"127.0.0.1:{18000 + i}" for i in range(parties))
    with tempfile.NamedTemporaryFile("w", delete=False, suffix=".conf", encoding="utf-8") as handle:
        handle.write(config)
        config_path = handle.name
    procs = []
    try:
        log_m = compute_ligesis_log_m(mu, parties)
        base_mu = compute_ligesis_base_mu(mu, parties)
        child_env = os.environ.copy()
        child_env["RAYON_NUM_THREADS"] = str(args.cores_per_worker)
        child_env["PQ_CORES_PER_WORKER"] = str(args.cores_per_worker)
        events: queue.Queue[tuple[int, str]] = queue.Queue()
        stdout_parts: list[list[str]] = []
        cpu_seconds: list[float | None] = []
        for party_id in range(parties):
            cmd = [
                str(binary),
                str(party_id),
                config_path,
                "--mu",
                str(mu),
                "--log-m",
                str(log_m),
                "--base-mu",
                str(base_mu),
            ]
            proc = subprocess.Popen(
                cmd,
                cwd=project_dir,
                text=True,
                encoding="utf-8",
                errors="replace",
                env=child_env,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
            )
            procs.append((cmd, proc))
            stdout_parts.append([])
            cpu_seconds.append(child_cpu_seconds(proc))
            threading.Thread(
                target=stream_reader,
                args=(party_id, proc, events),
                daemon=True,
            ).start()
        if getattr(args, "run_events_path", None) and getattr(args, "current_schedule_row", None):
            row = args.current_schedule_row
            write_jsonl_event(
                Path(args.run_events_path),
                {
                    "event": "pids",
                    "kind": "benchmark",
                    "row_index": row.get("index"),
                    "scheme": row.get("scheme"),
                    "nv": row.get("nv"),
                    "workers": row.get("workers"),
                    "pids": [proc.pid for _, proc in procs],
                },
            )

        returncode = 0
        start = time.monotonic()
        last_activity = start
        timeout_at = start + deadline_timeout(args, args.ligesis_timeout)
        idle_timeout = args.ligesis_idle_timeout
        idle_killed = False
        normal_timeout = False

        while True:
            saw_output = False
            while True:
                try:
                    party_id, line = events.get_nowait()
                except queue.Empty:
                    break
                stdout_parts[party_id].append(line)
                saw_output = True
            saw_cpu = False
            for index, (_, proc) in enumerate(procs):
                current_cpu = child_cpu_seconds(proc)
                previous_cpu = cpu_seconds[index]
                if current_cpu is not None and previous_cpu is not None and current_cpu > previous_cpu + 0.01:
                    saw_cpu = True
                if current_cpu is not None:
                    cpu_seconds[index] = current_cpu
            if saw_output or saw_cpu:
                last_activity = time.monotonic()
            if all(proc.poll() is not None for _, proc in procs):
                break
            now = time.monotonic()
            if now >= timeout_at:
                normal_timeout = True
                returncode = 124
                break
            if idle_timeout > 0 and now - last_activity >= idle_timeout:
                idle_killed = True
                returncode = 124
                break
            time.sleep(0.25)

        if idle_killed or normal_timeout:
            for _, proc in procs:
                if proc.poll() is None:
                    proc.kill()
        for _, proc in procs:
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait(timeout=5)
        while True:
            try:
                party_id, line = events.get_nowait()
            except queue.Empty:
                break
            stdout_parts[party_id].append(line)

        formatted_stdout = []
        for index, (cmd, proc) in enumerate(procs):
            formatted_stdout.append(
                f"$ {command_text(cmd)}\n{''.join(stdout_parts[index])}"
            )
            if proc.returncode:
                returncode = proc.returncode if returncode == 0 else returncode
        stderr = ""
        if idle_killed:
            stderr = (
                f"LigeSIS idle timeout: no stdout or child CPU progress for "
                f"{idle_timeout} seconds"
            )
        elif normal_timeout:
            stderr = "LigeSIS command timed out before completion"

        return CommandResult(
            returncode == 0,
            [
                str(binary),
                "--local-parties",
                str(parties),
                "--mu",
                str(mu),
                "--cores-per-worker",
                str(args.cores_per_worker),
            ],
            "\n".join(formatted_stdout),
            stderr,
            returncode,
        )
    finally:
        for _, proc in procs:
            if proc.poll() is None:
                proc.kill()
        Path(config_path).unlink(missing_ok=True)


def build_external_pcs_once(
    args: argparse.Namespace, ligesis_root: Path, scheme_key: str
) -> CommandResult:
    spec = EXTERNAL_PCS_SPECS[scheme_key]
    build_cwd = spec["build_cwd"](ligesis_root)
    if not build_cwd.exists():
        return CommandResult(
            False,
            spec["build_cmd"],
            "",
            f"external source directory not found: {build_cwd}",
            1,
        )
    return run(
        spec["build_cmd"],
        build_cwd,
        deadline_timeout(args, args.external_timeout),
    )


def run_external_pcs_local(
    args: argparse.Namespace,
    ligesis_root: Path,
    scheme_key: str,
    nv: int,
    parties: int,
) -> CommandResult:
    spec = EXTERNAL_PCS_SPECS[scheme_key]
    binary = external_binary_path(spec, ligesis_root)
    if not binary.exists():
        return CommandResult(False, [str(binary)], "", f"Binary not found: {binary}", 1)
    run_cwd = spec["run_cwd"](ligesis_root)
    if not run_cwd.exists():
        return CommandResult(False, [str(binary)], "", f"run cwd not found: {run_cwd}", 1)

    base_port = int(spec["port"])
    config = "\n".join(f"127.0.0.1:{base_port + i}" for i in range(parties))
    with tempfile.NamedTemporaryFile("w", delete=False, suffix=".conf", encoding="utf-8") as handle:
        handle.write(config)
        config_path = handle.name
    procs = []
    try:
        child_env = os.environ.copy()
        child_env["RAYON_NUM_THREADS"] = str(args.cores_per_worker)
        child_env["PQ_CORES_PER_WORKER"] = str(args.cores_per_worker)
        events: queue.Queue[tuple[int, str]] = queue.Queue()
        stdout_parts: list[list[str]] = []
        cpu_seconds: list[float | None] = []
        query_count = external_query_count_arg(args)
        for party_id in range(parties):
            cmd = [
                str(binary),
                *spec["args"](party_id, config_path, nv, args.repeats, query_count),
            ]
            proc = subprocess.Popen(
                cmd,
                cwd=run_cwd,
                text=True,
                encoding="utf-8",
                errors="replace",
                env=child_env,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
            )
            procs.append((cmd, proc))
            stdout_parts.append([])
            cpu_seconds.append(child_cpu_seconds(proc))
            threading.Thread(target=stream_reader, args=(party_id, proc, events), daemon=True).start()
        if getattr(args, "run_events_path", None) and getattr(args, "current_schedule_row", None):
            row = args.current_schedule_row
            write_jsonl_event(
                Path(args.run_events_path),
                {
                    "event": "pids",
                    "kind": "benchmark",
                    "row_index": row.get("index"),
                    "scheme": row.get("scheme"),
                    "nv": row.get("nv"),
                    "workers": row.get("workers"),
                    "pids": [proc.pid for _, proc in procs],
                },
            )

        returncode = 0
        start = time.monotonic()
        last_activity = start
        timeout_at = start + deadline_timeout(args, args.external_timeout)
        idle_timeout = args.ligesis_idle_timeout
        idle_killed = False
        normal_timeout = False

        while True:
            saw_output = False
            while True:
                try:
                    party_id, line = events.get_nowait()
                except queue.Empty:
                    break
                stdout_parts[party_id].append(line)
                saw_output = True
            saw_cpu = False
            for index, (_, proc) in enumerate(procs):
                current_cpu = child_cpu_seconds(proc)
                previous_cpu = cpu_seconds[index]
                if current_cpu is not None and previous_cpu is not None and current_cpu > previous_cpu + 0.01:
                    saw_cpu = True
                if current_cpu is not None:
                    cpu_seconds[index] = current_cpu
            if saw_output or saw_cpu:
                last_activity = time.monotonic()
            if all(proc.poll() is not None for _, proc in procs):
                break
            now = time.monotonic()
            if now >= timeout_at:
                normal_timeout = True
                returncode = 124
                break
            if idle_timeout > 0 and now - last_activity >= idle_timeout:
                idle_killed = True
                returncode = 124
                break
            time.sleep(0.25)

        if idle_killed or normal_timeout:
            for _, proc in procs:
                if proc.poll() is None:
                    proc.kill()
        for _, proc in procs:
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait(timeout=5)
        while True:
            try:
                party_id, line = events.get_nowait()
            except queue.Empty:
                break
            stdout_parts[party_id].append(line)

        formatted_stdout = []
        for index, (cmd, proc) in enumerate(procs):
            formatted_stdout.append(f"$ {command_text(cmd)}\n{''.join(stdout_parts[index])}")
            if proc.returncode:
                returncode = proc.returncode if returncode == 0 else returncode
        stderr = ""
        if idle_killed:
            stderr = (
                f"{spec['scheme']} idle timeout: no stdout or child CPU progress for "
                f"{idle_timeout} seconds"
            )
        elif normal_timeout:
            stderr = f"{spec['scheme']} command timed out before completion"

        return CommandResult(
            returncode == 0,
            [
                str(binary),
                "--local-parties",
                str(parties),
                "--mu",
                str(nv),
                "--cores-per-worker",
                str(args.cores_per_worker),
                *([] if query_count is None else ["--queries", str(query_count)]),
            ],
            "\n".join(formatted_stdout),
            stderr,
            returncode,
        )
    finally:
        for _, proc in procs:
            if proc.poll() is None:
                proc.kill()
        Path(config_path).unlink(missing_ok=True)


def external_query_count_arg(args: argparse.Namespace) -> int | None:
    if getattr(args, "force_external_query_count", False):
        return int(getattr(args, "query_count", 0) or args.pcs_queries)
    return None


def run_external_pcs(args: argparse.Namespace, report_lines: list[str]) -> list[MetricRow]:
    if not args.external_pcs_schemes:
        return []
    ligesis_root = (ROOT / args.ligesis_dir).resolve()
    rows: list[MetricRow] = []
    for scheme_key in args.external_pcs_schemes:
        spec = EXTERNAL_PCS_SPECS[scheme_key]
        if scheme_key == "dfrittata-pcs" and winterfell_missing(ligesis_root):
            report_lines.append(
                f"- {spec['scheme']} blocked: vendored FRIttata/Winterfell source is incomplete."
            )
            continue
        build = build_external_pcs_once(args, ligesis_root, scheme_key)
        if not build.ok:
            report_lines.append(
                f"- {spec['scheme']} blocked before parameter sweep: `{command_text(build.command)}` exited {build.returncode}."
            )
            if build.stderr.strip():
                report_lines.append(f"  stderr: `{build.stderr.strip()[:500]}`")
            elif build.stdout.strip():
                report_lines.append(f"  output: `{build.stdout.strip()[-500:]}`")
            continue
        for parties in args.ligesis_parties_list:
            if parties == 1:
                for nv in args.ligesis_nvs:
                    report_lines.append(
                        f"- {spec['scheme']} nv={nv} parties=1 blocked: external distributed runner requires parties>=2."
                    )
                continue
            for nv in args.ligesis_nvs:
                if deadline_expired(args):
                    report_lines.append(
                        f"- {spec['scheme']} stopped: global 15 minute experiment deadline expired."
                    )
                    return rows
                if parties > (1 << nv):
                    report_lines.append(
                        f"- {spec['scheme']} nv={nv} parties={parties} skipped: parties exceeds N=2^{nv}."
                    )
                    continue
                result = run_external_pcs_local(args, ligesis_root, scheme_key, nv, parties)
                if not result.ok:
                    report_lines.append(
                        f"- {spec['scheme']} nv={nv} parties={parties} blocked: `{command_text(result.command)}` exited {result.returncode}."
                    )
                    if result.stderr.strip():
                        report_lines.append(f"  stderr: `{result.stderr.strip()[:300]}`")
                    elif result.stdout.strip():
                        report_lines.append(f"  output: `{result.stdout.strip()[-300:]}`")
                    continue
                parsed = parse_external_pcs_output(
                    (result.stdout or "") + "\n" + (result.stderr or ""),
                    scheme_key,
                    nv,
                    parties,
                    command_text(result.command),
                )
                if parsed is None:
                    report_lines.append(
                        f"- {spec['scheme']} nv={nv} parties={parties} blocked: benchmark completed but timing markers were not parsed."
                    )
                    continue
                parsed.query_count_semantics = (
                    "query-unified"
                    if external_query_count_arg(args) is not None
                    else "scheme-native-external"
                )
                parsed.source = (
                    f"local {spec['scheme']} run; party_RAYON_NUM_THREADS={args.cores_per_worker}; "
                    f"total_party_processes={parties}; query_count={parsed.effective_query_count}; "
                    f"query_count_semantics={parsed.query_count_semantics}"
                )
                rows.append(parsed)
    return rows


def mean_metric_rows(rows: list[MetricRow], source: str) -> MetricRow:
    first = rows[0]
    count = float(len(rows))
    return MetricRow(
        scheme=first.scheme,
        backend=first.backend,
        backend_rate_inv=first.backend_rate_inv,
        runner=first.runner,
        opening=first.opening,
        workers=first.workers,
        nv=first.nv,
        polynomial_length=first.polynomial_length,
        commit_ms=sum(row.commit_ms for row in rows) / count,
        open_ms=sum(row.open_ms for row in rows) / count,
        verify_ms=sum(row.verify_ms for row in rows) / count,
        prover_ms=sum(row.prover_ms for row in rows) / count,
        proof_kib=sum(row.proof_kib for row in rows) / count,
        communication_kib=mean_optional(row.communication_kib for row in rows),
        verifier_communication_kib=mean_optional(row.verifier_communication_kib for row in rows),
        scheme_reported_communication_kib=mean_optional(
            row.scheme_reported_communication_kib for row in rows
        ),
        communication_basis=first.communication_basis,
        worker_local_compute_ms=None,
        end_to_end_open_proof_ms=None,
        worker_local_speedup=None,
        end_to_end_open_speedup=None,
        batch_claim_count=None,
        batch_open_ms=None,
        batch_verify_ms=None,
        batch_proof_bytes=None,
        effective_query_count=mean_optional(row.effective_query_count for row in rows),
        column_query_count=mean_optional(row.column_query_count for row in rows),
        pcs_query_count=mean_optional(row.pcs_query_count for row in rows),
        query_security_bits=mean_optional(row.query_security_bits for row in rows),
        algebraic_security_bits=mean_optional(row.algebraic_security_bits for row in rows),
        verified=str(len(rows)),
        source=source,
        query_count_semantics=first.query_count_semantics,
        query_count_target=first.query_count_target,
        host_logical_cores=first.host_logical_cores,
        max_workers=first.max_workers,
        cores_per_worker=first.cores_per_worker,
        backend_source=first.backend_source,
        field=first.field,
        hash=first.hash,
        code_rate_log=first.code_rate_log,
        security_target_bits=first.security_target_bits,
        security_effective_bits=first.security_effective_bits,
        security_exact=first.security_exact,
        source_rev=first.source_rev,
        communication_bytes=mean_optional(row.communication_bytes for row in rows),
        verifier_communication_bytes=mean_optional(row.verifier_communication_bytes for row in rows),
        scheme_reported_communication_bytes=mean_optional(
            row.scheme_reported_communication_bytes for row in rows
        ),
        network_commit_bytes=mean_optional(row.network_commit_bytes for row in rows),
        network_open_bytes=mean_optional(row.network_open_bytes for row in rows),
        network_bytes=mean_optional(row.network_bytes for row in rows),
        paper_worker_commit_max_ms=sum(row.paper_worker_commit_max_ms for row in rows) / count,
        paper_worker_commit_sum_ms=sum(row.paper_worker_commit_sum_ms for row in rows) / count,
        paper_worker_open_max_ms=sum(row.paper_worker_open_max_ms for row in rows) / count,
        paper_worker_open_sum_ms=sum(row.paper_worker_open_sum_ms for row in rows) / count,
        paper_master_assemble_ms=sum(row.paper_master_assemble_ms for row in rows) / count,
        paper_worker_verify_max_ms=sum(row.paper_worker_verify_max_ms for row in rows) / count,
        paper_worker_verify_sum_ms=sum(row.paper_worker_verify_sum_ms for row in rows) / count,
        paper_master_verify_ms=sum(row.paper_master_verify_ms for row in rows) / count,
        paper_batch_claim_ms=sum(row.paper_batch_claim_ms for row in rows) / count,
        paper_batch_sumcheck_ms=sum(row.paper_batch_sumcheck_ms for row in rows) / count,
        paper_batch_combined_open_ms=sum(row.paper_batch_combined_open_ms for row in rows) / count,
        paper_batch_merkle_ms=sum(row.paper_batch_merkle_ms for row in rows) / count,
        paper_batch_verify_ms=sum(row.paper_batch_verify_ms for row in rows) / count,
        paper_individual_worker_proof_count=sum(row.paper_individual_worker_proof_count for row in rows) / count,
        paper_batched_proof_count=sum(row.paper_batched_proof_count for row in rows) / count,
    )


def mean_optional(values) -> float | None:
    present = [value for value in values if value is not None]
    if not present:
        return None
    return sum(present) / len(present)


def fmt_optional(value: float | None) -> str:
    if value is None:
        return "n/a"
    return f"{value:.2f}"


def markdown_cell(value: str) -> str:
    return " ".join(str(value).split()).replace("|", "\\|")


def failure_excerpt(output: str, returncode: int) -> str:
    if not output:
        return f"exit {returncode}"
    markers = [
        "batch_unavailable_basefold_artifact_no_batch_api",
        "batch_unavailable_deepfold_artifact_native_batch_api_missing",
        "paper-backed Protocol 11 is not implemented yet: refusing to fall back to paper-native PCS core without pq_dSNARK Protocol10/11 network proof",
    ]
    for marker in markers:
        index = output.find(marker)
        if index >= 0:
            return " ".join(output[index:].splitlines()[0].split())
    return " ".join(output[-500:].split())


def run_ligesis(args: argparse.Namespace, report_lines: list[str]) -> list[MetricRow]:
    ligesis_root = (ROOT / args.ligesis_dir).resolve()
    if args.skip_ligesis:
        report_lines.append("- LigeSIS run skipped by `--skip-ligesis`.")
        return []
    if not ligesis_root.exists():
        report_lines.append(f"- LigeSIS blocked: `{ligesis_root}` does not exist.")
        return []
    if winterfell_missing(ligesis_root):
        report_lines.append(
            "- LigeSIS blocked: vendored checkout is missing "
            "`external/winterfell/crypto/Cargo.toml`, required by `ligesis-pcs` dev-dependencies."
        )
        return []
    runnable_parties = [parties for parties in args.ligesis_parties_list if parties != 1]
    for nv in args.ligesis_nvs:
        if 1 in args.ligesis_parties_list:
            report_lines.append(
                f"- LigeSIS nv={nv} parties=1 blocked: dLigesis single-party run hangs on this local distributed runner."
            )
    if not runnable_parties:
        return []
    build = build_ligesis_once(args, ligesis_root)
    if not build.ok:
        report_lines.append(
            f"- LigeSIS blocked before parameter sweep: `{command_text(build.command)}` exited {build.returncode}."
        )
        if build.stderr.strip():
            report_lines.append(f"  stderr: `{build.stderr.strip()[:500]}`")
        elif build.stdout.strip():
            report_lines.append(f"  output: `{build.stdout.strip()[-500:]}`")
        return []
    binary = ligesis_binary_path(ligesis_root)
    if not binary.exists():
        report_lines.append(f"- LigeSIS blocked before parameter sweep: binary not found `{binary}`.")
        return []
    rows: list[MetricRow] = []
    for parties in runnable_parties:
        for nv in args.ligesis_nvs:
            if deadline_expired(args):
                report_lines.append(
                    "- LigeSIS stopped: global 15 minute experiment deadline expired."
                )
                return rows
            if nv < 10 and not args.try_small_ligesis:
                report_lines.append(
                    f"- LigeSIS nv={nv} parties={parties} blocked: vendored local runner is unstable for nv<10 on this Windows checkout."
                )
                continue
            if parties > (1 << nv):
                report_lines.append(
                    f"- LigeSIS nv={nv} parties={parties} skipped: parties exceeds N=2^{nv}."
                )
                continue
            trial_rows: list[MetricRow] = []
            blocked = False
            for trial in range(1, args.repeats + 1):
                if deadline_expired(args):
                    report_lines.append(
                        "- LigeSIS stopped: global 15 minute experiment deadline expired."
                    )
                    return rows
                result = run_ligesis_local(args, ligesis_root, nv, parties)
                if not result.ok:
                    report_lines.append(
                        f"- LigeSIS nv={nv} parties={parties} trial={trial}/{args.repeats} blocked: `{command_text(result.command)}` exited {result.returncode}."
                    )
                    if result.stderr.strip():
                        report_lines.append(f"  stderr: `{result.stderr.strip()[:300]}`")
                    elif result.stdout.strip():
                        report_lines.append(f"  output: `{result.stdout.strip()[-300:]}`")
                    blocked = True
                    break
                parsed = parse_ligesis_output(
                    (result.stdout or "") + "\n" + (result.stderr or ""),
                    nv,
                    parties,
                    command_text(result.command),
                )
                if parsed is None:
                    report_lines.append(
                        f"- LigeSIS nv={nv} parties={parties} trial={trial}/{args.repeats} blocked: benchmark completed but timing markers were not parsed."
                    )
                    blocked = True
                    break
                trial_rows.append(parsed)
            if trial_rows:
                source = (
                    f"mean of {len(trial_rows)}/{args.repeats} local dLigesis runs; "
                    f"party_RAYON_NUM_THREADS={args.cores_per_worker}; "
                    f"total_party_processes={parties}; log_m={compute_ligesis_log_m(nv, parties)}; "
                    f"base_mu={compute_ligesis_base_mu(nv, parties)}; "
                    "query_count_semantics=scheme-native-ligesis"
                )
                rows.append(mean_metric_rows(trial_rows, source))
            if blocked:
                continue
    return rows


def write_csv(path: Path, rows: list[MetricRow]) -> None:
    fieldnames = [
        "scheme",
        "backend",
        "backend_rate_inv",
        "runner",
        "opening",
        "workers",
        "nv",
        "polynomial_length",
        "commit_ms",
        "open_ms",
        "verify_ms",
        "prover_ms",
        "proof_kib",
        "communication_kib",
        "verifier_communication_kib",
        "scheme_reported_communication_kib",
        "communication_basis",
        "communication_cost_kib",
        "communication_cost_basis",
        "communication_bytes",
        "verifier_communication_bytes",
        "scheme_reported_communication_bytes",
        "network_commit_bytes",
        "network_open_bytes",
        "network_bytes",
        "paper_worker_commit_max_ms",
        "paper_worker_commit_sum_ms",
        "paper_worker_open_max_ms",
        "paper_worker_open_sum_ms",
        "paper_master_assemble_ms",
        "paper_worker_verify_max_ms",
        "paper_worker_verify_sum_ms",
        "paper_master_verify_ms",
        "paper_batch_claim_ms",
        "paper_batch_sumcheck_ms",
        "paper_batch_combined_open_ms",
        "paper_batch_merkle_ms",
        "paper_batch_verify_ms",
        "paper_individual_worker_proof_count",
        "paper_batched_proof_count",
        "worker_local_compute_ms",
        "end_to_end_open_proof_ms",
        "worker_local_speedup",
        "end_to_end_open_speedup",
        "batch_claim_count",
        "batch_open_ms",
        "batch_verify_ms",
        "batch_proof_bytes",
        "effective_query_count",
        "column_query_count",
        "pcs_query_count",
        "query_security_bits",
        "algebraic_security_bits",
        "query_count_semantics",
        "query_count_target",
        "host_logical_cores",
        "max_workers",
        "cores_per_worker",
        "backend_source",
        "field",
        "hash",
        "code_rate_log",
        "security_target_bits",
        "security_effective_bits",
        "security_exact",
        "source_rev",
        "verified",
        "failure_reason",
        "source",
    ]
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        for row in rows:
            writer.writerow(row.__dict__)


def annotate_depcs_scaling(rows: list[MetricRow]) -> None:
    depcs = [row for row in rows if row.scheme.startswith("depcs-")]
    baseline_rows: dict[tuple[str, int], MetricRow] = {}
    for row in depcs:
        key = (row.scheme, row.nv)
        if key not in baseline_rows or row.workers < baseline_rows[key].workers:
            baseline_rows[key] = row
    worker_local_baselines = {
        key: row.worker_local_compute_ms
        for key, row in baseline_rows.items()
        if row.worker_local_compute_ms and row.worker_local_compute_ms > 0
    }
    open_baselines = {
        key: row.end_to_end_open_proof_ms
        for key, row in baseline_rows.items()
        if row.end_to_end_open_proof_ms and row.end_to_end_open_proof_ms > 0
    }
    for row in rows:
        row.worker_local_speedup = None
        row.end_to_end_open_speedup = None
        if not row.scheme.startswith("depcs-"):
            continue
        key = (row.scheme, row.nv)
        if (
            key in worker_local_baselines
            and row.worker_local_compute_ms
            and row.worker_local_compute_ms > 0
        ):
            row.worker_local_speedup = worker_local_baselines[key] / row.worker_local_compute_ms
        if (
            key in open_baselines
            and row.end_to_end_open_proof_ms
            and row.end_to_end_open_proof_ms > 0
        ):
            row.end_to_end_open_speedup = open_baselines[key] / row.end_to_end_open_proof_ms


def write_bar_svg(path: Path, rows: list[MetricRow], title: str, subtitle: str, value_name: str, value_fn) -> None:
    plotted = [
        row
        for row in sorted(rows, key=lambda row: (row.nv, row.workers, row.scheme))
        if value_fn(row) is not None
    ]
    width = 980
    height = max(320, 90 + len(plotted) * 34)
    label_width = 260
    plot_width = width - label_width - 80
    max_value = max((value_fn(row) for row in plotted), default=1.0)
    parts = [
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" viewBox="0 0 {width} {height}">',
        '<rect width="100%" height="100%" fill="#ffffff"/>',
        f'<text x="24" y="32" font-family="Arial" font-size="18" fill="#111827">{escape_xml(title)}</text>',
        f'<text x="24" y="54" font-family="Arial" font-size="12" fill="#4b5563">{escape_xml(subtitle)}</text>',
    ]
    for idx, row in enumerate(plotted):
        y = 84 + idx * 34
        current = value_fn(row)
        if current is None:
            continue
        bar = 0 if max_value == 0 else current / max_value * plot_width
        color = "#2563eb" if row.scheme.startswith("depcs-") else "#d97706"
        label = f"{display_scheme(row)} nodes={row.workers} nv={row.nv}"
        parts.append(f'<text x="24" y="{y + 17}" font-family="Arial" font-size="12" fill="#111827">{escape_xml(label)}</text>')
        parts.append(f'<rect x="{label_width}" y="{y}" width="{bar:.1f}" height="20" fill="{color}"/>')
        parts.append(f'<text x="{label_width + bar + 8:.1f}" y="{y + 15}" font-family="Arial" font-size="12" fill="#111827">{current:.3f} {escape_xml(value_name)}</text>')
    parts.append("</svg>\n")
    path.write_text("\n".join(parts), encoding="utf-8")


def write_speedup_svg(path: Path, rows: list[MetricRow]) -> None:
    depcs = [row for row in rows if row.scheme.startswith("depcs-")]
    baseline_rows: dict[int, MetricRow] = {}
    for row in depcs:
        if row.nv not in baseline_rows or row.workers < baseline_rows[row.nv].workers:
            baseline_rows[row.nv] = row
    baselines = {nv: row.prover_ms for nv, row in baseline_rows.items()}
    plotted = [
        (row, baselines[row.nv] / row.prover_ms)
        for row in depcs
        if row.nv in baselines and row.prover_ms > 0
    ]
    plotted.sort(key=lambda item: (item[0].nv, item[0].workers))
    width = 980
    height = max(320, 90 + len(plotted) * 34)
    label_width = 260
    plot_width = width - label_width - 80
    max_value = max((speedup for _, speedup in plotted), default=1.0)
    parts = [
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" viewBox="0 0 {width} {height}">',
        '<rect width="100%" height="100%" fill="#ffffff"/>',
        '<text x="24" y="32" font-family="Arial" font-size="18" fill="#111827">dePCS speedup by worker count</text>',
        '<text x="24" y="54" font-family="Arial" font-size="12" fill="#4b5563">Speedup is relative to the smallest requested dePCS worker count at the same nv.</text>',
    ]
    for idx, (row, speedup) in enumerate(plotted):
        y = 84 + idx * 34
        bar = 0 if max_value == 0 else speedup / max_value * plot_width
        label = f"nv={row.nv} N={row.polynomial_length} nodes={row.workers}"
        parts.append(f'<text x="24" y="{y + 17}" font-family="Arial" font-size="12" fill="#111827">{escape_xml(label)}</text>')
        parts.append(f'<rect x="{label_width}" y="{y}" width="{bar:.1f}" height="20" fill="#059669"/>')
        parts.append(f'<text x="{label_width + bar + 8:.1f}" y="{y + 15}" font-family="Arial" font-size="12" fill="#111827">{speedup:.3f}x</text>')
    parts.append("</svg>\n")
    path.write_text("\n".join(parts), encoding="utf-8")


def display_scheme(row: MetricRow) -> str:
    if row.scheme.startswith("depcs-deepfold"):
        return "dePCS_Deepfold"
    if row.scheme.startswith("depcs-basefold"):
        return "dePCS_Basefold"
    return row.scheme


def write_depcs_metric_scaling_svg(
    path: Path,
    rows: list[MetricRow],
    title: str,
    subtitle: str,
    metric_name: str,
    speedup_fn,
) -> None:
    depcs = [row for row in rows if row.scheme.startswith("depcs-")]
    series: dict[int, list[tuple[int, float]]] = {}
    max_workers = 1
    max_speedup = 1.0
    for row in depcs:
        speedup = speedup_fn(row)
        if speedup is None or speedup <= 0:
            continue
        series.setdefault(row.nv, []).append((row.workers, speedup))
        max_workers = max(max_workers, row.workers)
        max_speedup = max(max_speedup, speedup)
    for points in series.values():
        points.sort()

    width = 980
    height = 560
    left = 76
    top = 76
    plot_width = 760
    plot_height = 376
    right = left + plot_width
    bottom = top + plot_height
    x_max = max(2, max_workers)
    y_max = max(float(x_max), max_speedup) * 1.05
    palette = ["#2563eb", "#d97706", "#059669", "#7c3aed", "#dc2626", "#0891b2", "#4b5563"]

    def px(worker: int) -> float:
        return left + (worker - 1) / (x_max - 1) * plot_width

    def py(speedup: float) -> float:
        return bottom - speedup / y_max * plot_height

    parts = [
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" viewBox="0 0 {width} {height}">',
        '<rect width="100%" height="100%" fill="#ffffff"/>',
        f'<text x="24" y="32" font-family="Arial" font-size="18" fill="#111827">{escape_xml(title)}</text>',
        f'<text x="24" y="54" font-family="Arial" font-size="12" fill="#4b5563">{escape_xml(subtitle)}</text>',
        f'<line x1="{left}" y1="{bottom}" x2="{right}" y2="{bottom}" stroke="#111827" stroke-width="1"/>',
        f'<line x1="{left}" y1="{top}" x2="{left}" y2="{bottom}" stroke="#111827" stroke-width="1"/>',
        f'<text x="{left + plot_width / 2 - 36:.1f}" y="{height - 36}" font-family="Arial" font-size="12" fill="#111827">nodes / workers</text>',
        f'<text x="18" y="{top + plot_height / 2:.1f}" font-family="Arial" font-size="12" fill="#111827" transform="rotate(-90 18 {top + plot_height / 2:.1f})">{escape_xml(metric_name)} speedup</text>',
    ]
    for tick in range(1, x_max + 1):
        x = px(tick)
        parts.append(f'<line x1="{x:.1f}" y1="{bottom}" x2="{x:.1f}" y2="{bottom + 5}" stroke="#111827"/>')
        parts.append(f'<text x="{x - 4:.1f}" y="{bottom + 20}" font-family="Arial" font-size="10" fill="#111827">{tick}</text>')
    y_tick_step = max(1, int(math.ceil(y_max)) // 8 or 1)
    for tick in range(0, int(math.ceil(y_max)) + 1, y_tick_step):
        y = py(float(tick))
        parts.append(f'<line x1="{left - 5}" y1="{y:.1f}" x2="{left}" y2="{y:.1f}" stroke="#111827"/>')
        parts.append(f'<text x="{left - 36}" y="{y + 4:.1f}" font-family="Arial" font-size="10" fill="#111827">{tick}</text>')
    ideal_points = " ".join(f"{px(worker):.1f},{py(float(worker)):.1f}" for worker in range(1, x_max + 1))
    parts.append(f'<polyline points="{ideal_points}" fill="none" stroke="#9ca3af" stroke-width="2" stroke-dasharray="6 5"/>')
    parts.append(f'<text x="{right + 14}" y="{py(float(x_max)) + 4:.1f}" font-family="Arial" font-size="11" fill="#4b5563">ideal</text>')
    for idx, nv in enumerate(sorted(series)):
        color = palette[idx % len(palette)]
        points = series[nv]
        path_points = " ".join(f"{px(worker):.1f},{py(speedup):.1f}" for worker, speedup in points)
        parts.append(f'<polyline points="{path_points}" fill="none" stroke="{color}" stroke-width="2"/>')
        for worker, speedup in points:
            parts.append(f'<circle cx="{px(worker):.1f}" cy="{py(speedup):.1f}" r="3.5" fill="{color}"/>')
        legend_y = top + idx * 22
        parts.append(f'<line x1="{right + 22}" y1="{legend_y}" x2="{right + 46}" y2="{legend_y}" stroke="{color}" stroke-width="2"/>')
        parts.append(f'<text x="{right + 52}" y="{legend_y + 4}" font-family="Arial" font-size="11" fill="#111827">nv={nv}</text>')
    parts.append("</svg>\n")
    path.write_text("\n".join(parts), encoding="utf-8")


def write_linear_scaling_svg(path: Path, rows: list[MetricRow]) -> None:
    depcs = [row for row in rows if row.scheme.startswith("depcs-")]
    baseline_rows: dict[int, MetricRow] = {}
    for row in depcs:
        if row.nv not in baseline_rows or row.workers < baseline_rows[row.nv].workers:
            baseline_rows[row.nv] = row
    baselines = {nv: row.prover_ms for nv, row in baseline_rows.items()}
    series: dict[int, list[tuple[int, float]]] = {}
    max_workers = 1
    max_speedup = 1.0
    for row in depcs:
        if row.nv not in baselines or row.prover_ms <= 0:
            continue
        speedup = baselines[row.nv] / row.prover_ms
        series.setdefault(row.nv, []).append((row.workers, speedup))
        max_workers = max(max_workers, row.workers)
        max_speedup = max(max_speedup, speedup)
    for points in series.values():
        points.sort()

    width = 980
    height = 560
    left = 76
    top = 72
    plot_width = 760
    plot_height = 380
    right = left + plot_width
    bottom = top + plot_height
    x_max = max(2, max_workers)
    y_max = max(float(x_max), max_speedup) * 1.05
    palette = ["#2563eb", "#d97706", "#059669", "#7c3aed", "#dc2626", "#0891b2", "#4b5563"]

    def px(worker: int) -> float:
        return left + (worker - 1) / (x_max - 1) * plot_width

    def py(speedup: float) -> float:
        return bottom - speedup / y_max * plot_height

    parts = [
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" viewBox="0 0 {width} {height}">',
        '<rect width="100%" height="100%" fill="#ffffff"/>',
        '<text x="24" y="32" font-family="Arial" font-size="18" fill="#111827">dePCS linear scalability by node count</text>',
        '<text x="24" y="54" font-family="Arial" font-size="12" fill="#4b5563">Speedup is relative to the smallest requested worker count at the same nv; dashed line is ideal linear scaling.</text>',
        f'<line x1="{left}" y1="{bottom}" x2="{right}" y2="{bottom}" stroke="#111827" stroke-width="1"/>',
        f'<line x1="{left}" y1="{top}" x2="{left}" y2="{bottom}" stroke="#111827" stroke-width="1"/>',
        f'<text x="{left + plot_width / 2 - 36:.1f}" y="{height - 36}" font-family="Arial" font-size="12" fill="#111827">nodes / workers</text>',
        f'<text x="18" y="{top + plot_height / 2:.1f}" font-family="Arial" font-size="12" fill="#111827" transform="rotate(-90 18 {top + plot_height / 2:.1f})">speedup</text>',
    ]
    for tick in range(1, x_max + 1):
        x = px(tick)
        parts.append(f'<line x1="{x:.1f}" y1="{bottom}" x2="{x:.1f}" y2="{bottom + 5}" stroke="#111827"/>')
        parts.append(f'<text x="{x - 4:.1f}" y="{bottom + 20}" font-family="Arial" font-size="10" fill="#111827">{tick}</text>')
    for tick in range(0, int(math.ceil(y_max)) + 1, max(1, int(math.ceil(y_max)) // 8 or 1)):
        y = py(float(tick))
        parts.append(f'<line x1="{left - 5}" y1="{y:.1f}" x2="{left}" y2="{y:.1f}" stroke="#111827"/>')
        parts.append(f'<text x="{left - 36}" y="{y + 4:.1f}" font-family="Arial" font-size="10" fill="#111827">{tick}</text>')
    ideal_points = " ".join(f"{px(worker):.1f},{py(float(worker)):.1f}" for worker in range(1, x_max + 1))
    parts.append(f'<polyline points="{ideal_points}" fill="none" stroke="#9ca3af" stroke-width="2" stroke-dasharray="6 5"/>')
    parts.append(f'<text x="{right + 14}" y="{py(float(x_max)) + 4:.1f}" font-family="Arial" font-size="11" fill="#4b5563">ideal</text>')
    for idx, nv in enumerate(sorted(series)):
        color = palette[idx % len(palette)]
        points = series[nv]
        path_points = " ".join(f"{px(worker):.1f},{py(speedup):.1f}" for worker, speedup in points)
        parts.append(f'<polyline points="{path_points}" fill="none" stroke="{color}" stroke-width="2"/>')
        for worker, speedup in points:
            parts.append(f'<circle cx="{px(worker):.1f}" cy="{py(speedup):.1f}" r="3.5" fill="{color}"/>')
        legend_y = top + idx * 22
        parts.append(f'<line x1="{right + 22}" y1="{legend_y}" x2="{right + 46}" y2="{legend_y}" stroke="{color}" stroke-width="2"/>')
        parts.append(f'<text x="{right + 52}" y="{legend_y + 4}" font-family="Arial" font-size="11" fill="#111827">nv={nv}</text>')
    parts.append("</svg>\n")
    path.write_text("\n".join(parts), encoding="utf-8")


def write_all_svgs(out_dir: Path, rows: list[MetricRow]) -> list[str]:
    charts = [
        (
            "comparison_prover_time.svg",
            "dePCS BaseFold vs DeepFold vs external PCS prover time",
            "Commit + open time by nv and node count; blocked external rows are omitted.",
            "ms",
            lambda row: row.prover_ms,
        ),
        (
            "comparison_verify_time.svg",
            "dePCS BaseFold vs DeepFold vs external PCS verify time",
            "Verifier time by nv and node count; blocked external rows are omitted.",
            "ms",
            lambda row: row.verify_ms,
        ),
        (
            "comparison_proof_size.svg",
            "dePCS BaseFold vs DeepFold vs external PCS proof size",
            "Verifier-received commitment plus PCS opening proof in KiB by nv and node count; blocked external rows are omitted.",
            "KiB",
            lambda row: row.proof_kib,
        ),
        (
            "comparison_communication.svg",
            "Communication cost by scheme",
            "Blue dePCS bars use master/worker TCP sent+recv; orange external bars use scheme-native reported communication.",
            "KiB",
            lambda row: row.communication_cost_kib,
        ),
    ]
    names = []
    comparison_rows = [row for row in rows if row.verified != "blocked"]
    for filename, title, subtitle, value_name, value_fn in charts:
        write_bar_svg(out_dir / filename, comparison_rows, title, subtitle, value_name, value_fn)
        names.append(filename)
    for stale_name in ["depcs_speedup_by_workers.svg", "depcs_linear_scaling.svg"]:
        (out_dir / stale_name).unlink(missing_ok=True)
    write_depcs_metric_scaling_svg(
        out_dir / "depcs_worker_local_compute_scaling.svg",
        rows,
        "dePCS worker-local compute scalability",
        "Speedup uses worker_commit_ms + worker_eval_commit_ms relative to the smallest requested worker count at the same nv.",
        "worker-local compute",
        lambda row: row.worker_local_speedup,
    )
    names.append("depcs_worker_local_compute_scaling.svg")
    write_depcs_metric_scaling_svg(
        out_dir / "depcs_end_to_end_open_proof_scaling.svg",
        rows,
        "dePCS end-to-end open/proof scalability",
        "Speedup uses full open_ms relative to the smallest requested worker count at the same nv, including proof/opening composition overhead.",
        "open/proof",
        lambda row: row.end_to_end_open_speedup,
    )
    names.append("depcs_end_to_end_open_proof_scaling.svg")
    return names


def escape_xml(value: str) -> str:
    return (
        value.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
    )


def depcs_proof_component_summary(depcs_dirs: list[Path]) -> list[str]:
    component_fields = [
        ("commitment", "proof_commitment_object_bytes_mean"),
        ("public", "proof_point_query_public_bytes_mean"),
        ("eval_commitments", "proof_eval_commitments_bytes_mean"),
        ("merkle_roots", "proof_merkle_roots_bytes_mean"),
        ("column_openings", "proof_column_openings_bytes_mean"),
        ("f2_openings", "proof_f2_openings_bytes_mean"),
        ("protocol10_e1", "proof_protocol10_e1_bytes_mean"),
        ("protocol10_e2", "proof_protocol10_e2_bytes_mean"),
        ("transcript", "proof_transcript_overhead_bytes_mean"),
    ]
    lines: list[str] = []
    for depcs_dir in depcs_dirs:
        summary_path = depcs_dir / "summary_stats.csv"
        if not summary_path.exists():
            continue
        with summary_path.open(newline="", encoding="utf-8") as handle:
            for record in csv.DictReader(handle):
                available = [
                    (name, float(record[field]))
                    for name, field in component_fields
                    if field in record and record[field]
                ]
                if not available:
                    continue
                top_name, top_bytes = max(available, key=lambda item: item[1])
                proof_bytes = float(record.get("proof_bytes_mean", "0") or 0)
                share = 0.0 if proof_bytes == 0 else top_bytes / proof_bytes * 100.0
                lines.append(
                    f"- dePCS nv={record['nv']} workers={record['workers']}: largest proof component is `{top_name}` at {top_bytes / 1024.0:.2f} KiB ({share:.1f}% of proof KiB)."
                )
    return lines


def read_depcs_source_rows(depcs_dirs: list[Path]) -> list[dict[str, str]]:
    rows: list[dict[str, str]] = []
    for run_dir in depcs_dirs:
        source_path = run_dir / "source.csv"
        if not source_path.exists():
            continue
        with source_path.open(newline="", encoding="utf-8") as handle:
            for record in csv.DictReader(handle):
                record = dict(record)
                record["_run_dir"] = str(run_dir)
                rows.append(record)
    return rows


def read_metric_rows(path: Path) -> list[dict[str, str]]:
    if not path.exists():
        return []
    with path.open(newline="", encoding="utf-8") as handle:
        return list(csv.DictReader(handle))


def row_float(row: dict[str, str], field: str, default: float = 0.0) -> float:
    value = row.get(field)
    if value in (None, ""):
        return default
    try:
        return float(value)
    except ValueError:
        return default


def metric_row_value(row: MetricRow, metric: str) -> float | None:
    value = getattr(row, metric)
    return value if value is not None else None


def ratio_text(numerator: float | None, denominator: float | None) -> str:
    if numerator is None or denominator is None or denominator == 0:
        return "n/a"
    return f"{numerator / denominator:.2f}x"


def find_metric_row(
    rows: Iterable[MetricRow], scheme: str, workers: int, nv: int
) -> MetricRow | None:
    return next(
        (
            row
            for row in rows
            if row.scheme == scheme and row.workers == workers and row.nv == nv
        ),
        None,
    )


def write_depcs_bottleneck_report(
    path: Path,
    rows: list[MetricRow],
    depcs_dirs: list[Path],
    baseline_dir: Path | None,
) -> None:
    completed_rows = [row for row in rows if str(row.verified).lower() != "blocked"]
    depcs_rows = [row for row in completed_rows if row.scheme.startswith("depcs-")]
    external_rows = [row for row in completed_rows if not row.scheme.startswith("depcs-")]
    source_rows = read_depcs_source_rows(depcs_dirs)
    max_nv = max((row.nv for row in completed_rows), default=0)
    max_workers = max((row.workers for row in completed_rows), default=0)
    lines = [
        "# dePCS Bottleneck Investigation",
        "",
        f"- generated_at: {datetime.now().isoformat(timespec='seconds')}",
        "- scope: prover time, verifier time, proof size, communication cost, and linear scalability.",
        "- root_cause_labels: `implementation-centralized`, `backend-batching-missing`, `protocol-inherent`.",
        "",
        "## Headline At Largest Point",
        "",
        "| scheme | prover ms | verify ms | proof KiB | comm KiB |",
        "| --- | ---: | ---: | ---: | ---: |",
    ]
    for row in sorted(
        [row for row in completed_rows if row.nv == max_nv and row.workers == max_workers],
        key=lambda item: item.scheme,
    ):
        lines.append(
            f"| {display_scheme(row)} | {row.prover_ms:.3f} | {row.verify_ms:.3f} | "
            f"{row.proof_kib:.2f} | {fmt_optional(row.communication_kib)} |"
        )

    lines.extend(
        [
            "",
            "## dePCS Vs External Ratios",
            "",
            "| dePCS row | external row | prover | verify | proof | communication |",
            "| --- | --- | ---: | ---: | ---: | ---: |",
        ]
    )
    for depcs in sorted(depcs_rows, key=lambda item: (item.workers, item.nv, item.scheme)):
        peers = [
            row
            for row in external_rows
            if row.workers == depcs.workers and row.nv == depcs.nv
        ]
        if not peers:
            continue
        best_by_metric = {
            "prover_ms": min(peers, key=lambda row: row.prover_ms),
            "verify_ms": min(peers, key=lambda row: row.verify_ms),
            "proof_kib": min(peers, key=lambda row: row.proof_kib),
            "communication_kib": min(
                [row for row in peers if row.communication_kib is not None],
                key=lambda row: row.communication_kib or math.inf,
                default=None,
            ),
        }
        external_label = f"best at nv={depcs.nv}, workers={depcs.workers}"
        lines.append(
            f"| {display_scheme(depcs)} nv={depcs.nv} w={depcs.workers} | {external_label} | "
            f"{ratio_text(depcs.prover_ms, best_by_metric['prover_ms'].prover_ms)} | "
            f"{ratio_text(depcs.verify_ms, best_by_metric['verify_ms'].verify_ms)} | "
            f"{ratio_text(depcs.proof_kib, best_by_metric['proof_kib'].proof_kib)} | "
            f"{ratio_text(depcs.communication_kib, best_by_metric['communication_kib'].communication_kib if best_by_metric['communication_kib'] else None)} |"
        )

    lines.extend(
        [
            "",
            "## Root Cause Matrix",
            "",
            "| metric | observed dePCS bottleneck | root cause | optimization status |",
            "| --- | --- | --- | --- |",
            "| prover time | paper-backed rows separate distributed wall-clock from worker-local artifact PCS commit/open max and sum. | implementation-centralized + protocol-inherent | worker commit now caches prepared artifact prover state; open reuses the cache and no longer rebuilds initial interpolation/Merkle state. Remaining cost is artifact PCS proof generation plus Protocol10/11 assembly. |",
            "| verifier time | paper-backed rows separate independent worker artifact verification from master Protocol10/11 checks. | backend-batching-missing | independent artifact proofs are verified in parallel; no unsupported artifact batch verify API is claimed. |",
            "| proof size | e1/e2 Protocol 10 proofs are typically the largest components. | backend-batching-missing | duplicate source commitments in Protocol 10 weighted openings are now opened once with accumulated weight; different independent roots still need separate paths. |",
            "| communication cost | network open bytes dominate total communication. | implementation-centralized | commit rows, JSON bloat, full encoded rows, and redundant e/f vectors are removed from the benchmark path; communication now includes worker column-proof fragments. |",
            "| linear scalability | end-to-end open/proof speedup flattens or regresses at high workers. | implementation-centralized | staged column proofs make the distributed boundary explicit; remaining aggregation and combined-PC proof construction are still centralized. |",
        ]
    )

    if source_rows:
        lines.extend(
            [
                "",
                "## dePCS Raw Component Breakdown",
                "",
                "| scheme | nv | workers | commit KiB | open KiB | proof KiB | p10 e1 % | p10 e2 % | column % | f2 % | batch claims |",
                "| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |",
            ]
        )
        for record in sorted(
            source_rows,
            key=lambda item: (
                item.get("scheme", ""),
                int(item.get("workers", 0)),
                int(item.get("nv", 0)),
            ),
        ):
            proof_bytes = row_float(record, "proof_bytes", 0.0)
            def pct(field: str) -> float:
                return 0.0 if proof_bytes == 0 else row_float(record, field) / proof_bytes * 100.0

            lines.append(
                f"| {record.get('scheme','dePCS')} | {record.get('nv','')} | {record.get('workers','')} | "
                f"{row_float(record, 'network_commit_bytes') / 1024.0:.2f} | "
                f"{row_float(record, 'network_open_bytes') / 1024.0:.2f} | "
                f"{proof_bytes / 1024.0:.2f} | "
                f"{pct('proof_protocol10_e1_bytes'):.1f} | "
                f"{pct('proof_protocol10_e2_bytes'):.1f} | "
                f"{pct('proof_column_openings_bytes'):.1f} | "
                f"{pct('proof_f2_openings_bytes'):.1f} | "
                f"{row_float(record, 'batch_claim_count'):.0f} |"
            )

    if source_rows:
        lines.extend(
            [
                "",
                "## Paper Artifact Timing Breakdown",
                "",
                "| scheme | nv | workers | wall commit | worker commit max | worker commit sum | wall open | worker open max | worker open sum | master assemble | wall verify | worker verify max | worker verify sum | master verify |",
                "| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |",
            ]
        )
        for record in sorted(
            [
                item
                for item in source_rows
                if item.get("runner") == "paper-network-protocol11"
            ],
            key=lambda item: (
                item.get("scheme", ""),
                int(item.get("workers", 0)),
                int(item.get("nv", 0)),
            ),
        ):
            lines.append(
                f"| {record.get('scheme','dePCS')} | {record.get('nv','')} | {record.get('workers','')} | "
                f"{row_float(record, 'commit_ms'):.3f} | "
                f"{row_float(record, 'paper_worker_commit_max_ms'):.3f} | "
                f"{row_float(record, 'paper_worker_commit_sum_ms'):.3f} | "
                f"{row_float(record, 'open_ms'):.3f} | "
                f"{row_float(record, 'paper_worker_open_max_ms'):.3f} | "
                f"{row_float(record, 'paper_worker_open_sum_ms'):.3f} | "
                f"{row_float(record, 'paper_master_assemble_ms'):.3f} | "
                f"{row_float(record, 'verify_ms'):.3f} | "
                f"{row_float(record, 'paper_worker_verify_max_ms'):.3f} | "
                f"{row_float(record, 'paper_worker_verify_sum_ms'):.3f} | "
                f"{row_float(record, 'paper_master_verify_ms'):.3f} |"
            )

    lines.extend(
        [
            "",
            "## Scheme Differences",
            "",
            "- dePCS proves a Brakedown-style Protocol 11 evaluation plus two Protocol 10 encoding relations over independent per-worker transparent PC commitments.",
            "- LigeSIS uses SIS hashing plus DeepFold multi-chunked batch openings and extension-field sumchecks, which keeps verifier-facing proof size small but can send more network data at high party counts.",
            "- dFRIttata follows a FRI fold-and-batch path and avoids dePCS Protocol 10/11 encoding consistency proof shape.",
            "- dPIP-FRI is a specialized distributed PIP-FRI path; it has much smaller proof/verifier/communication constants but is not the same dePCS Brakedown protocol.",
        ]
    )

    if baseline_dir is not None:
        baseline_rows = read_metric_rows(baseline_dir / "comparison_summary.csv")
        if baseline_rows:
            current_by_key = {
                (row.scheme, row.workers, row.nv): row
                for row in rows
                if row.scheme.startswith("depcs-")
            }
            lines.extend(
                [
                    "",
                    "## dePCS Before After",
                    "",
                    f"- baseline: `{baseline_dir}`",
                    "",
                    "| row | prover | verify | proof | communication |",
                    "| --- | ---: | ---: | ---: | ---: |",
                ]
            )
            for old in baseline_rows:
                if not old.get("scheme", "").startswith("depcs-"):
                    continue
                key = (old["scheme"], int(old["workers"]), int(old["nv"]))
                current = current_by_key.get(key)
                if current is None:
                    continue
                lines.append(
                    f"| {old['scheme']} nv={old['nv']} w={old['workers']} | "
                    f"{row_float(old, 'prover_ms'):.3f} -> {current.prover_ms:.3f} | "
                    f"{row_float(old, 'verify_ms'):.3f} -> {current.verify_ms:.3f} | "
                    f"{row_float(old, 'proof_kib'):.2f} -> {current.proof_kib:.2f} | "
                    f"{row_float(old, 'communication_kib'):.2f} -> {fmt_optional(current.communication_kib)} |"
                )
    lines.append("")
    path.write_text("\n".join(lines), encoding="utf-8")


def write_report(
    path: Path,
    rows: list[MetricRow],
    notes: list[str],
    depcs_dirs: list[Path],
    chart_names: list[str],
    args: argparse.Namespace,
) -> None:
    depcs_dir_text = ", ".join(f"`{path}`" for path in depcs_dirs)
    chart_text = ", ".join(f"`{name}`" for name in chart_names)
    if getattr(args, "fair_sequential", False):
        benchmark_design = (
            f"fair sequential reproduction over nv={args.depcs_nv_range}; each benchmark row "
            "(scheme,nv,workers) runs alone with a per-row timeout, after release binaries are built."
        )
        scheduling = (
            f"strict row order is depcs-deepfold, depcs-basefold"
            f"{', depcs-deepfold-batch, depcs-basefold-batch' if getattr(args, 'include_depcs_batch', False) else ''}, "
            f"LigeSIS, dFRIttata, dPIP-FRI; "
            f"within each scheme rows run nv ascending then workers ascending. host_logical_cores="
            f"{args.host_logical_cores}, max_workers={args.max_workers}, cores_per_worker="
            f"{args.cores_per_worker}. protocol11 dePCS rows must report master/worker network "
            "sent+recv bytes; paper-native rows are PCS-only and external party processes use "
            "cores_per_worker threads each."
        )
        timeout_policy = (
            f"fair rows use per-row timeouts: dePCS={args.depcs_timeout}s, "
            f"LigeSIS={args.ligesis_timeout}s, external={args.external_timeout}s; "
            "a timeout marks only that row blocked."
        )
    else:
        benchmark_design = (
            f"LigeSIS Section 5.2 Distributed PCS fixes polynomial size at 2^28 and sweeps node count "
            f"1,2,4,8,16; this local run is a scaled reproduction over nv={args.depcs_nv_range} "
            "under the 15 minute deadline."
        )
        scheduling = (
            "dePCS is run in one process per worker value with `RAYON_NUM_THREADS = workers * "
            "cores_per_worker`; LigeSIS launches one process per party and sets each party process "
            "to `RAYON_NUM_THREADS = cores_per_worker`."
        )
        timeout_policy = (
            f"parties=1 is recorded as blocked without spawning dLigesis; runnable LigeSIS rows use "
            f"idle timeout {args.ligesis_idle_timeout}s plus the global 15 minute deadline."
        )
    lines = [
        "# dePCS BaseFold vs DeepFold vs External PCS Benchmark Report",
        "",
        f"- generated_at: {datetime.now().isoformat(timespec='seconds')}",
        f"- depcs_artifact_dirs: {depcs_dir_text}",
        f"- benchmark_design: {benchmark_design}",
        "- size_semantics: nv is the number of multilinear polynomial variables; polynomial length is N=2^nv. These are PCS sizes, not circuit gate counts.",
        f"- scheduling: {scheduling}",
        f"- timeout_policy: {timeout_policy}",
        "- query_count_semantics: dePCS BaseFold/DeepFold use the paper-backed backend query policy; dFRIttata, dPIP-FRI, and LigeSIS use their scheme-native query settings unless `--force-external-query-count` is explicitly set.",
        "- proof_size_semantics: `proof KiB` is the verifier-received PCS commitment object plus PCS opening proof. It is not prover-local committed polynomial storage.",
        "- communication_semantics: `dePCS send+recv KiB` is only master/worker network sent plus received bytes from dePCS protocol11 rows. External and LigeSIS native communication is reported separately as `native comm KiB`; `communication_cost_kib` is a chart-only derived value with `communication_cost_basis`.",
        "- verifier_semantics: paper-backed dePCS uses parallel independent artifact PCS verification plus batched Protocol10/11 consistency checks; no unsupported artifact batch-verify API is assumed.",
        "- batch_boundary: `protocol11-batch` is an explicit experimental runner. If a real artifact-native batch opening cannot be constructed without changing the field/backend semantics, the row is recorded as blocked instead of falling back to individual worker proofs.",
        "- scalability_semantics: worker-local and end-to-end scaling fields are meaningful only for distributed dePCS rows with `communication_basis=master_worker_sent_recv`.",
        "- interpretation: paper-native rows are PCS-only artifact timings and must not be read as distributed dePCS Protocol10/11 evidence.",
        "- local_simulation_caveat: this is a single-machine Rayon simulation, so high worker counts also include scheduler, cache, memory-bandwidth, and proof-object allocation noise.",
        "- implementation_boundary: `--opening protocol11` may not silently fall back to paper-native PCS core. If paper-backed Protocol10/11 is unavailable, the row is blocked instead of emitted as dePCS.",
        "- comparison_chart_filter: blocked rows are omitted from comparison bar charts; dePCS scalability baselines use the smallest requested worker count.",
        f"- charts: {chart_text}",
        "- raw_table: `comparison_summary.csv` includes `worker_local_compute_ms`, `end_to_end_open_proof_ms`, paper worker commit/open/verify max/sum, master assemble, and scaling fields.",
        "",
        "## Result Table",
        "",
        "| scheme | backend | rate inv | runner | opening | nv / N | nodes | commit ms | open ms | verify ms | prover ms | proof KiB | dePCS send+recv KiB | native comm KiB | comm basis | verified |",
        "| --- | --- | ---: | --- | --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | --- | ---: |",
    ]
    for row in rows:
        lines.append(
            f"| {display_scheme(row)} | {row.backend} | {row.backend_rate_inv} | {row.runner} | {row.opening} | {row.nv} / {row.polynomial_length} | "
            f"{row.workers} | {row.commit_ms:.3f} | {row.open_ms:.3f} | {row.verify_ms:.3f} | "
            f"{row.prover_ms:.3f} | {row.proof_kib:.2f} | "
            f"{fmt_optional(row.communication_kib)} | {fmt_optional(row.scheme_reported_communication_kib)} | "
            f"{row.communication_basis} | {row.verified} |"
        )
    blocked_rows = [row for row in rows if str(row.verified).lower() == "blocked"]
    if blocked_rows:
        lines.extend(
            [
                "",
                "## Blocked Rows",
                "",
                "| scheme | backend | opening | nv | nodes | reason |",
                "| --- | --- | --- | ---: | ---: | --- |",
            ]
        )
        for row in blocked_rows:
            lines.append(
                f"| {display_scheme(row)} | {row.backend} | {row.opening} | {row.nv} | "
                f"{row.workers} | {markdown_cell(row.failure_reason or 'blocked')} |"
            )
    proof_component_lines = depcs_proof_component_summary(depcs_dirs)
    if proof_component_lines:
        lines.extend(["", "## dePCS Proof Size Components", ""])
        lines.append(
            "- Detailed per-run charts are written as `proof_size_component_breakdown_by_nv.svg` inside each `pcs-bench-*` artifact directory."
        )
        lines.extend(proof_component_lines)
    lines.extend(["", "## Notes", ""])
    lines.extend(notes or ["- No blockers recorded."])
    lines.append("")
    path.write_text("\n".join(lines), encoding="utf-8")


def fair_row_command(args: argparse.Namespace, row: dict, out_dir: Path) -> list[str]:
    if row["kind"] == "depcs":
        security_bits = depcs_security_bits_for_row(args, row)
        return [
            "cargo",
            "run",
            "-p",
            "pq-experiments",
            "--release",
            "--",
            "pcs-benchmark",
            "--runner",
            args.depcs_runner,
            "--opening",
            row.get("opening") or args.depcs_opening,
            "--backend",
            row["backend"],
            "--backend-rate-inv",
            str(row["rate_inv"]),
            "--nv-range",
            f"{row['nv']}..{row['nv']}",
            "--workers",
            str(row["workers"]),
            "--pcs-queries",
            str(args.query_count),
            "--security-bits",
            str(security_bits),
            "--repeats",
            str(args.repeats),
            "--cores-per-worker",
            str(args.cores_per_worker),
            "--no-pcs-warmup",
            "--out",
            str(out_dir),
        ]
    ligesis_root = (ROOT / args.ligesis_dir).resolve()
    if row["kind"] == "ligesis":
        return [
            str(ligesis_binary_path(ligesis_root)),
            "--local-parties",
            str(row["workers"]),
            "--mu",
            str(row["nv"]),
            "--cores-per-worker",
            str(args.cores_per_worker),
            "--query-count-semantics",
            "scheme-native-ligesis",
        ]
    spec = EXTERNAL_PCS_SPECS[row["backend"]]
    query_count = external_query_count_arg(args)
    return [
        str(external_binary_path(spec, ligesis_root)),
        "--local-parties",
        str(row["workers"]),
        "--mu",
        str(row["nv"]),
        "--cores-per-worker",
        str(args.cores_per_worker),
        *([] if query_count is None else ["--queries", str(query_count)]),
    ]


def mark_schedule_row(
    row: dict,
    schedule_path: Path,
    schedule: list[dict],
    status: str,
    started_at: str | None = None,
    finished_at: str | None = None,
    elapsed_s: float | None = None,
    failure_reason: str | None = None,
) -> None:
    row["status"] = status
    if started_at is not None:
        row["started_at"] = started_at
    if finished_at is not None:
        row["finished_at"] = finished_at
    if elapsed_s is not None:
        row["elapsed_s"] = f"{elapsed_s:.3f}"
    if failure_reason is not None:
        row["failure_reason"] = failure_reason
    write_schedule_csv(schedule_path, schedule)


def blocked_metric_row(row: dict, args: argparse.Namespace, failure_reason: str) -> MetricRow:
    backend = row.get("backend", "")
    rate_inv = int(row.get("rate_inv", 0) or 0)
    nv = int(row.get("nv", 0) or 0)
    workers = int(row.get("workers", 0) or 0)
    security_bits = depcs_security_bits_for_row(args, row) if row.get("kind") == "depcs" else 0
    return MetricRow(
        scheme=row.get("scheme", "blocked"),
        backend=backend,
        backend_rate_inv=rate_inv,
        runner="paper-network-protocol11-batch"
        if row.get("opening") == "protocol11-batch"
        else row.get("kind", "blocked"),
        opening=row.get("opening") or args.depcs_opening,
        workers=workers,
        nv=nv,
        polynomial_length=(1 << nv) if 0 <= nv < 63 else 0,
        commit_ms=0.0,
        open_ms=0.0,
        verify_ms=0.0,
        prover_ms=0.0,
        proof_kib=0.0,
        communication_kib=None,
        verifier_communication_kib=None,
        scheme_reported_communication_kib=None,
        communication_basis="not_applicable",
        worker_local_compute_ms=None,
        end_to_end_open_proof_ms=None,
        worker_local_speedup=None,
        end_to_end_open_speedup=None,
        batch_claim_count=None,
        batch_open_ms=None,
        batch_verify_ms=None,
        batch_proof_bytes=None,
        effective_query_count=None,
        column_query_count=None,
        pcs_query_count=None,
        query_security_bits=None,
        algebraic_security_bits=None,
        verified="blocked",
        source="blocked fair-sequential row",
        query_count_semantics=row.get("query_count_semantics", ""),
        query_count_target=int(args.query_count),
        host_logical_cores=args.host_logical_cores,
        max_workers=args.max_workers,
        cores_per_worker=args.cores_per_worker,
        backend_source="deepfold-bench-v0.1-paper-artifact",
        field="Mersenne61Ext" if row.get("kind") == "depcs" else "",
        hash="Blake3" if row.get("kind") == "depcs" else "",
        code_rate_log=3 if backend == "basefold" and rate_inv == 8 else (1 if backend == "deepfold" and rate_inv == 2 else 0),
        security_target_bits=security_bits,
        security_effective_bits=0,
        security_exact="false",
        source_rev="deepfold-bench-v0.1",
        failure_reason=failure_reason,
    )


def depcs_security_bits_for_row(args: argparse.Namespace, row: dict) -> int:
    if (row.get("backend"), int(row.get("rate_inv", 0) or 0)) in {
        ("basefold", 8),
        ("deepfold", 2),
    }:
        return 100
    return int(args.security_bits)


def run_distributed_fair_row(
    args: argparse.Namespace,
    row: dict,
    events_path: Path,
    runner,
) -> tuple[CommandResult, float, str, str]:
    started_at = datetime.now().isoformat(timespec="seconds")
    start = time.monotonic()
    write_jsonl_event(
        events_path,
        {
            "event": "start",
            "kind": "benchmark",
            "row_index": row["index"],
            "scheme": row["scheme"],
            "nv": row["nv"],
            "workers": row["workers"],
            "command": row["command"],
            "pids": [],
            "started_at": started_at,
        },
    )
    args.current_schedule_row = row
    try:
        result = runner()
    finally:
        args.current_schedule_row = None
    elapsed = time.monotonic() - start
    finished_at = datetime.now().isoformat(timespec="seconds")
    status = "completed" if result.ok else ("timeout" if result.returncode == 124 else "blocked")
    write_jsonl_event(
        events_path,
        {
            "event": "end",
            "kind": "benchmark",
            "row_index": row["index"],
            "scheme": row["scheme"],
            "nv": row["nv"],
            "workers": row["workers"],
            "command": row["command"],
            "pids": [],
            "started_at": started_at,
            "finished_at": finished_at,
            "elapsed_s": round(elapsed, 3),
            "status": status,
            "returncode": result.returncode,
            "stdout_tail": command_tail(result.stdout),
            "stderr_tail": command_tail(result.stderr),
        },
    )
    return result, elapsed, started_at, finished_at


def build_fair_release_binaries(
    args: argparse.Namespace,
    out_dir: Path,
    events_path: Path,
    notes: list[str],
) -> bool:
    ligesis_root = (ROOT / args.ligesis_dir).resolve()
    build_jobs: list[tuple[str, list[str], Path, int]] = [
        (
            "pq-experiments",
            ["cargo", "build", "-p", "pq-experiments", "--release"],
            ROOT,
            max(args.depcs_timeout, 1800),
        )
    ]
    if not args.skip_ligesis:
        build_jobs.append(
            (
                "LigeSIS",
                ["cargo", "build", "--release", "--example", "dLigesis"],
                ligesis_root / "ligesis-pcs",
                max(args.ligesis_timeout, 1800),
            )
        )
    for scheme_key in args.external_pcs_schemes:
        spec = EXTERNAL_PCS_SPECS[scheme_key]
        build_jobs.append(
            (
                spec["scheme"],
                spec["build_cmd"],
                spec["build_cwd"](ligesis_root),
                max(args.external_timeout, 1800),
            )
        )
    for label, cmd, cwd, timeout in build_jobs:
        if not cwd.exists():
            notes.append(f"- build blocked for {label}: cwd does not exist `{cwd}`.")
            return False
        result = run_logged(cmd, cwd, timeout, None, events_path, None, "build")
        if not result.ok:
            notes.append(
                f"- build blocked for {label}: `{command_text(result.command)}` exited {result.returncode}."
            )
            output = (result.stderr or result.stdout).strip()
            if output:
                notes.append(f"  output: `{output[-500:]}`")
            return False
    return True


def run_fair_sequential(args: argparse.Namespace) -> int:
    schedule = build_fair_schedule(args)
    for row in schedule:
        row["command"] = command_text(fair_row_command(args, row, (ROOT / args.out).resolve()))
    if args.dry_run:
        for row in schedule:
            print(f"{row['index']},{row['scheme']},nv={row['nv']},workers={row['workers']}")
        return 0

    out_dir = (ROOT / args.out).resolve()
    out_dir.mkdir(parents=True, exist_ok=True)
    schedule_path = out_dir / "schedule.csv"
    events_path = out_dir / "run_events.jsonl"
    events_path.write_text("", encoding="utf-8")
    write_schedule_csv(schedule_path, schedule)
    args.run_events_path = events_path
    notes: list[str] = [
        (
            f"- fair_sequential: one benchmark row at a time; host_logical_cores="
            f"{args.host_logical_cores}; max_workers={args.max_workers}; "
            f"cores_per_worker={args.cores_per_worker}."
        ),
        (
            "- query_semantics: dePCS uses paper-backed backend query policy; "
            "dFRIttata, dPIP-FRI, and LigeSIS remain scheme-native by default."
        ),
    ]

    stale = active_benchmark_processes()
    if stale:
        notes.append(f"- preflight blocked: stale benchmark processes detected: {stale}.")
        write_report(out_dir / "comparison_report.md", [], notes, [], [], args)
        sys.stderr.write("preflight blocked by stale benchmark processes:\n")
        for process in stale:
            sys.stderr.write(f"  {process}\n")
        return 1

    if not build_fair_release_binaries(args, out_dir, events_path, notes):
        write_report(out_dir / "comparison_report.md", [], notes, [], [], args)
        return 1

    ligesis_root = (ROOT / args.ligesis_dir).resolve()
    rows: list[MetricRow] = []
    depcs_dirs: list[Path] = []

    for row in schedule:
        cmd = fair_row_command(args, row, out_dir)
        row["command"] = command_text(cmd)
        started_at = datetime.now().isoformat(timespec="seconds")
        mark_schedule_row(row, schedule_path, schedule, "running", started_at=started_at)
        start = time.monotonic()
        if row["kind"] == "depcs":
            before = {
                path
                for path in out_dir.iterdir()
                if path.is_dir() and path.name.startswith("pcs-bench-")
            }
            result = run_logged(
                cmd,
                ROOT,
                args.depcs_timeout,
                {
                    "RAYON_NUM_THREADS": str(row["total_thread_budget"]),
                    "PQ_CORES_PER_WORKER": str(args.cores_per_worker),
                },
                events_path,
                row,
                "benchmark",
            )
            elapsed = time.monotonic() - start
            finished_at = datetime.now().isoformat(timespec="seconds")
            if not result.ok:
                status = "timeout" if result.returncode == 124 else "blocked"
                failure = failure_excerpt((result.stderr or result.stdout).strip(), result.returncode)
                notes.append(
                    f"- {row['scheme']} nv={row['nv']} workers={row['workers']} {status}: "
                    f"`{command_text(result.command)}` exited {result.returncode}."
                )
                output = (result.stderr or result.stdout).strip()
                if output:
                    notes.append(f"  output: `{output[-500:]}`")
                mark_schedule_row(
                    row,
                    schedule_path,
                    schedule,
                    status,
                    finished_at=finished_at,
                    elapsed_s=elapsed,
                    failure_reason=failure,
                )
                rows.append(blocked_metric_row(row, args, failure))
                continue
            depcs_dir = newest_pcs_run_after(out_dir, before, start)
            if depcs_dir is None:
                failure = "no new pcs-bench-* artifact directory was found"
                notes.append(
                    f"- {row['scheme']} nv={row['nv']} workers={row['workers']} blocked: no new pcs-bench-* artifact directory was found."
                )
                mark_schedule_row(
                    row,
                    schedule_path,
                    schedule,
                    "blocked-no-artifact",
                    finished_at=finished_at,
                    elapsed_s=elapsed,
                    failure_reason=failure,
                )
                rows.append(blocked_metric_row(row, args, failure))
                continue
            parsed_rows = parse_pcs_summary(depcs_dir)
            matching_rows = [
                metric
                for metric in parsed_rows
                if metric.backend == row["backend"]
                and metric.nv == row["nv"]
                and metric.workers == row["workers"]
                and metric.opening == row["opening"]
            ]
            if not matching_rows:
                failure = f"no matching metric row in {depcs_dir}"
                notes.append(
                    f"- {row['scheme']} nv={row['nv']} workers={row['workers']} blocked: artifact parsed but no matching metric row was found in `{depcs_dir}`."
                )
                mark_schedule_row(
                    row,
                    schedule_path,
                    schedule,
                    "blocked-parse",
                    finished_at=finished_at,
                    elapsed_s=elapsed,
                    failure_reason=failure,
                )
                rows.append(blocked_metric_row(row, args, failure))
                continue
            for metric in matching_rows:
                metric.source = (
                    f"{depcs_dir}; pcs_queries_requested={args.query_count}; "
                    f"master_RAYON_NUM_THREADS={row['total_thread_budget']}; "
                    f"worker_process_RAYON_NUM_THREADS={args.cores_per_worker}; "
                    f"PQ_CORES_PER_WORKER={args.cores_per_worker}; "
                    f"query_count_semantics={metric.query_count_semantics or 'paper-backed-protocol11-artifact'}"
                )
                if (
                    metric.query_count_semantics == "query-unified"
                    and int(metric.pcs_query_count or 0) != int(args.query_count)
                ):
                    notes.append(
                        f"- {row['scheme']} nv={row['nv']} workers={row['workers']} query audit failed: "
                        f"pcs_query_count={metric.pcs_query_count}, expected {args.query_count}."
                    )
                rows.append(metric)
            depcs_dirs.append(depcs_dir)
            mark_schedule_row(row, schedule_path, schedule, "completed", finished_at=finished_at, elapsed_s=elapsed)
            continue

        if row["kind"] == "ligesis":
            result, elapsed, _, finished_at = run_distributed_fair_row(
                args,
                row,
                events_path,
                lambda: run_ligesis_local(args, ligesis_root, row["nv"], row["workers"]),
            )
            if not result.ok:
                status = "timeout" if result.returncode == 124 else "blocked"
                notes.append(
                    f"- LigeSIS nv={row['nv']} parties={row['workers']} {status}: "
                    f"`{command_text(result.command)}` exited {result.returncode}."
                )
                output = (result.stderr or result.stdout).strip()
                if output:
                    notes.append(f"  output: `{output[-500:]}`")
                mark_schedule_row(
                    row,
                    schedule_path,
                    schedule,
                    status,
                    finished_at=finished_at,
                    elapsed_s=elapsed,
                    failure_reason=failure_excerpt(output, result.returncode),
                )
                continue
            parsed = parse_ligesis_output(
                (result.stdout or "") + "\n" + (result.stderr or ""),
                row["nv"],
                row["workers"],
                command_text(result.command),
            )
            if parsed is None:
                notes.append(
                    f"- LigeSIS nv={row['nv']} parties={row['workers']} blocked: timing markers were not parsed."
                )
                mark_schedule_row(
                    row,
                    schedule_path,
                    schedule,
                    "blocked-parse",
                    finished_at=finished_at,
                    elapsed_s=elapsed,
                    failure_reason="timing markers were not parsed",
                )
                continue
            parsed.source = (
                f"local LigeSIS run; party_RAYON_NUM_THREADS={args.cores_per_worker}; "
                f"total_party_processes={row['workers']}; "
                f"log_m={compute_ligesis_log_m(row['nv'], row['workers'])}; "
                f"base_mu={compute_ligesis_base_mu(row['nv'], row['workers'])}; "
                "query_count_semantics=scheme-native-ligesis"
            )
            rows.append(parsed)
            mark_schedule_row(row, schedule_path, schedule, "completed", finished_at=finished_at, elapsed_s=elapsed)
            continue

        result, elapsed, _, finished_at = run_distributed_fair_row(
            args,
            row,
            events_path,
            lambda: run_external_pcs_local(
                args, ligesis_root, row["backend"], row["nv"], row["workers"]
            ),
        )
        spec = EXTERNAL_PCS_SPECS[row["backend"]]
        if not result.ok:
            status = "timeout" if result.returncode == 124 else "blocked"
            notes.append(
                f"- {spec['scheme']} nv={row['nv']} parties={row['workers']} {status}: "
                f"`{command_text(result.command)}` exited {result.returncode}."
            )
            output = (result.stderr or result.stdout).strip()
            if output:
                notes.append(f"  output: `{output[-500:]}`")
            mark_schedule_row(
                row,
                schedule_path,
                schedule,
                status,
                finished_at=finished_at,
                elapsed_s=elapsed,
                failure_reason=failure_excerpt(output, result.returncode),
            )
            continue
        parsed = parse_external_pcs_output(
            (result.stdout or "") + "\n" + (result.stderr or ""),
            row["backend"],
            row["nv"],
            row["workers"],
            command_text(result.command),
        )
        if parsed is None:
            notes.append(
                f"- {spec['scheme']} nv={row['nv']} parties={row['workers']} blocked: timing markers were not parsed."
            )
            mark_schedule_row(
                row,
                schedule_path,
                schedule,
                "blocked-parse",
                finished_at=finished_at,
                elapsed_s=elapsed,
                failure_reason="timing markers were not parsed",
            )
            continue
        parsed.query_count_semantics = (
            "query-unified"
            if external_query_count_arg(args) is not None
            else "scheme-native-external"
        )
        expected_external_queries = external_query_count_arg(args)
        if (
            expected_external_queries is not None
            and int(parsed.effective_query_count or 0) != int(expected_external_queries)
        ):
            notes.append(
                f"- {spec['scheme']} nv={row['nv']} parties={row['workers']} query audit failed: "
                f"query_count={parsed.effective_query_count}, expected {expected_external_queries}."
            )
        parsed.source = (
            f"local {spec['scheme']} run; party_RAYON_NUM_THREADS={args.cores_per_worker}; "
            f"total_party_processes={row['workers']}; query_count={parsed.effective_query_count}; "
            f"query_count_semantics={parsed.query_count_semantics}"
        )
        rows.append(parsed)
        mark_schedule_row(row, schedule_path, schedule, "completed", finished_at=finished_at, elapsed_s=elapsed)

    annotate_depcs_scaling(rows)
    annotate_run_context(rows, args)
    write_csv(out_dir / "comparison_summary.csv", rows)
    chart_names = write_all_svgs(out_dir, rows)
    validate_no_overlapping_benchmark_rows(events_path)
    write_report(out_dir / "comparison_report.md", rows, notes, depcs_dirs, chart_names, args)
    baseline_dir = (ROOT / args.baseline_dir).resolve() if args.baseline_dir else None
    if baseline_dir is not None and not baseline_dir.exists():
        baseline_dir = None
    write_depcs_bottleneck_report(
        out_dir / "depcs_bottleneck_report.md",
        rows,
        depcs_dirs,
        baseline_dir,
    )
    print(out_dir / "comparison_report.md")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", default="results/depcs-ligesis-nv14-18-workers2-4-8-16")
    parser.add_argument("--fair-sequential", action="store_true")
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--reuse-depcs-dir", default=None)
    parser.add_argument(
        "--baseline-dir",
        default="results/codex-network-full-with-frittata-pipfri-ligesis-fixed-nv14-18-workers2-4-8-16",
        help="Optional previous comparison output used for dePCS before/after diagnostics.",
    )
    parser.add_argument(
        "--depcs-nv-range",
        "--depcs-mu-range",
        "--depcs-n-range",
        dest="depcs_nv_range",
        default="14..18",
    )
    parser.add_argument("--depcs-workers", default="2,4,8,16")
    parser.add_argument("--cores-per-worker", type=int, default=None)
    parser.add_argument("--depcs-runner", default="local-network")
    parser.add_argument("--depcs-opening", default="protocol11")
    parser.add_argument(
        "--include-depcs-batch",
        action="store_true",
        help="Also schedule explicit protocol11-batch dePCS rows. Unavailable paper-native batch backends are kept as blocked rows instead of falling back.",
    )
    parser.add_argument(
        "--depcs-backends",
        default="basefold:4,deepfold:4",
        help="Comma-separated dePCS backend matrix as backend:rate_inv.",
    )
    parser.add_argument("--pcs-queries", type=int, default=1)
    parser.add_argument("--query-count", type=int, default=None)
    parser.add_argument("--security-bits", "--lambda", dest="security_bits", type=int, default=128)
    parser.add_argument("--repeats", type=int, default=1)
    parser.add_argument("--skip-ligesis", action="store_true")
    parser.add_argument("--ligesis-dir", default="third_party/ligesis-pcs-3447")
    parser.add_argument("--ligesis-nv", "--ligesis-mu", dest="ligesis_nv", type=int, default=14)
    parser.add_argument(
        "--ligesis-nvs",
        "--ligesis-mus",
        dest="ligesis_nvs",
        default=None,
        help="Comma-separated LigeSIS nv values.",
    )
    parser.add_argument(
        "--paper-nv",
        "--paper-mu",
        dest="paper_nv",
        type=int,
        default=None,
        help="Convenience option for a LigeSIS Figure 4 style fixed nv sweep, e.g. --paper-nv 28.",
    )
    parser.add_argument("--ligesis-parties", type=int, default=2, help=argparse.SUPPRESS)
    parser.add_argument(
        "--ligesis-parties-list",
        default=None,
        help="Comma-separated LigeSIS party counts. Defaults to --depcs-workers when omitted.",
    )
    parser.add_argument("--ligesis-iterations", type=int, default=1, help=argparse.SUPPRESS)
    parser.add_argument("--depcs-timeout", type=int, default=600)
    parser.add_argument("--ligesis-timeout", type=int, default=900)
    parser.add_argument("--external-timeout", type=int, default=900)
    parser.add_argument(
        "--ligesis-idle-timeout",
        type=int,
        default=90,
        help="Kill a local LigeSIS run after this many seconds without stdout or child CPU progress. Use 0 to disable.",
    )
    parser.add_argument(
        "--try-small-ligesis",
        action="store_true",
        help="Actually run LigeSIS nv<10. By default these rows are recorded as blocked because the vendored Windows runner crashes or hangs locally.",
    )
    parser.add_argument(
        "--external-pcs-schemes",
        default="",
        help="Comma-separated external PCS schemes to include: dfrittata-pcs,dpip-fri-pcs.",
    )
    parser.add_argument(
        "--force-external-query-count",
        action="store_true",
        help="Pass --queries to dFRIttata/dPIP-FRI instead of using their scheme-native defaults.",
    )
    args = parser.parse_args()
    if args.fair_sequential:
        args.experiment_deadline = math.inf
    else:
        args.experiment_deadline = time.monotonic() + MAX_EXPERIMENT_SECONDS
        args.depcs_timeout = min(args.depcs_timeout, MAX_EXPERIMENT_SECONDS)
        args.ligesis_timeout = min(args.ligesis_timeout, MAX_EXPERIMENT_SECONDS)
        args.external_timeout = min(args.external_timeout, MAX_EXPERIMENT_SECONDS)
    args.ligesis_nvs = (
        parse_csv_ints(args.ligesis_nvs)
        if args.ligesis_nvs is not None
        else ([args.paper_nv] if args.paper_nv is not None else [args.ligesis_nv])
    )
    if args.paper_nv is not None:
        args.depcs_nv_range = f"{args.paper_nv}..{args.paper_nv}"
    args.depcs_worker_values = parse_csv_ints(args.depcs_workers)
    args.ligesis_parties_list = (
        parse_csv_ints(args.ligesis_parties_list)
        if args.ligesis_parties_list is not None
        else args.depcs_worker_values
    )
    args.external_pcs_schemes = [
        scheme.strip()
        for scheme in args.external_pcs_schemes.split(",")
        if scheme.strip()
    ]
    args.depcs_backend_specs = parse_backend_specs(args.depcs_backends)
    args.host_logical_cores = os.cpu_count() or 1
    args.max_workers = max(args.depcs_worker_values)
    if args.fair_sequential:
        computed_cores_per_worker = max(1, args.host_logical_cores // args.max_workers)
        if args.cores_per_worker is not None and args.cores_per_worker != computed_cores_per_worker:
            parser.error(
                "--cores-per-worker must not override the fair sequential allocation; "
                f"expected {computed_cores_per_worker} from floor("
                f"{args.host_logical_cores}/{args.max_workers})"
            )
        args.cores_per_worker = computed_cores_per_worker
        if args.query_count is None:
            args.query_count = args.pcs_queries
        args.pcs_queries = args.query_count
    else:
        if args.cores_per_worker is None:
            args.cores_per_worker = 1
        if args.query_count is None:
            args.query_count = args.pcs_queries
    if args.cores_per_worker <= 0:
        parser.error("--cores-per-worker must be positive")
    if args.query_count <= 0:
        parser.error("--query-count/--pcs-queries must be positive")
    if args.ligesis_idle_timeout < 0:
        parser.error("--ligesis-idle-timeout must be non-negative")
    unknown_external = [
        scheme for scheme in args.external_pcs_schemes if scheme not in EXTERNAL_PCS_SPECS
    ]
    if unknown_external:
        parser.error(
            "--external-pcs-schemes contains unsupported entries: "
            + ",".join(unknown_external)
        )
    if args.ligesis_parties_list != args.depcs_worker_values:
        parser.error("--ligesis-parties-list must match --depcs-workers for fair comparison")
    if args.depcs_runner != "local-network":
        parser.error("--depcs-runner must be local-network")
    if any(workers < 2 for workers in args.depcs_worker_values):
        parser.error("--depcs-workers must be >= 2 for the local-network runner")
    if args.ligesis_iterations != 1:
        parser.error("--ligesis-iterations is deprecated; use --repeats so both schemes run the same repeat count")
    if args.fair_sequential:
        if args.reuse_depcs_dir:
            parser.error("--reuse-depcs-dir is incompatible with --fair-sequential")
        return run_fair_sequential(args)

    out_dir = (ROOT / args.out).resolve()
    out_dir.mkdir(parents=True, exist_ok=True)
    notes: list[str] = []

    depcs_dirs: list[Path] = []
    if args.reuse_depcs_dir:
        reuse = (ROOT / args.reuse_depcs_dir).resolve()
        if (reuse / "summary_stats.csv").exists():
            depcs_dirs = [reuse]
        else:
            depcs_dirs = sorted(
                [
                    path
                    for path in reuse.iterdir()
                    if path.is_dir() and path.name.startswith("pcs-bench-")
                ],
                key=lambda path: path.name,
            )
        if not depcs_dirs:
            sys.stderr.write(f"no pcs-bench-* directories found under {reuse}\n")
            return 1
    else:
        for backend, rate_inv in args.depcs_backend_specs:
            for workers in args.depcs_worker_values:
                if deadline_expired(args):
                    notes.append("- dePCS stopped: global 15 minute experiment deadline expired.")
                    break
                cmd = [
                    "cargo",
                    "run",
                    "-p",
                    "pq-experiments",
                    "--release",
                    "--",
                    "pcs-benchmark",
                    "--runner",
                    args.depcs_runner,
                    "--opening",
                    args.depcs_opening,
                    "--backend",
                    backend,
                    "--backend-rate-inv",
                    str(rate_inv),
                    "--nv-range",
                    args.depcs_nv_range,
                    "--workers",
                    str(workers),
                    "--pcs-queries",
                    str(args.pcs_queries),
                    "--security-bits",
                    str(args.security_bits),
                    "--repeats",
                    str(args.repeats),
                    "--cores-per-worker",
                    str(args.cores_per_worker),
                    "--no-pcs-warmup",
                    "--out",
                    str(out_dir),
                ]
                rayon_threads = workers * args.cores_per_worker
                result = run(
                    cmd,
                    ROOT,
                    deadline_timeout(args, args.depcs_timeout),
                    env={
                        "RAYON_NUM_THREADS": str(rayon_threads),
                        "PQ_CORES_PER_WORKER": str(args.cores_per_worker),
                    },
                )
                if not result.ok:
                    notes.append(
                        f"- dePCS backend={backend} rate_inv={rate_inv} workers={workers} blocked: `{command_text(result.command)}` exited {result.returncode}."
                    )
                    output = (result.stderr or result.stdout).strip()
                    if output:
                        notes.append(f"  output: `{output[-500:]}`")
                    if backend == "deepfold":
                        sys.stderr.write(result.stdout + result.stderr)
                        return result.returncode
                    if result.returncode == 124:
                        break
                    continue
                depcs_dir = newest_pcs_run(out_dir)
                if depcs_dir is None:
                    sys.stderr.write("dePCS benchmark completed but no pcs-bench-* directory was found\n")
                    return 1
                depcs_dirs.append(depcs_dir)

    rows = []
    for depcs_dir in depcs_dirs:
        rows.extend(parse_pcs_summary(depcs_dir))
    rows.extend(run_ligesis(args, notes))
    rows.extend(run_external_pcs(args, notes))
    annotate_depcs_scaling(rows)
    annotate_run_context(rows, args)

    write_csv(out_dir / "comparison_summary.csv", rows)
    chart_names = write_all_svgs(out_dir, rows)
    write_report(out_dir / "comparison_report.md", rows, notes, depcs_dirs, chart_names, args)
    baseline_dir = (ROOT / args.baseline_dir).resolve() if args.baseline_dir else None
    if baseline_dir is not None and not baseline_dir.exists():
        baseline_dir = None
    write_depcs_bottleneck_report(
        out_dir / "depcs_bottleneck_report.md",
        rows,
        depcs_dirs,
        baseline_dir,
    )
    print(out_dir / "comparison_report.md")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

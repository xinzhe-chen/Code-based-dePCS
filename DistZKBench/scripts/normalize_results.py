#!/usr/bin/env python3
"""Normalize artifacts produced before phase-category/perf schema fixes."""

import csv
import json
import pathlib
import sys


def normalize_run(run_dir: pathlib.Path) -> None:
    perf = run_dir / "perf_counters.csv"
    if perf.is_file():
        perf.write_text(
            perf.read_text().replace(
                ",0,not_collected", ",,unsupported_or_not_requested"
            )
        )

    ranks = run_dir / "per_rank.csv"
    events = run_dir / "events.jsonl"
    if not ranks.is_file() or not events.is_file():
        return
    with ranks.open(newline="") as handle:
        rows = list(csv.DictReader(handle))
    phase_totals: dict[int, dict[str, float]] = {}
    for line in events.read_text().splitlines():
        event = json.loads(line)
        rank = int(event["rank"])
        name = str(event["name"])
        category = "compute" if name == "protocol11.worker_commit" else "protocol"
        totals = phase_totals.setdefault(rank, {})
        totals[category] = totals.get(category, 0.0) + float(event["duration_ms"])
    fields = [
        "rank", "pid", "total_time_ms", "compute_time_ms", "serialize_time_ms",
        "send_time_ms", "recv_time_ms", "network_wait_ms", "barrier_wait_ms",
        "proof_assembly_ms", "protocol_time_ms", "serialized_sent_bytes",
        "serialized_recv_bytes", "thread_budget", "qos_class", "qos_applied",
    ]
    with ranks.open("w", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        for row in rows:
            totals = phase_totals.get(int(row["rank"]), {})
            writer.writerow({
                **row,
                "compute_time_ms": f'{totals.get("compute", 0.0):.3f}',
                "serialize_time_ms": "",
                "send_time_ms": "",
                "recv_time_ms": "",
                "network_wait_ms": "",
                "barrier_wait_ms": "",
                "proof_assembly_ms": "",
                "protocol_time_ms": f'{totals.get("protocol", 0.0):.3f}',
            })


def main() -> None:
    if len(sys.argv) != 2:
        raise SystemExit("usage: normalize_results.py <sweep-results-dir>")
    root = pathlib.Path(sys.argv[1])
    for run_json in root.rglob("run.json"):
        normalize_run(run_json.parent)


if __name__ == "__main__":
    main()

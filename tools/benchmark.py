#!/usr/bin/env python3
"""Measure complete CLI analysis + JSON/HTML export on local synthetic captures.

Linux wait4 supplies per-child peak RSS. Data generation and JSON inspection are
outside the timed region. Each size gets one untimed warm-up and N measured runs.
"""
from __future__ import annotations

import argparse
import csv
import json
import os
import platform
import statistics
import subprocess
import time
from pathlib import Path

from generate_fixtures import encode, frame, udp


def measure(executable: Path, capture: Path, output: Path) -> dict:
    with output.with_suffix(".stdout.txt").open("w") as stdout, output.with_suffix(".stderr.txt").open("w") as stderr:
        started = time.perf_counter()
        process = subprocess.Popen([str(executable), "analyze", str(capture), "--output", str(output)], stdout=stdout, stderr=stderr)
        _, status, usage = os.wait4(process.pid, 0)
        elapsed = time.perf_counter() - started
        process.returncode = os.waitstatus_to_exitcode(status)
        if process.returncode != 0:
            raise RuntimeError(f"Analysis failed with code {process.returncode}; see {output.with_suffix('.stderr.txt')}")
    report = json.loads((output / "report.json").read_text())
    return {
        "packets": report["summary"]["packets"], "flows": report["summary"]["flows"],
        "wall_seconds": elapsed, "peak_rss_kib": usage.ru_maxrss,
        "user_seconds": usage.ru_utime, "system_seconds": usage.ru_stime,
        "capture_bytes": capture.stat().st_size,
        "report_json_bytes": (output / "report.json").stat().st_size,
        "dashboard_bytes": (output / "index.html").stat().st_size,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--executable", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--sizes", type=int, nargs="+", default=[1000, 10000, 50000])
    parser.add_argument("--repeats", type=int, default=3)
    args = parser.parse_args()
    if platform.system() != "Linux":
        parser.error("This RSS measurement implementation requires Linux.")
    if not 1 <= args.repeats <= 20 or any(not 1 <= size <= 100000 for size in args.sizes):
        parser.error("Use 1..20 repeats and 1..100000 packets per size.")
    output = args.output
    output.mkdir(parents=False, exist_ok=False)
    executable = args.executable.resolve()
    template = [frame("192.0.2.99", "198.51.100.99", 17, udp(40000 + i, 9000 + i % 10, b"synthetic" * 12)) for i in range(100)]
    results = []
    for size in args.sizes:
        capture = output / f"synthetic-{size}.pcap"
        capture.write_bytes(encode([(i * 100, template[i % 100]) for i in range(size)]))
        measure(executable, capture, output / f"warmup-{size}")
        for repetition in range(1, args.repeats + 1):
            row = measure(executable, capture, output / f"run-{size}-{repetition}")
            assert row["packets"] == size and row["flows"] == min(size, 100)
            results.append({"repetition": repetition, **row})
        group = [r["wall_seconds"] for r in results if r["packets"] == size]
        print(f"{size:6} packets | median {statistics.median(group):.4f} s | {min(group):.4f}–{max(group):.4f} s", flush=True)
    environment = {
        "platform": platform.platform(), "machine": platform.machine(),
        "cpu_count_visible": os.cpu_count(), "python": platform.python_version(),
        "analyzer": subprocess.check_output([str(executable), "--version"], text=True).strip(),
        "compiler": subprocess.check_output(["c++", "--version"], text=True).splitlines()[0],
        "method": "Release CLI, SHA-256 + parsing + aggregation + rules + full JSON/HTML export + fsync. One warm-up per size; repeated file reads can be cached. Per-child Linux wait4 ru_maxrss in KiB.",
        "workload": "100 fixed UDP tuples, 100-microsecond spacing, 108-byte synthetic payload, 2 documentation IPv4 addresses; no network traffic sent.",
        "caveat": "Single shared container and narrow synthetic workload. Not throughput, security accuracy, cold-cache performance, or a comparison with another tool.",
    }
    (output / "measurements.json").write_text(json.dumps({"environment": environment, "runs": results}, indent=2) + "\n")
    with (output / "measurements.csv").open("w", newline="") as file:
        writer = csv.DictWriter(file, fieldnames=list(results[0])); writer.writeheader(); writer.writerows(results)


if __name__ == "__main__":
    main()

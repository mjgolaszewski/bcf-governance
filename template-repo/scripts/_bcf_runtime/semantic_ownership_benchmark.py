"""Reproducible benchmark harness for an exact semantic reference proof.

Copyright 2026 Michael Golaszewski.
Licensed under the MIT License.
"""

from __future__ import annotations

import argparse
import json
import os
import platform
import statistics
import sys
import time
from pathlib import Path

from .semantic_ownership_reference import prove_reference


def _p95(values: list[float]) -> float:
    ordered = sorted(values)
    index = max(0, min(len(ordered) - 1, (95 * len(ordered) + 99) // 100 - 1))
    return ordered[index]


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description="Benchmark an exact SOIP reference.")
    parser.add_argument("--consumer-root", type=Path, required=True)
    parser.add_argument("--expected-commit", required=True)
    parser.add_argument("--expected-tree", required=True)
    parser.add_argument("--expected-representations", type=int, required=True)
    parser.add_argument("--consumer-report", type=Path, required=True)
    parser.add_argument("--contract", type=Path, required=True)
    parser.add_argument("--warmups", type=int, default=1)
    parser.add_argument("--runs", type=int, default=10)
    parser.add_argument("--median-ceiling", type=float, default=30.0)
    parser.add_argument("--p95-ceiling", type=float, default=36.0)
    parser.add_argument("--expected-python", required=True)
    parser.add_argument("--substrate", choices=("provisional_local", "disposable_vm"), required=True)
    parser.add_argument("--image-digest")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    version = platform.python_version()
    if version != args.expected_python:
        raise SystemExit(
            f"benchmark Python mismatch: expected {args.expected_python}, observed {version}"
        )
    if args.substrate == "disposable_vm" and not args.image_digest:
        raise SystemExit("disposable_vm benchmark requires --image-digest")
    if args.warmups < 1 or args.runs < 2:
        raise SystemExit("benchmark requires at least one warmup and two measured runs")
    arguments = {
        "expected_commit": args.expected_commit,
        "expected_tree": args.expected_tree,
        "expected_representations": args.expected_representations,
        "consumer_report_path": args.consumer_report,
        "contract_path": args.contract,
    }
    for _ in range(args.warmups):
        prove_reference(args.consumer_root, **arguments)
    timings: list[float] = []
    final_proof: dict[str, object] = {}
    for _ in range(args.runs):
        started = time.monotonic()
        final_proof = prove_reference(args.consumer_root, **arguments)
        timings.append(time.monotonic() - started)
    median = statistics.median(timings)
    p95 = _p95(timings)
    proof_size = len(json.dumps(final_proof, sort_keys=True).encode())
    passed = median <= args.median_ceiling and p95 <= args.p95_ceiling and proof_size < 1024 * 1024
    proof_environment = final_proof.get("environment")
    if not isinstance(proof_environment, dict):
        proof_environment = {}
    report = {
        "document": {"kind": "semantic_reference_benchmark", "version": "1.0.0"},
        "environment": {
            "substrate": args.substrate,
            "image_digest": args.image_digest,
            "architecture": platform.machine(),
            "platform": platform.platform(),
            "python_version": version,
            "python_executable": Path(sys.executable).name,
            "vcpus": os.cpu_count(),
            "node_version": proof_environment.get("node_version"),
            "typescript_version": proof_environment.get("typescript_version"),
        },
        "warmup_count": args.warmups,
        "measured_run_count": args.runs,
        "timings_seconds": [round(value, 6) for value in timings],
        "median_seconds": round(median, 6),
        "p95_seconds": round(p95, 6),
        "median_ceiling_seconds": args.median_ceiling,
        "p95_ceiling_seconds": args.p95_ceiling,
        "compact_proof_bytes": proof_size,
        "compact_proof_ceiling_bytes": 1024 * 1024,
        "verdict": "pass" if passed else "fail",
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(
        f"semantic-reference-benchmark-{report['verdict']}: "
        f"median={median:.3f}s p95={p95:.3f}s"
    )
    if not passed:
        raise SystemExit(1)


if __name__ == "__main__":
    main()

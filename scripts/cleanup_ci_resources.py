"""Plan or remove Docker resources owned by one exact CI run label."""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Callable

LABEL_KEY = "io.bcf-governance.ci-run"
RUN_ID_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{5,127}$")


@dataclass(frozen=True)
class DockerResource:
    kind: str
    object_id: str


Runner = Callable[[list[str]], subprocess.CompletedProcess[str]]


def _run(command: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(command, check=False, capture_output=True, text=True)


def validate_run_id(run_id: str) -> None:
    if not RUN_ID_PATTERN.fullmatch(run_id):
        raise ValueError("run id must be 6-128 characters using letters, digits, dot, underscore, or hyphen")


def discover_resources(run_id: str, runner: Runner = _run) -> list[DockerResource]:
    validate_run_id(run_id)
    label = f"{LABEL_KEY}={run_id}"
    queries = {
        "container": ["docker", "ps", "-aq", "--filter", f"label={label}"],
        "network": ["docker", "network", "ls", "-q", "--filter", f"label={label}"],
        "volume": ["docker", "volume", "ls", "-q", "--filter", f"label={label}"],
        "image": ["docker", "image", "ls", "-q", "--filter", f"label={label}"],
    }
    resources: list[DockerResource] = []
    for kind, command in queries.items():
        result = runner(command)
        if result.returncode != 0:
            raise RuntimeError(result.stderr.strip() or f"Docker {kind} discovery failed")
        resources.extend(DockerResource(kind, value) for value in dict.fromkeys(result.stdout.split()) if value)
    return resources


def remove_resources(resources: list[DockerResource], runner: Runner = _run) -> None:
    removers = {
        "container": ["docker", "rm", "-f"],
        "network": ["docker", "network", "rm"],
        "volume": ["docker", "volume", "rm"],
        "image": ["docker", "image", "rm"],
    }
    for resource in resources:
        result = runner([*removers[resource.kind], resource.object_id])
        if result.returncode != 0:
            raise RuntimeError(result.stderr.strip() or f"failed to remove {resource.kind} {resource.object_id}")


def _confirm(assume_yes: bool) -> None:
    if assume_yes:
        return
    if not sys.stdin.isatty():
        raise RuntimeError("ci-cleanup --apply requires --yes when stdin is not a TTY")
    if input("Remove resources owned by this CI run? [y/N]: ").strip().lower() not in {"y", "yes"}:
        raise RuntimeError("CI cleanup aborted by user")


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Clean exact-label-owned Docker CI resources.")
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--repo-root", type=Path, default=Path.cwd())
    parser.add_argument("--apply", action="store_true")
    parser.add_argument("--yes", action="store_true")
    parser.add_argument("--format", choices=("text", "json"), default="text")
    parser.add_argument("--compact", action="store_true")
    return parser


def main(argv: list[str] | None = None) -> None:
    args = _parser().parse_args(argv)
    try:
        resources = discover_resources(args.run_id)
        if args.apply:
            _confirm(args.yes)
            remove_resources(resources)
    except (RuntimeError, ValueError) as exc:
        raise SystemExit(str(exc)) from exc
    payload = {
        "status": "changed" if args.apply and resources else "actionable" if resources else "clean",
        "run_id": args.run_id,
        "applied": args.apply,
        "resources": [asdict(item) for item in resources],
    }
    if args.format == "json":
        print(json.dumps(payload, indent=None if args.compact else 2, separators=(",", ":") if args.compact else None, sort_keys=True))
    else:
        print(f"status: {payload['status']}")
        print(f"run_id: {args.run_id}")
        print(f"applied: {str(args.apply).lower()}")
        for resource in resources:
            print(f"- {resource.kind}: {resource.object_id}")


if __name__ == "__main__":
    main()

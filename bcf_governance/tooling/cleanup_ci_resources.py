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
OBJECT_ID_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:@+-]{0,255}$")


@dataclass(frozen=True)
class DockerResource:
    kind: str
    object_id: str
    owner_run_id: str


Runner = Callable[[list[str]], subprocess.CompletedProcess[str]]


def _run(command: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(command, check=False, capture_output=True, text=True)


def validate_run_id(run_id: str) -> None:
    if not RUN_ID_PATTERN.fullmatch(run_id):
        raise ValueError("run id must be 6-128 characters using letters, digits, dot, underscore, or hyphen")


def _validate_object_id(object_id: str) -> None:
    if not OBJECT_ID_PATTERN.fullmatch(object_id):
        raise RuntimeError("Docker returned an unsafe resource identity")


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
        for value in dict.fromkeys(result.stdout.splitlines()):
            if not value:
                continue
            _validate_object_id(value)
            resources.append(DockerResource(kind, value, run_id))
    return resources


def _inspect_command(resource: DockerResource) -> list[str]:
    templates = {
        "container": ["docker", "container", "inspect"],
        "network": ["docker", "network", "inspect"],
        "volume": ["docker", "volume", "inspect"],
        "image": ["docker", "image", "inspect"],
    }
    identity = ".Name" if resource.kind == "volume" else ".Id"
    labels = ".Config.Labels" if resource.kind in {"container", "image"} else ".Labels"
    template = f'{{{{{identity}}}}}\t{{{{index {labels} "{LABEL_KEY}"}}}}'
    return [*templates[resource.kind], "--format", template, resource.object_id]


def _revalidate_ownership(resource: DockerResource, runner: Runner) -> None:
    validate_run_id(resource.owner_run_id)
    _validate_object_id(resource.object_id)
    result = runner(_inspect_command(resource))
    if result.returncode != 0:
        raise RuntimeError(
            result.stderr.strip()
            or f"failed to revalidate {resource.kind} {resource.object_id}"
        )
    fields = result.stdout.rstrip("\n").split("\t")
    if fields != [resource.object_id, resource.owner_run_id]:
        raise RuntimeError(
            f"Docker {resource.kind} ownership changed before cleanup: {resource.object_id}"
        )


def remove_resources(resources: list[DockerResource], runner: Runner = _run) -> None:
    removers = {
        "container": ["docker", "rm", "-fv"],
        "network": ["docker", "network", "rm"],
        "volume": ["docker", "volume", "rm"],
        "image": ["docker", "image", "rm"],
    }
    for resource in resources:
        if resource.kind not in removers:
            raise RuntimeError(f"unsupported Docker resource kind: {resource.kind}")
        _revalidate_ownership(resource, runner)
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

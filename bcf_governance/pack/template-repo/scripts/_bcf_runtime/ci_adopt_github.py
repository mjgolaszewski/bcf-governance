"""Transactional GitHub reference-topology adopter."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import shlex
from typing import Any

import yaml

from .ci_github import DISPATCH_EVENTS, topology_document
from .governance_install.transaction import apply_transaction


MANAGED_PATHS = (
    ".github/workflows/bcf-exact-main.yml",
    ".github/workflows/bcf-exact-ref.yml",
    ".github/workflows/bcf-trusted-finalizer.yml",
    ".github/workflows/bcf-status-publisher.yml",
    "governance/github-ci-topology.yml",
)


class GithubAdoptionError(ValueError):
    """Raised before mutation when GitHub CI adoption is ambiguous or unsafe."""


@dataclass(frozen=True)
class GithubAdoptionResult:
    status: str
    changed_paths: tuple[str, ...]


def _labels(values: tuple[str, ...]) -> str | list[str]:
    return values[0] if len(values) == 1 else list(values)


def _workflow(payload: dict[str, Any]) -> bytes:
    return yaml.safe_dump(payload, sort_keys=False, width=120).encode("utf-8")


def _trusted_step(command: str) -> list[dict[str, str]]:
    return [{"name": "Run trusted preinstalled BCF control", "run": command}]


def render_github_adoption(
    *,
    default_branch: str,
    candidate_labels: tuple[str, ...],
    trusted_labels: tuple[str, ...],
    producer_argv: tuple[str, ...],
) -> dict[str, bytes]:
    """Render the closed reference topology without reading a target repository."""

    if not default_branch or any(value in default_branch for value in ("..", " ", "\\")):
        raise GithubAdoptionError("default branch is unsafe")
    if not producer_argv or any(not value for value in producer_argv):
        raise GithubAdoptionError("producer argv must be exact and non-empty")
    topology = topology_document(
        candidate_labels=candidate_labels, trusted_labels=trusted_labels
    )
    topology["default_branch"] = default_branch
    topology["producer_argv"] = list(producer_argv)
    exact_main = {
        "name": "bcf/exact-main-kickoff",
        "on": {"push": {"branches": [default_branch]}},
        "permissions": {"actions": "write", "contents": "read"},
        "jobs": {
            "kickoff": {
                "runs-on": _labels(trusted_labels),
                "steps": _trusted_step(
                    "bcf ci-github kickoff --repository \"$GITHUB_REPOSITORY\" --sha \"$GITHUB_SHA\""
                ),
            }
        },
    }
    exact_ref = {
        "name": "bcf/exact-ref-worker",
        "on": {"repository_dispatch": {"types": [DISPATCH_EVENTS[0]]}},
        "permissions": {"contents": "read"},
        "jobs": {
            "producer": {
                "runs-on": _labels(candidate_labels),
                "timeout-minutes": 360,
                "steps": [
                    {
                        "uses": "actions/checkout@v4",
                        "with": {
                            "ref": "${{ github.event.client_payload.checkout_sha }}",
                            "persist-credentials": False,
                        },
                    },
                    {"name": "Run exact producer argv", "run": shlex.join(producer_argv)},
                ],
            }
        },
    }
    finalizer = {
        "name": "bcf/trusted-finalizer",
        "on": {"workflow_run": {"workflows": ["bcf/exact-ref-worker"], "types": ["completed"]}},
        "permissions": {"actions": "read", "contents": "read"},
        "jobs": {
            "finalize": {
                "runs-on": _labels(trusted_labels),
                "steps": _trusted_step(
                    "bcf ci-github finalize --repository \"$GITHUB_REPOSITORY\" --run-id \"${{ github.event.workflow_run.id }}\""
                ),
            }
        },
    }
    publisher = {
        "name": "bcf/status-publisher",
        "on": {"repository_dispatch": {"types": [DISPATCH_EVENTS[2]]}},
        "permissions": {"actions": "read", "contents": "read", "statuses": "write"},
        "jobs": {
            "publish": {
                "runs-on": _labels(trusted_labels),
                "steps": _trusted_step(
                    "bcf ci-github publish --repository \"$GITHUB_REPOSITORY\" --run-id \"${{ github.event.client_payload.run_id }}\""
                ),
            }
        },
    }
    return {
        ".github/workflows/bcf-exact-main.yml": _workflow(exact_main),
        ".github/workflows/bcf-exact-ref.yml": _workflow(exact_ref),
        ".github/workflows/bcf-trusted-finalizer.yml": _workflow(finalizer),
        ".github/workflows/bcf-status-publisher.yml": _workflow(publisher),
        "governance/github-ci-topology.yml": _workflow(topology),
    }


def plan_github_adoption(
    repo_root: Path,
    *,
    desired: dict[str, bytes],
) -> GithubAdoptionResult:
    unexpected = sorted(set(desired) - set(MANAGED_PATHS))
    if unexpected:
        raise GithubAdoptionError(f"adopter received unmanaged paths: {unexpected}")
    changed: list[str] = []
    conflicts: list[str] = []
    for relative, content in desired.items():
        path = repo_root / relative
        if path.is_symlink():
            raise GithubAdoptionError(f"managed path is a symlink: {relative}")
        if path.exists() and not path.is_file():
            raise GithubAdoptionError(f"managed path is not a regular file: {relative}")
        if not path.exists():
            changed.append(relative)
        elif path.read_bytes() != content:
            conflicts.append(relative)
    if conflicts:
        raise GithubAdoptionError(
            "existing managed GitHub paths differ; resolve before adoption: "
            + ", ".join(conflicts)
        )
    return GithubAdoptionResult(
        status="actionable" if changed else "clean", changed_paths=tuple(sorted(changed))
    )


def apply_github_adoption(repo_root: Path, *, desired: dict[str, bytes]) -> GithubAdoptionResult:
    """Validate the complete plan before an atomic managed-path transaction."""

    planned = plan_github_adoption(repo_root, desired=desired)
    if not planned.changed_paths:
        return planned

    def mutate(shadow: Path) -> None:
        for relative, content in desired.items():
            path = shadow / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(content)

    apply_transaction(repo_root, managed_paths=MANAGED_PATHS, mutate_shadow=mutate)
    verified = plan_github_adoption(repo_root, desired=desired)
    if verified.status != "clean":
        raise GithubAdoptionError("GitHub adoption transaction did not converge")
    return GithubAdoptionResult(status="changed", changed_paths=planned.changed_paths)

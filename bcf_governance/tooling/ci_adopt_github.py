"""Transactional GitHub reference-topology adopter."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import re
import shlex
from typing import Any

import yaml

from .ci_github import DISPATCH_EVENTS, topology_document
from .ci_github_actions import action_pin
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


ACTIVATION_EXPRESSION = "${{ vars.BCF_CI_AUTHORITY_ENABLED == 'true' }}"
EXACT_MAIN_PATH = ".github/workflows/bcf-exact-main.yml"
EXACT_REF_PATH = ".github/workflows/bcf-exact-ref.yml"
FINALIZER_PATH = ".github/workflows/bcf-trusted-finalizer.yml"
PUBLISHER_PATH = ".github/workflows/bcf-status-publisher.yml"


def _controller_command(arguments: str, controller_commit: str | None) -> str:
    if controller_commit is None:
        return f"bcf ci-github {arguments}"
    if not re.fullmatch(r"[a-f0-9]{40}", controller_commit):
        raise GithubAdoptionError("controller commit must be an exact Git SHA")
    return "\n".join(
        (
            'control_root="${RUNNER_TOOL_CACHE%/}/bcf-governance/$BCF_CONTROL_COMMIT"',
            'test -d "$control_root"',
            'test ! -L "$control_root"',
            'test -x "$control_root/bin/bcf"',
            f'"$control_root/bin/bcf" ci-github {arguments}',
        )
    )


def _trusted_steps(
    *, name: str, command: str, controller_commit: str | None
) -> list[dict[str, Any]]:
    steps: list[dict[str, Any]] = []
    if controller_commit is not None:
        steps.append(
            {
                "name": "Restore the trusted controller interpreter environment",
                "uses": action_pin("setup-python"),
                "with": {"python-version": "3.12"},
            }
        )
    steps.append({"name": name, "shell": "bash", "run": f"set -euo pipefail\n{command}"})
    return steps


def render_github_control_plane(
    *,
    default_branch: str,
    candidate_labels: tuple[str, ...],
    trusted_labels: tuple[str, ...],
    producer_workflow_names: tuple[str, ...],
    dispatch_exact_ref: bool = False,
    controller_commit: str | None = None,
) -> dict[str, bytes]:
    """Render acyclic admission, callback, and publication workflows."""

    if not default_branch or any(value in default_branch for value in ("..", " ", "\\")):
        raise GithubAdoptionError("default branch is unsafe")
    if (
        not producer_workflow_names
        or len(set(producer_workflow_names)) != len(producer_workflow_names)
        or any(not value or "\n" in value or "\r" in value for value in producer_workflow_names)
    ):
        raise GithubAdoptionError("producer workflow names must be unique and non-empty")
    topology = topology_document(
        candidate_labels=candidate_labels, trusted_labels=trusted_labels
    )
    if not dispatch_exact_ref:
        kickoff_role = next(
            role for role in topology["roles"] if role["id"] == "exact-main-kickoff"
        )
        kickoff_role["permissions"] = ["actions:read", "contents:read"]
    topology["default_branch"] = default_branch
    topology["producer_workflows"] = list(producer_workflow_names)
    topology["activation_variable"] = "BCF_CI_AUTHORITY_ENABLED"
    topology["dispatch_exact_ref"] = dispatch_exact_ref
    if controller_commit is not None:
        topology["controller_commit"] = controller_commit
    control_env = (
        {"BCF_CONTROL_COMMIT": controller_commit} if controller_commit is not None else {}
    )
    kickoff_arguments = (
        'kickoff --repository "$GITHUB_REPOSITORY" --sha "$GITHUB_SHA" '
        f"--control-workflow-path {EXACT_MAIN_PATH}"
        + (" --dispatch-exact-ref" if dispatch_exact_ref else "")
    )
    exact_main = {
        "name": "bcf/exact-main-admission",
        "on": {"push": {"branches": [default_branch]}},
        "permissions": {
            "actions": "write" if dispatch_exact_ref else "read",
            "contents": "read",
        },
        "env": control_env,
        "jobs": {
            "kickoff": {
                "name": "Authenticate exact-main admission",
                "if": ACTIVATION_EXPRESSION,
                "runs-on": _labels(trusted_labels),
                "timeout-minutes": 5,
                "steps": _trusted_steps(
                    name="Authenticate the exact default-branch commit",
                    command=_controller_command(kickoff_arguments, controller_commit),
                    controller_commit=controller_commit,
                ),
            }
        },
    }
    trigger_names = ["bcf/exact-main-admission", *producer_workflow_names]
    finalizer_arguments = (
        'finalize-callback --repository "$GITHUB_REPOSITORY" --resolve-control-run '
        f"--control-workflow-path {EXACT_MAIN_PATH} "
        f"--collector-workflow-path {FINALIZER_PATH} "
        '--output "$RUNNER_TEMP/bcf-trusted-callback"'
    )
    finalizer_steps = _trusted_steps(
        name="Reconstruct authenticated provider state",
        command=_controller_command(finalizer_arguments, controller_commit),
        controller_commit=controller_commit,
    )
    finalizer_steps.append(
        {
            "name": "Upload the immutable trusted callback envelope",
            "uses": action_pin("upload-artifact"),
            "with": {
                "name": "bcf-trusted-callback-${{ github.run_id }}-${{ github.run_attempt }}",
                "path": "${{ runner.temp }}/bcf-trusted-callback",
                "if-no-files-found": "error",
                "retention-days": 30,
            },
        }
    )
    finalizer = {
        "name": "bcf/trusted-evidence-finalizer",
        "on": {"workflow_run": {"workflows": trigger_names, "types": ["completed"]}},
        "permissions": {"actions": "read", "contents": "read"},
        "env": control_env,
        "jobs": {
            "finalize": {
                "name": "Reconstruct exact-main producer evidence",
                "if": ACTIVATION_EXPRESSION,
                "runs-on": _labels(trusted_labels),
                "timeout-minutes": 5,
                "steps": finalizer_steps,
            }
        },
    }
    publisher_steps: list[dict[str, Any]] = []
    if controller_commit is not None:
        publisher_steps.append(
            {
                "name": "Restore the trusted controller interpreter environment",
                "uses": action_pin("setup-python"),
                "with": {"python-version": "3.12"},
            }
        )
    publisher_steps.extend(
        (
            {
                "name": "Download only the triggering finalizer callback",
                "uses": action_pin("download-artifact"),
                "with": {
                    "name": "bcf-trusted-callback-${{ github.event.workflow_run.id }}-${{ github.event.workflow_run.run_attempt }}",
                    "github-token": "${{ github.token }}",
                    "repository": "${{ github.repository }}",
                    "run-id": "${{ github.event.workflow_run.id }}",
                    "path": "${{ runner.temp }}/bcf-trusted-callback",
                },
            },
            {
                "name": "Verify callback and publish authoritative exact-main status",
                "shell": "bash",
                "run": "set -euo pipefail\n"
                + _controller_command(
                    'publish-callback --repository "$GITHUB_REPOSITORY" '
                    '--callback "$RUNNER_TEMP/bcf-trusted-callback" '
                    '--target-url "https://github.com/$GITHUB_REPOSITORY/actions/runs/${{ github.event.workflow_run.id }}" '
                    '--collector-run-id "${{ github.event.workflow_run.id }}" '
                    '--collector-run-attempt "${{ github.event.workflow_run.run_attempt }}" '
                    f"--collector-workflow-path {FINALIZER_PATH}",
                    controller_commit,
                ),
            },
        )
    )
    publisher = {
        "name": "bcf/exact-main-status-publisher",
        "on": {
            "workflow_run": {
                "workflows": ["bcf/trusted-evidence-finalizer"],
                "types": ["completed"],
            }
        },
        "permissions": {"actions": "read", "contents": "read", "statuses": "write"},
        "env": control_env,
        "jobs": {
            "publish": {
                "name": "Publish verified exact-main status",
                "if": ACTIVATION_EXPRESSION,
                "runs-on": _labels(trusted_labels),
                "timeout-minutes": 5,
                "steps": publisher_steps,
            }
        },
    }
    return {
        EXACT_MAIN_PATH: _workflow(exact_main),
        FINALIZER_PATH: _workflow(finalizer),
        PUBLISHER_PATH: _workflow(publisher),
        "governance/github-ci-topology.yml": _workflow(topology),
    }


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
    rendered = render_github_control_plane(
        default_branch=default_branch,
        candidate_labels=candidate_labels,
        trusted_labels=trusted_labels,
        producer_workflow_names=("bcf/exact-ref-worker",),
        dispatch_exact_ref=True,
    )
    topology = yaml.safe_load(rendered["governance/github-ci-topology.yml"])
    topology.pop("producer_workflows")
    topology["producer_argv"] = list(producer_argv)
    exact_ref = {
        "name": "bcf/exact-ref-worker",
        "on": {"repository_dispatch": {"types": [DISPATCH_EVENTS[0]]}},
        "permissions": {"contents": "read"},
        "jobs": {
            "producer": {
                "name": "Execute exact candidate producer",
                "if": ACTIVATION_EXPRESSION,
                "runs-on": _labels(candidate_labels),
                "timeout-minutes": 360,
                "steps": [
                    {
                        "uses": action_pin("checkout"),
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
    return {
        **rendered,
        EXACT_REF_PATH: _workflow(exact_ref),
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

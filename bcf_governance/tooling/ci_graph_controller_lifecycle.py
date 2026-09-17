"""Resolve trusted-controller lifecycle and job requirements once."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
import hashlib
import json
from pathlib import Path
import re
import subprocess
from typing import Any

from jsonschema import Draft202012Validator

from .ci_graph_errors import CIGraphError


AUTHORIZATION_SCHEMA = Path("schemas/recovery-reentry-authorization.schema.json")
_SHA = re.compile(r"^[a-f0-9]{40}$")


class ControllerLifecycleState(str, Enum):
    ORDINARY_CURRENT = "ordinary-current"
    ORDINARY_PENDING_ROTATION = "ordinary-pending-rotation"
    AUTHENTICATED_RECOVERY_REENTRY = "authenticated-recovery-reentry"


class ControllerRequirement(str, Enum):
    CURRENT = "current"
    CURRENT_OR_RECOVERY_REENTRY = "current-or-recovery-reentry"


@dataclass(frozen=True)
class ControllerLifecycle:
    state: ControllerLifecycleState
    target_commit: str
    installed_commit: str
    recovery_reentry_condition: str | None = None

    @property
    def current(self) -> bool:
        return self.state is ControllerLifecycleState.ORDINARY_CURRENT


def _git(repo_root: Path, *args: str) -> str:
    result = subprocess.run(
        ["git", *args],
        cwd=repo_root,
        check=False,
        capture_output=True,
        text=True,
    )
    if result.returncode:
        raise CIGraphError("recovery re-entry source identity is unavailable")
    return result.stdout.strip()


def _authorization(repo_root: Path, value: object) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise CIGraphError("recovery re-entry authorization must be one object")
    schema_path = repo_root / AUTHORIZATION_SCHEMA
    try:
        schema = json.loads(schema_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise CIGraphError("recovery re-entry authorization schema is unavailable") from exc
    errors = sorted(
        Draft202012Validator(schema).iter_errors(value),
        key=lambda item: list(item.path),
    )
    if errors:
        location = ".".join(str(item) for item in errors[0].absolute_path) or "<root>"
        raise CIGraphError(
            f"recovery re-entry authorization schema violation at {location}: "
            f"{errors[0].message}"
        )
    return value


def resolve_controller_lifecycle(
    repo_root: Path, runner_security: dict[str, Any]
) -> ControllerLifecycle:
    pin = runner_security.get("trusted_controller_artifact")
    installation = runner_security.get("trusted_controller_installation")
    if not isinstance(pin, dict) or not isinstance(installation, dict):
        raise CIGraphError("self-governance policy lacks compiled controller custody")
    target = str(pin.get("BCF_BOOTSTRAP_COMMIT_SHA", ""))
    installed = str(installation.get("installed_commit_sha", ""))
    if _SHA.fullmatch(target) is None or _SHA.fullmatch(installed) is None:
        raise CIGraphError("self-governance controller custody is not exact")
    raw_authorization = runner_security.get("trusted_controller_recovery_reentry")
    if target == installed:
        if raw_authorization is not None:
            raise CIGraphError(
                "ordinary-current custody cannot retain active recovery re-entry authority"
            )
        return ControllerLifecycle(
            ControllerLifecycleState.ORDINARY_CURRENT, target, installed
        )
    if raw_authorization is None:
        return ControllerLifecycle(
            ControllerLifecycleState.ORDINARY_PENDING_ROTATION, target, installed
        )

    authorization = _authorization(repo_root, raw_authorization)
    binding = str(authorization["binding_sha256"])
    bound = {key: item for key, item in authorization.items() if key != "binding_sha256"}
    expected_binding = hashlib.sha256(
        json.dumps(bound, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    if binding != expected_binding:
        raise CIGraphError("recovery re-entry authorization binding is invalid")
    repository_id = str(pin.get("BCF_BOOTSTRAP_REPOSITORY_ID", ""))
    source_commit = str(authorization["authorized_source"]["commit"])
    source_tree = str(authorization["authorized_source"]["tree"])
    subject = authorization["recovery_subject"]
    provenance = authorization["provenance"]
    expected = {
        "repository_id": repository_id,
        "installed_controller_commit": installed,
        "recovery_subject_commit": str(installation.get("subject_commit_sha", "")),
        "recovery_subject_tree": str(installation.get("subject_tree_sha", "")),
        "install_run_id": str(installation.get("bootstrap_run_id", "")),
        "install_run_attempt": str(installation.get("bootstrap_run_attempt", "")),
        "probe_run_id": str(installation.get("probe_run_id", "")),
        "probe_run_attempt": str(installation.get("probe_run_attempt", "")),
    }
    actual = {
        "repository_id": str(authorization["repository_id"]),
        "installed_controller_commit": str(
            authorization["installed_controller_commit"]
        ),
        "recovery_subject_commit": str(subject["commit"]),
        "recovery_subject_tree": str(subject["tree"]),
        "install_run_id": str(provenance["install_run_id"]),
        "install_run_attempt": str(provenance["install_run_attempt"]),
        "probe_run_id": str(provenance["probe_run_id"]),
        "probe_run_attempt": str(provenance["probe_run_attempt"]),
    }
    if actual != expected:
        raise CIGraphError(
            "recovery re-entry authorization contradicts installed controller custody"
        )
    if _git(repo_root, "rev-parse", f"{source_commit}^{{tree}}") != source_tree:
        raise CIGraphError("recovery re-entry source commit and tree do not match")
    ancestor = subprocess.run(
        ["git", "merge-base", "--is-ancestor", source_commit, "HEAD"],
        cwd=repo_root,
        check=False,
        capture_output=True,
        text=True,
    )
    if ancestor.returncode != 0:
        raise CIGraphError("recovery re-entry source is not an ancestor of this projection")
    condition = (
        "${{ github.repository_id == "
        f"{repository_id} && github.event.repository.id == {repository_id} && "
        f"github.event.before == '{source_commit}' }}}}"
    )
    return ControllerLifecycle(
        ControllerLifecycleState.AUTHENTICATED_RECOVERY_REENTRY,
        target,
        installed,
        condition,
    )


def controller_requirement_condition(
    lifecycle: ControllerLifecycle, requirement: str | None
) -> str | None:
    if requirement is None:
        return None
    try:
        parsed = ControllerRequirement(requirement)
    except ValueError as exc:
        raise CIGraphError(f"unknown controller requirement: {requirement}") from exc
    if lifecycle.current:
        return None
    if parsed is ControllerRequirement.CURRENT:
        return "${{ false }}"
    if (
        lifecycle.state is ControllerLifecycleState.AUTHENTICATED_RECOVERY_REENTRY
        and lifecycle.recovery_reentry_condition is not None
    ):
        return lifecycle.recovery_reentry_condition
    return "${{ false }}"

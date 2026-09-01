"""Mechanically resolve the provider inputs for one release authorization.

Copyright 2026 Michael Golaszewski.
Licensed under the MIT License.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .ci_authority_contracts import authority_role_workflow
from .ci_github_api import GitHubAPI
from .ci_github_artifacts import (
    ProviderArtifact,
    provider_artifact_reference,
    provider_artifact_reference_keys,
    resolve_role_artifact,
)
from .ci_github_authority import authenticate_role_job_inventory, load_authority
from .ci_github_bundle import write_exclusive
from .ci_github_identity import GitHubControllerError, MainIdentity, resolve_main
from .ci_github_membership import select_latest_admission
from .ci_self_controller import resolve_self_controller_artifact


RELEASE_INPUT_KEYS = {
    "schema_version",
    "authority_contract_version",
    "subject",
    "exact_main",
    "certification_artifact",
    "controller",
}


def _exact_finalizer_run(
    api: GitHubAPI,
    *,
    repository: str,
    main: MainIdentity,
    authority: dict[str, Any],
) -> tuple[str, int]:
    workflow = authority_role_workflow(authority, "finalizer")
    runs = api.workflow_runs(
        repository,
        workflow["workflow_id"],
        head_sha=main.checkout_sha,
        event="workflow_run",
    )
    exact = [
        run
        for run in runs
        if str(run.get("head_sha")) == main.checkout_sha
        and str(run.get("head_branch")) == main.default_branch
        and str(run.get("repository", {}).get("id")) == main.repository_id
        and str(run.get("head_repository", {}).get("id")) == main.repository_id
        and str(run.get("event")) == "workflow_run"
    ]
    if not exact:
        raise GitHubControllerError("no exact-main finalizer run exists")
    selected = max(
        exact,
        key=lambda value: (
            int(str(value.get("id", 0))),
            int(str(value.get("run_attempt", 0))),
        ),
    )
    identity, _ = authenticate_role_job_inventory(
        api,
        repository=repository,
        main=main,
        authority=authority,
        role="finalizer",
        run_id=selected.get("id"),
        run_attempt=selected.get("run_attempt"),
        require_success=True,
        require_terminal=True,
    )
    return identity.run_id, identity.run_attempt


def resolve_release_authorization_inputs(
    api: GitHubAPI,
    *,
    repository: str,
    output_path: Path,
) -> dict[str, Any]:
    """Resolve release inputs without caller-selected provider identities."""

    main = resolve_main(api, repository)
    authority = load_authority(api, repository, main, required_version="1.1")
    admission_run_id, admission_attempt = select_latest_admission(
        api, repository=repository, main=main, authority=authority
    )
    controller_subject, controller_artifact = resolve_self_controller_artifact(
        api, repository=repository
    )
    if controller_subject != {
        "repository_id": main.repository_id,
        "commit_sha": main.checkout_sha,
        "tree_sha": main.tree_sha,
    } or (
        controller_artifact.run_id != admission_run_id
        or controller_artifact.run_attempt != admission_attempt
    ):
        raise GitHubControllerError("release controller is not from the newest exact main")
    finalizer_run_id, finalizer_attempt = _exact_finalizer_run(
        api, repository=repository, main=main, authority=authority
    )
    certification = resolve_role_artifact(
        api,
        repository=repository,
        main=main,
        authority=authority,
        role="finalizer",
        run_id=finalizer_run_id,
        run_attempt=finalizer_attempt,
        artifact_name=(
            f"bcf-exact-main-certification-{finalizer_run_id}-{finalizer_attempt}"
        ),
        require_success=True,
    )
    payload = {
        "schema_version": "1.0",
        "authority_contract_version": "1.1",
        "subject": {
            "commit_sha": main.checkout_sha,
            "tree_sha": main.tree_sha,
        },
        "exact_main": {
            "run_id": admission_run_id,
            "run_attempt": admission_attempt,
        },
        "certification_artifact": provider_artifact_reference(certification),
        "controller": {
            **provider_artifact_reference(controller_artifact),
            "commit_sha": main.checkout_sha,
            "tree_sha": main.tree_sha,
        },
    }
    write_exclusive(output_path, payload)
    return payload


def load_release_authorization_inputs(path: Path) -> dict[str, Any]:
    """Decode only the exact resolver-owned release-input representation."""

    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, ValueError) as exc:
        raise GitHubControllerError("release authorization inputs are invalid") from exc
    if not isinstance(value, dict) or set(value) != RELEASE_INPUT_KEYS:
        raise GitHubControllerError("release authorization input inventory is not exact")
    if value.get("schema_version") != "1.0" or (
        value.get("authority_contract_version") != "1.1"
    ):
        raise GitHubControllerError("release authorization input version is unsupported")
    subject = value.get("subject")
    exact_main = value.get("exact_main")
    certification = value.get("certification_artifact")
    controller = value.get("controller")
    if not all(isinstance(item, dict) for item in (
        subject, exact_main, certification, controller
    )):
        raise GitHubControllerError("release authorization input sections are invalid")
    provider_artifact_reference(certification, label="certification artifact")
    controller_keys = provider_artifact_reference_keys() | {"commit_sha", "tree_sha"}
    if set(controller) != controller_keys:
        raise GitHubControllerError("controller artifact identity is not exact")
    provider_artifact_reference(
        {key: controller[key] for key in provider_artifact_reference_keys()},
        label="controller artifact",
    )
    return value


def release_input_outputs(value: dict[str, Any]) -> dict[str, object]:
    """Project the minimal scalar download coordinates for workflow wiring."""

    certification = value["certification_artifact"]
    controller = value["controller"]
    return {
        "subject_commit": value["subject"]["commit_sha"],
        "subject_tree": value["subject"]["tree_sha"],
        "certification_artifact_id": certification["artifact_id"],
        "certification_run_id": certification["run_id"],
        "controller_artifact_id": controller["artifact_id"],
        "controller_run_id": controller["run_id"],
    }

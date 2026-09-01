"""Canonical loading and version selection for GitHub CI authority."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

from .ci_authority_contracts import (
    authority_role_jobs,
    authority_role_workflow,
    validate_ci_contract,
)
from .ci_github_api import GitHubAPI
from .ci_github_identity import (
    GitHubControllerError,
    MainIdentity,
    authenticate_trusted_run,
    positive_int,
)


def packaged_repo_root() -> Path:
    """Return the installed, schema-bearing BCF pack root."""

    root = Path(__file__).resolve().parents[1] / "pack/template-repo"
    if not (root / "schemas/ci-authority.schema.json").is_file():
        raise GitHubControllerError("installed BCF package lacks CI authority schemas")
    return root


def load_authority(
    api: GitHubAPI,
    repository: str,
    main: MainIdentity,
    *,
    required_version: str | None = None,
) -> dict[str, Any]:
    """Load and validate exact-main authority from authenticated provider bytes."""

    content = api.content(repository, "governance/ci-authority.yml", ref=main.checkout_sha)
    try:
        payload = yaml.safe_load(content.content.decode("utf-8"))
    except (UnicodeDecodeError, yaml.YAMLError) as exc:
        raise GitHubControllerError("trusted CI authority document is invalid YAML") from exc
    if not isinstance(payload, dict):
        raise GitHubControllerError("trusted CI authority document must contain a mapping")
    validate_ci_contract(packaged_repo_root(), "authority", payload)
    if payload["repository"] != {
        "provider": "github",
        "repository_id": main.repository_id,
    }:
        raise GitHubControllerError("CI authority repository identity is not current repository")
    if required_version is not None and payload.get("schema_version") != required_version:
        raise GitHubControllerError(
            f"operation requires CI authority contract version {required_version}"
        )
    return payload


def authenticate_role_run(
    api: GitHubAPI,
    *,
    repository: str,
    main: MainIdentity,
    authority: dict[str, Any],
    role: str,
    run_id: object,
    run_attempt: object,
    require_success: bool,
):
    """Authenticate one role against the single v1.1 workflow registry."""

    if authority.get("schema_version") != "1.1":
        raise GitHubControllerError(
            f"{role} requires CI authority contract version 1.1"
        )
    workflow = authority_role_workflow(authority, role)
    numeric_run_id = positive_int(run_id, field="trusted role run ID")
    run = api.run(repository, numeric_run_id)
    event = str(run.get("event", ""))
    if event not in workflow["allowed_events"]:
        raise GitHubControllerError(f"{role} run event is not admitted by authority")
    return authenticate_trusted_run(
        api,
        repository=repository,
        main=main,
        run_id=numeric_run_id,
        run_attempt=run_attempt,
        workflow_path=str(workflow["active_path"]),
        expected_event=event,
        require_success=require_success,
        expected_workflow_id=workflow["workflow_id"],
        expected_workflow_sha256=str(workflow["trusted_workflow_sha256"]),
        expected_workflow_blob_oid=workflow["trusted_workflow_blob_oid"],
        expected_workflow_definition_commit=workflow[
            "trusted_workflow_definition_commit"
        ],
    )


def authenticate_role_job_inventory(
    api: GitHubAPI,
    *,
    repository: str,
    main: MainIdentity,
    authority: dict[str, Any],
    role: str,
    run_id: object,
    run_attempt: object,
    require_success: bool,
    require_terminal: bool,
):
    """Authenticate one role and its exact provider job inventory together."""

    identity = authenticate_role_run(
        api,
        repository=repository,
        main=main,
        authority=authority,
        role=role,
        run_id=run_id,
        run_attempt=run_attempt,
        require_success=require_success,
    )
    jobs = api.jobs(repository, identity.run_id, attempt=identity.run_attempt)
    names = [str(value.get("name", "")) for value in jobs]
    expected = [str(value["job_id"]) for value in authority_role_jobs(authority, role)]
    names_set = set(names)
    expected_set = set(expected)
    if (
        not names
        or not all(names)
        or len(names_set) != len(names)
        or names_set - expected_set
        or (require_terminal and names_set != expected_set)
    ):
        raise GitHubControllerError("privileged workflow exact job inventory does not match authority")
    if require_terminal and any(str(value.get("status")) != "completed" for value in jobs):
        raise GitHubControllerError("privileged workflow job inventory is not terminal")
    if require_success and any(str(value.get("conclusion")) != "success" for value in jobs):
        raise GitHubControllerError("privileged workflow job inventory is not successful")
    return identity, jobs

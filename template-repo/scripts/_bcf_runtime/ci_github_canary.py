"""Mechanically observe isolated GitHub CI authority canaries."""

from __future__ import annotations

from typing import Any

from .ci_authority_contracts import authority_role_jobs
from .ci_authority_decisions import StatusConclusion, StatusContext
from .ci_github_api import GitHubAPI
from .ci_github_authority import (
    authenticate_role_job_inventory,
    authenticate_role_run,
    load_authority,
)
from .ci_github_identity import GitHubControllerError, resolve_main
from .ci_github_membership import admission_ordinal
from .ci_github_status import publish_observation


def _canary_conclusion(
    authority: dict[str, Any], jobs: tuple[dict[str, Any], ...]
) -> tuple[StatusConclusion, str]:
    roles = {
        str(value["job_id"]): str(value["role"])
        for value in authority_role_jobs(authority, "authority_canary")
    }
    required = [
        value
        for value in jobs
        if roles[str(value["name"])] in {"admission", "producer"}
    ]
    if any(str(value.get("status")) != "completed" for value in required):
        return StatusConclusion.FAILURE, "required canary job was not terminal"
    if any(str(value.get("conclusion")) != "success" for value in required):
        return StatusConclusion.FAILURE, "admission or producer failed"
    return StatusConclusion.SUCCESS, "exact current-attempt producers succeeded"


def admit_authority_canary(
    api: GitHubAPI,
    *,
    repository: str,
    expected_sha: str,
    run_id: object,
    run_attempt: object,
    target_url: str,
) -> dict[str, Any]:
    """Authenticate the current canary run and publish isolated pending authority."""

    main = resolve_main(api, repository)
    if expected_sha != main.checkout_sha:
        raise GitHubControllerError("canary subject is not current default main")
    authority = load_authority(api, repository, main, required_version="1.1")
    identity = authenticate_role_run(
        api,
        repository=repository,
        main=main,
        authority=authority,
        role="authority_canary",
        run_id=run_id,
        run_attempt=run_attempt,
        require_success=False,
    )
    ordinal = admission_ordinal(identity.run_id, identity.run_attempt, 1)
    status = publish_observation(
        api,
        repository=repository,
        subject_sha=main.checkout_sha,
        current_default_main_sha=main.checkout_sha,
        admission_ordinal=ordinal,
        control_plane_attempt=identity.run_attempt,
        conclusion=StatusConclusion.PENDING,
        description="BCF authority canary pending",
        target_url=target_url,
        status_context=StatusContext.AUTHORITY_CANARY,
    )
    return {
        **status,
        "tree_sha": main.tree_sha,
        "canary_run_id": identity.run_id,
        "canary_run_attempt": identity.run_attempt,
    }


def observe_authority_canary(
    api: GitHubAPI,
    *,
    repository: str,
    expected_sha: str,
    run_id: object,
    run_attempt: object,
    target_url: str,
) -> dict[str, Any]:
    """Publish a terminal decision from one exact canary run and attempt only."""

    main = resolve_main(api, repository)
    if expected_sha != main.checkout_sha:
        raise GitHubControllerError("canary subject is not current default main")
    authority = load_authority(api, repository, main, required_version="1.1")
    identity, jobs = authenticate_role_job_inventory(
        api,
        repository=repository,
        main=main,
        authority=authority,
        role="authority_canary",
        run_id=run_id,
        run_attempt=run_attempt,
        require_success=False,
        require_terminal=False,
    )
    conclusion, reason = _canary_conclusion(authority, jobs)
    ordinal = admission_ordinal(identity.run_id, identity.run_attempt, 1)
    status = publish_observation(
        api,
        repository=repository,
        subject_sha=main.checkout_sha,
        current_default_main_sha=main.checkout_sha,
        admission_ordinal=ordinal,
        control_plane_attempt=identity.run_attempt,
        conclusion=conclusion,
        description=f"BCF authority canary: {reason}",
        target_url=target_url,
        status_context=StatusContext.AUTHORITY_CANARY,
    )
    return {
        **status,
        "conclusion": conclusion.value,
        "tree_sha": main.tree_sha,
        "canary_run_id": identity.run_id,
        "canary_run_attempt": identity.run_attempt,
    }

"""Provider-role authentication for active trusted release collection."""

from __future__ import annotations

from typing import Any

from .ci_github_api import GitHubAPI
from .ci_github_authority import (
    authenticate_active_role_job_inventory,
    authenticate_role_job_inventory,
)
from .ci_github_identity import GitHubControllerError, MainIdentity


def authenticate_release_collection_roles(
    api: GitHubAPI,
    *,
    repository: str,
    main: MainIdentity,
    authority: dict[str, Any],
    authorization: dict[str, Any],
    build: dict[str, Any],
    verification: dict[str, Any],
    collector_run_id: object,
    collector_run_attempt: object,
):
    """Authenticate terminal inputs and the sole active collector attempt."""

    collector, _ = authenticate_active_role_job_inventory(
        api,
        repository=repository,
        main=main,
        authority=authority,
        role="release_collector",
        run_id=collector_run_id,
        run_attempt=collector_run_attempt,
    )
    for role, payload, key in (
        ("release_authorizer", authorization, "authorizer"),
        ("release_build", build, "builder"),
    ):
        identity = payload.get(key)
        if not isinstance(identity, dict):
            raise GitHubControllerError(f"{role} identity is missing")
        authenticate_role_job_inventory(
            api,
            repository=repository,
            main=main,
            authority=authority,
            role=role,
            run_id=identity.get("run_id"),
            run_attempt=identity.get("run_attempt"),
            require_success=True,
            require_terminal=True,
        )
    verifier = verification.get("verifier")
    if not isinstance(verifier, dict) or (
        str(verifier.get("run_id")) != collector.run_id
        or int(verifier.get("run_attempt", 0)) != collector.run_attempt
    ):
        raise GitHubControllerError(
            "release verification is not bound to the active collector attempt"
        )
    return collector

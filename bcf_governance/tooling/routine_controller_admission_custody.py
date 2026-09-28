"""Authenticate one exact-main admission's effective controller custody."""

from __future__ import annotations

from typing import Any, Mapping

from .ci_github_identity import GitHubControllerError, MainIdentity, positive_int
from .ci_controller_custody_auth import authenticate_controller_custody
from .controller_custody import (
    compile_controller_custody,
    require_controller_execution,
)


def authenticate_admission_custody(
    api: Any,
    *,
    repository: str,
    main: MainIdentity,
    authority: dict[str, Any],
    admission_run_id: object,
    admission_run_attempt: object,
    effective: Mapping[str, Any],
) -> dict[str, Any]:
    """Require the producer capsule, provider resolution, and executable to agree."""

    custody = authenticate_controller_custody(
        api,
        repository=repository,
        main=main,
        authority=authority,
        run_id=str(positive_int(admission_run_id, field="admission run ID")),
        run_attempt=positive_int(admission_run_attempt, field="admission run attempt"),
    )
    expected = compile_controller_custody(effective, repository=repository)
    if custody != expected:
        raise GitHubControllerError(
            "rotation authority differs from triggering admission custody"
        )
    require_controller_execution(custody)
    return custody

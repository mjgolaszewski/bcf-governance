"""Canonical provider job-inventory projection for authenticated PR evidence."""

from __future__ import annotations

from typing import Any

from .ci_authority_pins import CIAuthorityPinError, compiled_workflow_job_names
from .ci_github_identity import GitHubControllerError


GOVERNANCE_WORKFLOW_PATH = ".github/workflows/governance.yml"


def candidate_governance_job_inventory(
    api: Any, *, repository: str, candidate_sha: str
) -> tuple[str, ...]:
    """Project exact job names from the immutable candidate workflow bytes."""

    raw = api.content(
        repository, GOVERNANCE_WORKFLOW_PATH, ref=candidate_sha
    ).content
    try:
        names = compiled_workflow_job_names(raw)
    except CIAuthorityPinError as exc:
        raise GitHubControllerError(
            f"candidate governance workflow job inventory is invalid: {exc}"
        ) from exc
    if not names or len(set(names)) != len(names):
        raise GitHubControllerError(
            "candidate governance workflow job inventory is ambiguous"
        )
    return names

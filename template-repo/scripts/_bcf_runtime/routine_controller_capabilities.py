"""Typed optional self-recovery capability boundary for ordinary runtimes."""

from __future__ import annotations

from importlib import import_module
from pathlib import Path

from .ci_github_api import GitHubAPI
from .ci_github_identity import GitHubControllerError


def authenticate_optional_normalization(
    api: GitHubAPI, *, repository: str, repo_root: Path,
) -> dict[str, str]:
    """Refuse missing producer authority rather than installing it in adopters."""
    try:
        capability = import_module(".routine_controller_prospective", package=__package__)
    except ModuleNotFoundError as missing:
        raise GitHubControllerError(
            "prospective normalization requires the self-recovery authority runtime"
        ) from missing
    authenticate = getattr(capability, "prospective_normalized_controller_authority", None)
    if not callable(authenticate):
        raise GitHubControllerError("prospective normalization capability is malformed")
    result = authenticate(api, repository=repository, repo_root=repo_root)
    if (not isinstance(result, dict)
            or set(result) != {"controller_commit_sha", "controller_bundle_sha256"}
            or not all(isinstance(value, str) for value in result.values())):
        raise GitHubControllerError("prospective normalization authority is malformed")
    return {str(key): str(value) for key, value in result.items()}

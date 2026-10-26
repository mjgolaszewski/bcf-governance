"""Cheap local and provider parity for canonical workflow authority."""

from __future__ import annotations

import subprocess
from pathlib import Path

from .bootstrap.contracts import GitHubProviderSettings, WorkflowSettings
from .bootstrap.environment import github_provider_settings as _default_github_provider_settings
from .bootstrap.environment import workflow_settings as _default_workflow_settings
from .ci_authority_pins import (
    verify_provider_workflow_authority,
    verify_workflow_authority,
)
from .ci_github_api import GitHubAPI


def _provider_checkout(repo_root: Path, repository: str) -> bool:
    result = subprocess.run(
        ["git", "remote", "get-url", "origin"],
        cwd=repo_root,
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode:
        return False
    remote = result.stdout.strip().removesuffix(".git")
    return remote.endswith("/" + repository) or remote.endswith(":" + repository)


def verify_workflow_authority_preflight(
    repo_root: Path,
    *,
    provider_settings: GitHubProviderSettings | None=None,
    workflow_settings: WorkflowSettings | None=None,
) -> int:
    """Verify bytes always and provider identity in its authenticated checkout."""
    provider_settings = _default_github_provider_settings() if provider_settings is None else provider_settings
    workflow_settings = _default_workflow_settings() if workflow_settings is None else workflow_settings

    authority = Path("governance/ci-authority.yml")
    count = verify_workflow_authority(repo_root, authority_path=authority)
    repository = workflow_settings.repository("")
    token = provider_settings.token()
    if repository and token and _provider_checkout(repo_root, repository):
        verify_provider_workflow_authority(
            repo_root,
            authority_path=authority,
            api=GitHubAPI(
                token=token,
                api_url=provider_settings.api_url(),
            ),
            repository=repository,
        )
    return count

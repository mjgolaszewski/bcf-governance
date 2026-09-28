"""Cheap local and provider parity for canonical workflow authority."""

from __future__ import annotations

import os
from pathlib import Path
import subprocess

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


def verify_workflow_authority_preflight(repo_root: Path) -> int:
    """Verify bytes always and provider identity in its authenticated checkout."""

    authority = Path("governance/ci-authority.yml")
    count = verify_workflow_authority(repo_root, authority_path=authority)
    repository = os.environ.get("GITHUB_REPOSITORY", "")
    token = os.environ.get("GITHUB_TOKEN", "")
    if repository and token and _provider_checkout(repo_root, repository):
        verify_provider_workflow_authority(
            repo_root,
            authority_path=authority,
            api=GitHubAPI(
                token=token,
                api_url=os.environ.get("GITHUB_API_URL", "https://api.github.com"),
            ),
            repository=repository,
        )
    return count

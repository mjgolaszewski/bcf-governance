from __future__ import annotations

from pathlib import Path
import subprocess

import pytest

from bcf_governance.tooling import ci_authority_preflight as preflight
from bcf_governance.tooling.ci_authority_pins import (
    CIAuthorityPinError,
    pin_workflow_authority,
)
from tests.test_ci_authority_pins import Provider, _repository


def test_provider_checkout_rejects_stale_workflow_identity_before_evidence(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    root, commit, _ = _repository(tmp_path)
    subprocess.run(
        ["git", "remote", "add", "origin", "git@github.com:owner/repo.git"],
        cwd=root,
        check=True,
    )
    monkeypatch.setenv("GITHUB_REPOSITORY", "owner/repo")
    monkeypatch.setenv("GITHUB_TOKEN", "test-token")
    monkeypatch.setattr(
        preflight,
        "GitHubAPI",
        lambda **_kwargs: Provider({
            "exact.yml": {
                "id": 2,
                "path": ".github/workflows/exact.yml",
                "state": "active",
            }
        }),
    )
    pin_workflow_authority(
        root,
        authority_path=Path("governance/ci-authority.yml"),
        definition_commit=commit,
        references=("admission",),
        apply=True,
    )

    with pytest.raises(CIAuthorityPinError, match="provider workflow ID mismatched"):
        preflight.verify_workflow_authority_preflight(root)

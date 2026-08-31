from __future__ import annotations

from dataclasses import replace

import pytest

from bcf_governance.tooling.ci_authority_state import (
    CandidateIdentity,
    WorkflowIdentity,
)
from bcf_governance.tooling.ci_github import GithubRunIdentity
from bcf_governance.tooling.ci_github_artifacts import authenticate_role_artifact
from bcf_governance.tooling.ci_github_identity import (
    GitHubControllerError,
    MainIdentity,
)


COMMIT = "a" * 40
TREE = "b" * 40
DIGEST = f"sha256:{'c' * 64}"
MAIN = MainIdentity("101", "main", COMMIT, TREE)
WORKFLOW = WorkflowIdentity(
    provider="github",
    repository_id="101",
    workflow_id="202",
    active_path=".github/workflows/release.yml",
    trusted_workflow_blob_oid="d" * 40,
    trusted_workflow_sha256="e" * 64,
    trusted_workflow_definition_commit="f" * 40,
    event="workflow_dispatch",
)
RUN = GithubRunIdentity(WORKFLOW, CandidateIdentity(COMMIT, TREE), "303", 2)


class _ArtifactAPI:
    def __init__(self) -> None:
        self.artifact = {
            "id": 404,
            "name": "bcf-release-build-a-2",
            "expired": False,
            "digest": DIGEST,
            "workflow_run": {
                "id": 303,
                "repository_id": 101,
                "head_repository_id": 101,
                "head_branch": "main",
                "head_sha": COMMIT,
            },
        }

    def artifacts(self, repository: str, run_id: str):
        return (self.artifact,)


def _authenticate(monkeypatch: pytest.MonkeyPatch, api: _ArtifactAPI):
    monkeypatch.setattr(
        "bcf_governance.tooling.ci_github_artifacts.authenticate_role_run",
        lambda *args, **kwargs: RUN,
    )
    return authenticate_role_artifact(
        api,  # type: ignore[arg-type]
        repository="owner/repo",
        main=MAIN,
        authority={},
        role="release_build",
        run_id="303",
        run_attempt="2",
        artifact_id="404",
        artifact_name="bcf-release-build-a-2",
        artifact_digest=DIGEST,
        require_success=True,
    )


def test_role_artifact_binds_workflow_attempt_provider_digest_and_subject(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    result = _authenticate(monkeypatch, _ArtifactAPI())
    assert result.run_id == "303"
    assert result.run_attempt == 2
    assert result.artifact_id == "404"
    assert result.provider_digest == DIGEST
    assert result.workflow["active_path"] == ".github/workflows/release.yml"


@pytest.mark.parametrize(
    "mutation, message",
    [
        ("digest", "artifact identity"),
        ("expired", "artifact identity"),
        ("repository", "workflow subject"),
        ("branch", "workflow subject"),
        ("sha", "workflow subject"),
        ("duplicate", "artifact identity"),
    ],
)
def test_role_artifact_rejects_provider_identity_mutants(
    monkeypatch: pytest.MonkeyPatch, mutation: str, message: str
) -> None:
    api = _ArtifactAPI()
    if mutation == "digest":
        api.artifact["digest"] = f"sha256:{'0' * 64}"
    elif mutation == "expired":
        api.artifact["expired"] = True
    elif mutation == "repository":
        api.artifact["workflow_run"]["repository_id"] = 999  # type: ignore[index]
    elif mutation == "branch":
        api.artifact["workflow_run"]["head_branch"] = "feature"  # type: ignore[index]
    elif mutation == "sha":
        api.artifact["workflow_run"]["head_sha"] = "0" * 40  # type: ignore[index]
    else:
        artifact = dict(api.artifact)
        api.artifacts = lambda repository, run_id: (api.artifact, artifact)  # type: ignore[method-assign]
    with pytest.raises(GitHubControllerError, match=message):
        _authenticate(monkeypatch, api)


def test_role_artifact_uses_the_authenticated_attempt_identity(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        "bcf_governance.tooling.ci_github_artifacts.authenticate_role_run",
        lambda *args, **kwargs: replace(RUN, run_attempt=3),
    )
    result = authenticate_role_artifact(
        _ArtifactAPI(),  # type: ignore[arg-type]
        repository="owner/repo",
        main=MAIN,
        authority={},
        role="release_build",
        run_id="303",
        run_attempt="3",
        artifact_id="404",
        artifact_name="bcf-release-build-a-2",
        artifact_digest=DIGEST,
        require_success=True,
    )
    assert result.run_attempt == 3

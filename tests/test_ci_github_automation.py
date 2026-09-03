from __future__ import annotations

from pathlib import Path

import pytest

from bcf_governance.tooling.automation_contracts import AutomationContractError
from bcf_governance.tooling.ci_github_api import GitHubContent
from bcf_governance.tooling.ci_github_automation import (
    admit_automation_pr,
    reconcile_automation_changelog,
)
from bcf_governance.tooling.ci_github_identity import GitHubControllerError


ROOT = Path(__file__).resolve().parents[1]
REPOSITORY = "mjgolaszewski/bcf-governance"
REPOSITORY_ID = 1207503211
MAIN = "a" * 40
MAIN_TREE = "b" * 40
HEAD = "c" * 40
HEAD_TREE = "d" * 40
WORKFLOW_BLOB = "e" * 40
DEPENDENCY_BLOB = "f" * 40
CREATED_BLOB = "1" * 40
CREATED_TREE = "2" * 40
CREATED_COMMIT = "3" * 40
WORKFLOW = b"name: trusted\n"


class FakeAutomationAPI:
    def __init__(self) -> None:
        self.actor_id = 49699333
        self.actor_login = "dependabot[bot]"
        self.writer_head = HEAD
        self.changelog = (ROOT / "CHANGELOG.md").read_bytes()
        self.updated: tuple[str, str, str] | None = None
        self.created_content = b""
        self.runs = {
            "10": {
                "id": 10,
                "run_attempt": 1,
                "workflow_id": 101,
                "repository": {"id": REPOSITORY_ID},
                "event": "pull_request_target",
                "head_sha": HEAD,
                "status": "completed",
                "conclusion": "success",
                "pull_requests": [{"number": 7}],
            },
            "20": {
                "id": 20,
                "run_attempt": 1,
                "workflow_id": 102,
                "repository": {"id": REPOSITORY_ID},
                "event": "workflow_run",
                "head_sha": MAIN,
                "status": "in_progress",
                "conclusion": None,
            },
        }

    def repository(self, repository: str) -> dict[str, object]:
        assert repository == REPOSITORY
        return {"id": REPOSITORY_ID, "default_branch": "main"}

    def reference(self, repository: str, ref: str) -> dict[str, object]:
        assert repository == REPOSITORY
        sha = MAIN if ref == "heads/main" else self.writer_head
        return {"object": {"type": "commit", "sha": sha}}

    def commit(self, repository: str, sha: str) -> dict[str, object]:
        assert repository == REPOSITORY
        return {"sha": sha, "tree": {"sha": MAIN_TREE if sha == MAIN else HEAD_TREE}}

    def run(self, repository: str, run_id: object) -> dict[str, object]:
        assert repository == REPOSITORY
        return dict(self.runs[str(run_id)])

    def workflow(self, repository: str, workflow_id: object) -> dict[str, object]:
        assert repository == REPOSITORY
        paths = {
            "101": ".github/workflows/bcf-automation-admission.yml",
            "102": ".github/workflows/bcf-automation-reconcile.yml",
        }
        return {"id": int(str(workflow_id)), "path": paths[str(workflow_id)]}

    def content(self, repository: str, path: str, *, ref: str) -> GitHubContent:
        assert repository == REPOSITORY
        if path == "governance/automation-producers.yml":
            return GitHubContent(path, WORKFLOW_BLOB, (ROOT / path).read_bytes())
        if path == "CHANGELOG.md":
            assert ref == HEAD
            return GitHubContent(path, WORKFLOW_BLOB, self.changelog)
        assert path.startswith(".github/workflows/") and ref == MAIN
        return GitHubContent(path, WORKFLOW_BLOB, WORKFLOW)

    def pull_request(self, repository: str, number: object) -> dict[str, object]:
        assert repository == REPOSITORY and int(str(number)) == 7
        return {
            "number": 7,
            "state": "open",
            "draft": True,
            "user": {"id": self.actor_id, "login": self.actor_login},
            "head": {"sha": HEAD, "ref": "dependabot/pip/pytest-9.1", "repo": {"id": REPOSITORY_ID}},
            "base": {"ref": "main", "repo": {"id": REPOSITORY_ID}},
        }

    def pull_request_files(self, repository: str, number: object) -> tuple[dict[str, object], ...]:
        assert repository == REPOSITORY and int(str(number)) == 7
        return (
            {"filename": "requirements-governance.txt", "status": "modified", "sha": DEPENDENCY_BLOB},
        )

    def create_blob(self, repository: str, content: bytes) -> str:
        assert repository == REPOSITORY
        self.created_content = content
        return CREATED_BLOB

    def create_tree_entries(
        self,
        repository: str,
        *,
        base_tree: str,
        entries: tuple[tuple[str, str], ...],
    ) -> str:
        assert (repository, base_tree, entries) == (
            REPOSITORY,
            HEAD_TREE,
            (("CHANGELOG.md", CREATED_BLOB),),
        )
        return CREATED_TREE

    def create_commit(self, repository: str, *, message: str, tree: str, parent: str) -> str:
        assert repository == REPOSITORY
        assert message == "chore(governance): record automated dependency update"
        assert (tree, parent) == (CREATED_TREE, HEAD)
        return CREATED_COMMIT

    def update_reference(self, repository: str, *, branch: str, expected_sha: str, commit_sha: str) -> None:
        assert repository == REPOSITORY
        self.updated = (branch, expected_sha, commit_sha)


def test_metadata_admission_and_reconciliation_use_provider_identity_only() -> None:
    api = FakeAutomationAPI()
    admission = admit_automation_pr(
        api,
        repository=REPOSITORY,
        admission_run_id="10",
        admission_run_attempt="1",
    )
    assert admission["status"] == "admitted"
    result = reconcile_automation_changelog(
        api,
        api,
        repository=REPOSITORY,
        event={"workflow_run": {"id": 10, "run_attempt": 1, "title": "ignored"}},
        reconciler_run_id="20",
        reconciler_run_attempt="1",
    )
    assert result["status"] == "committed"
    assert api.updated == ("dependabot/pip/pytest-9.1", HEAD, CREATED_COMMIT)
    assert b"PR #7" in api.created_content
    assert b"pytest-9.1" not in api.created_content


def test_actor_name_spoof_does_not_replace_numeric_authority() -> None:
    api = FakeAutomationAPI()
    api.actor_id = 1
    with pytest.raises(AutomationContractError, match="numeric actor"):
        admit_automation_pr(
            api,
            repository=REPOSITORY,
            admission_run_id="10",
            admission_run_attempt="1",
        )
    assert api.updated is None


def test_admission_binds_candidate_head_separately_from_main_workflow_bytes() -> None:
    api = FakeAutomationAPI()
    api.runs["10"]["head_sha"] = "9" * 40

    with pytest.raises(GitHubControllerError, match="expected candidate"):
        admit_automation_pr(
            api,
            repository=REPOSITORY,
            admission_run_id="10",
            admission_run_attempt="1",
        )


def test_admission_rejects_pr_that_advances_during_provider_observation() -> None:
    api = FakeAutomationAPI()
    calls = 0
    original = api.pull_request

    def advancing(repository: str, number: object) -> dict[str, object]:
        nonlocal calls
        calls += 1
        result = original(repository, number)
        if calls == 2:
            result["head"] = {
                "sha": "9" * 40,
                "ref": "dependabot/pip/pytest-9.1",
                "repo": {"id": REPOSITORY_ID},
            }
        return result

    api.pull_request = advancing  # type: ignore[method-assign]
    with pytest.raises(GitHubControllerError, match="advanced while provider state"):
        admit_automation_pr(
            api,
            repository=REPOSITORY,
            admission_run_id="10",
            admission_run_attempt="1",
        )


def test_stale_writer_head_fails_before_blob_construction() -> None:
    api = FakeAutomationAPI()
    api.writer_head = "9" * 40
    with pytest.raises(GitHubControllerError, match="advanced"):
        reconcile_automation_changelog(
            api,
            api,
            repository=REPOSITORY,
            event={"workflow_run": {"id": 10, "run_attempt": 1}},
            reconciler_run_id="20",
            reconciler_run_attempt="1",
        )
    assert api.created_content == b""


def test_unrelated_path_is_rejected_before_writer_use() -> None:
    api = FakeAutomationAPI()
    api.pull_request_files = lambda *_args, **_kwargs: (  # type: ignore[method-assign]
        {"filename": "src/product.py", "status": "modified", "sha": DEPENDENCY_BLOB},
    )
    with pytest.raises(AutomationContractError, match="unexpected paths"):
        reconcile_automation_changelog(
            api,
            api,
            repository=REPOSITORY,
            event={"workflow_run": {"id": 10, "run_attempt": 1}},
            reconciler_run_id="20",
            reconciler_run_attempt="1",
        )
    assert api.updated is None

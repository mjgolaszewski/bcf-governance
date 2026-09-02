from __future__ import annotations

import copy
from pathlib import Path

import pytest

from bcf_governance.tooling.ci_github_api import GitHubContent
from bcf_governance.tooling.ci_github_identity import GitHubControllerError
from bcf_governance.tooling.ci_github_pr import finalize_pr, publish_pr
from bcf_governance.tooling.github_protection import (
    apply_protection,
    desired_ruleset,
    inspect_protection,
    load_protection,
)


ROOT = Path(__file__).resolve().parents[1]
REPOSITORY = "mjgolaszewski/bcf-governance"
REPOSITORY_ID = 1207503211
MAIN = "a" * 40
MAIN_TREE = "b" * 40
HEAD = "c" * 40
HEAD_TREE = "d" * 40
BLOB = "e" * 40
WORKFLOW = b"name: trusted\n"


class FakePRAuthorityAPI:
    def __init__(self) -> None:
        self.head = HEAD
        self.created_checks: list[dict[str, object]] = []
        self.pack_conclusion = "success"
        self.runs = {
            "30": self._run(30, 201, "pull_request", HEAD, "success", with_pr=True),
            "40": self._run(40, 202, "pull_request", HEAD, "success", with_pr=True),
            "50": self._run(50, 105, "workflow_run", MAIN, None),
            "60": self._run(60, 106, "workflow_run", MAIN, None),
        }

    @staticmethod
    def _run(
        run_id: int,
        workflow_id: int,
        event: str,
        sha: str,
        conclusion: str | None,
        *,
        with_pr: bool = False,
    ) -> dict[str, object]:
        return {
            "id": run_id,
            "run_attempt": 1,
            "workflow_id": workflow_id,
            "repository": {"id": REPOSITORY_ID},
            "event": event,
            "head_sha": sha,
            "status": "completed" if conclusion is not None else "in_progress",
            "conclusion": conclusion,
            "pull_requests": [{"number": 7}] if with_pr else [],
        }

    def repository(self, repository: str) -> dict[str, object]:
        assert repository == REPOSITORY
        return {"id": REPOSITORY_ID, "default_branch": "main"}

    def reference(self, repository: str, ref: str) -> dict[str, object]:
        assert repository == REPOSITORY and ref == "heads/main"
        return {"object": {"type": "commit", "sha": MAIN}}

    def commit(self, repository: str, sha: str) -> dict[str, object]:
        assert repository == REPOSITORY
        return {"tree": {"sha": MAIN_TREE if sha == MAIN else HEAD_TREE}}

    def run(self, repository: str, run_id: object) -> dict[str, object]:
        assert repository == REPOSITORY
        return copy.deepcopy(self.runs[str(run_id)])

    def workflow(self, repository: str, workflow_id: object) -> dict[str, object]:
        assert repository == REPOSITORY
        paths = {
            "105": ".github/workflows/bcf-pr-finalizer.yml",
            "106": ".github/workflows/bcf-pr-status-publisher.yml",
            "201": ".github/workflows/governance.yml",
            "202": ".github/workflows/governance-pack.yml",
        }
        return {"id": int(str(workflow_id)), "path": paths[str(workflow_id)]}

    def content(self, repository: str, path: str, *, ref: str) -> GitHubContent:
        assert repository == REPOSITORY and ref == MAIN
        if path == "governance/github-protection.yml":
            content = (ROOT / path).read_bytes()
        else:
            content = WORKFLOW
        return GitHubContent(path, BLOB, content)

    def pull_request(self, repository: str, number: object) -> dict[str, object]:
        assert repository == REPOSITORY and int(str(number)) == 7
        return {
            "number": 7,
            "state": "open",
            "head": {"sha": self.head, "ref": "dependabot/pip/pytest", "repo": {"id": REPOSITORY_ID}},
            "base": {"ref": "main", "repo": {"id": REPOSITORY_ID}},
        }

    def workflow_runs(
        self,
        repository: str,
        workflow_id: object,
        *,
        head_sha: str,
        event: str,
    ) -> tuple[dict[str, object], ...]:
        assert repository == REPOSITORY and head_sha == self.head and event == "pull_request"
        selected = self.runs["30" if str(workflow_id) == "governance.yml" else "40"]
        value = copy.deepcopy(selected)
        if str(workflow_id) == "governance-pack.yml":
            value["conclusion"] = self.pack_conclusion
        return (value,)

    def jobs(self, repository: str, run_id: object, *, attempt: int) -> tuple[dict[str, object], ...]:
        assert repository == REPOSITORY and attempt == 1
        names = (
            ["Verify exact-tree governance evidence"]
            if str(run_id) == "30"
            else ["Test package, templates, and release tooling", "Verify template architecture boundaries"]
        )
        return tuple(
            {"name": name, "status": "completed", "conclusion": "success"}
            for name in names
        )

    def artifacts(self, repository: str, run_id: object) -> tuple[dict[str, object], ...]:
        assert repository == REPOSITORY and str(run_id) == "50"
        return (
            {
                "id": 900,
                "name": "bcf-pr-finalization-50-1",
                "expired": False,
                "digest": "sha256:" + "f" * 64,
                "workflow_run": {
                    "id": 50,
                    "repository_id": REPOSITORY_ID,
                    "head_repository_id": REPOSITORY_ID,
                    "head_branch": "main",
                    "head_sha": MAIN,
                },
            },
        )

    def check_runs(self, repository: str, *, sha: str) -> tuple[dict[str, object], ...]:
        assert repository == REPOSITORY and sha == self.head
        return ()

    def create_check_run(self, repository: str, **values: object) -> dict[str, object]:
        assert repository == REPOSITORY
        self.created_checks.append(values)
        return {**values, "app": {"id": 15368}}


def test_pr_finalizer_and_publisher_bind_one_exact_current_head(tmp_path: Path) -> None:
    api = FakePRAuthorityAPI()
    bundle = tmp_path / "bundle"
    observation = finalize_pr(
        api,
        repository=REPOSITORY,
        event={"workflow_run": {"id": 30, "run_attempt": 1}},
        finalizer_run_id=50,
        finalizer_run_attempt=1,
        output_root=bundle,
    )
    assert observation["computed_state"] == "successful"
    api.runs["50"].update(status="completed", conclusion="success")
    result = publish_pr(
        api,
        repository=REPOSITORY,
        event={"workflow_run": {"id": 50, "run_attempt": 1}},
        publisher_run_id=60,
        publisher_run_attempt=1,
        bundle_root=bundle,
        target_url="https://github.com/owner/repo/actions/runs/50",
    )
    assert result["computed_state"] == "successful"
    assert api.created_checks[0]["name"] == "bcf/pr-certification"
    assert api.created_checks[0]["external_id"] == "bcf-pr-certification:50:1"


def test_latest_failed_producer_revokes_without_borrowing(tmp_path: Path) -> None:
    api = FakePRAuthorityAPI()
    api.pack_conclusion = "failure"
    result = finalize_pr(
        api,
        repository=REPOSITORY,
        event={"workflow_run": {"id": 40, "run_attempt": 1}},
        finalizer_run_id=50,
        finalizer_run_attempt=1,
        output_root=tmp_path / "bundle",
    )
    assert result["computed_state"] == "failed"
    assert {item["id"]: item["state"] for item in result["producers"]} == {
        "governance": "successful",
        "package": "failed",
    }


def test_publisher_rejects_a_moved_pr_head(tmp_path: Path) -> None:
    api = FakePRAuthorityAPI()
    bundle = tmp_path / "bundle"
    finalize_pr(
        api,
        repository=REPOSITORY,
        event={"workflow_run": {"id": 30, "run_attempt": 1}},
        finalizer_run_id=50,
        finalizer_run_attempt=1,
        output_root=bundle,
    )
    api.runs["50"].update(status="completed", conclusion="success")
    api.head = "9" * 40
    with pytest.raises(GitHubControllerError, match="current pull request head"):
        publish_pr(
            api,
            repository=REPOSITORY,
            event={"workflow_run": {"id": 50, "run_attempt": 1}},
            publisher_run_id=60,
            publisher_run_attempt=1,
            bundle_root=bundle,
            target_url="https://github.com/owner/repo/actions/runs/50",
        )


class FakeProtectionAPI:
    def __init__(self) -> None:
        self.declaration = load_protection(ROOT)
        self.desired = desired_ruleset(self.declaration)
        self.current = {**self.desired, "rules": []}
        self.updated = False

    def repository(self, repository: str) -> dict[str, object]:
        return {"id": REPOSITORY_ID, "default_branch": "main"}

    def pull_requests(self, repository: str, *, state: str) -> tuple[dict[str, object], ...]:
        assert state == "open"
        return ({
            "number": 7,
            "draft": True,
            "user": {"id": 49699333, "login": "dependabot[bot]"},
            "head": {"sha": HEAD, "ref": "dependabot/pip/pytest", "repo": {"id": REPOSITORY_ID}},
        },)

    def pull_request_files(self, repository: str, number: object) -> tuple[dict[str, object], ...]:
        return ({"filename": "pyproject.toml"}, {"filename": "CHANGELOG.md"})

    def repository_rulesets(self, repository: str) -> tuple[dict[str, object], ...]:
        return ({"id": 77, "name": "main-governance"},)

    def ruleset(self, repository: str, ruleset_id: object) -> dict[str, object]:
        return {"id": 77, **self.current}

    def check_runs(self, repository: str, *, sha: str) -> tuple[dict[str, object], ...]:
        assert sha == HEAD
        return (
            {
                "name": "bcf/pr-certification",
                "app": {"id": 15368},
                "head_sha": HEAD,
                "status": "completed",
                "conclusion": "success",
                "external_id": "bcf-pr-certification:50:1",
            },
        )

    def update_ruleset(self, repository: str, ruleset_id: object, payload: dict[str, object]) -> dict[str, object]:
        self.current = copy.deepcopy(payload)
        self.updated = True
        return {"id": 77, **payload}


def test_protection_requires_canary_and_converges_exactly() -> None:
    api = FakeProtectionAPI()
    assert inspect_protection(api, repo_root=ROOT, repository=REPOSITORY).status == "drift"
    result = apply_protection(api, repo_root=ROOT, repository=REPOSITORY)
    assert result.status == "applied" and api.updated
    assert inspect_protection(api, repo_root=ROOT, repository=REPOSITORY).status == "clean"


def test_protection_rejects_wrong_canary_app() -> None:
    api = FakeProtectionAPI()
    api.check_runs = lambda *_args, **_kwargs: (  # type: ignore[method-assign]
        {
            "name": "bcf/pr-certification",
            "app": {"id": 1},
            "head_sha": MAIN,
            "status": "completed",
            "conclusion": "success",
            "external_id": "bcf-pr-certification:50:1",
        },
    )
    with pytest.raises(GitHubControllerError, match="current successful"):
        apply_protection(api, repo_root=ROOT, repository=REPOSITORY)

from __future__ import annotations

import copy
import hashlib
import io
import json
import zipfile
from pathlib import Path

import pytest

from bcf_governance.tooling.ci_github_api import GitHubContent
from bcf_governance.tooling.ci_github_identity import GitHubControllerError
from bcf_governance.tooling.ci_github_pr import finalize_pr, publish_pr
from bcf_governance.tooling import ci_github_pr
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
RULESET_ID = 77


class FakePRAuthorityAPI:
    def __init__(self) -> None:
        self.head = HEAD
        self.created_checks: list[dict[str, object]] = []
        self.pack_conclusion = "success"
        self.candidate_archives: dict[str, bytes] = {}
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
        if path in {
            "governance/github-protection.yml",
            "governance/ci-graph.yml",
            "governance/self-governance-policy.yml",
        }:
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
            "base": {"sha": MAIN, "ref": "main", "repo": {"id": REPOSITORY_ID}},
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
        if str(workflow_id) == "governance.yml":
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
        assert repository == REPOSITORY
        if str(run_id) == "30" and self.candidate_archives:
            return tuple(
                {
                    "id": 910 + index,
                    "name": name,
                    "expired": False,
                    "digest": "sha256:" + hashlib.sha256(raw).hexdigest(),
                    "workflow_run": {
                        "id": 30,
                        "repository_id": REPOSITORY_ID,
                        "head_repository_id": REPOSITORY_ID,
                        "head_sha": HEAD,
                    },
                }
                for index, (name, raw) in enumerate(sorted(self.candidate_archives.items()))
            )
        assert str(run_id) == "50"
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

    def artifact_bytes(
        self, repository: str, artifact_id: object, *, maximum_bytes: int
    ) -> bytes:
        assert repository == REPOSITORY and maximum_bytes > 0
        index = int(str(artifact_id)) - 910
        return sorted(self.candidate_archives.items())[index][1]

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
        "governance": "failed",
    }


def _zip(name: str, raw: bytes) -> bytes:
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w") as archive:
        archive.writestr(name, raw)
    return output.getvalue()


def test_protected_evaluator_recomputes_truth_instead_of_accepting_candidate_pass(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    api = FakePRAuthorityAPI()
    api.candidate_archives = {
        "bcf-session-30-1": _zip("session/evidence-session.json", b"{}"),
        "bcf-evidence-30-1-shard-0": _zip("receipt/test.evidence.json", b"{}"),
    }
    candidate = tmp_path / "candidate"
    candidate.mkdir()
    called: list[Path] = []

    def reject_candidate_truth(repo_root: Path, *_args: object, **_kwargs: object) -> dict[str, object]:
        called.append(repo_root)
        return {
            "status": "fail",
            "merge_eligibility": "ineligible",
            "subject": {"commit_sha": HEAD, "tree_sha": HEAD_TREE},
        }

    monkeypatch.setattr(ci_github_pr, "derive_truth", reject_candidate_truth)
    with pytest.raises(GitHubControllerError, match="not exact and eligible"):
        finalize_pr(
            api,
            repository=REPOSITORY,
            event={"workflow_run": {"id": 30, "run_attempt": 1}},
            finalizer_run_id=50,
            finalizer_run_attempt=1,
            output_root=tmp_path / "bundle",
            candidate_root=candidate,
        )
    assert called == [candidate.resolve()]


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


def test_publisher_rejects_substituted_evaluator_identity(tmp_path: Path) -> None:
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
    observation_path = bundle / "pr-observation.json"
    observation = json.loads(observation_path.read_text(encoding="utf-8"))
    observation["evaluator"]["runtime"]["sha256"] = "0" * 64
    raw = (json.dumps(observation, indent=2, sort_keys=True) + "\n").encode()
    observation_path.write_bytes(raw)
    manifest_path = bundle / "bundle-manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["files"]["pr-observation.json"] = hashlib.sha256(raw).hexdigest()
    manifest_path.write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    api.runs["50"].update(status="completed", conclusion="success")
    with pytest.raises(GitHubControllerError, match="evaluator identity is not exact"):
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
        self.current = {
            **self.desired,
            "name": "protect-main-owner-prs",
            "rules": list(reversed(self.desired["rules"])),
        }
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
        return ({"id": RULESET_ID, "name": "protect-main-owner-prs"},)

    def ruleset(self, repository: str, ruleset_id: object) -> dict[str, object]:
        assert int(ruleset_id) == RULESET_ID
        return {"id": RULESET_ID, **self.current}

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
        assert int(ruleset_id) == RULESET_ID
        self.current = copy.deepcopy(payload)
        self.updated = True
        return {"id": RULESET_ID, **payload}


def test_protection_requires_canary_and_converges_exactly() -> None:
    api = FakeProtectionAPI()
    assert inspect_protection(api, repo_root=ROOT, repository=REPOSITORY).status == "drift"
    result = apply_protection(api, repo_root=ROOT, repository=REPOSITORY)
    assert result.status == "applied" and api.updated
    assert inspect_protection(api, repo_root=ROOT, repository=REPOSITORY).status == "clean"


def test_protection_rule_order_is_not_provider_authority() -> None:
    api = FakeProtectionAPI()
    api.current = {**api.desired, "rules": list(reversed(api.desired["rules"]))}
    assert inspect_protection(api, repo_root=ROOT, repository=REPOSITORY).status == "clean"
    pull_request = next(
        rule for rule in api.desired["rules"] if rule["type"] == "pull_request"
    )
    assert pull_request["parameters"] == {
        "allowed_merge_methods": ["merge", "squash", "rebase"],
        "dismiss_stale_reviews_on_push": True,
        "require_code_owner_review": False,
        "require_extra_approval_for_unattributed_changes": False,
        "require_last_push_approval": False,
        "required_approving_review_count": 0,
        "required_review_thread_resolution": True,
        "required_reviewers": [],
    }


def test_protection_rejects_ambiguous_existing_branch_rulesets() -> None:
    api = FakeProtectionAPI()
    api.repository_rulesets = lambda _repository: (  # type: ignore[method-assign]
        {"id": RULESET_ID, "name": "legacy-one"},
        {"id": 78, "name": "legacy-two"},
    )
    api.ruleset = lambda _repository, ruleset_id: {  # type: ignore[method-assign]
        "id": int(ruleset_id),
        **api.current,
        "name": f"legacy-{ruleset_id}",
    }
    api.create_ruleset = lambda *_args, **_kwargs: pytest.fail(  # type: ignore[attr-defined, method-assign]
        "an ambiguous replacement ruleset must not be created"
    )
    with pytest.raises(GitHubControllerError, match="ambiguous rulesets"):
        apply_protection(api, repo_root=ROOT, repository=REPOSITORY)


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


class BoundPRAuthorityAPI(FakePRAuthorityAPI):
    def __init__(self):
        super().__init__()
        self.base_sha = '1' * 40
        self.base_tree = '2' * 40
        self.base_ref = 'stack'
        self.ref_sha = self.base_sha
        self.main_sha = MAIN

    def reference(self, repository, ref):
        if ref == 'heads/main':
            return {'object': {'type': 'commit', 'sha': self.main_sha}}
        if ref == 'heads/' + self.base_ref:
            return {'ref': 'refs/' + ref, 'object': {'type': 'commit', 'sha': self.ref_sha}}
        return super().reference(repository, ref)

    def commit(self, repository, sha):
        if sha == self.base_sha:
            return {'tree': {'sha': self.base_tree}}
        return super().commit(repository, sha)

    def pull_request(self, repository, number):
        result = super().pull_request(repository, number)
        result['base'].update(sha=self.base_sha, ref=self.base_ref)
        return result


def test_bound_pr_evaluator_and_publisher_separate_comparison_from_protected_source(tmp_path):
    api = BoundPRAuthorityAPI()
    bundle = tmp_path / 'bundle'
    observation = finalize_pr(api, repository=REPOSITORY,
        event={'workflow_run': {'id': 30, 'run_attempt': 1}},
        finalizer_run_id=50, finalizer_run_attempt=1, output_root=bundle)
    assert observation['evaluator']['base'] == {'commit_sha': MAIN, 'tree_sha': MAIN_TREE, 'branch': 'main'}
    assert observation['evaluator']['comparison'] == {'commit_sha': api.base_sha, 'tree_sha': api.base_tree, 'branch': 'stack'}
    api.runs['50'].update(status='completed', conclusion='success')
    result = publish_pr(api, repository=REPOSITORY,
        event={'workflow_run': {'id': 50, 'run_attempt': 1}}, publisher_run_id=60,
        publisher_run_attempt=1, bundle_root=bundle, target_url='https://example.invalid/run/50')
    assert result['computed_state'] == 'successful'
    assert len(api.created_checks) == 1


@pytest.mark.parametrize('cause', ['reference-moved', 'invalid-tree'])
def test_bound_pr_evaluator_rejects_bad_comparison_before_producers(tmp_path, monkeypatch, cause):
    api = BoundPRAuthorityAPI()
    if cause == 'reference-moved': api.ref_sha = '3' * 40
    else: api.base_tree = 'not-a-tree'
    monkeypatch.setattr(ci_github_pr, '_producer_state', lambda *_a, **_k: pytest.fail('producer consumed before comparison validation'))
    with pytest.raises(GitHubControllerError):
        finalize_pr(api, repository=REPOSITORY,
            event={'workflow_run': {'id': 30, 'run_attempt': 1}}, finalizer_run_id=50,
            finalizer_run_attempt=1, output_root=tmp_path / 'bundle')


@pytest.mark.parametrize('cause', ['comparison', 'protected-source', 'comparison-ref'])
def test_bound_pr_finalizer_rejects_movement_during_producer_reads(tmp_path, monkeypatch, cause):
    api = BoundPRAuthorityAPI()
    original = api.jobs
    def jobs(*args, **kwargs):
        result = original(*args, **kwargs)
        if cause == 'comparison': api.base_sha = api.ref_sha = '3' * 40
        elif cause == 'comparison-ref': api.ref_sha = '3' * 40
        else: api.main_sha = '4' * 40
        return result
    monkeypatch.setattr(api, 'jobs', jobs)
    with pytest.raises(GitHubControllerError, match='moved during finalization|comparison reference'):
        finalize_pr(api, repository=REPOSITORY, event={'workflow_run': {'id': 30, 'run_attempt': 1}},
            finalizer_run_id=50, finalizer_run_attempt=1, output_root=tmp_path / 'bundle')
    assert not (tmp_path / 'bundle').exists()


@pytest.mark.parametrize('cause', ['retarget', 'base', 'late-base', 'late-protected-source', 'late-ref'])
def test_bound_pr_publisher_rejects_changed_context_before_write(tmp_path, monkeypatch, cause):
    api = BoundPRAuthorityAPI()
    bundle = tmp_path / 'bundle'
    finalize_pr(api, repository=REPOSITORY, event={'workflow_run': {'id': 30, 'run_attempt': 1}},
        finalizer_run_id=50, finalizer_run_attempt=1, output_root=bundle)
    api.runs['50'].update(status='completed', conclusion='success')
    if cause == 'retarget': api.base_ref = 'different-stack'
    elif cause == 'base': api.base_sha = api.ref_sha = '3' * 40
    else:
        original = api.check_runs
        def checks(*args, **kwargs):
            result = original(*args, **kwargs)
            if cause == 'late-base': api.base_sha = api.ref_sha = '3' * 40
            elif cause == 'late-ref': api.ref_sha = '3' * 40
            else: api.main_sha = '4' * 40
            return result
        monkeypatch.setattr(api, 'check_runs', checks)
    with pytest.raises(GitHubControllerError, match='evaluator identity is not exact|moved before publication|comparison reference'):
        publish_pr(api, repository=REPOSITORY, event={'workflow_run': {'id': 50, 'run_attempt': 1}},
            publisher_run_id=60, publisher_run_attempt=1, bundle_root=bundle, target_url='https://example.invalid/run/50')
    assert api.created_checks == []


def test_nondefault_pr_cannot_consume_default_main_transition_equivalence(tmp_path, monkeypatch):
    api = BoundPRAuthorityAPI()
    original = ci_github_pr._protection
    def protection(*args, **kwargs):
        result = original(*args, **kwargs)
        result['pr_certification']['producer_workflows'].append({'id': 'package',
            'path': '.github/workflows/governance-pack.yml', 'required_job_names': ['package']})
        return result
    monkeypatch.setattr(ci_github_pr, '_protection', protection)
    monkeypatch.setattr(ci_github_pr, '_producer_state', lambda *_a, **kw: {'id': kw['contract']['id'], 'state': 'successful'})
    monkeypatch.setattr(ci_github_pr, 'transition_is_applicable', lambda *_a, **_k: pytest.fail('default-main transition for stacked PR'))
    value = finalize_pr(api, repository=REPOSITORY, event={'workflow_run': {'id': 30, 'run_attempt': 1}},
        finalizer_run_id=50, finalizer_run_attempt=1, output_root=tmp_path / 'bundle')
    assert value['computed_state'] == 'successful'
    assert value['evaluator']['comparison']['branch'] == 'stack'


@pytest.mark.parametrize('ref_name', [None, 'refs/heads/other'])
def test_bound_pr_finalizer_rejects_contradictory_ref_name_with_matching_object(tmp_path, ref_name):
    api = BoundPRAuthorityAPI()
    original = api.reference
    def observed(repository, ref):
        result = original(repository, ref)
        if ref == 'heads/stack':
            if ref_name is None: result.pop('ref', None)
            else: result['ref'] = ref_name
        return result
    api.reference = observed
    with pytest.raises(GitHubControllerError, match='comparison reference'):
        finalize_pr(api, repository=REPOSITORY,
            event={'workflow_run': {'id': 30, 'run_attempt': 1}},
            finalizer_run_id=50, finalizer_run_attempt=1, output_root=tmp_path/'rejected')
    assert not (tmp_path/'rejected').exists()

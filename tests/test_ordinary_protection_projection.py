from __future__ import annotations

import copy
from pathlib import Path
import shutil
import subprocess
from types import SimpleNamespace

import pytest
import yaml

from bcf_governance.tooling.ci_github_identity import GitHubControllerError
from bcf_governance.tooling.github_protection import (
    apply_protection,
    desired_ruleset,
    load_protection,
)
from bcf_governance.tooling.ordinary_protection_projection import (
    OrdinaryProtectionProjection,
    apply_ordinary_protection_projection,
    compile_ordinary_protection_proposal,
    validate_ordinary_protection_submission,
)


ROOT = Path(__file__).resolve().parents[1]
REPOSITORY = "owner/adopter"
REPOSITORY_ID = 701
RULESET_ID = 81


def _provider_ruleset(*, bypass: object = None) -> dict[str, object]:
    return {
        "id": RULESET_ID,
        "name": "existing-main-policy",
        "target": "branch",
        "enforcement": "active",
        "bypass_actors": [] if bypass is None else bypass,
        "conditions": {
            "ref_name": {"include": ["refs/heads/main"], "exclude": []}
        },
        "rules": [
            {
                "type": "pull_request",
                "parameters": {
                    "allowed_merge_methods": ["merge"],
                    "dismiss_stale_reviews_on_push": True,
                    "require_code_owner_review": True,
                    "require_extra_approval_for_unattributed_changes": False,
                    "require_last_push_approval": True,
                    "required_approving_review_count": 1,
                    "required_review_thread_resolution": True,
                    "required_reviewers": [],
                },
            },
            {
                "type": "required_status_checks",
                "parameters": {
                    "do_not_enforce_on_create": False,
                    "required_status_checks": [
                        {"context": "application/test", "integration_id": 99}
                    ],
                    "strict_required_status_checks_policy": True,
                },
            },
            {"type": "non_fast_forward"},
            {"type": "deletion"},
        ],
    }


class ProjectionAPI:
    def __init__(self, detail: dict[str, object] | None) -> None:
        self.detail = copy.deepcopy(detail)
        self.updated = False
        self.main_sha = "0" * 40
        self.main_tree = "1" * 40
        self.source_bytes = b""

    def repository(self, repository: str) -> dict[str, object]:
        assert repository == REPOSITORY
        return {
            "id": REPOSITORY_ID,
            "full_name": REPOSITORY,
            "default_branch": "main",
        }

    def repository_rulesets(self, repository: str) -> tuple[dict[str, object], ...]:
        if self.detail is None:
            return ()
        return ({"id": RULESET_ID, "name": self.detail["name"]},)

    def ruleset(self, repository: str, ruleset_id: object) -> dict[str, object]:
        assert int(ruleset_id) == RULESET_ID and self.detail is not None
        return copy.deepcopy(self.detail)

    def update_ruleset(
        self, repository: str, ruleset_id: object, payload: dict[str, object]
    ) -> dict[str, object]:
        assert int(ruleset_id) == RULESET_ID
        self.detail = {"id": RULESET_ID, **copy.deepcopy(payload)}
        self.updated = True
        return copy.deepcopy(self.detail)

    def create_ruleset(
        self, repository: str, payload: dict[str, object]
    ) -> dict[str, object]:
        self.detail = {"id": RULESET_ID, **copy.deepcopy(payload)}
        self.updated = True
        return copy.deepcopy(self.detail)

    def reference(self, repository: str, ref: str) -> dict[str, object]:
        assert ref == "heads/main"
        return {"object": {"type": "commit", "sha": self.main_sha}}

    def commit(self, repository: str, sha: str) -> dict[str, object]:
        assert sha == self.main_sha
        return {"sha": sha, "tree": {"sha": self.main_tree}}

    def content(self, repository: str, path: str, *, ref: str) -> object:
        assert path == "governance/github-protection.yml" and ref == self.main_sha
        return SimpleNamespace(content=self.source_bytes)


def test_existing_provider_policy_compiles_losslessly_and_adds_bcf_context() -> None:
    declaration = compile_ordinary_protection_proposal(
        ProjectionAPI(_provider_ruleset()), repo_root=ROOT, repository=REPOSITORY
    )
    assert declaration["schema_version"] == "1.1"
    assert declaration["projection"]["kind"] == "ordinary_adopter"
    assert declaration["projection"]["provider_prestate"]["status"] == "present"
    ruleset = declaration["ruleset"]
    assert ruleset["allowed_merge_methods"] == ["merge"]
    assert ruleset["required_approving_review_count"] == 1
    assert ruleset["require_code_owner_review"] is True
    assert ruleset["require_last_push_approval"] is True
    assert ruleset["required_status_checks"] == [
        {"context": "application/test", "integration_id": 99},
        {"context": "bcf/pr-certification", "integration_id": 15368},
    ]
    assert declaration["pr_certification"]["producer_workflows"] == [
        {
            "id": "governance",
            "path": ".github/workflows/governance.yml",
            "required_job_names": ["Verify exact-tree governance evidence"],
        }
    ]


def test_new_repository_compiles_one_no_bypass_proposal() -> None:
    declaration = compile_ordinary_protection_proposal(
        ProjectionAPI(None), repo_root=ROOT, repository=REPOSITORY
    )
    assert declaration["projection"]["provider_prestate"]["status"] == "missing"
    assert "ruleset_id" not in declaration["projection"]["provider_prestate"]
    assert declaration["ruleset"]["bypass_actors"] == []
    assert declaration["ruleset"]["required_status_checks"] == [
        {"context": "bcf/pr-certification", "integration_id": 15368}
    ]


def test_apply_uses_exact_compiled_snapshot_without_provider_reread(
    tmp_path: Path,
) -> None:
    root = tmp_path / "adopter"
    (root / "governance").mkdir(parents=True)
    (root / "schemas").mkdir()
    shutil.copy2(
        ROOT / "schemas/github-protection.schema.json",
        root / "schemas/github-protection.schema.json",
    )
    api = ProjectionAPI(_provider_ruleset())
    planned = OrdinaryProtectionProjection(
        "actionable",
        ("governance/github-protection.yml",),
        compile_ordinary_protection_proposal(
            api, repo_root=ROOT, repository=REPOSITORY
        ),
    )
    api.repository = lambda _repository: (_ for _ in ()).throw(  # type: ignore[method-assign]
        AssertionError("provider state was reread after planning")
    )
    applied = apply_ordinary_protection_projection(
        repo_root=root, projection=planned
    )
    assert applied.status == "changed"
    assert load_protection(root) == planned.declaration


@pytest.mark.parametrize("bypass", [[{"actor_id": 7}], "redacted"])
def test_proposal_rejects_untrusted_bypass_inventory(bypass: object) -> None:
    with pytest.raises(GitHubControllerError, match="bypass"):
        compile_ordinary_protection_proposal(
            ProjectionAPI(_provider_ruleset(bypass=bypass)),
            repo_root=ROOT,
            repository=REPOSITORY,
        )


def test_proposal_rejects_wrong_repository_or_ambiguous_rulesets() -> None:
    wrong = ProjectionAPI(None)
    wrong.repository = lambda _repository: {  # type: ignore[method-assign]
        "id": REPOSITORY_ID, "full_name": "other/repo", "default_branch": "main"
    }
    with pytest.raises(GitHubControllerError, match="identity"):
        compile_ordinary_protection_proposal(
            wrong, repo_root=ROOT, repository=REPOSITORY
        )
    ambiguous = ProjectionAPI(_provider_ruleset())
    ambiguous.repository_rulesets = lambda _repository: (  # type: ignore[method-assign]
        {"id": RULESET_ID, "name": "one"},
        {"id": RULESET_ID + 1, "name": "two"},
    )
    ambiguous.ruleset = lambda _repository, ruleset_id: {  # type: ignore[method-assign]
        **_provider_ruleset(), "id": int(ruleset_id), "name": f"rule-{ruleset_id}"
    }
    with pytest.raises(GitHubControllerError, match="ambiguous"):
        compile_ordinary_protection_proposal(
            ambiguous, repo_root=ROOT, repository=REPOSITORY
        )


def _reviewed_repo(
    tmp_path: Path, api: ProjectionAPI, declaration: dict[str, object]
) -> Path:
    root = tmp_path / "adopter"
    (root / "governance").mkdir(parents=True)
    (root / "schemas").mkdir()
    shutil.copy2(
        ROOT / "schemas/github-protection.schema.json",
        root / "schemas/github-protection.schema.json",
    )
    source = yaml.safe_dump(declaration, sort_keys=False, width=1000).encode()
    (root / "governance/github-protection.yml").write_bytes(source)
    subprocess.run(["git", "init", "--quiet"], cwd=root, check=True)
    subprocess.run(["git", "config", "user.email", "fixture@example.invalid"], cwd=root, check=True)
    subprocess.run(["git", "config", "user.name", "Fixture"], cwd=root, check=True)
    subprocess.run(["git", "add", "."], cwd=root, check=True)
    subprocess.run(["git", "commit", "--quiet", "-m", "review protection"], cwd=root, check=True)
    api.main_sha = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=root, text=True).strip()
    api.main_tree = subprocess.check_output(["git", "rev-parse", "HEAD^{tree}"], cwd=root, text=True).strip()
    api.source_bytes = source
    return root


def test_reviewed_proposal_applies_exact_prestate_and_verifies_provider(
    tmp_path: Path,
) -> None:
    api = ProjectionAPI(_provider_ruleset())
    declaration = compile_ordinary_protection_proposal(
        api, repo_root=ROOT, repository=REPOSITORY
    )
    root = _reviewed_repo(tmp_path, api, declaration)
    result = apply_protection(api, repo_root=root, repository=REPOSITORY)
    assert result.status == "applied" and api.updated
    assert api.detail is not None
    assert api.detail["bypass_actors"] == []
    assert api.detail["rules"] == desired_ruleset(load_protection(root))["rules"]


def test_apply_rejects_stale_provider_or_unreviewed_source(tmp_path: Path) -> None:
    api = ProjectionAPI(_provider_ruleset())
    declaration = compile_ordinary_protection_proposal(
        api, repo_root=ROOT, repository=REPOSITORY
    )
    root = _reviewed_repo(tmp_path, api, declaration)
    assert api.detail is not None
    api.detail["enforcement"] = "disabled"
    with pytest.raises(GitHubControllerError, match="changed after"):
        apply_protection(api, repo_root=root, repository=REPOSITORY)
    api.detail["enforcement"] = "active"
    api.source_bytes = b"different"
    with pytest.raises(GitHubControllerError, match="differs from the reviewed"):
        apply_protection(api, repo_root=root, repository=REPOSITORY)


def test_submission_distinguishes_exact_proposal_from_reviewed_provider_parity(
    tmp_path: Path,
) -> None:
    api = ProjectionAPI(_provider_ruleset())
    declaration = compile_ordinary_protection_proposal(
        api, repo_root=ROOT, repository=REPOSITORY
    )
    root = tmp_path / "candidate"
    (root / "governance").mkdir(parents=True)
    (root / "schemas").mkdir()
    shutil.copy2(
        ROOT / "schemas/github-protection.schema.json",
        root / "schemas/github-protection.schema.json",
    )
    subprocess.run(["git", "init", "--quiet"], cwd=root, check=True)
    subprocess.run(["git", "config", "user.email", "fixture@example.invalid"], cwd=root, check=True)
    subprocess.run(["git", "config", "user.name", "Fixture"], cwd=root, check=True)
    subprocess.run(["git", "add", "."], cwd=root, check=True)
    subprocess.run(["git", "commit", "--quiet", "-m", "base"], cwd=root, check=True)
    base = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=root, text=True).strip()
    source = yaml.safe_dump(declaration, sort_keys=False, width=1000).encode()
    (root / "governance/github-protection.yml").write_bytes(source)
    assert validate_ordinary_protection_submission(
        api, repo_root=root, repository=REPOSITORY, base_sha=base
    ) == "exact_proposal"
    subprocess.run(["git", "add", "."], cwd=root, check=True)
    subprocess.run(["git", "commit", "--quiet", "-m", "review proposal"], cwd=root, check=True)
    api.detail = {"id": RULESET_ID, **desired_ruleset(declaration)}
    reviewed = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=root, text=True).strip()
    assert validate_ordinary_protection_submission(
        api, repo_root=root, repository=REPOSITORY, base_sha=reviewed
    ) == "reviewed_provider_match"

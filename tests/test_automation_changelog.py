from __future__ import annotations

import copy
from pathlib import Path
import shutil

import pytest
import yaml

from bcf_governance.tooling.automation_changelog import render_automation_changelog
from bcf_governance.tooling.automation_commands import adopt_dependabot
from bcf_governance.tooling.automation_contracts import (
    AutomationContractError,
    dependabot_allowed_paths,
    load_automation_registry,
    select_producer,
)


ROOT = Path(__file__).resolve().parents[1]
SOURCE_A = "a" * 64
SOURCE_B = "b" * 64


class AdoptionAPI:
    def repository(self, repository: str) -> dict[str, object]:
        return {"id": 1207503211}

    def user(self, login: str) -> dict[str, object]:
        return {"id": 49699333, "login": "dependabot[bot]", "type": "Bot"}


def _registry() -> dict[str, object]:
    value = yaml.safe_load((ROOT / "governance/automation-producers.yml").read_text())
    assert isinstance(value, dict)
    return value


def test_bcf_automation_registry_is_valid_and_provider_bound() -> None:
    registry = load_automation_registry(ROOT)
    assert registry["repository"] == {
        "full_name": "mjgolaszewski/bcf-governance",
        "numeric_id": 1207503211,
    }
    assert [(item["id"], item["actor_id"]) for item in registry["producers"]] == [
        ("dependabot", 49699333)
    ]


def test_changelog_projection_is_fixed_idempotent_and_source_sensitive() -> None:
    original = b"# Changelog\n\n## [Unreleased]\n\nNo unreleased changes.\n\n## [1.0.1] - 2026-09-02\n"
    first = render_automation_changelog(
        original,
        repository_id=42,
        producer_id="dependabot",
        pr_number=7,
        source_state=SOURCE_A,
        dependency_paths=("requirements.txt",),
    )
    assert first.changed
    assert "No unreleased changes." not in first.content.decode()
    assert first.entry == "- Automated dependency update `dependabot` from PR #7: `requirements.txt`."
    second = render_automation_changelog(
        first.content,
        repository_id=42,
        producer_id="dependabot",
        pr_number=7,
        source_state=SOURCE_A,
        dependency_paths=("requirements.txt",),
    )
    assert not second.changed
    assert second.content == first.content
    changed = render_automation_changelog(
        first.content,
        repository_id=42,
        producer_id="dependabot",
        pr_number=7,
        source_state=SOURCE_B,
        dependency_paths=("requirements.txt",),
    )
    assert changed.changed
    assert changed.content.count(b"bcf-automation-changelog") == 1
    assert changed.content.count(b"Automated dependency update") == 1


def test_changelog_projection_rejects_duplicate_or_detached_markers() -> None:
    marker = "<!-- bcf-automation-changelog:42:dependabot:7:bad -->"
    with pytest.raises(AutomationContractError, match="duplicate"):
        render_automation_changelog(
            f"# Changelog\n\n## [Unreleased]\n\n{marker}\nentry\n{marker}\nentry\n".encode(),
            repository_id=42,
            producer_id="dependabot",
            pr_number=7,
            source_state=SOURCE_A,
            dependency_paths=("requirements.txt",),
        )


def test_numeric_identity_and_paths_are_both_authoritative() -> None:
    registry = _registry()
    match = select_producer(
        registry,
        repository="mjgolaszewski/bcf-governance",
        repository_id=1207503211,
        actor_id=49699333,
        actor_login="dependabot[bot]",
        head_repository_id=1207503211,
        head_branch="dependabot/pip/pytest-9.1",
        changed_paths=("CHANGELOG.md", "requirements-governance.txt"),
    )
    assert match.dependency_paths == ("requirements-governance.txt",)
    for mutation, message in (
        ({"actor_id": 1}, "numeric actor"),
        ({"actor_login": "dependabot"}, "actor login"),
        ({"head_repository_id": 2}, "same repository"),
        ({"changed_paths": ("src/application.py",)}, "unexpected paths"),
    ):
        values = {
            "repository": "mjgolaszewski/bcf-governance",
            "repository_id": 1207503211,
            "actor_id": 49699333,
            "actor_login": "dependabot[bot]",
            "head_repository_id": 1207503211,
            "head_branch": "dependabot/pip/pytest-9.1",
            "changed_paths": ("requirements-governance.txt",),
            **mutation,
        }
        with pytest.raises(AutomationContractError, match=message):
            select_producer(registry, **values)


def test_dependabot_paths_are_derived_from_update_contract() -> None:
    classes, paths = dependabot_allowed_paths(
        {
            "version": 2,
            "updates": [
                {"package-ecosystem": "pip", "directory": "/"},
                {"package-ecosystem": "github-actions", "directory": "/"},
            ],
        }
    )
    assert classes == ("github-actions", "python")
    assert ".github/workflows/*.yml" in paths
    assert "requirements*.txt" in paths
    with pytest.raises(AutomationContractError, match="unsupported"):
        dependabot_allowed_paths(
            {"version": 2, "updates": [{"package-ecosystem": "terraform", "directory": "/"}]}
        )


def test_registry_rejects_duplicate_numeric_authority(tmp_path: Path) -> None:
    registry = _registry()
    registry["producers"].append(copy.deepcopy(registry["producers"][0]))
    registry["producers"][1]["id"] = "spoof"
    (tmp_path / "governance").mkdir()
    (tmp_path / "schemas").mkdir()
    (tmp_path / "governance/automation-producers.yml").write_text(
        yaml.safe_dump(registry, sort_keys=False)
    )
    (tmp_path / "schemas/automation-producers.schema.json").write_bytes(
        (ROOT / "schemas/automation-producers.schema.json").read_bytes()
    )
    with pytest.raises(AutomationContractError, match="numeric actor"):
        load_automation_registry(tmp_path)


def test_fresh_standard_adoption_is_explicit_transactional_and_idempotent(
    tmp_path: Path,
) -> None:
    (tmp_path / ".github").mkdir()
    (tmp_path / "schemas").mkdir()
    (tmp_path / ".github/dependabot.yml").write_text(
        "version: 2\nupdates:\n- package-ecosystem: pip\n  directory: /\n  schedule: {interval: monthly}\n",
        encoding="utf-8",
    )
    shutil.copy2(
        ROOT / "schemas/automation-producers.schema.json",
        tmp_path / "schemas/automation-producers.schema.json",
    )
    api = AdoptionAPI()
    check = adopt_dependabot(
        api, repo_root=tmp_path, repository="mjgolaszewski/bcf-governance", apply=False
    )
    assert check.status == "drift"
    assert not (tmp_path / "governance/automation-producers.yml").exists()
    applied = adopt_dependabot(
        api, repo_root=tmp_path, repository="mjgolaszewski/bcf-governance", apply=True
    )
    assert applied.status == "applied"
    assert load_automation_registry(tmp_path)["producers"][0]["id"] == "dependabot"
    assert adopt_dependabot(
        api, repo_root=tmp_path, repository="mjgolaszewski/bcf-governance", apply=False
    ).status == "clean"

from __future__ import annotations

import copy
from pathlib import Path
import shutil
import subprocess

import pytest
import yaml

from bcf_governance.tooling.automation_changelog import render_automation_changelog
from bcf_governance.tooling.automation_dependencies import (
    DependencyTransition,
    dependency_source_kind,
    derive_dependency_transitions,
)
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
    assert adopt_dependabot(
        AdoptionAPI(),
        repo_root=ROOT,
        repository="mjgolaszewski/bcf-governance",
        apply=False,
    ).status == "clean"


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


def test_changelog_projection_uses_manifest_derived_version_transitions() -> None:
    original = b"# Changelog\n\n## [Unreleased]\n\nNo unreleased changes.\n"
    transition = DependencyTransition(
        "pytest", "==9.0.3", "==9.1.1", ("requirements-governance.txt",)
    )
    result = render_automation_changelog(
        original,
        repository_id=42,
        producer_id="dependabot",
        pr_number=7,
        source_state=SOURCE_A,
        dependency_paths=("requirements-governance.txt",),
        dependency_transitions=(transition,),
    )
    assert result.entry == (
        "- Automated dependency update `dependabot` from PR #7: "
        "`pytest` from `==9.0.3` to `==9.1.1` (`requirements-governance.txt`)."
    )


def test_dependency_transitions_are_derived_from_exact_manifest_bytes() -> None:
    content = {
        ("pyproject.toml", "base"): b'[project]\ndependencies=["demo==1.0"]\n',
        ("pyproject.toml", "head"): b'[project]\ndependencies=["demo==2.0"]\n',
        ("requirements.txt", "base"): b"demo==1.0\n",
        ("requirements.txt", "head"): b"demo==2.0\n",
    }
    transitions = derive_dependency_transitions(
        (
            {"path": "pyproject.toml", "kind": "python-pyproject"},
            {"path": "requirements.txt", "kind": "python-requirements"},
        ),
        content=lambda path, ref: content[(path, ref)],
        base_ref="base",
        head_ref="head",
    )
    assert transitions == (
        DependencyTransition(
            "demo", "==1.0", "==2.0", ("pyproject.toml", "requirements.txt")
        ),
    )


def test_dependency_transition_rejects_versionless_or_conflicting_changes() -> None:
    with pytest.raises(AutomationContractError, match="no version transition"):
        derive_dependency_transitions(
            ({"path": "requirements.txt", "kind": "python-requirements"},),
            content=lambda _path, _ref: b"demo==1.0\n",
            base_ref="base",
            head_ref="head",
        )
    content = {
        ("a.txt", "base"): b"demo==1.0\n",
        ("a.txt", "head"): b"demo==2.0\n",
        ("b.txt", "base"): b"demo==1.0\n",
        ("b.txt", "head"): b"demo==3.0\n",
    }
    with pytest.raises(AutomationContractError, match="disagree"):
        derive_dependency_transitions(
            (
                {"path": "a.txt", "kind": "python-requirements"},
                {"path": "b.txt", "kind": "python-requirements"},
            ),
            content=lambda path, ref: content[(path, ref)],
            base_ref="base",
            head_ref="head",
        )


@pytest.mark.parametrize(
    ("path", "kind", "before", "after", "dependency", "old", "new"),
    [
        ("requirements.txt", "python-requirements", b"demo==1\n", b"demo==2\n", "demo", "==1", "==2"),
        ("pyproject.toml", "python-pyproject", b'[project]\ndependencies=["demo>=1"]\n', b'[project]\ndependencies=["demo>=2"]\n', "demo", ">=1", ">=2"),
        ("uv.lock", "python-lock", b'[[package]]\nname="demo"\nversion="1"\n', b'[[package]]\nname="demo"\nversion="2"\n', "demo", "1", "2"),
        ("Pipfile.lock", "python-pipfile-lock", b'{"default":{"demo":{"version":"==1"}}}', b'{"default":{"demo":{"version":"==2"}}}', "demo", "==1", "==2"),
        ("package.json", "npm-package", b'{"dependencies":{"demo-js":"1"}}', b'{"dependencies":{"demo-js":"2"}}', "demo-js", "1", "2"),
        ("package-lock.json", "npm-lock", b'{"packages":{"node_modules/demo-js":{"version":"1"}}}', b'{"packages":{"node_modules/demo-js":{"version":"2"}}}', "demo-js", "1", "2"),
        (".github/workflows/ci.yml", "github-actions", b'jobs:\n  test:\n    steps:\n    - uses: actions/checkout@v4\n', b'jobs:\n  test:\n    steps:\n    - uses: actions/checkout@v5\n', "actions/checkout", "v4", "v5"),
        ("Dockerfile", "dockerfile", b"FROM python:3.13\n", b"FROM python:3.14\n", "python", "3.13", "3.14"),
    ],
)
def test_supported_dependency_manifests_have_exact_version_decoders(
    path: str,
    kind: str,
    before: bytes,
    after: bytes,
    dependency: str,
    old: str,
    new: str,
) -> None:
    content = {(path, "base"): before, (path, "head"): after}

    assert dependency_source_kind(path) == kind
    assert derive_dependency_transitions(
        ({"path": path, "kind": kind},),
        content=lambda source, ref: content[(source, ref)],
        base_ref="base",
        head_ref="head",
    ) == (DependencyTransition(dependency, old, new, (path,)),)


def test_dependency_source_kind_rejects_unparsed_dependency_authority() -> None:
    with pytest.raises(AutomationContractError, match="no deterministic version extractor"):
        dependency_source_kind("vendor/custom.dependencies")


@pytest.mark.parametrize(
    ("before", "after", "old", "new"),
    [(None, b"demo==2\n", "absent", "==2"), (b"demo==1\n", None, "==1", "absent")],
)
def test_dependency_transition_supports_added_and_removed_manifests(
    before: bytes | None, after: bytes | None, old: str, new: str
) -> None:
    content = {("requirements.txt", "base"): before, ("requirements.txt", "head"): after}
    assert derive_dependency_transitions(
        ({"path": "requirements.txt", "kind": "python-requirements"},),
        content=lambda path, ref: content[(path, ref)],
        base_ref="base",
        head_ref="head",
    ) == (DependencyTransition("demo", old, new, ("requirements.txt",)),)


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
    assert match.projection_output_paths == ()
    projected = select_producer(
        registry,
        repository="mjgolaszewski/bcf-governance",
        repository_id=1207503211,
        actor_id=49699333,
        actor_login="dependabot[bot]",
        head_repository_id=1207503211,
        head_branch="dependabot/pip/pytest-9.1",
        changed_paths=(
            "bcf_governance/pack/template-repo/.bcf-pack-manifest.json",
            "bcf_governance/pack/template-repo/requirements-governance.txt",
            "template-repo/.bcf-pack-manifest.json",
            "template-repo/requirements-governance.txt",
        ),
    )
    assert projected.dependency_paths == (
        "template-repo/requirements-governance.txt",
    )
    assert projected.projection_output_paths == (
        "bcf_governance/pack/template-repo/.bcf-pack-manifest.json",
        "bcf_governance/pack/template-repo/requirements-governance.txt",
        "template-repo/.bcf-pack-manifest.json",
    )
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
        },
        repository_paths=(
            ".github/dependabot.yml",
            ".github/workflows/governance.yml",
            "pyproject.toml",
            "requirements-governance.txt",
            "src/product.py",
            "template-repo/requirements-governance.txt",
        ),
    )
    assert classes == ("github-actions", "python")
    assert paths == (
        ".github/workflows/governance.yml",
        "pyproject.toml",
        "requirements-governance.txt",
        "template-repo/requirements-governance.txt",
    )
    classes, paths = dependabot_allowed_paths(
        {
            "version": 2,
            "updates": [{"package-ecosystem": "github-actions", "directory": "/"}],
        },
        repository_paths=(
            ".github/workflows/generated.yml",
            ".github/workflows/project-owned.yml",
        ),
        excluded_paths=(".github/workflows/generated.yml",),
    )
    assert classes == ("github-actions",)
    assert paths == (".github/workflows/project-owned.yml",)
    with pytest.raises(AutomationContractError, match="mechanical exclusions"):
        dependabot_allowed_paths(
            {
                "version": 2,
                "updates": [
                    {"package-ecosystem": "github-actions", "directory": "/"}
                ],
            },
            repository_paths=(".github/workflows/generated.yml",),
            excluded_paths=(".github/workflows/generated.yml",),
        )
    with pytest.raises(AutomationContractError, match="unsupported"):
        dependabot_allowed_paths(
            {"version": 2, "updates": [{"package-ecosystem": "terraform", "directory": "/"}]},
            repository_paths=("main.tf",),
        )


def test_dependabot_adoption_rejects_renderer_owned_only_action_surface(
    tmp_path: Path,
) -> None:
    (tmp_path / ".github/workflows").mkdir(parents=True)
    (tmp_path / "schemas").mkdir()
    (tmp_path / ".github/dependabot.yml").write_text(
        "version: 2\nupdates:\n- package-ecosystem: github-actions\n"
        "  directory: /\n  schedule: {interval: monthly}\n",
        encoding="utf-8",
    )
    (tmp_path / ".github/workflows/governance.yml").write_text(
        "# Generated by BCF; edit governance/ci-graph.yml or a registered extension.\n"
        "name: governance\n",
        encoding="utf-8",
    )
    shutil.copy2(
        ROOT / "schemas/automation-producers.schema.json",
        tmp_path / "schemas/automation-producers.schema.json",
    )
    subprocess.run(["git", "init", "-q", str(tmp_path)], check=True)
    subprocess.run(["git", "-C", str(tmp_path), "add", "."], check=True)
    with pytest.raises(AutomationContractError, match="mechanical exclusions"):
        adopt_dependabot(
            AdoptionAPI(),
            repo_root=tmp_path,
            repository="mjgolaszewski/bcf-governance",
            apply=False,
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
    (tmp_path / "requirements.txt").write_text("pytest==9.1.1\n", encoding="utf-8")
    subprocess.run(["git", "init", "-q", str(tmp_path)], check=True)
    subprocess.run(["git", "-C", str(tmp_path), "add", "."], check=True)
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

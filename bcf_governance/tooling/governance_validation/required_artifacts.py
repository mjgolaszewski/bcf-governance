"""Semantic contracts for standard repository root artifacts."""
# ruff: noqa: F403,F405

from __future__ import annotations

import subprocess

from ..release_versions import ReleaseVersionError, parse_release_version
from .common import *  # noqa: F403,F405


def _validate_required_artifacts(repo_root: Path, manifest: dict[str, Any]) -> list[Path]:
    required = _require_mapping(
        manifest.get("required_artifacts"),
        context="governance/artifact-manifest.yml required_artifacts",
    )
    contracts = {
        "readme": ("README.md", "project_readme"),
        "license": ("LICENSE", "license_text"),
        "changelog": ("CHANGELOG.md", "keep_a_changelog"),
    }
    paths: dict[str, Path] = {}
    for artifact_id, (expected_path, expected_contract) in contracts.items():
        declaration = _require_mapping(
            required.get(artifact_id),
            context=(
                "governance/artifact-manifest.yml required_artifacts."
                f"{artifact_id}"
            ),
        )
        declared_path = _require_string(
            declaration.get("path"),
            context=(
                "governance/artifact-manifest.yml required_artifacts."
                f"{artifact_id}.path"
            ),
        )
        if declared_path != expected_path or declaration.get("contract") != expected_contract:
            raise GovernanceValidationError(
                "governance/artifact-manifest.yml must require "
                f"{expected_path} with the {expected_contract} contract"
            )
        path = repo_root / declared_path
        if path.is_symlink() or not path.is_file():
            raise GovernanceValidationError(
                f"required artifact {expected_path} must be a regular file"
            )
        paths[artifact_id] = path

    changelog_declaration = _require_mapping(
        required.get("changelog"),
        context="governance/artifact-manifest.yml required_artifacts.changelog",
    )
    if changelog_declaration.get("pull_request_policy") != "required_update":
        raise GovernanceValidationError(
            "governance/artifact-manifest.yml must require a CHANGELOG.md update "
            "on every pull request"
        )

    try:
        readme_text = paths["readme"].read_text(encoding="utf-8")
        license_text = paths["license"].read_text(encoding="utf-8")
        changelog_lines = paths["changelog"].read_text(encoding="utf-8").splitlines()
    except UnicodeDecodeError as exc:
        raise GovernanceValidationError(
            "required artifacts README.md, LICENSE, and CHANGELOG.md must be UTF-8"
        ) from exc

    readme_first = next((line.strip() for line in readme_text.splitlines() if line.strip()), "")
    if not re.fullmatch(r"#\s+\S.*", readme_first):
        raise GovernanceValidationError("README.md must begin with a non-empty level-one heading")

    normalized_license = license_text.strip()
    license_markers = re.compile(
        r"(?:copyright|license|licensed|permission|public domain|spdx-license-identifier)",
        re.IGNORECASE,
    )
    if len(normalized_license) < 20 or license_markers.search(normalized_license) is None:
        raise GovernanceValidationError(
            "LICENSE must contain substantive license or copyright text"
        )

    first = next((line.strip() for line in changelog_lines if line.strip()), "")
    if first != "# Changelog":
        raise GovernanceValidationError("CHANGELOG.md must begin with '# Changelog'")
    level_two = [line.strip() for line in changelog_lines if line.startswith("## ")]
    if level_two.count("## [Unreleased]") != 1:
        raise GovernanceValidationError("CHANGELOG.md must contain exactly one '## [Unreleased]'")
    release_pattern = re.compile(r"## \[([^\]]+)\] - \d{4}-\d{2}-\d{2}")
    parsed_versions: list[str] = []
    malformed: list[str] = []
    for heading in level_two:
        if heading == "## [Unreleased]":
            continue
        match = release_pattern.fullmatch(heading)
        if match is None:
            malformed.append(heading)
            continue
        try:
            parsed_versions.append(parse_release_version(match.group(1)).value)
        except ReleaseVersionError:
            malformed.append(heading)
    if malformed:
        raise GovernanceValidationError(
            "CHANGELOG.md release headings must use a canonical public version "
            "in '## [VERSION] - YYYY-MM-DD': "
            + ", ".join(malformed)
        )
    if len(parsed_versions) != len(set(parsed_versions)):
        raise GovernanceValidationError("CHANGELOG.md release versions must be unique")
    _validate_changelog_workflow_contract(repo_root)
    _validate_pull_request_changelog_update(repo_root)
    return list(paths.values())


def _validate_changelog_workflow_contract(repo_root: Path) -> None:
    workflow_path = repo_root / ".github/workflows/governance.yml"
    workflow = _load_yaml(workflow_path)
    environment = _require_mapping(
        workflow.get("env"), context=".github/workflows/governance.yml env"
    )
    expected = {
        "BCF_ENFORCE_PR_CHANGELOG": "${{ github.event_name == 'pull_request' }}",
        "BCF_PR_BASE_SHA": "${{ github.event.pull_request.base.sha }}",
    }
    if any(environment.get(name) != value for name, value in expected.items()):
        raise GovernanceValidationError(
            ".github/workflows/governance.yml must enforce CHANGELOG.md against "
            "the exact pull-request base SHA"
        )


def _validate_pull_request_changelog_update(repo_root: Path) -> None:
    enforce = os.environ.get("BCF_ENFORCE_PR_CHANGELOG", "").lower()
    if enforce not in {"1", "true"}:
        return
    if os.environ.get("GITHUB_EVENT_NAME") not in {"pull_request", "pull_request_target"}:
        raise GovernanceValidationError(
            "pull-request changelog enforcement requires a pull-request event"
        )
    base_sha = os.environ.get("BCF_PR_BASE_SHA", "")
    if re.fullmatch(r"[a-fA-F0-9]{40}", base_sha) is None:
        raise GovernanceValidationError(
            "pull-request changelog enforcement requires BCF_PR_BASE_SHA"
        )
    available = subprocess.run(
        ["git", "-C", str(repo_root), "cat-file", "-e", f"{base_sha}^{{commit}}"],
        capture_output=True,
        text=True,
        check=False,
    )
    if available.returncode != 0:
        raise GovernanceValidationError(
            "pull-request changelog base commit is unavailable; CI must checkout full history"
        )
    changed = subprocess.run(
        [
            "git",
            "-C",
            str(repo_root),
            "diff",
            "--name-only",
            f"{base_sha}...HEAD",
            "--",
            "CHANGELOG.md",
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    if changed.returncode != 0:
        raise GovernanceValidationError(
            "pull-request changelog diff could not be computed: " + changed.stderr.strip()
        )
    if "CHANGELOG.md" not in changed.stdout.splitlines():
        raise GovernanceValidationError("every pull request must update CHANGELOG.md")

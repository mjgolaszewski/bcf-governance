from __future__ import annotations

from datetime import datetime, timezone
import shutil
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

from bcf_governance.tooling.profile_contract_v2 import (
    ProfileV2Error,
    resolve_install_contract_version,
    validate_profile_v2_readiness,
)
from bcf_governance.tooling.ci_adopt_github import render_github_adoption
from bcf_governance.tooling.profile_v2_surfaces import (
    render_v2_makefile,
    render_v2_workflow,
)


REPO_ROOT = Path(__file__).resolve().parents[1]


def _git(repo: Path, *args: str) -> str:
    return subprocess.run(
        ["git", *args], cwd=repo, check=True, capture_output=True, text=True
    ).stdout.strip()


def _profile_repo(tmp_path: Path) -> Path:
    repo = tmp_path / "consumer"
    shutil.copytree(REPO_ROOT / "template-repo", repo)
    _git(repo, "init", "--quiet")
    _git(repo, "config", "user.email", "profile-v2@example.invalid")
    _git(repo, "config", "user.name", "Profile V2")
    _git(repo, "add", ".")
    _git(repo, "commit", "--quiet", "-m", "install governed consumer")
    return repo


def _na_record(subject_commit: str, *, trigger: dict[str, str] | None = None) -> dict:
    record = {
        "schema_version": "1.0",
        "record_id": "typescript-not-present",
        "subject": {"kind": "capability", "id": "typescript"},
        "repository_scope": "tracked source tree",
        "rationale": "No tracked TypeScript roots exist.",
        "supporting_evidence": ["git ls-files"],
        "approving_governance_role": "maintainer",
        "subject_commit": subject_commit,
        "profile": "standard",
        "profile_contract_version": "2.0",
        "reviewed_at": "2026-08-30T00:00:00Z",
        "release_claim_uses_ci_evidence": False,
    }
    if trigger is None:
        record["expires_at"] = "2026-09-30T00:00:00Z"
    else:
        record["re_review_trigger"] = trigger
    return record


def test_fresh_versions_and_upgrades_are_backward_compatible(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    assert resolve_install_contract_version(repo, None, None, False) == (
        "standard",
        "2.0",
    )
    assert resolve_install_contract_version(repo, "lite", None, False) == (
        "lite",
        "1.0",
    )
    (repo / "governance-profile.yml").write_text(
        "profile:\n  selected: standard\n", encoding="utf-8"
    )
    assert resolve_install_contract_version(repo, None, None, True) == (
        "standard",
        "1.0",
    )
    with pytest.raises(ProfileV2Error, match="use bcf profile promote"):
        resolve_install_contract_version(repo, None, "2.0", True)
    with pytest.raises(ProfileV2Error, match="profile changes"):
        resolve_install_contract_version(repo, "regulated", None, True)


def test_typed_na_is_ancestor_bound_and_expires(tmp_path: Path) -> None:
    repo = _profile_repo(tmp_path)
    subject = _git(repo, "rev-parse", "HEAD")
    path = repo / "governance/capability-na/typescript.yml"
    path.parent.mkdir(parents=True)
    path.write_text(yaml.safe_dump(_na_record(subject), sort_keys=False), encoding="utf-8")
    _git(repo, "add", ".")
    _git(repo, "commit", "--quiet", "-m", "record typed applicability decision")

    report = validate_profile_v2_readiness(
        repo,
        profile="standard",
        evaluated_at=datetime(2026, 9, 1, tzinfo=timezone.utc),
    )
    assert report.capability_na_records == 1
    with pytest.raises(ProfileV2Error, match="expired"):
        validate_profile_v2_readiness(
            repo,
            profile="standard",
            evaluated_at=datetime(2026, 10, 1, tzinfo=timezone.utc),
        )


def test_typed_na_re_review_trigger_fails_closed(tmp_path: Path) -> None:
    repo = _profile_repo(tmp_path)
    subject = _git(repo, "rev-parse", "HEAD")
    path = repo / "governance/capability-na/typescript.yml"
    path.parent.mkdir(parents=True)
    path.write_text(
        yaml.safe_dump(
            _na_record(
                subject,
                trigger={"kind": "tracked_path_exists", "value": "tsconfig.json"},
            ),
            sort_keys=False,
        ),
        encoding="utf-8",
    )
    _git(repo, "add", ".")
    _git(repo, "commit", "--quiet", "-m", "record path-triggered decision")
    validate_profile_v2_readiness(repo, profile="standard")
    (repo / "tsconfig.json").write_text("{}\n", encoding="utf-8")
    _git(repo, "add", ".")
    _git(repo, "commit", "--quiet", "-m", "introduce applicable capability")
    with pytest.raises(ProfileV2Error, match="re-review trigger is active"):
        validate_profile_v2_readiness(repo, profile="standard")


def test_declared_github_topology_requires_exact_installed_workflows(
    tmp_path: Path,
) -> None:
    repo = _profile_repo(tmp_path)
    desired = render_github_adoption(
        default_branch="main",
        candidate_labels=("ubuntu-latest",),
        trusted_labels=("self-hosted", "trusted"),
        producer_argv=("python3", "scripts/release_check.py"),
    )
    (repo / "governance/github-ci-topology.yml").write_bytes(
        desired["governance/github-ci-topology.yml"]
    )
    _git(repo, "add", ".")
    _git(repo, "commit", "--quiet", "-m", "declare incomplete topology")

    with pytest.raises(ProfileV2Error, match="missing managed workflows"):
        validate_profile_v2_readiness(repo, profile="standard")


def test_v2_surfaces_bind_one_session_and_do_not_wait() -> None:
    contract = {
        "profile_contract_version": "2.0",
        "gates": {
            "governance-validate": {
                "invocation": {
                    "argv": ["python3", "scripts/validate_governance_yaml.py"],
                    "cwd": ".",
                    "env": {},
                }
            }
        },
    }
    makefile = render_v2_makefile(contract)
    workflow_text = render_v2_workflow(contract, ["ubuntu-latest"])
    workflow = yaml.safe_load(workflow_text)

    assert "scripts/preflight_governance.py" in makefile
    assert 'session_dir="$${session%/evidence-session.json}"' in makefile
    assert workflow["jobs"]["evidence"]["needs"] == ["preflight"]
    assert workflow["jobs"]["governance-truthfulness"]["needs"] == [
        "preflight",
        "evidence",
    ]
    assert "github.run_attempt" in workflow_text
    assert "persist-credentials: false" in workflow_text
    assert "merge-multiple: true" not in workflow_text
    assert not any(value in workflow_text for value in ("sleep ", "poll", "while "))


def test_bcf_standard_v2_promotion_fits_declared_context_budgets(tmp_path: Path) -> None:
    repo = tmp_path / "bcf-self-adoption"
    shutil.copytree(
        REPO_ROOT,
        repo,
        ignore=shutil.ignore_patterns(".git", ".artifacts", ".venv", "__pycache__"),
    )
    _git(repo, "init", "--quiet")
    _git(repo, "config", "user.email", "profile-v2@example.invalid")
    _git(repo, "config", "user.name", "Profile V2")
    _git(repo, "add", ".")
    _git(repo, "commit", "--quiet", "-m", "copy exact BCF consumer")
    result = subprocess.run(
        [
            sys.executable,
            str(REPO_ROOT / "scripts/profile_governance.py"),
            "--repo-root",
            str(repo),
            "--to",
            "standard",
            "--contract-version",
            "2.0",
            "--check",
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stdout + result.stderr

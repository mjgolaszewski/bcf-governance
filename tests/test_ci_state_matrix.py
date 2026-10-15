from __future__ import annotations

from pathlib import Path
import subprocess

import pytest

from bcf_governance.tooling.governance_validation.ci_state_matrix import (
    CIStateMatrixError,
    validate_ci_state_matrix,
)


ROOT = Path(__file__).resolve().parents[1]


def _git(repo: Path, *args: str) -> str:
    return subprocess.run(
        ["git", *args], cwd=repo, capture_output=True, text=True, check=True
    ).stdout.strip()


def _repo(tmp_path: Path) -> Path:
    repo = tmp_path / "repo"
    (repo / "spec/phase0").mkdir(parents=True)
    (repo / "bcf_governance/tooling").mkdir(parents=True)
    (repo / "spec/RELEASE_TRAIN_STATE_DAG.md").write_bytes(
        (ROOT / "spec/RELEASE_TRAIN_STATE_DAG.md").read_bytes()
    )
    (repo / "spec/phase0/release-train-backtrace.yml").write_bytes(
        (ROOT / "spec/phase0/release-train-backtrace.yml").read_bytes()
    )
    (repo / "bcf_governance/tooling/preflight.py").write_text("VALUE = 1\n")
    _git(repo, "init", "--initial-branch=main")
    _git(repo, "config", "user.name", "BCF Test")
    _git(repo, "config", "user.email", "bcf@example.invalid")
    _git(repo, "add", ".")
    _git(repo, "commit", "-m", "base")
    _git(repo, "remote", "add", "origin", str(repo))
    _git(repo, "fetch", "origin", "main")
    return repo


def test_changed_ci_contract_requires_same_candidate_matrix_update(tmp_path: Path) -> None:
    repo = _repo(tmp_path)
    (repo / "bcf_governance/tooling/preflight.py").write_text("VALUE = 2\n")
    with pytest.raises(CIStateMatrixError, match="same-candidate state matrix"):
        validate_ci_state_matrix(repo)
    with (repo / "spec/RELEASE_TRAIN_STATE_DAG.md").open("a", encoding="utf-8") as stream:
        stream.write("\nCandidate-specific transition coverage.\n")
    report = validate_ci_state_matrix(repo)
    assert report["changed_contracts"] == ["bcf_governance/tooling/preflight.py", "spec/RELEASE_TRAIN_STATE_DAG.md"]
    assert report["machine_backtrace"] == {"edges": 19, "transitions": 15}


def test_machine_backtrace_rejects_an_incomplete_edge_before_ci_allocation(
    tmp_path: Path,
) -> None:
    repo = _repo(tmp_path)
    path = repo / "spec/phase0/release-train-backtrace.yml"
    path.write_text(
        path.read_text(encoding="utf-8").replace(
            "authority_effect: release_transaction_identity_only, ", "", 1
        ),
        encoding="utf-8",
    )
    with pytest.raises(CIStateMatrixError, match="AS-000 lacks: authority_effect"):
        validate_ci_state_matrix(repo)


def test_matrix_guard_is_self_required_and_adopter_inapplicable(tmp_path: Path) -> None:
    adopter = tmp_path / "adopter"
    adopter.mkdir()
    assert validate_ci_state_matrix(adopter)["status"] == "not_applicable_to_adopter"
    (adopter / "governance").mkdir()
    (adopter / "governance/self-governance-policy.yml").write_text("document: {}\n")
    with pytest.raises(CIStateMatrixError, match="unavailable"):
        validate_ci_state_matrix(adopter)

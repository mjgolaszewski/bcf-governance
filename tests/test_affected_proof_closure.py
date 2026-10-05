from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from bcf_governance.tooling.affected_proof_closure import (
    derive_affected_proof_set,
    verify_session_affected_proof_set,
)
from bcf_governance.tooling.evidence_execution import EvidenceError


def _git(root: Path, *args: str) -> str:
    return subprocess.check_output(["git", *args], cwd=root, text=True).strip()


def _repo(tmp_path: Path) -> tuple[Path, str, str, dict]:
    root = tmp_path / "repo"
    root.mkdir()
    subprocess.run(["git", "init", "-q"], cwd=root, check=True)
    subprocess.run(["git", "config", "user.email", "test@example.invalid"], cwd=root, check=True)
    subprocess.run(["git", "config", "user.name", "Test"], cwd=root, check=True)
    for relative, value in {
        "src/app.py": "VALUE = 1\n",
        "tests/test_app.py": "def test_app(): pass\n",
        "docs/guide.md": "guide\n",
    }.items():
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(value, encoding="utf-8")
    subprocess.run(["git", "add", "."], cwd=root, check=True)
    subprocess.run(["git", "commit", "-qm", "base"], cwd=root, check=True)
    commit, tree = _git(root, "rev-parse", "HEAD"), _git(root, "rev-parse", "HEAD^{tree}")
    model = {
        "version": "1.0",
        "dependency_sets": {
            "source": ["src/**"],
            "tests": ["tests/**"],
            "empty": ["never/**"],
            "editorial": ["docs/**"],
        },
        "non_proof_dependencies": ["editorial"],
        "execution_groups": {
            "test": {"producer": "test", "claims": ["app-valid"]},
        },
        "claims": {
            "app-valid": {
                "execution_group": "test",
                "dependencies": {
                    "subject": ["source"],
                    "detector": ["empty"],
                    "test_population": ["tests"],
                    "toolchain": ["empty"],
                    "trust": ["empty"],
                },
            },
        },
    }
    return root, commit, tree, model


def _subject(root: Path) -> dict[str, str]:
    return {
        "commit_sha": _git(root, "rev-parse", "HEAD"),
        "tree_sha": _git(root, "rev-parse", "HEAD^{tree}"),
    }


def test_dormant_v3_truth_recomputes_exact_affected_proof_set(tmp_path: Path) -> None:
    root, prior_commit, prior_tree, model = _repo(tmp_path)
    (root / "src/app.py").write_text("VALUE = 2\n", encoding="utf-8")
    subprocess.run(["git", "commit", "-qam", "change source"], cwd=root, check=True)
    affected = derive_affected_proof_set(
        root, model, ["app-valid"], current_subject=_subject(root),
        prior_subjects=[(prior_commit, prior_tree)],
    )
    assert affected["classifications"][0]["classification"] == "required"
    session = {"required_claims": ["app-valid"], "affected_proof_set": affected}
    receipt = {"subject": {"commit_sha": prior_commit, "tree_sha": prior_tree}}

    verify_session_affected_proof_set(
        root, model, session, current_subject=_subject(root), prior_receipts=[receipt],
    )
    session["affected_proof_set"] = {**affected, "classifications": []}
    with pytest.raises(EvidenceError, match="canonical reachability"):
        verify_session_affected_proof_set(
            root, model, session, current_subject=_subject(root), prior_receipts=[receipt],
        )


def test_unknown_change_expands_instead_of_becoming_unaffected(tmp_path: Path) -> None:
    root, prior_commit, prior_tree, model = _repo(tmp_path)
    (root / "unknown.txt").write_text("unknown\n", encoding="utf-8")
    subprocess.run(["git", "add", "unknown.txt"], cwd=root, check=True)
    subprocess.run(["git", "commit", "-qm", "unknown"], cwd=root, check=True)

    affected = derive_affected_proof_set(
        root, model, ["app-valid"], current_subject=_subject(root),
        prior_subjects=[(prior_commit, prior_tree)],
    )
    assert affected["unknown_paths"] == ["unknown.txt"]
    assert affected["classifications"][0]["classification"] == "ambiguous_requires_execution"

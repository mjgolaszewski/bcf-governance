from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
HARNESS = REPO_ROOT / ".github/scripts/run_validator_mutants.py"


def test_broken_mutation_baseline_aborts_without_claiming_kills(tmp_path: Path) -> None:
    env = dict(os.environ)
    env["PYTEST_ADDOPTS"] = "--bcf-invalid-option"

    result = subprocess.run(
        [
            sys.executable,
            str(HARNESS),
            "--profile",
            "semantic-high-value",
            "--mutant",
            "truth-current-tree",
        ],
        cwd=REPO_ROOT,
        env=env,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 2
    assert "mutation baseline failed; no mutant results are valid" in result.stderr
    assert "killed by declared test node" not in result.stdout


def test_mutant_harness_uses_its_selected_python_for_pytest() -> None:
    source = HARNESS.read_text(encoding="utf-8")
    assert 'PYTEST = (sys.executable, "-m", "pytest")' in source
    assert "shutil.which(\"pytest\")" not in source


def test_mutant_harness_emits_exact_subject_result(tmp_path: Path) -> None:
    output = tmp_path / "mutant-result.json"
    result = subprocess.run(
        [
            sys.executable,
            str(HARNESS),
            "--profile",
            "semantic-high-value",
            "--mutant",
            "truth-current-tree",
            "--output",
            str(output),
        ],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0, result.stderr
    report = json.loads(output.read_text(encoding="utf-8"))
    commit = subprocess.run(
        ["git", "rev-parse", "HEAD"], cwd=REPO_ROOT,
        check=True, capture_output=True, text=True,
    ).stdout.strip()
    tree = subprocess.run(
        ["git", "rev-parse", "HEAD^{tree}"], cwd=REPO_ROOT,
        check=True, capture_output=True, text=True,
    ).stdout.strip()
    status = subprocess.run(
        ["git", "status", "--porcelain=v1", "--untracked-files=all"], cwd=REPO_ROOT,
        check=True, capture_output=True, text=True,
    ).stdout.strip()
    assert report["kind"] == "scheduled_mutant_result"
    assert report["subject"] == {
        "commit_sha": commit,
        "tree_sha": tree,
        "status_porcelain": status,
    }
    assert report["result"] == "passed"
    assert report["summary"] == {
        "expected": 1,
        "killed": 1,
        "survived": 0,
        "infrastructure_failures": 0,
    }
    assert report["mutants"][0]["status"] == "killed"

from __future__ import annotations

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

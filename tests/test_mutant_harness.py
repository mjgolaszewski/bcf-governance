from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
HARNESS = REPO_ROOT / ".github/scripts/run_validator_mutants.py"


def test_broken_mutation_baseline_aborts_without_claiming_kills(tmp_path: Path) -> None:
    fake_pytest = tmp_path / "pytest"
    fake_pytest.write_text(
        '#!/bin/sh\nprintf "%s" "$PYTHONPATH" > "$MUTANT_ENV_CAPTURE"\nexit 1\n',
        encoding="utf-8",
    )
    fake_pytest.chmod(0o755)
    env_capture = tmp_path / "pythonpath.txt"
    env = dict(os.environ)
    env["PATH"] = str(tmp_path)
    env["MUTANT_ENV_CAPTURE"] = str(env_capture)

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
    assert env_capture.read_text(encoding="utf-8").split(os.pathsep)[0] == str(REPO_ROOT)

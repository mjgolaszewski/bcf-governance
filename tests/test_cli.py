from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]


def _run_bcf(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "-m", "bcf_governance.cli", *args],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
    )


def test_cli_reports_version() -> None:
    result = _run_bcf("--version")

    assert result.returncode == 0
    assert "bcf 0.1.0" in result.stdout


def test_cli_validate_dispatches_to_validator() -> None:
    result = _run_bcf(
        "validate",
        "--repo-root",
        "template-repo",
        "--allow-placeholders",
        "--allow-release-gate-placeholders",
        "--format",
        "json",
        "--compact",
    )

    assert result.returncode == 0
    assert json.loads(result.stdout)["status"] == "pass"

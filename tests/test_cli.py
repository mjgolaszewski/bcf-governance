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
    assert "bcf 0.4.4" in result.stdout


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


def test_cli_cleanup_dispatches_to_cleanup_planner(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    (repo / "docs/audits").mkdir(parents=True)
    (repo / "docs/audits/security.md").write_text("# Security\n", encoding="utf-8")

    result = _run_bcf(
        "cleanup",
        "--repo-root",
        str(repo),
        "--format",
        "json",
        "--compact",
    )

    assert result.returncode == 0
    payload = json.loads(result.stdout)
    assert payload["status"] == "actionable"
    assert payload["actions"][0]["kind"] == "create_audit_readme"


def test_cli_exposure_scan_dispatches_to_scanner() -> None:
    result = _run_bcf(
        "exposure-scan",
        "--repo-root",
        "template-repo",
        "--format",
        "json",
        "--compact",
    )

    assert result.returncode == 0
    assert json.loads(result.stdout)["status"] == "pass"

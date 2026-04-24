from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import yaml


REPO_ROOT = Path(__file__).resolve().parents[1]
INSTALLER = REPO_ROOT / "scripts" / "install_governance_pack.py"


def _run_installer(target: Path, *args: str, check: bool = True) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [
            sys.executable,
            str(INSTALLER),
            "--target",
            str(target),
            "--project-id",
            "demo",
            "--project-name",
            "Demo Project",
            "--product-name",
            "Demo Product",
            "--date",
            "2026-04-24",
            *args,
        ],
        check=check,
        capture_output=True,
        text=True,
    )


def _run_installed_validator(
    target: Path, *, allow_placeholders: bool = False
) -> subprocess.CompletedProcess[str]:
    command = [
        sys.executable,
        str(target / "scripts/validate_governance_yaml.py"),
        "--repo-root",
        str(target),
        "--format",
        "json",
        "--compact",
    ]
    if allow_placeholders:
        command.append("--allow-placeholders")
    return subprocess.run(command, capture_output=True, text=True)


def test_installer_bootstraps_standard_profile_and_reports_unwired_gates(tmp_path: Path) -> None:
    target = tmp_path / "demo-standard"
    result = _run_installer(target)

    assert "validation: bootstrap pass" in result.stdout
    assert "wire release gates: architecture-test, lint, typecheck, test, contract-test" in result.stdout
    assert not (target / "plans/phase-NN-plan.yml").exists()
    assert not (target / "phases/phase-NN-log.yml").exists()
    assert (target / ".github/workflows/governance.yml").exists()

    plan = yaml.safe_load((target / "plans/phase-01-plan.yml").read_text(encoding="utf-8"))
    assert plan["document"]["path"] == "plans/phase-01-plan.yml"
    assert plan["delivery_contract"]["tightly_scoped_deliverables"] == [
        "initial governed foundation"
    ]

    profile = yaml.safe_load((target / "governance-profile.yml").read_text(encoding="utf-8"))
    assert profile["profile"]["selected"] == "standard"

    strict = _run_installed_validator(target)
    assert strict.returncode == 1
    assert "release gate placeholder marker" in json.loads(strict.stdout)["error"]

    bootstrap = _run_installed_validator(target, allow_placeholders=True)
    assert bootstrap.returncode == 0
    assert json.loads(bootstrap.stdout)["status"] == "pass"


def test_installer_lite_profile_passes_strict_validation(tmp_path: Path) -> None:
    target = tmp_path / "demo-lite"
    result = _run_installer(target, "--profile", "lite", "--require-strict-validation")

    assert "validation: strict pass" in result.stdout
    profile = yaml.safe_load((target / "governance-profile.yml").read_text(encoding="utf-8"))
    assert profile["profile"]["selected"] == "lite"
    assert profile["release_gate_profile"]["gates"]["lint"]["status"] == "deferred"

    makefile = (target / "Makefile.fragment").read_text(encoding="utf-8")
    assert "$(MAKE) governance-validate" in makefile
    assert "$(MAKE) lint" not in makefile

    strict = _run_installed_validator(target)
    assert strict.returncode == 0
    assert json.loads(strict.stdout)["status"] == "pass"


def test_installer_gate_commands_can_make_standard_profile_strict(tmp_path: Path) -> None:
    target = tmp_path / "demo-standard-strict"
    result = _run_installer(
        target,
        "--gate-command",
        "architecture-test=python3 --version >/dev/null",
        "--gate-command",
        "lint=python3 --version >/dev/null",
        "--gate-command",
        "typecheck=python3 --version >/dev/null",
        "--gate-command",
        "test=python3 --version >/dev/null",
        "--gate-command",
        "contract-test=python3 --version >/dev/null",
        "--require-strict-validation",
    )

    assert "validation: strict pass" in result.stdout
    strict = _run_installed_validator(target)
    assert strict.returncode == 0


def test_installer_refuses_to_overwrite_without_force(tmp_path: Path) -> None:
    target = tmp_path / "existing"
    target.mkdir()
    (target / "AGENTS.yml").write_text("existing\n", encoding="utf-8")

    result = _run_installer(target, check=False)

    assert result.returncode == 1
    assert "--force" in result.stderr

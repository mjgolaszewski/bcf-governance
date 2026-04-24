from __future__ import annotations

import importlib.util
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest
import yaml


REPO_ROOT = Path(__file__).resolve().parents[1]
SCAFFOLD_MODULE_PATH = REPO_ROOT / "scripts" / "scaffold_governance_artifacts.py"


def _load_scaffold_module() -> Any:
    spec = importlib.util.spec_from_file_location(
        "scaffold_governance_artifacts",
        SCAFFOLD_MODULE_PATH,
    )
    if spec is None or spec.loader is None:
        raise RuntimeError(f"unable to load scaffold module from {SCAFFOLD_MODULE_PATH}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


SCAFFOLD_MODULE = _load_scaffold_module()


def test_scaffold_phase_artifacts_creates_expected_files_and_payloads(tmp_path: Path) -> None:
    created = SCAFFOLD_MODULE.scaffold_phase_artifacts(
        repo_root=tmp_path,
        project_id="demo",
        phase_id="P03",
        build_block="hardening",
        objective="close validation gaps",
        planner="codex",
        date="2026-04-24",
        hard_dependencies=["P02"],
        deliverables=["validator coverage", "scaffold coverage"],
        workstreams=["validator_tests", "scaffold_tests"],
        verification_commands=["pytest tests", "python3 scripts/validate_governance_yaml.py"],
        force=False,
    )

    assert {name: path.relative_to(tmp_path).as_posix() for name, path in created.items()} == {
        "plan": "plans/phase-03-plan.yml",
        "workitems": "plans/phase-03-workitems.yml",
        "log": "phases/phase-03-log.yml",
    }

    plan_payload = yaml.safe_load(created["plan"].read_text(encoding="utf-8"))
    assert plan_payload["document"]["path"] == "plans/phase-03-plan.yml"
    assert plan_payload["phase"] == {
        "id": "P03",
        "build_block": "hardening",
        "planner": "codex",
        "date": "2026-04-24",
        "scope_source": [
            "AGENTS.yml",
            "plans/product-spec.yml",
            "plans/build-plan.yml",
            "plans/phase-ledger.yml",
            "MEMORY.yml",
        ],
    }
    assert plan_payload["delivery_contract"]["parallelizable_workstreams"] == [
        {"id": "P03-WS1", "name": "validator_tests"},
        {"id": "P03-WS2", "name": "scaffold_tests"},
    ]
    assert plan_payload["verification_plan"] == [
        "pytest tests",
        "python3 scripts/validate_governance_yaml.py",
    ]

    workitems_payload = yaml.safe_load(created["workitems"].read_text(encoding="utf-8"))
    assert workitems_payload["document"]["path"] == "plans/phase-03-workitems.yml"
    assert [item["summary"] for item in workitems_payload["workitems"]] == [
        "deliver validator coverage",
        "deliver scaffold coverage",
    ]

    log_payload = yaml.safe_load(created["log"].read_text(encoding="utf-8"))
    assert log_payload["document"]["path"] == "phases/phase-03-log.yml"
    assert log_payload["summary"]["highlights"][0] == "P03 is opened for close validation gaps"
    assert log_payload["execution_evidence"]["planned_commands"] == [
        "pytest tests",
        "python3 scripts/validate_governance_yaml.py",
    ]


def test_scaffold_phase_artifacts_require_force_to_overwrite(tmp_path: Path) -> None:
    kwargs = {
        "repo_root": tmp_path,
        "project_id": "demo",
        "phase_id": "P01",
        "build_block": "foundation",
        "objective": "bootstrap",
        "planner": "codex",
        "date": "2026-04-24",
        "hard_dependencies": [],
        "deliverables": ["foundation"],
        "workstreams": ["bootstrap"],
        "verification_commands": ["pytest tests"],
    }
    SCAFFOLD_MODULE.scaffold_phase_artifacts(force=False, **kwargs)
    with pytest.raises(FileExistsError):
        SCAFFOLD_MODULE.scaffold_phase_artifacts(force=False, **kwargs)
    SCAFFOLD_MODULE.scaffold_phase_artifacts(force=True, **kwargs)


def test_scaffold_hotfix_log_uses_phase_numbered_filename_and_mode(tmp_path: Path) -> None:
    created = SCAFFOLD_MODULE.scaffold_hotfix_log(
        repo_root=tmp_path,
        project_id="demo",
        hotfix_id="HF-002",
        mode="lite",
        hotfix_number=2,
        summary="repair validation output",
        related_phase_id="P03",
        date="2026-04-24",
        validation_commands=["pytest tests", "python3 scripts/validate_governance_yaml.py"],
        force=False,
    )

    assert created.relative_to(tmp_path).as_posix() == "phases/phase-03-hotfix02.yml"
    payload = yaml.safe_load(created.read_text(encoding="utf-8"))
    assert payload["document"]["path"] == "phases/phase-03-hotfix02.yml"
    assert payload["hotfix"] == {
        "id": "HF-002",
        "mode": "lite",
        "related_phase_id": "P03",
        "hotfix_number": 2,
        "summary": "repair validation output",
    }
    assert payload["execution_evidence"]["planned_commands"] == [
        "pytest tests",
        "python3 scripts/validate_governance_yaml.py",
    ]


def test_scaffold_hotfix_cli_prints_relative_log_path(tmp_path: Path) -> None:
    result = subprocess.run(
        [
            sys.executable,
            str(SCAFFOLD_MODULE_PATH),
            "--repo-root",
            str(tmp_path),
            "--project-id",
            "demo",
            "hotfix",
            "--hotfix-id",
            "HF-003",
            "--mode",
            "full",
            "--hotfix-number",
            "3",
            "--summary",
            "repair release blocker",
            "--related-phase-id",
            "P04",
            "--date",
            "2026-04-24",
            "--validation-command",
            "pytest tests",
        ],
        check=True,
        capture_output=True,
        text=True,
    )
    assert result.stdout.strip() == "hotfix_log: phases/phase-04-hotfix03.yml"

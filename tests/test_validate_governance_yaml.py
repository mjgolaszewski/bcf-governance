from __future__ import annotations

import importlib.util
import json
import os
import shutil
import subprocess
from pathlib import Path
import sys
from typing import Any

import pytest
import yaml


REPO_ROOT = Path(__file__).resolve().parents[1]
FIXTURES_ROOT = REPO_ROOT / "tests" / "fixtures"
TEMPLATE_REPO_ROOT = REPO_ROOT / "template-repo"
VALIDATOR_MODULE_PATH = Path(
    os.environ.get(
        "BCF_VALIDATOR_MODULE_PATH",
        str(REPO_ROOT / "scripts" / "validate_governance_yaml.py"),
    )
).resolve()


def _load_validator_module() -> Any:
    spec = importlib.util.spec_from_file_location("validate_governance_yaml", VALIDATOR_MODULE_PATH)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"unable to load validator module from {VALIDATOR_MODULE_PATH}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


VALIDATOR_MODULE = _load_validator_module()
GovernanceValidationError = VALIDATOR_MODULE.GovernanceValidationError
validate_repo_root = VALIDATOR_MODULE.validate_repo_root


def _placeholder_values(repo_root: Path) -> dict[str, str]:
    return {
        "ACTIVE_PHASE_ID": "P01",
        "BACKEND_ARCHITECTURE": "cqrs_lite_with_strict_ports",
        "BUILD_BLOCK": "foundation",
        "CURRENT_TRANCHE": "governed_bootstrap",
        "DATA_ARCHITECTURE": "postgres",
        "DATE": "2026-04-24",
        "DELIVERABLE": "governed_foundation",
        "DEPENDENCY_PHASE_ID": "P01",
        "EXTERNAL_DEPENDENCY": "github_actions",
        "FRONTEND_ARCHITECTURE": "route_modules_thin_components",
        "HOTFIX_ID": "HF-TEMPLATE",
        "HOTFIX_MODE": "full",
        "HOTFIX_NUMBER": "1",
        "HOTFIX_SUMMARY": "template_hotfix",
        "NON_GOAL": "undefined_scope",
        "OPERATING_CONSTRAINT": "single_service_bootstrap",
        "PHASE_NUMBER": "01",
        "PHASE_OBJECTIVE": "establish governed foundation",
        "PLACEHOLDER": "TOKEN",
        "PLANNER": "codex",
        "PRODUCT_NAME": "Demo Product",
        "PRODUCT_POSITIONING": "governed demo product",
        "PROJECT_ID": "demo",
        "PROJECT_NAME": "Demo Project",
        "RELATED_PHASE_ID": "P01",
        "REPO_ROOT": str(repo_root),
        "RUNNER_LABELS": "ubuntu-latest",
        "TARGET_USER": "operators",
        "VALIDATION_COMMAND": "make governance-validate",
        "WORKSTREAM": "bootstrap_pack",
    }


def _replace_placeholders(repo_root: Path) -> None:
    replacements = {
        f"{{{{{key}}}}}": value for key, value in _placeholder_values(repo_root).items()
    }
    for path in sorted(repo_root.rglob("*")):
        if not path.is_file():
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            continue
        updated = text
        for placeholder, replacement in replacements.items():
            updated = updated.replace(placeholder, replacement)
        if updated != text:
            path.write_text(updated, encoding="utf-8")


def _copy_fixture_overrides(repo_root: Path, fixture_name: str) -> None:
    fixture_repo_root = FIXTURES_ROOT / fixture_name / "repo"
    if fixture_repo_root.exists():
        shutil.copytree(fixture_repo_root, repo_root, dirs_exist_ok=True)


def _load_fixture_mutations(fixture_name: str) -> list[dict[str, Any]]:
    mutation_path = FIXTURES_ROOT / fixture_name / "mutation.yml"
    if not mutation_path.exists():
        return []
    payload = yaml.safe_load(mutation_path.read_text(encoding="utf-8")) or {}
    mutations = payload.get("mutations", [])
    if not isinstance(mutations, list):
        raise RuntimeError(f"{mutation_path} must define a mutations list")
    return mutations


def _resolve_path_token(container: Any, token: str) -> Any:
    if isinstance(container, list):
        return container[int(token)]
    return container[token]


def _set_path(container: Any, dotted_path: str, value: Any) -> None:
    tokens = dotted_path.split(".")
    current = container
    for token in tokens[:-1]:
        current = _resolve_path_token(current, token)
    last = tokens[-1]
    if isinstance(current, list):
        current[int(last)] = value
        return
    current[last] = value


def _delete_path(container: Any, dotted_path: str) -> None:
    tokens = dotted_path.split(".")
    current = container
    for token in tokens[:-1]:
        current = _resolve_path_token(current, token)
    last = tokens[-1]
    if isinstance(current, list):
        del current[int(last)]
        return
    del current[last]


def _apply_mutations(repo_root: Path, fixture_name: str) -> None:
    for mutation in _load_fixture_mutations(fixture_name):
        relative_path = mutation["file"]
        target_path = repo_root / relative_path
        payload = yaml.safe_load(target_path.read_text(encoding="utf-8"))
        op = mutation["op"]
        dotted_path = mutation["path"]
        if op == "set":
            _set_path(payload, dotted_path, mutation["value"])
        elif op == "delete":
            _delete_path(payload, dotted_path)
        else:
            raise RuntimeError(f"unsupported mutation op {op!r} in fixture {fixture_name}")
        target_path.write_text(yaml.safe_dump(payload, sort_keys=False), encoding="utf-8")


def _instantiate_fixture_repo(tmp_path: Path, fixture_name: str) -> Path:
    repo_root = tmp_path / fixture_name
    shutil.copytree(TEMPLATE_REPO_ROOT, repo_root)
    _replace_placeholders(repo_root)
    _copy_fixture_overrides(repo_root, fixture_name)
    _apply_mutations(repo_root, fixture_name)
    return repo_root


def _run_validator_command(*args: str, check: bool) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(VALIDATOR_MODULE_PATH), *args],
        check=check,
        capture_output=True,
        text=True,
    )


def test_validate_repo_root_accepts_valid_fixture(tmp_path: Path) -> None:
    repo_root = _instantiate_fixture_repo(tmp_path, "valid_repo")
    validate_repo_root(repo_root)


def test_validate_repo_root_emits_compact_json_output(tmp_path: Path) -> None:
    repo_root = _instantiate_fixture_repo(tmp_path, "valid_repo")
    result = _run_validator_command(
        "--repo-root",
        str(repo_root),
        "--format",
        "json",
        "--compact",
        check=True,
    )
    payload = json.loads(result.stdout)
    assert payload == {
        "active_phase": "P01",
        "checks": {"placeholders": "pass", "schema": "pass", "semantic": "pass"},
        "status": "pass",
    }


def test_validate_template_repo_emits_compact_json_output_with_allowed_placeholders() -> None:
    result = _run_validator_command(
        "--repo-root",
        str(TEMPLATE_REPO_ROOT),
        "--allow-placeholders",
        "--format",
        "json",
        "--compact",
        check=True,
    )
    payload = json.loads(result.stdout)
    assert payload == {
        "active_phase": "P01",
        "checks": {"placeholders": "skipped", "schema": "pass", "semantic": "pass"},
        "status": "pass",
    }


def test_validate_repo_root_emits_compact_json_output_for_schema_failure(tmp_path: Path) -> None:
    repo_root = _instantiate_fixture_repo(tmp_path, "missing_schema_field")
    result = _run_validator_command(
        "--repo-root",
        str(repo_root),
        "--format",
        "json",
        "--compact",
        check=False,
    )
    assert result.returncode == 1
    payload = json.loads(result.stdout)
    assert payload["status"] == "fail"
    assert payload["active_phase"] == "P01"
    assert payload["checks"] == {
        "placeholders": "not_run",
        "schema": "fail",
        "semantic": "not_run",
    }
    assert "schemas/build-plan.schema.json" in payload["error"]


def test_validate_repo_root_emits_compact_json_output_for_semantic_failure(tmp_path: Path) -> None:
    repo_root = _instantiate_fixture_repo(tmp_path, "bad_hotfix_mode")
    result = _run_validator_command(
        "--repo-root",
        str(repo_root),
        "--format",
        "json",
        "--compact",
        check=False,
    )
    assert result.returncode == 1
    payload = json.loads(result.stdout)
    assert payload["status"] == "fail"
    assert payload["active_phase"] == "P01"
    assert payload["checks"] == {
        "placeholders": "not_run",
        "schema": "pass",
        "semantic": "fail",
    }
    assert "hotfix.mode must match phase-ledger hotfix mode full" in payload["error"]


def test_validate_template_repo_emits_compact_json_output_for_placeholder_failure() -> None:
    result = _run_validator_command(
        "--repo-root",
        str(TEMPLATE_REPO_ROOT),
        "--format",
        "json",
        "--compact",
        check=False,
    )
    assert result.returncode == 1
    payload = json.loads(result.stdout)
    assert payload["status"] == "fail"
    assert payload["active_phase"] == "P01"
    assert payload["checks"] == {
        "placeholders": "fail",
        "schema": "pass",
        "semantic": "pass",
    }
    assert "unresolved template placeholders remain in governed artifacts" in payload["error"]


@pytest.mark.parametrize(
    ("fixture_name", "expected_message"),
    [
        ("missing_schema_field", "schemas/build-plan.schema.json"),
        ("bad_hotfix_mode", "hotfix.mode must match phase-ledger hotfix mode full"),
        ("blocked_phase_missing_unblock_condition", "schemas/phase-ledger.schema.json"),
    ],
)
def test_validate_repo_root_rejects_invalid_fixtures(
    tmp_path: Path, fixture_name: str, expected_message: str
) -> None:
    repo_root = _instantiate_fixture_repo(tmp_path, fixture_name)
    with pytest.raises(GovernanceValidationError) as excinfo:
        validate_repo_root(repo_root)
    assert expected_message in str(excinfo.value)

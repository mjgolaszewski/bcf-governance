from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import re
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
        "ADOPTION_MODE": "fresh",
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
        "REPO_ROOT": ".",
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


def _configure_release_gates(repo_root: Path) -> None:
    makefile_path = repo_root / "Makefile.fragment"
    text = makefile_path.read_text(encoding="utf-8")
    replacements = {
        '\t@echo "configure repo-specific lint commands before release-check can pass"\n\t@false':
            "\t@ruff check .",
        '\t@echo "configure repo-specific typecheck commands before release-check can pass"\n\t@false':
            "\t@mypy .",
        '\t@echo "configure repo-specific test commands before release-check can pass"\n\t@false':
            "\t@$(PYTEST) backend/tests",
        '\t@echo "configure repo-specific contract-test commands before release-check can pass"\n\t@false':
            "\t@$(PYTEST) backend/tests/contracts",
        '\t@echo "configure repo-specific gitleaks or equivalent secret scan before release-check can pass"\n\t@false':
            "\t@gitleaks detect --source .",
        '\t@echo "configure repo-specific dependency audit before release-check can pass"\n\t@false':
            "\t@pip-audit",
        '\t@echo "configure repo-specific SBOM generation before release-check can pass"\n\t@false':
            "\t@syft dir:.",
        '\t@echo "configure repo-specific vulnerability scan before release-check can pass"\n\t@false':
            "\t@trivy fs .",
        '\t@echo "configure repo-specific runtime smoke command before release-check can pass"\n\t@false':
            "\t@docker compose config",
    }
    for placeholder, configured in replacements.items():
        text = text.replace(placeholder, configured)
    makefile_path.write_text(text, encoding="utf-8")


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


def _instantiate_fixture_repo(
    tmp_path: Path, fixture_name: str, *, configure_release_gates: bool = True
) -> Path:
    repo_root = tmp_path / fixture_name
    shutil.copytree(TEMPLATE_REPO_ROOT, repo_root)
    _replace_placeholders(repo_root)
    if configure_release_gates:
        _configure_release_gates(repo_root)
    _copy_fixture_overrides(repo_root, fixture_name)
    _apply_mutations(repo_root, fixture_name)
    return repo_root


def _write_yaml(path: Path, payload: dict[str, Any]) -> None:
    path.write_text(yaml.safe_dump(payload, sort_keys=False), encoding="utf-8")


def _set_manifest_retention_mode(repo_root: Path, mode: str) -> None:
    manifest_path = repo_root / "governance/artifact-manifest.yml"
    text = manifest_path.read_text(encoding="utf-8")
    if "  mode:" in text:
        text = re.sub(r"(?m)^  mode: .*$", f"  mode: {mode}", text)
    else:
        text = text.replace("phase_retention_policy:\n", f"phase_retention_policy:\n  mode: {mode}\n", 1)
    manifest_path.write_text(text, encoding="utf-8")


def _init_git_repo(repo_root: Path) -> str:
    subprocess.run(["git", "init"], cwd=repo_root, check=True, capture_output=True, text=True)
    subprocess.run(["git", "config", "user.email", "test@example.test"], cwd=repo_root, check=True)
    subprocess.run(["git", "config", "user.name", "Test User"], cwd=repo_root, check=True)
    subprocess.run(["git", "add", "."], cwd=repo_root, check=True)
    subprocess.run(["git", "commit", "-m", "seed"], cwd=repo_root, check=True, capture_output=True, text=True)
    return subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=repo_root,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()


def _git_blob_sha256(repo_root: Path, git_ref: str, relative_path: str) -> str:
    blob = subprocess.run(
        ["git", "show", f"{git_ref}:{relative_path}"],
        cwd=repo_root,
        check=True,
        capture_output=True,
    ).stdout
    return hashlib.sha256(blob).hexdigest()


def _copy_phase_triplet(repo_root: Path, source_number: str, target_number: str) -> None:
    replacements = {
        f"P{source_number}": f"P{target_number}",
        f"phase-{source_number}": f"phase-{target_number}",
        f"Phase {source_number}": f"Phase {target_number}",
    }
    for relative_path in (
        f"plans/phase-{source_number}-plan.yml",
        f"plans/phase-{source_number}-workitems.yml",
        f"phases/phase-{source_number}-log.yml",
    ):
        target_relative_path = relative_path.replace(
            f"phase-{source_number}", f"phase-{target_number}"
        )
        text = (repo_root / relative_path).read_text(encoding="utf-8")
        for old, new in replacements.items():
            text = text.replace(old, new)
        (repo_root / target_relative_path).write_text(text, encoding="utf-8")


def _advance_catalog_to_p02(repo_root: Path, *, add_history_entry: bool) -> None:
    product_spec_path = repo_root / "plans/product-spec.yml"
    product_spec = yaml.safe_load(product_spec_path.read_text(encoding="utf-8"))
    product_spec["execution_phases"].append(
        {
            "phase_id": "P02",
            "build_block": "foundation",
            "objective": "continue governed delivery",
            "release_train": "release_1",
        }
    )
    _write_yaml(product_spec_path, product_spec)

    build_plan_path = repo_root / "plans/build-plan.yml"
    build_plan = yaml.safe_load(build_plan_path.read_text(encoding="utf-8"))
    p02_phase = dict(build_plan["phase_sequence"][0])
    p02_phase["phase_id"] = "P02"
    p02_phase["objective"] = "continue governed delivery"
    build_plan["phase_sequence"].append(p02_phase)
    _write_yaml(build_plan_path, build_plan)

    _copy_phase_triplet(repo_root, "01", "02")

    ledger_path = repo_root / "plans/phase-ledger.yml"
    ledger = yaml.safe_load(ledger_path.read_text(encoding="utf-8"))
    ledger["active_phase"]["id"] = "P02"
    ledger["active_phase"]["plan"] = "plans/phase-02-plan.yml"
    ledger["active_phase"]["workitems"] = "plans/phase-02-workitems.yml"
    ledger["active_phase"]["log"] = "phases/phase-02-log.yml"
    _write_yaml(ledger_path, ledger)

    memory_path = repo_root / "MEMORY.yml"
    memory = yaml.safe_load(memory_path.read_text(encoding="utf-8"))
    active_artifacts = memory["environment_facts"]["active_artifacts"]
    active_artifacts["active_phase_plan"] = "plans/phase-02-plan.yml"
    active_artifacts["active_workitem_ledger"] = "plans/phase-02-workitems.yml"
    active_artifacts["active_phase_log"] = "phases/phase-02-log.yml"
    _write_yaml(memory_path, memory)

    archived_artifacts: list[dict[str, str]] = []
    if add_history_entry:
        archive_root = repo_root / "governance/archive/phase-artifacts"
        archive_root.mkdir(parents=True, exist_ok=True)
        for relative_path in (
            "plans/phase-01-plan.yml",
            "plans/phase-01-workitems.yml",
            "phases/phase-01-log.yml",
        ):
            source = repo_root / relative_path
            destination = archive_root / source.name
            shutil.copy2(source, destination)
            archived_artifacts.append(
                {
                    "path": destination.relative_to(repo_root).as_posix(),
                    "sha256": hashlib.sha256(destination.read_bytes()).hexdigest(),
                }
            )

    for relative_path in (
        "plans/phase-01-plan.yml",
        "plans/phase-01-workitems.yml",
        "phases/phase-01-log.yml",
    ):
        (repo_root / relative_path).unlink()

    if not add_history_entry:
        return
    history_path = repo_root / "plans/phase-history.yml"
    history = yaml.safe_load(history_path.read_text(encoding="utf-8"))
    history["entries"].append(
        {
            "phase_id": "P01",
            "build_block": "foundation",
            "release_train": "release_1",
            "status": "verified",
            "outcome": "foundation verified",
            "summary": ["foundation phase retained in compact history"],
            "validation": ["make governance-validate"],
            "archived_artifacts": archived_artifacts,
        }
    )
    _write_yaml(history_path, history)


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


def test_validate_repo_root_rejects_missing_observability_contract(tmp_path: Path) -> None:
    repo_root = _instantiate_fixture_repo(tmp_path, "valid_repo")
    (repo_root / "contracts/observability/v1/telemetry.contract.yml").unlink()

    with pytest.raises(GovernanceValidationError) as excinfo:
        validate_repo_root(repo_root)

    assert "observability contract template references missing path" in str(excinfo.value)


def test_validate_repo_root_rejects_invalid_observability_contract(tmp_path: Path) -> None:
    repo_root = _instantiate_fixture_repo(tmp_path, "valid_repo")
    contract_path = repo_root / "contracts/observability/v1/logging.contract.yml"
    contract = yaml.safe_load(contract_path.read_text(encoding="utf-8"))
    del contract["trace_alignment"]
    contract_path.write_text(yaml.safe_dump(contract, sort_keys=False), encoding="utf-8")

    with pytest.raises(GovernanceValidationError) as excinfo:
        validate_repo_root(repo_root)

    assert "schemas/observability-contract.schema.json" in str(excinfo.value)


def test_validate_repo_root_rejects_cleanup_contract_without_documentation_currency(
    tmp_path: Path,
) -> None:
    repo_root = _instantiate_fixture_repo(tmp_path, "valid_repo")
    contract_path = repo_root / "governance/repo-cleanup-contract.yml"
    contract = yaml.safe_load(contract_path.read_text(encoding="utf-8"))
    contract["llm_review_required"] = [
        item for item in contract["llm_review_required"] if item["id"] != "documentation_currency"
    ]
    contract_path.write_text(yaml.safe_dump(contract, sort_keys=False), encoding="utf-8")

    with pytest.raises(GovernanceValidationError) as excinfo:
        validate_repo_root(repo_root)

    assert "llm_review_required must include documentation_currency" in str(excinfo.value)


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
        "--allow-release-gate-placeholders",
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


def test_allow_placeholders_does_not_allow_release_gate_placeholders() -> None:
    result = _run_validator_command(
        "--repo-root",
        str(TEMPLATE_REPO_ROOT),
        "--allow-placeholders",
        "--format",
        "json",
        "--compact",
        check=False,
    )
    assert result.returncode == 1
    payload = json.loads(result.stdout)
    assert payload["checks"] == {
        "placeholders": "not_run",
        "schema": "pass",
        "semantic": "fail",
    }
    assert "release gate placeholder marker" in payload["error"]


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


def test_validate_repo_root_rejects_absolute_document_path(tmp_path: Path) -> None:
    repo_root = _instantiate_fixture_repo(tmp_path, "valid_repo")
    plan_path = repo_root / "plans/phase-01-plan.yml"
    payload = yaml.safe_load(plan_path.read_text(encoding="utf-8"))
    payload["document"]["path"] = str(plan_path)
    plan_path.write_text(yaml.safe_dump(payload, sort_keys=False), encoding="utf-8")

    with pytest.raises(GovernanceValidationError) as excinfo:
        validate_repo_root(repo_root)
    assert "document.path must be a repo-relative path" in str(excinfo.value)


def test_validate_repo_root_rejects_document_path_mismatch(tmp_path: Path) -> None:
    repo_root = _instantiate_fixture_repo(tmp_path, "valid_repo")
    log_path = repo_root / "phases/phase-01-log.yml"
    payload = yaml.safe_load(log_path.read_text(encoding="utf-8"))
    payload["document"]["path"] = "phases/not-the-active-log.yml"
    log_path.write_text(yaml.safe_dump(payload, sort_keys=False), encoding="utf-8")

    with pytest.raises(GovernanceValidationError) as excinfo:
        validate_repo_root(repo_root)
    assert "document.path must be 'phases/phase-01-log.yml'" in str(excinfo.value)


def test_validate_repo_root_rejects_placeholder_release_gates(tmp_path: Path) -> None:
    repo_root = _instantiate_fixture_repo(
        tmp_path, "valid_repo", configure_release_gates=False
    )

    with pytest.raises(GovernanceValidationError) as excinfo:
        validate_repo_root(repo_root)
    assert "release gate placeholder marker" in str(excinfo.value)


def test_validate_repo_root_rejects_missing_required_release_gate(tmp_path: Path) -> None:
    repo_root = _instantiate_fixture_repo(tmp_path, "valid_repo")
    makefile_path = repo_root / "Makefile.fragment"
    makefile_path.write_text(
        makefile_path.read_text(encoding="utf-8").replace("\t$(MAKE) typecheck\n", ""),
        encoding="utf-8",
    )

    with pytest.raises(GovernanceValidationError) as excinfo:
        validate_repo_root(repo_root)
    assert "release-check must invoke required release gate targets: typecheck" in str(excinfo.value)


def test_validate_repo_root_allows_omitted_optional_release_gate(tmp_path: Path) -> None:
    repo_root = _instantiate_fixture_repo(tmp_path, "valid_repo")
    profile_path = repo_root / "governance-profile.yml"
    profile_text = profile_path.read_text(encoding="utf-8")
    profile_text = profile_text.replace(
        "    contract_test: {target: contract-test, status: required,",
        "    contract_test: {target: contract-test, status: optional,",
    )
    profile_path.write_text(profile_text, encoding="utf-8")

    makefile_path = repo_root / "Makefile.fragment"
    makefile_path.write_text(
        makefile_path.read_text(encoding="utf-8").replace("\t$(MAKE) contract-test\n", ""),
        encoding="utf-8",
    )

    validate_repo_root(repo_root)


def test_validate_repo_root_rejects_meaningless_release_gate_command(tmp_path: Path) -> None:
    repo_root = _instantiate_fixture_repo(tmp_path, "valid_repo")
    makefile_path = repo_root / "Makefile.fragment"
    text = makefile_path.read_text(encoding="utf-8")
    text = text.replace("\t@ruff check .", "\t@python3 --version >/dev/null")
    makefile_path.write_text(text, encoding="utf-8")

    with pytest.raises(GovernanceValidationError) as excinfo:
        validate_repo_root(repo_root)
    assert "uses a version/probe command" in str(excinfo.value)


def test_validate_repo_root_rejects_product_build_phase_mismatch(tmp_path: Path) -> None:
    repo_root = _instantiate_fixture_repo(tmp_path, "valid_repo")
    build_plan_path = repo_root / "plans/build-plan.yml"
    payload = yaml.safe_load(build_plan_path.read_text(encoding="utf-8"))
    payload["phase_sequence"][0]["phase_id"] = "P02"
    build_plan_path.write_text(yaml.safe_dump(payload, sort_keys=False), encoding="utf-8")

    with pytest.raises(GovernanceValidationError) as excinfo:
        validate_repo_root(repo_root)
    assert "must declare the same phase ids" in str(excinfo.value)


def test_validate_repo_root_accepts_archived_phase_history_entry(tmp_path: Path) -> None:
    repo_root = _instantiate_fixture_repo(tmp_path, "valid_repo")
    _advance_catalog_to_p02(repo_root, add_history_entry=True)

    validate_repo_root(repo_root)


def test_validate_repo_root_archive_mode_rejects_stale_active_triplet(
    tmp_path: Path,
) -> None:
    repo_root = _instantiate_fixture_repo(tmp_path, "valid_repo")
    _advance_catalog_to_p02(repo_root, add_history_entry=True)
    _set_manifest_retention_mode(repo_root, "archive")
    (repo_root / ".gitignore").write_text(
        "governance/archive/phase-artifacts/*\n"
        "!governance/archive/phase-artifacts/.gitkeep\n",
        encoding="utf-8",
    )
    history_path = repo_root / "plans/phase-history.yml"
    history = yaml.safe_load(history_path.read_text(encoding="utf-8"))
    history["entries"][0]["retention_source"] = "archive"
    _write_yaml(history_path, history)
    for relative_path in (
        "plans/phase-01-plan.yml",
        "plans/phase-01-workitems.yml",
        "phases/phase-01-log.yml",
    ):
        source = repo_root / "governance/archive/phase-artifacts" / Path(relative_path).name
        destination = repo_root / relative_path
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, destination)

    with pytest.raises(GovernanceValidationError) as excinfo:
        validate_repo_root(repo_root)
    assert "outside the retained phase window" in str(excinfo.value)


def test_validate_repo_root_archive_mode_rejects_stale_hotfix_artifact(
    tmp_path: Path,
) -> None:
    repo_root = _instantiate_fixture_repo(tmp_path, "valid_repo")
    _advance_catalog_to_p02(repo_root, add_history_entry=True)
    _set_manifest_retention_mode(repo_root, "archive")
    (repo_root / ".gitignore").write_text(
        "governance/archive/phase-artifacts/*\n"
        "!governance/archive/phase-artifacts/.gitkeep\n",
        encoding="utf-8",
    )
    history_path = repo_root / "plans/phase-history.yml"
    history = yaml.safe_load(history_path.read_text(encoding="utf-8"))
    history["entries"][0]["retention_source"] = "archive"
    _write_yaml(history_path, history)
    _write_yaml(
        repo_root / "phases/phase-01-hotfix01.yml",
        {"document": {"status": "closed"}, "hotfix": {"id": "HF-001", "related_phase_id": "P01"}},
    )

    with pytest.raises(GovernanceValidationError) as excinfo:
        validate_repo_root(repo_root)
    assert "outside the retained phase window but active hotfix artifacts remain" in str(excinfo.value)


def test_validate_repo_root_archive_mode_allows_ignored_missing_archive_artifacts(
    tmp_path: Path,
) -> None:
    repo_root = _instantiate_fixture_repo(tmp_path, "valid_repo")
    _advance_catalog_to_p02(repo_root, add_history_entry=True)
    _set_manifest_retention_mode(repo_root, "archive")
    (repo_root / ".gitignore").write_text(
        "governance/archive/phase-artifacts/*\n"
        "!governance/archive/phase-artifacts/.gitkeep\n",
        encoding="utf-8",
    )
    history_path = repo_root / "plans/phase-history.yml"
    history = yaml.safe_load(history_path.read_text(encoding="utf-8"))
    history["entries"][0]["retention_source"] = "archive"
    _write_yaml(history_path, history)
    shutil.rmtree(repo_root / "governance/archive/phase-artifacts")
    (repo_root / "governance/archive/phase-artifacts").mkdir(parents=True)
    (repo_root / "governance/archive/phase-artifacts/.gitkeep").touch()

    validate_repo_root(repo_root)


def test_validate_repo_root_retention_mode_allows_unscaffolded_future_phase(
    tmp_path: Path,
) -> None:
    repo_root = _instantiate_fixture_repo(tmp_path, "valid_repo")
    _advance_catalog_to_p02(repo_root, add_history_entry=True)
    _set_manifest_retention_mode(repo_root, "archive")
    (repo_root / ".gitignore").write_text(
        "governance/archive/phase-artifacts/*\n"
        "!governance/archive/phase-artifacts/.gitkeep\n",
        encoding="utf-8",
    )
    history_path = repo_root / "plans/phase-history.yml"
    history = yaml.safe_load(history_path.read_text(encoding="utf-8"))
    history["entries"][0]["retention_source"] = "archive"
    _write_yaml(history_path, history)

    product_spec_path = repo_root / "plans/product-spec.yml"
    product_spec = yaml.safe_load(product_spec_path.read_text(encoding="utf-8"))
    product_spec["execution_phases"].append(
        {
            "phase_id": "P03",
            "build_block": "delivery",
            "objective": "future phase",
            "release_train": "release_1",
        }
    )
    _write_yaml(product_spec_path, product_spec)

    build_plan_path = repo_root / "plans/build-plan.yml"
    build_plan = yaml.safe_load(build_plan_path.read_text(encoding="utf-8"))
    p03_phase = dict(build_plan["phase_sequence"][-1])
    p03_phase["phase_id"] = "P03"
    p03_phase["build_block"] = "delivery"
    p03_phase["objective"] = "future phase"
    build_plan["phase_sequence"].append(p03_phase)
    _write_yaml(build_plan_path, build_plan)

    manifest_path = repo_root / "governance/artifact-manifest.yml"
    manifest = yaml.safe_load(manifest_path.read_text(encoding="utf-8"))
    manifest["context_budgets"]["agent_required_files"]["plans/product-spec.yml"] = 80
    manifest["context_budgets"]["agent_required_files"]["governance/artifact-manifest.yml"] = 120
    _write_yaml(manifest_path, manifest)

    validate_repo_root(repo_root)


def test_validate_repo_root_git_history_mode_accepts_commit_backed_history(
    tmp_path: Path,
) -> None:
    repo_root = _instantiate_fixture_repo(tmp_path, "valid_repo")
    commit = _init_git_repo(repo_root)
    _advance_catalog_to_p02(repo_root, add_history_entry=True)
    _set_manifest_retention_mode(repo_root, "git_history")
    history_path = repo_root / "plans/phase-history.yml"
    history = yaml.safe_load(history_path.read_text(encoding="utf-8"))
    artifacts = []
    for relative_path in (
        "plans/phase-01-plan.yml",
        "plans/phase-01-workitems.yml",
        "phases/phase-01-log.yml",
    ):
        artifacts.append(
            {
                "path": relative_path,
                "sha256": _git_blob_sha256(repo_root, commit, relative_path),
                "git_commit": commit,
            }
        )
    history["entries"][0]["retention_source"] = "git_history"
    history["entries"][0]["retention_ref"] = commit
    history["entries"][0]["archived_artifacts"] = artifacts
    _write_yaml(history_path, history)
    shutil.rmtree(repo_root / "governance/archive/phase-artifacts")
    (repo_root / "governance/archive/phase-artifacts").mkdir(parents=True)
    (repo_root / "governance/archive/phase-artifacts/.gitkeep").touch()

    validate_repo_root(repo_root)


def test_validate_repo_root_rejects_archived_phase_missing_history(
    tmp_path: Path,
) -> None:
    repo_root = _instantiate_fixture_repo(tmp_path, "valid_repo")
    _advance_catalog_to_p02(repo_root, add_history_entry=False)

    with pytest.raises(GovernanceValidationError) as excinfo:
        validate_repo_root(repo_root)
    assert "no active triplet and no plans/phase-history.yml entry" in str(excinfo.value)


def test_validate_repo_root_rejects_phase_history_entry_without_artifacts(
    tmp_path: Path,
) -> None:
    repo_root = _instantiate_fixture_repo(tmp_path, "valid_repo")
    _advance_catalog_to_p02(repo_root, add_history_entry=True)
    history_path = repo_root / "plans/phase-history.yml"
    history = yaml.safe_load(history_path.read_text(encoding="utf-8"))
    history["entries"][0]["archived_artifacts"] = []
    _write_yaml(history_path, history)

    with pytest.raises(GovernanceValidationError) as excinfo:
        validate_repo_root(repo_root)
    assert "archived_artifacts" in str(excinfo.value)


def test_validate_repo_root_rejects_completed_release_train_with_planned_log(
    tmp_path: Path,
) -> None:
    repo_root = _instantiate_fixture_repo(tmp_path, "valid_repo")
    ledger_path = repo_root / "plans/phase-ledger.yml"
    payload = yaml.safe_load(ledger_path.read_text(encoding="utf-8"))
    payload["release_trains"]["release_1"]["status"] = "completed"
    ledger_path.write_text(yaml.safe_dump(payload, sort_keys=False), encoding="utf-8")

    with pytest.raises(GovernanceValidationError) as excinfo:
        validate_repo_root(repo_root)
    assert "cannot reference planned phase log" in str(excinfo.value)


def test_validate_repo_root_rejects_stale_memory_active_artifacts(tmp_path: Path) -> None:
    repo_root = _instantiate_fixture_repo(tmp_path, "valid_repo")
    memory_path = repo_root / "MEMORY.yml"
    payload = yaml.safe_load(memory_path.read_text(encoding="utf-8"))
    payload["environment_facts"]["active_artifacts"]["active_phase_log"] = "phases/stale-log.yml"
    memory_path.write_text(yaml.safe_dump(payload, sort_keys=False), encoding="utf-8")

    with pytest.raises(GovernanceValidationError) as excinfo:
        validate_repo_root(repo_root)
    assert "MEMORY.yml active_artifacts.active_phase_log" in str(excinfo.value)


def test_validate_repo_root_rejects_workitems_missing_plan_deliverable(
    tmp_path: Path,
) -> None:
    repo_root = _instantiate_fixture_repo(tmp_path, "valid_repo")
    workitems_path = repo_root / "plans/phase-01-workitems.yml"
    payload = yaml.safe_load(workitems_path.read_text(encoding="utf-8"))
    payload["workitems"][0]["summary"] = "deliver a different scope"
    payload["workitems"][0]["acceptance"] = ["different_scope_is_complete"]
    workitems_path.write_text(yaml.safe_dump(payload, sort_keys=False), encoding="utf-8")

    with pytest.raises(GovernanceValidationError) as excinfo:
        validate_repo_root(repo_root)
    assert "workitems must cover phase deliverables" in str(excinfo.value)


def test_validate_repo_root_rejects_log_workitem_status_drift(tmp_path: Path) -> None:
    repo_root = _instantiate_fixture_repo(tmp_path, "valid_repo")
    log_path = repo_root / "phases/phase-01-log.yml"
    payload = yaml.safe_load(log_path.read_text(encoding="utf-8"))
    payload["workitems"][0]["status"] = "DONE"
    log_path.write_text(yaml.safe_dump(payload, sort_keys=False), encoding="utf-8")

    with pytest.raises(GovernanceValidationError) as excinfo:
        validate_repo_root(repo_root)
    assert "workitem statuses must match" in str(excinfo.value)


def test_validate_repo_root_rejects_closed_phase_with_open_workitems(tmp_path: Path) -> None:
    repo_root = _instantiate_fixture_repo(tmp_path, "valid_repo")
    log_path = repo_root / "phases/phase-01-log.yml"
    payload = yaml.safe_load(log_path.read_text(encoding="utf-8"))
    payload["document"]["status"] = "closed"
    payload["all_tickets_closed"] = True
    payload["required_suites_green"] = ["make test"]
    payload["ast_architecture_gates_green"] = True
    payload["health_checks_green"] = True
    payload["known_warnings"] = []
    log_path.write_text(yaml.safe_dump(payload, sort_keys=False), encoding="utf-8")

    with pytest.raises(GovernanceValidationError) as excinfo:
        validate_repo_root(repo_root)
    assert "cannot be verified or closed while workitems remain open" in str(excinfo.value)


def test_validate_repo_root_rejects_phase_sequence_gaps(tmp_path: Path) -> None:
    repo_root = _instantiate_fixture_repo(tmp_path, "valid_repo")
    product_spec_path = repo_root / "plans/product-spec.yml"
    product_spec = yaml.safe_load(product_spec_path.read_text(encoding="utf-8"))
    product_spec["execution_phases"].append(
        {
            "phase_id": "P03",
            "build_block": "later",
            "objective": "skip a phase",
            "release_train": "release_1",
        }
    )
    product_spec_path.write_text(yaml.safe_dump(product_spec, sort_keys=False), encoding="utf-8")

    build_plan_path = repo_root / "plans/build-plan.yml"
    build_plan = yaml.safe_load(build_plan_path.read_text(encoding="utf-8"))
    build_plan["phase_sequence"].append(
        {
            "phase_id": "P03",
            "build_block": "later",
            "objective": "skip a phase",
            "hard_dependencies": [],
            "tightly_scoped_deliverables": ["later deliverable"],
            "parallelizable_workstreams": ["later"],
            "verification_commands": ["make test"],
        }
    )
    build_plan_path.write_text(yaml.safe_dump(build_plan, sort_keys=False), encoding="utf-8")

    with pytest.raises(GovernanceValidationError) as excinfo:
        validate_repo_root(repo_root)
    assert "phase_sequence must use contiguous phase ids" in str(excinfo.value)


def test_validate_repo_root_rejects_undeclared_phase_artifacts(tmp_path: Path) -> None:
    repo_root = _instantiate_fixture_repo(tmp_path, "valid_repo")
    source = repo_root / "phases/phase-01-log.yml"
    target = repo_root / "phases/phase-02-log.yml"
    target.write_text(source.read_text(encoding="utf-8"), encoding="utf-8")

    with pytest.raises(GovernanceValidationError) as excinfo:
        validate_repo_root(repo_root)
    assert "artifacts exist without build-plan declarations: P02" in str(excinfo.value)


def test_validate_repo_root_rejects_audits_outside_audit_root(tmp_path: Path) -> None:
    repo_root = _instantiate_fixture_repo(tmp_path, "valid_repo")
    audit_path = repo_root / "docs/audits/sprint-review.md"
    audit_path.parent.mkdir(parents=True)
    audit_path.write_text("# Sprint Review\n", encoding="utf-8")

    with pytest.raises(GovernanceValidationError) as excinfo:
        validate_repo_root(repo_root)
    assert "audit artifacts must live under the declared audit root audits/" in str(excinfo.value)


def test_validate_repo_root_rejects_undeclared_nested_governance(tmp_path: Path) -> None:
    repo_root = _instantiate_fixture_repo(tmp_path, "valid_repo")
    nested_agents = repo_root / "vendor/client/AGENTS.yml"
    nested_agents.parent.mkdir(parents=True)
    nested_agents.write_text("document: {}\n", encoding="utf-8")

    with pytest.raises(GovernanceValidationError) as excinfo:
        validate_repo_root(repo_root)
    assert "nested governance artifacts must be declared as vendored packs" in str(excinfo.value)


def test_validate_repo_root_allows_declared_nested_vendor(tmp_path: Path) -> None:
    repo_root = _instantiate_fixture_repo(tmp_path, "valid_repo")
    nested_agents = repo_root / "vendor/client/AGENTS.yml"
    nested_agents.parent.mkdir(parents=True)
    nested_agents.write_text("document: {}\n", encoding="utf-8")

    manifest_path = repo_root / "governance/artifact-manifest.yml"
    manifest_text = manifest_path.read_text(encoding="utf-8").replace(
        "  declared_vendors: []",
        (
            "  declared_vendors:\n"
            "    - {path: vendor/client, source_repo: ../client, "
            "refresh_policy: pinned snapshot refreshed by explicit phase work, "
            "ownership: vendored read-only integration fixture}"
        ),
    )
    manifest_path.write_text(manifest_text, encoding="utf-8")

    validate_repo_root(repo_root)


def test_validate_repo_root_rejects_undeclared_test_root_invocation(tmp_path: Path) -> None:
    repo_root = _instantiate_fixture_repo(tmp_path, "valid_repo")
    browser_root = repo_root / "browser_tests"
    browser_root.mkdir()
    (browser_root / "test_browser.py").write_text("def test_browser():\n    assert True\n", encoding="utf-8")
    makefile_path = repo_root / "Makefile.fragment"
    makefile_path.write_text(
        makefile_path.read_text(encoding="utf-8")
        + "\nbrowser-test:\n\t@$(PYTEST) browser_tests\n",
        encoding="utf-8",
    )

    with pytest.raises(GovernanceValidationError) as excinfo:
        validate_repo_root(repo_root)
    assert "testing_governance.test_roots: browser_tests" in str(excinfo.value)


def test_validate_repo_root_rejects_context_budget_overrun(tmp_path: Path) -> None:
    repo_root = _instantiate_fixture_repo(tmp_path, "valid_repo")
    memory_path = repo_root / "MEMORY.yml"
    memory = yaml.safe_load(memory_path.read_text(encoding="utf-8"))
    memory["environment_facts"]["current_repo_state"].extend(
        f"extra context entry {index}" for index in range(120)
    )
    memory_path.write_text(yaml.safe_dump(memory, sort_keys=False), encoding="utf-8")

    with pytest.raises(GovernanceValidationError) as excinfo:
        validate_repo_root(repo_root)
    assert "agent-required governance files exceeded context budgets" in str(excinfo.value)
    assert "MEMORY.yml has" in str(excinfo.value)
    assert "line budget is" in str(excinfo.value)


def test_validate_repo_root_rejects_context_kib_budget_overrun(tmp_path: Path) -> None:
    repo_root = _instantiate_fixture_repo(tmp_path, "valid_repo")
    manifest_path = repo_root / "governance/artifact-manifest.yml"
    manifest = yaml.safe_load(manifest_path.read_text(encoding="utf-8"))
    budget = manifest["context_budgets"]["agent_required_files"]["governance/artifact-manifest.yml"]
    budget["line_hard_cap"] = 500
    budget["kib_hard_cap"] = 1
    manifest_path.write_text(yaml.safe_dump(manifest, sort_keys=False), encoding="utf-8")

    with pytest.raises(GovernanceValidationError) as excinfo:
        validate_repo_root(repo_root)
    assert "governance/artifact-manifest.yml is" in str(excinfo.value)
    assert "KiB budget is 1" in str(excinfo.value)


def test_validate_repo_root_accepts_legacy_integer_context_budget(tmp_path: Path) -> None:
    repo_root = _instantiate_fixture_repo(tmp_path, "valid_repo")
    manifest_path = repo_root / "governance/artifact-manifest.yml"
    manifest = yaml.safe_load(manifest_path.read_text(encoding="utf-8"))
    manifest["context_budgets"]["agent_required_files"]["governance/artifact-manifest.yml"][
        "line_hard_cap"
    ] = 200
    manifest["context_budgets"]["agent_required_files"]["MEMORY.yml"] = 500
    manifest_path.write_text(yaml.safe_dump(manifest, sort_keys=False), encoding="utf-8")

    validate_repo_root(repo_root)


def test_validator_json_reports_aggregate_context_budget_advisory(tmp_path: Path) -> None:
    repo_root = _instantiate_fixture_repo(tmp_path, "valid_repo")
    manifest_path = repo_root / "governance/artifact-manifest.yml"
    manifest = yaml.safe_load(manifest_path.read_text(encoding="utf-8"))
    manifest["context_budgets"]["agent_required_files"]["governance/artifact-manifest.yml"][
        "line_hard_cap"
    ] = 200
    manifest["context_budgets"]["aggregate_agent_required_kib_advisory"] = 1
    manifest_path.write_text(yaml.safe_dump(manifest, sort_keys=False), encoding="utf-8")

    result = _run_validator_command(
        "--repo-root",
        str(repo_root),
        "--format",
        "json",
        "--compact",
        check=True,
    )
    payload = json.loads(result.stdout)
    assert payload["status"] == "pass"
    assert "agent-required governance context is" in payload["advisories"][0]
    assert "recommended maximum is 1 KiB" in payload["advisories"][0]


def test_validate_repo_root_rejects_changed_agent_deconstruction_loc_cap(
    tmp_path: Path,
) -> None:
    repo_root = _instantiate_fixture_repo(tmp_path, "valid_repo")
    agents_path = repo_root / "AGENTS.yml"
    agents = yaml.safe_load(agents_path.read_text(encoding="utf-8"))
    agents["structural_guardrails"]["agent_deconstruction_contract"]["max_loc"] = 1000
    agents_path.write_text(yaml.safe_dump(agents, sort_keys=False), encoding="utf-8")

    with pytest.raises(GovernanceValidationError) as excinfo:
        validate_repo_root(repo_root)
    assert "agent_deconstruction_contract.max_loc must be 800" in str(excinfo.value)


def test_validate_repo_root_checks_vendored_artifact_provenance(tmp_path: Path) -> None:
    repo_root = _instantiate_fixture_repo(tmp_path, "valid_repo")
    artifact_path = repo_root / "vendor/client/client.whl"
    artifact_path.parent.mkdir(parents=True)
    artifact_path.write_bytes(b"client wheel")
    digest = hashlib.sha256(artifact_path.read_bytes()).hexdigest()

    manifest_path = repo_root / "governance/artifact-manifest.yml"
    manifest_text = manifest_path.read_text(encoding="utf-8").replace(
        "  artifacts: []",
        (
            "  artifacts:\n"
            "    - {artifact_path: vendor/client/client.whl, source_repo: ../client, "
            "source_commit: abc123, artifact_sha256: "
            f"\"{digest}\", refresh_policy: pinned snapshot refreshed by explicit phase work}}"
        ),
    )
    manifest_path.write_text(manifest_text, encoding="utf-8")
    validate_repo_root(repo_root)

    manifest_path.write_text(manifest_text.replace(digest, "0" * 64), encoding="utf-8")
    with pytest.raises(GovernanceValidationError) as excinfo:
        validate_repo_root(repo_root)
    assert "artifact_sha256 mismatch" in str(excinfo.value)


def test_validate_repo_root_rejects_ephemeral_evidence_without_durable_marker(
    tmp_path: Path,
) -> None:
    repo_root = _instantiate_fixture_repo(tmp_path, "valid_repo")
    audit_path = repo_root / "audits/security-review.md"
    audit_path.write_text("Evidence: .artifacts/security/report.json\n", encoding="utf-8")

    with pytest.raises(GovernanceValidationError) as excinfo:
        validate_repo_root(repo_root)
    assert "ephemeral artifact references" in str(excinfo.value)


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

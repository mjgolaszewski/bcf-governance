from __future__ import annotations

import json
import importlib.util
import subprocess
import sys
from pathlib import Path

import yaml


REPO_ROOT = Path(__file__).resolve().parents[1]
INSTALLER = REPO_ROOT / "scripts" / "install_governance_pack.py"
DOCTOR = REPO_ROOT / "scripts" / "doctor_governance_pack.py"


def _load_installer_module():
    spec = importlib.util.spec_from_file_location("install_governance_pack", INSTALLER)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _run_installer(
    target: Path, *args: str, check: bool = True, input_text: str | None = None
) -> subprocess.CompletedProcess[str]:
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
        input=input_text,
    )


def _run_installed_validator(
    target: Path,
    *,
    allow_placeholders: bool = False,
    allow_release_gate_placeholders: bool = False,
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
    if allow_release_gate_placeholders:
        command.append("--allow-release-gate-placeholders")
    return subprocess.run(command, capture_output=True, text=True)


def _run_doctor(target: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [
            sys.executable,
            str(DOCTOR),
            "--repo-root",
            str(target),
            "--format",
            "json",
            "--compact",
        ],
        capture_output=True,
        text=True,
    )


def test_template_file_iterator_skips_generated_python_cache_files(tmp_path: Path) -> None:
    installer = _load_installer_module()
    template_root = tmp_path / "template"
    (template_root / "scripts/__pycache__").mkdir(parents=True)
    (template_root / "scripts/keep.py").write_text("print('ok')\n", encoding="utf-8")
    (template_root / "scripts/skip.pyc").write_bytes(b"cache")
    (template_root / "scripts/__pycache__/skip.cpython-312.pyc").write_bytes(b"cache")

    relative_files = [
        path.relative_to(template_root).as_posix()
        for path in installer._iter_template_files(template_root)
    ]

    assert relative_files == ["scripts/keep.py"]


def test_installer_bootstraps_standard_profile_and_reports_unwired_gates(tmp_path: Path) -> None:
    target = tmp_path / "demo-standard"
    result = _run_installer(target)

    assert "validation: bootstrap pass" in result.stdout
    assert "wire release gates:" in result.stdout
    assert "architecture-module-size" in result.stdout
    assert "security-secret-scan" in result.stdout
    assert "runtime-smoke" in result.stdout
    assert not (target / "plans/phase-NN-plan.yml").exists()
    assert not (target / "phases/phase-NN-log.yml").exists()
    assert (target / "contracts/observability/v1/telemetry.contract.yml").exists()
    assert (target / "contracts/observability/v1/logging.contract.yml").exists()
    assert (target / "governance/repo-cleanup-contract.yml").exists()
    assert (target / "governance/REPO_CLEANUP.md").exists()
    assert not (target / "governance/EXISTING_REPO_ADOPTION.md").exists()
    assert not (target / "governance/existing-repo-adoption.yml").exists()
    assert (target / ".github/workflows/governance.yml").exists()
    workflow = (target / ".github/workflows/governance.yml").read_text(encoding="utf-8")
    assert "governance-exposure-scan" in workflow
    assert "scripts/check_governance_exposure.py --repo-root ." in workflow
    assert "AGENTS.yml" in (target / "AGENTS.md").read_text(encoding="utf-8")
    assert "AGENTS.yml" in (target / "CLAUDE.md").read_text(encoding="utf-8")

    agents = yaml.safe_load((target / "AGENTS.yml").read_text(encoding="utf-8"))
    memory = yaml.safe_load((target / "MEMORY.yml").read_text(encoding="utf-8"))
    assert agents["project"]["repo_root"] == "."
    assert agents["git_scope"]["default_root"] == "."
    assert memory["stable_decisions"]["canonical_repo_root"] == "."

    plan = yaml.safe_load((target / "plans/phase-01-plan.yml").read_text(encoding="utf-8"))
    assert plan["document"]["path"] == "plans/phase-01-plan.yml"
    assert plan["delivery_contract"]["tightly_scoped_deliverables"] == [
        "initial governed foundation"
    ]

    profile = yaml.safe_load((target / "governance-profile.yml").read_text(encoding="utf-8"))
    assert profile["profile"]["selected"] == "standard"
    assert profile["drift_guardrails"]["cleanup_contract"] == "governance/repo-cleanup-contract.yml"

    telemetry_contract = yaml.safe_load(
        (target / "contracts/observability/v1/telemetry.contract.yml").read_text(
            encoding="utf-8"
        )
    )
    logging_contract = yaml.safe_load(
        (target / "contracts/observability/v1/logging.contract.yml").read_text(
            encoding="utf-8"
        )
    )
    assert telemetry_contract["contract_id"] == "demo.observability.telemetry.v1"
    assert logging_contract["contract_id"] == "demo.observability.logging.v1"

    strict = _run_installed_validator(target)
    assert strict.returncode == 1
    assert "release gate placeholder marker" in json.loads(strict.stdout)["error"]

    bootstrap = _run_installed_validator(
        target, allow_placeholders=True, allow_release_gate_placeholders=True
    )
    assert bootstrap.returncode == 0
    assert json.loads(bootstrap.stdout)["status"] == "pass"

    doctor = _run_doctor(target)
    assert doctor.returncode == 1
    doctor_payload = json.loads(doctor.stdout)
    assert doctor_payload["status"] == "fail"
    assert any("placeholder marker" in blocker for blocker in doctor_payload["blockers"])
    assert any("replace lint" in action for action in doctor_payload["next_actions"])


def test_installer_lite_profile_passes_strict_validation(tmp_path: Path) -> None:
    target = tmp_path / "demo-lite"
    result = _run_installer(target, "--profile", "lite", "--require-strict-validation")

    assert "validation: strict pass" in result.stdout
    profile = yaml.safe_load((target / "governance-profile.yml").read_text(encoding="utf-8"))
    assert profile["profile"]["selected"] == "lite"
    assert profile["release_gate_profile"]["gates"]["lint"]["status"] == "deferred"

    makefile = (target / "Makefile.fragment").read_text(encoding="utf-8")
    assert "$(MAKE) governance-validate" in makefile
    assert "$(MAKE) governance-exposure-scan" in makefile
    assert "$(MAKE) lint" not in makefile
    assert "configure repo-specific" not in makefile

    strict = _run_installed_validator(target)
    assert strict.returncode == 0
    assert json.loads(strict.stdout)["status"] == "pass"


def test_installer_gate_commands_can_make_standard_profile_strict(tmp_path: Path) -> None:
    target = tmp_path / "demo-standard-strict"
    result = _run_installer(
        target,
        "--gate-command",
        "architecture-test=pytest backend/tests/architecture",
        "--gate-command",
        "architecture-module-size=pytest backend/tests/architecture -k production_modules_respect_loc_cap",
        "--gate-command",
        "architecture-layer-membership=pytest backend/tests/architecture -k production_modules_map_to_exactly_one_layer",
        "--gate-command",
        "architecture-context-membership=pytest backend/tests/architecture -k production_modules_map_to_exactly_one_bounded_context",
        "--gate-command",
        "architecture-import-boundaries=pytest backend/tests/architecture -k do_not_import",
        "--gate-command",
        "architecture-cqrs-side=pytest backend/tests/architecture -k cqrs",
        "--gate-command",
        "architecture-router-thinness=pytest backend/tests/architecture -k routers_remain_thin",
        "--gate-command",
        "architecture-duplication=pytest backend/tests/architecture -k 'duplication or shared_abstraction'",
        "--gate-command",
        "lint=ruff check .",
        "--gate-command",
        "typecheck=mypy .",
        "--gate-command",
        "test=pytest backend/tests",
        "--gate-command",
        "contract-test=pytest backend/tests/contracts",
        "--gate-command",
        "security-secret-scan=gitleaks detect --source .",
        "--gate-command",
        "security-dependency-audit=pip-audit",
        "--gate-command",
        "security-sbom=syft dir:.",
        "--gate-command",
        "security-vulnerability-scan=trivy fs .",
        "--gate-command",
        "runtime-smoke=docker compose config",
        "--require-strict-validation",
    )

    assert "validation: strict pass" in result.stdout
    strict = _run_installed_validator(target)
    assert strict.returncode == 0

    doctor = _run_doctor(target)
    assert doctor.returncode == 0
    assert json.loads(doctor.stdout)["status"] == "pass"


def test_installer_refuses_to_overwrite_without_force(tmp_path: Path) -> None:
    target = tmp_path / "existing"
    target.mkdir()
    (target / "AGENTS.yml").write_text("existing\n", encoding="utf-8")

    result = _run_installer(target, check=False)

    assert result.returncode == 1
    assert "--force" in result.stderr


def test_force_rescaffold_requires_confirmation_and_preserves_app_files(tmp_path: Path) -> None:
    target = tmp_path / "rescaffold"
    _run_installer(target, "--profile", "lite", "--require-strict-validation")
    (target / "plans/stale.yml").write_text("stale: true\n", encoding="utf-8")
    (target / "governance/stale.md").write_text("# stale\n", encoding="utf-8")
    (target / "app.py").write_text("print('keep')\n", encoding="utf-8")

    aborted = _run_installer(
        target,
        "--profile",
        "lite",
        "--force-rescaffold",
        "--require-strict-validation",
        check=False,
        input_text="n\n",
    )

    assert aborted.returncode == 1
    assert "WARNING: --force-rescaffold deletes" in aborted.stderr
    assert (target / "plans/stale.yml").exists()

    result = _run_installer(
        target,
        "--profile",
        "lite",
        "--force-rescaffold",
        "--require-strict-validation",
        input_text="y\n",
    )

    assert "validation: strict pass" in result.stdout
    assert "force-rescaffold removed:" in result.stdout
    assert not (target / "plans/stale.yml").exists()
    assert not (target / "governance/stale.md").exists()
    assert (target / "app.py").read_text(encoding="utf-8") == "print('keep')\n"


def test_installer_upgrade_refreshes_pack_support_files_without_state_reset(
    tmp_path: Path,
) -> None:
    target = tmp_path / "upgrade"
    _run_installer(target, "--profile", "lite", "--require-strict-validation")
    product_spec_before = (target / "plans/product-spec.yml").read_text(encoding="utf-8")
    (target / "scripts/validate_governance_yaml.py").write_text("old validator\n", encoding="utf-8")
    (target / "scripts/check_governance_exposure.py").unlink()

    result = _run_installer(target, "--upgrade", "--skip-validation")

    assert "upgraded governance pack into" in result.stdout
    assert "old validator" not in (target / "scripts/validate_governance_yaml.py").read_text(
        encoding="utf-8"
    )
    assert (target / "scripts/check_governance_exposure.py").exists()
    assert (target / "scripts/governance_validation/runner.py").exists()
    assert (target / "schemas/phase-history.schema.json").exists()
    assert (target / "plans/product-spec.yml").read_text(encoding="utf-8") == product_spec_before
    agents = yaml.safe_load((target / "AGENTS.yml").read_text(encoding="utf-8"))
    assert agents["governance"]["phase_retention_contract"]["default_cleanup_mode"] == "git_history"
    manifest = yaml.safe_load((target / "governance/artifact-manifest.yml").read_text(encoding="utf-8"))
    assert "mode" not in manifest["phase_retention_policy"]


def test_installer_upgrade_migrates_older_pack_state_to_strict_validation(
    tmp_path: Path,
) -> None:
    target = tmp_path / "upgrade-old-state"
    _run_installer(target, "--profile", "lite", "--require-strict-validation")
    product_spec_before = (target / "plans/product-spec.yml").read_text(encoding="utf-8")

    agents_path = target / "AGENTS.yml"
    agents = yaml.safe_load(agents_path.read_text(encoding="utf-8"))
    agents["governance"]["structural_schema_contract"]["required_schemas"].remove(
        "schemas/phase-history.schema.json"
    )
    agents["governance"]["semantic_validation_contract"]["required_checks"].remove(
        "phase_history_retention"
    )
    agents["governance"]["artifact_ownership_contract"]["canonical_owners"].pop(
        "compact_phase_history_and_archive_hashes"
    )
    agents["governance"].pop("phase_retention_contract")
    agents["structural_guardrails"].pop("agent_deconstruction_contract")
    agents_path.write_text(yaml.safe_dump(agents, sort_keys=False), encoding="utf-8")

    memory_path = target / "MEMORY.yml"
    memory = yaml.safe_load(memory_path.read_text(encoding="utf-8"))
    memory["stable_decisions"].pop("canonical_phase_history")
    memory["environment_facts"]["active_artifacts"].pop("phase_history")
    memory["references"]["governance"].remove("plans/phase-history.yml")
    memory_path.write_text(yaml.safe_dump(memory, sort_keys=False), encoding="utf-8")

    manifest_path = target / "governance/artifact-manifest.yml"
    manifest = yaml.safe_load(manifest_path.read_text(encoding="utf-8"))
    manifest["artifact_roots"].pop("phase_archive")
    manifest.pop("phase_retention_policy")
    manifest["context_budgets"].pop("aggregate_agent_required_kib_advisory")
    manifest["context_budgets"]["agent_required_files"]["MEMORY.yml"] = 105
    manifest["context_budgets"]["agent_required_files"].pop("plans/phase-history.yml")
    manifest_path.write_text(yaml.safe_dump(manifest, sort_keys=False), encoding="utf-8")

    profile_path = target / "governance-profile.yml"
    profile = yaml.safe_load(profile_path.read_text(encoding="utf-8"))
    profile["release_gate_profile"]["gates"].pop("governance_exposure_scan")
    profile["ci_profile"]["required_push_jobs"].remove("governance-exposure-scan")
    profile_path.write_text(yaml.safe_dump(profile, sort_keys=False), encoding="utf-8")

    makefile_path = target / "Makefile.fragment"
    makefile = makefile_path.read_text(encoding="utf-8")
    makefile = makefile.replace(" governance-exposure-scan", "")
    makefile = makefile.replace(
        "\ngovernance-exposure-scan:\n\t$(PYTHON) scripts/check_governance_exposure.py --repo-root .\n",
        "\n",
    )
    makefile = makefile.replace("\n\t$(MAKE) governance-exposure-scan\n", "\n")
    makefile_path.write_text(makefile, encoding="utf-8")

    (target / "plans/phase-history.yml").unlink()
    (target / "scripts/check_governance_exposure.py").unlink()

    result = _run_installer(target, "--upgrade", "--profile", "lite")

    assert "validation: strict pass" in result.stdout
    assert (target / "plans/product-spec.yml").read_text(encoding="utf-8") == product_spec_before
    agents = yaml.safe_load(agents_path.read_text(encoding="utf-8"))
    assert agents["governance"]["phase_retention_contract"]["default_cleanup_mode"] == "git_history"
    manifest = yaml.safe_load(manifest_path.read_text(encoding="utf-8"))
    memory_budget = manifest["context_budgets"]["agent_required_files"]["MEMORY.yml"]
    assert memory_budget["line_hard_cap"] == 105
    assert memory_budget["kib_hard_cap"] == 28
    assert (
        manifest["context_budgets"]["aggregate_agent_required_kib_advisory"] == 350
    )


def test_installer_upgrade_can_reset_profile_and_makefile_options(tmp_path: Path) -> None:
    target = tmp_path / "upgrade-reset"
    _run_installer(target, "--profile", "lite", "--require-strict-validation")
    (target / "Makefile.fragment").write_text("release-check:\n\t@echo stale\n", encoding="utf-8")
    profile_path = target / "governance-profile.yml"
    profile = yaml.safe_load(profile_path.read_text(encoding="utf-8"))
    profile["profile"]["selected"] = "stale"
    profile_path.write_text(yaml.safe_dump(profile, sort_keys=False), encoding="utf-8")

    result = _run_installer(
        target,
        "--upgrade",
        "--reset-options",
        "--profile",
        "lite",
        "--skip-validation",
    )

    assert "upgraded governance pack into" in result.stdout
    makefile = (target / "Makefile.fragment").read_text(encoding="utf-8")
    assert "$(MAKE) governance-validate" in makefile
    assert "$(MAKE) governance-exposure-scan" in makefile
    profile = yaml.safe_load(profile_path.read_text(encoding="utf-8"))
    assert profile["profile"]["selected"] == "lite"


def test_installer_existing_adoption_mode_labels_conversion_phase(tmp_path: Path) -> None:
    target = tmp_path / "existing-mode"
    result = _run_installer(target, "--profile", "lite", "--adoption-mode", "existing")

    assert "adoption mode: existing" in result.stdout
    assert "governance/EXISTING_REPO_ADOPTION.md" in result.stdout
    assert (target / "governance/EXISTING_REPO_ADOPTION.md").exists()
    assert (target / "governance/existing-repo-adoption.yml").exists()

    plan = yaml.safe_load((target / "plans/phase-01-plan.yml").read_text(encoding="utf-8"))
    assert plan["phase"]["build_block"] == "existing_repo_adoption"
    assert "inventory existing architecture, tests, CI, and release gates" in plan[
        "delivery_contract"
    ]["tightly_scoped_deliverables"]

    memory = yaml.safe_load((target / "MEMORY.yml").read_text(encoding="utf-8"))
    assert "existing adoption mode" in memory["environment_facts"]["current_repo_state"][0]

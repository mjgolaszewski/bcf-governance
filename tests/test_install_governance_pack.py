from __future__ import annotations

import importlib.util
import hashlib
import json
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

from bcf_governance.tooling.governance_install import transaction

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
    target.mkdir(parents=True, exist_ok=True)
    if not (target / ".git").exists():
        subprocess.run(["git", "init", "--quiet"], cwd=target, check=True)
        subprocess.run(
            ["git", "config", "user.email", "installer@example.invalid"],
            cwd=target,
            check=True,
        )
        subprocess.run(["git", "config", "user.name", "Installer Test"], cwd=target, check=True)
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


def test_installer_rejects_standard_profile_without_complete_config_before_mutation(tmp_path: Path) -> None:
    target = tmp_path / "demo-standard"
    target.mkdir()
    subprocess.run(["git", "init", "--quiet"], cwd=target, check=True)
    before = subprocess.run(
        ["git", "status", "--porcelain=v1"], cwd=target, capture_output=True, text=True, check=True
    ).stdout
    result = _run_installer(target, check=False)

    assert result.returncode == 1
    assert "--profile-config is required for standard" in result.stderr
    after = subprocess.run(
        ["git", "status", "--porcelain=v1"], cwd=target, capture_output=True, text=True, check=True
    ).stdout
    assert after == before


def test_installer_lite_profile_passes_strict_validation(tmp_path: Path) -> None:
    target = tmp_path / "demo-lite"
    result = _run_installer(target, "--profile", "lite", "--require-strict-validation")

    assert "validation: strict pass" in result.stdout
    profile = yaml.safe_load((target / "governance-profile.yml").read_text(encoding="utf-8"))
    assert profile["profile"]["selected"] == "lite"
    assert profile["release_gate_profile"]["gates"]["lint"]["status"] == "deferred"

    makefile = (target / "Makefile.fragment").read_text(encoding="utf-8")
    assert "scripts/governance_evidence.py" in makefile
    assert "$(MAKE) governance-truthfulness" in makefile
    assert "configure repo-specific" not in makefile

    strict = _run_installed_validator(target)
    assert strict.returncode == 0
    assert json.loads(strict.stdout)["status"] == "pass"
    assert (target / "README.md").read_text(encoding="utf-8").startswith("# Demo Project\n")
    assert "Copyright (c) 2026-04-24 Demo Project" in (target / "LICENSE").read_text(
        encoding="utf-8"
    )
    assert (target / "CHANGELOG.md").read_text(encoding="utf-8").startswith("# Changelog\n")


def test_existing_required_repository_artifacts_are_preserved_byte_identically(
    tmp_path: Path,
) -> None:
    target = tmp_path / "existing-required-artifacts"
    target.mkdir()
    expected = {
        "README.md": b"# Existing product\n\nApplication documentation.\n",
        "LICENSE": b"MIT License\n\nCopyright 2025 Existing Owner\n",
        "CHANGELOG.md": b"# Changelog\n\n## [Unreleased]\n\n- Existing history.\n",
    }
    for relative_path, content in expected.items():
        (target / relative_path).write_bytes(content)

    _run_installer(
        target,
        "--profile",
        "lite",
        "--adoption-mode",
        "existing",
        "--require-strict-validation",
    )

    assert {path: (target / path).read_bytes() for path in expected} == expected


def test_invalid_existing_required_artifact_rolls_back_install(tmp_path: Path) -> None:
    target = tmp_path / "invalid-existing-artifact"
    target.mkdir()
    readme = target / "README.md"
    readme.write_bytes(b"not a project readme\n")

    result = _run_installer(target, "--profile", "lite", check=False)

    assert result.returncode == 1
    assert "README.md must begin" in result.stderr
    assert readme.read_bytes() == b"not a project readme\n"
    assert not (target / "governance").exists()


def test_installer_rejects_removed_gate_command_option(tmp_path: Path) -> None:
    target = tmp_path / "demo-standard-strict"
    result = _run_installer(
        target,
        "--gate-command",
        "test=true",
        check=False,
    )
    assert result.returncode == 2
    assert "unrecognized arguments: --gate-command" in result.stderr


def test_installer_refuses_to_overwrite_without_force(tmp_path: Path) -> None:
    target = tmp_path / "existing"
    target.mkdir()
    (target / "AGENTS.yml").write_text("existing\n", encoding="utf-8")

    result = _run_installer(target, "--profile", "lite", check=False)

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
    protected_paths = (
        "AGENTS.yml",
        "MEMORY.yml",
        "architecture-boundaries.yml",
        "governance/artifact-manifest.yml",
        "governance/findings.yml",
        "plans/product-spec.yml",
        "plans/build-plan.yml",
        "plans/phase-01-plan.yml",
        "requirements-governance.txt",
        ".github/workflows/governance.yml",
    )
    for relative_path in protected_paths:
        path = target / relative_path
        path.write_text(
            path.read_text(encoding="utf-8") + "# local customization\n",
            encoding="utf-8",
        )
    state_before = {
        relative_path: (target / relative_path).read_bytes()
        for relative_path in protected_paths
    }
    (target / "scripts/validate_governance_yaml.py").write_text("old validator\n", encoding="utf-8")
    (target / "scripts/check_governance_exposure.py").unlink()

    result = _run_installer(target, "--upgrade", "--profile", "lite", "--skip-validation")

    assert "upgraded governance pack into" in result.stdout
    assert "old validator" not in (target / "scripts/validate_governance_yaml.py").read_text(
        encoding="utf-8"
    )
    assert (target / "scripts/check_governance_exposure.py").exists()
    assert (target / "scripts/_bcf_runtime/governance_validation/runner.py").exists()
    assert (target / "schemas/phase-history.schema.json").exists()
    assert (target / "governance/gate-contracts.yml").exists()
    assert {
        relative_path: (target / relative_path).read_bytes()
        for relative_path in protected_paths
    } == state_before


def test_installer_upgrade_runs_targeted_evidence_migration_without_rewriting_policy(
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

    phase_log_path = target / "phases/phase-01-log.yml"
    phase_log = yaml.safe_load(phase_log_path.read_text(encoding="utf-8"))
    phase_log["document"]["status"] = "verified"
    phase_log.pop("closeout_requirements")
    phase_log["security_review_complete"] = True
    phase_log_path.write_text(yaml.safe_dump(phase_log, sort_keys=False), encoding="utf-8")

    ledger_path = target / "plans/phase-ledger.yml"
    ledger = yaml.safe_load(ledger_path.read_text(encoding="utf-8"))
    ledger["active_phase"]["lifecycle_status"] = "closed"
    ledger["release_readiness"]["status"] = "release_ready"
    ledger_path.write_text(yaml.safe_dump(ledger, sort_keys=False), encoding="utf-8")

    workitems_path = target / "plans/phase-01-workitems.yml"
    workitems = yaml.safe_load(workitems_path.read_text(encoding="utf-8"))
    workitems["workitems"][0].pop("acceptance_evidence")
    workitems_path.write_text(yaml.safe_dump(workitems, sort_keys=False), encoding="utf-8")

    (target / "plans/phase-history.yml").unlink()
    (target / "scripts/check_governance_exposure.py").unlink()

    protected_paths = (
        agents_path,
        memory_path,
        manifest_path,
    )
    state_before = {path: path.read_bytes() for path in protected_paths}

    result = _run_installer(target, "--upgrade", "--profile", "lite", "--skip-validation")

    assert "upgraded governance pack into" in result.stdout
    assert (target / "plans/product-spec.yml").read_text(encoding="utf-8") == product_spec_before
    assert {path: path.read_bytes() for path in protected_paths} == state_before
    migrated_profile = yaml.safe_load(profile_path.read_text(encoding="utf-8"))
    assert migrated_profile["profile"]["selected"] == "lite"
    assert "governance_exposure_scan" in migrated_profile["release_gate_profile"]["gates"]
    assert "governance-exposure-scan" in makefile_path.read_text(encoding="utf-8")
    assert (target / "governance/gate-contracts.yml").exists()
    assert (target / "plans/phase-history.yml").exists()
    assert (target / "scripts/check_governance_exposure.py").exists()
    migrated_phase = yaml.safe_load(phase_log_path.read_text(encoding="utf-8"))
    assert migrated_phase["document"]["status"] == "completed"
    assert "security_review_complete" not in migrated_phase
    assert "closeout_requirements" in migrated_phase
    migrated_ledger = yaml.safe_load(ledger_path.read_text(encoding="utf-8"))
    assert migrated_ledger["active_phase"]["lifecycle_status"] == "completed"
    assert "status" not in migrated_ledger["release_readiness"]
    migrated_workitems = yaml.safe_load(workitems_path.read_text(encoding="utf-8"))
    assert migrated_workitems["workitems"][0]["acceptance_evidence"]
    assert (target / "governance/migrations/evidence-integrity-v1.yml").exists()


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
    assert "scripts/governance_evidence.py" in makefile
    assert "$(MAKE) governance-truthfulness" in makefile
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


def test_existing_install_never_rewrites_unrelated_placeholders_and_merges_gitignore(
    tmp_path: Path,
) -> None:
    target = tmp_path / "existing-app"
    target.mkdir()
    app = target / "app.py"
    app.write_text('BANNER = "{{PROJECT_NAME}}"\n', encoding="utf-8")
    gitignore = target / ".gitignore"
    original_gitignore = b"custom-cache/\n\n\n"
    gitignore.write_bytes(original_gitignore)

    _run_installer(
        target,
        "--profile",
        "lite",
        "--adoption-mode",
        "existing",
        "--require-strict-validation",
    )

    assert app.read_text(encoding="utf-8") == 'BANNER = "{{PROJECT_NAME}}"\n'
    merged_bytes = gitignore.read_bytes()
    assert merged_bytes.startswith(original_gitignore)
    merged = merged_bytes.decode("utf-8")
    assert merged.count("# BEGIN BCF GOVERNANCE") == 1
    assert merged.count("# END BCF GOVERNANCE") == 1
    installer = _load_installer_module()
    assert installer._merge_gitignore(
        merged_bytes, (REPO_ROOT / "template-repo/.gitignore").read_bytes()
    ) == merged_bytes


def test_existing_application_symlink_is_not_followed_or_rewritten(tmp_path: Path) -> None:
    target = tmp_path / "symlink-app"
    target.mkdir()
    external = tmp_path / "external.txt"
    external.write_text("{{PROJECT_NAME}}\n", encoding="utf-8")
    (target / "app-link.txt").symlink_to(external)

    _run_installer(target, "--profile", "lite", "--adoption-mode", "existing")

    assert external.read_text(encoding="utf-8") == "{{PROJECT_NAME}}\n"
    assert (target / "app-link.txt").is_symlink()


def test_install_rejects_managed_symlink_parent_without_outside_writes(tmp_path: Path) -> None:
    target = tmp_path / "symlink-destination"
    target.mkdir()
    external = tmp_path / "external-governance"
    external.mkdir()
    sentinel = external / "sentinel.txt"
    sentinel.write_text("unchanged\n", encoding="utf-8")
    (target / "governance").symlink_to(external, target_is_directory=True)

    result = _run_installer(target, "--profile", "lite", check=False)

    assert result.returncode == 1
    assert "symlink" in result.stderr
    assert sentinel.read_text(encoding="utf-8") == "unchanged\n"
    assert sorted(path.name for path in external.iterdir()) == ["sentinel.txt"]


def test_upgrade_rejects_managed_file_symlink_without_outside_writes(
    tmp_path: Path,
) -> None:
    target = tmp_path / "upgrade-symlink"
    target.mkdir()
    _run_installer(target, "--profile", "lite")
    external = tmp_path / "external-validator.py"
    external.write_text("# unchanged\n", encoding="utf-8")
    validator = target / "scripts/validate_governance_yaml.py"
    validator.unlink()
    validator.symlink_to(external)

    result = _run_installer(
        target,
        "--upgrade",
        "--profile",
        "lite",
        check=False,
    )

    assert result.returncode == 1
    assert "symlink" in result.stderr
    assert external.read_text(encoding="utf-8") == "# unchanged\n"


def test_manifest_path_escape_is_rejected() -> None:
    installer = _load_installer_module()
    with pytest.raises(ValueError, match="unsafe pack path"):
        installer._validate_relative_path(Path("../outside"))
    with pytest.raises(ValueError, match="unsafe pack path"):
        installer._validate_relative_path(Path("/outside"))


def test_pack_manifest_rejects_duplicate_destinations(tmp_path: Path) -> None:
    installer = _load_installer_module()
    (tmp_path / "a.txt").write_text("a\n", encoding="utf-8")
    digest = hashlib.sha256(b"a\n").hexdigest()
    (tmp_path / ".bcf-pack-manifest.json").write_text(
        '{"schema_version":"1.0","files":{'
        f'"a.txt":{{"sha256":"{digest}","operation":"copy"}},'
        f'"a.txt":{{"sha256":"{digest}","operation":"copy"}}'
        '},"generated":[]}',
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="duplicates destination a.txt"):
        installer._pack_manifest_entries(tmp_path)


def test_transaction_interrupt_restores_all_touched_files_byte_identically(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repo = tmp_path / "transaction"
    repo.mkdir()
    first = repo / "a.txt"
    second = repo / "b.txt"
    first.write_bytes(b"first-before\n")
    second.write_bytes(b"second-before\n")
    first.chmod(0o640)
    second.chmod(0o600)
    before = {
        path.name: (path.read_bytes(), path.stat().st_mode)
        for path in (first, second)
    }
    original = transaction._atomic_write
    writes = 0

    def interrupted(path: Path, data: bytes, mode: int) -> None:
        nonlocal writes
        writes += 1
        if writes == 2:
            raise KeyboardInterrupt("injected interruption")
        original(path, data, mode)

    monkeypatch.setattr(transaction, "_atomic_write", interrupted)

    def mutate(shadow: Path) -> None:
        (shadow / "a.txt").write_bytes(b"first-after\n")
        (shadow / "b.txt").write_bytes(b"second-after\n")

    with pytest.raises(KeyboardInterrupt, match="injected interruption"):
        transaction.apply_transaction(
            repo,
            managed_paths=("a.txt", "b.txt"),
            mutate_shadow=mutate,
        )

    assert {
        path.name: (path.read_bytes(), path.stat().st_mode)
        for path in (first, second)
    } == before

from __future__ import annotations

import importlib.util
import hashlib
import json
import os
import shutil
import subprocess
import sys
import venv
from pathlib import Path

import pytest
import yaml

from bcf_governance.tooling.governance_install import transaction, upgrade
from bcf_governance.tooling.runtime_capacity import EXECUTION_STATE_POLICY

REPO_ROOT = Path(__file__).resolve().parents[1]
INSTALLER = REPO_ROOT / "scripts" / "install_governance_pack.py"
DOCTOR = REPO_ROOT / "scripts" / "doctor_governance_pack.py"


def _candidate_source_runtime(root: Path) -> tuple[Path, dict[str, str]]:
    """Bind child CLI processes to the exact candidate source under test."""

    venv.EnvBuilder(with_pip=False, system_site_packages=True).create(root)
    python = root / "bin/python"
    environment = {
        key: value
        for key, value in os.environ.items()
        if key not in {"PYTHONHOME", "PYTHONPATH", "VIRTUAL_ENV"}
    }
    purelib = subprocess.run(
        [str(python), "-c", "import sysconfig; print(sysconfig.get_path('purelib'))"],
        env=environment,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    installed = Path(purelib) / "bcf_governance"
    shutil.copytree(
        REPO_ROOT / "bcf_governance",
        installed,
        ignore=shutil.ignore_patterns("__pycache__", "*.pyc"),
    )
    resolved = subprocess.run(
        [str(python), "-c", "import bcf_governance; print(bcf_governance.__file__)"],
        cwd=root,
        env=environment,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    assert Path(resolved).resolve() == (installed / "__init__.py").resolve()
    return python, environment


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
            "--candidate-runner-label",
            "ubuntu-24.04",
            "--trusted-runner-label",
            "ubuntu-24.04",
            "--candidate-runner-kind",
            "hosted",
            "--trusted-runner-kind",
            "hosted",
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
    assert "scripts/governance_truth.py" in makefile
    assert "configure repo-specific" not in makefile
    assert (target / "Makefile").read_text(encoding="utf-8") == (
        "include Makefile.fragment\n"
    )
    make = subprocess.run(
        ["make", "--dry-run", "release-check"],
        cwd=target,
        capture_output=True,
        text=True,
        check=False,
    )
    assert make.returncode == 0, make.stdout + make.stderr

    strict = _run_installed_validator(target)
    assert strict.returncode == 0
    assert json.loads(strict.stdout)["status"] == "pass"
    assert (target / "README.md").read_text(encoding="utf-8").startswith("# Demo Project\n")
    assert "Copyright (c) 2026-04-24 Demo Project" in (target / "LICENSE").read_text(
        encoding="utf-8"
    )
    assert (target / "CHANGELOG.md").read_text(encoding="utf-8").startswith("# Changelog\n")

    self_contract = yaml.safe_load(
        (REPO_ROOT / "governance/self-overlays.yml").read_text(encoding="utf-8")
    )
    excluded = {
        relative
        for overlay in self_contract["overlays"]
        for relative in overlay["adopter_excluded_pack_surfaces"]
    }
    assert excluded
    assert all(not (target / relative).exists() for relative in excluded)


def test_existing_install_reports_generated_release_owner_without_rewriting_makefile(
    tmp_path: Path,
) -> None:
    target = tmp_path / "existing-release-owner"
    target.mkdir()
    subprocess.run(["git", "init", "--quiet"], cwd=target, check=True)
    makefile = target / "Makefile"
    original = "application:\n\t@echo application\n"
    makefile.write_text(original, encoding="utf-8")

    result = _run_installer(
        target,
        "--profile",
        "lite",
        "--adoption-mode",
        "existing",
        "--skip-validation",
    )

    assert makefile.read_text(encoding="utf-8") == original
    assert "next: run make -f Makefile.fragment release-check" in result.stdout
    make = subprocess.run(
        ["make", "-f", "Makefile.fragment", "--dry-run", "release-check"],
        cwd=target,
        capture_output=True,
        text=True,
        check=False,
    )
    assert make.returncode == 0, make.stdout + make.stderr


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
        "governance-profile.yml",
        "governance/artifact-manifest.yml",
        "governance/gate-contracts.yml",
        "governance/evidence-policy.yml",
        "governance/findings.yml",
        "governance/ci-graph.yml",
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
    (target / "scripts/capture_governance_shard.py").unlink()
    (target / "scripts/restore_evidence_modes.py").unlink()

    result = _run_installer(target, "--upgrade", "--profile", "lite", "--skip-validation")

    assert "upgraded governance pack into" in result.stdout
    assert "old validator" not in (target / "scripts/validate_governance_yaml.py").read_text(
        encoding="utf-8"
    )
    assert (target / "scripts/check_governance_exposure.py").exists()
    assert (target / "scripts/capture_governance_shard.py").read_bytes() == (
        REPO_ROOT / "bcf_governance/pack/template-repo/scripts/capture_governance_shard.py"
    ).read_bytes()
    assert (target / "scripts/restore_evidence_modes.py").read_bytes() == (
        REPO_ROOT / "bcf_governance/pack/template-repo/scripts/restore_evidence_modes.py"
    ).read_bytes()
    assert (target / "scripts/_bcf_runtime/governance_validation/runner.py").exists()
    assert (target / "schemas/phase-history.schema.json").exists()
    assert (target / "governance/gate-contracts.yml").exists()
    assert {
        relative_path: (target / relative_path).read_bytes()
        for relative_path in protected_paths
    } == state_before


def test_upgrade_rejects_ungoverned_repository_before_mutation(tmp_path: Path) -> None:
    target = tmp_path / "ungoverned"
    target.mkdir()
    application = target / "app.py"
    application.write_text("PRODUCT = True\n", encoding="utf-8")

    result = _run_installer(target, "--upgrade", "--skip-validation", check=False)

    assert result.returncode == 1
    assert "reject_not_installed" in result.stderr
    assert application.read_text(encoding="utf-8") == "PRODUCT = True\n"
    assert not (target / "scripts/_bcf_runtime").exists()


def test_upgrade_rejects_partial_installation_before_mutation(tmp_path: Path) -> None:
    target = tmp_path / "partial"
    target.mkdir()
    profile = target / "governance-profile.yml"
    profile.write_text("profile: lite\n", encoding="utf-8")

    result = _run_installer(target, "--upgrade", "--skip-validation", check=False)

    assert result.returncode == 1
    assert "reject_partial_installation" in result.stderr
    assert profile.read_text(encoding="utf-8") == "profile: lite\n"
    assert not (target / "scripts/_bcf_runtime").exists()


def test_upgrade_retires_only_declared_self_authority_pack_surfaces(
    tmp_path: Path,
) -> None:
    target = tmp_path / "upgrade-self-authority"
    _run_installer(target, "--profile", "lite", "--require-strict-validation")
    contract = yaml.safe_load(
        (REPO_ROOT / "governance/self-overlays.yml").read_text(encoding="utf-8")
    )
    excluded = {
        relative
        for overlay in contract["overlays"]
        for relative in overlay["adopter_excluded_pack_surfaces"]
    }
    for relative in excluded:
        destination = target / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes((REPO_ROOT / "template-repo" / relative).read_bytes())
    retained = target / "scripts/_bcf_runtime/ci_graph_contracts.py"
    before = retained.read_bytes()

    result = _run_installer(
        target,
        "--upgrade",
        "--profile",
        "lite",
        "--require-strict-validation",
    )

    assert "validation: strict pass" in result.stdout
    assert all(not (target / relative).exists() for relative in excluded)
    assert retained.read_bytes() == before


def test_upgrade_reconcile_uses_candidate_tree_after_retiring_tracked_self_authority(
    tmp_path: Path,
) -> None:
    target = tmp_path / "upgrade-tracked-self-authority"
    _run_installer(target, "--profile", "lite", "--require-strict-validation")
    contract = yaml.safe_load(
        (REPO_ROOT / "governance/self-overlays.yml").read_text(encoding="utf-8")
    )
    excluded = {
        relative
        for overlay in contract["overlays"]
        for relative in overlay["adopter_excluded_pack_surfaces"]
    }
    for relative in excluded:
        destination = target / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes((REPO_ROOT / "template-repo" / relative).read_bytes())
    subprocess.run(["git", "add", "."], cwd=target, check=True)
    subprocess.run(
        ["git", "commit", "--quiet", "-m", "adopter before upgrade"],
        cwd=target,
        check=True,
    )

    _run_installer(target, "--upgrade", "--profile", "lite", "--require-strict-validation")
    tool_python, tool_environment = _candidate_source_runtime(
        tmp_path / "candidate-tool-runtime"
    )

    result = subprocess.run(
        [
            str(tool_python),
            "-m",
            "bcf_governance.cli",
            "reconcile",
            "--repo-root",
            str(target),
            "--python",
            sys.executable,
            "--apply",
        ],
        cwd=REPO_ROOT,
        env=tool_environment,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert all(not (target / relative).exists() for relative in excluded)


def test_upgrade_reconciles_graph_owned_workflows_before_strict_validation(
    tmp_path: Path,
) -> None:
    target = tmp_path / "upgrade-graph-projection"
    _run_installer(target, "--profile", "lite", "--require-strict-validation")
    graph_path = target / "governance/ci-graph.yml"
    graph = yaml.safe_load(graph_path.read_text(encoding="utf-8"))
    graph["workflows"][0]["display_name"] = "Governance adopter projection"
    graph_path.write_text(yaml.safe_dump(graph, sort_keys=False), encoding="utf-8")

    result = _run_installer(target, "--upgrade", "--require-strict-validation")

    assert "validation: strict pass" in result.stdout
    workflow = yaml.safe_load(
        (target / graph["workflows"][0]["path"]).read_text(encoding="utf-8")
    )
    assert workflow["name"] == "Governance adopter projection"


def test_upgrade_migrates_exact_runtime_v1_without_overwriting_capacity(
    tmp_path: Path,
) -> None:
    target = tmp_path / "upgrade-runtime-contract"
    _run_installer(target, "--profile", "lite", "--require-strict-validation")
    runtime_path = target / "governance/ci-runtime.yml"
    runtime_path.write_text(
        "schema_version: '1.0'\n"
        "runtime_root: .artifacts/runtime # non-authoritative local runtime state\n"
        "minimum_free_bytes: 987654321\n"
        "maximum_owned_containers: 17\n"
        "database:\n"
        "  storage: repository_bind_mount\n"
        "  relative_path: .artifacts/runtime/database # non-authoritative local runtime state\n"
        "cleanup:\n"
        "  caller_globs: false\n"
        "  daemon_global_prune: false\n"
        "  exact_owner_revalidation: true\n"
        "  remove_anonymous_volumes: true\n",
        encoding="utf-8",
    )

    result = _run_installer(target, "--upgrade", "--require-strict-validation")

    assert "validation: strict pass" in result.stdout
    migrated = yaml.safe_load(runtime_path.read_text(encoding="utf-8"))
    assert migrated["schema_version"] == "1.1"
    assert migrated["minimum_free_bytes"] == 987654321
    assert migrated["maximum_owned_containers"] == 17
    assert migrated["execution_state"] == EXECUTION_STATE_POLICY


def test_upgrade_rejects_ambiguous_legacy_runtime_contract(tmp_path: Path) -> None:
    target = tmp_path / "upgrade-ambiguous-runtime"
    _run_installer(target, "--profile", "lite", "--require-strict-validation")
    runtime_path = target / "governance/ci-runtime.yml"
    runtime = yaml.safe_load(runtime_path.read_text(encoding="utf-8"))
    runtime["schema_version"] = "1.0"
    runtime.pop("execution_state")
    runtime["undeclared_state_policy"] = "retain"
    runtime_path.write_text(yaml.safe_dump(runtime, sort_keys=False), encoding="utf-8")

    result = _run_installer(target, "--upgrade", "--skip-validation", check=False)

    assert result.returncode == 1
    assert "not an exact migratable v1.0 shape" in result.stderr


def test_upgrade_rejects_drift_in_runtime_locked_consumer_file(tmp_path: Path) -> None:
    target = tmp_path / "upgrade-locked-drift"
    _run_installer(target, "--profile", "lite", "--require-strict-validation")
    relative = "backend/tests/architecture/test_boundaries_ast.py"
    path = target / relative
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    (target / "governance/bcf-runtime-lock.json").write_text(
        json.dumps(
            {
                "schema_version": "1.0",
                "version": "2.1.4",
                "source_repository": "mjgolaszewski/bcf-governance",
                "source_repository_id": 1207503211,
                "source_commit": "a" * 40,
                "release_id": 1,
                "release_url": "https://github.com/mjgolaszewski/bcf-governance/releases/tag/v2.1.4",
                "wheel_sha256": "b" * 64,
                "source_archive_sha256": "c" * 64,
                "checksum_manifest_sha256": "d" * 64,
                "official_installer_adaptations": {},
                "files": {},
                "preserved_consumer_files": {relative: digest},
            }
        ),
        encoding="utf-8",
    )
    path.write_text("unexplained drift\n", encoding="utf-8")
    assets = tmp_path / "release-assets"
    assets.mkdir()
    result = _run_installer(
        target,
        "--upgrade",
        "--release-assets",
        str(assets),
        "--skip-validation",
        check=False,
    )
    assert result.returncode == 1
    assert "consumer_preserved_drift" in result.stderr


def test_upgrade_preserves_bounded_package_metadata_ownership(tmp_path: Path) -> None:
    target = tmp_path / "package-metadata-upgrade"
    _run_installer(target, "--profile", "lite", "--require-strict-validation")
    architecture_path = target / "architecture-boundaries.yml"
    architecture_text = architecture_path.read_text(encoding="utf-8")
    ownership = [
        {
            "path": "backend/src/demo/__init__.py",
            "layer": "infrastructure",
            "context": "distribution",
            "exports": ["__version__"],
        }
    ]
    marker = "architecture:\n"
    assert architecture_text.count(marker) == 1
    ownership_line = (
        "architecture:\n"
        "  package_metadata_ownership: [{path: backend/src/demo/__init__.py, "
        "layer: infrastructure, context: distribution, exports: [__version__]}]\n"
    )
    architecture_path.write_text(
        architecture_text.replace(marker, ownership_line), encoding="utf-8"
    )

    result = _run_installer(target, "--upgrade", "--require-strict-validation")

    assert "validation: strict pass" in result.stdout
    upgraded = yaml.safe_load(architecture_path.read_text(encoding="utf-8"))
    assert upgraded["architecture"]["package_metadata_ownership"] == ownership


def test_upgrade_refreshes_code_without_implicitly_migrating_legacy_state(
    tmp_path: Path,
) -> None:
    target = tmp_path / "upgrade-legacy-state"
    _run_installer(target, "--profile", "lite", "--require-strict-validation")
    governed = (
        "AGENTS.yml",
        "MEMORY.yml",
        "governance-profile.yml",
        "governance/gate-contracts.yml",
        "governance/evidence-policy.yml",
        "plans/phase-ledger.yml",
        "phases/phase-01-log.yml",
    )
    before = {path: (target / path).read_bytes() for path in governed}
    (target / "scripts/validate_governance_yaml.py").write_text(
        "old validator\n", encoding="utf-8"
    )

    result = _run_installer(target, "--upgrade", "--skip-validation")

    assert "upgraded governance pack into" in result.stdout
    assert "old validator" not in (
        target / "scripts/validate_governance_yaml.py"
    ).read_text(encoding="utf-8")
    assert {path: (target / path).read_bytes() for path in governed} == before
    assert not (target / "governance/migrations/evidence-integrity-v1.yml").exists()


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
    assert "scripts/governance_truth.py" in makefile
    profile = yaml.safe_load(profile_path.read_text(encoding="utf-8"))
    assert profile["profile"]["selected"] == "lite"


def test_upgrade_projects_v3_release_check_from_selective_plan(tmp_path: Path) -> None:
    target = tmp_path / "upgrade-v3-release-check"
    target.mkdir()
    (target / "governance-profile.yml").write_text(
        yaml.safe_dump(
            {
                "profile": {"selected": "standard"},
                "profile_contract_version": "3.0",
                "release_gate_profile": {
                    "gates": {
                        "governance_validate": {
                            "target": "governance-validate", "status": "required"
                        },
                        "test": {"target": "test", "status": "required"},
                    }
                },
            },
            sort_keys=False,
        ),
        encoding="utf-8",
    )
    (target / "Makefile.fragment").write_text(
        "BCF_EVIDENCE_DIR ?= .artifacts/bcf\n\n"
        ".PHONY: release-check governance-validate test\n\n"
        "release-check:\n"
        "\t@for gate in governance-validate test; do echo $$gate; done\n",
        encoding="utf-8",
    )

    template = tmp_path / "template"
    template.mkdir()
    upgrade.upgrade_state_files(
        template_root=template,
        target_root=target,
        values={},
    )

    release_check = (target / "Makefile.fragment").read_text(encoding="utf-8").split(
        "release-check:", 1
    )[1]
    assert "scripts/capture_governance_shard.py" in release_check
    assert "--all-planned" in release_check
    assert "for gate in" not in release_check


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


def test_pack_manifest_rejects_unknown_installation_scope(tmp_path: Path) -> None:
    installer = _load_installer_module()
    (tmp_path / "a.txt").write_text("a\n", encoding="utf-8")
    digest = hashlib.sha256(b"a\n").hexdigest()
    (tmp_path / ".bcf-pack-manifest.json").write_text(
        json.dumps(
            {
                "schema_version": "1.0",
                "files": {
                    "a.txt": {
                        "sha256": digest,
                        "operation": "copy",
                        "installation_scope": "unknown",
                    }
                },
                "generated": [],
            }
        ),
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="invalid installation scope"):
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


def test_transaction_final_projection_failure_rolls_back_exact_bytes(
    tmp_path: Path,
) -> None:
    repo = tmp_path / "transaction-final"
    repo.mkdir()
    path = repo / "generated.yml"
    path.write_bytes(b"before\n")

    def mutate(shadow: Path) -> None:
        (shadow / "generated.yml").write_bytes(b"after\n")

    def reject_final() -> None:
        raise ValueError("generated projection drift")

    with pytest.raises(ValueError, match="generated projection drift"):
        transaction.apply_transaction(
            repo,
            managed_paths=("generated.yml",),
            mutate_shadow=mutate,
            validate_final=reject_final,
        )

    assert path.read_bytes() == b"before\n"

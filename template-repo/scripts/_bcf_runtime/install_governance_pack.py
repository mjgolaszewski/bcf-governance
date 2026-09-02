"""Install the governance template pack into a target repository."""

from __future__ import annotations

import argparse
import hashlib
import importlib.resources
import json
import os
import re
import shutil
import subprocess
import sys
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

_SCRIPT_ROOT = Path(__file__).resolve().parent
if str(_SCRIPT_ROOT) not in sys.path:
    sys.path.insert(0, str(_SCRIPT_ROOT))

from .governance_install.args import build_parser  # noqa: E402
from .governance_install.ci_graph import write_reference_ci_graph  # noqa: E402
from .governance_install.phase import generate_phase_artifacts  # noqa: E402
from .governance_install.artifacts import (  # noqa: E402
    ensure_required_artifacts,
    merge_gitignore as _merge_gitignore,
)
from .governance_install.reporting import print_summary  # noqa: E402
from .governance_install.transaction import apply_transaction  # noqa: E402
from .governance_install.upgrade import replace_placeholders_in_files, upgrade_state_files  # noqa: E402
from .governance_profiles import (  # noqa: E402
    apply_profile_contract,
    apply_scaffold_requirements,
    load_contract,
)
from .profile_contract_v2 import resolve_install_contract_version  # noqa: E402

PROFILE_CHOICES = ("lite", "standard", "regulated")
ADOPTION_MODE_CHOICES = ("fresh", "existing")
DEFAULT_TARGET_USER = "operators"
DEFAULT_RUNNER_LABELS = "ubuntu-latest"
TEMPLATE_EXAMPLE_ARTIFACTS = (
    "plans/phase-NN-plan.yml",
    "plans/phase-NN-workitems.yml",
    "phases/phase-NN-log.yml",
    "phases/phase-NN-hotfixNN.yml",
)
RESCAFFOLD_REMOVE_PATHS = (
    "AGENTS.yml",
    "AGENTS.md",
    "CLAUDE.md",
    "MEMORY.yml",
    "architecture-boundaries.yml",
    "governance-profile.yml",
    "Makefile.fragment",
    "requirements-governance.txt",
    "audits",
    "governance",
    "phases",
    "plans",
    "schemas",
    "contracts/observability",
    "backend/tests/architecture/test_boundaries_ast.py",
    ".github/workflows/governance.yml",
    ".github/workflows/bcf-exact-main.yml",
    ".github/workflows/bcf-trusted-finalizer.yml",
    ".github/workflows/bcf-status-publisher.yml",
    ".github/workflows/governance-mutants-nightly.yml",
    ".github/workflows/governance-mutants-weekly.yml",
    "governance/ci-graph.yml",
    "governance/ci-extensions",
    "scripts/check_governance_exposure.py",
    "scripts/governance_evidence.py",
    "scripts/governance_truth.py",
    "scripts/governance_truth_support.py",
    "scripts/preflight_governance.py", "scripts/semantic_ownership.py",
    "scripts/_bcf_runtime",
    "scripts/migrate_governance_evidence.py",
    "scripts/profile_governance.py",
    "scripts/governance_validation",
    "scripts/scaffold_governance_artifacts.py",
    "scripts/validate_governance_yaml.py",
)
INSTALL_MANAGED_PATHS = tuple(
    dict.fromkeys(
        (
            *RESCAFFOLD_REMOVE_PATHS,
            "docs/OPERATIONS.md",
            ".gitignore",
            "README.md",
            "LICENSE",
            "CHANGELOG.md",
        )
    )
)
PRESERVED_REQUIRED_ARTIFACTS = ("README.md", "LICENSE", "CHANGELOG.md")
EXISTING_ADOPTION_ARTIFACTS = (
    "governance/EXISTING_REPO_ADOPTION.md",
    "governance/existing-repo-adoption.yml",
)
LITE_DEFERRED_GATES = (
    "architecture-test",
    "architecture-module-size",
    "architecture-layer-membership",
    "architecture-context-membership",
    "architecture-import-boundaries",
    "architecture-cqrs-side",
    "architecture-router-thinness",
    "architecture-duplication",
    "lint",
    "typecheck",
    "test",
    "contract-test",
    "security-secret-scan",
    "security-dependency-audit",
    "security-sbom",
    "security-vulnerability-scan",
    "security-review",
    "runtime-smoke",
)
REQUIRED_STANDARD_GATES = ("governance-validate", "governance-exposure-scan", *LITE_DEFERRED_GATES)
UPGRADE_REFRESH_PATHS = (
    "schemas",
    "backend/tests/architecture/test_boundaries_ast.py",
    "governance/REPO_CLEANUP.md",
    "scripts/check_governance_exposure.py",
    "scripts/governance_evidence.py",
    "scripts/governance_truth.py",
    "scripts/governance_truth_support.py",
    "scripts/preflight_governance.py", "scripts/semantic_ownership.py",
    "scripts/_bcf_runtime",
    "scripts/migrate_governance_evidence.py",
    "scripts/profile_governance.py",
    "scripts/governance_validation",
    "scripts/scaffold_governance_artifacts.py",
    "scripts/validate_governance_yaml.py",
)
UPGRADE_PROJECT_OWNED_PATHS = (
    "governance-profile.yml",
    "governance/gate-contracts.yml",
    "governance/evidence-policy.yml",
    "governance/ci-graph.yml",
    "governance/ci-extensions",
    ".github/workflows",
)
UPGRADE_RESET_OPTION_PATHS = (
    "Makefile.fragment",
    "architecture-boundaries.yml",
    "governance-profile.yml",
)
@dataclass(frozen=True)
class InstallResult:
    copied_files: int
    rescaffold_removed_paths: list[str]
    removed_template_examples: list[str]
    generated_artifacts: dict[str, Path]
    strict_validation_passed: bool
    bootstrap_validation_passed: bool
    strict_validation_output: str
    bootstrap_validation_output: str


def _pack_root() -> Path:
    return Path(__file__).resolve().parents[1]


def _template_root() -> Path:
    source_template = _pack_root() / "template-repo"
    if source_template.exists():
        return source_template
    packaged_template = importlib.resources.files("bcf_governance").joinpath("pack", "template-repo")
    return Path(str(packaged_template))


def _phase_number(phase_id: str) -> int:
    if not phase_id.startswith("P") or not phase_id[1:].isdigit():
        raise ValueError(f"invalid phase id {phase_id!r}; expected values like 'P01'")
    return int(phase_id[1:])


def _project_id_from_name(name: str) -> str:
    normalized = re.sub(r"[^a-z0-9]+", "-", name.lower()).strip("-")
    return normalized or "project"


def _title_from_id(project_id: str) -> str:
    return " ".join(part.capitalize() for part in project_id.replace("_", "-").split("-") if part) or "Project"


def _is_template_artifact(path: Path) -> bool:
    return (
        "__pycache__" not in path.parts
        and path.suffix != ".pyc"
        and path.name != ".bcf-pack-manifest.json"
    )


def _iter_template_files(template_root: Path) -> list[Path]:
    files: list[Path] = []
    for path in sorted(template_root.rglob("*")):
        if path.is_symlink():
            raise ValueError(f"template pack contains forbidden symlink: {path}")
        if path.is_file() and _is_template_artifact(path):
            files.append(path)
    return files


def _validate_relative_path(relative_path: Path) -> None:
    if relative_path.is_absolute() or not relative_path.parts or ".." in relative_path.parts:
        raise ValueError(f"unsafe pack path: {relative_path}")


def _reject_symlink_destination(target_root: Path, relative_path: Path) -> None:
    _validate_relative_path(relative_path)
    current = target_root
    for part in relative_path.parts:
        current = current / part
        if current.is_symlink():
            raise ValueError(f"refusing to install through symlink: {relative_path}")


def _pack_manifest_entries(template_root: Path) -> dict[str, dict[str, Any]]:
    manifest_path = template_root / ".bcf-pack-manifest.json"
    if not manifest_path.is_file() or manifest_path.is_symlink():
        raise ValueError("template pack is missing .bcf-pack-manifest.json")
    def unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError(f"pack manifest duplicates destination {key}")
            result[key] = value
        return result

    payload = json.loads(
        manifest_path.read_text(encoding="utf-8"), object_pairs_hook=unique_object
    )
    raw_files = payload.get("files") if isinstance(payload, dict) else None
    if not isinstance(raw_files, dict) or not raw_files:
        raise ValueError("pack manifest must declare a non-empty files mapping")
    entries: dict[str, dict[str, Any]] = {}
    for raw_path, raw_entry in raw_files.items():
        relative = Path(str(raw_path))
        _validate_relative_path(relative)
        if not isinstance(raw_entry, dict):
            raise ValueError(f"pack manifest entry for {raw_path} must be a mapping")
        digest = raw_entry.get("sha256")
        if not isinstance(digest, str) or not re.fullmatch(r"[a-f0-9]{64}", digest):
            raise ValueError(f"pack manifest has invalid digest for {raw_path}")
        if raw_entry.get("operation") not in {"copy", "merge", "generate", "preserve"}:
            raise ValueError(f"pack manifest has invalid operation for {raw_path}")
        profiles = raw_entry.get("profiles")
        if profiles is not None and (
            not isinstance(profiles, list)
            or not profiles
            or not all(value in PROFILE_CHOICES for value in profiles)
        ):
            raise ValueError(f"pack manifest has invalid profiles for {raw_path}")
        if relative.as_posix() in entries:
            raise ValueError(f"pack manifest duplicates {raw_path}")
        entries[relative.as_posix()] = raw_entry
    actual = {
        path.relative_to(template_root).as_posix(): hashlib.sha256(path.read_bytes()).hexdigest()
        for path in _iter_template_files(template_root)
    }
    expected_digests = {path: str(entry["sha256"]) for path, entry in entries.items()}
    if actual != expected_digests:
        missing = sorted(set(actual) - set(entries))
        stale = sorted(set(entries) - set(actual))
        mismatched = sorted(
            path
            for path in set(actual) & set(entries)
            if actual[path] != expected_digests[path]
        )
        raise ValueError(
            "pack manifest mismatch: "
            f"missing={missing}, stale={stale}, digest_mismatch={mismatched}"
        )
    return entries


def _copy_template(
    *,
    template_root: Path,
    target_root: Path,
    allow_replace: bool,
    profile: str,
) -> tuple[int, list[Path]]:
    conflicts: list[str] = []
    entries = _pack_manifest_entries(template_root)
    relative_paths = [
        Path(value)
        for value in sorted(entries)
        if profile in entries[value].get("profiles", PROFILE_CHOICES)
    ]
    for relative_path in relative_paths:
        _reject_symlink_destination(target_root, relative_path)
        destination = target_root / relative_path
        operation = entries[relative_path.as_posix()]["operation"]
        if (
            destination.exists()
            and operation not in {"merge", "preserve"}
            and not allow_replace
        ):
            conflicts.append(relative_path.as_posix())

    if conflicts:
        preview = "\n".join(f"- {path}" for path in conflicts)
        raise FileExistsError(
            "target already contains governance pack paths; use --upgrade or explicitly confirmed "
            "--force-rescaffold instead of overwriting them:\n"
            f"{preview}"
        )

    destinations: list[Path] = []
    for relative_path in relative_paths:
        source = template_root / relative_path
        destination = target_root / relative_path
        destination.parent.mkdir(parents=True, exist_ok=True)
        operation = entries[relative_path.as_posix()]["operation"]
        if operation == "preserve" and destination.exists():
            continue
        if operation == "merge":
            existing = destination.read_bytes() if destination.exists() else None
            destination.write_bytes(_merge_gitignore(existing, source.read_bytes()))
        else:
            shutil.copy2(source, destination)
        destinations.append(destination)
    return len(destinations), destinations


def _copy_selected_template_paths(
    *,
    template_root: Path,
    target_root: Path,
    relative_paths: tuple[str, ...],
) -> tuple[int, list[Path]]:
    copied_files = 0
    destinations: list[Path] = []
    for relative_path in relative_paths:
        source = template_root / relative_path
        destination = target_root / relative_path
        if not source.exists():
            continue
        if source.is_dir():
            for source_file in _iter_template_files(source):
                nested_relative = source_file.relative_to(source)
                destination_file = destination / nested_relative
                _reject_symlink_destination(
                    target_root, destination_file.relative_to(target_root)
                )
                destination_file.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(source_file, destination_file)
                destinations.append(destination_file)
                copied_files += 1
            continue
        _reject_symlink_destination(target_root, Path(relative_path))
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, destination)
        destinations.append(destination)
        copied_files += 1
    return copied_files, destinations


def _prune_empty_parents(target_root: Path, start: Path) -> None:
    current = start.parent
    while current != target_root and current.is_relative_to(target_root):
        try:
            current.rmdir()
        except OSError:
            return
        current = current.parent


def _confirm_force_rescaffold(target_root: Path, assume_yes: bool) -> None:
    if assume_yes:
        return
    print(
        "WARNING: --force-rescaffold deletes existing BCF governance artifacts under "
        f"{target_root} before reinstalling them.",
        file=sys.stderr,
    )
    print(
        "It removes pack-owned roots such as plans/, phases/, governance/, audits/, "
        "schemas/, and BCF validator/scaffold files.",
        file=sys.stderr,
    )
    response = input("Continue with destructive rescaffold? [y/N]: ").strip().lower()
    if response not in {"y", "yes"}:
        raise RuntimeError("force rescaffold aborted by user")


def _force_rescaffold_cleanup(target_root: Path) -> list[str]:
    removed: list[str] = []
    for relative_path in RESCAFFOLD_REMOVE_PATHS:
        path = target_root / relative_path
        if not path.exists():
            continue
        if path.is_dir():
            shutil.rmtree(path)
        else:
            path.unlink()
            _prune_empty_parents(target_root, path)
        removed.append(relative_path)
    return removed


def _remove_template_examples(target_root: Path) -> list[str]:
    removed: list[str] = []
    for relative_path in TEMPLATE_EXAMPLE_ARTIFACTS:
        path = target_root / relative_path
        if path.exists():
            path.unlink()
            removed.append(relative_path)
    return removed


def _remove_fresh_adoption_artifacts(target_root: Path, adoption_mode: str) -> None:
    if adoption_mode != "fresh":
        return
    for relative_path in EXISTING_ADOPTION_ARTIFACTS:
        path = target_root / relative_path
        if path.exists():
            path.unlink()


def _placeholder_values(args: argparse.Namespace, target_root: Path) -> dict[str, str]:
    phase_number = f"{_phase_number(args.phase_id):02d}"
    deliverable = args.deliverable[0]
    workstream = args.workstream[0]
    return {
        "ACTIVE_PHASE_ID": args.phase_id,
        "ADOPTION_MODE": args.adoption_mode,
        "BACKEND_ARCHITECTURE": args.backend_architecture,
        "BUILD_BLOCK": args.build_block,
        "CURRENT_TRANCHE": args.build_block,
        "DATA_ARCHITECTURE": args.data_architecture,
        "DATE": args.date,
        "DELIVERABLE": deliverable,
        "DEPENDENCY_PHASE_ID": args.phase_id,
        "EXTERNAL_DEPENDENCY": "github_actions",
        "FRONTEND_ARCHITECTURE": args.frontend_architecture,
        "HOTFIX_ID": "HF-TEMPLATE",
        "HOTFIX_MODE": "full",
        "HOTFIX_NUMBER": "1",
        "HOTFIX_SUMMARY": "template_hotfix",
        "NON_GOAL": "undefined_scope",
        "OPERATING_CONSTRAINT": args.operating_constraint,
        "PHASE_NUMBER": phase_number,
        "PHASE_OBJECTIVE": args.phase_objective,
        "PLACEHOLDER": "TOKEN",
        "PLANNER": args.planner,
        "PRODUCT_NAME": args.product_name,
        "PRODUCT_POSITIONING": args.product_positioning,
        "PROJECT_ID": args.project_id,
        "PROJECT_NAME": args.project_name,
        "RELATED_PHASE_ID": args.phase_id,
        "REPO_ROOT": ".",
        "RUNNER_LABELS": args.runner_labels,
        "TARGET_USER": args.target_user,
        "VALIDATION_COMMAND": "make governance-validate",
        "WORKSTREAM": workstream,
    }


def _configure_architecture_boundaries(target_root: Path, profile: str) -> None:
    if profile != "lite":
        return
    path = target_root / "architecture-boundaries.yml"
    text = path.read_text(encoding="utf-8")
    human_review_rules = "\n".join(
        [
            "    human_review_only_rules:",
            *[
                "\n".join(
                    [
                        f"      - rule_id: {target}",
                        "        rationale: lite profile defers this structural gate until standard promotion",
                        "        reviewer_role: technical_lead",
                        "        phase_log_evidence: phases/phase-01-log.yml",
                    ]
                )
                for target in LITE_DEFERRED_GATES
                if target.startswith("architecture-") and target != "architecture-test"
            ],
        ]
    )
    text = text.replace("    human_review_only_rules: []", human_review_rules, 1)
    path.write_text(text, encoding="utf-8")


def _customized_default(args: argparse.Namespace, name: str) -> bool:
    return getattr(args, name) != _parser().get_default(name)


def _apply_adoption_mode_defaults(args: argparse.Namespace) -> None:
    if args.adoption_mode != "existing":
        return
    if not _customized_default(args, "phase_objective"):
        args.phase_objective = "convert existing repository into governed delivery"
    if args.deliverable == _parser().get_default("deliverable"):
        args.deliverable = [
            "inventory existing architecture, tests, CI, and release gates",
            "install governed artifacts without rewriting application code",
            "wire or classify mandatory structural gates",
        ]
    if args.workstream == _parser().get_default("workstream"):
        args.workstream = [
            "existing_repo_inventory",
            "governance_artifact_install",
            "gate_gap_analysis",
        ]
    if not _customized_default(args, "build_block"):
        args.build_block = "existing_repo_adoption"


def _run_validation(
    target_root: Path,
    *,
    allow_placeholders: bool,
    allow_release_gate_placeholders: bool,
) -> subprocess.CompletedProcess[str]:
    command = [
        sys.executable,
        str(target_root / "scripts" / "validate_governance_yaml.py"),
        "--repo-root",
        str(target_root),
        "--format",
        "json",
        "--compact",
    ]
    if allow_placeholders:
        command.append("--allow-placeholders")
    if allow_release_gate_placeholders:
        command.append("--allow-release-gate-placeholders")
    return subprocess.run(command, capture_output=True, text=True)


def _upgrade_pack(args: argparse.Namespace, target_root: Path) -> InstallResult:
    if not target_root.exists() or not target_root.is_dir():
        raise NotADirectoryError(f"{target_root} is not an existing directory; use install without --upgrade")
    if args.force_rescaffold:
        raise RuntimeError("--upgrade cannot be combined with --force-rescaffold")

    template_root = _template_root()
    upgrade_paths = UPGRADE_REFRESH_PATHS + (
        UPGRADE_RESET_OPTION_PATHS if args.reset_options else ()
    )
    copied_files, destinations = _copy_selected_template_paths(
        template_root=template_root,
        target_root=target_root,
        relative_paths=tuple(dict.fromkeys(upgrade_paths)),
    )
    required_count, required_destinations = ensure_required_artifacts(
        template_root=template_root,
        target_root=target_root,
        relative_paths=PRESERVED_REQUIRED_ARTIFACTS,
        reject_destination=_reject_symlink_destination,
    )
    copied_files += required_count
    destinations.extend(required_destinations)
    values = _placeholder_values(args, target_root)
    replace_placeholders_in_files(destinations, values)
    copied_files += len(
        upgrade_state_files(
        template_root=template_root,
        target_root=target_root,
        values=values,
        reset_options=args.reset_options,
        )
    )
    if args.reset_options:
        apply_profile_contract(target_root, args.profile_contract, write_workflow=False)
    if args.reset_options:
        _configure_architecture_boundaries(target_root, args.profile)

    strict_validation_passed = False
    bootstrap_validation_passed = False
    strict_output = ""
    bootstrap_output = ""
    if not args.skip_validation:
        strict_result = _run_validation(
            target_root,
            allow_placeholders=False,
            allow_release_gate_placeholders=False,
        )
        strict_validation_passed = strict_result.returncode == 0
        strict_output = (strict_result.stdout or strict_result.stderr).strip()
        if not strict_validation_passed:
            bootstrap_result = _run_validation(
                target_root,
                allow_placeholders=True,
                allow_release_gate_placeholders=True,
            )
            bootstrap_validation_passed = bootstrap_result.returncode == 0
            bootstrap_output = (bootstrap_result.stdout or bootstrap_result.stderr).strip()
            if not bootstrap_validation_passed:
                raise RuntimeError(
                    "bootstrap governance validation failed after upgrade:\n"
                    f"{bootstrap_output}"
                )
            if args.require_strict_validation:
                raise RuntimeError(
                    "strict governance validation failed after upgrade:\n"
                    f"{strict_output}\n"
                    "bootstrap validation output:\n"
                    f"{bootstrap_output}"
                )
        else:
            bootstrap_validation_passed = True
            bootstrap_output = strict_output

    return InstallResult(
        copied_files=copied_files,
        rescaffold_removed_paths=[],
        removed_template_examples=[],
        generated_artifacts={},
        strict_validation_passed=strict_validation_passed,
        bootstrap_validation_passed=bootstrap_validation_passed,
        strict_validation_output=strict_output,
        bootstrap_validation_output=bootstrap_output,
    )


def _install_direct(args: argparse.Namespace, target_root: Path) -> InstallResult:
    template_root = _template_root()
    rescaffold_removed_paths: list[str] = []
    if args.force_rescaffold:
        rescaffold_removed_paths = _force_rescaffold_cleanup(target_root)

    copied_files, installed_destinations = _copy_template(
        template_root=template_root,
        target_root=target_root,
        allow_replace=args.force_rescaffold,
        profile=args.profile,
    )
    removed_examples = _remove_template_examples(target_root)
    _remove_fresh_adoption_artifacts(target_root, args.adoption_mode)
    values = _placeholder_values(args, target_root)
    replace_placeholders_in_files(installed_destinations, values)
    _configure_architecture_boundaries(target_root, args.profile)
    contract = args.profile_contract
    contract_version = str(contract.get("profile_contract_version", "1.0"))
    graph_enabled = args.profile == "lite" or contract_version == "2.0"
    apply_profile_contract(target_root, contract, write_workflow=not graph_enabled)
    if graph_enabled:
        write_reference_ci_graph(args, target_root, contract)
    generated_artifacts = generate_phase_artifacts(args, target_root)
    apply_scaffold_requirements(target_root, contract, generated_artifacts)

    strict_validation_passed = False
    bootstrap_validation_passed = False
    strict_output = ""
    bootstrap_output = ""
    if not args.skip_validation:
        strict_result = _run_validation(
            target_root,
            allow_placeholders=False,
            allow_release_gate_placeholders=False,
        )
        strict_validation_passed = strict_result.returncode == 0
        strict_output = (strict_result.stdout or strict_result.stderr).strip()
        if not strict_validation_passed:
            bootstrap_result = _run_validation(
                target_root,
                allow_placeholders=True,
                allow_release_gate_placeholders=True,
            )
            bootstrap_validation_passed = bootstrap_result.returncode == 0
            bootstrap_output = (bootstrap_result.stdout or bootstrap_result.stderr).strip()
            if not bootstrap_validation_passed:
                raise RuntimeError(
                    "bootstrap governance validation failed:\n"
                    f"{bootstrap_output}"
                )
            if args.require_strict_validation:
                raise RuntimeError(
                    "strict governance validation failed:\n"
                    f"{strict_output}\n"
                    "bootstrap validation output:\n"
                    f"{bootstrap_output}"
                )
        else:
            bootstrap_validation_passed = True
            bootstrap_output = strict_output

    return InstallResult(
        copied_files=copied_files,
        rescaffold_removed_paths=rescaffold_removed_paths,
        removed_template_examples=removed_examples,
        generated_artifacts=generated_artifacts,
        strict_validation_passed=strict_validation_passed,
        bootstrap_validation_passed=bootstrap_validation_passed,
        strict_validation_output=strict_output,
        bootstrap_validation_output=bootstrap_output,
    )


def install(args: argparse.Namespace) -> InstallResult:
    target_root = args.target.resolve()
    if not target_root.exists() or not target_root.is_dir():
        raise NotADirectoryError(f"{target_root} is not a directory")
    git_root = subprocess.run(
        ["git", "-C", str(target_root), "rev-parse", "--show-toplevel"],
        capture_output=True,
        text=True,
        check=False,
    )
    if git_root.returncode != 0 or Path(git_root.stdout.strip()).resolve() != target_root:
        raise RuntimeError("installation target must be the root of an initialized Git repository")
    args.profile, contract_version = resolve_install_contract_version(
        target_root, args.profile, args.profile_contract_version, args.upgrade, args.reset_options)
    # Ordinary upgrades refresh pack-owned code only. Project-owned profiles,
    # gate contracts, graphs, extensions, workflows, and state change only
    # through their explicit migration, promotion, or reset commands.
    args.profile_contract = None
    if not args.upgrade or args.reset_options:
        contract_root = _template_root()
        args.profile_contract = load_contract(
            contract_root,
            args.profile,
            args.profile_config,
            asset_root=target_root,
            contract_version=contract_version,
        )
    if args.force_rescaffold:
        _confirm_force_rescaffold(target_root, args.yes)
    result_box: list[InstallResult] = []

    def mutate(shadow: Path) -> None:
        result_box.append(
            _upgrade_pack(args, shadow) if args.upgrade else _install_direct(args, shadow)
        )

    apply_transaction(
        target_root,
        managed_paths=INSTALL_MANAGED_PATHS,
        mutate_shadow=mutate,
    )
    result = result_box[0]
    generated = {
        key: target_root / path.relative_to(path.parents[1])
        if path.is_absolute() and len(path.parents) > 1
        else path
        for key, path in result.generated_artifacts.items()
    }
    return InstallResult(
        copied_files=result.copied_files,
        rescaffold_removed_paths=result.rescaffold_removed_paths,
        removed_template_examples=result.removed_template_examples,
        generated_artifacts=generated,
        strict_validation_passed=result.strict_validation_passed,
        bootstrap_validation_passed=result.bootstrap_validation_passed,
        strict_validation_output=result.strict_validation_output,
        bootstrap_validation_output=result.bootstrap_validation_output,
    )


def _parser() -> argparse.ArgumentParser:
    return build_parser(
        profile_choices=PROFILE_CHOICES,
        adoption_mode_choices=ADOPTION_MODE_CHOICES,
        default_target_user=DEFAULT_TARGET_USER,
        default_runner_labels=DEFAULT_RUNNER_LABELS,
        default_date=datetime.now(UTC).date().isoformat(),
    )


def _finalize_args(args: argparse.Namespace) -> argparse.Namespace:
    if args.project_id is None:
        args.project_id = _project_id_from_name(args.target.resolve().name)
    if args.project_name is None:
        args.project_name = _title_from_id(args.project_id)
    if args.product_name is None:
        args.product_name = args.project_name
    _apply_adoption_mode_defaults(args)
    return args


def main(argv: list[str] | None = None) -> None:
    args = _finalize_args(_parser().parse_args(argv))
    try:
        result = install(args)
    except Exception as exc:
        print(f"install-governance-pack failed: {exc}", file=sys.stderr)
        raise SystemExit(1) from exc
    print_summary(
        args,
        result,
        required_standard_gates=REQUIRED_STANDARD_GATES,
    )


if __name__ == "__main__":
    main()

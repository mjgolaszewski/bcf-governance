"""Install the governance template pack into a target repository."""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
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
from .governance_install.reporting import print_summary  # noqa: E402
from .governance_install.transaction import apply_transaction  # noqa: E402
from .governance_install.upgrade import replace_placeholders_in_files, upgrade_state_files  # noqa: E402
from .governance_profiles import (  # noqa: E402
    apply_profile_contract,
    apply_scaffold_requirements,
    load_contract,
)
from . import migrate_governance_evidence  # noqa: E402


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
    "scripts/check_governance_exposure.py",
    "scripts/governance_evidence.py",
    "scripts/governance_truth.py",
    "scripts/governance_truth_support.py",
    "scripts/_bcf_runtime",
    "scripts/migrate_governance_evidence.py",
    "scripts/profile_governance.py",
    "scripts/governance_validation",
    "scripts/scaffold_governance_artifacts.py",
    "scripts/validate_governance_yaml.py",
)
INSTALL_MANAGED_PATHS = tuple(
    dict.fromkeys((*RESCAFFOLD_REMOVE_PATHS, "docs/OPERATIONS.md", ".gitignore"))
)
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
REQUIRED_STANDARD_GATES = (
    "governance-validate", "governance-exposure-scan", *LITE_DEFERRED_GATES
)
UPGRADE_REFRESH_PATHS = (
    "schemas",
    "backend/tests/architecture/test_boundaries_ast.py",
    "governance/REPO_CLEANUP.md",
    "scripts/check_governance_exposure.py",
    "scripts/governance_evidence.py",
    "scripts/governance_truth.py",
    "scripts/governance_truth_support.py",
    "scripts/_bcf_runtime",
    "scripts/migrate_governance_evidence.py",
    "scripts/profile_governance.py",
    "scripts/governance_validation",
    "scripts/scaffold_governance_artifacts.py",
    "scripts/validate_governance_yaml.py",
)
UPGRADE_RESET_OPTION_PATHS = (
    ".github/workflows/governance.yml",
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


def _load_scaffold_module() -> Any:
    from . import scaffold_governance_artifacts

    return scaffold_governance_artifacts


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


def _merge_gitignore(existing: bytes | None, template: bytes) -> bytes:
    begin = b"# BEGIN BCF GOVERNANCE"
    end = b"# END BCF GOVERNANCE"
    template_lines = [
        line
        for line in template.decode("utf-8").splitlines()
        if line.strip()
        and line.strip() not in {begin.decode("ascii"), end.decode("ascii")}
    ]
    block = b"\n".join(
        [begin, *[line.encode("utf-8") for line in template_lines], end]
    ) + b"\n"
    original = existing or b""
    if begin in original or end in original:
        if not (
            begin in original
            and end in original
            and original.index(begin) < original.index(end)
        ):
            raise ValueError("existing .gitignore contains an incomplete BCF managed block")
        start = original.index(begin)
        suffix_start = original.index(end, start) + len(end)
        if original[suffix_start : suffix_start + 2] == b"\r\n":
            suffix_start += 2
        elif original[suffix_start : suffix_start + 1] == b"\n":
            suffix_start += 1
        return original[:start] + block + original[suffix_start:]
    separator = b"" if not original or original.endswith(b"\n\n") else (
        b"\n" if original.endswith((b"\n", b"\r\n")) else b"\n\n"
    )
    return original + separator + block


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
        if raw_entry.get("operation") not in {"copy", "merge", "generate"}:
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
        if destination.exists() and relative_path.as_posix() != ".gitignore" and not allow_replace:
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
        if entries[relative_path.as_posix()]["operation"] == "merge":
            existing = destination.read_bytes() if destination.exists() else None
            destination.write_bytes(_merge_gitignore(existing, source.read_bytes()))
        else:
            shutil.copy2(source, destination)
        destinations.append(destination)
    return len(relative_paths), destinations


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


def _validation_commands(profile: str) -> list[str]:
    if profile == "lite":
        return ["make governance-validate"]
    return ["make governance-validate", "make architecture-test", "make release-check"]


def _generate_phase_artifacts(args: argparse.Namespace, target_root: Path) -> dict[str, Path]:
    scaffold = _load_scaffold_module()
    return scaffold.scaffold_phase_artifacts(
        repo_root=target_root,
        project_id=args.project_id,
        phase_id=args.phase_id,
        build_block=args.build_block,
        objective=args.phase_objective,
        planner=args.planner,
        date=args.date,
        hard_dependencies=args.hard_dependency,
        deliverables=args.deliverable,
        workstreams=args.workstream,
        verification_commands=_validation_commands(args.profile),
        force=True,
    )


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


def _upgrade_paths(args: argparse.Namespace) -> tuple[str, ...]:
    paths = list(UPGRADE_REFRESH_PATHS)
    if args.reset_options:
        paths.extend(UPGRADE_RESET_OPTION_PATHS)
    return tuple(dict.fromkeys(paths))


def _upgrade_pack(args: argparse.Namespace, target_root: Path) -> InstallResult:
    if not target_root.exists() or not target_root.is_dir():
        raise NotADirectoryError(f"{target_root} is not an existing directory; use install without --upgrade")
    if args.force_rescaffold:
        raise RuntimeError("--upgrade cannot be combined with --force-rescaffold")

    template_root = _template_root()
    copied_files, destinations = _copy_selected_template_paths(
        template_root=template_root,
        target_root=target_root,
        relative_paths=_upgrade_paths(args),
    )
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
    migrate_governance_evidence.migration_plan(target_root, apply=True)
    apply_profile_contract(target_root, args.profile_contract)
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
    apply_profile_contract(target_root, contract)
    generated_artifacts = _generate_phase_artifacts(args, target_root)
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
    # Profile configuration is validated against the immutable pack catalog so
    # damaged or partial 0.5 profile state cannot weaken an upgrade.
    contract_root = _template_root()
    args.profile_contract = load_contract(
        contract_root,
        args.profile,
        args.profile_config,
        asset_root=target_root,
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

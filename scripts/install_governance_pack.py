"""Install the governance template pack into a target repository."""

from __future__ import annotations

import argparse
import importlib.util
import importlib.resources
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

from governance_install.args import build_parser  # noqa: E402
from governance_install.reporting import print_summary  # noqa: E402
from governance_install.upgrade import replace_placeholders_in_files, upgrade_state_files  # noqa: E402


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
    "scripts/governance_validation",
    "scripts/scaffold_governance_artifacts.py",
    "scripts/validate_governance_yaml.py",
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
    "runtime-smoke",
)
REQUIRED_STANDARD_GATES = (
    "governance-validate",
    "governance-exposure-scan",
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
    "runtime-smoke",
)
UPGRADE_REFRESH_PATHS = (
    "schemas",
    "backend/tests/architecture/test_boundaries_ast.py",
    "governance/REPO_CLEANUP.md",
    "scripts/check_governance_exposure.py",
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
MAKE_TARGET_PATTERN = re.compile(r"^([A-Za-z0-9_.-]+)\s*:(?:\s|$)")


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
    try:
        from scripts import scaffold_governance_artifacts

        return scaffold_governance_artifacts
    except ImportError:
        pass

    scaffold_path = _pack_root() / "scripts" / "scaffold_governance_artifacts.py"
    spec = importlib.util.spec_from_file_location("scaffold_governance_artifacts", scaffold_path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"unable to load scaffold helper from {scaffold_path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _phase_number(phase_id: str) -> int:
    if not phase_id.startswith("P") or not phase_id[1:].isdigit():
        raise ValueError(f"invalid phase id {phase_id!r}; expected values like 'P01'")
    return int(phase_id[1:])


def _project_id_from_name(name: str) -> str:
    normalized = re.sub(r"[^a-z0-9]+", "-", name.lower()).strip("-")
    return normalized or "project"


def _title_from_id(project_id: str) -> str:
    return " ".join(part.capitalize() for part in project_id.replace("_", "-").split("-") if part) or "Project"


def _parse_gate_command(value: str) -> tuple[str, str]:
    if "=" not in value:
        raise argparse.ArgumentTypeError("--gate-command must use TARGET=COMMAND")
    target, command = value.split("=", 1)
    target = target.strip()
    command = command.strip()
    if not target or not command:
        raise argparse.ArgumentTypeError("--gate-command must use non-empty TARGET=COMMAND")
    return target, command


def _is_template_artifact(path: Path) -> bool:
    return "__pycache__" not in path.parts and path.suffix != ".pyc"


def _iter_template_files(template_root: Path) -> list[Path]:
    return sorted(
        path for path in template_root.rglob("*") if path.is_file() and _is_template_artifact(path)
    )


def _copy_template(
    *,
    template_root: Path,
    target_root: Path,
    force: bool,
) -> int:
    conflicts: list[str] = []
    template_files = _iter_template_files(template_root)
    for source in template_files:
        relative_path = source.relative_to(template_root)
        destination = target_root / relative_path
        if destination.exists() and not force:
            conflicts.append(relative_path.as_posix())

    if conflicts:
        preview = "\n".join(f"- {path}" for path in conflicts[:25])
        suffix = f"\n... and {len(conflicts) - 25} more" if len(conflicts) > 25 else ""
        raise FileExistsError(
            "target already contains governance pack paths; rerun with --force to overwrite:\n"
            f"{preview}{suffix}"
        )

    for source in template_files:
        relative_path = source.relative_to(template_root)
        destination = target_root / relative_path
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, destination)
    return len(template_files)


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
                destination_file.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(source_file, destination_file)
                destinations.append(destination_file)
                copied_files += 1
            continue
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


def _replace_placeholders(target_root: Path, values: dict[str, str]) -> None:
    for path in sorted(target_root.rglob("*")):
        if not path.is_file() or ".git" in path.parts:
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            continue
        updated = text
        for key, value in values.items():
            updated = updated.replace(f"{{{{{key}}}}}", value)
        if updated != text:
            path.write_text(updated, encoding="utf-8")


def _replace_first_after_marker(text: str, marker: str, old: str, new: str) -> str:
    marker_index = text.index(marker)
    old_index = text.index(old, marker_index)
    return text[:old_index] + new + text[old_index + len(old) :]


def _replace_block_between_markers(text: str, start_marker: str, end_marker: str, new_block: str) -> str:
    start_index = text.index(start_marker)
    end_index = text.index(end_marker, start_index)
    return text[:start_index] + new_block + text[end_index:]


def _configure_governance_profile(target_root: Path, profile: str) -> None:
    path = target_root / "governance-profile.yml"
    text = path.read_text(encoding="utf-8")
    rationale_by_profile = {
        "lite": "minimum viable governance for lightweight agent-led delivery",
        "standard": "balanced governance for agent-led delivery without regulated evidence overhead",
        "regulated": "release evidence, provenance, security, and hotfix reconciliation are mandatory",
    }
    text = re.sub(r"selected: \w+", f"selected: {profile}", text, count=1)
    text = re.sub(
        r"rationale: .+",
        f"rationale: {rationale_by_profile[profile]}",
        text,
        count=1,
    )

    if profile == "lite":
        deferred_gate_ids = (
            "architecture_test",
            "architecture_module_size",
            "architecture_layer_membership",
            "architecture_context_membership",
            "architecture_import_boundaries",
            "architecture_cqrs_side",
            "architecture_router_thinness",
            "architecture_duplication",
            "lint",
            "typecheck",
            "test",
            "contract_test",
            "security_secret_scan",
            "security_dependency_audit",
            "security_sbom",
            "security_vulnerability_scan",
            "runtime_smoke",
        )
        for gate_id in deferred_gate_ids:
            text = _replace_first_after_marker(text, f"    {gate_id}:", "status: required", "status: deferred")
        text = _replace_block_between_markers(
            text,
            "  required_push_jobs:\n",
            "  runner_rules:\n",
            "  required_push_jobs:\n    - governance-validate\n    - governance-exposure-scan\n",
        )
    path.write_text(text, encoding="utf-8")


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


def _find_target_span(lines: list[str], target: str) -> tuple[int, int] | None:
    start: int | None = None
    for index, line in enumerate(lines):
        match = MAKE_TARGET_PATTERN.match(line)
        if match is None:
            continue
        if match.group(1) == target:
            start = index
            continue
        if start is not None:
            return start, index
    if start is None:
        return None
    return start, len(lines)


def _rewrite_make_target(text: str, target: str, commands: list[str]) -> str:
    lines = text.splitlines()
    span = _find_target_span(lines, target)
    if span is None:
        raise ValueError(f"Makefile.fragment does not define target {target!r}")
    start, end = span
    replacement = [lines[start], *[f"\t@{command}" for command in commands]]
    return "\n".join([*lines[:start], *replacement, *lines[end:]]) + "\n"


def _configure_makefile(
    *,
    target_root: Path,
    profile: str,
    gate_commands: dict[str, str],
) -> None:
    path = target_root / "Makefile.fragment"
    text = path.read_text(encoding="utf-8")

    if profile == "lite":
        text = _rewrite_make_target(
            text,
            "release-check",
            ["$(MAKE) governance-validate", "$(MAKE) governance-exposure-scan"],
        )
        for target in LITE_DEFERRED_GATES:
            text = _rewrite_make_target(text, target, ["true"])

    for target, command in gate_commands.items():
        text = _rewrite_make_target(text, target, [command])

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


def _all_required_gates_wired(profile: str, gate_commands: dict[str, str]) -> bool:
    if profile == "lite":
        return True
    built_in_targets = {"governance-validate", "governance-exposure-scan"}
    return all(target in gate_commands for target in REQUIRED_STANDARD_GATES if target not in built_in_targets)


def _upgrade_paths(args: argparse.Namespace) -> tuple[str, ...]:
    paths = list(UPGRADE_REFRESH_PATHS)
    if args.reset_options:
        paths.extend(UPGRADE_RESET_OPTION_PATHS)
    return tuple(dict.fromkeys(paths))


def _upgrade_pack(args: argparse.Namespace, target_root: Path) -> InstallResult:
    if not target_root.exists() or not target_root.is_dir():
        raise NotADirectoryError(f"{target_root} is not an existing directory; use install without --upgrade")
    if args.force or args.force_rescaffold:
        raise RuntimeError("--upgrade cannot be combined with --force or --force-rescaffold")
    if args.gate_command and not args.reset_options:
        raise RuntimeError("--gate-command with --upgrade requires --reset-options")

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
    if args.reset_options:
        _configure_governance_profile(target_root, args.profile)
        _configure_architecture_boundaries(target_root, args.profile)
        _configure_makefile(
            target_root=target_root,
            profile=args.profile,
            gate_commands=dict(args.gate_command),
        )

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


def install(args: argparse.Namespace) -> InstallResult:
    target_root = args.target.resolve()
    if args.upgrade:
        return _upgrade_pack(args, target_root)

    target_root.mkdir(parents=True, exist_ok=True)
    if not target_root.is_dir():
        raise NotADirectoryError(f"{target_root} is not a directory")

    template_root = _template_root()
    rescaffold_removed_paths: list[str] = []
    if args.force_rescaffold:
        _confirm_force_rescaffold(target_root, args.yes)
        rescaffold_removed_paths = _force_rescaffold_cleanup(target_root)

    copied_files = _copy_template(
        template_root=template_root,
        target_root=target_root,
        force=args.force or args.force_rescaffold,
    )
    removed_examples = _remove_template_examples(target_root)
    _remove_fresh_adoption_artifacts(target_root, args.adoption_mode)
    values = _placeholder_values(args, target_root)
    _replace_placeholders(target_root, values)
    _configure_governance_profile(target_root, args.profile)
    _configure_architecture_boundaries(target_root, args.profile)
    gate_commands = dict(args.gate_command)
    _configure_makefile(target_root=target_root, profile=args.profile, gate_commands=gate_commands)
    generated_artifacts = _generate_phase_artifacts(args, target_root)

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


def _parser() -> argparse.ArgumentParser:
    return build_parser(
        profile_choices=PROFILE_CHOICES,
        adoption_mode_choices=ADOPTION_MODE_CHOICES,
        default_target_user=DEFAULT_TARGET_USER,
        default_runner_labels=DEFAULT_RUNNER_LABELS,
        default_date=datetime.now(UTC).date().isoformat(),
        parse_gate_command=_parse_gate_command,
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
        all_required_gates_wired=_all_required_gates_wired,
    )


if __name__ == "__main__":
    main()

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


PROFILE_CHOICES = ("lite", "standard", "regulated")
DEFAULT_TARGET_USER = "operators"
DEFAULT_RUNNER_LABELS = "ubuntu-latest"
TEMPLATE_EXAMPLE_ARTIFACTS = (
    "plans/phase-NN-plan.yml",
    "plans/phase-NN-workitems.yml",
    "phases/phase-NN-log.yml",
    "phases/phase-NN-hotfixNN.yml",
)
LITE_DEFERRED_GATES = ("architecture-test", "lint", "typecheck", "test", "contract-test")
REQUIRED_STANDARD_GATES = (
    "governance-validate",
    "architecture-test",
    "lint",
    "typecheck",
    "test",
    "contract-test",
)
MAKE_TARGET_PATTERN = re.compile(r"^([A-Za-z0-9_.-]+)\s*:(?:\s|$)")


@dataclass(frozen=True)
class InstallResult:
    copied_files: int
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


def _remove_template_examples(target_root: Path) -> list[str]:
    removed: list[str] = []
    for relative_path in TEMPLATE_EXAMPLE_ARTIFACTS:
        path = target_root / relative_path
        if path.exists():
            path.unlink()
            removed.append(relative_path)
    return removed


def _placeholder_values(args: argparse.Namespace, target_root: Path) -> dict[str, str]:
    phase_number = f"{_phase_number(args.phase_id):02d}"
    deliverable = args.deliverable[0]
    workstream = args.workstream[0]
    return {
        "ACTIVE_PHASE_ID": args.phase_id,
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
        "REPO_ROOT": str(target_root),
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
        deferred_gate_ids = ("architecture_test", "lint", "typecheck", "test", "contract_test")
        for gate_id in deferred_gate_ids:
            text = _replace_first_after_marker(text, f"    {gate_id}:", "status: required", "status: deferred")
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
        text = _rewrite_make_target(text, "release-check", ["$(MAKE) governance-validate"])
        for target in LITE_DEFERRED_GATES:
            text = _rewrite_make_target(text, target, ["true"])

    for target, command in gate_commands.items():
        text = _rewrite_make_target(text, target, [command])

    path.write_text(text, encoding="utf-8")


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
    return all(target in gate_commands for target in REQUIRED_STANDARD_GATES if target != "governance-validate")


def install(args: argparse.Namespace) -> InstallResult:
    target_root = args.target.resolve()
    target_root.mkdir(parents=True, exist_ok=True)
    if not target_root.is_dir():
        raise NotADirectoryError(f"{target_root} is not a directory")

    template_root = _template_root()
    copied_files = _copy_template(
        template_root=template_root,
        target_root=target_root,
        force=args.force,
    )
    removed_examples = _remove_template_examples(target_root)
    values = _placeholder_values(args, target_root)
    _replace_placeholders(target_root, values)
    _configure_governance_profile(target_root, args.profile)
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
        removed_template_examples=removed_examples,
        generated_artifacts=generated_artifacts,
        strict_validation_passed=strict_validation_passed,
        bootstrap_validation_passed=bootstrap_validation_passed,
        strict_validation_output=strict_output,
        bootstrap_validation_output=bootstrap_output,
    )


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Install the governance pack into a target repository.")
    parser.add_argument("--target", type=Path, required=True, help="Target repository root.")
    parser.add_argument("--profile", choices=PROFILE_CHOICES, default="standard")
    parser.add_argument("--project-id", help="Machine-readable project id. Defaults from --target name.")
    parser.add_argument("--project-name", help="Human-readable project name. Defaults from --project-id.")
    parser.add_argument("--product-name", help="Product name. Defaults from --project-name.")
    parser.add_argument(
        "--product-positioning",
        default="governed agent-led software delivery",
        help="Short product positioning used in product-spec.yml.",
    )
    parser.add_argument("--target-user", default=DEFAULT_TARGET_USER)
    parser.add_argument("--runner-labels", default=DEFAULT_RUNNER_LABELS)
    parser.add_argument("--phase-id", default="P01")
    parser.add_argument("--build-block", default="foundation")
    parser.add_argument("--phase-objective", default="establish governed foundation")
    parser.add_argument("--planner", default="codex")
    parser.add_argument("--date", default=datetime.now(UTC).date().isoformat())
    parser.add_argument("--hard-dependency", action="append", default=[])
    parser.add_argument("--deliverable", action="append", default=["initial governed foundation"])
    parser.add_argument("--workstream", action="append", default=["bootstrap governance pack"])
    parser.add_argument("--backend-architecture", default="cqrs_lite_with_strict_ports")
    parser.add_argument("--frontend-architecture", default="route_modules_thin_components")
    parser.add_argument("--data-architecture", default="repo_defined")
    parser.add_argument("--operating-constraint", default="repo_native_runtime")
    parser.add_argument(
        "--gate-command",
        action="append",
        type=_parse_gate_command,
        default=[],
        metavar="TARGET=COMMAND",
        help="Replace a Makefile.fragment gate target body. Repeat for lint, typecheck, test, etc.",
    )
    parser.add_argument("--force", action="store_true", help="Overwrite existing governance pack files.")
    parser.add_argument("--skip-validation", action="store_true")
    parser.add_argument(
        "--require-strict-validation",
        action="store_true",
        help="Fail installation if strict validation does not pass after install.",
    )
    return parser


def _finalize_args(args: argparse.Namespace) -> argparse.Namespace:
    if args.project_id is None:
        args.project_id = _project_id_from_name(args.target.resolve().name)
    if args.project_name is None:
        args.project_name = _title_from_id(args.project_id)
    if args.product_name is None:
        args.product_name = args.project_name
    return args


def _print_summary(args: argparse.Namespace, result: InstallResult) -> None:
    target_root = args.target.resolve()
    print(f"installed governance pack into {target_root}")
    print(f"profile: {args.profile}")
    print(f"copied files: {result.copied_files}")
    if result.removed_template_examples:
        print("removed template examples: " + ", ".join(result.removed_template_examples))
    for artifact_type, path in result.generated_artifacts.items():
        print(f"{artifact_type}: {path.relative_to(target_root).as_posix()}")

    if args.skip_validation:
        print("validation: skipped")
    elif result.strict_validation_passed:
        print("validation: strict pass")
    elif result.bootstrap_validation_passed:
        print("validation: bootstrap pass; strict validation is blocked by unwired release gates")
        if not _all_required_gates_wired(args.profile, dict(args.gate_command)):
            missing = [
                target
                for target in REQUIRED_STANDARD_GATES
                if target != "governance-validate" and target not in dict(args.gate_command)
            ]
            print("wire release gates: " + ", ".join(missing))
    else:
        print("validation: failed")
        if result.strict_validation_output:
            print(result.strict_validation_output)
        if result.bootstrap_validation_output:
            print(result.bootstrap_validation_output)

    print("next: merge Makefile.fragment into the repo Makefile or include it from the repo Makefile")


def main(argv: list[str] | None = None) -> None:
    args = _finalize_args(_parser().parse_args(argv))
    try:
        result = install(args)
    except Exception as exc:
        print(f"install-governance-pack failed: {exc}", file=sys.stderr)
        raise SystemExit(1) from exc
    _print_summary(args, result)


if __name__ == "__main__":
    main()

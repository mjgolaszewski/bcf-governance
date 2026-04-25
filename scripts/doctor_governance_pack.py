"""Diagnose remaining governance-pack adoption work in a target repository."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

try:
    from scripts import validate_governance_yaml as validator
except ImportError:  # pragma: no cover - used when executed directly from scripts/
    import validate_governance_yaml as validator  # type: ignore[no-redef]


DOCTOR_OUTPUT_FORMATS = {"text", "json"}
PLACEHOLDER_SCAN_EXCLUDE_PARTS = {".git", "__pycache__"}
PLACEHOLDER_SCAN_EXTENSIONS = {".yml", ".yaml", ".json", ".md", ".toml", ".txt"}


def _scan_placeholders(repo_root: Path) -> list[str]:
    violations: list[str] = []
    for path in sorted(repo_root.rglob("*")):
        if not path.is_file() or any(part in PLACEHOLDER_SCAN_EXCLUDE_PARTS for part in path.parts):
            continue
        if path.suffix not in PLACEHOLDER_SCAN_EXTENSIONS and path.name not in {"Makefile", "Makefile.fragment"}:
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            continue
        for line_number, line in enumerate(text.splitlines(), start=1):
            for match in validator.PLACEHOLDER_PATTERN.finditer(line):
                violations.append(
                    f"{path.relative_to(repo_root).as_posix()}:{line_number}: {match.group(0)}"
                )
    return violations


def _load_profile(repo_root: Path) -> dict[str, Any] | None:
    profile_path = repo_root / "governance-profile.yml"
    if not profile_path.exists():
        return None
    return validator._load_yaml(profile_path)


def _release_gate_diagnostics(repo_root: Path) -> tuple[list[str], list[str], list[str]]:
    blockers: list[str] = []
    warnings: list[str] = []
    next_actions: list[str] = []

    profile = _load_profile(repo_root)
    gates = validator._release_gates_from_profile(profile)
    makefile_path = validator._release_gate_makefile_path(repo_root)
    if makefile_path is None:
        blockers.append("Makefile or Makefile.fragment is missing release-check")
        next_actions.append("add or merge Makefile.fragment so release-check is defined")
        return blockers, warnings, next_actions

    makefile_display = makefile_path.relative_to(repo_root).as_posix()
    text = makefile_path.read_text(encoding="utf-8")
    lowered = text.lower()
    for marker in validator.RELEASE_GATE_PLACEHOLDER_MARKERS:
        if marker in lowered:
            blockers.append(f"{makefile_display} still contains release-gate placeholder marker {marker!r}")

    target_bodies = validator._makefile_target_bodies(makefile_path)
    release_check_body = target_bodies.get("release-check")
    if release_check_body is None:
        blockers.append(f"{makefile_display} is missing release-check")
        next_actions.append("define release-check and invoke required release gate targets")
        return blockers, warnings, next_actions

    invoked_targets = {
        match.group(1)
        for line in release_check_body
        for match in validator.MAKE_INVOKED_TARGET_PATTERN.finditer(line)
    }
    unknown_invocations = sorted(invoked_targets - set(gates))
    for target in unknown_invocations:
        blockers.append(f"release-check invokes undeclared target {target}")
        next_actions.append(f"declare {target} in governance-profile.yml or remove it from release-check")

    for target, gate in sorted(gates.items()):
        status = gate["status"]
        if status == "required" and target not in invoked_targets:
            blockers.append(f"required release gate {target} is not invoked by release-check")
            next_actions.append(f"add $(MAKE) {target} to release-check")
            continue
        if status == "optional" and target not in invoked_targets:
            warnings.append(f"optional release gate {target} is omitted")
            continue
        if status in validator.RELEASE_GATE_INACTIVE_STATUSES:
            if target in invoked_targets:
                blockers.append(f"inactive release gate {target} is still invoked by release-check")
                next_actions.append(f"remove $(MAKE) {target} from release-check")
            continue
        if target not in invoked_targets:
            continue

        target_body = target_bodies.get(target)
        if target_body is None:
            blockers.append(f"release gate target {target} is not defined")
            next_actions.append(f"define {target} in {makefile_display}")
            continue
        commands = validator._meaningful_make_commands(target_body)
        if not commands:
            blockers.append(f"release gate target {target} has no meaningful command")
            next_actions.append(f"replace {target} with a real {gate['command_policy']} command")
            continue
        try:
            validator._validate_release_gate_command_semantics(
                makefile_display=makefile_display,
                target=target,
                commands=commands,
                command_policy=gate["command_policy"],
            )
        except validator.GovernanceValidationError as exc:
            blockers.append(str(exc))
            next_actions.append(f"replace {target} with a real {gate['command_policy']} command")

    return blockers, warnings, next_actions


def doctor_repo(repo_root: Path) -> dict[str, Any]:
    repo_root = repo_root.resolve()
    blockers: list[str] = []
    warnings: list[str] = []
    next_actions: list[str] = []

    placeholders = _scan_placeholders(repo_root)
    if placeholders:
        blockers.append(f"{len(placeholders)} unresolved template placeholder(s) remain")
        next_actions.extend(f"replace {entry}" for entry in placeholders[:10])

    gate_blockers, gate_warnings, gate_actions = _release_gate_diagnostics(repo_root)
    blockers.extend(gate_blockers)
    warnings.extend(gate_warnings)
    next_actions.extend(gate_actions)

    try:
        validator.validate_repo_root(repo_root)
    except validator.GovernanceValidationError as exc:
        if str(exc) not in blockers:
            blockers.append(str(exc))

    status = "fail" if blockers else "warn" if warnings else "pass"
    return {
        "status": status,
        "blockers": blockers,
        "warnings": warnings,
        "next_actions": list(dict.fromkeys(next_actions)),
    }


def _emit_text(report: dict[str, Any]) -> None:
    print(f"doctor-{report['status']}")
    if report["blockers"]:
        print("blockers:")
        for blocker in report["blockers"]:
            print(f"- {blocker}")
    if report["warnings"]:
        print("warnings:")
        for warning in report["warnings"]:
            print(f"- {warning}")
    if report["next_actions"]:
        print("next actions:")
        for action in report["next_actions"]:
            print(f"- {action}")


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description="Diagnose governance pack adoption gaps.")
    parser.add_argument("--repo-root", type=Path, default=Path.cwd())
    parser.add_argument("--format", choices=sorted(DOCTOR_OUTPUT_FORMATS), default="text")
    parser.add_argument("--compact", action="store_true", help="Use compact JSON with --format json.")
    args = parser.parse_args(argv)

    report = doctor_repo(args.repo_root)
    if args.format == "json":
        separators = (",", ":") if args.compact else None
        indent = None if args.compact else 2
        print(json.dumps(report, indent=indent, separators=separators, sort_keys=True))
    else:
        _emit_text(report)
    if report["status"] == "fail":
        raise SystemExit(1)


if __name__ == "__main__":
    main()

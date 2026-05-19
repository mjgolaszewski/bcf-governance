"""Plan and apply conservative governance tree cleanup for BCF repos."""

from __future__ import annotations

import argparse
import json
import os
import shutil
import sys
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any


OUTPUT_FORMATS = {"text", "json"}
SKIP_DIRS = {
    ".git",
    ".hg",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
    ".tox",
    ".venv",
    "__pycache__",
    "artifacts",
    ".artifacts",
    "build",
    "dist",
    "node_modules",
    "venv",
}
AUDIT_MOVE_ROOTS = {
    "docs/audits": "audits",
    "governance/parity-reviews": "audits/parity-reviews",
    "governance/test-audits": "audits/test-audits",
    "governance/code-reviews": "audits/code-reviews",
}
GOVERNANCE_MARKER_FILES = {
    "AGENTS.yml",
    "CLAUDE.md",
    "MEMORY.yml",
    "architecture-boundaries.yml",
    "governance-profile.yml",
}
GOVERNANCE_MARKER_DIRS = {"plans", "phases"}
TEXT_SUFFIXES = {
    ".cfg",
    ".ini",
    ".json",
    ".md",
    ".py",
    ".rst",
    ".sh",
    ".toml",
    ".txt",
    ".yaml",
    ".yml",
}


@dataclass(frozen=True)
class CleanupAction:
    kind: str
    source: str
    destination: str | None
    reason: str
    safe_to_apply: bool


@dataclass(frozen=True)
class ManualAction:
    kind: str
    path: str
    reason: str
    llm_support: str


@dataclass(frozen=True)
class CleanupReport:
    status: str
    repo_root: str
    cleanup_contract: str | None
    applied: bool
    actions: list[CleanupAction]
    manual_actions: list[ManualAction]
    rewritten_files: list[str]
    warnings: list[str]


def _repo_relative(repo_root: Path, path: Path) -> str:
    return path.relative_to(repo_root).as_posix()


def _cleanup_contract(repo_root: Path) -> str | None:
    path = repo_root / "governance/repo-cleanup-contract.yml"
    return "governance/repo-cleanup-contract.yml" if path.exists() else None


def _iter_repo_files(repo_root: Path) -> list[Path]:
    files: list[Path] = []
    for current_root, dirnames, filenames in os.walk(repo_root):
        dirnames[:] = [name for name in dirnames if name not in SKIP_DIRS]
        root_path = Path(current_root)
        for filename in filenames:
            files.append(root_path / filename)
    return sorted(files)


def _is_text_file(path: Path) -> bool:
    if path.suffix.lower() in TEXT_SUFFIXES:
        return True
    return path.name in {"Makefile", "Makefile.fragment", "README", "LICENSE"}


def _path_is_under(relative_path: str, prefix: str) -> bool:
    normalized = prefix.rstrip("/")
    return relative_path == normalized or relative_path.startswith(f"{normalized}/")


def _destination_for_move(relative_path: str) -> str | None:
    for source_root, destination_root in AUDIT_MOVE_ROOTS.items():
        if _path_is_under(relative_path, source_root):
            suffix = relative_path.removeprefix(source_root).lstrip("/")
            return f"{destination_root}/{suffix}" if suffix else destination_root
    return None


def _audit_move_actions(repo_root: Path) -> list[CleanupAction]:
    actions: list[CleanupAction] = []
    for path in _iter_repo_files(repo_root):
        relative_path = _repo_relative(repo_root, path)
        destination = _destination_for_move(relative_path)
        if destination is None:
            continue
        actions.append(
            CleanupAction(
                kind="move_audit_artifact",
                source=relative_path,
                destination=destination,
                reason="audit and review evidence belongs under the canonical audits/ root",
                safe_to_apply=True,
            )
        )
    return actions


def _is_nested_governance_marker(relative_path: str) -> bool:
    path = Path(relative_path)
    parts = path.parts
    if len(parts) > 1 and path.name in GOVERNANCE_MARKER_FILES:
        return True
    if path.suffix.lower() not in {".yml", ".yaml"}:
        return False
    return any(marker_dir in parts[:-1] and parts[0] != marker_dir for marker_dir in GOVERNANCE_MARKER_DIRS)


def _nested_governance_actions(repo_root: Path) -> list[ManualAction]:
    actions: list[ManualAction] = []
    for path in _iter_repo_files(repo_root):
        relative_path = _repo_relative(repo_root, path)
        if not _is_nested_governance_marker(relative_path):
            continue
        actions.append(
            ManualAction(
                kind="nested_governance_boundary",
                path=relative_path,
                reason="nested governance must be declared as a vendored pack or removed from the active repo",
                llm_support="optional for policy choice; deterministic manifest declaration is possible after owner/source is known",
            )
        )
    return actions


def _legacy_governance_actions(repo_root: Path) -> list[ManualAction]:
    actions: list[ManualAction] = []
    for relative_path, reason in (
        ("plans", "active plans should be rescaffolded or compacted into the current BCF phase catalog"),
        ("phases", "historical phase logs should be summarized or archived before starting a fresh adoption phase"),
        ("docs/architecture", "architecture docs require semantic review before consolidation"),
        ("docs/security", "security docs require semantic review before consolidation"),
    ):
        path = repo_root / relative_path
        if not path.exists():
            continue
        actions.append(
            ManualAction(
                kind="semantic_compaction_required",
                path=relative_path,
                reason=reason,
                llm_support="required for accurate consolidation and stale/current language decisions",
            )
        )
    return actions


def _ensure_audit_readme(repo_root: Path) -> CleanupAction | None:
    if (repo_root / "audits" / "README.md").exists():
        return None
    return CleanupAction(
        kind="create_audit_readme",
        source="",
        destination="audits/README.md",
        reason="document the canonical audit root for future agents",
        safe_to_apply=True,
    )


def plan_cleanup(repo_root: Path) -> CleanupReport:
    repo_root = repo_root.resolve()
    if not repo_root.exists() or not repo_root.is_dir():
        raise NotADirectoryError(f"{repo_root} is not a directory")

    actions = _audit_move_actions(repo_root)
    readme_action = _ensure_audit_readme(repo_root)
    if readme_action is not None:
        actions.insert(0, readme_action)

    manual_actions = [*_nested_governance_actions(repo_root), *_legacy_governance_actions(repo_root)]
    status = "actionable" if actions or manual_actions else "clean"
    return CleanupReport(
        status=status,
        repo_root=str(repo_root),
        cleanup_contract=_cleanup_contract(repo_root),
        applied=False,
        actions=actions,
        manual_actions=manual_actions,
        rewritten_files=[],
        warnings=[],
    )


def _confirm_apply(repo_root: Path, assume_yes: bool) -> None:
    if assume_yes:
        return
    print(
        "WARNING: bcf cleanup --apply moves governance audit/review files and rewrites exact path references.",
        file=sys.stderr,
    )
    print(f"Target repo: {repo_root}", file=sys.stderr)
    response = input("Continue with cleanup apply? [y/N]: ").strip().lower()
    if response not in {"y", "yes"}:
        raise RuntimeError("cleanup apply aborted by user")


def _write_audit_readme(repo_root: Path) -> None:
    path = repo_root / "audits" / "README.md"
    if path.exists():
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        "# Audits\n\n"
        "Use this root for codebase audits, drift reviews, sprint reports, and review evidence.\n\n"
        "Keep reports terse: intent, scope, evidence, result, and next action.\n",
        encoding="utf-8",
    )


def _move_file(repo_root: Path, source: str, destination: str) -> None:
    source_path = repo_root / source
    destination_path = repo_root / destination
    if not source_path.exists():
        return
    if destination_path.exists():
        raise FileExistsError(f"cleanup destination already exists: {destination}")
    destination_path.parent.mkdir(parents=True, exist_ok=True)
    shutil.move(str(source_path), str(destination_path))


def _prune_empty_dirs(repo_root: Path) -> None:
    for relative_path in sorted(AUDIT_MOVE_ROOTS, key=lambda value: value.count("/"), reverse=True):
        path = repo_root / relative_path
        while path != repo_root and path.exists():
            try:
                path.rmdir()
            except OSError:
                break
            path = path.parent


def _reference_replacements(actions: list[CleanupAction]) -> dict[str, str]:
    replacements: dict[str, str] = {}
    for action in actions:
        if action.kind == "move_audit_artifact" and action.destination is not None:
            replacements[action.source] = action.destination
    for source_root, destination_root in AUDIT_MOVE_ROOTS.items():
        replacements[f"{source_root}/"] = f"{destination_root.rstrip('/')}/"
    return replacements


def _rewrite_references(repo_root: Path, replacements: dict[str, str]) -> list[str]:
    rewritten: list[str] = []
    for path in _iter_repo_files(repo_root):
        if not _is_text_file(path):
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            continue
        updated = text
        for old, new in replacements.items():
            updated = updated.replace(old, new)
        if updated != text:
            path.write_text(updated, encoding="utf-8")
            rewritten.append(_repo_relative(repo_root, path))
    return rewritten


def apply_cleanup(repo_root: Path, *, assume_yes: bool) -> CleanupReport:
    repo_root = repo_root.resolve()
    report = plan_cleanup(repo_root)
    safe_actions = [action for action in report.actions if action.safe_to_apply]
    _confirm_apply(repo_root, assume_yes)

    warnings: list[str] = []
    for action in safe_actions:
        if action.kind == "create_audit_readme":
            _write_audit_readme(repo_root)
        elif action.kind == "move_audit_artifact" and action.destination is not None:
            _move_file(repo_root, action.source, action.destination)
    _prune_empty_dirs(repo_root)
    rewritten_files = _rewrite_references(repo_root, _reference_replacements(safe_actions))
    if report.manual_actions:
        warnings.append("manual semantic compaction remains after safe cleanup")

    return CleanupReport(
        status="changed" if safe_actions or rewritten_files else report.status,
        repo_root=str(repo_root),
        cleanup_contract=_cleanup_contract(repo_root),
        applied=True,
        actions=safe_actions,
        manual_actions=report.manual_actions,
        rewritten_files=rewritten_files,
        warnings=warnings,
    )


def _report_to_dict(report: CleanupReport) -> dict[str, Any]:
    return asdict(report)


def _emit_json(report: CleanupReport, *, compact: bool) -> None:
    separators = (",", ":") if compact else None
    indent = None if compact else 2
    print(json.dumps(_report_to_dict(report), indent=indent, separators=separators, sort_keys=True))


def _emit_text(report: CleanupReport) -> None:
    print(f"status: {report.status}")
    print(f"repo_root: {report.repo_root}")
    if report.cleanup_contract:
        print(f"cleanup_contract: {report.cleanup_contract}")
    print(f"applied: {str(report.applied).lower()}")
    if report.actions:
        print("safe actions:")
        for action in report.actions:
            if action.destination:
                print(f"- {action.kind}: {action.source} -> {action.destination}")
            else:
                print(f"- {action.kind}: {action.destination}")
    if report.manual_actions:
        print("manual actions:")
        for action in report.manual_actions:
            print(f"- {action.kind}: {action.path} ({action.reason})")
    if report.rewritten_files:
        print("rewritten references:")
        for path in report.rewritten_files:
            print(f"- {path}")
    if report.warnings:
        print("warnings:")
        for warning in report.warnings:
            print(f"- {warning}")


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Plan or apply conservative BCF governance cleanup.")
    parser.add_argument("--repo-root", type=Path, default=Path.cwd())
    parser.add_argument("--apply", action="store_true", help="Apply safe path-level cleanup actions.")
    parser.add_argument("--yes", action="store_true", help="Confirm destructive --apply without prompting.")
    parser.add_argument(
        "--format",
        dest="output_format",
        choices=sorted(OUTPUT_FORMATS),
        default="text",
    )
    parser.add_argument("--compact", action="store_true", help="Use compact JSON output.")
    return parser


def main(argv: list[str] | None = None) -> None:
    args = _parser().parse_args(argv)
    try:
        report = (
            apply_cleanup(args.repo_root, assume_yes=args.yes)
            if args.apply
            else plan_cleanup(args.repo_root)
        )
    except Exception as exc:
        print(f"cleanup-governance-pack failed: {exc}", file=sys.stderr)
        raise SystemExit(1) from exc

    if args.output_format == "json":
        _emit_json(report, compact=args.compact)
    else:
        _emit_text(report)


if __name__ == "__main__":
    main()

"""Plan and apply conservative governance tree cleanup for BCF repos."""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile
from dataclasses import asdict, replace
from pathlib import Path
from typing import Any

_SCRIPT_ROOT = Path(__file__).resolve().parent
if str(_SCRIPT_ROOT) not in sys.path:
    sys.path.insert(0, str(_SCRIPT_ROOT))

from .governance_cleanup.models import (  # noqa: E402
    CleanupAction,
    CleanupReport,
    ManualAction,
)
from .governance_cleanup.phase_retention import (  # noqa: E402
    load_truth_reports,
    phase_retention_actions,
    prune_phase_hotfix_records,
    set_phase_retention_mode,
    write_archive_gitignore,
    write_phase_history,
)

OUTPUT_FORMATS = {"text", "json"}
PHASE_RETENTION_MODE_CHOICES = {"archive", "git-history"}
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
GOVERNANCE_PACK_REMOVE_PATHS = (
    "AGENTS.yml",
    "AGENTS.md",
    "CLAUDE.md",
    "MEMORY.yml",
    "architecture-boundaries.yml",
    "governance-profile.yml",
    "Makefile.fragment",
    "requirements-governance.txt",
    ".github/workflows/governance.yml",
    "audits",
    "contracts/observability",
    "docs/OPERATIONS.md",
    "governance",
    "phases",
    "plans",
    "schemas",
    "backend/tests/architecture/test_boundaries_ast.py",
    "scripts/check_governance_exposure.py",
    "scripts/governance_evidence.py",
    "scripts/governance_truth.py",
    "scripts/governance_truth_support.py",
    "scripts/migrate_governance_evidence.py",
    "scripts/governance_validation",
    "scripts/scaffold_governance_artifacts.py",
    "scripts/validate_governance_yaml.py",
)
BCF_CI_REFERENCE_MARKERS = (
    "bcf validate",
    "bcf exposure-scan",
    "governance-validate",
    "governance-exposure-scan",
    "check_governance_exposure.py",
    "validate_governance_yaml.py",
    "Makefile.fragment",
)
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
def _governance_pack_remove_actions(repo_root: Path) -> list[CleanupAction]:
    actions: list[CleanupAction] = []
    for relative_path in GOVERNANCE_PACK_REMOVE_PATHS:
        path = repo_root / relative_path
        if not path.exists():
            continue
        actions.append(
            CleanupAction(
                kind="remove_governance_artifact",
                source=relative_path,
                destination=None,
                reason="remove BCF governance pack-owned artifact or dedicated CI gate",
                safe_to_apply=True,
            )
        )
    return actions


def _bcf_ci_reference_actions(repo_root: Path) -> list[ManualAction]:
    workflow_root = repo_root / ".github" / "workflows"
    if not workflow_root.exists():
        return []
    actions: list[ManualAction] = []
    for path in sorted([*workflow_root.glob("*.yml"), *workflow_root.glob("*.yaml")]):
        relative_path = _repo_relative(repo_root, path)
        if relative_path == ".github/workflows/governance.yml":
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            continue
        lowered = text.lower()
        if not any(marker.lower() in lowered for marker in BCF_CI_REFERENCE_MARKERS):
            continue
        actions.append(
            ManualAction(
                kind="bcf_ci_reference",
                path=relative_path,
                reason="workflow contains BCF governance references but is not the dedicated pack-owned workflow",
                llm_support="optional; remove only the BCF job or step without deleting unrelated CI",
            )
        )
    return actions


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


def plan_cleanup(
    repo_root: Path,
    *,
    archive_closed_phases: bool = False,
    phase_retention_mode: str | None = None,
    truth_report_paths: list[Path] | None = None,
    remove_governance_pack: bool = False,
) -> CleanupReport:
    repo_root = repo_root.resolve()
    if not repo_root.exists() or not repo_root.is_dir():
        raise NotADirectoryError(f"{repo_root} is not a directory")

    if remove_governance_pack:
        actions = _governance_pack_remove_actions(repo_root)
        manual_actions = _bcf_ci_reference_actions(repo_root)
        status = "actionable" if actions or manual_actions else "clean"
        warnings = (
            ["remove_governance_pack deletes BCF-owned governance files and evidence roots when applied"]
            if actions
            else []
        )
        return CleanupReport(
            status=status,
            repo_root=str(repo_root),
            cleanup_contract=_cleanup_contract(repo_root),
            applied=False,
            actions=actions,
            manual_actions=manual_actions,
            rewritten_files=[],
            warnings=warnings,
        )

    actions = _audit_move_actions(repo_root)
    warnings: list[str] = []
    effective_retention_mode = _effective_phase_retention_mode(
        archive_closed_phases=archive_closed_phases,
        phase_retention_mode=phase_retention_mode,
    )
    if effective_retention_mode is not None:
        truth_reports = load_truth_reports(repo_root, truth_report_paths)
        retention_actions, retention_warnings = phase_retention_actions(
            repo_root, mode=effective_retention_mode, truth_reports=truth_reports
        )
        actions.extend(retention_actions)
        warnings.extend(retention_warnings)
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
        warnings=warnings,
    )


def _confirm_apply(repo_root: Path, assume_yes: bool, *, remove_governance_pack: bool = False) -> None:
    if assume_yes:
        return
    if remove_governance_pack:
        print(
            "WARNING: bcf cleanup --remove-governance-pack --apply deletes BCF governance files, "
            "directories, and the dedicated governance CI workflow.",
            file=sys.stderr,
        )
    else:
        print(
            "WARNING: bcf cleanup --apply moves governance files and rewrites exact path references.",
            file=sys.stderr,
        )
    print(f"Target repo: {repo_root}", file=sys.stderr)
    if not sys.stdin.isatty():
        raise RuntimeError("cleanup --apply requires --yes when stdin is not a TTY")
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


def _prune_empty_parent_dirs(repo_root: Path, start: Path) -> None:
    current = start
    while current != repo_root and current.is_relative_to(repo_root):
        try:
            current.rmdir()
        except OSError:
            return
        current = current.parent


def _remove_path(repo_root: Path, relative_path: str) -> None:
    path = (repo_root / relative_path).resolve()
    if path == repo_root or not path.is_relative_to(repo_root):
        raise ValueError(f"refusing to remove path outside repo root: {relative_path}")
    if not path.exists():
        return
    parent = path.parent
    if path.is_dir():
        shutil.rmtree(path)
    else:
        path.unlink()
    _prune_empty_parent_dirs(repo_root, parent)


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


def _effective_phase_retention_mode(
    *,
    archive_closed_phases: bool,
    phase_retention_mode: str | None,
) -> str | None:
    if phase_retention_mode is None:
        return "archive" if archive_closed_phases else None
    normalized = phase_retention_mode.replace("-", "_")
    if archive_closed_phases and normalized != "archive":
        raise ValueError("--archive-closed-phases cannot be combined with --phase-retention-mode git-history")
    return normalized


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


def _apply_cleanup_direct(
    repo_root: Path,
    *,
    assume_yes: bool,
    archive_closed_phases: bool = False,
    phase_retention_mode: str | None = None,
    truth_report_paths: list[Path] | None = None,
    remove_governance_pack: bool = False,
) -> CleanupReport:
    repo_root = repo_root.resolve()
    effective_retention_mode = _effective_phase_retention_mode(
        archive_closed_phases=archive_closed_phases,
        phase_retention_mode=phase_retention_mode,
    )
    report = plan_cleanup(
        repo_root,
        archive_closed_phases=archive_closed_phases,
        phase_retention_mode=phase_retention_mode,
        truth_report_paths=truth_report_paths,
        remove_governance_pack=remove_governance_pack,
    )
    safe_actions = [action for action in report.actions if action.safe_to_apply]
    _confirm_apply(repo_root, assume_yes, remove_governance_pack=remove_governance_pack)

    warnings: list[str] = list(report.warnings)
    if remove_governance_pack:
        for action in safe_actions:
            if action.kind == "remove_governance_artifact":
                _remove_path(repo_root, action.source)
        if report.manual_actions:
            warnings.append("manual BCF references remain outside dedicated pack-owned paths")
        return CleanupReport(
            status="changed" if safe_actions else report.status,
            repo_root=str(repo_root),
            cleanup_contract=None,
            applied=True,
            actions=safe_actions,
            manual_actions=report.manual_actions,
            rewritten_files=[],
            warnings=warnings,
        )

    phase_history_path = write_phase_history(
        repo_root,
        safe_actions,
        mode=effective_retention_mode,
        truth_reports=load_truth_reports(repo_root, truth_report_paths),
    )
    if phase_history_path is not None:
        warnings.append(f"phase history updated: {phase_history_path}")
    if effective_retention_mode is not None:
        set_phase_retention_mode(repo_root, effective_retention_mode)
    hotfix_ledger_path = prune_phase_hotfix_records(repo_root, safe_actions)
    if hotfix_ledger_path is not None:
        warnings.append(f"phase hotfix records pruned: {hotfix_ledger_path}")
    for action in safe_actions:
        if action.kind == "create_audit_readme":
            _write_audit_readme(repo_root)
        elif action.kind == "ignore_phase_archive_root":
            write_archive_gitignore(repo_root)
        elif action.kind == "move_audit_artifact" and action.destination is not None:
            _move_file(repo_root, action.source, action.destination)
        elif action.kind == "archive_phase_artifact" and action.destination is not None:
            _move_file(repo_root, action.source, action.destination)
        elif action.kind == "remove_phase_artifact":
            _remove_path(repo_root, action.source)
        elif action.kind == "prune_phase_hotfix_records":
            continue
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


def _copy_working_tree(source: Path, destination: Path) -> None:
    for path in _iter_repo_files(source):
        relative = path.relative_to(source)
        target = destination / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(path, target)


def _remove_shadow_files_absent_from_source(source: Path, shadow: Path) -> None:
    source_paths = {
        path.relative_to(source).as_posix() for path in _iter_repo_files(source)
    }
    for path in _iter_repo_files(shadow):
        relative = path.relative_to(shadow).as_posix()
        if relative not in source_paths:
            path.unlink()
            _prune_empty_parent_dirs(shadow, path.parent)


def _shadow_repository(repo_root: Path, parent: Path) -> Path:
    shadow = parent / "repo"
    if (repo_root / ".git").exists():
        result = subprocess.run(
            ["git", "clone", "--shared", "--quiet", str(repo_root), str(shadow)],
            capture_output=True,
            text=True,
            check=False,
        )
        if result.returncode != 0:
            raise RuntimeError(result.stderr.strip() or "failed to create cleanup shadow repository")
        _remove_shadow_files_absent_from_source(repo_root, shadow)
        _copy_working_tree(repo_root, shadow)
    else:
        shadow.mkdir(parents=True)
        _copy_working_tree(repo_root, shadow)
    return shadow


def _file_snapshot(repo_root: Path) -> dict[str, bytes]:
    return {
        path.relative_to(repo_root).as_posix(): path.read_bytes()
        for path in _iter_repo_files(repo_root)
    }


def _file_modes(repo_root: Path) -> dict[str, int]:
    return {
        path.relative_to(repo_root).as_posix(): path.stat().st_mode
        for path in _iter_repo_files(repo_root)
    }


def _validate_shadow(repo_root: Path, *, remove_governance_pack: bool) -> None:
    if remove_governance_pack:
        return
    required = ("AGENTS.yml", "MEMORY.yml", "governance-profile.yml", "plans/phase-ledger.yml")
    if not all((repo_root / path).exists() for path in required):
        return
    from . import check_governance_exposure, validate_governance_yaml

    validate_governance_yaml.validate_repo_root(repo_root)
    exposure = check_governance_exposure.scan_exposures(repo_root)
    if exposure.findings:
        raise RuntimeError("cleanup proposal failed governance exposure validation")


def _commit_shadow(
    repo_root: Path,
    before: dict[str, bytes],
    after: dict[str, bytes],
    before_modes: dict[str, int],
    after_modes: dict[str, int],
) -> None:
    changed = sorted(set(before) | set(after))
    changed = [path for path in changed if before.get(path) != after.get(path)]
    applied: list[str] = []
    try:
        for relative in changed:
            target = repo_root / relative
            if relative not in after:
                if target.exists():
                    target.unlink()
                    _prune_empty_parent_dirs(repo_root, target.parent)
            else:
                target.parent.mkdir(parents=True, exist_ok=True)
                with tempfile.NamedTemporaryFile(dir=target.parent, delete=False) as handle:
                    handle.write(after[relative])
                    staged = Path(handle.name)
                try:
                    os.chmod(staged, after_modes[relative])
                    staged.replace(target)
                finally:
                    if staged.exists():
                        staged.unlink()
            applied.append(relative)
    except Exception:
        for relative in reversed(applied):
            target = repo_root / relative
            if relative not in before:
                if target.exists():
                    target.unlink()
            else:
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(before[relative])
                os.chmod(target, before_modes[relative])
        raise
    _prune_empty_dirs(repo_root)


def apply_cleanup(
    repo_root: Path,
    *,
    assume_yes: bool,
    archive_closed_phases: bool = False,
    phase_retention_mode: str | None = None,
    truth_report_paths: list[Path] | None = None,
    remove_governance_pack: bool = False,
) -> CleanupReport:
    repo_root = repo_root.resolve()
    _confirm_apply(repo_root, assume_yes, remove_governance_pack=remove_governance_pack)
    normalized_truth_paths = [
        (path if path.is_absolute() else repo_root / path).resolve()
        for path in truth_report_paths or []
    ]
    before = _file_snapshot(repo_root)
    before_modes = _file_modes(repo_root)
    with tempfile.TemporaryDirectory(prefix="bcf-cleanup-") as temporary:
        shadow = _shadow_repository(repo_root, Path(temporary))
        report = _apply_cleanup_direct(
            shadow,
            assume_yes=True,
            archive_closed_phases=archive_closed_phases,
            phase_retention_mode=phase_retention_mode,
            truth_report_paths=normalized_truth_paths,
            remove_governance_pack=remove_governance_pack,
        )
        _validate_shadow(shadow, remove_governance_pack=remove_governance_pack)
        after = _file_snapshot(shadow)
        after_modes = _file_modes(shadow)
        _commit_shadow(repo_root, before, after, before_modes, after_modes)
    return replace(report, repo_root=str(repo_root))


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
                print(f"- {action.kind}: {action.source}")
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
    parser.add_argument(
        "--archive-closed-phases",
        action="store_true",
        help="Alias for --phase-retention-mode archive.",
    )
    parser.add_argument(
        "--phase-retention-mode",
        nargs="?",
        const="git-history",
        choices=sorted(PHASE_RETENTION_MODE_CHOICES),
        help=(
            "Plan or apply closed phase triplet retention cleanup. With no value, "
            "defaults to git-history. archive moves old triplets to the ignored "
            "archive root; git-history records hashes and removes old triplets "
            "after verifying HEAD contains them."
        ),
    )
    parser.add_argument(
        "--remove-governance-pack",
        action="store_true",
        help="Plan or apply removal of BCF governance pack-owned artifacts and dedicated CI gates.",
    )
    parser.add_argument(
        "--truth-report",
        dest="truth_report_paths",
        action="append",
        type=Path,
        help="Passing closed truth report required for each phase selected for retention.",
    )
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
            apply_cleanup(
                args.repo_root,
                assume_yes=args.yes,
                archive_closed_phases=args.archive_closed_phases,
                phase_retention_mode=args.phase_retention_mode,
                truth_report_paths=args.truth_report_paths,
                remove_governance_pack=args.remove_governance_pack,
            )
            if args.apply
            else plan_cleanup(
                args.repo_root,
                archive_closed_phases=args.archive_closed_phases,
                phase_retention_mode=args.phase_retention_mode,
                truth_report_paths=args.truth_report_paths,
                remove_governance_pack=args.remove_governance_pack,
            )
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

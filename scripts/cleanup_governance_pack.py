"""Plan and apply conservative governance tree cleanup for BCF repos."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import sys
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

import yaml  # type: ignore[import-untyped]


OUTPUT_FORMATS = {"text", "json"}
ARCHIVABLE_PHASE_STATUSES = {"verified", "closed"}
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
DEFAULT_PHASE_ARCHIVE_ROOT = "governance/archive/phase-artifacts"
DEFAULT_PHASE_HISTORY_PATH = "plans/phase-history.yml"
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


def _load_yaml(path: Path) -> dict[str, Any] | None:
    if not path.exists():
        return None
    payload = yaml.safe_load(path.read_text(encoding="utf-8"))
    return payload if isinstance(payload, dict) else None


def _file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


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


def _phase_number(phase_id: str) -> int:
    if not phase_id.startswith("P") or not phase_id[1:].isdigit():
        raise ValueError(f"invalid phase id {phase_id!r}; expected values like 'P01'")
    return int(phase_id[1:])


def _phase_stem(phase_id: str) -> str:
    return f"phase-{_phase_number(phase_id):02d}"


def _phase_triplet_paths(phase_id: str) -> tuple[str, str, str]:
    stem = _phase_stem(phase_id)
    return (
        f"plans/{stem}-plan.yml",
        f"plans/{stem}-workitems.yml",
        f"phases/{stem}-log.yml",
    )


def _phase_retention_policy(repo_root: Path) -> dict[str, Any]:
    manifest = _load_yaml(repo_root / "governance" / "artifact-manifest.yml") or {}
    policy = manifest.get("phase_retention_policy")
    return policy if isinstance(policy, dict) else {}


def _phase_history_path(repo_root: Path) -> str:
    policy = _phase_retention_policy(repo_root)
    history_path = policy.get("history_path")
    return history_path if isinstance(history_path, str) and history_path else DEFAULT_PHASE_HISTORY_PATH


def _phase_archive_root(repo_root: Path) -> str:
    policy = _phase_retention_policy(repo_root)
    archive = policy.get("archive")
    if isinstance(archive, dict):
        root = archive.get("root")
        if isinstance(root, str) and root:
            return root.rstrip("/")
    return DEFAULT_PHASE_ARCHIVE_ROOT


def _closed_phase_statuses(repo_root: Path) -> set[str]:
    policy = _phase_retention_policy(repo_root)
    archive = policy.get("archive")
    if not isinstance(archive, dict):
        return set(ARCHIVABLE_PHASE_STATUSES)
    statuses = archive.get("closed_phase_statuses")
    if not isinstance(statuses, list):
        return set(ARCHIVABLE_PHASE_STATUSES)
    parsed = {str(status) for status in statuses if status}
    return parsed or set(ARCHIVABLE_PHASE_STATUSES)


def _active_window(repo_root: Path) -> dict[str, Any]:
    policy = _phase_retention_policy(repo_root)
    window = policy.get("active_window")
    return window if isinstance(window, dict) else {}


def _active_phase_id(repo_root: Path) -> str | None:
    ledger = _load_yaml(repo_root / "plans" / "phase-ledger.yml") or {}
    active_phase = ledger.get("active_phase")
    if not isinstance(active_phase, dict):
        return None
    phase_id = active_phase.get("id")
    return phase_id if isinstance(phase_id, str) and phase_id else None


def _build_phase_ids(repo_root: Path) -> list[str]:
    build_plan = _load_yaml(repo_root / "plans" / "build-plan.yml") or {}
    phase_sequence = build_plan.get("phase_sequence")
    if not isinstance(phase_sequence, list):
        return []
    phase_ids = [
        phase.get("phase_id")
        for phase in phase_sequence
        if isinstance(phase, dict) and isinstance(phase.get("phase_id"), str)
    ]
    return sorted(phase_ids, key=_phase_number)


def _phase_log_status(repo_root: Path, phase_id: str) -> str | None:
    log = _load_yaml(repo_root / f"phases/{_phase_stem(phase_id)}-log.yml") or {}
    document = log.get("document")
    if not isinstance(document, dict):
        return None
    status = document.get("status")
    return status if isinstance(status, str) else None


def _retained_phase_ids(repo_root: Path) -> set[str]:
    phase_ids = _build_phase_ids(repo_root)
    active_id = _active_phase_id(repo_root)
    if active_id is None or active_id not in phase_ids:
        return set(phase_ids)

    window = _active_window(repo_root)
    retained: set[str] = set()
    if window.get("include_active", True):
        retained.add(active_id)
    if window.get("include_next", True):
        for phase_id in phase_ids:
            if _phase_number(phase_id) > _phase_number(active_id):
                retained.add(phase_id)
                break
    keep_recent_closed = int(window.get("keep_recent_closed", 0) or 0)
    prior_phase_ids = [
        phase_id for phase_id in phase_ids if _phase_number(phase_id) < _phase_number(active_id)
    ]
    retained.update(prior_phase_ids[-keep_recent_closed:] if keep_recent_closed else [])
    return retained


def _phase_archive_actions(repo_root: Path) -> tuple[list[CleanupAction], list[str]]:
    actions: list[CleanupAction] = []
    warnings: list[str] = []
    archive_root = _phase_archive_root(repo_root)
    retained = _retained_phase_ids(repo_root)
    statuses = _closed_phase_statuses(repo_root)
    for phase_id in _build_phase_ids(repo_root):
        if phase_id in retained:
            continue
        if _phase_log_status(repo_root, phase_id) not in statuses:
            continue
        for source in _phase_triplet_paths(phase_id):
            source_path = repo_root / source
            if not source_path.exists():
                continue
            destination = f"{archive_root}/{Path(source).name}"
            if (repo_root / destination).exists():
                warnings.append(f"phase archive destination already exists: {destination}")
                continue
            actions.append(
                CleanupAction(
                    kind="archive_phase_artifact",
                    source=source,
                    destination=destination,
                    reason=(
                        "closed phase triplet can be moved out of active governance "
                        "after compact phase-history is recorded"
                    ),
                    safe_to_apply=True,
                )
            )
    return actions, warnings


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
    if archive_closed_phases:
        archive_actions, archive_warnings = _phase_archive_actions(repo_root)
        actions.extend(archive_actions)
        warnings.extend(archive_warnings)
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


def _phase_history_entry(
    repo_root: Path,
    phase_id: str,
    *,
    archive_actions: list[CleanupAction],
) -> dict[str, Any]:
    plan = _load_yaml(repo_root / f"plans/{_phase_stem(phase_id)}-plan.yml") or {}
    log = _load_yaml(repo_root / f"phases/{_phase_stem(phase_id)}-log.yml") or {}
    product_spec = _load_yaml(repo_root / "plans" / "product-spec.yml") or {}

    phase = plan.get("phase") if isinstance(plan.get("phase"), dict) else {}
    summary = log.get("summary") if isinstance(log.get("summary"), dict) else {}
    document = log.get("document") if isinstance(log.get("document"), dict) else {}
    execution_evidence = (
        log.get("execution_evidence")
        if isinstance(log.get("execution_evidence"), dict)
        else {}
    )
    release_train = None
    for entry in product_spec.get("execution_phases", []) or []:
        if isinstance(entry, dict) and entry.get("phase_id") == phase_id:
            release_train = entry.get("release_train")
            break

    artifact_entries = []
    for action in archive_actions:
        if action.kind != "archive_phase_artifact" or action.destination is None:
            continue
        if action.source not in _phase_triplet_paths(phase_id):
            continue
        artifact_entries.append(
            {
                "path": action.destination,
                "sha256": _file_sha256(repo_root / action.source),
            }
        )

    highlights = summary.get("highlights")
    return {
        "phase_id": phase_id,
        "build_block": str(phase.get("build_block") or ""),
        **({"release_train": release_train} if isinstance(release_train, str) else {}),
        "status": str(document.get("status") or "completed"),
        "outcome": str(summary.get("outcome") or document.get("status") or "completed"),
        "summary": highlights if isinstance(highlights, list) and highlights else ["archived closed phase"],
        "validation": (
            execution_evidence.get("executed_commands")
            if isinstance(execution_evidence.get("executed_commands"), list)
            else []
        ),
        "archived_artifacts": artifact_entries,
    }


def _write_phase_history(repo_root: Path, archive_actions: list[CleanupAction]) -> str | None:
    phase_ids = sorted(
        {
            f"P{int(match.group(1)):02d}"
            for action in archive_actions
            if action.kind == "archive_phase_artifact"
            for match in [re.match(r"plans/phase-(\d+)-plan\.ya?ml", action.source)]
            if match is not None
        },
        key=_phase_number,
    )
    if not phase_ids:
        return None

    history_rel = _phase_history_path(repo_root)
    history_path = repo_root / history_rel
    history = _load_yaml(history_path)
    if history is None:
        project_id = (repo_root / "pyproject.toml").stem if (repo_root / "pyproject.toml").exists() else "project"
        history = {
            "document": {
                "kind": "phase_history",
                "name": "Phase History",
                "id": f"{project_id}-phase-history",
                "version": "1.0.0",
                "generated_at_utc": "1970-01-01T00:00:00Z",
                "status": "active",
                "path": history_rel,
            },
            "retention_policy": {
                "source": "governance/artifact-manifest.yml",
                "purpose": "compact machine-readable history for archived closed phase artifacts",
            },
            "entries": [],
        }

    entries = history.get("entries")
    if not isinstance(entries, list):
        entries = []
    retained_entries = [
        entry
        for entry in entries
        if not (isinstance(entry, dict) and entry.get("phase_id") in set(phase_ids))
    ]
    retained_entries.extend(
        _phase_history_entry(repo_root, phase_id, archive_actions=archive_actions)
        for phase_id in phase_ids
    )
    history["entries"] = sorted(
        retained_entries,
        key=lambda entry: _phase_number(str(entry.get("phase_id", "P0"))) if isinstance(entry, dict) else 0,
    )
    history_path.parent.mkdir(parents=True, exist_ok=True)
    history_path.write_text(yaml.safe_dump(history, sort_keys=False), encoding="utf-8")
    return history_rel


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


def apply_cleanup(
    repo_root: Path,
    *,
    assume_yes: bool,
    archive_closed_phases: bool = False,
    remove_governance_pack: bool = False,
) -> CleanupReport:
    repo_root = repo_root.resolve()
    report = plan_cleanup(
        repo_root,
        archive_closed_phases=archive_closed_phases,
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

    phase_history_path = _write_phase_history(repo_root, safe_actions)
    if phase_history_path is not None:
        warnings.append(f"phase history updated: {phase_history_path}")
    for action in safe_actions:
        if action.kind == "create_audit_readme":
            _write_audit_readme(repo_root)
        elif action.kind == "move_audit_artifact" and action.destination is not None:
            _move_file(repo_root, action.source, action.destination)
        elif action.kind == "archive_phase_artifact" and action.destination is not None:
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
        help="Plan or apply closed phase triplet archival using phase_retention_policy.",
    )
    parser.add_argument(
        "--remove-governance-pack",
        action="store_true",
        help="Plan or apply removal of BCF governance pack-owned artifacts and dedicated CI gates.",
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
                remove_governance_pack=args.remove_governance_pack,
            )
            if args.apply
            else plan_cleanup(
                args.repo_root,
                archive_closed_phases=args.archive_closed_phases,
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

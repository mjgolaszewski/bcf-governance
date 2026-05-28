"""Phase-retention cleanup policy and persistence."""

from __future__ import annotations

import hashlib
import re
import subprocess
from pathlib import Path
from typing import Any

import yaml  # type: ignore[import-untyped]

from .models import CleanupAction

ARCHIVABLE_PHASE_STATUSES = {"verified", "closed"}
DEFAULT_PHASE_ARCHIVE_ROOT = "governance/archive/phase-artifacts"
DEFAULT_PHASE_HISTORY_PATH = "plans/phase-history.yml"
PHASE_RETENTION_MODES = {"archive", "git_history"}

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


def _phase_retention_mode(repo_root: Path, mode: str | None) -> str:
    if mode is not None:
        normalized = mode.replace("-", "_")
    else:
        policy = _phase_retention_policy(repo_root)
        configured = policy.get("mode")
        normalized = str(configured).replace("-", "_") if configured else "archive"
    if normalized not in PHASE_RETENTION_MODES:
        raise ValueError(f"phase retention mode must be one of {sorted(PHASE_RETENTION_MODES)}")
    return normalized


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


def _archive_gitignore_patterns(repo_root: Path) -> tuple[str, str]:
    archive_root = _phase_archive_root(repo_root).rstrip("/")
    return f"{archive_root}/*", f"!{archive_root}/.gitkeep"


def _archive_root_is_ignored(repo_root: Path) -> bool:
    gitignore = repo_root / ".gitignore"
    if not gitignore.exists():
        return False
    ignored_pattern, _ = _archive_gitignore_patterns(repo_root)
    lines = {
        line.strip()
        for line in gitignore.read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.strip().startswith("#")
    }
    archive_root = _phase_archive_root(repo_root).rstrip("/")
    return ignored_pattern in lines or f"{archive_root}/" in lines


def _ignore_archive_root_action(repo_root: Path) -> CleanupAction | None:
    if _archive_root_is_ignored(repo_root):
        return None
    return CleanupAction(
        kind="ignore_phase_archive_root",
        source="",
        destination=".gitignore",
        reason="phase archive contents are local history and must not be retained in git",
        safe_to_apply=True,
    )


def _phase_retention_actions(
    repo_root: Path, *, mode: str | None = None
) -> tuple[list[CleanupAction], list[str]]:
    actions: list[CleanupAction] = []
    warnings: list[str] = []
    retention_mode = _phase_retention_mode(repo_root, mode)
    archive_root = _phase_archive_root(repo_root)
    retained = _retained_phase_ids(repo_root)
    statuses = _closed_phase_statuses(repo_root)
    active_id = _active_phase_id(repo_root)
    active_number = _phase_number(active_id) if active_id else None

    if retention_mode == "archive":
        ignore_action = _ignore_archive_root_action(repo_root)
        if ignore_action is not None:
            actions.append(ignore_action)

    for phase_id in _build_phase_ids(repo_root):
        if active_number is not None and _phase_number(phase_id) >= active_number:
            continue
        if phase_id in retained:
            continue
        if _phase_log_status(repo_root, phase_id) not in statuses:
            continue
        for source in _phase_triplet_paths(phase_id):
            source_path = repo_root / source
            if not source_path.exists():
                continue
            destination = (
                f"{archive_root}/{Path(source).name}"
                if retention_mode == "archive"
                else None
            )
            if destination is not None and (repo_root / destination).exists():
                warnings.append(f"phase archive destination already exists: {destination}")
                continue
            actions.append(
                CleanupAction(
                    kind=(
                        "archive_phase_artifact"
                        if retention_mode == "archive"
                        else "remove_phase_artifact"
                    ),
                    source=source,
                    destination=destination,
                    reason=(
                        "closed phase triplet is outside the retained phase window "
                        "after compact phase-history is recorded"
                    ),
                    safe_to_apply=True,
                )
            )
    return actions, warnings


def _git_head(repo_root: Path) -> str:
    result = subprocess.run(
        ["git", "-C", str(repo_root), "rev-parse", "HEAD"],
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        raise RuntimeError("git-history phase retention requires a git repository with HEAD")
    return result.stdout.strip()


def _sha256_bytes(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _verify_git_history_sources(
    repo_root: Path, actions: list[CleanupAction], retention_ref: str
) -> None:
    for action in actions:
        if action.kind != "remove_phase_artifact":
            continue
        path = repo_root / action.source
        result = subprocess.run(
            ["git", "-C", str(repo_root), "show", f"{retention_ref}:{action.source}"],
            capture_output=True,
            check=False,
        )
        if result.returncode != 0:
            raise RuntimeError(
                f"git-history phase retention requires {action.source} to exist at {retention_ref}"
            )
        if _sha256_bytes(result.stdout) != _file_sha256(path):
            raise RuntimeError(
                f"git-history phase retention requires {action.source} to match {retention_ref}"
            )

def _phase_history_entry(
    repo_root: Path,
    phase_id: str,
    *,
    phase_actions: list[CleanupAction],
    mode: str,
    retention_ref: str | None,
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
    retained_action_kinds = {"archive_phase_artifact", "remove_phase_artifact"}
    for action in phase_actions:
        if action.kind not in retained_action_kinds:
            continue
        if action.source not in _phase_triplet_paths(phase_id):
            continue
        artifact_entry = {
            "path": action.destination or action.source,
            "sha256": _file_sha256(repo_root / action.source),
        }
        if retention_ref is not None:
            artifact_entry["git_commit"] = retention_ref
        artifact_entries.append(artifact_entry)

    highlights = summary.get("highlights")
    return {
        "phase_id": phase_id,
        "build_block": str(phase.get("build_block") or ""),
        **({"release_train": release_train} if isinstance(release_train, str) else {}),
        "retention_source": mode,
        **({"retention_ref": retention_ref} if retention_ref is not None else {}),
        "status": str(document.get("status") or "completed"),
        "outcome": str(summary.get("outcome") or document.get("status") or "completed"),
        "summary": highlights if isinstance(highlights, list) and highlights else ["closed phase retained"],
        "validation": (
            execution_evidence.get("executed_commands")
            if isinstance(execution_evidence.get("executed_commands"), list)
            else []
        ),
        "archived_artifacts": artifact_entries,
    }


def _write_phase_history(
    repo_root: Path,
    phase_actions: list[CleanupAction],
    *,
    mode: str | None = None,
) -> str | None:
    retention_mode = _phase_retention_mode(repo_root, mode)
    retained_action_kinds = {"archive_phase_artifact", "remove_phase_artifact"}
    phase_ids = sorted(
        {
            f"P{int(match.group(1)):02d}"
            for action in phase_actions
            if action.kind in retained_action_kinds
            for match in [re.match(r"plans/phase-(\d+)-plan\.ya?ml", action.source)]
            if match is not None
        },
        key=_phase_number,
    )
    if not phase_ids:
        return None

    retention_ref = _git_head(repo_root) if retention_mode == "git_history" else None
    if retention_ref is not None:
        _verify_git_history_sources(repo_root, phase_actions, retention_ref)

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
                "purpose": "compact machine-readable history for removed closed phase artifacts",
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
        _phase_history_entry(
            repo_root,
            phase_id,
            phase_actions=phase_actions,
            mode=retention_mode,
            retention_ref=retention_ref,
        )
        for phase_id in phase_ids
    )
    history["entries"] = sorted(
        retained_entries,
        key=lambda entry: _phase_number(str(entry.get("phase_id", "P0"))) if isinstance(entry, dict) else 0,
    )
    history_path.parent.mkdir(parents=True, exist_ok=True)
    history_path.write_text(
        yaml.safe_dump(history, sort_keys=False, default_flow_style=None, width=4096),
        encoding="utf-8",
    )
    return history_rel

def _write_archive_gitignore(repo_root: Path) -> None:
    gitignore = repo_root / ".gitignore"
    ignored_pattern, keep_pattern = _archive_gitignore_patterns(repo_root)
    gitkeep = repo_root / _phase_archive_root(repo_root) / ".gitkeep"
    gitkeep.parent.mkdir(parents=True, exist_ok=True)
    gitkeep.touch()
    existing = gitignore.read_text(encoding="utf-8").splitlines() if gitignore.exists() else []
    lines = list(existing)
    if ignored_pattern not in {line.strip() for line in lines}:
        lines.append(ignored_pattern)
    if keep_pattern not in {line.strip() for line in lines}:
        lines.append(keep_pattern)
    gitignore.write_text("\n".join(lines).rstrip() + "\n", encoding="utf-8")


def _set_phase_retention_mode(repo_root: Path, mode: str) -> None:
    retention_mode = _phase_retention_mode(repo_root, mode)
    manifest_path = repo_root / "governance" / "artifact-manifest.yml"
    if not manifest_path.exists():
        return
    lines = manifest_path.read_text(encoding="utf-8").splitlines()
    policy_index = next(
        (index for index, line in enumerate(lines) if line == "phase_retention_policy:"),
        None,
    )
    if policy_index is None:
        manifest = _load_yaml(manifest_path) or {}
        manifest["phase_retention_policy"] = {"mode": retention_mode}
        manifest_path.write_text(
            yaml.safe_dump(manifest, sort_keys=False, default_flow_style=None, width=4096),
            encoding="utf-8",
        )
        return
    insert_at = policy_index + 1
    while insert_at < len(lines) and lines[insert_at].startswith("  #"):
        insert_at += 1
    for index in range(policy_index + 1, len(lines)):
        line = lines[index]
        if line and not line.startswith(" "):
            break
        if line.startswith("  mode:"):
            lines[index] = f"  mode: {retention_mode}"
            manifest_path.write_text("\n".join(lines).rstrip() + "\n", encoding="utf-8")
            return
    lines.insert(insert_at, f"  mode: {retention_mode}")
    manifest_path.write_text("\n".join(lines).rstrip() + "\n", encoding="utf-8")


def _phase_archive_actions(repo_root: Path) -> tuple[list[CleanupAction], list[str]]:
    return _phase_retention_actions(repo_root, mode="archive")


phase_archive_actions = _phase_archive_actions
phase_retention_actions = _phase_retention_actions
write_phase_history = _write_phase_history
write_archive_gitignore = _write_archive_gitignore
set_phase_retention_mode = _set_phase_retention_mode

"""Phase-retention cleanup policy and persistence."""

from __future__ import annotations

import hashlib
import re
from pathlib import Path
from typing import Any

import yaml  # type: ignore[import-untyped]

from .models import CleanupAction

ARCHIVABLE_PHASE_STATUSES = {"verified", "closed"}
DEFAULT_PHASE_ARCHIVE_ROOT = "governance/archive/phase-artifacts"
DEFAULT_PHASE_HISTORY_PATH = "plans/phase-history.yml"

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
    history_path.write_text(
        yaml.safe_dump(history, sort_keys=False, default_flow_style=None, width=4096),
        encoding="utf-8",
    )
    return history_rel

phase_archive_actions = _phase_archive_actions
write_phase_history = _write_phase_history

"""Phase-retention cleanup policy and persistence."""

from __future__ import annotations

import hashlib
import json
import re
import subprocess
from pathlib import Path
from typing import Any

import yaml  # type: ignore[import-untyped]

from .models import CleanupAction
from .truth_reports import load_truth_reports

ARCHIVABLE_PHASE_STATUSES = {"completed"}
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


def _context_budget(repo_root: Path, relative_path: str) -> tuple[int | None, int | None]:
    manifest = _load_yaml(repo_root / "governance" / "artifact-manifest.yml") or {}
    budgets = manifest.get("context_budgets")
    required = budgets.get("agent_required_files") if isinstance(budgets, dict) else None
    value = required.get(relative_path) if isinstance(required, dict) else None
    if isinstance(value, int):
        return value, None
    if not isinstance(value, dict):
        return None, None
    line_cap = value.get("line_hard_cap")
    kib_cap = value.get("kib_hard_cap")
    return (
        line_cap if isinstance(line_cap, int) else None,
        kib_cap if isinstance(kib_cap, int) else None,
    )


def _flow_line(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"))


def _budgeted_yaml(repo_root: Path, relative_path: str, payload: dict[str, Any]) -> str:
    line_cap, kib_cap = _context_budget(repo_root, relative_path)
    if relative_path.endswith("phase-history.yml") and isinstance(payload.get("entries"), list):
        lines = [
            f"document: {_flow_line(payload.get('document', {}))}",
            f"retention_policy: {_flow_line(payload.get('retention_policy', {}))}",
            "entries:",
            *[f"- {_flow_line(entry)}" for entry in payload["entries"]],
        ]
        rendered = "\n".join(lines) + "\n"
        if line_cap is not None and len(lines) > line_cap:
            rendered = "\n".join(
                [
                    f"document: {_flow_line(payload.get('document', {}))}",
                    f"retention_policy: {_flow_line(payload.get('retention_policy', {}))}",
                    f"entries: {_flow_line(payload['entries'])}",
                ]
            ) + "\n"
    else:
        rendered = yaml.safe_dump(payload, sort_keys=False, default_flow_style=None, width=4096)
        if line_cap is not None and len(rendered.splitlines()) > line_cap:
            rendered = _flow_line(payload) + "\n"
    if line_cap is not None and len(rendered.splitlines()) > line_cap:
        raise RuntimeError(f"{relative_path} would exceed line budget {line_cap}")
    if kib_cap is not None and len(rendered.encode("utf-8")) > kib_cap * 1024:
        raise RuntimeError(f"{relative_path} would exceed size budget {kib_cap} KiB")
    return rendered


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


def _phase_hotfix_paths(repo_root: Path, phase_id: str) -> list[str]:
    phases_root = repo_root / "phases"
    if not phases_root.exists():
        return []
    pattern = re.compile(rf"{re.escape(_phase_stem(phase_id))}-hotfix\d+\.ya?ml$")
    return [
        f"phases/{path.name}"
        for path in sorted(phases_root.iterdir())
        if path.is_file() and pattern.match(path.name)
    ]


def _phase_retained_artifact_paths(repo_root: Path, phase_id: str) -> list[str]:
    return [*_phase_triplet_paths(phase_id), *_phase_hotfix_paths(repo_root, phase_id)]


def _phase_id_from_retained_artifact_path(relative_path: str) -> str | None:
    match = re.match(
        r"(?:plans|phases)/phase-(\d+)-(?:plan|workitems|log|hotfix\d+)\.ya?ml$",
        relative_path,
    )
    return f"P{int(match.group(1)):02d}" if match else None


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


def _phase_history_entries(repo_root: Path) -> dict[str, dict[str, Any]]:
    history = _load_yaml(repo_root / _phase_history_path(repo_root)) or {}
    entries = history.get("entries")
    if not isinstance(entries, list):
        return {}
    by_phase: dict[str, dict[str, Any]] = {}
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        phase_id = entry.get("phase_id")
        if isinstance(phase_id, str):
            by_phase[phase_id] = entry
    return by_phase


def _phase_status_for_retention(repo_root: Path, phase_id: str) -> str | None:
    log_status = _phase_log_status(repo_root, phase_id)
    if log_status is not None:
        return log_status
    history_entry = _phase_history_entries(repo_root).get(phase_id)
    if not isinstance(history_entry, dict):
        return None
    status = history_entry.get("status")
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


def _is_phase_hotfix_path(relative_path: str) -> bool:
    return re.match(r"phases/phase-\d+-hotfix\d+\.ya?ml$", relative_path) is not None


def _phase_hotfix_ledger_prune_action(
    repo_root: Path, artifact_actions: list[CleanupAction]
) -> CleanupAction | None:
    hotfix_sources = {
        action.source for action in artifact_actions if _is_phase_hotfix_path(action.source)
    }
    if not hotfix_sources:
        return None
    ledger = _load_yaml(repo_root / "plans" / "phase-ledger.yml") or {}
    hotfix_lane = ledger.get("hotfix_lane")
    if not isinstance(hotfix_lane, dict):
        return None
    for key in ("open_records", "remediation_history"):
        records = hotfix_lane.get(key)
        if not isinstance(records, list):
            continue
        if any(isinstance(record, dict) and record.get("hotfix_log") in hotfix_sources for record in records):
            return CleanupAction(
                kind="prune_phase_hotfix_records",
                source="plans/phase-ledger.yml",
                destination=None,
                reason="phase-scoped hotfix lane records move out of active governance with their phase",
                safe_to_apply=True,
            )
    return None


def _phase_retention_actions(
    repo_root: Path,
    *,
    mode: str | None = None,
    truth_reports: dict[str, dict[str, Any]] | None = None,
) -> tuple[list[CleanupAction], list[str]]:
    actions: list[CleanupAction] = []
    warnings: list[str] = []
    retention_mode = _phase_retention_mode(repo_root, mode)
    archive_root = _phase_archive_root(repo_root)
    retained = _retained_phase_ids(repo_root)
    statuses = _closed_phase_statuses(repo_root)
    active_id = _active_phase_id(repo_root)
    active_number = _phase_number(active_id) if active_id else None
    reports = truth_reports or {}

    if retention_mode == "archive":
        ignore_action = _ignore_archive_root_action(repo_root)
        if ignore_action is not None:
            actions.append(ignore_action)

    for phase_id in _build_phase_ids(repo_root):
        if active_number is not None and _phase_number(phase_id) >= active_number:
            continue
        if phase_id in retained:
            continue
        if _phase_status_for_retention(repo_root, phase_id) not in statuses:
            continue
        if phase_id not in reports:
            warnings.append(
                f"phase {phase_id} is completed but cannot be retained without a passing "
                "closed truth report"
            )
            continue
        for source in _phase_retained_artifact_paths(repo_root, phase_id):
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
                        "closed phase artifact is outside the retained phase window "
                        "after compact phase-history is recorded"
                    ),
                    safe_to_apply=True,
                )
            )
    prune_action = _phase_hotfix_ledger_prune_action(repo_root, actions)
    if prune_action is not None:
        actions.append(prune_action)
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


def _verify_truth_bound_sources(
    repo_root: Path,
    actions: list[CleanupAction],
    reports: dict[str, dict[str, Any]],
) -> None:
    for action in actions:
        if action.kind not in {"archive_phase_artifact", "remove_phase_artifact"}:
            continue
        phase_id = _phase_id_from_retained_artifact_path(action.source)
        if phase_id is None:
            continue
        commit_sha = reports[phase_id]["report"]["subject"]["commit_sha"]
        result = subprocess.run(
            ["git", "-C", str(repo_root), "show", f"{commit_sha}:{action.source}"],
            capture_output=True,
            check=False,
        )
        if result.returncode != 0 or _sha256_bytes(result.stdout) != _file_sha256(repo_root / action.source):
            raise RuntimeError(
                f"phase retention requires {action.source} to match its closed truth-report tree"
            )

def _phase_history_entry(
    repo_root: Path,
    phase_id: str,
    *,
    phase_actions: list[CleanupAction],
    mode: str,
    retention_ref: str | None,
    existing_entry: dict[str, Any] | None,
    truth_snapshot: dict[str, Any],
) -> dict[str, Any]:
    plan = _load_yaml(repo_root / f"plans/{_phase_stem(phase_id)}-plan.yml") or {}
    log = _load_yaml(repo_root / f"phases/{_phase_stem(phase_id)}-log.yml") or {}
    product_spec = _load_yaml(repo_root / "plans" / "product-spec.yml") or {}
    build_plan = _load_yaml(repo_root / "plans" / "build-plan.yml") or {}

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
    build_block = phase.get("build_block")
    if not isinstance(build_block, str) or not build_block:
        for entry in build_plan.get("phase_sequence", []) or []:
            if isinstance(entry, dict) and entry.get("phase_id") == phase_id:
                build_block = entry.get("build_block")
                break
    if (not isinstance(release_train, str) or not release_train) and existing_entry is not None:
        release_train = existing_entry.get("release_train")
    if (not isinstance(build_block, str) or not build_block) and existing_entry is not None:
        build_block = existing_entry.get("build_block")

    artifact_entries_by_path: dict[str, dict[str, Any]] = {}
    if existing_entry is not None and isinstance(existing_entry.get("archived_artifacts"), list):
        for artifact in existing_entry["archived_artifacts"]:
            if isinstance(artifact, dict) and isinstance(artifact.get("path"), str):
                artifact_entries_by_path[artifact["path"]] = dict(artifact)
    retained_action_kinds = {"archive_phase_artifact", "remove_phase_artifact"}
    phase_artifact_paths = set(_phase_retained_artifact_paths(repo_root, phase_id))
    for action in phase_actions:
        if action.kind not in retained_action_kinds:
            continue
        if action.source not in phase_artifact_paths:
            continue
        artifact_entry = {
            "path": action.destination or action.source,
            "sha256": _file_sha256(repo_root / action.source),
        }
        if retention_ref is not None:
            artifact_entry["git_commit"] = retention_ref
        artifact_entries_by_path[artifact_entry["path"]] = artifact_entry

    highlights = summary.get("highlights")
    status = document.get("status")
    outcome = summary.get("outcome") or document.get("status")
    validation = execution_evidence.get("executed_commands")
    if existing_entry is not None:
        status = status or existing_entry.get("status")
        outcome = outcome or existing_entry.get("outcome")
        highlights = highlights or existing_entry.get("summary")
        validation = validation or existing_entry.get("validation")
    return {
        "phase_id": phase_id,
        "build_block": str(build_block or ""),
        **({"release_train": release_train} if isinstance(release_train, str) else {}),
        "retention_source": mode,
        **({"retention_ref": retention_ref} if retention_ref is not None else {}),
        "status": "completed",
        "derived_state_at_capture": "closed",
        "verification_snapshot": truth_snapshot,
        "outcome": str(outcome or "completed"),
        "summary": highlights if isinstance(highlights, list) and highlights else ["closed phase retained"],
        "validation": validation if isinstance(validation, list) else [],
        "archived_artifacts": list(artifact_entries_by_path.values()),
    }


def _write_phase_history(
    repo_root: Path,
    phase_actions: list[CleanupAction],
    *,
    mode: str | None = None,
    truth_reports: dict[str, dict[str, Any]] | None = None,
) -> str | None:
    retention_mode = _phase_retention_mode(repo_root, mode)
    retained_action_kinds = {"archive_phase_artifact", "remove_phase_artifact"}
    phase_ids = sorted(
        {
            phase_id
            for action in phase_actions
            if action.kind in retained_action_kinds
            for phase_id in [_phase_id_from_retained_artifact_path(action.source)]
            if phase_id is not None
        },
        key=_phase_number,
    )
    if not phase_ids:
        return None
    reports = truth_reports or {}
    missing_reports = sorted(set(phase_ids) - set(reports))
    if missing_reports:
        raise RuntimeError(
            "phase history requires passing closed truth reports for: "
            + ", ".join(missing_reports)
        )
    _verify_truth_bound_sources(repo_root, phase_actions, reports)

    retention_ref = _git_head(repo_root) if retention_mode == "git_history" else None
    if retention_ref is not None:
        _verify_git_history_sources(repo_root, phase_actions, retention_ref)
        stale_reports = sorted(
            phase_id
            for phase_id in phase_ids
            if reports[phase_id]["report"]["subject"]["commit_sha"] != retention_ref
        )
        if stale_reports:
            raise RuntimeError(
                "git-history phase retention requires truth reports captured at HEAD for: "
                + ", ".join(stale_reports)
            )

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
    existing_entries = {
        entry.get("phase_id"): entry
        for entry in entries
        if isinstance(entry, dict) and isinstance(entry.get("phase_id"), str)
    }
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
            existing_entry=existing_entries.get(phase_id),
            truth_snapshot=reports[phase_id]["verification_snapshot"],
        )
        for phase_id in phase_ids
    )
    history["entries"] = sorted(
        retained_entries,
        key=lambda entry: _phase_number(str(entry.get("phase_id", "P0"))) if isinstance(entry, dict) else 0,
    )
    history_path.parent.mkdir(parents=True, exist_ok=True)
    history_path.write_text(_budgeted_yaml(repo_root, history_rel, history), encoding="utf-8")
    return history_rel


def _prune_phase_hotfix_records(repo_root: Path, phase_actions: list[CleanupAction]) -> str | None:
    hotfix_sources = {
        action.source for action in phase_actions if _is_phase_hotfix_path(action.source)
    }
    if not hotfix_sources:
        return None
    ledger_path = repo_root / "plans" / "phase-ledger.yml"
    ledger = _load_yaml(ledger_path)
    if ledger is None:
        return None
    hotfix_lane = ledger.get("hotfix_lane")
    if not isinstance(hotfix_lane, dict):
        return None
    changed = False
    for key in ("open_records", "remediation_history"):
        records = hotfix_lane.get(key)
        if not isinstance(records, list):
            continue
        retained = [
            record
            for record in records
            if not (isinstance(record, dict) and record.get("hotfix_log") in hotfix_sources)
        ]
        if len(retained) != len(records):
            hotfix_lane[key] = retained
            changed = True
    if not changed:
        return None
    ledger_path.write_text(
        _budgeted_yaml(repo_root, "plans/phase-ledger.yml", ledger), encoding="utf-8"
    )
    return "plans/phase-ledger.yml"


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


def _phase_archive_actions(
    repo_root: Path,
    *,
    truth_reports: dict[str, dict[str, Any]] | None = None,
) -> tuple[list[CleanupAction], list[str]]:
    return _phase_retention_actions(repo_root, mode="archive", truth_reports=truth_reports)


phase_archive_actions = _phase_archive_actions
phase_retention_actions = _phase_retention_actions
write_phase_history = _write_phase_history
write_archive_gitignore = _write_archive_gitignore
set_phase_retention_mode = _set_phase_retention_mode
prune_phase_hotfix_records = _prune_phase_hotfix_records

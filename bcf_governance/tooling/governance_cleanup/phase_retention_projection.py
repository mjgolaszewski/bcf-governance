"""Project phase-history retention into active roadmaps and hotfix state."""

from __future__ import annotations

from pathlib import Path

from .models import CleanupAction
from .phase_retention import (
    _budgeted_yaml,
    _is_phase_hotfix_path,
    _load_yaml,
    _phase_history_entries,
    _phase_id_from_retained_artifact_path,
    _phase_number,
)


def compact_phase_roadmaps(
    repo_root: Path,
    phase_actions: list[CleanupAction],
) -> list[str]:
    """Remove history-custodied phases from both active roadmap projections."""

    compacted_phase_ids = {
        phase_id
        for action in phase_actions
        if action.kind in {"archive_phase_artifact", "remove_phase_artifact"}
        for phase_id in [_phase_id_from_retained_artifact_path(action.source)]
        if phase_id is not None
    }
    if not compacted_phase_ids:
        return []
    history_entries = _phase_history_entries(repo_root)
    if not compacted_phase_ids.issubset(history_entries):
        raise RuntimeError(
            "phase roadmaps cannot compact before every selected phase is in phase history"
        )
    through_phase = max(history_entries, key=_phase_number)
    rewritten: list[str] = []
    for relative_path, sequence_key in (
        ("plans/build-plan.yml", "phase_sequence"),
        ("plans/product-spec.yml", "execution_phases"),
    ):
        path = repo_root / relative_path
        payload = _load_yaml(path) or {}
        sequence = payload.get(sequence_key)
        if not isinstance(sequence, list):
            raise RuntimeError(f"{relative_path} must declare {sequence_key}")
        payload[sequence_key] = [
            entry
            for entry in sequence
            if not (
                isinstance(entry, dict)
                and str(entry.get("phase_id")) in compacted_phase_ids
            )
        ]
        history_owner = payload.get("phase_history")
        if history_owner is not None:
            if not isinstance(history_owner, dict):
                raise RuntimeError(f"{relative_path} phase_history must be a mapping")
            history_owner["through_phase"] = through_phase
        path.write_text(
            _budgeted_yaml(repo_root, relative_path, payload), encoding="utf-8"
        )
        rewritten.append(relative_path)
    return rewritten


def prune_phase_hotfix_records(
    repo_root: Path, phase_actions: list[CleanupAction]
) -> str | None:
    """Remove live ledger references after their hotfix logs gain Git custody."""

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
            if not (
                isinstance(record, dict)
                and record.get("hotfix_log") in hotfix_sources
            )
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

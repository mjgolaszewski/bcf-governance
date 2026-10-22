from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from bcf_governance.tooling.operational_observations import (
    OperationalObservationError,
    amplification_observation,
    lifecycle_projection,
    progress_event,
    provider_queue_observation,
    validate_operational_observation,
    validate_progress_stream,
)


def test_progress_is_exact_ordered_and_non_authoritative() -> None:
    events = [
        progress_event(execution_id="train-1", sequence=1, stage="preflight", state="started", monotonic_ms=1),
        progress_event(execution_id="train-1", sequence=2, stage="preflight", state="complete", monotonic_ms=2),
    ]
    validate_progress_stream(events)
    assert all(item["authority"] is False for item in events)
    with pytest.raises(OperationalObservationError, match="out of order"):
        validate_progress_stream([events[1], events[0]])


def test_provider_queue_keeps_absent_timestamps_unknown() -> None:
    report = provider_queue_observation(
        repository="owner/repo",
        run_id=7,
        run_attempt=2,
        job={"id": 9, "created_at": "2026-01-01T00:00:00Z", "labels": ["X64", "self-hosted"]},
    )
    assert report["provider_queue_ms"] == "unknown"
    assert report["execution_ms"] == "unknown"
    assert report["authority"] is False


def test_amplification_rejects_duplicate_events() -> None:
    event = {"event_id": "job-1", "kind": "jobs", "duration_ms": 20}
    with pytest.raises(OperationalObservationError, match="duplicated"):
        amplification_observation(
            train_id="P29", commit_sha="a" * 40, tree_sha="b" * 40, events=[event, event]
        )


def test_lifecycle_projection_derives_frontier(tmp_path: Path) -> None:
    (tmp_path / "plans").mkdir()
    (tmp_path / "plans/phase-ledger.yml").write_text(
        yaml.safe_dump({"active_phase": {"id": "P29", "workitems": "plans/items.yml"}}), encoding="utf-8"
    )
    (tmp_path / "plans/items.yml").write_text(
        yaml.safe_dump({"workitems": [
            {"id": "P29-P0-01", "status": "DONE"},
            {"id": "P29-P0-02", "status": "IN_PROGRESS"},
            {"id": "P29-P0-03", "status": "TODO"},
        ]}), encoding="utf-8"
    )
    assert lifecycle_projection(tmp_path) == {
        "schema_version": "1.0",
        "kind": "lifecycle_projection",
        "authority": "lifecycle",
        "phase_id": "P29",
        "completed_prefix": ["P29-P0-01"],
        "predecessor": "P29-P0-01",
        "current": "P29-P0-02",
        "successor": "P29-P0-03",
        "history_owner": "plans/phase-history.yml",
    }


def test_repository_operational_schema_accepts_each_observation() -> None:
    root = Path(__file__).resolve().parents[1]
    progress = progress_event(
        execution_id="run", sequence=1, stage="preflight", state="complete", monotonic_ms=2
    )
    queue = provider_queue_observation(
        repository="owner/repo", run_id=1, run_attempt=1, job={"id": 2, "labels": []}
    )
    amplification = amplification_observation(
        train_id="P29", commit_sha="a" * 40, tree_sha="b" * 40, events=[]
    )
    for value in (progress, queue, amplification):
        validate_operational_observation(root, value)

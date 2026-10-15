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


@pytest.fixture
def timing_inputs():
    return dict(
        repository='owner/repo', repository_id=17, source_snapshot_sha256='c' * 64,
        commit_sha='a' * 40, tree_sha='b' * 40, pipeline='pr',
        clock_id='provider:run-1:attempt-1', clock_basis='provider_utc_ms',
        start_ms=0, end_ms=10,
        intervals=[
            dict(id='job-1', clock_id='provider:run-1:attempt-1', kind='execution', status='passed', start_ms=0, end_ms=10),
            dict(id='job-2', clock_id='provider:run-1:attempt-1', kind='execution', status='failed', start_ms=0, end_ms=10),
        ],
    )


def _timing(inputs):
    from bcf_governance.tooling.operational_observations import pipeline_timing_observation

    return pipeline_timing_observation(**inputs)


def test_pipeline_timing_keeps_parallel_elapsed_separate_from_sum_and_cpu(timing_inputs):
    result = _timing(timing_inputs)
    assert result['elapsed_ms'] == 10
    assert result['execution_union_ms'] == 10
    assert result['execution_sum_ms'] == 20
    assert result['external_wait_union_ms'] == 0
    assert result['uncovered_ms'] == 0
    assert result['cpu_ms'] == 'unknown'
    assert {row['status'] for row in result['intervals']} == {'passed', 'failed'}
    assert result['authority'] is False


def test_pipeline_timing_retains_waits_gaps_cancellation_and_supersession(timing_inputs):
    timing_inputs['end_ms'] = 50
    timing_inputs['intervals'] += [
        dict(id='wait', clock_id=timing_inputs['clock_id'], kind='external_wait', status='completed', start_ms=15, end_ms=30),
        dict(id='cancelled', clock_id=timing_inputs['clock_id'], kind='execution', status='cancelled', start_ms=20, end_ms=25),
        dict(id='superseded', clock_id=timing_inputs['clock_id'], kind='execution', status='superseded', start_ms=35, end_ms=40),
    ]
    result = _timing(timing_inputs)
    assert result['elapsed_ms'] == 50
    assert result['execution_union_ms'] == 20
    assert result['execution_sum_ms'] == 30
    assert result['external_wait_union_ms'] == 15
    assert result['uncovered_ms'] == 20
    assert len(result['intervals']) == 5


def test_pipeline_timing_only_reports_cpu_when_every_execution_is_observed(timing_inputs):
    timing_inputs['intervals'][0]['cpu_ms'] = 7
    assert _timing(timing_inputs)['cpu_ms'] == 'unknown'
    timing_inputs['intervals'][1]['cpu_ms'] = 12
    assert _timing(timing_inputs)['cpu_ms'] == 19


@pytest.mark.parametrize('defect', ['mixed_clock', 'duplicate', 'outside', 'reversed', 'boolean_time', 'negative_cpu', 'boolean_cpu'])
def test_pipeline_timing_rejects_ambiguous_or_invalid_intervals(timing_inputs, defect):
    row = timing_inputs['intervals'][0]
    if defect == 'mixed_clock':
        row['clock_id'] = 'another-origin'
    elif defect == 'duplicate':
        timing_inputs['intervals'].append(dict(row))
    elif defect == 'outside':
        row['end_ms'] = 11
    elif defect == 'reversed':
        row['start_ms'], row['end_ms'] = 8, 2
    elif defect == 'boolean_time':
        row['start_ms'] = False
    elif defect == 'negative_cpu':
        row['cpu_ms'] = -1
    else:
        row['cpu_ms'] = True
    with pytest.raises(OperationalObservationError):
        _timing(timing_inputs)


@pytest.mark.parametrize('field,value', [('start_ms', -1), ('end_ms', False), ('pipeline', 'combined-everything'), ('clock_basis', 'estimated')])
def test_pipeline_timing_rejects_invalid_window_or_context(timing_inputs, field, value):
    timing_inputs[field] = value
    with pytest.raises(OperationalObservationError):
        _timing(timing_inputs)


def test_pipeline_timing_is_deterministic_detached_and_schema_valid(timing_inputs):
    first = _timing(timing_inputs)
    timing_inputs['intervals'].reverse()
    assert _timing(timing_inputs) == first
    validate_operational_observation(Path(__file__).resolve().parents[1], first)
    timing_inputs['intervals'][0]['status'] = 'cancelled'
    assert first['intervals'][1]['status'] == 'failed'


def test_pipeline_timing_empty_population_preserves_unobserved_span(timing_inputs):
    timing_inputs['intervals'] = []
    result = _timing(timing_inputs)
    assert result['uncovered_ms'] == 10
    assert result['cpu_ms'] == 'unknown'


@pytest.mark.parametrize('defect', ['missing_time', 'unknown_kind', 'unknown_status', 'unknown_field'])
def test_pipeline_timing_rejects_uninterpretable_interval_shape(timing_inputs, defect):
    row = timing_inputs['intervals'][0]
    if defect == 'missing_time':
        del row['start_ms']
    elif defect == 'unknown_kind':
        row['kind'] = 'estimated_work'
    elif defect == 'unknown_status':
        row['status'] = 'probably_passed'
    else:
        row['authority'] = True
    with pytest.raises(OperationalObservationError):
        _timing(timing_inputs)


def test_pipeline_timing_preserves_skipped_without_manufacturing_success(timing_inputs):
    timing_inputs['intervals'][0].update(status='skipped', end_ms=0)
    result = _timing(timing_inputs)
    assert result['intervals'][0]['status'] == 'skipped'
    assert result['execution_sum_ms'] == 10
    validate_operational_observation(Path(__file__).resolve().parents[1], result)


def test_pipeline_timing_rejects_wrong_subject_and_reversed_window(timing_inputs):
    timing_inputs['commit_sha'] = 'not-a-subject'
    with pytest.raises(OperationalObservationError, match='subject'):
        _timing(timing_inputs)
    timing_inputs['commit_sha'] = 'a' * 40
    timing_inputs['start_ms'], timing_inputs['end_ms'] = 10, 0
    with pytest.raises(OperationalObservationError, match='window'):
        _timing(timing_inputs)


@pytest.mark.parametrize('field,value', [('repository', 'unbound'), ('repository_id', True), ('source_snapshot_sha256', 'missing')])
def test_pipeline_timing_rejects_unbound_repository_or_snapshot(timing_inputs, field, value):
    timing_inputs[field] = value
    with pytest.raises(OperationalObservationError, match='identity'):
        _timing(timing_inputs)


def test_retained_provider_capture_has_exact_snapshot_binding_and_honest_clocks():
    import hashlib
    import json

    from bcf_governance.tooling.operational_observations import pipeline_timing_observation

    root = Path(__file__).resolve().parents[1]
    capture = json.loads((root / 'audits/issue-394/observations/pr-421-attempt-1.json').read_text())
    source = capture['source_snapshot']
    value = capture['observation']
    assert capture['capture_policy']['matched_cohort'] is False
    assert capture['capture_policy']['percentile_certification'] is False
    digest = hashlib.sha256(json.dumps(source, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()).hexdigest()
    assert value['source_snapshot_sha256'] == digest
    assert value['repository_id'] == source['repository']['id']
    assert value['subject'] == {'commit_sha': source['commit']['sha'], 'tree_sha': source['commit']['tree_sha']}
    assert {row['id'] for row in value['intervals']} == {str(row['id']) for row in source['jobs']['jobs']}
    assert len(value['intervals']) == source['jobs']['total_count']
    fields = ['repository', 'repository_id', 'source_snapshot_sha256', 'pipeline', 'clock_id', 'clock_basis', 'start_ms', 'end_ms', 'intervals']
    assert pipeline_timing_observation(**{field: value[field] for field in fields}, **value['subject']) == value
    validate_operational_observation(root, value)
    assert value['elapsed_ms'] != value['execution_sum_ms']
    assert value['cpu_ms'] == 'unknown'

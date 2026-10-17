"""Keep actual prospective event semantics while moving progress ownership."""

from pathlib import Path

import pytest

from bcf_governance.tooling import local_pr as prospective
from bcf_governance.tooling.operational_observations import (
    validate_operational_observation, validate_progress_stream,
)
from tests.test_prospective_validation import (
    REPO_ROOT, TRAIN, _authored_target_ready, _front_door, _runner,  # noqa: F401
)


def _prepare(monkeypatch):
    _front_door(monkeypatch, [])
    monkeypatch.setattr(prospective, "run_preflight", lambda *a, **kw: {
        "status": "pass", "self_controller": None,
    })


def _run(root, sink):
    return prospective._run_prospective_train(
        root, **TRAIN, python_executable=Path("/python"),
        execute_evidence=False, runner=_runner, progress_sink=sink,
    )


def test_actual_progress_validates_each_event_before_delivering_same_object(tmp_path, monkeypatch):
    _prepare(monkeypatch)
    validated = []
    delivered = []
    order = []
    def validate(root, event):
        assert root == tmp_path
        validate_operational_observation(REPO_ROOT, event)
        validated.append(event)
        order.append(("validate", event["sequence"]))
    def sink(event):
        assert order[-1] == ("validate", event["sequence"])
        assert event is validated[-1]
        delivered.append(event)
        order.append(("sink", event["sequence"]))
    monkeypatch.setattr(prospective, "validate_operational_observation", validate)
    report = _run(tmp_path, sink)
    assert report["status"] == "deterministic_front_door_pass"
    assert validated == delivered and delivered
    validate_progress_stream(delivered)
    assert all(event["authority"] is False for event in delivered)


def test_actual_progress_retains_failed_stage_and_original_failure(tmp_path, monkeypatch):
    _prepare(monkeypatch)
    error = prospective.PreflightError("exact exposure failure")
    def reject(root):
        raise error
    monkeypatch.setattr(prospective, "_exposure_scan", reject)
    events = []
    with pytest.raises(prospective.ProspectiveValidationError) as caught:
        _run(tmp_path, events.append)
    assert caught.value.__cause__ is error
    assert [(event["stage"], event["state"]) for event in events[-2:]] == [
        ("exposure", "started"), ("exposure", "failed"),
    ]
    validate_progress_stream(events)


def test_actual_progress_validator_failure_prevents_sink_delivery(tmp_path, monkeypatch):
    _prepare(monkeypatch)
    error = RuntimeError("validator failed")
    def reject(root, event):
        raise error
    monkeypatch.setattr(prospective, "validate_operational_observation", reject)
    events = []
    with pytest.raises(RuntimeError) as caught:
        _run(tmp_path, events.append)
    assert caught.value is error and events == []


def test_actual_progress_sink_failure_preserves_exception_identity(tmp_path, monkeypatch):
    _prepare(monkeypatch)
    error = RuntimeError("sink failed")
    seen = []
    def reject(event):
        seen.append(event)
        raise error
    with pytest.raises(RuntimeError) as caught:
        _run(tmp_path, reject)
    assert caught.value is error and len(seen) == 1
    assert seen[0]["sequence"] == 1 and seen[0]["state"] == "started"


def test_actual_progress_without_sink_still_validates_events(tmp_path, monkeypatch):
    _prepare(monkeypatch)
    events = []
    monkeypatch.setattr(prospective, "validate_operational_observation", lambda root, event: events.append(event))
    _run(tmp_path, None)
    assert events
    validate_progress_stream(events)

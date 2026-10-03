"""Non-authoritative operational observations and derived lifecycle projection."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
import re
from typing import Any, Iterable, Mapping

import yaml  # type: ignore[import-untyped]
from jsonschema import Draft202012Validator

from .evidence_workitem_lifecycle import (
    WorkitemContractError,
    validate_workitem_dependencies,
)


_SHA = re.compile(r"^[a-f0-9]{40}$")
_TERMINAL = frozenset({"complete", "failed"})


class OperationalObservationError(ValueError):
    """Operational data is ambiguous, duplicated, or falsely authoritative."""


@dataclass(frozen=True)
class ProgressEvent:
    execution_id: str
    sequence: int
    stage: str
    state: str
    monotonic_ms: int

    def as_dict(self) -> dict[str, Any]:
        return {
            "schema_version": "1.0",
            "kind": "prospective_progress",
            "authority": False,
            "execution_id": self.execution_id,
            "sequence": self.sequence,
            "stage": self.stage,
            "state": self.state,
            "monotonic_ms": self.monotonic_ms,
        }


def progress_event(
    *, execution_id: str, sequence: int, stage: str, state: str, monotonic_ms: int
) -> dict[str, Any]:
    if not execution_id or not stage or state not in {"started", *_TERMINAL}:
        raise OperationalObservationError("progress event identity or state is invalid")
    if sequence < 1 or monotonic_ms < 0:
        raise OperationalObservationError("progress ordering is invalid")
    return ProgressEvent(execution_id, sequence, stage, state, monotonic_ms).as_dict()


def validate_progress_stream(events: Iterable[Mapping[str, Any]]) -> None:
    values = list(events)
    if not values:
        raise OperationalObservationError("progress stream is empty")
    execution_ids = {item.get("execution_id") for item in values}
    if len(execution_ids) != 1 or None in execution_ids:
        raise OperationalObservationError("progress stream execution identity is not exact")
    sequences = [item.get("sequence") for item in values]
    if sequences != list(range(1, len(values) + 1)):
        raise OperationalObservationError("progress stream is duplicated or out of order")
    clocks = [item.get("monotonic_ms") for item in values]
    if any(not isinstance(value, int) for value in clocks) or clocks != sorted(clocks):
        raise OperationalObservationError("progress stream clock is not monotonic")
    if any(item.get("authority") is not False for item in values):
        raise OperationalObservationError("operational progress cannot carry authority")


def _timestamp(value: object) -> datetime | None:
    if not isinstance(value, str) or not value:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed.astimezone(timezone.utc)


def _latency(start: datetime | None, end: datetime | None) -> int | str:
    if start is None or end is None or end < start:
        return "unknown"
    return int((end - start).total_seconds() * 1000)


def provider_queue_observation(
    *, repository: str, run_id: int, run_attempt: int, job: Mapping[str, Any]
) -> dict[str, Any]:
    if "/" not in repository or run_id < 1 or run_attempt < 1:
        raise OperationalObservationError("provider execution identity is invalid")
    created = _timestamp(job.get("created_at"))
    started = _timestamp(job.get("started_at"))
    completed = _timestamp(job.get("completed_at"))
    return {
        "schema_version": "1.0",
        "kind": "provider_queue",
        "authority": False,
        "repository": repository,
        "run_id": run_id,
        "run_attempt": run_attempt,
        "job_id": job.get("id") if isinstance(job.get("id"), int) else "unknown",
        "runner_labels": sorted(
            value for value in job.get("labels", []) if isinstance(value, str)
        ),
        "provider_queue_ms": _latency(created, started),
        "execution_ms": _latency(started, completed),
    }


def amplification_observation(
    *, train_id: str, commit_sha: str, tree_sha: str, events: Iterable[Mapping[str, Any]]
) -> dict[str, Any]:
    if not train_id or _SHA.fullmatch(commit_sha) is None or _SHA.fullmatch(tree_sha) is None:
        raise OperationalObservationError("amplification subject is invalid")
    values = list(events)
    identities = [str(item.get("event_id", "")) for item in values]
    if any(not value for value in identities) or len(identities) != len(set(identities)):
        raise OperationalObservationError("amplification events are missing or duplicated")
    kinds = ("commits", "pull_requests", "jobs", "controller_transitions", "human_interventions")
    counters = {kind: 0 for kind in kinds}
    wall_clock_ms = 0
    compute_ms = 0
    for item in values:
        kind = item.get("kind")
        if kind not in counters:
            raise OperationalObservationError("amplification event kind is unsupported")
        counters[str(kind)] += 1
        duration = item.get("duration_ms", 0)
        if not isinstance(duration, int) or duration < 0:
            raise OperationalObservationError("amplification duration is invalid")
        wall_clock_ms += duration
        if kind == "jobs":
            compute_ms += duration
    return {
        "schema_version": "1.0",
        "kind": "governance_amplification",
        "authority": False,
        "train_id": train_id,
        "subject": {"commit_sha": commit_sha, "tree_sha": tree_sha},
        "counters": counters,
        "wall_clock_ms": wall_clock_ms,
        "compute_ms": compute_ms,
    }


def lifecycle_projection(repo_root: Path) -> dict[str, Any]:
    """Derive current workitem frontier and retained predecessor from canonical state."""

    ledger = yaml.safe_load((repo_root / "plans/phase-ledger.yml").read_text(encoding="utf-8"))
    active = ledger.get("active_phase") if isinstance(ledger, dict) else None
    if not isinstance(active, dict):
        raise OperationalObservationError("active phase is missing")
    phase_id = active.get("id")
    workitems_path = active.get("workitems")
    if not isinstance(phase_id, str) or not isinstance(workitems_path, str):
        raise OperationalObservationError("active phase identity is incomplete")
    payload = yaml.safe_load((repo_root / workitems_path).read_text(encoding="utf-8"))
    workitems = payload.get("workitems") if isinstance(payload, dict) else None
    if not isinstance(workitems, list) or not workitems:
        raise OperationalObservationError("active workitem inventory is empty")
    if not all(isinstance(item, dict) for item in workitems):
        raise OperationalObservationError("active workitem inventory is invalid")
    try:
        validate_workitem_dependencies(workitems)
    except WorkitemContractError as exc:
        raise OperationalObservationError(str(exc)) from exc
    ids = [item.get("id") for item in workitems if isinstance(item, dict)]
    if len(ids) != len(workitems) or any(not isinstance(value, str) for value in ids):
        raise OperationalObservationError("active workitem identity is invalid")
    done: list[str] = []
    for item in workitems:
        if item.get("status") != "DONE":
            break
        done.append(str(item["id"]))
    current = next(
        (str(item["id"]) for item in workitems if isinstance(item, dict) and item.get("status") != "DONE"),
        None,
    )
    current_index = ids.index(current) if current is not None else len(ids)
    return {
        "schema_version": "1.0",
        "kind": "lifecycle_projection",
        "authority": "lifecycle",
        "phase_id": phase_id,
        "completed_prefix": done,
        "predecessor": ids[current_index - 1] if current_index else None,
        "current": current,
        "successor": ids[current_index + 1] if current is not None and current_index + 1 < len(ids) else None,
        "history_owner": "plans/phase-history.yml",
    }


def validate_operational_observation(
    repo_root: Path, observation: Mapping[str, Any]
) -> None:
    schema = __import__("json").loads(
        (repo_root / "schemas/operational-observation.schema.json").read_text(
            encoding="utf-8"
        )
    )
    errors = sorted(
        Draft202012Validator(schema).iter_errors(dict(observation)),
        key=lambda item: list(item.path),
    )
    if errors:
        raise OperationalObservationError(
            "operational observation is invalid: " + errors[0].message
        )

"""Non-authoritative operational observations and derived lifecycle projection."""

from __future__ import annotations

import hashlib
import json

from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
import re
from typing import Any, Iterable, Mapping

from jsonschema import Draft202012Validator

from .evidence_workitem_lifecycle import (
    WorkitemContractError, _authored_yaml,
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
    kind: str = "prospective_progress"

    def as_dict(self) -> dict[str, Any]:
        return {
            "schema_version": "1.0",
            "kind": self.kind,
            "authority": False,
            "execution_id": self.execution_id,
            "sequence": self.sequence,
            "stage": self.stage,
            "state": self.state,
            "monotonic_ms": self.monotonic_ms,
        }


def progress_event(
    *, execution_id: str, sequence: int, stage: str, state: str, monotonic_ms: int,
    kind: str = "prospective_progress",
) -> dict[str, Any]:
    if kind not in {"prospective_progress", "submission_progress"}:
        raise OperationalObservationError("progress event kind is invalid")
    if not execution_id or not stage or state not in {"started", *_TERMINAL}:
        raise OperationalObservationError("progress event identity or state is invalid")
    if sequence < 1 or monotonic_ms < 0:
        raise OperationalObservationError("progress ordering is invalid")
    return ProgressEvent(execution_id, sequence, stage, state, monotonic_ms, kind).as_dict()


def validate_progress_stream(events: Iterable[Mapping[str, Any]]) -> None:
    values = list(events)
    if not values:
        raise OperationalObservationError("progress stream is empty")
    kinds = {item.get("kind") for item in values}
    if len(kinds) != 1 or not kinds <= {"prospective_progress", "submission_progress"}:
        raise OperationalObservationError("progress stream kind is not exact")
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
        if parsed.tzinfo is None:
            return None
        return parsed.astimezone(timezone.utc)
    except (ValueError, OverflowError):
        return None


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


PIPELINE_CLOCKS = frozenset({
    "pr", "exact_main", "controller", "release", "adopter",
    "publication_to_custody", "dispatch_to_custody", "merge_to_custody",
    "periodic", "developer_interruption",
})


def _timing_milliseconds(value: object) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise OperationalObservationError("pipeline timing requires nonnegative integer milliseconds")
    return value


def _interval_union_ms(intervals: list[dict[str, Any]]) -> int:
    total = 0
    current_end = 0
    for start, end in sorted((row["start_ms"], row["end_ms"]) for row in intervals):
        total += max(0, end - max(start, current_end))
        current_end = max(current_end, end)
    return total


def pipeline_timing_observation(
    *, repository: str, repository_id: int, source_snapshot_sha256: str,
    commit_sha: str, tree_sha: str, pipeline: str,
    clock_id: str, clock_basis: str, start_ms: int, end_ms: int,
    intervals: Iterable[Mapping[str, Any]],
) -> dict[str, Any]:
    """Measure one observed pipeline window without summing parallel wall time.

    The caller authenticates snapshots and supplies one explicit clock domain.
    Missing execution intervals remain uncovered time, never fabricated zero-cost
    work. Execution and wait unions may overlap and must not be added together.
    CPU is independently observed, not estimated from job elapsed time.
    This opt-in observation neither changes legacy reports nor confers authority.
    """

    if re.fullmatch(r"[^/\s]+/[^/\s]+", repository) is None or (
        isinstance(repository_id, bool) or not isinstance(repository_id, int) or repository_id < 1
    ):
        raise OperationalObservationError("pipeline timing repository identity is invalid")
    if re.fullmatch(r"[a-f0-9]{64}", source_snapshot_sha256) is None:
        raise OperationalObservationError("pipeline timing source snapshot identity is invalid")
    if _SHA.fullmatch(commit_sha) is None or _SHA.fullmatch(tree_sha) is None:
        raise OperationalObservationError("pipeline timing subject identity is invalid")
    if pipeline not in PIPELINE_CLOCKS or clock_basis not in {"provider_utc_ms", "monotonic_ms"}:
        raise OperationalObservationError("pipeline timing context or clock basis is invalid")
    if not isinstance(clock_id, str) or not clock_id:
        raise OperationalObservationError("pipeline timing clock identity is invalid")
    start_ms, end_ms = _timing_milliseconds(start_ms), _timing_milliseconds(end_ms)
    if end_ms < start_ms:
        raise OperationalObservationError("pipeline timing window is reversed")
    rows: dict[str, dict[str, Any]] = {}
    required = {"id", "clock_id", "kind", "status", "start_ms", "end_ms"}
    for value in intervals:
        row = dict(value)
        if not required.issubset(row) or set(row) - required - {"cpu_ms"}:
            raise OperationalObservationError("pipeline timing interval fields are incomplete or unknown")
        identity = row["id"]
        if not isinstance(identity, str) or not identity or identity in rows:
            raise OperationalObservationError("pipeline timing interval identity is absent or duplicated")
        if row["clock_id"] != clock_id:
            raise OperationalObservationError("pipeline timing interval mixes clock identities")
        if row["kind"] not in {"execution", "external_wait"}:
            raise OperationalObservationError("pipeline timing interval kind is invalid")
        statuses = {"passed", "failed", "cancelled", "superseded", "skipped"}
        if row["kind"] == "external_wait":
            statuses = {"completed", "failed", "cancelled", "superseded"}
        if row["status"] not in statuses:
            raise OperationalObservationError("pipeline timing interval status is invalid")
        left = _timing_milliseconds(row["start_ms"])
        right = _timing_milliseconds(row["end_ms"])
        if not start_ms <= left <= right <= end_ms:
            raise OperationalObservationError("pipeline timing interval is reversed or outside its window")
        if "cpu_ms" in row:
            _timing_milliseconds(row["cpu_ms"])
            if row["kind"] != "execution":
                raise OperationalObservationError("pipeline timing external wait cannot supply execution CPU")
        rows[identity] = row
    ordered = [rows[key] for key in sorted(rows)]
    executions = [row for row in ordered if row["kind"] == "execution"]
    waits = [row for row in ordered if row["kind"] == "external_wait"]
    cpu: int | str = "unknown"
    if executions and all("cpu_ms" in row for row in executions):
        cpu = sum(row["cpu_ms"] for row in executions)
    return {
        "schema_version": "1.0", "kind": "pipeline_timing", "authority": False,
        "subject": {"commit_sha": commit_sha, "tree_sha": tree_sha},
        "repository": repository, "repository_id": repository_id,
        "source_snapshot_sha256": source_snapshot_sha256,
        "pipeline": pipeline, "clock_id": clock_id, "clock_basis": clock_basis,
        "start_ms": start_ms, "end_ms": end_ms, "elapsed_ms": end_ms - start_ms,
        "execution_union_ms": _interval_union_ms(executions),
        "execution_sum_ms": sum(row["end_ms"] - row["start_ms"] for row in executions),
        "external_wait_union_ms": _interval_union_ms(waits),
        "uncovered_ms": end_ms - start_ms - _interval_union_ms(ordered),
        "cpu_ms": cpu, "intervals": ordered,
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

    def authored(path: Path) -> dict[str, Any]:
        try:
            return _authored_yaml(path)
        except WorkitemContractError as exc:
            raise OperationalObservationError(str(exc)) from exc

    ledger = authored(repo_root / "plans/phase-ledger.yml")
    active = ledger.get("active_phase") if isinstance(ledger, dict) else None
    if not isinstance(active, dict):
        raise OperationalObservationError("active phase is missing")
    phase_id = active.get("id")
    workitems_path = active.get("workitems")
    if not isinstance(phase_id, str) or not isinstance(workitems_path, str):
        raise OperationalObservationError("active phase identity is incomplete")
    payload = authored(repo_root / workitems_path)
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


def provider_attempt_timing_observation(
    source_snapshot: Mapping[str, Any], *, expected_run_id: int,
    expected_attempt: int, pipeline: str, expected_event: str | None = None,
) -> dict[str, Any]:
    """Project retained provider facts; caller authenticates capture and endpoint.

    This checks snapshot conformance, not provider custody or job-attempt origin.
    The caller must bind the complete job response to its exact attempt endpoint.
    Missing, unsupported or ambiguous facts cannot become timing certification.
    Context intent requires protected workflow policy; an event alone does not
    distinguish controller, exact-main, release, adopter or periodic work.
    """
    def reject(message: str) -> None:
        raise OperationalObservationError("provider timing snapshot " + message)

    def milliseconds(value: Any) -> int:
        parsed = _timestamp(value)
        if parsed is None or parsed.microsecond % 1000:
            reject("timestamp is absent or outside the qualified clock")
        delta = parsed - datetime(1970, 1, 1, tzinfo=timezone.utc)
        return delta.days * 86400000 + delta.seconds * 1000 + delta.microseconds // 1000

    if any(type(value) is not int or value < 1 for value in (expected_run_id, expected_attempt)):
        reject("expected attempt identity is invalid")
    try:
        repository, run, commit, population = (
            source_snapshot[key] for key in ("repository", "run", "commit", "jobs")
        )
        if any(not isinstance(value, Mapping) for value in (repository, run, commit, population)):
            reject("record population is malformed")
        if (type(run["id"]) is not int or run["id"] != expected_run_id
                or type(run["run_attempt"]) is not int or run["run_attempt"] != expected_attempt
                or run["head_sha"] != commit["sha"] or run["status"] != "completed"):
            reject("run attempt or subject is unbound or nonterminal")
        if pipeline not in PIPELINE_CLOCKS or pipeline in {
            "publication_to_custody", "dispatch_to_custody", "merge_to_custody", "developer_interruption",
        }:
            reject("workflow context requires unobserved clock endpoints")
        event = run.get("event")
        if (not isinstance(event, str) or not event.strip()
                or (expected_event is not None and (not isinstance(expected_event, str)
                    or not expected_event.strip() or event != expected_event))):
            reject("workflow context contradicts provider event identity")
        jobs = population["jobs"]
        if (not isinstance(jobs, list) or type(population["total_count"]) is not int
                or population["total_count"] != len(jobs)):
            reject("job population is incomplete")
        clock = f"github:{repository['id']}:run:{expected_run_id}:attempt:{expected_attempt}"
        start = milliseconds(run["created_at"])
        end = milliseconds(run["updated_at"])
        begun = milliseconds(run["run_started_at"])
        if not start <= begun <= end:
            reject("run timestamp order is invalid")
        statuses = {"success": "passed", "failure": "failed", "timed_out": "failed",
                    "cancelled": "cancelled", "skipped": "skipped"}
        intervals = []
        for job in jobs:
            if (not isinstance(job, Mapping) or type(job["id"]) is not int or job["id"] < 1
                    or type(job["run_id"]) is not int or job["run_id"] != expected_run_id
                    or job["head_sha"] != commit["sha"] or job["status"] != "completed"
                    or ("run_attempt" in job and (type(job["run_attempt"]) is not int
                                                 or job["run_attempt"] != expected_attempt))):
                reject("job identity is unbound or nonterminal")
            if job["conclusion"] not in statuses:
                reject("job conclusion is unsupported")
            left, right = milliseconds(job["started_at"]), milliseconds(job["completed_at"])
            end = max(end, right)
            intervals.append(dict(id=str(job["id"]), clock_id=clock, kind="execution",
                                  status=statuses[job["conclusion"]], start_ms=left, end_ms=right))
        digest = hashlib.sha256(json.dumps(
            source_snapshot, sort_keys=True, separators=(",", ":"), allow_nan=False,
        ).encode()).hexdigest()
        return pipeline_timing_observation(
            repository=repository["full_name"], repository_id=repository["id"],
            source_snapshot_sha256=digest, commit_sha=commit["sha"], tree_sha=commit["tree_sha"],
            pipeline=pipeline, clock_id=clock, clock_basis="provider_utc_ms",
            start_ms=start, end_ms=end, intervals=intervals,
        )
    except (KeyError, TypeError, ValueError) as exc:
        if isinstance(exc, OperationalObservationError):
            raise
        raise OperationalObservationError(f"provider timing snapshot is malformed: {exc}") from exc

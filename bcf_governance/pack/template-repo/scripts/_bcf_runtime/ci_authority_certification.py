"""Normalize and independently verify authenticated provider CI snapshots."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
import hashlib
import json
from pathlib import Path
from typing import Any, Iterable

from jsonschema import Draft202012Validator

from .ci_authority_contracts import (
    CIAuthorityContractError,
    validate_ci_contract,
)
from .ci_authority_state import (
    Admission,
    AuthorityContractError,
    AuthorityEvaluation,
    AuthorityState,
    CandidateIdentity,
    CertificationStage,
    JobKey,
    JobObservation,
    ProducerContract,
    ProducerRun,
    RunAttempt,
    RunStatus,
    WorkflowIdentity,
    evaluate_authority,
)


class CICertificationError(ValueError):
    """Raised when certification material is unsafe, incomplete, or inconsistent."""


@dataclass(frozen=True)
class CertificationVerification:
    """Computed certification state and exact input hashes."""

    status: str
    computed_state: str
    admission_ordinal: int | None
    selected_attempts: tuple[tuple[str, int], ...]
    reasons: tuple[str, ...]
    certification_sha256: str
    session_manifest_sha256: str
    raw_snapshot_sha256: tuple[tuple[str, str], ...]

    def as_dict(self) -> dict[str, Any]:
        return {
            "status": self.status,
            "computed_state": self.computed_state,
            "admission_ordinal": self.admission_ordinal,
            "selected_attempts": [
                {"producer_id": producer_id, "run_attempt": attempt}
                for producer_id, attempt in self.selected_attempts
            ],
            "reasons": list(self.reasons),
            "certification_sha256": self.certification_sha256,
            "session_manifest_sha256": self.session_manifest_sha256,
            "raw_snapshot_sha256": dict(self.raw_snapshot_sha256),
        }


def _canonical_bytes(payload: dict[str, Any]) -> bytes:
    return (json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n").encode()


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _load_json(path: Path, *, label: str) -> dict[str, Any]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise CICertificationError(f"unable to load {label}: {path.name}") from exc
    if not isinstance(payload, dict):
        raise CICertificationError(f"{label} must contain an object")
    return payload


def _safe_snapshot_path(root: Path, relative_value: str) -> Path:
    relative = Path(relative_value)
    if relative.is_absolute() or not relative.parts or ".." in relative.parts:
        raise CICertificationError("raw snapshot path must be safe and relative")
    candidate = root / relative
    current = root
    for token in relative.parts:
        current /= token
        if current.is_symlink():
            raise CICertificationError("raw snapshot path cannot contain symlinks")
    try:
        candidate.resolve().relative_to(root.resolve())
    except ValueError as exc:
        raise CICertificationError("raw snapshot path escapes the certification root") from exc
    if not candidate.is_file():
        raise CICertificationError(f"raw snapshot is missing: {relative.as_posix()}")
    return candidate


def _workflow(payload: dict[str, Any]) -> WorkflowIdentity:
    return WorkflowIdentity(
        provider=str(payload["provider"]),
        repository_id=str(payload["repository_id"]),
        workflow_id=str(payload["workflow_id"]),
        active_path=str(payload["active_path"]),
        trusted_workflow_blob_oid=str(payload["trusted_workflow_blob_oid"]),
        trusted_workflow_sha256=str(payload["trusted_workflow_sha256"]),
        trusted_workflow_definition_commit=str(
            payload["trusted_workflow_definition_commit"]
        ),
        event=str(payload["event"]),
    )


def _job_key(payload: dict[str, Any]) -> JobKey:
    matrix = payload.get("matrix")
    normalized = (
        {str(key): str(value) for key, value in matrix.items()}
        if isinstance(matrix, dict)
        else {}
    )
    return JobKey.create(str(payload["job_id"]), normalized)


def _producer_contracts(authority: dict[str, Any]) -> tuple[ProducerContract, ...]:
    repository = authority["repository"]
    contracts: list[ProducerContract] = []
    for raw in authority["producers"]:
        workflow = raw["workflow"]
        allowed_events = tuple(str(value) for value in workflow["allowed_events"])
        contracts.append(
            ProducerContract(
                producer_id=str(raw["producer_id"]),
                workflow=WorkflowIdentity(
                    provider=str(repository["provider"]),
                    repository_id=str(repository["repository_id"]),
                    workflow_id=str(workflow["workflow_id"]),
                    active_path=str(workflow["active_path"]),
                    trusted_workflow_blob_oid=str(
                        workflow["trusted_workflow_blob_oid"]
                    ),
                    trusted_workflow_sha256=str(workflow["trusted_workflow_sha256"]),
                    trusted_workflow_definition_commit=str(
                        workflow["trusted_workflow_definition_commit"]
                    ),
                    event=allowed_events[0],
                ),
                expected_jobs=tuple(_job_key(value) for value in raw["expected_jobs"]),
                allowed_events=allowed_events,
            )
        )
    return tuple(contracts)


def _run(payload: dict[str, Any]) -> ProducerRun:
    attempts: list[RunAttempt] = []
    for raw_attempt in payload["attempts"]:
        attempts.append(
            RunAttempt(
                attempt=int(raw_attempt["run_attempt"]),
                status=RunStatus(str(raw_attempt["status"])),
                conclusion=(
                    str(raw_attempt["conclusion"])
                    if raw_attempt["conclusion"] is not None
                    else None
                ),
                jobs=tuple(
                    JobObservation(
                        key=_job_key(raw_job),
                        status=RunStatus(str(raw_job["status"])),
                        conclusion=(
                            str(raw_job["conclusion"])
                            if raw_job["conclusion"] is not None
                            else None
                        ),
                    )
                    for raw_job in raw_attempt["jobs"]
                ),
            )
        )
    return ProducerRun(
        producer_id=str(payload["producer_id"]),
        run_id=str(payload["run_id"]),
        workflow=_workflow(payload["workflow"]),
        attempts=tuple(attempts),
    )


def _shared_admission(payload: dict[str, Any]) -> dict[str, Any]:
    return {
        "admission_ordinal": str(payload["admission_ordinal"]),
        "control_plane_run_id": str(payload["control_plane_run_id"]),
        "control_plane_run_attempt": int(payload["control_plane_run_attempt"]),
        "dispatch_sequence": int(payload["dispatch_sequence"]),
        "candidate": dict(payload["candidate"]),
        "collection_complete": bool(payload["collection_complete"]),
    }


def _merged_authority_input(
    repo_root: Path,
    authority: dict[str, Any],
    snapshots: Iterable[dict[str, Any]],
) -> tuple[
    tuple[ProducerContract, ...],
    tuple[Admission, ...],
    dict[int, dict[str, Any]],
    CandidateIdentity,
]:
    try:
        validate_ci_contract(repo_root, "authority", authority)
    except CIAuthorityContractError as exc:
        raise CICertificationError(str(exc)) from exc
    snapshot_map: dict[str, dict[str, Any]] = {}
    for snapshot in snapshots:
        try:
            validate_ci_contract(repo_root, "provider_snapshot", snapshot)
        except CIAuthorityContractError as exc:
            raise CICertificationError(str(exc)) from exc
        producer_id = str(snapshot["producer_id"])
        if producer_id in snapshot_map:
            raise CICertificationError(f"duplicate raw snapshot for producer {producer_id}")
        snapshot_map[producer_id] = snapshot
    expected_producers = {str(value["producer_id"]) for value in authority["producers"]}
    if set(snapshot_map) != expected_producers:
        raise CICertificationError(
            "raw snapshot producer inventory must exactly match authority producers"
        )
    repositories = {
        json.dumps(snapshot["repository"], sort_keys=True) for snapshot in snapshot_map.values()
    }
    if repositories != {json.dumps(authority["repository"], sort_keys=True)}:
        raise CICertificationError("raw snapshots must match the authority repository")
    current_candidates = {
        (
            str(snapshot["current_default_main"]["checkout_sha"]),
            str(snapshot["current_default_main"]["tree_sha"]),
        )
        for snapshot in snapshot_map.values()
    }
    if len(current_candidates) != 1:
        raise CICertificationError("raw snapshots disagree on current default main")
    current_sha, current_tree = current_candidates.pop()
    admission_maps = {
        producer_id: {
            int(raw["admission_ordinal"]): raw for raw in snapshot["admissions"]
        }
        for producer_id, snapshot in snapshot_map.items()
    }
    ordinal_sets = {tuple(sorted(values)) for values in admission_maps.values()}
    if len(ordinal_sets) != 1:
        raise CICertificationError("raw snapshots disagree on admitted run inventory")
    ordinals = next(iter(ordinal_sets))
    shared_by_ordinal: dict[int, dict[str, Any]] = {}
    admissions: list[Admission] = []
    for ordinal in ordinals:
        raw_values = [values[ordinal] for values in admission_maps.values()]
        shared_values = [_shared_admission(value) for value in raw_values]
        if any(value != shared_values[0] for value in shared_values[1:]):
            raise CICertificationError(
                f"raw snapshots disagree on admission {ordinal} authority material"
            )
        shared = shared_values[0]
        shared_by_ordinal[ordinal] = shared
        candidate = shared["candidate"]
        admissions.append(
            Admission(
                admission_ordinal=ordinal,
                control_plane_run_id=str(shared["control_plane_run_id"]),
                control_plane_attempt=int(shared["control_plane_run_attempt"]),
                candidate=CandidateIdentity(
                    checkout_sha=str(candidate["checkout_sha"]),
                    tree_sha=str(candidate["tree_sha"]),
                ),
                collection_complete=bool(shared["collection_complete"]),
                producer_runs=tuple(_run(value["producer_run"]) for value in raw_values),
            )
        )
    return (
        _producer_contracts(authority),
        tuple(admissions),
        shared_by_ordinal,
        CandidateIdentity(checkout_sha=current_sha, tree_sha=current_tree),
    )


def _selected_attempt(run: ProducerRun) -> RunAttempt:
    if not run.attempts:
        raise CICertificationError(f"producer {run.producer_id} has no run attempt")
    return max(run.attempts, key=lambda value: value.attempt)


def _workflow_payload(workflow: WorkflowIdentity) -> dict[str, str]:
    return {
        "provider": workflow.provider,
        "repository_id": workflow.repository_id,
        "workflow_id": workflow.workflow_id,
        "active_path": workflow.active_path,
        "trusted_workflow_blob_oid": workflow.trusted_workflow_blob_oid,
        "trusted_workflow_sha256": workflow.trusted_workflow_sha256,
        "trusted_workflow_definition_commit": workflow.trusted_workflow_definition_commit,
        "event": workflow.event,
    }


def normalize_ci_certification(
    repo_root: Path,
    *,
    authority: dict[str, Any],
    snapshots: Iterable[dict[str, Any]],
    raw_snapshot_descriptors: list[dict[str, Any]],
    evidence_session: dict[str, Any],
    generated_at: str | None = None,
) -> dict[str, Any]:
    """Construct a deterministic non-certified report from authenticated snapshots."""

    snapshot_values = tuple(snapshots)
    contracts, admissions, shared, current = _merged_authority_input(
        repo_root, authority, snapshot_values
    )
    try:
        evaluation = evaluate_authority(
            contracts=contracts,
            admissions=admissions,
            current_default_main_sha=current.checkout_sha,
            current_default_main_tree=current.tree_sha,
            stage=CertificationStage.NORMALIZED,
        )
    except AuthorityContractError as exc:
        raise CICertificationError(str(exc)) from exc
    if evaluation.admission_ordinal is None:
        raise CICertificationError("certification cannot be normalized without an admission")
    selected = next(
        value
        for value in admissions
        if value.admission_ordinal == evaluation.admission_ordinal
    )
    shared_value = shared[selected.admission_ordinal]
    producer_contracts = {value.producer_id: value for value in contracts}
    report_runs: list[dict[str, Any]] = []
    exact_jobs = True
    for run in sorted(selected.producer_runs, key=lambda value: value.producer_id):
        attempt = _selected_attempt(run)
        if attempt.status is not RunStatus.COMPLETED:
            raise CICertificationError(
                "normalized certification requires terminal selected producer attempts"
            )
        expected_jobs = set(producer_contracts[run.producer_id].expected_jobs)
        actual_jobs = {value.key for value in attempt.jobs}
        inventory_exact = len(actual_jobs) == len(attempt.jobs) and actual_jobs == expected_jobs
        exact_jobs = exact_jobs and inventory_exact
        report_runs.append(
            {
                "producer_id": run.producer_id,
                "workflow": _workflow_payload(run.workflow),
                "selected_attempt": {
                    "run_id": run.run_id,
                    "run_attempt": attempt.attempt,
                    "status": attempt.status.value,
                    "conclusion": attempt.conclusion,
                    "exact_job_inventory": inventory_exact,
                },
            }
        )
    candidate = {
        "checkout_sha": selected.candidate.checkout_sha,
        "tree_sha": selected.candidate.tree_sha,
        "current_default_main_sha": current.checkout_sha,
    }
    report = {
        "schema_version": "1.0",
        "repository": dict(authority["repository"]),
        "subject": candidate,
        "admission": {
            "admission_ordinal": str(selected.admission_ordinal),
            "control_plane_run_id": selected.control_plane_run_id,
            "control_plane_run_attempt": selected.control_plane_attempt,
            "dispatch_sequence": int(shared_value["dispatch_sequence"]),
            "candidate": candidate,
            "producer_runs": report_runs,
        },
        "raw_snapshots": raw_snapshot_descriptors,
        "evidence_session": evidence_session,
        "state": evaluation.state.value,
        "evaluation": {
            "exact_producer_inventory": len(selected.producer_runs) == len(contracts),
            "exact_job_inventory": exact_jobs,
            "selected_attempts": [
                {
                    "producer_id": str(value["producer_id"]),
                    "run_attempt": int(value["selected_attempt"]["run_attempt"]),
                }
                for value in report_runs
            ],
            "reasons": list(evaluation.reasons),
        },
        "generated_at": generated_at
        or datetime.now(UTC).isoformat().replace("+00:00", "Z"),
    }
    try:
        validate_ci_contract(repo_root, "certification", report)
    except CIAuthorityContractError as exc:
        raise CICertificationError(str(exc)) from exc
    return report


def load_authenticated_snapshots(
    repo_root: Path,
    certification_path: Path,
    certification: dict[str, Any],
) -> tuple[dict[str, Any], ...]:
    """Load and hash-check the exact raw snapshots named by a certification report."""

    root = certification_path.resolve().parent
    snapshots: list[dict[str, Any]] = []
    for descriptor in certification["raw_snapshots"]:
        path = _safe_snapshot_path(root, str(descriptor["artifact_path"]))
        if _sha256(path) != descriptor["sha256"]:
            raise CICertificationError(
                f"raw snapshot digest mismatch: {descriptor['artifact_path']}"
            )
        payload = _load_json(path, label="raw provider snapshot")
        try:
            validate_ci_contract(repo_root, "provider_snapshot", payload)
        except CIAuthorityContractError as exc:
            raise CICertificationError(str(exc)) from exc
        if payload["producer_id"] != descriptor["producer_id"]:
            raise CICertificationError("raw snapshot descriptor producer mismatch")
        if payload["authentication"]["captured_at"] != descriptor["authenticated_at"]:
            raise CICertificationError("raw snapshot authentication timestamp mismatch")
        snapshots.append(payload)
    return tuple(snapshots)


def _verify_session(
    repo_root: Path,
    session_path: Path,
    certification: dict[str, Any],
) -> dict[str, Any]:
    if session_path.is_symlink() or not session_path.is_file():
        raise CICertificationError("evidence session manifest must be a regular file")
    payload = _load_json(session_path, label="evidence session manifest")
    session_schema = json.loads(
        (repo_root / "schemas/evidence-session.schema.json").read_text(encoding="utf-8")
    )
    session_errors = sorted(
        Draft202012Validator(session_schema).iter_errors(payload),
        key=lambda error: ([str(value) for value in error.absolute_path], error.message),
    )
    if session_errors:
        first = session_errors[0]
        location = ".".join(str(value) for value in first.absolute_path)
        raise CICertificationError(
            f"evidence session {location or '<root>'}: {first.message}"
        )
    expected = certification["evidence_session"]
    if _sha256(session_path) != expected["manifest_sha256"]:
        raise CICertificationError("evidence session manifest digest mismatch")
    producer = payload.get("producer")
    if not isinstance(producer, dict):
        raise CICertificationError("evidence session producer identity is missing")
    if (
        payload.get("session_id") != expected["session_id"]
        or producer.get("run_id") != expected["run_id"]
        or str(producer.get("run_attempt")) != str(expected["run_attempt"])
    ):
        raise CICertificationError("evidence session identity does not match certification")
    subject = payload.get("subject")
    report_subject = certification["subject"]
    if not isinstance(subject, dict) or (
        subject.get("commit_sha") != report_subject["checkout_sha"]
        or subject.get("tree_sha") != report_subject["tree_sha"]
    ):
        raise CICertificationError("evidence session subject does not match certification")
    expected_producers = set(payload.get("expected_producer_inventory", []))
    report_producers = {
        value["producer_id"] for value in certification["admission"]["producer_runs"]
    }
    if expected_producers != report_producers:
        raise CICertificationError("evidence session producer inventory mismatch")
    return payload


def verify_ci_certification(
    repo_root: Path,
    *,
    authority_path: Path,
    certification_path: Path,
    session_manifest_path: Path,
) -> CertificationVerification:
    """Recompute a normalized report and return truth-stage certification state."""

    authority = _load_json(authority_path, label="CI authority contract")
    certification = _load_json(certification_path, label="CI certification report")
    try:
        validate_ci_contract(repo_root, "authority", authority)
        validate_ci_contract(repo_root, "certification", certification)
    except CIAuthorityContractError as exc:
        raise CICertificationError(str(exc)) from exc
    snapshots = load_authenticated_snapshots(repo_root, certification_path, certification)
    _verify_session(repo_root, session_manifest_path, certification)
    expected = normalize_ci_certification(
        repo_root,
        authority=authority,
        snapshots=snapshots,
        raw_snapshot_descriptors=list(certification["raw_snapshots"]),
        evidence_session=dict(certification["evidence_session"]),
        generated_at=str(certification["generated_at"]),
    )
    if _canonical_bytes(expected) != _canonical_bytes(certification):
        raise CICertificationError(
            "normalized CI certification does not match independently recomputed provider state"
        )
    contracts, admissions, _, current = _merged_authority_input(
        repo_root, authority, snapshots
    )
    try:
        evaluation: AuthorityEvaluation = evaluate_authority(
            contracts=contracts,
            admissions=admissions,
            current_default_main_sha=current.checkout_sha,
            current_default_main_tree=current.tree_sha,
            stage=CertificationStage.TRUTH_VERIFIED,
        )
    except AuthorityContractError as exc:
        raise CICertificationError(str(exc)) from exc
    return CertificationVerification(
        status="pass" if evaluation.state is AuthorityState.CERTIFIED else "fail",
        computed_state=evaluation.state.value,
        admission_ordinal=evaluation.admission_ordinal,
        selected_attempts=evaluation.selected_attempts,
        reasons=evaluation.reasons,
        certification_sha256=_sha256(certification_path),
        session_manifest_sha256=_sha256(session_manifest_path),
        raw_snapshot_sha256=tuple(
            sorted(
                (str(value["producer_id"]), str(value["sha256"]))
                for value in certification["raw_snapshots"]
            )
        ),
    )

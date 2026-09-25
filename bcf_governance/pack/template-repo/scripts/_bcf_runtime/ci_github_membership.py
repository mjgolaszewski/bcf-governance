"""Authority-v1.1 exact-main admission and same-run producer membership."""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Any

import yaml

from .ci_authority_contracts import (
    authority_role_workflow,
    producer_workflow,
)
from .ci_github_api import GitHubAPI
from .ci_github_identity import (
    GitHubControllerError,
    MainIdentity,
    authenticate_producer_workflow,
    authenticate_trusted_run,
    positive_int,
)


def admission_ordinal(
    run_id: object, run_attempt: object, dispatch_sequence: object
) -> int:
    """Map GitHub's authenticated tuple to one positive total ordinal."""

    run = positive_int(run_id, field="control-plane run ID")
    attempt = positive_int(run_attempt, field="control-plane run attempt")
    sequence = positive_int(dispatch_sequence, field="dispatch sequence")
    if attempt >= 1_000 or sequence >= 1_000:
        raise GitHubControllerError("attempt and dispatch sequence must be below 1000")
    return run * 1_000_000 + attempt * 1_000 + sequence


def _require_v11(authority: dict[str, Any]) -> None:
    if authority.get("schema_version") != "1.1":
        raise GitHubControllerError(
            "exact-main common-admission authority requires contract version 1.1"
        )


class AdmissionTopologyState(StrEnum):
    CERTIFIABLE = "certifiable"
    PENDING_ROTATION = "pending_rotation"
    NONCERTIFYING = "noncertifying"


@dataclass(frozen=True)
class AdmissionTopology:
    state: AdmissionTopologyState
    reason: str


def _authority_job_inventory(
    authority: dict[str, Any],
) -> tuple[list[str], list[str], dict[str, list[str]]]:
    admission = [str(value["job_id"]) for value in authority["admission_jobs"]]
    builders = [
        str(value["job_id"])
        for value in authority.get("controller_builder_jobs", [])
    ]
    producers = {
        str(producer["producer_id"]): [
            str(value["job_id"]) for value in producer["expected_jobs"]
        ]
        for producer in authority["producers"]
    }
    complete = admission + builders + [
        name for values in producers.values() for name in values
    ]
    if len(set(complete)) != len(complete):
        raise GitHubControllerError("authority admission job inventory is duplicated")
    return admission, builders, producers


def _pending_producer_facades(
    api: GitHubAPI,
    *,
    repository: str,
    main: MainIdentity,
    authority: dict[str, Any],
) -> list[str]:
    """Project skipped producer callers from the authenticated admission workflow."""

    workflow = authority_role_workflow(authority, "admission")
    raw = api.content(
        repository, str(workflow["active_path"]), ref=main.checkout_sha
    ).content
    try:
        payload = yaml.safe_load(raw)
    except yaml.YAMLError as exc:
        raise GitHubControllerError("admission workflow is not readable YAML") from exc
    jobs = payload.get("jobs") if isinstance(payload, dict) else None
    roles = workflow.get("job_roles")
    if not isinstance(jobs, dict) or not isinstance(roles, dict):
        raise GitHubControllerError("admission workflow producer roles are invalid")
    facades: list[str] = []
    for job_id, role in roles.items():
        if role != "producer":
            continue
        job = jobs.get(job_id)
        name = job.get("name") if isinstance(job, dict) else None
        if not isinstance(name, str) or not name:
            raise GitHubControllerError(
                "admission workflow producer facade is invalid"
            )
        facades.append(name)
    if not facades or len(set(facades)) != len(facades):
        raise GitHubControllerError(
            "admission workflow producer facade inventory is invalid"
        )
    return facades


def classify_admission_topology(
    api: GitHubAPI,
    *,
    repository: str,
    main: MainIdentity,
    authority: dict[str, Any],
    admission_run_id: object,
    admission_run_attempt: object,
) -> AdmissionTopology:
    """Classify exact provider topology before strict certification collection."""

    _require_v11(authority)
    run_id = str(positive_int(admission_run_id, field="admission run ID"))
    attempt = positive_int(admission_run_attempt, field="admission run attempt")
    run = api.run(repository, run_id)
    if positive_int(run.get("run_attempt"), field="admission run attempt") != attempt:
        raise GitHubControllerError("admission run attempt is no longer authoritative")
    admission_workflow = authority_role_workflow(authority, "admission")
    authenticate_trusted_run(
        api,
        repository=repository,
        main=main,
        run_id=run_id,
        run_attempt=attempt,
        workflow_path=str(admission_workflow["active_path"]),
        expected_event=str(run.get("event")),
        require_success=False,
        expected_workflow_id=admission_workflow["workflow_id"],
        expected_workflow_sha256=str(
            admission_workflow["trusted_workflow_sha256"]
        ),
        expected_workflow_blob_oid=admission_workflow["trusted_workflow_blob_oid"],
        expected_workflow_definition_commit=admission_workflow[
            "trusted_workflow_definition_commit"
        ],
    )
    references = _reference_map(run, repository, main.checkout_sha)
    _validate_reference_inventory(authority, references)
    jobs = api.jobs(repository, run_id, attempt=attempt)
    names = [str(value.get("name", "")) for value in jobs]
    if not names or not all(names):
        raise GitHubControllerError("admission job inventory is empty")
    if len(set(names)) != len(names):
        raise GitHubControllerError("admission job inventory is duplicated")
    admission_jobs, builder_jobs, producer_jobs = _authority_job_inventory(authority)
    complete = set(admission_jobs + builder_jobs)
    complete.update(name for values in producer_jobs.values() for name in values)
    actual = set(names)
    unknown = actual - complete
    job_map = {str(value["name"]): value for value in jobs}
    if unknown and any(
        str(job_map[name].get("status")) != "completed"
        or str(job_map[name].get("conclusion")) != "skipped"
        for name in unknown
    ):
        raise GitHubControllerError("admission job inventory contains an active extra job")
    builder_ready = bool(builder_jobs) and all(
            str(job_map[name].get("status")) == "completed"
            and str(job_map[name].get("conclusion")) == "success"
            for name in builder_jobs
        )
    admission_skipped = all(
            str(job_map[name].get("status")) == "completed"
            and str(job_map[name].get("conclusion")) == "skipped"
            for name in admission_jobs
            if name in job_map
        ) and set(admission_jobs).issubset(actual)
    if builder_ready and admission_skipped:
        pending_facades = _pending_producer_facades(
            api,
            repository=repository,
            main=main,
            authority=authority,
        )
        pending_complete = set(admission_jobs + builder_jobs + pending_facades)
        if actual == pending_complete and all(
            str(job_map[name].get("status")) == "completed"
            and str(job_map[name].get("conclusion")) == "skipped"
            for name in pending_facades
        ):
            return AdmissionTopology(
                AdmissionTopologyState.PENDING_ROTATION,
                "pending_controller_rotation",
            )
    if not set(admission_jobs).issubset(actual) or any(
        str(job_map[name].get("status")) != "completed"
        or str(job_map[name].get("conclusion")) != "success"
        for name in admission_jobs
        if name in job_map
    ):
        return AdmissionTopology(
            AdmissionTopologyState.NONCERTIFYING,
            "admission_not_successful",
        )
    expected_producers = {
        name for values in producer_jobs.values() for name in values
    }
    if actual != complete or any(
        str(job_map[name].get("status")) != "completed"
        or str(job_map[name].get("conclusion")) == "skipped"
        for name in expected_producers
        if name in job_map
    ):
        return AdmissionTopology(
            AdmissionTopologyState.NONCERTIFYING,
            "producer_topology_incomplete",
        )
    return AdmissionTopology(AdmissionTopologyState.CERTIFIABLE, "complete")


def certification_producer_ids(
    authority: dict[str, Any], evaluation_scope: dict[str, Any]
) -> tuple[str, ...]:
    """Return the exact producer set admitted for one terminal evaluation intent."""

    intent = evaluation_scope.get("intent")
    target = evaluation_scope.get("target")
    expected_kind = {"workitem": "workitem", "closure": "phase"}.get(str(intent))
    if expected_kind is None or not isinstance(target, dict):
        raise GitHubControllerError(
            "exact-main certification evaluation scope is unsupported"
        )
    if target.get("kind") != expected_kind or not isinstance(target.get("id"), str):
        raise GitHubControllerError(
            "exact-main certification evaluation target is invalid"
        )
    producer_ids = tuple(str(value["producer_id"]) for value in authority["producers"])
    if not producer_ids or len(set(producer_ids)) != len(producer_ids):
        raise GitHubControllerError("certification producer inventory is invalid")
    return producer_ids


def _authenticate_admission_candidate(
    api: GitHubAPI,
    *,
    repository: str,
    main: MainIdentity,
    workflow: dict[str, Any],
    candidate: dict[str, Any],
):
    """Authenticate one provider candidate through the canonical admission path."""

    if str(candidate.get("head_branch")) != main.default_branch:
        raise GitHubControllerError("admission run branch is not current default main")
    head_repository = candidate.get("head_repository")
    if not isinstance(head_repository, dict) or str(
        head_repository.get("id")
    ) != main.repository_id:
        raise GitHubControllerError(
            "admission run head repository identity does not match authority"
        )
    event = str(candidate.get("event"))
    if event not in workflow["allowed_events"]:
        raise GitHubControllerError("admission run event is not admitted by authority")
    run_id = str(positive_int(candidate.get("id"), field="admission run ID"))
    attempt = positive_int(
        candidate.get("run_attempt"), field="admission run attempt"
    )
    return authenticate_trusted_run(
        api,
        repository=repository,
        main=main,
        run_id=run_id,
        run_attempt=attempt,
        workflow_path=str(workflow["active_path"]),
        expected_event=event,
        require_success=False,
        expected_workflow_id=workflow["workflow_id"],
        expected_workflow_sha256=str(workflow["trusted_workflow_sha256"]),
        expected_workflow_blob_oid=workflow["trusted_workflow_blob_oid"],
        expected_workflow_definition_commit=workflow[
            "trusted_workflow_definition_commit"
        ],
    )


def select_latest_admission(
    api: GitHubAPI,
    *,
    repository: str,
    main: MainIdentity,
    authority: dict[str, Any],
    trigger_run_id: object | None = None,
    trigger_run_attempt: object | None = None,
) -> tuple[str, int]:
    """Select an authenticated admission without success fallback.

    A workflow-run callback selects its exact triggering admission.  Without a trigger,
    the newest admission for the supplied immutable subject is selected.
    """

    _require_v11(authority)
    workflow = authority_role_workflow(authority, "admission")
    candidates: list[dict[str, Any]] = []
    if (trigger_run_id is None) != (trigger_run_attempt is None):
        raise GitHubControllerError(
            "admission trigger run ID and attempt must be supplied together"
        )
    if trigger_run_id is not None:
        expected_run_id = str(
            positive_int(trigger_run_id, field="trigger admission run ID")
        )
        expected_attempt = positive_int(
            trigger_run_attempt, field="trigger admission run attempt"
        )
        trigger = api.run(repository, expected_run_id)
        if (
            str(positive_int(trigger.get("id"), field="admission run ID"))
            != expected_run_id
            or positive_int(
                trigger.get("run_attempt"), field="admission run attempt"
            )
            != expected_attempt
        ):
            raise GitHubControllerError(
                "provider admission run does not match trigger locator"
            )
        authenticated = _authenticate_admission_candidate(
            api,
            repository=repository,
            main=main,
            workflow=workflow,
            candidate=trigger,
        )
        if authenticated.run_id != expected_run_id:
            raise GitHubControllerError(
                "provider admission run does not match trigger locator"
            )
        return authenticated.run_id, authenticated.run_attempt
    for event in workflow["allowed_events"]:
        candidates.extend(
            api.workflow_runs(
                repository,
                workflow["workflow_id"],
                head_sha=main.checkout_sha,
                event=str(event),
            )
        )
    exact_by_identity: dict[tuple[str, int], dict[str, Any]] = {}
    for value in candidates:
        if not (
            str(value.get("head_sha")) == main.checkout_sha
            and str(value.get("workflow_id")) == str(workflow["workflow_id"])
            and str(value.get("repository", {}).get("id")) == main.repository_id
            and str(value.get("event")) in workflow["allowed_events"]
        ):
            continue
        identity = (
            str(positive_int(value.get("id"), field="admission run ID")),
            positive_int(value.get("run_attempt"), field="admission run attempt"),
        )
        exact_by_identity.setdefault(identity, value)
    exact = list(exact_by_identity.values())
    if not exact:
        raise GitHubControllerError("no authenticated exact-main admission exists")
    selected = max(
        exact,
        key=lambda value: (
            positive_int(value.get("id"), field="admission run ID"),
            positive_int(value.get("run_attempt"), field="admission run attempt"),
        ),
    )
    selected_identity = (
        str(positive_int(selected["id"], field="admission run ID")),
        positive_int(selected["run_attempt"], field="admission run attempt"),
    )
    _authenticate_admission_candidate(
        api,
        repository=repository,
        main=main,
        workflow=workflow,
        candidate=selected,
    )
    return selected_identity


def _reference_map(
    run: dict[str, Any], repository: str, commit_sha: str
) -> dict[str, str]:
    references = run.get("referenced_workflows")
    if not isinstance(references, list) or any(
        not isinstance(value, dict) for value in references
    ):
        raise GitHubControllerError(
            "admission run lacks authenticated referenced-workflow inventory"
        )
    resolved: dict[str, str] = {}
    prefix = f"{repository}/"
    suffix = f"@{commit_sha}"
    for value in references:
        path = str(value.get("path", ""))
        sha = str(value.get("sha", ""))
        if path.startswith(prefix) and path.endswith(suffix):
            path = path[len(prefix) : -len(suffix)]
        if not path.startswith(".github/workflows/") or sha != commit_sha:
            raise GitHubControllerError(
                "referenced workflow is not bound to the admitted repository commit"
            )
        if path in resolved:
            raise GitHubControllerError("referenced workflow inventory contains duplicates")
        resolved[path] = sha
    return resolved


def _validate_reference_inventory(
    authority: dict[str, Any], references: dict[str, str]
) -> None:
    expected_paths = {
        str(producer_workflow(authority, value)["active_path"])
        for value in authority["producers"]
    }
    if set(references) != expected_paths:
        raise GitHubControllerError(
            "referenced workflow inventory does not match admitted producers"
        )


def collect_same_run_producers(
    api: GitHubAPI,
    *,
    repository: str,
    main: MainIdentity,
    authority: dict[str, Any],
    admission_run_id: object,
    admission_run_attempt: object,
    dispatch_sequence: object = 1,
    producer_ids: tuple[str, ...] | None = None,
    require_complete_admission_inventory: bool = True,
) -> tuple[dict[str, Any], ...]:
    """Collect producer observations only from one admission run and exact attempt.

    Certification uses the default complete-admission contract.  A bootstrap query may
    select a bounded producer from a partial admission when an earlier failed job kept
    unrelated matrices from expanding; the selected producer's own inventory remains
    exact and complete.
    """

    _require_v11(authority)
    run_id = str(positive_int(admission_run_id, field="admission run ID"))
    attempt = positive_int(admission_run_attempt, field="admission run attempt")
    sequence = positive_int(dispatch_sequence, field="dispatch sequence")
    run = api.run(repository, run_id)
    if positive_int(run.get("run_attempt"), field="admission run attempt") != attempt:
        raise GitHubControllerError("admission run attempt is no longer authoritative")
    admission = authority_role_workflow(authority, "admission")
    authenticate_trusted_run(
        api,
        repository=repository,
        main=main,
        run_id=run_id,
        run_attempt=attempt,
        workflow_path=str(admission["active_path"]),
        expected_event=str(run.get("event")),
        require_success=False,
        expected_workflow_id=admission["workflow_id"],
        expected_workflow_sha256=str(admission["trusted_workflow_sha256"]),
        expected_workflow_blob_oid=admission["trusted_workflow_blob_oid"],
        expected_workflow_definition_commit=admission[
            "trusted_workflow_definition_commit"
        ],
    )
    references = _reference_map(run, repository, main.checkout_sha)
    jobs = api.jobs(repository, run_id, attempt=attempt)
    actual_jobs = [str(value.get("name", "")) for value in jobs]
    if not all(actual_jobs) or len(set(actual_jobs)) != len(actual_jobs):
        raise GitHubControllerError("admission job inventory is empty or duplicated")
    expected_admission, expected_controller_builders, producer_expected = (
        _authority_job_inventory(authority)
    )
    selected_ids = (
        tuple(producer_expected)
        if producer_ids is None
        else tuple(str(value) for value in producer_ids)
    )
    if (
        not selected_ids
        or len(set(selected_ids)) != len(selected_ids)
        or set(selected_ids) - set(producer_expected)
    ):
        raise GitHubControllerError("selected admission producer inventory is invalid")
    expected_all = expected_admission + expected_controller_builders + [
        name for values in producer_expected.values() for name in values
    ]
    expected_selected = set(expected_admission)
    for producer_id in selected_ids:
        expected_selected.update(producer_expected[producer_id])
    actual_set = set(actual_jobs)
    if require_complete_admission_inventory and actual_set != set(expected_all):
        raise GitHubControllerError("admission exact job inventory does not match authority")
    if not require_complete_admission_inventory and not expected_selected.issubset(actual_set):
        raise GitHubControllerError(
            "selected producer exact job inventory is incomplete in admission"
        )
    job_map = {str(value["name"]): value for value in jobs}
    ordinal = admission_ordinal(run_id, attempt, sequence)
    _validate_reference_inventory(authority, references)
    observations: list[dict[str, Any]] = []
    for producer in authority["producers"]:
        producer_id = str(producer["producer_id"])
        if producer_id not in selected_ids:
            continue
        workflow = producer_workflow(authority, producer)
        run_view = {
            **run,
            "workflow_id": workflow["workflow_id"],
            "event": "workflow_call",
        }
        workflow_identity = authenticate_producer_workflow(
            api,
            repository=repository,
            main=main,
            producer={**producer, "workflow": workflow},
            run=run_view,
        )
        selected_jobs = [job_map[name] for name in producer_expected[producer_id]]
        terminal = all(str(value.get("status")) == "completed" for value in selected_jobs)
        conclusions = [str(value.get("conclusion")) for value in selected_jobs]
        producer_conclusion: str | None = None
        if terminal:
            producer_conclusion = (
                "success"
                if all(value == "success" for value in conclusions)
                else next(value for value in conclusions if value != "success")
            )
        observations.append(
            {
                "producer_id": producer_id,
                "run_id": run_id,
                "workflow": workflow_identity,
                "attempts": [
                    {
                        "run_attempt": attempt,
                        "status": "completed" if terminal else "in_progress",
                        "conclusion": producer_conclusion,
                        "jobs": [
                            {
                                "job_id": str(value["name"]),
                                "matrix": {},
                                "status": str(value.get("status")),
                                "conclusion": value.get("conclusion"),
                            }
                            for value in selected_jobs
                        ],
                    }
                ],
                "same_run_membership": {
                    "repository_id": main.repository_id,
                    "commit_sha": main.checkout_sha,
                    "tree_sha": main.tree_sha,
                    "admission_run_id": run_id,
                    "admission_run_attempt": attempt,
                    "dispatch_sequence": sequence,
                    "admission_ordinal": str(ordinal),
                    "producer_id": producer_id,
                    "producer_run_id": run_id,
                    "producer_run_attempt": attempt,
                    "referenced_workflow_path": str(workflow["active_path"]),
                    "referenced_workflow_sha": references[str(workflow["active_path"])],
                    "exact_job_inventory": True,
                },
            }
        )
    return tuple(observations)

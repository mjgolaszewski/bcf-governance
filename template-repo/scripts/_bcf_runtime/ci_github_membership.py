"""Authority-v1.1 exact-main admission and same-run producer membership."""

from __future__ import annotations

from typing import Any

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


def select_latest_admission(
    api: GitHubAPI,
    *,
    repository: str,
    main: MainIdentity,
    authority: dict[str, Any],
) -> tuple[str, int]:
    """Select the newest authenticated exact-main admission without success fallback."""

    _require_v11(authority)
    workflow = authority_role_workflow(authority, "admission")
    candidates: list[dict[str, Any]] = []
    for event in workflow["allowed_events"]:
        candidates.extend(
            api.workflow_runs(
                repository,
                workflow["workflow_id"],
                head_sha=main.checkout_sha,
                event=str(event),
            )
        )
    exact = [
        value
        for value in candidates
        if str(value.get("head_sha")) == main.checkout_sha
        and str(value.get("workflow_id")) == str(workflow["workflow_id"])
        and str(value.get("repository", {}).get("id")) == main.repository_id
        and str(value.get("event")) in workflow["allowed_events"]
    ]
    if not exact:
        raise GitHubControllerError("no authenticated exact-main admission exists")
    selected = max(
        exact,
        key=lambda value: (
            positive_int(value.get("id"), field="admission run ID"),
            positive_int(value.get("run_attempt"), field="admission run attempt"),
        ),
    )
    run_id = str(positive_int(selected["id"], field="admission run ID"))
    attempt = positive_int(selected["run_attempt"], field="admission run attempt")
    authenticate_trusted_run(
        api,
        repository=repository,
        main=main,
        run_id=run_id,
        run_attempt=attempt,
        workflow_path=str(workflow["active_path"]),
        expected_event=str(selected["event"]),
        require_success=False,
        expected_workflow_id=workflow["workflow_id"],
        expected_workflow_sha256=str(workflow["trusted_workflow_sha256"]),
        expected_workflow_blob_oid=workflow["trusted_workflow_blob_oid"],
        expected_workflow_definition_commit=workflow[
            "trusted_workflow_definition_commit"
        ],
    )
    return run_id, attempt


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


def collect_same_run_producers(
    api: GitHubAPI,
    *,
    repository: str,
    main: MainIdentity,
    authority: dict[str, Any],
    admission_run_id: object,
    admission_run_attempt: object,
    dispatch_sequence: object = 1,
) -> tuple[dict[str, Any], ...]:
    """Collect producer observations only from one admission run and exact attempt."""

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
    expected_admission = [str(value["job_id"]) for value in authority["admission_jobs"]]
    producer_expected = {
        str(producer["producer_id"]): [
            str(value["job_id"]) for value in producer["expected_jobs"]
        ]
        for producer in authority["producers"]
    }
    expected_all = expected_admission + [
        name for values in producer_expected.values() for name in values
    ]
    if len(set(expected_all)) != len(expected_all) or set(actual_jobs) != set(expected_all):
        raise GitHubControllerError("admission exact job inventory does not match authority")
    job_map = {str(value["name"]): value for value in jobs}
    ordinal = admission_ordinal(run_id, attempt, sequence)
    expected_paths = {
        str(producer_workflow(authority, value)["active_path"])
        for value in authority["producers"]
    }
    if set(references) != expected_paths:
        raise GitHubControllerError(
            "referenced workflow inventory does not match admitted producers"
        )
    observations: list[dict[str, Any]] = []
    for producer in authority["producers"]:
        producer_id = str(producer["producer_id"])
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

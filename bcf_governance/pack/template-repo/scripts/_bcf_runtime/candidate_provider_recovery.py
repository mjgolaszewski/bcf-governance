"""Closed provider recovery for one exact prospectively proved candidate."""

from __future__ import annotations

from dataclasses import asdict
from typing import Any, Mapping, Protocol

import yaml

from .ci_authority_pins import CIAuthorityPinError, compiled_workflow_job_names
from .ci_github import GithubReferenceError, authenticate_github_run
from .ci_recovery_frontier import candidate_provider_frontier
from .local_pr import ProspectiveValidationError


GOVERNANCE_WORKFLOW = ".github/workflows/governance.yml"
GOVERNANCE_WORKFLOW_NAME = "governance.yml"
MAX_PROVIDER_ATTEMPTS = 2
_TRANSIENT_UPLOAD_MARKERS = (
    "ETIMEDOUT",
    "ECONNRESET",
    "EAI_AGAIN",
    "socket hang up",
    "TLS connection was non-properly terminated",
)


class CandidateProviderAPI(Protocol):
    def repository(self, repository: str) -> dict[str, Any]: ...
    def workflow_runs(
        self, repository: str, workflow_id: str | int, *, head_sha: str, event: str
    ) -> tuple[dict[str, Any], ...]: ...
    def workflow(self, repository: str, workflow_id: str | int) -> dict[str, Any]: ...
    def content(self, repository: str, path: str, *, ref: str) -> Any: ...
    def jobs(
        self, repository: str, run_id: str | int, *, attempt: int
    ) -> tuple[dict[str, Any], ...]: ...
    def artifacts(
        self, repository: str, run_id: str | int
    ) -> tuple[dict[str, Any], ...]: ...
    def check_run_annotations(
        self, repository: str, check_run_id: str | int
    ) -> tuple[dict[str, Any], ...]: ...
    def rerun_workflow(self, repository: str, run_id: object) -> None: ...


def _positive(value: object, *, field: str) -> int:
    if isinstance(value, bool) or not str(value).isdigit() or int(str(value)) < 1:
        raise ProspectiveValidationError(f"{field} is not a positive provider ID")
    return int(str(value))


def _run_binds_pr(
    run: Mapping[str, Any], *, pull_request: int, base_sha: str, head_sha: str
) -> bool:
    values = run.get("pull_requests")
    if not isinstance(values, list) or len(values) != 1:
        return False
    value = values[0]
    if not isinstance(value, Mapping):
        return False
    head, base = value.get("head"), value.get("base")
    return (
        value.get("number") == pull_request
        and isinstance(head, Mapping)
        and isinstance(base, Mapping)
        and head.get("sha") == head_sha
        and base.get("sha") == base_sha
    )


def _terminal_upload_step(raw: bytes, terminal_job_name: str) -> str:
    try:
        payload = yaml.safe_load(raw)
    except yaml.YAMLError as exc:
        raise ProspectiveValidationError(
            "protected-base governance workflow is invalid YAML"
        ) from exc
    jobs = payload.get("jobs") if isinstance(payload, Mapping) else None
    if not isinstance(jobs, Mapping):
        raise ProspectiveValidationError(
            "protected-base governance workflow has no job contract"
        )
    matching = [
        value for value in jobs.values()
        if isinstance(value, Mapping) and value.get("name") == terminal_job_name
    ]
    if len(matching) != 1 or not isinstance(matching[0].get("steps"), list):
        raise ProspectiveValidationError(
            "protected-base terminal truth job is ambiguous"
        )
    uploads = []
    for step in matching[0]["steps"]:
        if not isinstance(step, Mapping):
            continue
        uses = str(step.get("uses", ""))
        with_value = step.get("with")
        name = step.get("name")
        if (
            uses.startswith("actions/upload-artifact@")
            and isinstance(with_value, Mapping)
            and "bcf-governance-truth-" in str(with_value.get("name", ""))
            and isinstance(name, str)
        ):
            uploads.append(name)
    if len(uploads) != 1:
        raise ProspectiveValidationError(
            "protected-base terminal truth upload is ambiguous"
        )
    return uploads[0]


def _transient_terminal_upload(
    api: CandidateProviderAPI,
    *,
    repository: str,
    run_id: int,
    attempt: int,
    jobs: tuple[dict[str, Any], ...],
    expected_jobs: tuple[str, ...],
    terminal_job_name: str,
    terminal_upload_step: str,
) -> bool:
    workflow_jobs = [job for job in jobs if str(job.get("name")) in expected_jobs]
    if (
        len(workflow_jobs) != len(expected_jobs)
        or {str(job.get("name")) for job in workflow_jobs} != set(expected_jobs)
        or any(str(job.get("status")) != "completed" for job in workflow_jobs)
    ):
        return False
    failures = [job for job in workflow_jobs if job.get("conclusion") != "success"]
    if len(failures) != 1 or failures[0].get("name") != terminal_job_name:
        return False
    terminal = failures[0]
    if (
        _positive(terminal.get("run_id"), field="terminal job run ID") != run_id
        or _positive(terminal.get("run_attempt"), field="terminal job attempt")
        != attempt
    ):
        return False
    steps = terminal.get("steps")
    if not isinstance(steps, list):
        return False
    failed_steps = [
        step for step in steps
        if isinstance(step, Mapping) and step.get("conclusion") == "failure"
    ]
    if len(failed_steps) != 1 or failed_steps[0].get("name") != terminal_upload_step:
        return False
    upload_number = _positive(failed_steps[0].get("number"), field="upload step number")
    if any(
        isinstance(step, Mapping)
        and _positive(step.get("number"), field="terminal step number") < upload_number
        and step.get("conclusion") not in {"success", "skipped"}
        for step in steps
    ):
        return False
    annotations = api.check_run_annotations(
        repository, _positive(terminal.get("id"), field="terminal job ID")
    )
    failures = [
        value for value in annotations
        if value.get("annotation_level") == "failure"
    ]
    if len(failures) != 1:
        return False
    message = str(failures[0].get("message", ""))
    if not (
        message.startswith("Failed to CreateArtifact: Unable to make request:")
        and any(marker in message for marker in _TRANSIENT_UPLOAD_MARKERS)
    ):
        return False
    shard_count = sum(name.startswith("Evidence / ") for name in expected_jobs)
    expected_artifacts = {
        f"bcf-session-{run_id}-{attempt}",
        *{
            f"bcf-evidence-{run_id}-{attempt}-shard-{index}"
            for index in range(shard_count)
        },
    }
    active_artifacts = [
        value for value in api.artifacts(repository, run_id)
        if value.get("expired") is False
    ]
    observed = {str(value.get("name")) for value in active_artifacts}
    return len(active_artifacts) == len(observed) and observed == expected_artifacts


def resolve_candidate_provider_recovery(
    api: CandidateProviderAPI,
    *,
    repository: str,
    pull_request: Mapping[str, Any],
    base_sha: str,
    head_sha: str,
    tree_sha: str,
) -> dict[str, Any]:
    """Authenticate provider execution and compile its sole lawful next action."""

    observed_repository = api.repository(repository)
    repository_id = _positive(
        observed_repository.get("id"), field="repository ID"
    )
    workflow_runs = api.workflow_runs(
        repository, GOVERNANCE_WORKFLOW_NAME, head_sha=head_sha, event="pull_request"
    )
    exact = [
        run for run in workflow_runs
        if run.get("head_sha") == head_sha
        and run.get("event") == "pull_request"
        and str(run.get("repository", {}).get("id")) == str(repository_id)
        and _run_binds_pr(
            run,
            pull_request=_positive(pull_request.get("number"), field="pull request"),
            base_sha=base_sha,
            head_sha=head_sha,
        )
    ]
    common: dict[str, Any] = {
        "repository": repository,
        "repository_id": str(repository_id),
        "pull_request": str(pull_request["number"]),
        "base_sha": base_sha,
        "head_sha": head_sha,
        "tree_sha": tree_sha,
    }
    if not exact:
        workflow = api.workflow(repository, GOVERNANCE_WORKFLOW_NAME)
        return candidate_provider_frontier(
            identity={
                **common,
                "workflow_id": str(_positive(workflow.get("id"), field="workflow ID")),
                "workflow_path": GOVERNANCE_WORKFLOW,
            },
            state="not_started",
        )
    selected = max(
        exact,
        key=lambda value: (
            _positive(value.get("id"), field="workflow run ID"),
            _positive(value.get("run_attempt"), field="workflow run attempt"),
        ),
    )
    run_id = _positive(selected.get("id"), field="workflow run ID")
    attempt = _positive(selected.get("run_attempt"), field="workflow run attempt")
    workflow_id = _positive(selected.get("workflow_id"), field="workflow ID")
    workflow = api.workflow(repository, workflow_id)
    trusted = api.content(repository, GOVERNANCE_WORKFLOW, ref=base_sha)
    try:
        authenticated = authenticate_github_run(
            expected_repository_id=str(repository_id),
            expected_workflow_id=str(workflow_id),
            expected_active_path=GOVERNANCE_WORKFLOW,
            allowed_events=("pull_request",),
            repository=observed_repository,
            workflow=workflow,
            run=selected,
            trusted_workflow_bytes=trusted.content,
            trusted_workflow_blob_oid=trusted.blob_oid,
            trusted_workflow_definition_commit=base_sha,
            candidate_tree_sha=tree_sha,
        )
    except GithubReferenceError as exc:
        raise ProspectiveValidationError(
            f"candidate provider workflow is not authenticated: {exc}"
        ) from exc
    if authenticated.run_id != str(run_id) or authenticated.run_attempt != attempt:
        raise ProspectiveValidationError("candidate provider run identity changed")
    try:
        expected_jobs = compiled_workflow_job_names(trusted.content)
    except CIAuthorityPinError as exc:
        raise ProspectiveValidationError(
            f"protected-base workflow inventory is invalid: {exc}"
        ) from exc
    jobs = api.jobs(repository, run_id, attempt=attempt)
    identity = {
        **common,
        "workflow_id": str(workflow_id),
        "workflow_path": GOVERNANCE_WORKFLOW,
        "run_id": str(run_id),
        "run_attempt": str(attempt),
    }
    if selected.get("status") != "completed":
        return candidate_provider_frontier(identity=identity, state="active")
    if selected.get("conclusion") == "success":
        completed = [
            job for job in jobs if str(job.get("name")) in expected_jobs
        ]
        state = (
            "succeeded"
            if len(completed) == len(expected_jobs)
            and {str(job.get("name")) for job in completed} == set(expected_jobs)
            and all(
                job.get("status") == "completed"
                and job.get("conclusion") == "success"
                for job in completed
            )
            else "terminal_failure"
        )
        return candidate_provider_frontier(identity=identity, state=state)
    failed_expected = [
        job for job in jobs
        if str(job.get("name")) in expected_jobs
        and job.get("conclusion") != "success"
    ]
    terminal_job = failed_expected[0] if len(failed_expected) == 1 else None
    retryable = terminal_job is not None and _transient_terminal_upload(
        api,
        repository=repository,
        run_id=run_id,
        attempt=attempt,
        jobs=jobs,
        expected_jobs=expected_jobs,
        terminal_job_name=str(terminal_job["name"]),
        terminal_upload_step=_terminal_upload_step(
            trusted.content, str(terminal_job["name"])
        ),
    )
    state = (
        "retryable_terminal_transport"
        if retryable and attempt < MAX_PROVIDER_ATTEMPTS
        else "retry_exhausted"
        if retryable
        else "terminal_failure"
    )
    if state in {"retryable_terminal_transport", "retry_exhausted"}:
        if terminal_job is None:
            raise ProspectiveValidationError(
                "retryable provider failure lacks an exact terminal job"
            )
        identity["terminal_job_id"] = str(
            _positive(terminal_job.get("id"), field="terminal job ID")
        )
    return candidate_provider_frontier(identity=identity, state=state)


def execute_candidate_provider_recovery(
    api: CandidateProviderAPI, *, repository: str, frontier: Mapping[str, Any]
) -> bool:
    """Execute only the exact rerun selected by a compiled recovery frontier."""

    if frontier.get("operation") != "candidate_provider":
        raise ProspectiveValidationError("candidate provider frontier is invalid")
    action = frontier.get("action")
    if not isinstance(action, Mapping):
        raise ProspectiveValidationError("candidate provider action is missing")
    if action.get("kind") != "rerun_exact_provider_workflow":
        return False
    identity = frontier.get("identity")
    if not isinstance(identity, Mapping) or identity.get("repository") != repository:
        raise ProspectiveValidationError("candidate provider rerun identity is invalid")
    api.rerun_workflow(repository, identity.get("run_id"))
    return True

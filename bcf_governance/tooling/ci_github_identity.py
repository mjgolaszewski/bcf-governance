"""Authenticated GitHub workflow and exact-main identity reconstruction."""

from __future__ import annotations

from dataclasses import asdict, dataclass
import hashlib
from pathlib import PurePosixPath
import re
from typing import Any

from .ci_github import GithubReferenceError, GithubRunIdentity, authenticate_github_run
from .ci_github_api import GitHubAPI, GitHubContent


SHA_PATTERN = re.compile(r"^[a-f0-9]{40}$")


class GitHubControllerError(ValueError):
    """Raised when authenticated provider state does not establish one identity."""


class ProducerNotStarted(Exception):
    """Internal signal that an admitted producer has no exact run yet."""


@dataclass(frozen=True)
class MainIdentity:
    repository_id: str
    default_branch: str
    checkout_sha: str
    tree_sha: str


def exact_sha(value: object, *, field: str) -> str:
    text = str(value)
    if not SHA_PATTERN.fullmatch(text):
        raise GitHubControllerError(f"{field} must be an exact 40-character Git SHA")
    return text


def positive_int(value: object, *, field: str) -> int:
    if isinstance(value, bool):
        raise GitHubControllerError(f"{field} must be a positive integer")
    try:
        number = int(str(value))
    except ValueError as exc:
        raise GitHubControllerError(f"{field} must be a positive integer") from exc
    if number < 1:
        raise GitHubControllerError(f"{field} must be a positive integer")
    return number


def _workflow_path(value: object) -> str:
    text = str(value)
    path = PurePosixPath(text)
    if path.is_absolute() or ".." in path.parts or not text.startswith(
        ".github/workflows/"
    ):
        raise GitHubControllerError("trusted workflow path is unsafe")
    if not re.fullmatch(r"\.github/workflows/[A-Za-z0-9_.-]+\.ya?ml", text):
        raise GitHubControllerError("trusted workflow path must name one workflow file")
    return text


def resolve_main(api: GitHubAPI, repository: str) -> MainIdentity:
    repo = api.repository(repository)
    repository_id = str(positive_int(repo.get("id"), field="repository ID"))
    branch = repo.get("default_branch")
    if not isinstance(branch, str) or not re.fullmatch(r"[A-Za-z0-9._/-]+", branch):
        raise GitHubControllerError("default branch is missing or unsafe")
    reference = api.reference(repository, f"heads/{branch}")
    target = reference.get("object")
    if not isinstance(target, dict) or target.get("type") != "commit":
        raise GitHubControllerError("default branch must resolve directly to a commit")
    commit_sha = exact_sha(target.get("sha"), field="default-main SHA")
    commit = api.commit(repository, commit_sha)
    tree = commit.get("tree")
    if not isinstance(tree, dict):
        raise GitHubControllerError("default-main commit tree is missing")
    return MainIdentity(
        repository_id=repository_id,
        default_branch=branch,
        checkout_sha=commit_sha,
        tree_sha=exact_sha(tree.get("sha"), field="default-main tree SHA"),
    )


def _trusted_workflow_source(
    api: GitHubAPI,
    *,
    repository: str,
    main: MainIdentity,
    active_path: str,
    expected_blob_oid: object | None,
    expected_sha256: str | None,
    definition_commit: object | None,
) -> tuple[GitHubContent, str]:
    """Bind current workflow bytes to their declared immutable definition."""

    current = api.content(repository, active_path, ref=main.checkout_sha)
    definition = (
        main.checkout_sha
        if definition_commit is None
        else exact_sha(definition_commit, field="workflow definition commit")
    )
    pinned = current if definition == main.checkout_sha else api.content(
        repository, active_path, ref=definition
    )
    if expected_blob_oid is not None and pinned.blob_oid != exact_sha(
        expected_blob_oid, field="trusted workflow blob OID"
    ):
        raise GitHubControllerError(
            "trusted workflow bytes blob does not match its definition"
        )
    digest = hashlib.sha256(pinned.content).hexdigest()
    if expected_sha256 is not None:
        if not re.fullmatch(r"[a-f0-9]{64}", expected_sha256):
            raise GitHubControllerError("trusted workflow digest pin must be SHA-256")
        if digest != expected_sha256:
            raise GitHubControllerError(
                "trusted workflow bytes digest does not match its definition"
            )
    if current.blob_oid != pinned.blob_oid or current.content != pinned.content:
        raise GitHubControllerError(
            "current default-main workflow bytes differ from the pinned definition"
        )
    return pinned, definition


def authenticate_trusted_run(
    api: GitHubAPI,
    *,
    repository: str,
    main: MainIdentity,
    run_id: object,
    run_attempt: object,
    workflow_path: str,
    expected_event: str,
    require_success: bool,
    expected_workflow_id: object | None = None,
    expected_workflow_sha256: str | None = None,
    expected_workflow_blob_oid: object | None = None,
    expected_workflow_definition_commit: object | None = None,
) -> GithubRunIdentity:
    """Authenticate provider identity without self-embedding workflow digests."""

    numeric_run = str(positive_int(run_id, field="trusted run ID"))
    attempt = positive_int(run_attempt, field="trusted run attempt")
    active_path = _workflow_path(workflow_path)
    run = api.run(repository, numeric_run)
    observed_workflow_id = str(
        positive_int(run.get("workflow_id"), field="observed workflow ID")
    )
    if expected_workflow_id is not None and observed_workflow_id != str(
        positive_int(expected_workflow_id, field="expected workflow ID")
    ):
        raise GitHubControllerError(
            "trusted workflow run is not authenticated: workflow ID does not match "
            "the optional pin"
        )
    workflow = api.workflow(repository, observed_workflow_id)
    trusted, definition_commit = _trusted_workflow_source(
        api,
        repository=repository,
        main=main,
        active_path=active_path,
        expected_blob_oid=expected_workflow_blob_oid,
        expected_sha256=expected_workflow_sha256,
        definition_commit=expected_workflow_definition_commit,
    )
    try:
        identity = authenticate_github_run(
            expected_repository_id=main.repository_id,
            expected_workflow_id=observed_workflow_id,
            expected_active_path=active_path,
            allowed_events=(expected_event,),
            repository={"id": int(main.repository_id)},
            workflow=workflow,
            run=run,
            trusted_workflow_bytes=trusted.content,
            trusted_workflow_blob_oid=trusted.blob_oid,
            trusted_workflow_definition_commit=definition_commit,
            candidate_tree_sha=main.tree_sha,
        )
    except GithubReferenceError as exc:
        raise GitHubControllerError(
            f"trusted workflow run is not authenticated: {exc}"
        ) from exc
    if (
        identity.run_id != numeric_run
        or identity.run_attempt != attempt
        or identity.candidate.checkout_sha != main.checkout_sha
        or identity.candidate.tree_sha != main.tree_sha
    ):
        raise GitHubControllerError("trusted run is not bound to current exact main")
    digest = hashlib.sha256(trusted.content).hexdigest()
    if expected_workflow_sha256 is not None:
        if not re.fullmatch(r"[a-f0-9]{64}", expected_workflow_sha256):
            raise GitHubControllerError("optional workflow digest pin must be SHA-256")
        if digest != expected_workflow_sha256:
            raise GitHubControllerError(
                "trusted workflow run is not authenticated: workflow bytes do not "
                "match the optional pin"
            )
    if require_success and not (
        run.get("status") == "completed" and run.get("conclusion") == "success"
    ):
        raise GitHubControllerError("latest trusted run attempt is not successful")
    return identity


def resolve_trusted_run(
    api: GitHubAPI,
    *,
    repository: str,
    main: MainIdentity,
    workflow_path: str,
    expected_event: str,
    require_success: bool,
    expected_workflow_id: object | None = None,
    expected_workflow_sha256: str | None = None,
    expected_workflow_blob_oid: object | None = None,
    expected_workflow_definition_commit: object | None = None,
) -> GithubRunIdentity:
    """Select the latest exact-SHA attempt, then authenticate it without fallback."""

    active_path = _workflow_path(workflow_path)
    candidates = api.workflow_runs(
        repository,
        PurePosixPath(active_path).name,
        head_sha=main.checkout_sha,
        event=expected_event,
    )
    exact = [
        run
        for run in candidates
        if str(run.get("head_sha")) == main.checkout_sha
        and str(run.get("repository", {}).get("id")) == main.repository_id
        and str(run.get("event")) == expected_event
    ]
    if not exact:
        raise GitHubControllerError("no exact-main trusted workflow run exists")
    selected = max(
        exact,
        key=lambda value: (
            positive_int(value.get("id"), field="trusted run ID"),
            positive_int(value.get("run_attempt"), field="trusted run attempt"),
        ),
    )
    return authenticate_trusted_run(
        api,
        repository=repository,
        main=main,
        run_id=selected.get("id"),
        run_attempt=selected.get("run_attempt"),
        workflow_path=active_path,
        expected_event=expected_event,
        require_success=require_success,
        expected_workflow_id=expected_workflow_id,
        expected_workflow_sha256=expected_workflow_sha256,
        expected_workflow_blob_oid=expected_workflow_blob_oid,
        expected_workflow_definition_commit=expected_workflow_definition_commit,
    )


def authenticate_producer_workflow(
    api: GitHubAPI,
    *,
    repository: str,
    main: MainIdentity,
    producer: dict[str, Any],
    run: dict[str, Any],
) -> dict[str, str]:
    expected = producer["workflow"]
    workflow = api.workflow(repository, expected["workflow_id"])
    trusted, definition_commit = _trusted_workflow_source(
        api,
        repository=repository,
        main=main,
        active_path=str(expected["active_path"]),
        expected_blob_oid=expected["trusted_workflow_blob_oid"],
        expected_sha256=str(expected["trusted_workflow_sha256"]),
        definition_commit=expected["trusted_workflow_definition_commit"],
    )
    try:
        identity = authenticate_github_run(
            expected_repository_id=main.repository_id,
            expected_workflow_id=str(expected["workflow_id"]),
            expected_active_path=str(expected["active_path"]),
            allowed_events=tuple(str(value) for value in expected["allowed_events"]),
            repository={"id": int(main.repository_id)},
            workflow=workflow,
            run=run,
            trusted_workflow_bytes=trusted.content,
            trusted_workflow_blob_oid=trusted.blob_oid,
            trusted_workflow_definition_commit=definition_commit,
            candidate_tree_sha=main.tree_sha,
        )
    except GithubReferenceError as exc:
        raise GitHubControllerError(
            f"producer {producer['producer_id']} run is not authenticated: {exc}"
        ) from exc
    observed = asdict(identity.workflow)
    pinned = {
        "workflow_id": str(expected["workflow_id"]),
        "active_path": str(expected["active_path"]),
        "trusted_workflow_blob_oid": str(expected["trusted_workflow_blob_oid"]),
        "trusted_workflow_sha256": str(expected["trusted_workflow_sha256"]),
        "trusted_workflow_definition_commit": str(
            expected["trusted_workflow_definition_commit"]
        ),
    }
    if any(str(observed[key]) != value for key, value in pinned.items()):
        raise GitHubControllerError(
            f"producer {producer['producer_id']} trusted workflow bytes do not match authority"
        )
    return {key: str(value) for key, value in observed.items()}


def select_producer_run(
    api: GitHubAPI,
    *,
    repository: str,
    main: MainIdentity,
    producer: dict[str, Any],
) -> dict[str, Any]:
    expected = producer["workflow"]
    candidates: list[dict[str, Any]] = []
    for event in expected["allowed_events"]:
        candidates.extend(
            api.workflow_runs(
                repository,
                expected["workflow_id"],
                head_sha=main.checkout_sha,
                event=str(event),
            )
        )
    exact = [
        run
        for run in candidates
        if str(run.get("head_sha")) == main.checkout_sha
        and str(run.get("workflow_id")) == str(expected["workflow_id"])
        and str(run.get("repository", {}).get("id")) == main.repository_id
    ]
    if not exact:
        raise ProducerNotStarted
    return max(
        exact,
        key=lambda value: (
            positive_int(value["id"], field="producer run ID"),
            positive_int(value["run_attempt"], field="producer run attempt"),
        ),
    )

"""GitHub reference topology and authenticated run identity.

Provider callbacks are hints.  This module accepts only provider API records and
trusted default-branch workflow bytes when it constructs an authority identity.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
import hashlib
from pathlib import Path, PurePosixPath
import re
from typing import Any

from .ci_authority_state import CandidateIdentity, WorkflowIdentity


SHA_PATTERN = re.compile(r"^[a-f0-9]{40}$")
DISPATCH_EVENTS = (
    "bcf-exact-ref-v1",
    "bcf-certification-finalize-v1",
    "bcf-status-publish-v1",
)
FORBIDDEN_CANDIDATE_CAPABILITIES = frozenset(
    {
        "actions:write",
        "checks:write",
        "contents:write",
        "deployments:write",
        "id-token:write",
        "packages:write",
        "statuses:write",
    }
)


class GithubReferenceError(ValueError):
    """Raised when GitHub identity or topology is not fail-closed."""


@dataclass(frozen=True)
class GithubRunIdentity:
    workflow: WorkflowIdentity
    candidate: CandidateIdentity
    run_id: str
    run_attempt: int


def _integer_id(value: Any, *, field: str) -> str:
    if isinstance(value, bool) or not isinstance(value, (int, str)):
        raise GithubReferenceError(f"{field} must be a positive numeric provider ID")
    text = str(value)
    if not text.isdigit() or int(text) <= 0:
        raise GithubReferenceError(f"{field} must be a positive numeric provider ID")
    return text


def _sha(value: Any, *, field: str) -> str:
    text = str(value)
    if not SHA_PATTERN.fullmatch(text):
        raise GithubReferenceError(f"{field} must be an exact 40-character Git SHA")
    return text


def _active_path(value: Any) -> str:
    text = str(value)
    path = PurePosixPath(text)
    if path.is_absolute() or ".." in path.parts or not text.startswith(".github/workflows/"):
        raise GithubReferenceError("workflow path must be an active repository workflow path")
    return text


def authenticate_github_run(
    *,
    expected_repository_id: str,
    expected_workflow_id: str,
    expected_active_path: str,
    allowed_events: tuple[str, ...],
    repository: dict[str, Any],
    workflow: dict[str, Any],
    run: dict[str, Any],
    trusted_workflow_bytes: bytes,
    trusted_workflow_blob_oid: str,
    trusted_workflow_definition_commit: str,
    candidate_tree_sha: str,
) -> GithubRunIdentity:
    """Authenticate one run from provider API records, never presentation fields."""

    repository_id = _integer_id(repository.get("id"), field="repository.id")
    workflow_id = _integer_id(workflow.get("id"), field="workflow.id")
    run_workflow_id = _integer_id(run.get("workflow_id"), field="run.workflow_id")
    if repository_id != _integer_id(expected_repository_id, field="expected repository ID"):
        raise GithubReferenceError("provider repository identity does not match authority")
    if workflow_id != _integer_id(expected_workflow_id, field="expected workflow ID"):
        raise GithubReferenceError("provider workflow identity does not match authority")
    if run_workflow_id != workflow_id:
        raise GithubReferenceError("run workflow identity does not match active workflow")
    active_path = _active_path(workflow.get("path"))
    if active_path != _active_path(expected_active_path):
        raise GithubReferenceError("active workflow path does not match authority")
    event = str(run.get("event", ""))
    if event not in allowed_events:
        raise GithubReferenceError("run event is not admitted by authority")
    run_repository = run.get("repository")
    if not isinstance(run_repository, dict) or str(run_repository.get("id")) != repository_id:
        raise GithubReferenceError("run repository identity does not match authority")
    attempt = run.get("run_attempt")
    if isinstance(attempt, bool) or not isinstance(attempt, int) or attempt <= 0:
        raise GithubReferenceError("run attempt must be a positive integer")
    digest = hashlib.sha256(trusted_workflow_bytes).hexdigest()
    workflow_identity = WorkflowIdentity(
        provider="github",
        repository_id=repository_id,
        workflow_id=workflow_id,
        active_path=active_path,
        trusted_workflow_blob_oid=_sha(
            trusted_workflow_blob_oid, field="trusted workflow blob OID"
        ),
        trusted_workflow_sha256=digest,
        trusted_workflow_definition_commit=_sha(
            trusted_workflow_definition_commit,
            field="trusted workflow definition commit",
        ),
        event=event,
    )
    return GithubRunIdentity(
        workflow=workflow_identity,
        candidate=CandidateIdentity(
            checkout_sha=_sha(run.get("head_sha"), field="run.head_sha"),
            tree_sha=_sha(candidate_tree_sha, field="candidate tree SHA"),
        ),
        run_id=_integer_id(run.get("id"), field="run.id"),
        run_attempt=attempt,
    )


def reference_topology(
    *,
    candidate_labels: tuple[str, ...],
    trusted_labels: tuple[str, ...],
) -> dict[str, Any]:
    """Return the provider-neutral security shape used by the GitHub adopter."""

    if not candidate_labels or not trusted_labels:
        raise GithubReferenceError("candidate and trusted runner labels must be non-empty")
    if set(candidate_labels) & set(trusted_labels):
        raise GithubReferenceError("candidate and trusted runner labels must be disjoint")
    return {
        "schema_version": "1.0",
        "provider": "github",
        "dispatch_events": list(DISPATCH_EVENTS),
        "roles": [
            {
                "id": "exact-main-kickoff",
                "runner_labels": list(trusted_labels),
                "code_execution": False,
                "checkout": False,
                "permissions": ["actions:write", "contents:read"],
            },
            {
                "id": "exact-ref-producer",
                "runner_labels": list(candidate_labels),
                "code_execution": True,
                "checkout": True,
                "persist_credentials": False,
                "permissions": ["contents:read"],
                "disposable": True,
            },
            {
                "id": "trusted-finalizer",
                "runner_labels": list(trusted_labels),
                "code_execution": False,
                "checkout": False,
                "permissions": ["actions:read", "contents:read"],
            },
            {
                "id": "status-publisher",
                "runner_labels": list(trusted_labels),
                "code_execution": False,
                "checkout": False,
                "permissions": ["actions:read", "contents:read", "statuses:write"],
            },
        ],
        "coordination": {
            "polling": False,
            "sleeping": False,
            "idle_waiter": False,
            "callback_payload_authoritative": False,
            "provider_api_reconstruction": True,
        },
    }


def validate_reference_topology(payload: dict[str, Any]) -> None:
    """Fail closed on privilege crossover, presentation authority, or idle coordination."""

    if payload.get("provider") != "github" or payload.get("schema_version") != "1.0":
        raise GithubReferenceError("unsupported GitHub topology contract")
    if tuple(payload.get("dispatch_events", ())) != DISPATCH_EVENTS:
        raise GithubReferenceError("GitHub dispatch event inventory must be exact and closed")
    roles = payload.get("roles")
    if not isinstance(roles, list):
        raise GithubReferenceError("GitHub topology roles must be a list")
    by_id = {str(role.get("id")): role for role in roles if isinstance(role, dict)}
    expected = {"exact-main-kickoff", "exact-ref-producer", "trusted-finalizer", "status-publisher"}
    if set(by_id) != expected or len(roles) != len(expected):
        raise GithubReferenceError("GitHub topology role inventory must be exact")
    candidate = by_id["exact-ref-producer"]
    candidate_permissions = set(candidate.get("permissions", ()))
    if candidate_permissions & FORBIDDEN_CANDIDATE_CAPABILITIES:
        raise GithubReferenceError("candidate role has write authority")
    if not candidate.get("disposable") or candidate.get("persist_credentials") is not False:
        raise GithubReferenceError("candidate role must be disposable without persisted credentials")
    candidate_labels = set(candidate.get("runner_labels", ()))
    for role_id in expected - {"exact-ref-producer"}:
        role = by_id[role_id]
        if role.get("code_execution") or role.get("checkout"):
            raise GithubReferenceError(f"trusted role {role_id} may not execute or check out code")
        if candidate_labels & set(role.get("runner_labels", ())):
            raise GithubReferenceError("candidate and trusted runner labels overlap")
    coordination = payload.get("coordination", {})
    if any(coordination.get(key) for key in ("polling", "sleeping", "idle_waiter")):
        raise GithubReferenceError("GitHub reference topology may not idle or poll")
    if coordination.get("callback_payload_authoritative") is not False:
        raise GithubReferenceError("callback payload cannot be authority")
    if coordination.get("provider_api_reconstruction") is not True:
        raise GithubReferenceError("trusted decisions must reconstruct provider state")


def topology_document(
    *, candidate_labels: tuple[str, ...], trusted_labels: tuple[str, ...]
) -> dict[str, Any]:
    payload = reference_topology(
        candidate_labels=candidate_labels, trusted_labels=trusted_labels
    )
    validate_reference_topology(payload)
    return payload


def workflow_digest(path: Path) -> str:
    if not path.is_file() or path.is_symlink():
        raise GithubReferenceError(f"trusted workflow is not a regular file: {path}")
    return hashlib.sha256(path.read_bytes()).hexdigest()


def identity_as_dict(identity: GithubRunIdentity) -> dict[str, Any]:
    return asdict(identity)

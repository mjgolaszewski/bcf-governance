"""Authenticate exact GitHub workflow artifacts for privileged control decisions."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import asdict, dataclass, fields
import re
from typing import Any

from .ci_github_api import GitHubAPI
from .ci_github_authority import authenticate_role_run
from .ci_github_identity import GitHubControllerError, MainIdentity


@dataclass(frozen=True)
class ProviderArtifact:
    """One provider-authenticated artifact bound to an exact workflow attempt."""

    run_id: str
    run_attempt: int
    artifact_id: str
    artifact_name: str
    provider_digest: str
    workflow: dict[str, Any]

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


def provider_artifact_reference_keys() -> frozenset[str]:
    """Derive the closed download-coordinate shape from its semantic owner."""

    return frozenset(
        field.name for field in fields(ProviderArtifact) if field.name != "workflow"
    )


def provider_artifact_reference(
    value: ProviderArtifact | Mapping[str, Any], *, label: str = "provider artifact"
) -> dict[str, Any]:
    """Project or decode the sole closed artifact reference accepted by workflows."""

    keys = provider_artifact_reference_keys()
    if isinstance(value, ProviderArtifact):
        return {key: getattr(value, key) for key in sorted(keys)}
    if set(value) != keys:
        raise GitHubControllerError(f"{label} identity is not exact")
    return {key: value[key] for key in sorted(keys)}


def provider_digest(value: object) -> str:
    """Decode the sole provider digest representation accepted by BCF."""

    text = str(value)
    if not re.fullmatch(r"sha256:[a-f0-9]{64}", text):
        raise GitHubControllerError("provider artifact digest must be SHA-256")
    return text


def _artifact_name(value: object) -> str:
    name = str(value)
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,254}", name):
        raise GitHubControllerError("provider artifact name is unsafe")
    return name


def _positive_id(value: object, *, label: str) -> str:
    text = str(value)
    if not text.isdigit() or int(text) < 1:
        raise GitHubControllerError(f"{label} must be a positive provider ID")
    return text


def authenticate_role_artifact(
    api: GitHubAPI,
    *,
    repository: str,
    main: MainIdentity,
    authority: dict[str, Any],
    role: str,
    run_id: object,
    run_attempt: object,
    artifact_id: object,
    artifact_name: object,
    artifact_digest: object,
    require_success: bool,
) -> ProviderArtifact:
    """Authenticate role, attempt, artifact metadata, repository, and subject together."""

    identity = authenticate_role_run(
        api,
        repository=repository,
        main=main,
        authority=authority,
        role=role,
        run_id=run_id,
        run_attempt=run_attempt,
        require_success=require_success,
    )
    expected_id = _positive_id(artifact_id, label="provider artifact ID")
    expected_name = _artifact_name(artifact_name)
    expected_digest = provider_digest(artifact_digest)
    matching = [
        artifact
        for artifact in api.artifacts(repository, identity.run_id)
        if str(artifact.get("id")) == expected_id
        and artifact.get("name") == expected_name
        and artifact.get("expired") is False
        and artifact.get("digest") == expected_digest
    ]
    return _materialize_artifact(identity, main=main, matching=matching)


def _materialize_artifact(
    identity: Any, *, main: MainIdentity, matching: list[dict[str, Any]]
) -> ProviderArtifact:
    if len(matching) != 1:
        raise GitHubControllerError("provider artifact identity is not exact")
    artifact = matching[0]
    workflow_run = artifact.get("workflow_run")
    if not isinstance(workflow_run, dict) or workflow_run != {
        "id": int(identity.run_id),
        "repository_id": int(main.repository_id),
        "head_repository_id": int(main.repository_id),
        "head_branch": main.default_branch,
        "head_sha": main.checkout_sha,
    }:
        raise GitHubControllerError("provider artifact workflow subject is not exact")
    return ProviderArtifact(
        run_id=identity.run_id,
        run_attempt=identity.run_attempt,
        artifact_id=_positive_id(artifact.get("id"), label="provider artifact ID"),
        artifact_name=_artifact_name(artifact.get("name")),
        provider_digest=provider_digest(artifact.get("digest")),
        workflow=asdict(identity.workflow),
    )


def resolve_role_artifact(
    api: GitHubAPI,
    *,
    repository: str,
    main: MainIdentity,
    authority: dict[str, Any],
    role: str,
    run_id: object,
    run_attempt: object,
    artifact_name: object,
    require_success: bool,
) -> ProviderArtifact:
    """Resolve one exact-name artifact only after authenticating its owning role."""

    identity = authenticate_role_run(
        api,
        repository=repository,
        main=main,
        authority=authority,
        role=role,
        run_id=run_id,
        run_attempt=run_attempt,
        require_success=require_success,
    )
    expected_name = _artifact_name(artifact_name)
    matching = [
        artifact
        for artifact in api.artifacts(repository, identity.run_id)
        if artifact.get("name") == expected_name and artifact.get("expired") is False
    ]
    return _materialize_artifact(identity, main=main, matching=matching)

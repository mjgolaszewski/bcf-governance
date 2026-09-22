"""Authenticate one same-admission trusted prior-evidence transport artifact."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
from typing import Any

from .ci_github_artifacts import ProviderArtifact, resolve_role_artifact
from .ci_github_authority import packaged_repo_root
from .ci_github_identity import GitHubControllerError, MainIdentity
from .evidence_execution import EvidenceError
from .prior_evidence_receipts import _transport_schema, validate_transport_material
from .prior_evidence_transport import _archive_files


@dataclass(frozen=True)
class AuthenticatedPriorTransport:
    artifact: ProviderArtifact
    manifest: dict[str, Any]
    files: dict[str, bytes]


def _validate_transport_schema(manifest: dict[str, Any]) -> None:
    try:
        _transport_schema(manifest, packaged_repo_root() / "schemas")
    except EvidenceError as exc:
        raise GitHubControllerError("prior transport schema is not exact") from exc


def _validate_source_references(manifest: dict[str, Any], files: dict[str, bytes]) -> None:
    artifacts = {value["artifact_id"]: value for value in manifest["artifacts"]}
    if len(artifacts) != len(manifest["artifacts"]):
        raise GitHubControllerError("prior transport artifact identities are duplicated")
    for artifact in artifacts.values():
        if artifact["provider_digest"] != "sha256:" + artifact["archive_sha256"]:
            raise GitHubControllerError("prior transport archive provider digest differs")
    repository = manifest["repository"]["full_name"]
    run_id = manifest["producer"]["run_id"]
    attempt = manifest["producer"]["run_attempt"]
    identities: set[str] = set()
    for receipt in manifest["receipts"]:
        artifact = artifacts.get(receipt["artifact_id"])
        if artifact is None or artifact["name"] != receipt["artifact_name"]:
            raise GitHubControllerError("prior transport receipt artifact is not exact")
        expected = (
            f"github-actions://{repository}/runs/{run_id}/attempts/{attempt}/"
            f"artifacts/{receipt['artifact_id']}/{receipt['path']}"
        )
        if receipt["immutable_reference"] != expected:
            raise GitHubControllerError("prior transport receipt reference is not immutable")
        raw = files[f"expanded/{receipt['artifact_id']}/{receipt['path']}"]
        try:
            payload = json.loads(raw)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise GitHubControllerError("prior transport source receipt is invalid") from exc
        evidence_id = receipt["evidence_id"]
        if (not isinstance(payload, dict) or payload.get("evidence_id") != evidence_id
            or evidence_id in identities):
            raise GitHubControllerError("prior transport receipt identity is not exact")
        identities.add(evidence_id)


def authenticate_prior_transport(
    api: Any, *, repository: str, main: MainIdentity,
    authority: dict[str, Any], run_id: str, run_attempt: int,
) -> AuthenticatedPriorTransport:
    """Bind transport bytes to the exact trusted admission workflow attempt."""
    artifact = resolve_role_artifact(
        api, repository=repository, main=main, authority=authority,
        role="admission", run_id=run_id, run_attempt=run_attempt,
        artifact_name=f"bcf-prior-evidence-transport-{run_id}-{run_attempt}",
        require_success=False,
    )
    raw = api.artifact_bytes(
        repository, artifact.artifact_id, maximum_bytes=104_857_600,
    )
    if artifact.provider_digest != "sha256:" + hashlib.sha256(raw).hexdigest():
        raise GitHubControllerError("prior transport artifact differs from provider digest")
    files = _archive_files(raw)
    manifest_bytes = files.get("prior-evidence-transport.json")
    if manifest_bytes is None:
        raise GitHubControllerError("prior transport manifest is missing")
    try:
        manifest = json.loads(manifest_bytes.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise GitHubControllerError("prior transport manifest is invalid") from exc
    if not isinstance(manifest, dict):
        raise GitHubControllerError("prior transport manifest must be an object")
    _validate_transport_schema(manifest)
    merge = manifest.get("merge")
    if manifest.get("repository") != {
        "provider": "github", "full_name": repository,
        "repository_id": main.repository_id,
    } or not isinstance(merge, dict) or merge.get("commit_sha") != main.checkout_sha:
        raise GitHubControllerError("prior transport repository or merge is not exact")
    protection = manifest.get("protection")
    if (not isinstance(protection, dict) or protection.get("provider_state") != "clean"
        or protection.get("bypass_actors") != []
        or protection.get("required_context") != "bcf/pr-certification"
        or protection.get("publisher_app_id") != 15368):
        raise GitHubControllerError("prior transport protection authority is not exact")
    try:
        validate_transport_material(
            files, manifest,
            {"commit_sha": main.checkout_sha, "tree_sha": main.tree_sha},
        )
    except EvidenceError as exc:
        raise GitHubControllerError(str(exc)) from exc
    _validate_source_references(manifest, files)
    return AuthenticatedPriorTransport(artifact, manifest, files)

"""Provider and packaged-runtime checks for exact adopter qualification."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any, Mapping

from .ci_github_api import GitHubAPI
from .ci_github_artifacts import ProviderArtifact, resolve_role_artifact
from .ci_github_identity import GitHubControllerError
from .ci_github_identity import MainIdentity
from .ci_authority_contracts import authority_role_workflow
from .release_adopter_qualification import (
    ReleaseQualificationError,
    parse_contract,
    validate_qualification_receipt,
)
from .release_adopter_sources import (
    AdopterSourceError,
    adopter_provider_access_from_environment,
    authenticate_adopter_sources,
)


def _json_object(path: Path, label: str) -> dict[str, Any]:
    if path.is_symlink() or not path.is_file():
        raise GitHubControllerError(f"{label} must be a regular file")
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise GitHubControllerError(f"{label} is invalid JSON") from exc
    if not isinstance(value, dict):
        raise GitHubControllerError(f"{label} must contain an object")
    return value


def authenticate_release_qualification(
    api: GitHubAPI,
    *,
    repository: str,
    main: MainIdentity,
    authority: dict[str, Any],
    qualification_path: Path,
    release_assets: Mapping[str, str],
    version: str,
    run_id: object,
    run_attempt: object,
    artifact_name: str,
) -> tuple[dict[str, Any], ProviderArtifact]:
    """Authenticate one provider-produced exact adopter qualification artifact."""

    contract_content = api.content(
        repository, "governance/release-qualification.yml", ref=main.checkout_sha
    )
    schema_content = api.content(
        repository, "schemas/release-qualification.schema.json", ref=main.checkout_sha
    )
    contract = parse_contract(contract_content.content, schema_content.content)
    try:
        adopter_provider_access = adopter_provider_access_from_environment(contract)
    except AdopterSourceError as exc:
        raise GitHubControllerError(
            "release qualification provider credentials are invalid"
        ) from exc
    qualification = _json_object(
        qualification_path, "release qualification receipt"
    )
    workflow = authority_role_workflow(authority, "release_verifier")
    producer = {
        "repository_id": main.repository_id,
        "workflow": workflow["active_path"],
        "job": "qualify",
        "run_id": str(run_id),
        "run_attempt": str(run_attempt),
    }
    try:
        validated = validate_qualification_receipt(
            qualification,
            contract=contract,
            contract_sha256=hashlib.sha256(contract_content.content).hexdigest(),
            repository=repository,
            commit_sha=main.checkout_sha,
            tree_sha=main.tree_sha,
            version=version,
            assets=release_assets,
            producer=producer,
        )
        authenticate_adopter_sources(adopter_provider_access, validated)
    except (KeyError, TypeError, AdopterSourceError, ReleaseQualificationError) as exc:
        raise GitHubControllerError("release qualification receipt is invalid") from exc
    artifact = resolve_role_artifact(
        api,
        repository=repository,
        main=main,
        authority=authority,
        role="release_verifier",
        run_id=run_id,
        run_attempt=run_attempt,
        artifact_name=artifact_name,
        require_success=False,
    )
    return validated, artifact


def require_publication_qualification(
    path: Path,
    *,
    contract_bytes: bytes,
    schema_bytes: bytes,
    repository: str,
    commit_sha: str,
    tree_sha: str,
    version: str,
    assets: Mapping[str, str],
    producer: Mapping[str, Any],
) -> None:
    """Fail closed unless publication consumes the exact packaged contract result."""

    try:
        qualification = _json_object(path, "release qualification receipt")
        validate_qualification_receipt(
            qualification,
            contract=parse_contract(contract_bytes, schema_bytes),
            contract_sha256=hashlib.sha256(contract_bytes).hexdigest(),
            repository=repository,
            commit_sha=commit_sha,
            tree_sha=tree_sha,
            version=version,
            assets=assets,
            producer=producer,
        )
    except ReleaseQualificationError as exc:
        raise GitHubControllerError(
            "publication requires exact passing adopter qualification"
        ) from exc


def require_provider_publication_qualification(
    api: GitHubAPI,
    *,
    repository: str,
    main: MainIdentity,
    path: Path,
    version: str,
    assets: Mapping[str, str],
    producer: Mapping[str, Any],
) -> None:
    """Resolve exact-main contract bytes before checking publication eligibility."""

    require_publication_qualification(
        path,
        contract_bytes=api.content(
            repository, "governance/release-qualification.yml", ref=main.checkout_sha
        ).content,
        schema_bytes=api.content(
            repository, "schemas/release-qualification.schema.json", ref=main.checkout_sha
        ).content,
        repository=repository,
        commit_sha=main.checkout_sha,
        tree_sha=main.tree_sha,
        version=version,
        assets=assets,
        producer=producer,
    )

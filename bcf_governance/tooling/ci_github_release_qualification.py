"""Provider and packaged-runtime checks for exact adopter qualification."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any, Mapping

from .ci_github_api import GitHubAPI
from .ci_github_bundle import write_exclusive
from .ci_github_identity import GitHubControllerError, resolve_main
from .ci_github_identity import MainIdentity
from .release_adopter_qualification import (
    ReleaseQualificationError,
    parse_contract,
    validate_qualification_receipt,
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
    event_path: Path,
    output_path: Path,
) -> dict[str, Any]:
    """Authenticate one exact local observation carried by repository dispatch."""

    event = _json_object(event_path, "release qualification event")
    event_repository = event.get("repository")
    payload = event.get("client_payload")
    if event.get("action") != "bcf_release_qualified":
        raise GitHubControllerError("release qualification event type is not exact")
    if (
        not isinstance(event_repository, dict)
        or event_repository.get("full_name") != repository
        or not isinstance(payload, dict)
        or set(payload) != {"qualification"}
    ):
        raise GitHubControllerError("release qualification event custody is not exact")
    main = resolve_main(api, repository)
    if str(event_repository.get("id")) != main.repository_id:
        raise GitHubControllerError("release qualification repository identity differs")
    contract_content = api.content(
        repository, "governance/release-qualification.yml", ref=main.checkout_sha
    )
    schema_content = api.content(
        repository, "schemas/release-qualification.schema.json", ref=main.checkout_sha
    )
    contract = parse_contract(contract_content.content, schema_content.content)
    qualification = payload["qualification"]
    try:
        release = qualification["release"]
        validated = validate_qualification_receipt(
            qualification,
            contract=contract,
            contract_sha256=hashlib.sha256(contract_content.content).hexdigest(),
            repository=repository,
            commit_sha=main.checkout_sha,
            tree_sha=main.tree_sha,
            version=release["version"],
            assets=release["assets"],
        )
    except (KeyError, TypeError, ReleaseQualificationError) as exc:
        raise GitHubControllerError("release qualification receipt is invalid") from exc
    write_exclusive(output_path, validated)
    return validated


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
    )

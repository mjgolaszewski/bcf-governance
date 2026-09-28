"""Authenticate one exact-main admission's standalone controller custody."""

from __future__ import annotations

import hashlib
import json
from typing import Any

from .ci_github_artifacts import resolve_role_artifact
from .ci_github_identity import GitHubControllerError, MainIdentity
from .controller_custody import validate_controller_custody
from .prior_evidence_transport import _archive_files


def authenticate_controller_custody(
    api: Any,
    *,
    repository: str,
    main: MainIdentity,
    authority: dict[str, Any],
    run_id: str,
    run_attempt: int,
) -> dict[str, Any]:
    """Require one closed provider artifact bound to admission, subject, and repo."""

    artifact = resolve_role_artifact(
        api,
        repository=repository,
        main=main,
        authority=authority,
        role="admission",
        run_id=run_id,
        run_attempt=run_attempt,
        artifact_name=f"bcf-controller-custody-{run_id}-{run_attempt}",
        require_success=False,
    )
    raw = api.artifact_bytes(
        repository, artifact.artifact_id, maximum_bytes=1_048_576
    )
    if artifact.provider_digest != "sha256:" + hashlib.sha256(raw).hexdigest():
        raise GitHubControllerError("controller custody artifact differs from provider digest")
    files = _archive_files(raw)
    if set(files) != {"controller-custody.json"}:
        raise GitHubControllerError("controller custody artifact inventory is not exact")
    try:
        custody = validate_controller_custody(
            json.loads(files["controller-custody.json"])
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise GitHubControllerError("controller custody artifact is invalid") from exc
    if custody["repository"] != {
        "full_name": repository,
        "repository_id": main.repository_id,
    } or custody["subject"] != {
        "commit_sha": main.checkout_sha,
        "tree_sha": main.tree_sha,
    }:
        raise GitHubControllerError("controller custody artifact subject is not exact")
    return custody

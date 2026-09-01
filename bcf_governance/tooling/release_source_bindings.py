"""Exact-main Git custody for closed release dependency inputs."""

from __future__ import annotations

import hashlib
from pathlib import Path
import re
from typing import Any

from .ci_github_api import GitHubAPI
from .ci_github_identity import GitHubControllerError


SOURCES = {
    "dependency_lock": "release/requirements-cp312-linux-x86_64.lock",
    "wheelhouse_manifest": "release/wheelhouse-manifest.yml",
}


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def release_source_bindings(
    api: GitHubAPI, repository: str, commit_sha: str
) -> dict[str, dict[str, str]]:
    """Bind closed release inputs to authenticated exact-main Git blobs."""

    bindings: dict[str, dict[str, str]] = {}
    for key, relative in SOURCES.items():
        source = api.content(repository, relative, ref=commit_sha)
        bindings[key] = {
            "path": relative,
            "blob_oid": source.blob_oid,
            "sha256": hashlib.sha256(source.content).hexdigest(),
        }
    return bindings


def verify_release_source_bindings(
    authorization: dict[str, Any], manifest_path: Path, lock_path: Path
) -> None:
    """Reject candidate-selected dependency inputs before build or verification."""

    bindings = authorization.get("release_inputs")
    if not isinstance(bindings, dict) or set(bindings) != set(SOURCES):
        raise GitHubControllerError("release source binding inventory is not exact")
    paths = {"dependency_lock": lock_path, "wheelhouse_manifest": manifest_path}
    for key, relative in SOURCES.items():
        value = bindings.get(key)
        if not isinstance(value, dict) or set(value) != {"path", "blob_oid", "sha256"}:
            raise GitHubControllerError("release source binding is invalid")
        if value.get("path") != relative or value.get("sha256") != _sha256(paths[key]):
            raise GitHubControllerError("release source bytes differ from authorized exact main")
        if not re.fullmatch(r"[a-f0-9]{40,64}", str(value.get("blob_oid", ""))):
            raise GitHubControllerError("release source blob identity is invalid")

"""Safe, content-addressed GitHub authority bundle storage."""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from typing import Any

from .ci_github import GithubRunIdentity
from .ci_github_identity import GitHubControllerError, MainIdentity


def canonical_json(payload: dict[str, Any]) -> bytes:
    """Encode one controller object in its canonical byte representation."""

    return (json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n").encode()


def write_exclusive(path: Path, payload: dict[str, Any]) -> str:
    """Create one immutable-by-construction JSON artifact and return its digest."""

    raw = canonical_json(payload)
    with path.open("xb") as stream:
        stream.write(raw)
    return hashlib.sha256(raw).hexdigest()


def prepare_output(path: Path) -> Path:
    """Create a private nonsymlink controller output root."""

    parent = path.parent
    if parent.is_symlink() or not parent.is_dir():
        raise GitHubControllerError("certification output parent must be a regular directory")
    path.mkdir(mode=0o700)
    if path.is_symlink():
        raise GitHubControllerError("certification output cannot be a symlink")
    return path.resolve()


def verify_bundle(root: Path) -> dict[str, Any]:
    """Verify an exact, nonsymlink bundle inventory and every declared digest."""

    if root.is_symlink() or not root.is_dir():
        raise GitHubControllerError("certification bundle must be a regular directory")
    manifest_path = root / "bundle-manifest.json"
    if manifest_path.is_symlink() or not manifest_path.is_file():
        raise GitHubControllerError("certification bundle manifest is missing or unsafe")
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise GitHubControllerError("certification bundle manifest is invalid") from exc
    files = manifest.get("files") if isinstance(manifest, dict) else None
    if not isinstance(manifest, dict) or not isinstance(files, dict) or not files:
        raise GitHubControllerError("certification bundle file inventory is missing")
    actual: set[str] = set()
    for path in root.rglob("*"):
        if path.is_symlink():
            raise GitHubControllerError("certification bundle cannot contain symlinks")
        if path.is_file():
            actual.add(path.relative_to(root).as_posix())
    expected = set(files) | {"bundle-manifest.json"}
    if actual != expected:
        raise GitHubControllerError("certification bundle file inventory is not exact")
    for relative, digest in files.items():
        if (
            not isinstance(relative, str)
            or not isinstance(digest, str)
            or not re.fullmatch(r"[a-f0-9]{64}", digest)
        ):
            raise GitHubControllerError("certification bundle digest inventory is invalid")
        path = root / relative
        if hashlib.sha256(path.read_bytes()).hexdigest() != digest:
            raise GitHubControllerError(
                f"certification bundle digest mismatch: {relative}"
            )
    return manifest


def provider_snapshot(
    *, main: MainIdentity, admission: dict[str, Any], producer_run: dict[str, Any],
    captured_at: str, authority_contract_version: str | None = None,
) -> dict[str, Any]:
    """Encode already-authenticated inputs; grant no authentication or authority."""
    payload = {
        "schema_version": "1.0",
        "producer_id": producer_run["producer_id"],
        "repository": {"provider": "github", "repository_id": main.repository_id},
        "authentication": {
            "collector_id": "bcf-trusted-finalizer", "provider_api_verified": True,
            "captured_at": captured_at,
        },
        "current_default_main": {"checkout_sha": main.checkout_sha, "tree_sha": main.tree_sha},
        "admissions": [{**admission, "producer_run": producer_run}],
    }
    if authority_contract_version is not None:
        payload["authority_contract_version"] = authority_contract_version
    return payload


def certification_session(
    *, main: MainIdentity, repository: str, collector: GithubRunIdentity,
    session_id: str, producer_ids: tuple[str, ...], created_at: str,
) -> dict[str, Any]:
    """Encode the common finalizer session from independently authenticated inputs."""
    return {
        "schema_version": "1.0", "session_id": session_id,
        "subject": {"commit_sha": main.checkout_sha, "tree_sha": main.tree_sha},
        "profile": "standard", "profile_contract_version": "3.0",
        "producer": {
            "kind": "workflow", "provider": "github", "repository": repository,
            "repository_id": main.repository_id, "run_id": collector.run_id,
            "run_attempt": str(collector.run_attempt), "producer_id": "bcf-trusted-finalizer",
        },
        "expected_gate_inventory": ["ci-certification"],
        "expected_producer_inventory": sorted(producer_ids), "created_at": created_at,
        "session_root_policy": {"mode": "0700", "root_kind": "external", "immutable_manifest": True},
    }

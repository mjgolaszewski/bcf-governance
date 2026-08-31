"""Acyclic trusted callback artifacts for GitHub finalization and publication."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import re
from typing import Any

from .ci_github_api import GitHubAPI
from .ci_github_controller import (
    GitHubControllerError,
    finalize,
    publish,
    result_dict,
)
from .ci_github_identity import (
    authenticate_trusted_run,
    positive_int,
    resolve_main,
)


CALLBACK_FILENAME = "callback-result.json"
CALLBACK_KEYS = frozenset(
    {
        "schema_version",
        "status",
        "collector",
        "bundle_manifest_sha256",
    }
)


def _canonical(payload: dict[str, Any]) -> bytes:
    return (json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n").encode()


def _prepare_root(path: Path) -> Path:
    parent = path.parent
    if parent.is_symlink() or not parent.is_dir():
        raise GitHubControllerError("callback output parent must be a regular directory")
    path.mkdir(mode=0o700)
    if path.is_symlink():
        raise GitHubControllerError("callback output cannot be a symlink")
    return path.resolve()


def _write_callback(path: Path, payload: dict[str, Any]) -> None:
    with path.open("xb") as stream:
        stream.write(_canonical(payload))
    path.chmod(0o400)


def finalize_callback(
    api: GitHubAPI,
    *,
    repository: str,
    control_run_id: object,
    control_run_attempt: object,
    control_workflow_id: object | None,
    control_workflow_path: str,
    control_workflow_sha256: str | None,
    collector_run_id: object,
    collector_run_attempt: object,
    collector_workflow_path: str,
    collector_workflow_id: object | None,
    collector_workflow_sha256: str | None,
    output_root: Path,
) -> dict[str, Any]:
    """Write one trusted callback envelope and an optional terminal bundle."""

    root = _prepare_root(output_root)
    result = finalize(
        api,
        repository=repository,
        control_run_id=control_run_id,
        control_run_attempt=control_run_attempt,
        control_workflow_id=control_workflow_id,
        control_workflow_path=control_workflow_path,
        control_workflow_sha256=control_workflow_sha256,
        collector_run_id=collector_run_id,
        collector_run_attempt=collector_run_attempt,
        collector_workflow_path=collector_workflow_path,
        collector_workflow_id=collector_workflow_id,
        collector_workflow_sha256=collector_workflow_sha256,
        output_dir=root / "bundle",
    )
    bundle_digest: str | None = None
    if result.status == "terminal":
        manifest = root / "bundle/bundle-manifest.json"
        if not manifest.is_file() or manifest.is_symlink():
            raise GitHubControllerError("terminal callback bundle manifest is missing")
        bundle_digest = hashlib.sha256(manifest.read_bytes()).hexdigest()
    payload = {
        "schema_version": "1.0",
        "status": result.status,
        "collector": {
            "run_id": str(positive_int(collector_run_id, field="collector run ID")),
            "run_attempt": positive_int(
                collector_run_attempt, field="collector run attempt"
            ),
        },
        "bundle_manifest_sha256": bundle_digest,
    }
    _write_callback(root / CALLBACK_FILENAME, payload)
    return {**result_dict(result), "callback_dir": str(root)}


def _load_callback(root: Path) -> dict[str, Any]:
    if root.is_symlink() or not root.is_dir():
        raise GitHubControllerError("callback artifact must be a regular directory")
    callback = root / CALLBACK_FILENAME
    if callback.is_symlink() or not callback.is_file():
        raise GitHubControllerError("callback result is missing or unsafe")
    try:
        payload = json.loads(callback.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise GitHubControllerError("callback result is invalid JSON") from exc
    if not isinstance(payload, dict) or set(payload) != CALLBACK_KEYS:
        raise GitHubControllerError("callback result inventory is not exact")
    if payload.get("schema_version") != "1.0" or payload.get("status") not in {
        "pending",
        "terminal",
    }:
        raise GitHubControllerError("callback result status is invalid")
    collector = payload.get("collector")
    if not isinstance(collector, dict) or set(collector) != {"run_id", "run_attempt"}:
        raise GitHubControllerError("callback collector identity is invalid")
    positive_int(collector.get("run_id"), field="callback collector run ID")
    positive_int(collector.get("run_attempt"), field="callback collector run attempt")
    status = str(payload["status"])
    expected_entries = {CALLBACK_FILENAME} if status == "pending" else {
        CALLBACK_FILENAME,
        "bundle",
    }
    if {path.name for path in root.iterdir()} != expected_entries:
        raise GitHubControllerError("callback artifact top-level inventory is not exact")
    digest = payload.get("bundle_manifest_sha256")
    if status == "pending":
        if digest is not None:
            raise GitHubControllerError("pending callback cannot claim terminal evidence")
    else:
        if not isinstance(digest, str) or not re.fullmatch(r"[a-f0-9]{64}", digest):
            raise GitHubControllerError("terminal callback bundle digest is invalid")
        manifest = root / "bundle/bundle-manifest.json"
        if manifest.is_symlink() or not manifest.is_file():
            raise GitHubControllerError("terminal callback bundle manifest is missing")
        if hashlib.sha256(manifest.read_bytes()).hexdigest() != digest:
            raise GitHubControllerError("terminal callback bundle digest does not match")
    return payload


def publish_callback(
    api: GitHubAPI,
    *,
    repository: str,
    callback_dir: Path,
    target_url: str,
    collector_run_id: object,
    collector_run_attempt: object,
    collector_workflow_path: str,
    collector_workflow_id: object | None = None,
    collector_workflow_sha256: str | None = None,
) -> dict[str, Any]:
    """Authenticate a trusted callback; publish only a terminal verified bundle."""

    if callback_dir.is_symlink():
        raise GitHubControllerError("callback artifact cannot be a symlink")
    root = callback_dir.resolve()
    payload = _load_callback(root)
    collector = payload["collector"]
    expected_collector = {
        "run_id": str(positive_int(collector_run_id, field="collector run ID")),
        "run_attempt": positive_int(
            collector_run_attempt, field="collector run attempt"
        ),
    }
    if collector != expected_collector:
        raise GitHubControllerError("callback does not match the triggering collector")
    if payload["status"] == "pending":
        main = resolve_main(api, repository)
        authenticate_trusted_run(
            api,
            repository=repository,
            main=main,
            run_id=collector_run_id,
            run_attempt=collector_run_attempt,
            workflow_path=collector_workflow_path,
            expected_event="workflow_run",
            require_success=True,
            expected_workflow_id=collector_workflow_id,
            expected_workflow_sha256=collector_workflow_sha256,
        )
        return {
            "status": "suppressed",
            "reason": "producers_pending",
        }
    return publish(
        api,
        repository=repository,
        bundle_dir=root / "bundle",
        target_url=target_url,
        collector_run_id=collector_run_id,
        collector_run_attempt=collector_run_attempt,
        collector_workflow_path=collector_workflow_path,
        collector_workflow_id=collector_workflow_id,
        collector_workflow_sha256=collector_workflow_sha256,
    )

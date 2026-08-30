"""Independently verify profile-v2 evidence-session bundles."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any, Iterable

from jsonschema import Draft202012Validator


SESSION_FILENAME = "evidence-session.json"
SESSION_MEDIA_TYPE = "application/vnd.bcf.evidence-session+json"


def _sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _safe_artifact(receipt_path: Path, raw_path: object) -> Path | None:
    if not isinstance(raw_path, str) or not raw_path:
        return None
    relative = Path(raw_path)
    if relative.is_absolute() or ".." in relative.parts:
        return None
    candidate = receipt_path.parent / relative
    try:
        resolved = candidate.resolve(strict=True)
    except OSError:
        return None
    if not resolved.is_relative_to(receipt_path.parent.resolve()) or not resolved.is_file():
        return None
    return resolved


def _session_artifact(
    receipt_path: Path, receipt: dict[str, Any]
) -> tuple[Path | None, str | None]:
    artifacts = receipt.get("artifacts")
    if not isinstance(artifacts, list):
        return None, None
    matches = [
        value
        for value in artifacts
        if isinstance(value, dict)
        and value.get("path") == SESSION_FILENAME
        and value.get("media_type") == SESSION_MEDIA_TYPE
    ]
    if len(matches) != 1:
        return None, None
    artifact = matches[0]
    return _safe_artifact(receipt_path, artifact.get("path")), (
        str(artifact.get("sha256")) if isinstance(artifact.get("sha256"), str) else None
    )


def _manifest_issues(
    repo_root: Path,
    result: dict[str, Any],
    *,
    current: dict[str, Any],
    selected_profile: str,
    contract_version: str,
    expected_gates: set[str],
    schema: dict[str, Any],
) -> tuple[list[str], dict[str, Any] | None, str | None]:
    receipt = result.get("receipt")
    receipt_path_value = result.get("receipt_path")
    if not isinstance(receipt, dict) or not isinstance(receipt_path_value, str):
        return ["evidence_session_receipt_invalid"], None, None
    receipt_path = Path(receipt_path_value)
    manifest_path, declared_artifact_digest = _session_artifact(receipt_path, receipt)
    if manifest_path is None:
        return ["evidence_session_manifest_artifact_missing"], None, None
    encoded = manifest_path.read_bytes()
    digest = _sha256(encoded)
    issues: list[str] = []
    if declared_artifact_digest != digest:
        issues.append("evidence_session_artifact_digest_mismatch")
    try:
        manifest = json.loads(encoded)
    except (json.JSONDecodeError, UnicodeDecodeError):
        return [*issues, "evidence_session_manifest_invalid_json"], None, digest
    if not isinstance(manifest, dict):
        return [*issues, "evidence_session_manifest_not_object"], None, digest
    if any(Draft202012Validator(schema).iter_errors(manifest)):
        issues.append("evidence_session_schema_invalid")
    observations = receipt.get("observations")
    session_observation = (
        observations.get("evidence_session") if isinstance(observations, dict) else None
    )
    if not isinstance(session_observation, dict):
        issues.append("evidence_session_observation_missing")
    else:
        if session_observation.get("session_id") != manifest.get("session_id"):
            issues.append("evidence_session_id_mismatch")
        if session_observation.get("manifest_sha256") != digest:
            issues.append("evidence_session_observed_digest_mismatch")
    if manifest.get("subject") != {
        "commit_sha": current.get("commit_sha"),
        "tree_sha": current.get("tree_sha"),
    }:
        issues.append("evidence_session_subject_mismatch")
    if manifest.get("profile") != selected_profile:
        issues.append("evidence_session_profile_mismatch")
    if manifest.get("profile_contract_version") != contract_version:
        issues.append("evidence_session_contract_version_mismatch")
    gate_inventory = manifest.get("expected_gate_inventory")
    if not isinstance(gate_inventory, list) or set(gate_inventory) != expected_gates:
        issues.append("evidence_session_gate_inventory_mismatch")
    gate_id = receipt.get("gate_id")
    if not isinstance(gate_inventory, list) or gate_id not in gate_inventory:
        issues.append("evidence_session_gate_not_admitted")
    invocation = receipt.get("invocation")
    workflow = invocation.get("workflow") if isinstance(invocation, dict) else None
    producer = manifest.get("producer")
    producer_inventory = manifest.get("expected_producer_inventory")
    if not isinstance(workflow, dict) or not isinstance(producer, dict):
        issues.append("evidence_session_producer_binding_missing")
    else:
        for receipt_key, manifest_key in (
            ("provider", "provider"),
            ("run_id", "run_id"),
            ("run_attempt", "run_attempt"),
        ):
            if workflow.get(receipt_key) != producer.get(manifest_key):
                issues.append(f"evidence_session_{receipt_key}_mismatch")
        job = workflow.get("job")
        if job != producer.get("producer_id"):
            issues.append("evidence_session_producer_id_mismatch")
        if not isinstance(producer_inventory, list) or job not in producer_inventory:
            issues.append("evidence_session_producer_not_admitted")
    return sorted(set(issues)), manifest, digest


def apply_session_validation(
    repo_root: Path,
    results: Iterable[dict[str, Any]],
    *,
    current: dict[str, Any],
    selected_profile: str,
    contract_version: str,
    expected_gates: set[str],
) -> None:
    """Mutate receipt results with independently recomputed session failures."""
    schema_path = repo_root / "schemas/evidence-session.schema.json"
    try:
        schema = json.loads(schema_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError, UnicodeDecodeError):
        schema = {}
    material: list[tuple[dict[str, Any], dict[str, Any] | None, str | None]] = []
    for result in results:
        issues, manifest, digest = _manifest_issues(
            repo_root,
            result,
            current=current,
            selected_profile=selected_profile,
            contract_version=contract_version,
            expected_gates=expected_gates,
            schema=schema,
        )
        result["issues"] = sorted(set([*result.get("issues", []), *issues]))
        material.append((result, manifest, digest))
    identities = {
        (manifest.get("session_id"), digest)
        for _, manifest, digest in material
        if isinstance(manifest, dict) and isinstance(digest, str)
    }
    run_attempts = {
        (
            manifest.get("producer", {}).get("run_id"),
            manifest.get("producer", {}).get("run_attempt"),
        )
        for _, manifest, _ in material
        if isinstance(manifest, dict) and isinstance(manifest.get("producer"), dict)
    }
    bundle_issues: list[str] = []
    if len(identities) > 1:
        bundle_issues.append("evidence_session_mixed_bundle")
    if len(run_attempts) > 1:
        bundle_issues.append("evidence_session_mixed_run_attempt")
    for result, _, _ in material:
        result["issues"] = sorted(set([*result.get("issues", []), *bundle_issues]))
        if result["issues"]:
            result["result"] = "invalid"

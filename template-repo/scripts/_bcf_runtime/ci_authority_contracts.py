"""Schema and semantic validation for provider-neutral CI authority contracts."""

from __future__ import annotations

from datetime import datetime, timezone
import json
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator


SCHEMAS = {
    "authority": "ci-authority.schema.json",
    "certification": "ci-certification.schema.json",
    "capability_na": "capability-na.schema.json",
    "provider_snapshot": "ci-provider-snapshot.schema.json",
}

class CIAuthorityContractError(ValueError):
    """Raised when a CI authority document is structurally or semantically invalid."""


def _schema(repo_root: Path, contract: str) -> dict[str, Any]:
    try:
        schema_name = SCHEMAS[contract]
    except KeyError as exc:
        raise CIAuthorityContractError(f"unsupported CI authority contract: {contract}") from exc
    payload = json.loads((repo_root / "schemas" / schema_name).read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise CIAuthorityContractError(f"schemas/{schema_name} must contain an object")
    return payload


def _validate_schema(repo_root: Path, contract: str, payload: dict[str, Any]) -> None:
    errors = sorted(
        Draft202012Validator(_schema(repo_root, contract)).iter_errors(payload),
        key=lambda error: ([str(value) for value in error.absolute_path], error.message),
    )
    if not errors:
        return
    first = errors[0]
    location = ".".join(str(value) for value in first.absolute_path)
    prefix = f"{contract}.{location}" if location else contract
    raise CIAuthorityContractError(f"{prefix}: {first.message}")


def _matrix_key(job: dict[str, Any]) -> tuple[str, tuple[tuple[str, str], ...]]:
    matrix = job.get("matrix", {})
    return str(job["job_id"]), tuple(sorted((str(key), str(value)) for key, value in matrix.items()))


def authority_workflow(
    payload: dict[str, Any], reference: str
) -> dict[str, Any]:
    """Resolve one v1.1 workflow reference from the canonical registry."""

    registry = payload.get("workflow_registry")
    if not isinstance(registry, dict) or reference not in registry:
        raise CIAuthorityContractError(
            f"authority workflow reference is not registered: {reference}"
        )
    workflow = registry[reference]
    if not isinstance(workflow, dict):
        raise CIAuthorityContractError(
            f"authority workflow registry entry is invalid: {reference}"
        )
    return workflow


def producer_workflow(
    authority: dict[str, Any], producer: dict[str, Any]
) -> dict[str, Any]:
    """Resolve a producer workflow while preserving authority-v1 compatibility."""

    if authority.get("schema_version") == "1.1":
        return authority_workflow(authority, str(producer["workflow_ref"]))
    workflow = producer.get("workflow")
    if not isinstance(workflow, dict):
        raise CIAuthorityContractError("authority-v1 producer workflow is missing")
    return workflow


def authority_role_workflow(
    authority: dict[str, Any], role: str
) -> dict[str, Any]:
    """Resolve one singular v1.1 role through the canonical workflow registry."""

    if authority.get("schema_version") != "1.1":
        raise CIAuthorityContractError("authority role resolution requires version 1.1")
    roles = authority.get("roles")
    if not isinstance(roles, dict) or role not in roles or role == "reusable_producers":
        raise CIAuthorityContractError(f"authority role is missing or not singular: {role}")
    return authority_workflow(authority, str(roles[role]))


def _validate_authority(payload: dict[str, Any]) -> None:
    version = str(payload["schema_version"])
    if version == "1.1":
        if "admission_workflow" in payload:
            raise CIAuthorityContractError(
                "authority-v1.1 admission identity must use the canonical role registry"
            )
        registry = payload["workflow_registry"]
        identity_keys = [
            (value["workflow_id"], value["active_path"])
            for value in registry.values()
        ]
        if len(set(identity_keys)) != len(identity_keys):
            raise CIAuthorityContractError(
                "authority.workflow_registry must have unique workflow identity and path"
            )
        roles = payload["roles"]
        references = [
            str(reference)
            for role, reference in roles.items()
            if role != "reusable_producers"
        ]
        references.extend(str(value) for value in roles["reusable_producers"])
        missing = sorted(set(references) - set(registry))
        if missing:
            raise CIAuthorityContractError(
                "authority.roles contain unregistered workflow references: "
                + ", ".join(missing)
            )
        producer_refs = [str(value["workflow_ref"]) for value in payload["producers"]]
        if producer_refs != [str(value) for value in roles["reusable_producers"]]:
            raise CIAuthorityContractError(
                "authority producers must exactly follow reusable_producers role order"
            )
    else:
        if "workflow_registry" in payload or "roles" in payload:
            raise CIAuthorityContractError(
                "authority-v1.0 cannot claim the v1.1 workflow registry"
            )
    producers = payload["producers"]
    producer_ids = [producer["producer_id"] for producer in producers]
    if len(set(producer_ids)) != len(producer_ids):
        raise CIAuthorityContractError("authority.producers must have unique producer_id values")
    workflow_keys: set[tuple[str, str]] = set()
    for producer in producers:
        workflow = producer_workflow(payload, producer)
        workflow_key = (workflow["workflow_id"], workflow["active_path"])
        if workflow_key in workflow_keys:
            raise CIAuthorityContractError(
                "authority.producers must not share workflow identity and active path"
            )
        workflow_keys.add(workflow_key)
        jobs = [_matrix_key(job) for job in producer["expected_jobs"]]
        if len(set(jobs)) != len(jobs):
            raise CIAuthorityContractError(
                f"authority producer {producer['producer_id']} has duplicate expected jobs"
            )
    external_ids = [value["input_id"] for value in payload.get("trusted_external_inputs", [])]
    if len(set(external_ids)) != len(external_ids):
        raise CIAuthorityContractError(
            "authority.trusted_external_inputs must have unique input_id values"
        )


def _parse_timestamp(value: str, *, field: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise CIAuthorityContractError(f"{field} must be an ISO-8601 timestamp") from exc
    if parsed.tzinfo is None:
        raise CIAuthorityContractError(f"{field} must include a timezone")
    return parsed.astimezone(timezone.utc)


def _validate_capability_na(payload: dict[str, Any], *, evaluated_at: datetime) -> None:
    if payload["profile"] == "regulated":
        raise CIAuthorityContractError("regulated requirements cannot be bypassed by N/A")
    if payload["release_claim_uses_ci_evidence"]:
        raise CIAuthorityContractError(
            "CI authority cannot be N/A when CI evidence supports a release claim"
        )
    reviewed = _parse_timestamp(payload["reviewed_at"], field="capability_na.reviewed_at")
    if "expires_at" in payload:
        expires = _parse_timestamp(payload["expires_at"], field="capability_na.expires_at")
        if expires <= reviewed:
            raise CIAuthorityContractError(
                "capability_na.expires_at must be later than reviewed_at"
            )
        if expires <= evaluated_at:
            raise CIAuthorityContractError("capability_na record has expired")


def _validate_certification(payload: dict[str, Any]) -> None:
    admission = payload["admission"]
    if payload["subject"] != admission["candidate"]:
        raise CIAuthorityContractError(
            "certification subject must exactly match the admitted candidate"
        )
    producer_ids = [run["producer_id"] for run in admission["producer_runs"]]
    if len(set(producer_ids)) != len(producer_ids):
        raise CIAuthorityContractError(
            "certification.admission producer runs must have unique producer_id values"
        )
    snapshot_ids = [snapshot["producer_id"] for snapshot in payload["raw_snapshots"]]
    if len(set(snapshot_ids)) != len(snapshot_ids):
        raise CIAuthorityContractError(
            "certification.raw_snapshots must have unique producer_id values"
        )
    if set(producer_ids) != set(snapshot_ids):
        raise CIAuthorityContractError(
            "certification raw snapshots must exactly match admitted producer runs"
        )
    repository = payload["repository"]
    for run in admission["producer_runs"]:
        workflow = run["workflow"]
        if (
            workflow["provider"] != repository["provider"]
            or workflow["repository_id"] != repository["repository_id"]
        ):
            raise CIAuthorityContractError(
                "certification workflow identity must match the report repository"
            )
    selected_attempts = {
        value["producer_id"]: value["run_attempt"]
        for value in payload["evaluation"]["selected_attempts"]
    }
    if len(selected_attempts) != len(payload["evaluation"]["selected_attempts"]):
        raise CIAuthorityContractError(
            "certification selected attempts must have unique producer_id values"
        )
    expected_attempts = {
        run["producer_id"]: run["selected_attempt"]["run_attempt"]
        for run in admission["producer_runs"]
    }
    if selected_attempts != expected_attempts:
        raise CIAuthorityContractError(
            "certification selected attempts must match admitted producer runs"
        )
    if payload.get("authority_contract_version") == "1.1":
        subject = payload["subject"]
        for run in admission["producer_runs"]:
            membership = run["same_run_membership"]
            selected = run["selected_attempt"]
            expected_membership = {
                "repository_id": payload["repository"]["repository_id"],
                "commit_sha": subject["checkout_sha"],
                "tree_sha": subject["tree_sha"],
                "admission_run_id": admission["control_plane_run_id"],
                "admission_run_attempt": admission["control_plane_run_attempt"],
                "dispatch_sequence": admission["dispatch_sequence"],
                "admission_ordinal": admission["admission_ordinal"],
                "producer_id": run["producer_id"],
                "producer_run_id": selected["run_id"],
                "producer_run_attempt": selected["run_attempt"],
            }
            if any(membership.get(key) != value for key, value in expected_membership.items()):
                raise CIAuthorityContractError(
                    "certification v1.1 producer is not a member of its admission"
                )
    if payload["state"] in {"successful", "active"}:
        subject = payload["subject"]
        evaluation = payload["evaluation"]
        all_successful = all(
            run["selected_attempt"]["conclusion"] == "success"
            and run["selected_attempt"]["exact_job_inventory"]
            for run in admission["producer_runs"]
        )
        if (
            subject["checkout_sha"] != subject["current_default_main_sha"]
            or not evaluation["exact_producer_inventory"]
            or not evaluation["exact_job_inventory"]
            or evaluation["reasons"]
            or not all_successful
        ):
            raise CIAuthorityContractError(
                "successful certification state requires exact current-main green evidence"
            )


def _validate_provider_snapshot(payload: dict[str, Any]) -> None:
    repository = payload["repository"]
    producer_id = payload["producer_id"]
    ordinals: set[str] = set()
    for admission in payload["admissions"]:
        ordinal = admission["admission_ordinal"]
        if ordinal in ordinals:
            raise CIAuthorityContractError(
                f"provider snapshot {producer_id} has duplicate admission ordinal {ordinal}"
            )
        ordinals.add(ordinal)
        run = admission["producer_run"]
        if run["producer_id"] != producer_id:
            raise CIAuthorityContractError(
                "provider snapshot producer_run must match producer_id"
            )
        if payload.get("authority_contract_version") == "1.1":
            membership = run["same_run_membership"]
            expected_membership = {
                "repository_id": repository["repository_id"],
                "commit_sha": admission["candidate"]["checkout_sha"],
                "tree_sha": admission["candidate"]["tree_sha"],
                "admission_run_id": admission["control_plane_run_id"],
                "admission_run_attempt": admission["control_plane_run_attempt"],
                "dispatch_sequence": admission["dispatch_sequence"],
                "admission_ordinal": admission["admission_ordinal"],
                "producer_id": producer_id,
                "producer_run_id": run["run_id"],
            }
            if any(membership.get(key) != value for key, value in expected_membership.items()):
                raise CIAuthorityContractError(
                    "provider snapshot v1.1 producer is not a member of its admission"
                )
            membership_attempt_ids = [
                int(value["run_attempt"]) for value in run["attempts"]
            ]
            if membership["producer_run_attempt"] != max(membership_attempt_ids):
                raise CIAuthorityContractError(
                    "provider snapshot membership must bind the latest exact run attempt"
                )
        workflow = run["workflow"]
        if (
            workflow["provider"] != repository["provider"]
            or workflow["repository_id"] != repository["repository_id"]
        ):
            raise CIAuthorityContractError(
                "provider snapshot workflow identity must match repository"
            )
        attempt_ids: set[int] = set()
        for attempt in run["attempts"]:
            attempt_id = attempt["run_attempt"]
            if attempt_id in attempt_ids:
                raise CIAuthorityContractError(
                    f"provider snapshot {producer_id} has duplicate run attempt {attempt_id}"
                )
            attempt_ids.add(attempt_id)
            job_keys = [_matrix_key(job) for job in attempt["jobs"]]
            if len(set(job_keys)) != len(job_keys):
                raise CIAuthorityContractError(
                    f"provider snapshot {producer_id} attempt {attempt_id} has duplicate jobs"
                )
            completed = attempt["status"] == "completed"
            if completed != (attempt["conclusion"] is not None):
                raise CIAuthorityContractError(
                    "provider snapshot conclusion must be present exactly for completed attempts"
                )


def validate_ci_contract(
    repo_root: Path,
    contract: str,
    payload: dict[str, Any],
    *,
    evaluated_at: datetime | None = None,
) -> None:
    """Validate one CI authority contract without modifying repository state."""

    _validate_schema(repo_root, contract, payload)
    if contract == "capability_na":
        instant = evaluated_at or datetime.now(timezone.utc)
        if instant.tzinfo is None:
            raise CIAuthorityContractError("evaluated_at must include a timezone")
        _validate_capability_na(payload, evaluated_at=instant.astimezone(timezone.utc))
    elif contract == "authority":
        _validate_authority(payload)
    elif contract == "certification":
        _validate_certification(payload)
    else:
        _validate_provider_snapshot(payload)

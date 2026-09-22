"""Trusted same-admission verification of candidate-observed reuse decisions."""

from __future__ import annotations

from datetime import datetime
import hashlib
import json
from pathlib import Path
from pathlib import PurePosixPath
from typing import Any

from jsonschema import Draft202012Validator, ValidationError

from .ci_github_artifacts import resolve_role_artifact
from .ci_github_authority import packaged_repo_root
from .ci_github_identity import GitHubControllerError, MainIdentity
from .ci_prior_evidence_auth import authenticate_prior_transport
from .evidence_reuse_attestations import compose_reuse_attestations
from .evidence_execution import EvidenceError
from .prior_evidence_transport import _archive_files
from .provider_reuse_closure import trusted_main_claim_context


def _time(value: object, *, field: str) -> datetime:
    if not isinstance(value, str):
        raise GitHubControllerError(f"{field} is not a timestamp")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise GitHubControllerError(f"{field} is not a timestamp") from exc
    if parsed.tzinfo is None:
        raise GitHubControllerError(f"{field} lacks a timezone")
    return parsed


def _same_admission_plan(
    api: Any, *, repository: str, main: MainIdentity,
    authority: dict[str, Any], run_id: str, run_attempt: int,
) -> tuple[dict[str, Any], str]:
    """Authenticate the exact governance session whose planner skipped claims."""
    artifact = resolve_role_artifact(
        api, repository=repository, main=main, authority=authority,
        role="admission", run_id=run_id, run_attempt=run_attempt,
        artifact_name=f"bcf-session-{run_id}-{run_attempt}", require_success=False,
    )
    raw = api.artifact_bytes(repository, artifact.artifact_id, maximum_bytes=8_000_000)
    if artifact.provider_digest != "sha256:" + hashlib.sha256(raw).hexdigest():
        raise GitHubControllerError("reuse session artifact differs from provider digest")
    files = _archive_files(raw)
    if len(files) != 1:
        raise GitHubControllerError("reuse session artifact inventory is not exact")
    path, encoded = next(iter(files.items()))
    parts = PurePosixPath(path).parts
    if len(parts) != 2 or parts[1] != "evidence-session.json":
        raise GitHubControllerError("reuse session manifest path is not exact")
    try:
        plan = json.loads(encoded)
        schema = json.loads(
            (packaged_repo_root() / "schemas/evidence-session.schema.json")
            .read_text(encoding="utf-8")
        )
        Draft202012Validator(schema).validate(plan)
    except (OSError, ValueError, ValidationError) as exc:
        raise GitHubControllerError("reuse session manifest is invalid") from exc
    if not isinstance(plan, dict) or plan.get("schema_version") != "2.0":
        raise GitHubControllerError("reuse session is not a v3 verification plan")
    producer = plan.get("producer")
    if (parts[0] != plan.get("session_id")
        or plan.get("subject") != {
            "commit_sha": main.checkout_sha, "tree_sha": main.tree_sha,
        }
        or not isinstance(producer, dict)
        or {key: producer.get(key) for key in (
            "kind", "provider", "repository", "repository_id", "run_id", "run_attempt"
        )} != {
            "kind": "workflow", "provider": "github-actions", "repository": repository,
            "repository_id": main.repository_id, "run_id": str(run_id),
            "run_attempt": str(run_attempt),
        }):
        raise GitHubControllerError("reuse session subject or producer is not exact")
    nodes = plan.get("execution_dag", {}).get("nodes", [])
    producers = [node.get("producer") for node in nodes if isinstance(node, dict)]
    if (len(producers) != len(nodes)
        or any(not isinstance(value, str) or not value for value in producers)
        or len(producers) != len(set(producers))
        or sorted(producers) != sorted(plan.get("expected_gate_inventory", []))):
        raise GitHubControllerError("reuse session producer inventory is not exact")
    return plan, hashlib.sha256(encoded).hexdigest()


def _planned_reuse(plan: dict[str, Any]) -> dict[str, str]:
    required = plan.get("required_claims")
    preflight = plan.get("preflight_satisfied_claims")
    entries = plan.get("reused_evidence")
    if (not isinstance(required, list) or not isinstance(preflight, list)
        or not isinstance(entries, list)):
        raise GitHubControllerError("reuse session claim inventories are invalid")
    planned: dict[str, str] = {}
    for entry in entries:
        if (not isinstance(entry, dict)
            or set(entry) != {"claim_id", "evidence_id", "artifact_sha256", "reason"}
            or not isinstance(entry.get("claim_id"), str)
            or not isinstance(entry.get("evidence_id"), str)
            or not entry["evidence_id"]
            or entry.get("reason") != "dependency fingerprints remain applicable"
            or entry["claim_id"] in planned
            or entry["claim_id"] not in required
            or entry["claim_id"] in preflight):
            raise GitHubControllerError("reuse session skipped-claim inventory is invalid")
        planned[entry["claim_id"]] = entry["evidence_id"]
    if list(planned) != sorted(planned):
        raise GitHubControllerError("reuse session skipped-claim inventory is ambiguous")
    return planned


def verify_same_admission_reuse(
    api: Any, *, repository: str, main: MainIdentity,
    authority: dict[str, Any], run_id: str, run_attempt: int,
    truth_report: dict[str, Any], repo_root: Path,
) -> tuple[str, ...]:
    """Authenticate every claimed decision before any scoped certification."""
    observed = truth_report.get("reuse_attestations")
    if observed is None:
        metrics = truth_report.get("advisory_metrics")
        if isinstance(metrics, dict) and metrics.get("reused_claims", 0) != 0:
            raise GitHubControllerError("claimed reuse lacks a trusted attestation inventory")
        return ()  # Dormant compatible controller: ordinary evidence remains unchanged.
    if not isinstance(observed, list) or not observed:
        raise GitHubControllerError("reuse attestation inventory is empty or invalid")
    if any(not isinstance(value, dict) for value in observed):
        raise GitHubControllerError("reuse attestation is not an object")
    claims = [
        value["claim"].get("claim_id") if isinstance(value.get("claim"), dict) else None
        for value in observed
    ]
    if (any(not isinstance(value, str) or not value for value in claims)
        or claims != sorted(set(claims))):
        raise GitHubControllerError("reuse attestation claim inventory is ambiguous")
    timestamps = [value.get("emitted_at") for value in observed]
    if any(not isinstance(value, str) for value in timestamps) or len(set(timestamps)) != 1:
        raise GitHubControllerError("reuse attestations do not share an emission time")
    emitted_at = timestamps[0]
    run = api.run(repository, run_id)
    if (not isinstance(run, dict) or str(run.get("id")) != str(run_id)
        or run.get("run_attempt") != run_attempt
        or run.get("head_sha") != main.checkout_sha):
        raise GitHubControllerError("reuse admission run identity is not exact")
    if not (_time(run.get("created_at"), field="admission creation")
            <= _time(emitted_at, field="reuse emission")
            <= _time(run.get("updated_at"), field="admission completion")):
        raise GitHubControllerError("reuse attestation emission is outside admission")
    transport = authenticate_prior_transport(
        api, repository=repository, main=main, authority=authority,
        run_id=run_id, run_attempt=run_attempt,
    )
    try:
        contract, entries, _ = trusted_main_claim_context(
            api, repository, main, claims, repo_root=repo_root,
        )
        expected, _fallback = compose_reuse_attestations(
            repo_root, transport, main, contract, entries, claims,
            emitted_at=emitted_at,
        )
    except (EvidenceError, OSError, ValueError, KeyError, TypeError) as exc:
        raise GitHubControllerError("reuse attestation main recomputation failed") from exc
    if observed != expected:
        raise GitHubControllerError("reuse attestation differs from trusted main recomputation")
    admitted = tuple(
        value["claim"]["claim_id"] for value in expected
        if value["decision"] == "reuse_admitted"
    )
    session, manifest_sha256 = _same_admission_plan(
        api, repository=repository, main=main, authority=authority,
        run_id=run_id, run_attempt=run_attempt,
    )
    if truth_report.get("reuse_session_binding") != {
        "session_id": session["session_id"], "manifest_sha256": manifest_sha256,
    }:
        raise GitHubControllerError("reuse truth does not bind its exact evidence session")
    planned = _planned_reuse(session)
    if planned != {
        value["claim"]["claim_id"]: value["source_receipt"]["evidence_id"]
        for value in expected if value["decision"] == "reuse_admitted"
    }:
        raise GitHubControllerError("reuse decisions differ from the complete skipped-claim plan")
    metrics = truth_report.get("advisory_metrics")
    if not isinstance(metrics, dict) or metrics.get("reused_claims") != len(admitted):
        raise GitHubControllerError("reuse claim count differs from trusted decisions")
    return admitted

"""Trusted same-admission verification of candidate-observed reuse decisions."""

from __future__ import annotations

from datetime import datetime
from pathlib import Path
from typing import Any

from .ci_github_identity import GitHubControllerError, MainIdentity
from .ci_prior_evidence_auth import authenticate_prior_transport
from .evidence_reuse_attestations import compose_reuse_attestations
from .evidence_execution import EvidenceError
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
    metrics = truth_report.get("advisory_metrics")
    if not isinstance(metrics, dict) or metrics.get("reused_claims") != len(admitted):
        raise GitHubControllerError("reuse claim count differs from trusted decisions")
    return admitted

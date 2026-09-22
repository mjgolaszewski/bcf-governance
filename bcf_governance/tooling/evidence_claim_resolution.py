"""Canonical claim ownership and authenticated evidence resolution."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Iterable, Iterator

import yaml  # type: ignore[import-untyped]


def load_claim_gate_projection(
    repo_root: Path, claim_ids: Iterable[str]
) -> dict[str, dict[str, Any]]:
    """Load only claim, producer, and gate facts required by receipt consumers."""
    payload = yaml.safe_load(
        (repo_root / "governance/gate-contracts.yml").read_text(encoding="utf-8")
    )
    return claim_gate_projection(payload, claim_ids)


def claim_gate_projection(
    payload: object, claim_ids: Iterable[str],
) -> dict[str, dict[str, Any]]:
    """Project the same owner from exact provider-read contract bytes."""
    model = payload.get("claim_model") if isinstance(payload, dict) else None
    gates = payload.get("gates") if isinstance(payload, dict) else None
    claims = model.get("claims") if isinstance(model, dict) else None
    groups = model.get("execution_groups") if isinstance(model, dict) else None
    if (
        not isinstance(model, dict)
        or model.get("version") != "1.0"
        or not isinstance(gates, dict)
        or not isinstance(claims, dict)
        or not isinstance(groups, dict)
    ):
        raise ValueError("claim gate contract is invalid")
    projection: dict[str, dict[str, Any]] = {}
    for claim_id in claim_ids:
        claim = claims.get(claim_id)
        if claim is None:
            continue
        group = groups.get(claim.get("execution_group")) if isinstance(claim, dict) else None
        legacy_gate = claim.get("legacy_gate") if isinstance(claim, dict) else None
        producer = group.get("producer") if isinstance(group, dict) else None
        gate = gates.get(legacy_gate) if isinstance(legacy_gate, str) else None
        producer_gate = gates.get(producer) if isinstance(producer, str) else None
        if (
            not isinstance(claim, dict)
            or not isinstance(group, dict)
            or claim_id not in group.get("claims", [])
            or not isinstance(legacy_gate, str)
            or not isinstance(producer, str)
            or not isinstance(gate, dict)
            or not isinstance(producer_gate, dict)
        ):
            raise ValueError(f"claim {claim_id} gate contract is invalid")
        projection[claim_id] = {
            "legacy_gate": legacy_gate,
            "producer": producer,
            "gate": gate,
        }
    return projection


def eligible_claim_receipts(
    receipts: dict[str, list[dict[str, Any]]], model: dict[str, Any], claim_id: str,
    preflight_claims: set[str], *, include_preflight: bool = True,
) -> Iterator[dict[str, Any]]:
    """Yield validated evidence from the canonical producer for one exact claim."""
    claim = model.get("claims", {}).get(claim_id)
    if not isinstance(claim, dict):
        return
    group = model.get("execution_groups", {}).get(claim.get("execution_group"))
    if not isinstance(group, dict) or not isinstance(group.get("producer"), str):
        return
    producer = group["producer"]
    gate_id = str(claim.get("legacy_gate", claim_id))
    if include_preflight and claim_id in preflight_claims:
        yield {"evidence_id": f"preflight:{claim_id}", "gate_id": gate_id, "kind": "gate",
               "result": "verified", "issues": [], "source": "evidence-session-v2"}
    for values in receipts.values():
        for candidate in values:
            receipt = candidate.get("receipt")
            if not isinstance(receipt, dict) or candidate.get("result") != "verified":
                continue
            if receipt.get("schema_version") == "3.0":
                claims = receipt.get("claims")
                if candidate.get("gate_id") == producer and isinstance(claims, list) and claim_id in claims:
                    yield candidate
                continue
            subject = receipt.get("subject")
            if candidate.get("gate_id") == gate_id and isinstance(subject, dict) and subject.get("binding") == "exact_tree":
                yield candidate


def eligible_receipts(
    receipts: dict[str, list[dict[str, Any]]], model: dict[str, Any], gate_id: str,
    preflight_claims: set[str], *, include_preflight: bool = True,
) -> Iterator[dict[str, Any]]:
    """Resolve one legacy gate through its unique canonical claim identity."""
    claim_ids = [str(claim_id) for claim_id, raw in model.get("claims", {}).items()
                 if isinstance(raw, dict) and raw.get("legacy_gate") == gate_id]
    if not claim_ids and not model.get("claims"):
        for candidate in receipts.get(gate_id, []):
            receipt = candidate.get("receipt")
            subject = receipt.get("subject") if isinstance(receipt, dict) else None
            if candidate.get("result") == "verified" and isinstance(subject, dict) and subject.get("binding") == "exact_tree":
                yield candidate
        return
    if len(claim_ids) == 1:
        yield from eligible_claim_receipts(
            receipts, model, claim_ids[0], preflight_claims,
            include_preflight=include_preflight,
        )


def verified_candidate(
    receipts: dict[str, list[dict[str, Any]]], model: dict[str, Any], gate_id: str,
    preflight_claims: set[str],
) -> dict[str, Any] | None:
    return next(eligible_receipts(receipts, model, gate_id, preflight_claims), None)


def resolved_session_claims(
    receipts: dict[str, list[dict[str, Any]]], model: dict[str, Any] | None,
    preflight_claims: set[str], required_claims: Iterable[object],
) -> set[str]:
    if model is None:
        return set()
    return {
        claim_id for claim_id in required_claims if isinstance(claim_id, str)
        and next(eligible_claim_receipts(receipts, model, claim_id, preflight_claims), None)
        is not None
    }

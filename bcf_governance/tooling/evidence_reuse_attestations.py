"""Compose non-authoritative main-side decisions from trusted transport facts.

Only a trusted finalizer may confer authority after independently reproducing
these bytes from the same admission's provider-authenticated transport.
"""

from __future__ import annotations

from datetime import datetime
import hashlib
import json
from pathlib import Path
from typing import Any, Iterable, Mapping, Protocol

from jsonschema import Draft202012Validator, ValidationError

from .ci_github_bundle import canonical_json
from .ci_github_authority import packaged_repo_root
from .ci_github_identity import MainIdentity
from .evidence_claims import qualification_equivalence
from .evidence_execution import EvidenceError
from .evidence_planning import (
    build_dependency_manifest, parse_claim_model, receipt_applicability,
)


class PriorTransportMaterial(Protocol):
    """Byte material only; implementing this shape does not confer custody."""

    manifest: dict[str, Any]
    files: dict[str, bytes]


def _sha(value: Any) -> str:
    return hashlib.sha256(canonical_json(value)).hexdigest()


def _rejection_reasons(
    applicability: list[str], *, closure_equal: bool, qualified: bool,
    producer_exact: bool,
) -> list[str]:
    reasons: set[str] = set()
    if not producer_exact:
        reasons.add("authority_ambiguous")
    if not closure_equal:
        reasons.add("dependency_closure_mismatch")
    if not qualified:
        reasons.add("qualification_mismatch")
    for reason in applicability:
        if reason == "freshness_expired":
            reasons.add("freshness_expired")
        elif reason == "qualification_missing":
            reasons.add("qualification_mismatch")
        elif reason == "claim_producer_mismatch":
            reasons.add("authority_ambiguous")
        else:
            reasons.add("dependency_closure_mismatch")
    return sorted(reasons)


def compose_reuse_attestations(
    repo_root: Path, transport: PriorTransportMaterial, main: MainIdentity,
    contract_payload: Mapping[str, Any], tree_entries: Iterable[tuple[str, str]],
    claim_ids: Iterable[str], *, emitted_at: str,
) -> tuple[list[dict[str, Any]], list[str]]:
    """Return schema-closed decisions and claims requiring canonical execution.

    The caller must authenticate transport/provider identities first.  This
    pure composition alone is not evidence and cannot authorize skipped work.
    """
    try:
        emitted = datetime.fromisoformat(emitted_at.replace("Z", "+00:00"))
    except ValueError as exc:
        raise EvidenceError("reuse attestation emission time is invalid") from exc
    if emitted.tzinfo is None:
        raise EvidenceError("reuse attestation emission time must be timezone-aware")
    model = parse_claim_model(contract_payload)
    selected = sorted(set(claim_ids))
    if not selected or any(claim_id not in model["claims"] for claim_id in selected):
        raise EvidenceError("reuse claims are missing or not declared")
    entries = tuple(tree_entries)
    main_subject = {"commit_sha": main.checkout_sha, "tree_sha": main.tree_sha}
    manifest = transport.manifest
    if manifest.get("main") != main_subject:
        raise EvidenceError("reuse transport main subject is not exact")
    main_manifest = build_dependency_manifest(
        repo_root, selected, model=model, tree_entries=entries,
    )
    source_artifacts = {
        value["artifact_id"]: value for value in manifest["artifacts"]
    }
    candidates: dict[str, list[tuple[dict[str, Any], dict[str, Any]]]] = {
        claim_id: [] for claim_id in selected
    }
    for reference in manifest["receipts"]:
        raw = transport.files[f"expanded/{reference['artifact_id']}/{reference['path']}"]
        receipt = json.loads(raw)
        for claim_id in receipt.get("claims", []):
            if claim_id in candidates:
                candidates[claim_id].append((receipt, reference))
    schema = json.loads(
        (packaged_repo_root() / "schemas/reuse-attestation.schema.json").read_text(encoding="utf-8")
    )
    validator = Draft202012Validator(schema)
    attestations: list[dict[str, Any]] = []
    fallback: list[str] = []
    for claim_id in selected:
        sources = candidates[claim_id]
        if len(sources) != 1:
            fallback.append(claim_id)
            continue
        receipt, reference = sources[0]
        claim = model["claims"][claim_id]
        group_id = str(claim["execution_group"])
        producer_exact = (
            model["execution_groups"][group_id]["producer"] == receipt.get("gate_id")
        )
        applicable, applicability = receipt_applicability(
            repo_root, receipt, claim_id, current_subject=main_subject,
            model=model, tree_entries=entries,
        )
        source_dependencies = (
            receipt.get("dependency_manifest", {}).get("claim_dependencies", {}).get(claim_id)
        )
        main_dependencies = main_manifest["claim_dependencies"][claim_id]
        closure = {
            "source_sha256": _sha(source_dependencies),
            "main_sha256": _sha(main_dependencies),
            "equivalent": source_dependencies == main_dependencies,
        }
        qualified = qualification_equivalence(
            repo_root, receipt, claim_id, contract_payload=contract_payload,
            tree_entries=entries,
        )
        reasons = _rejection_reasons(
            applicability, closure_equal=closure["equivalent"],
            qualified=qualified["equivalent"], producer_exact=producer_exact,
        )
        if not applicable and not reasons:
            reasons = ["authority_ambiguous"]
        source = receipt.get("subject")
        if not isinstance(source, dict):
            raise EvidenceError("source receipt subject is missing")
        artifact = source_artifacts[reference["artifact_id"]]
        attestation = {
            "schema_version": "1.0", "kind": "reuse_attestation",
            "claim": {"claim_id": claim_id, "execution_group_id": group_id},
            "source_receipt": {
                "evidence_id": reference["evidence_id"],
                "receipt_sha256": reference["receipt_sha256"],
                "artifact_sha256": artifact["archive_sha256"],
                "immutable_reference": reference["immutable_reference"],
            },
            "source_subject": {
                "commit_sha": source.get("commit_sha"), "tree_sha": source.get("tree_sha"),
            },
            "main_subject": main_subject,
            "dependency_closure": closure,
            "qualification": qualified,
            "provider_custody": {
                "provider": "github",
                "repository_id": manifest["repository"]["repository_id"],
                "pull_request_number": manifest["pull_request"],
                "candidate": manifest["candidate"],
                "merge_commit_sha": manifest["merge"]["commit_sha"],
                "main": manifest["main"],
                "producer": manifest["producer"],
                "artifact": {
                    "artifact_id": reference["artifact_id"],
                    "artifact_sha256": artifact["archive_sha256"],
                },
                "authority": manifest["authority"],
                "protection_sha256": manifest["protection"]["declaration_sha256"],
                "authenticated_at": manifest["authenticated_at"],
            },
            "decision": "canonical_execution_required" if reasons else "reuse_admitted",
            "rejection_reasons": reasons,
            "emitted_at": emitted_at,
        }
        attestation["attestation_id"] = _sha(attestation)
        try:
            validator.validate(attestation)
        except ValidationError as exc:
            raise EvidenceError("composed reuse attestation violates its closed contract") from exc
        attestations.append(attestation)
        if reasons:
            fallback.append(claim_id)
    return attestations, sorted(fallback)

"""Canonical claim ownership and authenticated evidence resolution."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any, Iterable, Iterator, Mapping, NamedTuple

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
    reuse_attestations: Mapping[str, dict[str, Any]] | None = None,
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
    attestation = (reuse_attestations or {}).get(claim_id)
    identity = attestation.get("claim") if isinstance(attestation, dict) else None
    source = attestation.get("source_receipt") if isinstance(attestation, dict) else None
    if (
        isinstance(identity, dict) and isinstance(source, dict)
        and identity == {
            "claim_id": claim_id, "execution_group_id": claim["execution_group"],
        }
        and attestation.get("decision") == "reuse_admitted"
        and isinstance(attestation.get("attestation_id"), str)
        and isinstance(source.get("evidence_id"), str)
    ):
        yield {
            "kind": "reuse_attestation", "source": "provisional_reuse_v1",
            "gate_id": gate_id, "claim_id": claim_id,
            "evidence_id": source["evidence_id"],
            "attestation_id": attestation["attestation_id"],
            "result": "provisional", "issues": [],
        }


def eligible_receipts(
    receipts: dict[str, list[dict[str, Any]]], model: dict[str, Any], gate_id: str,
    preflight_claims: set[str], *, include_preflight: bool = True,
    reuse_attestations: Mapping[str, dict[str, Any]] | None = None,
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
            reuse_attestations=reuse_attestations,
        )


def verified_candidate(
    receipts: dict[str, list[dict[str, Any]]], model: dict[str, Any], gate_id: str,
    preflight_claims: set[str],
    reuse_attestations: Mapping[str, dict[str, Any]] | None = None,
) -> dict[str, Any] | None:
    return next(eligible_receipts(
        receipts, model, gate_id, preflight_claims,
        reuse_attestations=reuse_attestations,
    ), None)


def resolved_session_claims(
    receipts: dict[str, list[dict[str, Any]]], model: dict[str, Any] | None,
    preflight_claims: set[str], required_claims: Iterable[object],
    reuse_attestations: Mapping[str, dict[str, Any]] | None = None,
) -> set[str]:
    if model is None:
        return set()
    return {
        claim_id for claim_id in required_claims if isinstance(claim_id, str)
        and next(eligible_claim_receipts(
            receipts, model, claim_id, preflight_claims,
            reuse_attestations=reuse_attestations,
        ), None)
        is not None
    }


def _multi_claim_test_issues(
    repo_root: Path, receipt: dict[str, Any], *, policy_inputs=None,
) -> list[str]:
    if receipt.get("schema_version") != "3.0" or receipt.get("kind") != "test_suite":
        return []
    observations = receipt.get("observations")
    observed = {
        str(value)
        for value in (
            observations.get("test_node_ids", [])
            if isinstance(observations, dict)
            else []
        )
    }
    try:
        projection = _receipt_claim_projection(repo_root, receipt.get("claims", []), policy_inputs)
    except (OSError, yaml.YAMLError, ValueError):
        return ["claim_contract_unreadable"]
    issues: list[str] = []
    for claim_id in receipt.get("claims", []):
        claim_contract = projection.get(str(claim_id))
        if not isinstance(claim_contract, dict):
            issues.append(f"claim_{claim_id}_not_declared")
            continue
        gate = claim_contract["gate"]
        evidence = gate.get("evidence") if isinstance(gate, dict) else None
        test_contract = evidence.get("test_contract") if isinstance(evidence, dict) else None
        manifest_value = (
            test_contract.get("expected_node_manifest")
            if isinstance(test_contract, dict)
            else None
        )
        if not isinstance(manifest_value, str):
            if isinstance(evidence, dict) and evidence.get("kind") == "test_suite":
                issues.append(f"claim_{claim_id}_test_manifest_undeclared")
            continue
        try:
            text = _receipt_manifest_text(repo_root, manifest_value, policy_inputs)
        except (OSError, UnicodeError, ValueError):
            issues.append(f"claim_{claim_id}_test_manifest_missing")
            continue
        expected = {line.strip() for line in text.splitlines() if line.strip()}
        if not expected.issubset(observed):
            issues.append(f"claim_{claim_id}_expected_test_nodes_missing")
    return issues


def _qualification_issues(repo_root: Path, receipt: dict[str, Any], *, policy_inputs=None) -> list[str]:
    if receipt.get("schema_version") != "3.0":
        return []
    qualification = receipt.get("qualification")
    references = receipt.get("qualification_refs")
    referenced_claims = {
        str(value.get("claim_id"))
        for value in references
        if isinstance(value, dict) and isinstance(value.get("claim_id"), str)
    } if isinstance(references, list) else set()
    if isinstance(qualification, dict) and qualification.get("satisfied") is True:
        try:
            projection = _receipt_claim_projection(repo_root, receipt.get("claims", []), policy_inputs)
            expected = {
                str(control.get("id"))
                for claim_id in receipt.get("claims", [])
                if claim_id not in referenced_claims
                for gate in [projection.get(str(claim_id), {}).get("gate")]
                if isinstance(gate, dict)
                for control in gate.get("negative_controls", [])
                if isinstance(control, dict) and isinstance(control.get("id"), str)
            }
        except (OSError, yaml.YAMLError, ValueError, KeyError, TypeError):
            return ["qualification_contract_unreadable"]
        actual = qualification.get("control_ids")
        if not isinstance(actual, list) or set(actual) != expected:
            return ["qualification_control_inventory_incomplete"]
        return []
    if (
        isinstance(references, list)
        and references
        and referenced_claims == set(receipt.get("claims", []))
    ):
        return []
    return ["qualification_missing"]



class _ClaimPolicyCapture(NamedTuple):
    root: Path
    subject: tuple[str, str]
    gate_bytes: bytes
    schema_bytes: bytes
    profile_bytes: bytes
    evidence_policy_bytes: bytes
    tree_entries: tuple


def capture_claim_policy(repo_root: Path, subject):
    """Capture exact policy inputs; the consuming actor authenticates selection."""
    from .semantic_source_paths import committed_regular_blob_capture, committed_source_tree_population
    from .semantic_yaml import load_unique_mapping_text
    from .evidence_planning import parse_claim_model

    if type(subject) is not dict or set(subject) != {"commit_sha", "tree_sha"}:
        raise ValueError("protected receipt policy requires an exact subject")
    root = repo_root.resolve()
    population = committed_source_tree_population(root, **subject)
    if population["unresolved_entries"]:
        raise ValueError("protected receipt policy contains unresolved source entries")
    _, gates = committed_regular_blob_capture(root, path="governance/gate-contracts.yml", **subject)
    _, schema = committed_regular_blob_capture(root, path="schemas/evidence-receipt.schema.json", **subject)
    _, profile = committed_regular_blob_capture(root, path="governance-profile.yml", **subject)
    _, policy = committed_regular_blob_capture(root, path="governance/evidence-policy.yml", **subject)
    load_unique_mapping_text(profile)
    load_unique_mapping_text(policy)
    parse_claim_model(load_unique_mapping_text(gates))
    if not isinstance(json.loads(schema), dict):
        raise ValueError("protected receipt schema must be a mapping")
    return _ClaimPolicyCapture(root, tuple(subject[key] for key in ("commit_sha", "tree_sha")),
        gates, schema, profile, policy, tuple((path, oid) for path, _, oid in population["regular_blobs"]))


def _claim_policy_inputs(capture):
    """Re-read committed bindings before any consumer uses their decoded policy."""
    from .semantic_yaml import load_unique_mapping_text
    from .evidence_planning import parse_claim_model

    if type(capture) is not _ClaimPolicyCapture:
        raise ValueError("protected receipt policy capture is incompatible")
    subject = dict(zip(("commit_sha", "tree_sha"), capture.subject))
    if capture_claim_policy(capture.root, subject) != capture:
        raise ValueError("protected receipt policy differs from capture")
    gates = load_unique_mapping_text(capture.gate_bytes)
    return dict(root=capture.root, subject=subject, model=parse_claim_model(gates),
        gates=gates, schema=json.loads(capture.schema_bytes), tree_entries=capture.tree_entries,
        profile=load_unique_mapping_text(capture.profile_bytes),
        evidence_policy=load_unique_mapping_text(capture.evidence_policy_bytes),
        identity=dict(subject=subject, gate_contracts_sha256=hashlib.sha256(capture.gate_bytes).hexdigest(),
                      receipt_schema_sha256=hashlib.sha256(capture.schema_bytes).hexdigest(),
                      profile_sha256=hashlib.sha256(capture.profile_bytes).hexdigest(),
                      evidence_policy_sha256=hashlib.sha256(capture.evidence_policy_bytes).hexdigest()))


def _receipt_claim_projection(repo_root, claims, policy_inputs):
    return (load_claim_gate_projection(repo_root, claims) if policy_inputs is None
            else claim_gate_projection(policy_inputs["gates"], claims))


def _receipt_manifest_text(repo_root, value, policy_inputs):
    if policy_inputs is None:
        manifest = repo_root / value
        if not manifest.is_file() or manifest.is_symlink():
            raise OSError("test manifest is unavailable")
        return manifest.read_text(encoding="utf-8")
    from .semantic_source_paths import committed_regular_blob_capture
    _, raw = committed_regular_blob_capture(policy_inputs["root"], path=value, **policy_inputs["subject"])
    return raw.decode("utf-8")


def _require_receipt_policy_settings(inputs, *, require_negative_control, tree_independent_allowlist,
                                     expected_kinds, invocations, require_session, selected_profile, contract_version):
    """Keep every receipt-admission setting attached to the same protected policy."""
    from .evidence_gate_contracts import expected_evidence_kinds, expected_invocations

    profile = inputs["profile"]
    settings = inputs["evidence_policy"].get("settings", {})
    if not isinstance(settings, dict):
        raise ValueError("protected receipt evidence settings are invalid")
    block = profile.get("profile", {})
    allowlist = settings.get("tree_independent_allowlist", [])
    if (not isinstance(block, dict) or not isinstance(allowlist, list)
            or any(not isinstance(value, str) for value in allowlist)):
        raise ValueError("protected receipt profile or allowlist is invalid")
    root, subject = inputs["root"], inputs["subject"]
    if (contract_version != "3.0" or profile.get("profile_contract_version") != "3.0"
            or require_session is not True
            or selected_profile != block.get("selected", "standard")
            or require_negative_control != bool(settings.get("require_negative_control_for_required_gates", True))
            or tree_independent_allowlist != set(allowlist)
            or expected_kinds != expected_evidence_kinds(root, source_subject=subject)
            or invocations != expected_invocations(root, source_subject=subject)):
        raise ValueError("protected receipt admission settings differ from canonical policy")

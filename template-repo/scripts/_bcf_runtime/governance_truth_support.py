"""Finding accounting and detached attestation support for governance truth."""

from __future__ import annotations

import base64
import hashlib
import json
import subprocess
import tempfile
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

import yaml  # type: ignore[import-untyped]

from .governance_evidence import bundle_digest


BLOCKING_FINDING_DISPOSITIONS = {"open", "remediation_completed", "deferred", "accepted_risk"}
DSSE_PAYLOAD_TYPE = "application/vnd.bcf.evidence-bundle.v1+json"


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def artifact_issues(receipt_path: Path, receipt: dict[str, Any]) -> list[str]:
    """Verify each raw artifact path and digest relative to its receipt."""
    artifacts = receipt.get("artifacts")
    if not isinstance(artifacts, list):
        return ["artifacts_missing"]
    issues: list[str] = []
    for index, raw in enumerate(artifacts):
        if not isinstance(raw, dict):
            issues.append(f"artifact_{index}_invalid")
            continue
        relative = raw.get("path")
        expected = raw.get("sha256")
        if not isinstance(relative, str) or Path(relative).is_absolute() or ".." in Path(relative).parts:
            issues.append(f"artifact_{index}_path_invalid")
            continue
        path = receipt_path.parent / relative
        if not path.is_file():
            issues.append(f"artifact_{index}_missing")
        elif not isinstance(expected, str) or _sha256(path) != expected:
            issues.append(f"artifact_{index}_sha256_mismatch")
    return issues


def workitem_observation(
    repo_root: Path, receipts: dict[str, list[dict[str, Any]]]
) -> dict[str, Any]:
    ledger = yaml.safe_load((repo_root / "plans/phase-ledger.yml").read_text(encoding="utf-8"))
    active = ledger.get("active_phase") if isinstance(ledger, dict) else None
    workitems_path = active.get("workitems") if isinstance(active, dict) else None
    if not isinstance(workitems_path, str):
        return {"satisfied": False, "issue": "active_workitem_ledger_missing"}
    payload = yaml.safe_load((repo_root / workitems_path).read_text(encoding="utf-8"))
    entries = payload.get("workitems") if isinstance(payload, dict) else None
    if not isinstance(entries, list) or not entries:
        return {"satisfied": False, "issue": "workitems_missing"}
    open_ids = sorted(
        str(entry.get("id", "unknown"))
        for entry in entries
        if not isinstance(entry, dict) or entry.get("status") != "DONE"
    )
    acceptance_evidence = sorted(
        {
            str(gate_id)
            for entry in entries
            if isinstance(entry, dict)
            for gate_id in entry.get("acceptance_evidence", [])
            if isinstance(gate_id, str)
        }
    )
    missing_acceptance_evidence = sorted(
        gate_id
        for gate_id in acceptance_evidence
        if not any(
            candidate["result"] == "verified"
            and (candidate.get("receipt", {}).get("subject", {})).get("binding")
            == "exact_tree"
            for candidate in receipts.get(gate_id, [])
        )
    )
    return {
        "satisfied": not open_ids and not missing_acceptance_evidence,
        "workitems_path": workitems_path,
        "total": len(entries),
        "open_ids": open_ids,
        "acceptance_evidence": acceptance_evidence,
        "missing_acceptance_evidence": missing_acceptance_evidence,
    }


def compute_hotfix_reports(
    repo_root: Path,
    phase_id: str,
    receipts: dict[str, list[dict[str, Any]]],
    *,
    findings_clear: bool,
) -> tuple[list[dict[str, Any]], set[str], list[str]]:
    """Compute current-tree hotfix verification and closure for the active phase."""
    reports: list[dict[str, Any]] = []
    required_gates: set[str] = set()
    issues: list[str] = []
    for path in sorted((repo_root / "phases").glob("phase-[0-9]*-hotfix*.yml")):
        payload = yaml.safe_load(path.read_text(encoding="utf-8"))
        if not isinstance(payload, dict):
            continue
        hotfix = payload.get("hotfix")
        if not isinstance(hotfix, dict) or hotfix.get("related_phase_id") != phase_id:
            continue
        document = payload.get("document")
        authored_state = str(document.get("status", "planned")) if isinstance(document, dict) else "planned"
        closeout = payload.get("closeout_requirements")
        closeout = closeout if isinstance(closeout, dict) else {}
        raw_claims = closeout.get("claims")
        raw_claims = raw_claims if isinstance(raw_claims, dict) else {}
        claim_reports: dict[str, Any] = {}
        claims_verified = bool(raw_claims)
        for claim_id, raw in raw_claims.items():
            requirement = raw if isinstance(raw, dict) else {}
            gate_ids = [
                str(value)
                for value in requirement.get("required_evidence", [])
                if isinstance(value, str)
            ]
            required_gates.update(gate_ids)
            missing = [
                gate_id
                for gate_id in gate_ids
                if not any(
                    candidate["result"] == "verified"
                    and (candidate.get("receipt", {}).get("subject", {})).get("binding")
                    == "exact_tree"
                    for candidate in receipts.get(gate_id, [])
                )
            ]
            verified = bool(gate_ids) and not missing
            claims_verified = claims_verified and verified
            claim_reports[str(claim_id)] = {
                "effective_state": "verified" if verified else "completed",
                "required_evidence": gate_ids,
                "missing_or_invalid": missing,
            }
        reconciliation = closeout.get("reconciliation")
        reconciliation = reconciliation if isinstance(reconciliation, dict) else {}
        reconciliation_gates = [
            str(value)
            for value in reconciliation.get("required_evidence", [])
            if isinstance(value, str)
        ]
        required_gates.update(reconciliation_gates)
        reconciliation_verified = bool(reconciliation_gates) and all(
            any(
                candidate["result"] == "verified"
                and (candidate.get("receipt", {}).get("subject", {})).get("binding")
                == "exact_tree"
                for candidate in receipts.get(gate_id, [])
            )
            for gate_id in reconciliation_gates
        )
        effective_state = authored_state
        if authored_state == "completed" and claims_verified:
            effective_state = "verified"
            if reconciliation_verified and findings_clear:
                effective_state = "closed"
        hotfix_id = str(hotfix.get("id", path.stem))
        if effective_state != "closed":
            issues.append(f"hotfix_{hotfix_id}_effective_state_{effective_state}")
        reports.append(
            {
                "hotfix_id": hotfix_id,
                "path": path.relative_to(repo_root).as_posix(),
                "authored_state": authored_state,
                "effective_state": effective_state,
                "claims": claim_reports,
                "reconciliation": {
                    "effective_state": "verified" if reconciliation_verified else "completed",
                    "required_evidence": reconciliation_gates,
                },
            }
        )
    return reports, required_gates, issues


def _dsse_pae(payload_type: str, payload: bytes) -> bytes:
    return (
        b"DSSEv1 "
        + str(len(payload_type.encode("utf-8"))).encode("ascii")
        + b" "
        + payload_type.encode("utf-8")
        + b" "
        + str(len(payload)).encode("ascii")
        + b" "
        + payload
    )


def finding_report(
    repo_root: Path,
    registry: dict[str, Any],
    receipts: dict[str, list[dict[str, Any]]],
    profile: str,
    policy: dict[str, Any],
) -> dict[str, Any]:
    raw_findings = registry.get("findings", [])
    findings = raw_findings if isinstance(raw_findings, list) else []
    severity_counts: Counter[str] = Counter()
    disposition_counts: Counter[str] = Counter()
    blocking_ids: list[str] = []
    same_actor: list[str] = []
    issues: list[str] = []
    warnings: list[str] = []
    blocking_by_review: Counter[str] = Counter()
    findings_by_review: Counter[str] = Counter()
    severity_by_review: dict[str, Counter[str]] = defaultdict(Counter)
    disposition_by_review: dict[str, Counter[str]] = defaultdict(Counter)
    finding_ids_by_review: dict[str, set[str]] = defaultdict(set)
    finding_reviewers_by_review: dict[str, list[dict[str, Any]]] = defaultdict(list)
    seen_finding_ids: set[str] = set()
    provenance_policy = policy.get("provenance")
    provenance_policy = provenance_policy if isinstance(provenance_policy, dict) else {}
    permitted_risk_authorities = {
        str(value) for value in provenance_policy.get("permitted_risk_authorities", [])
    }
    same_actor_policy = str(provenance_policy.get("standard_same_actor_policy", "warn"))
    for index, raw in enumerate(findings, start=1):
        if not isinstance(raw, dict):
            issues.append(f"finding_{index}_invalid")
            continue
        finding_id = str(raw.get("id", f"finding-{index}"))
        severity = str(raw.get("severity", "unknown")).lower()
        disposition = str(raw.get("disposition", "open"))
        review_id = str(raw.get("review_id", ""))
        if finding_id in seen_finding_ids:
            issues.append(f"finding_{finding_id}_duplicate_id")
        seen_finding_ids.add(finding_id)
        severity_counts[severity] += 1
        disposition_counts[disposition] += 1
        findings_by_review[review_id] += 1
        severity_by_review[review_id][severity] += 1
        disposition_by_review[review_id][disposition] += 1
        finding_ids_by_review[review_id].add(finding_id)
        provenance = raw.get("provenance")
        provenance = provenance if isinstance(provenance, dict) else {}
        finding_reviewer = provenance.get("reviewer")
        if isinstance(finding_reviewer, dict):
            finding_reviewers_by_review[review_id].append(finding_reviewer)
        producer_ids = {
            str(actor.get("id"))
            for actor in provenance.get("producers", [])
            if isinstance(actor, dict)
        }
        remediator_ids = {
            str(actor.get("id"))
            for actor in provenance.get("remediators", [])
            if isinstance(actor, dict)
        }
        verifier = provenance.get("verifier")
        verifier_id = str(verifier.get("id")) if isinstance(verifier, dict) else ""
        if verifier_id and verifier_id in producer_ids | remediator_ids:
            same_actor.append(finding_id)
            if profile == "regulated" and severity in {"critical", "high"}:
                issues.append(f"finding_{finding_id}_independent_verifier_required")
            elif same_actor_policy == "fail":
                issues.append(f"finding_{finding_id}_same_actor_verification_forbidden")
            elif same_actor_policy == "warn":
                warnings.append(f"finding_{finding_id}_same_actor_verification")
        proofs = raw.get("proofs", [])
        proof_valid = False
        if isinstance(proofs, list):
            for proof in proofs:
                if not isinstance(proof, dict):
                    continue
                gate_id = proof.get("gate_id")
                node_id = proof.get("node_id")
                control_id = proof.get("negative_control_id")
                for candidate in receipts.get(str(gate_id), []):
                    if candidate["result"] != "verified":
                        continue
                    receipt = candidate.get("receipt", {})
                    observations = receipt.get("observations", {}) if isinstance(receipt, dict) else {}
                    nodes = observations.get("test_node_ids", []) if isinstance(observations, dict) else []
                    controls = receipt.get("behavioral_probes", []) if isinstance(receipt, dict) else []
                    control_ids = {
                        str(control.get("id"))
                        for control in controls
                        if isinstance(control, dict)
                        and control.get("mutation_applied") is True
                        and isinstance(control.get("observed_exit_code"), int)
                        and control["observed_exit_code"] != 0
                    }
                    proof_kind = proof.get("kind")
                    if (
                        (proof_kind == "test_node" and node_id in nodes and control_id in control_ids)
                        or (proof_kind == "behavioral_probe" and control_id in control_ids)
                    ):
                        proof_valid = True
        needs_proof = severity in {"critical", "high"} or profile == "regulated"
        if disposition == "remediation_completed" and needs_proof and not proof_valid:
            issues.append(f"finding_{finding_id}_behavioral_proof_missing")
        if (
            profile == "regulated"
            and severity in {"critical", "high"}
            and disposition == "remediation_completed"
            and (not verifier_id or verifier_id in producer_ids | remediator_ids)
        ):
            issues.append(f"finding_{finding_id}_independent_verifier_required")
        risk_acceptance = raw.get("risk_acceptance")
        authority = risk_acceptance.get("authority") if isinstance(risk_acceptance, dict) else None
        authority_id = str(authority.get("id")) if isinstance(authority, dict) else ""
        risk_authorized = bool(
            disposition == "accepted_risk"
            and authority_id in permitted_risk_authorities
            and isinstance(risk_acceptance.get("reference"), str)
            and risk_acceptance.get("reference")
        )
        is_blocking = disposition in BLOCKING_FINDING_DISPOSITIONS and (
            (disposition == "remediation_completed" and needs_proof and not proof_valid)
            or (disposition == "accepted_risk" and not risk_authorized)
            or disposition in {"open", "deferred"}
        )
        if is_blocking:
            blocking_ids.append(finding_id)
            blocking_by_review[review_id] += 1
    reviews = registry.get("reviews", [])
    review_ids: set[str] = set()
    if isinstance(reviews, list):
        for review in reviews:
            if not isinstance(review, dict) or not review.get("id"):
                continue
            review_id = str(review["id"])
            if review_id in review_ids:
                issues.append(f"review_{review_id}_duplicate_id")
            review_ids.add(review_id)
            declared_finding_ids = review.get("finding_ids")
            if not isinstance(declared_finding_ids, list) or set(
                str(value) for value in declared_finding_ids
            ) != finding_ids_by_review[review_id]:
                issues.append(f"review_{review_id}_finding_ids_mismatch")
            review_actor = review.get("reviewer")
            if any(
                review_actor != finding_reviewer
                for finding_reviewer in finding_reviewers_by_review[review_id]
            ):
                issues.append(f"review_{review_id}_reviewer_provenance_mismatch")
            source_path = review.get("source_path")
            source_sha256 = review.get("source_sha256")
            if not isinstance(source_path, str) or not (repo_root / source_path).is_file():
                issues.append(f"review_{review_id}_source_missing")
            elif _sha256(repo_root / source_path) != source_sha256:
                issues.append(f"review_{review_id}_source_hash_mismatch")
            summary = review.get("summary")
            if isinstance(summary, dict):
                if summary.get("findings_total") != findings_by_review[review_id]:
                    issues.append(f"review_{review_id}_findings_total_mismatch")
                if summary.get("open_count") != blocking_by_review[review_id]:
                    issues.append(f"review_{review_id}_open_count_mismatch")
                if "severity_counts" in summary and summary.get("severity_counts") != dict(
                    sorted(severity_by_review[review_id].items())
                ):
                    issues.append(f"review_{review_id}_severity_counts_mismatch")
                if "disposition_counts" in summary and summary.get(
                    "disposition_counts"
                ) != dict(sorted(disposition_by_review[review_id].items())):
                    issues.append(f"review_{review_id}_disposition_counts_mismatch")
    for raw in findings:
        if isinstance(raw, dict) and str(raw.get("review_id")) not in review_ids:
            issues.append(f"finding_{raw.get('id', 'unknown')}_review_missing")
    if sum(severity_counts.values()) != len(findings) or sum(
        disposition_counts.values()
    ) != len(findings):
        issues.append("finding_registry_accounting_identity_failed")
    return {
        "findings_total": len(findings),
        "severity_counts": dict(sorted(severity_counts.items())),
        "disposition_counts": dict(sorted(disposition_counts.items())),
        "open_count": len(blocking_ids),
        "blocking_finding_ids": sorted(blocking_ids),
        "same_actor_closure": sorted(same_actor),
        "warnings": sorted(set(warnings)),
        "issues": sorted(set(issues)),
    }


def verify_attestation(
    repo_root: Path, evidence_dir: Path, policy: dict[str, Any], current: dict[str, Any]
) -> dict[str, Any]:
    profile_config = policy.get("provenance")
    profile_config = profile_config if isinstance(profile_config, dict) else {}
    trusted_keys = profile_config.get("trusted_verifier_keys", {})
    trusted_keys = trusted_keys if isinstance(trusted_keys, dict) else {}
    issues: list[str] = []
    valid: list[dict[str, Any]] = []
    attestation_paths = sorted(evidence_dir.rglob("*.attestation.json"))
    excluded_names = {path.name for path in attestation_paths}
    expected_bundle = bundle_digest(evidence_dir, exclude_names=excluded_names | {"truth-report.json"})
    for path in attestation_paths:
        try:
            envelope = json.loads(path.read_text(encoding="utf-8"))
            payload_type = envelope["payloadType"]
            payload = base64.b64decode(envelope["payload"], validate=True)
            signatures = envelope["signatures"]
            signature_entry = signatures[0]
            key_id = signature_entry["keyid"]
            signature = base64.b64decode(signature_entry["sig"], validate=True)
            statement = json.loads(payload)
        except (IndexError, KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
            issues.append(f"attestation_{path.name}_invalid:{exc}")
            continue
        if payload_type != DSSE_PAYLOAD_TYPE or not isinstance(statement, dict):
            issues.append(f"attestation_{path.name}_payload_type_invalid")
            continue
        key_path_value = trusted_keys.get(key_id) if isinstance(key_id, str) else None
        if not isinstance(key_path_value, str):
            issues.append(f"attestation_{path.name}_untrusted_key")
            continue
        key_path = Path(key_path_value)
        if key_path.is_absolute() or ".." in key_path.parts:
            issues.append(f"attestation_{path.name}_trusted_key_path_invalid")
            continue
        if statement.get("bundle_sha256") != expected_bundle:
            issues.append(f"attestation_{path.name}_bundle_mismatch")
            continue
        if statement.get("commit_sha") != current["commit_sha"] or statement.get("tree_sha") != current["tree_sha"]:
            issues.append(f"attestation_{path.name}_subject_stale")
            continue
        verifier = statement.get("verifier")
        if (
            not isinstance(verifier, dict)
            or verifier.get("kind") not in {"human", "model", "service", "workflow"}
            or not isinstance(verifier.get("id"), str)
            or not verifier.get("id")
        ):
            issues.append(f"attestation_{path.name}_verifier_invalid")
            continue
        signed_payload = _dsse_pae(payload_type, payload)
        with tempfile.NamedTemporaryFile() as payload_file, tempfile.NamedTemporaryFile() as signature_file:
            payload_file.write(signed_payload)
            payload_file.flush()
            signature_file.write(signature)
            signature_file.flush()
            result = subprocess.run(
                [
                    "openssl", "pkeyutl", "-verify", "-rawin", "-pubin", "-inkey",
                    str(repo_root / key_path), "-in", payload_file.name,
                    "-sigfile", signature_file.name,
                ],
                capture_output=True,
                text=True,
            )
        if result.returncode != 0:
            issues.append(f"attestation_{path.name}_signature_invalid")
            continue
        valid.append(statement)
    return {"valid_attestations": valid, "issues": sorted(issues)}

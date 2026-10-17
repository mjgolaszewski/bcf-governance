"""Derive verified and closed governance lifecycle state from evidence."""

from __future__ import annotations

import json
import re
import subprocess
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import yaml  # type: ignore[import-untyped]

from .governance_evidence import (
    bundle_digest,
    expected_evidence_kinds,
    expected_invocations,
)
from .ci_authority_certification import (
    CICertificationError,
    verify_ci_certification,
)
from .governance_truth_support import (
    compute_hotfix_reports,
    finding_report,
    verify_attestation,
)
from .evidence_workitem_lifecycle import workitem_observation
from .evidence_execution import EvidenceError
from .evidence_plan_scope import truth_scope_projection
from .evidence_reuse_attestations import compose_local_reuse
from .affected_proof_closure import verify_session_affected_proof_set
from .prior_evidence_receipts import load_provisional_transport, provisional_receipts
from .truth_receipts import ReceiptError, load_receipts
from .evidence_planning import load_claim_model
from .truth_reporting import (
    REQUIRED_DIRECT_CLAIMS,
    active_log_path,
    current_subject,
    current_session_plan,
    exact_session_binding,
    failure_envelope,
    profile_closeout_requirements,
    verified_candidate,
)
from .evidence_claim_resolution import resolved_session_claims
from .evaluation_scope import (
    EvaluationIntent,
    EvaluationScopeError,
    certified_proposition,
    evaluation_scope,
)
from .truth_workflow_graph import workflow_gate_issues


class TruthfulnessError(ValueError):
    """Raised when a truth report cannot be evaluated."""


AUTHORED_STATES = {"planned", "active", "blocked", "paused", "completed"}


def _load_yaml(path: Path) -> dict[str, Any]:
    if not path.exists():
        raise TruthfulnessError(f"missing required path {path}")
    payload = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise TruthfulnessError(f"{path} must deserialize to a mapping")
    return payload


def _git(repo_root: Path, *args: str, check: bool = True) -> str:
    result = subprocess.run(
        ["git", *args], cwd=repo_root, capture_output=True, text=True
    )
    if check and result.returncode != 0:
        raise TruthfulnessError(result.stderr.strip() or f"git {' '.join(args)} failed")
    return result.stdout.strip()





def _workflow_gate_issues(repo_root: Path, policy: dict[str, Any], gate_ids: set[str]) -> list[str]:
    return workflow_gate_issues(repo_root, policy, gate_ids, load_yaml=_load_yaml)


def derive_truth(
    repo_root: Path,
    evidence_dir: Path,
    *,
    evaluation_mode: str = "closure",
    evaluation_target: str | None = None,
    trusted_digest: str | None = None,
    ci_authority_path: Path | None = None,
    ci_certification_path: Path | None = None,
    ci_session_manifest_path: Path | None = None,
    prior_transport_dir: Path | None = None,
) -> dict[str, Any]:
    repo_root = repo_root.resolve()
    evidence_dir = evidence_dir.resolve()
    current = current_subject(repo_root)
    policy = _load_yaml(repo_root / "governance/evidence-policy.yml")
    profile_payload = _load_yaml(repo_root / "governance-profile.yml")
    profile_block = profile_payload.get("profile")
    profile_block = profile_block if isinstance(profile_block, dict) else {}
    selected_profile = str(profile_block.get("selected", "standard"))
    contract_version = str(profile_payload.get("profile_contract_version", "1.0"))
    settings = policy.get("settings")
    settings = settings if isinstance(settings, dict) else {}
    require_negative = bool(settings.get("require_negative_control_for_required_gates", True))
    tree_independent_allowlist = {
        str(value) for value in settings.get("tree_independent_allowlist", [])
    }
    try:
        receipts = load_receipts(
            repo_root,
            evidence_dir,
            current,
            require_negative_control=require_negative,
            tree_independent_allowlist=tree_independent_allowlist,
            expected_kinds=expected_evidence_kinds(repo_root),
            invocations=expected_invocations(repo_root),
            require_session=contract_version in {"2.0", "3.0"},
            selected_profile=selected_profile,
            contract_version=contract_version,
        )
    except ReceiptError as exc:
        raise TruthfulnessError(str(exc)) from exc
    claim_model = load_claim_model(repo_root) if contract_version == "3.0" else None
    session_plan = (
        current_session_plan(evidence_dir, current)
        if contract_version == "3.0"
        else {}
    )
    if session_plan.get("schema_version") == "3.0":
        try:
            prior_receipts = (
                provisional_receipts(load_provisional_transport(
                    repo_root, prior_transport_dir, current_subject=current,
                ))
                if prior_transport_dir is not None
                else []
            )
            verify_session_affected_proof_set(
                repo_root,
                claim_model,
                session_plan,
                current_subject=current,
                prior_receipts=prior_receipts,
            )
        except (EvidenceError, OSError, ValueError) as exc:
            raise TruthfulnessError(
                "evidence session affected proof set is not canonical"
            ) from exc
    reuse_session_binding = (
        exact_session_binding(evidence_dir, current, session_plan)
        if session_plan.get("reused_evidence") else None
    )
    preflight_claims = {
        str(value)
        for value in session_plan.get("preflight_satisfied_claims", [])
        if isinstance(value, str)
    }
    reuse_decisions: list[dict[str, Any]] = []
    reuse_index: dict[str, dict[str, Any]] = {}
    if session_plan.get("reused_evidence"):
        if prior_transport_dir is None:
            raise TruthfulnessError("planned reuse lacks its prior transport bytes")
        try:
            reuse_decisions, reuse_index = compose_local_reuse(
                repo_root, prior_transport_dir, session_plan, current,
                emitted_at=datetime.now(UTC).isoformat().replace("+00:00", "Z"),
            )
        except (EvidenceError, OSError, ValueError) as exc:
            raise TruthfulnessError("planned reuse lacks complete applicable attestations") from exc
    phase_log = _load_yaml(active_log_path(repo_root))
    ledger_payload = _load_yaml(repo_root / "plans/phase-ledger.yml")
    active_phase = ledger_payload.get("active_phase")
    ledger_state = (
        str(active_phase.get("lifecycle_status", "planned"))
        if isinstance(active_phase, dict)
        else "planned"
    )
    document = phase_log.get("document")
    authored_state = str(document.get("status", "planned")) if isinstance(document, dict) else "planned"
    phase = phase_log.get("phase")
    phase_id = str(phase.get("id", "")) if isinstance(phase, dict) else ""
    if not phase_id:
        raise TruthfulnessError("active phase log does not declare phase.id")
    try:
        scope = evaluation_scope(
            evaluation_mode,
            target=evaluation_target,
            phase_id=phase_id,
            subject_commit=str(current["commit_sha"]),
        )
    except EvaluationScopeError as exc:
        raise TruthfulnessError(str(exc)) from exc
    scoped_gate_ids, session_scope_issues = truth_scope_projection(
        repo_root, session_plan, evaluation_mode=evaluation_mode,
        evaluation_target=evaluation_target, enabled=contract_version == "3.0",
    )
    if authored_state not in AUTHORED_STATES:
        raise TruthfulnessError(
            f"phase authored status {authored_state!r} is invalid; verified and closed are computed"
        )
    closeout = phase_log.get("closeout_requirements")
    closeout = closeout if isinstance(closeout, dict) else {}
    raw_claims = closeout.get("claims")
    raw_claims = raw_claims if isinstance(raw_claims, dict) else {}
    profile_requirements = profile_closeout_requirements(repo_root, profile_payload)
    missing_claim_declarations = sorted(REQUIRED_DIRECT_CLAIMS - set(raw_claims))
    claims: dict[str, Any] = {}
    direct_verified = not missing_claim_declarations
    workitems = workitem_observation(
        repo_root, receipts, claim_model or {"claims": {}}, preflight_claims, current,
        reuse_attestations=reuse_index,
    )
    required_gate_ids: set[str] = set()
    for claim_id, raw in raw_claims.items():
        requirement = raw if isinstance(raw, dict) else {}
        authored_gate_ids = [
            str(value)
            for value in requirement.get("required_evidence", [])
            if isinstance(value, str)
        ]
        profile_gate_ids = profile_requirements["claims"].get(str(claim_id), [])
        gate_ids = sorted(set(authored_gate_ids).union(profile_gate_ids))
        if str(claim_id) == "workitems_closed":
            gate_ids = sorted(
                set(gate_ids) | set(workitems.get("acceptance_evidence", []))
            )
        required_gate_ids.update(gate_ids)
        refs: list[dict[str, Any]] = []
        missing: list[str] = []
        for gate_id in gate_ids:
            candidates = receipts.get(gate_id, [])
            verified = (
                verified_candidate(receipts, claim_model, gate_id, preflight_claims,
                                   reuse_index)
                if claim_model is not None
                else next(
                    (
                        candidate
                        for candidate in candidates
                        if candidate["result"] == "verified"
                        and (candidate.get("receipt", {}).get("subject", {})).get("binding")
                        == "exact_tree"
                    ),
                    None,
                )
            )
            if verified is None:
                missing.append(gate_id)
                refs.extend(candidates)
            else:
                refs.append(verified)
        measurement_ok = not (
            str(claim_id) == "workitems_closed"
            and workitems.get("satisfied") is not True
        )
        applicable = bool(gate_ids)
        verified_claim = applicable and not missing and measurement_ok
        if str(claim_id) != "findings_resolved":
            direct_verified = direct_verified and (verified_claim or not applicable)
        claims[str(claim_id)] = {
            "applicability": "applicable" if applicable else "not_applicable",
            "effective_state": (
                "verified" if verified_claim else "not_applicable" if not applicable else "completed"
            ),
            "required_evidence": gate_ids,
            "profile_required_evidence": sorted(profile_gate_ids),
            "authored_additional_evidence": sorted(
                set(authored_gate_ids) - set(profile_gate_ids)
            ),
            "evidence_refs": [
                {key: value for key, value in ref.items() if key not in {"receipt"}}
                for ref in refs
            ],
            "missing_or_invalid": missing,
            **(
                {"repository_observation": workitems}
                if str(claim_id) == "workitems_closed"
                else {}
            ),
        }
    reconciliation = closeout.get("reconciliation")
    reconciliation = reconciliation if isinstance(reconciliation, dict) else {}
    authored_reconciliation_gates = [
        str(value)
        for value in reconciliation.get("required_evidence", [])
        if isinstance(value, str)
    ]
    reconciliation_gates = sorted(
        set(authored_reconciliation_gates).union(profile_requirements["reconciliation"])
    )
    required_gate_ids.update(reconciliation_gates)
    reconciliation_verified = bool(reconciliation_gates) and all(
        (
            verified_candidate(receipts, claim_model, gate_id, preflight_claims,
                               reuse_index)
            is not None
            if claim_model is not None
            else any(
                candidate["result"] == "verified"
                and (candidate.get("receipt", {}).get("subject", {})).get("binding")
                == "exact_tree"
                for candidate in receipts.get(gate_id, [])
            )
        )
        for gate_id in reconciliation_gates
    )
    dependency_policy = policy.get("claim_dependencies")
    dependency_policy = dependency_policy if isinstance(dependency_policy, dict) else {}
    changed_paths: set[str] = set()
    changed_categories: set[str] = set()
    for values in receipts.values():
        for candidate in values:
            invalidation = candidate.get("invalidation")
            if not isinstance(invalidation, dict):
                continue
            changed_paths.update(str(value) for value in invalidation.get("paths", []))
            changed_categories.update(
                str(value) for value in invalidation.get("categories", [])
            )
    affected_claims = sorted(
        claim_id
        for claim_id, dependencies in dependency_policy.items()
        if isinstance(dependencies, list)
        and changed_categories.intersection(str(value) for value in dependencies)
    )
    if "security_impact" in changed_categories and "security_review_complete" not in affected_claims:
        affected_claims.append("security_review_complete")
    findings = finding_report(
        repo_root,
        _load_yaml(repo_root / "governance/findings.yml"),
        receipts,
        selected_profile,
        policy,
        claim_model or {"claims": {}},
        preflight_claims,
    )
    findings_claim = claims.get("findings_resolved")
    if isinstance(findings_claim, dict):
        findings_clear = findings["open_count"] == 0 and not findings["issues"]
        findings_evidence_valid = not findings_claim["missing_or_invalid"]
        findings_applicable = findings_claim["applicability"] == "applicable"
        findings_claim["effective_state"] = (
            "verified"
            if findings_clear and findings_evidence_valid and findings_applicable
            else "not_applicable"
            if not findings_applicable
            else "completed"
        )
        findings_claim["registry_observation"] = findings
        # Current finding evidence is a direct verification requirement. Open or
        # inadequately remediated findings block closure, but do not erase valid
        # verification of the implementation gates on the same tree.
        direct_verified = direct_verified and (
            findings_evidence_valid or not findings_applicable
        )
    hotfixes, hotfix_gate_ids, hotfix_issues = compute_hotfix_reports(
        repo_root,
        phase_id,
        receipts,
        findings_clear=findings["open_count"] == 0 and not findings["issues"],
        claim_model=claim_model or {"claims": {}},
        preflight_claims=preflight_claims,
        reuse_attestations=reuse_index,
    )
    required_gate_ids.update(hotfix_gate_ids)
    release_profile = profile_payload.get("release_gate_profile")
    release_profile = release_profile if isinstance(release_profile, dict) else {}
    configured_gates = release_profile.get("gates")
    configured_gates = configured_gates if isinstance(configured_gates, dict) else {}
    release_gate_ids = {
        str(gate.get("target"))
        for gate in configured_gates.values()
        if isinstance(gate, dict)
        and gate.get("status") == "required"
        and isinstance(gate.get("target"), str)
    }
    missing_release_gates = sorted(
        gate_id
        for gate_id in release_gate_ids
        if (
            verified_candidate(receipts, claim_model, gate_id, preflight_claims,
                               reuse_index)
            is None
            if claim_model is not None
            else not any(
                candidate["result"] == "verified"
                and (candidate.get("receipt", {}).get("subject", {})).get("binding")
                == "exact_tree"
                for candidate in receipts.get(gate_id, [])
            )
        )
    )
    workflow_issues = _workflow_gate_issues(
        repo_root,
        policy,
        scoped_gate_ids
        if scoped_gate_ids is not None
        else required_gate_ids | release_gate_ids,
    )
    attestation = verify_attestation(repo_root, evidence_dir, policy, current)
    signature_required = selected_profile == "regulated"
    provenance_ok = not signature_required or bool(attestation["valid_attestations"])
    lifecycle_consistent = authored_state == ledger_state
    effective_state = authored_state
    if direct_verified:
        effective_state = "verified"
        if reconciliation_verified and findings["open_count"] == 0 and not findings["issues"] and provenance_ok:
            effective_state = "closed"
    attestation_names = {path.name for path in evidence_dir.rglob("*.attestation.json")}
    actual_bundle_digest = bundle_digest(
        evidence_dir, exclude_names=attestation_names | {"truth-report.json"}
    )
    digest_issue = bool(trusted_digest and trusted_digest != actual_bundle_digest)
    truth_issues = list(workflow_issues) + list(attestation["issues"]) + session_scope_issues
    if scope.intent is not EvaluationIntent.WORKITEM_CERTIFICATION:
        truth_issues.extend(findings["issues"])
        truth_issues.extend(hotfix_issues)
    if scope.intent is EvaluationIntent.PR_PROGRESS:
        truth_issues = [
            issue
            for issue in truth_issues
            if not re.fullmatch(r"hotfix_.+_effective_state_planned", issue)
        ]
    ci_paths = (
        ci_authority_path,
        ci_certification_path,
        ci_session_manifest_path,
    )
    ci_certification: dict[str, Any] = {
        "applicability": "not_enabled",
        "status": "not_applicable",
    }
    if any(value is not None for value in ci_paths):
        if not all(value is not None for value in ci_paths):
            ci_certification = {
                "applicability": "enabled",
                "status": "fail",
                "computed_state": "incomplete",
                "reasons": ["ci_certification_inputs_incomplete"],
            }
            truth_issues.append("ci_certification_inputs_incomplete")
        else:
            try:
                verification = verify_ci_certification(
                    repo_root,
                    authority_path=ci_authority_path,
                    certification_path=ci_certification_path,
                    session_manifest_path=ci_session_manifest_path,
                )
                ci_certification = {
                    "applicability": "enabled",
                    **verification.as_dict(),
                }
            except CICertificationError as exc:
                ci_certification = {
                    "applicability": "enabled",
                    "status": "fail",
                    "computed_state": "invalid",
                    "reasons": [str(exc)],
                }
            if ci_certification.get("status") != "pass":
                truth_issues.append("ci_certification_not_verified")
    if scope.intent is not EvaluationIntent.WORKITEM_CERTIFICATION:
        truth_issues.extend(
            f"required_claim_{claim_id}_not_declared"
            for claim_id in missing_claim_declarations
        )
    if not lifecycle_consistent and scope.intent is EvaluationIntent.PHASE_CLOSURE:
        truth_issues.append("ledger_log_lifecycle_mismatch")
    if ledger_state in {"blocked", "paused", "abandoned"} and scope.intent is EvaluationIntent.PHASE_CLOSURE:
        truth_issues.append(f"ledger_state_{ledger_state}_cannot_verify")
    all_receipts = [candidate for values in receipts.values() for candidate in values]
    for candidate in all_receipts:
        identity_failure = any(
            "identity" in issue or "duplicate" in issue
            for issue in candidate.get("issues", [])
        )
        if candidate["result"] != "verified" and identity_failure:
            truth_issues.append(
                f"evidence_receipt_invalid:{candidate.get('gate_id')}:{candidate.get('evidence_id')}"
            )
        if "unsupported_schema_version" in candidate.get("issues", []):
            truth_issues.append(
                f"{candidate.get('gate_id')}:unsupported_schema_version"
            )
    if scope.intent is not EvaluationIntent.WORKITEM_CERTIFICATION:
        truth_issues.extend(
            f"release_gate_{gate_id}_missing_or_invalid"
            for gate_id in missing_release_gates
        )
    if digest_issue:
        truth_issues.append("trusted_bundle_digest_mismatch")
    if signature_required and not provenance_ok:
        truth_issues.append("regulated_attestation_required")
    if scope.intent is EvaluationIntent.PHASE_CLOSURE and effective_state != "closed":
        truth_issues.append(f"phase_effective_state_{effective_state}")
    if scope.intent is EvaluationIntent.WORKITEM_CERTIFICATION:
        target = next(
            (item for item in workitems.get("items", []) if item.get("id") == scope.target_id),
            None,
        )
        if not isinstance(target, dict) or target.get("effective_state") != "closed":
            truth_issues.append("bounded_workitem_target_not_closed")
    release_state = (
        "closed"
        if effective_state == "closed"
        and all(hotfix["effective_state"] == "closed" for hotfix in hotfixes)
        and not missing_release_gates
        and not truth_issues
        else "completed"
    )
    final_issues = sorted(set(truth_issues))
    envelope = failure_envelope(
        evidence_dir,
        current,
        session_plan,
        final_issues,
        all_receipts,
        resolved_claims=resolved_session_claims(
            receipts,
            claim_model,
            preflight_claims,
            session_plan.get("required_claims", []),
            reuse_index,
        ),
    )
    required_count = len(session_plan.get("required_claims", []))
    reused_count = len(session_plan.get("reused_evidence", []))
    invalidated_count = len(session_plan.get("invalidated_evidence", []))
    execution_nodes = session_plan.get("execution_dag", {}).get("nodes", [])
    advisory_metrics = {
        "required_claims": required_count,
        "reused_claims": reused_count,
        "invalidated_claims": invalidated_count,
        "newly_executed_claims": sum(
            len(node.get("claims", [])) for node in execution_nodes
            if isinstance(node, dict)
        ),
        "execution_nodes_avoided": reused_count,
        "unique_causal_roots": len(envelope["root_causes"]),
        "raw_failure_count": len(envelope["raw_failures"]),
    }
    status = "pass" if not truth_issues else "fail"
    proposition = certified_proposition(
        scope, subject=current, status=status, workitems=workitems
    )
    return {
        "schema_version": "3.0" if contract_version == "3.0" else "2.0",
        "evaluation_mode": evaluation_mode,
        "evaluation_scope": scope.as_dict(),
        "certified_proposition": proposition,
        "merge_eligibility": (
            "eligible"
            if scope.intent is EvaluationIntent.PR_PROGRESS and not truth_issues
            else "not_evaluated"
            if scope.intent is not EvaluationIntent.PR_PROGRESS
            else "ineligible"
        ),
        "phase_id": phase_id,
        "status": status,
        "failure_class": None if not truth_issues else "truthfulness",
        "engine": "evidence_truthfulness",
        "checks": {
            "evidence_integrity": "pass"
            if all_receipts and all(candidate["result"] == "verified" for candidate in all_receipts)
            else "fail",
            "exact_tree": "pass"
            if all_receipts and all(
                not any("current" in issue or "clean" in issue for issue in candidate["issues"])
                for values in receipts.values()
                for candidate in values
            )
            else "fail",
            "workflow_execution": "pass" if not workflow_issues else "fail",
            "test_execution": "pass"
            if claims.get("required_suites_green", {}).get("effective_state")
            in {"verified", "not_applicable"}
            else "fail",
            "finding_accounting": "pass" if not findings["issues"] else "fail",
            "provenance": "pass" if provenance_ok and not attestation["issues"] else "fail",
            "ci_certification": ci_certification["status"],
        },
        "subject": current,
        "bundle_sha256": actual_bundle_digest,
        "authored_state": authored_state,
        "ledger_state": ledger_state,
        "effective_state": effective_state,
        "release_readiness": {
            "effective_state": release_state,
            "required_gates": sorted(release_gate_ids),
            "missing_or_invalid": missing_release_gates,
        },
        "claims": claims,
        "invalidation": {
            "changed_paths": sorted(changed_paths),
            "categories": sorted(changed_categories),
            "affected_claims": sorted(set(affected_claims)),
            "affected_phase": phase_id if affected_claims else None,
            "affected_release": bool(affected_claims),
        },
        "reconciliation": {
            "effective_state": "verified" if reconciliation_verified else "completed",
            "required_evidence": reconciliation_gates,
            "profile_required_evidence": profile_requirements["reconciliation"],
            "authored_additional_evidence": sorted(
                set(authored_reconciliation_gates)
                - set(profile_requirements["reconciliation"])
            ),
        },
        "hotfixes": hotfixes,
        "findings": findings,
        "attestation": attestation,
        "ci_certification": ci_certification,
        "verifier": (
            attestation["valid_attestations"][0].get("verifier")
            if attestation["valid_attestations"]
            else {"kind": "service", "id": "bcf truth"}
        ),
        "warnings": findings["warnings"],
        "issues": final_issues,
        "failure_envelope": envelope,
        "advisory_metrics": advisory_metrics,
        **({"reuse_attestations": reuse_decisions} if reuse_decisions else {}),
        **({"reuse_session_binding": reuse_session_binding}
           if reuse_session_binding is not None else {}),
    }


def main(argv: list[str] | None = None) -> None:
    from .governance_truth_cli import main as cli_main

    cli_main(argv)


if __name__ == "__main__":
    main()

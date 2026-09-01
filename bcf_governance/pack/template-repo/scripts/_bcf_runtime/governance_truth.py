"""Derive verified and closed governance lifecycle state from evidence."""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
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
    workitem_observation,
)
from .truth_receipts import ReceiptError, load_receipts
from .truth_workflow_graph import graph_workflow_gate_issues
from .release_receipts import (
    ReleaseReceiptError,
    build_release_receipt,
    emit_release_receipt,
)


class TruthfulnessError(ValueError):
    """Raised when a truth report cannot be evaluated."""


AUTHORED_STATES = {"planned", "completed"}
REQUIRED_DIRECT_CLAIMS = {
    "workitems_closed", "required_suites_green", "architecture_gates_green",
    "health_checks_green", "security_review_complete", "findings_resolved",
}
def _profile_closeout_requirements(
    repo_root: Path, profile_payload: dict[str, Any]
) -> dict[str, Any]:
    """Derive non-authorable claim applicability from canonical gate contracts."""
    registry = _load_yaml(repo_root / "governance/gate-contracts.yml")
    contract_gates = registry.get("gates")
    if not isinstance(contract_gates, dict):
        raise TruthfulnessError("governance/gate-contracts.yml gates must be a mapping")
    configured = profile_payload.get("release_gate_profile", {}).get("gates", {})
    configured = configured if isinstance(configured, dict) else {}
    policies = {
        str(value.get("target")): str(value.get("command_policy", ""))
        for value in configured.values()
        if isinstance(value, dict) and isinstance(value.get("target"), str)
    }
    claims: dict[str, list[str]] = {claim: [] for claim in REQUIRED_DIRECT_CLAIMS}
    for target in sorted(str(value) for value in contract_gates):
        command_policy = policies.get(target, "")
        if target == "governance-validate":
            claims["workitems_closed"].append(target)
        if command_policy.startswith("architecture_") or command_policy == "architecture_tests":
            claims["architecture_gates_green"].append(target)
        elif command_policy in {"automated_tests", "contract_tests", "lint", "typecheck"}:
            claims["required_suites_green"].append(target)
        if command_policy == "runtime_smoke":
            claims["health_checks_green"].append(target)
        if command_policy == "security_review":
            claims["security_review_complete"].append(target)
            claims["findings_resolved"].append(target)
        if command_policy == "security_vulnerability_scan":
            claims["findings_resolved"].append(target)
    if not claims["findings_resolved"] and "governance-validate" in contract_gates:
        claims["findings_resolved"].append("governance-validate")
    return {
        "claims": claims,
        "reconciliation": sorted(
            {"governance-validate", "governance-exposure-scan"}.intersection(contract_gates)
        ),
    }


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


def _active_log_path(repo_root: Path) -> Path:
    ledger = _load_yaml(repo_root / "plans/phase-ledger.yml")
    active = ledger.get("active_phase")
    if not isinstance(active, dict) or not isinstance(active.get("log"), str):
        raise TruthfulnessError("plans/phase-ledger.yml active_phase.log is required")
    return repo_root / str(active["log"])


def _current_subject(repo_root: Path) -> dict[str, Any]:
    status = _git(
        repo_root,
        "status",
        "--porcelain=v1",
        "--untracked-files=all",
        "--ignored=no",
    )
    return {
        "commit_sha": _git(repo_root, "rev-parse", "HEAD"),
        "tree_sha": _git(repo_root, "rev-parse", "HEAD^{tree}"),
        "tracked_clean": not bool(status),
        "untracked_clean": not bool(status),
    }


def _safe_contract_file(repo_root: Path, value: str) -> bool:
    relative = Path(value)
    if relative.is_absolute() or ".." in relative.parts:
        return False
    candidate = repo_root / relative
    try:
        candidate.resolve().relative_to(repo_root.resolve())
    except ValueError:
        return False
    return candidate.is_file() and not candidate.is_symlink()


def _workflow_gate_issues(repo_root: Path, policy: dict[str, Any], gate_ids: set[str]) -> list[str]:
    contract = policy.get("workflow_contract")
    if not isinstance(contract, dict):
        return ["workflow_contract_missing"]
    paths = contract.get("paths")
    required_events = contract.get("required_events", [])
    if not isinstance(paths, list) or not paths:
        return ["workflow_paths_missing"]
    graph_path = repo_root / "governance/ci-graph.yml"
    if graph_path.is_file():
        return graph_workflow_gate_issues(
            repo_root,
            paths=paths,
            required_events=required_events,
            gate_ids=gate_ids,
        )
    resolved_gates: set[str] = set()
    discovered_events: set[str] = set()
    issues: list[str] = []
    queue = [str(value) for value in paths if isinstance(value, str)]
    roots = set(queue)
    visited: set[str] = set()
    raw_resolvers = contract.get("gate_resolvers", [])
    resolvers = raw_resolvers if isinstance(raw_resolvers, list) else []
    while queue:
        relative_path = queue.pop(0)
        if relative_path in visited:
            continue
        visited.add(relative_path)
        path = repo_root / relative_path
        if not path.is_file():
            issues.append(f"workflow_path_{relative_path}_missing")
            continue
        payload = _load_yaml(path)
        if relative_path in roots:
            on_value = payload.get("on", payload.get(True))
            if isinstance(on_value, dict):
                discovered_events.update(str(key) for key in on_value)
            elif isinstance(on_value, list):
                discovered_events.update(str(value) for value in on_value)
            elif isinstance(on_value, str):
                discovered_events.add(on_value)
        jobs = payload.get("jobs")
        if not isinstance(jobs, dict):
            issues.append(f"workflow_{relative_path}_jobs_unresolved")
            continue
        for job_id, job in jobs.items():
            if not isinstance(job, dict):
                continue
            reusable = job.get("uses")
            if isinstance(reusable, str):
                if reusable.startswith("./"):
                    reusable_path = reusable[2:].split("@", 1)[0]
                    if reusable_path.startswith(".github/workflows/"):
                        queue.append(reusable_path)
                    else:
                        issues.append(f"workflow_job_{job_id}_local_reusable_path_invalid")
                else:
                    issues.append(f"workflow_job_{job_id}_external_reusable_unresolved")
                continue
            strategy = job.get("strategy")
            matrix = strategy.get("matrix") if isinstance(strategy, dict) else None
            job_matrix_gates: set[str] = set()
            if isinstance(matrix, dict):
                for key in ("gate", "target"):
                    values = matrix.get(key)
                    if isinstance(values, list):
                        job_matrix_gates.update(str(value) for value in values)
                    elif values is not None:
                        issues.append(f"workflow_job_{job_id}_{key}_matrix_dynamic")
            steps = job.get("steps")
            runs = "\n".join(
                str(step.get("run"))
                for step in steps
                if isinstance(step, dict) and isinstance(step.get("run"), str)
            ) if isinstance(steps, list) else ""
            wrapper_present = bool(
                re.search(
                    r"(?:governance_evidence\.py[\s\S]{0,300}\brun\b|bcf\s+evidence\s+run)"
                    r"[\s\S]{0,300}--gate",
                    runs,
                )
            )
            matching_resolvers = [
                resolver
                for resolver in resolvers
                if isinstance(resolver, dict)
                and resolver.get("workflow_path") == relative_path
                and resolver.get("job_id") == str(job_id)
            ]
            resolver_valid = False
            for resolver in matching_resolvers:
                resolver_id = str(resolver.get("id", job_id))
                matrix_key = resolver.get("matrix_key")
                script_path = resolver.get("script_path")
                gate_contract_path = resolver.get("gate_contract_path")
                profile_path = resolver.get("profile_path")
                values = matrix.get(matrix_key) if isinstance(matrix, dict) else None
                if (
                    resolver.get("kind") != "canonical_contract_shards"
                    or not isinstance(matrix_key, str)
                    or not isinstance(script_path, str)
                    or not isinstance(gate_contract_path, str)
                    or not isinstance(profile_path, str)
                    or not isinstance(values, list)
                    or any(not isinstance(value, int) for value in values)
                    or values != list(range(len(values)))
                    or not values
                    or not _safe_contract_file(repo_root, script_path)
                    or not _safe_contract_file(repo_root, gate_contract_path)
                    or not _safe_contract_file(repo_root, profile_path)
                ):
                    issues.append(f"workflow_gate_resolver_{resolver_id}_invalid")
                    continue
                index_pattern = re.compile(
                    rf"--shard-index(?:=|\s+)[\"']?\$\{{\{{\s*matrix\.{re.escape(matrix_key)}\s*\}}\}}[\"']?"
                )
                count_pattern = re.compile(
                    rf"--shard-count(?:=|\s+)[\"']?{len(values)}(?:[\"'\s]|$)"
                )
                if (
                    script_path not in runs
                    or index_pattern.search(runs) is None
                    or count_pattern.search(runs) is None
                ):
                    issues.append(
                        f"workflow_gate_resolver_{resolver_id}_invocation_invalid"
                    )
                    continue
                resolver_valid = True
            if resolver_valid:
                resolved_gates.update(gate_ids)
            if wrapper_present:
                resolved_gates.update(job_matrix_gates)
                for gate_id in gate_ids:
                    if re.search(rf"--gate(?:=|\s+)[\"']?{re.escape(gate_id)}(?:[\"'\s]|$)", runs):
                        resolved_gates.add(gate_id)
            elif job_matrix_gates.intersection(gate_ids):
                issues.append(f"workflow_job_{job_id}_evidence_wrapper_missing")
    issues.extend(
        f"workflow_event_{event}_missing"
        for event in required_events
        if isinstance(event, str) and event not in discovered_events
    )
    for gate_id in sorted(gate_ids):
        if gate_id not in resolved_gates:
            issues.append(f"workflow_gate_{gate_id}_unresolved")
    return sorted(set(issues))


def derive_truth(
    repo_root: Path,
    evidence_dir: Path,
    *,
    evaluation_mode: str = "closure",
    trusted_digest: str | None = None,
    ci_authority_path: Path | None = None,
    ci_certification_path: Path | None = None,
    ci_session_manifest_path: Path | None = None,
) -> dict[str, Any]:
    if evaluation_mode not in {"closure", "pr"}:
        raise TruthfulnessError("truth evaluation mode must be closure or pr")
    repo_root = repo_root.resolve()
    evidence_dir = evidence_dir.resolve()
    current = _current_subject(repo_root)
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
            require_session=contract_version == "2.0",
            selected_profile=selected_profile,
            contract_version=contract_version,
        )
    except ReceiptError as exc:
        raise TruthfulnessError(str(exc)) from exc
    phase_log = _load_yaml(_active_log_path(repo_root))
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
    if authored_state not in AUTHORED_STATES:
        raise TruthfulnessError(
            f"phase authored status {authored_state!r} is invalid; verified and closed are computed"
        )
    closeout = phase_log.get("closeout_requirements")
    closeout = closeout if isinstance(closeout, dict) else {}
    raw_claims = closeout.get("claims")
    raw_claims = raw_claims if isinstance(raw_claims, dict) else {}
    profile_requirements = _profile_closeout_requirements(repo_root, profile_payload)
    missing_claim_declarations = sorted(REQUIRED_DIRECT_CLAIMS - set(raw_claims))
    claims: dict[str, Any] = {}
    direct_verified = not missing_claim_declarations
    workitems = workitem_observation(repo_root, receipts)
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
            verified = next(
                (
                    candidate
                    for candidate in candidates
                    if candidate["result"] == "verified"
                    and (candidate.get("receipt", {}).get("subject", {})).get("binding")
                    == "exact_tree"
                ),
                None,
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
        any(
            candidate["result"] == "verified"
            and (candidate.get("receipt", {}).get("subject", {})).get("binding")
            == "exact_tree"
            for candidate in receipts.get(gate_id, [])
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
        if not any(
            candidate["result"] == "verified"
            and (candidate.get("receipt", {}).get("subject", {})).get("binding")
            == "exact_tree"
            for candidate in receipts.get(gate_id, [])
        )
    )
    workflow_issues = _workflow_gate_issues(
        repo_root, policy, required_gate_ids | release_gate_ids
    )
    attestation = verify_attestation(repo_root, evidence_dir, policy, current)
    signature_required = selected_profile == "regulated"
    provenance_ok = not signature_required or bool(attestation["valid_attestations"])
    lifecycle_consistent = (authored_state == "completed") == (ledger_state == "completed")
    if authored_state == "completed" and ledger_state == "completed" and direct_verified:
        effective_state = "verified"
        if reconciliation_verified and findings["open_count"] == 0 and not findings["issues"] and provenance_ok:
            effective_state = "closed"
    else:
        effective_state = authored_state
    attestation_names = {path.name for path in evidence_dir.rglob("*.attestation.json")}
    actual_bundle_digest = bundle_digest(
        evidence_dir, exclude_names=attestation_names | {"truth-report.json"}
    )
    digest_issue = bool(trusted_digest and trusted_digest != actual_bundle_digest)
    truth_issues = (
        list(workflow_issues)
        + list(findings["issues"])
        + list(attestation["issues"])
        + hotfix_issues
    )
    if evaluation_mode == "pr":
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
    truth_issues.extend(
        f"required_claim_{claim_id}_not_declared"
        for claim_id in missing_claim_declarations
    )
    if not lifecycle_consistent:
        truth_issues.append("ledger_log_lifecycle_mismatch")
    if ledger_state in {"blocked", "paused", "abandoned"}:
        truth_issues.append(f"ledger_state_{ledger_state}_cannot_verify")
    all_receipts = [candidate for values in receipts.values() for candidate in values]
    for candidate in all_receipts:
        if candidate["result"] != "verified":
            truth_issues.append(
                f"evidence_receipt_invalid:{candidate.get('gate_id')}:{candidate.get('evidence_id')}"
            )
        if "unsupported_schema_version" in candidate.get("issues", []):
            truth_issues.append(
                f"{candidate.get('gate_id')}:unsupported_schema_version"
            )
    truth_issues.extend(f"release_gate_{gate_id}_missing_or_invalid" for gate_id in missing_release_gates)
    if digest_issue:
        truth_issues.append("trusted_bundle_digest_mismatch")
    if signature_required and not provenance_ok:
        truth_issues.append("regulated_attestation_required")
    if authored_state == "completed" and effective_state != "closed":
        truth_issues.append(f"completed_phase_effective_state_{effective_state}")
    elif authored_state != "completed" and evaluation_mode == "closure":
        truth_issues.append("phase_not_completed")
    release_state = (
        "closed"
        if effective_state == "closed"
        and all(hotfix["effective_state"] == "closed" for hotfix in hotfixes)
        and not missing_release_gates
        and not truth_issues
        else "completed"
    )
    return {
        "schema_version": "2.0",
        "evaluation_mode": evaluation_mode,
        "merge_eligibility": (
            "eligible"
            if evaluation_mode == "pr" and not truth_issues
            else "not_evaluated"
            if evaluation_mode == "closure"
            else "ineligible"
        ),
        "phase_id": phase_id,
        "status": "pass" if not truth_issues else "fail",
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
        "issues": sorted(set(truth_issues)),
    }


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description="Derive governance truth from evidence.")
    parser.add_argument("--repo-root", type=Path, default=Path.cwd())
    parser.add_argument("--evidence-dir", type=Path, required=True)
    parser.add_argument(
        "--evaluation-mode", choices=("closure", "pr"), default="closure"
    )
    parser.add_argument("--trusted-digest")
    parser.add_argument("--ci-authority", type=Path)
    parser.add_argument("--ci-certification", type=Path)
    parser.add_argument("--ci-session-manifest", type=Path)
    parser.add_argument("--release-receipt-output", type=Path)
    parser.add_argument("--release-artifact", type=Path, action="append", default=[])
    parser.add_argument("--durable-ref")
    parser.add_argument("--output", type=Path)
    parser.add_argument("--format", choices=("text", "json"), default="text")
    parser.add_argument("--compact", action="store_true")
    args = parser.parse_args(argv)
    try:
        report = derive_truth(
            args.repo_root,
            args.evidence_dir,
            evaluation_mode=args.evaluation_mode,
            trusted_digest=args.trusted_digest,
            ci_authority_path=args.ci_authority,
            ci_certification_path=args.ci_certification,
            ci_session_manifest_path=args.ci_session_manifest,
        )
    except TruthfulnessError as exc:
        print(str(exc), file=os.sys.stderr)
        raise SystemExit(1)
    if args.durable_ref:
        report["durable_ref"] = args.durable_ref
    rendered = json.dumps(
        report,
        indent=None if args.compact else 2,
        separators=(",", ":") if args.compact else None,
        sort_keys=True,
    )
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(rendered + "\n", encoding="utf-8")
    if args.release_receipt_output and args.evaluation_mode != "closure":
        print("release receipts require closure truth evaluation", file=os.sys.stderr)
        raise SystemExit(1)
    if args.release_receipt_output and report["status"] == "pass":
        if not all(
            (
                args.output,
                args.ci_certification,
                args.ci_session_manifest,
                args.release_artifact,
            )
        ):
            print(
                "release receipt requires truth output, CI certification, session manifest, and release artifacts",
                file=os.sys.stderr,
            )
            raise SystemExit(1)
        try:
            certification = json.loads(
                args.ci_certification.read_text(encoding="utf-8")
            )
            receipt = build_release_receipt(
                args.repo_root.resolve(),
                truth_report=report,
                truth_report_path=args.output,
                certification=certification,
                certification_path=args.ci_certification,
                certification_verification=report["ci_certification"],
                session_manifest_path=args.ci_session_manifest,
                evidence_dir=args.evidence_dir,
                release_artifacts=args.release_artifact,
                output_path=args.release_receipt_output,
            )
            emit_release_receipt(args.release_receipt_output, receipt)
        except (OSError, json.JSONDecodeError, ReleaseReceiptError) as exc:
            print(str(exc), file=os.sys.stderr)
            raise SystemExit(1)
    if args.format == "json":
        print(rendered)
    else:
        print(f"governance-truth-{report['status']} state={report['effective_state']}")
        for issue in report["issues"]:
            print(f"- {issue}")
    if report["status"] != "pass":
        raise SystemExit(1)


if __name__ == "__main__":
    main()

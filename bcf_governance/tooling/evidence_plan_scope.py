"""Bind evaluation intent and target scope to canonical evidence planning."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Mapping

import yaml  # type: ignore[import-untyped]

from .evidence_execution import EvidenceError
from .evidence_planning import (
    claims_for_legacy_gate,
    load_claim_model,
    plan_verification,
    receipt_producing_legacy_gates,
    required_claims,
)
from .evidence_scheduling import assign_duration_aware_shards
from .evidence_session_schema import active_planned_session_version
from .evidence_workitem_lifecycle import bounded_target_acceptance_evidence


def _scoped_gates(
    repo_root: Path, evaluation_mode: str, evaluation_target: str | None,
) -> list[str] | None:
    if evaluation_mode == "workitem":
        if not evaluation_target:
            raise EvidenceError("bounded verification requires exact target evidence scope")
        return bounded_target_acceptance_evidence(repo_root, evaluation_target)
    if evaluation_target is not None:
        raise EvidenceError("only bounded verification may name an evaluation target")
    return None


def evaluation_evidence_scope(
    repo_root: Path, evaluation_mode: str, evaluation_target: str | None,
) -> tuple[list[str] | None, list[str]]:
    """Derive the exact governed gate and claim closure for one evaluation."""

    scoped_gates = _scoped_gates(repo_root, evaluation_mode, evaluation_target)
    profile = yaml.safe_load(
        (repo_root / "governance-profile.yml").read_text(encoding="utf-8")
    )
    if isinstance(profile, dict) and profile.get("profile_contract_version") == "3.0":
        if scoped_gates is None:
            return None, required_claims(repo_root)
        model = load_claim_model(repo_root)
        producing = receipt_producing_legacy_gates(model)
        non_receipt = sorted(set(scoped_gates) - producing)
        if non_receipt:
            raise EvidenceError(
                "bounded verification gates are not receipt-producing: "
                + ", ".join(non_receipt)
            )
        mapped = {gate: claims_for_legacy_gate(repo_root, gate) for gate in scoped_gates}
        missing = sorted(gate for gate, claims in mapped.items() if not claims)
        if missing:
            raise EvidenceError(
                "bounded verification gates lack canonical claims: " + ", ".join(missing)
            )
        claims = sorted({claim for values in mapped.values() for claim in values})
        outside_profile = sorted(set(claims) - set(required_claims(repo_root)))
        if outside_profile:
            raise EvidenceError(
                "bounded verification claims are outside the active profile: "
                + ", ".join(outside_profile)
            )
        return scoped_gates, claims
    return scoped_gates, []


def verification_scope_issues(
    repo_root: Path, plan: Mapping[str, Any], *, evaluation_mode: str,
    evaluation_target: str | None,
) -> list[str]:
    """Independently reject a plan that broadens or truncates its proposition."""

    try:
        scoped_gates, expected_claims = evaluation_evidence_scope(
            repo_root, evaluation_mode, evaluation_target
        )
    except (EvidenceError, OSError, ValueError) as exc:
        return [f"verification_scope_unresolvable:{exc}"]
    required = plan.get("required_claims")
    if not isinstance(required, list) or required != sorted(set(required)):
        return ["verification_scope_required_claims_invalid"]
    if expected_claims and required != expected_claims:
        return ["verification_scope_required_claims_mismatch"]
    if not expected_claims and scoped_gates is not None and required != scoped_gates:
        return ["verification_scope_required_claims_mismatch"]
    if expected_claims:
        model = load_claim_model(repo_root)
        groups = model["execution_groups"]
        target_groups = {
            str(model["claims"][claim_id]["execution_group"])
            for claim_id in expected_claims
        }
        allowed_groups = set(target_groups)
        pending = sorted(target_groups)
        while pending:
            group_id = pending.pop(0)
            for dependency in groups[group_id].get("depends_on", []):
                if dependency not in allowed_groups:
                    allowed_groups.add(dependency)
                    pending.append(dependency)
                    pending.sort()
        dag = plan.get("execution_dag")
        nodes = dag.get("nodes") if isinstance(dag, dict) else None
        edges = dag.get("edges") if isinstance(dag, dict) else None
        if not isinstance(nodes, list) or not isinstance(edges, list):
            return ["verification_scope_execution_dag_invalid"]
        by_id = {
            str(node.get("id")): node for node in nodes
            if isinstance(node, dict) and isinstance(node.get("id"), str)
        }
        if len(by_id) != len(nodes) or not set(by_id).issubset(allowed_groups):
            return ["verification_scope_execution_dag_invalid"]
        for group_id, node in by_id.items():
            claims = node.get("claims")
            expected_dependencies = list(groups[group_id].get("depends_on", []))
            if (
                node.get("producer") != groups[group_id].get("producer")
                or not isinstance(claims, list)
                or not claims
                or claims != sorted(set(claims))
                or not set(claims).issubset(set(groups[group_id]["claims"]))
                or node.get("depends_on") != expected_dependencies
                or not set(expected_dependencies).issubset(by_id)
            ):
                return ["verification_scope_execution_dag_invalid"]
            if group_id not in target_groups and claims != sorted(groups[group_id]["claims"]):
                return ["verification_scope_dependency_claims_incomplete"]
        expected_edges = sorted(
            (dependency, group_id)
            for group_id, node in by_id.items()
            for dependency in node.get("depends_on", [])
        )
        actual_edges = sorted(
            (edge.get("from"), edge.get("to"))
            for edge in edges if isinstance(edge, dict)
        )
        if len(actual_edges) != len(edges) or actual_edges != expected_edges:
            return ["verification_scope_execution_edges_invalid"]
        preflight = plan.get("preflight_satisfied_claims", [])
        reused = plan.get("reused_evidence", [])
        if not isinstance(preflight, list) or not isinstance(reused, list):
            return ["verification_scope_resolution_invalid"]
        reused_claims = [
            row.get("claim_id") for row in reused if isinstance(row, dict)
        ]
        if len(reused_claims) != len(reused) or len(reused_claims) != len(set(reused_claims)):
            return ["verification_scope_resolution_invalid"]
        resolved = set(preflight) | set(reused_claims)
        executed = {
            claim_id for node in nodes for claim_id in node.get("claims", [])
            if claim_id in expected_claims
        }
        if resolved - set(expected_claims) or executed != set(expected_claims) - resolved:
            return ["verification_scope_resolution_incomplete"]
    return []


def truth_scope_projection(
    repo_root: Path, plan: Mapping[str, Any], *, evaluation_mode: str,
    evaluation_target: str | None, enabled: bool = True,
) -> tuple[set[str] | None, list[str]]:
    """Project truth's exact gate scope and independent session diagnostics."""

    if not enabled:
        return None, []
    issues = verification_scope_issues(
        repo_root, plan, evaluation_mode=evaluation_mode,
        evaluation_target=evaluation_target,
    )
    if evaluation_mode != "workitem":
        return None, issues
    try:
        gates, _ = evaluation_evidence_scope(
            repo_root, evaluation_mode, evaluation_target
        )
    except (EvidenceError, OSError, ValueError) as exc:
        issues.append(f"verification_scope_unresolvable:{exc}")
        gates = []
    return set(gates or []), issues


def scoped_verification_plan(
    repo_root: Path,
    subject: Mapping[str, Any],
    prior_receipts: list[Mapping[str, Any]],
    *,
    evaluation_mode: str,
    evaluation_target: str | None,
) -> dict[str, Any]:
    """Select profile planning while preserving the exact evaluation proposition."""

    scoped_gates, scoped_claims = evaluation_evidence_scope(
        repo_root, evaluation_mode, evaluation_target
    )
    profile = yaml.safe_load(
        (repo_root / "governance-profile.yml").read_text(encoding="utf-8")
    )
    if isinstance(profile, dict) and profile.get("profile_contract_version") == "3.0":
        model = load_claim_model(repo_root)
        preflight_claims = sorted(
            claim_id for claim_id, claim in model["claims"].items()
            if isinstance(claim, dict)
            and model["execution_groups"][claim["execution_group"]].get(
                "captured_by_preflight"
            ) is True
        )
        result = plan_verification(
            repo_root, prior_receipts,
            preflight_claims=preflight_claims,
            affected_proof=active_planned_session_version(repo_root) == "3.0",
            required_claim_ids=scoped_claims if scoped_gates is not None else None,
        )
    else:
        release = profile.get("release_gate_profile") if isinstance(profile, dict) else None
        raw_gates = release.get("gates") if isinstance(release, dict) else None
        values = raw_gates.values() if isinstance(raw_gates, dict) else ()
        gates = sorted(
            str(value["target"]) for value in values
            if isinstance(value, dict) and value.get("status") == "required"
            and isinstance(value.get("target"), str)
        )
        missing = [] if scoped_gates is None else sorted(set(scoped_gates) - set(gates))
        if missing:
            raise EvidenceError(
                "bounded verification gates are outside the active profile: "
                + ", ".join(missing)
            )
        gates = gates if scoped_gates is None else scoped_gates
        nodes = assign_duration_aware_shards([
            {"id": gate, "producer": gate, "claims": [gate], "depends_on": [],
             "reason": "legacy profile requires exact-subject execution"}
            for gate in gates
        ], {})
        result = {
            "current_subject": {"commit_sha": subject.get("commit_sha"),
                                "tree_sha": subject.get("tree_sha")},
            "prior_subject": None, "changed_paths": [], "changed_domains": [],
            "required_claims": gates, "preflight_satisfied_claims": [],
            "reused_evidence": [],
            "invalidated_evidence": [
                {"claim_id": gate, "evidence_ids": [],
                 "reasons": ["legacy_evidence_exact_subject_only"]} for gate in gates
            ],
            "execution_dag": {"nodes": nodes, "edges": []},
            "decision_explanations": [
                f"executed because legacy claim {gate} is exact-subject only" for gate in gates
            ],
        }
    result["evaluation_scope"] = {
        "mode": evaluation_mode, "target": evaluation_target,
        "required_gates": scoped_gates,
    }
    issues = verification_scope_issues(
        repo_root, result, evaluation_mode=evaluation_mode,
        evaluation_target=evaluation_target,
    )
    if issues:
        raise EvidenceError("; ".join(issues))
    return result

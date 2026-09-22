"""Verification-plan projection, closeout mapping, and compact truth reporting."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import re
import subprocess
from typing import Any

import yaml  # type: ignore[import-untyped]

from .evidence_claim_resolution import eligible_claim_receipts, eligible_receipts, verified_candidate


REQUIRED_DIRECT_CLAIMS = {
    "workitems_closed", "required_suites_green", "architecture_gates_green",
    "health_checks_green", "security_review_complete", "findings_resolved",
}


def current_subject(repo_root: Path) -> dict[str, Any]:
    def git(*args: str) -> str:
        result = subprocess.run(["git", *args], cwd=repo_root, capture_output=True, text=True)
        if result.returncode:
            raise ValueError(result.stderr.strip() or "Git subject resolution failed")
        return result.stdout.strip()
    status = git("status", "--porcelain=v1", "--untracked-files=all", "--ignored=no")
    return {"commit_sha": git("rev-parse", "HEAD"), "tree_sha": git("rev-parse", "HEAD^{tree}"),
            "tracked_clean": not bool(status), "untracked_clean": not bool(status)}


def active_log_path(repo_root: Path) -> Path:
    ledger = yaml.safe_load((repo_root / "plans/phase-ledger.yml").read_text(encoding="utf-8"))
    active = ledger.get("active_phase") if isinstance(ledger, dict) else None
    if not isinstance(active, dict) or not isinstance(active.get("log"), str):
        raise ValueError("plans/phase-ledger.yml active_phase.log is required")
    return repo_root / active["log"]


def current_session_plan(evidence_dir: Path, current: dict[str, Any]) -> dict[str, Any]:
    matches: list[dict[str, Any]] = []
    for path in evidence_dir.rglob("evidence-session.json"):
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError):
            continue
        if (
            isinstance(payload, dict)
            and payload.get("schema_version") == "2.0"
            and payload.get("subject")
            == {"commit_sha": current["commit_sha"], "tree_sha": current["tree_sha"]}
        ):
            matches.append(payload)
    identities = {(value.get("session_id"), json.dumps(value, sort_keys=True)) for value in matches}
    if len(identities) > 1:
        raise ValueError("current evidence contains ambiguous verification plans")
    return matches[0] if matches else {}


def exact_session_binding(
    evidence_dir: Path, current: dict[str, Any], session_plan: dict[str, Any]
) -> dict[str, str]:
    """Bind truth to the raw manifest bytes actually found at fan-in."""
    if not session_plan or not isinstance(session_plan.get("session_id"), str):
        raise ValueError("reused claims lack an exact evidence session")
    expected_subject = {
        "commit_sha": current["commit_sha"], "tree_sha": current["tree_sha"],
    }
    digests: set[str] = set()
    for path in evidence_dir.rglob("evidence-session.json"):
        try:
            encoded = path.read_bytes()
            payload = json.loads(encoded)
        except (OSError, UnicodeDecodeError, json.JSONDecodeError):
            continue
        if payload == session_plan and payload.get("subject") == expected_subject:
            digests.add(hashlib.sha256(encoded).hexdigest())
    if len(digests) != 1:
        raise ValueError("reused claims have ambiguous evidence-session bytes")
    return {
        "session_id": session_plan["session_id"],
        "manifest_sha256": next(iter(digests)),
    }


def profile_closeout_requirements(repo_root: Path, profile_payload: dict[str, Any]) -> dict[str, Any]:
    registry = yaml.safe_load(
        (repo_root / "governance/gate-contracts.yml").read_text(encoding="utf-8")
    )
    contract_gates = registry.get("gates") if isinstance(registry, dict) else None
    if not isinstance(contract_gates, dict):
        raise ValueError("governance/gate-contracts.yml gates must be a mapping")
    configured = profile_payload.get("release_gate_profile", {}).get("gates", {})
    configured = configured if isinstance(configured, dict) else {}
    policies = {
        str(value.get("target")): str(value.get("command_policy", ""))
        for value in configured.values() if isinstance(value, dict)
    }
    claims: dict[str, list[str]] = {claim: [] for claim in REQUIRED_DIRECT_CLAIMS}
    for target in sorted(str(value) for value in contract_gates):
        command_policy = policies.get(target, "")
        if target == "governance-validate":
            claims["workitems_closed"].append(target)
        if command_policy.startswith("architecture_"):
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
    if not claims["security_review_complete"] and "governance-validate" in contract_gates:
        claims["security_review_complete"].append("governance-validate")
    if not claims["findings_resolved"] and "governance-validate" in contract_gates:
        claims["findings_resolved"].append("governance-validate")
    return {"claims": claims, "reconciliation": sorted(
        {"governance-validate", "governance-exposure-scan"}.intersection(contract_gates)
    )}


def _digest(value: object) -> str:
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()


def failure_envelope(
    evidence_dir: Path,
    current: dict[str, Any],
    session_plan: dict[str, Any],
    issues: list[str],
    raw_results: list[dict[str, Any]] | None = None,
    resolved_claims: set[str] | None = None,
) -> dict[str, Any]:
    roots: dict[str, dict[str, Any]] = {}
    for issue in sorted(set(issues)):
        fields = issue.split(":")
        root_id = (
            ":".join(fields[:3])
            if fields[0] == "evidence_receipt_invalid" and len(fields) >= 3
            else fields[0]
        )
        root = roots.setdefault(root_id, {"root_cause_id": root_id, "affected_claims": [],
                                         "diagnostics": [], "raw_result_refs": []})
        root["diagnostics"].append(issue)
        match = re.search(r"(?:claim_|release_gate_)([^:]+?)(?:_not|_missing|$)", issue)
        if match:
            root["affected_claims"].append(match.group(1))
    for result in raw_results or []:
        if result.get("result") == "verified":
            continue
        gate_id = str(result.get("gate_id") or "")
        evidence_id = str(result.get("evidence_id") or "")
        matching_roots = [
            root for root_id, root in roots.items()
            if (
                root_id == f"evidence_receipt_invalid:{gate_id}:{evidence_id}"
                if root_id.startswith("evidence_receipt_invalid:")
                else any(gate_id and gate_id in diagnostic for diagnostic in root["diagnostics"])
                or any(evidence_id and evidence_id in diagnostic for diagnostic in root["diagnostics"])
            )
        ]
        reference = {
            "evidence_id": evidence_id,
            "gate_id": gate_id,
            "artifact_sha256": result.get("artifact_sha256"),
            "issues": sorted(set(result.get("issues", []))),
        }
        for root in matching_roots:
            root["raw_result_refs"].append(reference)
    for root in roots.values():
        root["affected_claims"] = sorted(set(root["affected_claims"]))
        root["raw_result_refs"] = sorted(
            root["raw_result_refs"],
            key=lambda value: (value["gate_id"], value["evidence_id"]),
        )
    plan_identity = _digest({key: session_plan.get(key) for key in (
        "session_id", "required_claims", "reused_evidence",
        "invalidated_evidence", "execution_dag"
    )})
    causal = _digest({"subject": current, "plan_identity": plan_identity, "roots": roots})
    prior_fingerprint = None
    prior_path = evidence_dir / "prior-truth-report.json"
    if prior_path.is_file():
        try:
            prior_fingerprint = json.loads(prior_path.read_text(encoding="utf-8")).get(
                "failure_envelope", {}
            ).get("causal_result_fingerprint")
        except (OSError, UnicodeDecodeError, json.JSONDecodeError, AttributeError):
            pass
    resolved = resolved_claims or set()
    raw_dag = session_plan.get("execution_dag", {"nodes": [], "edges": []})
    raw_dag = raw_dag if isinstance(raw_dag, dict) else {"nodes": [], "edges": []}
    nodes = []
    for raw in raw_dag.get("nodes", []):
        if not isinstance(raw, dict):
            continue
        claims = [
            str(value)
            for value in raw.get("claims", [])
            if isinstance(value, str) and value not in resolved
        ]
        if claims:
            nodes.append({**raw, "claims": claims})
    node_ids = {str(node.get("id")) for node in nodes}
    for node in nodes:
        if isinstance(node.get("depends_on"), list):
            node["depends_on"] = [
                value for value in node["depends_on"] if str(value) in node_ids
            ]
    edges = [
        edge
        for edge in raw_dag.get("edges", [])
        if not isinstance(edge, dict)
        or all(
            str(edge[key]) in node_ids
            for key in ("from", "to")
            if key in edge
        )
    ]
    remaining_invalidated = [
        value
        for value in session_plan.get("invalidated_evidence", [])
        if not isinstance(value, dict) or value.get("claim_id") not in resolved
    ]
    return {"current_subject": current, "plan_identity": plan_identity,
            "prior_subject": session_plan.get("prior_subject"),
            "reused_evidence": session_plan.get("reused_evidence", []),
            "invalidated_evidence": remaining_invalidated,
            "root_causes": sorted(roots.values(), key=lambda value: value["root_cause_id"]),
            "raw_failures": sorted(issues),
            "required_next_action": {"nodes": nodes, "edges": edges},
            "causal_result_fingerprint": causal,
            "no_new_information": prior_fingerprint == causal}

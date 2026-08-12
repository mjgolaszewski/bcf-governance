"""Derive verified and closed governance lifecycle state from evidence."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import yaml  # type: ignore[import-untyped]
from jsonschema import Draft202012Validator

try:
    from scripts.governance_evidence import RECEIPT_SUFFIX, bundle_digest, expected_evidence_kinds, recompute_test_artifact_observations
except ImportError:  # pragma: no cover - copied script execution
    from governance_evidence import RECEIPT_SUFFIX, bundle_digest, expected_evidence_kinds, recompute_test_artifact_observations  # type: ignore[no-redef]

try:
    from governance_truth_support import artifact_issues, compute_hotfix_reports, finding_report, verify_attestation, workitem_observation
except ImportError:  # pragma: no cover - package import
    from scripts.governance_truth_support import artifact_issues, compute_hotfix_reports, finding_report, verify_attestation, workitem_observation


class TruthfulnessError(ValueError):
    """Raised when a truth report cannot be evaluated."""


AUTHORED_STATES = {"planned", "completed"}
REQUIRED_DIRECT_CLAIMS = {
    "workitems_closed", "required_suites_green", "architecture_gates_green",
    "health_checks_green", "security_review_complete", "findings_resolved",
}
SECURITY_TOKENS = {
    "auth",
    "oauth",
    "oidc",
    "saml",
    "federation",
    "crypto",
    "token",
    "session",
    "tenant",
    "secret",
    "custody",
    "middleware",
    "migration",
    "workflow",
    "security", "rbac", "permission", "credential", "mfa", "passkey",
    "webauthn", "jwt", "jwks", "signing", "encryption", "certificate",
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


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _active_log_path(repo_root: Path) -> Path:
    ledger = _load_yaml(repo_root / "plans/phase-ledger.yml")
    active = ledger.get("active_phase")
    if not isinstance(active, dict) or not isinstance(active.get("log"), str):
        raise TruthfulnessError("plans/phase-ledger.yml active_phase.log is required")
    return repo_root / str(active["log"])


def _current_subject(repo_root: Path) -> dict[str, Any]:
    return {
        "commit_sha": _git(repo_root, "rev-parse", "HEAD"),
        "tree_sha": _git(repo_root, "rev-parse", "HEAD^{tree}"),
        "tracked_clean": not bool(
            _git(repo_root, "status", "--porcelain", "--untracked-files=no")
        ),
    }


def _changed_paths(repo_root: Path, commit_sha: object) -> list[str]:
    if not isinstance(commit_sha, str) or not commit_sha:
        return []
    comparisons = (
        ("diff", "--name-only", commit_sha, "HEAD"),
        ("diff", "--name-only"),
        ("diff", "--cached", "--name-only"),
    )
    paths: set[str] = set()
    for args in comparisons:
        result = _git(repo_root, *args, check=False)
        paths.update(line for line in result.splitlines() if line)
    return sorted(paths)


def _change_categories(paths: list[str]) -> list[str]:
    categories: set[str] = set()
    for path in paths:
        lowered = path.lower()
        if lowered.startswith((".github/workflows/", ".gitlab-ci", "ci/")):
            categories.add("workflow")
        if lowered.startswith(("tests/", "test/", "backend/tests/", "browser_tests/")):
            categories.add("test")
        if lowered.startswith(("docs/", "readme")):
            categories.add("docs")
        if lowered.startswith("audits/"):
            categories.add("audit")
        if lowered.startswith(("governance/", "plans/", "phases/")) or lowered.endswith(
            ("agents.yml", "memory.yml", "governance-profile.yml")
        ):
            categories.add("governance")
        if any(token in lowered for token in SECURITY_TOKENS):
            categories.add("security_impact")
        suffix = Path(lowered).suffix
        if suffix in {".py", ".js", ".ts", ".go", ".rs", ".java", ".cs", ".rb"}:
            categories.add("source")
        if suffix in {".yml", ".yaml", ".toml", ".ini", ".env", ".json"}:
            categories.add("config")
    return sorted(categories)


def _subject_issues(
    repo_root: Path,
    receipt: dict[str, Any],
    current: dict[str, Any],
    tree_independent_allowlist: set[str],
) -> tuple[list[str], dict[str, Any]]:
    issues: list[str] = []
    subject = receipt.get("subject")
    if not isinstance(subject, dict):
        return ["subject_missing"], {"paths": [], "categories": []}
    binding = subject.get("binding")
    kind = receipt.get("kind")
    forbidden_independent = kind in {
        "test_suite",
        "runtime_health",
        "security_review",
        "finding_verification",
        "phase_closeout",
        "release",
    }
    if binding == "tree_independent" and forbidden_independent:
        issues.append("tree_independent_forbidden_for_kind")
    elif binding == "tree_independent" and receipt.get("gate_id") not in tree_independent_allowlist:
        issues.append("tree_independent_not_allowlisted")
    elif binding == "exact_tree":
        if subject.get("commit_sha") != current["commit_sha"]:
            issues.append("commit_sha_not_current_head")
        if subject.get("tree_sha") != current["tree_sha"]:
            issues.append("tree_sha_not_current_tree")
        if subject.get("tracked_clean") is not True or current["tracked_clean"] is not True:
            issues.append("tracked_tree_not_clean")
    elif binding != "tree_independent":
        issues.append("subject_binding_invalid")
    paths = _changed_paths(repo_root, subject.get("commit_sha"))
    return issues, {"paths": paths, "categories": _change_categories(paths)}


def _probe_issues(receipt: dict[str, Any], *, required: bool) -> list[str]:
    probes = receipt.get("behavioral_probes")
    if not isinstance(probes, list):
        return ["behavioral_probes_missing"] if required else []
    if required and not probes:
        return ["negative_behavioral_control_required"]
    issues: list[str] = []
    for raw in probes:
        if not isinstance(raw, dict):
            issues.append("behavioral_probe_invalid")
            continue
        if raw.get("mutation_applied") is not True:
            issues.append(f"behavioral_probe_{raw.get('id', 'unknown')}_mutation_not_applied")
        exit_code = raw.get("observed_exit_code")
        if not isinstance(exit_code, int) or exit_code == 0:
            issues.append(f"behavioral_probe_{raw.get('id', 'unknown')}_did_not_fail")
    return issues


def _test_issues(receipt_path: Path, receipt: dict[str, Any]) -> list[str]:
    if receipt.get("kind") != "test_suite":
        return []
    observations = receipt.get("observations")
    if not isinstance(observations, dict):
        return ["test_observations_missing"]
    counts = observations.get("test_counts")
    thresholds = observations.get("test_thresholds")
    if not isinstance(counts, dict) or not isinstance(thresholds, dict):
        return ["test_counts_or_thresholds_missing"]
    issues: list[str] = []
    count_keys = (
        "collected", "executed", "passed", "failed", "errors", "skipped", "xfailed", "xpassed"
    )
    for key in count_keys:
        if not isinstance(counts.get(key), int) or int(counts[key]) < 0:
            issues.append(f"test_{key}_invalid")
    if issues:
        return issues
    raw_counts, raw_nodes = recompute_test_artifact_observations(receipt_path, receipt)
    if any(counts[key] != raw_counts[key] for key in count_keys):
        issues.append("test_normalized_counts_do_not_match_raw_report")
    actual_nodes = observations.get("test_node_ids", [])
    if raw_nodes is not None and (
        not isinstance(actual_nodes, list) or sorted(actual_nodes) != raw_nodes
    ):
        issues.append("test_normalized_nodes_do_not_match_raw_report")
    if counts["collected"] < int(thresholds.get("min_collected", 1)):
        issues.append("test_min_collected_not_met")
    if counts["executed"] < int(thresholds.get("min_executed", 1)):
        issues.append("test_min_executed_not_met")
    if counts["skipped"] > int(thresholds.get("max_skipped", 0)):
        issues.append("test_max_skipped_exceeded")
    if counts["failed"] or counts["errors"]:
        issues.append("test_failures_present")
    expected = observations.get("expected_test_node_ids", [])
    actual = observations.get("test_node_ids", [])
    if isinstance(expected, list) and expected:
        if not isinstance(actual, list):
            issues.append("test_node_ids_missing")
        elif observations.get("expected_nodes_mode") == "exact" and set(actual) != set(expected):
            issues.append("test_node_manifest_not_exact")
        elif not set(expected).issubset(set(actual)):
            issues.append("expected_test_nodes_missing")
    return issues


def _environment_issues(receipt: dict[str, Any]) -> list[str]:
    observations = receipt.get("observations")
    if not isinstance(observations, dict):
        return ["observations_missing"]
    assertions = observations.get("environment_assertions", [])
    if not isinstance(assertions, list):
        return ["environment_assertions_invalid"]
    return [
        f"environment_assertion_{raw.get('name', 'unknown')}_failed"
        for raw in assertions
        if not isinstance(raw, dict) or raw.get("satisfied") is not True
    ]


def _output_requirement_issues(receipt: dict[str, Any]) -> list[str]:
    observations = receipt.get("observations")
    if not isinstance(observations, dict):
        return ["observations_missing"]
    requirements = observations.get("output_requirements", [])
    if not isinstance(requirements, list):
        return ["output_requirements_invalid"]
    return [
        f"output_requirement_{raw.get('path', 'unknown')}_failed"
        for raw in requirements
        if not isinstance(raw, dict) or raw.get("satisfied") is not True
    ]


def _freshness_issues(receipt: dict[str, Any]) -> list[str]:
    limit = receipt.get("freshness_limit_seconds")
    if limit is None:
        return []
    timestamp = receipt.get("timestamp")
    if not isinstance(limit, int) or limit < 1 or not isinstance(timestamp, str):
        return ["freshness_contract_invalid"]
    try:
        captured = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
    except ValueError:
        return ["timestamp_invalid"]
    if captured.tzinfo is None:
        return ["timestamp_timezone_missing"]
    return ["evidence_freshness_expired"] if (datetime.now(UTC) - captured).total_seconds() > limit else []


def _receipt_result(
    repo_root: Path,
    receipt_path: Path,
    receipt: dict[str, Any],
    current: dict[str, Any],
    *,
    require_negative_control: bool,
    tree_independent_allowlist: set[str],
    receipt_schema: dict[str, Any],
    expected_kinds: dict[str, str],
) -> dict[str, Any]:
    required_fields = {
        "schema_version",
        "kind",
        "evidence_id",
        "gate_id",
        "producer",
        "invocation",
        "subject",
        "artifacts",
        "observations",
        "behavioral_probes",
        "result",
        "timestamp",
    }
    issues = [f"missing_{field}" for field in sorted(required_fields - set(receipt))]
    schema_errors = sorted(
        Draft202012Validator(receipt_schema).iter_errors(receipt),
        key=lambda error: ([str(token) for token in error.absolute_path], error.message),
    )
    issues.extend(f"receipt_schema:{error.message}" for error in schema_errors)
    expected_kind = expected_kinds.get(str(receipt.get("gate_id", "")))
    if expected_kind is not None and receipt.get("kind") != expected_kind:
        issues.append(f"evidence_kind_must_be_{expected_kind}")
    observations = receipt.get("observations")
    if not isinstance(observations, dict) or observations.get("exit_code") != 0:
        issues.append("observed_exit_code_not_zero")
    issues.extend(artifact_issues(receipt_path, receipt))
    subject_issues, invalidation = _subject_issues(
        repo_root, receipt, current, tree_independent_allowlist
    )
    issues.extend(subject_issues)
    issues.extend(_probe_issues(receipt, required=require_negative_control))
    issues.extend(_test_issues(receipt_path, receipt))
    issues.extend(_environment_issues(receipt))
    issues.extend(_output_requirement_issues(receipt))
    issues.extend(_freshness_issues(receipt))
    return {
        "evidence_id": receipt.get("evidence_id"),
        "gate_id": receipt.get("gate_id"),
        "kind": receipt.get("kind"),
        "producer": receipt.get("producer"),
        "commit_sha": (receipt.get("subject") or {}).get("commit_sha")
        if isinstance(receipt.get("subject"), dict)
        else None,
        "tree_sha": (receipt.get("subject") or {}).get("tree_sha")
        if isinstance(receipt.get("subject"), dict)
        else None,
        "artifact_sha256": _sha256(receipt_path),
        "result": "verified" if not issues else "invalid",
        "timestamp": receipt.get("timestamp"),
        "issues": sorted(set(issues)),
        "invalidation": invalidation,
        "receipt_path": receipt_path.as_posix(),
        "receipt": receipt,
    }


def _load_receipts(
    repo_root: Path,
    evidence_dir: Path,
    current: dict[str, Any],
    *,
    require_negative_control: bool,
    tree_independent_allowlist: set[str],
    expected_kinds: dict[str, str],
) -> dict[str, list[dict[str, Any]]]:
    by_gate: dict[str, list[dict[str, Any]]] = {}
    receipt_schema = _load_yaml(repo_root / "schemas/evidence-receipt.schema.json")
    for path in sorted(evidence_dir.rglob(f"*{RECEIPT_SUFFIX}")):
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            raise TruthfulnessError(f"invalid evidence receipt {path}: {exc}") from exc
        if not isinstance(payload, dict):
            raise TruthfulnessError(f"evidence receipt {path} must be an object")
        result = _receipt_result(
            repo_root,
            path,
            payload,
            current,
            require_negative_control=require_negative_control,
            tree_independent_allowlist=tree_independent_allowlist,
            receipt_schema=receipt_schema,
            expected_kinds=expected_kinds,
        )
        gate_id = str(result.get("gate_id") or "")
        by_gate.setdefault(gate_id, []).append(result)
    return by_gate


def _workflow_gate_issues(repo_root: Path, policy: dict[str, Any], gate_ids: set[str]) -> list[str]:
    contract = policy.get("workflow_contract")
    if not isinstance(contract, dict):
        return ["workflow_contract_missing"]
    paths = contract.get("paths")
    required_events = contract.get("required_events", [])
    if not isinstance(paths, list) or not paths:
        return ["workflow_paths_missing"]
    resolved_gates: set[str] = set()
    discovered_events: set[str] = set()
    issues: list[str] = []
    queue = [str(value) for value in paths if isinstance(value, str)]
    roots = set(queue)
    visited: set[str] = set()
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
    repo_root: Path, evidence_dir: Path, *, trusted_digest: str | None = None
) -> dict[str, Any]:
    repo_root = repo_root.resolve()
    evidence_dir = evidence_dir.resolve()
    current = _current_subject(repo_root)
    policy = _load_yaml(repo_root / "governance/evidence-policy.yml")
    profile_payload = _load_yaml(repo_root / "governance-profile.yml")
    profile_block = profile_payload.get("profile")
    profile_block = profile_block if isinstance(profile_block, dict) else {}
    selected_profile = str(profile_block.get("selected", "standard"))
    settings = policy.get("settings")
    settings = settings if isinstance(settings, dict) else {}
    require_negative = bool(settings.get("require_negative_control_for_required_gates", True))
    tree_independent_allowlist = {
        str(value) for value in settings.get("tree_independent_allowlist", [])
    }
    receipts = _load_receipts(
        repo_root,
        evidence_dir,
        current,
        require_negative_control=require_negative,
        tree_independent_allowlist=tree_independent_allowlist,
        expected_kinds=expected_evidence_kinds(repo_root),
    )
    phase_log = _load_yaml(_active_log_path(repo_root))
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
    missing_claim_declarations = sorted(REQUIRED_DIRECT_CLAIMS - set(raw_claims))
    claims: dict[str, Any] = {}
    direct_verified = not missing_claim_declarations
    workitems = workitem_observation(repo_root, receipts)
    required_gate_ids: set[str] = set()
    for claim_id, raw in raw_claims.items():
        requirement = raw if isinstance(raw, dict) else {}
        gate_ids = [str(value) for value in requirement.get("required_evidence", []) if isinstance(value, str)]
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
        verified_claim = bool(gate_ids) and not missing and measurement_ok
        if str(claim_id) != "findings_resolved":
            direct_verified = direct_verified and verified_claim
        claims[str(claim_id)] = {
            "effective_state": "verified" if verified_claim else "completed",
            "required_evidence": gate_ids,
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
    reconciliation_gates = [
        str(value)
        for value in reconciliation.get("required_evidence", [])
        if isinstance(value, str)
    ]
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
        findings_claim["effective_state"] = (
            "verified" if findings_clear and findings_evidence_valid else "completed"
        )
        findings_claim["registry_observation"] = findings
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
    if authored_state == "completed" and direct_verified:
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
    truth_issues.extend(
        f"required_claim_{claim_id}_not_declared"
        for claim_id in missing_claim_declarations
    )
    all_receipts = [candidate for values in receipts.values() for candidate in values]
    for candidate in all_receipts:
        if candidate["result"] != "verified":
            truth_issues.append(
                f"evidence_receipt_invalid:{candidate.get('gate_id')}:{candidate.get('evidence_id')}"
            )
    truth_issues.extend(f"release_gate_{gate_id}_missing_or_invalid" for gate_id in missing_release_gates)
    if digest_issue:
        truth_issues.append("trusted_bundle_digest_mismatch")
    if signature_required and not provenance_ok:
        truth_issues.append("regulated_attestation_required")
    if authored_state == "completed" and effective_state != "closed":
        truth_issues.append(f"completed_phase_effective_state_{effective_state}")
    elif authored_state != "completed":
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
        "schema_version": "1.0",
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
            if claims.get("required_suites_green", {}).get("effective_state") == "verified"
            else "fail",
            "finding_accounting": "pass" if not findings["issues"] else "fail",
            "provenance": "pass" if provenance_ok and not attestation["issues"] else "fail",
        },
        "subject": current,
        "bundle_sha256": actual_bundle_digest,
        "authored_state": authored_state,
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
        },
        "hotfixes": hotfixes,
        "findings": findings,
        "attestation": attestation,
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
    parser.add_argument("--trusted-digest")
    parser.add_argument("--durable-ref")
    parser.add_argument("--output", type=Path)
    parser.add_argument("--format", choices=("text", "json"), default="text")
    parser.add_argument("--compact", action="store_true")
    args = parser.parse_args(argv)
    try:
        report = derive_truth(
            args.repo_root, args.evidence_dir, trusted_digest=args.trusted_digest
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

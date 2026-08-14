"""Independent recomputation and validation of evidence receipts."""

from __future__ import annotations

import hashlib
import json
import re
import subprocess
import xml.etree.ElementTree as ET
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import yaml  # type: ignore[import-untyped]
from jsonschema import Draft202012Validator

from .evidence_test_adapters import recompute_test_artifact_observations
from .governance_truth_support import artifact_issues


RECEIPT_SUFFIX = ".evidence.json"
SECURITY_TOKENS = {
    "auth", "oauth", "oidc", "saml", "federation", "crypto", "token",
    "session", "tenant", "secret", "custody", "middleware", "migration",
    "workflow", "security", "rbac", "permission", "credential", "mfa",
    "passkey", "webauthn", "jwt", "jwks", "signing", "encryption", "certificate",
}


class ReceiptError(ValueError):
    """Raised when a receipt bundle cannot be parsed."""


def _git(repo_root: Path, *args: str, check: bool = True) -> str:
    result = subprocess.run(
        ["git", *args], cwd=repo_root, capture_output=True, text=True
    )
    if check and result.returncode != 0:
        raise ReceiptError(result.stderr.strip() or f"git {' '.join(args)} failed")
    return result.stdout.strip()


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


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
        "test_suite", "runtime_health", "security_review", "finding_verification",
        "phase_closeout", "release",
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
        if subject.get("execution_tree_sha") != subject.get("tree_sha"):
            issues.append("execution_tree_sha_mismatch")
        if (
            subject.get("tracked_clean") is not True
            or subject.get("untracked_clean") is not True
            or current["tracked_clean"] is not True
            or current["untracked_clean"] is not True
        ):
            issues.append("tracked_tree_not_clean")
    elif binding != "tree_independent":
        issues.append("subject_binding_invalid")
    paths = _changed_paths(repo_root, subject.get("commit_sha"))
    return issues, {"paths": paths, "categories": _change_categories(paths)}


def _probe_issues(
    receipt_path: Path, receipt: dict[str, Any], *, required: bool
) -> list[str]:
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
        probe_id = raw.get("id", "unknown")
        exit_code = raw.get("observed_exit_code")
        oracle = raw.get("oracle")
        raw_artifacts = raw.get("raw_artifacts")
        if not isinstance(oracle, dict) or not isinstance(raw_artifacts, dict):
            issues.append(f"behavioral_probe_{probe_id}_oracle_invalid")
            continue
        satisfied = False
        if oracle.get("kind") == "diagnostic":
            stream = oracle.get("stream")
            artifact_name = raw_artifacts.get(stream) if isinstance(stream, str) else None
            path = receipt_path.parent / str(artifact_name)
            value = path.read_text(encoding="utf-8") if path.is_file() else ""
            pattern = oracle.get("regex")
            exit_codes = oracle.get("exit_codes")
            satisfied = (
                isinstance(exit_code, int)
                and isinstance(exit_codes, list)
                and exit_code in exit_codes
                and 1 <= exit_code <= 125
                and isinstance(pattern, str)
                and re.search(pattern, value) is not None
            )
        elif oracle.get("kind") == "test_node_failure":
            junit_name = raw_artifacts.get("junit")
            junit_path = receipt_path.parent / str(junit_name)
            failed: set[str] = set()
            if junit_path.is_file():
                try:
                    for case in ET.parse(junit_path).getroot().iter("testcase"):
                        if case.find("failure") is None and case.find("error") is None:
                            continue
                        classname = case.attrib.get("classname", "")
                        name = case.attrib.get("name", "")
                        failed.add(f"{classname}::{name}" if classname else name)
                except ET.ParseError:
                    failed = set()
            expected = {str(value) for value in oracle.get("node_ids", [])}
            observations = receipt.get("observations")
            baseline_nodes = {
                str(value)
                for value in (
                    observations.get("test_node_ids", [])
                    if isinstance(observations, dict)
                    else []
                )
                if isinstance(value, str)
            }
            satisfied = (
                bool(expected)
                and expected.issubset(failed)
                and expected.issubset(baseline_nodes)
            )
        unexpected = raw.get("unexpected_worktree_changes")
        if not isinstance(exit_code, int) or not 1 <= exit_code <= 125:
            satisfied = False
        if not isinstance(unexpected, list) or unexpected:
            satisfied = False
        if not satisfied:
            issues.append(f"behavioral_probe_{probe_id}_oracle_not_satisfied")
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
    invocations: dict[str, dict[str, Any]],
) -> dict[str, Any]:
    required_fields = {
        "schema_version", "kind", "evidence_id", "gate_id", "producer", "invocation",
        "subject", "artifacts", "observations", "behavioral_probes", "result", "timestamp",
    }
    issues = [f"missing_{field}" for field in sorted(required_fields - set(receipt))]
    if receipt.get("schema_version") != "2.0":
        issues.append("unsupported_schema_version")
    schema_errors = sorted(
        Draft202012Validator(receipt_schema).iter_errors(receipt),
        key=lambda error: ([str(token) for token in error.absolute_path], error.message),
    )
    issues.extend(f"receipt_schema:{error.message}" for error in schema_errors)
    expected_kind = expected_kinds.get(str(receipt.get("gate_id", "")))
    if expected_kind is not None and receipt.get("kind") != expected_kind:
        issues.append(f"evidence_kind_must_be_{expected_kind}")
    gate_id = str(receipt.get("gate_id", ""))
    expected_invocation = invocations.get(gate_id)
    invocation = receipt.get("invocation")
    if not isinstance(invocation, dict) or expected_invocation is None:
        issues.append("canonical_invocation_missing")
    elif (
        invocation.get("argv") != expected_invocation.get("argv")
        or invocation.get("cwd") != expected_invocation.get("cwd", ".")
    ):
        issues.append("invocation_does_not_match_gate_contract")
    observations = receipt.get("observations")
    if not isinstance(observations, dict) or observations.get("exit_code") != 0:
        issues.append("observed_exit_code_not_zero")
    if not isinstance(observations, dict) or observations.get("execution_tree_clean") is not True:
        issues.append("execution_tree_not_clean")
    if receipt.get("result") != "passed":
        issues.append("receipt_recomputed_result_failed")
    issues.extend(artifact_issues(receipt_path, receipt))
    subject_issues, invalidation = _subject_issues(
        repo_root, receipt, current, tree_independent_allowlist
    )
    issues.extend(subject_issues)
    issues.extend(_probe_issues(receipt_path, receipt, required=require_negative_control))
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
        if isinstance(receipt.get("subject"), dict) else None,
        "tree_sha": (receipt.get("subject") or {}).get("tree_sha")
        if isinstance(receipt.get("subject"), dict) else None,
        "artifact_sha256": _sha256(receipt_path),
        "result": "verified" if not issues else "invalid",
        "timestamp": receipt.get("timestamp"),
        "issues": sorted(set(issues)),
        "invalidation": invalidation,
        "receipt_path": receipt_path.as_posix(),
        "receipt": receipt,
    }


def load_receipts(
    repo_root: Path,
    evidence_dir: Path,
    current: dict[str, Any],
    *,
    require_negative_control: bool,
    tree_independent_allowlist: set[str],
    expected_kinds: dict[str, str],
    invocations: dict[str, dict[str, Any]],
) -> dict[str, list[dict[str, Any]]]:
    by_gate: dict[str, list[dict[str, Any]]] = {}
    schema_path = repo_root / "schemas/evidence-receipt.schema.json"
    receipt_schema = yaml.safe_load(schema_path.read_text(encoding="utf-8"))
    if not isinstance(receipt_schema, dict):
        raise ReceiptError(f"{schema_path} must deserialize to a mapping")
    for path in sorted(evidence_dir.rglob(f"*{RECEIPT_SUFFIX}")):
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            raise ReceiptError(f"invalid evidence receipt {path}: {exc}") from exc
        if not isinstance(payload, dict):
            raise ReceiptError(f"evidence receipt {path} must be an object")
        result = _receipt_result(
            repo_root,
            path,
            payload,
            current,
            require_negative_control=require_negative_control,
            tree_independent_allowlist=tree_independent_allowlist,
            receipt_schema=receipt_schema,
            expected_kinds=expected_kinds,
            invocations=invocations,
        )
        gate_id = str(result.get("gate_id") or "")
        by_gate.setdefault(gate_id, []).append(result)
    return by_gate

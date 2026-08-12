"""Structural contracts for evidence policy and finding registry artifacts."""

from __future__ import annotations

from .common import *  # noqa: F403,F405
from .phase_artifacts import _validate_document_path


def _load_evidence_contracts(
    repo_root: Path, schema_cache: dict[str, dict[str, Any]]
) -> tuple[dict[str, Any], Path, dict[str, Any], Path]:
    policy_path = repo_root / "governance/evidence-policy.yml"
    policy = _load_yaml(policy_path)
    _validate_schema(
        repo_root,
        schema_cache,
        policy,
        schema_name="evidence-policy.schema.json",
        context=str(policy_path),
    )
    _validate_document_path(repo_root, policy, policy_path, context=str(policy_path))

    findings_path = repo_root / "governance/findings.yml"
    findings = _load_yaml(findings_path)
    _validate_schema(
        repo_root,
        schema_cache,
        findings,
        schema_name="findings.schema.json",
        context=str(findings_path),
    )
    _validate_document_path(repo_root, findings, findings_path, context=str(findings_path))
    _validate_finding_registry_structure(repo_root, findings)
    return policy, policy_path, findings, findings_path


def _validate_finding_registry_structure(repo_root: Path, registry: dict[str, Any]) -> None:
    reviews = _require_sequence(
        registry.get("reviews"), context="governance/findings.yml reviews"
    )
    findings = _require_sequence(
        registry.get("findings"), context="governance/findings.yml findings"
    )
    review_ids: set[str] = set()
    indexed_finding_ids: set[str] = set()
    for index, raw in enumerate(reviews, start=1):
        review = _require_mapping(raw, context=f"governance/findings.yml reviews[{index}]")
        review_id = _require_string(
            review.get("id"), context=f"governance/findings.yml reviews[{index}].id"
        )
        if review_id in review_ids:
            raise GovernanceValidationError(
                f"governance/findings.yml contains duplicate review id {review_id}"
            )
        review_ids.add(review_id)
        source_path = _require_string(
            review.get("source_path"),
            context=f"governance/findings.yml reviews[{index}].source_path",
        )
        _require_path(
            repo_root,
            source_path,
            context=f"governance/findings.yml reviews[{index}].source_path",
        )
        indexed_finding_ids.update(
            _require_string_sequence(
                review.get("finding_ids"),
                context=f"governance/findings.yml reviews[{index}].finding_ids",
            )
        )
    finding_ids: set[str] = set()
    for index, raw in enumerate(findings, start=1):
        finding = _require_mapping(raw, context=f"governance/findings.yml findings[{index}]")
        finding_id = _require_string(
            finding.get("id"), context=f"governance/findings.yml findings[{index}].id"
        )
        if finding_id in finding_ids:
            raise GovernanceValidationError(
                f"governance/findings.yml contains duplicate finding id {finding_id}"
            )
        finding_ids.add(finding_id)
        if finding.get("review_id") not in review_ids:
            raise GovernanceValidationError(
                f"governance/findings.yml finding {finding_id} references unknown review"
            )
    if finding_ids != indexed_finding_ids:
        raise GovernanceValidationError(
            "governance/findings.yml review finding_ids must exactly index all findings"
        )

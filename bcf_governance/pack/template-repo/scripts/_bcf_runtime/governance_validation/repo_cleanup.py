"""repo cleanup validation helpers."""
# ruff: noqa: F403,F405

from __future__ import annotations

from .common import *  # noqa: F403,F405

def _validate_repo_cleanup_contract_semantics(
    profile: dict[str, Any],
    contract: dict[str, Any],
) -> None:
    drift_guardrails = _require_mapping(
        profile.get("drift_guardrails"), context="governance-profile.yml drift_guardrails"
    )
    audit_root = _require_string(
        drift_guardrails.get("audit_root"),
        context="governance-profile.yml drift_guardrails.audit_root",
    )
    canonical_roots = _require_mapping(
        contract.get("canonical_roots"),
        context="governance/repo-cleanup-contract.yml canonical_roots",
    )
    for group_name, value in canonical_roots.items():
        for relative_path in _require_string_sequence(
            value,
            context=f"governance/repo-cleanup-contract.yml canonical_roots.{group_name}",
            min_items=1,
        ):
            _validate_portable_relative_path(
                relative_path.rstrip("/"),
                context=f"governance/repo-cleanup-contract.yml canonical_roots.{group_name}",
            )
    historical_evidence = _require_string_sequence(
        canonical_roots.get("historical_evidence"),
        context="governance/repo-cleanup-contract.yml canonical_roots.historical_evidence",
        min_items=1,
    )
    if audit_root not in historical_evidence:
        raise GovernanceValidationError(
            "governance/repo-cleanup-contract.yml canonical_roots.historical_evidence "
            f"must include governance-profile.yml audit_root {audit_root}"
        )

    drift_pattern_ids = {
        _require_string(
            _require_mapping(
                pattern,
                context=f"governance/repo-cleanup-contract.yml drift_patterns[{index}]",
            ).get("id"),
            context=f"governance/repo-cleanup-contract.yml drift_patterns[{index}].id",
        )
        for index, pattern in enumerate(
            _require_sequence(
                contract.get("drift_patterns"),
                context="governance/repo-cleanup-contract.yml drift_patterns",
            ),
            start=1,
        )
    }
    for required_id in ("misplaced_audits", "stale_human_documentation"):
        if required_id not in drift_pattern_ids:
            raise GovernanceValidationError(
                "governance/repo-cleanup-contract.yml drift_patterns must include "
                f"{required_id}"
            )

    deterministic_commands = [
        _require_string(
            _require_mapping(
                action,
                context=f"governance/repo-cleanup-contract.yml deterministic_actions[{index}]",
            ).get("command"),
            context=f"governance/repo-cleanup-contract.yml deterministic_actions[{index}].command",
        )
        for index, action in enumerate(
            _require_sequence(
                contract.get("deterministic_actions"),
                context="governance/repo-cleanup-contract.yml deterministic_actions",
            ),
            start=1,
        )
    ]
    if not any("bcf cleanup" in command for command in deterministic_commands):
        raise GovernanceValidationError(
            "governance/repo-cleanup-contract.yml deterministic_actions must include bcf cleanup"
        )
    if not any("--force-rescaffold" in command for command in deterministic_commands):
        raise GovernanceValidationError(
            "governance/repo-cleanup-contract.yml deterministic_actions must include force rescaffold"
        )

    llm_review_ids = {
        _require_string(
            _require_mapping(
                item,
                context=f"governance/repo-cleanup-contract.yml llm_review_required[{index}]",
            ).get("id"),
            context=f"governance/repo-cleanup-contract.yml llm_review_required[{index}].id",
        )
        for index, item in enumerate(
            _require_sequence(
                contract.get("llm_review_required"),
                context="governance/repo-cleanup-contract.yml llm_review_required",
            ),
            start=1,
        )
    }
    if "documentation_currency" not in llm_review_ids:
        raise GovernanceValidationError(
            "governance/repo-cleanup-contract.yml llm_review_required must include "
            "documentation_currency"
        )

    validation_required = _require_mapping(
        contract.get("validation_required"),
        context="governance/repo-cleanup-contract.yml validation_required",
    )
    validation_commands = _require_string_sequence(
        validation_required.get("commands"),
        context="governance/repo-cleanup-contract.yml validation_required.commands",
        min_items=1,
    )
    if not any(
        "bcf validate" in command or "governance-validate" in command
        for command in validation_commands
    ):
        raise GovernanceValidationError(
            "governance/repo-cleanup-contract.yml validation_required.commands "
            "must include governance validation"
        )


def _load_repo_cleanup_contract(
    repo_root: Path,
    schema_cache: dict[str, dict[str, Any]],
    profile: dict[str, Any] | None,
) -> tuple[dict[str, Any] | None, Path | None]:
    if profile is None:
        return None, None
    drift_guardrails = _require_mapping(
        profile.get("drift_guardrails"), context="governance-profile.yml drift_guardrails"
    )
    contract_rel = drift_guardrails.get("cleanup_contract")
    if contract_rel is None:
        return None, None
    contract_path = _require_path(
        repo_root,
        _require_string(
            contract_rel,
            context="governance-profile.yml drift_guardrails.cleanup_contract",
        ),
        context="governance-profile.yml drift_guardrails.cleanup_contract",
    )
    contract = _load_yaml(contract_path)
    _validate_schema(
        repo_root,
        schema_cache,
        contract,
        schema_name=REPO_CLEANUP_CONTRACT_SCHEMA,
        context=str(contract_path),
    )
    _validate_document_path(repo_root, contract, contract_path, context=str(contract_path))
    _validate_repo_cleanup_contract_semantics(profile, contract)
    return contract, contract_path

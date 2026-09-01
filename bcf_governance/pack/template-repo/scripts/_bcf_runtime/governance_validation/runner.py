"""runner validation helpers."""
# ruff: noqa: F403,F405

from __future__ import annotations

import argparse

from ..ci_graph_contracts import CIGraphError, validate_ci_graph
from ..ci_graph_render import check_ci_graph
from ..semantic_ownership_registry import (
    SemanticOwnershipRegistryError,
    load_registry as load_semantic_ownership_registry,
)

from .common import *  # noqa: F403,F405
from .artifact_policy import _load_phase_history, _validate_artifact_manifest, _validate_observability_contracts
from .context_budgets import _context_budget_advisories
from .evidence_contracts import _load_evidence_contracts, _validate_gate_contract_registry
from .phase_artifacts import _validate_agents
from .phase_catalog import (
    _validate_active_closeout_evidence_ownership,
    _validate_active_phase,
    _validate_declared_phase_catalog,
    _validate_hotfix_lane,
)
from .release_gates import _validate_ci_profile, _validate_release_gate_targets, _validate_structural_gate_contract
from .repo_cleanup import _load_repo_cleanup_contract


def _validate_test_tombstones(repo_root: Path, schema_cache: dict[str, dict[str, Any]]) -> Path | None:
    path = repo_root / "governance" / "test-tombstones.yml"
    if not path.exists():
        return None
    registry = _load_yaml(path)
    _validate_schema(
        repo_root,
        schema_cache,
        registry,
        schema_name="test-tombstones.schema.json",
        context=str(path),
    )
    _validate_document_path(repo_root, registry, path, context=str(path))
    nodes = [str(entry["removed_node"]) for entry in registry.get("entries", [])]
    duplicates = sorted({node for node in nodes if nodes.count(node) > 1})
    if duplicates:
        raise GovernanceValidationError(
            "governance/test-tombstones.yml removed_node values must be unique: "
            + ", ".join(duplicates)
        )
    return path


def validate_repo_root(
    repo_root: Path,
    *,
    allow_placeholders: bool = False,
    allow_release_gate_placeholders: bool = False,
) -> None:
    schema_cache: dict[str, dict[str, Any]] = {}
    agents = _load_yaml(repo_root / "AGENTS.yml")
    memory = _load_yaml(repo_root / "MEMORY.yml")
    product_spec_path = repo_root / "plans" / "product-spec.yml"
    build_plan_path = repo_root / "plans" / "build-plan.yml"
    phase_ledger_path = repo_root / "plans" / "phase-ledger.yml"
    product_spec = _load_yaml(product_spec_path)
    build_plan = _load_yaml(build_plan_path)
    ledger = _load_yaml(phase_ledger_path)
    governance_profile, governance_profile_path = _load_governance_profile(repo_root, schema_cache)
    artifact_manifest, artifact_manifest_path = _load_artifact_manifest(
        repo_root, schema_cache, governance_profile
    )
    phase_history, phase_history_path = _load_phase_history(
        repo_root, schema_cache, artifact_manifest
    )
    _, cleanup_contract_path = _load_repo_cleanup_contract(
        repo_root, schema_cache, governance_profile
    )
    architecture_rules, architecture_boundaries_path = _load_architecture_boundaries(repo_root, schema_cache)
    (
        evidence_policy,
        evidence_policy_path,
        _,
        findings_path,
        gate_contracts,
        gate_contracts_path,
    ) = _load_evidence_contracts(repo_root, schema_cache)
    selected_profile = governance_profile.get("profile", {}).get("selected")
    if gate_contracts.get("target_profile") != selected_profile:
        raise GovernanceValidationError(
            "governance/gate-contracts.yml target_profile must match governance-profile.yml"
        )
    configured_gates = governance_profile.get("release_gate_profile", {}).get("gates", {})
    required_targets = {
        str(value.get("target"))
        for value in configured_gates.values()
        if isinstance(value, dict) and value.get("status") == "required"
    } if isinstance(configured_gates, dict) else set()
    contract_targets = set(gate_contracts.get("gates", {}))
    if required_targets != contract_targets:
        raise GovernanceValidationError(
            "governance/gate-contracts.yml gates must exactly match profile-required targets"
        )
    _validate_gate_contract_registry(
        repo_root, governance_profile, gate_contracts, evidence_policy
    )
    test_tombstones_path = _validate_test_tombstones(repo_root, schema_cache)

    _validate_schema(repo_root, schema_cache, agents, schema_name="agents.schema.json", context="AGENTS.yml")
    _validate_schema(repo_root, schema_cache, memory, schema_name="memory.schema.json", context="MEMORY.yml")
    _validate_schema(
        repo_root,
        schema_cache,
        product_spec,
        schema_name="product-spec.schema.json",
        context=str(product_spec_path),
    )
    _validate_schema(
        repo_root,
        schema_cache,
        build_plan,
        schema_name="build-plan.schema.json",
        context=str(build_plan_path),
    )
    _validate_schema(
        repo_root,
        schema_cache,
        ledger,
        schema_name="phase-ledger.schema.json",
        context=str(phase_ledger_path),
    )
    _validate_document_path(repo_root, agents, repo_root / "AGENTS.yml", context="AGENTS.yml")
    _validate_document_path(repo_root, memory, repo_root / "MEMORY.yml", context="MEMORY.yml")
    _validate_document_path(repo_root, product_spec, product_spec_path, context=str(product_spec_path))
    _validate_document_path(repo_root, build_plan, build_plan_path, context=str(build_plan_path))
    _validate_document_path(repo_root, ledger, phase_ledger_path, context=str(phase_ledger_path))

    _validate_agents(repo_root, agents)
    required_artifact_paths = _validate_artifact_manifest(repo_root, artifact_manifest, agents)
    observability_contract_paths = _validate_observability_contracts(repo_root, schema_cache)
    declared_phase_paths = _validate_declared_phase_catalog(
        repo_root, schema_cache, product_spec, build_plan, ledger, artifact_manifest, phase_history
    )
    hotfix_paths = _validate_hotfix_lane(repo_root, schema_cache, ledger)
    active_phase_paths = _validate_active_phase(
        repo_root, schema_cache, ledger, memory, declared_phase_paths
    )
    _validate_active_closeout_evidence_ownership(repo_root, ledger, governance_profile)
    _validate_ci_profile(governance_profile)
    _validate_structural_gate_contract(governance_profile, architecture_rules)
    ci_graph_path = repo_root / "governance/ci-graph.yml"
    if ci_graph_path.exists():
        try:
            validate_ci_graph(repo_root)
            graph_parity = check_ci_graph(repo_root)
        except CIGraphError as exc:
            raise GovernanceValidationError(str(exc)) from exc
        if graph_parity.status != "clean":
            raise GovernanceValidationError(
                "generated CI workflow drift: " + ", ".join(graph_parity.changed_paths)
            )
    if (repo_root / "governance/canonical-representations.yml").is_file():
        try:
            load_semantic_ownership_registry(repo_root)
        except SemanticOwnershipRegistryError as exc:
            raise GovernanceValidationError(str(exc)) from exc

    if not allow_placeholders:
        optional_paths = [
            repo_root / relative_path
            for relative_path in OPTIONAL_PLACEHOLDER_SCAN_PATHS
            if (repo_root / relative_path).exists()
        ]
        _validate_no_unresolved_placeholders(
            repo_root,
            [
                repo_root / "AGENTS.yml",
                repo_root / "MEMORY.yml",
                product_spec_path,
                build_plan_path,
                phase_ledger_path,
                *[path for triplet in declared_phase_paths.values() for path in triplet],
                *hotfix_paths,
                *observability_contract_paths,
                *active_phase_paths,
                *([phase_history_path] if phase_history_path is not None else []),
                *([governance_profile_path] if governance_profile_path is not None else []),
                *([artifact_manifest_path] if artifact_manifest_path is not None else []),
                *required_artifact_paths,
                *([cleanup_contract_path] if cleanup_contract_path is not None else []),
                *(
                    [architecture_boundaries_path]
                    if architecture_boundaries_path is not None
                    else []
                ),
                *optional_paths,
                evidence_policy_path,
                findings_path,
                gate_contracts_path,
                *([ci_graph_path] if ci_graph_path.is_file() else []),
                *([test_tombstones_path] if test_tombstones_path is not None else []),
            ],
        )
    _validate_release_gate_targets(
        repo_root,
        governance_profile,
        allow_release_gate_placeholders=allow_release_gate_placeholders,
    )


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description="Validate governed YAML artifacts.")
    parser.add_argument("--repo-root", type=Path, default=Path.cwd())
    parser.add_argument(
        "--format",
        dest="output_format",
        choices=sorted(VALIDATION_OUTPUT_FORMATS),
        default="text",
        help="Output format for validation results.",
    )
    parser.add_argument(
        "--compact",
        action="store_true",
        help="Use compact output formatting when combined with --format json.",
    )
    parser.add_argument(
        "--allow-placeholders",
        action="store_true",
        help="Allow unresolved {{PLACEHOLDER}} tokens while validating the uninstantiated template pack.",
    )
    parser.add_argument(
        "--allow-release-gate-placeholders",
        action="store_true",
        help="Allow fail-closed starter release gates while validating the uninstantiated template pack.",
    )
    args = parser.parse_args(argv)
    repo_root = args.repo_root.resolve()
    try:
        validate_repo_root(
            repo_root,
            allow_placeholders=args.allow_placeholders,
            allow_release_gate_placeholders=args.allow_release_gate_placeholders,
        )
    except GovernanceValidationError as error:
        _emit_output(
            _failure_report(repo_root, error),
            output_format=args.output_format,
            compact=args.compact,
        )
        raise SystemExit(1)
    _emit_output(
        _success_report(
            repo_root,
            allow_placeholders=args.allow_placeholders,
            advisories=_context_budget_advisories(repo_root),
        ),
        output_format=args.output_format,
        compact=args.compact,
        default_text="governance-yaml-ok",
    )


if __name__ == "__main__":
    main()

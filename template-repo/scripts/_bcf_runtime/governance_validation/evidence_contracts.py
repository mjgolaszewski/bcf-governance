"""Structural contracts for evidence policy and finding registry artifacts."""

from __future__ import annotations

from .common import *  # noqa: F403,F405
from .phase_artifacts import _validate_document_path

TEST_COMMAND_POLICIES = {
    "automated_tests",
    "contract_tests",
    "architecture_tests",
    "architecture_module_size",
    "architecture_layer_membership",
    "architecture_context_membership",
    "architecture_import_boundaries",
    "architecture_cqrs_side",
    "architecture_router_thinness",
    "architecture_duplication",
}


def _validate_gate_contract_registry(
    repo_root: Path, profile: dict[str, Any], contracts: dict[str, Any], policy: dict[str, Any]
) -> None:
    if str(profile.get("profile_contract_version", "1.0")) == "2.0" and policy.get("gate_overrides"):
        raise GovernanceValidationError(
            "profile-v2 evidence semantics must be owned only by governance/gate-contracts.yml"
        )
    configured = profile.get("release_gate_profile", {}).get("gates", {})
    configured = configured if isinstance(configured, dict) else {}
    policies = {
        str(value.get("target")): str(value.get("command_policy", ""))
        for value in configured.values()
        if isinstance(value, dict) and isinstance(value.get("target"), str)
    }
    gates = _require_mapping(
        contracts.get("gates"), context="governance/gate-contracts.yml gates"
    )
    interpreter = contracts.get("interpreter_contract")
    if isinstance(interpreter, dict):
        projection = interpreter.get("requirements_projection")
        if projection is not None:
            _validate_portable_relative_path(
                _require_string(
                    projection,
                    context=(
                        "governance/gate-contracts.yml "
                        "interpreter_contract.requirements_projection"
                    ),
                ),
                context=(
                    "governance/gate-contracts.yml "
                    "interpreter_contract.requirements_projection"
                ),
            )
            _require_path(
                repo_root,
                projection,
                context=(
                    "governance/gate-contracts.yml "
                    "interpreter_contract.requirements_projection"
                ),
            )
        requirements = _require_mapping(
            interpreter.get("gate_requirements"),
            context="governance/gate-contracts.yml interpreter_contract.gate_requirements",
        )
        unknown = sorted(set(requirements) - set(gates))
        if unknown:
            raise GovernanceValidationError(
                "interpreter requirements name unknown gates: " + ", ".join(unknown)
            )
    mutation_issues: list[str] = []
    for target, raw in gates.items():
        gate = _require_mapping(raw, context=f"gate contract {target}")
        invocation = _require_mapping(
            gate.get("invocation"), context=f"gate contract {target}.invocation"
        )
        argv = _require_string_sequence(
            invocation.get("argv"), context=f"gate contract {target}.invocation.argv", min_items=1
        )
        executable = Path(argv[0]).name.lower()
        if executable in {"true", "false", "echo", "printf", ":"}:
            raise GovernanceValidationError(
                f"gate contract {target} uses a no-op instead of executable evidence"
            )
        if executable in {"sh", "bash", "dash", "zsh", "cmd", "cmd.exe", "powershell", "pwsh"}:
            raise GovernanceValidationError(
                f"gate contract {target} must use direct argv, not a shell interpreter"
            )
        if "-c" in argv and executable.startswith(("python", "perl", "ruby", "node")):
            raise GovernanceValidationError(
                f"gate contract {target} must use a tracked script instead of inline code"
            )
        for index, argument in enumerate(argv):
            path_argument = Path(argument)
            if path_argument.is_absolute() or ".." in path_argument.parts:
                raise GovernanceValidationError(
                    f"gate contract {target}.invocation.argv[{index}] escapes the repository"
                )
        if executable.startswith(("python", "node", "ruby", "perl")):
            if len(argv) < 2 or argv[1].startswith("-"):
                raise GovernanceValidationError(
                    f"gate contract {target} must invoke a tracked repository script"
                )
            _require_path(
                repo_root,
                argv[1],
                context=f"gate contract {target}.invocation.argv[1]",
            )
        cwd = _require_string(
            invocation.get("cwd"), context=f"gate contract {target}.invocation.cwd"
        )
        _validate_portable_relative_path(cwd, context=f"gate contract {target}.invocation.cwd")
        controls = _require_sequence(
            gate.get("negative_controls"), context=f"gate contract {target}.negative_controls"
        )
        for index, raw_control in enumerate(controls, start=1):
            control = _require_mapping(
                raw_control, context=f"gate contract {target}.negative_controls[{index}]"
            )
            mutation = _require_mapping(
                control.get("mutation"),
                context=f"gate contract {target}.negative_controls[{index}].mutation",
            )
            mutation_path = _require_string(
                mutation.get("path"),
                context=f"gate contract {target}.negative_controls[{index}].mutation.path",
            )
            if mutation_path != "@active_phase_log":
                _validate_portable_relative_path(
                    mutation_path,
                    context=f"gate contract {target}.negative_controls[{index}].mutation.path",
                )
                mutation_file = repo_root / mutation_path
                search = mutation.get("search")
                if not mutation_file.is_file() or mutation_file.is_symlink():
                    mutation_issues.append(f"{control.get('id')}:missing-path")
                elif not isinstance(search, str) or not search:
                    mutation_issues.append(f"{control.get('id')}:missing-search")
                else:
                    occurrences = mutation_file.read_text(encoding="utf-8").count(search)
                    if occurrences != 1:
                        mutation_issues.append(
                            f"{control.get('id')}:search-count={occurrences}"
                        )
            oracle = _require_mapping(
                control.get("oracle"),
                context=f"gate contract {target}.negative_controls[{index}].oracle",
            )
            if policies.get(str(target)) in TEST_COMMAND_POLICIES and oracle.get("kind") != "test_node_failure":
                raise GovernanceValidationError(
                    f"test gate contract {target} requires named test_node_failure controls"
                )
    if mutation_issues:
        raise GovernanceValidationError(
            "negative-control mutations must resolve exactly once: "
            + ", ".join(mutation_issues)
        )


def _load_evidence_contracts(
    repo_root: Path, schema_cache: dict[str, dict[str, Any]]
) -> tuple[dict[str, Any], Path, dict[str, Any], Path, dict[str, Any], Path]:
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
    contracts_path = repo_root / "governance/gate-contracts.yml"
    contracts = _load_yaml(contracts_path)
    _validate_schema(
        repo_root,
        schema_cache,
        contracts,
        schema_name="gate-contracts.schema.json",
        context=str(contracts_path),
    )
    _validate_document_path(
        repo_root, contracts, contracts_path, context=str(contracts_path)
    )
    return policy, policy_path, findings, findings_path, contracts, contracts_path


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

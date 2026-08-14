"""phase artifacts validation helpers."""
# ruff: noqa: F403,F405

from __future__ import annotations

from .common import *  # noqa: F403,F405

def _document_status(payload: dict[str, Any], *, context: str) -> str:
    document = _require_mapping(payload.get("document"), context=f"{context}.document")
    status = document.get("status")
    if not isinstance(status, str):
        raise GovernanceValidationError(f"{context}.document.status must be a string")
    return status


def _validate_document_path(
    repo_root: Path,
    payload: dict[str, Any],
    actual_path: Path,
    *,
    context: str,
) -> None:
    document = _require_mapping(payload.get("document"), context=f"{context}.document")
    document_path = _require_string(document.get("path"), context=f"{context}.document.path")
    _validate_portable_relative_path(document_path, context=f"{context}.document.path")
    expected_path = _repo_relative_path(repo_root, actual_path)
    if document_path != expected_path:
        raise GovernanceValidationError(
            f"{context}.document.path must be {expected_path!r}, got {document_path!r}"
        )


def _phase_number(phase_id: str) -> int:
    if not phase_id.startswith("P") or not phase_id[1:].isdigit():
        raise GovernanceValidationError(f"invalid phase id {phase_id!r}; expected values like 'P01'")
    return int(phase_id[1:])


def _phase_stem(phase_id: str) -> str:
    return f"phase-{_phase_number(phase_id):02d}"


def _phase_artifact_paths(repo_root: Path, phase_id: str) -> tuple[Path, Path, Path]:
    stem = _phase_stem(phase_id)
    return (
        repo_root / "plans" / f"{stem}-plan.yml",
        repo_root / "plans" / f"{stem}-workitems.yml",
        repo_root / "phases" / f"{stem}-log.yml",
    )


def _hotfix_stem(related_phase_id: str, hotfix_number: int) -> str:
    return f"{_phase_stem(related_phase_id)}-hotfix{hotfix_number:02d}"


def _validate_phase_log_closeout(log: dict[str, Any], *, log_path: Path) -> None:
    for field in (
        "all_tickets_closed",
        "required_suites_green",
        "ast_architecture_gates_green",
        "health_checks_green",
        "security_review_complete",
        "release_ready",
        "zero_findings",
    ):
        if field in log:
            raise GovernanceValidationError(
                f"{log_path} contains self-attested terminal field {field}; "
                "completed is authored while verified and closed are computed by bcf truth"
            )
    closeout = _require_mapping(
        log.get("closeout_requirements"), context=f"{log_path} closeout_requirements"
    )
    claims = _require_mapping(
        closeout.get("claims"), context=f"{log_path} closeout_requirements.claims"
    )
    for claim_id, requirement in claims.items():
        mapping = _require_mapping(
            requirement,
            context=f"{log_path} closeout_requirements.claims.{claim_id}",
        )
        _require_string_sequence(
            mapping.get("required_evidence"),
            context=f"{log_path} closeout_requirements.claims.{claim_id}.required_evidence",
            min_items=0,
        )


def _validate_phase_workitem_consistency(
    plan: dict[str, Any],
    workitems: dict[str, Any],
    log: dict[str, Any],
    *,
    plan_path: Path,
    workitems_path: Path,
    log_path: Path,
) -> None:
    delivery_contract = _require_mapping(
        plan.get("delivery_contract"), context=f"{plan_path} delivery_contract"
    )
    deliverables = _require_string_sequence(
        delivery_contract.get("tightly_scoped_deliverables"),
        context=f"{plan_path} delivery_contract.tightly_scoped_deliverables",
        min_items=1,
    )
    workitem_entries = _require_sequence(
        workitems.get("workitems"), context=f"{workitems_path} workitems"
    )
    log_workitem_entries = _require_sequence(log.get("workitems"), context=f"{log_path} workitems")

    workitem_text = "\n".join(
        " ".join(
            [
                str(_require_mapping(item, context=f"{workitems_path} workitems[{index}]").get("summary", "")),
                " ".join(str(value) for value in item.get("acceptance", []))
                if isinstance(item.get("acceptance"), list)
                else "",
            ]
        )
        for index, item in enumerate(workitem_entries, start=1)
    )
    missing_deliverables = [
        deliverable for deliverable in deliverables if deliverable not in workitem_text
    ]
    if missing_deliverables:
        raise GovernanceValidationError(
            f"{workitems_path} workitems must cover phase deliverables from {plan_path}: "
            + ", ".join(missing_deliverables)
        )

    workitem_statuses: dict[str, str] = {}
    for index, item in enumerate(workitem_entries, start=1):
        item_mapping = _require_mapping(item, context=f"{workitems_path} workitems[{index}]")
        item_id = _require_string(item_mapping.get("id"), context=f"{workitems_path} workitems[{index}].id")
        if item_id in workitem_statuses:
            raise GovernanceValidationError(f"{workitems_path} contains duplicate workitem id {item_id}")
        workitem_statuses[item_id] = _require_string(
            item_mapping.get("status"), context=f"{workitems_path} workitems[{index}].status"
        )

    log_statuses: dict[str, str] = {}
    for index, item in enumerate(log_workitem_entries, start=1):
        item_mapping = _require_mapping(item, context=f"{log_path} workitems[{index}]")
        item_id = _require_string(item_mapping.get("id"), context=f"{log_path} workitems[{index}].id")
        if item_id in log_statuses:
            raise GovernanceValidationError(f"{log_path} contains duplicate workitem id {item_id}")
        log_statuses[item_id] = _require_string(
            item_mapping.get("status"), context=f"{log_path} workitems[{index}].status"
        )

    if set(workitem_statuses) != set(log_statuses):
        missing_in_log = sorted(set(workitem_statuses) - set(log_statuses))
        missing_in_workitems = sorted(set(log_statuses) - set(workitem_statuses))
        details: list[str] = []
        if missing_in_log:
            details.append(f"missing in phase log: {', '.join(missing_in_log)}")
        if missing_in_workitems:
            details.append(f"missing in workitem ledger: {', '.join(missing_in_workitems)}")
        raise GovernanceValidationError(
            f"{log_path} workitems must match {workitems_path}"
            + (f" ({'; '.join(details)})" if details else "")
        )

    mismatched_statuses = sorted(
        item_id
        for item_id, status in workitem_statuses.items()
        if log_statuses[item_id] != status
    )
    if mismatched_statuses:
        raise GovernanceValidationError(
            f"{log_path} workitem statuses must match {workitems_path}: "
            + ", ".join(mismatched_statuses)
        )

    if _document_status(log, context=str(log_path)) == "completed":
        open_workitems = sorted(
            item_id
            for item_id, status in workitem_statuses.items()
            if status not in CLOSED_WORKITEM_STATUSES
        )
        if open_workitems:
            raise GovernanceValidationError(
                f"{log_path} cannot be completed while workitems remain open: "
                + ", ".join(open_workitems)
            )


def _validate_phase_artifact_triplet(
    repo_root: Path,
    schema_cache: dict[str, dict[str, Any]],
    *,
    phase_id: str,
    build_block: str | None = None,
) -> tuple[Path, Path, Path]:
    plan_path, workitems_path, log_path = _phase_artifact_paths(repo_root, phase_id)
    plan = _load_yaml(plan_path)
    workitems = _load_yaml(workitems_path)
    log = _load_yaml(log_path)
    _validate_schema(
        repo_root,
        schema_cache,
        plan,
        schema_name="phase-plan.schema.json",
        context=str(plan_path),
    )
    _validate_schema(
        repo_root,
        schema_cache,
        workitems,
        schema_name="phase-workitems.schema.json",
        context=str(workitems_path),
    )
    _validate_schema(
        repo_root,
        schema_cache,
        log,
        schema_name="phase-log.schema.json",
        context=str(log_path),
    )
    _validate_document_path(repo_root, plan, plan_path, context=str(plan_path))
    _validate_document_path(repo_root, workitems, workitems_path, context=str(workitems_path))
    _validate_document_path(repo_root, log, log_path, context=str(log_path))

    plan_phase = _require_mapping(plan.get("phase"), context=f"{plan_path} phase")
    if plan_phase.get("id") != phase_id:
        raise GovernanceValidationError(f"{plan_path} phase.id must match declared phase {phase_id}")
    if build_block is not None and plan_phase.get("build_block") != build_block:
        raise GovernanceValidationError(
            f"{plan_path} phase.build_block must match declared build block {build_block}"
        )

    workitems_document = _require_mapping(
        workitems.get("document"), context=f"{workitems_path} document"
    )
    if workitems_document.get("phase_id") != phase_id:
        raise GovernanceValidationError(
            f"{workitems_path} document.phase_id must match declared phase {phase_id}"
        )

    log_phase = _require_mapping(log.get("phase"), context=f"{log_path} phase")
    if log_phase.get("id") != phase_id:
        raise GovernanceValidationError(f"{log_path} phase.id must match declared phase {phase_id}")
    if build_block is not None and log_phase.get("build_block") != build_block:
        raise GovernanceValidationError(
            f"{log_path} phase.build_block must match declared build block {build_block}"
        )

    _validate_phase_workitem_consistency(
        plan,
        workitems,
        log,
        plan_path=plan_path,
        workitems_path=workitems_path,
        log_path=log_path,
    )
    _validate_phase_log_closeout(log, log_path=log_path)
    return plan_path, workitems_path, log_path


def _validate_agents(repo_root: Path, agents: dict[str, Any]) -> None:
    governance = _require_mapping(agents.get("governance"), context="AGENTS.yml governance")
    structural = _require_mapping(
        governance.get("structural_schema_contract"),
        context="AGENTS.yml governance.structural_schema_contract",
    )
    if _require_string(
        structural.get("root"),
        context="AGENTS.yml governance.structural_schema_contract.root",
    ) != "schemas/":
        raise GovernanceValidationError(
            "AGENTS.yml governance.structural_schema_contract.root must be schemas/"
        )
    for schema_path in _require_string_sequence(
        structural.get("required_schemas"),
        context="AGENTS.yml governance.structural_schema_contract.required_schemas",
        min_items=1,
    ):
        _require_path(
            repo_root,
            schema_path,
            context="AGENTS.yml governance.structural_schema_contract.required_schemas",
        )

    semantic = _require_mapping(
        governance.get("semantic_validation_contract"),
        context="AGENTS.yml governance.semantic_validation_contract",
    )
    if semantic.get("validator") != "scripts/validate_governance_yaml.py":
        raise GovernanceValidationError(
            "AGENTS.yml governance.semantic_validation_contract.validator must be "
            "scripts/validate_governance_yaml.py"
        )
    retention_contract = _require_mapping(
        governance.get("phase_retention_contract"),
        context="AGENTS.yml governance.phase_retention_contract",
    )
    if retention_contract.get("default_cleanup_mode") != "git_history":
        raise GovernanceValidationError(
            "AGENTS.yml governance.phase_retention_contract.default_cleanup_mode must be git_history"
        )
    modes = set(
        _require_string_sequence(
            retention_contract.get("modes"),
            context="AGENTS.yml governance.phase_retention_contract.modes",
            min_items=2,
        )
    )
    if modes != {"git_history", "archive"}:
        raise GovernanceValidationError(
            "AGENTS.yml governance.phase_retention_contract.modes must be archive and git_history"
        )

    references = _require_mapping(agents.get("references"), context="AGENTS.yml references")
    for key in (
        "canonical_product_spec",
        "canonical_build_plan",
        "canonical_active_ledger",
        "canonical_memory",
        "governance_validator",
    ):
        value = references.get(key)
        if not isinstance(value, str):
            raise GovernanceValidationError(f"AGENTS.yml references.{key} must be a string")
        _require_path(repo_root, value, context=f"AGENTS.yml references.{key}")

    testing = _require_mapping(agents.get("testing_governance"), context="AGENTS.yml testing_governance")
    for test_root in _require_string_sequence(
        testing.get("test_roots"),
        context="AGENTS.yml testing_governance.test_roots",
        min_items=1,
    ):
        _require_path(repo_root, test_root, context="AGENTS.yml testing_governance.test_roots")

    guardrails = _require_mapping(
        agents.get("structural_guardrails"), context="AGENTS.yml structural_guardrails"
    )
    deconstruction = _require_mapping(
        guardrails.get("agent_deconstruction_contract"),
        context="AGENTS.yml structural_guardrails.agent_deconstruction_contract",
    )
    if deconstruction.get("max_loc") != 800:
        raise GovernanceValidationError(
            "AGENTS.yml structural_guardrails.agent_deconstruction_contract.max_loc must be 800"
        )
    phase_rules = set(
        _require_string_sequence(
            deconstruction.get("required_phase_rules"),
            context="AGENTS.yml structural_guardrails.agent_deconstruction_contract.required_phase_rules",
            min_items=1,
        )
    )
    required_rules = {
        "one_fatty_per_phase",
        "characterization_test_first",
        "preserve_cli_entrypoint",
        "split_by_responsibility",
        "split_shape_plan_validate_execute_report",
        "ast_boundary_gate",
        "targeted_tests",
        "delete_dead_code_immediately",
    }
    missing_rules = sorted(required_rules - phase_rules)
    if missing_rules:
        raise GovernanceValidationError(
            "AGENTS.yml structural_guardrails.agent_deconstruction_contract.required_phase_rules "
            f"missing required rules: {', '.join(missing_rules)}"
        )

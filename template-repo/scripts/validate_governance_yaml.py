"""Validate core YAML governance artifacts for the template governance pack."""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator  # type: ignore[import-untyped]
import yaml  # type: ignore[import-untyped]


class GovernanceValidationError(ValueError):
    """Raised when governance artifacts are syntactically valid but semantically inconsistent."""


PLACEHOLDER_PATTERN = re.compile(r"\{\{[^{}\n]+\}\}")
OPTIONAL_PLACEHOLDER_SCAN_PATHS = (
    "docs/OPERATIONS.md",
    "Makefile.fragment",
    ".github/workflows/governance.yml",
    "phases/phase-NN-hotfixNN.yml",
)
SCHEMA_ROOT = "schemas"
PHASE_CLOSEOUT_STATUSES = {"verified", "closed"}
ACTIVE_PHASE_LIFECYCLE_STATUSES = {
    "planned",
    "active",
    "blocked",
    "paused",
    "completed",
    "verified",
    "closed",
    "abandoned",
}
COMPLETED_RELEASE_TRAIN_STATUSES = {"completed", "closed", "released"}
HOTFIX_MODES = {"lite", "full"}


def _load_yaml(path: Path) -> dict[str, Any]:
    if not path.exists():
        raise GovernanceValidationError(f"missing required path {path}")
    payload = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise GovernanceValidationError(f"{path} must deserialize to a mapping")
    return payload


def _load_json(path: Path) -> dict[str, Any]:
    if not path.exists():
        raise GovernanceValidationError(f"missing required path {path}")
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise GovernanceValidationError(f"{path} must contain valid JSON") from exc
    if not isinstance(payload, dict):
        raise GovernanceValidationError(f"{path} must deserialize to a mapping")
    return payload


def _require_mapping(value: object, *, context: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise GovernanceValidationError(f"{context} must be a mapping")
    return value


def _require_sequence(value: object, *, context: str) -> list[Any]:
    if not isinstance(value, list):
        raise GovernanceValidationError(f"{context} must be a sequence")
    return value


def _require_string(value: object, *, context: str) -> str:
    if not isinstance(value, str) or not value:
        raise GovernanceValidationError(f"{context} must be a non-empty string")
    return value


def _require_positive_int(value: object, *, context: str) -> int:
    try:
        number = int(value)
    except (TypeError, ValueError) as exc:
        raise GovernanceValidationError(f"{context} must be a positive integer") from exc
    if number <= 0:
        raise GovernanceValidationError(f"{context} must be a positive integer")
    return number


def _require_string_sequence(
    value: object,
    *,
    context: str,
    min_items: int = 0,
    max_items: int | None = None,
) -> list[str]:
    sequence = _require_sequence(value, context=context)
    strings = [
        _require_string(item, context=f"{context}[{index}]")
        for index, item in enumerate(sequence, start=1)
    ]
    if len(strings) < min_items:
        raise GovernanceValidationError(f"{context} must contain at least {min_items} item(s)")
    if max_items is not None and len(strings) > max_items:
        raise GovernanceValidationError(f"{context} must contain at most {max_items} item(s)")
    return strings


def _require_path(repo_root: Path, relative_path: str, *, context: str) -> Path:
    path = repo_root / relative_path
    if not path.exists():
        raise GovernanceValidationError(f"{context} references missing path {relative_path}")
    return path


def _dedupe_paths(paths: list[Path]) -> list[Path]:
    seen: set[Path] = set()
    deduped: list[Path] = []
    for path in paths:
        resolved = path.resolve()
        if resolved in seen:
            continue
        seen.add(resolved)
        deduped.append(path)
    return deduped


def _relative_display(repo_root: Path, path: Path) -> str:
    try:
        return str(path.relative_to(repo_root))
    except ValueError:
        return str(path)


def _load_schema(
    repo_root: Path, schema_name: str, schema_cache: dict[str, dict[str, Any]]
) -> dict[str, Any]:
    if schema_name not in schema_cache:
        schema_cache[schema_name] = _load_json(repo_root / SCHEMA_ROOT / schema_name)
    return schema_cache[schema_name]


def _schema_error_location(context: str, error: object) -> str:
    path = ".".join(str(token) for token in getattr(error, "absolute_path"))
    return f"{context}.{path}" if path else context


def _validate_schema(
    repo_root: Path,
    schema_cache: dict[str, dict[str, Any]],
    payload: dict[str, Any],
    *,
    schema_name: str,
    context: str,
) -> None:
    schema = _load_schema(repo_root, schema_name, schema_cache)
    errors = sorted(
        Draft202012Validator(schema).iter_errors(payload),
        key=lambda error: ([str(token) for token in error.absolute_path], error.message),
    )
    if not errors:
        return
    first_error = errors[0]
    raise GovernanceValidationError(
        f"{_schema_error_location(context, first_error)} failed structural schema "
        f"{SCHEMA_ROOT}/{schema_name}: {first_error.message}"
    )


def _validate_no_unresolved_placeholders(repo_root: Path, paths: list[Path]) -> None:
    violations: list[str] = []
    for path in _dedupe_paths(paths):
        text = path.read_text(encoding="utf-8")
        for line_number, line in enumerate(text.splitlines(), start=1):
            for match in PLACEHOLDER_PATTERN.finditer(line):
                violations.append(
                    f"{_relative_display(repo_root, path)}:{line_number}: {match.group(0)}"
                )

    if violations:
        preview_limit = 50
        preview = "\n".join(violations[:preview_limit])
        remainder = len(violations) - preview_limit
        suffix = f"\n... and {remainder} more" if remainder > 0 else ""
        raise GovernanceValidationError(
            "unresolved template placeholders remain in governed artifacts:\n"
            f"{preview}{suffix}"
        )


def _document_status(payload: dict[str, Any], *, context: str) -> str:
    document = _require_mapping(payload.get("document"), context=f"{context}.document")
    status = document.get("status")
    if not isinstance(status, str):
        raise GovernanceValidationError(f"{context}.document.status must be a string")
    return status


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
    if _document_status(log, context=str(log_path)) not in PHASE_CLOSEOUT_STATUSES:
        return
    for field in (
        "all_tickets_closed",
        "required_suites_green",
        "ast_architecture_gates_green",
        "health_checks_green",
        "known_warnings",
        "known_constraints",
    ):
        if field not in log:
            raise GovernanceValidationError(f"{log_path} missing closeout field {field}")
    _require_sequence(log["required_suites_green"], context=f"{log_path} required_suites_green")
    _require_sequence(log["known_warnings"], context=f"{log_path} known_warnings")
    _require_sequence(log["known_constraints"], context=f"{log_path} known_constraints")


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


def _validate_declared_phase_catalog(
    repo_root: Path,
    schema_cache: dict[str, dict[str, Any]],
    product_spec: dict[str, Any],
    build_plan: dict[str, Any],
    ledger: dict[str, Any],
) -> dict[str, tuple[Path, Path, Path]]:
    execution_phases = _require_sequence(
        product_spec.get("execution_phases"), context="plans/product-spec.yml execution_phases"
    )
    phase_sequence = _require_sequence(
        build_plan.get("phase_sequence"), context="plans/build-plan.yml phase_sequence"
    )

    product_phase_map: dict[str, dict[str, Any]] = {}
    for index, phase in enumerate(execution_phases, start=1):
        phase_mapping = _require_mapping(
            phase, context=f"plans/product-spec.yml execution_phases[{index}]"
        )
        phase_id = _require_string(
            phase_mapping.get("phase_id"),
            context=f"plans/product-spec.yml execution_phases[{index}].phase_id",
        )
        product_phase_map[phase_id] = phase_mapping

    build_phase_map: dict[str, dict[str, Any]] = {}
    declared_phase_paths: dict[str, tuple[Path, Path, Path]] = {}
    for index, phase in enumerate(phase_sequence, start=1):
        phase_mapping = _require_mapping(
            phase, context=f"plans/build-plan.yml phase_sequence[{index}]"
        )
        phase_id = _require_string(
            phase_mapping.get("phase_id"),
            context=f"plans/build-plan.yml phase_sequence[{index}].phase_id",
        )
        build_phase_map[phase_id] = phase_mapping
        build_block = _require_string(
            phase_mapping.get("build_block"),
            context=f"plans/build-plan.yml phase_sequence[{index}].build_block",
        )
        declared_phase_paths[phase_id] = _validate_phase_artifact_triplet(
            repo_root,
            schema_cache,
            phase_id=phase_id,
            build_block=build_block,
        )

    if set(product_phase_map) != set(build_phase_map):
        missing_in_build_plan = sorted(set(product_phase_map) - set(build_phase_map))
        missing_in_product_spec = sorted(set(build_phase_map) - set(product_phase_map))
        details: list[str] = []
        if missing_in_build_plan:
            details.append(f"missing in build plan: {', '.join(missing_in_build_plan)}")
        if missing_in_product_spec:
            details.append(f"missing in product spec: {', '.join(missing_in_product_spec)}")
        raise GovernanceValidationError(
            "plans/product-spec.yml execution_phases and plans/build-plan.yml phase_sequence must "
            "declare the same phase ids"
            + (f" ({'; '.join(details)})" if details else "")
        )

    for phase_id, product_phase in product_phase_map.items():
        build_phase = build_phase_map[phase_id]
        if product_phase.get("build_block") != build_phase.get("build_block"):
            raise GovernanceValidationError(
                f"phase {phase_id} build_block must align between product spec and build plan"
            )

    release_trains = _require_mapping(
        ledger.get("release_trains"), context="plans/phase-ledger.yml release_trains"
    )
    for release_name, release_payload in release_trains.items():
        release_mapping = _require_mapping(
            release_payload,
            context=f"plans/phase-ledger.yml release_trains.{release_name}",
        )
        release_status = _require_string(
            release_mapping.get("status"),
            context=f"plans/phase-ledger.yml release_trains.{release_name}.status",
        )
        if release_status not in COMPLETED_RELEASE_TRAIN_STATUSES:
            continue

        phase_ids = [
            phase_id
            for phase_id, phase in product_phase_map.items()
            if phase.get("release_train") == release_name
        ]
        if not phase_ids:
            raise GovernanceValidationError(
                f"completed release train {release_name} must own at least one declared phase"
            )

        for phase_id in phase_ids:
            log = _load_yaml(declared_phase_paths[phase_id][2])
            log_path = declared_phase_paths[phase_id][2]
            if _document_status(log, context=str(log_path)) == "planned":
                raise GovernanceValidationError(
                    f"completed release train {release_name} cannot reference planned phase log "
                    f"{log_path.relative_to(repo_root)}"
                )

    return declared_phase_paths


def _validate_hotfix_log(
    repo_root: Path,
    schema_cache: dict[str, dict[str, Any]],
    hotfix_log_path: Path,
    *,
    expected_hotfix_id: str,
    expected_mode: str,
) -> dict[str, Any]:
    hotfix_log = _load_yaml(hotfix_log_path)
    _validate_schema(
        repo_root,
        schema_cache,
        hotfix_log,
        schema_name="hotfix-log.schema.json",
        context=str(hotfix_log_path),
    )
    hotfix = _require_mapping(hotfix_log.get("hotfix"), context=f"{hotfix_log_path} hotfix")
    if hotfix.get("id") != expected_hotfix_id:
        raise GovernanceValidationError(
            f"{hotfix_log_path} hotfix.id must match phase-ledger hotfix id {expected_hotfix_id}"
        )
    mode = _require_string(hotfix.get("mode"), context=f"{hotfix_log_path} hotfix.mode")
    if mode not in HOTFIX_MODES:
        raise GovernanceValidationError(f"{hotfix_log_path} hotfix.mode must be one of {sorted(HOTFIX_MODES)}")
    if mode != expected_mode:
        raise GovernanceValidationError(
            f"{hotfix_log_path} hotfix.mode must match phase-ledger hotfix mode {expected_mode}"
        )
    related_phase_id = _require_string(
        hotfix.get("related_phase_id"),
        context=f"{hotfix_log_path} hotfix.related_phase_id",
    )
    hotfix_number = _require_positive_int(
        hotfix.get("hotfix_number"),
        context=f"{hotfix_log_path} hotfix.hotfix_number",
    )
    expected_filename = f"{_hotfix_stem(related_phase_id, hotfix_number)}.yml"
    if hotfix_log_path.name != expected_filename:
        raise GovernanceValidationError(
            f"{hotfix_log_path} must follow the filename convention {expected_filename}"
        )

    document = _require_mapping(hotfix_log.get("document"), context=f"{hotfix_log_path} document")
    document_path = _require_string(document.get("path"), context=f"{hotfix_log_path} document.path")
    expected_relative_path = f"phases/{expected_filename}"
    if not document_path.endswith(expected_relative_path):
        raise GovernanceValidationError(
            f"{hotfix_log_path} document.path must end with {expected_relative_path}"
        )

    execution_evidence = _require_mapping(
        hotfix_log.get("execution_evidence"),
        context=f"{hotfix_log_path} execution_evidence",
    )
    _require_string_sequence(
        execution_evidence.get("planned_commands"),
        context=f"{hotfix_log_path} execution_evidence.planned_commands",
        min_items=1,
    )
    _require_sequence(
        execution_evidence.get("executed_commands"),
        context=f"{hotfix_log_path} execution_evidence.executed_commands",
    )
    _require_string_sequence(
        execution_evidence.get("notes"),
        context=f"{hotfix_log_path} execution_evidence.notes",
        min_items=1,
    )
    return hotfix_log


def _validate_hotfix_lane(
    repo_root: Path, schema_cache: dict[str, dict[str, Any]], ledger: dict[str, Any]
) -> list[Path]:
    hotfix_lane = _require_mapping(
        ledger.get("hotfix_lane"), context="plans/phase-ledger.yml hotfix_lane"
    )
    default_mode = _require_string(
        hotfix_lane.get("default_mode"),
        context="plans/phase-ledger.yml hotfix_lane.default_mode",
    )
    if default_mode not in HOTFIX_MODES:
        raise GovernanceValidationError(
            "plans/phase-ledger.yml hotfix_lane.default_mode must be one of "
            f"{sorted(HOTFIX_MODES)}"
        )
    modes = _require_mapping(
        hotfix_lane.get("modes"), context="plans/phase-ledger.yml hotfix_lane.modes"
    )
    for mode_name in HOTFIX_MODES:
        mode_mapping = _require_mapping(
            modes.get(mode_name),
            context=f"plans/phase-ledger.yml hotfix_lane.modes.{mode_name}",
        )
        key = "allowed_when" if mode_name == "lite" else "required_when"
        _require_string_sequence(
            mode_mapping.get(key),
            context=f"plans/phase-ledger.yml hotfix_lane.modes.{mode_name}.{key}",
            min_items=1,
        )

    open_records = _require_sequence(
        hotfix_lane.get("open_records"), context="plans/phase-ledger.yml hotfix_lane.open_records"
    )
    remediation_history = _require_sequence(
        hotfix_lane.get("remediation_history"),
        context="plans/phase-ledger.yml hotfix_lane.remediation_history",
    )

    hotfix_paths: list[Path] = []
    seen_hotfix_ids: set[str] = set()

    for index, record in enumerate(open_records, start=1):
        record_mapping = _require_mapping(
            record, context=f"plans/phase-ledger.yml hotfix_lane.open_records[{index}]"
        )
        hotfix_id = _require_string(
            record_mapping.get("id"),
            context=f"plans/phase-ledger.yml hotfix_lane.open_records[{index}].id",
        )
        if hotfix_id in seen_hotfix_ids:
            raise GovernanceValidationError(f"duplicate hotfix id {hotfix_id} in plans/phase-ledger.yml")
        seen_hotfix_ids.add(hotfix_id)

        mode = _require_string(
            record_mapping.get("mode"),
            context=f"plans/phase-ledger.yml hotfix_lane.open_records[{index}].mode",
        )
        if mode not in HOTFIX_MODES:
            raise GovernanceValidationError(
                "plans/phase-ledger.yml hotfix_lane.open_records"
                f"[{index}].mode must be one of {sorted(HOTFIX_MODES)}"
            )
        _require_string(
            record_mapping.get("status"),
            context=f"plans/phase-ledger.yml hotfix_lane.open_records[{index}].status",
        )
        triggered_by_commits = _require_string_sequence(
            record_mapping.get("triggered_by_commits"),
            context=f"plans/phase-ledger.yml hotfix_lane.open_records[{index}].triggered_by_commits",
            min_items=1,
        )
        if mode == "lite" and len(triggered_by_commits) != 1:
            raise GovernanceValidationError(
                "plans/phase-ledger.yml hotfix_lane.open_records"
                f"[{index}].triggered_by_commits must contain exactly one commit in lite mode"
            )
        _require_string_sequence(
            record_mapping.get("failing_workflows"),
            context=f"plans/phase-ledger.yml hotfix_lane.open_records[{index}].failing_workflows",
        )
        _require_string(
            record_mapping.get("root_cause"),
            context=f"plans/phase-ledger.yml hotfix_lane.open_records[{index}].root_cause",
        )
        _require_string(
            record_mapping.get("remediated_in_phase"),
            context=f"plans/phase-ledger.yml hotfix_lane.open_records[{index}].remediated_in_phase",
        )
        _require_string_sequence(
            record_mapping.get("canonical_artifacts"),
            context=f"plans/phase-ledger.yml hotfix_lane.open_records[{index}].canonical_artifacts",
        )
        hotfix_log = _require_string(
            record_mapping.get("hotfix_log"),
            context=f"plans/phase-ledger.yml hotfix_lane.open_records[{index}].hotfix_log",
        )
        hotfix_log_path = _require_path(
            repo_root,
            hotfix_log,
            context=f"plans/phase-ledger.yml hotfix_lane.open_records[{index}].hotfix_log",
        )
        _validate_hotfix_log(
            repo_root,
            schema_cache,
            hotfix_log_path,
            expected_hotfix_id=hotfix_id,
            expected_mode=mode,
        )
        hotfix_paths.append(hotfix_log_path)

    for index, record in enumerate(remediation_history, start=1):
        record_mapping = _require_mapping(
            record, context=f"plans/phase-ledger.yml hotfix_lane.remediation_history[{index}]"
        )
        hotfix_id = _require_string(
            record_mapping.get("id"),
            context=f"plans/phase-ledger.yml hotfix_lane.remediation_history[{index}].id",
        )
        if hotfix_id in seen_hotfix_ids:
            raise GovernanceValidationError(f"duplicate hotfix id {hotfix_id} in plans/phase-ledger.yml")
        seen_hotfix_ids.add(hotfix_id)

        mode = _require_string(
            record_mapping.get("mode"),
            context=f"plans/phase-ledger.yml hotfix_lane.remediation_history[{index}].mode",
        )
        if mode not in HOTFIX_MODES:
            raise GovernanceValidationError(
                "plans/phase-ledger.yml hotfix_lane.remediation_history"
                f"[{index}].mode must be one of {sorted(HOTFIX_MODES)}"
            )
        _require_string(
            record_mapping.get("recorded_at_utc"),
            context=f"plans/phase-ledger.yml hotfix_lane.remediation_history[{index}].recorded_at_utc",
        )
        _require_string(
            record_mapping.get("action"),
            context=f"plans/phase-ledger.yml hotfix_lane.remediation_history[{index}].action",
        )
        _require_string(
            record_mapping.get("remediated_in_phase"),
            context=f"plans/phase-ledger.yml hotfix_lane.remediation_history[{index}].remediated_in_phase",
        )
        _require_string_sequence(
            record_mapping.get("canonical_artifacts"),
            context=f"plans/phase-ledger.yml hotfix_lane.remediation_history[{index}].canonical_artifacts",
        )
        _require_string_sequence(
            record_mapping.get("local_validation"),
            context=f"plans/phase-ledger.yml hotfix_lane.remediation_history[{index}].local_validation",
            min_items=1,
        )
        hotfix_log = _require_string(
            record_mapping.get("hotfix_log"),
            context=f"plans/phase-ledger.yml hotfix_lane.remediation_history[{index}].hotfix_log",
        )
        hotfix_log_path = _require_path(
            repo_root,
            hotfix_log,
            context=f"plans/phase-ledger.yml hotfix_lane.remediation_history[{index}].hotfix_log",
        )
        hotfix_log_payload = _validate_hotfix_log(
            repo_root,
            schema_cache,
            hotfix_log_path,
            expected_hotfix_id=hotfix_id,
            expected_mode=mode,
        )
        if _document_status(hotfix_log_payload, context=str(hotfix_log_path)) == "planned":
            raise GovernanceValidationError(
                f"{hotfix_log_path} cannot remain planned after it is moved into remediation_history"
            )
        remote_validation = record_mapping.get("remote_validation_completed")
        if remote_validation is not None:
            remote_mapping = _require_mapping(
                remote_validation,
                context=(
                    "plans/phase-ledger.yml "
                    f"hotfix_lane.remediation_history[{index}].remote_validation_completed"
                ),
            )
            _require_string(
                remote_mapping.get("commit"),
                context=(
                    "plans/phase-ledger.yml "
                    f"hotfix_lane.remediation_history[{index}].remote_validation_completed.commit"
                ),
            )
            _require_string_sequence(
                remote_mapping.get("workflows"),
                context=(
                    "plans/phase-ledger.yml "
                    f"hotfix_lane.remediation_history[{index}].remote_validation_completed.workflows"
                ),
                min_items=1,
            )
        hotfix_paths.append(hotfix_log_path)

    return hotfix_paths


def _validate_active_phase(
    repo_root: Path,
    schema_cache: dict[str, dict[str, Any]],
    ledger: dict[str, Any],
    memory: dict[str, Any],
    declared_phase_paths: dict[str, tuple[Path, Path, Path]],
) -> list[Path]:
    active_phase = _require_mapping(
        ledger.get("active_phase"), context="plans/phase-ledger.yml active_phase"
    )
    phase_id = _require_string(active_phase.get("id"), context="plans/phase-ledger.yml active_phase.id")
    if phase_id not in declared_phase_paths:
        raise GovernanceValidationError(
            f"plans/phase-ledger.yml active_phase.id {phase_id} is not declared in the build plan"
        )

    lifecycle_status = _require_string(
        active_phase.get("lifecycle_status"),
        context="plans/phase-ledger.yml active_phase.lifecycle_status",
    )
    if lifecycle_status not in ACTIVE_PHASE_LIFECYCLE_STATUSES:
        raise GovernanceValidationError(
            "plans/phase-ledger.yml active_phase.lifecycle_status must be one of "
            f"{sorted(ACTIVE_PHASE_LIFECYCLE_STATUSES)}"
        )
    _require_string(active_phase.get("owner"), context="plans/phase-ledger.yml active_phase.owner")
    if lifecycle_status == "blocked":
        _require_string(
            active_phase.get("blocked_reason"),
            context="plans/phase-ledger.yml active_phase.blocked_reason",
        )
        _require_string(
            active_phase.get("unblock_condition"),
            context="plans/phase-ledger.yml active_phase.unblock_condition",
        )
    if lifecycle_status == "paused":
        _require_string(
            active_phase.get("paused_reason"),
            context="plans/phase-ledger.yml active_phase.paused_reason",
        )
        _require_string(
            active_phase.get("resume_condition"),
            context="plans/phase-ledger.yml active_phase.resume_condition",
        )
    if lifecycle_status == "abandoned":
        _require_string(
            active_phase.get("abandonment_reason"),
            context="plans/phase-ledger.yml active_phase.abandonment_reason",
        )

    plan_rel = _require_string(active_phase.get("plan"), context="active_phase.plan")
    workitems_rel = _require_string(active_phase.get("workitems"), context="active_phase.workitems")
    log_rel = _require_string(active_phase.get("log"), context="active_phase.log")
    _require_path(
        repo_root,
        _require_string(active_phase.get("memory"), context="active_phase.memory"),
        context="active_phase.memory",
    )
    _require_path(
        repo_root,
        _require_string(active_phase.get("spec"), context="active_phase.spec"),
        context="active_phase.spec",
    )
    _require_path(
        repo_root,
        _require_string(active_phase.get("build_plan"), context="active_phase.build_plan"),
        context="active_phase.build_plan",
    )
    _require_string_sequence(
        active_phase.get("validation_commands"),
        context="plans/phase-ledger.yml active_phase.validation_commands",
        min_items=1,
    )

    plan_path = _require_path(repo_root, plan_rel, context="active_phase.plan")
    workitems_path = _require_path(repo_root, workitems_rel, context="active_phase.workitems")
    log_path = _require_path(repo_root, log_rel, context="active_phase.log")
    if (plan_path, workitems_path, log_path) != declared_phase_paths[phase_id]:
        raise GovernanceValidationError(
            "plans/phase-ledger.yml active_phase paths must follow the declared phase artifact "
            f"convention for {phase_id}"
        )

    _validate_phase_artifact_triplet(
        repo_root,
        schema_cache,
        phase_id=phase_id,
        build_block=_require_string(
            active_phase.get("build_block"), context="plans/phase-ledger.yml active_phase.build_block"
        ),
    )

    active_log = _load_yaml(log_path)
    active_log_status = _document_status(active_log, context=str(log_path))
    if lifecycle_status == "verified" and active_log_status not in {"verified", "closed"}:
        raise GovernanceValidationError(
            f"{log_path} must be verified or closed when the active phase lifecycle_status is verified"
        )
    if lifecycle_status == "closed" and active_log_status != "closed":
        raise GovernanceValidationError(
            f"{log_path} must be closed when the active phase lifecycle_status is closed"
        )
    if lifecycle_status == "completed" and active_log_status == "planned":
        raise GovernanceValidationError(
            f"{log_path} cannot remain planned when the active phase lifecycle_status is completed"
        )

    environment_facts = _require_mapping(
        memory.get("environment_facts"), context="MEMORY.yml environment_facts"
    )
    active_artifacts = _require_mapping(
        environment_facts.get("active_artifacts"),
        context="MEMORY.yml environment_facts.active_artifacts",
    )
    expected_memory_paths = {
        "spec": active_phase.get("spec"),
        "build_plan": active_phase.get("build_plan"),
        "active_phase_ledger": "plans/phase-ledger.yml",
        "active_phase_plan": active_phase.get("plan"),
        "active_workitem_ledger": active_phase.get("workitems"),
        "active_phase_log": active_phase.get("log"),
    }
    for key, expected in expected_memory_paths.items():
        if active_artifacts.get(key) != expected:
            raise GovernanceValidationError(
                f"MEMORY.yml active_artifacts.{key} must be {expected!r}"
            )

    return [plan_path, workitems_path, log_path]


def validate_repo_root(repo_root: Path, *, allow_placeholders: bool = False) -> None:
    schema_cache: dict[str, dict[str, Any]] = {}
    agents = _load_yaml(repo_root / "AGENTS.yml")
    memory = _load_yaml(repo_root / "MEMORY.yml")
    product_spec_path = repo_root / "plans" / "product-spec.yml"
    build_plan_path = repo_root / "plans" / "build-plan.yml"
    phase_ledger_path = repo_root / "plans" / "phase-ledger.yml"
    product_spec = _load_yaml(product_spec_path)
    build_plan = _load_yaml(build_plan_path)
    ledger = _load_yaml(phase_ledger_path)

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

    _validate_agents(repo_root, agents)
    declared_phase_paths = _validate_declared_phase_catalog(
        repo_root, schema_cache, product_spec, build_plan, ledger
    )
    hotfix_paths = _validate_hotfix_lane(repo_root, schema_cache, ledger)
    active_phase_paths = _validate_active_phase(
        repo_root, schema_cache, ledger, memory, declared_phase_paths
    )

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
                *active_phase_paths,
                *optional_paths,
            ],
        )


def main() -> None:
    parser = argparse.ArgumentParser(description="Validate governed YAML artifacts.")
    parser.add_argument("--repo-root", type=Path, default=Path.cwd())
    parser.add_argument(
        "--allow-placeholders",
        action="store_true",
        help="Allow unresolved {{PLACEHOLDER}} tokens while validating the uninstantiated template pack.",
    )
    args = parser.parse_args()
    validate_repo_root(args.repo_root.resolve(), allow_placeholders=args.allow_placeholders)
    print("governance-yaml-ok")


if __name__ == "__main__":
    main()

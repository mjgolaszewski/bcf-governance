"""Validate governed hotfix logs and lane history."""
from __future__ import annotations

from .common import (
    HOTFIX_MODES,
    Any,
    GovernanceValidationError,
    Path,
    _document_status,
    _load_yaml,
    _require_mapping,
    _require_path,
    _require_positive_int,
    _require_sequence,
    _require_string,
    _require_string_sequence,
    _validate_document_path,
    _validate_schema,
    re,
)
from .phase_artifacts import _hotfix_stem


def _phase_hotfix_paths_by_phase(repo_root: Path) -> dict[str, list[Path]]:
    phases_root = repo_root / "phases"
    if not phases_root.exists():
        return {}
    pattern = re.compile(r"phase-(\d+)-hotfix\d+\.ya?ml$")
    paths_by_phase: dict[str, list[Path]] = {}
    for path in sorted(phases_root.iterdir()):
        if not path.is_file():
            continue
        match = pattern.match(path.name)
        if match is None:
            continue
        phase_id = f"P{int(match.group(1)):02d}"
        paths_by_phase.setdefault(phase_id, []).append(path)
    return paths_by_phase


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

    expected_relative_path = f"phases/{expected_filename}"
    _validate_document_path(repo_root, hotfix_log, hotfix_log_path, context=str(hotfix_log_path))
    document = _require_mapping(hotfix_log.get("document"), context=f"{hotfix_log_path} document")
    document_path = _require_string(document.get("path"), context=f"{hotfix_log_path} document.path")
    if document_path != expected_relative_path:
        raise GovernanceValidationError(
            f"{hotfix_log_path} document.path must be {expected_relative_path}"
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

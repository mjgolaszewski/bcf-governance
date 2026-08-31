"""phase catalog validation helpers."""
# ruff: noqa: F403,F405

from __future__ import annotations

from .common import *  # noqa: F403,F405
from .phase_artifacts import (
    _document_status,
    _hotfix_stem,
    _phase_number,
    _validate_phase_artifact_triplet,
)
from .artifact_policy import (
    _retained_phase_ids,
    _strict_phase_retention_enabled,
    _validate_phase_history_entries,
)


def _declared_phase_ids_are_contiguous(phase_ids: set[str]) -> tuple[bool, list[str]]:
    if not phase_ids:
        return True, []
    phase_numbers = sorted(_phase_number(phase_id) for phase_id in phase_ids)
    expected_numbers = set(range(phase_numbers[0], phase_numbers[-1] + 1))
    missing = sorted(expected_numbers - set(phase_numbers))
    return not missing, [f"P{number:02d}" for number in missing]


def _phase_ids_from_existing_artifacts(repo_root: Path) -> set[str]:
    phase_ids: set[str] = set()
    patterns = (
        (repo_root / "plans", re.compile(r"phase-(\d+)-(?:plan|workitems)\.ya?ml$")),
        (repo_root / "phases", re.compile(r"phase-(\d+)-log\.ya?ml$")),
    )
    for root, pattern in patterns:
        if not root.exists():
            continue
        for path in root.iterdir():
            if not path.is_file():
                continue
            match = pattern.match(path.name)
            if match is not None:
                phase_ids.add(f"P{int(match.group(1)):02d}")
    return phase_ids


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


def _validate_declared_phase_catalog(
    repo_root: Path,
    schema_cache: dict[str, dict[str, Any]],
    product_spec: dict[str, Any],
    build_plan: dict[str, Any],
    ledger: dict[str, Any],
    manifest: dict[str, Any],
    phase_history: dict[str, Any] | None,
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

    history_entries = _validate_phase_history_entries(
        repo_root,
        phase_history,
        product_phase_map=product_phase_map,
        build_phase_map=build_phase_map,
        manifest=manifest,
    )
    product_history = product_spec.get("phase_history")
    build_history = build_plan.get("phase_history")
    if (product_history is None) != (build_history is None) or (
        product_history is not None and product_history != build_history
    ):
        raise GovernanceValidationError(
            "product spec and build plan must declare the same phase_history owner"
        )
    if product_history is not None:
        history_owner = _require_mapping(
            product_history, context="plans/product-spec.yml phase_history"
        )
        through = _require_string(
            history_owner.get("through_phase"),
            context="plans/product-spec.yml phase_history.through_phase",
        )
        if not history_entries or through != max(history_entries, key=_phase_number):
            raise GovernanceValidationError(
                "phase_history.through_phase must name the highest retained history entry"
            )
        if any(
            _phase_number(phase_id) <= _phase_number(through)
            for phase_id in build_phase_map
        ):
            raise GovernanceValidationError(
                "active roadmap phases must follow phase_history.through_phase"
            )
    complete_phase_ids = set(build_phase_map) | set(history_entries)
    contiguous, missing_phase_ids = _declared_phase_ids_are_contiguous(complete_phase_ids)
    if not contiguous:
        raise GovernanceValidationError(
            "plans/build-plan.yml phase_sequence must use contiguous phase ids across "
            "the active roadmap and phase history; missing: "
            + ", ".join(missing_phase_ids)
        )
    retained_phase_ids = _retained_phase_ids(
        build_phase_map=build_phase_map,
        ledger=ledger,
        manifest=manifest,
    )
    strict_retention = _strict_phase_retention_enabled(manifest)
    active_phase = _require_mapping(
        ledger.get("active_phase"), context="plans/phase-ledger.yml active_phase"
    )
    active_id = _require_string(active_phase.get("id"), context="plans/phase-ledger.yml active_phase.id")

    existing_phase_ids = _phase_ids_from_existing_artifacts(repo_root)
    existing_hotfix_paths = _phase_hotfix_paths_by_phase(repo_root)
    undeclared_phase_ids = sorted(existing_phase_ids - complete_phase_ids)
    if undeclared_phase_ids:
        raise GovernanceValidationError(
            "phase plan, workitem, or log artifacts exist without build-plan declarations: "
            + ", ".join(undeclared_phase_ids)
        )
    if strict_retention:
        undeclared_hotfix_phase_ids = sorted(set(existing_hotfix_paths) - complete_phase_ids)
        if undeclared_hotfix_phase_ids:
            raise GovernanceValidationError(
                "phase hotfix artifacts exist without build-plan declarations: "
                + ", ".join(undeclared_hotfix_phase_ids)
            )

    for phase_id, product_phase in product_phase_map.items():
        build_phase = build_phase_map[phase_id]
        if product_phase.get("build_block") != build_phase.get("build_block"):
            raise GovernanceValidationError(
                f"phase {phase_id} build_block must align between product spec and build plan"
            )

    for index, phase in enumerate(phase_sequence, start=1):
        phase_mapping = _require_mapping(
            phase, context=f"plans/build-plan.yml phase_sequence[{index}]"
        )
        phase_id = _require_string(
            phase_mapping.get("phase_id"),
            context=f"plans/build-plan.yml phase_sequence[{index}].phase_id",
        )
        build_block = _require_string(
            phase_mapping.get("build_block"),
            context=f"plans/build-plan.yml phase_sequence[{index}].build_block",
        )
        must_retain_triplet = retained_phase_ids is None or phase_id in retained_phase_ids
        triplet_exists = phase_id in existing_phase_ids
        phase_number = _phase_number(phase_id)
        active_number = _phase_number(active_id)
        is_historical = phase_number < active_number
        is_future = phase_number > active_number
        if strict_retention and is_historical and not must_retain_triplet and triplet_exists:
            raise GovernanceValidationError(
                f"phase {phase_id} is outside the retained phase window but active triplet artifacts remain"
            )
        if strict_retention and is_historical and not must_retain_triplet and phase_id in existing_hotfix_paths:
            paths = ", ".join(path.relative_to(repo_root).as_posix() for path in existing_hotfix_paths[phase_id])
            raise GovernanceValidationError(
                f"phase {phase_id} is outside the retained phase window but active hotfix artifacts remain: "
                f"{paths}"
            )
        if strict_retention and is_future and not triplet_exists:
            continue
        if must_retain_triplet or triplet_exists:
            declared_phase_paths[phase_id] = _validate_phase_artifact_triplet(
                repo_root,
                schema_cache,
                phase_id=phase_id,
                build_block=build_block,
            )
        elif phase_id not in history_entries:
            raise GovernanceValidationError(
                f"phase {phase_id} has no active triplet and no plans/phase-history.yml entry"
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
        phase_ids.extend(
            phase_id
            for phase_id, phase in history_entries.items()
            if phase_id not in product_phase_map
            and phase.get("release_train") == release_name
        )
        if not phase_ids:
            raise GovernanceValidationError(
                f"completed release train {release_name} must own at least one declared phase"
            )

        for phase_id in phase_ids:
            if phase_id in declared_phase_paths:
                log = _load_yaml(declared_phase_paths[phase_id][2])
                status = _document_status(log, context=str(declared_phase_paths[phase_id][2]))
                display = declared_phase_paths[phase_id][2].relative_to(repo_root).as_posix()
            else:
                status = _require_string(
                    history_entries[phase_id].get("status"),
                    context=f"plans/phase-history.yml entries.{phase_id}.status",
                )
                display = "plans/phase-history.yml"
            if status == "planned":
                raise GovernanceValidationError(
                    f"completed release train {release_name} cannot reference planned phase log "
                    f"{display}"
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
    if (lifecycle_status == "completed") != (active_log_status == "completed"):
        raise GovernanceValidationError(
            f"{log_path} and plans/phase-ledger.yml must declare completed together"
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


def _validate_active_closeout_evidence_ownership(
    repo_root: Path,
    ledger: dict[str, Any],
    governance_profile: dict[str, Any],
) -> None:
    """Reject closeout evidence that truth cannot receive from a required gate."""
    active_phase = _require_mapping(
        ledger.get("active_phase"), context="plans/phase-ledger.yml active_phase"
    )
    configured = _require_mapping(
        governance_profile.get("release_gate_profile", {}).get("gates"),
        context="governance-profile.yml release_gate_profile.gates",
    )
    status_by_target = {
        _require_string(
            _require_mapping(raw, context=f"release gate {gate_id}").get("target"),
            context=f"release gate {gate_id}.target",
        ): _require_string(
            _require_mapping(raw, context=f"release gate {gate_id}").get("status"),
            context=f"release gate {gate_id}.status",
        )
        for gate_id, raw in configured.items()
    }
    references: list[tuple[str, str]] = []
    workitems_path = _require_path(
        repo_root,
        _require_string(active_phase.get("workitems"), context="active_phase.workitems"),
        context="active_phase.workitems",
    )
    workitems = _load_yaml(workitems_path)
    for index, raw in enumerate(
        _require_sequence(workitems.get("workitems"), context=f"{workitems_path} workitems"),
        start=1,
    ):
        item = _require_mapping(raw, context=f"{workitems_path} workitems[{index}]")
        item_id = _require_string(
            item.get("id"), context=f"{workitems_path} workitems[{index}].id"
        )
        references.extend(
            (f"workitem {item_id}", target)
            for target in _require_string_sequence(
                item.get("acceptance_evidence"),
                context=f"{workitems_path} workitems[{index}].acceptance_evidence",
                min_items=1,
            )
        )
    log_path = _require_path(
        repo_root,
        _require_string(active_phase.get("log"), context="active_phase.log"),
        context="active_phase.log",
    )
    closeout = _require_mapping(
        _load_yaml(log_path).get("closeout_requirements"),
        context=f"{log_path} closeout_requirements",
    )
    claims = _require_mapping(
        closeout.get("claims"), context=f"{log_path} closeout_requirements.claims"
    )
    for claim_id, raw in claims.items():
        claim = _require_mapping(raw, context=f"{log_path} claim {claim_id}")
        references.extend(
            (f"claim {claim_id}", target)
            for target in _require_string_sequence(
                claim.get("required_evidence"),
                context=f"{log_path} claim {claim_id}.required_evidence",
                min_items=0,
            )
        )
    reconciliation = _require_mapping(
        closeout.get("reconciliation"), context=f"{log_path} reconciliation"
    )
    references.extend(
        ("reconciliation", target)
        for target in _require_string_sequence(
            reconciliation.get("required_evidence"),
            context=f"{log_path} reconciliation.required_evidence",
            min_items=0,
        )
    )
    unknown = sorted(f"{owner}: {target}" for owner, target in references if target not in status_by_target)
    if unknown:
        raise GovernanceValidationError(
            "active closeout evidence must reference configured release-gate targets: "
            + ", ".join(unknown)
        )
    if active_phase.get("lifecycle_status") == "completed":
        inactive = sorted(
            f"{owner}: {target} ({status_by_target[target]})"
            for owner, target in references
            if status_by_target[target] != "required"
        )
        if inactive:
            raise GovernanceValidationError(
                "completed active closeout evidence must reference required gates that emit truth receipts: "
                + ", ".join(inactive)
            )

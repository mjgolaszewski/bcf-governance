"""Cheap canonical consistency checks for authored phase state."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml  # type: ignore[import-untyped]


class AuthoredPhaseStateError(ValueError):
    """Raised before reconciliation when authored phase state contradicts itself."""


def _mapping(value: Any, *, context: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise AuthoredPhaseStateError(f"{context} must be a mapping")
    return value


def _string(value: Any, *, context: str) -> str:
    if not isinstance(value, str) or not value:
        raise AuthoredPhaseStateError(f"{context} must be a non-empty string")
    return value


def _load(path: Path) -> dict[str, Any]:
    try:
        return _mapping(yaml.safe_load(path.read_text(encoding="utf-8")), context=str(path))
    except (OSError, yaml.YAMLError) as exc:
        raise AuthoredPhaseStateError(f"cannot read authored phase state {path}: {exc}") from exc


def _phase_map(entries: Any, *, context: str) -> dict[str, dict[str, Any]]:
    if not isinstance(entries, list):
        raise AuthoredPhaseStateError(f"{context} must be a sequence")
    result: dict[str, dict[str, Any]] = {}
    for index, value in enumerate(entries, start=1):
        entry = _mapping(value, context=f"{context}[{index}]")
        phase_id = _string(entry.get("phase_id"), context=f"{context}[{index}].phase_id")
        if phase_id in result:
            raise AuthoredPhaseStateError(f"{context} contains duplicate phase {phase_id}")
        result[phase_id] = entry
    return result


def active_phase_paths(repo_root: Path) -> tuple[str, str, str]:
    """Derive the active phase artifact paths from the canonical ledger."""

    ledger = _load(repo_root / "plans/phase-ledger.yml")
    active = _mapping(ledger.get("active_phase"), context="phase-ledger active_phase")
    return tuple(
        _string(active.get(key), context=f"phase-ledger active_phase.{key}")
        for key in ("plan", "workitems", "log")
    )  # type: ignore[return-value]


def validate_authored_phase_state(repo_root: Path) -> dict[str, Any]:
    """Reject contradictory authored phase state before derived reconciliation."""

    product = _load(repo_root / "plans/product-spec.yml")
    build = _load(repo_root / "plans/build-plan.yml")
    ledger = _load(repo_root / "plans/phase-ledger.yml")
    memory = _load(repo_root / "MEMORY.yml")
    product_phases = _phase_map(product.get("execution_phases"), context="product-spec execution_phases")
    build_phases = _phase_map(build.get("phase_sequence"), context="build-plan phase_sequence")
    if set(product_phases) != set(build_phases):
        raise AuthoredPhaseStateError(
            "product-spec and build-plan must declare the same phase identities"
        )
    for phase_id in product_phases:
        if product_phases[phase_id].get("build_block") != build_phases[phase_id].get("build_block"):
            raise AuthoredPhaseStateError(f"{phase_id} build_block differs across authored catalogs")

    active = _mapping(ledger.get("active_phase"), context="phase-ledger active_phase")
    phase_id = _string(active.get("id"), context="phase-ledger active_phase.id")
    if phase_id not in build_phases:
        raise AuthoredPhaseStateError(f"active phase {phase_id} is absent from authored catalogs")
    build_block = _string(active.get("build_block"), context="phase-ledger active_phase.build_block")
    if build_phases[phase_id].get("build_block") != build_block:
        raise AuthoredPhaseStateError(f"active phase {phase_id} build_block differs from authored catalogs")

    number = int(phase_id[1:]) if phase_id.startswith("P") and phase_id[1:].isdigit() else -1
    expected_paths = (
        f"plans/phase-{number:02d}-plan.yml",
        f"plans/phase-{number:02d}-workitems.yml",
        f"phases/phase-{number:02d}-log.yml",
    )
    paths = active_phase_paths(repo_root)
    if number < 0 or paths != expected_paths:
        raise AuthoredPhaseStateError(f"active phase {phase_id} artifact paths are not canonical")

    payloads = [_load(repo_root / relative) for relative in paths]
    plan_phase = _mapping(payloads[0].get("phase"), context=f"{paths[0]} phase")
    workitem_document = _mapping(payloads[1].get("document"), context=f"{paths[1]} document")
    log_phase = _mapping(payloads[2].get("phase"), context=f"{paths[2]} phase")
    identities = (
        (plan_phase.get("id"), plan_phase.get("build_block")),
        (workitem_document.get("phase_id"), build_block),
        (log_phase.get("id"), log_phase.get("build_block")),
    )
    if any(identity != (phase_id, build_block) for identity in identities):
        raise AuthoredPhaseStateError("active phase artifacts disagree on phase/build identity")

    lifecycle = _string(active.get("lifecycle_status"), context="active phase lifecycle_status")
    log_document = _mapping(payloads[2].get("document"), context=f"{paths[2]} document")
    log_status = _string(log_document.get("status"), context=f"{paths[2]} document.status")
    if (lifecycle == "completed") != (log_status == "completed"):
        raise AuthoredPhaseStateError("active phase ledger and log must declare completed together")

    facts = _mapping(memory.get("environment_facts"), context="MEMORY environment_facts")
    artifacts = _mapping(facts.get("active_artifacts"), context="MEMORY active_artifacts")
    expected_memory = {
        "spec": "plans/product-spec.yml",
        "build_plan": "plans/build-plan.yml",
        "active_phase_ledger": "plans/phase-ledger.yml",
        "active_phase_plan": paths[0],
        "active_workitem_ledger": paths[1],
        "active_phase_log": paths[2],
    }
    for key, expected in expected_memory.items():
        if artifacts.get(key) != expected:
            raise AuthoredPhaseStateError(f"MEMORY active_artifacts.{key} must be {expected!r}")
    return {"phase_id": phase_id, "build_block": build_block, "paths": list(paths)}

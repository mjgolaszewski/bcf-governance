"""Typed supplemental-publication validation for phase release catalogs."""

from __future__ import annotations

from collections.abc import Callable, Mapping
import re
from typing import Any

from .common import GovernanceValidationError, _require_mapping, _require_string


def release_phase_ids(
    release_name: str,
    product_phase_map: Mapping[str, Mapping[str, Any]],
    history_entries: Mapping[str, Mapping[str, Any]],
) -> list[str]:
    """Return the exact current or retained phases owned by one release."""

    current = [
        phase_id
        for phase_id, phase in product_phase_map.items()
        if phase.get("release_train") == release_name
    ]
    current.extend(
        phase_id
        for phase_id, phase in history_entries.items()
        if phase_id not in product_phase_map
        and phase.get("release_train") == release_name
    )
    return current


def validate_supplemental_publication(
    *,
    release_name: str,
    release_mapping: Mapping[str, Any],
    release_trains: Mapping[str, Any],
    phase_ids_for: Callable[[str], list[str]],
) -> bool:
    """Validate one completed child publication; return whether it is a child."""

    if release_mapping.get("kind", "phase_train") != "supplemental_publication":
        return False
    parent_release = _require_string(
        release_mapping.get("parent_release"),
        context=f"plans/phase-ledger.yml release_trains.{release_name}.parent_release",
    )
    if parent_release == release_name or parent_release not in release_trains:
        raise GovernanceValidationError(
            f"supplemental release {release_name} has invalid parent {parent_release}"
        )
    parent_mapping = _require_mapping(
        release_trains[parent_release],
        context=f"plans/phase-ledger.yml release_trains.{parent_release}",
    )
    if parent_mapping.get("kind", "phase_train") != "phase_train":
        raise GovernanceValidationError(
            f"supplemental release {release_name} parent must be a phase train"
        )
    if not phase_ids_for(parent_release):
        raise GovernanceValidationError(
            f"supplemental release {release_name} parent must own a declared phase"
        )
    custody = _require_mapping(
        release_mapping.get("publication_custody"),
        context=(
            f"plans/phase-ledger.yml release_trains.{release_name}.publication_custody"
        ),
    )
    if custody.get("version") != release_mapping.get("target_version"):
        raise GovernanceValidationError(
            f"supplemental release {release_name} custody version must match target_version"
        )
    if phase_ids_for(release_name):
        raise GovernanceValidationError(
            f"supplemental release {release_name} cannot own a declared phase"
        )
    return True


def declared_release_train_terminal(
    *,
    product: dict[str, Any],
    build: dict[str, Any],
    ledger: dict[str, Any],
    history: dict[str, Any],
    version: str,
) -> str:
    """Derive a declared terminal; this query never proves phase closure.

    Inputs belong to the existing canonical catalog. A protected consumer must
    authenticate their source and separately require applicable closure truth.
    Missing historical dependency topology is not reconstructed from phase names.
    """
    from .authored_phase_state import _phase_map

    version = _require_string(version, context="release train version")
    phases = _phase_map(product.get("execution_phases"), context="release product phases")
    planned = _phase_map(build.get("phase_sequence"), context="release build phases")
    retained = _phase_map(history.get("entries"), context="release retained phases")
    if phases.keys() != planned.keys():
        raise GovernanceValidationError("release train phase inventory is contradictory")
    for phase in phases.keys() & retained.keys():
        snapshot = retained[phase]
        if (
            snapshot.get("build_block") != phases[phase].get("build_block")
            or (snapshot.get("release_train") is not None
                and snapshot.get("release_train") != phases[phase].get("release_train"))
        ):
            raise GovernanceValidationError("release train retained phase identity is contradictory")
    known = phases.keys() | retained.keys()
    if any(re.fullmatch(r"P[0-9]{2,}", phase) is None for phase in known):
        raise GovernanceValidationError("release train phase identity is invalid")
    for phase, declaration in phases.items():
        block = _require_string(declaration.get("build_block"), context=f"release phase {phase} build block")
        if block != _require_string(planned[phase].get("build_block"), context=f"release build {phase} block"):
            raise GovernanceValidationError("release train build identity is contradictory")
    active = _require_mapping(ledger.get("active_phase"), context="release active phase")
    active_id = _require_string(active.get("id"), context="release active phase id")
    active_block = _require_string(active.get("build_block"), context="release active build block")
    if active_id not in phases or active_block != phases[active_id].get("build_block"):
        raise GovernanceValidationError("release train active phase is contradictory")
    release = _require_string(phases[active_id].get("release_train"), context="release train id")
    trains = _require_mapping(ledger.get("release_trains"), context="release trains")
    for phase, declaration in phases.items():
        owner = _require_string(declaration.get("release_train"), context=f"release phase {phase} owner")
        if owner not in trains:
            raise GovernanceValidationError("release train phase owner is undeclared")
    matching = []
    for name, value in trains.items():
        entry = _require_mapping(value, context=f"release train {name}")
        if entry.get("target_version") == version and entry.get("kind", "phase_train") == "phase_train":
            matching.append(name)
    if matching != [release]:
        raise GovernanceValidationError("release train version owner is absent or ambiguous")
    members = set(release_phase_ids(release, phases, retained))
    if not members or not members <= planned.keys():
        raise GovernanceValidationError("release train dependency inventory is incomplete")
    dependencies: dict[str, set[str]] = {}
    for phase, row in planned.items():
        values = row.get("hard_dependencies")
        if (
            not isinstance(values, list)
            or any(not isinstance(value, str) or value not in known for value in values)
            or len(set(values)) != len(values)
            or phase in values
        ):
            raise GovernanceValidationError("release train dependency inventory is invalid")
        dependencies[phase] = set(values)
    unresolved, resolved = set(planned), set(retained) - set(planned)
    while unresolved:
        ready = {phase for phase in unresolved if dependencies[phase] <= resolved}
        if not ready:
            raise GovernanceValidationError("release train dependency cycle is unresolved")
        unresolved -= ready
        resolved |= ready
    terminals = members - {
        dependency for phase in members for dependency in dependencies[phase] & members
    }
    if len(terminals) != 1:
        raise GovernanceValidationError("release train terminal phase is ambiguous")
    return next(iter(terminals))

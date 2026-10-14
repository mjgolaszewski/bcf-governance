"""Typed supplemental-publication validation for phase release catalogs."""

from __future__ import annotations

from collections.abc import Callable, Mapping
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

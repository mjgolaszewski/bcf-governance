"""Canonical installation scope for generated governance-pack surfaces."""

from __future__ import annotations

from pathlib import Path, PurePosixPath
from typing import Any, Mapping

import yaml  # type: ignore[import-untyped]


class PackInstallationScopeError(ValueError):
    """The canonical self-only pack inventory is malformed or ambiguous."""


def self_authority_pack_surfaces(repo_root: Path) -> dict[str, str]:
    """Return exact template paths owned by one self-authority overlay."""

    path = repo_root.resolve() / "governance/self-overlays.yml"
    try:
        payload = yaml.safe_load(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, yaml.YAMLError) as exc:
        raise PackInstallationScopeError("cannot read self-authority overlay contract") from exc
    overlays = payload.get("overlays") if isinstance(payload, Mapping) else None
    if not isinstance(overlays, list):
        raise PackInstallationScopeError("self-authority overlays must be a list")
    result: dict[str, str] = {}
    for raw in overlays:
        if not isinstance(raw, Mapping) or not isinstance(raw.get("id"), str):
            raise PackInstallationScopeError("self-authority overlay identity is invalid")
        surfaces = raw.get("adopter_excluded_pack_surfaces")
        if not isinstance(surfaces, list):
            raise PackInstallationScopeError(
                f"{raw['id']}.adopter_excluded_pack_surfaces must be a list"
            )
        for value in surfaces:
            candidate = PurePosixPath(value) if isinstance(value, str) else PurePosixPath(".")
            if (
                not isinstance(value, str)
                or candidate.is_absolute()
                or not candidate.parts
                or ".." in candidate.parts
                or candidate.as_posix() != value
            ):
                raise PackInstallationScopeError("self-only pack surface path is unsafe")
            if value in result:
                raise PackInstallationScopeError(
                    f"self-only pack surface {value} has multiple overlay owners"
                )
            result[value] = str(raw["id"])
    return result

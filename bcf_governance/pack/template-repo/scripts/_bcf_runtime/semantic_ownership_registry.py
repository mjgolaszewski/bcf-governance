"""Strict generalized semantic-ownership registry loading.

Copyright 2026 Michael Golaszewski.
Licensed under the MIT License.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import date
from pathlib import Path
from typing import Any

import yaml  # type: ignore[import-untyped]
from jsonschema import Draft202012Validator  # type: ignore[import-untyped]


REGISTRY_PATH = Path("governance/canonical-representations.yml")
SCHEMA_PATH = Path("schemas/canonical-representations.schema.json")


class SemanticOwnershipRegistryError(ValueError):
    """Raised when the sole semantic registry is malformed or ambiguous."""


@dataclass(frozen=True)
class RegistryEntry:
    semantic_id: str
    family: str
    lifecycle: str
    canonical_symbol: str
    owner_symbol: str
    authorized_constructors: frozenset[str]
    authorized_delegates: frozenset[str]
    blocking: bool
    raw: dict[str, Any]


@dataclass(frozen=True)
class Registry:
    phase: str
    mode: str
    unresolved_dynamic_policy: str
    authoritative_python_roots: tuple[str, ...]
    generated_mirror_roots: tuple[str, ...]
    entries: tuple[RegistryEntry, ...]
    raw: dict[str, Any]


def _mapping(path: Path) -> dict[str, Any]:
    try:
        value = yaml.safe_load(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, yaml.YAMLError) as exc:
        raise SemanticOwnershipRegistryError(f"cannot load {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise SemanticOwnershipRegistryError(f"{path} must contain an object")
    return value


def _validate_schema(repo_root: Path, payload: dict[str, Any]) -> None:
    try:
        schema = json.loads((repo_root / SCHEMA_PATH).read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise SemanticOwnershipRegistryError(f"cannot load {SCHEMA_PATH}: {exc}") from exc
    errors = sorted(
        Draft202012Validator(schema).iter_errors(payload),
        key=lambda error: ([str(value) for value in error.absolute_path], error.message),
    )
    if errors:
        first = errors[0]
        location = ".".join(str(value) for value in first.absolute_path)
        raise SemanticOwnershipRegistryError(
            f"{REGISTRY_PATH}{'.' + location if location else ''}: {first.message}"
        )


def _safe_roots(values: object, *, field: str) -> tuple[str, ...]:
    if not isinstance(values, list) or not values:
        raise SemanticOwnershipRegistryError(f"{field} must be a non-empty list")
    roots: list[str] = []
    for value in values:
        relative = Path(str(value))
        if (
            not isinstance(value, str)
            or not value
            or relative.is_absolute()
            or ".." in relative.parts
        ):
            raise SemanticOwnershipRegistryError(f"{field} contains an unsafe path")
        roots.append(relative.as_posix().rstrip("/"))
    return tuple(sorted(set(roots)))


def load_registry(repo_root: Path) -> Registry:
    """Load declarations only after a caller has completed source discovery."""
    payload = _mapping(repo_root / REGISTRY_PATH)
    _validate_schema(repo_root, payload)
    enforcement = payload["enforcement"]
    source_authority = payload["source_authority"]
    blocking_ids = set(enforcement["blocking_semantic_ids"])
    declared_families = set(enforcement["declared_families"])
    entries_payload = payload["representations"]
    semantic_ids = [str(value["semantic_id"]) for value in entries_payload]
    if len(semantic_ids) != len(set(semantic_ids)):
        raise SemanticOwnershipRegistryError("registry semantic IDs must be unique")
    if blocking_ids - set(semantic_ids):
        raise SemanticOwnershipRegistryError(
            "blocking semantic IDs must be present in the registry"
        )
    owners: dict[str, str] = {}
    entries: list[RegistryEntry] = []
    today = date.today()
    for raw in entries_payload:
        semantic_id = str(raw["semantic_id"])
        family = str(raw["family"])
        if family not in declared_families:
            raise SemanticOwnershipRegistryError(
                f"{semantic_id} family is not declared by enforcement"
            )
        canonical = str(raw["canonical_type"]["symbol"])
        owner = str(raw["authoritative_owner"]["symbol"])
        previous = owners.get(canonical)
        if previous is not None:
            raise SemanticOwnershipRegistryError(
                f"canonical symbol {canonical} has competing semantic IDs "
                f"{previous} and {semantic_id}"
            )
        owners[canonical] = semantic_id
        authorized = frozenset(str(value) for value in raw["authorized_constructors_and_factories"])
        if owner not in authorized:
            raise SemanticOwnershipRegistryError(
                f"{semantic_id} owner must be an authorized constructor"
            )
        for suppression in raw["narrow_suppressions"]:
            try:
                expires = date.fromisoformat(str(suppression["expires_on"]))
            except ValueError as exc:
                raise SemanticOwnershipRegistryError(
                    f"{semantic_id} suppression expiration is invalid"
                ) from exc
            if expires < today:
                raise SemanticOwnershipRegistryError(
                    f"{semantic_id} suppression expired on {expires.isoformat()}"
                )
        entries.append(
            RegistryEntry(
                semantic_id=semantic_id,
                family=family,
                lifecycle=str(raw["lifecycle"]),
                canonical_symbol=canonical,
                owner_symbol=owner,
                authorized_constructors=authorized,
                authorized_delegates=frozenset(
                    str(value) for value in raw["authorized_pure_delegates"]
                ),
                blocking=semantic_id in blocking_ids,
                raw=raw,
            )
        )
    return Registry(
        phase=str(enforcement["phase"]),
        mode=str(enforcement["default_mode"]),
        unresolved_dynamic_policy=str(enforcement["unresolved_dynamic_policy"]),
        authoritative_python_roots=_safe_roots(
            source_authority["authoritative_python_roots"],
            field="source_authority.authoritative_python_roots",
        ),
        generated_mirror_roots=tuple(
            sorted(str(value).rstrip("/") for value in source_authority["generated_mirror_roots"])
        ),
        entries=tuple(entries),
        raw=payload,
    )

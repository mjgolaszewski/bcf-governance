"""Aggregate independent semantic-adoption blockers before mutation.

Copyright 2026 Michael Golaszewski.
Licensed under the MIT License.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from .semantic_authority_contracts import (
    SemanticAuthorityError,
    _load_yaml,
    _validate_families,
    _validate_operations,
    _validate_secondary_coverage,
    collect_representation_provenance,
)
from .semantic_authority_migrations import (
    SemanticMigrationError,
    validate_exact_base_migrations,
)
from .semantic_ownership_registry import Registry


def validate_adoption_repository(
    repo_root: Path, inventory: dict[str, Any], registry: Registry
) -> None:
    """Report every independently evaluable semantic blocker in one pass."""
    blockers: list[tuple[str, str]] = []
    families: dict[str, Any] | None = None
    operations: dict[str, Any] | None = None

    try:
        families = _load_yaml(repo_root / "governance/semantic-families.yml")
        _validate_families(repo_root, families, registry, inventory)
    except SemanticAuthorityError as exc:
        blockers.append(("semantic_family_completeness", str(exc)))

    try:
        operations = _load_yaml(repo_root / "governance/application-operations.yml")
        _validate_operations(repo_root, operations, inventory)
    except SemanticAuthorityError as exc:
        blockers.append(("application_operation_inventory", str(exc)))

    provenance = None
    try:
        provenance = collect_representation_provenance(repo_root, registry, inventory)
        if families is not None:
            _validate_secondary_coverage(families, registry, provenance)
    except SemanticAuthorityError as exc:
        blockers.append(("representation_provenance", str(exc)))

    if families is not None and operations is not None:
        try:
            validate_exact_base_migrations(repo_root, families, operations, registry)
        except SemanticMigrationError as exc:
            blockers.append(("semantic_migration", str(exc)))

    if blockers:
        details = "; ".join(f"[{kind}] {message}" for kind, message in blockers)
        raise SemanticAuthorityError(
            f"semantic adoption has {len(blockers)} blocker(s): {details}"
        )

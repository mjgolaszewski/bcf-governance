"""Exact-base migration checks for governed semantic authority contracts.

Copyright 2026 Michael Golaszewski.
Licensed under the MIT License.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
from pathlib import Path
from typing import Any

import yaml  # type: ignore[import-untyped]

from .semantic_ownership_registry import Registry


class SemanticMigrationError(ValueError):
    """Raised when a semantic change lacks exact-base migration custody."""


def _stable_digest(payload: Any) -> str:
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(encoded).hexdigest()


def _git_yaml(repo_root: Path, base_sha: str, relative: Path) -> dict[str, Any] | None:
    result = subprocess.run(
        ["git", "show", f"{base_sha}:{relative.as_posix()}"],
        cwd=repo_root,
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        return None
    payload = yaml.safe_load(result.stdout)
    return payload if isinstance(payload, dict) else None


def _migration_index(*payloads: dict[str, Any]) -> set[tuple[str, ...]]:
    return {
        (
            str(row["subject_kind"]),
            str(row["subject_id"]),
            str(row["change"]),
            str(row["base_sha"]),
            str(row["previous_sha256"]),
            str(row["current_sha256"]),
        )
        for payload in payloads
        for row in payload.get("migrations", [])
    }


def _require_migration(
    migrations: set[tuple[str, ...]],
    *,
    kind: str,
    subject_id: str,
    change: str,
    base_sha: str,
    previous: Any,
    current: Any,
) -> None:
    key = (
        kind,
        subject_id,
        change,
        base_sha,
        _stable_digest(previous),
        _stable_digest(current),
    )
    if key not in migrations:
        raise SemanticMigrationError(
            f"{kind} {subject_id} {change} requires an exact-base semantic migration record"
        )


def _family_changes(
    old_payload: dict[str, Any],
    new_payload: dict[str, Any],
    migrations: set[tuple[str, ...]],
    base_sha: str,
) -> None:
    old = {str(row["id"]): row for row in old_payload.get("families", [])}
    new = {str(row["id"]): row for row in new_payload["families"]}
    for subject_id, previous in old.items():
        current = new.get(subject_id)
        if current is None:
            _require_migration(
                migrations,
                kind="family",
                subject_id=subject_id,
                change="retired",
                base_sha=base_sha,
                previous=previous,
                current=None,
            )
            continue
        downgraded = (
            previous.get("ownership_required") and not current.get("ownership_required")
        ) or (
            previous.get("significance") == "authoritative"
            and current.get("significance") != "authoritative"
        )
        if downgraded:
            _require_migration(
                migrations,
                kind="family",
                subject_id=subject_id,
                change="downgraded",
                base_sha=base_sha,
                previous=previous,
                current=current,
            )
        if previous.get("canonical_semantic_ids") != current.get("canonical_semantic_ids"):
            _require_migration(
                migrations,
                kind="family",
                subject_id=subject_id,
                change="reassigned",
                base_sha=base_sha,
                previous=previous,
                current=current,
            )


def _operation_changes(
    old_payload: dict[str, Any],
    new_payload: dict[str, Any],
    migrations: set[tuple[str, ...]],
    base_sha: str,
) -> None:
    old = {str(row["id"]): row for row in old_payload.get("operations", [])}
    new = {str(row["id"]): row for row in new_payload["operations"]}
    effect_fields = (
        "authoritative_read",
        "authoritative_mutation",
        "authority_conferral",
        "produces_projection",
        "model_callable",
        "allowed_mutation_ports",
        "allowed_authority_ports",
    )
    for subject_id, previous in old.items():
        current = new.get(subject_id)
        if current is None:
            _require_migration(
                migrations,
                kind="operation",
                subject_id=subject_id,
                change="retired",
                base_sha=base_sha,
                previous=previous,
                current=None,
            )
            continue
        if previous.get("semantic_kind") != current.get("semantic_kind"):
            _require_migration(
                migrations,
                kind="operation",
                subject_id=subject_id,
                change="semantic_kind_changed",
                base_sha=base_sha,
                previous=previous,
                current=current,
            )
        if any(previous.get(field) != current.get(field) for field in effect_fields):
            _require_migration(
                migrations,
                kind="operation",
                subject_id=subject_id,
                change="effect_changed",
                base_sha=base_sha,
                previous=previous,
                current=current,
            )


def _representation_changes(
    old_payload: dict[str, Any],
    registry: Registry,
    migrations: set[tuple[str, ...]],
    base_sha: str,
) -> None:
    old = {str(row["semantic_id"]): row for row in old_payload.get("representations", [])}
    new = {entry.semantic_id: entry.raw for entry in registry.entries}
    for subject_id, previous in old.items():
        current = new.get(subject_id)
        if current is None:
            _require_migration(
                migrations,
                kind="representation",
                subject_id=subject_id,
                change="retired",
                base_sha=base_sha,
                previous=previous,
                current=None,
            )
        elif previous.get("family") != current.get("family"):
            _require_migration(
                migrations,
                kind="representation",
                subject_id=subject_id,
                change="reassigned",
                base_sha=base_sha,
                previous=previous,
                current=current,
            )
    old_secondary = {
        str(row["id"]): row for row in old_payload.get("secondary_representations", [])
    }
    new_secondary = {
        str(row["id"]): row
        for row in registry.raw.get("secondary_representations", [])
    }
    for subject_id, previous in old_secondary.items():
        current = new_secondary.get(subject_id)
        if current is None:
            change = "retired"
        elif previous != current:
            change = (
                "exception_changed"
                if previous.get("classification") == "exception"
                else "recipe_changed"
            )
        else:
            continue
        _require_migration(
            migrations,
            kind="representation",
            subject_id=subject_id,
            change=change,
            base_sha=base_sha,
            previous=previous,
            current=current,
        )


def validate_exact_base_migrations(
    repo_root: Path,
    families: dict[str, Any],
    operations: dict[str, Any],
    registry: Registry,
) -> None:
    """Require typed custody for weakening or reassigning a governed contract."""
    base_sha = os.environ.get("BCF_PR_BASE_SHA")
    if not base_sha:
        return
    if not re.fullmatch(r"[a-f0-9]{40}", base_sha):
        raise SemanticMigrationError("BCF_PR_BASE_SHA must be an exact 40-character commit")
    old_families = _git_yaml(repo_root, base_sha, Path("governance/semantic-families.yml"))
    old_operations = _git_yaml(
        repo_root, base_sha, Path("governance/application-operations.yml")
    )
    old_registry = _git_yaml(
        repo_root, base_sha, Path("governance/canonical-representations.yml")
    )
    migrations = _migration_index(families, operations)
    if old_families is not None:
        _family_changes(old_families, families, migrations, base_sha)
    if old_operations is not None:
        _operation_changes(old_operations, operations, migrations, base_sha)
    if old_registry is not None:
        _representation_changes(old_registry, registry, migrations, base_sha)

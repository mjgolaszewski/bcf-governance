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
from .semantic_locking import atomic_write, prepend_compact_list_rows


class SemanticMigrationError(ValueError):
    """Raised when a semantic change lacks exact-base migration custody."""


def _stable_digest(payload: Any) -> str:
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(encoded).hexdigest()


_OPERATION_EFFECT_FIELDS = (
    "authoritative_read",
    "authoritative_mutation",
    "authority_conferral",
    "produces_projection",
    "model_callable",
    "allowed_mutation_ports",
    "allowed_authority_ports",
)


def _operation_change_kinds(
    previous: dict[str, Any], current: dict[str, Any] | None
) -> tuple[str, ...]:
    if current is None:
        return ("retired",)
    changes = []
    if previous.get("semantic_kind") != current.get("semantic_kind"):
        changes.append("semantic_kind_changed")
    if any(previous.get(field) != current.get(field) for field in _OPERATION_EFFECT_FIELDS):
        changes.append("effect_changed")
    return tuple(changes)


def _validate_exact_base(repo_root: Path, base_sha: str) -> None:
    if not re.fullmatch(r"[a-f0-9]{40}", base_sha):
        raise SemanticMigrationError("base SHA must be an exact 40-character commit")
    result = subprocess.run(
        ["git", "merge-base", "--is-ancestor", base_sha, "HEAD"],
        cwd=repo_root,
        capture_output=True,
        check=False,
    )
    if result.returncode != 0:
        raise SemanticMigrationError("semantic migration base is not an ancestor of HEAD")


def register_operation_migration(
    repo_root: Path,
    *,
    base_sha: str,
    subject_id: str,
    owner: str,
    reason: str,
    apply: bool,
) -> tuple[dict[str, Any], ...]:
    """Compute and register exact-base operation migrations without transcribed digests."""

    _validate_exact_base(repo_root, base_sha)
    relative = Path("governance/application-operations.yml")
    path = repo_root / relative
    if not path.is_file() or path.is_symlink():
        raise SemanticMigrationError("application-operation registry must be a regular file")
    previous_payload = _git_yaml(repo_root, base_sha, relative)
    current_payload = yaml.safe_load(path.read_text(encoding="utf-8"))
    if previous_payload is None or not isinstance(current_payload, dict):
        raise SemanticMigrationError("cannot load exact-base application-operation registries")
    previous_rows = {
        str(row["id"]): row for row in previous_payload.get("operations", [])
    }
    current_rows = {str(row["id"]): row for row in current_payload.get("operations", [])}
    previous = previous_rows.get(subject_id)
    if previous is None:
        raise SemanticMigrationError("operation migration subject is absent from exact base")
    current = current_rows.get(subject_id)
    changes = _operation_change_kinds(previous, current)
    if not changes:
        raise SemanticMigrationError("operation migration has no governed semantic change")
    owner_path = Path(owner)
    if owner_path.is_absolute() or ".." in owner_path.parts:
        raise SemanticMigrationError("operation migration owner must be repository-relative")
    resolved_owner = repo_root / owner_path
    if not resolved_owner.is_file() or resolved_owner.is_symlink():
        raise SemanticMigrationError("operation migration owner must be a regular file")
    if not reason.strip():
        raise SemanticMigrationError("operation migration reason must be non-empty")
    rows = tuple(
        {
            "subject_kind": "operation",
            "subject_id": subject_id,
            "change": change,
            "base_sha": base_sha,
            "previous_sha256": _stable_digest(previous),
            "current_sha256": _stable_digest(current),
            "owner": owner_path.as_posix(),
            "reason": reason.strip(),
        }
        for change in changes
    )
    key_fields = (
        "subject_kind", "subject_id", "change", "base_sha",
        "previous_sha256", "current_sha256",
    )
    existing_rows = {
        tuple(str(row[field]) for field in key_fields): row
        for row in current_payload.get("migrations", [])
    }
    for row in rows:
        key = tuple(str(row[field]) for field in key_fields)
        if key in existing_rows and existing_rows[key] != row:
            raise SemanticMigrationError(
                "computed operation migration conflicts with registered custody metadata"
            )
    missing = [
        row
        for row in rows
        if tuple(str(row[field]) for field in key_fields) not in existing_rows
    ]
    if not apply:
        if missing:
            raise SemanticMigrationError("computed operation migration is not registered")
        return rows
    if missing:
        migrations = current_payload.setdefault("migrations", [])
        if not isinstance(migrations, list):
            raise SemanticMigrationError("application-operation migrations must be a list")
        atomic_write(path, prepend_compact_list_rows(path.read_bytes(), "migrations", missing))
    return rows


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
        for change in _operation_change_kinds(previous, current):
            _require_migration(
                migrations,
                kind="operation",
                subject_id=subject_id,
                change=change,
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

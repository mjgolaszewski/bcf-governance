"""Semantic-custody integration for atomic governance-pack upgrades."""

from __future__ import annotations

from pathlib import Path
from typing import Protocol

from ..semantic_authority_commands import _lock
from .existing_adoption import existing_adoption_requires_history_for_upgrade


class InstallHistoryInputs(Protocol):
    """Inputs that can require authenticated Git custody in a transaction."""

    semantic_config_payload: object
    existing_adoption_inventory: object
    skip_validation: bool


def semantic_upgrade_requires_history(
    repo_root: Path, *, skip_validation: bool
) -> bool:
    """Return whether upgrade reconciliation needs authenticated Git inventory."""

    return (
        not skip_validation
        and (repo_root / "governance/semantic-lock.yml").is_file()
    )


def reconcile_upgrade_semantic_custody(
    repo_root: Path, *, skip_validation: bool
) -> None:
    """Converge semantic source custody before an upgrade reports success."""

    if semantic_upgrade_requires_history(repo_root, skip_validation=skip_validation):
        _lock(repo_root, apply=True)


def install_transaction_requires_history(
    repo_root: Path, inputs: InstallHistoryInputs
) -> bool:
    """Derive every governed reason an install transaction must retain Git."""

    return bool(
        inputs.semantic_config_payload is not None
        or getattr(inputs.existing_adoption_inventory, "source_commit", None) is not None
        or existing_adoption_requires_history_for_upgrade(repo_root)
        or semantic_upgrade_requires_history(
            repo_root, skip_validation=inputs.skip_validation
        )
    )

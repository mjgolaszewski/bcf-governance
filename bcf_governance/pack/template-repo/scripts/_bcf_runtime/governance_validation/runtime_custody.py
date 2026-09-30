"""Earliest deterministic runtime-custody validation boundary."""

from __future__ import annotations

from pathlib import Path

from ..governance_install.runtime_custody import (
    RUNTIME_LOCK_PATH,
    RuntimeCustodyError,
    RuntimeCustodyState,
    inspect_runtime_custody,
)
from ..runtime_capacity import executing_runtime_version
from .common import GovernanceValidationError


def validate_runtime_custody(repo_root: Path) -> None:
    """Reject stale or ambiguous persisted custody before broader validation."""

    if not (repo_root / RUNTIME_LOCK_PATH).exists():
        return
    try:
        snapshot = inspect_runtime_custody(repo_root)
    except RuntimeCustodyError as exc:
        raise GovernanceValidationError(str(exc)) from exc
    runtime_version = executing_runtime_version()
    if snapshot.version != runtime_version:
        raise GovernanceValidationError(
            "runtime_custody_version_mismatch: "
            f"installed={snapshot.version} executing={runtime_version}"
        )
    if snapshot.state is not RuntimeCustodyState.NORMALIZED_EXACT:
        raise GovernanceValidationError(
            "runtime_custody_not_normalized: " + snapshot.state.value
        )

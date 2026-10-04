"""Earliest deterministic runtime-custody validation boundary."""

from __future__ import annotations

from pathlib import Path

from ..governance_install.runtime_custody import (
    CANDIDATE_QUALIFICATION_PATH,
    RUNTIME_LOCK_PATH,
    RuntimeCustodyError,
    RuntimeCustodyState,
    inspect_runtime_custody,
)
from ..runtime_capacity import executing_runtime_version
from .common import GovernanceValidationError


def validate_runtime_custody(repo_root: Path) -> None:
    """Reject stale or ambiguous persisted custody before broader validation."""

    if not (
        (repo_root / RUNTIME_LOCK_PATH).exists()
        or (repo_root / CANDIDATE_QUALIFICATION_PATH).exists()
    ):
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
    if snapshot.state not in {
        RuntimeCustodyState.NORMALIZED_EXACT,
        RuntimeCustodyState.CANDIDATE_QUALIFICATION_EXACT,
    }:
        raise GovernanceValidationError(
            "runtime_custody_not_normalized: " + snapshot.state.value
        )

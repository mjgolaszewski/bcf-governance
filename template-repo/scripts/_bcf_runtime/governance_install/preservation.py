"""Compatibility projections over canonical runtime-custody classification."""

from __future__ import annotations

from pathlib import Path

from .runtime_custody import inspect_runtime_custody


def preserved_consumer_inventory(target_root: Path) -> dict[str, str]:
    """Return the consumer partition from the sole custody-state primitive."""

    snapshot = inspect_runtime_custody(target_root)
    return snapshot.consumer_preserved


def preserved_consumer_files(target_root: Path) -> frozenset[str]:
    """Return exact paths from the authenticated adopter-owned inventory."""

    return frozenset(preserved_consumer_inventory(target_root))

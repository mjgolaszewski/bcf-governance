"""Shared frozen reconciliation action contract for canonical projection owners."""
from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass

Action = Callable[[], object]


@dataclass(frozen=True)
class ReconcileStep:
    """One canonical projection owner with distinct check and apply actions."""

    step_id: str
    check: Action
    apply: Action
    apply_verifies: bool = False
    watch_paths: tuple[str, ...] | None = None


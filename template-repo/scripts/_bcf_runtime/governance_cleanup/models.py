"""Cleanup report models."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class CleanupAction:
    kind: str
    source: str
    destination: str | None
    reason: str
    safe_to_apply: bool


@dataclass(frozen=True)
class ManualAction:
    kind: str
    path: str
    reason: str
    llm_support: str


@dataclass(frozen=True)
class CleanupReport:
    status: str
    repo_root: str
    cleanup_contract: str | None
    applied: bool
    actions: list[CleanupAction]
    manual_actions: list[ManualAction]
    rewritten_files: list[str]
    warnings: list[str]

"""Pure cancellation and status-publication authority decisions."""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum


class CIDecisionError(ValueError):
    """Raised when authority observations are ambiguous or unauthenticated."""


class ExecutionStatus(StrEnum):
    QUEUED = "queued"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"


class StatusContext(StrEnum):
    PULL_REQUEST = "bcf/pr-certification"
    EXACT_MAIN = "bcf/exact-main-certification"
    AUTHORITY_CANARY = "bcf/authority-canary"


class StatusConclusion(StrEnum):
    PENDING = "pending"
    SUCCESS = "success"
    FAILURE = "failure"
    OBSOLETE = "obsolete"


@dataclass(frozen=True)
class ChildExecution:
    run_id: str
    owner_control_plane_run_id: str
    owner_control_plane_attempt: int
    status: ExecutionStatus
    authenticated: bool


@dataclass(frozen=True)
class CancellationDecision:
    targets: tuple[str, ...]
    rejected: tuple[tuple[str, str], ...]


@dataclass(frozen=True)
class StatusObservation:
    context: StatusContext
    subject_sha: str
    admission_ordinal: int
    control_plane_attempt: int
    conclusion: StatusConclusion
    authenticated: bool = True


@dataclass(frozen=True)
class StatusDecision:
    publish: bool
    reason: str
    selected: StatusObservation


def owned_cancellation_targets(
    children: tuple[ChildExecution, ...],
    *,
    owner_control_plane_run_id: str,
    owner_control_plane_attempt: int,
) -> CancellationDecision:
    """Select only authenticated unfinished children owned by one exact attempt."""

    if not owner_control_plane_run_id or owner_control_plane_attempt < 1:
        raise CIDecisionError("cancellation owner identity must be complete")
    run_ids = [child.run_id for child in children]
    if not all(run_ids) or len(set(run_ids)) != len(run_ids):
        raise CIDecisionError("child run identities must be unique and non-empty")
    targets: list[str] = []
    rejected: list[tuple[str, str]] = []
    for child in children:
        if not child.authenticated:
            rejected.append((child.run_id, "unauthenticated"))
        elif (
            child.owner_control_plane_run_id != owner_control_plane_run_id
            or child.owner_control_plane_attempt != owner_control_plane_attempt
        ):
            rejected.append((child.run_id, "foreign_owner"))
        elif child.status is ExecutionStatus.COMPLETED:
            rejected.append((child.run_id, "already_terminal"))
        else:
            targets.append(child.run_id)
    return CancellationDecision(tuple(sorted(targets)), tuple(sorted(rejected)))


def decide_status_publication(
    *,
    proposed: StatusObservation,
    current: StatusObservation | None,
    trusted_publisher: bool,
    current_default_main_sha: str | None = None,
) -> StatusDecision:
    """Select the latest authenticated status without crossing status contexts."""

    if not trusted_publisher:
        raise CIDecisionError("candidate execution cannot publish status")
    if not proposed.authenticated:
        raise CIDecisionError("proposed status observation is not authenticated")
    if proposed.admission_ordinal < 1 or proposed.control_plane_attempt < 1:
        raise CIDecisionError("status authority ordinal and attempt must be positive")
    if (
        proposed.context in {StatusContext.EXACT_MAIN, StatusContext.AUTHORITY_CANARY}
        and proposed.subject_sha != current_default_main_sha
    ):
        obsolete = StatusObservation(
            context=proposed.context,
            subject_sha=proposed.subject_sha,
            admission_ordinal=proposed.admission_ordinal,
            control_plane_attempt=proposed.control_plane_attempt,
            conclusion=StatusConclusion.OBSOLETE,
            authenticated=True,
        )
        return StatusDecision(False, "default_main_moved", obsolete)
    if current is None:
        return StatusDecision(True, "no_existing_status", proposed)
    if not current.authenticated:
        raise CIDecisionError("current published status is not authenticated")
    if current.context is not proposed.context or current.subject_sha != proposed.subject_sha:
        return StatusDecision(True, "independent_status_identity", proposed)
    current_order = (current.admission_ordinal, current.control_plane_attempt)
    proposed_order = (proposed.admission_ordinal, proposed.control_plane_attempt)
    if proposed_order < current_order:
        return StatusDecision(False, "older_authority_cannot_overwrite", current)
    if proposed_order == current_order and proposed.conclusion != current.conclusion:
        if current.conclusion is StatusConclusion.PENDING and proposed.conclusion in {
            StatusConclusion.SUCCESS,
            StatusConclusion.FAILURE,
        }:
            return StatusDecision(True, "pending_authority_became_terminal", proposed)
        raise CIDecisionError("equal terminal authority cannot publish conflicting conclusions")
    return StatusDecision(
        proposed_order > current_order,
        "newer_authority" if proposed_order > current_order else "idempotent_replay",
        proposed,
    )

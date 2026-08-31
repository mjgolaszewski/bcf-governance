from __future__ import annotations

import pytest

from bcf_governance.tooling.ci_authority_decisions import (
    CIDecisionError,
    ChildExecution,
    ExecutionStatus,
    StatusConclusion,
    StatusContext,
    StatusObservation,
    decide_status_publication,
    owned_cancellation_targets,
)


SHA_A = "a" * 40
SHA_B = "b" * 40


def _status(
    *,
    context: StatusContext = StatusContext.EXACT_MAIN,
    subject: str = SHA_A,
    ordinal: int = 1,
    attempt: int = 1,
    conclusion: StatusConclusion = StatusConclusion.SUCCESS,
) -> StatusObservation:
    return StatusObservation(context, subject, ordinal, attempt, conclusion)


def test_cancellation_targets_only_authenticated_unfinished_owned_children() -> None:
    children = (
        ChildExecution("owned-running", "control", 2, ExecutionStatus.IN_PROGRESS, True),
        ChildExecution("owned-queued", "control", 2, ExecutionStatus.QUEUED, True),
        ChildExecution("owned-done", "control", 2, ExecutionStatus.COMPLETED, True),
        ChildExecution("foreign", "other", 2, ExecutionStatus.IN_PROGRESS, True),
        ChildExecution("untrusted", "control", 2, ExecutionStatus.IN_PROGRESS, False),
    )

    decision = owned_cancellation_targets(
        children,
        owner_control_plane_run_id="control",
        owner_control_plane_attempt=2,
    )

    assert decision.targets == ("owned-queued", "owned-running")
    assert dict(decision.rejected) == {
        "foreign": "foreign_owner",
        "owned-done": "already_terminal",
        "untrusted": "unauthenticated",
    }


def test_ambiguous_child_identity_blocks_cancellation() -> None:
    child = ChildExecution("duplicate", "control", 1, ExecutionStatus.QUEUED, True)
    with pytest.raises(CIDecisionError, match="unique"):
        owned_cancellation_targets(
            (child, child),
            owner_control_plane_run_id="control",
            owner_control_plane_attempt=1,
        )


def test_candidate_execution_cannot_publish_status() -> None:
    with pytest.raises(CIDecisionError, match="candidate execution"):
        decide_status_publication(
            proposed=_status(),
            current=None,
            trusted_publisher=False,
            current_default_main_sha=SHA_A,
        )


def test_older_completion_cannot_overwrite_newer_authority() -> None:
    current = _status(ordinal=3, conclusion=StatusConclusion.FAILURE)
    proposed = _status(ordinal=2, conclusion=StatusConclusion.SUCCESS)

    decision = decide_status_publication(
        proposed=proposed,
        current=current,
        trusted_publisher=True,
        current_default_main_sha=SHA_A,
    )

    assert decision.publish is False
    assert decision.reason == "older_authority_cannot_overwrite"
    assert decision.selected == current


def test_later_failure_revokes_earlier_success() -> None:
    decision = decide_status_publication(
        proposed=_status(ordinal=4, conclusion=StatusConclusion.FAILURE),
        current=_status(ordinal=3, conclusion=StatusConclusion.SUCCESS),
        trusted_publisher=True,
        current_default_main_sha=SHA_A,
    )

    assert decision.publish is True
    assert decision.reason == "newer_authority"
    assert decision.selected.conclusion is StatusConclusion.FAILURE


def test_moved_main_is_obsolete_and_not_published() -> None:
    decision = decide_status_publication(
        proposed=_status(subject=SHA_A),
        current=None,
        trusted_publisher=True,
        current_default_main_sha=SHA_B,
    )

    assert decision.publish is False
    assert decision.reason == "default_main_moved"
    assert decision.selected.conclusion is StatusConclusion.OBSOLETE


def test_pr_and_exact_main_statuses_have_independent_identity() -> None:
    decision = decide_status_publication(
        proposed=_status(
            context=StatusContext.PULL_REQUEST,
            subject=SHA_B,
            ordinal=1,
        ),
        current=_status(context=StatusContext.EXACT_MAIN, ordinal=99),
        trusted_publisher=True,
    )

    assert decision.publish is True
    assert decision.reason == "independent_status_identity"


@pytest.mark.parametrize(
    "terminal", [StatusConclusion.SUCCESS, StatusConclusion.FAILURE]
)
def test_equal_pending_authority_can_publish_its_terminal_state(
    terminal: StatusConclusion,
) -> None:
    decision = decide_status_publication(
        proposed=_status(conclusion=terminal),
        current=_status(conclusion=StatusConclusion.PENDING),
        trusted_publisher=True,
        current_default_main_sha=SHA_A,
    )

    assert decision.publish is True
    assert decision.reason == "pending_authority_became_terminal"
    assert decision.selected.conclusion is terminal


def test_equal_terminal_authority_cannot_publish_conflicting_status() -> None:
    with pytest.raises(CIDecisionError, match="terminal authority"):
        decide_status_publication(
            proposed=_status(conclusion=StatusConclusion.FAILURE),
            current=_status(conclusion=StatusConclusion.SUCCESS),
            trusted_publisher=True,
            current_default_main_sha=SHA_A,
        )

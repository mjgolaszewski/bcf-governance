from __future__ import annotations

import copy

import pytest

from bcf_governance.tooling.ci_recovery_frontier import (
    RecoveryFrontierError,
    compile_recovery_frontier,
    controller_transition_frontier,
    provider_read_frontier,
    protected_merge_frontier,
    submission_frontier,
)


IDENTITY = {
    "repository": "owner/repository",
    "base_sha": "1" * 40,
    "head_sha": "2" * 40,
    "tree_sha": "3" * 40,
}


def test_candidate_submission_has_one_derived_action() -> None:
    initial = submission_frontier(identity=IDENTITY, prospective_proved=False)
    proved = submission_frontier(identity=IDENTITY, prospective_proved=True)
    assert initial["action"]["kind"] == "run_prospective_and_push"
    assert initial["successor"] == "provider_proof_required"
    assert proved["action"]["kind"] == "push_exact_candidate"
    assert proved["successor"] == "pr_provider_pending"
    assert initial["release_authority"] is False
    assert len(str(initial["frontier_sha256"])) == 64


def test_proved_candidate_derives_native_protected_auto_merge() -> None:
    identity = {
        **IDENTITY,
        "repository_id": "17",
        "pull_request": "7",
        "protection_sha256": "9" * 64,
    }
    frontier = protected_merge_frontier(
        identity=identity,
        state="prospective_proved",
        certification_identity="prospective:" + "4" * 64,
    )
    assert frontier["action"]["kind"] == "request_provider_auto_merge"
    assert frontier["successor"] == "pr_pending"
    assert frontier["release_authority"] is False


@pytest.mark.parametrize(
    ("outcome", "action"),
    [
        ("transient", "retry_identical_read"),
        ("success", "consume_exact_read"),
        ("terminal", "stop"),
        ("exhausted", "stop"),
    ],
)
def test_provider_retry_taxonomy_is_closed(outcome: str, action: str) -> None:
    assert provider_read_frontier(
        request_sha256="4" * 64, outcome=outcome
    )["action"]["kind"] == action


def test_ambiguous_or_overlapping_frontier_fails_closed() -> None:
    with pytest.raises(RecoveryFrontierError, match="no governed recovery edge"):
        compile_recovery_frontier(
            operation="candidate_submission",
            state="carry_on",
            identity=IDENTITY,
            owner="owner",
        )
    with pytest.raises(RecoveryFrontierError, match="preserved and invalidated"):
        compile_recovery_frontier(
            operation="candidate_submission",
            state="exact_candidate",
            identity=IDENTITY,
            owner="owner",
            preserve=("proof",),
            invalidate=("proof",),
        )


def _decision(decision: str) -> dict[str, object]:
    subject = {"commit_sha": "5" * 40, "tree_sha": "6" * 40}
    if decision == "no_transition":
        return {
            "decision": decision,
            "subject": subject,
            "controller_custody": {"controller": {"commit_sha": "7" * 40}},
        }
    if decision == "routine_transition_authorized":
        return {
            "decision": decision,
            "transition_class": "runtime_only",
            "transition": {
                "subject": subject,
                "authority": {"installed_controller_commit": "7" * 40},
                "artifact": {"commit_sha": "8" * 40},
            },
        }
    return {
        "decision": decision,
        "subject": subject,
        "authority": {"installed_controller_commit": "7" * 40},
        "target": {"BCF_BOOTSTRAP_COMMIT_SHA": "8" * 40},
        "alternate_lane": {
            "id": "ordinary_protected_n_n_plus_1",
            "required_sequence": ["derive"],
        },
    }


@pytest.mark.parametrize(
    ("decision", "action"),
    [
        ("no_transition", "emit_no_transition"),
        ("routine_transition_authorized", "invoke_routine_transition"),
        ("alternate_lane_required", "invoke_exact_alternate_lane"),
    ],
)
def test_controller_decision_maps_to_one_closed_action(
    decision: str, action: str
) -> None:
    assert controller_transition_frontier(_decision(decision))["action"]["kind"] == action


def test_controller_target_and_installation_cannot_silently_collapse() -> None:
    value = _decision("routine_transition_authorized")
    value = copy.deepcopy(value)
    value["transition"]["artifact"]["commit_sha"] = "7" * 40  # type: ignore[index]
    with pytest.raises(RecoveryFrontierError, match="silently collapses"):
        controller_transition_frontier(value)

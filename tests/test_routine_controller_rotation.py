from __future__ import annotations

import copy
from pathlib import Path

import pytest

from bcf_governance.tooling.routine_controller_rotation import (
    RoutineRotationError,
    select_active_transition,
    transition_id,
    validate_transition,
)


ROOT = Path(__file__).resolve().parents[1]
OLD = "1" * 40
NEW = "2" * 40
TREE = "3" * 40
DIGEST = "sha256:" + "4" * 64
POLICY = "5" * 64


def _receipt(*, state: str = "active") -> dict:
    identity = transition_id(
        repository_id="1207503211", installed_commit=OLD,
        subject_commit=NEW, subject_tree=TREE, artifact_digest=DIGEST,
    )
    proofs = lambda run: [
        {"runner": runner, "controller_commit": NEW, "run_id": run, "run_attempt": "1", "job_id": str(int(run) * 10 + index)}
        for index, runner in enumerate(("bcf-trusted-control-1", "bcf-trusted-control-2"), 1)
    ]
    value = {
        "schema_version": "1.0", "transition_id": identity, "state": state,
        "repository": {"id": "1207503211", "full_name": "mjgolaszewski/bcf-governance"},
        "subject": {"commit_sha": NEW, "tree_sha": TREE},
        "authority": {"installed_controller_commit": OLD, "admission_run_id": "10", "admission_run_attempt": "1", "implementation_pr": "300", "policy_before_sha256": POLICY, "policy_after_sha256": POLICY},
        "artifact": {"id": "20", "name": f"bcf-trusted-control-{NEW}-1", "provider_digest": DIGEST, "wheel_sha256": "6" * 64, "run_id": "10", "run_attempt": "1", "commit_sha": NEW, "tree_sha": TREE},
        "required_runners": ["bcf-trusted-control-1", "bcf-trusted-control-2"],
        "bootstrap": proofs("30"), "probe": proofs("40"), "promotion": proofs("50"),
    }
    if state == "active":
        value["activation"] = {"transition_id": identity, "authorizing_controller_commit": OLD, "run_id": "60", "run_attempt": "1"}
    return value


def test_active_transition_is_exact_and_selectable() -> None:
    receipt = _receipt()
    assert validate_transition(ROOT, receipt) == receipt
    assert select_active_transition(
        ROOT, [receipt], repository_id="1207503211",
        installed_commit=OLD, current_main_commit=NEW,
    ) == receipt


@pytest.mark.parametrize("field", ["repository", "installed", "subject"])
def test_wrong_scope_or_replayed_transition_is_not_selected(field: str) -> None:
    values = {"repository_id": "1207503211", "installed_commit": OLD, "current_main_commit": NEW}
    values[{"repository": "repository_id", "installed": "installed_commit", "subject": "current_main_commit"}[field]] = "9" * 40 if field != "repository" else "9"
    assert select_active_transition(ROOT, [_receipt()], **values) is None


def test_candidate_cannot_authorize_its_own_activation() -> None:
    receipt = _receipt()
    receipt["activation"]["authorizing_controller_commit"] = NEW
    with pytest.raises(RoutineRotationError, match="cannot authorize itself"):
        validate_transition(ROOT, receipt)


@pytest.mark.parametrize("stage", ["bootstrap", "probe", "promotion"])
def test_partial_or_mixed_runner_proof_fails_closed(stage: str) -> None:
    receipt = _receipt()
    receipt[stage].pop()
    with pytest.raises(RoutineRotationError, match="runner inventory"):
        validate_transition(ROOT, receipt)


def test_policy_change_is_not_a_routine_rotation() -> None:
    receipt = _receipt()
    receipt["authority"]["policy_after_sha256"] = "7" * 64
    with pytest.raises(RoutineRotationError, match="cannot change authorization policy"):
        validate_transition(ROOT, receipt)


def test_artifact_substitution_and_ambiguous_activation_fail_closed() -> None:
    receipt = _receipt()
    substituted = copy.deepcopy(receipt)
    substituted["artifact"]["tree_sha"] = "8" * 40
    with pytest.raises(RoutineRotationError, match="differs from transition subject"):
        validate_transition(ROOT, substituted)
    with pytest.raises(RoutineRotationError, match="ambiguous"):
        select_active_transition(
            ROOT, [receipt, copy.deepcopy(receipt)], repository_id="1207503211",
            installed_commit=OLD, current_main_commit=NEW,
        )

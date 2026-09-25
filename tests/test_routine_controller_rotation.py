from __future__ import annotations

import copy
from pathlib import Path

import pytest

from bcf_governance.tooling.routine_controller_rotation import (
    RoutineRotationError,
    advance_transition,
    effective_controller_pin,
    select_active_transition,
    select_controller_chain,
    transition_follows_normalization,
    transition_id,
    validate_transition,
)


ROOT = Path(__file__).resolve().parents[1]
OLD = "1" * 40
NEW = "2" * 40
TREE = "3" * 40
DIGEST = "sha256:" + "4" * 64
POLICY = "5" * 64


def test_source_normalization_absorbs_only_older_active_transitions() -> None:
    older = "1" * 40
    normalized = "2" * 40
    newer = "3" * 40
    ancestry = {(normalized, newer): True, (older, normalized): True}
    relation = lambda base, head: ancestry.get((base, head), base == head)
    assert transition_follows_normalization(
        transition_subject=older,
        normalization_subject=normalized,
        is_ancestor=relation,
    ) is False
    assert transition_follows_normalization(
        transition_subject=newer,
        normalization_subject=normalized,
        is_ancestor=relation,
    ) is True
    with pytest.raises(RoutineRotationError, match="not ordered"):
        transition_follows_normalization(
            transition_subject="4" * 40,
            normalization_subject=normalized,
            is_ancestor=relation,
        )


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
        "bootstrap": proofs("30") if state in {"installing", "probed", "active", "superseded"} else [],
        "probe": proofs("40") if state in {"probed", "active", "superseded"} else [],
        "promotion": proofs("50") if state in {"active", "superseded"} else [],
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


def test_transition_advances_only_through_authenticated_states() -> None:
    authorized = _receipt(state="authorized")
    installing = advance_transition(
        ROOT, authorized, state="installing", proofs=_receipt()["bootstrap"]
    )
    probed = advance_transition(
        ROOT, installing, state="probed", proofs=_receipt()["probe"]
    )
    active = advance_transition(
        ROOT,
        probed,
        state="active",
        proofs=_receipt()["promotion"],
        activation=_receipt()["activation"],
    )
    assert active == _receipt()
    with pytest.raises(RoutineRotationError, match="not canonical"):
        advance_transition(ROOT, authorized, state="active")


def test_linear_transition_chain_projects_effective_controller() -> None:
    first = _receipt()
    second = copy.deepcopy(first)
    second["authority"]["installed_controller_commit"] = NEW
    second["subject"] = {"commit_sha": "7" * 40, "tree_sha": "8" * 40}
    second["artifact"].update(
        {
            "id": "21",
            "name": f"bcf-trusted-control-{'7' * 40}-1",
            "commit_sha": "7" * 40,
            "tree_sha": "8" * 40,
            "provider_digest": "sha256:" + "9" * 64,
            "wheel_sha256": "a" * 64,
        }
    )
    second["transition_id"] = transition_id(
        repository_id="1207503211",
        installed_commit=NEW,
        subject_commit="7" * 40,
        subject_tree="8" * 40,
        artifact_digest="sha256:" + "9" * 64,
    )
    for stage in ("bootstrap", "probe", "promotion"):
        for proof in second[stage]:
            proof["controller_commit"] = "7" * 40
    second["activation"].update(
        {
            "transition_id": second["transition_id"],
            "authorizing_controller_commit": NEW,
        }
    )
    chain = select_controller_chain(
        ROOT,
        [first, second],
        repository_id="1207503211",
        baseline_installed_commit=OLD,
        ancestor_commits=[NEW, "7" * 40],
    )
    pin = effective_controller_pin({"legacy": "ignored"}, chain)
    assert [value["artifact"]["commit_sha"] for value in chain] == [NEW, "7" * 40]
    assert pin["BCF_BOOTSTRAP_COMMIT_SHA"] == "7" * 40


def test_chain_replay_fork_and_disconnected_receipts_fail_closed() -> None:
    receipt = _receipt()
    with pytest.raises(RoutineRotationError, match="replay"):
        select_controller_chain(
            ROOT,
            [receipt, copy.deepcopy(receipt)],
            repository_id="1207503211",
            baseline_installed_commit=OLD,
            ancestor_commits=[NEW],
        )
    fork = copy.deepcopy(receipt)
    fork["subject"] = {"commit_sha": "7" * 40, "tree_sha": "8" * 40}
    fork["artifact"]["commit_sha"] = "7" * 40
    fork["artifact"]["tree_sha"] = "8" * 40
    fork["artifact"]["name"] = f"bcf-trusted-control-{'7' * 40}-1"
    fork["artifact"]["provider_digest"] = "sha256:" + "9" * 64
    fork["transition_id"] = transition_id(
        repository_id="1207503211", installed_commit=OLD,
        subject_commit="7" * 40, subject_tree="8" * 40,
        artifact_digest="sha256:" + "9" * 64,
    )
    for stage in ("bootstrap", "probe", "promotion"):
        for proof in fork[stage]:
            proof["controller_commit"] = "7" * 40
    fork["activation"]["transition_id"] = fork["transition_id"]
    with pytest.raises(RoutineRotationError, match="ambiguous"):
        select_controller_chain(
            ROOT,
            [receipt, fork],
            repository_id="1207503211",
            baseline_installed_commit=OLD,
            ancestor_commits=[NEW, "7" * 40],
        )

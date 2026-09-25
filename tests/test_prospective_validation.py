from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest

from bcf_governance.tooling.local_pr import LocalPRContext
from bcf_governance.tooling import local_pr as prospective


REPO_ROOT = Path(__file__).resolve().parents[1]
HEAD = "1" * 40
TREE = "2" * 40
BASE = "3" * 40
BASE_TREE = "5" * 40
POLICY_IDENTITY = {
    "source": {
        "commit_sha": BASE,
        "tree_sha": BASE_TREE,
        "policy_sha256": "6" * 64,
    },
    "candidate": {
        "commit_sha": HEAD,
        "tree_sha": TREE,
        "policy_sha256": "6" * 64,
    },
}
TRAIN = {
    "semantic_intent": "workitem",
    "evaluation_target": "P27-P0-03",
    "subject_commit": HEAD,
    "subject_tree": TREE,
}


class Result:
    def __init__(self, stdout: str = "", returncode: int = 0) -> None:
        self.stdout = stdout
        self.stderr = ""
        self.returncode = returncode


def _runner(command: list[str], **_kwargs: object) -> Result:
    values = {
        ("git", "rev-parse", "--verify", "HEAD"): HEAD,
        ("git", "rev-parse", "--verify", "HEAD^{tree}"): TREE,
        ("git", "status", "--porcelain=v1", "--untracked-files=all", "--ignored=no"): "",
        ("git", "diff", "--name-only", BASE, HEAD): "source.py\n",
    }
    return Result(values[tuple(command)])


def _compiled(mode: str = "workitem", target: str | None = "P27-P0-03") -> SimpleNamespace:
    return SimpleNamespace(
        workflows=[
            {
                "id": "exact-main",
                "jobs": [
                    {
                        "id": "admit",
                        "executor": {
                            "evaluation_mode": mode,
                            "evaluation_target": target,
                        },
                    },
                    {
                        "id": "governance",
                        "executor": {
                            "inputs": {
                                "evaluation_mode": mode,
                                "evaluation_target": target,
                            }
                        },
                    },
                ],
            }
        ]
    )


def _front_door(monkeypatch: pytest.MonkeyPatch, trace: list[str]) -> None:
    monkeypatch.setattr(
        prospective,
        "resolve_local_pr_context",
        lambda *_args, **_kwargs: LocalPRContext("origin", "main", BASE, HEAD, "feature"),
    )
    monkeypatch.setattr(
        prospective,
        "reconcile_steps",
        lambda *_args, **_kwargs: (
            SimpleNamespace(check=lambda: trace.append("reconcile")),
        ),
    )
    monkeypatch.setattr(prospective, "validate_ci_graph", lambda *_args: _compiled())
    monkeypatch.setattr(
        prospective,
        "exact_main_evaluation",
        lambda workflows: SimpleNamespace(
            mode=workflows[0]["jobs"][0]["executor"]["evaluation_mode"],
            target=workflows[0]["jobs"][0]["executor"].get("evaluation_target"),
        ),
    )
    monkeypatch.setattr(
        prospective,
        "_controller_policy_identity",
        lambda *_args, **_kwargs: POLICY_IDENTITY,
    )
    monkeypatch.setattr(
        prospective, "_validate_train_telemetry", lambda *_args: None
    )


def test_deterministic_walk_orders_reconcile_before_preflight_and_never_claims_authority(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    trace: list[str] = []
    _front_door(monkeypatch, trace)

    def preflight(*_args: object, **_kwargs: object) -> dict:
        trace.append("preflight")
        return {"status": "pass", "self_controller": 24}

    monkeypatch.setattr(prospective, "run_preflight", preflight)
    report = prospective._run_prospective_train(
        tmp_path,
        **TRAIN,
        python_executable=Path("/python"),
        execute_evidence=False,
        runner=_runner,
    )
    assert trace == ["reconcile", "preflight"]
    assert report["status"] == "deterministic_front_door_pass"
    assert report["provider_authority_substituted"] is False
    assert report["post_merge_evaluation"] == {
        "mode": "workitem",
        "target": "P27-P0-03",
    }


def test_stale_projection_fails_before_preflight_or_evidence(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    trace: list[str] = []
    monkeypatch.setattr(
        prospective,
        "resolve_local_pr_context",
        lambda *_args, **_kwargs: LocalPRContext("origin", "main", BASE, HEAD, "feature"),
    )

    def reject() -> None:
        trace.append("reconcile")
        raise prospective.ReconcileError("stale manifest")

    monkeypatch.setattr(
        prospective,
        "reconcile_steps",
        lambda *_args, **_kwargs: (SimpleNamespace(check=reject),),
    )
    monkeypatch.setattr(
        prospective,
        "run_preflight",
        lambda *_args, **_kwargs: pytest.fail("preflight ran after stale projection"),
    )
    with pytest.raises(prospective.ProspectiveValidationError, match="stale manifest"):
        prospective._run_prospective_train(
            tmp_path,
            **TRAIN,
            python_executable=Path("/python"),
            execute_evidence=False,
            runner=_runner,
        )
    assert trace == ["reconcile"]


def test_graph_intent_mismatch_fails_before_evidence(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    trace: list[str] = []
    _front_door(monkeypatch, trace)
    monkeypatch.setattr(
        prospective,
        "exact_main_evaluation",
        lambda *_args: (_ for _ in ()).throw(
            prospective.CIGraphError("exact-main admission and governance evaluation intents differ")
        ),
    )
    with pytest.raises(
        prospective.ProspectiveValidationError,
        match="evaluation intents differ",
    ):
        prospective._run_prospective_train(
            tmp_path,
            **TRAIN,
            python_executable=Path("/python"),
            execute_evidence=False,
            runner=_runner,
        )


def test_exact_subject_input_rejects_wrong_tree_before_preflight(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    trace: list[str] = []
    _front_door(monkeypatch, trace)
    monkeypatch.setattr(
        prospective,
        "run_preflight",
        lambda *_args, **_kwargs: pytest.fail("preflight ran for wrong subject"),
    )
    with pytest.raises(
        prospective.ProspectiveValidationError,
        match="does not match the exact committed tree",
    ):
        prospective._run_prospective_train(
            tmp_path,
            **{**TRAIN, "subject_tree": "9" * 40},
            python_executable=Path("/python"),
            execute_evidence=False,
            runner=_runner,
        )


def test_typed_intent_must_match_canonical_graph_before_preflight(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    trace: list[str] = []
    _front_door(monkeypatch, trace)
    monkeypatch.setattr(
        prospective,
        "run_preflight",
        lambda *_args, **_kwargs: pytest.fail("preflight ran for wrong intent"),
    )
    with pytest.raises(
        prospective.ProspectiveValidationError,
        match="intent/target does not match",
    ):
        prospective._run_prospective_train(
            tmp_path,
            **{
                **TRAIN,
                "semantic_intent": "closure",
                "evaluation_target": None,
            },
            python_executable=Path("/python"),
            execute_evidence=False,
            runner=_runner,
        )


def test_terminal_reauthentication_rejects_base_movement(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    trace: list[str] = []
    contexts = iter(
        (
            LocalPRContext("origin", "main", BASE, HEAD, "feature"),
            LocalPRContext("origin", "main", "4" * 40, HEAD, "feature"),
        )
    )
    monkeypatch.setattr(
        prospective,
        "resolve_local_pr_context",
        lambda *_args, **_kwargs: next(contexts),
    )
    monkeypatch.setattr(
        prospective,
        "reconcile_steps",
        lambda *_args, **_kwargs: (
            SimpleNamespace(check=lambda: trace.append("reconcile")),
        ),
    )
    monkeypatch.setattr(prospective, "validate_ci_graph", lambda *_args: _compiled())
    monkeypatch.setattr(
        prospective,
        "exact_main_evaluation",
        lambda *_args: SimpleNamespace(mode="workitem", target="P27-P0-03"),
    )
    monkeypatch.setattr(
        prospective,
        "run_preflight",
        lambda *_args, **_kwargs: {"status": "pass", "self_controller": 24},
    )
    monkeypatch.setattr(
        prospective,
        "_controller_policy_identity",
        lambda *_args, **_kwargs: POLICY_IDENTITY,
    )
    with pytest.raises(
        prospective.ProspectiveValidationError,
        match="changed during validation",
    ):
        prospective._run_prospective_train(
            tmp_path,
            **TRAIN,
            python_executable=Path("/python"),
            execute_evidence=False,
            runner=_runner,
        )


def test_full_walk_preserves_provider_boundary_and_exact_scope(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    trace: list[str] = []
    _front_door(monkeypatch, trace)
    session = SimpleNamespace(
        manifest_path=tmp_path / "session.json",
        root=tmp_path / "session",
    )
    monkeypatch.setattr(prospective, "select_session", lambda *_args: session)
    monkeypatch.setattr(
        prospective,
        "run_preflight",
        lambda *_args, **_kwargs: {
            "status": "pass",
            "self_controller": {
                "status": "pending_rotation",
                "release_authority": False,
            },
            "verification_plan": {
                "execution_dag": {"nodes": [{"producer": "test"}]}
            },
        },
    )
    monkeypatch.setattr(
        prospective,
        "_capture_planned_evidence",
        lambda *_args, **_kwargs: trace.append("evidence"),
    )
    subject = {"commit_sha": HEAD, "tree_sha": TREE}
    pr_truth = {
        "status": "pass",
        "issues": [],
        "merge_eligibility": "eligible",
        "bundle_sha256": "4" * 64,
    }
    bounded = {
        "status": "pass",
        "issues": [],
        "subject": {**subject, "repository_id": "1207503211"},
        "evaluation_scope": {
            "intent": "workitem",
            "target": {"kind": "workitem", "id": "P27-P0-03"},
        },
        "certified_proposition": {
            "predicate": "workitem_closed",
            "target": {"kind": "workitem", "id": "P27-P0-03"},
            "subject": subject,
            "conclusion": "success",
            "authorizes": ["declared_successor_workitem_eligibility"],
            "eligible_successors": ["P27-P0-04"],
        },
    }
    truths = iter((pr_truth, bounded))
    monkeypatch.setattr(prospective, "derive_truth", lambda *_args, **_kwargs: next(truths))
    report = prospective.run_prospective_train(
        tmp_path,
        **TRAIN,
        python_executable=Path("/python"),
        runner=_runner,
    )
    assert tuple(value["id"] for value in report["boundaries"]) == prospective.BOUNDARY_CHAIN
    assert report["provider_authority_substituted"] is False
    assert report["ephemeral_state"] == {
        "scope": "exact_prospective_run",
        "state": "retired",
    }
    assert {item["stage"] for item in report["telemetry"]["measurements"]} == {
        "fixed_point", "planning", "reuse", "setup", "producers",
        "positive_tests", "controls", "normalization", "truth",
        "finalization", "publication",
    }
    lifecycle = next(value for value in report["boundaries"] if value["id"] == "controller_lifecycle")
    assert lifecycle == {
        "id": "controller_lifecycle",
        "state": "rotation_required",
        "transition_class": "runtime_only",
    }
    eligibility = report["boundaries"][-1]
    publisher = next(value for value in report["boundaries"] if value["id"] == "publisher")
    assert publisher["status_context"] == "bcf/workitem-certification"
    assert eligibility["eligible_successors"] == ["P27-P0-04"]
    assert eligibility["release_authority"] is False


def test_protected_policy_change_requires_exact_alternate_lane(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    trace: list[str] = []
    _front_door(monkeypatch, trace)
    monkeypatch.setattr(
        prospective,
        "_changed_paths",
        lambda *_args, **_kwargs: ("governance/self-governance-policy.yml",),
    )
    changed_policy = {
        **POLICY_IDENTITY,
        "candidate": {
            **POLICY_IDENTITY["candidate"],
            "policy_sha256": "7" * 64,
        },
    }
    monkeypatch.setattr(
        prospective,
        "_controller_policy_identity",
        lambda *_args, **_kwargs: changed_policy,
    )
    monkeypatch.setattr(
        prospective,
        "run_preflight",
        lambda *_args, **_kwargs: {
            "status": "pass",
            "self_controller": {
                "status": "pending_rotation",
                "release_authority": False,
            },
        },
    )
    report = prospective._run_prospective_train(
        tmp_path,
        **TRAIN,
        python_executable=Path("/python"),
        execute_evidence=False,
        runner=_runner,
    )
    compatibility = report["boundaries"][1]
    assert compatibility["transition_class"] == "protected_policy_change"
    assert compatibility["transition_requirement"] == "alternate_lane_required"
    assert compatibility["policy_identity"] == changed_policy
    assert compatibility["alternate_lane"] == {
        "id": "ordinary_protected_n_n_plus_1",
        "required_sequence": [
            "project_exact_provider_target",
            "bootstrap_required_runners",
            "probe_required_runners",
            "provider_compile_confirmation",
            "protected_confirmation_merge",
            "normalize_ordinary_current",
        ],
        "required_initial_state": "ordinary-pending-rotation",
        "required_terminal_state": "ordinary-current",
    }



def test_full_walk_rejects_wrong_finalizer_truth_subject(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    trace: list[str] = []
    _front_door(monkeypatch, trace)
    session = SimpleNamespace(
        manifest_path=tmp_path / "session.json",
        root=tmp_path / "session",
    )
    monkeypatch.setattr(prospective, "select_session", lambda *_args: session)
    monkeypatch.setattr(
        prospective,
        "run_preflight",
        lambda *_args, **_kwargs: {
            "status": "pass",
            "self_controller": {"status": "current"},
            "verification_plan": {
                "execution_dag": {"nodes": [{"producer": "test"}]}
            },
        },
    )
    monkeypatch.setattr(
        prospective, "_capture_planned_evidence", lambda *_args, **_kwargs: None
    )
    pr_truth = {
        "status": "pass",
        "issues": [],
        "merge_eligibility": "eligible",
        "bundle_sha256": "4" * 64,
    }
    bounded = {
        "status": "pass",
        "issues": [],
        "subject": {"commit_sha": "9" * 40, "tree_sha": TREE},
        "evaluation_scope": {
            "intent": "workitem",
            "target": {"kind": "workitem", "id": "P27-P0-03"},
        },
        "certified_proposition": {
            "predicate": "workitem_closed",
            "target": {"kind": "workitem", "id": "P27-P0-03"},
            "subject": {"commit_sha": HEAD, "tree_sha": TREE},
            "conclusion": "success",
            "authorizes": ["declared_successor_workitem_eligibility"],
            "eligible_successors": ["P27-P0-04"],
        },
    }
    truths = iter((pr_truth, bounded))
    monkeypatch.setattr(
        prospective, "derive_truth", lambda *_args, **_kwargs: next(truths)
    )
    with pytest.raises(
        prospective.ProspectiveValidationError,
        match="governance truth subject is not exact main",
    ):
        prospective.run_prospective_train(
            tmp_path,
            **TRAIN,
            python_executable=Path("/python"),
            runner=_runner,
        )


def test_train_telemetry_schema_rejects_missing_stage() -> None:
    telemetry = {
        "schema_version": "1.0",
        "subject": {"commit_sha": HEAD, "tree_sha": TREE},
        "measurements": [],
        "producer_observations": [],
    }
    with pytest.raises(
        prospective.ProspectiveValidationError,
        match="stage inventory is not exact",
    ):
        prospective._validate_train_telemetry(REPO_ROOT, telemetry)

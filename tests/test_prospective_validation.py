from __future__ import annotations

import hashlib
import json
from pathlib import Path
import sys
from types import SimpleNamespace

import pytest

from bcf_governance.tooling.local_pr import LocalPRContext
from bcf_governance.tooling import local_pr as prospective
from bcf_governance.tooling import controller_custody_prospective as custody
from bcf_governance.tooling.ci_graph_defaults import build_reference_ci_graph
from bcf_governance.tooling.ci_authority_prospective_lanes import (
    direct_policy_identity,
    ordinary_authority_policy_identity,
)
from bcf_governance.tooling.routine_controller_rotation import (
    prospective_no_transition_topology,
)
from bcf_governance.tooling.evidence_workitem_lifecycle import (
    validate_phase_closure_authored_ready,
)


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


@pytest.fixture(autouse=True)
def _authored_target_ready(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        prospective, "validate_evaluation_authored_ready", lambda *_args, **_kwargs: None
    )
    monkeypatch.setattr(
        prospective,
        "validate_controller_custody_graph",
        lambda *_args, **_kwargs: (
            prospective.post_merge_evaluation(prospective.validate_ci_graph(REPO_ROOT).graph),
            {
                "status": "proved",
                "custody_state": "managed_controller",
                "no_transition_callback_probe": "no_transition",
            },
        ),
    )


class Result:
    def __init__(self, stdout: str = "", returncode: int = 0) -> None:
        self.stdout = stdout
        self.stderr = ""
        self.returncode = returncode


def test_planned_evidence_stops_on_first_failed_producer(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    seen: list[str] = []
    def capture(_root: Path, gate: str, output: Path, **_kwargs: object) -> Path:
        seen.append(gate)
        output.mkdir(parents=True)
        (output / f"{gate}.stderr.txt").write_text("causal diagnostic\n")
        receipt = output / f"{gate}.evidence.json"
        receipt.write_text(json.dumps({
            "result": "failed",
            "observations": {"exit_code": 3},
        }))
        return receipt
    monkeypatch.setattr(prospective, "capture_gate", capture)
    with pytest.raises(
        prospective.ProspectiveValidationError,
        match="first failed with exit 3.*causal diagnostic",
    ):
        prospective._capture_planned_evidence(
            tmp_path,
            python_executable=Path("/python"),
            session_manifest=tmp_path / "session.json",
            session_root=tmp_path / "receipts",
            producers=("first", "second"),
        )
    assert seen == ["first"]


def _runner(command: list[str], **_kwargs: object) -> Result:
    values = {
        ("git", "rev-parse", "--verify", "HEAD"): HEAD,
        ("git", "rev-parse", "--verify", "HEAD^{tree}"): TREE,
        ("git", "rev-parse", "--verify", f"{BASE}^{{tree}}"): BASE_TREE,
        ("git", "status", "--porcelain=v1", "--untracked-files=all", "--ignored=no"): "",
        ("git", "diff", "--name-only", BASE, HEAD): "source.py\n",
    }
    return Result(values[tuple(command)])


def _compiled(mode: str = "workitem", target: str | None = "P27-P0-03") -> SimpleNamespace:
    workflows = [
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
    return SimpleNamespace(workflows=workflows, graph={"workflows": workflows})


def _evaluation(mode: str = "workitem", target: str | None = "P27-P0-03") -> SimpleNamespace:
    return SimpleNamespace(
        mode=mode,
        target=target,
        lane="trusted_exact_main",
        workflow_id="exact-main",
        terminal_job_id="governance",
        as_dict=lambda: {
            "mode": mode,
            "target": target,
            "lane": "trusted_exact_main",
            "workflow_id": "exact-main",
            "terminal_job_id": "governance",
        },
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
        "post_merge_evaluation",
        lambda graph: _evaluation(
            graph["workflows"][0]["jobs"][0]["executor"]["evaluation_mode"],
            graph["workflows"][0]["jobs"][0]["executor"].get("evaluation_target"),
        ),
    )
    monkeypatch.setattr(
        prospective,
        "prospective_policy_binding",
        lambda *_args, **_kwargs: ("runtime_only", POLICY_IDENTITY),
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
        "lane": "trusted_exact_main",
        "workflow_id": "exact-main",
        "terminal_job_id": "governance",
    }


def test_provider_effective_controller_is_mechanically_bound_to_prospective_preflight(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    pin = {
        "BCF_BOOTSTRAP_COMMIT_SHA": "a" * 40,
        "BCF_BOOTSTRAP_WHEEL_SHA256": "b" * 64,
    }
    monkeypatch.setattr(
        prospective,
        "validate_ci_graph",
        lambda *_args: SimpleNamespace(graph={"workflows": []}),
    )
    monkeypatch.setattr(
        prospective,
        "post_merge_evaluation",
        lambda *_args: SimpleNamespace(lane="trusted_exact_main"),
    )
    monkeypatch.setattr(
        prospective,
        "effective_controller_authority",
        lambda api, *, repository, repo_root: {
            "controller_commit_sha": pin["BCF_BOOTSTRAP_COMMIT_SHA"],
            "controller_bundle_sha256": pin["BCF_BOOTSTRAP_WHEEL_SHA256"],
        },
    )
    captured: dict[str, object] = {}

    def train(*_args: object, **kwargs: object) -> dict[str, object]:
        captured.update(kwargs)
        return {"status": "pass"}

    monkeypatch.setattr(prospective, "_run_prospective_train", train)
    result = prospective.run_prospective_train(
        tmp_path,
        **TRAIN,
        python_executable=Path("/python"),
        repository="owner/repo",
        provider_api=object(),  # type: ignore[arg-type]
    )
    assert result == {"status": "pass"}
    assert captured["controller_authority"] == {
        "controller_commit_sha": "a" * 40,
        "controller_bundle_sha256": "b" * 64,
    }


def test_direct_protected_main_lane_does_not_resolve_controller_authority(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setattr(
        prospective,
        "validate_ci_graph",
        lambda *_args: SimpleNamespace(graph={"workflows": []}),
    )
    monkeypatch.setattr(
        prospective,
        "post_merge_evaluation",
        lambda *_args: SimpleNamespace(lane="direct_protected_main"),
    )
    monkeypatch.setattr(
        prospective,
        "effective_controller_authority",
        lambda *_args, **_kwargs: pytest.fail("direct adopter resolved a controller"),
    )
    monkeypatch.setattr(
        prospective,
        "_run_prospective_train",
        lambda *_args, **kwargs: {"controller_authority": kwargs["controller_authority"]},
    )
    report = prospective.run_prospective_train(
        tmp_path,
        **TRAIN,
        python_executable=Path("/python"),
        repository="owner/repo",
        provider_api=object(),  # type: ignore[arg-type]
    )
    assert report == {"controller_authority": None}


def test_direct_adopter_custody_never_enters_controller_topology(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    graph = build_reference_ci_graph(
        project_id="direct-adopter",
        profile="lite",
        profile_contract_version="1.0",
        gates=["governance-validate"],
        candidate_labels=["ubuntu-24.04"],
        trusted_labels=["ubuntu-24.04"],
        candidate_hosted=True,
        trusted_hosted=True,
    )
    monkeypatch.setattr(
        custody, "validate_ci_graph", lambda *_args: SimpleNamespace(graph=graph)
    )
    monkeypatch.setattr(
        custody,
        "validate_controller_custody_chain",
        lambda *_args, **_kwargs: pytest.fail("direct adopter entered controller custody"),
    )
    monkeypatch.setattr(
        custody,
        "prospective_no_transition_topology",
        lambda *_args, **_kwargs: pytest.fail("direct adopter entered controller callback"),
    )

    evaluation, proof = custody.validate_controller_custody_graph(
        tmp_path, python_executable=Path(sys.executable)
    )

    assert evaluation.lane == "direct_protected_main"
    assert proof == {
        "schema_version": "1.0",
        "status": "proved",
        "custody_state": "controller_not_adopted",
        "controller_required": False,
        "authority": "direct_protected_main_graph",
        "workflow_id": "governance",
        "terminal_job_id": "governance-truthfulness",
        "release_authority": False,
    }


def test_ordinary_exact_main_does_not_require_optional_rotation_topology(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    graph = build_reference_ci_graph(
        project_id="ordinary-adopter",
        profile="standard",
        profile_contract_version="3.0",
        gates=["governance-validate"],
        candidate_labels=["ubuntu-24.04"],
        trusted_labels=["ubuntu-24.04"],
        candidate_hosted=True,
        trusted_hosted=True,
    )
    monkeypatch.setattr(
        custody, "validate_ci_graph", lambda *_args: SimpleNamespace(graph=graph)
    )
    monkeypatch.setattr(
        custody,
        "prospective_no_transition_topology",
        lambda *_args, **_kwargs: pytest.fail("ordinary adopter entered rotation callback"),
    )

    evaluation, proof = custody.validate_controller_custody_graph(
        tmp_path, python_executable=Path(sys.executable)
    )

    assert evaluation.lane == "trusted_exact_main"
    assert proof["custody_state"] == "ordinary_executable_controller"
    assert proof["controller_custody_required"] is False
    assert proof["release_authority"] is False


def test_fresh_ordinary_exact_main_authenticates_absent_optional_authority() -> None:
    blobs = {
        (HEAD, "governance/ci-graph.yml"): b"candidate graph\n",
    }

    identity = ordinary_authority_policy_identity(
        base_sha=BASE,
        base_tree=BASE_TREE,
        candidate_sha=HEAD,
        candidate_tree=TREE,
        read_blob=lambda ref, path: blobs.get((ref, path)),
    )

    assert identity["source"]["policy_paths"]["governance/ci-graph.yml"]["state"] == "absent"
    assert identity["candidate"]["policy_paths"]["governance/ci-graph.yml"]["state"] == "present"
    assert identity["candidate"]["policy_paths"]["governance/ci-authority.yml"]["state"] == "absent"


def test_provider_workflow_identity_mismatch_stops_before_prospective_evidence(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setattr(
        prospective,
        "validate_ci_graph",
        lambda *_args: SimpleNamespace(graph={"workflows": []}),
    )
    monkeypatch.setattr(
        prospective,
        "post_merge_evaluation",
        lambda *_args: SimpleNamespace(lane="trusted_exact_main"),
    )
    monkeypatch.setattr(
        prospective,
        "effective_controller_authority",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            prospective.GitHubControllerError("provider workflow ID mismatched")
        ),
    )
    monkeypatch.setattr(
        prospective,
        "_run_prospective_train",
        lambda *_args, **_kwargs: pytest.fail("evidence train was allocated"),
    )

    with pytest.raises(
        prospective.GitHubControllerError, match="provider workflow ID mismatched"
    ):
        prospective.run_prospective_train(
            tmp_path,
            **TRAIN,
            python_executable=Path("/python"),
            repository="owner/repo",
            provider_api=object(),  # type: ignore[arg-type]
        )


def test_direct_protected_main_lane_is_closed_without_controller_or_release_authority() -> None:
    evaluation = SimpleNamespace(
        mode="closure",
        target=None,
        lane="direct_protected_main",
        workflow_id="governance",
        terminal_job_id="governance-truthfulness",
        as_dict=lambda: {
            "mode": "closure", "target": None, "lane": "direct_protected_main",
            "workflow_id": "governance", "terminal_job_id": "governance-truthfulness",
        },
    )
    provider = prospective.provider_boundaries(
        evaluation,
        controller_state="not_adopted",
        transition_class="direct_runtime_only",
        policy_identity={"candidate": {"policy_sha256": "a" * 64}},
        controller_probe=None,
    )
    terminal = prospective.terminal_boundaries(
        evaluation,
        proposition={"eligible_successors": []},
        proposition_sha256="b" * 64,
        bounded_truth={"evaluation_scope": {"intent": "closure"}},
    )
    assert provider[0]["state"] == "direct_protected_main_reexecution_required"
    assert provider[1]["state"] == "not_adopted_direct_lane"
    assert provider[1]["governed_alternate_lane"]["policy_sha256"] == "a" * 64
    assert terminal[0]["state"] == "same_workflow_terminal_truth_required"
    assert terminal[1]["status_context"] == "governance-truthfulness"
    assert terminal[2]["release_authority"] is False


def test_fresh_direct_policy_identity_is_exact_and_typed() -> None:
    candidate = b"document: {kind: ci_graph}\n"

    identity = direct_policy_identity(
        base_sha=BASE,
        base_tree=BASE_TREE,
        candidate_sha=HEAD,
        candidate_tree=TREE,
        base_graph=None,
        candidate_graph=candidate,
    )

    assert identity["source"] == {
        "commit_sha": BASE,
        "tree_sha": BASE_TREE,
        "policy_state": "absent",
        "policy_sha256": None,
    }
    assert identity["candidate"] == {
        "commit_sha": HEAD,
        "tree_sha": TREE,
        "policy_state": "present",
        "policy_sha256": hashlib.sha256(candidate).hexdigest(),
    }


def test_pr_progress_provider_boundary_is_explicitly_noncertifying() -> None:
    evaluation = SimpleNamespace(
        mode="pr",
        target=None,
        lane="trusted_exact_main",
        workflow_id="exact-main",
        terminal_job_id="governance",
    )

    terminal = prospective.terminal_boundaries(
        evaluation,
        proposition={"eligible_successors": []},
        proposition_sha256="b" * 64,
        bounded_truth={"evaluation_scope": {"intent": "pr"}},
    )

    assert terminal == [
        {
            "id": "finalizer",
            "state": "provider_noncertifying_observation_required",
            "proposition_sha256": "b" * 64,
            "terminal_job_id": "governance",
        },
        {
            "id": "publisher",
            "state": "provider_suppression_required",
            "scope": "pr",
            "status_context": None,
        },
        {
            "id": "successor_or_release_eligibility",
            "state": "proved_scope",
            "eligible_successors": [],
            "release_authority": False,
        },
    ]


def test_prospective_lifecycle_uses_exact_provider_effective_controller(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    trace: list[str] = []
    _front_door(monkeypatch, trace)
    authority = {
        "controller_commit_sha": "a" * 40,
        "controller_bundle_sha256": "b" * 64,
    }

    def preflight(*_args: object, **kwargs: object) -> dict[str, object]:
        return {"status": "pass", "self_controller": 24}

    monkeypatch.setattr(prospective, "run_preflight", preflight)
    monkeypatch.setattr(
        prospective,
        "classify_trusted_controller_applicability",
        lambda *_args, **_kwargs: SimpleNamespace(state=SimpleNamespace(value="current")),
    )
    report = prospective._run_prospective_train(
        tmp_path,
        **TRAIN,
        python_executable=Path("/python"),
        execute_evidence=False,
        controller_authority=authority,
        runner=_runner,
    )
    compatibility = report["boundaries"][1]
    assert compatibility["controller_state"] == "current"
    assert compatibility["transition_requirement"] == "no_transition"
    assert compatibility["effective_controller_source"] == "provider_authenticated"


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


def test_authored_todo_workitem_fails_before_reconcile_or_evidence(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    trace: list[str] = []
    _front_door(monkeypatch, trace)
    monkeypatch.setattr(
        prospective,
        "validate_evaluation_authored_ready",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            prospective.WorkitemContractError(
                "target_not_ready_for_bounded_certification: bounded workitem target P28-P0-04 is not authored DONE"
            )
        ),
    )
    with pytest.raises(
        prospective.ProspectiveValidationError,
        match="target_not_ready_for_bounded_certification.*not authored DONE",
    ):
        prospective._run_prospective_train(
            tmp_path,
            semantic_intent="workitem",
            evaluation_target="P28-P0-04",
            subject_commit=HEAD,
            subject_tree=TREE,
            python_executable=Path("/python"),
            execute_evidence=False,
            runner=_runner,
        )
    assert trace == []


def test_authored_todo_workitem_fails_before_provider_resolution(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setattr(
        prospective,
        "validate_evaluation_authored_ready",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            prospective.WorkitemContractError(
                "target_not_ready_for_bounded_certification: target is not authored DONE"
            )
        ),
    )
    monkeypatch.setattr(
        prospective,
        "effective_controller_authority",
        lambda *_args, **_kwargs: pytest.fail("provider resolution ran"),
    )
    with pytest.raises(
        prospective.ProspectiveValidationError,
        match="target_not_ready_for_bounded_certification",
    ):
        prospective.run_prospective_train(
            tmp_path,
            **TRAIN,
            python_executable=Path("/python"),
            repository="owner/repo",
            provider_api=object(),  # type: ignore[arg-type]
        )


def test_planned_hotfix_fails_phase_closure_before_reconcile_or_evidence(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    trace: list[str] = []
    _front_door(monkeypatch, trace)
    monkeypatch.setattr(
        prospective,
        "validate_evaluation_authored_ready",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            prospective.WorkitemContractError(
                "target_not_ready_for_phase_closure: phase closure hotfix P28-HF04 is not authored completed"
            )
        ),
    )
    with pytest.raises(
        prospective.ProspectiveValidationError,
        match="target_not_ready_for_phase_closure.*P28-HF04",
    ):
        prospective._run_prospective_train(
            tmp_path,
            semantic_intent="closure",
            evaluation_target=None,
            subject_commit=HEAD,
            subject_tree=TREE,
            python_executable=Path("/python"),
            execute_evidence=True,
            runner=_runner,
        )
    assert trace == []


def test_phase_closure_readiness_reads_exact_authored_hotfix_state(
    tmp_path: Path,
) -> None:
    (tmp_path / "plans").mkdir()
    (tmp_path / "phases").mkdir()
    (tmp_path / "plans/phase-ledger.yml").write_text(
        "active_phase: {id: P28, log: phases/phase-28-log.yml}\n",
        encoding="utf-8",
    )
    (tmp_path / "phases/phase-28-log.yml").write_text(
        "document: {status: completed}\nphase: {id: P28}\n",
        encoding="utf-8",
    )
    hotfix = tmp_path / "phases/phase-28-hotfix04.yml"
    hotfix.write_text(
        "document: {status: planned}\nhotfix: {id: P28-HF04, related_phase_id: P28}\n",
        encoding="utf-8",
    )
    with pytest.raises(
        prospective.WorkitemContractError,
        match="P28-HF04 is not authored completed",
    ):
        validate_phase_closure_authored_ready(tmp_path)
    hotfix.write_text(
        "document: {status: completed}\nhotfix:\n  id: P28-HF04\n  broken:\nnot-indented\n",
        encoding="utf-8",
    )
    with pytest.raises(
        prospective.WorkitemContractError,
        match="authored lifecycle contract is unreadable",
    ):
        validate_phase_closure_authored_ready(tmp_path)
    hotfix.write_text(
        "document: {status: completed}\nhotfix: {id: P28-HF04, related_phase_id: P28}\n",
        encoding="utf-8",
    )
    validate_phase_closure_authored_ready(tmp_path)


def test_graph_intent_mismatch_fails_before_evidence(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    trace: list[str] = []
    _front_door(monkeypatch, trace)
    monkeypatch.setattr(
        prospective,
        "post_merge_evaluation",
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
        "post_merge_evaluation",
        lambda *_args: _evaluation(),
    )
    monkeypatch.setattr(
        prospective,
        "run_preflight",
        lambda *_args, **_kwargs: {"status": "pass", "self_controller": 24},
    )
    monkeypatch.setattr(
        prospective,
        "prospective_policy_binding",
        lambda *_args, **_kwargs: ("runtime_only", POLICY_IDENTITY),
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
    required = ["test"]
    selected_python = tmp_path / "venv/bin/python"
    selected_python.parent.mkdir(parents=True)
    selected_python.symlink_to(sys.executable)
    monkeypatch.setattr(
        prospective,
        "reconcile_steps",
        lambda _root, python: (
            SimpleNamespace(check=lambda: trace.append("reconcile")),
        )
        if python == selected_python
        else pytest.fail("prospective reconciliation changed its selected interpreter"),
    )
    def allocate(_root: Path, _artifacts: Path, gates: tuple[str, ...], **_kwargs: object) -> SimpleNamespace:
        assert gates == tuple(required)
        return session
    monkeypatch.setattr(prospective, "allocate_session", allocate)
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
        lambda *_args, producers, python_executable, **_kwargs: (
            trace.append("evidence")
            if producers == tuple(required) and python_executable == selected_python
            else pytest.fail("prospective execution changed its planned producer or interpreter")
        ),
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
        python_executable=selected_python,
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
        "no_transition_callback_probe": "no_transition",
    }
    eligibility = report["boundaries"][-1]
    publisher = next(value for value in report["boundaries"] if value["id"] == "publisher")
    assert publisher["status_context"] == "bcf/workitem-certification"
    assert eligibility["eligible_successors"] == ["P27-P0-04"]
    assert eligibility["release_authority"] is False


def test_prospective_callback_probe_executes_real_skipped_matrix_classifier() -> None:
    assert prospective_no_transition_topology(REPO_ROOT) == "no_transition"


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
        "prospective_policy_binding",
        lambda *_args, **_kwargs: ("protected_policy_change", changed_policy),
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


def test_installed_n_rotation_incompatibility_preserves_typed_alternate_lane(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    trace: list[str] = []
    _front_door(monkeypatch, trace)
    monkeypatch.setattr(
        prospective,
        "run_preflight",
        lambda *_args, **_kwargs: {
            "status": "pass",
            "self_controller": {
                "status": "pending_rotation",
                "transition_requirement": "alternate_lane_required",
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
    assert compatibility["transition_class"] == "runtime_only"
    assert compatibility["transition_requirement"] == "alternate_lane_required"
    assert compatibility["alternate_lane"]["id"] == (
        "ordinary_protected_n_n_plus_1"
    )



def test_full_walk_rejects_wrong_finalizer_truth_subject(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    trace: list[str] = []
    _front_door(monkeypatch, trace)
    session = SimpleNamespace(
        manifest_path=tmp_path / "session.json",
        root=tmp_path / "session",
    )
    monkeypatch.setattr(prospective, "allocate_session", lambda *_args, **_kwargs: session)
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

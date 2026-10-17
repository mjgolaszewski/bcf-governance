from __future__ import annotations

import copy
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
from types import SimpleNamespace

import pytest

from bcf_governance.tooling.local_pr import LocalPRContext
from bcf_governance.tooling import local_pr as prospective
from bcf_governance.tooling import prospective_candidate_identity as candidate_identity
from bcf_governance.tooling import local_proof_bundles
from bcf_governance.tooling import controller_custody_prospective as custody
from bcf_governance.tooling.ci_graph_defaults import build_reference_ci_graph
from bcf_governance.tooling.ci_authority_prospective_lanes import (
    direct_policy_identity,
    ordinary_authority_applicability,
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
def _authored_target_ready(monkeypatch: pytest.MonkeyPatch, tmp_path: Path):
    from bcf_governance.tooling import local_execution_admission as admission
    namespace = hashlib.sha256(('unit-prospective:' + str(tmp_path)).encode()).hexdigest()
    monkeypatch.setattr(admission, 'authenticated_execution_state_namespace', lambda _env: namespace)
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
    monkeypatch.setattr(
        prospective,
        "validate_local_toolchain",
        lambda *_args, **_kwargs: SimpleNamespace(
            node_executable="/usr/bin/node",
            as_dict=lambda: {
                "status": "ready",
                "execution_id": "toolchain-only",
            },
        ),
    )
    monkeypatch.setattr(
        prospective, "validate_operational_observation", lambda *_args: None
    )
    monkeypatch.setattr(
        prospective,
        "lifecycle_projection",
        lambda *_args: {
            "schema_version": "1.0",
            "kind": "lifecycle_projection",
            "authority": "lifecycle",
            "phase_id": "P27",
            "completed_prefix": [],
            "predecessor": None,
            "current": "P27-P0-03",
            "successor": None,
            "history_owner": "plans/phase-history.yml",
        },
    )
    yield
    Path(f'/tmp/bcf-local-gate-{os.getuid()}-{namespace}.lock').unlink(missing_ok=True)


class Result:
    def __init__(self, stdout: str = "", returncode: int = 0) -> None:
        self.stdout = stdout
        self.stderr = ""
        self.returncode = returncode


def test_canonical_prospective_inputs_derive_subject_and_scope_without_caller_choice(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setattr(candidate_identity, "require_clean_candidate_root", lambda root, **_kw: root.resolve())
    context = prospective.LocalPRContext("origin", "main", BASE, HEAD, "feature")
    monkeypatch.setattr(
        candidate_identity, "resolve_local_pr_context", lambda *_args, **_kwargs: context
    )
    monkeypatch.setattr(
        candidate_identity,
        "_candidate_identity",
        lambda *_args, **_kwargs: SimpleNamespace(commit_sha=HEAD, tree_sha=TREE),
    )
    monkeypatch.setattr(
        candidate_identity,
        "validate_ci_graph",
        lambda *_args: SimpleNamespace(graph={}),
    )
    monkeypatch.setattr(
        candidate_identity,
        "post_merge_evaluation",
        lambda *_args: SimpleNamespace(mode="workitem", target="P27-P0-03"),
    )
    observed: list[tuple[str, str | None]] = []
    monkeypatch.setattr(
        candidate_identity,
        "authored_candidate_title",
        lambda _root, *, mode, target: observed.append((mode, target)) or "candidate",
    )

    assert candidate_identity.canonical_prospective_inputs(tmp_path) == {
        "semantic_intent": "workitem",
        "evaluation_target": "P27-P0-03",
        "subject_commit": HEAD,
        "subject_tree": TREE,
    }
    assert observed == [("workitem", "P27-P0-03")]


def test_planned_evidence_stops_on_first_failed_producer(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    subprocess.run(["git", "init", "--quiet"], cwd=tmp_path, check=True)
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
    monkeypatch.setattr(local_proof_bundles, "capture_gate", capture)
    (tmp_path / "session.json").write_text(
        json.dumps(
            {
                "session_id": "a" * 32,
                "subject": {"commit_sha": HEAD, "tree_sha": TREE},
                "producer": {
                    "kind": "local",
                    "provider": "local",
                    "repository": "fixture",
                    "repository_id": "local",
                    "run_id": "prospective-local",
                    "run_attempt": "1",
                    "producer_id": "prospective-local",
                },
            }
        )
    )
    bindings = {gate: {} for gate in ("first", "second")}
    with pytest.raises(
        local_proof_bundles.LocalProofBundleError,
        match="first failed with exit 3.*causal diagnostic",
    ) as raised:
        prospective._capture_planned_evidence(
            tmp_path,
            python_executable=Path("/python"),
            session_manifest=tmp_path / "session.json",
            session_root=tmp_path / "receipts",
            producers=("first", "second"),
            producer_environments=bindings,
        )
    assert seen == ["first"]
    assert "retained failure bundle" in str(raised.value)
    retained = list((tmp_path / ".git/bcf/failure-bundles").glob("*/failure-bundle.json"))
    assert len(retained) == 1


def test_planned_evidence_reports_failed_control_when_command_passed(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    def capture(_root: Path, gate: str, output: Path, **_kwargs: object) -> Path:
        output.mkdir(parents=True)
        raw = output / f"{gate}.control.stderr.txt"
        raw.write_text("owned invariant was not reached\n", encoding="utf-8")
        receipt = output / f"{gate}.evidence.json"
        receipt.write_text(
            json.dumps(
                {
                    "result": "failed",
                    "observations": {"exit_code": 0},
                    "behavioral_probes": [
                        {
                            "id": "control",
                            "oracle_observation": {"satisfied": False},
                            "raw_artifacts": {"stderr": raw.name},
                        }
                    ],
                }
            ),
            encoding="utf-8",
        )
        return receipt

    monkeypatch.setattr(local_proof_bundles, "capture_gate", capture)
    with pytest.raises(
        local_proof_bundles.LocalProofBundleError,
        match=(
            "producer passed-command failed with exit 0.*"
            "behavioral_probe control: oracle_not_satisfied.*"
            "owned invariant was not reached"
        ),
    ):
        prospective._capture_planned_evidence(
            tmp_path,
            python_executable=Path("/python"),
            session_manifest=tmp_path / "session.json",
            session_root=tmp_path / "receipts",
            producers=("passed-command",),
            producer_environments={"passed-command": {}},
        )


def test_planned_evidence_projects_exact_graph_job_environment(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    prepared = tmp_path / ".artifacts/prepared"
    prepared.mkdir(parents=True)
    prepared.joinpath("ready").write_text("admitted")
    observed: list[tuple[str, dict[str, str], str]] = []

    def capture(_root: Path, gate: str, output: Path, **kwargs: object) -> Path:
        environment = dict(kwargs["job_environment"])
        workspace = Path(environment["PREPARED_ROOT"]).parents[1]
        observed.append(
            (gate, environment, Path(environment["PREPARED_ROOT"], "ready").read_text())
        )
        output.mkdir(parents=True)
        receipt = output / f"{gate}.evidence.json"
        receipt.write_text(
            json.dumps({
                "result": "passed",
                "observations": {"duration_ms": 1},
                "claims": [],
                "behavioral_probes": [],
                "started_at": "2026-09-29T00:00:00Z",
                "timestamp": "2026-09-29T00:00:01Z",
            }),
            encoding="utf-8",
        )
        return receipt

    monkeypatch.setattr(local_proof_bundles, "capture_gate", capture)
    (tmp_path / "session.json").write_text("{}")
    prospective._capture_planned_evidence(
        tmp_path,
        python_executable=Path("/python"),
        session_manifest=tmp_path / "session.json",
        session_root=tmp_path / "receipts",
        producers=("first", "second", "third"),
        producer_environments={
            producer: {"PREPARED_ROOT": "${{ github.workspace }}/.artifacts/prepared"}
            for producer in ("first", "second", "third")
        },
    )

    first = Path(observed[0][1]["PREPARED_ROOT"]).parents[1]
    second = Path(observed[1][1]["PREPARED_ROOT"]).parents[1]
    third = Path(observed[2][1]["PREPARED_ROOT"]).parents[1]
    assert first == second == third == tmp_path
    assert [item[2] for item in observed] == ["admitted", "admitted", "admitted"]


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
    return SimpleNamespace(
        workflows=workflows, graph={"workflows": workflows}, commands={}
    )


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
    monkeypatch.setattr(prospective, "require_clean_candidate_root", lambda root, **_kw: root.resolve())
    monkeypatch.setattr(prospective, "_negative_control_targets", lambda _root: 0)
    monkeypatch.setattr(prospective, "_pack_manifest", lambda *_a, **_k: {"applicable": False}, raising=False)
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
    monkeypatch.setattr(
        prospective,
        "local_gate_execution_environments",
        lambda _root, _graph, producers: {producer: {} for producer in producers},
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
    assert trace == ["reconcile", "preflight", "preflight"]
    assert report["status"] == "deterministic_front_door_pass"
    assert report["provider_authority_substituted"] is False
    assert report["post_merge_evaluation"] == {
        "mode": "workitem",
        "target": "P27-P0-03",
        "lane": "trusted_exact_main",
        "workflow_id": "exact-main",
        "terminal_job_id": "governance",
    }


def test_prospective_train_executes_exact_direct_push_preflight_before_evidence(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    trace: list[str] = []
    calls: list[dict[str, object]] = []
    _front_door(monkeypatch, trace)

    def preflight(*_args: object, **kwargs: object) -> dict[str, object]:
        calls.append(dict(kwargs))
        if len(calls) == 2:
            assert kwargs["mode"] == "release"
            assert kwargs["evaluation_mode"] == "workitem"
            assert kwargs["evaluation_target"] == "P27-P0-03"
            assert prospective.os.environ["BCF_PROVIDER_EVENT"] == "push"
            assert prospective.os.environ["BCF_COMPARISON_BASE_SHA"] == BASE
            raise prospective.PreflightError(
                "bounded workitem target P27-P0-03 would strand unfinished workitems"
            )
        return {"status": "pass", "self_controller": 24}

    monkeypatch.setattr(prospective, "run_preflight", preflight)
    monkeypatch.setattr(
        prospective,
        "allocate_session",
        lambda *_args, **_kwargs: pytest.fail("evidence allocated after push rejection"),
    )
    with pytest.raises(
        prospective.ProspectiveValidationError,
        match="direct-push preflight.*would strand unfinished workitems",
    ):
        prospective._run_prospective_train(
            tmp_path,
            **TRAIN,
            python_executable=Path("/python"),
            execute_evidence=True,
            runner=_runner,
        )
    assert len(calls) == 2


def test_pending_rotation_pr_projection_uses_direct_push_release_preflight(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    trace: list[str] = []
    calls: list[dict[str, object]] = []
    _front_door(monkeypatch, trace)
    monkeypatch.setattr(
        prospective,
        "validate_controller_custody_graph",
        lambda *_args, **_kwargs: (
            _evaluation("pr", None),
            {
                "status": "proved",
                "custody_state": "managed_controller",
                "no_transition_callback_probe": "no_transition",
            },
        ),
    )

    def preflight(*_args: object, **kwargs: object) -> dict[str, object]:
        calls.append(dict(kwargs))
        return {
            "status": "pass",
            "self_controller": {
                "status": "pending_rotation",
                "release_authority": False,
            },
        }

    monkeypatch.setattr(prospective, "run_preflight", preflight)
    report = prospective._run_prospective_train(
        tmp_path,
        semantic_intent="pr",
        evaluation_target=None,
        subject_commit=HEAD,
        subject_tree=TREE,
        python_executable=Path("/python"),
        execute_evidence=False,
        runner=_runner,
    )

    assert report["status"] == "deterministic_front_door_pass"
    assert [(call["mode"], call["evaluation_mode"]) for call in calls] == [
        ("pr", "pr"),
        ("release", "pr"),
    ]
    assert calls[1]["controller_state_expectation"] == (
        "prospective_pending_rotation"
    )


def test_provider_context_is_mechanically_bound_to_exact_prospective_train(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setattr(prospective, "require_clean_candidate_root", lambda root, **_kw: root.resolve())
    api = object()
    monkeypatch.setattr(
        prospective,
        "validate_ci_graph",
        lambda *_args: SimpleNamespace(graph={"workflows": []}, commands={}),
    )
    monkeypatch.setattr(
        prospective,
        "post_merge_evaluation",
        lambda *_args: SimpleNamespace(lane="trusted_exact_main"),
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
        provider_api=api,  # type: ignore[arg-type]
    )
    assert result == {
        "status": "pass",
        "local_execution_admission": {
            "status": "ready",
            "execution_id": "toolchain-only",
        },
    }
    assert captured["repository"] == "owner/repo"
    assert captured["provider_api"] is api


def test_direct_protected_main_lane_does_not_resolve_controller_authority(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setattr(prospective, "require_clean_candidate_root", lambda root, **_kw: root.resolve())
    monkeypatch.setattr(
        prospective,
        "validate_ci_graph",
        lambda *_args: SimpleNamespace(graph={"workflows": []}, commands={}),
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
        "verify_provider_workflow_authority",
        lambda *_args, **_kwargs: pytest.fail("direct adopter resolved provider authority"),
    )
    monkeypatch.setattr(
        prospective,
        "_run_prospective_train",
        lambda *_args, **kwargs: {
            "repository": kwargs["repository"],
            "provider_api": kwargs["provider_api"],
        },
    )
    read_api = object()
    report = prospective.run_prospective_train(
        tmp_path,
        **TRAIN,
        python_executable=Path("/python"),
        repository="owner/repo",
        provider_api=read_api,  # type: ignore[arg-type]
    )
    assert report == {
        "repository": None,
        "provider_api": read_api,
        "local_execution_admission": {
            "status": "ready",
            "execution_id": "toolchain-only",
        },
    }


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
    assert ordinary_authority_applicability(identity) == "bootstrap_provider_authority_absent"


def test_established_ordinary_authority_cannot_disappear() -> None:
    blobs = {
        (BASE, "governance/ci-graph.yml"): b"source graph\n",
        (BASE, "governance/ci-authority.yml"): b"source authority\n",
        (HEAD, "governance/ci-graph.yml"): b"candidate graph\n",
    }
    identity = ordinary_authority_policy_identity(
        base_sha=BASE,
        base_tree=BASE_TREE,
        candidate_sha=HEAD,
        candidate_tree=TREE,
        read_blob=lambda ref, path: blobs.get((ref, path)),
    )
    with pytest.raises(
        prospective.ProspectiveLaneError,
        match="removes established provider workflow authority",
    ):
        ordinary_authority_applicability(identity)


def test_fresh_ordinary_authority_bootstrap_reaches_local_proof_without_provider_file(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    trace: list[str] = []
    _front_door(monkeypatch, trace)
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
    monkeypatch.setattr(
        prospective,
        "validate_controller_custody_graph",
        lambda *_args, **_kwargs: (
            _evaluation(),
            {"status": "proved", "custody_state": "ordinary_executable_controller"},
        ),
    )
    monkeypatch.setattr(
        prospective,
        "prospective_policy_binding",
        lambda *_args, **_kwargs: ("ordinary_authority_change", identity),
    )
    monkeypatch.setattr(
        prospective,
        "verify_provider_workflow_authority",
        lambda *_args, **_kwargs: pytest.fail("absent bootstrap authority was verified"),
    )
    monkeypatch.setattr(
        prospective,
        "run_preflight",
        lambda *_args, **_kwargs: {"status": "pass", "self_controller": None},
    )

    report = prospective._run_prospective_train(
        tmp_path,
        **TRAIN,
        python_executable=Path("/python"),
        execute_evidence=False,
        repository="owner/repo",
        provider_api=object(),  # type: ignore[arg-type]
        runner=_runner,
    )

    assert report["status"] == "deterministic_front_door_pass"
    assert report["boundaries"][1]["provider_authority_applicability"] == (
        "bootstrap_provider_authority_absent"
    )
    assert report["provider_authority_substituted"] is False


def test_provider_workflow_identity_mismatch_stops_before_prospective_evidence(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    trace: list[str] = []
    _front_door(monkeypatch, trace)
    blobs = {
        (BASE, "governance/ci-graph.yml"): b"source graph\n",
        (BASE, "governance/ci-authority.yml"): b"source authority\n",
        (HEAD, "governance/ci-graph.yml"): b"candidate graph\n",
        (HEAD, "governance/ci-authority.yml"): b"candidate authority\n",
    }
    identity = ordinary_authority_policy_identity(
        base_sha=BASE,
        base_tree=BASE_TREE,
        candidate_sha=HEAD,
        candidate_tree=TREE,
        read_blob=lambda ref, path: blobs.get((ref, path)),
    )
    monkeypatch.setattr(
        prospective,
        "validate_controller_custody_graph",
        lambda *_args, **_kwargs: (
            _evaluation(),
            {"status": "proved", "custody_state": "ordinary_executable_controller"},
        ),
    )
    monkeypatch.setattr(
        prospective,
        "prospective_policy_binding",
        lambda *_args, **_kwargs: ("ordinary_runtime_only", identity),
    )
    monkeypatch.setattr(
        prospective,
        "verify_provider_workflow_authority",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            prospective.GitHubControllerError("provider workflow ID mismatched")
        ),
    )
    monkeypatch.setattr(
        prospective,
        "run_preflight",
        lambda *_args, **_kwargs: pytest.fail("preflight ran before authority verification"),
    )

    with pytest.raises(
        prospective.GitHubControllerError, match="provider workflow ID mismatched"
    ):
        prospective._run_prospective_train(
            tmp_path,
            **TRAIN,
            python_executable=Path("/python"),
            execute_evidence=False,
            repository="owner/repo",
            provider_api=object(),  # type: ignore[arg-type]
            runner=_runner,
        )


def test_provider_bound_adopter_delegates_authority_applicability_to_exact_train(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setattr(prospective, "require_clean_candidate_root", lambda root, **_kw: root.resolve())
    graph = {"workflows": [], "trusted_controller": {"kind": "executable"}}
    train_calls: list[dict[str, object]] = []
    monkeypatch.setattr(
        prospective,
        "validate_ci_graph",
        lambda *_args: SimpleNamespace(graph=graph, commands={}),
    )
    monkeypatch.setattr(
        prospective,
        "post_merge_evaluation",
        lambda *_args: SimpleNamespace(lane="trusted_exact_main"),
    )
    monkeypatch.setattr(
        prospective,
        "_run_prospective_train",
        lambda *_args, **kwargs: train_calls.append(kwargs) or {},
    )

    report = prospective.run_prospective_train(
        tmp_path,
        **TRAIN,
        python_executable=Path("/python"),
        repository="owner/repo",
        provider_api=object(),  # type: ignore[arg-type]
    )

    assert train_calls[0]["repository"] == "owner/repo"
    assert train_calls[0]["provider_api"] is not None
    assert report == {
        "local_execution_admission": {
            "status": "ready",
            "execution_id": "toolchain-only",
        },
    }


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
    preflight_authorities: list[object] = []
    _front_door(monkeypatch, trace)
    authority = {
        "controller_commit_sha": "a" * 40,
        "controller_bundle_sha256": "b" * 64,
    }

    def preflight(*_args: object, **kwargs: object) -> dict[str, object]:
        preflight_authorities.append(kwargs.get("transported_authority"))
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
    assert preflight_authorities == [authority, authority]


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
    monkeypatch.setattr(prospective, "require_clean_candidate_root", lambda root, **_kw: root.resolve())
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


def test_exact_main_missing_comparison_binding_fails_before_preflight(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    trace: list[str] = []
    _front_door(monkeypatch, trace)
    graph = build_reference_ci_graph(
        project_id="comparison-binding-fixture",
        profile="standard",
        profile_contract_version="3.0",
        gates=["governance-validate"],
        candidate_labels=["ubuntu-24.04"],
        trusted_labels=["ubuntu-24.04"],
        candidate_hosted=True,
        trusted_hosted=True,
    )
    exact = next(item for item in graph["workflows"] if item["id"] == "exact-main")
    producer = next(
        item for item in exact["jobs"]
        if item["semantic_role"] == "exact-main-governance-producer"
    )
    producer["executor"]["inputs"].pop("comparison_base_sha")
    monkeypatch.setattr(
        prospective,
        "validate_controller_custody_graph",
        lambda *_args, **_kwargs: (
            custody.post_merge_evaluation(copy.deepcopy(graph)),
            {},
        ),
    )
    monkeypatch.setattr(
        prospective,
        "run_preflight",
        lambda *_args, **_kwargs: pytest.fail(
            "preflight ran without exact-main comparison-base binding"
        ),
    )
    with pytest.raises(
        prospective.ProspectiveValidationError,
        match="comparison base is not canonically bound",
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
    monkeypatch.setattr(prospective, "_negative_control_targets", lambda _root: 0)
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
    required = ["contract-test", "test", "security-review"]
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
    preflight_expectations: list[str | None] = []

    def run_preflight(*_args: object, **kwargs: object) -> dict:
        expectation = kwargs.get("controller_state_expectation")
        assert expectation is None or isinstance(expectation, str)
        preflight_expectations.append(expectation)
        return {
            "status": "pass",
            "self_controller": {
                "status": "pending_rotation",
                "release_authority": False,
            },
            "verification_plan": {
                "execution_dag": {
                    "nodes": [
                        {
                            "id": "review",
                            "producer": "security-review",
                            "assigned_shard": 0,
                            "depends_on": ["contracts", "quality"],
                        },
                        {
                            "id": "quality",
                            "producer": "test",
                            "assigned_shard": 0,
                            "depends_on": [],
                        },
                        {
                            "id": "contracts",
                            "producer": "contract-test",
                            "assigned_shard": 0,
                            "depends_on": [],
                        }
                    ],
                    "edges": [
                        {"from": "contracts", "to": "review"},
                        {"from": "quality", "to": "review"},
                    ],
                }
            },
        }

    monkeypatch.setattr(prospective, "run_preflight", run_preflight)
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
    assert preflight_expectations == [None, "prospective_pending_rotation"]


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
                "execution_dag": {
                    "nodes": [
                        {
                            "id": "test",
                            "producer": "test",
                            "assigned_shard": 0,
                            "depends_on": [],
                        }
                    ],
                    "edges": [],
                }
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


@pytest.mark.parametrize('failure', ['workflow', 'controller', 'graph', 'oserror', None])
def test_provider_authority_progress_brackets_existing_queries_without_changing_errors(monkeypatch, tmp_path, failure):
    trace = []
    events = []
    _front_door(monkeypatch, trace)
    error_type = OSError if failure == 'oserror' else prospective.CIGraphError if failure == 'graph' else prospective.GitHubControllerError
    error = error_type('exact provider rejection')
    def policy(graph):
        if failure == 'graph':
            raise error
        return 'policy'
    monkeypatch.setattr(prospective, 'graph_controller_policy_path', policy)
    def verify(*args, **kwargs):
        assert events[-1]['stage'] == 'provider_authority'
        assert events[-1]['state'] == 'started'
        trace.append('provider-workflow')
        if failure == 'workflow':
            raise error
    def resolve(*args, **kwargs):
        assert events[-1]['stage'] == 'provider_authority'
        assert events[-1]['state'] == 'started'
        trace.append('provider-controller')
        if failure in {'controller', 'oserror'}:
            raise error
        return {'controller_commit_sha': BASE, 'controller_bundle_sha256': '6' * 64}
    def preflight(*args, **kwargs):
        assert any(row['stage'] == 'provider_authority' and row['state'] == 'complete' for row in events)
        trace.append('preflight')
        return {'status': 'pass', 'self_controller': None}
    monkeypatch.setattr(prospective, 'verify_provider_workflow_authority', verify)
    monkeypatch.setattr(prospective, 'effective_controller_authority', resolve)
    monkeypatch.setattr(prospective, 'run_preflight', preflight)
    monkeypatch.setattr(prospective, 'classify_trusted_controller_applicability', lambda *args, **kwargs: SimpleNamespace(state=SimpleNamespace(value='current')))
    def run():
        return prospective._run_prospective_train(tmp_path, **TRAIN, python_executable=Path('/python'), execute_evidence=False,
            repository='owner/repo', provider_api=object(), runner=_runner, progress_sink=events.append)
    if failure:
        with pytest.raises(type(error)) as caught:
            run()
        assert caught.value is error
        assert 'preflight' not in trace
    else:
        run()
    authority = [row for row in events if row['stage'] == 'provider_authority']
    assert [row['state'] for row in authority] == ['started', 'failed' if failure else 'complete']
    assert all(row['authority'] is False for row in events)


def test_provider_authority_progress_absent_when_no_provider_is_required(monkeypatch, tmp_path):
    events = []
    _front_door(monkeypatch, [])
    monkeypatch.setattr(prospective, 'run_preflight', lambda *args, **kwargs: {'status': 'pass', 'self_controller': None})
    prospective._run_prospective_train(tmp_path, **TRAIN, python_executable=Path('/python'), execute_evidence=False,
        runner=_runner, progress_sink=events.append)
    assert all(row['stage'] != 'provider_authority' for row in events)


def test_exposure_failure_stops_before_provider_authority_and_retains_cause(monkeypatch, tmp_path):
    _front_door(monkeypatch, [])
    events = []
    failure = prospective.PreflightError('governance exposure preflight failed: retained audit')
    def exposure(root):
        raise failure
    monkeypatch.setattr(prospective, '_exposure_scan', exposure, raising=False)
    monkeypatch.setattr(prospective, 'verify_provider_workflow_authority', lambda *args, **kwargs: pytest.fail('provider ran before exposure rejection'))
    monkeypatch.setattr(prospective, 'run_preflight', lambda *args, **kwargs: pytest.fail('late preflight ran'))
    with pytest.raises(prospective.ProspectiveValidationError, match='governance exposure preflight failed') as caught:
        prospective._run_prospective_train(tmp_path, **TRAIN, python_executable=Path('/python'), execute_evidence=False,
            repository='owner/repo', provider_api=object(), runner=_runner, progress_sink=events.append)
    assert caught.value.__cause__ is failure
    assert [(row['stage'], row['state']) for row in events[-2:]] == [('exposure', 'started'), ('exposure', 'failed')]


def test_static_control_failure_stops_before_provider_and_preserves_cause(monkeypatch, tmp_path):
    _front_door(monkeypatch, [])
    events = []
    failure = prospective.PreflightError('scheduled mutant target is stale')
    def controls(root):
        raise failure
    monkeypatch.setattr(prospective, '_negative_control_targets', controls, raising=False)
    monkeypatch.setattr(prospective, 'verify_provider_workflow_authority', lambda *args, **kwargs: pytest.fail('provider ran before static control rejection'))
    with pytest.raises(prospective.ProspectiveValidationError, match='scheduled mutant target is stale') as caught:
        prospective._run_prospective_train(tmp_path, **TRAIN, python_executable=Path('/python'), execute_evidence=False,
            repository='owner/repo', provider_api=object(), runner=_runner, progress_sink=events.append)
    assert caught.value.__cause__ is failure
    assert [(row['stage'], row['state']) for row in events[-2:]] == [('negative_controls', 'started'), ('negative_controls', 'failed')]


def test_prospective_unit_namespace_retains_real_lease_exclusion():
    from bcf_governance.tooling.local_execution_admission import local_gate_lease, LocalExecutionAdmissionError
    with local_gate_lease(HEAD):
        with pytest.raises(LocalExecutionAdmissionError, match='local_execution_busy_deferred: active=' + HEAD):
            with local_gate_lease(BASE):
                pytest.fail('unit namespace admitted overlapping host gate')


def test_semantic_ownership_failure_rejects_before_provider_and_preserves_cause(monkeypatch, tmp_path):
    _front_door(monkeypatch, [])
    events = []
    failure = prospective.PreflightError('semantic ownership preflight failed: downstream_normalization:retry')
    def reject(*_a):
        raise failure
    monkeypatch.setattr(prospective, '_semantic_ownership', reject, raising=False)
    monkeypatch.setattr(prospective, 'verify_provider_workflow_authority', lambda *_a, **_k: pytest.fail('provider reached before semantic rejection'))
    with pytest.raises(prospective.ProspectiveValidationError, match='downstream_normalization') as caught:
        prospective._run_prospective_train(tmp_path, **TRAIN, python_executable=Path('/python'), execute_evidence=False,
            repository='owner/repo', provider_api=object(), runner=_runner, progress_sink=events.append)
    assert caught.value.__cause__ is failure
    assert [(e['stage'], e['state']) for e in events[-2:]] == [('semantic_ownership', 'started'), ('semantic_ownership', 'failed')]


@pytest.mark.parametrize(("report", "message"), [
    ({"status": "pass", "issues": [], "marker": "retained"}, None),
    ({"status": "fail", "issues": ["first", "second"]}, "golden rejected candidate: first, second"),
    ({"status": "fail"}, "golden rejected candidate: truth failed"),
    ({"status": "failed", "issues": []}, "golden rejected candidate: truth failed"),
    ({"issues": ["missing status"]}, "golden rejected candidate: missing status"),
])
def test_prospective_truth_acceptance_extraction_characterization(report, message):
    if message is None:
        observed = prospective._require_truth(report, boundary="golden")
        assert observed == report and observed is not report
    else:
        with pytest.raises(prospective.ProspectiveValidationError) as observed:
            prospective._require_truth(report, boundary="golden")
        assert str(observed.value) == message


def test_prospective_policy_consumer_receives_separate_protected_context(monkeypatch, tmp_path):
    trace = []
    _front_door(monkeypatch, trace)
    context = LocalPRContext('origin', 'main', BASE, HEAD, 'feature', protected_default_sha=BASE, protected_default_tree=BASE_TREE)
    monkeypatch.setattr(prospective, 'resolve_local_pr_context', lambda *_a, **_k: context)
    def bind(*_args, **kwargs):
        assert kwargs.get('policy_context') is context
        assert kwargs.get('runner') is _runner
        raise RuntimeError('policy context boundary observed')
    monkeypatch.setattr(prospective, 'prospective_policy_binding', bind)
    with pytest.raises(RuntimeError, match='policy context boundary observed'):
        prospective._run_prospective_train(tmp_path, **TRAIN, python_executable=Path('/python'), execute_evidence=False, runner=_runner)


@pytest.fixture
def policy_stack(tmp_path):
    def git(*args):
        return subprocess.check_output(['git', *args], cwd=tmp_path, text=True).strip()
    git('init', '-q')
    git('config', 'user.email', 'fixture@example.invalid')
    git('config', 'user.name', 'Policy fixture')
    policy = tmp_path / 'governance'
    policy.mkdir()
    (policy / 'ci-graph.yml').write_text('revision: protected\n')
    (policy / 'ci-authority.yml').write_text('authority: protected\n')
    git('add', '.')
    git('commit', '-qm', 'protected source')
    source, source_tree = git('rev-parse', 'HEAD'), git('rev-parse', 'HEAD^{tree}')
    (policy / 'ci-authority.yml').write_text('authority: feature\n')
    git('add', '.')
    git('commit', '-qm', 'feature base policy change')
    base, base_tree = git('rev-parse', 'HEAD'), git('rev-parse', 'HEAD^{tree}')
    (tmp_path / 'README.md').write_text('leaf docs\n')
    git('add', '.')
    git('commit', '-qm', 'leaf docs')
    head, tree = git('rev-parse', 'HEAD'), git('rev-parse', 'HEAD^{tree}')
    context = LocalPRContext('origin', 'main', base, head, 'leaf', base_ref='stack', repository='owner/repo', repository_id=17,
        protected_default_sha=source, protected_default_tree=source_tree)
    return SimpleNamespace(root=tmp_path, context=context, source=source, source_tree=source_tree, base=base, base_tree=base_tree, head=head, tree=tree)


def test_policy_invalidation_includes_feature_base_changes_relative_to_protected_source(policy_stack):
    from bcf_governance.tooling.ci_authority_prospective_lanes import prospective_policy_binding
    f = policy_stack
    transition, policy = prospective_policy_binding(f.root, lane='trusted_exact_main', custody_state='ordinary_executable_controller',
        changed_paths=('README.md',), base_sha=f.base, base_tree=f.base_tree, candidate_sha=f.head, candidate_tree=f.tree, policy_context=f.context)
    assert transition == 'ordinary_authority_change'
    assert policy['source']['commit_sha'] == f.source
    assert policy['source']['tree_sha'] == f.source_tree
    assert policy['source']['policy_sha256'] != policy['candidate']['policy_sha256']
    assert f.context.base_sha == f.base


@pytest.mark.parametrize('cause', ['partial-sha', 'partial-tree', 'missing-snapshot', 'wrong-tree', 'wrong-comparison', 'wrong-head', 'unknown-commit'])
def test_policy_context_rejects_incomplete_or_wrong_source_subject(policy_stack, cause):
    from dataclasses import replace
    from bcf_governance.tooling.ci_authority_prospective_lanes import prospective_policy_binding, ProspectiveLaneError
    f = policy_stack
    fields = {'partial-sha': {'protected_default_sha': None}, 'partial-tree': {'protected_default_tree': None},
        'missing-snapshot': {'protected_default_sha': None, 'protected_default_tree': None},
        'wrong-tree': {'protected_default_tree': f.tree}, 'wrong-comparison': {'base_sha': f.source},
        'wrong-head': {'head_sha': f.base}, 'unknown-commit': {'protected_default_sha': '0' * 40}}
    with pytest.raises(ProspectiveLaneError):
        prospective_policy_binding(f.root, lane='trusted_exact_main', custody_state='ordinary_executable_controller', changed_paths=('README.md',),
            base_sha=f.base, base_tree=f.base_tree, candidate_sha=f.head, candidate_tree=f.tree, policy_context=replace(f.context, **fields[cause]))

def test_source_distribution_failure_rejects_before_provider_and_preserves_cause(monkeypatch, tmp_path):
    _front_door(monkeypatch, [])
    events = []
    failure = prospective.PreflightError('source distribution failed: source manifest omits tracked source: audits/collector.py')
    def reject(*_a, **_k):
        raise failure
    monkeypatch.setattr(prospective, '_pack_manifest', reject, raising=False)
    monkeypatch.setattr(prospective, 'verify_provider_workflow_authority', lambda *_a, **_k: pytest.fail('provider reached before source distribution rejection'))
    with pytest.raises(prospective.ProspectiveValidationError, match='source manifest omits') as caught:
        prospective._run_prospective_train(tmp_path, **TRAIN, python_executable=Path('/python'), execute_evidence=False,
            repository='owner/repo', provider_api=object(), runner=_runner, progress_sink=events.append)
    assert caught.value.__cause__ is failure
    assert [(e['stage'], e['state']) for e in events[-2:]] == [('source_distribution', 'started'), ('source_distribution', 'failed')]


def test_prospective_cache_identity_receives_resolved_context_and_lane(monkeypatch, tmp_path):
    trace = []
    _front_door(monkeypatch, trace)
    context = LocalPRContext('origin', 'main', BASE, HEAD, 'feature', protected_default_sha=BASE, protected_default_tree=BASE_TREE)
    monkeypatch.setattr(prospective, 'resolve_local_pr_context', lambda *_a, **_k: context)
    monkeypatch.setattr(prospective, 'run_preflight', lambda *_a, **_k: {'status': 'pass', 'self_controller': 24,
        'verification_plan': {'execution_dag': {'nodes': [{'id': 'test', 'producer': 'test', 'depends_on': []}], 'edges': []}}})
    monkeypatch.setattr(prospective, 'planned_gate_targets', lambda *_a, **_k: ('test',))
    monkeypatch.setattr(prospective, 'validate_controller_custody_graph', lambda *_a, **_k: (_evaluation(), {'status': 'proved', 'custody_state': 'ordinary_executable_controller'}))
    monkeypatch.setattr(prospective, 'ordinary_authority_applicability', lambda *_a: 'bootstrap_provider_authority_absent')
    def identity(**kwargs):
        assert kwargs['comparison_context'] == {**context.as_dict(), 'validation_lane': 'provider_pr'}
        raise RuntimeError('proof context observed')
    monkeypatch.setattr(prospective, 'proof_identity', identity)
    with pytest.raises(RuntimeError, match='proof context observed'):
        prospective._run_prospective_train(tmp_path, **TRAIN, python_executable=Path('/python'),
            repository='owner/repo', runner=_runner)


def test_rendered_budget_failure_precedes_costly_qualification_with_exact_existing_owner(monkeypatch, tmp_path):
    import yaml
    from bcf_governance.tooling import preflight
    from bcf_governance.tooling.governance_validation import preflight_distribution as distribution
    from bcf_governance.tooling.profile_yaml import render_profile_surface
    trace = []
    _front_door(monkeypatch, trace)
    (tmp_path/'bcf_governance/pack/template-repo').mkdir(parents=True)
    (tmp_path/'governance').mkdir()
    payload = {f'k{index}': 'x' for index in range(140)}
    raw = yaml.safe_dump(payload, sort_keys=False)
    assert len(raw.encode()) <= 1024 < len(render_profile_surface(payload, width=4096).encode())
    contract = tmp_path/'governance/gate-contracts.yml'
    contract.write_text(raw)
    manifest = {'context_budgets': {'agent_required_files': {
        'governance/gate-contracts.yml': {'line_hard_cap': 800, 'kib_hard_cap': 1}}}}
    (tmp_path/'governance/artifact-manifest.yml').write_text(yaml.safe_dump(manifest))
    monkeypatch.setattr(distribution, '_pack_manifest_entries', lambda *_a: {})
    monkeypatch.setattr(distribution, 'derive_interpreter_environment', lambda *_a: None)
    monkeypatch.setattr(distribution, 'validate_source_distribution', lambda *_a, **_k: {'applicable': True})
    monkeypatch.setattr(prospective, '_pack_manifest', preflight._pack_manifest)
    monkeypatch.setattr(prospective, '_exposure_scan', lambda *_a: trace.append('exposure'))
    def forbidden(*_a, **_k): pytest.fail('rendered budget failure reached costly qualification or provider')
    monkeypatch.setattr(prospective, '_negative_control_targets', forbidden)
    monkeypatch.setattr(prospective, '_semantic_ownership', forbidden)
    monkeypatch.setattr(prospective, 'verify_provider_workflow_authority', forbidden)
    events = []
    with pytest.raises(prospective.ProspectiveValidationError, match='exceeded context budgets'):
        prospective._run_prospective_train(tmp_path, **TRAIN, python_executable=Path('/python'),
            execute_evidence=False, repository='owner/repo', provider_api=object(), runner=_runner,
            progress_sink=events.append)
    assert trace == ['reconcile', 'exposure']
    assert [(e['stage'], e['state']) for e in events[-2:]] == [('source_distribution','started'),('source_distribution','failed')]
    assert contract.read_text() == raw

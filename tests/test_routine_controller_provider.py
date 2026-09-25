from __future__ import annotations

import copy
import io
import json
from pathlib import Path
from types import SimpleNamespace
import zipfile

import pytest
import yaml

from bcf_governance.tooling.ci_github_identity import (
    GitHubControllerError,
    MainIdentity,
)
from bcf_governance.tooling import routine_controller_provider as provider
from bcf_governance.tooling.routine_controller_rotation import (
    AUTHORIZE_JOB,
    RoutineCallbackTopologyError,
    classify_callback_topology,
    skipped_matrix_facades,
    transition_id,
)
from bcf_governance.tooling.ci_authority_contracts import authority_role_jobs


ROOT = Path(__file__).resolve().parents[1]
OLD = "1" * 40
NEW = "2" * 40
TREE = "3" * 40
MAIN = MainIdentity("1207503211", "main", NEW, TREE)


def _pin(commit: str = NEW) -> dict[str, str]:
    return {
        "BCF_BOOTSTRAP_ARTIFACT_ID": "20",
        "BCF_BOOTSTRAP_ARTIFACT_NAME": f"bcf-trusted-control-{commit}-1",
        "BCF_BOOTSTRAP_ARTIFACT_DIGEST": "sha256:" + "4" * 64,
        "BCF_BOOTSTRAP_RUN_ID": "10",
        "BCF_BOOTSTRAP_RUN_ATTEMPT": "1",
        "BCF_BOOTSTRAP_COMMIT_SHA": commit,
        "BCF_BOOTSTRAP_TREE_SHA": TREE,
        "BCF_BOOTSTRAP_REPOSITORY_ID": "1207503211",
        "BCF_BOOTSTRAP_WHEEL_SHA256": "6" * 64,
    }


def _authorized() -> dict:
    identity = transition_id(
        repository_id="1207503211",
        installed_commit=OLD,
        subject_commit=NEW,
        subject_tree=TREE,
        artifact_digest="sha256:" + "4" * 64,
    )
    return {
        "schema_version": "1.0",
        "transition_id": identity,
        "state": "authorized",
        "repository": {
            "id": "1207503211",
            "full_name": "mjgolaszewski/bcf-governance",
        },
        "subject": {"commit_sha": NEW, "tree_sha": TREE},
        "authority": {
            "installed_controller_commit": OLD,
            "admission_run_id": "10",
            "admission_run_attempt": "1",
            "implementation_pr": "260",
            "policy_before_sha256": "5" * 64,
            "policy_after_sha256": "5" * 64,
        },
        "artifact": {
            "id": "20",
            "name": f"bcf-trusted-control-{NEW}-1",
            "provider_digest": "sha256:" + "4" * 64,
            "wheel_sha256": "6" * 64,
            "run_id": "10",
            "run_attempt": "1",
            "commit_sha": NEW,
            "tree_sha": TREE,
        },
        "required_runners": [
            "bcf-trusted-control-1",
            "bcf-trusted-control-2",
        ],
        "bootstrap": [],
        "probe": [],
        "promotion": [],
    }


def _active() -> dict:
    value = _authorized()
    value["state"] = "active"
    proofs = [
        {
            "runner": runner,
            "controller_commit": NEW,
            "run_id": "30",
            "run_attempt": "1",
            "job_id": str(100 + index),
        }
        for index, runner in enumerate(value["required_runners"], 1)
    ]
    for stage in ("bootstrap", "probe", "promotion"):
        value[stage] = copy.deepcopy(proofs)
    value["activation"] = {
        "transition_id": value["transition_id"],
        "authorizing_controller_commit": OLD,
        "run_id": "30",
        "run_attempt": "1",
    }
    return value


def _transition_zip(value: dict) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        archive.writestr(provider.TRANSITION_REPORT, json.dumps(value))
    return buffer.getvalue()


def test_authorization_binds_protected_merge_policy_and_exact_artifact(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    source = MainIdentity("1207503211", "main", "7" * 40, "8" * 40)
    pull = {"number": 260, "merged_at": "2026-09-23T00:00:00Z"}
    monkeypatch.setattr(provider, "resolve_main", lambda *_args, **_kwargs: MAIN)
    monkeypatch.setattr(
        provider, "resolve_run_subject", lambda *_args, **_kwargs: MAIN
    )
    monkeypatch.setattr(provider, "load_authority", lambda *_args, **_kwargs: {})
    monkeypatch.setattr(provider, "authenticate_role_run", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(
        provider,
        "classify_admission_topology",
        lambda *_args, **_kwargs: SimpleNamespace(
            state=provider.AdmissionTopologyState.PENDING_ROTATION,
            reason="pending_controller_rotation",
        ),
    )
    monkeypatch.setattr(
        provider,
        "resolve_effective_controller",
        lambda *_args, **_kwargs: {"pin": _pin(OLD)},
    )
    monkeypatch.setattr(
        provider, "compile_self_controller_pin", lambda *_args, **_kwargs: _pin()
    )
    monkeypatch.setattr(
        provider,
        "authenticate_merged_pull",
        lambda *_args, **_kwargs: (
            pull,
            SimpleNamespace(checkout_sha="9" * 40),
            source,
            "feature",
        ),
    )
    monkeypatch.setattr(
        provider, "authenticate_pr_certification", lambda *_args, **_kwargs: ({}, "1", 1)
    )
    monkeypatch.setattr(provider, "_policy_digest", lambda *_args, **_kwargs: "5" * 64)
    monkeypatch.setattr(
        provider,
        "_runner_policy",
        lambda *_args, **_kwargs: (
            _pin(OLD),
            {"installed_commit_sha": OLD},
            ("bcf-trusted-control-1", "bcf-trusted-control-2"),
        ),
    )
    receipt = provider.authorize_transition(
        object(),
        repository="mjgolaszewski/bcf-governance",
        admission_run_id="10",
        admission_run_attempt="1",
        artifact_dir=tmp_path,
    )
    assert receipt == {
        "schema_version": "1.0",
        "decision": "routine_transition_authorized",
        "transition_class": "runtime_only",
        "applicable": True,
        "reason": "pending_controller_rotation",
        "transition": _authorized(),
    }


def test_authorization_closes_current_controller_as_no_transition(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setattr(provider, "resolve_main", lambda *_args, **_kwargs: MAIN)
    monkeypatch.setattr(
        provider, "resolve_run_subject", lambda *_args, **_kwargs: MAIN
    )
    monkeypatch.setattr(provider, "load_authority", lambda *_args, **_kwargs: {})
    monkeypatch.setattr(provider, "authenticate_role_run", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(
        provider,
        "classify_admission_topology",
        lambda *_args, **_kwargs: SimpleNamespace(
            state=provider.AdmissionTopologyState.CERTIFIABLE,
            reason="complete",
        ),
    )
    monkeypatch.setattr(
        provider,
        "compile_self_controller_pin",
        lambda *_args, **_kwargs: pytest.fail(
            "a current topology must not select a controller artifact"
        ),
    )

    result = provider.authorize_transition(
        object(),
        repository="mjgolaszewski/bcf-governance",
        admission_run_id="10",
        admission_run_attempt="1",
        artifact_dir=tmp_path,
    )

    assert result == {
        "schema_version": "1.0",
        "decision": "no_transition",
        "transition_class": "none",
        "applicable": False,
        "reason": "controller_current",
        "subject": {"commit_sha": NEW, "tree_sha": TREE},
        "admission": {"run_id": "10", "run_attempt": "1"},
        "release_authority": False,
    }


def test_authorization_routes_policy_change_out_of_routine_rotation(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setattr(provider, "resolve_main", lambda *_args, **_kwargs: MAIN)
    monkeypatch.setattr(
        provider, "resolve_run_subject", lambda *_args, **_kwargs: MAIN
    )
    monkeypatch.setattr(provider, "load_authority", lambda *_args, **_kwargs: {})
    monkeypatch.setattr(provider, "authenticate_role_run", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(
        provider,
        "classify_admission_topology",
        lambda *_args, **_kwargs: SimpleNamespace(
            state=provider.AdmissionTopologyState.PENDING_ROTATION,
            reason="pending_controller_rotation",
        ),
    )
    monkeypatch.setattr(
        provider,
        "resolve_effective_controller",
        lambda *_args, **_kwargs: {"pin": _pin(OLD)},
    )
    monkeypatch.setattr(
        provider, "compile_self_controller_pin", lambda *_args, **_kwargs: _pin()
    )
    monkeypatch.setattr(
        provider,
        "authenticate_merged_pull",
        lambda *_args, **_kwargs: (
            {"number": 260, "merged_at": "2026-09-23T00:00:00Z"},
            SimpleNamespace(checkout_sha="9" * 40),
            MainIdentity("1207503211", "main", "7" * 40, "8" * 40),
            "feature",
        ),
    )
    monkeypatch.setattr(
        provider, "authenticate_pr_certification", lambda *_args, **_kwargs: ({}, "1", 1)
    )
    monkeypatch.setattr(
        provider,
        "_runner_policy",
        lambda *_args, **_kwargs: (
            _pin(OLD),
            {"installed_commit_sha": OLD},
            ("bcf-trusted-control-1", "bcf-trusted-control-2"),
        ),
    )
    values = iter(("5" * 64, "6" * 64))
    monkeypatch.setattr(provider, "_policy_digest", lambda *_args, **_kwargs: next(values))
    result = provider.authorize_transition(
        object(), repository="mjgolaszewski/bcf-governance",
        admission_run_id="10", admission_run_attempt="1", artifact_dir=tmp_path,
    )
    assert result == {
        "schema_version": "1.0",
        "decision": "alternate_lane_required",
        "transition_class": "protected_policy_change",
        "applicable": False,
        "reason": "authorization_policy_changed",
        "subject": {"commit_sha": NEW, "tree_sha": TREE},
        "admission": {"run_id": "10", "run_attempt": "1"},
        "authority": {
            "installed_controller_commit": OLD,
            "implementation_pr": "260",
            "candidate_commit_sha": "9" * 40,
            "source_main_commit_sha": "7" * 40,
            "policy_before_sha256": "5" * 64,
            "policy_after_sha256": "6" * 64,
        },
        "target": _pin(),
        "alternate_lane": {
            "id": "ordinary_protected_n_n_plus_1",
            "required_sequence": list(provider.ALTERNATE_POLICY_LANE_SEQUENCE),
            "required_initial_state": "ordinary-pending-rotation",
            "required_terminal_state": "ordinary-current",
        },
        "release_authority": False,
    }


def test_unrelated_noncertifying_topology_cannot_become_no_transition(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setattr(provider, "resolve_main", lambda *_args, **_kwargs: MAIN)
    monkeypatch.setattr(provider, "resolve_run_subject", lambda *_args, **_kwargs: MAIN)
    monkeypatch.setattr(provider, "load_authority", lambda *_args, **_kwargs: {})
    monkeypatch.setattr(provider, "authenticate_role_run", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(
        provider,
        "classify_admission_topology",
        lambda *_args, **_kwargs: SimpleNamespace(
            state=provider.AdmissionTopologyState.NONCERTIFYING,
            reason="producer_inventory_incomplete",
        ),
    )
    monkeypatch.setattr(
        provider,
        "compile_self_controller_pin",
        lambda *_args, **_kwargs: pytest.fail("failed topology selected a target"),
    )
    with pytest.raises(GitHubControllerError, match="producer_inventory_incomplete"):
        provider.authorize_transition(
            object(), repository="mjgolaszewski/bcf-governance",
            admission_run_id="10", admission_run_attempt="1", artifact_dir=tmp_path,
        )


def test_alternate_lane_decision_rejects_ambiguous_or_broadened_routes() -> None:
    route = {
        "schema_version": "1.0",
        "decision": "alternate_lane_required",
        "transition_class": "protected_policy_change",
        "applicable": False,
        "reason": "authorization_policy_changed",
        "subject": {"commit_sha": NEW, "tree_sha": TREE},
        "admission": {"run_id": "10", "run_attempt": "1"},
        "authority": {
            "installed_controller_commit": OLD,
            "implementation_pr": "260",
            "candidate_commit_sha": "9" * 40,
            "source_main_commit_sha": "7" * 40,
            "policy_before_sha256": "5" * 64,
            "policy_after_sha256": "6" * 64,
        },
        "target": _pin(),
        "alternate_lane": {
            "id": "ordinary_protected_n_n_plus_1",
            "required_sequence": list(provider.ALTERNATE_POLICY_LANE_SEQUENCE),
            "required_initial_state": "ordinary-pending-rotation",
            "required_terminal_state": "ordinary-current",
        },
        "release_authority": False,
    }
    assert provider.validate_routine_decision(route) == route
    for mutation in (
        lambda value: value.update(release_authority=True),
        lambda value: value["alternate_lane"].update(id="carry_on"),
        lambda value: value["authority"].update(policy_after_sha256="5" * 64),
        lambda value: value.update(unowned="ambiguous"),
    ):
        candidate = copy.deepcopy(route)
        mutation(candidate)
        with pytest.raises(GitHubControllerError):
            provider.validate_routine_decision(candidate)


def test_authorization_rejects_self_selection(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setattr(provider, "resolve_main", lambda *_args, **_kwargs: MAIN)
    monkeypatch.setattr(provider, "resolve_run_subject", lambda *_args, **_kwargs: MAIN)
    monkeypatch.setattr(provider, "load_authority", lambda *_args, **_kwargs: {})
    monkeypatch.setattr(provider, "authenticate_role_run", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(
        provider,
        "classify_admission_topology",
        lambda *_args, **_kwargs: SimpleNamespace(
            state=provider.AdmissionTopologyState.PENDING_ROTATION,
            reason="pending_controller_rotation",
        ),
    )
    monkeypatch.setattr(
        provider,
        "resolve_effective_controller",
        lambda *_args, **_kwargs: {"pin": _pin()},
    )
    monkeypatch.setattr(provider, "compile_self_controller_pin", lambda *_args, **_kwargs: _pin())
    with pytest.raises(GitHubControllerError, match="no new target"):
        provider.authorize_transition(
            object(), repository="mjgolaszewski/bcf-governance",
            admission_run_id="10", admission_run_attempt="1", artifact_dir=tmp_path,
        )


class StageAPI:
    def __init__(self, jobs: tuple[dict, ...]) -> None:
        self._jobs = jobs

    def jobs(self, *_args, **_kwargs):
        return self._jobs


def _jobs(prefix: str) -> tuple[dict, ...]:
    return tuple(
        {
            "id": 100 + index,
            "name": prefix + runner,
            "status": "completed",
            "conclusion": "success",
        }
        for index, runner in enumerate(
            ("bcf-trusted-control-1", "bcf-trusted-control-2"), 1
        )
    )


def test_provider_stages_require_exact_green_runner_inventory(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        provider, "resolve_run_subject", lambda *_args, **_kwargs: MAIN
    )
    monkeypatch.setattr(provider, "resolve_main", lambda *_args, **_kwargs: MAIN)
    monkeypatch.setattr(
        provider,
        "load_authority",
        lambda *_args, **_kwargs: {
            "schema_version": "1.1",
            "roles": {"controller_rotation": "rotation"},
            "workflow_registry": {
                "rotation": {
                    "expected_jobs": [
                        {"job_id": prefix + runner}
                        for prefix in provider.STAGE_JOB_PREFIXES.values()
                        for runner in (
                            "bcf-trusted-control-1",
                            "bcf-trusted-control-2",
                        )
                    ]
                }
            },
        },
    )
    monkeypatch.setattr(
        provider,
        "authenticate_role_run",
        lambda *_args, **_kwargs: SimpleNamespace(run_id="30", run_attempt=1),
    )
    installing = provider.advance_provider_transition(
        StageAPI(_jobs(provider.STAGE_JOB_PREFIXES["bootstrap"])),
        repository="mjgolaszewski/bcf-governance",
        receipt=_authorized(),
        stage="bootstrap",
        rotation_run_id="30",
        rotation_run_attempt="1",
    )
    assert installing["state"] == "installing"
    incomplete = _jobs(provider.STAGE_JOB_PREFIXES["bootstrap"])[:1]
    with pytest.raises(GitHubControllerError, match="not exactly green"):
        provider.advance_provider_transition(
            StageAPI(incomplete),
            repository="mjgolaszewski/bcf-governance",
            receipt=_authorized(),
            stage="bootstrap",
            rotation_run_id="30",
            rotation_run_attempt="1",
        )


def test_effective_controller_uses_only_linear_authenticated_chain(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    active = _active()
    monkeypatch.setattr(provider, "resolve_main", lambda *_args, **_kwargs: MAIN)
    monkeypatch.setattr(
        provider,
        "_runner_policy",
        lambda *_args, **_kwargs: (
            _pin(OLD),
            {"installed_commit_sha": OLD, "subject_commit_sha": OLD},
            tuple(active["required_runners"]),
        ),
    )
    monkeypatch.setattr(
        provider,
        "load_authority",
        lambda *_args, **_kwargs: {
            "schema_version": "1.1",
            "roles": {"controller_rotation": "rotation"}
        },
    )
    monkeypatch.setattr(provider, "_active_receipts", lambda *_args, **_kwargs: (active,))
    resolved = provider.resolve_effective_controller(
        object(), repository="mjgolaszewski/bcf-governance"
    )
    assert resolved["source"] == "provider_transition"
    assert resolved["pin"]["BCF_BOOTSTRAP_COMMIT_SHA"] == NEW


def test_transition_artifact_inventory_is_closed() -> None:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        archive.writestr(provider.TRANSITION_REPORT, json.dumps(_authorized()))
    assert provider._receipt_from_zip(buffer.getvalue())["state"] == "authorized"
    bad = io.BytesIO()
    with zipfile.ZipFile(bad, "w") as archive:
        archive.writestr(provider.TRANSITION_REPORT, json.dumps(_authorized()))
        archive.writestr("extra.json", "{}")
    with pytest.raises(GitHubControllerError, match="inventory"):
        provider._receipt_from_zip(bad.getvalue())


def test_callback_binds_completed_rotation_before_dispatch(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    active = _active()
    dispatched: list[tuple[str, dict]] = []
    authority = yaml.safe_load((ROOT / "governance/ci-authority.yml").read_text())
    expected = [
        value["job_id"] for value in authority_role_jobs(authority, "controller_rotation")
    ]
    api = SimpleNamespace(
        dispatch=lambda _repo, *, event_type, client_payload: dispatched.append(
            (event_type, client_payload)
        ),
        jobs=lambda *_args, **_kwargs: tuple(
            {"name": name, "conclusion": "skipped" if name.startswith("Commit ") else "success"}
            for name in expected
        ),
    )
    monkeypatch.setattr(provider, "resolve_main", lambda *_args, **_kwargs: MAIN)
    monkeypatch.setattr(
        provider,
        "load_authority",
        lambda *_args, **_kwargs: authority,
    )
    monkeypatch.setattr(
        provider,
        "authenticate_role_run",
        lambda *_args, role, **_kwargs: SimpleNamespace(
            run_id="40" if role == "controller_rotation_callback" else "30",
            run_attempt=1,
        ),
    )
    monkeypatch.setattr(
        provider,
        "resolve_effective_controller",
        lambda *_args, **_kwargs: {
            "source": "provider_transition",
            "normalization_subject": OLD,
            "subject": {"commit_sha": NEW, "tree_sha": TREE},
            "pin": _pin(),
            "transition_ids": [active["transition_id"]],
        },
    )
    monkeypatch.setattr(
        provider, "_active_receipts", lambda *_args, **_kwargs: (active,)
    )
    result = provider.dispatch_post_rotation_certification(
        api,
        repository="mjgolaszewski/bcf-governance",
        callback_run_id="40",
        callback_run_attempt="1",
        rotation_run_id="30",
        rotation_run_attempt="1",
    )
    assert result["rotation_run_id"] == "30"
    assert dispatched == [
        (
            "bcf-controller-rotation-certified",
            {
                "subject_commit": NEW,
                "subject_tree": TREE,
                "transition_id": active["transition_id"],
            },
        )
    ]


def test_callback_rejects_another_rotation_run(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    active = _active()
    authority = yaml.safe_load((ROOT / "governance/ci-authority.yml").read_text())
    monkeypatch.setattr(provider, "resolve_main", lambda *_args, **_kwargs: MAIN)
    monkeypatch.setattr(provider, "load_authority", lambda *_args, **_kwargs: authority)
    monkeypatch.setattr(
        provider,
        "authenticate_role_run",
        lambda *_args, role, **_kwargs: SimpleNamespace(
            run_id="40" if role == "controller_rotation_callback" else "31",
            run_attempt=1,
        ),
    )
    monkeypatch.setattr(
        provider,
        "resolve_effective_controller",
        lambda *_args, **_kwargs: {
            "source": "provider_transition",
            "normalization_subject": OLD,
            "subject": {},
            "pin": _pin(),
            "transition_ids": [active["transition_id"]],
        },
    )
    monkeypatch.setattr(
        provider, "_active_receipts", lambda *_args, **_kwargs: (active,)
    )
    expected = [
        value["job_id"] for value in authority_role_jobs(authority, "controller_rotation")
    ]
    with pytest.raises(GitHubControllerError, match="does not bind"):
        provider.dispatch_post_rotation_certification(
            SimpleNamespace(jobs=lambda *_args, **_kwargs: tuple(
                {"name": name, "conclusion": "skipped" if name.startswith("Commit ") else "success"}
                for name in expected
            )),
            repository="mjgolaszewski/bcf-governance",
            callback_run_id="40",
            callback_run_attempt="1",
            rotation_run_id="31",
            rotation_run_attempt="1",
        )


def test_callback_closes_exact_no_transition_without_dispatch(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    authority = yaml.safe_load((ROOT / "governance/ci-authority.yml").read_text())
    _, _, jobs = _collapsed_no_transition()
    workflow = authority["workflow_registry"][authority["roles"]["controller_rotation"]]
    raw = (ROOT / workflow["active_path"]).read_bytes()
    dispatched: list[object] = []
    api = SimpleNamespace(
        jobs=lambda *_args, **_kwargs: tuple(jobs),
        content=lambda *_args, **_kwargs: SimpleNamespace(
            content=raw, blob_oid=workflow["trusted_workflow_blob_oid"]
        ),
        dispatch=lambda *_args, **_kwargs: dispatched.append(True),
    )
    monkeypatch.setattr(provider, "resolve_main", lambda *_args, **_kwargs: MAIN)
    monkeypatch.setattr(provider, "load_authority", lambda *_args, **_kwargs: authority)
    monkeypatch.setattr(
        provider,
        "authenticate_role_run",
        lambda *_args, role, **_kwargs: SimpleNamespace(
            run_id="40" if role == "controller_rotation_callback" else "30",
            run_attempt=1,
        ),
    )
    result = provider.dispatch_post_rotation_certification(
        api,
        repository="mjgolaszewski/bcf-governance",
        callback_run_id="40",
        callback_run_attempt="1",
        rotation_run_id="30",
        rotation_run_attempt="1",
    )
    assert result == {
        "status": "no_transition",
        "dispatched": False,
        "subject": {"commit_sha": NEW, "tree_sha": TREE},
        "rotation_run_id": "30",
        "rotation_run_attempt": 1,
        "release_authority": False,
    }
    assert dispatched == []


def _collapsed_no_transition() -> tuple[set[str], dict[str, set[str]], list[dict[str, str]]]:
    authority = yaml.safe_load((ROOT / "governance/ci-authority.yml").read_text())
    workflow = authority["workflow_registry"][authority["roles"]["controller_rotation"]]
    raw = (ROOT / workflow["active_path"]).read_bytes()
    expected = {
        str(value["job_id"])
        for value in authority_role_jobs(authority, "controller_rotation")
    }
    facades = skipped_matrix_facades(raw, expected_jobs=expected)
    definitions = yaml.safe_load(raw)["jobs"]
    jobs = [
        {
            "name": str(value.get("name", source)),
            "conclusion": (
                "success"
                if str(value.get("name", source)) == AUTHORIZE_JOB
                else "skipped"
            ),
        }
        for source, value in definitions.items()
    ]
    return expected, facades, jobs


def test_callback_accepts_exact_provider_collapsed_no_transition() -> None:
    expected, facades, jobs = _collapsed_no_transition()
    assert classify_callback_topology(
        expected_jobs=expected, jobs=jobs, skipped_facades=facades
    ) == "no_transition"


@pytest.mark.parametrize("mutation", ("facade_success", "expanded_laundering", "extra"))
def test_callback_collapsed_no_transition_still_fails_closed(mutation: str) -> None:
    expected, facades, jobs = _collapsed_no_transition()
    facade = next(iter(facades))
    if mutation == "facade_success":
        next(value for value in jobs if value["name"] == facade)["conclusion"] = "success"
    elif mutation == "expanded_laundering":
        jobs.append({"name": next(iter(facades[facade])), "conclusion": "skipped"})
    else:
        jobs.append({"name": "Undeclared rotation job", "conclusion": "skipped"})
    with pytest.raises(RoutineCallbackTopologyError):
        classify_callback_topology(
            expected_jobs=expected, jobs=jobs, skipped_facades=facades
        )


@pytest.mark.parametrize("mutation", ("missing", "extra", "partial"))
def test_callback_rejects_nonexact_no_transition_topology(
    monkeypatch: pytest.MonkeyPatch, mutation: str
) -> None:
    authority = yaml.safe_load((ROOT / "governance/ci-authority.yml").read_text())
    expected = [
        value["job_id"]
        for value in provider.authority_role_jobs(authority, "controller_rotation")
    ]
    jobs = [
        {
            "name": name,
            "conclusion": (
                "success"
                if name == "Authorize protected routine controller transition"
                else "skipped"
            ),
        }
        for name in expected
    ]
    if mutation == "missing":
        jobs.pop()
    elif mutation == "extra":
        jobs.append({"name": "Undeclared rotation job", "conclusion": "skipped"})
    else:
        jobs[-1]["conclusion"] = "success"
    monkeypatch.setattr(provider, "resolve_main", lambda *_args, **_kwargs: MAIN)
    monkeypatch.setattr(provider, "load_authority", lambda *_args, **_kwargs: authority)
    monkeypatch.setattr(
        provider,
        "authenticate_role_run",
        lambda *_args, role, **_kwargs: SimpleNamespace(
            run_id="40" if role == "controller_rotation_callback" else "30",
            run_attempt=1,
        ),
    )
    workflow = authority["workflow_registry"][authority["roles"]["controller_rotation"]]
    raw = (ROOT / workflow["active_path"]).read_bytes()
    api = SimpleNamespace(
        jobs=lambda *_args, **_kwargs: tuple(jobs),
        content=lambda *_args, **_kwargs: SimpleNamespace(
            content=raw, blob_oid=workflow["trusted_workflow_blob_oid"]
        ),
    )
    error = "inventory is not exact" if mutation != "partial" else "topology is partial"
    with pytest.raises(GitHubControllerError, match=error):
        provider.dispatch_post_rotation_certification(
            api,
            repository="mjgolaszewski/bcf-governance",
            callback_run_id="40",
            callback_run_attempt="1",
            rotation_run_id="30",
            rotation_run_attempt="1",
        )


@pytest.mark.parametrize("failure", ("digest", "repository", "expired"))
def test_active_transition_artifact_fails_closed_on_provider_custody(
    monkeypatch: pytest.MonkeyPatch, failure: str
) -> None:
    active = _active()
    if failure == "repository":
        active["repository"]["full_name"] = "other/repository"
    raw = _transition_zip(active)
    artifact = {
        "id": 50,
        "name": provider.TRANSITION_ARTIFACT_PREFIX + active["transition_id"],
        "digest": "sha256:" + provider._sha256(raw),
        "expired": False,
        "workflow_run": {
            "id": 30,
            "repository_id": int(MAIN.repository_id),
            "head_repository_id": int(MAIN.repository_id),
            "head_branch": MAIN.default_branch,
            "head_sha": NEW,
        },
    }
    if failure == "digest":
        artifact["digest"] = "sha256:" + "0" * 64
    if failure == "expired":
        artifact["expired"] = True
    api = SimpleNamespace(
        repository_artifacts=lambda _repository: (artifact,),
        artifact_bytes=lambda *_args, **_kwargs: raw,
    )
    monkeypatch.setattr(provider, "_is_ancestor", lambda *_args, **_kwargs: True)
    monkeypatch.setattr(
        provider, "resolve_run_subject", lambda *_args, **_kwargs: MAIN
    )
    monkeypatch.setattr(provider, "load_authority", lambda *_args, **_kwargs: {})
    monkeypatch.setattr(provider, "authenticate_role_run", lambda *_args, **_kwargs: None)
    message = {
        "digest": "bytes do not match",
        "repository": "repository identity",
        "expired": "expired",
    }[failure]
    with pytest.raises(GitHubControllerError, match=message):
        provider._active_receipts(
            api,
            "mjgolaszewski/bcf-governance",
            current=MAIN,
            normalization_subject=OLD,
        )

from __future__ import annotations

import copy
import hashlib
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
from bcf_governance.tooling import (
    ci_controller_provider,
    routine_controller_materialization as materialization,
    routine_controller_provider as provider,
)
from bcf_governance.tooling.routine_controller_rotation import (
    ALTERNATE_POLICY_LANE_SEQUENCE,
    AUTHORIZE_JOB,
    OUTCOME_JOB,
    RoutineCallbackTopologyError,
    classify_callback_topology,
    skipped_matrix_facades,
    transition_id,
)
from bcf_governance.tooling.ci_authority_contracts import authority_role_jobs
from bcf_governance.tooling.ci_authority_pins import compiled_workflow_job_names
from bcf_governance.tooling.controller_custody import compile_controller_custody


ROOT = Path(__file__).resolve().parents[1]
OLD = "1" * 40
NEW = "2" * 40
TREE = "3" * 40
MAIN = MainIdentity("1207503211", "main", NEW, TREE)


def test_adopter_controller_policy_is_resolved_without_self_authority() -> None:
    paths = [
        "governance/ci-extensions/bcf-controller-rotation.yml",
        "governance/ci-graph.yml",
        "governance/github-protection.yml",
        "governance/trusted-controller-policy.yml",
        "schemas/controller-transition.schema.json",
    ]
    policy = {
        "schema_version": "1.0",
        "runner_security": {
            "trusted_labels": ["Linux", "X64", "fixture", "self-hosted"],
            "trusted_instance_labels": ["fixture-control-1", "fixture-control-2"],
            "trusted_controller_artifact": _pin(OLD),
            "trusted_controller_installation": {
                "schema_version": "1.0",
                "installed_commit_sha": OLD,
                "subject_commit_sha": OLD,
                "subject_tree_sha": TREE,
                "bootstrap_run_id": "1",
                "bootstrap_run_attempt": "1",
                "probe_run_id": "2",
                "probe_run_attempt": "1",
            },
        },
        "rotation_policy_paths": paths,
    }
    graph = {
        "trusted_controller": {
            "kind": "governed_controller_policy",
            "policy_path": "governance/trusted-controller-policy.yml",
        }
    }
    content = {
        "governance/ci-graph.yml": yaml.safe_dump(graph).encode(),
        "governance/trusted-controller-policy.yml": yaml.safe_dump(policy).encode(),
    }

    class API:
        def content(self, _repository: str, path: str, *, ref: str):
            assert ref == NEW
            return SimpleNamespace(content=content[path])

    resolved, policy_paths = ci_controller_provider.source_policy(
        API(), "owner/adopter", ref=NEW
    )

    assert resolved == policy
    assert policy_paths == tuple(paths)
    for path in paths:
        content.setdefault(path, path.encode())
    before = ci_controller_provider.policy_digest(
        API(), "owner/adopter", ref=NEW
    )
    content["governance/github-protection.yml"] = b"changed protection contract"
    assert ci_controller_provider.policy_digest(
        API(), "owner/adopter", ref=NEW
    ) != before


def test_adopter_controller_policy_rejects_foreign_repository(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    policy = {
        "runner_security": {
            "trusted_controller_artifact": _pin(OLD),
            "trusted_controller_installation": {
                "schema_version": "1.0",
                "installed_commit_sha": OLD,
                "subject_commit_sha": OLD,
                "subject_tree_sha": TREE,
                "bootstrap_run_id": "1",
                "bootstrap_run_attempt": "1",
                "probe_run_id": "2",
                "probe_run_attempt": "1",
            },
            "trusted_instance_labels": ["fixture-control-1", "fixture-control-2"],
        }
    }
    policy["runner_security"]["trusted_controller_artifact"][
        "BCF_BOOTSTRAP_REPOSITORY_ID"
    ] = "999"
    monkeypatch.setattr(
        ci_controller_provider,
        "source_policy",
        lambda *_args, **_kwargs: (policy, ()),
    )
    with pytest.raises(GitHubControllerError, match="another repository"):
        ci_controller_provider.runner_policy(
            object(), "owner/adopter", main=MAIN
        )


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


def _resolved(commit: str = OLD, *, source: str = "source_policy") -> dict:
    return {
        "source": source,
        "normalization_subject": commit,
        "subject": {"commit_sha": NEW, "tree_sha": TREE},
        "pin": _pin(commit),
        "transition_ids": [],
    }


def _custody(commit: str = OLD) -> dict:
    return compile_controller_custody(
        _resolved(commit), repository="mjgolaszewski/bcf-governance"
    )


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


def _alternate() -> dict:
    return {
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
            "required_sequence": list(ALTERNATE_POLICY_LANE_SEQUENCE),
            "required_initial_state": "ordinary-pending-rotation",
            "required_terminal_state": "ordinary-current",
        },
        "release_authority": False,
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


def _callback_outcome(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, value: dict
) -> None:
    path = tmp_path / "controller-rotation-outcome.json"
    path.write_text(json.dumps(value), encoding="utf-8")
    monkeypatch.setenv("BCF_CONTROLLER_CUSTODY_PATH", str(path))


def _rotation_authority() -> dict:
    authority = yaml.safe_load((ROOT / "governance/ci-authority.yml").read_text())
    workflow = authority["workflow_registry"][authority["roles"]["controller_rotation"]]
    raw = (ROOT / workflow["active_path"]).read_bytes()
    workflow["expected_jobs"] = [
        {"job_id": name} for name in compiled_workflow_job_names(raw)
    ]
    workflow["trusted_workflow_sha256"] = hashlib.sha256(raw).hexdigest()
    workflow["trusted_workflow_blob_oid"] = "local-candidate"
    return authority


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
        lambda *_args, **_kwargs: _resolved(),
    )
    monkeypatch.setattr(
        provider, "authenticate_admission_custody", lambda *_args, **_kwargs: _custody()
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
        provider, "resolve_effective_controller", lambda *_args, **_kwargs: _resolved()
    )
    monkeypatch.setattr(
        provider, "authenticate_admission_custody", lambda *_args, **_kwargs: _custody()
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
        "controller_custody": _custody(),
        "release_authority": False,
    }


def test_authorization_materializes_policy_change_as_governed_rotation(
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
        lambda *_args, **_kwargs: _resolved(),
    )
    monkeypatch.setattr(
        provider, "authenticate_admission_custody", lambda *_args, **_kwargs: _custody()
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
    expected = _authorized()
    expected["authority"]["policy_after_sha256"] = "6" * 64
    assert result == {
        "schema_version": "1.0",
        "decision": "routine_transition_authorized",
        "transition_class": "protected_policy_change",
        "applicable": True,
        "reason": "pending_protected_policy_rotation",
        "transition": expected,
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
    route = _alternate()
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


def test_installed_n_alternate_decision_materializes_exact_rotation(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    source = MainIdentity("1207503211", "main", "7" * 40, "8" * 40)
    monkeypatch.setattr(materialization, "resolve_main", lambda *_args, **_kwargs: MAIN)
    monkeypatch.setattr(materialization, "load_authority", lambda *_args, **_kwargs: {})
    monkeypatch.setattr(materialization, "authenticate_role_run", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(
        materialization, "resolve_effective_controller",
        lambda *_args, **_kwargs: {"pin": _pin(OLD)},
    )
    monkeypatch.setattr(
        materialization, "compile_self_controller_pin", lambda *_args, **_kwargs: _pin()
    )
    monkeypatch.setattr(
        materialization, "authenticate_merged_pull",
        lambda *_args, **_kwargs: (
            {"number": 260, "merged_at": "2026-09-23T00:00:00Z"},
            SimpleNamespace(checkout_sha="9" * 40), source, "feature",
        ),
    )
    monkeypatch.setattr(
        materialization, "authenticate_pr_certification",
        lambda *_args, **_kwargs: ({}, "1", 1),
    )
    values = iter(("5" * 64, "6" * 64))
    monkeypatch.setattr(materialization, "policy_digest", lambda *_args, **_kwargs: next(values))
    monkeypatch.setattr(
        materialization, "runner_policy",
        lambda *_args, **_kwargs: (
            _pin(OLD), {"installed_commit_sha": OLD},
            ("bcf-trusted-control-1", "bcf-trusted-control-2"),
        ),
    )
    result = materialization.materialize_transition_authorization(
        object(), repository="mjgolaszewski/bcf-governance",
        decision=_alternate(), artifact_dir=tmp_path,
    )

    assert result["decision"] == "routine_transition_authorized"
    assert result["transition_class"] == "protected_policy_change"
    assert result["transition"]["authority"]["policy_before_sha256"] != (
        result["transition"]["authority"]["policy_after_sha256"]
    )
    assert result["transition"]["subject"] == _alternate()["subject"]


def test_materialization_rejects_no_transition(tmp_path: Path) -> None:
    no_transition = {
        "schema_version": "1.0", "decision": "no_transition",
        "transition_class": "none", "applicable": False,
        "reason": "controller_current",
        "subject": {"commit_sha": NEW, "tree_sha": TREE},
        "admission": {"run_id": "10", "run_attempt": "1"},
        "controller_custody": _custody(),
        "release_authority": False,
    }
    with pytest.raises(GitHubControllerError, match="requires a rotation decision"):
        materialization.materialize_transition_authorization(
            object(), repository="mjgolaszewski/bcf-governance",
            decision=no_transition, artifact_dir=tmp_path,
        )


def test_current_authorized_decision_materializes_without_reinterpretation(
    tmp_path: Path,
) -> None:
    decision = {
        "schema_version": "1.0", "decision": "routine_transition_authorized",
        "transition_class": "runtime_only", "applicable": True,
        "reason": "pending_controller_rotation", "transition": _authorized(),
    }
    assert materialization.materialize_transition_authorization(
        object(), repository="mjgolaszewski/bcf-governance",
        decision=decision, artifact_dir=tmp_path,
    ) == decision
    mismatched = copy.deepcopy(decision)
    mismatched["transition_class"] = "protected_policy_change"
    mismatched["reason"] = "pending_protected_policy_rotation"
    with pytest.raises(GitHubControllerError, match="differs from exact policy custody"):
        provider.validate_routine_decision(mismatched)


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
        lambda *_args, **_kwargs: _resolved(NEW),
    )
    monkeypatch.setattr(
        provider, "authenticate_admission_custody", lambda *_args, **_kwargs: _custody(NEW)
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
    assert "transition_class" not in active  # Historical provider receipt shape.
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


def test_callback_binds_completed_rotation_before_exact_admission_rerun(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path,
) -> None:
    active = _active()
    reruns: list[object] = []
    authority = _rotation_authority()
    expected = [
        value["job_id"] for value in authority_role_jobs(authority, "controller_rotation")
    ]
    api = SimpleNamespace(
        rerun_workflow=lambda _repo, run_id: reruns.append(run_id),
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
            run_id={"controller_rotation_callback": "40", "controller_rotation": "30", "admission": "10"}[role],
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
    _callback_outcome(monkeypatch, tmp_path, active)
    result = provider.dispatch_post_rotation_certification(
        api,
        repository="mjgolaszewski/bcf-governance",
        callback_run_id="40",
        callback_run_attempt="1",
        rotation_run_id="30",
        rotation_run_attempt="1",
    )
    assert result["rotation_run_id"] == "30"
    assert result["status"] == "rerun_requested"
    assert result["source_run_id"] == "10"
    assert result["expected_run_attempt"] == 2
    assert result["release_authority"] is False
    assert reruns == ["10"]


def test_callback_rejects_another_rotation_run(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path,
) -> None:
    active = _active()
    authority = _rotation_authority()
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
            "subject": {"commit_sha": NEW, "tree_sha": TREE},
            "pin": _pin(),
            "transition_ids": [active["transition_id"]],
        },
    )
    monkeypatch.setattr(
        provider, "_active_receipts", lambda *_args, **_kwargs: (active,)
    )
    _callback_outcome(monkeypatch, tmp_path, active)
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


def test_callback_closes_exact_no_transition_without_rerun(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path,
) -> None:
    authority = _rotation_authority()
    _, _, jobs = _collapsed_no_transition()
    workflow = authority["workflow_registry"][authority["roles"]["controller_rotation"]]
    raw = (ROOT / workflow["active_path"]).read_bytes()
    reruns: list[object] = []
    api = SimpleNamespace(
        jobs=lambda *_args, **_kwargs: tuple(jobs),
        content=lambda *_args, **_kwargs: SimpleNamespace(
            content=raw, blob_oid=workflow["trusted_workflow_blob_oid"]
        ),
        rerun_workflow=lambda *_args, **_kwargs: reruns.append(True),
    )
    monkeypatch.setattr(provider, "resolve_main", lambda *_args, **_kwargs: MAIN)
    monkeypatch.setattr(provider, "load_authority", lambda *_args, **_kwargs: authority)
    monkeypatch.setattr(
        provider, "resolve_effective_controller", lambda *_args, **_kwargs: _resolved()
    )
    monkeypatch.setattr(
        provider,
        "authenticate_role_run",
        lambda *_args, role, **_kwargs: SimpleNamespace(
            run_id="40" if role == "controller_rotation_callback" else "30",
            run_attempt=1,
        ),
    )
    no_transition = {
        "schema_version": "1.0",
        "decision": "no_transition",
        "transition_class": "none",
        "applicable": False,
        "reason": "controller_current",
        "subject": {"commit_sha": NEW, "tree_sha": TREE},
        "admission": {"run_id": "10", "run_attempt": "1"},
        "controller_custody": _custody(),
        "release_authority": False,
    }
    _callback_outcome(monkeypatch, tmp_path, no_transition)
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
    assert reruns == []


def _collapsed_no_transition() -> tuple[set[str], dict[str, set[str]], list[dict[str, str]]]:
    authority = _rotation_authority()
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
                if str(value.get("name", source)) in {AUTHORIZE_JOB, OUTCOME_JOB}
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
    authority = _rotation_authority()
    expected = [
        value["job_id"]
        for value in provider.authority_role_jobs(authority, "controller_rotation")
    ]
    jobs = [
        {
            "name": name,
            "conclusion": (
                "success"
                if name in {AUTHORIZE_JOB, OUTCOME_JOB}
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
        next(
            value
            for value in jobs
            if str(value["name"]).startswith("Bootstrap routine controller")
        )["conclusion"] = "success"
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

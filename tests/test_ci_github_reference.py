from __future__ import annotations

from copy import deepcopy
import hashlib
from pathlib import Path
import re

import pytest
import yaml

from bcf_governance.tooling.ci_adopt_github import (
    ACTIVATION_EXPRESSION,
    FINALIZER_ACTIVATION_EXPRESSION,
    GithubAdoptionError,
    PUBLISHER_ACTIVATION_EXPRESSION,
    TRUSTED_CONTROLLER_TOKEN_ENV,
    apply_github_adoption,
    plan_github_adoption,
    render_github_adoption,
    render_github_control_plane,
)
from bcf_governance.tooling.ci_github import (
    DISPATCH_EVENTS,
    GithubReferenceError,
    authenticate_github_run,
    reference_topology,
    validate_reference_topology,
)
from bcf_governance.tooling.ci_github_actions import ACTION_PINS


SHA_A = "a" * 40
SHA_B = "b" * 40
SHA_C = "c" * 40


def _identity(**overrides: object):
    values = {
        "expected_repository_id": "101",
        "expected_workflow_id": "202",
        "expected_active_path": ".github/workflows/ci.yml",
        "allowed_events": ("repository_dispatch",),
        "repository": {"id": 101, "full_name": "owner/repo"},
        "workflow": {"id": 202, "path": ".github/workflows/ci.yml", "name": "presentation"},
        "run": {
            "id": 303,
            "run_attempt": 2,
            "workflow_id": 202,
            "repository": {"id": 101},
            "event": "repository_dispatch",
            "head_sha": SHA_A,
            "name": "ignored run name",
            "display_title": "ignored title",
        },
        "trusted_workflow_bytes": b"name: trusted\n",
        "trusted_workflow_blob_oid": SHA_B,
        "trusted_workflow_definition_commit": SHA_C,
        "candidate_tree_sha": SHA_B,
    }
    values.update(overrides)
    return authenticate_github_run(**values)  # type: ignore[arg-type]


def test_github_identity_binds_provider_and_trusted_workflow_bytes() -> None:
    identity = _identity()
    assert identity.run_id == "303"
    assert identity.run_attempt == 2
    assert identity.candidate.checkout_sha == SHA_A
    assert identity.workflow.trusted_workflow_sha256 == hashlib.sha256(
        b"name: trusted\n"
    ).hexdigest()


@pytest.mark.parametrize(
    ("mutation", "message"),
    [
        ({"repository": {"id": 999}}, "repository identity"),
        ({"workflow": {"id": 202, "path": ".github/workflows/moved.yml"}}, "active workflow path"),
        ({"run": {"id": 303, "run_attempt": 1, "workflow_id": 999, "repository": {"id": 101}, "event": "repository_dispatch", "head_sha": SHA_A}}, "run workflow identity"),
        ({"run": {"id": 303, "run_attempt": 1, "workflow_id": 202, "repository": {"id": 101}, "event": "workflow_dispatch", "head_sha": SHA_A}}, "event is not admitted"),
        ({"run": {"id": 303, "run_attempt": 1, "workflow_id": 202, "repository": [], "event": "repository_dispatch", "head_sha": SHA_A}}, "run repository identity"),
    ],
)
def test_github_identity_rejects_unauthenticated_provider_state(
    mutation: dict[str, object], message: str
) -> None:
    with pytest.raises(GithubReferenceError, match=message):
        _identity(**mutation)


def test_run_name_and_display_title_have_no_authority() -> None:
    baseline = _identity()
    run = {
        "id": 303,
        "run_attempt": 2,
        "workflow_id": 202,
        "repository": {"id": 101},
        "event": "repository_dispatch",
        "head_sha": SHA_A,
        "name": "forged green",
        "display_title": "forged authority",
    }
    assert _identity(run=run) == baseline


def test_reference_topology_is_closed_without_idle_coordination() -> None:
    topology = reference_topology(
        candidate_labels=("ubuntu-latest",), trusted_labels=("self-hosted", "trusted")
    )
    validate_reference_topology(topology)
    assert tuple(topology["dispatch_events"]) == DISPATCH_EVENTS
    assert topology["coordination"]["polling"] is False


@pytest.mark.parametrize(
    ("mutate", "message"),
    [
        (lambda value: value["roles"][1]["permissions"].append("statuses:write"), "write authority"),
        (lambda value: value["roles"][1].update({"persist_credentials": True}), "persisted credentials"),
        (lambda value: value["roles"][2].update({"checkout": True}), "may not execute or check out"),
        (lambda value: value["coordination"].update({"polling": True}), "may not idle or poll"),
        (lambda value: value.update({"dispatch_events": ["open-ended"]}), "exact and closed"),
    ],
)
def test_reference_topology_security_mutants_fail(mutate, message: str) -> None:
    topology = reference_topology(
        candidate_labels=("candidate",), trusted_labels=("trusted",)
    )
    mutate(topology)
    with pytest.raises(GithubReferenceError, match=message):
        validate_reference_topology(topology)


def test_transactional_adopter_preserves_unmanaged_workflows(tmp_path: Path) -> None:
    existing = tmp_path / ".github/workflows/application.yml"
    existing.parent.mkdir(parents=True)
    existing.write_bytes(b"name: application\n")
    desired = render_github_adoption(
        default_branch="main",
        candidate_labels=("ubuntu-latest",),
        trusted_labels=("self-hosted", "trusted"),
        producer_argv=("python3", "scripts/release_check.py"),
    )
    assert plan_github_adoption(tmp_path, desired=desired).status == "actionable"
    result = apply_github_adoption(tmp_path, desired=desired)
    assert result.status == "changed"
    assert existing.read_bytes() == b"name: application\n"
    assert plan_github_adoption(tmp_path, desired=desired).status == "clean"
    for relative, content in desired.items():
        assert (tmp_path / relative).read_bytes() == content

    producer = yaml.safe_load((tmp_path / ".github/workflows/bcf-exact-ref.yml").read_text())
    checkout = producer["jobs"]["producer"]["steps"][0]
    assert checkout["with"]["persist-credentials"] is False
    assert producer["permissions"] == {"contents": "read"}
    assert producer["jobs"]["producer"]["name"] == "Execute exact candidate producer"
    assert producer["jobs"]["producer"]["if"] == ACTIVATION_EXPRESSION
    for relative in (
        ".github/workflows/bcf-exact-main.yml",
        ".github/workflows/bcf-trusted-finalizer.yml",
        ".github/workflows/bcf-status-publisher.yml",
    ):
        trusted = yaml.safe_load((tmp_path / relative).read_text())
        steps = [step for job in trusted["jobs"].values() for step in job["steps"]]
        assert all(not step.get("uses", "").startswith("actions/checkout@") for step in steps)
        assert all(
            "uses" not in step or step["uses"] in ACTION_PINS.values() for step in steps
        )


def test_control_plane_is_event_driven_disabled_and_descriptively_named() -> None:
    desired = render_github_control_plane(
        default_branch="main",
        candidate_labels=("ubuntu-latest",),
        trusted_labels=("self-hosted", "trusted"),
        producer_workflow_names=("application", "governance"),
        controller_commit=SHA_A,
    )
    workflows = {
        path: yaml.safe_load(content) for path, content in desired.items()
        if path.startswith(".github/workflows/")
    }
    assert workflows[".github/workflows/bcf-exact-main.yml"]["jobs"]["kickoff"]["name"] == (
        "Authenticate exact-main admission"
    )
    assert workflows[".github/workflows/bcf-trusted-finalizer.yml"]["jobs"]["finalize"]["name"] == (
        "Reconstruct exact-main producer evidence"
    )
    assert workflows[".github/workflows/bcf-status-publisher.yml"]["jobs"]["publish"]["name"] == (
        "Publish verified exact-main status"
    )
    expected_guards = {
        ".github/workflows/bcf-exact-main.yml": ACTIVATION_EXPRESSION,
        ".github/workflows/bcf-trusted-finalizer.yml": (
            FINALIZER_ACTIVATION_EXPRESSION
        ),
        ".github/workflows/bcf-status-publisher.yml": (
            PUBLISHER_ACTIVATION_EXPRESSION
        ),
    }
    for path, workflow in workflows.items():
        job = next(iter(workflow["jobs"].values()))
        assert job["if"] == expected_guards[path]
        assert job["timeout-minutes"] == 5
        command = "\n".join(step.get("run", "") for step in job["steps"])
        assert not re.search(r"\b(?:sleep|poll|wait|while|until)\b", command)
        controller_steps = [
            step for step in job["steps"] if "ci-github" in step.get("run", "")
        ]
        assert len(controller_steps) == 1
        assert controller_steps[0]["env"] == TRUSTED_CONTROLLER_TOKEN_ENV
        assert "GITHUB_TOKEN" not in workflow.get("env", {})
    finalizer_trigger = workflows[".github/workflows/bcf-trusted-finalizer.yml"]["on"]
    assert finalizer_trigger == {
        "workflow_run": {
            "workflows": ["bcf/exact-main-admission", "application", "governance"],
            "types": ["completed"],
        }
    }
    assert "repository_dispatch" not in str(finalizer_trigger)


def test_adopter_conflict_fails_before_any_other_path_is_written(tmp_path: Path) -> None:
    conflict = tmp_path / ".github/workflows/bcf-exact-main.yml"
    conflict.parent.mkdir(parents=True)
    conflict.write_bytes(b"owner bytes\n")
    desired = render_github_adoption(
        default_branch="main",
        candidate_labels=("candidate",),
        trusted_labels=("trusted",),
        producer_argv=("python3", "-m", "pytest"),
    )
    with pytest.raises(GithubAdoptionError, match="resolve before adoption"):
        apply_github_adoption(tmp_path, desired=desired)
    assert conflict.read_bytes() == b"owner bytes\n"
    assert not (tmp_path / "governance/github-ci-topology.yml").exists()

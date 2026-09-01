from __future__ import annotations

from pathlib import Path

import yaml


REPO_ROOT = Path(__file__).resolve().parents[1]
WORKFLOW_ROOT = REPO_ROOT / ".github/workflows"
TRUSTED_LABELS = [
    "self-hosted",
    "Linux",
    "X64",
    "bcf-governance",
    "vm-linux-ci-runner",
]


def _workflow(name: str) -> dict[str, object]:
    return yaml.safe_load((WORKFLOW_ROOT / name).read_text(encoding="utf-8"))


def _serialized(name: str) -> str:
    return (WORKFLOW_ROOT / name).read_text(encoding="utf-8")


def test_release_authorizer_is_owner_dispatched_no_checkout_control_plane() -> None:
    workflow = _workflow("release.yml")
    assert workflow[True] == {"workflow_dispatch": None}
    assert workflow["permissions"] == {}
    assert list(workflow["jobs"]) == ["authorize", "build"]  # type: ignore[arg-type]
    authorize = workflow["jobs"]["authorize"]  # type: ignore[index]
    assert authorize["runs-on"] == TRUSTED_LABELS
    assert authorize["if"] == (
        "${{ github.actor == 'mjgolaszewski' && github.ref == 'refs/heads/main' }}"
    )
    steps = "\n".join(str(step) for step in authorize["steps"])
    assert "actions/checkout@" not in steps
    assert "ci-github release resolve" in steps
    assert "ci-github release authorize" in steps


def test_release_builder_uses_exact_subject_closed_runtime_and_no_credentials() -> None:
    build = _workflow("release.yml")["jobs"]["build"]  # type: ignore[index]
    assert build["needs"] == ["authorize"]
    assert build["runs-on"] == "ubuntu-24.04"
    assert build["permissions"] == {"actions": "read", "contents": "read"}
    checkout = next(
        step for step in build["steps"] if str(step.get("uses", "")).startswith("actions/checkout@")
    )
    assert checkout["with"] == {
        "ref": "${{ needs.authorize.outputs.subject_commit }}",
        "fetch-depth": 0,
        "persist-credentials": False,
    }
    serialized = _serialized("release.yml")
    assert 'python-version: "3.12.14"' in serialized
    assert "--require-hashes" in serialized
    assert "--no-isolation" in serialized
    assert "--release-artifact-dir" in serialized
    assert "python -m pytest" in serialized


def test_verifier_separates_token_free_runtime_from_provider_authentication() -> None:
    workflow = _workflow("bcf-release-verifier.yml")
    assert list(workflow["jobs"]) == ["runtime", "authenticate"]  # type: ignore[arg-type]
    runtime = workflow["jobs"]["runtime"]  # type: ignore[index]
    authenticate = workflow["jobs"]["authenticate"]  # type: ignore[index]
    assert runtime["runs-on"] == authenticate["runs-on"] == "ubuntu-24.04"
    assert authenticate["needs"] == ["runtime"]
    runtime_command = next(
        step for step in runtime["steps"] if "ci-github release runtime" in str(step.get("run", ""))
    )
    assert runtime_command["env"] == {
        "GITHUB_TOKEN": "",
        "ACTIONS_ID_TOKEN_REQUEST_TOKEN": "",
        "ACTIONS_RUNTIME_TOKEN": "",
    }
    authenticate_text = "\n".join(str(step) for step in authenticate["steps"])
    assert "ci-github release verify-evidence" in authenticate_text
    assert "ci-github release runtime" not in authenticate_text
    assert "actions/checkout@" not in _serialized("bcf-release-verifier.yml")


def test_release_file_selection_and_attempt_fan_in_are_controller_owned() -> None:
    release = _serialized("release.yml")
    verifier = _serialized("bcf-release-verifier.yml")
    collector = _serialized("bcf-release-collector.yml")
    assert "--release-artifact-dir" in release
    assert "--release-artifact-dir" in verifier
    assert "--runtime-evidence-dir" in verifier
    assert "--release-artifact-dir" in collector
    assert "--runtime-evidence-dir" in collector
    assert "bcf-release-runtime-${{ github.run_id }}-${{ github.run_attempt }}" in verifier
    assert "bcf-release-verification-${{ github.run_id }}-${{ github.run_attempt }}" in verifier
    assert "bcf-release-verification-${{ github.event.workflow_run.id }}-${{ github.event.workflow_run.run_attempt }}" in collector
    for forbidden in ("jq ", "gh api", "max_by", "sleep ", "while "):
        assert forbidden not in release + verifier + collector


def test_collector_is_no_checkout_trusted_recomputation_and_sole_receipt_owner() -> None:
    workflow = _workflow("bcf-release-collector.yml")
    assert list(workflow["jobs"]) == ["collect"]  # type: ignore[arg-type]
    collect = workflow["jobs"]["collect"]  # type: ignore[index]
    assert collect["runs-on"] == TRUSTED_LABELS
    assert collect["if"] == (
        "${{ github.event.workflow_run.event == 'workflow_run' && "
        "github.event.workflow_run.head_branch == 'main' && "
        "github.event.workflow_run.conclusion == 'success' }}"
    )
    serialized = _serialized("bcf-release-collector.yml")
    assert "actions/checkout@" not in serialized
    assert "ci-github release collect" in serialized
    assert "pip install" not in serialized
    assert "python -m build" not in serialized


def test_publisher_remains_fail_closed_pending_explicit_owner_approval() -> None:
    workflow = _workflow("bcf-release-publisher.yml")
    assert list(workflow["jobs"]) == ["publish"]  # type: ignore[arg-type]
    publish = workflow["jobs"]["publish"]  # type: ignore[index]
    assert publish["if"] == "${{ false }}"
    serialized = _serialized("bcf-release-publisher.yml")
    for forbidden in ("actions/checkout@", "python -m build", "pip install", "gh release"):
        assert forbidden not in serialized

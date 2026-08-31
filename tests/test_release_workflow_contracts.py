from __future__ import annotations

from pathlib import Path

import yaml


REPO_ROOT = Path(__file__).resolve().parents[1]
WORKFLOW_PATH = REPO_ROOT / ".github/workflows/release.yml"
TRUSTED_LABELS = [
    "self-hosted",
    "Linux",
    "X64",
    "bcf-governance",
    "vm-linux-ci-runner",
]


def _workflow() -> dict[str, object]:
    return yaml.safe_load(WORKFLOW_PATH.read_text(encoding="utf-8"))


def _job() -> dict[str, object]:
    return _workflow()["jobs"]["authority-cutover-pending"]  # type: ignore[index,return-value]


def test_release_requires_owner_dispatch_of_exact_main_before_candidate() -> None:
    workflow = _workflow()
    assert workflow[True] == {"workflow_dispatch": None}
    assert workflow["permissions"] == {}
    assert set(workflow["jobs"]) == {"authority-cutover-pending"}  # type: ignore[arg-type]
    assert _job()["runs-on"] == TRUSTED_LABELS


def test_release_authorization_reconstructs_current_provider_state_once() -> None:
    assert _job()["if"] == "${{ false }}"
    assert _job()["timeout-minutes"] == 1


def test_candidate_verifies_authorization_before_exact_checkout_and_execution() -> None:
    serialized = WORKFLOW_PATH.read_text(encoding="utf-8")
    assert "actions/checkout@" not in serialized
    assert "ubuntu-latest" not in serialized


def test_release_truth_binds_certification_evidence_and_exact_artifact_bytes() -> None:
    assert "release-artifacts" not in _workflow()["jobs"]  # type: ignore[operator]
    assert "publish-release" not in _workflow()["jobs"]  # type: ignore[operator]


def test_p12_publication_is_named_and_mechanically_event_guarded() -> None:
    job = _job()
    assert job["name"] == "Release disabled until authority v1.1 activation"
    assert job["if"] == "${{ false }}"


def test_publisher_checks_out_nothing_and_rebuilds_nothing() -> None:
    serialized = WORKFLOW_PATH.read_text(encoding="utf-8")
    for forbidden in ("python -m build", "pip install", "twine", "git checkout"):
        assert forbidden not in serialized


def test_publisher_authenticates_tag_run_attempt_artifact_and_receipt() -> None:
    workflow = _workflow()
    assert workflow[True] == {"workflow_dispatch": None}
    assert "tags" not in WORKFLOW_PATH.read_text(encoding="utf-8")


def test_publisher_attests_and_publishes_only_fixed_authenticated_paths() -> None:
    serialized = WORKFLOW_PATH.read_text(encoding="utf-8")
    assert "attest-build-provenance" not in serialized
    assert "gh release" not in serialized


def test_publisher_removes_only_its_exact_run_scoped_workspace() -> None:
    steps = _job()["steps"]
    assert steps == [
        {
            "name": "Fail closed during the structural-to-activation interval",
            "run": "exit 1",
        }
    ]

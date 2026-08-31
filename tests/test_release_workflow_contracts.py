from __future__ import annotations

from pathlib import Path

import yaml


REPO_ROOT = Path(__file__).resolve().parents[1]
WORKFLOW_PATH = REPO_ROOT / ".github/workflows/release.yml"
OWNER_MAIN = (
    "${{ github.actor == 'mjgolaszewski' && github.ref == 'refs/heads/main' }}"
)
TRUSTED_LABELS = [
    "self-hosted",
    "Linux",
    "X64",
    "bcf-governance",
    "vm-linux-ci-runner",
]


def _workflow() -> dict[str, object]:
    return yaml.safe_load(WORKFLOW_PATH.read_text(encoding="utf-8"))


def _commands(job: dict[str, object]) -> str:
    return "\n".join(
        str(step.get("run", ""))
        for step in job["steps"]  # type: ignore[index,union-attr]
    )


def test_release_requires_owner_dispatch_of_exact_main_before_candidate() -> None:
    workflow = _workflow()
    assert workflow[True] == {"workflow_dispatch": None}
    assert workflow["permissions"] == {}
    jobs = workflow["jobs"]
    assert set(jobs) == {
        "authorize-release-subject",
        "release-artifacts",
        "publish-release",
    }

    authorization = jobs["authorize-release-subject"]
    candidate = jobs["release-artifacts"]
    assert authorization["if"] == OWNER_MAIN
    assert authorization["runs-on"] == TRUSTED_LABELS
    assert authorization["permissions"] == {
        "actions": "read",
        "contents": "read",
        "statuses": "read",
    }
    assert all(
        "actions/checkout@" not in str(step.get("uses", ""))
        for step in authorization["steps"]
    )
    assert candidate["needs"] == ["authorize-release-subject"]
    assert candidate["runs-on"] == "ubuntu-latest"


def test_release_authorization_reconstructs_current_provider_state_once() -> None:
    authorization = _workflow()["jobs"]["authorize-release-subject"]
    commands = _commands(authorization)
    assert "actions/workflows/bcf-trusted-finalizer.yml/runs" in commands
    assert '-f head_sha="$GITHUB_SHA"' in commands
    assert "max_by(.id)" in commands
    assert "bcf-trusted-callback-$collector_run_id-$collector_run_attempt" in commands
    assert "ci-github publish-callback" in commands
    assert '.reason == "idempotent_replay"' in commands
    assert '.subject_sha == $sha' in commands
    assert '.computed_state == "certified"' in commands
    assert not any(word in commands.lower().split() for word in ("poll", "sleep", "wait"))


def test_candidate_verifies_authorization_before_exact_checkout_and_execution() -> None:
    candidate = _workflow()["jobs"]["release-artifacts"]
    steps = candidate["steps"]
    names = [str(step.get("name", "")) for step in steps]
    verify_index = names.index("Verify authorization bytes before candidate checkout")
    checkout_index = next(
        index
        for index, step in enumerate(steps)
        if str(step.get("uses", "")).startswith("actions/checkout@")
    )
    assert verify_index < checkout_index
    checkout = steps[checkout_index]
    assert checkout["with"] == {
        "fetch-depth": 0,
        "persist-credentials": False,
        "ref": "${{ github.sha }}",
    }
    assert "0.7.0" in _commands(candidate)


def test_release_truth_binds_certification_evidence_and_exact_artifact_bytes() -> None:
    candidate = _workflow()["jobs"]["release-artifacts"]
    commands = _commands(candidate)
    for required in (
        "--ci-authority",
        "--ci-certification",
        "--ci-session-manifest",
        "--release-receipt-output",
        "dist/bcf_governance-0.7.0-py3-none-any.whl",
        "dist/bcf_governance-0.7.0.tar.gz",
        "dist/SHA256SUMS",
    ):
        assert required in commands
    evidence_directory = commands.index("--evidence-dir")
    receipt_output = commands.index("--release-receipt-output")
    assert evidence_directory < receipt_output
    assert ".artifacts/bcf/release-evidence" in commands
    assert "$RUNNER_TEMP/bcf-release-authorization/bundle/ci-certification.json" in commands
    assert ".artifacts/release-certification/release.evidence.json" in commands


def test_p11_publication_is_named_and_mechanically_disabled() -> None:
    workflow = _workflow()
    jobs = workflow["jobs"]
    assert jobs["authorize-release-subject"]["name"] == (
        "Authenticate the exact-main release subject"
    )
    assert jobs["release-artifacts"]["name"] == (
        "Build, test, and certify exact-main distributions"
    )
    publisher = jobs["publish-release"]
    assert publisher["name"] == "Publish pre-certified distributions without rebuilding"
    assert publisher["if"] == "${{ false }}"
    assert publisher["needs"] == ["release-artifacts"]
    assert publisher["runs-on"] == TRUSTED_LABELS

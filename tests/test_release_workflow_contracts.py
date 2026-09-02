from __future__ import annotations

from pathlib import Path

from bcf_governance.tooling.ci_graph_contracts import validate_ci_graph
from bcf_governance.tooling.ci_graph_render import render_ci_graph


REPO_ROOT = Path(__file__).resolve().parents[1]


def _workflow(workflow_id: str) -> dict[str, object]:
    return next(
        workflow
        for workflow in validate_ci_graph(REPO_ROOT).workflows
        if workflow["id"] == workflow_id
    )


def _job(workflow_id: str, job_id: str) -> dict[str, object]:
    return next(job for job in _workflow(workflow_id)["jobs"] if job["id"] == job_id)


def test_release_authorizer_is_owner_dispatched_no_checkout_control_plane() -> None:
    workflow = _workflow("release-authority")
    authorize = _job("release-authority", "authorize")
    assert workflow["events"] == [{"type": "workflow_dispatch"}]
    assert [job["id"] for job in workflow["jobs"]] == ["authorize", "build"]
    assert authorize["trust"] == "trusted" and authorize["checkout"] is False
    assert authorize["condition"] == "release-owner-main"
    assert validate_ci_graph(REPO_ROOT).graph["conditions"]["release-owner-main"] == (
        "github.actor == 'mjgolaszewski' && github.ref == 'refs/heads/main'"
    )
    assert authorize["executor"]["components"] == [
        "setup-python", "setup-release-directories", "resolve-release-inputs",
        "download-release-certification", "download-release-controller",
        "authorize-release", "upload-release-authorization",
    ]


def test_release_builder_uses_exact_subject_closed_runtime_and_no_credentials() -> None:
    compiled = validate_ci_graph(REPO_ROOT)
    build = _job("release-authority", "build")
    assert build["needs"] == ["authorize"]
    assert build["resource_class"] == "hosted-release"
    assert build["permissions"] == {"actions": "read", "contents": "read"}
    checkout = compiled.graph["step_components"]["checkout-authorized-release"]
    assert checkout["with"] == {
        "ref": "${{ needs.authorize.outputs.subject_commit }}",
        "fetch-depth": 0,
        "persist-credentials": False,
    }
    command = compiled.commands["build-release-bundle"]["argv"]
    assert command[:3] == ["{python}", ".github/scripts/build_release_bundle.py", "--output"]


def test_verifier_separates_token_free_runtime_from_provider_authentication() -> None:
    compiled = validate_ci_graph(REPO_ROOT)
    workflow = _workflow("release-verifier")
    assert [job["id"] for job in workflow["jobs"]] == ["runtime", "authenticate"]
    runtime = _job("release-verifier", "runtime")
    authenticate = _job("release-verifier", "authenticate")
    assert authenticate["needs"] == ["runtime"]
    assert runtime["trust"] == authenticate["trust"] == "candidate"
    assert runtime["checkout"] is authenticate["checkout"] is False
    assert compiled.commands["verify-release-runtime"]["environment"] == {
        "GITHUB_TOKEN": "",
        "ACTIONS_ID_TOKEN_REQUEST_TOKEN": "",
        "ACTIONS_RUNTIME_TOKEN": "",
    }
    assert runtime["produces"] == ["release-runtime-evidence"]
    assert runtime["consumes"] == [
        "release-authorization", "release-build-bundle"
    ]
    assert authenticate["consumes"] == [
        "release-authorization", "release-build-bundle", "release-runtime-evidence"
    ]
    upload = compiled.graph["step_components"]["upload-release-runtime"]
    assert upload["condition"] == "always-step"


def test_verifier_controller_is_bound_to_the_triggering_authorization_attempt() -> None:
    compiled = validate_ci_graph(REPO_ROOT)
    download = compiled.graph["step_components"][
        "download-triggering-release-authorization"
    ]
    assert download["with"] == {
        "name": (
            "bcf-release-authorization-${{ github.event.workflow_run.id }}-"
            "${{ github.event.workflow_run.run_attempt }}"
        ),
        "github-token": "${{ github.token }}",
        "repository": "${{ github.repository }}",
        "run-id": "${{ github.event.workflow_run.id }}",
        "path": "${{ runner.temp }}/bcf-release-authorization",
        "digest-mismatch": "error",
    }
    install = compiled.graph["step_components"][
        "install-triggering-release-controller"
    ]
    assert install["artifact_dir"].endswith("/bcf-release-authorization/controller")
    assert install["wheel_sha256_file"].endswith("/release-authorization.json")
    assert install["wheel_sha256_key"] == "controller.wheel_sha256"
    for job_id in ("runtime", "authenticate"):
        components = _job("release-verifier", job_id)["executor"]["components"]
        assert components.index("download-triggering-release-authorization") < (
            components.index("install-triggering-release-controller")
        )
    rendered = render_ci_graph(REPO_ROOT)[
        ".github/workflows/bcf-release-verifier.yml"
    ].decode()
    assert "trusted_controller_artifact" not in rendered
    assert "controller.wheel_sha256" not in rendered
    assert "keys=[" in rendered and "wheel_sha256" in rendered
    assert "hexdigest()==expected" in rendered


def test_release_file_selection_and_attempt_fan_in_are_controller_owned() -> None:
    compiled = validate_ci_graph(REPO_ROOT)
    commands = {
        name: " ".join(command["argv"])
        for name, command in compiled.commands.items()
        if name in {
            "resolve-release-inputs", "authorize-release", "verify-release-runtime",
            "authenticate-release-verification", "collect-release",
            "resolve-release-publication", "publish-release",
        }
    }
    assert all("jq " not in value and "gh api" not in value for value in commands.values())
    assert "--runtime-evidence-dir" in commands["authenticate-release-verification"]
    assert "--release-artifact-dir" in commands["collect-release"]
    assert "resolve-publication" in commands["resolve-release-publication"]
    download = compiled.graph["step_components"]["download-release-receipt"]
    assert download["with"]["artifact-ids"] == (
        "${{ steps.resolve.outputs.receipt_artifact_id }}"
    )
    attest = compiled.graph["step_components"]["attest-release-assets"]
    assert attest["with"]["subject-path"].endswith("/receipt/assets/*")
    assert _job("release-collector", "collect")["consumes"] == [
        "release-verifier-bundle"
    ]


def test_collector_is_no_checkout_trusted_recomputation_and_sole_receipt_owner() -> None:
    collect = _job("release-collector", "collect")
    assert collect["trust"] == "trusted" and collect["checkout"] is False
    assert collect["produces"] == ["release-receipt-bundle"]
    producers = [
        (workflow["id"], job["id"])
        for workflow in validate_ci_graph(REPO_ROOT).workflows
        for job in workflow["jobs"]
        if "release-receipt-bundle" in job["produces"]
    ]
    assert producers == [("release-collector", "collect")]

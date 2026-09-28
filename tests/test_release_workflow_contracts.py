from __future__ import annotations

import copy
import hashlib
import importlib.util
import os
from pathlib import Path
import subprocess
import sys

import pytest
import yaml

from bcf_governance.tooling.ci_graph_contracts import validate_ci_graph
from bcf_governance.tooling.ci_graph_execution import job_execution_issues
from bcf_governance.tooling.ci_graph_render import render_ci_graph


REPO_ROOT = Path(__file__).resolve().parents[1]


def _release_builder_module():
    script_root = REPO_ROOT / ".github/scripts"
    sys.path.insert(0, str(script_root))
    try:
        spec = importlib.util.spec_from_file_location(
            "bcf_test_build_release_bundle", script_root / "build_release_bundle.py"
        )
        assert spec is not None and spec.loader is not None
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module
    finally:
        sys.path.remove(str(script_root))


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
    route = _job("release-authority", "controller-route")
    authorize = _job("release-authority", "authorize")
    assert workflow["events"] == [{"type": "workflow_dispatch"}]
    assert [job["id"] for job in workflow["jobs"]] == [
        "controller-route", "authorize", "build",
    ]
    assert route["trust"] == "candidate"
    assert route["controller_requirement"] is None
    assert authorize["trust"] == "trusted" and authorize["checkout"] is False
    assert authorize["needs"] == ["controller-route"]
    assert authorize["controller_requirement"] == "current"
    assert authorize["condition"] == "release-owner-main"
    assert validate_ci_graph(REPO_ROOT).graph["conditions"]["release-owner-main"] == (
        "github.actor == 'mjgolaszewski' && github.ref == 'refs/heads/main'"
    )
    assert authorize["executor"]["components"] == [
        "setup-python", "setup-release-directories",
        "resolve-release-inputs",
        "download-release-certification", "download-release-controller",
        "authorize-release", "upload-release-authorization",
    ]
    compiled = validate_ci_graph(REPO_ROOT)
    routed = (
        "${{ runner.tool_cache }}/bcf-governance/"
        "${{ needs.controller-route.outputs.target_commit }}/bin/bcf"
    )
    assert compiled.commands["resolve-release-inputs"]["argv"][0] == routed
    assert compiled.commands["authorize-release"]["argv"][0] == routed


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


def test_release_builder_does_not_replay_source_tests() -> None:
    module = _release_builder_module()
    source = Path(module.__file__).read_text(encoding="utf-8")
    assert "_run_source_tests" not in source
    assert '"pytest"' not in source


def test_release_runtime_defaults_to_artifact_specific_checks() -> None:
    source = (REPO_ROOT / "bcf_governance/tooling/release_runtime_verification.py").read_text(
        encoding="utf-8"
    )
    assert '"sdist-tests"' not in source
    assert '"sdist-smoke"' in source
    assert '"wheel-installed-consumer"' in source


def test_release_builder_preserves_and_surfaces_failed_command_evidence(
    tmp_path: Path, capsys
) -> None:
    module = _release_builder_module()
    stdout = tmp_path / "command.stdout"
    stderr = tmp_path / "command.stderr"

    with pytest.raises(subprocess.CalledProcessError):
        module._run(
            [
                sys.executable,
                "-c",
                "import sys; print('retained-output'); print('retained-error', file=sys.stderr); raise SystemExit(17)",
            ],
            stdout=stdout,
            stderr=stderr,
        )

    captured = capsys.readouterr()
    assert stdout.read_text(encoding="utf-8") == "retained-output\n"
    assert stderr.read_text(encoding="utf-8") == "retained-error\n"
    assert captured.out == "retained-output\n"
    assert captured.err == "retained-error\n"


def test_release_builder_uploads_partial_attempt_evidence_on_failure() -> None:
    compiled = validate_ci_graph(REPO_ROOT)
    upload = compiled.graph["step_components"]["upload-release-build"]
    assert upload["condition"] == "always-step"
    assert upload["with"]["if-no-files-found"] == "error"
    assert compiled.graph["conditions"]["release-trigger-success"] == (
        "github.event.workflow_run.event == 'workflow_dispatch' && "
        "github.event.workflow_run.head_branch == 'main' && "
        "github.event.workflow_run.conclusion == 'success'"
    )

    verifier = render_ci_graph(REPO_ROOT)[
        ".github/workflows/bcf-release-verifier.yml"
    ].decode()
    assert "github.event.workflow_run.conclusion == 'success'" in verifier


def test_verifier_separates_token_free_runtime_from_provider_authentication() -> None:
    compiled = validate_ci_graph(REPO_ROOT)
    workflow = _workflow("release-verifier")
    assert [job["id"] for job in workflow["jobs"]] == ["runtime", "collect"]
    runtime = _job("release-verifier", "runtime")
    authenticate = _job("release-verifier", "collect")
    assert authenticate["needs"] == ["runtime"]
    assert runtime["trust"] == "candidate" and authenticate["trust"] == "trusted"
    assert runtime["checkout"] is authenticate["checkout"] is False
    assert compiled.commands["verify-release-runtime"]["environment"] == {
        "GITHUB_TOKEN": "",
        "ACTIONS_ID_TOKEN_REQUEST_TOKEN": "",
        "ACTIONS_RUNTIME_TOKEN": "",
    }
    assert runtime["produces"] == ["release-runtime-evidence"]
    assert authenticate["controller_requirement"] is None
    assert runtime["consumes"] == [
        "release-authorization", "release-build-bundle"
    ]
    assert authenticate["consumes"] == [
        "release-authorization", "release-build-bundle", "release-runtime-evidence"
    ]
    upload = compiled.graph["step_components"]["upload-release-runtime"]
    assert upload["condition"] == "always-step"


def test_release_collector_recomputes_verification_before_emitting_receipt() -> None:
    collect = _job("release-verifier", "collect")
    components = collect["executor"]["components"]
    assert components.index("authenticate-release-verification") < components.index(
        "collect-release"
    ) < components.index("upload-release-receipt")
    compiled = validate_ci_graph(REPO_ROOT)
    assert "release-verification" not in compiled.graph["artifacts"]
    assert "--verification-artifact-name" not in " ".join(
        compiled.commands["collect-release"]["argv"]
    )
    assert compiled.commands["collect-release"]["argv"][0] == "{ephemeral_controller}"


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
    assert install["wheel_sha256_keys"] == ["controller", "wheel_sha256"]
    for job_id in ("runtime", "collect"):
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
    release_contract_path = REPO_ROOT / "governance/public-contracts.yml"
    release_contract = yaml.safe_load(release_contract_path.read_text(encoding="utf-8"))
    release_tag = f"v{release_contract['package']['version']}"
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
    routed = (
        "${{ runner.tool_cache }}/bcf-governance/"
        "${{ needs.controller-route.outputs.target_commit }}/bin/bcf"
    )
    for command_id in (
        "resolve-release-inputs", "authorize-release",
        "resolve-release-publication", "publish-release",
    ):
        assert compiled.commands[command_id]["argv"][0] == routed
    assert compiled.commands["collect-release"]["argv"][0] == "{ephemeral_controller}"
    publisher = _job("release-publisher", "publish")
    assert publisher["needs"] == ["controller-route"]
    assert publisher["executor"]["components"][:2] == [
        "setup-python", "setup-publication-directories",
    ]
    assert release_tag in commands["publish-release"]
    assert "steps.resolve.outputs.tag" not in commands["publish-release"]
    assert (
        release_contract_path.relative_to(REPO_ROOT).as_posix(),
        hashlib.sha256(release_contract_path.read_bytes()).hexdigest(),
    ) in validate_ci_graph(REPO_ROOT).input_sha256
    download = compiled.graph["step_components"]["download-release-receipt"]
    assert download["with"]["artifact-ids"] == (
        "${{ steps.resolve.outputs.receipt_artifact_id }}"
    )
    attest = compiled.graph["step_components"]["attest-release-assets"]
    assert attest["with"]["subject-path"].endswith("/receipt/assets/*")
    assert _job("release-verifier", "collect")["consumes"] == [
        "release-authorization", "release-build-bundle", "release-runtime-evidence"
    ]


def test_collector_is_no_checkout_trusted_recomputation_and_sole_receipt_owner() -> None:
    collect = _job("release-verifier", "collect")
    assert collect["trust"] == "trusted" and collect["checkout"] is False
    assert collect["produces"] == ["release-receipt-bundle"]
    producers = [
        (workflow["id"], job["id"])
        for workflow in validate_ci_graph(REPO_ROOT).workflows
        for job in workflow["jobs"]
        if "release-receipt-bundle" in job["produces"]
    ]
    assert producers == [("release-verifier", "collect")]


@pytest.mark.parametrize(
    ("workflow_id", "job_id", "command_id", "replacement", "diagnostic"),
    [
        ("release-authority", "authorize", "resolve-release-inputs", "{controller}", "provider-effective"),
        ("release-authority", "authorize", "authorize-release", "{controller}", "provider-effective"),
        ("release-verifier", "runtime", "verify-release-runtime", "{controller}", "exact triggering"),
        ("release-verifier", "collect", "authenticate-release-verification", "{controller}", "exact triggering"),
        ("release-verifier", "collect", "collect-release", "{controller}", "exact triggering"),
        ("release-publisher", "publish", "resolve-release-publication", "{controller}", "provider-effective"),
        ("release-publisher", "publish", "publish-release", "{controller}", "provider-effective"),
    ],
)
def test_release_controller_routing_fails_before_provider_execution(
    workflow_id: str,
    job_id: str,
    command_id: str,
    replacement: str,
    diagnostic: str,
) -> None:
    compiled = validate_ci_graph(REPO_ROOT)
    graph = copy.deepcopy(compiled.graph)
    graph["commands"][command_id]["argv"][0] = replacement
    workflow = next(item for item in graph["workflows"] if item["id"] == workflow_id)
    job = next(item for item in workflow["jobs"] if item["id"] == job_id)
    assert any(
        diagnostic in issue
        for issue in job_execution_issues(graph, job, job["executor"], workflow)
    )


def test_release_triggering_controller_must_be_installed_before_use() -> None:
    compiled = validate_ci_graph(REPO_ROOT)
    graph = copy.deepcopy(compiled.graph)
    workflow = next(
        item for item in graph["workflows"] if item["id"] == "release-verifier"
    )
    job = next(item for item in workflow["jobs"] if item["id"] == "collect")
    components = job["executor"]["components"]
    components.remove("install-triggering-release-controller")
    components.append("install-triggering-release-controller")
    assert any(
        "exact triggering" in issue
        for issue in job_execution_issues(graph, job, job["executor"], workflow)
    )

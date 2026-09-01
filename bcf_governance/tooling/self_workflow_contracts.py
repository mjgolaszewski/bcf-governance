"""Mechanical validation for BCF's self-governed workflow topology."""

from __future__ import annotations

from pathlib import Path
import re
from typing import Any

import yaml

from .ci_adopt_github import (
    ACTIVATION_EXPRESSION,
    FINALIZER_ACTIVATION_EXPRESSION,
    PUBLISHER_ACTIVATION_EXPRESSION,
    TRUSTED_CONTROLLER_TOKEN_ENV,
)
from .ci_github_actions import ACTION_PINS


class SelfWorkflowContractError(ValueError):
    """Raised when self-hosted policy and executable workflow bytes diverge."""


OWNER_MAIN = "${{ github.actor == 'mjgolaszewski' && github.ref == 'refs/heads/main' }}"
OWNER_AFTER_DEPENDENCIES = (
    "${{ always() && github.actor == 'mjgolaszewski' && "
    "github.ref == 'refs/heads/main' && needs.admit.result == 'success' }}"
)
ACTIVATION_GUARDS = {
    "owner_main_dispatch": OWNER_MAIN,
    "owner_main_dispatch_after_dependencies": OWNER_AFTER_DEPENDENCIES,
    "repository_variable_enabled": ACTIVATION_EXPRESSION,
    "repository_variable_exact_main_only": FINALIZER_ACTIVATION_EXPRESSION,
    "repository_variable_all_finalizer_conclusions": PUBLISHER_ACTIVATION_EXPRESSION,
    "exact_release_verifier_success": (
        "${{ github.event.workflow_run.event == 'workflow_run' && "
        "github.event.workflow_run.head_branch == 'main' && "
        "github.event.workflow_run.conclusion == 'success' }}"
    ),
}
TRUSTED_CLASSES = {"trusted", "trusted_bootstrap"}
RELEASE_CLASSES = {"release_candidate", "provider_control_hosted"}
COORDINATION = re.compile(r"\b(?:sleep|poll|wait|while|until)\b", re.IGNORECASE)


def _mapping(path: Path, *, label: str) -> dict[str, Any]:
    try:
        payload = yaml.safe_load(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, yaml.YAMLError) as exc:
        raise SelfWorkflowContractError(f"{label} is not readable YAML") from exc
    if not isinstance(payload, dict):
        raise SelfWorkflowContractError(f"{label} must be a mapping")
    return payload


def _expected_runner(
    runner: dict[str, Any], trust_class: str, job: dict[str, Any], release_os: str
) -> object:
    if trust_class in TRUSTED_CLASSES:
        expected = list(runner["trusted_labels"])
        matrix = job.get("strategy", {}).get("matrix", {})
        if "trusted_runner" in matrix:
            if matrix["trusted_runner"] != runner["trusted_instance_labels"]:
                raise SelfWorkflowContractError("trusted runner matrix is not canonical")
            expected.append("${{ matrix.trusted_runner }}")
        return expected
    if trust_class in RELEASE_CLASSES:
        return release_os
    if trust_class == "candidate":
        return runner["candidate_routing"]["candidate_runner"]
    raise SelfWorkflowContractError(f"unknown executable job trust class: {trust_class}")


def _validate_actions_and_commands(
    *, workflow_path: str, job: dict[str, Any], trusted: bool,
    release_admin_env: dict[str, str],
) -> set[str]:
    observed: set[str] = set()
    for step in job.get("steps", []):
        source = step.get("uses")
        if source:
            action_id = str(source).split("@", 1)[0].removeprefix("actions/")
            if ACTION_PINS.get(action_id) != source:
                raise SelfWorkflowContractError(
                    f"workflow action is not canonically pinned: {workflow_path}"
                )
            observed.add(action_id)
            if trusted and str(source).startswith("actions/checkout@"):
                raise SelfWorkflowContractError("trusted job may not check out candidate code")
        command = str(step.get("run", ""))
        if COORDINATION.search(command):
            raise SelfWorkflowContractError("workflow may not occupy a runner for coordination")
        if trusted and ("scripts/" in command or ".github/scripts/" in command):
            raise SelfWorkflowContractError("trusted job may not invoke candidate scripts")
        if trusted and "ci-github" in command and "ci-github --help" not in command:
            expected_env = (
                release_admin_env
                if workflow_path == ".github/workflows/bcf-release-publisher.yml"
                and "ci-github release publish" in command
                else TRUSTED_CONTROLLER_TOKEN_ENV
            )
            if step.get("env") != expected_env:
                diagnostic = (
                    "release publisher lacks repository administration authority"
                    if expected_env == release_admin_env
                    else "trusted controller step must receive only the explicit GitHub token"
                )
                raise SelfWorkflowContractError(diagnostic)
    return observed


def _validate_publisher(
    workflow: dict[str, Any], installed_commit: str, *, secret_name: str
) -> None:
    if workflow.get(True) != {"workflow_dispatch": None}:
        raise SelfWorkflowContractError("release publisher must be owner-dispatched")
    if workflow.get("permissions") != {} or workflow.get("env") != {
        "BCF_CONTROL_COMMIT": installed_commit
    }:
        raise SelfWorkflowContractError("release publisher authority is not closed")
    job = workflow["jobs"]["publish"]
    if job.get("permissions") != {
        "actions": "read",
        "attestations": "write",
        "contents": "write",
        "id-token": "write",
    }:
        raise SelfWorkflowContractError("release publisher permissions are not exact")
    steps = job.get("steps", [])
    names = [step.get("name") for step in steps]
    if names != [
        "Restore the trusted controller interpreter environment",
        "Require the short-lived release administration credential",
        "Resolve the newest exact-main release receipt mechanically",
        "Download only the resolver-selected receipt and certified assets",
        "Attest the exact closed release asset inventory",
        "Publish only the authenticated pre-certified bytes",
    ]:
        raise SelfWorkflowContractError("release publisher step inventory is not exact")
    credential = steps[1]
    resolve = steps[2]
    download = steps[3]
    attest = steps[4]
    publish_step = steps[5]
    publish = str(publish_step.get("run", ""))
    secret_expression = f"${{{{ secrets.{secret_name} }}}}"
    if credential.get("env") != {"BCF_RELEASE_ADMIN_TOKEN": secret_expression} or (
        credential.get("run") != 'test -n "$BCF_RELEASE_ADMIN_TOKEN"'
    ):
        raise SelfWorkflowContractError("release administration credential is not exact")
    if publish_step.get("env") != {"GITHUB_TOKEN": secret_expression}:
        raise SelfWorkflowContractError("release publisher lacks repository administration authority")
    if "ci-github release resolve-publication" not in str(resolve.get("run", "")):
        raise SelfWorkflowContractError("release publisher lacks mechanical input resolution")
    if download.get("with") != {
        "artifact-ids": "${{ steps.resolve.outputs.receipt_artifact_id }}",
        "github-token": "${{ github.token }}",
        "repository": "${{ github.repository }}",
        "run-id": "${{ steps.resolve.outputs.receipt_run_id }}",
        "path": "${{ runner.temp }}/bcf-publication/receipt",
        "digest-mismatch": "error",
    }:
        raise SelfWorkflowContractError("release publisher download is not resolver-owned")
    if attest.get("with") != {
        "subject-path": "${{ runner.temp }}/bcf-publication/receipt/assets/*"
    }:
        raise SelfWorkflowContractError("release publisher attestation inventory is not exact")
    required = (
        "ci-github release publish",
        '--tag "${{ steps.resolve.outputs.tag }}"',
        '--commit "${{ steps.resolve.outputs.subject_commit }}"',
        '--release-artifact-dir "$RUNNER_TEMP/bcf-publication/receipt/assets"',
        '--receipt-artifact-id "${{ steps.resolve.outputs.receipt_artifact_id }}"',
        '--receipt-artifact-name "${{ steps.resolve.outputs.receipt_artifact_name }}"',
        '--receipt-provider-digest "${{ steps.resolve.outputs.receipt_provider_digest }}"',
    )
    if any(value not in publish for value in required):
        raise SelfWorkflowContractError("release publisher has hand-authored authority inputs")
    if any(value in publish for value in ("pip install", "python -m build", "gh api", "jq ")):
        raise SelfWorkflowContractError("release publisher may not build or decode authority")


def validate_self_workflow_contracts(repo_root: Path) -> int:
    """Validate each self workflow once from canonical policy and action owners."""

    root = repo_root.resolve()
    policy = _mapping(
        root / "governance/self-governance-policy.yml", label="self-governance policy"
    )
    runner = policy.get("runner_security")
    if not isinstance(runner, dict):
        raise SelfWorkflowContractError("self-governance runner policy is invalid")
    if runner.get("hosted_fallback_allowed") is not False or runner.get(
        "candidate_substrate"
    ) != "github_standard_hosted_fresh_vm":
        raise SelfWorkflowContractError("candidate routing permits an undeclared fallback")
    if runner.get("coordination_policy") != [
        "no_polling",
        "no_sleeping",
        "no_idle_waiters",
    ]:
        raise SelfWorkflowContractError("runner coordination policy is not canonical")
    if runner.get("temporary_local_window", {}).get(
        "privileged_publication_enabled"
    ) is not True:
        raise SelfWorkflowContractError("release publication is not mechanically activated")
    jobs = runner.get("jobs")
    activations = runner.get("trusted_job_activation")
    if not isinstance(jobs, dict) or not isinstance(activations, dict):
        raise SelfWorkflowContractError("self-governance workflow inventories are invalid")
    release = _mapping(
        root / "release/wheelhouse-manifest.yml", label="release wheelhouse manifest"
    )
    release_os = str(release.get("subject", {}).get("operating_system", ""))
    installed = str(
        runner.get("trusted_controller_installation", {}).get("installed_commit_sha", "")
    )
    required_python = runner.get("trusted_controller_interpreter", {})
    release_credential = runner.get("trusted_release_credential", {})
    if release_credential != {
        "secret_name": "BCF_RELEASE_ADMIN_TOKEN",
        "lifecycle": "provision_before_dispatch_remove_after_publication",
        "required_permissions": [
            "administration_read",
            "attestations_read",
            "contents_write",
        ],
        "required_workflow": ".github/workflows/bcf-release-publisher.yml",
    }:
        raise SelfWorkflowContractError("trusted release credential contract is not exact")
    release_admin_env = {
        "GITHUB_TOKEN": "${{ secrets.BCF_RELEASE_ADMIN_TOKEN }}"
    }
    required_workflows = set(required_python.get("required_workflows", []))
    observed_actions: set[str] = set()
    executable_jobs = 0
    for relative, classification in jobs.items():
        workflow = _mapping(root / relative, label=str(relative))
        workflow_jobs = workflow.get("jobs")
        if not isinstance(classification, dict) or not isinstance(workflow_jobs, dict):
            raise SelfWorkflowContractError("self-governance job inventory is invalid")
        if set(workflow_jobs) != set(classification):
            raise SelfWorkflowContractError(f"workflow job inventory drifted: {relative}")
        for job_id, trust_class in classification.items():
            job = workflow_jobs[job_id]
            name = job.get("name") if isinstance(job, dict) else None
            if not isinstance(name, str) or len(name.split()) < 2 or name == job_id:
                raise SelfWorkflowContractError("repository job name is not descriptive")
            if trust_class == "reusable_candidate":
                if "runs-on" in job or not str(job.get("uses", "")).startswith(
                    "./.github/workflows/"
                ):
                    raise SelfWorkflowContractError("reusable candidate routing is invalid")
                continue
            executable_jobs += 1
            expected_runner = _expected_runner(runner, trust_class, job, release_os)
            if job.get("runs-on") != expected_runner:
                raise SelfWorkflowContractError(f"workflow runner drifted: {relative}:{job_id}")
            trusted = trust_class in TRUSTED_CLASSES
            observed_actions.update(
                _validate_actions_and_commands(
                    workflow_path=str(relative), job=job, trusted=trusted,
                    release_admin_env=release_admin_env,
                )
            )
            activation = activations.get(relative, {}).get(job_id)
            if trusted:
                expected_guard = ACTIVATION_GUARDS.get(str(activation))
                if expected_guard is None or job.get("if") != expected_guard:
                    raise SelfWorkflowContractError("trusted job activation is not canonical")
            if relative in required_workflows and trusted:
                setup = [
                    step for step in job.get("steps", [])
                    if str(step.get("uses", "")).startswith("actions/setup-python@")
                ]
                if len(setup) != 1 or setup[0].get("uses") != required_python.get("action") or (
                    setup[0].get("with") != {"python-version": required_python.get("python_version")}
                ):
                    raise SelfWorkflowContractError("trusted interpreter is not provisioned first")
    if observed_actions != set(ACTION_PINS):
        raise SelfWorkflowContractError("canonical action pin inventory is stale or unused")
    publisher = _mapping(
        root / ".github/workflows/bcf-release-publisher.yml",
        label="release publisher workflow",
    )
    _validate_publisher(
        publisher, installed, secret_name=release_credential["secret_name"]
    )
    return executable_jobs

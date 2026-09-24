"""Mechanical BCF self-controller selection and workflow projection."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import re
from typing import Any

import yaml

from .ci_github_api import GitHubAPI
from .ci_github_artifacts import ProviderArtifact, resolve_role_artifact
from .ci_github_authority import authenticate_role_run, load_authority
from .ci_github_bootstrap import (
    verify_controller_inventory,
    verify_controller_subject_metadata,
)
from .ci_github_identity import GitHubControllerError, positive_int, resolve_main
from .ci_github_membership import collect_same_run_producers, select_latest_admission
from .ci_graph_contracts import CIGraphError, validate_ci_graph
from .ci_graph_locks import check_ci_graph_locks
from .ci_graph_render import check_ci_graph


PIN_KEYS = (
    "BCF_BOOTSTRAP_ARTIFACT_ID",
    "BCF_BOOTSTRAP_ARTIFACT_NAME",
    "BCF_BOOTSTRAP_ARTIFACT_DIGEST",
    "BCF_BOOTSTRAP_RUN_ID",
    "BCF_BOOTSTRAP_RUN_ATTEMPT",
    "BCF_BOOTSTRAP_COMMIT_SHA",
    "BCF_BOOTSTRAP_TREE_SHA",
    "BCF_BOOTSTRAP_REPOSITORY_ID",
    "BCF_BOOTSTRAP_WHEEL_SHA256",
)
TOPOLOGY_PATH = "governance/github-ci-topology.yml"
INSTALLATION_KEYS = (
    "schema_version",
    "installed_commit_sha",
    "subject_commit_sha",
    "subject_tree_sha",
    "bootstrap_run_id",
    "bootstrap_run_attempt",
    "probe_run_id",
    "probe_run_attempt",
)


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _pin(value: Any) -> dict[str, str]:
    if not isinstance(value, dict) or set(value) != set(PIN_KEYS):
        raise GitHubControllerError("self-controller pin inventory is not exact")
    pin = {key: str(value[key]) for key in PIN_KEYS}
    numeric = (
        "BCF_BOOTSTRAP_ARTIFACT_ID", "BCF_BOOTSTRAP_RUN_ID",
        "BCF_BOOTSTRAP_RUN_ATTEMPT", "BCF_BOOTSTRAP_REPOSITORY_ID",
    )
    if any(not pin[key].isdigit() or int(pin[key]) < 1 for key in numeric):
        raise GitHubControllerError("self-controller provider identities must be positive")
    for key in ("BCF_BOOTSTRAP_COMMIT_SHA", "BCF_BOOTSTRAP_TREE_SHA"):
        if not re.fullmatch(r"[a-f0-9]{40}", pin[key]):
            raise GitHubControllerError("self-controller Git identity is not exact")
    if not re.fullmatch(r"sha256:[a-f0-9]{64}", pin["BCF_BOOTSTRAP_ARTIFACT_DIGEST"]):
        raise GitHubControllerError("self-controller provider digest is not exact")
    if not re.fullmatch(r"[a-f0-9]{64}", pin["BCF_BOOTSTRAP_WHEEL_SHA256"]):
        raise GitHubControllerError("self-controller wheel digest is not exact")
    expected_name = (
        f"bcf-trusted-control-{pin['BCF_BOOTSTRAP_COMMIT_SHA']}-"
        f"{pin['BCF_BOOTSTRAP_RUN_ATTEMPT']}"
    )
    if pin["BCF_BOOTSTRAP_ARTIFACT_NAME"] != expected_name:
        raise GitHubControllerError("self-controller artifact name is not derived")
    return pin


def _installation(value: Any) -> dict[str, str]:
    if not isinstance(value, dict) or set(value) != set(INSTALLATION_KEYS):
        raise GitHubControllerError("installed-controller proof inventory is not exact")
    proof = {key: str(value[key]) for key in INSTALLATION_KEYS}
    if proof["schema_version"] != "1.0":
        raise GitHubControllerError("installed-controller proof version is unsupported")
    for key in ("installed_commit_sha", "subject_commit_sha", "subject_tree_sha"):
        if not re.fullmatch(r"[a-f0-9]{40}", proof[key]):
            raise GitHubControllerError("installed-controller Git identity is not exact")
    for key in (
        "bootstrap_run_id", "bootstrap_run_attempt", "probe_run_id",
        "probe_run_attempt",
    ):
        if not proof[key].isdigit() or int(proof[key]) < 1:
            raise GitHubControllerError("installed-controller run identity is not positive")
    if int(proof["probe_run_id"]) <= int(proof["bootstrap_run_id"]):
        raise GitHubControllerError("controller probe must follow its bootstrap run")
    return proof


def validate_controller_pin(value: Any) -> dict[str, str]:
    """Expose the closed canonical controller-pin validator to trusted consumers."""

    return _pin(value)


def validate_controller_installation(value: Any) -> dict[str, str]:
    """Expose the closed installed-controller proof validator."""

    return _installation(value)


def resolve_self_controller_artifact(
    api: GitHubAPI,
    *,
    repository: str,
    trigger_run_id: object | None = None,
    trigger_run_attempt: object | None = None,
) -> tuple[dict[str, str], ProviderArtifact]:
    """Select the latest exact-main controller without a caller-supplied run or name."""

    main = resolve_main(api, repository)
    authority = load_authority(api, repository, main, required_version="1.1")
    run_id, attempt = select_latest_admission(
        api,
        repository=repository,
        main=main,
        authority=authority,
        trigger_run_id=trigger_run_id,
        trigger_run_attempt=trigger_run_attempt,
    )
    builders = (
        authority["controller_builder_jobs"]
        if "controller_builder_jobs" in authority
        else None
    )
    if builders is None:
        producers = collect_same_run_producers(
            api,
            repository=repository,
            main=main,
            authority=authority,
            admission_run_id=run_id,
            admission_run_attempt=attempt,
            producer_ids=("governance",),
            require_complete_admission_inventory=False,
        )
        governance = [
            value for value in producers if value["producer_id"] == "governance"
        ]
        if len(governance) != 1:
            raise GitHubControllerError(
                "latest exact-main governance producer is not unique"
            )
        governance_attempt = governance[0]["attempts"][0]
        if governance_attempt["status"] != "completed" or (
            governance_attempt["conclusion"] != "success"
        ):
            raise GitHubControllerError(
                "latest exact-main governance producer is not successful"
            )
    else:
        if (
            not isinstance(builders, list)
            or len(builders) != 1
            or not isinstance(builders[0], dict)
            or set(builders[0]) != {"job_id"}
        ):
            raise GitHubControllerError(
                "independent controller builder authority is not exact"
            )
        authenticate_role_run(
            api,
            repository=repository,
            main=main,
            authority=authority,
            role="admission",
            run_id=run_id,
            run_attempt=attempt,
            require_success=False,
        )
        run = api.run(repository, run_id)
        if run["status"] != "completed" or positive_int(
            run["run_attempt"], field="admission run attempt"
        ) != attempt:
            raise GitHubControllerError(
                "latest exact-main admission is not terminal for controller resolution"
            )
        jobs = api.jobs(repository, run_id, attempt=attempt)
        names = [str(value["name"]) for value in jobs]
        if not names or not all(names) or len(names) != len(set(names)):
            raise GitHubControllerError(
                "exact-main job inventory is empty or duplicated"
            )
        expected_builder = str(builders[0]["job_id"])
        selected = [value for value in jobs if value["name"] == expected_builder]
        if len(selected) != 1:
            raise GitHubControllerError(
                "independent controller builder job identity is not exact"
            )
        builder = selected[0]
        positive_int(builder["id"], field="controller builder job ID")
        if (
            builder["status"] != "completed"
            or builder["conclusion"] != "success"
        ):
            raise GitHubControllerError(
                "independent controller builder job is not successful"
            )
    name = f"bcf-trusted-control-{main.checkout_sha}-{attempt}"
    artifact = resolve_role_artifact(
        api,
        repository=repository,
        main=main,
        authority=authority,
        role="admission",
        run_id=run_id,
        run_attempt=attempt,
        artifact_name=name,
        require_success=False,
    )
    if (
        artifact.run_id != run_id
        or artifact.run_attempt != attempt
        or artifact.artifact_name != name
    ):
        raise GitHubControllerError(
            "independent controller artifact is not bound to its builder admission"
        )
    return {
        "repository_id": main.repository_id,
        "commit_sha": main.checkout_sha,
        "tree_sha": main.tree_sha,
    }, artifact


def compile_self_controller_pin(
    api: GitHubAPI,
    *,
    repository: str,
    artifact_dir: Path,
    trigger_run_id: object | None = None,
    trigger_run_attempt: object | None = None,
) -> dict[str, str]:
    """Compile one canonical pin from provider state and downloaded exact bytes."""

    subject, artifact = resolve_self_controller_artifact(
        api,
        repository=repository,
        trigger_run_id=trigger_run_id,
        trigger_run_attempt=trigger_run_attempt,
    )
    root = artifact_dir.resolve()
    wheel, _ = verify_controller_inventory(root)
    verify_controller_subject_metadata(
        root / "CONTROL-METADATA.json",
        commit_sha=subject["commit_sha"],
        tree_sha=subject["tree_sha"],
        run_id=artifact.run_id,
        run_attempt=str(artifact.run_attempt),
    )
    return _pin(
        {
            "BCF_BOOTSTRAP_ARTIFACT_ID": artifact.artifact_id,
            "BCF_BOOTSTRAP_ARTIFACT_NAME": artifact.artifact_name,
            "BCF_BOOTSTRAP_ARTIFACT_DIGEST": artifact.provider_digest,
            "BCF_BOOTSTRAP_RUN_ID": artifact.run_id,
            "BCF_BOOTSTRAP_RUN_ATTEMPT": str(artifact.run_attempt),
            "BCF_BOOTSTRAP_COMMIT_SHA": subject["commit_sha"],
            "BCF_BOOTSTRAP_TREE_SHA": subject["tree_sha"],
            "BCF_BOOTSTRAP_REPOSITORY_ID": subject["repository_id"],
            "BCF_BOOTSTRAP_WHEEL_SHA256": _sha256(wheel),
        }
    )


def verify_self_controller_projection(repo_root: Path) -> int:
    """Reject any graph projection that differs from the immutable source baseline."""

    root = repo_root.resolve()
    try:
        check_ci_graph_locks(root)
        check_ci_graph(root)
        compiled = validate_ci_graph(root)
    except CIGraphError as exc:
        raise GitHubControllerError(str(exc)) from exc
    return 1 + sum(
        job["trust"] == "trusted"
        for workflow in compiled.workflows
        for job in workflow["jobs"]
    )

"""BCF self-adoption checks layered over the canonical CI graph compiler."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

from .ci_graph_contracts import CIGraphError, validate_ci_graph
from .ci_graph_render import check_ci_graph


class SelfWorkflowContractError(ValueError):
    """Raised when BCF's self-adoption policy conflicts with its CI graph."""


def _mapping(path: Path, *, label: str) -> dict[str, Any]:
    try:
        payload = yaml.safe_load(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, yaml.YAMLError) as exc:
        raise SelfWorkflowContractError(f"{label} is not readable YAML") from exc
    if not isinstance(payload, dict):
        raise SelfWorkflowContractError(f"{label} must be a mapping")
    return payload


def _self_policy(root: Path) -> dict[str, Any]:
    policy = _mapping(
        root / "governance/self-governance-policy.yml",
        label="self-governance policy",
    )
    runner = policy.get("runner_security")
    if not isinstance(runner, dict):
        raise SelfWorkflowContractError("self-governance runner policy is invalid")
    if runner.get("hosted_fallback_allowed") is not False:
        raise SelfWorkflowContractError("candidate routing permits an undeclared fallback")
    if runner.get("candidate_substrate") != "github_standard_hosted_fresh_vm":
        raise SelfWorkflowContractError("candidate substrate is not a fresh hosted VM")
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
    return runner


def validate_self_workflow_contracts(repo_root: Path) -> int:
    """Validate self-adoption without independently decoding generated workflows."""

    root = repo_root.resolve()
    runner = _self_policy(root)
    try:
        compiled = validate_ci_graph(root)
        parity = check_ci_graph(root)
    except CIGraphError as exc:
        raise SelfWorkflowContractError(str(exc)) from exc
    if parity.status != "clean":
        raise SelfWorkflowContractError(
            "generated workflow parity drifted: " + ", ".join(parity.changed_paths)
        )

    candidate_runner = runner.get("candidate_routing", {}).get("candidate_runner")
    trusted_labels = runner.get("trusted_labels")
    resources = compiled.graph["resource_classes"]
    hosted_candidates = [
        resource
        for resource in resources.values()
        if resource["hosted"] and resource["trust"] == "candidate"
    ]
    if not hosted_candidates or any(
        resource["runner"] not in {candidate_runner, "ubuntu-24.04"}
        for resource in hosted_candidates
    ):
        raise SelfWorkflowContractError("candidate runner mapping conflicts with self policy")
    trusted_resources = [
        resource for resource in resources.values() if resource["trust"] == "trusted"
    ]
    if not isinstance(trusted_labels, list) or not trusted_resources or any(
        list(resource["runner"][: len(trusted_labels)]) != trusted_labels
        for resource in trusted_resources
    ):
        raise SelfWorkflowContractError("trusted runner mapping conflicts with self policy")

    credential = runner.get("trusted_release_credential")
    secret = credential.get("secret_name") if isinstance(credential, dict) else None
    publish = compiled.commands.get("publish-release")
    if not isinstance(secret, str) or not isinstance(publish, dict) or (
        publish.get("required_environment") != [secret]
    ):
        raise SelfWorkflowContractError("release administration authority is not exact")

    return sum(
        job["executor"]["kind"] != "reusable_workflow"
        for workflow in compiled.workflows
        for job in workflow["jobs"]
    )

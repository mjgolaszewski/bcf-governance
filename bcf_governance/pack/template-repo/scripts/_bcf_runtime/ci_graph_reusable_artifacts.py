"""Typed same-run artifact bindings across a governed reusable-workflow call."""

from __future__ import annotations

import re
from typing import Any

from .ci_graph_errors import CIGraphError


_PERMISSION_LEVEL = {"none": 0, "read": 1, "write": 2}


def project_reusable_workflow_permissions(graph: dict[str, Any]) -> None:
    """Derive each local reusable caller's least permission upper bound."""

    workflows = {workflow["path"]: workflow for workflow in graph["workflows"]}
    if len(workflows) != len(graph["workflows"]):
        raise CIGraphError("CI graph workflow paths must be unique")
    visiting: set[str] = set()
    resolved: dict[str, dict[str, str]] = {}

    def required(path: str) -> dict[str, str]:
        if path in resolved:
            return resolved[path]
        if path in visiting or path not in workflows:
            raise CIGraphError("CI graph reusable workflow call topology is invalid")
        visiting.add(path)
        result: dict[str, str] = {}
        workflow = workflows[path]
        for job in workflow["jobs"]:
            executor = job["executor"]
            permissions = (
                required(executor["path"])
                if executor["kind"] == "reusable_workflow"
                else job["permissions"] or workflow["permissions"]
            )
            for name, level in permissions.items():
                if level not in _PERMISSION_LEVEL:
                    raise CIGraphError("CI graph permission level is invalid")
                if _PERMISSION_LEVEL[level] > _PERMISSION_LEVEL.get(result.get(name, "none"), 0):
                    result[name] = level
            if executor["kind"] == "reusable_workflow":
                job["permissions"] = dict(sorted(permissions.items()))
        visiting.remove(path)
        resolved[path] = dict(sorted(result.items()))
        return resolved[path]

    for workflow in graph["workflows"]:
        required(workflow["path"])


def reusable_artifact_binding(
    graph: dict[str, Any], called_workflow: dict[str, Any], artifact: str,
) -> tuple[str, tuple[tuple[dict[str, Any], dict[str, Any]], ...]] | None:
    """Resolve one exact caller input and every caller bound to this artifact."""
    calls = [
        (workflow, job)
        for workflow in graph["workflows"]
        for job in workflow["jobs"]
        if job["executor"]["kind"] == "reusable_workflow"
        and job["executor"]["path"] == called_workflow["path"]
    ]
    bound = [
        (workflow, job, job["executor"].get("artifact_bindings", {}).get(artifact))
        for workflow, job in calls
        if artifact in job["executor"].get("artifact_bindings", {})
    ]
    if not bound:
        return None
    contract = graph["artifacts"].get(artifact)
    if (not isinstance(contract, dict) or contract.get("scope") != "run-attempt"
        or contract.get("kind") != "control"):
        raise CIGraphError(
            f"CI graph reusable artifact {artifact} is not a run-attempt control artifact"
        )
    inputs = {name for _, _, name in bound}
    if len(inputs) != 1:
        raise CIGraphError(f"CI graph reusable artifact {artifact} has ambiguous input bindings")
    input_name = next(iter(inputs))
    if not isinstance(input_name, str) or re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", input_name) is None:
        raise CIGraphError(f"CI graph reusable artifact {artifact} input is not expression-safe")
    declarations = [
        event.get("inputs", {}).get(input_name)
        for event in called_workflow["events"]
        if event["type"] == "workflow_call"
    ]
    if (len(declarations) != 1 or not isinstance(declarations[0], dict)
        or declarations[0].get("type") != "boolean"
        or declarations[0].get("default") is not False):
        raise CIGraphError(
            f"CI graph reusable artifact {artifact} requires a false-default boolean input"
        )
    for _, job in calls:
        enabled = job["executor"].get("inputs", {}).get(input_name) is True
        declared = job["executor"].get("artifact_bindings", {}).get(artifact) == input_name
        if enabled != declared:
            raise CIGraphError(
                f"CI graph reusable artifact {artifact} input and binding disagree"
            )
    return input_name, tuple((workflow, job) for workflow, job, _ in bound)


def validate_reusable_binding_declarations(
    graph: dict[str, Any], caller_job: dict[str, Any],
) -> None:
    """Reject declared bindings that no called job can actually consume."""
    executor = caller_job["executor"]
    if executor["kind"] != "reusable_workflow":
        return
    bindings = executor.get("artifact_bindings", {})
    if not bindings:
        return
    called = [
        workflow for workflow in graph["workflows"]
        if workflow["path"] == executor["path"]
    ]
    if len(called) != 1:
        raise CIGraphError("CI graph reusable artifact caller has no exact workflow")
    for artifact in bindings:
        if (
            artifact not in caller_job["consumes"]
            or not any(artifact in job["consumes"] for job in called[0]["jobs"])
        ):
            raise CIGraphError(
                f"CI graph reusable artifact {artifact} lacks exact called-job consumption"
            )

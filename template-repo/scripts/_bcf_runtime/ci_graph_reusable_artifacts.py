"""Typed same-run artifact bindings across a governed reusable-workflow call."""

from __future__ import annotations

import re
from typing import Any

from .ci_graph_errors import CIGraphError


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
    if not isinstance(contract, dict) or contract.get("scope") != "run-attempt":
        raise CIGraphError(f"CI graph reusable artifact {artifact} is not run-attempt scoped")
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

"""Deterministic workflow-run chain constraints for canonical CI graphs."""

from __future__ import annotations

from typing import Any


class WorkflowRunTopologyError(ValueError):
    """Raised when a workflow-run topology cannot execute on GitHub."""


def validate_workflow_run_depth(workflows: list[dict[str, Any]]) -> None:
    """Reject cycles and chains beyond GitHub's three-level workflow_run cap."""

    by_name = {str(item["display_name"]): str(item["id"]) for item in workflows}
    parents: dict[str, set[str]] = {str(item["id"]): set() for item in workflows}
    for workflow in workflows:
        target = str(workflow["id"])
        for event in workflow["events"]:
            if event["type"] != "workflow_run":
                continue
            parents[target].update(
                by_name[name] for name in event["workflows"] if name in by_name
            )

    visiting: set[str] = set()
    depths: dict[str, int] = {}

    def depth(workflow_id: str) -> int:
        if workflow_id in depths:
            return depths[workflow_id]
        if workflow_id in visiting:
            raise WorkflowRunTopologyError("CI graph workflow_run topology is cyclic")
        visiting.add(workflow_id)
        value = max((depth(parent) + 1 for parent in parents[workflow_id]), default=0)
        visiting.remove(workflow_id)
        depths[workflow_id] = value
        return value

    for workflow_id in parents:
        if depth(workflow_id) > 3:
            raise WorkflowRunTopologyError(
                "CI graph workflow_run chain exceeds GitHub's three-level limit"
            )

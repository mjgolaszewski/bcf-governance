"""Separate one protected push authority from ordinary candidate CI consumers."""
from __future__ import annotations

from typing import Any

from .ci_graph_errors import CIGraphError


def validate_push_authority(graph: dict[str, Any]) -> None:
    """Keep one exact-main authority; additional push workflows are read-only."""
    workflows = graph["workflows"]
    authorities = [item for item in workflows if item["role"] == "exact-main"]
    if len(authorities) != 1 or not any(
        event["type"] == "push" for event in authorities[0]["events"]
    ):
        raise CIGraphError("CI graph must have one exact-main push authority",
                           kind="event", identifier="push")
    by_path = {item["path"]: item for item in workflows}

    def check_consumer(workflow: dict[str, Any], stack: tuple[str, ...] = ()) -> None:
        if workflow["path"] in stack:
            raise CIGraphError("push authority consumer reusable call cycle")
        stack = (*stack, workflow["path"])
        if any(value == "write" for value in workflow["permissions"].values()):
            raise CIGraphError("push authority consumer cannot hold workflow write permissions")
        for job in workflow["jobs"]:
            if job["trust"] != "candidate" or any(
                value == "write" for value in job["permissions"].values()
            ):
                raise CIGraphError("push authority consumer jobs must be candidate and read-only")
            if job["semantic_role"].startswith("exact-main-"):
                raise CIGraphError("push authority semantic roles cannot belong to a consumer")
            executor = job["executor"]
            if executor["kind"] not in {
                "command", "component_sequence", "gate_group", "gate_shard", "reusable_workflow"
            }:
                raise CIGraphError("push authority consumer cannot execute authority or truth operations")
            if executor["kind"] == "reusable_workflow":
                target = by_path.get(executor["path"])
                if target is None or target["role"] in {"exact-main", "trusted-control", "release"}:
                    raise CIGraphError("push authority consumer cannot call a privileged reusable workflow")
                check_consumer(target, stack)
            for component_id in executor.get("components", []):
                component = graph["step_components"][component_id]
                if component["kind"] == "controller_install" or component.get("action") in {
                    "create-github-app-token", "attest-build-provenance"
                }:
                    raise CIGraphError("push authority consumer cannot install a controller or mint credentials")
            if any(graph["artifacts"].get(name, {}).get("kind") in {"control", "terminal"}
                   for name in job["produces"]):
                raise CIGraphError("push authority consumer cannot produce control or terminal authority")

    for workflow in workflows:
        events = {event["type"] for event in workflow["events"]}
        consumer = workflow["role"] == "push-consumer"
        if "push" not in events and not consumer:
            continue
        if workflow is authorities[0]:
            continue
        if not consumer or "push" not in events or events - {"push", "workflow_dispatch"}:
            raise CIGraphError("additional push authority requires explicit push-consumer role",
                               kind="event", identifier=workflow["id"])
        check_consumer(workflow)

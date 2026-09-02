"""Mechanical execution-input invariants for compiled CI graph jobs."""

from __future__ import annotations

from typing import Any


_EXPLICIT_EXECUTORS = {"component_sequence", "gate_shard", "terminal_truth"}
_REPOSITORY_PREFIXES = ("./", ".github/", "governance/", "scripts/")


def _strings(value: Any) -> tuple[str, ...]:
    if isinstance(value, str):
        return (value,)
    if isinstance(value, dict):
        return tuple(item for nested in value.values() for item in _strings(nested))
    if isinstance(value, list):
        return tuple(item for nested in value for item in _strings(nested))
    return ()


def _command_ids(
    graph: dict[str, Any], executor: dict[str, Any]
) -> tuple[str, ...]:
    if executor["kind"] in _EXPLICIT_EXECUTORS:
        return tuple(
            graph["step_components"][component_id]["command"]
            for component_id in executor["components"]
            if graph["step_components"][component_id]["kind"] == "command"
        )
    if executor["kind"] in {"command", "truth"}:
        return (executor["command"],)
    return ()


def job_execution_issues(
    graph: dict[str, Any], job: dict[str, Any], executor: dict[str, Any]
) -> tuple[str, ...]:
    """Return deterministic interpreter and trusted-input contract violations."""

    issues: list[str] = []
    if executor["kind"] in _EXPLICIT_EXECUTORS:
        python_ready = False
        for component_id in executor["components"]:
            component = graph["step_components"][component_id]
            if component["kind"] == "action" and component["action"] == "setup-python":
                python_ready = True
                continue
            if (
                component["kind"] == "command"
                and "{python}" in graph["commands"][component["command"]]["argv"]
                and not python_ready
            ):
                issues.append(
                    f"CI graph job {job['id']} must provision selected Python before governed commands"
                )
    elif executor["kind"] in {"command", "truth"}:
        command = graph["commands"][executor["command"]]
        if "{python}" in command["argv"] and "python" not in job["components"]:
            issues.append(
                f"CI graph job {job['id']} must provision selected Python before governed commands"
            )
    if job["trust"] == "trusted" and job["checkout"] is False:
        relative = sorted(
            {
                value
                for command_id in _command_ids(graph, executor)
                for value in graph["commands"][command_id]["argv"]
                if value.startswith(_REPOSITORY_PREFIXES)
            }
        )
        if relative:
            issues.append(
                f"trusted no-checkout job {job['id']} references repository-relative inputs {relative}"
            )
    return tuple(issues)


def workflow_input_issues(
    graph: dict[str, Any], workflow: dict[str, Any]
) -> tuple[str, ...]:
    """Reject raw workflow inputs that disappear under a workflow's direct events."""

    direct_events = sorted(
        event["type"]
        for event in workflow["events"]
        if event["type"] not in {"workflow_call", "workflow_dispatch"}
    )
    if not direct_events:
        return ()
    issues: list[str] = []
    for job in workflow["jobs"]:
        surfaces: list[tuple[str, Any]] = [("job outputs", job.get("outputs", {}))]
        for command_id in _command_ids(graph, job["executor"]):
            surfaces.append((f"command {command_id}", graph["commands"][command_id]))
        executor = job["executor"]
        if executor["kind"] in _EXPLICIT_EXECUTORS:
            for component_id in executor["components"]:
                component = graph["step_components"][component_id]
                if component["kind"] == "action":
                    surfaces.append((f"action {component_id}", component))
        if executor["kind"] == "reusable_workflow":
            surfaces.append(("reusable-workflow inputs", executor["inputs"]))
        for surface, payload in surfaces:
            for value in _strings(payload):
                if "inputs." in value and "||" not in value:
                    issues.append(
                        f"direct-event workflow {workflow['id']} {surface} "
                        f"must provide an input fallback for {direct_events}"
                    )
    return tuple(sorted(set(issues)))

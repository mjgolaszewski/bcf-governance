"""Mechanical execution-input invariants for compiled CI graph jobs."""

from __future__ import annotations

import re
from typing import Any


_EXPLICIT_EXECUTORS = {"component_sequence", "gate_shard", "terminal_truth"}
_REPOSITORY_PREFIXES = ("./", ".artifacts/", ".github/", "governance/", "scripts/")
_ENV_REFERENCE = "${{ env.%s }}"
_RUN_AND_DONE_FORBIDDEN = frozenset(
    {"sleep", "poll", "watch", "wait", "while", "until", "wait-for-runner", "lease-runner"}
)
_SELECTED_PYTHON_EXECUTABLES = frozenset(
    {"{python}", "{controller}", "{ephemeral_controller}"}
)


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


def _requires_selected_python(command: dict[str, Any]) -> bool:
    """Return whether a governed executable depends on the selected Python runtime."""

    return bool(_SELECTED_PYTHON_EXECUTABLES.intersection(command["argv"]))


def job_required_environment(
    graph: dict[str, Any],
    workflow: dict[str, Any],
    job: dict[str, Any],
    executor: dict[str, Any],
) -> tuple[dict[str, str], tuple[str, ...]]:
    """Derive each job's required environment once and reject missing/conflicting bindings."""

    inherited = {**workflow.get("environment", {}), **job.get("environment", {})}
    component_bindings: dict[str, list[str]] = {}
    if executor["kind"] in _EXPLICIT_EXECUTORS:
        for component_id in executor["components"]:
            component = graph["step_components"][component_id]
            if component["kind"] != "command":
                continue
            for name, value in component.get("environment", {}).items():
                component_bindings.setdefault(name, []).append(value)
    bindings: dict[str, str] = {}
    issues: list[str] = []
    for command_id in _command_ids(graph, executor):
        command = graph["commands"][command_id]
        for name in command.get("required_environment", []):
            candidates = [
                *component_bindings.get(name, ()),
                *([command["environment"][name]] if name in command["environment"] else []),
                *([inherited[name]] if name in inherited else []),
            ]
            usable = [
                value
                for value in candidates
                if isinstance(value, str)
                and value
                and value != _ENV_REFERENCE % name
            ]
            step_outputs = [value for value in usable if "${{ steps." in value]
            if step_outputs:
                issues.append(
                    f"CI graph job {job['id']} cannot preflight required environment {name} from a future step output"
                )
                continue
            distinct = list(dict.fromkeys(usable))
            if not distinct:
                issues.append(
                    f"CI graph job {job['id']} is missing required environment binding {name}"
                )
            elif len(distinct) > 1:
                issues.append(
                    f"CI graph job {job['id']} has conflicting required environment binding {name}"
                )
            else:
                bindings[name] = distinct[0]
    return bindings, tuple(issues)


def job_execution_issues(
    graph: dict[str, Any],
    job: dict[str, Any],
    executor: dict[str, Any],
    workflow: dict[str, Any] | None = None,
) -> tuple[str, ...]:
    """Return deterministic interpreter and trusted-input contract violations."""

    issues: list[str] = []
    if workflow is not None:
        _, environment_issues = job_required_environment(
            graph, workflow, job, executor
        )
        issues.extend(environment_issues)
    if executor["kind"] in _EXPLICIT_EXECUTORS:
        python_ready = False
        for component_id in executor["components"]:
            component = graph["step_components"][component_id]
            if component["kind"] == "action" and component["action"] == "setup-python":
                python_ready = True
                continue
            if (
                component["kind"] == "command"
                and _requires_selected_python(
                    graph["commands"][component["command"]]
                )
                and not python_ready
            ):
                issues.append(
                    f"CI graph job {job['id']} must provision selected Python before governed commands"
                )
    elif executor["kind"] in {"command", "truth"}:
        command = graph["commands"][executor["command"]]
        if _requires_selected_python(command) and "python" not in job["components"]:
            issues.append(
                f"CI graph job {job['id']} must provision selected Python before governed commands"
            )
    elif (
        executor["kind"] in {"authority", "durable_publish"}
        and "python" not in job["components"]
    ):
        issues.append(
            f"CI graph job {job['id']} must provision selected Python before governed commands"
        )
    if job["trust"] == "trusted" and job["checkout"] is False:
        execution_inputs: list[Any] = [job.get("environment", {})]
        execution_inputs.extend(
            graph["commands"][command_id]
            for command_id in _command_ids(graph, executor)
        )
        if executor["kind"] in _EXPLICIT_EXECUTORS:
            execution_inputs.extend(
                graph["step_components"][component_id]
                for component_id in executor["components"]
            )
        relative = sorted(
            {
                value
                for payload in execution_inputs
                for value in _strings(payload)
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


def hosted_command_issues(graph: dict[str, Any]) -> tuple[str, ...]:
    """Reject hosted coordination and incomplete run-and-done policy."""
    configured = {
        str(value).lower() for value in graph["policy"]["forbidden_hosted_tokens"]
    }
    if graph["policy"].get("hosted_orchestration") == "run_and_done":
        missing = sorted(_RUN_AND_DONE_FORBIDDEN - configured)
        if missing:
            return (f"run-and-done hosted policy is missing tokens {missing}",)
    issues: list[str] = []
    for workflow in graph["workflows"]:
        issues.extend(workflow_input_issues(graph, workflow))
        for job in workflow["jobs"]:
            resource = graph["resource_classes"][job["resource_class"]]
            if not resource["hosted"]:
                continue
            for command_id in _command_ids(graph, job["executor"]):
                normalized = " ".join(graph["commands"][command_id]["argv"]).lower()
                for token in configured:
                    if re.search(
                        rf"(?:^|[^a-z0-9]){re.escape(token)}(?:$|[^a-z0-9])",
                        normalized,
                    ):
                        issues.append(
                            f"hosted waiter token {token!r} is prohibited in job {job['id']}"
                        )
    return tuple(issues)

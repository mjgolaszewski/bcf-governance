"""Validate opt-in authored CI projections before ordinary graph compilation."""
from __future__ import annotations

from typing import Any

from .ci_github_actions import action_pin
from .ci_graph_conditions import validate_authored_conditions
from .ci_graph_environment_bindings import validate_environment_output_bindings
from .ci_graph_environment_placement import validate_environment_placement
from .ci_graph_errors import CIGraphError
from .ci_graph_permission_projection import validate_permission_projection
from .ci_graph_step_outcomes import validate_deferred_step_failures
from .exception_messages import native_exception_message


def validate_compatibility_declarations(graph: dict[str, Any]) -> None:
    """Keep exact-shell, null-event and immutable-source projections bounded."""
    validate_permission_projection(graph)
    validate_environment_placement(graph)
    validate_authored_conditions(graph)
    validate_deferred_step_failures(graph)
    validate_environment_output_bindings(graph)
    for command_id, command in graph["commands"].items():
        if command.get("render_mode") != "shell-body":
            for value in command["argv"]:
                if value.startswith("{env:") and value.endswith("}"):
                    env_name = value[5:-1]
                    if not env_name.replace("_", "A").isalnum() or env_name.upper() != env_name:
                        raise CIGraphError(f"invalid governed environment placeholder {value}")
        if command.get("render_mode") == "shell-body":
            argv = command["argv"]
            if len(argv) != 3 or argv[:2] != ["bash", "-c"]:
                raise CIGraphError(
                    f"CI graph command {command_id} shell-body requires exact bash -c argv"
                )
            if "\x00" in argv[2]:
                raise CIGraphError(f"CI graph command {command_id} shell-body contains NUL")
    for workflow in graph["workflows"]:
        for job in workflow.get("jobs", []):
            if "needs_style" in job and (
                job["needs_style"] != "singleton-scalar" or len(job["needs"]) != 1
            ):
                raise CIGraphError("singleton-scalar needs style requires exactly one declared need")
        for event in workflow["events"]:
            if "empty_configuration" in event and (
                event["type"] != "workflow_call"
                or set(event) != {"type", "empty_configuration"}
            ):
                raise CIGraphError("null event configuration requires empty workflow_call")
    for component in graph["step_components"].values():
        condition = component.get("condition")
        if component.get("condition_style") == "bare" and condition not in {
            "always", "failure", "cancelled"
        }:
            raise CIGraphError("bare condition style requires a built-in status condition")
        if component.get("condition_style") == "named" and (
            condition not in graph["conditions"]
            or condition in {"success", "always", "failure", "cancelled"}
        ):
            raise CIGraphError("named condition style requires a declared graph condition")
        if component["kind"] == "action":
            try:
                action_pin(component["action"], component.get("source_pin"))
            except ValueError as exc:
                raise CIGraphError(native_exception_message(exc)) from exc

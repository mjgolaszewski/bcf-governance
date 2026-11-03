"""Validate opt-in authored CI projections before ordinary graph compilation."""
from __future__ import annotations

from typing import Any

from .ci_github_actions import action_pin
from .ci_graph_errors import CIGraphError


def validate_compatibility_declarations(graph: dict[str, Any]) -> None:
    """Keep exact-shell, null-event and immutable-source projections bounded."""
    for command_id, command in graph["commands"].items():
        if command.get("render_mode") == "shell-body":
            argv = command["argv"]
            if len(argv) != 3 or argv[:2] != ["bash", "-c"]:
                raise CIGraphError(
                    f"CI graph command {command_id} shell-body requires exact bash -c argv"
                )
            if "\x00" in argv[2]:
                raise CIGraphError(f"CI graph command {command_id} shell-body contains NUL")
    for workflow in graph["workflows"]:
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
        if component["kind"] == "action":
            try:
                action_pin(component["action"], component.get("source_pin"))
            except ValueError as exc:
                raise CIGraphError(str(exc)) from exc

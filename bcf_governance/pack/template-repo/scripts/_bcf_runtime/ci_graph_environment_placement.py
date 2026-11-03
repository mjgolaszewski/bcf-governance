"""Validate the bounded repository preparation prefix before environment checks."""
from __future__ import annotations

from typing import Any

from .ci_graph_errors import CIGraphError

POSITION = "after-repo-preparation"


def _exact_command(graph: dict[str, Any], component: dict[str, Any], argv: list[str], body: str) -> bool:
    if component.get("kind") != "command":
        return False
    command = graph["commands"].get(component.get("command"), {})
    actual = command.get("argv")
    return (command.get("cwd") == "." and not command.get("environment")
            and not command.get("required_environment") and (
                actual == argv or (command.get("render_mode") == "shell-body"
                    and isinstance(actual, list) and len(actual) == 3
                    and actual[:2] == ["bash", "-c"] and actual[2].strip() == body)))


def validate_environment_placement(graph: dict[str, Any]) -> None:
    """Never move credential validation behind arbitrary candidate work."""
    for workflow in graph["workflows"]:
        for job in workflow.get("jobs", []):
            if "required_environment_position" not in job:
                continue
            executor = job["executor"]
            sequence = executor.get("components", [])
            if (job["required_environment_position"] != POSITION
                    or executor.get("kind") not in {"component_sequence", "gate_shard", "terminal_truth"}
                    or job.get("checkout") or job.get("components") or job.get("consumes")
                    or len(sequence) < 3 or any(key not in graph["step_components"] for key in sequence[:3])):
                raise CIGraphError("environment placement requires an explicit safe repository preparation prefix")
            prefix = [graph["step_components"][key] for key in sequence[:3]]
            if any(component.get("condition") is not None or component.get("continue_on_error")
                   or component.get("environment") or component.get("produces") or component.get("consumes")
                   for component in prefix):
                raise CIGraphError("environment preparation prefix must be unconditional and effect-bounded")
            checkout, cleanup, temporary = prefix
            checkout_inputs = checkout.get("with", {})
            safe_checkout = (
                isinstance(checkout_inputs, dict)
                and set(checkout_inputs) <= {"persist-credentials", "ref", "fetch-depth"}
                and checkout_inputs.get("persist-credentials") is False
                and ("ref" not in checkout_inputs or checkout_inputs["ref"] == "${{ github.sha }}")
                and ("fetch-depth" not in checkout_inputs or (
                    type(checkout_inputs["fetch-depth"]) is int and checkout_inputs["fetch-depth"] == 0))
            )
            if (checkout.get("kind") != "action" or checkout.get("action") != "checkout"
                    or not safe_checkout
                    or not _exact_command(graph, cleanup,
                        ["bash", "scripts/tools/ci_cleanup.sh", "start"], "bash scripts/tools/ci_cleanup.sh start")
                    or not _exact_command(graph, temporary,
                        ["mkdir", "-p", ".artifacts/tmp"], "mkdir -p .artifacts/tmp")):
                raise CIGraphError("environment preparation must be credential-free checkout, owned cleanup start and temp setup")

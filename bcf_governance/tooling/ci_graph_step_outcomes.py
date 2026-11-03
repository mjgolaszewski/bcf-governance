"""Bound deferred scan failures to their declared later native outcome guard."""
from __future__ import annotations

from typing import Any

from .ci_graph_errors import CIGraphError

_GOVERNANCE_ROLES = frozenset({
    "cheap-preflight", "structural-evidence", "terminal-governance-truth", "framework-architecture"
})
_AUTHORITY_ARTIFACTS = frozenset({"session", "terminal", "control", "durable-reference"})


def validate_deferred_step_failures(graph: dict[str, Any]) -> None:
    """Allow report-before-fail commands without suppressing governed truth."""
    components = graph["step_components"]
    deferred = []
    for key, component in components.items():
        if "continue_on_error" in component and not isinstance(component["continue_on_error"], bool):
            raise CIGraphError("continue_on_error must be a literal boolean")
        if not component.get("continue_on_error", False):
            if "failure_guard" in component:
                raise CIGraphError("failure_guard requires continue_on_error true")
            continue
        if component["kind"] != "command" or not component.get("id"):
            raise CIGraphError("deferred failure requires a named command step")
        guard_id = component.get("failure_guard")
        guard = components.get(guard_id)
        if guard is None or guard["kind"] != "command" or guard.get("continue_on_error", False):
            raise CIGraphError("deferred failure requires a noncontinued command guard")
        command = graph["commands"].get(guard["command"])
        if command is None:
            raise CIGraphError("deferred failure guard references an unknown command")
        argv = command["argv"]
        if argv != ["exit", "1"] and not (
            command.get("render_mode") == "shell-body"
            and argv[:2] == ["bash", "-c"] and len(argv) == 3 and argv[2].strip() == "exit 1"
        ):
            raise CIGraphError("deferred failure guard must terminate with exit 1")
        condition = guard.get("condition")
        if (guard.get("condition_style", "expression") not in {"named", "expression"}
                or condition in {"success", "always", "failure", "cancelled"}
                or condition not in graph["conditions"]):
            raise CIGraphError("deferred failure guard requires an unambiguous declared condition")
        expression = graph["conditions"][condition]
        atom = "steps." + component["id"] + ".outcome != 'success'"
        allowed = {atom, "always() && " + atom}
        summary_paths = {
            "nightly-mutation": ".artifacts/mutation/nightly/summary.json",
            "weekly-mutation": ".artifacts/mutation/weekly/summary.json",
        }
        if component["id"] in summary_paths:
            allowed.add(atom + " && hashFiles('" + summary_paths[component["id"]] + "') == ''")
        if expression not in allowed:
            raise CIGraphError("deferred failure guard must check its exact native step outcome")
        deferred.append((key, guard_id))
    for component_id, guard_id in deferred:
        used = False
        for workflow in graph["workflows"]:
            for job in workflow.get("jobs", []):
                executor = job["executor"]
                sequence = executor.get("components", [])
                if component_id not in sequence:
                    continue
                used = True
                roles = [*job["produces"], *job["consumes"],
                         *components[component_id]["produces"], *components[component_id]["consumes"]]
                if (executor["kind"] != "component_sequence" or job["trust"] != "candidate"
                        or job["semantic_role"] in _GOVERNANCE_ROLES
                        or job["semantic_role"].startswith("exact-main-")
                        or any(key in executor for key in ["evaluation_mode", "evaluator_source", "protection_inspection"])
                        or any(value == "write" for value in job["permissions"].values())
                        or any(graph["artifacts"].get(name, {}).get("kind") in _AUTHORITY_ARTIFACTS for name in roles)):
                    raise CIGraphError("governance, authority and evidence execution cannot defer failure")
                if guard_id not in sequence or sequence.index(guard_id) <= sequence.index(component_id):
                    raise CIGraphError("deferred failure guard must execute later in the same job")
        if not used:
            raise CIGraphError("deferred failure must belong to a declared job")

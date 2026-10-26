"""Canonical provider-permission contracts for CI execution components."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from .ci_graph_yaml import load_yaml_path, render_yaml

_CAPTURE_SCRIPT = "scripts/capture_governance_shard.py"
_LEVEL = {"none": 0, "read": 1, "write": 2}


def command_required_permissions(command: dict[str, Any]) -> dict[str, str]:
    """Derive provider reads owned by one governed command."""

    argv = command.get("argv", ())
    if (
        isinstance(argv, list)
        and _CAPTURE_SCRIPT in argv
        and "--shard-index" in argv
        and "--shard-count" in argv
    ):
        return {"actions": "read"}
    return {}


def component_required_permissions(
    graph: dict[str, Any], component: dict[str, Any]
) -> dict[str, str]:
    """Return the canonical provider contract for one execution component."""

    if component.get("kind") != "command":
        return {}
    command = graph.get("commands", {}).get(component.get("command"))
    return command_required_permissions(command) if isinstance(command, dict) else {}


def permission_satisfies(actual: object, required: str) -> bool:
    """Compare one GitHub permission without treating omission as read access."""

    return isinstance(actual, str) and _LEVEL.get(actual, -1) >= _LEVEL[required]


def project_provider_permission_edges(graph: dict[str, Any]) -> bool:
    """Project exact component requirements and least job read permissions."""

    changed = False
    components = graph.get("step_components")
    workflows = graph.get("workflows")
    if not isinstance(components, dict) or not isinstance(workflows, list):
        return False
    required_components: dict[str, dict[str, str]] = {}
    for component_id, component in components.items():
        if not isinstance(component, dict):
            continue
        required = component_required_permissions(graph, component)
        if not required:
            continue
        declared = component.get("required_permissions")
        if declared not in (None, required):
            raise ValueError(
                f"CI graph component {component_id} provider permission contract is customized"
            )
        if declared is None:
            component["required_permissions"] = required
            changed = True
        required_components[str(component_id)] = required
    for workflow in workflows:
        if not isinstance(workflow, dict):
            continue
        for job in workflow.get("jobs", ()):
            if not isinstance(job, dict):
                continue
            executor = job.get("executor")
            if not isinstance(executor, dict):
                continue
            used = set(executor.get("components", ())) & required_components.keys()
            if not used:
                continue
            permissions = job.get("permissions")
            if not isinstance(permissions, dict):
                raise ValueError(
                    f"CI graph job {job.get('id')} permission contract is unreadable"
                )
            for component_id in sorted(used):
                for name, level in required_components[component_id].items():
                    actual = permissions.get(name)
                    if actual == "write":
                        raise ValueError(
                            f"CI graph job {job.get('id')} has unexpected write authority for {name}"
                        )
                    if not permission_satisfies(actual, level):
                        permissions[name] = level
                        changed = True
    return changed


def reconcile_provider_permission_edges(
    repo_root: Path, *, apply: bool
) -> tuple[str, ...]:
    """Reconcile provider capability edges into the canonical CI graph."""

    path = repo_root.resolve() / "governance/ci-graph.yml"
    if not path.is_file():
        return ()
    graph = load_yaml_path(path)
    changed = project_provider_permission_edges(graph)
    if changed and apply:
        path.write_bytes(render_yaml(graph))
    return ("governance/ci-graph.yml",) if changed else ()

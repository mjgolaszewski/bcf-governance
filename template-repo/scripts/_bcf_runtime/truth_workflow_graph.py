"""Resolve truth workflow ownership from the canonical compiled CI graph."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from .ci_graph_contracts import CIGraphError, validate_ci_graph
from .ci_graph_render import check_ci_graph


def graph_workflow_gate_issues(
    repo_root: Path,
    *,
    paths: list[Any],
    required_events: list[Any],
    gate_ids: set[str],
) -> list[str]:
    try:
        compiled = validate_ci_graph(repo_root)
        parity = check_ci_graph(repo_root)
    except CIGraphError:
        return ["ci_graph_invalid"]
    if parity.status != "clean":
        return [f"ci_graph_workflow_drift_{path}" for path in parity.changed_paths]
    by_path = {workflow["path"]: workflow for workflow in compiled.workflows}
    queue = [str(value) for value in paths if isinstance(value, str)]
    visited: set[str] = set()
    resolved_gates: set[str] = set()
    discovered_events = {
        event["type"]
        for workflow in compiled.workflows
        for event in workflow["events"]
    }
    issues: list[str] = []
    while queue:
        relative_path = queue.pop(0)
        if relative_path in visited:
            continue
        visited.add(relative_path)
        workflow = by_path.get(relative_path)
        if workflow is None:
            issues.append(f"workflow_path_{relative_path}_missing_from_ci_graph")
            continue
        for job in workflow["jobs"]:
            executor = job["executor"]
            if executor["kind"] == "gate_group":
                resolved_gates.update(executor["gates"])
            elif executor["kind"] == "reusable_workflow":
                queue.append(executor["path"])
    issues.extend(
        f"workflow_event_{event}_missing"
        for event in required_events
        if isinstance(event, str) and event not in discovered_events
    )
    issues.extend(
        f"workflow_gate_{gate_id}_unresolved"
        for gate_id in sorted(gate_ids - resolved_gates)
    )
    return sorted(set(issues))

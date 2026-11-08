"""Resolve truth workflow ownership from the canonical compiled CI graph."""

from __future__ import annotations

from collections import Counter
from pathlib import Path
from typing import Any

from .ci_graph_contracts import CIGraphError, validate_ci_graph
from .ci_graph_render import check_ci_graph


def _serial_capture_gates(graph: dict[str, Any], executor: dict[str, Any],
                          gate_ids: set[str]) -> list[str]:
    """Resolve the supported literal capture form, never shell text or names."""
    found: list[str] = []
    for identifier in executor["components"]:
        component = graph["step_components"][identifier]
        if component["kind"] != "command" or component.get("condition") != "always":
            continue
        command = graph["commands"][component["command"]]
        if command["cwd"] != ".":
            continue
        for gate_id in sorted(gate_ids):
            script = (
                "set -euo pipefail\n"
                'session="$(.venv/bin/python scripts/governance_evidence.py '
                '--repo-root . select-session --session-root .artifacts/bcf/sessions)"\n'
                'session_dir="$(dirname -- "$session")"\n'
                ".venv/bin/python scripts/governance_evidence.py --repo-root . run "
                f'--gate {gate_id} --output "$session_dir/{gate_id}" '
                '--python .venv/bin/python --session-manifest "$session"'
            )
            if command["argv"] == ["bash", "-c", script]:
                found.append(gate_id)
    return found


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
    discovered_events: set[str] = set()
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
        discovered_events.update(event["type"] for event in workflow["events"])
        workflow_gates: list[str] = []
        for job in workflow["jobs"]:
            executor = job["executor"]
            if executor["kind"] in {"gate_group", "gate_shard"}:
                workflow_gates.extend(executor["gates"])
            elif executor["kind"] == "component_sequence":
                workflow_gates.extend(_serial_capture_gates(compiled.graph, executor, gate_ids))
            elif executor["kind"] == "reusable_workflow":
                queue.append(executor["path"])
        issues.extend(
            f"workflow_gate_{gate_id}_multiple_owners"
            for gate_id, count in sorted(Counter(workflow_gates).items())
            if count > 1
        )
        resolved_gates.update(workflow_gates)
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

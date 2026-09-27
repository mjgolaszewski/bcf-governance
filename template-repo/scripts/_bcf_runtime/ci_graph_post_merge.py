"""Typed post-merge evaluation lanes derived from the canonical CI graph."""

from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .ci_graph_errors import CIGraphError
from .ci_graph_execution import DIRECT_POST_MERGE_MODE, exact_main_evaluation
from .ci_graph_yaml import load_yaml_path, render_yaml


CALLER_MODE = "${{ inputs.evaluation_mode || 'pr' }}"


@dataclass(frozen=True)
class PostMergeEvaluation:
    """One closed provider lane and its exact terminal proposition."""

    mode: str
    target: str | None
    lane: str
    workflow_id: str
    terminal_job_id: str

    def as_dict(self) -> dict[str, str | None]:
        return {
            "mode": self.mode,
            "target": self.target,
            "lane": self.lane,
            "workflow_id": self.workflow_id,
            "terminal_job_id": self.terminal_job_id,
        }


def _strings(value: Any) -> tuple[str, ...]:
    if isinstance(value, str):
        return (value,)
    if isinstance(value, dict):
        return tuple(item for nested in value.values() for item in _strings(nested))
    if isinstance(value, list):
        return tuple(item for nested in value for item in _strings(nested))
    return ()


def _direct_workflow(graph: dict[str, Any]) -> dict[str, Any] | None:
    if any(item.get("id") == "exact-main" for item in graph["workflows"]):
        return None
    branch = str(graph.get("default_branch", ""))
    selected = []
    for workflow in graph["workflows"]:
        events = workflow.get("events", [])
        types = {item.get("type") for item in events}
        pushes = [item for item in events if item.get("type") == "push"]
        if (
            workflow.get("role") == "exact-main"
            and {"pull_request", "workflow_call", "push"}.issubset(types)
            and len(pushes) == 1
            and pushes[0].get("branches") == [branch]
        ):
            selected.append(workflow)
    if len(selected) > 1:
        raise CIGraphError("canonical graph has ambiguous direct protected-main workflows")
    return selected[0] if selected else None


def _workflow_call_defaults(workflow: dict[str, Any]) -> tuple[Any, Any]:
    calls = [item for item in workflow["events"] if item.get("type") == "workflow_call"]
    if len(calls) != 1:
        raise CIGraphError("direct protected-main workflow_call contract is not unique")
    inputs = calls[0].get("inputs", {})
    mode = inputs.get("evaluation_mode", {})
    target = inputs.get("evaluation_target", {})
    return mode.get("default"), target.get("default")


def _command_ids(graph: dict[str, Any], job: dict[str, Any]) -> tuple[str, ...]:
    executor = job["executor"]
    if executor.get("kind") in {"component_sequence", "gate_shard", "terminal_truth"}:
        return tuple(
            graph["step_components"][component_id]["command"]
            for component_id in executor.get("components", [])
            if graph["step_components"][component_id].get("kind") == "command"
        )
    command = executor.get("command")
    return (command,) if isinstance(command, str) else ()


def post_merge_evaluation(graph: dict[str, Any]) -> PostMergeEvaluation:
    """Resolve trusted exact-main or direct protected-main authority without fallback."""

    exact = [item for item in graph["workflows"] if item.get("id") == "exact-main"]
    if exact:
        evaluation = exact_main_evaluation(tuple(graph["workflows"]))
        producer = next(
            job for job in exact[0]["jobs"]
            if job.get("semantic_role") == "exact-main-governance-producer"
        )
        return PostMergeEvaluation(
            evaluation.mode,
            evaluation.target,
            "trusted_exact_main",
            "exact-main",
            str(producer["id"]),
        )
    workflow = _direct_workflow(graph)
    if workflow is None:
        raise CIGraphError(
            "canonical graph has neither trusted exact-main nor direct protected-main authority"
        )
    mode_default, target_default = _workflow_call_defaults(workflow)
    if mode_default != "pr" or target_default != "":
        raise CIGraphError("direct protected-main caller defaults are not canonical")
    terminals = [
        job for job in workflow["jobs"]
        if job.get("executor", {}).get("kind") == "terminal_truth"
    ]
    if len(terminals) != 1:
        raise CIGraphError("direct protected-main terminal truth owner is not unique")
    referenced = tuple(
        value
        for job in workflow["jobs"]
        for command_id in _command_ids(graph, job)
        for value in _strings(graph["commands"][command_id])
        if "inputs.evaluation_mode" in value
    )
    if not referenced or any(value != DIRECT_POST_MERGE_MODE for value in referenced):
        raise CIGraphError(
            "direct protected-main evaluation intent is not event-bound to closure"
        )
    return PostMergeEvaluation(
        "closure",
        None,
        "direct_protected_main",
        str(workflow["id"]),
        str(terminals[0]["id"]),
    )


def _replace_caller_mode(value: Any) -> tuple[Any, bool]:
    if isinstance(value, str):
        return (DIRECT_POST_MERGE_MODE, True) if value == CALLER_MODE else (value, False)
    if isinstance(value, list):
        changed = False
        result = []
        for item in value:
            replaced, item_changed = _replace_caller_mode(item)
            result.append(replaced)
            changed = changed or item_changed
        return result, changed
    if isinstance(value, dict):
        changed = False
        result = {}
        for key, item in value.items():
            replaced, item_changed = _replace_caller_mode(item)
            result[key] = replaced
            changed = changed or item_changed
        return result, changed
    return value, False


def reconcile_direct_post_merge_scope(repo_root: Path, *, apply: bool) -> bool:
    """Normalize declared direct-main v3 authority through the fixed-point owner."""

    path = repo_root / "governance/ci-graph.yml"
    graph = load_yaml_path(path)
    workflow = _direct_workflow(graph)
    if workflow is None or str(graph.get("profile_contract_version")) != "3.0":
        return False
    proposed = deepcopy(graph)
    proposed_workflow = next(
        item for item in proposed["workflows"] if item["id"] == workflow["id"]
    )
    command_ids = {
        command_id
        for job in proposed_workflow["jobs"]
        for command_id in _command_ids(proposed, job)
    }
    changed = False
    for command_id in command_ids:
        proposed["commands"][command_id], command_changed = _replace_caller_mode(
            proposed["commands"][command_id]
        )
        changed = changed or command_changed
    if changed and not apply:
        raise CIGraphError(
            "direct protected-main scope is stale; run canonical reconciliation"
        )
    if changed:
        path.write_bytes(render_yaml(proposed))
    post_merge_evaluation(proposed)
    return changed

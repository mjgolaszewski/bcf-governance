"""Typed post-merge evaluation lanes derived from the canonical CI graph."""

from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .ci_graph_errors import CIGraphError
from .ci_graph_execution import (
    direct_post_merge_mode,
    direct_post_merge_target,
    exact_main_evaluation,
    parse_direct_post_merge_mode,
    parse_direct_post_merge_target,
)
from .ci_graph_yaml import load_yaml_path, render_yaml
from .evidence_workitem_lifecycle import (
    WorkitemContractError,
    validate_workitem_dependencies,
)
from .repository_comparison_context import (
    PUSH_COMPARISON_BASE_EXPRESSION,
    comparison_base_input_contract,
)


CALLER_MODE = "${{ inputs.evaluation_mode || 'pr' }}"
CALLER_TARGET = "${{ inputs.evaluation_target || '' }}"


def _direct_target(target: str | None) -> str:
    if target is None:
        return CALLER_TARGET
    return direct_post_merge_target(target)


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
    if inputs.get("comparison_base_sha") != comparison_base_input_contract():
        raise CIGraphError(
            "direct protected-main reusable comparison input is not required and exact"
        )
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
        if producer.get("executor", {}).get("inputs", {}).get(
            "comparison_base_sha"
        ) != PUSH_COMPARISON_BASE_EXPRESSION:
            raise CIGraphError(
                "exact-main reusable governance comparison base is not "
                "canonically bound to the outer push event"
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
        if job.get("semantic_role") == "terminal-governance-truth"
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
    modes = {parse_direct_post_merge_mode(value) for value in referenced}
    if len(modes) != 1 or None in modes:
        raise CIGraphError(
            "direct protected-main evaluation intent is not canonically event-bound"
        )
    mode = modes.pop()
    target_values = tuple(
        value
        for job in workflow["jobs"]
        for command_id in _command_ids(graph, job)
        for value in _strings(graph["commands"][command_id])
        if "inputs.evaluation_target" in value
    )
    if mode == "workitem":
        targets = {parse_direct_post_merge_target(value) for value in target_values}
        if len(targets) != 1 or None in targets:
            raise CIGraphError("direct protected-main bounded target is not exact")
        target = targets.pop()
    else:
        if not target_values or any(value != CALLER_TARGET for value in target_values):
            raise CIGraphError("direct protected-main unbounded target is not exact")
        target = None
    return PostMergeEvaluation(
        str(mode),
        target,
        "direct_protected_main",
        str(workflow["id"]),
        str(terminals[0]["id"]),
    )


def authored_post_merge_scope(repo_root: Path) -> tuple[str, str | None]:
    """Derive the sole legal next post-merge proposition from authored lifecycle state."""

    try:
        ledger = load_yaml_path(repo_root / "plans/phase-ledger.yml")
        active = ledger["active_phase"]
        workitems = load_yaml_path(repo_root / str(active["workitems"]))["workitems"]
        phase = load_yaml_path(repo_root / str(active["log"]))
    except (KeyError, TypeError, OSError) as exc:
        raise CIGraphError("post-merge lifecycle identity is incomplete") from exc
    if not isinstance(workitems, list) or not all(
        isinstance(item, dict) for item in workitems
    ):
        raise CIGraphError("post-merge workitem inventory is invalid")
    try:
        validate_workitem_dependencies(workitems)
    except WorkitemContractError as exc:
        raise CIGraphError(str(exc)) from exc
    statuses = {str(item.get("id")): item.get("status") for item in workitems}
    if any(value not in {"TODO", "IN_PROGRESS", "BLOCKED", "DONE"} for value in statuses.values()):
        raise CIGraphError("post-merge workitem status is invalid")
    document = phase.get("document") if isinstance(phase, dict) else None
    if isinstance(document, dict) and document.get("status") == "completed":
        if set(statuses.values()) != {"DONE"}:
            raise CIGraphError("completed phase contains unfinished workitems")
        return "closure", None
    completed_prefix = []
    for item in workitems:
        identity = str(item["id"])
        if statuses[identity] != "DONE":
            break
        completed_prefix.append(identity)
    if completed_prefix and len(completed_prefix) < len(workitems):
        successor = workitems[len(completed_prefix)]
        dependency = f"requires-workitem-closure:{completed_prefix[-1]}"
        if (
            successor.get("status") in {"IN_PROGRESS", "BLOCKED"}
            and dependency in successor.get("acceptance", [])
        ):
            return "pr", None
    return (
        ("workitem", completed_prefix[-1])
        if completed_prefix
        else ("pr", None)
    )


def _replace_caller_scope(
    value: Any, *, mode: str, target: str | None
) -> tuple[Any, bool]:
    if isinstance(value, str):
        if value == CALLER_MODE or parse_direct_post_merge_mode(value) is not None:
            replacement = direct_post_merge_mode(mode)
            return replacement, replacement != value
        if value == CALLER_TARGET or parse_direct_post_merge_target(value) is not None:
            replacement = _direct_target(target)
            return replacement, replacement != value
        return value, False
    if isinstance(value, list):
        changed = False
        result = []
        for item in value:
            replaced, item_changed = _replace_caller_scope(
                item, mode=mode, target=target
            )
            result.append(replaced)
            changed = changed or item_changed
        return result, changed
    if isinstance(value, dict):
        changed = False
        result = {}
        for key, item in value.items():
            replaced, item_changed = _replace_caller_scope(
                item, mode=mode, target=target
            )
            result[key] = replaced
            changed = changed or item_changed
        return result, changed
    return value, False


def reconcile_direct_post_merge_scope(repo_root: Path, *, apply: bool) -> bool:
    """Normalize declared direct-main v3 authority through the fixed-point owner."""

    path = repo_root / "governance/ci-graph.yml"
    graph = load_yaml_path(path)
    workflow = _direct_workflow(graph)
    if workflow is None:
        return False
    proposed = deepcopy(graph)
    mode, target = authored_post_merge_scope(repo_root)
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
        proposed["commands"][command_id], command_changed = _replace_caller_scope(
            proposed["commands"][command_id], mode=mode, target=target
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


def reconcile_post_merge_scope(repo_root: Path, *, apply: bool) -> bool:
    """Project authored lifecycle intent into exact-main or direct-main authority."""

    path = repo_root / "governance/ci-graph.yml"
    graph = load_yaml_path(path)
    exact = [item for item in graph["workflows"] if item.get("id") == "exact-main"]
    if not exact:
        return reconcile_direct_post_merge_scope(repo_root, apply=apply)
    mode, target = authored_post_merge_scope(repo_root)
    proposed = deepcopy(graph)
    workflow = next(item for item in proposed["workflows"] if item["id"] == "exact-main")
    admission = next(
        item for item in workflow["jobs"]
        if item.get("semantic_role") == "exact-main-admission"
    )
    producer = next(
        item for item in workflow["jobs"]
        if item.get("semantic_role") == "exact-main-governance-producer"
    )
    admission["executor"]["evaluation_mode"] = mode
    producer["executor"].setdefault("inputs", {})["evaluation_mode"] = mode
    producer["executor"]["inputs"][
        "comparison_base_sha"
    ] = PUSH_COMPARISON_BASE_EXPRESSION
    if target is None:
        admission["executor"].pop("evaluation_target", None)
        producer["executor"]["inputs"].pop("evaluation_target", None)
    else:
        admission["executor"]["evaluation_target"] = target
        producer["executor"]["inputs"]["evaluation_target"] = target
    command = proposed["commands"].get("exact-main-admit-effective")
    if isinstance(command, dict) and isinstance(command.get("argv"), list):
        argv = command["argv"]
        mode_index = argv.index("--evaluation-mode")
        argv[mode_index + 1] = mode
        if "--evaluation-target" in argv:
            target_index = argv.index("--evaluation-target")
            del argv[target_index : target_index + 2]
        if target is not None:
            argv.extend(["--evaluation-target", target])
    changed = proposed != graph
    if changed and not apply:
        raise CIGraphError(
            "post-merge evaluation scope is stale; run canonical reconciliation"
        )
    if changed:
        path.write_bytes(render_yaml(proposed))
    post_merge_evaluation(proposed)
    return changed

"""Deterministic duration observations and constrained evidence assignment."""

from __future__ import annotations

from datetime import datetime
from typing import Any, Iterable, Mapping


def validate_group_dependencies(
    groups: Mapping[str, Any],
) -> dict[str, tuple[str, ...]]:
    """Validate the closed execution-group DAG once and return canonical edges."""

    dependencies_by_group: dict[str, tuple[str, ...]] = {}
    for group_id, raw in groups.items():
        dependencies = raw.get("depends_on", []) if isinstance(raw, dict) else None
        if (
            not isinstance(dependencies, list)
            or any(not isinstance(value, str) or not value for value in dependencies)
            or len(dependencies) != len(set(dependencies))
        ):
            raise ValueError(f"execution group {group_id} dependencies are invalid")
        dependencies_by_group[str(group_id)] = tuple(dependencies)
    pending = {group_id: len(values) for group_id, values in dependencies_by_group.items()}
    ready = sorted(group_id for group_id, count in pending.items() if count == 0)
    visited: list[str] = []
    for group_id, dependencies in dependencies_by_group.items():
        for dependency in dependencies:
            if dependency not in groups:
                raise ValueError(
                    f"execution group {group_id} depends on unknown group {dependency}"
                )
            if dependency == group_id:
                raise ValueError(f"execution group {group_id} depends on itself")
            if groups[dependency].get("captured_by_preflight") is True:
                raise ValueError(
                    f"execution group {group_id} cannot depend on preflight-only group {dependency}"
                )
    while ready:
        current = ready.pop(0)
        visited.append(current)
        for group_id, dependencies in dependencies_by_group.items():
            if current in dependencies:
                pending[group_id] -= 1
                if pending[group_id] == 0:
                    ready.append(group_id)
                    ready.sort()
    if len(visited) != len(groups):
        raise ValueError("execution group dependencies contain a cycle")
    return dependencies_by_group


def expand_group_dependencies(
    grouped: Mapping[str, list[str]], groups: Mapping[str, Any]
) -> tuple[dict[str, list[str]], set[str]]:
    """Close a planned group set over current-run producer dependencies."""

    expanded = {group_id: list(claims) for group_id, claims in grouped.items()}
    scheduled = set(expanded)
    pending = sorted(scheduled)
    forced: set[str] = set()
    while pending:
        group_id = pending.pop(0)
        for dependency in groups[group_id].get("depends_on", []):
            if dependency not in scheduled:
                scheduled.add(dependency)
                forced.add(dependency)
                expanded[dependency] = list(groups[dependency]["claims"])
                pending.append(dependency)
                pending.sort()
    return expanded, forced


def invalidate_dependency_reuse(
    grouped: Mapping[str, list[str]],
    forced_groups: set[str],
    reused: list[dict[str, Any]],
    invalidated: list[dict[str, Any]],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Require newly forced prerequisites from the same execution session."""

    forced_claims = {
        claim_id for group_id in forced_groups for claim_id in grouped[group_id]
    }
    forced_reuse = {
        item["claim_id"]: item for item in reused if item["claim_id"] in forced_claims
    }
    retained = [item for item in reused if item["claim_id"] not in forced_claims]
    invalidated_ids = {item["claim_id"] for item in invalidated}
    for claim_id, item in sorted(forced_reuse.items()):
        if claim_id not in invalidated_ids:
            invalidated.append(
                {
                    "claim_id": claim_id,
                    "evidence_ids": [str(item["evidence_id"])],
                    "reasons": ["current_run_dependency_required"],
                }
            )
    return retained, invalidated


def receipt_duration_ms(receipt: Mapping[str, Any]) -> int | None:
    """Return one closed, deterministic elapsed observation when present."""

    try:
        started = datetime.fromisoformat(
            str(receipt["started_at"]).replace("Z", "+00:00")
        )
        completed = datetime.fromisoformat(
            str(receipt["timestamp"]).replace("Z", "+00:00")
        )
    except (KeyError, TypeError, ValueError):
        return None
    if started.tzinfo is None or completed.tzinfo is None or completed < started:
        return None
    elapsed = int((completed - started).total_seconds() * 1000)
    return elapsed if elapsed >= 1 else 1


def duration_estimates(
    receipts: Iterable[Mapping[str, Any]], model: Mapping[str, Any]
) -> dict[str, int]:
    """Derive median observed group durations without an authored timing registry."""

    observations: dict[str, list[int]] = {}
    for receipt in receipts:
        if receipt.get("result") != "passed":
            continue
        duration = receipt_duration_ms(receipt)
        claims = receipt.get("claims")
        if duration is None or not isinstance(claims, list) or not claims:
            continue
        groups = {
            str(claim["execution_group"])
            for claim_id in claims
            if isinstance((claim := model["claims"].get(claim_id)), dict)
        }
        if len(groups) != 1:
            continue
        group_id = next(iter(groups))
        group = model["execution_groups"].get(group_id)
        if not isinstance(group, dict) or group.get("producer") != receipt.get("gate_id"):
            continue
        observations.setdefault(group_id, []).append(duration)
    return {
        group_id: sorted(values)[(len(values) - 1) // 2]
        for group_id, values in observations.items()
    }


def assign_duration_aware_shards(
    nodes: list[dict[str, Any]], estimates: Mapping[str, int], *, shard_count: int = 4
) -> list[dict[str, Any]]:
    """Assign dependency components to shards and preserve topological execution."""

    if shard_count < 1:
        raise ValueError("evidence shard count must be positive")
    by_id = {str(node["id"]): node for node in nodes}
    if len(by_id) != len(nodes):
        raise ValueError("evidence execution node IDs must be unique")
    dependents: dict[str, list[str]] = {group_id: [] for group_id in by_id}
    indegree: dict[str, int] = {}
    parent = {group_id: group_id for group_id in by_id}

    def root(group_id: str) -> str:
        while parent[group_id] != group_id:
            parent[group_id] = parent[parent[group_id]]
            group_id = parent[group_id]
        return group_id

    def union(left: str, right: str) -> None:
        left_root, right_root = root(left), root(right)
        if left_root != right_root:
            parent[max(left_root, right_root)] = min(left_root, right_root)

    for group_id, node in by_id.items():
        dependencies = node.get("depends_on")
        if (
            not isinstance(dependencies, list)
            or any(not isinstance(value, str) or value not in by_id for value in dependencies)
            or len(dependencies) != len(set(dependencies))
        ):
            raise ValueError("evidence execution dependencies are incomplete or ambiguous")
        indegree[group_id] = len(dependencies)
        for dependency in dependencies:
            dependents[dependency].append(group_id)
            union(group_id, dependency)
    ready = sorted(group_id for group_id, count in indegree.items() if count == 0)
    ordered_ids: list[str] = []
    while ready:
        group_id = ready.pop(0)
        ordered_ids.append(group_id)
        for dependent in sorted(dependents[group_id]):
            indegree[dependent] -= 1
            if indegree[dependent] == 0:
                ready.append(dependent)
                ready.sort()
    if len(ordered_ids) != len(nodes):
        raise ValueError("evidence execution dependencies contain a cycle")
    components: dict[str, list[str]] = {}
    for group_id in by_id:
        components.setdefault(root(group_id), []).append(group_id)
    loads = [0] * shard_count
    component_assignment: dict[str, int] = {}
    ordered_components = sorted(
        components.items(),
        key=lambda item: (
            -sum(estimates.get(group_id, 1) for group_id in item[1]),
            tuple(sorted(item[1])),
        ),
    )
    for component_id, group_ids in ordered_components:
        duration = sum(estimates.get(group_id, 1) for group_id in group_ids)
        shard = min(range(shard_count), key=lambda index: (loads[index], index))
        component_assignment[component_id] = shard
        loads[shard] += duration
    return [
        {
            **by_id[group_id],
            "assigned_shard": component_assignment[root(group_id)],
            "estimated_duration_ms": estimates.get(group_id, 1),
            "duration_source": "observed_receipt" if group_id in estimates else "unknown_default",
        }
        for group_id in ordered_ids
    ]

"""Deterministic duration observations and constrained evidence assignment."""

from __future__ import annotations

from datetime import datetime
from typing import Any, Iterable, Mapping


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
    """Apply deterministic longest-processing-time assignment to independent groups."""

    if shard_count < 1:
        raise ValueError("evidence shard count must be positive")
    loads = [0] * shard_count
    assigned: dict[str, tuple[int, int, str]] = {}
    ordered = sorted(
        nodes,
        key=lambda node: (-estimates.get(str(node["id"]), 1), str(node["id"])),
    )
    for node in ordered:
        group_id = str(node["id"])
        duration = estimates.get(group_id, 1)
        shard = min(range(shard_count), key=lambda index: (loads[index], index))
        assigned[group_id] = (
            shard,
            duration,
            "observed_receipt" if group_id in estimates else "unknown_default",
        )
        loads[shard] += duration
    return [
        {
            **node,
            "assigned_shard": assigned[str(node["id"])][0],
            "estimated_duration_ms": assigned[str(node["id"])][1],
            "duration_source": assigned[str(node["id"])][2],
        }
        for node in nodes
    ]

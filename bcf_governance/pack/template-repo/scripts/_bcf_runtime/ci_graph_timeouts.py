"""Mechanical compatibility between evidence subprocess and workflow timeouts."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from .ci_graph_errors import CIGraphError
from .ci_graph_yaml import GraphYAMLError, load_yaml_path


LEGACY_GATE_TIMEOUT_SECONDS = 1800
LEGACY_HEADROOM_SECONDS = 60


def gate_timeout_contract(repo_root: Path) -> tuple[int, dict[str, int]]:
    """Read the canonical gate timeout defaults and optional per-gate overrides."""

    path = repo_root / "governance/gate-contracts.yml"
    if not path.is_file() or path.is_symlink():
        return LEGACY_GATE_TIMEOUT_SECONDS, {}
    try:
        registry = load_yaml_path(path)
    except GraphYAMLError as exc:
        raise CIGraphError(str(exc)) from exc
    policy = registry.get("execution_policy", {})
    default = policy.get("default_timeout_seconds", LEGACY_GATE_TIMEOUT_SECONDS)
    gates = registry.get("gates", {})
    if (
        isinstance(default, bool)
        or not isinstance(default, int)
        or default < 1
        or not isinstance(gates, dict)
    ):
        raise CIGraphError("gate execution timeout policy is invalid")
    overrides: dict[str, int] = {}
    for gate_id, raw in gates.items():
        invocation = raw.get("invocation") if isinstance(raw, dict) else None
        timeout = invocation.get("timeout_seconds") if isinstance(invocation, dict) else None
        if timeout is None:
            continue
        if isinstance(timeout, bool) or not isinstance(timeout, int) or timeout < 1:
            raise CIGraphError(f"gate {gate_id} execution timeout is invalid")
        overrides[str(gate_id)] = timeout
    return default, overrides


def validate_gate_job_timeouts(repo_root: Path, graph: dict[str, Any]) -> None:
    """Reject any evidence lane whose outer deadline cannot contain one gate deadline."""

    default, overrides = gate_timeout_contract(repo_root)
    headroom = graph["policy"].get(
        "minimum_gate_timeout_headroom_seconds", LEGACY_HEADROOM_SECONDS
    )
    if isinstance(headroom, bool) or not isinstance(headroom, int) or headroom < 1:
        raise CIGraphError("CI graph gate timeout headroom is invalid")
    for workflow in graph["workflows"]:
        for job in workflow["jobs"]:
            executor = job["executor"]
            if executor["kind"] not in {"gate_group", "gate_shard"}:
                continue
            maximum = max(overrides.get(str(gate), default) for gate in executor["gates"])
            available = int(job["timeout_minutes"]) * 60
            required = maximum + headroom
            if available < required:
                raise CIGraphError(
                    f"CI graph evidence job {job['id']} timeout {available}s cannot contain "
                    f"the {maximum}s gate timeout plus {headroom}s headroom"
                )

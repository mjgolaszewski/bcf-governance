"""Mechanical compatibility between evidence subprocess and workflow timeouts."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from .ci_graph_errors import CIGraphError
from .ci_graph_yaml import GraphYAMLError, load_yaml_path


LEGACY_GATE_TIMEOUT_SECONDS = 1800
LEGACY_HEADROOM_SECONDS = 60
LEGACY_GATE_CLEANUP_SECONDS = LEGACY_HEADROOM_SECONDS
INTERPRETER_PROBE_TIMEOUT_SECONDS = 30


def bounded_execution_seconds(value: object, *, field: str) -> int:
    """Validate the common execution-policy scalar before resource allocation."""
    if type(value) is not int or not 1 <= value <= 21600:
        raise CIGraphError(f"{field} must be integer seconds in1..21600")
    return value


def gate_cleanup_timeout_seconds(policy: dict[str, Any]) -> int:
    """One cleanup policy owner for execution, admission and deadline consumers."""
    if not isinstance(policy, dict):
        raise CIGraphError("gate cleanup timeout policy is invalid")
    return bounded_execution_seconds(
        policy.get('default_cleanup_timeout_seconds', LEGACY_GATE_CLEANUP_SECONDS),
        field='gate cleanup timeout',
    )


def quantized_deadline_ms(*, bounded_work_ms: int, setup_ms: int, cleanup_ms: int,
                          measured_lower_bound_ms: int, headroom_ms: int) -> int:
    """Compose supplied bounds; authentication/qualification belongs to consumers."""
    values = (bounded_work_ms, setup_ms, cleanup_ms, measured_lower_bound_ms, headroom_ms)
    if any(type(value) is not int or value < 0 for value in values):
        raise CIGraphError("deadline bounds must be nonnegative integer milliseconds")
    required = max(bounded_work_ms + setup_ms + cleanup_ms, measured_lower_bound_ms) + headroom_ms
    return ((required + 59999) // 60000) * 60000


def gate_deadline_contract(repo_root: Path) -> tuple[int, dict[str, int], int]:
    """Read the canonical gate timeout defaults and optional per-gate overrides."""

    path = repo_root / "governance/gate-contracts.yml"
    if not path.exists() and not path.is_symlink():
        return LEGACY_GATE_TIMEOUT_SECONDS, {}, LEGACY_GATE_CLEANUP_SECONDS
    try:
        registry = load_yaml_path(path)
    except GraphYAMLError as exc:
        raise CIGraphError(str(exc)) from exc
    policy = registry.get("execution_policy", {})
    if not isinstance(policy, dict):
        raise CIGraphError("gate execution timeout policy is invalid")
    cleanup = gate_cleanup_timeout_seconds(policy)
    default = policy.get("default_timeout_seconds", LEGACY_GATE_TIMEOUT_SECONDS)
    gates = registry.get("gates", {})
    if (
        isinstance(default, bool)
        or not isinstance(default, int)
        or default < 1
        or not isinstance(gates, dict)
    ):
        raise CIGraphError("gate execution timeout policy is invalid")
    default = bounded_execution_seconds(default, field="gate execution timeout")
    overrides: dict[str, int] = {}
    for gate_id, raw in gates.items():
        if not isinstance(raw, dict):
            raise CIGraphError(f"gate {gate_id} timeout invocation contract is invalid")
        if "invocation" not in raw:
            continue
        invocation = raw["invocation"]
        if not isinstance(invocation, dict):
            raise CIGraphError(f"gate {gate_id} timeout invocation contract is invalid")
        if "timeout_seconds" not in invocation:
            continue
        timeout = invocation["timeout_seconds"]
        if isinstance(timeout, bool) or not isinstance(timeout, int) or timeout < 1:
            raise CIGraphError(f"gate {gate_id} execution timeout is invalid")
        overrides[str(gate_id)] = bounded_execution_seconds(timeout, field=f"gate {gate_id} execution timeout")
    return default, overrides, cleanup


def gate_timeout_contract(repo_root: Path) -> tuple[int, dict[str, int]]:
    """Preserve the existing interface while validating complete deadline policy."""
    default, overrides, _cleanup = gate_deadline_contract(repo_root)
    return default, overrides


def validate_gate_job_timeouts(repo_root: Path, graph: dict[str, Any]) -> None:
    """Reject any evidence lane whose outer deadline cannot contain one gate deadline."""

    default, overrides, cleanup = gate_deadline_contract(repo_root)
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
            required = quantized_deadline_ms(bounded_work_ms=maximum * 1000, setup_ms=INTERPRETER_PROBE_TIMEOUT_SECONDS * 1000,
                cleanup_ms=2 * cleanup * 1000, measured_lower_bound_ms=0, headroom_ms=headroom * 1000) // 1000
            if available < required:
                raise CIGraphError(
                    f"CI graph evidence job {job['id']} timeout {available}s cannot contain "
                    f"the {maximum}s gate timeout plus {INTERPRETER_PROBE_TIMEOUT_SECONDS}s interpreter setup, "
                    f"two {cleanup}s cleanup bounds and {headroom}s headroom"
                )


def validate_component_job_timeouts(graph: dict[str, Any]) -> None:
    """Reject jobs whose deadline cannot contain a declared component minimum."""

    components = graph["step_components"]
    for workflow in graph["workflows"]:
        for job in workflow["jobs"]:
            executor = job["executor"]
            if executor["kind"] != "component_sequence":
                continue
            for component_id in executor["components"]:
                minimum = components[component_id].get("minimum_job_timeout_minutes")
                if minimum is None:
                    continue
                available = int(job["timeout_minutes"])
                required = quantized_deadline_ms(bounded_work_ms=int(minimum) * 60000, setup_ms=0,
                    cleanup_ms=0, measured_lower_bound_ms=0, headroom_ms=0) // 60000
                if available < required:
                    raise CIGraphError(
                        f"CI graph job {workflow['id']}/{job['id']} timeout "
                        f"{available}m cannot contain component {component_id} minimum "
                        f"{minimum}m"
                    )

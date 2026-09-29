"""Derive minimal test-node commands for isolated negative controls."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import subprocess
from typing import Any, Callable
import xml.etree.ElementTree as ET

from .evidence_gate_contracts import _gate_contract
from .test_manifests import OracleManifestIndex, PytestSelectorMap, TestManifestError
from .test_manifests import check_gate_selectors, oracle_manifest_index


class NegativeControlCommandError(ValueError):
    """Raised when a declared test-node oracle cannot be executed exactly."""


def selected_oracle_manifest_index(
    repo_root: Path, controls: list[object]
) -> OracleManifestIndex | None:
    """Load manifests only when a selected control owns a test-node oracle."""

    required = any(
        isinstance(control, dict)
        and isinstance(control.get("oracle"), dict)
        and control["oracle"].get("kind") == "test_node_failure"
        for control in controls
    )
    return oracle_manifest_index(repo_root) if required else None


@dataclass(frozen=True)
class NegativeControlOracleExecution:
    """Exact graph-owned test producer for one negative-control oracle."""

    gate_id: str
    contract: dict[str, Any]
    selector_map: PytestSelectorMap | None


def _pytest_selector(
    value: object, selector_map: PytestSelectorMap | None
) -> str:
    if selector_map is None:
        raise NegativeControlCommandError(
            "test-node oracle requires a verified pytest collection mapping"
        )
    try:
        return selector_map.selector_for(value)
    except TestManifestError as exc:
        raise NegativeControlCommandError(str(exc)) from exc


def negative_control_command(
    canonical: list[str],
    contract: dict[str, Any],
    control: dict[str, Any],
    python_executable: Path,
    worktree: Path,
    selector_map: PytestSelectorMap | None = None,
) -> list[str]:
    """Run only named pytest oracle nodes when the test contract supports it."""

    oracle = control.get("oracle")
    test_contract = contract.get("test_contract")
    if (
        not isinstance(oracle, dict)
        or oracle.get("kind") != "test_node_failure"
        or not isinstance(test_contract, dict)
        or not isinstance(test_contract.get("selectors"), list)
        or not isinstance(test_contract.get("expected_node_manifest"), str)
    ):
        return canonical
    nodes = oracle.get("node_ids")
    if not isinstance(nodes, list) or not nodes:
        raise NegativeControlCommandError("test-node oracle has no nodes")
    junit_value = test_contract.get("junit_xml")
    if not isinstance(junit_value, str):
        raise NegativeControlCommandError("test-node oracle has no JUnit contract")
    junit = Path(junit_value)
    if junit.is_absolute() or ".." in junit.parts:
        raise NegativeControlCommandError("test-node JUnit path escapes the repository")
    parent = (worktree / junit).parent.resolve()
    if not parent.is_relative_to(worktree.resolve()):
        raise NegativeControlCommandError("test-node JUnit parent escapes the repository")
    parent.mkdir(parents=True, exist_ok=True)
    return [
        str(python_executable),
        "-m",
        "pytest",
        "-q",
        *(_pytest_selector(value, selector_map) for value in nodes),
        f"--junitxml={junit.as_posix()}",
    ]


def resolve_negative_control_oracle(
    repo_root: Path,
    owning_contract: dict[str, Any],
    control: dict[str, Any],
    *,
    python_executable: Path,
    manifest_index: OracleManifestIndex | None = None,
    selector_maps: dict[str, PytestSelectorMap] | None = None,
) -> NegativeControlOracleExecution:
    """Resolve a test oracle through its actual governed producer."""

    oracle = control.get("oracle")
    if not isinstance(oracle, dict) or oracle.get("kind") != "test_node_failure":
        return NegativeControlOracleExecution(
            str(owning_contract["target"]), owning_contract, None
        )
    try:
        index = manifest_index or oracle_manifest_index(repo_root)
        owning_test_contract = owning_contract.get("test_contract")
        if (
            not index.manifests
            and isinstance(owning_test_contract, dict)
            and isinstance(owning_test_contract.get("junit_xml"), str)
        ):
            return NegativeControlOracleExecution(
                str(owning_contract["target"]), owning_contract, None
            )
        gate_id = index.resolve(
            oracle.get("node_ids"),
            preferred_gate=str(owning_contract["target"]),
        )
        contract = _gate_contract(repo_root, gate_id)
        cache = selector_maps if selector_maps is not None else {}
        selector_map = cache.get(gate_id)
        if selector_map is None:
            selector_map = check_gate_selectors(
                repo_root, gate_id, python_executable=python_executable
            )
            cache[gate_id] = selector_map
    except TestManifestError as exc:
        raise NegativeControlCommandError(str(exc)) from exc
    return NegativeControlOracleExecution(gate_id, contract, selector_map)


def junit_nodes(path: Path) -> tuple[set[str], set[str]]:
    if not path.is_file() or path.is_symlink():
        return set(), set()
    observed: set[str] = set()
    failed: set[str] = set()
    root = ET.parse(path).getroot()
    for case in root.iter("testcase"):
        classname = case.attrib.get("classname", "")
        name = case.attrib.get("name", "")
        identity = f"{classname}::{name}" if classname else name
        observed.add(identity)
        if case.find("failure") is not None or case.find("error") is not None:
            failed.add(identity)
    return observed, failed


def execute_cross_gate_baseline(
    repo_root: Path,
    worktree: Path,
    owning_command: list[str],
    execution: NegativeControlOracleExecution,
    control: dict[str, Any],
    python_executable: Path,
    *,
    session_id: str,
    require_state: bool,
    runner: Callable[..., tuple[subprocess.CompletedProcess[str], dict[str, str], dict[str, Any], dict[str, Any]]],
    job_environment: dict[str, str] | None = None,
) -> bool:
    """Prove a cross-gate oracle passes before applying its exact mutation."""

    command = negative_control_command(
        owning_command,
        execution.contract,
        control,
        python_executable,
        worktree,
        execution.selector_map,
    )
    result, _environment, _metadata, _state = runner(
        repo_root,
        worktree,
        execution.contract,
        command,
        python_executable,
        session_id=session_id,
        execution_id=f"negative-control-baseline:{control['id']}",
        require_state=require_state,
        job_environment=job_environment,
    )
    test_contract = execution.contract.get("test_contract")
    junit_value = (
        test_contract.get("junit_xml") if isinstance(test_contract, dict) else None
    )
    observed, failed = (
        junit_nodes(worktree / junit_value)
        if isinstance(junit_value, str)
        else (set(), set())
    )
    required = {
        str(node)
        for node in control.get("oracle", {}).get("node_ids", [])
        if isinstance(node, str)
    }
    return result.returncode == 0 and bool(required) and required <= observed and not failed

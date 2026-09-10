"""Derive minimal test-node commands for isolated negative controls."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from .test_manifests import PytestSelectorMap, TestManifestError


class NegativeControlCommandError(ValueError):
    """Raised when a declared test-node oracle cannot be executed exactly."""


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

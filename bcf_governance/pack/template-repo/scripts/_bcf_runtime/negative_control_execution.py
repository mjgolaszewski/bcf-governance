"""Derive minimal test-node commands for isolated negative controls."""

from __future__ import annotations

from pathlib import Path
import re
from typing import Any


class NegativeControlCommandError(ValueError):
    """Raised when a declared test-node oracle cannot be executed exactly."""


def _pytest_selector(value: object) -> str:
    if not isinstance(value, str) or value.count("::") < 1:
        raise NegativeControlCommandError("test-node oracle is not exact")
    module, remainder = value.split("::", 1)
    if not remainder or any(
        ord(character) < 32 or ord(character) > 126 for character in remainder
    ):
        raise NegativeControlCommandError("test-node oracle contains an unsafe node")
    if module.endswith(".py"):
        relative = Path(module)
    else:
        if not re.fullmatch(r"[A-Za-z0-9_.]+", module):
            raise NegativeControlCommandError("test-node oracle contains an unsafe module")
        relative = Path(*module.split(".")).with_suffix(".py")
    if relative.is_absolute() or ".." in relative.parts:
        raise NegativeControlCommandError("test-node oracle escapes the repository")
    return f"{relative.as_posix()}::{remainder}"


def negative_control_command(
    canonical: list[str],
    contract: dict[str, Any],
    control: dict[str, Any],
    python_executable: Path,
    worktree: Path,
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
        *(_pytest_selector(value) for value in nodes),
        f"--junitxml={junit.as_posix()}",
    ]

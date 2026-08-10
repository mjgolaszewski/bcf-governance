from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))
try:
    from scripts.cleanup_ci_resources import (
        discover_resources,
        remove_resources,
        validate_run_id,
    )
finally:
    sys.path.pop(0)


class DockerRunner:
    def __init__(self) -> None:
        self.commands: list[list[str]] = []

    def __call__(self, command: list[str]) -> subprocess.CompletedProcess[str]:
        self.commands.append(command)
        outputs = {
            "ps": "container-owned\n",
            "network": "network-owned\n",
            "volume": "volume-owned\n",
            "image": "image-owned\nimage-owned\n",
        }
        kind = command[1]
        return subprocess.CompletedProcess(command, 0, outputs.get(kind, ""), "")


@pytest.mark.parametrize("run_id", ["", "all", "*", "bad id", "../../broad"])
def test_ci_cleanup_rejects_unsafe_run_ids(run_id: str) -> None:
    with pytest.raises(ValueError):
        validate_run_id(run_id)


def test_ci_cleanup_discovers_only_exact_label_owned_resources() -> None:
    runner = DockerRunner()

    resources = discover_resources("run-12345", runner)

    assert {(item.kind, item.object_id) for item in resources} == {
        ("container", "container-owned"),
        ("network", "network-owned"),
        ("volume", "volume-owned"),
        ("image", "image-owned"),
    }
    assert all(
        "label=io.bcf-governance.ci-run=run-12345" in command for command in runner.commands
    )


def test_ci_cleanup_removes_only_resources_returned_by_owned_plan() -> None:
    runner = DockerRunner()
    resources = discover_resources("run-12345", runner)
    runner.commands.clear()

    remove_resources(resources, runner)

    assert runner.commands == [
        ["docker", "rm", "-f", "container-owned"],
        ["docker", "network", "rm", "network-owned"],
        ["docker", "volume", "rm", "volume-owned"],
        ["docker", "image", "rm", "image-owned"],
    ]
    assert all("prune" not in command for command in runner.commands)

from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest
import yaml

from bcf_governance.tooling.test_manifests import (
    TestManifestError as ManifestError,
    check_gate,
    collect_nodes,
    declared_test_gates,
    update_gate,
)


REPO_ROOT = Path(__file__).resolve().parents[1]


def _repo(tmp_path: Path) -> Path:
    repo = tmp_path / "repo"
    (repo / "governance/test-manifests").mkdir(parents=True)
    (repo / "tests").mkdir()
    (repo / "AGENTS.yml").write_text(
        "testing_governance:\n  test_roots: [tests]\n", encoding="utf-8"
    )
    (repo / "tests/test_sample.py").write_text(
        "def test_one():\n    assert True\n\ndef test_two():\n    assert True\n",
        encoding="utf-8",
    )
    gate = {
        "evidence": {
            "test_contract": {
                "selectors": ["@test_roots"],
                "expected_node_manifest": "governance/test-manifests/test.txt",
            }
        }
    }
    (repo / "governance/gate-contracts.yml").write_text(
        yaml.safe_dump({"gates": {"test": gate}}, sort_keys=False), encoding="utf-8"
    )
    return repo


def test_manifest_update_and_check_use_contract_selectors(tmp_path: Path) -> None:
    repo = _repo(tmp_path)

    path = update_gate(repo, "test", python_executable=sys.executable)
    nodes = check_gate(repo, "test", python_executable=sys.executable)

    assert path.read_text(encoding="utf-8").splitlines() == nodes
    assert nodes == ["tests.test_sample::test_one", "tests.test_sample::test_two"]


def test_manifest_drift_reports_missing_and_extra_nodes(tmp_path: Path) -> None:
    repo = _repo(tmp_path)
    path = update_gate(repo, "test", python_executable=sys.executable)
    path.write_text("tests.test_sample::test_missing\n", encoding="utf-8")

    with pytest.raises(ManifestError, match="test node manifest drift"):
        check_gate(repo, "test", python_executable=sys.executable)


def test_manifest_collection_uses_selected_interpreter_not_host_path(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repo = _repo(tmp_path)
    selected = Path(sys.executable)
    hostile_bin = tmp_path / "host"
    hostile_bin.mkdir()
    hostile = hostile_bin / "python"
    hostile.write_text("#!/bin/sh\nexit 93\n", encoding="utf-8")
    hostile.chmod(0o755)
    monkeypatch.setenv("PATH", f"{hostile_bin}{os.pathsep}{os.environ['PATH']}")

    assert collect_nodes(repo, "test", python_executable=selected) == [
        "tests.test_sample::test_one",
        "tests.test_sample::test_two",
    ]


def test_manifest_collection_classifies_missing_pytest_as_infrastructure(
    tmp_path: Path,
) -> None:
    repo = _repo(tmp_path)
    selected = tmp_path / "python-without-pytest"
    selected.write_text("#!/bin/sh\nexit 77\n", encoding="utf-8")
    selected.chmod(0o755)

    with pytest.raises(ManifestError, match="collection infrastructure failure"):
        collect_nodes(repo, "test", python_executable=selected)


def test_current_repo_declares_exact_manifest_for_every_test_gate() -> None:
    gates = declared_test_gates(REPO_ROOT)

    assert gates == [
        "architecture-context-membership",
        "architecture-cqrs-side",
        "architecture-duplication",
        "architecture-import-boundaries",
        "architecture-layer-membership",
        "architecture-module-size",
        "architecture-router-thinness",
        "architecture-test",
        "contract-test",
        "test",
    ]
    for gate in gates:
        assert check_gate(REPO_ROOT, gate, python_executable=sys.executable)

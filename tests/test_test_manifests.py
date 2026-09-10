from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest
import yaml

from bcf_governance.tooling.test_manifests import (
    TestManifestError as ManifestError,
    _selector_map_from_nodes,
    check_gate,
    check_gate_selectors,
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


def test_selector_map_preserves_function_class_unittest_nested_and_parameter_nodes(
    tmp_path: Path,
) -> None:
    repo = _repo(tmp_path)
    (repo / "tests/test_sample.py").write_text(
        """import unittest
import pytest

def test_function():
    assert True

class TestPytestClass:
    def test_method(self):
        assert True

    class TestNestedClass:
        def test_nested(self):
            assert True

class TestUnittestCase(unittest.TestCase):
    def test_unittest_method(self):
        self.assertTrue(True)

@pytest.mark.parametrize("value", ["one::two", "two"])
def test_parameterized(value):
    assert value
""",
        encoding="utf-8",
    )
    update_gate(repo, "test", python_executable=sys.executable)

    mapping = check_gate_selectors(repo, "test", python_executable=sys.executable)

    assert mapping.selector_for("tests.test_sample::test_function") == (
        "tests/test_sample.py::test_function"
    )
    assert mapping.selector_for("tests.test_sample.TestPytestClass::test_method") == (
        "tests/test_sample.py::TestPytestClass::test_method"
    )
    assert mapping.selector_for(
        "tests.test_sample.TestPytestClass.TestNestedClass::test_nested"
    ) == "tests/test_sample.py::TestPytestClass::TestNestedClass::test_nested"
    assert mapping.selector_for(
        "tests.test_sample.TestUnittestCase::test_unittest_method"
    ) == "tests/test_sample.py::TestUnittestCase::test_unittest_method"
    assert mapping.selector_for("tests.test_sample::test_parameterized[one::two]") == (
        "tests/test_sample.py::test_parameterized[one::two]"
    )


def test_selector_map_rejects_ambiguous_junit_identity() -> None:
    with pytest.raises(ManifestError, match="ambiguous JUnit node identity"):
        _selector_map_from_nodes(
            "test",
            [
                "tests/test_collision.py::TestCase::test_same",
                "tests/test_collision/TestCase.py::test_same",
            ],
        )


def test_selector_map_rejects_absent_oracle_node() -> None:
    mapping = _selector_map_from_nodes("test", ["tests/test_sample.py::test_present"])

    with pytest.raises(ManifestError, match="absent from the verified collection mapping"):
        mapping.selector_for("tests.test_sample.TestCase::test_missing")


def test_selector_map_rejects_unsafe_raw_selector() -> None:
    with pytest.raises(ManifestError, match="unsafe node"):
        _selector_map_from_nodes("test", ["-tests/test_sample.py::test_option"])


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

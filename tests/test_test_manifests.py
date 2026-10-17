from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest
import yaml

from bcf_governance.tooling.test_manifests import (
    TestManifestError as ManifestError,
    _collect_raw_nodes,
    _selector_map_from_nodes,
    check_all,
    check_gate,
    check_gate_selectors,
    collect_nodes,
    declared_test_gates,
    resolve_oracle_test_gate,
    update_gate,
    update_all,
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


@pytest.mark.parametrize(
    "node, pattern",
    [
        (
            "tests/test_sample.py::test_parameter[/docker/project-fixture]",
            "local_workspace_path",
        ),
        (
            "tests/test_sample.py::test_parameter[service.corp]",
            "private_hostname",
        ),
    ],
    ids=("local-path", "private-host"),
)
def test_manifest_producer_rejects_nonportable_collected_identity_before_write(
    tmp_path: Path, node: str, pattern: str
) -> None:
    repo = _repo(tmp_path)
    manifest = repo / "governance/test-manifests/test.txt"

    with pytest.raises(ManifestError, match=pattern):
        _selector_map_from_nodes("test", [node])

    assert not manifest.exists()


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


def test_manifest_collection_removes_controller_import_path_from_project(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repo = _repo(tmp_path)
    (repo / "scripts").mkdir()
    (repo / "scripts/frontend_toolchain.py").write_text(
        "VALUE = 'project'\n", encoding="utf-8"
    )
    (repo / "tests/test_sample.py").write_text(
        "from scripts.frontend_toolchain import VALUE\n\n"
        "def test_project_module():\n    assert VALUE == 'project'\n",
        encoding="utf-8",
    )
    controller = tmp_path / "controller"
    (controller / "scripts").mkdir(parents=True)
    (controller / "scripts/__init__.py").write_text("", encoding="utf-8")
    monkeypatch.setenv("PYTHONPATH", str(controller))

    assert collect_nodes(repo, "test", python_executable=sys.executable) == [
        "tests.test_sample::test_project_module"
    ]


def test_manifest_collection_failure_preserves_both_bounded_streams(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repo = _repo(tmp_path)

    def fail(*args: object, **kwargs: object) -> object:
        del args, kwargs
        return __import__("subprocess").CompletedProcess(
            [], 4, stdout="causal import failure", stderr="no collectors"
        )

    monkeypatch.setattr(
        "bcf_governance.tooling.test_manifests.subprocess.run", fail
    )

    with pytest.raises(ManifestError) as captured:
        _collect_raw_nodes(repo, ["tests"], python_executable=sys.executable)

    assert "stdout:\ncausal import failure" in str(captured.value)
    assert "stderr:\nno collectors" in str(captured.value)


def test_manifest_collection_classifies_missing_pytest_as_infrastructure(
    tmp_path: Path,
) -> None:
    repo = _repo(tmp_path)
    selected = tmp_path / "python-without-pytest"
    selected.write_text("#!/bin/sh\nexit 77\n", encoding="utf-8")
    selected.chmod(0o755)

    with pytest.raises(ManifestError, match="collection infrastructure failure"):
        collect_nodes(repo, "test", python_executable=selected)


def test_all_manifests_share_one_collection_and_partition_exactly(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repo = _repo(tmp_path)
    payload = yaml.safe_load(
        (repo / "governance/gate-contracts.yml").read_text(encoding="utf-8")
    )
    payload["gates"]["focused"] = {
        "evidence": {
            "test_contract": {
                "selectors": ["tests/test_sample.py::test_one"],
                "expected_node_manifest": "governance/test-manifests/focused.txt",
            }
        }
    }
    (repo / "governance/gate-contracts.yml").write_text(
        yaml.safe_dump(payload, sort_keys=False), encoding="utf-8"
    )
    calls = 0
    original = __import__(
        "bcf_governance.tooling.test_manifests", fromlist=["subprocess"]
    ).subprocess.run

    def observe(*args: object, **kwargs: object) -> object:
        nonlocal calls
        calls += 1
        return original(*args, **kwargs)

    monkeypatch.setattr(
        "bcf_governance.tooling.test_manifests.subprocess.run", observe
    )

    paths = update_all(repo, python_executable=sys.executable)
    assert calls == 1
    assert paths["focused"].read_text(encoding="utf-8").splitlines() == [
        "tests.test_sample::test_one"
    ]
    assert paths["test"].read_text(encoding="utf-8").splitlines() == [
        "tests.test_sample::test_one",
        "tests.test_sample::test_two",
    ]
    counts = check_all(repo, python_executable=sys.executable)
    assert calls == 2
    assert counts == {"focused": 1, "test": 2}


def test_oracle_producer_resolves_preferred_or_unique_most_specific_manifest(
    tmp_path: Path,
) -> None:
    repo = _repo(tmp_path)
    payload = yaml.safe_load(
        (repo / "governance/gate-contracts.yml").read_text(encoding="utf-8")
    )
    payload["gates"]["focused"] = {
        "evidence": {
            "test_contract": {
                "selectors": ["tests/test_sample.py::test_one"],
                "expected_node_manifest": "governance/test-manifests/focused.txt",
            }
        }
    }
    (repo / "governance/gate-contracts.yml").write_text(
        yaml.safe_dump(payload, sort_keys=False), encoding="utf-8"
    )
    update_all(repo, python_executable=sys.executable)

    assert resolve_oracle_test_gate(
        repo, ["tests.test_sample::test_one"]
    ) == "focused"
    assert resolve_oracle_test_gate(
        repo, ["tests.test_sample::test_one"], preferred_gate="test"
    ) == "test"
    assert resolve_oracle_test_gate(
        repo,
        ["tests.test_sample::test_one", "tests.test_sample::test_two"],
    ) == "test"


def test_oracle_producer_rejects_ambiguous_equal_manifests(tmp_path: Path) -> None:
    repo = _repo(tmp_path)
    payload = yaml.safe_load(
        (repo / "governance/gate-contracts.yml").read_text(encoding="utf-8")
    )
    for gate_id in ("left", "right"):
        payload["gates"][gate_id] = {
            "evidence": {
                "test_contract": {
                    "selectors": ["tests/test_sample.py::test_one"],
                    "expected_node_manifest": f"governance/test-manifests/{gate_id}.txt",
                }
            }
        }
    (repo / "governance/gate-contracts.yml").write_text(
        yaml.safe_dump(payload, sort_keys=False), encoding="utf-8"
    )
    update_all(repo, python_executable=sys.executable)

    with pytest.raises(ManifestError, match="producer is ambiguous"):
        resolve_oracle_test_gate(repo, ["tests.test_sample::test_one"])


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
    assert all(check_all(REPO_ROOT, python_executable=sys.executable).values())


@pytest.fixture
def reference_repo(tmp_path):
    repo = _repo(tmp_path)
    path = repo / 'governance/gate-contracts.yml'
    registry = yaml.safe_load(path.read_text())
    registry['gates']['test']['evidence']['test_contract']['reference_inventories'] = [
        {'path': 'references.yml', 'format': 'implementation_slice_bindings.v1'}]
    path.write_text(yaml.safe_dump(registry))
    inventory = {'implementation_slices': {'sample': {'positive_tests': ['tests.test_sample::test_one'],
        'negative_controls': [{'cause': 'second-case', 'test': 'tests.test_sample::test_two'}]}}}
    (repo / 'references.yml').write_text(yaml.safe_dump(inventory))
    return repo


def test_authored_reference_inventory_uses_exact_collection_before_generated_manifest(reference_repo):
    from bcf_governance.tooling import test_manifests as manifests
    manifest = reference_repo / 'governance/test-manifests/test.txt'
    manifest.write_text('tests.test_sample::obsolete\n')
    result = manifests.validate_authored_test_reference_inventories(reference_repo, python_executable=sys.executable)
    assert result == {'authority': False, 'execution_qualified': False, 'inventories_checked': 1, 'nodes_checked': 2}
    assert manifest.read_text() == 'tests.test_sample::obsolete\n'
    with pytest.raises(ManifestError, match='reference inventory'):
        manifests.validate_declared_test_reference_inventories(reference_repo, manifest_index=manifests.oracle_manifest_index(reference_repo))
    manifest.write_text('tests.test_sample::test_one\ntests.test_sample::test_two\n')
    assert manifests.validate_declared_test_reference_inventories(reference_repo,
        manifest_index=manifests.oracle_manifest_index(reference_repo)) == result


@pytest.mark.parametrize('defect', ['null-declarations', 'empty-declarations', 'unknown-format', 'escaping-path',
    'missing-file', 'symlink', 'duplicate-yaml', 'empty-positive', 'duplicate-positive', 'empty-negative',
    'duplicate-cause', 'missing-test', 'empty-inventory'])
def test_reference_inventory_rejects_malformed_inputs_before_collection(reference_repo, monkeypatch, defect):
    from bcf_governance.tooling import test_manifests as manifests
    policy_path = reference_repo / 'governance/gate-contracts.yml'
    registry = yaml.safe_load(policy_path.read_text())
    contract = registry['gates']['test']['evidence']['test_contract']
    descriptor = contract['reference_inventories'][0]
    path = reference_repo / 'references.yml'
    inventory = yaml.safe_load(path.read_text())
    binding = inventory['implementation_slices']['sample']
    if defect == 'null-declarations': contract['reference_inventories'] = None
    elif defect == 'empty-declarations': contract['reference_inventories'] = []
    elif defect == 'unknown-format': descriptor['format'] = 'unknown'
    elif defect == 'escaping-path': descriptor['path'] = '../references.yml'
    elif defect == 'missing-file': descriptor['path'] = 'absent.yml'
    elif defect == 'symlink':
        path.rename(reference_repo / 'real.yml')
        path.symlink_to('real.yml')
    elif defect == 'empty-positive': binding['positive_tests'] = []
    elif defect == 'duplicate-positive': binding['positive_tests'] *= 2
    elif defect == 'empty-negative': binding['negative_controls'] = []
    elif defect == 'duplicate-cause': binding['negative_controls'] *= 2
    elif defect == 'missing-test': del binding['negative_controls'][0]['test']
    elif defect == 'empty-inventory': inventory['implementation_slices'] = {}
    if defect != 'symlink':
        path.write_text(yaml.safe_dump(inventory))
    if defect == 'duplicate-yaml':
        path.write_text(path.read_text() + 'implementation_slices: {}\n')
    policy_path.write_text(yaml.safe_dump(registry))
    monkeypatch.setattr(manifests, 'collect_selector_maps', lambda *_a, **_k: pytest.fail('collected malformed inventory'))
    with pytest.raises(ManifestError, match='reference inventor'):
        manifests.validate_authored_test_reference_inventories(reference_repo, python_executable=sys.executable)


def test_reference_inventory_never_expands_a_bare_parameterized_reference(reference_repo):
    from bcf_governance.tooling import test_manifests as manifests
    (reference_repo / 'tests/test_sample.py').write_text('import pytest\n@pytest.mark.parametrize("value", [1, 2])\ndef test_one(value):\n    assert value\n\ndef test_two():\n    assert True\n')
    with pytest.raises(ManifestError, match='reference inventory'):
        manifests.validate_authored_test_reference_inventories(reference_repo, python_executable=sys.executable)


def test_reference_inventory_cannot_switch_to_another_producer(reference_repo):
    from bcf_governance.tooling import test_manifests as manifests
    index = manifests.OracleManifestIndex((('other', frozenset({'tests.test_sample::test_one', 'tests.test_sample::test_two'})),))
    with pytest.raises(ManifestError, match='reference inventory'):
        manifests.validate_declared_test_reference_inventories(reference_repo, manifest_index=index)


def test_reference_inventory_legacy_absence_does_not_collect(tmp_path, monkeypatch):
    from bcf_governance.tooling import test_manifests as manifests
    repo = _repo(tmp_path)
    monkeypatch.setattr(manifests, 'collect_selector_maps', lambda *_a, **_k: pytest.fail('collected legacy absence'))
    result = manifests.validate_authored_test_reference_inventories(repo, python_executable=sys.executable)
    assert result['inventories_checked'] == 0 and result['nodes_checked'] == 0
    assert result['authority'] is False and result['execution_qualified'] is False


def test_preflight_reference_inventory_uses_same_exact_manifest_owner(reference_repo):
    from bcf_governance.tooling.governance_validation.preflight_negative_controls import stale_negative_control_oracles, NegativeControlPreflightError
    (reference_repo / 'governance/test-manifests/test.txt').write_text('tests.test_sample::obsolete\n')
    with pytest.raises(NegativeControlPreflightError, match='reference inventory'):
        stale_negative_control_oracles(reference_repo)


@pytest.mark.parametrize('changed', ['references.yml', 'governance/gate-contracts.yml'])
def test_reference_inventory_input_movement_during_collection_blocks(reference_repo, monkeypatch, changed):
    from bcf_governance.tooling import test_manifests as manifests
    def collect(*_args, **_kwargs):
        path = reference_repo / changed
        path.write_text(path.read_text() + '# changed during collection\n')
        return {'test': manifests.PytestSelectorMap('test', (
            ('tests.test_sample::test_one', 'tests/test_sample.py::test_one'),
            ('tests.test_sample::test_two', 'tests/test_sample.py::test_two')))}
    monkeypatch.setattr(manifests, 'collect_selector_maps', collect)
    with pytest.raises(ManifestError, match='reference inventory.*changed'):
        manifests.validate_authored_test_reference_inventories(reference_repo, python_executable=sys.executable)


def test_reference_inventory_legacy_absence_preserves_existing_yaml_merge_inputs(tmp_path, monkeypatch):
    from bcf_governance.tooling import test_manifests as manifests
    repo = _repo(tmp_path)
    (repo / 'governance/gate-contracts.yml').write_text('gates:\n  seed:\n    evidence:\n      test_contract: &base\n        selectors: [tests]\n        expected_node_manifest: nodes.txt\n  test:\n    evidence:\n      test_contract:\n        <<: *base\n')
    monkeypatch.setattr(manifests, 'collect_selector_maps', lambda *_a, **_k: pytest.fail('collected legacy merge input'))
    result = manifests.validate_authored_test_reference_inventories(repo, python_executable=sys.executable)
    assert result['inventories_checked'] == 0

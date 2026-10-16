from __future__ import annotations

import copy
from pathlib import Path

import pytest

from bcf_governance.tooling.semantic_operation_effects import (
    SemanticOperationEffectError, source_operation_call_population,
)
from bcf_governance.tooling.semantic_ownership_inventory import discover_python_source


@pytest.fixture
def inventory(tmp_path: Path):
    path = tmp_path / "runtime.py"
    path.write_text("def root():\n    declared_port()\n    declared_port()\ndef declared_port():\n    hidden(1)\n    root()\ndef disconnected():\n    unrelated()\n")
    return discover_python_source(tmp_path, files=[path], call_contracts_version="1.0")


def test_operation_call_population_crosses_ports_and_terminates_cycles(inventory):
    before = copy.deepcopy(inventory)
    result = source_operation_call_population("runtime.py::root", inventory)
    assert result["authority"] is False
    assert result["execution_qualified"] is False
    assert result["scope"] == "discovered_python_functions_only"
    assert result["functions"] == ("runtime.py::declared_port", "runtime.py::root")
    assert len(result["calls"]) == 4
    assert result["unresolved_calls"] == 1
    assert sorted(row[3] for row in result["calls"] if row[0] == "runtime.py::root") == [0, 1]
    assert result["source_files"] == (("runtime.py", inventory["files"][0]["sha256"]),)
    assert inventory == before
    inventory["functions"].reverse()
    assert source_operation_call_population("runtime.py::root", inventory) == result


def test_added_call_changes_population_without_removing_functions(inventory):
    original = source_operation_call_population("runtime.py::root", inventory)
    helper = next(row for row in inventory["functions"] if row["symbol"].endswith("::declared_port"))
    added = copy.deepcopy(helper["calls"][0])
    added["call_contract"]["occurrence"] += 1
    helper["calls"].append(added)
    changed = source_operation_call_population("runtime.py::root", inventory)
    assert changed["functions"] == original["functions"]
    assert len(changed["calls"]) == len(original["calls"]) + 1
    assert changed["unresolved_calls"] == 2


@pytest.mark.parametrize("defect", ["version", "authority", "duplicate_function", "missing_facts", "duplicate_call", "bad_digest", "bad_occurrence", "wrong_entrypoint"])
def test_operation_call_population_rejects_incompatible_or_ambiguous_input(inventory, defect):
    entrypoint = "runtime.py::root"
    call = inventory["functions"][0]["calls"][0]
    if defect == "version":
        inventory["call_contracts_version"] = "2.0"
    elif defect == "authority":
        inventory["authority"] = True
    elif defect == "duplicate_function":
        inventory["functions"].append(copy.deepcopy(inventory["functions"][0]))
    elif defect == "missing_facts":
        del call["call_contract"]
    elif defect == "duplicate_call":
        inventory["functions"][0]["calls"].append(copy.deepcopy(call))
    elif defect == "bad_digest":
        call["call_contract"]["expression_sha256"] = "x" * 64
    elif defect == "bad_occurrence":
        call["call_contract"]["occurrence"] = True
    else:
        entrypoint = "other/runtime.py::root"
    with pytest.raises(SemanticOperationEffectError):
        source_operation_call_population(entrypoint, inventory)


def test_ambiguous_dispatch_stays_unresolved_and_is_not_followed(inventory):
    for call in inventory["functions"][0]["calls"]:
        call["dispatch_resolution"] = "unresolved"
    result = source_operation_call_population("runtime.py::root", inventory)
    assert result["functions"] == ("runtime.py::root",)
    assert result["unresolved_calls"] == 2


@pytest.mark.parametrize("defect", ["functions", "files", "file_digest", "duplicate_file", "unbound_source_file"])
def test_operation_call_population_requires_bound_source_files(inventory, defect):
    if defect in {"functions", "files"}:
        inventory[defect] = None
    elif defect == "file_digest":
        inventory["files"][0]["sha256"] = "invalid"
    elif defect == "duplicate_file":
        inventory["files"].append(copy.deepcopy(inventory["files"][0]))
    else:
        inventory["files"][0]["path"] = "another.py"
    with pytest.raises(SemanticOperationEffectError):
        source_operation_call_population("runtime.py::root", inventory)


@pytest.fixture
def initialization_inventory(tmp_path):
    paths = [tmp_path / 'root.py', tmp_path / 'other.py']
    paths[0].write_text('initialize()\ndef root():\n    pass\n')
    paths[1].write_text('unrelated_initialization()\n')
    return discover_python_source(tmp_path, files=paths, call_contracts_version='1.0', initialization_contracts_version='1.0')


def test_opted_initialization_population_covers_every_discovered_module(initialization_inventory):
    original = copy.deepcopy(initialization_inventory)
    result = source_operation_call_population('root.py::root', initialization_inventory, include_initialization=True)
    assert result['scope'] == 'discovered_python_functions_and_possible_initialization'
    assert result['execution_qualified'] is False
    assert result['completeness_qualified'] is False
    assert [row[0] for row in result['module_initializers']] == ['other.py', 'root.py']
    assert initialization_inventory == original
    initialization_inventory['module_initializers'].reverse()
    assert source_operation_call_population('root.py::root', initialization_inventory, include_initialization=True) == result
    assert source_operation_call_population('root.py::root', initialization_inventory) == source_operation_call_population('root.py::root', initialization_inventory, include_initialization=False)


@pytest.mark.parametrize('defect', ['version', 'missing_module', 'duplicate_module', 'unbound_module', 'duplicate_site', 'missing_call_name', 'authority', 'completeness', 'limitations', 'site_digest'])
def test_initialization_population_rejects_incompatible_or_incomplete_facts(initialization_inventory, defect):
    rows = initialization_inventory['module_initializers']
    if defect == 'version':
        initialization_inventory['initialization_contracts_version'] = '2.0'
    elif defect == 'missing_module':
        rows.pop()
    elif defect == 'duplicate_module':
        rows.append(copy.deepcopy(rows[0]))
    elif defect == 'unbound_module':
        rows[0]['path'] = 'unknown.py'
    elif defect == 'duplicate_site':
        rows[0]['sites'].append(copy.deepcopy(rows[0]['sites'][0]))
    elif defect == 'missing_call_name':
        del rows[0]['sites'][0]['call_name']
    elif defect == 'authority':
        rows[0]['authority'] = True
    elif defect == 'completeness':
        rows[0]['completeness_qualified'] = True
    elif defect == 'limitations':
        rows[0]['limitations'] = []
    else:
        rows[0]['sites'][0]['expression_sha256'] = 'invalid'
    with pytest.raises(SemanticOperationEffectError, match='initialization'):
        source_operation_call_population('root.py::root', initialization_inventory, include_initialization=True)


def test_source_initialization_change_is_observed_without_removing_functions(tmp_path):
    path = tmp_path / 'root.py'
    def population(source):
        path.write_text(source)
        inventory = discover_python_source(tmp_path, files=[path], call_contracts_version='1.0', initialization_contracts_version='1.0')
        return source_operation_call_population('root.py::root', inventory, include_initialization=True)
    first = population('initialize(1)\ndef root():\n    pass\n')
    changed = population('initialize(2)\ndef root():\n    pass\n')
    assert first['functions'] == changed['functions']
    assert first['module_initializers'] != changed['module_initializers']


def test_invalid_initialization_rejects_before_function_closure_traversal(initialization_inventory):
    initialization_inventory['module_initializers'].clear()
    initialization_inventory['functions'][0]['calls'] = None
    with pytest.raises(SemanticOperationEffectError, match='initialization'):
        source_operation_call_population('root.py::root', initialization_inventory, include_initialization=True)

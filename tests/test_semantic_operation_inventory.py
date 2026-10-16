from __future__ import annotations

import copy

import pytest

from bcf_governance.tooling import semantic_operation_effects as effects


@pytest.fixture
def source_effects():
    def call(symbol):
        return {'called_symbol': symbol, 'call_name': symbol.split('::')[-1]}
    operation = dict(
        id='runtime.operation.v1', allowed_mutation_ports=['runtime.py::save'],
        allowed_authority_ports=['runtime.py::deliver'],
        non_authoritative_output_effects=['runtime.py::observe'],
    )
    inventory = {'functions': [
        {'symbol': 'runtime.py::entry', 'calls': [call('runtime.py::helper')]},
        {'symbol': 'runtime.py::helper', 'calls': [call('runtime.py::save'), call('runtime.py::deliver'), call('runtime.py::observe')]},
        {'symbol': 'runtime.py::save', 'calls': [call('path::write_text')]},
        {'symbol': 'runtime.py::deliver', 'calls': [call('provider::publish')]},
        {'symbol': 'runtime.py::observe', 'calls': []},
    ]}
    return operation, inventory


def _inventory(operation, inventory):
    return effects.validated_operation_effect_inventory(operation, 'runtime.py::entry', inventory)


def test_validated_inventory_preserves_port_classes_and_legacy_counts(source_effects):
    operation, inventory = source_effects
    before = copy.deepcopy(source_effects)
    observed = _inventory(operation, inventory)
    assert observed == (
        ('authority', 'function', 'runtime.py::deliver'),
        ('mutation', 'function', 'runtime.py::save'),
        ('observation', 'function', 'runtime.py::observe'),
    )
    assert effects.validate_operation_effects(operation, 'runtime.py::entry', inventory) == (1, 1)
    inventory['functions'].reverse()
    assert _inventory(operation, inventory) == observed
    assert before[0] == operation
    assert sorted(before[1]['functions'], key=lambda row: row['symbol']) == sorted(inventory['functions'], key=lambda row: row['symbol'])


@pytest.mark.parametrize('role,message', [('allowed_mutation_ports', 'undeclared write'), ('allowed_authority_ports', 'undeclared authority')])
def test_deleted_port_cannot_hide_source_effect(source_effects, role, message):
    operation, inventory = source_effects
    operation[role] = []
    with pytest.raises(effects.SemanticOperationEffectError, match=message):
        _inventory(operation, inventory)
    with pytest.raises(effects.SemanticOperationEffectError, match=message):
        effects.validate_operation_effects(operation, 'runtime.py::entry', inventory)


def test_effect_inventory_rejects_unreachable_declared_port(source_effects):
    operation, inventory = source_effects
    operation['allowed_authority_ports'].append('runtime.py::unreachable')
    with pytest.raises(effects.SemanticOperationEffectError, match='unreachable effect ports'):
        _inventory(operation, inventory)


def test_effect_inventory_rejects_unresolved_path_before_projection(source_effects):
    operation, inventory = source_effects
    inventory['functions'][1]['unresolved'] = [{'kind': 'dynamic_call'}]
    with pytest.raises(effects.SemanticOperationEffectError, match='unresolved dynamic call path'):
        _inventory(operation, inventory)


def test_effect_inventory_retains_exact_external_port_identity(source_effects):
    operation, inventory = source_effects
    operation['allowed_authority_ports'] = ['provider::publish']
    observed = _inventory(operation, inventory)
    assert ('authority', 'call', 'provider::publish') in observed
    assert effects.validate_operation_effects(operation, 'runtime.py::entry', inventory) == (1, 1)

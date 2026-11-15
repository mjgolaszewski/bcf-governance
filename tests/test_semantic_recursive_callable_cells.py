"""Recursive binding and immutable defaults grant identity, never body purity."""
from __future__ import annotations

import pytest

from bcf_governance.tooling.semantic_operation_effects import (
    SemanticOperationEffectError,
    validate_operation_effects,
)
from tests.test_consumer_callback_contracts import OPERATION, inventory, witness


def test_native_empty_tuple_default_keeps_real_body_traversal(tmp_path):
    path, facts = inventory(tmp_path, '''
        def read():
            def callback(stack=()):
                return len(stack)
            return callback()
    ''')
    assert witness(path) == [0, 0]
    definition = next(row for row in facts['functions'] if row['symbol'] == 'consumer.py::read')['source_callable_definitions'][0]
    assert definition['stable']
    assert validate_operation_effects(OPERATION, 'consumer.py::read', facts, experimental_protocols=False) == (0, 0)


@pytest.mark.parametrize('default', ['[]', '(foreign(),)', 'tuple()'])
def test_executable_or_mutable_defaults_are_not_new_native_facts(tmp_path, default):
    _, facts = inventory(tmp_path, 'def read():\n def callback(stack='+default+'):\n  return 7\n return callback()\n')
    with pytest.raises(SemanticOperationEffectError):
        validate_operation_effects(OPERATION, 'consumer.py::read', facts, experimental_protocols=False)


def test_empty_tuple_default_cannot_hide_a_global_write(tmp_path):
    path, facts = inventory(tmp_path, '''
        EVENTS=[]
        def read():
            def callback(stack=()):
                EVENTS.append(7)
                return len(EVENTS)
            return callback()
    ''')
    assert witness(path) == [1, 2]
    with pytest.raises(SemanticOperationEffectError):
        validate_operation_effects(OPERATION, 'consumer.py::read', facts, experimental_protocols=False)


def test_stable_recursive_cell_resolves_its_actual_body(tmp_path):
    path, facts = inventory(tmp_path, '''
        def read():
            def walk(depth):
                if depth == 0:
                    return 7
                return walk(depth-1)
            return walk(2)
    ''')
    assert witness(path) == [7, 7]
    assert validate_operation_effects(OPERATION, 'consumer.py::read', facts, experimental_protocols=False) == (0, 0)


def test_recursive_cell_still_rejects_real_effects(tmp_path):
    path, facts = inventory(tmp_path, '''
        EVENTS=[]
        def read():
            def walk(depth):
                EVENTS.append(7)
                if depth == 0:
                    return len(EVENTS)
                return walk(depth-1)
            return walk(2)
    ''')
    assert witness(path) == [3, 6]
    with pytest.raises(SemanticOperationEffectError):
        validate_operation_effects(OPERATION, 'consumer.py::read', facts, experimental_protocols=False)


def test_recursive_name_replacement_is_not_its_original_cell(tmp_path):
    _, facts = inventory(tmp_path, '''
        def read(replacement):
            def walk(depth): return walk(depth-1)
            walk=replacement
            return walk(2)
    ''')
    with pytest.raises(SemanticOperationEffectError):
        validate_operation_effects(OPERATION, 'consumer.py::read', facts, experimental_protocols=False)

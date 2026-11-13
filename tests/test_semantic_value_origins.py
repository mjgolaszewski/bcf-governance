"""Causal ownership controls: a helper parameter is not inherently retained."""
from __future__ import annotations

import pytest

from bcf_governance.tooling.semantic_operation_effects import (
    SemanticOperationEffectError,
    validate_operation_effects,
)
from tests.test_consumer_callback_contracts import OPERATION, inventory, witness


@pytest.mark.parametrize("body", [
    "rows=[]\n rows.append(7)\n return rows",
    "rows={}\n rows['value']=7\n return rows",
    "rows=[]\n alias=rows\n alias.append(7)\n return rows",
    "rows=[]\n fill(rows)\n return rows",
    "rows=[]\n fill(rows=rows)\n return rows",
    "rows=make()\n rows.append(7)\n return rows",
    "rows=[]\n if True:\n  rows=[]\n else:\n  rows=[]\n rows.append(7)\n return rows",
])
def test_owned_literal_and_source_callers_are_read_only(tmp_path, body):
    source = "def fill(rows):\n rows.append(7)\ndef make():\n return []\ndef read():\n " + body + "\n"
    path, facts = inventory(tmp_path, source)
    expected = [{"value": 7}, {"value": 7}] if "{}" in body else [[7], [7]]
    assert witness(path) == expected
    assert validate_operation_effects(OPERATION, "consumer.py::read", facts) == (0, 0)


@pytest.mark.parametrize("body", [
    "fill(STATE)",
    "rows=STATE\n fill(rows)",
    "rows=[STATE]\n rows[0].append(7)",
    "rows=[]\n retain(rows)\n rows.append(7)",
    "rows=[]\n fill(rows)\n fill(STATE)",
    "rows=[]\n if True:\n  rows=STATE\n else:\n  rows=[]\n rows.append(7)",
])
def test_borrowed_mixed_nested_and_escaped_values_stay_effectful(tmp_path, body):
    source = "STATE=[]\nKEPT=[]\ndef fill(rows):\n rows.append(7)\ndef retain(rows):\n KEPT.append(rows)\ndef read():\n " + body + "\n return STATE,KEPT\n"
    path, facts = inventory(tmp_path, source)
    observed = witness(path)
    assert observed != [[[], []], [[], []]]
    with pytest.raises(SemanticOperationEffectError):
        validate_operation_effects(OPERATION, "consumer.py::read", facts)


def test_fresh_path_does_not_hide_filesystem_write(tmp_path):
    _, facts = inventory(tmp_path, "from pathlib import Path\ndef read():\n path=Path('out')\n path.write_text('retained')\n")
    with pytest.raises(SemanticOperationEffectError):
        validate_operation_effects(OPERATION, "consumer.py::read", facts)


@pytest.mark.parametrize("body,expected", [
    ("rows=[]\n rows.append(STATE)\n return rows", [[1]]),
    ("rows=[STATE]\n rows.append(7)\n return rows", [[1], 7]),
    ("rows=[]\n for value in [1,2]:\n  rows.append(value)\n return rows", [1, 2]),
    ("rows=[]\n for value in [1,2]:\n  fill(rows,value)\n return rows", [1, 2]),
    ("rows=[]\n rows.extend([STATE])\n return rows", [[1]]),
])
def test_owned_structure_does_not_require_ownership_of_borrowed_children(tmp_path, body, expected):
    path, facts = inventory(tmp_path, "STATE=[1]\ndef fill(rows,value):\n rows.append(value)\ndef read():\n " + body + "\n")
    assert witness(path) == [expected, expected]
    assert validate_operation_effects(OPERATION, "consumer.py::read", facts) == (0, 0)


@pytest.mark.parametrize("body", [
    "rows=[]\n for value in [1,2]:\n  rows.append(7)\n  rows=STATE",
    "rows=[]\n for value in [1,2]:\n  fill(rows,7)\n  rows=STATE",
    "rows=[STATE]\n for value in rows:\n  value.append(7)",
])
def test_loop_fixed_point_cannot_publish_first_iteration_ownership(tmp_path, body):
    path, facts = inventory(tmp_path, "STATE=[]\ndef fill(rows,value):\n rows.append(value)\ndef read():\n " + body + "\n return STATE\n")
    assert witness(path) != [[], []]
    with pytest.raises(SemanticOperationEffectError):
        validate_operation_effects(OPERATION, "consumer.py::read", facts)


def test_unknown_child_finalizer_is_not_hidden_by_owned_container_clear(tmp_path):
    path, facts = inventory(tmp_path, """
        EVENTS=[]
        class Record:
            def __del__(self):
                EVENTS.append(7)
        def append_value(rows,value):
            rows.append(value)
        def read():
            rows=[]
            append_value(rows,Record())
            rows.clear()
            return len(EVENTS)
    """)
    assert witness(path) == [1, 2]
    with pytest.raises(SemanticOperationEffectError):
        validate_operation_effects(OPERATION, "consumer.py::read", facts)


def test_declared_effect_port_does_not_keep_escaped_container_locally_owned(tmp_path):
    path, facts = inventory(tmp_path, """
        KEPT=[]
        def retain(value):
            KEPT.append(value)
        def read():
            rows=[]
            box={'child':rows}
            retain(box['child'])
            rows.append(7)
            return KEPT[0]
    """)
    assert witness(path) == [[7], [7]]
    operation = {**OPERATION, "allowed_mutation_ports": ["consumer.py::retain"]}
    with pytest.raises(SemanticOperationEffectError, match="undeclared write"):
        validate_operation_effects(operation, "consumer.py::read", facts)


def test_exact_builtin_container_predicate_preserves_local_ownership(tmp_path):
    path, facts = inventory(tmp_path, """
        def read():
            rows=list()
            if bool(rows):
                rows.append(1)
            else:
                rows.append(7)
            return rows
    """)
    assert witness(path) == [[7], [7]]
    assert validate_operation_effects(OPERATION, "consumer.py::read", facts) == (0, 0)


def test_shadowed_builtin_name_cannot_hide_input_callback_or_retention(tmp_path):
    path, facts = inventory(tmp_path, """
        EVENTS=[]
        def bool(rows):
            EVENTS.append(rows)
            return False
        def read():
            rows=[]
            if bool(rows):
                rows.append(1)
            else:
                rows.append(7)
            return EVENTS[0]
    """)
    assert witness(path) == [[7], [7]]
    operation = {**OPERATION, "allowed_mutation_ports": ["consumer.py::bool"]}
    with pytest.raises(SemanticOperationEffectError, match="undeclared write"):
        validate_operation_effects(operation, "consumer.py::read", facts)


def test_builtin_module_mutation_cannot_supply_a_fresh_allocation_contract(tmp_path):
    path, facts = inventory(tmp_path, """
        import builtins
        STATE=[]
        ORIGINAL=builtins.list
        def replacement():
            return STATE
        def change():
            builtins.list=replacement
        def restore():
            builtins.list=ORIGINAL
        def read():
            change()
            rows=list()
            rows.append(7)
            restore()
            return STATE
    """)
    assert witness(path) == [[7, 7], [7, 7]]
    operation = {**OPERATION, "allowed_mutation_ports": ["consumer.py::change", "consumer.py::restore"]}
    with pytest.raises(SemanticOperationEffectError, match="undeclared write"):
        validate_operation_effects(operation, "consumer.py::read", facts)

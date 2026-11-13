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

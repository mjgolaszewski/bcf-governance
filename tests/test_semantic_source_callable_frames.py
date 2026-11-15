"""Source callback bindings must traverse bodies and retain unknown captures."""
import pytest

from bcf_governance.tooling.semantic_operation_effects import (
    SemanticOperationEffectError,
    validate_operation_effects,
)
from tests.test_consumer_callback_contracts import OPERATION, inventory, witness


@pytest.mark.parametrize("declaration,argument",[("def callback(): return 7","callback"),("","lambda: 7")])
def test_closed_source_callback_reaches_real_helper(tmp_path,declaration,argument):
    source="def invoke(callback=None):\n if callback is None:\n  return 0\n return callback()\ndef read():\n " + (declaration+"\n " if declaration else "") + "return invoke("+argument+")\n"
    path,facts=inventory(tmp_path,source)
    assert witness(path)==[7,7]
    assert validate_operation_effects(OPERATION,"consumer.py::read",facts,experimental_protocols=False)==(0,0)


def test_default_none_callback_branch_is_not_executed(tmp_path):
    _,facts=inventory(tmp_path,"def invoke(callback=None):\n if callback is not None:\n  callback()\n return 7\ndef read():\n return invoke()\n")
    assert validate_operation_effects(OPERATION,"consumer.py::read",facts,experimental_protocols=False)==(0,0)


def test_bound_source_callback_mutation_is_not_hidden(tmp_path):
    source="EVENTS=[]\ndef invoke(callback=None):\n if callback is not None:\n  callback()\ndef read():\n def callback():\n  EVENTS.append(7)\n invoke(callback)\n return len(EVENTS)\n"
    path,facts=inventory(tmp_path,source)
    assert witness(path)==[1,2]
    with pytest.raises(SemanticOperationEffectError):
        validate_operation_effects(OPERATION,"consumer.py::read",facts,experimental_protocols=False)


def test_unknown_callback_capture_stays_unqualified(tmp_path):
    _,facts=inventory(tmp_path,"def invoke(callback):\n return callback()\ndef read(store):\n def callback():\n  store.commit()\n return invoke(callback)\n")
    with pytest.raises(SemanticOperationEffectError):
        validate_operation_effects(OPERATION,"consumer.py::read",facts,experimental_protocols=False)


@pytest.mark.parametrize("body",["return unknown()","return value['key']"])
def test_deferred_source_body_does_not_hide_unknown_protocol(tmp_path,body):
    _,facts=inventory(tmp_path,"def invoke(callback):\n return callback()\ndef read(value):\n def callback():\n  "+body+"\n return invoke(callback)\n")
    with pytest.raises(SemanticOperationEffectError):
        validate_operation_effects(OPERATION,"consumer.py::read",facts,experimental_protocols=False)


def test_local_function_replaces_default_none_cell(tmp_path):
    source="EVENTS=[]\ndef invoke(callback):\n if callback is not None:\n  callback()\ndef read(callback=None):\n def callback():\n  EVENTS.append(7)\n invoke(callback)\n return len(EVENTS)\n"
    path,facts=inventory(tmp_path,source)
    assert witness(path)==[1,2]
    with pytest.raises(SemanticOperationEffectError):
        validate_operation_effects(OPERATION,"consumer.py::read",facts,experimental_protocols=False)



def test_escaped_source_callback_cannot_recover_closed_binding(tmp_path):
    _,facts=inventory(tmp_path,"KEPT=[]\ndef retain(value):\n KEPT.append(value)\ndef invoke(callback):\n return callback()\ndef read():\n def callback(): return 7\n retain(callback)\n return invoke(callback)\n")
    operation={**OPERATION,"allowed_mutation_ports":["consumer.py::retain"]}
    with pytest.raises(SemanticOperationEffectError):
        validate_operation_effects(operation,"consumer.py::read",facts,experimental_protocols=False)


def test_rebound_source_callback_stays_unqualified(tmp_path):
    _,facts=inventory(tmp_path,"def invoke(callback):\n return callback()\ndef read(value):\n def callback(): return 7\n callback=value\n return invoke(callback)\n")
    with pytest.raises(SemanticOperationEffectError):
        validate_operation_effects(OPERATION,"consumer.py::read",facts,experimental_protocols=False)


def test_nonasync_source_callback_does_not_purify_custom_awaitable(tmp_path):
    _,facts=inventory(tmp_path,"import asyncio\nEVENTS=[]\nclass Probe:\n def __await__(self):\n  EVENTS.append(7)\n  yield\nPROBE=Probe()\nasync def invoke(callback):\n return await callback()\ndef read():\n def callback(): return PROBE\n return asyncio.run(invoke(callback))\n")
    with pytest.raises(SemanticOperationEffectError):
        validate_operation_effects(OPERATION,"consumer.py::read",facts,experimental_protocols=False)

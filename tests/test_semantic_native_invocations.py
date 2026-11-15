"""Invocation proof never grants protocols on returned classes or exceptions."""
import json
import subprocess
import sys

import pytest

from bcf_governance.tooling.semantic_operation_effects import (
    SemanticOperationEffectError,
    validate_operation_effects,
)
from tests.test_consumer_callback_contracts import OPERATION, inventory

HOSTILE = """
EVENTS=[]
class Probe:
 @property
 def __class__(self):
  EVENTS.append('class')
  return Probe
 def __str__(self):
  EVENTS.append('str')
  return 'hostile'
 def __format__(self, spec):
  EVENTS.append('format')
  return 'hostile'
 def __index__(self):
  EVENTS.append('index')
  return 0
"""


def observe(path):
    script = "import runpy,json;n=runpy.run_path(" + repr(str(path)) + ");v=n['Probe']();n['read'](v);a=list(n['EVENTS']);n['read'](v);print(json.dumps([a,n['EVENTS']]))"
    result = subprocess.run([sys.executable, "-I", "-B", "-c", script], check=True, capture_output=True, text=True, timeout=10)
    return json.loads(result.stdout)


@pytest.mark.parametrize("expression", ["type(value)", "BaseException(value)", "Exception(value)", "ValueError(value)", "RuntimeError(value)"])
def test_exact_native_invocation_does_not_invoke_borrowed_protocols(tmp_path, expression):
    path, facts = inventory(tmp_path, HOSTILE + "\ndef invoke(callback): return callback()\ndef read(value):\n def callback():\n  " + expression + "\n return invoke(callback)\n")
    assert observe(path) == [[], []]
    assert validate_operation_effects(OPERATION, "consumer.py::read", facts, experimental_protocols=False) == (0, 0)


@pytest.mark.parametrize("expression", ["str(ValueError(value))", "f'{ValueError(value)}'", "type(value).__name__", "isinstance(value, int)", "type(*value)", "ValueError(*value)", "ValueError(**value)", "type('New', (), {})"])
def test_native_invocation_does_not_grant_unknown_follow_on_protocols(tmp_path, expression):
    _, facts = inventory(tmp_path, "def invoke(callback): return callback()\ndef read(value):\n def callback():\n  return " + expression + "\n return invoke(callback)\n")
    with pytest.raises(SemanticOperationEffectError):
        validate_operation_effects(OPERATION, "consumer.py::read", facts, experimental_protocols=False)


@pytest.mark.parametrize("name", ["type", "ValueError"])
def test_shadowed_native_name_keeps_real_source_effects(tmp_path, name):
    source = "EVENTS=[]\ndef " + name + "(value):\n EVENTS.append(7)\ndef invoke(callback): return callback()\ndef read(value):\n def callback():\n  " + name + "(value)\n return invoke(callback)\n"
    _, facts = inventory(tmp_path, source)
    with pytest.raises(SemanticOperationEffectError):
        validate_operation_effects(OPERATION, "consumer.py::read", facts, experimental_protocols=False)


@pytest.mark.parametrize("name", ["type", "ValueError"])
def test_rebound_native_parameter_is_not_a_builtin_proof(tmp_path, name):
    _, facts = inventory(tmp_path, "def invoke(callback): return callback()\ndef read(value, " + name + "):\n def callback():\n  return " + name + "(value)\n return invoke(callback)\n")
    with pytest.raises(SemanticOperationEffectError):
        validate_operation_effects(OPERATION, "consumer.py::read", facts, experimental_protocols=False)


@pytest.mark.parametrize("expression,event", [("str(ValueError(value))", "str"), ("f'{value}'", "format"), ("int(value)", "index"), ("isinstance(value, int)", "class")])
def test_hostile_protocol_witnesses_remain_rejected(tmp_path, expression, event):
    path, facts = inventory(tmp_path, HOSTILE + "\ndef invoke(callback): return callback()\ndef read(value):\n def callback():\n  return " + expression + "\n return invoke(callback)\n")
    assert observe(path) == [[event], [event, event]]
    with pytest.raises(SemanticOperationEffectError):
        validate_operation_effects(OPERATION, "consumer.py::read", facts, experimental_protocols=False)


def test_type_result_metaclass_getter_remains_effectful(tmp_path):
    path, facts = inventory(tmp_path, "EVENTS=[]\nclass Meta(type):\n def __getattribute__(cls, name):\n  if name == '__name__': EVENTS.append('getter')\n  return super().__getattribute__(name)\nclass Probe(metaclass=Meta): pass\ndef invoke(callback): return callback()\ndef read(value):\n def callback(): return type(value).__name__\n return invoke(callback)\n")
    assert observe(path) == [["getter"], ["getter", "getter"]]
    with pytest.raises(SemanticOperationEffectError):
        validate_operation_effects(OPERATION, "consumer.py::read", facts, experimental_protocols=False)


def test_native_invocations_survive_unknown_regex_control_without_purifying_it(tmp_path):
    _, facts = inventory(tmp_path, "import re\ndef require_export_id(value):\n if type(value) is not str or re.fullmatch(r'export-[a-f0-9]{32}', value) is None:\n  raise ValueError('export_index_facts')\ndef invoke(callback): return callback()\ndef read(value):\n def callback(): return require_export_id(value)\n return invoke(callback)\n")
    with pytest.raises(SemanticOperationEffectError) as error:
        validate_operation_effects(OPERATION, "consumer.py::read", facts, experimental_protocols=False)
    message = str(error.value)
    assert "unqualified source callable protocol" in message
    assert "unqualified source callable target: re::module.fullmatch" in message
    assert "unqualified source callable target: consumer.py::type" not in message
    assert "unqualified source callable target: consumer.py::ValueError" not in message

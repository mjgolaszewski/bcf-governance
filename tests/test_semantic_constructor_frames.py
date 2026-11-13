"""Actual constructor writes require allocation and caller-context evidence."""
from __future__ import annotations

import pytest

from bcf_governance.tooling.semantic_operation_effects import (
    SemanticOperationEffectError,
    validate_operation_effects,
)
from tests.test_consumer_callback_contracts import OPERATION, inventory, witness


@pytest.mark.parametrize("source", [
    "class Record:\n def __init__(self,value):\n  self.value=value\ndef read():\n return Record(7).value\n",
    "class Parent:\n def __init__(self,value):\n  self.value=value\nclass Record(Parent):pass\ndef read():\n return Record(7).value\n",
    "class Record(ValueError):pass\ndef read():\n Record('ok')\n return 7\n",
    "class Record(ValueError):\n def __init__(self,message):\n  super().__init__(message)\n  self.value=7\ndef read():\n return Record('ok').value\n",
])
def test_literal_source_initializer_owns_only_its_new_receiver(tmp_path, source):
    path, facts = inventory(tmp_path, source)
    assert witness(path) == [7, 7]
    assert validate_operation_effects(OPERATION, "consumer.py::read", facts) == (0, 0)


def test_initializer_global_effect_is_not_hidden_by_fresh_receiver(tmp_path):
    path, facts = inventory(tmp_path, """
        EVENTS=[]
        class Record:
            def __init__(self):
                EVENTS.append(7)
                self.value=7
        def read():
            Record()
            return len(EVENTS)
    """)
    assert witness(path) == [1, 2]
    with pytest.raises(SemanticOperationEffectError):
        validate_operation_effects(OPERATION, "consumer.py::read", facts)


def test_initializer_escape_port_does_not_authorize_later_retained_write(tmp_path):
    path, facts = inventory(tmp_path, """
        KEPT=[]
        def retain(value):
            KEPT.append(value)
        class Record:
            def __init__(self):
                retain(self)
                self.value=7
        def read():
            Record()
            return KEPT[-1].value
    """)
    assert witness(path) == [7, 7]
    operation = {**OPERATION, "allowed_mutation_ports": ["consumer.py::retain"]}
    with pytest.raises(SemanticOperationEffectError):
        validate_operation_effects(operation, "consumer.py::read", facts)


def test_explicit_initializer_on_borrowed_receiver_remains_a_write(tmp_path):
    path, facts = inventory(tmp_path, """
        class Record:
            def __init__(self,value):
                self.value=value
        STATE=Record(0)
        def read():
            before=STATE.value
            Record.__init__(STATE,7)
            return before,STATE.value
    """)
    assert witness(path) == [[0, 7], [7, 7]]
    with pytest.raises(SemanticOperationEffectError):
        validate_operation_effects(OPERATION, "consumer.py::read", facts)


@pytest.mark.parametrize("declaration", [
    "class Parent:\n def __new__(cls):\n  EVENTS.append(7)\n  return object.__new__(cls)\nclass Record(Parent):pass\n",
    "class Meta(type):\n def __call__(cls,*args,**kwargs):\n  EVENTS.append(7)\n  return super().__call__(*args,**kwargs)\nclass Parent(metaclass=Meta):pass\nclass Record(Parent):pass\n",
])
def test_inherited_allocator_or_metaclass_does_not_get_a_fresh_frame(tmp_path, declaration):
    path, facts = inventory(tmp_path, "EVENTS=[]\n" + declaration + "def read():\n Record()\n return len(EVENTS)\n")
    assert witness(path) == [1, 2]
    with pytest.raises(SemanticOperationEffectError):
        validate_operation_effects(OPERATION, "consumer.py::read", facts)


@pytest.mark.parametrize("declaration,expression", [
    ("def __iter__(self):\n  EVENTS.append(7)\n  return iter([7])", "[value for value in PROBE]"),
    ("def __hash__(self):\n  EVENTS.append(7)\n  return 7", "{PROBE:7}"),
])
def test_fresh_receiver_does_not_close_unknown_input_protocols(tmp_path, declaration, expression):
    source = "EVENTS=[]\nclass Probe:\n " + declaration + "\nPROBE=Probe()\nclass Record:\n def __init__(self):\n  ignored=" + expression + "\ndef read():\n Record()\n return len(EVENTS)\n"
    path, facts = inventory(tmp_path, source)
    assert witness(path) == [1, 2]
    with pytest.raises(SemanticOperationEffectError):
        validate_operation_effects(OPERATION, "consumer.py::read", facts)


@pytest.mark.parametrize("signature", ["def __del__(self, extra): pass", "async def __del__(self): pass"])
def test_invalid_noop_finalizer_is_not_pure(tmp_path, signature):
    path, facts = inventory(tmp_path, "class Record:\n " + signature + "\ndef read():\n Record()\n return 0\n")
    assert witness(path) == [0, 0]
    with pytest.raises(SemanticOperationEffectError):
        validate_operation_effects(OPERATION, "consumer.py::read", facts)


def test_class_alias_cannot_replace_fresh_allocation(tmp_path):
    path, facts = inventory(tmp_path, """
        class Record:
            def __init__(self,value): self.value=value
        EXISTING=object.__new__(Record)
        EXISTING.value=0
        Alias=Record
        Alias.__new__=staticmethod(lambda cls,*args:EXISTING)
        def read():
            before=EXISTING.value
            Record(7)
            return before,EXISTING.value
    """)
    assert witness(path) == [[0, 7], [7, 7]]
    with pytest.raises(SemanticOperationEffectError):
        validate_operation_effects(OPERATION, "consumer.py::read", facts)


def test_native_initializer_precedes_later_source_mixin(tmp_path):
    path, facts = inventory(tmp_path, """
        EVENTS=[]
        class Mixin:
            def __init__(self): EVENTS.append(7)
        class Record(ValueError, Mixin): pass
        def read():
            Record()
            return len(EVENTS)
    """)
    assert witness(path) == [0, 0]
    assert validate_operation_effects(OPERATION, "consumer.py::read", facts) == (0, 0)


@pytest.mark.parametrize("argument", ["source()", "value"])
def test_source_produced_scalar_reaches_initializer_frame(tmp_path, argument):
    path, facts = inventory(tmp_path, """
        def source(): return 'ok'
        class Record:
            def __init__(self,value):
                if not value: raise ValueError('empty')
                self.value=value
        def read():
            value=source()
            return Record(ARGUMENT).value
    """.replace('ARGUMENT', argument))
    assert witness(path) == ['ok', 'ok']
    assert validate_operation_effects(OPERATION, "consumer.py::read", facts) == (0, 0)


def test_unknown_producer_truth_callback_is_not_a_scalar_annotation(tmp_path):
    path, facts = inventory(tmp_path, """
        EVENTS=[]
        class Probe:
            def __bool__(self):
                EVENTS.append(7)
                return True
        PROBE=Probe()
        def source() -> str: return PROBE
        class Record:
            def __init__(self,value):
                if not value: raise ValueError('empty')
                self.value=value
        def read():
            Record(source())
            return len(EVENTS)
    """)
    assert witness(path) == [1, 2]
    with pytest.raises(SemanticOperationEffectError):
        validate_operation_effects(OPERATION, "consumer.py::read", facts)


@pytest.mark.parametrize('escaped', [False, True])
def test_constructor_argument_ownership_cannot_survive_a_later_escape_argument(tmp_path, escaped):
    path, facts = inventory(tmp_path, """
        KEPT=[]
        def retain(value):
            KEPT.append(value)
            return 0
        class Record:
            def __init__(self,box,unused): box.append(7)
        def read():
            box=[]
            Record(box,SECOND)
            return len(box)
    """.replace('SECOND', 'retain(box)' if escaped else '0'))
    assert witness(path) == [1, 1]
    operation = {**OPERATION, 'allowed_mutation_ports': ['consumer.py::retain'] if escaped else []}
    if escaped:
        with pytest.raises(SemanticOperationEffectError):
            validate_operation_effects(operation, 'consumer.py::read', facts)
    else:
        assert validate_operation_effects(operation, 'consumer.py::read', facts) == (0, 0)

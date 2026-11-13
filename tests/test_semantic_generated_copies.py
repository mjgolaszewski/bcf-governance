"""Generated copies allocate material values without purifying their callbacks."""
from __future__ import annotations

import pytest

from bcf_governance.tooling.semantic_operation_effects import (
    SemanticOperationEffectError,
    validate_operation_effects,
)
from bcf_governance.tooling.semantic_ownership_registry import Registry, RegistryEntry
from bcf_governance.tooling.semantic_ownership_scan import evaluate_discovery
from tests.test_consumer_callback_contracts import OPERATION, inventory, witness


def registry():
    entry=RegistryEntry('record.v1','records','enforced','consumer.py::Record','consumer.py::owner',
        frozenset({'consumer.py::owner'}),frozenset(),True,{})
    return Registry('P04','declared_families_blocking','fail_closed',('consumer.py',),(),(entry,),{})


BASE='''
    from dataclasses import dataclass, replace
    @dataclass
    class Record:
        value: str
    def owner(value: str) -> Record: return Record(value)
    def reader(record: Record) -> str: return record.value
'''


@pytest.mark.parametrize('change',["record.value","'changed'"])
def test_generated_copy_competitor_is_discovered_with_actual_reader(tmp_path,change):
    path,facts=inventory(tmp_path,BASE+'''
    def alternate(record: Record) -> Record:
        return replace(record,value=CHANGE)
    def read(): return reader(alternate(owner('actual')))
    '''.replace('CHANGE',change))
    assert witness(path)==(['actual']*2 if change=='record.value' else ['changed']*2)
    result=evaluate_discovery(facts,registry())
    assert any(item['kind']=='unauthorized_constructor' and item['symbol']=='consumer.py::alternate'
               for item in result['violations'])


def test_native_generated_copy_frame_preserves_actual_changed_value(tmp_path):
    path,facts=inventory(tmp_path,BASE+'''
    def read():
        original=owner('actual')
        copied=replace(original,value='changed')
        return reader(copied)
    ''')
    assert witness(path)==['changed']*2
    assert validate_operation_effects(OPERATION,'consumer.py::read',facts)==(0,0)


def test_annotation_only_copy_input_does_not_grant_a_runtime_frame(tmp_path):
    _,facts=inventory(tmp_path,BASE+'''
    def read(record: Record): return replace(record,value='changed')
    ''')
    with pytest.raises(SemanticOperationEffectError,match='unqualified_generated_copy_binding'):
        validate_operation_effects(OPERATION,'consumer.py::read',facts)


def test_self_assignment_copy_keeps_its_neutral_allocation_candidate(tmp_path):
    _,facts=inventory(tmp_path,BASE+'''
    def alternate(record: Record) -> Record:
        record=replace(record,value='changed')
        return record
    ''')
    result=evaluate_discovery(facts,registry())
    assert any(item['kind']=='unauthorized_constructor' and item['symbol']=='consumer.py::alternate'
               for item in result['violations'])


@pytest.mark.parametrize('declaration',[
    "@dataclass\nclass Record:\n value: str\n def __post_init__(self): EVENTS.append(7)",
    "@dataclass\nclass Record:\n value: str\n cached: str=field(init=False,default_factory=factory)",
    "@dataclass(init=False)\nclass Record:\n value: str\n def __init__(self,value): self.value=value; EVENTS.append(7)",
])
def test_generated_copy_does_not_skip_init_factory_or_post_init(tmp_path,declaration):
    _,facts=inventory(tmp_path,"from dataclasses import dataclass,field,replace\nEVENTS=[]\ndef factory():\n EVENTS.append(7)\n return 'cached'\n"+declaration+"\ndef read():\n record=Record('actual')\n return replace(record,value='changed')\n")
    with pytest.raises(SemanticOperationEffectError):
        validate_operation_effects(OPERATION,'consumer.py::read',facts)


def test_keyword_callback_invalidates_the_copy_receiver_class_frame(tmp_path):
    _,facts=inventory(tmp_path,BASE+'''
    @dataclass
    class Other:
        value: str
    def mutate(record):
        record.__class__=Other
        return 'changed'
    def read():
        original=owner('actual')
        return replace(original,value=mutate(original))
    ''')
    operation={**OPERATION,'allowed_mutation_ports':['consumer.py::mutate']}
    with pytest.raises(SemanticOperationEffectError,match='unqualified_generated_copy_binding'):
        validate_operation_effects(operation,'consumer.py::read',facts)


def test_mutated_library_binding_is_not_a_qualified_copy_primitive(tmp_path):
    _,facts=inventory(tmp_path,BASE+'''
    import dataclasses
    def different(record,**changes): return record
    dataclasses.replace=different
    def read():
        original=owner('actual')
        return dataclasses.replace(original,value='changed')
    ''')
    with pytest.raises(SemanticOperationEffectError,match='unqualified_generated_copy_binding'):
        validate_operation_effects(OPERATION,'consumer.py::read',facts)

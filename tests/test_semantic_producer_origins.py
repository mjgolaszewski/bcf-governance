"""Producer value facts remain separate from execution effects."""
from __future__ import annotations

import pytest

from bcf_governance.tooling.semantic_operation_effects import (
    SemanticOperationEffectError,
    validate_operation_effects,
)
from tests.test_consumer_callback_contracts import OPERATION, inventory, witness


def test_normal_effect_validation_reports_independent_callback_frontiers(tmp_path):
    _,facts=inventory(tmp_path,"""
        def first(value): return f'first {value}'
        def second(value): return f'second {value}'
        def read(value):
            first(value)
            return second(value)
    """)
    with pytest.raises(SemanticOperationEffectError) as error:
        validate_operation_effects(OPERATION,'consumer.py::read',facts)
    assert 'consumer.py::first' in str(error.value)
    assert 'consumer.py::second' in str(error.value)


def test_normal_effect_diagnostics_preserve_authority_and_callback_rejections(tmp_path):
    _,facts=inventory(tmp_path,"""
        def first(value): return f'first {value}'
        def read(value):
            first(value)
            publish_receipt()
            return 7
    """)
    with pytest.raises(SemanticOperationEffectError) as error:
        validate_operation_effects(OPERATION,'consumer.py::read',facts)
    assert 'unqualified_format_callback' in str(error.value)
    assert 'undeclared authority effects' in str(error.value)


def test_generated_record_field_uses_actual_producer_values(tmp_path):
    path,facts=inventory(tmp_path,"""
        from dataclasses import dataclass
        @dataclass(frozen=True)
        class Record:
            value: str
        def produce():
            try:
                return Record('actual')
            except ValueError:
                raise
        def read():
            record=produce()
            return f'value {record.value}'
    """)
    assert witness(path)==['value actual']*2
    assert validate_operation_effects(OPERATION,'consumer.py::read',facts)==(0,0)


@pytest.mark.parametrize('construction', [
    'Record(PROBE)',
    'Record(value=PROBE)',
])
def test_generated_record_annotation_does_not_purify_borrowed_field(tmp_path,construction):
    path,facts=inventory(tmp_path,"""
        from dataclasses import dataclass
        EVENTS=[]
        class Probe:
            def __format__(self,spec):
                EVENTS.append(7)
                return 'message'
        PROBE=Probe()
        @dataclass
        class Record:
            value: str
        def read():
            record=CONSTRUCTION
            return f'value {record.value}', len(EVENTS)
    """.replace('CONSTRUCTION',construction))
    assert witness(path)==[['value message',1],['value message',2]]
    with pytest.raises(SemanticOperationEffectError):
        validate_operation_effects(OPERATION,'consumer.py::read',facts)


@pytest.mark.parametrize('mutation', [
    'alias=record\n            alias.value=PROBE',
    'replace(record)',
])
def test_generated_record_field_proof_expires_after_alias_mutation(tmp_path,mutation):
    path,facts=inventory(tmp_path,"""
        from dataclasses import dataclass
        EVENTS=[]
        class Probe:
            def __format__(self,spec):
                EVENTS.append(7)
                return 'message'
        PROBE=Probe()
        @dataclass
        class Record:
            value: str
        def replace(record):
            record.value=PROBE
        def read():
            record=Record('actual')
            MUTATION
            return f'value {record.value}', len(EVENTS)
    """.replace('MUTATION',mutation))
    assert witness(path)==[['value message',1],['value message',2]]
    with pytest.raises(SemanticOperationEffectError):
        validate_operation_effects(OPERATION,'consumer.py::read',facts)


@pytest.mark.parametrize('annotation,import_line',[
    ('ClassVar[str]','from typing import ClassVar'),
    ('Alias[str]','from typing import ClassVar as Alias'),
    ('InitVar[str]','from dataclasses import InitVar'),
])
def test_special_dataclass_fields_do_not_create_false_positional_storage_facts(tmp_path,annotation,import_line):
    _,facts=inventory(tmp_path,"""
        from dataclasses import dataclass
        IMPORT
        @dataclass
        class Record:
            first: ANNOTATION='default'
            value: str='actual'
        def read():
            record=Record('actual')
            return f'value {record.value}'
    """.replace('IMPORT',import_line).replace('ANNOTATION',annotation))
    # This bounded producer contract must decline an uncertain generated
    # signature, rather than invent positional field/value correspondence.
    calls=[call for row in facts['functions'] for call in row.get('calls',[])
           if str(call.get('called_symbol','')).endswith('::Record')]
    assert calls and all('source_record_fields' not in call for call in calls)


def test_native_record_result_does_not_purify_producer_effects(tmp_path):
    path,facts=inventory(tmp_path,"""
        from dataclasses import dataclass
        EVENTS=[]
        @dataclass
        class Record:
            value: str
        def produce():
            EVENTS.append(7)
            return Record('actual')
        def read():
            result=f'value {produce().value}'
            return len(EVENTS)
    """)
    assert witness(path)==[1,2]
    with pytest.raises(SemanticOperationEffectError,match='undeclared write effects'):
        validate_operation_effects(OPERATION,'consumer.py::read',facts)


def test_finally_mutation_cannot_preserve_pending_record_return_facts(tmp_path):
    path,facts=inventory(tmp_path,"""
        from dataclasses import dataclass
        EVENTS=[]
        class Probe:
            def __format__(self,spec):
                EVENTS.append(7)
                return 'message'
        PROBE=Probe()
        @dataclass
        class Record:
            value: str
        def produce():
            record=Record('actual')
            try: return record
            finally: record.value=PROBE
        def read():
            result=f'value {produce().value}'
            return len(EVENTS)
    """)
    assert witness(path)==[1,2]
    with pytest.raises(SemanticOperationEffectError):
        validate_operation_effects(OPERATION,'consumer.py::read',facts)


def test_property_named_as_a_record_field_is_not_native_storage(tmp_path):
    path,facts=inventory(tmp_path,"""
        from dataclasses import dataclass
        EVENTS=[]
        @dataclass
        class Record:
            value: str='actual'
            @property
            def value(self):
                EVENTS.append(7)
                return 'actual'
            @value.setter
            def value(self,value): pass
        def read():
            result=f'value {Record().value}'
            return len(EVENTS)
    """)
    assert witness(path)==[1,2]
    with pytest.raises(SemanticOperationEffectError):
        validate_operation_effects(OPERATION,'consumer.py::read',facts)


def test_conditional_annotation_alias_cannot_change_record_signature_unnoticed(tmp_path):
    _,facts=inventory(tmp_path,"""
        from dataclasses import dataclass
        from typing import ClassVar
        if True: Alias=ClassVar
        @dataclass
        class Record:
            first: Alias[str]='default'
            value: str='actual'
        def read():
            record=Record('actual')
            return f'value {record.value}'
    """)
    calls=[call for row in facts['functions'] for call in row.get('calls',[])
           if str(call.get('called_symbol','')).endswith('::Record')]
    assert calls and all('source_record_fields' not in call for call in calls)


def test_conditional_field_declaration_does_not_invent_generated_signature(tmp_path):
    _,facts=inventory(tmp_path,"""
        from dataclasses import dataclass
        @dataclass
        class Record:
            if True:
                extra: str
            value: str
        def read():
            record=Record('first','actual')
            return f'value {record.value}'
    """)
    calls=[call for row in facts['functions'] for call in row.get('calls',[])
           if str(call.get('called_symbol','')).endswith('::Record')]
    assert calls and all('source_record_fields' not in call for call in calls)


def test_ordinary_diagnostic_output_is_bounded_and_still_rejects(tmp_path):
    source='\n'.join(f"def helper_{index}(value): return f'value {{value}}'" for index in range(40))
    source+='\ndef read(value):\n'+''.join(f'    helper_{index}(value)\n' for index in range(40))+'    return 7\n'
    _,facts=inventory(tmp_path,source)
    with pytest.raises(SemanticOperationEffectError) as error:
        validate_operation_effects(OPERATION,'consumer.py::read',facts)
    assert '8 additional failure observations omitted' in str(error.value)
    assert str(error.value).count('unqualified_format_callback')==32




def test_unrelated_borrowed_getter_argument_is_not_purified_by_a_native_record_field(tmp_path):
    path,facts=inventory(tmp_path,"""
        from dataclasses import dataclass
        EVENTS=[]
        class Probe:
            @property
            def value(self):
                EVENTS.append(7)
                return 'borrowed'
        PROBE=Probe()
        @dataclass
        class Record:
            value: str
            other: str
        def read():
            record=Record('actual',PROBE.value)
            result=f'value {record.value}'
            return len(EVENTS)
    """)
    assert witness(path)==[1,2]
    with pytest.raises(SemanticOperationEffectError):
        validate_operation_effects(OPERATION,'consumer.py::read',facts)


def test_source_helper_literal_result_does_not_erase_unknown_getter_evaluation(tmp_path):
    path,facts=inventory(tmp_path,"""
        from dataclasses import dataclass
        EVENTS=[]
        class Probe:
            @property
            def value(self):
                EVENTS.append(7)
                return 'borrowed'
        PROBE=Probe()
        @dataclass
        class Record:
            value: str
        def input_value():
            borrowed=PROBE.value
            return 'actual'
        def read():
            record=Record(input_value())
            result=f'value {record.value}'
            return len(EVENTS)
    """)
    assert witness(path)==[1,2]
    with pytest.raises(SemanticOperationEffectError):
        validate_operation_effects(OPERATION,'consumer.py::read',facts)

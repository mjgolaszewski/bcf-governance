"""Native container provenance grants neither borrowed ownership nor effects."""
from __future__ import annotations

import pytest

from bcf_governance.tooling.semantic_operation_effects import (
    SemanticOperationEffectError,
    validate_operation_effects,
)
from tests.test_consumer_callback_contracts import OPERATION, inventory, witness


@pytest.mark.parametrize('body,expected',[
    ("data={'first':'one','second':'two'}\nresult=''\nfor key,value in data.items():\n result=f'{key}:{value}'\nreturn result",'second:two'),
    ("data={'rows':[{'name':'actual'}]}\nresult=''\nfor row in data.get('rows',[]):\n result=f\"value {row.get('name','missing')}\"\nreturn result",'value actual'),
])
def test_deep_native_mapping_views_and_nested_get_preserve_values(tmp_path,body,expected):
    path,facts=inventory(tmp_path,'def read():\n'+''.join(' '+line+'\n' for line in body.splitlines()))
    assert witness(path)==[expected,expected]
    assert validate_operation_effects(OPERATION,'consumer.py::read',facts)==(0,0)


def test_escaped_view_loses_native_element_facts_at_the_loop_fixed_point(tmp_path):
    path,facts=inventory(tmp_path,"""
        EVENTS=[]
        class Probe:
            def __format__(self,spec):
                EVENTS.append(7)
                return 'foreign'
        PROBE=Probe()
        def mutate(data):
            data['second']=PROBE
        def read():
            data={'first':'one','second':'two'}
            view=data.values()
            for value in view:
                rendered=f'value {value}'
                mutate(data)
            return len(EVENTS)
    """)
    assert witness(path)==[1,2]
    operation={**OPERATION,'allowed_mutation_ports':['consumer.py::mutate']}
    with pytest.raises(SemanticOperationEffectError):
        validate_operation_effects(operation,'consumer.py::read',facts)


def test_local_foreign_append_does_not_retain_first_iteration_format_proof(tmp_path):
    path,facts=inventory(tmp_path,"""
        EVENTS=[]
        class Probe:
            def __format__(self,spec):
                EVENTS.append(7)
                return 'foreign'
        PROBE=Probe()
        def read():
            rows=['native']
            for value in rows:
                rendered=f'value {value}'
                if len(rows)==1: rows.append(PROBE)
            return len(EVENTS)
    """)
    assert witness(path)==[1,2]
    with pytest.raises(SemanticOperationEffectError):
        validate_operation_effects(OPERATION,'consumer.py::read',facts)


def test_mutating_a_borrowed_child_invalidates_record_field_facts(tmp_path):
    path,facts=inventory(tmp_path,"""
        from dataclasses import dataclass
        EVENTS=[]
        class Probe:
            def __repr__(self):
                EVENTS.append(7)
                return 'foreign'
        PROBE=Probe()
        @dataclass
        class Record:
            values: list
        def read():
            child=[]
            record=Record(child)
            child.append(PROBE)
            rendered=f'value {record.values}'
            return len(EVENTS)
    """)
    assert witness(path)==[1,2]
    with pytest.raises(SemanticOperationEffectError):
        validate_operation_effects(OPERATION,'consumer.py::read',facts)


def test_single_field_fstring_from_a_port_does_not_prove_an_exact_native_string(tmp_path):
    path,facts=inventory(tmp_path,"""
        EVENTS=[]
        class Rendered(str):
            def __format__(self,spec):
                EVENTS.append(7)
                return 'foreign'
        class Token:
            def __format__(self,spec): return Rendered('actual')
        TOKEN=Token()
        def render(): return f'{TOKEN}'
        def read():
            value=render()
            rendered=f'{value}'
            return len(EVENTS)
    """)
    assert witness(path)==[1,2]
    operation={**OPERATION,'non_authoritative_output_effects':['consumer.py::render']}
    with pytest.raises(SemanticOperationEffectError):
        validate_operation_effects(operation,'consumer.py::read',facts)


def test_native_receiver_proof_does_not_reach_an_unrelated_source_read_port(tmp_path):
    path,facts=inventory(tmp_path,"""
        class Pretend:
            def get(self,key): return 'pretend'
        def read():
            data: Pretend={'name':'actual'}
            return f\"value {data.get('name')}\"
    """)
    assert witness(path)==['value actual','value actual']
    operation={**OPERATION,'allowed_read_ports':['consumer.py::Pretend.get'],'authoritative_read':True}
    with pytest.raises(SemanticOperationEffectError,match='unreachable effect ports'):
        validate_operation_effects(operation,'consumer.py::read',facts)


@pytest.mark.parametrize('protocol',['str','repr'])
def test_str_and_repr_protocol_results_do_not_grant_exact_native_kind(tmp_path,protocol):
    path,facts=inventory(tmp_path,"""
        EVENTS=[]
        class Rendered(str):
            def __format__(self,spec):
                EVENTS.append(7)
                return 'foreign'
        class Token:
            def __PROTOCOL__(self): return Rendered('actual')
        TOKEN=Token()
        def render(): return PROTOCOL(TOKEN)
        def read():
            value=render()
            rendered=f'{value}'
            return len(EVENTS)
    """.replace('PROTOCOL',protocol))
    assert witness(path)==[1,2]
    operation={**OPERATION,'non_authoritative_output_effects':['consumer.py::render']}
    with pytest.raises(SemanticOperationEffectError):
        validate_operation_effects(operation,'consumer.py::read',facts)

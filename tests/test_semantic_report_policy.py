"""Existing report policy observes uncertainty and never proves callbacks pure."""
import pytest

from bcf_governance.tooling.semantic_operation_effects import (
    SemanticOperationEffectError,
    validate_operation_effects,
)
from tests.test_consumer_callback_contracts import OPERATION, inventory


def test_unresolved_protocol_is_reported_and_still_fails_closed(tmp_path):
    _,facts=inventory(tmp_path,"def read(value): return f'{value}'")
    with pytest.raises(SemanticOperationEffectError):
        validate_operation_effects(OPERATION,'consumer.py::read',facts)
    assert validate_operation_effects(OPERATION,'consumer.py::read',facts,unresolved_dynamic_policy='report')==(0,0)
    assert any(row['kind']=='unqualified_format_callback' and row['qualified'] is False for row in facts['unresolved'])


def test_report_policy_does_not_hide_reached_source_callback_writes(tmp_path):
    _,facts=inventory(tmp_path,"""
        EVENTS=[]
        class Probe:
            def __format__(self,spec):
                EVENTS.append(7)
                return 'foreign'
        def read(): return f'{Probe()}'
    """)
    with pytest.raises(SemanticOperationEffectError,match='undeclared write effects'):
        validate_operation_effects(OPERATION,'consumer.py::read',facts,unresolved_dynamic_policy='report')


def test_report_policy_does_not_relax_existing_authority_failures(tmp_path):
    _,facts=inventory(tmp_path,'def read():\n publish_receipt()\n return 7')
    with pytest.raises(SemanticOperationEffectError,match='undeclared authority effects'):
        validate_operation_effects(OPERATION,'consumer.py::read',facts,unresolved_dynamic_policy='report')


@pytest.mark.parametrize('policy', ['report', 'fail_closed'])
def test_known_retained_write_rejects_in_ordinary_body(tmp_path, policy):
    _, facts = inventory(tmp_path, "EVENTS=[]\ndef read():\n EVENTS.append(7)\n return 7")
    with pytest.raises(SemanticOperationEffectError, match='undeclared write effects'):
        validate_operation_effects(OPERATION, 'consumer.py::read', facts, unresolved_dynamic_policy=policy)

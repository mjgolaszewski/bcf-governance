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


def test_source_callback_uncertainty_remains_observed_in_report(tmp_path):
    _, facts = inventory(tmp_path, "class Probe:\n def __format__(self,spec): return f'{spec}'\ndef read(): return f'{Probe()}'")
    assert validate_operation_effects(OPERATION, 'consumer.py::read', facts, unresolved_dynamic_policy='report') == (0, 0)
    assert any(row['qualified'] is False for row in facts['unresolved'])
    with pytest.raises(SemanticOperationEffectError):
        validate_operation_effects(OPERATION, 'consumer.py::read', facts)


def test_neutral_cache_does_not_reuse_report_acceptance_in_strict_mode(tmp_path):
    _, facts = inventory(tmp_path, "def read(value): return f'{value}'")
    cache = {}
    assert validate_operation_effects(OPERATION, 'consumer.py::read', facts,
        unresolved_dynamic_policy='report', _origin_cache=cache) == (0, 0)
    with pytest.raises(SemanticOperationEffectError):
        validate_operation_effects(OPERATION, 'consumer.py::read', facts, _origin_cache=cache)


def test_neutral_cache_does_not_hide_new_source_alias_escape(tmp_path):
    source = "EVENTS=[]\ndef read():\n items=[]\n items.append(7)\n return len(items)"
    _, first = inventory(tmp_path, source)
    cache = {}
    assert validate_operation_effects(OPERATION, 'consumer.py::read', first, _origin_cache=cache) == (0, 0)
    _, changed = inventory(tmp_path, source.replace('items=[]', 'items=EVENTS'))
    with pytest.raises(SemanticOperationEffectError, match='undeclared write effects'):
        validate_operation_effects(OPERATION, 'consumer.py::read', changed, _origin_cache=cache)


def test_neutral_cache_does_not_reuse_declared_port_authority(tmp_path):
    _, facts = inventory(tmp_path, "from pathlib import Path\ndef persist(): Path('output').write_text('data')\ndef read(): persist()")
    cache = {}
    command = {**OPERATION, 'id': 'command.v1', 'allowed_mutation_ports': ['consumer.py::persist']}
    assert validate_operation_effects(command, 'consumer.py::read', facts, _origin_cache=cache) == (1, 0)
    with pytest.raises(SemanticOperationEffectError, match='undeclared write effects'):
        validate_operation_effects(OPERATION, 'consumer.py::read', facts, _origin_cache=cache)

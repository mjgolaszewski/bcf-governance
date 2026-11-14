"""Vendor record normalization is not normalization of a request selector."""
from textwrap import dedent

import pytest

from bcf_governance.tooling.semantic_ownership_scan import evaluate_discovery
from tests.test_consumer_callback_contracts import inventory
from tests.test_semantic_generated_copies import BASE, registry


def test_source_constructed_vendor_record_is_distinct_from_request_field(tmp_path):
    _,facts=inventory(tmp_path,BASE+'''
    @dataclass
    class Snapshot:
        status: str
        @classmethod
        def from_vendor(cls,payload):
            value=payload.get('status')
            return cls(value)
    def read(record: Record,service):
        payload=service.status(record.value)
        snapshot=Snapshot.from_vendor(payload)
        return snapshot.status.strip().lower()=='done'
    ''')
    result=evaluate_discovery(facts,registry())
    assert not [item for item in result['violations'] if item['kind']=='downstream_normalization']


@pytest.mark.parametrize('body',[
    'snapshot: Snapshot=record',
    'snapshot=Snapshot.from_vendor(record)',
    "snapshot=Snapshot('done')\n        snapshot=record",
])
def test_annotations_aliases_and_nonconstructing_factories_do_not_hide_request_normalization(tmp_path,body):
    _,facts=inventory(tmp_path,BASE+'''
    @dataclass
    class Snapshot:
        status: str
        @classmethod
        def from_vendor(cls,payload) -> Snapshot:
            return payload
    def read(record: Record):
        BODY
        return snapshot.value.strip()
    '''.replace('BODY',body))
    result=evaluate_discovery(facts,registry())
    assert any(item['kind']=='downstream_normalization' for item in result['violations'])


def test_injected_dispatch_map_get_does_not_normalize_lookup_key(tmp_path):
    _, facts = inventory(tmp_path, dedent(BASE) + "\nclass Handler:\n def __init__(self, operations): self.operations=operations\n def read(self, record: Record): return self.operations.get(record.value, None)\n")
    result = evaluate_discovery(facts, registry())
    assert not [row for row in result['violations'] if row['kind'] == 'downstream_normalization']


def test_canonical_receiver_method_and_parameter_alias_still_normalize(tmp_path):
    _, facts = inventory(tmp_path, dedent(BASE) + "\ndef read(record: Record):\n alias=record\n return alias.value.get('key', 'default')\n")
    result = evaluate_discovery(facts, registry())
    assert any(row['kind'] == 'downstream_normalization' for row in result['violations'])


@pytest.mark.parametrize('owner,lost,field,accepted', [
    ('consumer.py::display', [], 'value', True),
    ('consumer.py::other', [], 'value', False),
    ('consumer.py::display', ['value'], 'value', False),
])
def test_projection_permission_is_exact_owner_and_retained_field(tmp_path, owner, lost, field, accepted):
    from dataclasses import replace
    _, facts = inventory(tmp_path, BASE + '''
    def display(record: Record): return record.FIELD.lower()
    '''.replace('FIELD', field))
    original = registry()
    entry = original.entries[0]
    entry = replace(entry, raw={'field_invariants': [{'field': 'value'}],
        'intentional_projections': [{'source_semantic_id': entry.semantic_id,
            'owner': owner, 'lost_fields': lost}]})
    result = evaluate_discovery(facts, replace(original, entries=(entry,)))
    failures = [row for row in result['violations'] if row['kind'] == 'downstream_normalization']
    assert bool(failures) is not accepted


@pytest.mark.parametrize('expression,shadow,accepted', [
    ('Path(record.value).suffix.lower() == ".json"', '', True),
    ('Path(record.value).suffix.lower()', '', False),
    ('record.value.lower() == ".json"', '', False),
    ('Path(record.value).suffix.lower() == ".json"', 'Path=lambda value: value', False),
])
def test_path_format_predicate_is_not_whole_identity_normalization(tmp_path, expression, shadow, accepted):
    _, facts = inventory(tmp_path, BASE + '''
    from pathlib import Path
    def read(record: Record):
        SHADOW
        return EXPRESSION
    '''.replace('SHADOW', shadow or 'pass').replace('EXPRESSION', expression))
    failures = [row for row in evaluate_discovery(facts, registry())['violations']
        if row['kind'] == 'downstream_normalization']
    assert bool(failures) is not accepted


@pytest.mark.parametrize('assignment,transport,accepted', [
    ('content=transport(stored, identity=record.value)', 'return data', True),
    ('content=record.value', 'return data', False),
    ('content=opaque(stored, identity=record.value)', 'return data', False),
    ('content=transport(stored, identity=record.value)\n        content=record.value', 'return data', False),
    ('content=transport(stored, identity=record.value)', 'return identity', False),
])
def test_verified_content_role_is_not_annotation_or_field_alias_purity(tmp_path, assignment, transport, accepted):
    _, facts = inventory(tmp_path, BASE + '''
    import hashlib
    def transport(data, *, identity): TRANSPORT
    def verified(record: Record, stored):
        ASSIGNMENT
        if hashlib.sha256(content).hexdigest() != record.value:
            raise ValueError('changed')
        return content
    def read(record: Record, stored):
        content=verified(record,stored)
        return content.decode('utf-8')
    '''.replace('TRANSPORT', transport).replace('ASSIGNMENT', assignment))
    failures = [row for row in evaluate_discovery(facts, registry())['violations']
        if row['kind'] == 'downstream_normalization' and row['symbol'] == 'consumer.py::read']
    assert bool(failures) is not accepted
    if accepted:
        read = next(row for row in facts['functions'] if row['symbol'] == 'consumer.py::read')
        assert read['normalizations'][0]['receiver_role_execution_qualified'] is False


@pytest.mark.parametrize('payload,setup,transport,helper,accepted', [
    ('stored', 'pass', 'return data', '', True),
    ('record.value', 'pass', 'return data', '', False),
    ('alias', 'alias=record.value', 'return data', '', False),
    ('record.value', 'pass', 'return choose(data, identity=identity)', 'def choose(data, *, identity): return data', False),
    ('stored', 'pass', 'return choose(data, identity=identity)', 'def choose(data, *, identity): return identity', False),
    ('stored', 'pass', 'return opaque(data, identity=identity)', '', False),
    ('stored', 'pass', 'return choose(data, identity=identity)', 'def choose(data, *, identity): return data', True),
])
def test_verified_content_binds_actual_payload_and_source_return(tmp_path, payload, setup, transport, helper, accepted):
    _, facts = inventory(tmp_path, BASE.replace('value: str', 'value: bytes') + '''
    import hashlib
    HELPER
    def transport(data, *, identity): TRANSPORT
    def verified(record: Record, stored):
        content=transport(stored, identity=record.value)
        if hashlib.sha256(content).hexdigest() != hashlib.sha256(record.value).hexdigest():
            raise ValueError('changed')
        return content
    def read(record: Record, stored):
        SETUP
        content=verified(record=record, stored=PAYLOAD)
        return content.decode()
    '''.replace('HELPER', helper).replace('TRANSPORT', transport).replace('SETUP', setup).replace('PAYLOAD', payload))
    failures = [row for row in evaluate_discovery(facts, registry())['violations']
                if row['kind'] == 'downstream_normalization' and row['symbol'] == 'consumer.py::read']
    assert bool(failures) is not accepted


def test_verified_payload_caller_forwarding_does_not_hide_field(tmp_path):
    _, facts = inventory(tmp_path, BASE + '''
    import hashlib
    def transport(data, *, identity): return data
    def verified(record: Record, stored):
        content=transport(stored, identity=record.value)
        hashlib.sha256(content)
        return content
    def read(record: Record, stored):
        content=verified(record, stored)
        return content.decode()
    def outer(record: Record): return read(record, record.value)
    ''')
    assert any(row['kind'] == 'downstream_normalization' and row['symbol'] == 'consumer.py::read'
               for row in evaluate_discovery(facts, registry())['violations'])


@pytest.mark.parametrize('rebound', [False, True])
def test_module_path_rebinding_retains_ordinary_normalization(tmp_path, rebound):
    _, facts = inventory(tmp_path, BASE + '\n    from pathlib import Path\n' + (
        '    class Fake:\n        def __init__(self, value): self.suffix=value\n    Path=Fake\n'
        if rebound else '') + '    def read(record: Record):\n        return Path(record.value).suffix.lower()==".json"\n')
    failures = [row for row in evaluate_discovery(facts, registry())['violations']
                if row['kind'] == 'downstream_normalization']
    assert bool(failures) is rebound

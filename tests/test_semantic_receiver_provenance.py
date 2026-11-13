"""Vendor record normalization is not normalization of a request selector."""
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

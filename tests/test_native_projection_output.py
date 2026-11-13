"""Native CLI projection compatibility and callback boundary controls."""
from __future__ import annotations

import json
from enum import Enum, StrEnum

import pytest

from bcf_governance.tooling.native_projection_output import (
    snapshot_native_projection,
    write_native_projection,
)


@pytest.mark.parametrize('output_format', ['text', 'json'])
def test_native_projection_preserves_current_native_output(capsys, output_format):
    payload = {'result': [1, True, None, {'label': 'native'}], 'count': 3}
    write_native_projection(payload, output_format)
    expected = json.dumps(payload, sort_keys=True) + '\n' if output_format == 'json' else ''.join(f'{key}: {value}\n' for key, value in payload.items())
    assert capsys.readouterr().out == expected


@pytest.mark.parametrize('output_format', ['text', 'json'])
def test_projection_preserves_actual_legacy_framework_enum_contract(capsys, output_format):
    from bcf_governance.tooling.local_pr_context import LocalValidationLane
    member = next(iter(LocalValidationLane))
    payload = {'lane': member, 'nested': [member, {'lane': member}]}
    write_native_projection(payload, output_format)
    expected = json.dumps(payload, sort_keys=True) + '\n' if output_format == 'json' else ''.join(f'{key}: {value}\n' for key, value in payload.items())
    assert capsys.readouterr().out == expected


def test_projection_snapshot_never_retains_mutable_input_children():
    child = {'items': ['original']}
    payload = {'first': child, 'second': child}
    snapshot = snapshot_native_projection(payload)
    child['items'].append('later')
    assert snapshot == {'first': {'items': ['original']}, 'second': {'items': ['original']}}
    assert snapshot['first'] is not child and snapshot['second'] is not child


@pytest.mark.parametrize('kind', ['mapping', 'list', 'format', 'repr', 'format_choice'])
def test_projection_rejects_foreign_protocols_before_output(capsys, kind):
    events = []
    class MappingProbe(dict):
        def items(self):
            events.append('items')
            return super().items()
    class ListProbe(list):
        def __iter__(self):
            events.append('iter')
            return super().__iter__()
    class FormatProbe:
        def __format__(self, spec):
            events.append('format')
            return 'foreign'
    class ReprProbe:
        def __repr__(self):
            events.append('repr')
            return 'foreign'
    class FormatChoice:
        def __eq__(self, other):
            events.append('eq')
            return True
    values = {'mapping': MappingProbe(a=1), 'list': {'node': ListProbe([1])},
              'format': {'node': FormatProbe()}, 'repr': {'node': [ReprProbe()]},
              'format_choice': {'node': 'native'}}
    with pytest.raises(TypeError):
        write_native_projection(values[kind], FormatChoice() if kind == 'format_choice' else 'text')
    assert events == [] and capsys.readouterr().out == ''


def test_projection_rejects_custom_enum_formatter_before_callback(capsys):
    events = []
    class Custom(StrEnum):
        VALUE = 'value'
        def __format__(self, spec):
            events.append('format')
            return 'foreign'
    with pytest.raises(TypeError):
        write_native_projection({'node': Custom.VALUE}, 'text')
    assert events == [] and capsys.readouterr().out == ''


def test_native_enum_text_preserves_scalar_and_nested_representations(capsys):
    class Legacy(StrEnum):
        VALUE = 'value'
        __str__ = Enum.__str__
        __format__ = Enum.__format__
    payload = {'value': Legacy.VALUE, 'nested': (Legacy.VALUE, [Legacy.VALUE])}
    write_native_projection(payload, 'text')
    assert capsys.readouterr().out == ''.join(f'{key}: {value}\n' for key, value in payload.items())

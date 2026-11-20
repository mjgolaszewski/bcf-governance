"""Unconditional native protocol obligations remain visible without their observer rows."""
import copy

import pytest

from bcf_governance.tooling.semantic_authority_contracts import SemanticAuthorityError
from tests.test_independent_call_coverage import capture, consume, work

SOURCES = {
    'attribute_read': 'def work(value):\n    return value.attribute\n',
    'context_manager': 'def work(value):\n    with value:\n        return 1\n',
    'async_context': 'async def work(value):\n    async with value:\n        return 1\n',
    'await': 'async def work(value):\n    return await value\n',
}
KINDS = {'async_context': 'context_manager'}


def facts_for(root, mode, version=None):
    return capture(root, SOURCES[mode] + "COMMANDS={'work':work}\n", version)


@pytest.mark.parametrize('version', [None, '1.0'])
@pytest.mark.parametrize('mode', list(SOURCES))
@pytest.mark.parametrize('defect', ['erase', 'duplicate', 'digest', 'span', 'caller'])
def test_independent_mandatory_protocol_coverage(tmp_path, version, mode, defect):
    facts = facts_for(tmp_path, mode, version)
    kind = KINDS.get(mode, mode)
    rows = work(facts)['calls']
    selected = [row for row in rows if row.get('implicit_protocol', {}).get('kind') == kind]
    assert len(selected) == 1
    row = selected[0]
    if defect == 'erase':
        rows.remove(row)
    elif defect == 'duplicate':
        rows.append(copy.deepcopy(row))
    elif defect == 'digest':
        row['implicit_protocol']['expression_sha256'] = '0' * 64
        if 'call_contract' in row:
            row['call_contract']['expression_sha256'] = '0' * 64
    elif defect == 'span':
        row['column'] += 1
    else:
        row['caller'] = 'runtime.py::other'
    with pytest.raises(SemanticAuthorityError, match='Python source implicit protocol coverage'):
        consume(tmp_path, facts)


@pytest.mark.parametrize('mode', list(SOURCES))
def test_authentic_unsupported_protocol_stays_blocked(tmp_path, mode):
    facts = facts_for(tmp_path, mode, '1.0')
    with pytest.raises(SemanticAuthorityError, match='unresolved effect runtime protocol'):
        consume(tmp_path, facts)


@pytest.mark.parametrize('source', [
    'def work():\n    return 1\n',
    'def work(value):\n    return value.method()\n',
    'def work(value):\n    return lambda: value.attribute\n',
    'from __future__ import annotations\ndef work(value: marker.attribute):\n    return 1\n',
])
def test_coverage_does_not_reclassify_native_or_deferred_contexts(tmp_path, source):
    facts = capture(tmp_path, source + "COMMANDS={'work':work}\n", '1.0')
    from bcf_governance.tooling.semantic_authority_operations import _validate_python_call_source_coverage
    from bcf_governance.tooling.semantic_operation_effects import _source_function_population
    _validate_python_call_source_coverage(tmp_path, facts, _source_function_population(facts), None)


@pytest.mark.parametrize('mode', list(SOURCES))
def test_actual_callback_witness_survives_inventory_erasure(tmp_path, mode):
    events = []

    class Input:
        @property
        def attribute(self):
            events.append('attribute')
            return 1

        def __enter__(self):
            events.append('enter')
            return self

        def __exit__(self, *args):
            events.append('exit')

        async def __aenter__(self):
            events.append('async-enter')
            return self

        async def __aexit__(self, *args):
            events.append('async-exit')

        def __await__(self):
            events.append('await')
            if False:
                yield
            return 1

    namespace = {}
    exec(compile(SOURCES[mode], 'runtime.py', 'exec'), namespace)
    result = namespace['work'](Input())
    if mode in {'async_context', 'await'}:
        with pytest.raises(StopIteration) as stopped:
            result.send(None)
        assert stopped.value.value == 1
    else:
        assert result == 1
    assert events == {'attribute_read': ['attribute'], 'context_manager': ['enter', 'exit'],
        'async_context': ['async-enter', 'async-exit'], 'await': ['await']}[mode]
    facts = facts_for(tmp_path, mode, '1.0')
    work(facts)['calls'] = []
    with pytest.raises(SemanticAuthorityError, match='Python source implicit protocol coverage'):
        consume(tmp_path, facts)

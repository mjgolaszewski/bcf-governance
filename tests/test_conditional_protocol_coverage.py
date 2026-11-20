"""Conditional protocol obligations and occurrence identities come from cold source."""
import copy
from unittest.mock import patch

import pytest

from bcf_governance.tooling import semantic_python_calls as producer
from bcf_governance.tooling.semantic_authority_contracts import SemanticAuthorityError
from bcf_governance.tooling.semantic_authority_operations import _validate_python_call_source_coverage
from bcf_governance.tooling.semantic_operation_effects import _source_function_population
from tests.conditional_protocol_support import SOURCES, erased, facts_for
from tests.test_independent_call_coverage import capture, consume, work


def audit(root, facts):
    _validate_python_call_source_coverage(root, facts, _source_function_population(facts), None)


@pytest.mark.parametrize('version', [None, '1.0'])
@pytest.mark.parametrize('mode', list(SOURCES))
def test_erased_conditional_protocol_remains_required(tmp_path, version, mode):
    facts = erased(tmp_path, mode, version)
    with pytest.raises(SemanticAuthorityError, match='Python source implicit protocol coverage'):
        consume(tmp_path, facts)


@pytest.mark.parametrize('part', ['classifier', 'emitter'])
@pytest.mark.parametrize('mode', list(SOURCES))
def test_producer_removal_cannot_remove_independent_obligation(tmp_path, part, mode):
    if part == 'classifier':
        target = patch.object(producer, 'implicit_runtime_protocols', return_value=())
    else:
        target = patch.object(producer.FunctionVisitor, '_record_implicit_protocol', return_value=None)
    with target:
        facts = facts_for(tmp_path, mode)
    assert work(facts)['calls'] == []
    with pytest.raises(SemanticAuthorityError, match='Python source implicit protocol coverage'):
        consume(tmp_path, facts)


@pytest.mark.parametrize('source', [
    'def work():\n    values=[1,2]\n    values[0]=3\n    return values[0]\n',
    'def work(value):\n    if value is None:\n        return 1\n    return 0\n',
    'def work(value):\n    if not value:\n        return 1\n    return 0\n',
    'def work():\n    return [element for element in [1,2]]\n',
    'def work():\n    return {element:1 for element in [1,2]}\n',
    'def work(value):\n    def child(item=value[0]):\n        return value[1]\n    return 1\n',
    'def work(value):\n    def child(item: value[0]):\n        return 1\n    return 1\n',
    'def work(value):\r\n    return f"é{value}"\r\n',
])
def test_closed_context_membership_is_compatible(tmp_path, source):
    facts = capture(tmp_path, source + "COMMANDS={'work':work}\n", '1.0')
    audit(tmp_path, facts)


@pytest.mark.parametrize('mode', list(SOURCES))
@pytest.mark.parametrize('defect', ['duplicate', 'digest', 'span', 'kind', 'occurrence', 'version'])
def test_conditional_identity_cannot_be_substituted(tmp_path, mode, defect):
    facts = facts_for(tmp_path, mode)
    rows = work(facts)['calls']
    row = rows[0]
    if defect == 'duplicate':
        rows.append(copy.deepcopy(row))
    elif defect == 'digest':
        row['implicit_protocol']['expression_sha256'] = '0' * 64
        row['call_contract']['expression_sha256'] = '0' * 64
    elif defect == 'span':
        row['column'] += 1
    elif defect == 'kind':
        row['implicit_protocol']['kind'] = 'await'
        row['implicit_protocol']['version'] = '1.1'
        row['called_symbol'] = 'python-implicit::await'
    elif defect == 'occurrence':
        row['implicit_protocol']['occurrence'] = 100
        row['call_contract']['occurrence'] = 100
    else:
        row['implicit_protocol']['version'] = '99.0'
    with pytest.raises(SemanticAuthorityError, match='Python source implicit protocol coverage'):
        audit(tmp_path, facts)


@pytest.mark.parametrize('defect', ['marker', 'contract', 'swap', 'boolean'])
def test_shared_guard_and_explicit_call_occurrences_are_source_bound(tmp_path, defect):
    source = ('def predicate(value):\n    return True\ndef work(value):\n'
        '    return [element for element in [1] if predicate(value)]\nCOMMANDS={"work":work}\n')
    facts = capture(tmp_path, source, '1.0')
    rows = work(facts)['calls']
    guard = next(row for row in rows if 'implicit_protocol' in row)
    explicit = next(row for row in rows if 'implicit_protocol' not in row)
    assert guard['implicit_protocol']['occurrence'] == 0
    assert explicit['call_contract']['occurrence'] == 1
    audit(tmp_path, facts)
    if defect == 'marker':
        guard['implicit_protocol']['occurrence'] = 9
        guard['call_contract']['occurrence'] = 9
    elif defect == 'contract':
        explicit['call_contract']['occurrence'] = 0
    elif defect == 'boolean':
        explicit['call_contract']['occurrence'] = True
    else:
        guard['implicit_protocol']['occurrence'] = guard['call_contract']['occurrence'] = 1
        explicit['call_contract']['occurrence'] = 0
    with pytest.raises(SemanticAuthorityError, match='Python source .* coverage'):
        audit(tmp_path, facts)


@pytest.mark.parametrize('defect', ['large', 'swap', 'boolean'])
def test_repeated_explicit_call_occurrence_is_independently_bound(tmp_path, defect):
    facts = capture(tmp_path, 'def helper():\n    return 1\ndef work():\n'
        '    return [helper(),helper()]\nCOMMANDS={"work":work}\n', '1.0')
    rows = work(facts)['calls']
    assert [row['call_contract']['occurrence'] for row in rows] == [0,1]
    assert consume(tmp_path, facts)
    if defect == 'large':
        rows[0]['call_contract']['occurrence'] = 100
    elif defect == 'boolean':
        rows[1]['call_contract']['occurrence'] = True
    else:
        rows[0]['call_contract']['occurrence'], rows[1]['call_contract']['occurrence'] = 1,0
    with pytest.raises(SemanticAuthorityError, match='Python source call coverage'):
        consume(tmp_path, facts)


@pytest.mark.parametrize('mode', ['truth', 'operator', 'for_iteration', 'dict_collection', 'subscript', 'format'])
def test_actual_conditional_callback_remains_visible_after_erasure(tmp_path, mode):
    events = []

    class Input:
        def __bool__(self):
            events.append('bool')
            return True

        def __add__(self, other):
            events.append('add')
            return 1

        def __iter__(self):
            events.append('iter')
            return iter([1])

        def __hash__(self):
            events.append('hash')
            return 1

        def __getitem__(self, key):
            events.append('getitem')
            return 1

        def __format__(self, spec):
            events.append('format')
            return '1'

    namespace = {}
    exec(compile(SOURCES[mode], 'runtime.py', 'exec'), namespace)
    namespace['work'](Input())
    assert events == [{'truth':'bool','operator':'add','for_iteration':'iter',
        'dict_collection':'hash','subscript':'getitem','format':'format'}[mode]]
    with pytest.raises(SemanticAuthorityError, match='Python source implicit protocol coverage'):
        consume(tmp_path, erased(tmp_path, mode))

"""Actual BCF _unknown source, defaults and owned result regressions; UNRUN."""
from pathlib import Path
from typing import Any

import pytest

from bcf_governance.tooling.semantic_ownership_inventory import (
    SemanticInventoryError, discover_python_source, resolve_python_imports,
)
from bcf_governance.tooling.semantic_operation_effects import (
    SemanticOperationEffectError, validate_operation_effects,
)
from bcf_governance.tooling.semantic_python_return_facts import _contains_opaque_input

ORIGINAL = (Path(__file__).resolve().parents[1] / 'fixtures/bcf/semantic_python_return_facts.py').read_text()


def inventory(tmp_path: Path, expression: str, *, source: str = ORIGINAL,
              parameters: str = '') -> dict[str, Any]:
    (tmp_path / 'facts.py').write_text(source)
    (tmp_path / 'consumer.py').write_text('from facts import _unknown\n\ndef entry(' + parameters + '):\n    return ' + expression + '\n')
    discovered = discover_python_source(tmp_path, sorted(tmp_path.glob('*.py')))
    found = resolve_python_imports(tmp_path, discovered)
    assert found['return_facts'] == discovered['return_facts']
    assert found['definition_time_obligations'] == discovered['definition_time_obligations']
    return found


def entry(found: dict[str, Any]) -> dict[str, Any]:
    return next(f for f in found['functions'] if f['symbol'] == 'consumer.py::entry')


def operation() -> dict[str, Any]:
    return {'id': 'query', 'allowed_mutation_ports': [], 'allowed_authority_ports': [],
            'non_authoritative_output_effects': []}


@pytest.mark.parametrize('expression, marker, source_kind', [
    ('_unknown("origin_budget")', False, 'omitted_default'),
    ('_unknown("origin_budget", opaque=True)', True, 'explicit_keyword'),
    ('_unknown("origin_budget", opaque=False)', False, 'explicit_keyword'),
])
def test_complete_real_callee_result_and_local_effects_are_positive(tmp_path: Path, expression: str,
                                                                 marker: bool, source_kind: str) -> None:
    found = inventory(tmp_path, expression)
    caller = entry(found)
    edge = caller['calls'][0]
    assert edge['dispatch_resolution'] == 'exact_source_literal_default_call'
    model = edge['literal_default_call_model']
    expected: dict[str, Any] = {'kind': 'unknown', 'reason': 'origin_budget'}
    if marker:
        expected['opaque_parameter'] = True
    assert model['result_value'] == [expected]
    assert model['bindings']['opaque']['source'] == source_kind
    reason = model['result_provenance']['elements'][0]['fields']['reason']
    assert reason['source'] == 'explicit_positional' and reason['parameter'] == 'reason'
    assert reason['value'] == 'origin_budget'
    assert _contains_opaque_input(model['result_value']) is marker
    assert model['local_effects_complete'] is True and model['external_effects'] == []
    assert {e['kind'] for e in model['effects']} >= {'local_dict_allocation', 'local_list_allocation'}
    assert any(e['kind'] == 'local_container_write' for e in model['effects']) is marker
    assert validate_operation_effects(operation(), caller['symbol'], found) == (0, 0)


def test_actual_original_three_default_calls_keep_full_body_models_but_not_caller_permission(tmp_path: Path) -> None:
    found = inventory(tmp_path, '_unknown("origin_budget")')
    real = next(f for f in found['functions'] if f['symbol'] == 'facts.py::_Flow.expression')
    selected = [c for c in real['calls'] if c.get('line') in {163, 165, 166} and c.get('call_name') == '_unknown']
    assert len(selected) == 3
    for edge in selected:
        assert edge['literal_default_call_model']['result_value'] == [{'kind': 'unknown', 'reason': 'origin_budget'}]
        assert edge['literal_default_call_model']['bindings']['opaque']['source'] == 'omitted_default'
        assert edge['literal_default_admission'] is False
        assert edge['literal_default_refusal'] == 'caller_context_not_closed'
    with pytest.raises(SemanticOperationEffectError):
        validate_operation_effects(operation(), real['symbol'], found)


@pytest.mark.parametrize('expression, parameters', [
    ('_unknown()', ''),
    ('_unknown("r", reason="duplicate")', ''),
    ('_unknown("r", unexpected=True)', ''),
    ('_unknown(reason="r", **{})', ''),
    ('_unknown(*["r"])', ''),
    ('_unknown(reason)', 'reason'),
    ('_unknown("r", opaque=None)', ''),
    ('_unknown("r", opaque=True).as_dict()', ''),
])
def test_invalid_or_opaque_context_cannot_be_hidden_by_read_port(tmp_path: Path, expression: str, parameters: str) -> None:
    found = inventory(tmp_path, expression, parameters=parameters)
    caller = entry(found)
    edge = next(c for c in caller['calls'] if c['call_name'] == '_unknown')
    assert edge.get('literal_default_admission') is not True
    op = operation()
    op.update(authoritative_read=True, allowed_read_ports=[edge['called_symbol']])
    with pytest.raises(SemanticOperationEffectError):
        validate_operation_effects(op, caller['symbol'], found)


def test_changed_literal_default_changes_the_result_instead_of_reusing_false(tmp_path: Path) -> None:
    source = ORIGINAL.replace('opaque: bool = False', 'opaque: bool = True')
    assert source != ORIGINAL
    found = inventory(tmp_path, '_unknown("origin_budget")', source=source)
    model = entry(found)['calls'][0]['literal_default_call_model']
    assert model['bindings']['opaque']['value'] is True
    assert model['result_value'] == [{'kind': 'unknown', 'reason': 'origin_budget', 'opaque_parameter': True}]
    assert validate_operation_effects(operation(), 'consumer.py::entry', found) == (0, 0)


def test_local_call_model_does_not_erase_real_module_definition_effects(tmp_path: Path) -> None:
    found = inventory(tmp_path, '_unknown("origin_budget")')
    with pytest.raises(SemanticOperationEffectError):
        validate_operation_effects(operation(), 'consumer.py::entry', found, source_modules=('facts.py',))


@pytest.mark.parametrize('source, expression', [
    (ORIGINAL.replace('opaque: bool = False', 'opaque: bool'), '_unknown("r")'),
    (ORIGINAL.replace('opaque: bool = False', 'opaque: bool = external()'), '_unknown("r")'),
    (ORIGINAL.replace('row["opaque_parameter"] = True', 'row["opaque_parameter"] = external()'), '_unknown("r", opaque=True)'),
    (ORIGINAL + '\n_unknown = external\n', '_unknown("r")'),
    (ORIGINAL.replace('    return [row]', '    if False:\n        yield None\n    return [row]', 1), '_unknown("r")'),
])
def test_required_nonliteral_active_effect_and_rebound_source_refuse(tmp_path: Path, source: str, expression: str) -> None:
    found = inventory(tmp_path, expression, source=source)
    with pytest.raises(SemanticOperationEffectError):
        validate_operation_effects(operation(), 'consumer.py::entry', found)


def test_old_discovery_cannot_reuse_a_changed_default(tmp_path: Path) -> None:
    path = tmp_path / 'facts.py'
    path.write_text(ORIGINAL)
    original = discover_python_source(tmp_path, [path])
    path.write_text(ORIGINAL.replace('opaque: bool = False', 'opaque: bool = True'))
    with pytest.raises(SemanticInventoryError, match='changed'):
        resolve_python_imports(tmp_path, original)

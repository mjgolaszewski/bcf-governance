"""Maintained resolver/effect regressions; source prepared, not yet executed."""
from __future__ import annotations

import copy
from pathlib import Path
import shutil
from typing import Any

import pytest

from bcf_governance.tooling.semantic_ownership_inventory import (
    SemanticInventoryError, discover_python_source, resolve_python_imports,
)
from bcf_governance.tooling.semantic_operation_effects import (
    SemanticOperationEffectError, validate_operation_effects,
)


def query() -> dict[str, Any]:
    return {'id': 'query', 'allowed_mutation_ports': [], 'allowed_authority_ports': [],
            'non_authoritative_output_effects': []}


def inventory(tmp_path: Path, source: str) -> dict[str, Any]:
    path = tmp_path / 'subject.py'
    path.write_text(source)
    found = discover_python_source(tmp_path, [path])
    original = copy.deepcopy(found)
    result = resolve_python_imports(tmp_path, found)
    assert found == original
    return result


CELL = '''class Cell:
    def __init__(self, *, ttl=300):
        self._cache = None
        self._cache_expires_at = 0.0
    def clear_cache(self):
        self._cache = None
        self._cache_expires_at = 0.0
'''


def function(found: dict[str, Any], symbol: str) -> dict[str, Any]:
    return next(row for row in found['functions'] if row['symbol'] == symbol)


def test_original_sdk_slice_retains_defaults_cache_writes_and_await_barrier(tmp_path: Path) -> None:
    fixture = Path(__file__).resolve().parents[1] / 'fixtures/sdk'
    shutil.copytree(fixture, tmp_path / 'sdk')
    root = tmp_path / 'sdk'
    files = sorted(root.rglob('*.py'))
    discovered = discover_python_source(root, files)
    before = copy.deepcopy(discovered)
    found = resolve_python_imports(root, discovered, ('src', 'tests'))
    assert discovered == before
    caller = function(found, 'tests/test_jwks_and_introspection_contracts.py::test_jwks_client_caches_until_clear_cache')
    events = caller['constructor_context']['events']
    constructor = next(e for e in events if e['kind'] == 'constructor_context' and e['line'] == 20)
    bindings = constructor['context']['argument_bindings']
    assert bindings['timeout_seconds']['expression_AST'] == '5.0'
    assert bindings['timeout_seconds']['source'] == 'omitted_default'
    assert bindings['ttl_seconds']['expression_AST'] == '300'
    assert bindings['http_client']['opaque_parameter'] is True
    method = next(e for e in events if e['kind'] == 'method_context' and e['line'] == 30)
    assert method['source_target'] == 'src/chrysalis_identity_client/jwks.py::JWKSClient.clear_cache'
    assert method['status'] == 'conditional'
    assert 'await_or_suspend' in method['guards']
    assert method['runtime_identity'] == 'UNPROVEN'
    assert {w['attribute'] for w in method['body_effects']['writes']} == {'_cache', '_cache_expires_at'}
    assert method['body_effects']['return_fact'] == 'fallthrough_none'
    assert method['permits_acceptance'] is False
    # Invocation rows do not own decorator/default/deferred evaluation.
    def definition_owners(value: dict[str, Any]) -> dict[str, Any]:
        return {
            str(row['symbol']): {
                'obligations': row.get('definition_time_obligations', []),
                'contracts': row.get('definition_time_contracts', []),
            }
            for row in value['functions'] if '::<' in str(row['symbol'])
        }

    before_owners = definition_owners(discovered)
    after_owners = definition_owners(found)
    assert after_owners == before_owners
    test_path = 'tests/test_jwks_and_introspection_contracts.py'
    module_owner = after_owners[test_path + '::<module>']
    deferred_owner = after_owners['src/chrysalis_identity_client/jwks.py::<deferred-annotations>']
    assert any(row['kind'] == 'definition_time_decorator_application'
               for row in module_owner['obligations'])
    assert deferred_owner['obligations']
    assert all(row['execution_context']['owner_symbol'] == test_path + '::<module>'
               for row in module_owner['obligations'])
    assert all(row['execution_context']['owner_symbol'] == 'src/chrysalis_identity_client/jwks.py::<deferred-annotations>'
               for row in deferred_owner['obligations'])
    assert found['definition_time_obligations'] == discovered['definition_time_obligations']
    with pytest.raises(SemanticOperationEffectError, match='unresolved constructor caller/effect'):
        validate_operation_effects(query(), caller['symbol'], found)


@pytest.mark.parametrize('prelude', ['await unknown()', 'alias = value\n    escape(alias)', 'unknown()'])
def test_preserved_barrier_cannot_be_erased_by_a_read_port(tmp_path: Path, prelude: str) -> None:
    found = inventory(tmp_path, CELL + '\nasync def entry():\n    value = Cell()\n    ' + prelude + '\n    value.clear_cache()\n')
    caller = function(found, 'subject.py::entry')
    obligation = caller['constructor_context_obligations'][0]
    assert obligation['status'] == 'conditional'
    call = next(c for c in caller['calls'] if c['call_name'] == 'clear_cache')
    operation = query()
    operation.update(authoritative_read=True, allowed_read_ports=[call['called_symbol']])
    with pytest.raises(SemanticOperationEffectError, match='unresolved constructor caller/effect'):
        validate_operation_effects(operation, caller['symbol'], found)


def test_local_cache_stores_are_preserved_as_ownership_obligations(tmp_path: Path) -> None:
    found = inventory(tmp_path, CELL + '\ndef entry():\n    value = Cell()\n    value.clear_cache()\n')
    caller = function(found, 'subject.py::entry')
    obligation = caller['constructor_context_obligations'][0]
    assert obligation['status'] == 'candidate'
    assert obligation['permits_acceptance'] is False
    assert len(obligation['body_effects']['writes']) == 2
    assert len(obligation['initializer']['writes']) == 2
    with pytest.raises(SemanticOperationEffectError, match='unresolved constructor caller/effect'):
        validate_operation_effects(query(), caller['symbol'], found)


def test_unknown_parameter_does_not_gain_constructor_identity(tmp_path: Path) -> None:
    found = inventory(tmp_path, CELL + '\ndef entry(value: Cell):\n    value.clear_cache()\n')
    caller = function(found, 'subject.py::entry')
    assert caller['constructor_context_obligations'] == []
    with pytest.raises(SemanticOperationEffectError, match='unresolved'):
        validate_operation_effects(query(), caller['symbol'], found)


def test_changed_source_cannot_join_a_previous_discovery_snapshot(tmp_path: Path) -> None:
    path = tmp_path / 'subject.py'
    path.write_text(CELL + '\ndef entry():\n    value = Cell()\n    value.clear_cache()\n')
    found = discover_python_source(tmp_path, [path])
    path.write_text(path.read_text().replace('self._cache = None', 'self._cache = external()'))
    with pytest.raises(SemanticInventoryError, match='changed'):
        resolve_python_imports(tmp_path, found)


def test_population_budget_marks_unvisited_callers_unresolved(tmp_path: Path) -> None:
    source = ''.join(f'def entry{i}():\n    return None\n' for i in range(129))
    found = inventory(tmp_path, source)
    last = function(found, 'subject.py::entry128')
    assert last['constructor_context_budget_unresolved'] is True
    with pytest.raises(SemanticOperationEffectError, match='constructor context budget'):
        validate_operation_effects(query(), last['symbol'], found)

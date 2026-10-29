"""An unknown interface cannot become pure because no same-named method exists."""
from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from bcf_governance.tooling.semantic_operation_effects import (
    SemanticOperationEffectError,
    validate_operation_effects,
)
from bcf_governance.tooling.semantic_ownership_inventory import (
    discover_python_source,
    resolve_python_imports,
)


def inventory(tmp_path: Path, source: str) -> dict[str, Any]:
    path = tmp_path / 'subject.py'
    path.write_text(source)
    return resolve_python_imports(tmp_path, discover_python_source(tmp_path, [path]))


def query_operation() -> dict[str, Any]:
    return {'id': 'query', 'allowed_mutation_ports': [], 'allowed_authority_ports': [],
            'non_authoritative_output_effects': []}


@pytest.mark.parametrize('method', ['get', 'json', 'strip'])
@pytest.mark.parametrize('read_port', [False, True], ids=['without-port', 'with-valid-read-port'])
def test_unknown_interface_refuses_without_a_project_method_name_collision(tmp_path: Path, method: str, read_port: bool) -> None:
    arguments = "'key'" if method == 'get' else ''
    found = inventory(tmp_path, f'def query(value):\n    return value.{method}({arguments})\n')
    function = next(row for row in found['functions'] if row['symbol'] == 'subject.py::query')
    call = next(row for row in function['calls'] if row['call_name'] == method)
    operation = query_operation()
    if read_port:
        operation.update(authoritative_read=True, allowed_read_ports=[call['called_symbol']])
    with pytest.raises(SemanticOperationEffectError, match='unresolved'):
        validate_operation_effects(operation, 'subject.py::query', found)


def test_annotation_does_not_prove_an_exact_builtin_receiver(tmp_path: Path) -> None:
    found = inventory(tmp_path, 'def query(value: dict):\n    return value.get("key")\n')
    with pytest.raises(SemanticOperationEffectError, match='unresolved'):
        validate_operation_effects(query_operation(), 'subject.py::query', found)


def test_escaped_parameter_alias_keeps_its_interface_obligation(tmp_path: Path) -> None:
    found = inventory(tmp_path, 'def note(value): return None\ndef query(value):\n    note(value)\n    alias = value\n    return alias.get("key")\n')
    function = next(row for row in found['functions'] if row['symbol'] == 'subject.py::query')
    call = next(row for row in function['calls'] if row['call_name'] == 'get')
    assert call.get('dispatch_resolution') == 'unresolved'
    assert call.get('dispatch_port_eligible') is False
    with pytest.raises(SemanticOperationEffectError, match='unresolved'):
        validate_operation_effects(query_operation(), 'subject.py::query', found)


def test_returned_receiver_across_await_remains_unadmitted(tmp_path: Path) -> None:
    found = inventory(tmp_path, 'async def query(client):\n    response = await client.request()\n    return response.json()\n')
    function = next(row for row in found['functions'] if row['symbol'] == 'subject.py::query')
    call = next(row for row in function['calls'] if row['call_name'] == 'json')
    assert call.get('dispatch_resolution') == 'unresolved'
    assert call.get('dispatch_port_eligible') is False


def test_same_line_opaque_calls_cannot_escape_column_ambiguity(tmp_path: Path) -> None:
    found = inventory(tmp_path, 'def query(left, right): return left.get("x") + right.get("y")\n')
    function = next(row for row in found['functions'] if row['symbol'] == 'subject.py::query')
    calls = [row for row in function['calls'] if row['call_name'] == 'get']
    assert len(calls) == 2
    assert all(row.get('dispatch_resolution') == 'unresolved' and row.get('dispatch_port_eligible') is False for row in calls)


@pytest.mark.parametrize('source', [
    'def query(value):\n    for item in [1]:\n        value.get("key")\n',
    'def query(value):\n    try:\n        value.get("key")\n    finally:\n        pass\n',
    'def query(*values):\n    return values.get("key")\n',
    'def query(**values):\n    return values.get("key")\n',
])
def test_unsupported_flow_never_erases_an_opaque_receiver(tmp_path: Path, source: str) -> None:
    found = inventory(tmp_path, source)
    with pytest.raises(SemanticOperationEffectError, match='unresolved'):
        validate_operation_effects(query_operation(), 'subject.py::query', found)


@pytest.mark.parametrize('source', [
    'async def query(value):\n    bound = value.get\n    return bound("key")\n',
    'def query(value):\n    bound = value.get\n    for item in [1]:\n        bound("key")\n',
])
def test_bound_opaque_callback_does_not_escape_through_unsupported_flow(tmp_path: Path, source: str) -> None:
    found = inventory(tmp_path, source)
    with pytest.raises(SemanticOperationEffectError, match='unresolved'):
        validate_operation_effects(query_operation(), 'subject.py::query', found)

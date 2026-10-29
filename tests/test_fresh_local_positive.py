"""Positive local allocation and adverse guard removal; SOURCE PREPARED ONLY."""
from pathlib import Path
from typing import Any

import pytest

from bcf_governance.tooling.semantic_ownership_inventory import discover_python_source, resolve_python_imports
from bcf_governance.tooling.semantic_operation_effects import SemanticOperationEffectError, validate_operation_effects


SOURCE = '''class Cell:
    def __init__(self):
        self._cache = None
        self._cache_expires_at = 0.0
    def clear_cache(self):
        self._cache = None
        self._cache_expires_at = 0.0

def entry():
    value = Cell()
    value.clear_cache()
'''


def discover(tmp_path: Path, source: str) -> dict[str, Any]:
    p = tmp_path / 'subject.py'
    p.write_text(source)
    return resolve_python_imports(tmp_path, discover_python_source(tmp_path, [p]))


def operation() -> dict[str, Any]:
    return {'id': 'query', 'allowed_mutation_ports': [], 'allowed_authority_ports': [],
            'non_authoritative_output_effects': []}


def entry(found: dict[str, Any]) -> dict[str, Any]:
    return next(f for f in found['functions'] if f['symbol'] == 'subject.py::entry')


def test_literal_stores_on_fresh_local_receiver_are_positive_without_write_ports(tmp_path: Path) -> None:
    found = discover(tmp_path, SOURCE)
    caller = entry(found)
    assert validate_operation_effects(operation(), caller['symbol'], found) == (0, 0)
    local = caller['fresh_local_receiver_effects']
    assert local['escape'] is False
    assert len(local['initializer_writes']) == len(local['method_writes']) == 2
    assert {r['attribute'] for r in local['method_writes']} == {'_cache', '_cache_expires_at'}
    assert all(c['dispatch_resolution'] == 'exact_source_fresh_local_context' for c in caller['calls'])
    assert all(c['fresh_local_receiver_effects']['return_fact'] == 'fallthrough_none' for c in caller['calls'])
    # A callee is never classified globally pure or stripped of its source facts.
    method = next(f for f in found['functions'] if f['symbol'] == 'subject.py::Cell.clear_cache')
    assert 'fresh_local_receiver_effects' not in method
    assert next(c for c in found['classes'] if c['symbol'] == 'subject.py::Cell')


ADVERSES = {
    'await': SOURCE.replace('def entry():', 'async def entry():').replace('    value.clear_cache()', '    await external()\n    value.clear_cache()'),
    'escape': SOURCE.replace('    value.clear_cache()', '    escape(value)\n    value.clear_cache()'),
    'alias-escape': SOURCE.replace('    value.clear_cache()', '    alias = value\n    escape(alias)\n    value.clear_cache()'),
    'unknown-callback': SOURCE.replace('    value.clear_cache()', '    callback()\n    value.clear_cache()'),
    'return-escape': SOURCE + '    return value\n',
    'initializer-call': SOURCE.replace('        self._cache = None', '        self._cache = external()', 1),
    'method-call': SOURCE.replace('    def clear_cache(self):\n', '    def clear_cache(self):\n        callback()\n'),
    'opaque-value-store': SOURCE.replace('        self._cache = None', '        self._cache = external_value'),
    'instance-hook': SOURCE.replace('class Cell:\n', 'class Cell:\n    def __setattr__(self, name, value):\n        external()\n'),
    'descriptor': SOURCE.replace('    def clear_cache(self):', '    @property\n    def clear_cache(self):'),
    'inheritance': SOURCE.replace('class Cell:', 'class Cell(External):'),
    'method-rebound': SOURCE.replace('\ndef entry():', '\nCell.clear_cache = external\n\ndef entry():'),
    'dunder-store': SOURCE.replace('self._cache = None', 'self.__class__ = None'),
    'extra-caller-effect': SOURCE + '    publish()\n',
    'parameter-receiver': SOURCE.replace('def entry():\n    value = Cell()', 'def entry(value):\n    value = value'),
}


@pytest.mark.parametrize('source', ADVERSES.values(), ids=ADVERSES.keys())
def test_source_guard_removal_cannot_reuse_local_ownership_positive(tmp_path: Path, source: str) -> None:
    found = discover(tmp_path, source)
    caller = entry(found)
    assert 'fresh_local_receiver_effects' not in caller
    with pytest.raises(SemanticOperationEffectError):
        validate_operation_effects(operation(), caller['symbol'], found)


def test_local_proof_does_not_discharge_an_opaque_call_elsewhere(tmp_path: Path) -> None:
    found = discover(tmp_path, SOURCE + '\ndef opaque(value):\n    value.clear_cache()\n')
    with pytest.raises(SemanticOperationEffectError):
        validate_operation_effects(operation(), 'subject.py::opaque', found)

from __future__ import annotations

import json
from pathlib import Path

from bcf_governance.tooling.semantic_ownership_inventory import (
    discover_python_source,
    resolve_python_imports,
)


FIXTURES = Path(__file__).parent / 'fixtures'


def _source(root: Path) -> Path:
    source = root / 'model.py'
    source.write_bytes((FIXTURES / 'semantic-python-inventory-source.txt').read_bytes())
    return source


def test_python_inventory_matches_pre_deconstruction_characterization(tmp_path):
    source = _source(tmp_path)
    before = source.read_bytes()
    expected = json.loads((FIXTURES / 'semantic-python-inventory-before-deconstruction.json').read_text())
    discovered = discover_python_source(tmp_path, files=[source])
    assert discovered == expected['discovered']
    assert resolve_python_imports(tmp_path, discovered) == expected['resolved']
    assert source.read_bytes() == before
    assert discovered['endpoints'][0]['path'] == '/api/rows/{name}'
    assert any(function['unresolved'] for function in discovered['functions'])
    assert any('classmethod' in function['decorators'] for function in discovered['functions'])


def test_python_inventory_characterization_observes_source_call_mutation(tmp_path):
    source = _source(tmp_path)
    source.write_text(source.read_text().replace('.read_text()', '.write_text("changed")'))
    discovered = discover_python_source(tmp_path, files=[source])
    reader = next(function for function in discovered['functions'] if function['symbol'] == 'model.py::Repository.read')
    assert 'write_text' in {call['call_name'] for call in reader['calls']}
    assert 'read_text' not in {call['call_name'] for call in reader['calls']}
    expected = json.loads((FIXTURES / 'semantic-python-inventory-before-deconstruction.json').read_text())
    assert discovered['files'] != expected['discovered']['files']
    assert discovered != expected['discovered']

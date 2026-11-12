from __future__ import annotations

import ast
from copy import deepcopy
import json
import hashlib

import pytest
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



def _pre_deconstruction_view(inventory, source):
    """Validate additive facts independently, then preserve every historical field."""
    nodes = ast.parse(source.read_text())
    call_nodes = {(node.lineno, node.col_offset, node.end_lineno, node.end_col_offset): node for node in ast.walk(nodes) if isinstance(node, ast.Call)}
    spans = {
        (node.lineno, node.col_offset, node.end_lineno, node.end_col_offset)
        for node in ast.walk(nodes) if isinstance(node, ast.Call)
    }
    symbols = {function['symbol'] for function in inventory['functions']}

    def fact_view(fact):
        actual = dict(fact)
        span = (actual['line'], actual['column'], actual['end_line'], actual['end_column'])
        assert span in spans
        expression = call_nodes[span]
        owner = actual['caller'].partition('::')[2]
        members = nodes.body
        for name in owner.split('.')[:-1]:
            declarations = [node for node in members if isinstance(node, ast.ClassDef) and node.name == name]
            assert len(declarations) == 1
            members = declarations[0].body
        declarations = [node for node in members if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
                        and node.name == owner.split('.')[-1] and node.lineno <= span[0] <= node.end_lineno]
        assert len(declarations) == 1
        declaration = declarations[0]
        parameters = {arg.arg for arg in declaration.args.posonlyargs + declaration.args.args + declaration.args.kwonlyargs}
        bindings = {name: {name} for name in parameters}
        assignments = sorted((node for node in ast.walk(declaration)
                              if isinstance(node, (ast.Assign, ast.AnnAssign)) and node.lineno < span[0]),
                             key=lambda node: (node.lineno, node.col_offset))
        for assignment in assignments:
            value = assignment.value
            if value is None:
                continue
            roots = {node.id for node in ast.walk(value) if isinstance(node, ast.Name)}
            derived = set().union(*(bindings.get(name, set()) for name in roots))
            assigned = assignment.targets if isinstance(assignment, ast.Assign) else [assignment.target]
            for target in assigned:
                if isinstance(target, ast.Name):
                    bindings[target.id] = bindings.get(target.id, set()) | derived
        targets = {node.id for node in ast.walk(expression.func) if isinstance(node, ast.Name)}
        derived = set().union(*(bindings.get(name, set()) for name in targets))
        expected_origins = sorted('parameter:' + name for name in derived)
        # The immutable fixture's self-method dispatch remains with the existing owner.
        if owner.startswith('Repository.') and 'self' in targets:
            expected_origins = []
        if expected_origins:
            assert actual.pop('runtime_target_origins') == expected_origins
        else:
            assert 'runtime_target_origins' not in actual
        for key in ('column', 'end_line', 'end_column'):
            actual.pop(key)
        if 'construction_effect_observation' in actual:
            observation = actual.pop('construction_effect_observation')
            assert set(observation) == {
                'authority', 'source_class_resolved', 'class_candidates',
                'function_candidates', 'unresolved', 'qualification',
            }
            assert observation['authority'] is False
            assert observation['source_class_resolved'] is True
            assert observation['class_candidates'] == ['model.py::Repository']
            assert 'model.py::Repository.__init__' in observation['function_candidates']
            assert set(observation['function_candidates']) <= symbols
            assert all(isinstance(value, str) and value for value in observation['unresolved'])
            assert observation['qualification'] == 'SOURCE_OBLIGATIONS_ONLY_RUNTIME_PROVENANCE_REQUIRED'
        return actual

    result = dict(inventory)
    result['classes'] = []
    for row in inventory['classes']:
        actual = dict(row)
        # The immutable fixture has annotations and methods, no descriptor-valued assignment.
        assert actual.pop('descriptor_bindings') == []
        result['classes'].append(actual)
    result['functions'] = []
    for row in inventory['functions']:
        actual = dict(row)
        if row['symbol'] == 'model.py::Repository.__init__':
            declaration = next(node for node in nodes.body if isinstance(node, ast.ClassDef) and node.name == 'Repository')
            method = next(node for node in declaration.body if isinstance(node, ast.FunctionDef) and node.name == '__init__')
            stores = [node for node in ast.walk(method) if isinstance(node, ast.Attribute) and isinstance(node.ctx, (ast.Store, ast.Del))]
            assert len(stores) == 1
            node = stores[0]
            digest = hashlib.sha256(ast.dump(node, include_attributes=False).encode()).hexdigest()
            assert actual.pop('source_store_observations') == [{
                'authority': False, 'execution_qualified': False, 'caller': row['symbol'],
                'kind': 'attribute_store', 'phase': 'operation_eager',
                'expression_sha256': digest, 'occurrence': 0,
                'line': node.lineno, 'column': node.col_offset,
                'end_line': node.end_lineno, 'end_column': node.end_col_offset,
                'disposition': 'unresolved_object_binding',
            }]
            assert actual.pop('effects') == [{
                'kind': 'unresolved', 'target': 'attribute', 'scope': 'object_binding',
                'line': node.lineno, 'column': node.col_offset, 'source_store_key': digest + ':0',
            }]
        if 'effect_unresolved' in actual and row.get('decorators') in (['classmethod'], ['staticmethod']):
            # New fail-closed uncertainty is checked before comparing the immutable old view.
            scope = row['symbol'].partition('::')[2].split('.')
            members = nodes.body
            for owner in scope[:-1]:
                declarations = [node for node in members
                                if isinstance(node, ast.ClassDef) and node.name == owner]
                assert len(declarations) == 1
                members = declarations[0].body
            declarations = [node for node in members
                            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
                            and node.name == scope[-1]]
            assert len(declarations) == 1
            assert [ast.unparse(value) for value in declarations[0].decorator_list] == row['decorators']
            assert actual['effect_unresolved'] == [{
                'kind': 'ambiguous_method_definition', 'dispatch_kind': 'decorated_method',
                'symbol': row['symbol'], 'decorators': row['decorators'],
            }]
            actual['effect_unresolved'] = []
        for key in ('calls', 'constructors', 'normalizations'):
            actual[key] = [fact_view(fact) for fact in row[key]]
        result['functions'].append(actual)
    for key in ('constructors', 'normalizations'):
        result[key] = [fact_view(fact) for fact in inventory[key]]
    return result


def test_python_inventory_matches_pre_deconstruction_characterization(tmp_path):
    source = _source(tmp_path)
    before = source.read_bytes()
    expected = json.loads((FIXTURES / 'semantic-python-inventory-before-deconstruction.json').read_text())
    discovered = discover_python_source(tmp_path, files=[source])
    assert _pre_deconstruction_view(discovered, source) == expected['discovered']
    assert _pre_deconstruction_view(resolve_python_imports(tmp_path, discovered), source) == expected['resolved']
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
    assert _pre_deconstruction_view(discovered, source) != expected['discovered']


@pytest.mark.parametrize('defect', ('old-field', 'unrecognized-field', 'span', 'descriptor', 'authority', 'decorator-uncertainty', 'decorator-erasure', 'decorator-symbol'))
def test_characterization_view_does_not_hide_unaccounted_changes(tmp_path, defect):
    source = _source(tmp_path)
    inventory = resolve_python_imports(tmp_path, discover_python_source(tmp_path, files=[source]))
    inventory = deepcopy(inventory)
    function = next(row for row in inventory['functions'] if row['calls'])
    call = function['calls'][0]
    if defect == 'old-field':
        call['called_symbol'] = 'forged.py::old-field'
    elif defect == 'unrecognized-field':
        call['unrecognized_authority'] = True
    elif defect == 'span':
        call['column'] += 10000
    elif defect == 'descriptor':
        inventory['classes'][0]['descriptor_bindings'] = ['forged']
    elif defect.startswith('decorator-'):
        decorated = next(row for row in inventory['functions'] if row.get('decorators') == ['staticmethod'])
        if defect == 'decorator-erasure':
            decorated['effect_unresolved'] = []
        elif defect == 'decorator-symbol':
            decorated['effect_unresolved'][0]['symbol'] = 'forged.py::other'
        else:
            decorated['effect_unresolved'][0]['authority'] = True
    else:
        constructor = inventory['constructors'][0]
        constructor['construction_effect_observation']['authority'] = True
    if defect in {'old-field', 'unrecognized-field'}:
        expected = json.loads((FIXTURES / 'semantic-python-inventory-before-deconstruction.json').read_text())
        assert _pre_deconstruction_view(inventory, source) != expected['resolved']
    else:
        with pytest.raises(AssertionError):
            _pre_deconstruction_view(inventory, source)


@pytest.mark.parametrize('defect', ('authority', 'span', 'local-disposition', 'drop-effect'))
def test_characterization_attribute_additions_cannot_hide_forgery(tmp_path, defect):
    source = _source(tmp_path)
    inventory = deepcopy(resolve_python_imports(tmp_path, discover_python_source(tmp_path, files=[source])))
    function = next(row for row in inventory['functions'] if row['symbol'] == 'model.py::Repository.__init__')
    observations = function.get('source_store_observations', [])
    assert observations, 'attribute source store observations omitted'
    if defect == 'authority':
        observations[0]['authority'] = True
    elif defect == 'span':
        observations[0]['column'] += 1
    elif defect == 'local-disposition':
        observations[0]['disposition'] = 'closed_native_literal_region'
    else:
        function['effects'] = []
    with pytest.raises(AssertionError):
        _pre_deconstruction_view(inventory, source)


@pytest.mark.parametrize('defect', ('erasure', 'wrong-parameter', 'duplicate', 'empty'))
def test_characterization_runtime_target_origins_cannot_hide_changes(tmp_path, defect):
    source = _source(tmp_path)
    inventory = deepcopy(resolve_python_imports(tmp_path, discover_python_source(tmp_path, files=[source])))
    function = next(row for row in inventory['functions'] if row['symbol'] == 'model.py::Repository.from_root')
    call = function['calls'][0]
    assert call.get('runtime_target_origins') == ['parameter:cls'], 'runtime target origins omitted'
    if defect == 'erasure':
        del call['runtime_target_origins']
    elif defect == 'wrong-parameter':
        call['runtime_target_origins'] = ['parameter:root']
    elif defect == 'duplicate':
        call['runtime_target_origins'] *= 2
    else:
        call['runtime_target_origins'] = []
    with pytest.raises((AssertionError, KeyError)):
        _pre_deconstruction_view(inventory, source)

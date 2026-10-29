"""Whole original BCF module dependency witnesses never discharge guards."""
from pathlib import Path
from typing import Any

import pytest

from bcf_governance.tooling.semantic_ownership_inventory import discover_python_source, resolve_python_imports
from bcf_governance.tooling.semantic_operation_effects import SemanticOperationEffectError, validate_operation_effects

ORIGINAL = (Path(__file__).resolve().parents[1] / 'fixtures/bcf/semantic_python_return_facts.py').read_text()


def found(tmp_path: Path, source: str = ORIGINAL) -> dict[str, Any]:
    (tmp_path / 'facts.py').write_text(source)
    (tmp_path / 'consumer.py').write_text('from facts import _unknown\ndef entry():\n    return _unknown("origin_budget")\n')
    return resolve_python_imports(tmp_path, discover_python_source(tmp_path, sorted(tmp_path.glob('*.py'))))


def dependencies(value: dict[str, Any]) -> dict[str, Any]:
    return next(row for row in value['binding_dependencies'] if row['source_path'] == 'facts.py')


def refuses(value: dict[str, Any]) -> None:
    operation = {'id': 'query', 'allowed_mutation_ports': [], 'allowed_authority_ports': [],
                 'non_authoritative_output_effects': []}
    with pytest.raises(SemanticOperationEffectError):
        validate_operation_effects(operation, 'consumer.py::entry', value)


def accepts(value: dict[str, Any]) -> None:
    operation = {'id': 'query', 'allowed_mutation_ports': [], 'allowed_authority_ports': [],
                 'non_authoritative_output_effects': []}
    assert validate_operation_effects(operation, 'consumer.py::entry', value) == (0, 0)


def test_actual_three_field_reads_keep_set_input_and_lifetime_dependencies(tmp_path: Path) -> None:
    value = found(tmp_path)
    facts = dependencies(value)
    reads = facts['field_alias_reads']
    assert {r['read']['line'] for r in reads} == {246, 277, 291}
    for read in reads:
        assert read['field'] == 'locals' and read['owner'].startswith('facts.py::_Flow.')
        stores = read['candidate_source_stores']
        assert len(stores) == 1 and stores[0]['initializer'] is True
        assert stores[0]['assigned_input_kind'] == 'builtin_set_expression'
        assert stores[0]['receiver_store_semantics'] == 'UNPROVEN'
        assert read['receiver_lifetime'] == read['read_value_identity'] == 'UNPROVEN'
        assert read['permits_acceptance'] is False
    assert facts['identity_authority'] is False and facts['budget_exhausted'] is False
    assert value['namespace_value_contracts']['closed'] is True
    assert len(value['namespace_value_contracts']['aliases']) == 3
    accepts(value)


def test_actual_ast_argument_escapes_gain_expression_and_consumer_witnesses(tmp_path: Path) -> None:
    value = found(tmp_path)
    rows = dependencies(value)['module_argument_dependencies']
    ast_rows = [r for r in rows if r['source_root_name'] == 'ast']
    assert len(ast_rows) == 22
    for row in ast_rows:
        assert row['declared_import_module'] == 'ast'
        assert row['original_escape']['role'] == 'argument'
        assert row['alternatives']
        assert row['ambiguous_span'] is (len(row['alternatives']) != 1)
        for alternative in row['alternatives']:
            assert alternative['argument']['AST_sha256']
            assert alternative['consumer_AST']
            assert alternative['consumer_contract'] == 'UNPROVEN'
            assert alternative['projected_value_identity'] == 'UNPROVEN'
        assert row['permits_acceptance'] is False
    assert len(value['namespace_value_contracts']['escapes']) == 22
    accepts(value)


def test_mutator_field_input_cannot_reuse_set_expression_witness(tmp_path: Path) -> None:
    source = ORIGINAL.replace(
        'self.locals = {value.id for value in nodes\n                       if isinstance(value, ast.Name) and isinstance(value.ctx, (ast.Store, ast.Del))}',
        'self.locals = locals')
    assert source != ORIGINAL
    value = found(tmp_path, source)
    reads = dependencies(value)['field_alias_reads']
    assert reads
    for read in reads:
        assert read['candidate_source_stores'][0]['assigned_input_kind'] == 'possible_namespace_mutator_reference'
        assert read['permits_acceptance'] is False
    refuses(value)


def test_direct_module_argument_is_distinct_from_an_attribute_projection(tmp_path: Path) -> None:
    source = ORIGINAL.replace('isinstance(node, ast.Name)', 'isinstance(node, ast)', 1)
    assert source != ORIGINAL
    value = found(tmp_path, source)
    rows = dependencies(value)['module_argument_dependencies']
    assert any(a['argument_is_imported_root'] is True
               for row in rows for a in row['alternatives'])
    refuses(value)


def test_import_name_does_not_authenticate_a_stdlib_projection(tmp_path: Path) -> None:
    value = found(tmp_path, ORIGINAL.replace('import ast\n', 'import foreign_provider as ast\n', 1))
    rows = dependencies(value)['module_argument_dependencies']
    assert any(row['declared_import_module'] == 'foreign_provider' for row in rows)
    assert all(row['loader_binding'] == 'UNPROVEN' and row['permits_acceptance'] is False for row in rows)
    refuses(value)

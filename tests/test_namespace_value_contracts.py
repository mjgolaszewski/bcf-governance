"""Restore original real positives only through exact value/consumer contracts."""
from pathlib import Path
from typing import Any

import pytest

from bcf_governance.tooling.semantic_ownership_inventory import discover_python_source, resolve_python_imports
from bcf_governance.tooling.semantic_operation_effects import SemanticOperationEffectError, validate_operation_effects

ORIGINAL = (Path(__file__).resolve().parents[1] / 'fixtures/bcf/semantic_python_return_facts.py').read_text()
FIELD = 'self.locals = {value.id for value in nodes\n                       if isinstance(value, ast.Name) and isinstance(value.ctx, (ast.Store, ast.Del))}'


def inventory(tmp_path: Path, source: str, *, shadow: bool = False) -> dict[str, Any]:
    (tmp_path / 'facts.py').write_text(source)
    (tmp_path / 'consumer.py').write_text('from facts import _unknown\ndef entry():\n    return _unknown("origin_budget")\n')
    if shadow:
        (tmp_path / 'ast.py').write_text('Name = object\n')
    discovered = discover_python_source(tmp_path, sorted(tmp_path.glob('*.py')))
    found = resolve_python_imports(tmp_path, discovered)
    assert found['return_facts'] == discovered['return_facts']
    assert found['definition_time_obligations'] == discovered['definition_time_obligations']
    assert all(s['namespace_mutations'] for s in found['descriptor_syntax'] if s['path'] == 'facts.py')
    return found


def op() -> dict[str, Any]:
    return {'id': 'query', 'allowed_mutation_ports': [], 'allowed_authority_ports': [],
            'non_authoritative_output_effects': []}


def test_real_complete_module_discharge_is_value_nonretention_not_body_purity(tmp_path: Path) -> None:
    found = inventory(tmp_path, ORIGINAL)
    contracts = found['namespace_value_contracts']
    assert contracts['closed'] is True
    assert len(contracts['aliases']) == 3 and len(contracts['escapes']) == 22
    assert all(c['other_body_effects'] == 'PRESERVED' for c in contracts['aliases'])
    assert all(c['input_and_body_effects'] == 'PRESERVED_UNRESOLVED' for c in contracts['escapes'])
    assert validate_operation_effects(op(), 'consumer.py::entry', found) == (0, 0)
    with pytest.raises(SemanticOperationEffectError):
        validate_operation_effects(op(), 'facts.py::_Flow.expression', found)
    with pytest.raises(SemanticOperationEffectError):
        validate_operation_effects(op(), 'consumer.py::entry', found, source_modules=('facts.py',))


ADVERSES = {
    'field-mutator': ORIGINAL.replace(FIELD, 'self.locals = locals'),
    'receiver-alias': ORIGINAL.replace('    def facts(self)', '    def export(self):\n        return self\n\n    def facts(self)', 1),
    'method-alias': ORIGINAL.replace('    def facts(self)', '    def export(self):\n        return self.facts\n\n    def facts(self)', 1),
    'getter-hook': ORIGINAL.replace('class _Flow:\n', 'class _Flow:\n    def __getattribute__(self, name):\n        return external()\n', 1),
    'class-export': ORIGINAL + '\nexported = _Flow\n',
    'field-rebound': ORIGINAL + '\n_Flow.locals = property(external)\n',
    'ast-module-argument': ORIGINAL.replace('isinstance(node, ast.Name)', 'isinstance(node, ast)', 1),
    'ast-provider': ORIGINAL.replace('import ast\n', 'import foreign_provider as ast\n', 1),
    'builtin-shadow': ORIGINAL + '\nisinstance = external\n',
    'builtin-any-shadow': ORIGINAL + '\nany = external\n',
    'builtin-len-shadow': ORIGINAL + '\nlen = external\n',
    'metadata-rebound': ORIGINAL + '\nast.Name = external\n',
    'metaclass-hook': ORIGINAL + '\nast.Name.__instancecheck__ = external\n',
    'generator-retained': ORIGINAL.replace('if any(isinstance(part, ast.Name)', 'if external(isinstance(part, ast.Name)', 1),
    'defaults-mutated': ORIGINAL + '\n_unknown.__defaults__ = (True,)\n',
    'loader-alias': ORIGINAL + '\nimport sys\ncache = sys.modules\n',
    'later-field-write': ORIGINAL + '\ndef mutate(value):\n    value.locals = external\n',
    'qualified-class-export': ORIGINAL + '\nimport facts\nexported = facts._Flow\n',
    'wildcard-binding': ORIGINAL + '\nfrom provider import *\n',
}


@pytest.mark.parametrize('source', ADVERSES.values(), ids=ADVERSES.keys())
def test_guard_removal_retains_whole_source_binding_refusal(tmp_path: Path, source: str) -> None:
    assert source != ORIGINAL
    found = inventory(tmp_path, source)
    assert found['namespace_value_contracts']['closed'] is False
    with pytest.raises(SemanticOperationEffectError):
        validate_operation_effects(op(), 'consumer.py::entry', found)


def test_project_ast_shadow_is_not_a_stdlib_contract(tmp_path: Path) -> None:
    found = inventory(tmp_path, ORIGINAL, shadow=True)
    assert found['namespace_value_contracts']['closed'] is False
    with pytest.raises(SemanticOperationEffectError):
        validate_operation_effects(op(), 'consumer.py::entry', found)

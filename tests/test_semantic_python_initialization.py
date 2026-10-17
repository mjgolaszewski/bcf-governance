from pathlib import Path

import pytest

from bcf_governance.tooling.semantic_ownership_inventory import (
    SemanticInventoryError, discover_python_source,
)


def discover(root: Path, source: str):
    path = root / "model.py"
    path.write_text(source)
    return discover_python_source(root, files=[path], initialization_contracts_version="1.0")


def test_initialization_excludes_deferred_bodies_and_retains_definition_effects(tmp_path):
    result = discover(tmp_path, "top()\n@decorate\ndef work(x=default()):\n    deferred()\nclass C(base()):\n    body()\n    def method(self):\n        later()\n")
    facts = result["module_initializers"][0]
    assert facts["authority"] is False
    assert facts["execution_qualified"] is False
    assert [row["call_name"] for row in facts["sites"] if row["kind"] == "call"] == ["top", "default", "base", "body"]
    assert {row["kind"] for row in facts["sites"]} >= {"decorator_application", "class_construction"}
    assert facts["unresolved"]


def test_imports_annotations_and_deferred_expressions_remain_conservative(tmp_path):
    result = discover(tmp_path, "if flag:\n    from unknown import *\ndef f(x: annotation()):\n    pass\nf = lambda: deferred()\ng = (deferred_generator(x) for x in iterable())\n")
    facts = result["module_initializers"][0]
    assert any(row["kind"] == "import" for row in facts["sites"])
    assert {row["reason"] for row in facts["unresolved"]} >= {"import_execution", "annotation_evaluation", "deferred_expression"}
    calls = [row["call_name"] for row in facts["sites"] if row["kind"] == "call"]
    assert "deferred" not in calls
    assert "deferred_generator" not in calls


@pytest.mark.parametrize("version", ["", "2.0", 1, True, []])
def test_unknown_initialization_version_rejects_before_reads(tmp_path, version):
    with pytest.raises(SemanticInventoryError, match="initialization contract version"):
        discover_python_source(tmp_path, files=[tmp_path / "missing.py"], initialization_contracts_version=version)


def test_default_inventory_and_existing_function_facts_are_unchanged(tmp_path):
    path = tmp_path / 'model.py'
    path.write_text('top()\ndef work():\n    inside()\n')
    legacy = discover_python_source(tmp_path, files=[path])
    assert discover_python_source(tmp_path, files=[path], initialization_contracts_version=None) == legacy
    opted = discover_python_source(tmp_path, files=[path], initialization_contracts_version='1.0')
    for key, value in legacy.items():
        assert opted[key] == value
    assert 'module_initializers' not in legacy


def test_initialization_identity_is_stable_and_literal_values_are_not_emitted(tmp_path):
    import json

    source = "send('private-token')\nsend('private-token')\n"
    first = discover(tmp_path, source)['module_initializers'][0]
    moved = discover(tmp_path, '\n\n' + source)['module_initializers'][0]
    assert [{k: v for k, v in site.items() if k != 'line'} for site in first['sites']] == [
        {k: v for k, v in site.items() if k != 'line'} for site in moved['sites']
    ]
    assert [site['occurrence'] for site in first['sites']] == [0, 1]
    assert 'private-token' not in json.dumps(first)
    changed = discover(tmp_path, source.replace('private-token', 'changed'))['module_initializers'][0]
    assert first['sites'][0]['expression_sha256'] != changed['sites'][0]['expression_sha256']


def test_initialization_schema_rejects_authority_and_malformed_sites(tmp_path):
    import copy
    import json
    from jsonschema import Draft202012Validator

    schema = json.loads((Path(__file__).parents[1] / 'schemas/semantic-initialization-contracts.schema.json').read_text())
    validator = Draft202012Validator(schema)
    result = discover(tmp_path, 'execute()\n')
    validator.validate(result)
    for field, value in [('authority', True), ('execution_qualified', True), ('scope', 'complete')]:
        changed = copy.deepcopy(result)
        changed['module_initializers'][0][field] = value
        assert list(validator.iter_errors(changed))
    for field, value in [('expression_sha256', 'invalid'), ('occurrence', True), ('kind', 'pure')]:
        changed = copy.deepcopy(result)
        changed['module_initializers'][0]['sites'][0][field] = value
        assert list(validator.iter_errors(changed))
    del result['module_initializers'][0]['sites'][0]['call_name']
    assert list(validator.iter_errors(result))


def test_async_definition_and_class_keywords_retain_effects_without_method_bodies(tmp_path):
    result = discover(tmp_path, '@factory()\nclass C(base(), metaclass=choose()):\n    @decorate\n    async def work(self, x=default(), *, y=keyword_default()) -> annotation():\n        await deferred()\n')
    facts = result['module_initializers'][0]
    assert [row['call_name'] for row in facts['sites'] if row['kind'] == 'call'] == [
        'factory', 'base', 'choose', 'default', 'keyword_default'
    ]
    assert len([row for row in facts['sites'] if row['kind'] == 'decorator_application']) == 2
    assert any(row['reason'] == 'annotation_evaluation' for row in facts['unresolved'])


def test_dynamic_immediate_invocation_and_generator_input_keep_uncertainty(tmp_path):
    result = discover(tmp_path, '(lambda: hidden())()\ng = (later(x) for x in outer())\nexec("opaque()")\n')
    facts = result['module_initializers'][0]
    assert [row['call_name'] for row in facts['sites'] if row['kind'] == 'call'] == [
        '<dynamic>', 'outer', 'exec'
    ]
    assert len([row for row in facts['unresolved'] if row['reason'] == 'deferred_expression']) == 2
    assert facts['execution_qualified'] is False


def test_conditional_calls_and_class_annotated_value_are_possible_sites(tmp_path):
    result = discover(tmp_path, 'if condition():\n    import unknown\nelse:\n    alternative()\nclass C:\n    value: annotation() = initializer()\n')
    facts = result['module_initializers'][0]
    assert [row['call_name'] for row in facts['sites'] if row['kind'] == 'call'] == [
        'condition', 'alternative', 'initializer'
    ]
    assert any(row['kind'] == 'annotation' for row in facts['sites'])
    assert any(row['kind'] == 'import' for row in facts['sites'])
    assert any(row['reason'] == 'metaclass_and_implicit_class_hooks' for row in facts['unresolved'])


def test_empty_explicit_site_population_cannot_claim_effect_completeness(tmp_path):
    facts = discover(tmp_path, 'result = left + right\n')['module_initializers'][0]
    assert facts['sites'] == []
    assert facts['execution_qualified'] is False
    assert facts['completeness_qualified'] is False
    assert facts['limitations'] == [
        'implicit_protocol_effects_not_enumerated',
        'external_native_dynamic_execution_not_resolved',
    ]

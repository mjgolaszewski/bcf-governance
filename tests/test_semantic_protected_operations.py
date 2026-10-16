from __future__ import annotations

import copy
import hashlib
import shutil
from pathlib import Path

import pytest
import yaml

from bcf_governance.tooling import semantic_authority_contracts as owner
from bcf_governance.tooling.semantic_ownership_inventory import discover_python_source


@pytest.fixture
def inputs(tmp_path):
    (tmp_path / 'schemas').mkdir()
    shutil.copy2(Path(__file__).parents[1] / 'schemas/application-operations.schema.json', tmp_path / 'schemas/application-operations.schema.json')
    source = tmp_path / 'runtime.py'
    source.write_text('def work():\n    return 1\nCOMMANDS = {"work": work}\n')
    payload = dict(schema_version='1.0', document=dict(kind='application_operation_registry', id='example-operations', version='1.0.0', status='active', path='governance/application-operations.yml'), populations=[dict(id='cli', adapter='python_mapping', source='runtime.py', symbol='COMMANDS', public_only=True)], operations=[dict(id='example.work.v1', population='cli', population_key='work', family='example', bounded_context='example', entrypoints=['runtime.py::work'], semantic_kind='query', authoritative_read=True, authoritative_mutation=False, authority_conferral=False, produces_projection=False, model_callable=False, allowed_mutation_ports=[], allowed_authority_ports=[], non_authoritative_output_effects=[])], migrations=[])
    path = tmp_path / 'governance/application-operations.yml'
    path.parent.mkdir()
    path.write_text(yaml.safe_dump(payload, sort_keys=False))
    return tmp_path, source, path, hashlib.sha256(path.read_bytes()).hexdigest()


def run(inputs, digest=None):
    root, source, path, original = inputs
    return owner.required_application_operation_population(root, discover_python_source(root, files=[source]), expected_registry_sha256=original if digest is None else digest)


def test_protected_operations_are_source_derived_and_deterministic(inputs):
    first = run(inputs)
    assert first['authority'] is False
    assert first['execution_qualified'] is False
    assert first['registry_sha256'] == inputs[3]
    assert first['operations'] == (('example.work.v1', 'query', 'runtime.py::work', ()),)
    assert run(inputs) == first


@pytest.mark.parametrize('digest', [None, '', True, 'a' * 63, 'A' * 64])
def test_invalid_protected_registry_digest_rejects_before_discovery(inputs, monkeypatch, digest):
    monkeypatch.setattr(owner, '_discover_population', lambda *a, **kw: pytest.fail('source discovered without protected registry identity'))
    with pytest.raises(owner.SemanticAuthorityError, match='digest'):
        owner.required_application_operation_population(inputs[0], {}, expected_registry_sha256=digest)


def test_registry_substitution_rejects_before_discovery(inputs, monkeypatch):
    root, source, path, digest = inputs
    path.write_text(path.read_text().replace('authoritative_read: true', 'authoritative_read: false'))
    monkeypatch.setattr(owner, '_discover_population', lambda *a, **kw: pytest.fail('source discovered after registry substitution'))
    with pytest.raises(owner.SemanticAuthorityError, match='digest'):
        run(inputs)


@pytest.mark.parametrize('change', ['added', 'removed', 'dynamic'])
def test_public_population_changes_cannot_erase_required_operations(inputs, change):
    source = inputs[1]
    if change == 'added':
        source.write_text('def work():\n    return 1\ndef extra():\n    return 2\nCOMMANDS = {"work": work, "extra": extra}\n')
    elif change == 'removed':
        source.write_text('def work():\n    return 1\nCOMMANDS = {}\n')
    else:
        source.write_text('def work():\n    return 1\nCOMMANDS = dict(work=work)\n')
    with pytest.raises(owner.SemanticAuthorityError):
        run(inputs)

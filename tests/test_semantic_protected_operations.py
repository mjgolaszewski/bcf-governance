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


def test_required_population_cannot_be_disabled_by_candidate_capabilities(inputs):
    root, source, path, digest = inputs
    (root / 'governance-profile.yml').write_text('semantic_capabilities: {application_operation_inventory: disabled}\n')
    inventory = discover_python_source(root, files=[source])
    assert owner.validate_application_operations(root, inventory) == []
    result = owner.required_application_operation_population(root, inventory, expected_registry_sha256=digest)
    assert len(result['operations']) == 1


def test_registry_digest_and_decode_use_the_same_captured_bytes(inputs, monkeypatch):
    root, source, path, digest = inputs
    inventory = discover_python_source(root, files=[source])
    real = Path.read_bytes
    reads = []
    def captured(candidate):
        raw = real(candidate)
        if candidate == path:
            reads.append(candidate)
            path.write_text('invalid after capture\n')
        return raw
    monkeypatch.setattr(Path, 'read_bytes', captured)
    result = owner.required_application_operation_population(root, inventory, expected_registry_sha256=digest)
    assert reads == [path]
    assert result['registry_sha256'] == digest
    assert result['operations'][0][0] == 'example.work.v1'


def test_removing_registry_entry_and_source_entry_cannot_self_exempt(inputs):
    root, source, path, _ = inputs
    payload = yaml.safe_load(path.read_text())
    extra = copy.deepcopy(payload['operations'][0])
    extra.update(id='example.other.v1', population_key='other', entrypoints=['runtime.py::other'])
    payload['operations'].append(extra)
    path.write_text(yaml.safe_dump(payload, sort_keys=False))
    protected_digest = hashlib.sha256(path.read_bytes()).hexdigest()
    source.write_text('def work():\n    return 1\ndef other():\n    return 2\nCOMMANDS = {"work": work, "other": other}\n')
    inventory = discover_python_source(root, files=[source])
    assert len(owner.required_application_operation_population(root, inventory, expected_registry_sha256=protected_digest)['operations']) == 2
    payload['operations'].pop()
    path.write_text(yaml.safe_dump(payload, sort_keys=False))
    source.write_text('def work():\n    return 1\nCOMMANDS = {"work": work}\n')
    inventory = discover_python_source(root, files=[source])
    # Candidate-local structural/effect consistency alone accepts the smaller set.
    assert len(owner._validate_operations(root, payload, inventory)) == 1
    with pytest.raises(owner.SemanticAuthorityError, match='digest'):
        owner.required_application_operation_population(root, inventory, expected_registry_sha256=protected_digest)


def test_protected_factory_preserves_legacy_decode(inputs):
    root, _, _, digest = inputs
    assert owner.load_application_operations(root).raw == owner.load_application_operations(root, expected_sha256=digest).raw


@pytest.fixture
def committed_inputs(inputs):
    import subprocess

    root, source, path, digest = inputs
    def git(*args):
        return subprocess.run(['git', *args], cwd=root, check=True, capture_output=True).stdout.decode().strip()
    git('init', '-q')
    git('config', 'user.name', 'Policy Test')
    git('config', 'user.email', 'policy@example.invalid')
    git('add', '.')
    git('commit', '-qm', 'policy')
    return inputs, git, dict(policy_commit_sha=git('rev-parse', 'HEAD'), policy_tree_sha=git('rev-parse', 'HEAD^{tree}'))


def committed_run(committed_inputs):
    inputs, git, subject = committed_inputs
    root, source, path, digest = inputs
    return owner.required_committed_application_operation_population(root, discover_python_source(root, files=[source]), **subject)


def test_committed_policy_derives_digest_and_reuses_existing_population(committed_inputs):
    inputs, git, subject = committed_inputs
    result = committed_run(committed_inputs)
    assert result['registry_sha256'] == inputs[3]
    assert result['operations'] == run(inputs)['operations']
    assert result['authority'] is False
    assert result['execution_qualified'] is False
    assert result['policy_subject'] == dict(commit_sha=subject['policy_commit_sha'], tree_sha=subject['policy_tree_sha'])


def test_dirty_policy_cannot_supply_its_own_required_digest(committed_inputs, monkeypatch):
    inputs, git, subject = committed_inputs
    inputs[2].write_text(inputs[2].read_text() + '# candidate substitution\n')
    monkeypatch.setattr(owner, '_validate_operations', lambda *args: pytest.fail('discovery before policy check'))
    with pytest.raises(owner.SemanticAuthorityError, match='digest'):
        committed_run(committed_inputs)


@pytest.mark.parametrize('kind', ['missing', 'symlink', 'gitlink'])
def test_committed_policy_requires_a_regular_blob(committed_inputs, kind):
    inputs, git, subject = committed_inputs
    root, source, path, digest = inputs
    path.unlink()
    if kind == 'symlink':
        path.symlink_to('../outside.yml')
    git('add', '-A')
    if kind == 'gitlink':
        git('update-index', '--add', '--cacheinfo', '160000,' + subject['policy_commit_sha'] + ',governance/application-operations.yml')
    git('commit', '-qm', kind)
    subject.update(policy_commit_sha=git('rev-parse', 'HEAD'), policy_tree_sha=git('rev-parse', 'HEAD^{tree}'))
    with pytest.raises(owner.SemanticAuthorityError, match='regular blob'):
        committed_run(committed_inputs)


@pytest.mark.parametrize('change', ['malformed', 'wrong_tree', 'unavailable'])
def test_committed_policy_subject_rejects_before_population(committed_inputs, monkeypatch, change):
    inputs, git, subject = committed_inputs
    if change == 'malformed':
        subject['policy_commit_sha'] = 'HEAD'
    elif change == 'unavailable':
        subject['policy_commit_sha'] = 'a' * 40
    else:
        subject['policy_tree_sha'] = git('rev-parse', 'HEAD:schemas')
    monkeypatch.setattr(owner, '_validate_operations', lambda *args: pytest.fail('population before subject validation'))
    with pytest.raises(owner.SemanticAuthorityError):
        committed_run(committed_inputs)


def test_replacement_ref_cannot_change_committed_policy(committed_inputs):
    inputs, git, subject = committed_inputs
    inputs[2].write_text(inputs[2].read_text() + '# replacement\n')
    git('add', '.')
    git('commit', '-qm', 'replacement')
    git('replace', subject['policy_commit_sha'], git('rev-parse', 'HEAD'))
    inputs[2].write_text(inputs[2].read_text().replace('# replacement\n', ''))
    assert committed_run(committed_inputs)['registry_sha256'] == inputs[3]

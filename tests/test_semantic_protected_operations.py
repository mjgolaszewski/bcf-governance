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


@pytest.mark.parametrize('outcome', ['unavailable', 'substituted'])
def test_committed_policy_blob_read_failure_or_substitution_blocks(committed_inputs, monkeypatch, outcome):
    from bcf_governance.tooling import semantic_source_paths

    original = semantic_source_paths._committed_git
    blob_reads = []
    def read(root, *args):
        if args[:2] == ('cat-file', 'blob'):
            blob_reads.append(args)
            if outcome == 'unavailable':
                raise ValueError('cannot resolve committed policy blob')
            return b'poisoned policy bytes'
        return original(root, *args)
    monkeypatch.setattr(semantic_source_paths, '_committed_git', read)
    monkeypatch.setattr(owner, '_validate_operations', lambda *args: pytest.fail('population before blob authentication'))
    with pytest.raises(owner.SemanticAuthorityError, match='blob'):
        committed_run(committed_inputs)
    assert len(blob_reads) == 1


def test_permissive_candidate_schema_cannot_relax_protected_policy(inputs, monkeypatch):
    root, source, path, digest = inputs
    payload = yaml.safe_load(path.read_text())
    payload['operations'][0]['semantic_kind'] = 'invented_kind'
    path.write_text(yaml.safe_dump(payload))
    (root / 'schemas/application-operations.schema.json').write_text('{}')
    monkeypatch.setattr(owner, '_discover_population', lambda *args: pytest.fail('population before trusted schema validation'))
    with pytest.raises(owner.SemanticAuthorityError, match='application-operations.schema.json'):
        run(inputs, hashlib.sha256(path.read_bytes()).hexdigest())


@pytest.mark.parametrize('candidate_schema', [None, 'false', '{malformed'])
def test_candidate_schema_cannot_reject_valid_protected_policy(inputs, candidate_schema):
    path = inputs[0] / 'schemas/application-operations.schema.json'
    if candidate_schema is None:
        path.unlink()
    else:
        path.write_text(candidate_schema)
    assert len(run(inputs)['operations']) == 1


def test_ordinary_authored_factory_keeps_authored_schema(inputs):
    (inputs[0] / 'schemas/application-operations.schema.json').write_text('false')
    with pytest.raises(owner.SemanticAuthorityError):
        owner.load_application_operations(inputs[0])


@pytest.mark.parametrize('trusted_schema', ['valid', 'missing', 'malformed'])
def test_protected_schema_resolves_from_executing_portable_layout(inputs, monkeypatch, tmp_path, trusted_schema):
    installed = tmp_path / 'installed'
    schema_root = installed / 'schemas'
    schema_root.mkdir(parents=True)
    schema = schema_root / 'application-operations.schema.json'
    if trusted_schema == 'valid':
        shutil.copy2(Path(__file__).parents[1] / 'schemas/application-operations.schema.json', schema)
    elif trusted_schema == 'malformed':
        schema.write_text('{invalid')
    monkeypatch.setattr(owner, '__file__', str(installed / 'scripts/_bcf_runtime/semantic_authority_contracts.py'))
    if trusted_schema == 'valid':
        (inputs[0] / 'schemas/application-operations.schema.json').write_text('false')
        assert len(run(inputs)['operations']) == 1
    else:
        # Valid candidate schema must not become fallback for missing trusted bytes.
        with pytest.raises(owner.SemanticAuthorityError, match='cannot load schemas'):
            run(inputs)


def _authored_query_inputs(inputs, monkeypatch, *, source_text=None, local_port=False):
    from bcf_governance.tooling import semantic_ownership_scan as scan
    from bcf_governance.tooling.semantic_ownership_inventory import resolve_python_imports

    root, source, path, _ = inputs
    if source_text is not None:
        source.write_text(source_text)
    if local_port:
        payload = yaml.safe_load(path.read_text())
        payload['operations'][0]['non_authoritative_output_effects'] = ['runtime.py::scoped']
        path.write_text(yaml.safe_dump(payload, sort_keys=False))
    (root / 'governance-profile.yml').write_text(
        'semantic_capabilities: {application_operation_inventory: blocking}\n'
    )
    (root / 'governance/canonical-representations.yml').write_text('declared')
    facts = resolve_python_imports(root, discover_python_source(root, files=[source]))
    monkeypatch.setattr(scan, '_discover_ownership_inputs', lambda *_a, **_k: (facts, facts, {}, object()))
    monkeypatch.setattr(scan, 'evaluate_discovery', lambda *_a: {
        'verdict': 'conformant', 'blocking_violation_count': 0, 'violations': [],
    })
    return root, facts


_SCOPED_SOURCE = '''from contextlib import contextmanager
@contextmanager
def scoped():
    yield
def work():
    with scoped():
        return 1
COMMANDS = {"work": work}
'''


@pytest.mark.parametrize('defect', ['decorated_effect', 'dynamic_population'])
def test_authored_query_rejects_operation_defects_before_normalization(inputs, monkeypatch, defect):
    from bcf_governance.tooling import semantic_ownership_scan as scan
    from bcf_governance.tooling.semantic_ownership_registry import SemanticOwnershipRegistryError

    source = (_SCOPED_SOURCE if defect == 'decorated_effect' else
              'def work():\n    return 1\nCOMMANDS = dict(work=work)\n')
    root, _ = _authored_query_inputs(inputs, monkeypatch, source_text=source)
    with pytest.raises(SemanticOwnershipRegistryError, match='authored application operations failed'):
        scan.validate_authored_semantic_ownership(root)


def test_authored_query_accepts_exact_declared_local_effect(inputs, monkeypatch):
    from bcf_governance.tooling import semantic_ownership_scan as scan

    root, facts = _authored_query_inputs(inputs, monkeypatch, source_text=_SCOPED_SOURCE, local_port=True)
    report = scan.validate_authored_semantic_ownership(root)
    assert report['authority'] is False and report['execution_qualified'] is False
    assert report['operation_observations'] == owner.validate_application_operations(root, facts)
    assert report['operation_observations'][0]['authority_effect_count'] == 0


def _add_foreign_population(path):
    payload = yaml.safe_load(path.read_text())
    payload['populations'].append(dict(
        id='foreign', adapter='typescript_exports', source='foreign.ts', symbol='exports',
        public_only=True, tsconfig='tsconfig.json', package_lock='package-lock.json', node_executable='node',
    ))
    operation = dict(payload['operations'][0])
    operation.update(id='example.foreign.v1', population='foreign', entrypoints=['foreign.ts::work'])
    payload['operations'].append(operation)
    path.write_text(yaml.safe_dump(payload, sort_keys=False))


def test_authored_query_checks_python_without_foreign_compiler_and_preserves_full_gate(inputs, monkeypatch):
    from bcf_governance.tooling import semantic_ownership_scan as scan

    root, facts = _authored_query_inputs(inputs, monkeypatch)
    _add_foreign_population(inputs[2])
    monkeypatch.setattr('subprocess.run', lambda *_a, **_k: pytest.fail('materialized a toolchain in authored query'))
    report = scan.validate_authored_semantic_ownership(root)
    assert [row['operation'] for row in report['operation_observations']] == ['example.work.v1']
    with pytest.raises(owner.SemanticAuthorityError):
        owner.validate_application_operations(root, facts)


@pytest.mark.parametrize('defect', ['duplicate_id', 'query_mutation'])
def test_authored_query_cannot_hide_malformed_foreign_registry_structure(inputs, monkeypatch, defect):
    from bcf_governance.tooling import semantic_ownership_scan as scan
    from bcf_governance.tooling.semantic_ownership_registry import SemanticOwnershipRegistryError

    root, _ = _authored_query_inputs(inputs, monkeypatch)
    _add_foreign_population(inputs[2])
    payload = yaml.safe_load(inputs[2].read_text())
    if defect == 'duplicate_id':
        payload['operations'][1]['id'] = payload['operations'][0]['id']
    else:
        payload['operations'][1]['authoritative_mutation'] = True
    inputs[2].write_text(yaml.safe_dump(payload, sort_keys=False))
    with pytest.raises(SemanticOwnershipRegistryError, match='authored application operations failed'):
        scan.validate_authored_semantic_ownership(root)


def test_operation_source_scope_is_closed_and_typed(inputs):
    with pytest.raises(owner.SemanticAuthorityError, match='source scope'):
        owner.validate_application_operations(inputs[0], {}, source_language='unknown')


@pytest.mark.parametrize('target', ['python', 'missing_python', 'foreign'])
def test_authored_python_catalog_scope_uses_discovered_source_facts(inputs, monkeypatch, target):
    from bcf_governance.tooling import semantic_ownership_scan as scan
    from bcf_governance.tooling.semantic_ownership_registry import SemanticOwnershipRegistryError

    root, facts = _authored_query_inputs(inputs, monkeypatch)
    before = json.loads(json.dumps(facts))
    entrypoint = {'python': 'runtime.py::work', 'missing_python': 'runtime.py::missing',
                  'foreign': 'foreign.ts::work'}[target]
    (root / 'catalog.yml').write_text(yaml.safe_dump({'catalog': {'work': entrypoint}}))
    payload = yaml.safe_load(inputs[2].read_text())
    payload['populations'][0].update(adapter='canonical_yaml_catalog', source='catalog.yml',
                                     symbol='catalog', catalog_path=['catalog'])
    payload['operations'][0]['entrypoints'] = [entrypoint]
    inputs[2].write_text(yaml.safe_dump(payload, sort_keys=False))
    if target == 'missing_python':
        with pytest.raises(SemanticOwnershipRegistryError, match='shared source inventory'):
            scan.validate_authored_semantic_ownership(root)
    else:
        report = scan.validate_authored_semantic_ownership(root)
        assert len(report['operation_observations']) == (1 if target == 'python' else 0)
        if target == 'foreign':
            with pytest.raises(owner.SemanticAuthorityError):
                owner.validate_application_operations(root, facts)
    assert facts == before

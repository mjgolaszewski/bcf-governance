"""Native model declarations bind protected claims without granting effect credit."""
import copy
import hashlib

import pytest
import yaml

from bcf_governance.tooling import ci_graph_composition_operations as owner
from bcf_governance.tooling import semantic_authority_contracts as contracts
from bcf_governance.tooling.ci_graph_errors import CIGraphError
from tests.test_separate_policy_source import arguments, git, inventory, roots as roots, subject


def declare(root, *, version='1.1', declarations=True):
    path = root / 'governance/application-operations.yml'
    payload = yaml.safe_load(path.read_text())
    payload['schema_version'] = version
    payload['document']['version'] = version + '.0'
    if declarations:
        payload['operations'][0]['runtime_qualifications'] = [dict(
            model='python.exact-string-snapshot', version='1.0',
            claims=['native-model-qualified'], profiles=['self'])]
    path.write_text(yaml.safe_dump(payload))
    deps = {kind:['native'] for kind in ['subject','detector','test_population','toolchain','trust']}
    gate = dict(claim_model=dict(version='1.0', dependency_sets={'native':['**']},
        execution_groups={'native-tests':dict(producer='native-test',claims=['native-model-qualified'])},
        claims={'native-model-qualified':dict(execution_group='native-tests',legacy_gate='native-test',
            dependencies=deps,qualification_scope='subject',profiles=['self'])}),gates={'native-test':{}})
    (root / 'governance/gate-contracts.yml').write_text(yaml.safe_dump(gate))
    git(root, 'add', '.'); git(root, 'commit', '-qm', 'declare native model policy')
    return payload, gate


def save(root, name, payload):
    (root / 'governance' / name).write_text(yaml.safe_dump(payload))
    git(root, 'add', '.'); git(root, 'commit', '-qm', 'change qualification policy')


def test_valid_declaration_binds_committed_canonical_claim_without_runtime_credit(roots):
    protected, candidate = roots
    declare(protected)
    args = dict(arguments(candidate, subject(protected)), policy_repo_root=protected)
    captured = owner.capture_public_operation_bindings(**args)
    expected = hashlib.sha256((protected / 'governance/gate-contracts.yml').read_bytes()).hexdigest()
    assert captured.metadata['runtime_claims_sha256'] == expected
    result = owner.validate_public_operation_capture(candidate, inventory(candidate), captured)
    assert result['runtime_claims_sha256'] == expected
    assert result['authority'] is False and result['execution_qualified'] is False


@pytest.mark.parametrize('version', ['1.0', '1.1'])
def test_no_declarations_preserve_legacy_capture_metadata(roots, version):
    protected, candidate = roots
    declare(protected, version=version, declarations=False)
    captured = owner.capture_public_operation_bindings(**dict(arguments(candidate, subject(protected)), policy_repo_root=protected))
    assert 'runtime_claims_sha256' not in captured.metadata
    assert owner.validate_public_operation_capture(candidate, inventory(candidate), captured)['authority'] is False


@pytest.mark.parametrize('defect', ['unknown','detector','none','profile','preflight','producer','dependency'])
def test_inapplicable_claim_blocks_before_catalog_discovery(roots, monkeypatch, defect):
    protected, candidate = roots
    payload, gate = declare(protected)
    claim = gate['claim_model']['claims']['native-model-qualified']
    if defect == 'unknown':
        payload['operations'][0]['runtime_qualifications'][0]['claims'] = ['missing']
        save(protected, 'application-operations.yml', payload)
    elif defect in {'detector', 'none'}:
        claim['qualification_scope'] = defect
    elif defect == 'profile':
        claim['profiles'] = ['normal']
    elif defect == 'preflight':
        gate['claim_model']['execution_groups']['native-tests']['captured_by_preflight'] = True
    elif defect == 'producer':
        gate['claim_model']['execution_groups']['native-tests']['producer'] = 'missing'
    else:
        claim['dependencies'].pop('trust')
    if defect != 'unknown':
        save(protected, 'gate-contracts.yml', gate)
    monkeypatch.setattr(owner, '_discover_population', lambda *a, **kw: pytest.fail('catalog read before invalid native policy rejection'))
    with pytest.raises(CIGraphError, match='runtime qualification policy'):
        owner.capture_public_operation_bindings(**dict(arguments(candidate, subject(protected)), policy_repo_root=protected))


@pytest.mark.parametrize('defect', ['old','document','unknown-field','empty','claims','profiles','duplicate-scope','overlap-version'])
def test_version_and_scope_ambiguity_rejects(roots, defect):
    protected, _ = roots
    payload, _ = declare(protected)
    rows = payload['operations'][0]['runtime_qualifications']
    if defect == 'old':
        payload['schema_version'] = '1.0'; payload['document']['version'] = '1.0.0'
    elif defect == 'document':
        payload['document']['version'] = '1.0.0'
    elif defect == 'unknown-field':
        rows[0]['verified'] = True
    elif defect == 'empty':
        rows.clear()
    elif defect in {'claims', 'profiles'}:
        rows[0][defect] = []
    else:
        row = copy.deepcopy(rows[0]); row['version'] = '2.0' if defect == 'overlap-version' else '1.0'
        rows.append(row)
    path = protected / 'governance/application-operations.yml'
    raw = yaml.safe_dump(payload).encode()
    with pytest.raises(contracts.SemanticAuthorityError):
        contracts.load_application_operations(protected, expected_sha256=hashlib.sha256(raw).hexdigest(), source_bytes=raw)


def test_candidate_and_dirty_protected_contracts_cannot_supply_authority(roots):
    protected, candidate = roots
    declare(protected)
    args = dict(arguments(candidate, subject(protected)), policy_repo_root=protected)
    (protected / 'governance/gate-contracts.yml').write_text('invalid dirty protected file')
    (candidate / 'governance/gate-contracts.yml').write_text('verified: true')
    captured = owner.capture_public_operation_bindings(**args)
    assert owner.validate_public_operation_capture(candidate, inventory(candidate), captured)['execution_qualified'] is False


@pytest.mark.parametrize('defect', ['object','capture','metadata'])
def test_consumption_reauthenticates_exact_protected_claim_bytes(roots, defect):
    protected, candidate = roots
    declare(protected)
    captured = owner.capture_public_operation_bindings(**dict(arguments(candidate, subject(protected)), policy_repo_root=protected))
    if defect == 'object':
        oid = git(protected, 'rev-parse', 'HEAD:governance/gate-contracts.yml')
        path = protected / '.git/objects' / oid[:2] / oid[2:]
        assert path.is_file(); path.unlink()
    elif defect == 'capture':
        captured = captured._replace(runtime_claims_sha256='0' * 64)
    else:
        captured.metadata['runtime_claims_sha256'] = '0' * 64
    with pytest.raises(CIGraphError, match='public operation.*(qualification|metadata)'):
        owner.validate_public_operation_capture(candidate, inventory(candidate), captured)

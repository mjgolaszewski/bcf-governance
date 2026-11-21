"""Qualifier receipts use exact protected inputs throughout canonical admission."""
import json

import pytest
import yaml

from bcf_governance.tooling import truth_receipts as owner
from bcf_governance.tooling.evidence_gate_contracts import expected_evidence_kinds, expected_invocations
from bcf_governance.tooling.truth_reporting import current_subject
from tests.test_governance_truth import _make_repo, _enable_v3_grouped_session, _git
from tests.test_truth_receipts_adversarial import _repo


@pytest.fixture
def bundle(tmp_path):
    root = _make_repo(tmp_path)
    evidence = _enable_v3_grouped_session(root, session_version='3.0')
    current = current_subject(root)
    policy = yaml.safe_load((root / 'governance/evidence-policy.yml').read_text())
    settings = policy.get('settings', {})
    args = dict(repo_root=root, evidence_dir=evidence, current=current,
        require_negative_control=bool(settings.get('require_negative_control_for_required_gates', True)),
        tree_independent_allowlist=set(settings.get('tree_independent_allowlist', [])),
        expected_kinds=expected_evidence_kinds(root), invocations=expected_invocations(root),
        require_session=True, selected_profile='standard', contract_version='3.0')
    return root, evidence, args, {key:current[key] for key in ['commit_sha','tree_sha']}


def rows(results):
    return [row for group in results.values() for row in group]


def test_claim_population_and_controls_characterization(tmp_path):
    root = _repo(tmp_path)
    receipt = dict(schema_version='3.0', kind='test_suite', claims=['subset'],
        observations={'test_node_ids':['tests.test_subset::test_required']},
        qualification={'satisfied':True,'control_ids':[]})
    assert owner._multi_claim_test_issues(root, receipt) == []
    assert owner._qualification_issues(root, receipt) == []
    receipt['observations']['test_node_ids'] = []
    assert owner._multi_claim_test_issues(root, receipt) == ['claim_subset_expected_test_nodes_missing']
    receipt['qualification']['control_ids'] = ['forged']
    assert owner._qualification_issues(root, receipt) == ['qualification_control_inventory_incomplete']
    receipt['qualification']['satisfied'] = False
    assert owner._qualification_issues(root, receipt) == ['qualification_missing']


def test_existing_receipts_are_unchanged_without_protected_context(bundle):
    _, _, args, _ = bundle
    result = rows(owner.load_receipts(**args))
    assert result and all(row['result']=='verified' for row in result), result
    assert all('admission_policy' not in row for row in result)


@pytest.mark.parametrize('dirty', [None, 'schema','gate','profile','policy','session-schema','all'])
def test_bound_receipts_ignore_dirty_policy_and_preserve_original_bindings(bundle, dirty):
    root, _, args, subject = bundle
    paths = {'schema':'schemas/evidence-receipt.schema.json','gate':'governance/gate-contracts.yml',
        'profile':'governance-profile.yml','policy':'governance/evidence-policy.yml',
        'session-schema':'schemas/evidence-session-v3.schema.json'}
    for key, path in paths.items():
        if dirty in {key, 'all'}:
            (root / path).write_text('false' if path.endswith('.json') else 'candidate: cannot_supply_authority')
    result = rows(owner.load_receipts(**args, policy_subject=subject))
    assert result and all(row['result']=='verified' for row in result), result
    assert all(row['admission_policy']['subject']==subject for row in result)
    assert all(len(row['admission_policy']['gate_contracts_sha256'])==64 for row in result)


@pytest.mark.parametrize('defect', ['missing','wrong-current','unknown-commit','wrong-tree','extra'])
def test_bad_subject_blocks_before_evidence_discovery(bundle, monkeypatch, defect):
    _, _, args, subject = bundle
    if defect=='missing':subject.pop('tree_sha')
    elif defect=='wrong-current':args['current']=dict(args['current'], tree_sha='0'*40)
    elif defect=='unknown-commit':subject['commit_sha']='f'*40; args['current']=dict(args['current'],commit_sha='f'*40)
    elif defect=='wrong-tree':subject['tree_sha']='f'*40; args['current']=dict(args['current'],tree_sha='f'*40)
    else:subject['authority']=True
    monkeypatch.setattr(type(args['evidence_dir']), 'rglob', lambda *a,**kw: pytest.fail('evidence discovered before invalid policy rejection'))
    with pytest.raises(owner.ReceiptError, match='protected receipt policy'):
        owner.load_receipts(**args, policy_subject=subject)


@pytest.mark.parametrize('field', ['require_session','require_negative_control','tree_independent_allowlist','expected_kinds','invocations','selected_profile','contract_version'])
def test_caller_cannot_weaken_canonical_admission_settings(bundle, field):
    _, _, args, subject = bundle
    if field in {'require_session','require_negative_control'}:args[field]=not args[field]
    elif field=='tree_independent_allowlist':args[field]={'test'}
    elif field in {'expected_kinds','invocations'}:args[field]={}
    else:args[field]='wrong'
    with pytest.raises(owner.ReceiptError, match='admission settings'):
        owner.load_receipts(**args, policy_subject=subject)


@pytest.mark.parametrize('defect', ['qualification','producer','dependency','session','schema'])
def test_forged_runtime_qualifier_evidence_still_fails(bundle, defect):
    root, evidence, args, subject = bundle
    path = evidence / 'test.evidence.json'
    receipt = json.loads(path.read_bytes())
    if defect=='qualification':receipt['qualification']['satisfied']=False
    elif defect=='producer':receipt['gate_id']='wrong'
    elif defect=='dependency':receipt['dependency_manifest']['claim_model_sha256']='0'*64
    elif defect=='schema':receipt.pop('producer')
    else:receipt['observations']['evidence_session']['session_id']='f'*32
    path.write_text(json.dumps(receipt))
    (root / 'schemas/evidence-receipt.schema.json').write_text('{}')
    (root / 'schemas/evidence-session-v3.schema.json').write_text('{}')
    result = rows(owner.load_receipts(**args, policy_subject=subject))
    selected = next(row for row in result if row['evidence_id']==receipt['evidence_id'])
    assert selected['result']=='invalid', selected
    assert selected['issues']


@pytest.mark.parametrize('path', ['governance/gate-contracts.yml','schemas/evidence-receipt.schema.json','governance-profile.yml','governance/evidence-policy.yml'])
def test_missing_protected_objects_reject_even_with_good_working_bytes(bundle, path):
    root, _, args, subject = bundle
    oid = _git(root, 'rev-parse', 'HEAD:'+path)
    loose = root / '.git/objects' / oid[:2] / oid[2:]
    assert loose.is_file(); loose.unlink()
    with pytest.raises(owner.ReceiptError, match='protected receipt policy'):
        owner.load_receipts(**args, policy_subject=subject)


def test_consuming_boundary_reauthenticates_after_receipt_verification(bundle, monkeypatch):
    root, _, args, subject = bundle
    original = owner._receipt_result
    oid = _git(root, 'rev-parse', 'HEAD:governance/gate-contracts.yml')
    loose = root / '.git/objects' / oid[:2] / oid[2:]
    def moving(*a, **kw):
        result = original(*a, **kw)
        if loose.exists():loose.unlink()
        return result
    monkeypatch.setattr(owner, '_receipt_result', moving)
    with pytest.raises(owner.ReceiptError, match='changed during evaluation'):
        owner.load_receipts(**args, policy_subject=subject)


def test_source_tree_projection_keeps_nonpython_dependency_bytes(bundle):
    from bcf_governance.tooling.semantic_source_paths import committed_source_tree_population, committed_python_source_population
    root, _, _, subject = bundle
    all_rows = committed_source_tree_population(root, **subject)
    python_rows = committed_python_source_population(root, **subject)
    assert any(row[0]=='governance/gate-contracts.yml' for row in all_rows['regular_blobs'])
    assert python_rows['python_blobs']==tuple(row for row in all_rows['regular_blobs'] if row[0].endswith('.py'))

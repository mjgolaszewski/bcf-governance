"""Protected qualifier metadata cannot replace required actual control traces."""
import copy
import json
import shutil

import pytest
import yaml

from bcf_governance.tooling import truth_receipts as owner
from bcf_governance.tooling.evidence_gate_contracts import expected_evidence_kinds, expected_invocations
from bcf_governance.tooling.truth_reporting import current_subject
from tests.test_governance_truth import _make_repo, _enable_v3_grouped_session


@pytest.fixture
def qualifier(tmp_path):
    root = _make_repo(tmp_path)
    path = root / 'governance/gate-contracts.yml'
    gate = yaml.safe_load(path.read_text())
    gate['gates']['test']['negative_controls'] = [dict(id='assertion-removed',
        mutation=dict(path='plans/phase-01-workitems.yml', yaml_path='workitems[0].status', value='TODO'),
        oracle=dict(kind='test_node_failure', node_ids=['tests/test_security.py::test_auth']))]
    path.write_text(yaml.safe_dump(gate))
    evidence = _enable_v3_grouped_session(root, session_version='3.0')
    receipt_path = evidence / 'test.evidence.json'
    receipt = json.loads(receipt_path.read_bytes())
    receipt['qualification']['control_ids'] = ['assertion-removed']
    receipt_path.write_text(json.dumps(receipt))
    current = current_subject(root)
    subject = {key:current[key] for key in ['commit_sha','tree_sha']}
    args = dict(repo_root=root,evidence_dir=evidence,current=current,
        require_negative_control=True,tree_independent_allowlist=set(),
        expected_kinds=expected_evidence_kinds(root),invocations=expected_invocations(root),
        require_session=True,selected_profile='standard',contract_version='3.0',policy_subject=subject)
    return receipt_path, args


def mutate(path, mode):
    receipt = json.loads(path.read_bytes())
    probes = receipt['behavioral_probes']
    if mode=='missing':
        removed = set(probes[0]['raw_artifacts'].values())
        receipt['artifacts'] = [row for row in receipt['artifacts'] if row['path'] not in removed]
        receipt['behavioral_probes']=[]
    elif mode=='renamed':probes[0]['id']='unrelated-control'
    elif mode=='oracle':probes[0]['oracle']=dict(kind='diagnostic',stream='stdout',regex='.*',exit_codes=[1])
    elif mode in {'unregistered','escape'}:
        original = path.parent / probes[0]['raw_artifacts']['junit']
        replacement = 'unregistered.junit.xml' if mode=='unregistered' else '../escaped.junit.xml'
        shutil.copyfile(original,path.parent / replacement)
        probes[0]['raw_artifacts']['junit']=replacement
        receipt['artifacts']=[row for row in receipt['artifacts'] if row['path']!=original.name]
    elif mode in {'symlink', 'parent-symlink'}:
        original = path.parent / probes[0]['raw_artifacts']['junit']
        outside = path.parent.parent / 'outside-control'
        outside.mkdir()
        shutil.copyfile(original, outside / 'probe.junit.xml')
        if mode=='symlink':
            original.unlink(); original.symlink_to(outside / 'probe.junit.xml')
        else:
            (path.parent / 'foreign').symlink_to(outside, target_is_directory=True)
            old = probes[0]['raw_artifacts']['junit']
            probes[0]['raw_artifacts']['junit']='foreign/probe.junit.xml'
            for artifact in receipt['artifacts']:
                if artifact['path']==old:artifact['path']='foreign/probe.junit.xml'
    elif mode=='duplicate':probes.append(copy.deepcopy(probes[0]))
    elif mode=='false-mutation':probes[0]['mutation_applied']=False
    elif mode=='missing-metadata':receipt['qualification']['control_ids']=[]
    elif mode!='valid':raise AssertionError(mode)
    path.write_text(json.dumps(receipt))


def selected(args):
    return next(row for group in owner.load_receipts(**args).values() for row in group
        if row['evidence_id']=='test-evidence')


@pytest.mark.parametrize('mode',['missing','renamed','oracle','unregistered','escape','duplicate','symlink','parent-symlink'])
def test_required_control_trace_substitution_is_rejected(qualifier, mode):
    path,args=qualifier
    mutate(path,mode)
    result=selected(args)
    assert result['result']=='invalid', 'protected required control accepted '+mode
    assert result['issues']


@pytest.mark.parametrize('mode',['false-mutation','missing-metadata'])
def test_existing_actual_control_rejections_remain(qualifier, mode):
    path,args=qualifier
    mutate(path,mode)
    assert selected(args)['result']=='invalid'


def test_actual_declared_control_remains_admissible(qualifier):
    _,args=qualifier
    result=selected(args)
    assert result['result']=='verified',result
    assert result['admission_policy']['subject']==args['policy_subject']


@pytest.mark.parametrize('mode',['missing','renamed','oracle','unregistered','escape','duplicate','symlink','parent-symlink'])
def test_invalid_bound_control_stops_before_receipt_oracle_consumption(qualifier, monkeypatch, mode):
    path,args=qualifier
    mutate(path,mode)
    original=owner._probe_issues
    def consume(receipt_path, receipt, **options):
        if receipt.get('evidence_id')=='test-evidence':
            pytest.fail('untrusted invalid control oracle consumed '+mode)
        return original(receipt_path, receipt, **options)
    monkeypatch.setattr(owner,'_probe_issues',consume)
    assert selected(args)['result']=='invalid'

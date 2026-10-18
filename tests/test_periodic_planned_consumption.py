"""Modern periodic execution consumes the session plan rather than literal aliases."""
import json
from pathlib import Path
import subprocess

import pytest
import yaml

from bcf_governance.tooling.ci_graph_contracts import validate_ci_graph
from bcf_governance.tooling.ci_graph_render import render_ci_graph
from bcf_governance.tooling.evidence_planning import verification_plan
from bcf_governance.tooling.evidence_sessions import allocate_session, bind_session, local_producer_identity
from bcf_governance.tooling.evidence_shards import partition_required_gates
from test_evidence_planning import _repo
from test_reference_deadline_projection import _build, _contract

ROOT = Path(__file__).resolve().parents[1]


@pytest.mark.parametrize('scope', ['normal', 'regulated', 'self'])
def test_periodic_targets_are_selected_from_exact_real_git_session(tmp_path, scope):
    root = _repo(tmp_path, scope=scope)
    path = root / 'governance/gate-contracts.yml'
    contract = yaml.safe_load(path.read_text())
    profile = 'regulated' if scope == 'regulated' else 'standard'
    contract.update(profile_contract_version='3.0', target_profile=profile)
    contract['gates']['governance-validate'] = {}
    path.write_text(yaml.safe_dump(contract, sort_keys=False))
    subprocess.run(['git', '-C', str(root), 'add', '.'], check=True)
    subprocess.run(['git', '-C', str(root), 'commit', '-qm', 'bound periodic fixture'], check=True)
    subject = {key: subprocess.check_output(['git', '-C', str(root), 'rev-parse', ref], text=True).strip()
               for key, ref in [('commit_sha', 'HEAD'), ('tree_sha', 'HEAD^{tree}')]}
    plan = verification_plan(root, subject, [])
    targets = [node['producer'] for node in plan['execution_dag']['nodes']]
    session = allocate_session(root, tmp_path / 'evidence', targets, expected_producers=['local'],
        producer_identity=local_producer_identity(root), verification_plan=plan)
    graph = _build(contract, profile=profile, gates=list(contract['gates']))
    for workflow in graph['workflows']:
        if workflow['role'] != 'scheduled': continue
        evidence = [j for j in workflow['jobs'] if j['executor']['kind'] == 'gate_shard']
        assert len(evidence) == 1, 'periodic workflow still executes literal aliases'
        job = evidence[0]; assert job['executor']['shard_count'] == 4
        component = next(graph['step_components'][key] for key in job['executor']['components']
                         if graph['step_components'][key].get('command', '').endswith('capture-shard'))
        command = graph['commands'][component['command']]['argv']
        assert 'scripts/capture_governance_shard.py' in command
        consumed = []
        for index in range(job['executor']['shard_count']):
            for target in partition_required_gates(root, shard_index=index, shard_count=4,
                    planned_targets=session.payload['expected_gate_inventory'],
                    execution_dag=session.payload['execution_dag']):
                bind_session(root, target, session.root / target, session.manifest_path, required=True)
                consumed.append(target)
        assert sorted(consumed) == sorted(targets) and len(consumed) == len(set(consumed))
        assert 'governance-validate' not in consumed
        if scope == 'normal': assert 'custody' not in consumed and 'self' not in consumed


def test_modern_periodic_graph_validates_and_isolates_every_transport_namespace(tmp_path):
    contract = _contract(); graph = _build(contract)
    (tmp_path / 'governance/ci-extensions').mkdir(parents=True)
    (tmp_path / 'schemas').mkdir()
    for name in ('ci-graph.schema.json', 'ci-graph-extension.schema.json'):
        (tmp_path / 'schemas' / name).write_bytes((ROOT / 'schemas' / name).read_bytes())
    (tmp_path / 'governance/gate-contracts.yml').write_text(yaml.safe_dump(contract))
    (tmp_path / 'governance/ci-graph.yml').write_text(yaml.safe_dump(graph, sort_keys=False))
    validate_ci_graph(tmp_path)
    rendered = render_ci_graph(tmp_path)
    prior_names = set()
    for workflow in graph['workflows']:
        if workflow['role'] != 'scheduled': continue
        wid = workflow['id']; jobs = workflow['jobs']
        assert [j['id'] for j in jobs] == [wid + '-preflight', wid + '-controls', wid + '-truth']
        assert jobs[1]['executor']['kind'] == 'gate_shard'
        assert jobs[2]['executor']['kind'] == 'terminal_truth'
        assert jobs[2]['condition'] == 'always' and jobs[2]['needs'] == [jobs[0]['id'], jobs[1]['id']]
        assert jobs[2]['consumes'] == [wid + '-receipts']
        payload = yaml.safe_load(rendered[workflow['path']])
        names = {step['with'].get('name', step['with'].get('pattern'))
                 for job in payload['jobs'].values() for step in job['steps']
                 if 'with' in step and ('artifact' in step.get('uses', ''))}
        assert names and not (names & prior_names)
        assert all(wid in name for name in names)
        prior_names |= names
        argv = graph['commands'][wid + '-truth']['argv']
        assert any('/bcf-' + wid + '-truth' in value for value in argv)
        assert graph['commands'][wid + '-truth']['environment']['BCF_EVALUATION_MODE'] == 'closure'
        assert 'use_prior_evidence' not in json.dumps(workflow)

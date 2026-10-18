"""Actual planner assignments must fit before proof allocation or provider reads."""
import copy
from types import SimpleNamespace

import pytest
import yaml

from bcf_governance.tooling import evidence_shards as owner
from bcf_governance.tooling.ci_graph_errors import CIGraphError


def _inputs(root):
    policy = root / 'governance/gate-contracts.yml'
    policy.parent.mkdir(parents=True)
    policy.write_text(yaml.safe_dump({'execution_policy': {
        'default_timeout_seconds': 200, 'default_cleanup_timeout_seconds': 10}}))
    dag = {'nodes': [
        {'id': gate, 'producer': gate, 'assigned_shard': shard, 'depends_on': []}
        for gate, shard in [('first', 0), ('second', 0), ('third', 1)]
    ], 'edges': []}
    job = {'id': 'evidence', 'timeout_minutes': 10,
           'executor': {'kind': 'gate_shard', 'shard_count': 2,
                        'gates': ['first', 'second', 'third']}}
    graph = {'policy': {'minimum_gate_timeout_headroom_seconds': 60},
             'workflows': [{'id': 'pr', 'events': [{'type': 'pull_request'}], 'jobs': [job]}]}
    return graph, dag, ['first', 'second', 'third']


def test_actual_shard_parallelism_retains_separate_outer_budgets(tmp_path):
    graph, dag, targets = _inputs(tmp_path)
    owner.validate_planned_shard_deadlines(tmp_path, graph, targets, dag)


def test_actual_serial_assignment_rejects_maximum_only_budget(tmp_path):
    graph, dag, targets = _inputs(tmp_path)
    graph['workflows'][0]['jobs'][0]['timeout_minutes'] = 9
    with pytest.raises(CIGraphError, match='cannot contain'):
        owner.validate_planned_shard_deadlines(tmp_path, graph, targets, dag)


@pytest.mark.parametrize('defect', ['missing-owner', 'duplicate-owner', 'split-owner',
                                  'count', 'boolean-count', 'out-of-range',
                                  'cross-shard-dependency', 'missing-edge', 'wrong-inventory'])
def test_actual_shard_rejects_ambiguous_or_contradictory_plan(tmp_path, defect):
    graph, dag, targets = _inputs(tmp_path)
    job = graph['workflows'][0]['jobs'][0]
    if defect == 'missing-owner': job['executor']['gates'].remove('third')
    elif defect == 'duplicate-owner': graph['workflows'][0]['jobs'].append(copy.deepcopy(job))
    elif defect == 'split-owner':
        second = copy.deepcopy(job); second['id'] = 'other'
        job['executor']['gates'] = ['first', 'second']; second['executor']['gates'] = ['third']
        graph['workflows'][0]['jobs'].append(second)
    elif defect == 'count': job['executor']['shard_count'] = 0
    elif defect == 'boolean-count': job['executor']['shard_count'] = True
    elif defect == 'out-of-range': dag['nodes'][0]['assigned_shard'] = 2
    elif defect == 'cross-shard-dependency':
        dag['nodes'][2]['depends_on'] = ['first']; dag['edges'] = [{'from': 'first', 'to': 'third'}]
    elif defect == 'missing-edge': dag['nodes'][1]['depends_on'] = ['first']
    else: targets.remove('third')
    with pytest.raises(CIGraphError):
        owner.validate_planned_shard_deadlines(tmp_path, graph, targets, dag)


def test_empty_remainder_requires_empty_dependency_population(tmp_path):
    graph, _, _ = _inputs(tmp_path)
    owner.validate_planned_shard_deadlines(tmp_path, graph, [], {'nodes': [], 'edges': []})
    with pytest.raises((CIGraphError, ValueError)):
        owner.validate_planned_shard_deadlines(tmp_path, graph, [], {
            'nodes': [], 'edges': [{'from': 'removed', 'to': 'removed-too'}]})


def test_legacy_graph_absence_retains_local_behavior_but_modern_absence_blocks(tmp_path):
    owner.admit_planned_shard_deadlines(tmp_path, {'execution_dag': {'nodes': [], 'edges': []}})
    (tmp_path / 'governance-profile.yml').write_text('profile_contract_version: "3.0"\n')
    with pytest.raises(CIGraphError, match='graph'):
        owner.admit_planned_shard_deadlines(tmp_path, {'execution_dag': {'nodes': [], 'edges': []}})


def test_native_shard_rechecks_all_assignments_before_provider_or_gate_work(tmp_path, monkeypatch):
    graph, dag, targets = _inputs(tmp_path)
    graph['workflows'][0]['jobs'][0]['timeout_minutes'] = 9
    (tmp_path / 'governance/ci-graph.yml').write_text('{}\n')
    session = SimpleNamespace(payload={'schema_version': '2.0',
        'expected_gate_inventory': targets, 'execution_dag': dag},
        root=tmp_path / 'session', manifest_path=tmp_path / 'session/evidence-session.json')
    monkeypatch.setattr(owner, 'select_session', lambda _: session)
    monkeypatch.setattr(owner, 'validate_ci_graph', lambda _: SimpleNamespace(graph=graph))
    monkeypatch.setattr(owner.subprocess, 'run', lambda *a, **kw: pytest.fail('allocated gate'))
    monkeypatch.setattr(owner, 'materialize_prior_provider_proofs', lambda *a, **kw: pytest.fail('provider read'))
    monkeypatch.setenv('GITHUB_ACTIONS', 'true')
    # Select the cheap shard; its expensive sibling must still reject admission.
    with pytest.raises(CIGraphError, match='cannot contain'):
        owner.main(['--repo-root', str(tmp_path), '--shard-index', '1', '--shard-count', '2',
                    '--session-root', str(tmp_path / 'sessions')])

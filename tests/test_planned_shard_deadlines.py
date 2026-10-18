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


@pytest.mark.parametrize(('minutes', 'count', 'diagnostic'), [(9, 2, 'cannot contain'), (10, 3, 'count')])
def test_native_shard_rechecks_all_assignments_before_provider_or_gate_work(tmp_path, monkeypatch, minutes, count, diagnostic):
    graph, dag, targets = _inputs(tmp_path)
    job = graph['workflows'][0]['jobs'][0]
    job['timeout_minutes'] = minutes
    job['executor']['gates'][2] = targets[2] = 'test'
    dag['nodes'][2].update(id='test', producer='test')
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
    with pytest.raises(CIGraphError, match=diagnostic):
        owner.main(['--repo-root', str(tmp_path), '--shard-index', '1', '--shard-count', str(count),
                    '--session-root', str(tmp_path / 'sessions')])


def test_assignment_cannot_expand_iteration_beyond_configured_shards(tmp_path, monkeypatch):
    graph, dag, targets = _inputs(tmp_path)
    dag['nodes'][0]['assigned_shard'] = 10**9
    builtin_range = range
    def bounded_range(count):
        assert count <= 4, 'untrusted assignment expanded query iteration'
        return builtin_range(count)
    monkeypatch.setattr(owner, 'range', bounded_range, raising=False)
    with pytest.raises(CIGraphError):
        owner.validate_planned_shard_deadlines(tmp_path, graph, targets, dag)


def test_local_order_query_iterates_only_populated_shards(tmp_path, monkeypatch):
    _, dag, targets = _inputs(tmp_path)
    dag['nodes'][0]['assigned_shard'] = 10**9
    builtin_range = range
    def bounded_range(count):
        assert count <= 4, 'local order query iterated unpopulated shards'
        return builtin_range(count)
    monkeypatch.setattr(owner, 'range', bounded_range, raising=False)
    assert owner.planned_gate_targets(tmp_path, planned_targets=targets, execution_dag=dag) == [
        'second', 'third', 'first']


def test_runtime_count_is_typed_even_when_boolean_equals_configured_integer(tmp_path):
    graph, dag, targets = _inputs(tmp_path)
    job = graph['workflows'][0]['jobs'][0]
    job['executor']['shard_count'] = 1; job['timeout_minutes'] = 15
    for node in dag['nodes']: node['assigned_shard'] = 0
    with pytest.raises(CIGraphError):
        owner.validate_planned_shard_deadlines(tmp_path, graph, targets, dag, shard_count=True)


@pytest.mark.parametrize('allowed', [True, False])
def test_legacy_direct_allowance_stays_with_existing_owner(tmp_path, allowed):
    graph, _, _ = _inputs(tmp_path)
    graph['workflows'][0]['jobs'] = []
    (tmp_path / 'governance-profile.yml').write_text(yaml.safe_dump({
        'profile_contract_version': '1.0', 'ci_profile': {
            'required_push_jobs': ['legacy'] if allowed else []},
        'release_gate_profile': {'gates': {'legacy': {'status': 'required', 'target': 'legacy'}}}}))
    policy = tmp_path / 'governance/gate-contracts.yml'
    value = yaml.safe_load(policy.read_text())
    value.update(gate_catalog={'legacy': {'target': 'legacy'}}, gates={'legacy': {}})
    policy.write_text(yaml.safe_dump(value))
    dag = {'nodes': [{'id': 'legacy', 'producer': 'legacy', 'assigned_shard': 0, 'depends_on': []}], 'edges': []}
    if allowed:
        owner.validate_planned_shard_deadlines(tmp_path, graph, ['legacy'], dag)
    else:
        with pytest.raises(CIGraphError):
            owner.validate_planned_shard_deadlines(tmp_path, graph, ['legacy'], dag)

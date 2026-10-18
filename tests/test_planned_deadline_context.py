"""Declared workflow context cannot inherit another workflow's budget."""
import copy

import pytest

from bcf_governance.tooling.evidence_shards import validate_planned_shard_deadlines
from bcf_governance.tooling.ci_graph_errors import CIGraphError
from test_planned_shard_deadlines import _inputs


def _contexts(root):
    graph, dag, targets = _inputs(root)
    graph['workflows'][0]['path'] = '.github/workflows/pr.yml'
    scheduled = copy.deepcopy(graph['workflows'][0])
    scheduled.update(id='scheduled-full', path='.github/workflows/periodic.yml',
                     events=[{'type': 'schedule', 'cron': ['0 0 * * *']}])
    graph['workflows'].append(scheduled)
    return graph, dag, targets


def test_periodic_composed_budget_cannot_borrow_passing_pr_budget(tmp_path):
    graph, dag, targets = _contexts(tmp_path)
    graph['workflows'][1]['jobs'][0]['timeout_minutes'] = 9
    with pytest.raises(CIGraphError, match='cannot contain'):
        validate_planned_shard_deadlines(tmp_path, graph, targets, dag,
                                        workflow_id='scheduled-full', shard_count=2)


def test_bound_periodic_context_does_not_borrow_wrong_pr_population(tmp_path):
    graph, dag, targets = _contexts(tmp_path)
    graph['workflows'][0]['jobs'][0]['executor']['gates'] = ['unrelated']
    validate_planned_shard_deadlines(tmp_path, graph, targets, dag,
                                    workflow_id='scheduled-full', shard_count=2)


@pytest.mark.parametrize('defect', ['missing', 'duplicate', 'missing-owner', 'boolean-count'])
def test_bound_deadline_context_rejects_uncertain_inventory(tmp_path, defect):
    graph, dag, targets = _contexts(tmp_path)
    wid = 'scheduled-full'
    if defect == 'missing': wid = 'unknown'
    elif defect == 'duplicate': graph['workflows'].append(copy.deepcopy(graph['workflows'][1]))
    elif defect == 'missing-owner': graph['workflows'][1]['jobs'][0]['executor']['gates'].remove('third')
    else: graph['workflows'][1]['jobs'][0]['executor']['shard_count'] = True
    with pytest.raises(CIGraphError):
        validate_planned_shard_deadlines(tmp_path, graph, targets, dag,
                                        workflow_id=wid, shard_count=2)


def test_native_periodic_admission_checks_current_declared_workflow(tmp_path, monkeypatch):
    from types import SimpleNamespace
    from bcf_governance.tooling import evidence_shards as owner
    graph, dag, targets = _contexts(tmp_path)
    graph['workflows'][1]['jobs'][0]['timeout_minutes'] = 9
    (tmp_path / 'governance/ci-graph.yml').write_text('{}\n')
    monkeypatch.setattr(owner, 'validate_ci_graph', lambda _: SimpleNamespace(graph=graph))
    monkeypatch.setenv('GITHUB_ACTIONS', 'true')
    monkeypatch.setenv('GITHUB_REPOSITORY', 'fixture/repo')
    monkeypatch.setenv('GITHUB_WORKFLOW_REF', 'fixture/repo/.github/workflows/periodic.yml@refs/heads/main')
    monkeypatch.setenv('GITHUB_JOB', 'evidence')
    with pytest.raises(CIGraphError, match='cannot contain'):
        owner.admit_planned_shard_deadlines(tmp_path,
            {'expected_gate_inventory': targets, 'execution_dag': dag}, shard_count=2)


def test_reusable_caller_context_resolves_declared_callee_without_pr_guess(tmp_path, monkeypatch):
    from types import SimpleNamespace
    from bcf_governance.tooling import evidence_shards as owner
    graph, dag, targets = _contexts(tmp_path)
    graph['workflows'][0]['jobs'][0]['timeout_minutes'] = 9
    graph['workflows'].append({'id': 'caller', 'path': '.github/workflows/main.yml',
        'events': [{'type': 'push'}], 'jobs': [{'id': 'invoke',
            'executor': {'kind': 'reusable_workflow', 'path': '.github/workflows/pr.yml'}}]})
    (tmp_path / 'governance/ci-graph.yml').write_text('{}\n')
    monkeypatch.setattr(owner, 'validate_ci_graph', lambda _: SimpleNamespace(graph=graph))
    monkeypatch.setenv('GITHUB_ACTIONS', 'true')
    monkeypatch.setenv('GITHUB_REPOSITORY', 'fixture/repo')
    monkeypatch.setenv('GITHUB_WORKFLOW_REF', 'fixture/repo/.github/workflows/main.yml@refs/heads/main')
    monkeypatch.setenv('GITHUB_JOB', 'evidence')
    with pytest.raises(CIGraphError, match='cannot contain'):
        owner.admit_planned_shard_deadlines(tmp_path,
            {'expected_gate_inventory': targets, 'execution_dag': dag}, shard_count=2)

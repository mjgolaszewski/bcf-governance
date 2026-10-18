"""Declared workflow context cannot inherit another workflow's budget."""
import copy

import pytest

from bcf_governance.tooling.evidence_shards import validate_planned_shard_deadlines
from bcf_governance.tooling.ci_graph_errors import CIGraphError
from test_planned_shard_deadlines import _inputs


@pytest.mark.parametrize('field', ['ref', 'sha', 'repository', 'file_path'])
def test_command_projects_defining_workflow_provider_facts(field):
    from pathlib import Path
    from bcf_governance.tooling.ci_graph_contracts import validate_ci_graph
    from bcf_governance.tooling.ci_graph_render import _command_step
    compiled = validate_ci_graph(Path(__file__).resolve().parents[1])
    step = _command_step(compiled, 'governance-truth', name='context')
    assert step['env']['BCF_JOB_WORKFLOW_' + field.upper()] == '${{ job.workflow_' + field + ' }}'


@pytest.mark.parametrize('surface', ['workflow', 'job', 'component', 'command'])
def test_defining_workflow_facts_cannot_be_authored(surface):
    from pathlib import Path
    from bcf_governance.tooling.ci_graph_contracts import validate_ci_graph
    from bcf_governance.tooling.ci_graph_render import _command_step, _workflow as render_workflow
    compiled = validate_ci_graph(Path(__file__).resolve().parents[1])
    workflow = next(item for item in compiled.workflows if item['id'] == 'governance')
    target = {'workflow': workflow, 'job': workflow['jobs'][0],
              'component': compiled.graph['step_components']['checkout-candidate'],
              'command': compiled.commands['governance-truth']}[surface]
    target['environment']['BCF_JOB_WORKFLOW_SHA'] = 'candidate-owned'
    with pytest.raises(AssertionError, match='reserved context'):
        if surface == 'command':
            _command_step(compiled, 'governance-truth', name='forged')
        else:
            render_workflow(compiled, workflow)


def _contexts(root):
    graph, dag, targets = _inputs(root)
    graph['workflows'][0]['path'] = '.github/workflows/pr.yml'
    scheduled = copy.deepcopy(graph['workflows'][0])
    scheduled.update(id='scheduled-full', path='.github/workflows/periodic.yml',
                     events=[{'type': 'schedule', 'cron': ['0 0 * * *']}])
    graph['workflows'].append(scheduled)
    return graph, dag, targets


@pytest.mark.parametrize('defect', ['none', 'partial', 'contradictory', 'sha', 'wrong-job'])
def test_defining_workflow_quartet_binds_callee_and_rejects_uncertainty(tmp_path, defect):
    from bcf_governance.tooling.ci_graph_execution import declared_workflow_context
    graph, _, _ = _contexts(tmp_path)
    # Caller context is deliberately distinct from the defining workflow.
    env = {'GITHUB_ACTIONS': 'true', 'GITHUB_REPOSITORY': 'fixture/repo',
           'GITHUB_WORKFLOW_REF': 'fixture/repo/.github/workflows/pr.yml@refs/heads/main',
           'GITHUB_JOB': 'evidence', 'BCF_JOB_WORKFLOW_REPOSITORY': 'fixture/repo',
           'BCF_JOB_WORKFLOW_FILE_PATH': '.github/workflows/periodic.yml',
           'BCF_JOB_WORKFLOW_REF': 'fixture/repo/.github/workflows/periodic.yml@refs/heads/main',
           'BCF_JOB_WORKFLOW_SHA': 'a' * 40}
    if defect == 'partial': del env['BCF_JOB_WORKFLOW_SHA']
    elif defect == 'contradictory': env['BCF_JOB_WORKFLOW_REPOSITORY'] = 'other/repo'
    elif defect == 'sha': env['BCF_JOB_WORKFLOW_SHA'] = 'main'
    elif defect == 'wrong-job': env['GITHUB_JOB'] = 'unknown'
    if defect == 'none':
        assert declared_workflow_context(graph, env) == 'scheduled-full'
    else:
        with pytest.raises(CIGraphError):
            declared_workflow_context(graph, env)


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

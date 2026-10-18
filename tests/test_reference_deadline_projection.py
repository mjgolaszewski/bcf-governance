"""Reference budgets consume actual contract populations before installation."""
import copy
import json
from pathlib import Path
from types import SimpleNamespace

import pytest
import yaml

from bcf_governance.tooling import ci_graph_timeouts as owner
from bcf_governance.tooling.ci_graph_defaults import build_reference_ci_graph
from bcf_governance.tooling.governance_install.ci_graph import reference_ci_graph


def _contract(profile='standard'):
    deps = {name: [] for name in ('subject', 'detector', 'test_population', 'toolchain', 'trust')}
    groups = {
        'preflight': {'producer': 'preflight', 'captured_by_preflight': True, 'claims': ['structure']},
        'tests': {'producer': 'test', 'claims': ['unit', 'contract']},
        'runtime': {'producer': 'runtime-smoke', 'claims': ['runtime']},
    }
    claims = {cid: {'execution_group': group, 'legacy_gate': gate,
                    'dependencies': copy.deepcopy(deps)}
              for cid, group, gate in [('structure', 'preflight', 'governance-validate'),
                  ('unit', 'tests', 'test'), ('contract', 'tests', 'contract-test'),
                  ('runtime', 'runtime', 'runtime-smoke')]}
    return {'profile_contract_version': '3.0', 'target_profile': profile,
            'execution_policy': {'default_timeout_seconds': 1800, 'default_cleanup_timeout_seconds': 60},
            'gates': {name: ({'invocation': {'timeout_seconds': 2400}} if name == 'test' else {})
                      for name in ('governance-validate', 'test', 'contract-test', 'runtime-smoke')},
            'claim_model': {'version': '1.0', 'dependency_sets': {'whole': ['**']},
                            'execution_groups': groups, 'claims': claims}}


def _build(contract=None, *, profile='standard', gates=None):
    return build_reference_ci_graph(project_id='bound-fixture', profile=profile,
        profile_contract_version='3.0', gates=gates or list(_contract()['gates']),
        candidate_labels=['ubuntu-24.04'], trusted_labels=['self-hosted'],
        candidate_hosted=True, trusted_hosted=False, gate_contract=contract)


def _shard(graph):
    return next(job for workflow in graph['workflows'] for job in workflow['jobs']
                if job['executor']['kind'] == 'gate_shard')


@pytest.mark.parametrize('profile', ['lite', 'standard', 'regulated'])
def test_reference_budget_uses_producers_and_exact_policy(profile):
    # Only test + runtime emit planned work:4200body+300probe/cleanup+300headroom=80m.
    graph = _build(_contract(profile), profile=profile)
    assert _shard(graph)['timeout_minutes'] == 80
    quality = [job for w in graph['workflows'] for job in w['jobs']
               if job['executor']['kind'] == 'gate_group' and
               job['executor']['gates'] == ['test', 'contract-test']]
    if quality: assert quality[0]['timeout_minutes'] == 80
    for workflow in graph['workflows']:
        for job in workflow['jobs']:
            if job['executor']['kind'] == 'gate_group' and job['executor']['gates'] == list(_contract()['gates']):
                assert job['timeout_minutes'] == 145  # Full literal sentinel population retained.


def test_reference_legacy_missing_contract_conservatively_contains_literal_population():
    assert _shard(_build())['timeout_minutes'] == 135


@pytest.mark.parametrize('defect', ['missing-model', 'duplicate-producer', 'wrong-version',
                                  'wrong-profile', 'boolean-body', 'boolean-override', 'omitted-producer'])
def test_reference_contract_rejects_missing_or_contradictory_facts(defect):
    contract = _contract(); gates = list(contract['gates'])
    if defect == 'missing-model': del contract['claim_model']
    elif defect == 'duplicate-producer': contract['claim_model']['execution_groups']['runtime']['producer'] = 'test'
    elif defect == 'wrong-version': contract['profile_contract_version'] = '2.0'
    elif defect == 'wrong-profile': contract['target_profile'] = 'lite'
    elif defect == 'boolean-body': contract['execution_policy']['default_timeout_seconds'] = True
    elif defect == 'boolean-override': contract['gates']['test']['invocation']['timeout_seconds'] = True
    else: gates.remove('runtime-smoke')
    with pytest.raises(ValueError): _build(contract, gates=gates)


def test_projection_preserves_larger_budget_and_rejects_late_cap_atomically():
    graph = _build(_contract()); _shard(graph)['timeout_minutes'] = 150
    owner.project_reference_gate_deadlines(graph, _contract())
    assert _shard(graph)['timeout_minutes'] == 150
    graph = {'policy': {'minimum_gate_timeout_headroom_seconds': 60}, 'workflows': [{'jobs': [
        {'timeout_minutes': 10, 'executor': {'kind': 'gate_group', 'gates': ['first']}},
        {'timeout_minutes': 10, 'executor': {'kind': 'gate_group', 'gates': ['g'+str(i) for i in range(26)]}},
    ]}]}
    original = copy.deepcopy(graph)
    with pytest.raises(ValueError, match='360'):
        owner.project_reference_gate_deadlines(graph, None)
    assert graph == original


def test_provider_ceiling_matches_existing_canonical_schema():
    schema = json.loads((Path(__file__).resolve().parents[1] / 'schemas/ci-graph.schema.json').read_text())
    assert owner.GITHUB_JOB_TIMEOUT_LIMIT_MINUTES == schema['$defs']['job']['properties']['timeout_minutes']['maximum']


def test_installation_caller_binds_actual_contract_without_target_mutation(tmp_path):
    args = SimpleNamespace(project_id='consumer', profile='standard',
        candidate_runner_label=['ubuntu-24.04'], trusted_runner_label=['self-hosted'],
        candidate_runner_kind='hosted', trusted_runner_kind='self-hosted')
    graph = reference_ci_graph(args, _contract())
    assert _shard(graph)['timeout_minutes'] == 80
    assert list(tmp_path.iterdir()) == []


@pytest.mark.parametrize('estimate_kind', ['unknown', 'uniform', 'heavy-test', 'heavy-security'])
def test_real_model_projection_contains_duration_aware_assignments(estimate_kind):
    from bcf_governance.tooling.evidence_planning import parse_claim_model
    from bcf_governance.tooling.evidence_scheduling import assign_duration_aware_shards
    from bcf_governance.tooling.evidence_shards import validate_planned_shard_deadlines
    root = Path(__file__).resolve().parents[1]
    contract = yaml.safe_load((root / 'governance/gate-contracts.yml').read_text())
    model = parse_claim_model(contract)
    graph = yaml.safe_load((root / 'governance/ci-graph.yml').read_text())
    owner.project_reference_gate_deadlines(graph, contract)
    nodes = [{'id': name, 'producer': group['producer'], 'depends_on': group.get('depends_on', [])}
             for name, group in model['execution_groups'].items() if group.get('captured_by_preflight') is not True]
    # Synthetic duration inputs exercise placement, not evidence reuse or performance.
    estimates = {} if estimate_kind == 'unknown' else {node['id']: 1 for node in nodes}
    if estimate_kind.startswith('heavy'):
        for node in nodes:
            if ('test' if estimate_kind == 'heavy-test' else 'security') in node['producer']:
                estimates[node['id']] = 10**9
    placed = assign_duration_aware_shards(nodes, estimates)
    dag = {'nodes': placed, 'edges': [{'from': dep, 'to': node['id']}
                                   for node in placed for dep in node['depends_on']]}
    validate_planned_shard_deadlines(root, graph, [node['producer'] for node in placed], dag)
    assert _shard(graph)['timeout_minutes'] == 243


def test_full_twenty_gate_periodic_reference_preserves_every_control():
    root = Path(__file__).resolve().parents[1]
    contract = yaml.safe_load((root / 'governance/gate-contracts.yml').read_text())
    gates = list(contract['gates']); original = copy.deepcopy(contract)
    graph = _build(contract, gates=gates)
    for workflow in graph['workflows']:
        if workflow['role'] != 'scheduled': continue
        parts = [job for job in workflow['jobs'] if job['executor']['kind'] == 'gate_group']
        assert len(parts) > 1
        assert [gate for job in parts for gate in job['executor']['gates']] == gates
        assert all(job['timeout_minutes'] <= 360 for job in parts)
    assert contract == original


def test_cap_failure_precedes_install_transaction_path_allocation(tmp_path):
    from bcf_governance.tooling.governance_install.transaction_paths import install_transaction_paths
    root = Path(__file__).resolve().parents[1]
    contract = yaml.safe_load((root / 'governance/gate-contracts.yml').read_text())
    args = SimpleNamespace(project_id='consumer', profile='standard', upgrade=False,
        candidate_runner_label=['ubuntu-24.04'], trusted_runner_label=['self-hosted'],
        candidate_runner_kind='hosted', trusted_runner_kind='self-hosted')
    contract['gates']['governance-validate'].setdefault('invocation', {})['timeout_seconds'] = 21600
    target = tmp_path / 'unallocated'
    with pytest.raises(ValueError, match='360.*partition'):
        install_transaction_paths(args, contract=contract, contract_version='3.0',
            target_root=target, template_root=root / 'template-repo', baseline=())
    assert not target.exists()

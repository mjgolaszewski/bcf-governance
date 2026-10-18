"""Scheduled partition keeps complete ordered populations and cumulative custody."""
import copy
from pathlib import Path

import pytest
import yaml

from bcf_governance.tooling.ci_graph_defaults import build_reference_ci_graph
from bcf_governance.tooling.ci_graph_contracts import validate_ci_graph
from bcf_governance.tooling.ci_graph_render import render_ci_graph

ROOT = Path(__file__).resolve().parents[1]


def build(gates, *, seconds=1800, profile='standard', cleanup=60):
    contract = {'profile_contract_version': '2.0', 'target_profile': profile,
        'gates': {gate: {} for gate in gates}, 'execution_policy': {
            'default_timeout_seconds': seconds, 'default_cleanup_timeout_seconds': cleanup}}
    before = copy.deepcopy(contract)
    graph = build_reference_ci_graph(project_id='bounded', profile=profile,
        profile_contract_version='2.0', gates=gates, candidate_labels=['ubuntu-24.04'],
        trusted_labels=['self-hosted'], candidate_hosted=True, trusted_hosted=False,
        gate_contract=contract)
    assert contract == before
    return graph


def scheduled(graph):
    return [w for w in graph['workflows'] if w['role'] == 'scheduled']


@pytest.mark.parametrize('profile', ['standard', 'regulated'])
def test_partition_carries_same_session_and_all_receipts_to_stable_terminal(profile):
    gates = [prefix + str(i) for prefix in ('governance-', 'quality-', 'security-', 'runtime-') for i in range(5)]
    graph = build(gates, profile=profile)
    assert graph == build(gates, profile=profile)
    for workflow in scheduled(graph):
        wid = workflow['id']; parts = [j for j in workflow['jobs'] if j['executor']['kind'] == 'gate_group']
        assert len(parts) == 2
        assert [gate for j in parts for gate in j['executor']['gates']] == gates
        assert parts[0]['id'] == wid + '-controls'
        previous_job = workflow['jobs'][0]['id']; previous_artifact = wid + '-session'
        for part in parts:
            assert part['needs'] == [previous_job] and part['consumes'] == [previous_artifact]
            assert part['condition'] == 'success'
            assert graph['artifacts'][part['produces'][0]]['path'] == '.artifacts/bcf/sessions'
            assert part['timeout_minutes'] <= 360
            previous_job, previous_artifact = part['id'], part['produces'][0]
        assert previous_artifact == wid + '-receipts'
        truth = workflow['jobs'][-1]
        assert truth['id'] == wid + '-truth' and truth['condition'] == 'always'
        assert truth['needs'] == [j['id'] for j in parts]
        assert truth['consumes'] == [j['produces'][0] for j in parts]
        argv = graph['commands'][wid + '-preflight']['argv']
        assert [argv[i+1] for i,v in enumerate(argv) if v == '--expected-producer'] == [j['id'] for j in parts]


@pytest.mark.parametrize('seconds, expected_parts', [(10500, 1), (10501, 2)])
def test_partition_uses_exact_quantized_probe_cleanup_headroom_bound(seconds, expected_parts):
    graph = build(['governance-first', 'runtime-last'], seconds=seconds)
    for w in scheduled(graph):
        parts = [j for j in w['jobs'] if j['executor']['kind'] == 'gate_group']
        assert len(parts) == expected_parts
        if expected_parts == 1: assert parts[0]['timeout_minutes'] == 360


def test_partition_validates_and_renders_exact_predecessor_downloads(tmp_path):
    gates = [prefix + str(i) for prefix in ('governance-', 'quality-', 'security-', 'runtime-') for i in range(5)]
    graph = build(gates)
    (tmp_path/'governance/ci-extensions').mkdir(parents=True)
    (tmp_path/'schemas').mkdir()
    for name in ('ci-graph.schema.json', 'ci-graph-extension.schema.json'):
        (tmp_path/'schemas'/name).write_bytes((ROOT/'schemas'/name).read_bytes())
    (tmp_path/'governance/ci-graph.yml').write_text(yaml.safe_dump(graph, sort_keys=False))
    compiled = validate_ci_graph(tmp_path)
    assert compiled.workflows
    rendered = render_ci_graph(tmp_path)
    for workflow in scheduled(graph):
        payload = yaml.safe_load(rendered[Path(workflow['path'])])
        parts = [j for j in workflow['jobs'] if j['executor']['kind'] == 'gate_group']
        assert len(parts) == 2
        for part in parts:
            steps = payload['jobs'][part['id']]['steps']
            downloads = [s['with'] for s in steps if s.get('name','').startswith('Download exact')]
            assert len(downloads) == 1
            assert downloads[0]['name'] == 'bcf-' + part['consumes'][0] + '-${{ github.run_id }}-${{ github.run_attempt }}'
            assert downloads[0]['path'] == '.artifacts/bcf/sessions'

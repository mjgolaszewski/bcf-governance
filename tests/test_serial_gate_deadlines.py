"""Fixed serial execution must fit its existing outer job deadline."""
import pytest
import yaml

from bcf_governance.tooling.ci_graph_errors import CIGraphError
from bcf_governance.tooling.ci_graph_timeouts import validate_gate_job_timeouts


def _policy(root, *, body=200, cleanup=10, overrides=None):
    path = root / 'governance/gate-contracts.yml'
    path.parent.mkdir(parents=True)
    path.write_text(yaml.safe_dump({
        'execution_policy': {'default_timeout_seconds': body,
                             'default_cleanup_timeout_seconds': cleanup},
        'gates': {gate: {'invocation': {'timeout_seconds': value}}
                  for gate, value in (overrides or {}).items()},
    }))


def _graph(minutes, *, kind='gate_group', gates=('first', 'second')):
    return {'policy': {'minimum_gate_timeout_headroom_seconds': 60},
            'workflows': [{'id': 'verify', 'jobs': [
                {'id': 'evidence', 'timeout_minutes': minutes,
                 'executor': {'kind': kind, 'gates': list(gates)}}]}]}


@pytest.mark.parametrize('minutes', [6, 8, 9])
def test_serial_group_rejects_total_that_largest_gate_would_admit(tmp_path, minutes):
    _policy(tmp_path)
    # Two*(200 body +30 interpreter +2*10 cleanup)+60 headroom =560s ->10m.
    with pytest.raises(CIGraphError, match='cannot contain'):
        validate_gate_job_timeouts(tmp_path, _graph(minutes))


def test_serial_group_accepts_exact_quantized_boundary(tmp_path):
    _policy(tmp_path)
    validate_gate_job_timeouts(tmp_path, _graph(10))


@pytest.mark.parametrize(('body', 'cleanup', 'minutes'), [(200, 30, 10), (220, 10, 9)])
def test_serial_group_counts_each_probe_and_cleanup(tmp_path, body, cleanup, minutes):
    _policy(tmp_path, body=body, cleanup=cleanup)
    with pytest.raises(CIGraphError, match='cannot contain'):
        validate_gate_job_timeouts(tmp_path, _graph(minutes))


def test_serial_group_override_remains_in_sum(tmp_path):
    _policy(tmp_path, overrides={'second': 400})
    with pytest.raises(CIGraphError, match='cannot contain'):
        validate_gate_job_timeouts(tmp_path, _graph(12))
    validate_gate_job_timeouts(tmp_path, _graph(13))


def test_serial_group_checks_every_sibling_consumer(tmp_path):
    _policy(tmp_path)
    graph = _graph(10)
    graph['workflows'].append({'id': 'sibling', 'jobs': _graph(9)['workflows'][0]['jobs']})
    with pytest.raises(CIGraphError, match='cannot contain'):
        validate_gate_job_timeouts(tmp_path, graph)


def test_serial_group_legacy_absence_composes_existing_defaults(tmp_path):
    # 2*(1800+30+120)+60=3960s =66m, preserving the existing absence defaults.
    with pytest.raises(CIGraphError, match='cannot contain'):
        validate_gate_job_timeouts(tmp_path, _graph(65))
    validate_gate_job_timeouts(tmp_path, _graph(66))


def test_singleton_and_shard_static_floor_preserve_scope(tmp_path):
    _policy(tmp_path)
    validate_gate_job_timeouts(tmp_path, _graph(6, gates=('first',)))
    validate_gate_job_timeouts(tmp_path, _graph(6, kind='gate_shard'))
    with pytest.raises(CIGraphError, match='cannot contain'):
        validate_gate_job_timeouts(tmp_path, _graph(5, kind='gate_shard'))


@pytest.mark.parametrize('profile', ['lite', 'standard'])
def test_reference_builder_derives_serial_defaults_for_every_group(tmp_path, profile):
    from bcf_governance.tooling.ci_graph_defaults import build_reference_ci_graph
    graph = build_reference_ci_graph(
        project_id='serial-fixture', profile=profile, profile_contract_version='3.0',
        gates=['governance-validate', 'architecture-test', 'lint', 'test',
               'security-secret-scan', 'runtime-smoke'],
        candidate_labels=['ubuntu-24.04'], trusted_labels=['self-hosted'],
        candidate_hosted=True, trusted_hosted=False,
    )
    validate_gate_job_timeouts(tmp_path, graph)

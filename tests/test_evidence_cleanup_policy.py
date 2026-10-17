"""One cleanup budget must reach early admission, execution and outer deadlines."""
from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from bcf_governance.tooling import evidence_execution as execution
from bcf_governance.tooling.ci_graph_errors import CIGraphError
from bcf_governance.tooling.ci_graph_timeouts import gate_timeout_contract, validate_gate_job_timeouts


def _registry(root, cleanup):
    (root / 'governance').mkdir()
    (root / 'governance/gate-contracts.yml').write_text(yaml.safe_dump({
        'execution_policy': {'default_timeout_seconds': 568,
                             'default_cleanup_timeout_seconds': cleanup},
        'gates': {},
    }))


def test_gate_deadline_includes_real_cleanup_before_outer_allocation(tmp_path):
    _registry(tmp_path, 30)
    graph = {'policy': {'minimum_gate_timeout_headroom_seconds': 3}, 'workflows': [
        {'id': 'pipeline', 'jobs': [{'id': 'evidence', 'timeout_minutes': 10,
         'executor': {'kind': 'gate_group', 'gates': ['test']}}]},
    ]}
    with pytest.raises(CIGraphError, match='cleanup'):
        validate_gate_job_timeouts(tmp_path, graph)
    graph['workflows'][0]['jobs'][0]['timeout_minutes'] = 11
    validate_gate_job_timeouts(tmp_path, graph)


@pytest.mark.parametrize('cleanup', [None, 0, -1, False, 1.5, '1', 21601])
def test_cleanup_policy_rejects_at_existing_authored_admission_query(tmp_path, cleanup):
    _registry(tmp_path, cleanup)
    with pytest.raises(CIGraphError, match='cleanup'):
        gate_timeout_contract(tmp_path)


@pytest.mark.parametrize('cleanup', [None, 0, -1, False, 1.5, '1', 21601])
def test_invalid_cleanup_cannot_load_or_allocate_runtime(tmp_path, monkeypatch, cleanup):
    seen = []

    def unexpected(*args, **kwargs):
        seen.append('runtime')
        raise AssertionError('known invalid cleanup budget reached runtime allocation')

    monkeypatch.setattr(execution, 'load_runtime_contract', unexpected)
    monkeypatch.setattr(execution, 'allocate_execution_state', unexpected)
    with pytest.raises(execution.EvidenceError, match='cleanup'):
        execution._run_with_execution_state(
            tmp_path, tmp_path,
            {'target': 'test', 'invocation': {'cwd': '.'}, 'execution_timeout_seconds': 1,
             'execution_cleanup_timeout_seconds': cleanup},
            ['unused'], Path('/unused'), session_id='session', execution_id='run', require_state=True,
        )
    assert seen == []


def test_unproven_process_cleanup_preserves_execution_state_custody(tmp_path, monkeypatch):
    error = execution.EvidenceProcessCleanupError
    retired = []

    class Lease:
        def environment(self):
            return {}

    monkeypatch.setattr(execution, 'load_runtime_contract', lambda *args: {})
    monkeypatch.setattr(execution, 'allocate_execution_state', lambda *args, **kwargs: Lease())
    monkeypatch.setattr(execution, '_execution_env', lambda *args, **kwargs: ({}, {}))
    monkeypatch.setattr(execution, 'retire_execution_state', lambda lease: retired.append(lease))

    def uncertain(*args, **kwargs):
        raise error('process cleanup could not be authenticated')

    monkeypatch.setattr(execution, '_run', uncertain)
    with pytest.raises(error, match='cleanup'):
        execution._run_with_execution_state(
            tmp_path, tmp_path,
            {'target': 'test', 'invocation': {'cwd': '.'}, 'execution_timeout_seconds': 1,
             'execution_cleanup_timeout_seconds': 1},
            ['unused'], Path('/unused'), session_id='session', execution_id='run', require_state=True,
        )
    assert retired == []


@pytest.mark.parametrize('platform', ['darwin', 'win32'])
def test_unqualified_group_inventory_host_blocks_before_allocation(tmp_path, monkeypatch, platform):
    seen = []
    monkeypatch.setattr(execution.sys, 'platform', platform)

    def unexpected(*args, **kwargs):
        seen.append('allocation')
        raise AssertionError('unqualified process-group inventory reached allocation')

    monkeypatch.setattr(execution, 'load_runtime_contract', unexpected)
    monkeypatch.setattr(execution, 'allocate_execution_state', unexpected)
    with pytest.raises(execution.EvidenceError, match='Linux'):
        execution._run_with_execution_state(
            tmp_path, tmp_path,
            {'target': 'test', 'invocation': {'cwd': '.'}, 'execution_timeout_seconds': 1,
             'execution_cleanup_timeout_seconds': 1},
            ['unused'], Path('/unused'), session_id='session', execution_id='run', require_state=True,
        )
    assert seen == []

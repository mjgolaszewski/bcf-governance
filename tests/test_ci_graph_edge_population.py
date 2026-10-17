"""Independent graph consumers reject incomplete producer populations early."""
from dataclasses import replace
from pathlib import Path

import pytest

from bcf_governance.tooling import ci_graph_contracts as owner
from bcf_governance.tooling.ci_graph_errors import CIGraphError


ROOT = Path(__file__).resolve().parents[1]


@pytest.mark.parametrize('defect', [
    'omitted-pair', 'duplicate-pair', 'unknown-node', 'self-pair',
    'reachable-with-exclusion', 'unknown-exclusion', 'nonboolean-reachability',
])
def test_consumer_rejects_corrupt_population_before_downstream_checks(monkeypatch, defect):
    compiler = owner.compile_edge_contracts
    downstream = []

    def corrupt(graph):
        rows = list(compiler(graph))
        reachable = next(i for i, row in enumerate(rows) if row.reachable)
        excluded = next(i for i, row in enumerate(rows) if not row.reachable)
        if defect == 'omitted-pair':
            rows.pop(reachable)
        elif defect == 'duplicate-pair':
            rows[-1] = rows[0]
        elif defect == 'unknown-node':
            rows[0] = replace(rows[0], producer='unknown:producer')
        elif defect == 'self-pair':
            rows[0] = replace(rows[0], consumer=rows[0].producer)
        elif defect == 'reachable-with-exclusion':
            rows[reachable] = replace(rows[reachable], exclusion_reason='reverse_dependency')
        elif defect == 'unknown-exclusion':
            rows[excluded] = replace(rows[excluded], exclusion_reason='candidate-says-unneeded')
        else:
            rows[reachable] = replace(rows[reachable], reachable=1)
        return tuple(rows)

    def forbidden_downstream(*args, **kwargs):
        downstream.append('timeout-consumer')
        raise AssertionError('corrupt producer population reached downstream consumer')

    monkeypatch.setattr(owner, 'compile_edge_contracts', corrupt)
    monkeypatch.setattr(owner, 'validate_gate_job_timeouts', forbidden_downstream)
    with pytest.raises(CIGraphError, match='CI edge population'):
        owner.validate_ci_graph(ROOT)
    assert downstream == []

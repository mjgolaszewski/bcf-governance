from __future__ import annotations

import hashlib
import importlib.util
from pathlib import Path
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).parents[1]


def collector():
    spec = importlib.util.spec_from_file_location('issue394_deadlines', ROOT / 'audits/issue-394/collect_deadline_inventory.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture
def inputs(tmp_path, monkeypatch):
    module = collector()
    files = {'governance/ci-graph.yml': b'graph', 'schemas/ci-graph.schema.json': b'schema'}
    for path, raw in files.items():
        target = tmp_path / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(raw)
    graph = {'step_components': {'resolve': {'kind': 'command', 'command': 'resolve-controller', 'minimum_job_timeout_minutes': 10}},
             'workflows': [{'id': 'main', 'jobs': [
                 {'id': 'first', 'timeout_minutes': 10, 'executor': {'kind': 'component_sequence', 'components': ['resolve']}},
                 {'id': 'second', 'timeout_minutes': 15, 'executor': {'kind': 'component_sequence', 'components': ['resolve']}},
                 {'id': 'gate', 'timeout_minutes': 40, 'executor': {'kind': 'gate_group', 'gates': ['test']}}]}]}
    compiled = SimpleNamespace(graph=graph, graph_sha256='a' * 64, input_sha256=(), extension_sha256=())
    monkeypatch.setattr(module, 'validate_ci_graph', lambda root: compiled)
    monkeypatch.setattr(module, '_subject', lambda root: {'commit_sha': 'a' * 40, 'tree_sha': 'b' * 40})
    monkeypatch.setattr(module, 'committed_regular_blob_capture', lambda root, *, path, **kwargs: ({'sha256': hashlib.sha256(files[path]).hexdigest()}, files[path]))
    return module, tmp_path, graph


def test_deadline_inventory_preserves_all_jobs_and_sibling_floor_consumers(inputs):
    module, root, graph = inputs
    before = {p: p.read_bytes() for p in root.rglob('*') if p.is_file()}
    value = module.collect(root)
    assert value == module.collect(root)
    assert value['authority'] is False and value['execution_qualified'] is False
    assert [(row['workflow'], row['job']) for row in value['jobs']] == [('main', 'first'), ('main', 'gate'), ('main', 'second')]
    assert [row['job'] for row in value['jobs'] if row['component_floors']] == ['first', 'second']
    assert next(row for row in value['jobs'] if row['job'] == 'gate')['executor'] == graph['workflows'][0]['jobs'][2]['executor']
    assert {p: p.read_bytes() for p in root.rglob('*') if p.is_file()} == before


@pytest.mark.parametrize('defect', ['input', 'subject'])
def test_deadline_inventory_rejects_moving_or_uncommitted_source(inputs, monkeypatch, defect):
    module, root, graph = inputs
    if defect == 'input':
        (root / 'governance/ci-graph.yml').write_bytes(b'changed')
    else:
        subjects = iter([{'commit_sha': 'a' * 40, 'tree_sha': 'b' * 40}, {'commit_sha': 'c' * 40, 'tree_sha': 'b' * 40}])
        monkeypatch.setattr(module, '_subject', lambda root: next(subjects))
    with pytest.raises(ValueError, match='deadline inventory'):
        module.collect(root)

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


@pytest.mark.parametrize("kind,target", [("controller", "bcf_governance/tooling/routine_controller_provider.py::resolve_effective_controller"), ("provider_read", "bcf_governance/tooling/provider_read.py::open_provider_get")])
def test_controller_consumer_inventory_uses_exact_full_source_and_retains_every_call(monkeypatch, tmp_path, kind, target):
    module = collector()
    subject = {'commit_sha': 'a' * 40, 'tree_sha': 'b' * 40}
    inventory = {'files': [{'path': 'caller.py', 'sha256': 'c' * 64}], 'functions': [
        {'symbol': name, 'calls': [{'called_symbol': target, 'line': 1}]}
        for name in ('caller.py::first', 'caller.py::second', 'tests/control.py::case')]}
    inventory['functions'].append({'symbol': 'unrelated.py::other', 'calls': [{'called_symbol': 'other.py::read', 'line': 2}]})
    collect = getattr(module, f'collect_{kind}_consumers')
    monkeypatch.setattr(module, '_subject', lambda root: subject)
    def discover(root, **kwargs):
        assert root == tmp_path
        assert kwargs == {'call_contracts_version': '1.0', 'source_subject': subject}
        return inventory
    monkeypatch.setattr(module, 'discover_python_source', discover)
    monkeypatch.setattr(module, 'resolve_python_imports', lambda root, value: value)
    value = collect(tmp_path)
    assert value == collect(tmp_path)
    assert value['authority'] is False and value['execution_qualified'] is False
    assert {row['consumer'] for row in value['consumers']} == {'caller.py::first', 'caller.py::second', 'tests/control.py::case'}
    subjects = iter([subject, {**subject, 'commit_sha': 'd' * 40}])
    monkeypatch.setattr(module, '_subject', lambda root: next(subjects))
    with pytest.raises(ValueError, match=f'{kind} consumer inventory source changed'):
        collect(tmp_path)


def test_provider_io_candidates_retain_unresolved_reads_and_transport_occurrences(monkeypatch, tmp_path):
    module = collector()
    subject = {'commit_sha': 'a' * 40, 'tree_sha': 'b' * 40}
    targets = {
        'bcf_governance/tooling/provider_read.py::open_provider_get',
        'bcf_governance/tooling/ci_github_downloads.py::open_download',
        'bcf_governance/tooling/protection_inspection_client.py::_open_inspection',
        'urllib.request::urlopen', 'urllib.request::build_opener',
    }
    calls = [{'called_symbol': target, 'call_name': 'alias', 'line': line}
             for line, target in enumerate(sorted(targets), 1)]
    calls += [{'called_symbol': f'caller.py::renamed.{name}', 'call_name': name, 'line': line}
              for line, name in enumerate(('read', 'read1', 'readinto', 'readinto1'), 10)]
    calls += [{'called_symbol': 'caller.py::ordinary_file.read', 'call_name': 'read', 'line': line}
              for line in (20, 21)]
    unrelated = {'called_symbol': 'other.py::write', 'call_name': 'write', 'line': 22}
    inventory = {'files': [{'path': 'caller.py', 'sha256': 'c' * 64}], 'functions': [
        {'symbol': 'caller.py::first', 'calls': calls + [unrelated]},
        {'symbol': 'tests/control.py::case', 'calls': [calls[-1]]},
    ]}
    monkeypatch.setattr(module, '_subject', lambda root: subject)
    def discover(root, **kwargs):
        assert root == tmp_path
        assert kwargs == {'call_contracts_version': '1.0', 'source_subject': subject}
        return inventory
    monkeypatch.setattr(module, 'discover_python_source', discover)
    monkeypatch.setattr(module, 'resolve_python_imports', lambda root, value: value)
    value = module.collect_provider_io_candidates(tmp_path)
    assert value == module.collect_provider_io_candidates(tmp_path)
    assert not list(tmp_path.iterdir())
    assert value['authority'] is False and value['execution_qualified'] is False
    assert set(value['selectors']['resolved_transport_symbols']) == targets
    assert set(value['selectors']['lexical_read_names']) == {'read', 'read1', 'readinto', 'readinto1'}
    assert len(value['consumers']) == len(calls) + 1
    assert {row['producer'] for row in value['consumers'] if row['classification'] == 'resolved_transport_call'} == targets
    reads = [row for row in value['consumers'] if row['classification'] == 'lexical_read_candidate']
    assert len(reads) == 7
    assert {row['call']['line'] for row in reads} == {10, 11, 12, 13, 20, 21}
    assert any(row['consumer'].startswith('tests/') for row in reads)
    assert any('response-object identity' in item for item in value['unqualified'])
    subjects = iter([subject, {**subject, 'tree_sha': 'd' * 40}])
    monkeypatch.setattr(module, '_subject', lambda root: next(subjects))
    with pytest.raises(ValueError, match='provider_io consumer inventory source changed'):
        module.collect_provider_io_candidates(tmp_path)

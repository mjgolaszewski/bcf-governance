"""Real preflight runtimes must consume actual native guardian custody."""
from __future__ import annotations

import json
import os
from pathlib import Path
import shutil
import subprocess
import sys

import pytest

from tests.test_native_lease_custody import lease_path, _busy
from test_source_admission_authority import _fixture

from bcf_governance.tooling import evidence_process_supervisor, test_manifests
from bcf_governance.tooling.governance_validation import preflight_distribution, source_inventory
from bcf_governance.tooling.local_execution_admission import local_gate_lease
from bcf_governance.tooling.semantic_ownership_typescript import (
    contract_from_mapping, discover_typescript_source,
)


def _observed_executable(binary, executable, identity, observations):
    binary.write_text(f"""#!{sys.executable}
import json,os,sys
from pathlib import Path
parent=Path('/proc',str(os.getppid()))
expected=({identity.st_dev},{identity.st_ino})
def has_lease(root):
    for entry in (root/'fd').iterdir():
        try: value=entry.stat()
        except FileNotFoundError: continue
        if (value.st_dev,value.st_ino)==expected: return True
    return False
owned={str(Path(evidence_process_supervisor.__file__).resolve())!r}.encode() in (parent/'cmdline').read_bytes().split(bytes([0]))
record=dict(guardian=owned,parent_lease=has_lease(parent),command_lease=has_lease(Path('/proc/self')))
with Path({str(observations)!r}).open('a') as stream: stream.write(json.dumps(record)+'\\n')
if not record['guardian'] or not record['parent_lease'] or record['command_lease']:
    print('preflight-consumer-native-owner-bypassed',file=sys.stderr)
    sys.exit(23)
os.execv({str(executable)!r},[{str(executable)!r},*sys.argv[1:]])
""")
    binary.chmod(0o700)


@pytest.mark.parametrize('consumer', ['distribution', 'collection', 'typescript', 'inventory-git'])
def test_preflight_runtime_has_actual_guardian_and_descriptor(
    lease_path, tmp_path, monkeypatch, consumer,
):
    repo = tmp_path / 'project'
    repo.mkdir()
    executable = Path(sys.executable)
    if consumer in {'distribution', 'inventory-git'}:
        _fixture(repo, coverage=True, program="raise AssertionError('candidate evaluator ran')\n")
        # Establish the actual protected evaluator succeeds before the custody control.
        assert preflight_distribution.validate_source_distribution(
            repo, python_executable=executable,
        )['file_count'] == 5
        if consumer == 'inventory-git':
            executable = Path(shutil.which('git'))
    elif consumer == 'collection':
        (repo / 'test_value.py').write_text("def test_value():\n    raise AssertionError('collection executed a test body')\n")
        assert test_manifests._collect_raw_nodes(
            repo, ['test_value.py'], python_executable=executable,
        ) == ['test_value.py::test_value']
    else:
        from semantic_typescript_fixture import compiler
        engine = compiler(repo)
        source = repo / 'src/value.ts'
        source.parent.mkdir()
        source.write_text('export function value(): number { return 1; }\n')
        executable = Path(shutil.which('node'))
        inventory = discover_typescript_source(repo, contract_from_mapping(engine), [source])
        assert inventory['compiler_version'] == '6.0.3'
        assert any(row['symbol'] == 'src/value.ts::value' for row in inventory['functions'])
    observations = tmp_path / 'runtime-custody.jsonl'
    binary = tmp_path / ('git' if consumer == 'inventory-git' else 'observed-runtime')
    with local_gate_lease('b' * 40):
        _observed_executable(binary, executable, lease_path.stat(), observations)
        monkeypatch.setenv('PATH', str(tmp_path) + os.pathsep + os.environ['PATH'])
        try:
            if consumer == 'distribution':
                result = preflight_distribution.validate_source_distribution(repo, python_executable=binary)
                assert result['file_count'] == 5 and result['authority'] is False
            elif consumer == 'collection':
                assert test_manifests._collect_raw_nodes(
                    repo, ['test_value.py'], python_executable=binary,
                ) == ['test_value.py::test_value']
            elif consumer == 'inventory-git':
                assert len(source_inventory.tracked_source_inventory(repo)) == 5
            else:
                result = discover_typescript_source(
                    repo, contract_from_mapping({**engine, 'node_executable': binary.name}), [source],
                )
                assert result['compiler_version'] == '6.0.3'
                assert any(row['symbol'] == 'src/value.ts::value' for row in result['functions'])
        finally:
            assert observations.is_file(), 'real runtime did not observe its native parent'
            records = [json.loads(line) for line in observations.read_text().splitlines()]
            assert records == [dict(guardian=True, parent_lease=True, command_lease=False)], (
                'preflight runtime bypassed actual guardian descriptor custody', records,
            )
    assert not _busy(lease_path)


@pytest.mark.parametrize('consumer', ['direct-inventory', 'isolated-project-evaluator'])
def test_distribution_inventory_never_executes_repository_fsmonitor(tmp_path, consumer):
    repo = tmp_path / 'project'
    repo.mkdir()
    _fixture(repo, coverage=True, program="raise AssertionError('candidate evaluator ran')\n")
    marker = tmp_path / 'candidate-program-executed'
    monitor = tmp_path / 'candidate-fsmonitor'
    monitor.write_text('#!/bin/sh\ntouch "' + str(marker) + '"\nprintf "token\\0"\n')
    monitor.chmod(0o700)
    subprocess.run(['git', '-C', str(repo), 'config', 'core.fsmonitor', str(monitor)], check=True)
    if consumer == 'direct-inventory':
        assert len(source_inventory.tracked_source_inventory(repo)) == 5
    else:
        assert preflight_distribution.validate_source_distribution(
            repo, python_executable=Path(sys.executable),
        )['file_count'] == 5
    assert not marker.exists(), 'source distribution inventory executed candidate Git configuration'
    assert subprocess.check_output(
        ['git', '-C', str(repo), 'config', '--get', 'core.fsmonitor'], text=True,
    ).strip() == str(monitor)


def _committed_repository(root):
    root.mkdir()
    _fixture(root, coverage=True, program="raise AssertionError('candidate evaluator ran')\n")
    subprocess.run(
        ['git', '-C', str(root), '-c', 'core.hooksPath=/dev/null', '-c', 'core.fsmonitor=false',
         '-c', 'user.name=Custody fixture', '-c', 'user.email=custody@example.invalid',
         'commit', '-qm', 'exact fixture'], check=True,
    )
    return subprocess.check_output(['git', '-C', str(root), 'rev-parse', 'HEAD'], text=True).strip()


def _repository_query(root, consumer, commit, monkeypatch):
    from bcf_governance.tooling.governance_validation import (
        ci_state_matrix, preflight_repository_context as context,
    )
    if consumer == 'value':
        assert context.git_value(root, 'status', '--porcelain=v1', '--untracked-files=all') == ''
    elif consumer == 'files':
        assert len(context.tracked_files(root)) == 5
    elif consumer == 'state':
        observed = context.git_state(root)
        assert observed['commit_sha'] == commit and len(observed['tree_sha']) == 40
    elif consumer == 'comparison':
        for key, value in {
            'BCF_PROVIDER_EVENT': 'pull_request', 'GITHUB_EVENT_NAME': 'pull_request',
            'BCF_INVOCATION_KIND': 'direct_event', 'BCF_COMPARISON_BASE_SHA': commit,
            'BCF_ORIGIN_COMPARISON_BASE_SHA': commit, 'BCF_PR_BASE_SHA': commit,
            'BCF_CALLER_COMPARISON_BASE_SHA': '',
        }.items():
            monkeypatch.setenv(key, value)
        observed = context.pr_context(root, 'pr')
        assert observed['applicable'] and observed['base_sha'] == commit
    elif consumer == 'candidate':
        from bcf_governance.tooling import local_pr_context
        assert local_pr_context.require_clean_candidate_root(
            root, runner=local_pr_context._run,
        ) == root.resolve()
    else:
        assert consumer == 'matrix'
        assert ci_state_matrix._git(root, 'diff', '--name-only', commit, '--') == ''


@pytest.mark.parametrize('consumer,count', [('value', 1), ('files', 1), ('state', 4),
                                           ('comparison', 2), ('matrix', 1), ('candidate', 1)])
def test_repository_context_queries_have_actual_guardian_and_descriptor(
    lease_path, tmp_path, monkeypatch, consumer, count,
):
    repo = tmp_path / 'project'
    commit = _committed_repository(repo)
    # First prove the same real query works in its ordinary unbound context.
    _repository_query(repo, consumer, commit, monkeypatch)
    executable = Path(shutil.which('git'))
    observations = tmp_path / 'repository-custody.jsonl'
    with local_gate_lease('c' * 40):
        _observed_executable(tmp_path / 'git', executable, lease_path.stat(), observations)
        monkeypatch.setenv('PATH', str(tmp_path) + os.pathsep + os.environ['PATH'])
        try:
            _repository_query(repo, consumer, commit, monkeypatch)
        finally:
            assert observations.is_file(), 'repository query allocated no observed Git process'
            records = [json.loads(line) for line in observations.read_text().splitlines()]
            assert records == [dict(guardian=True, parent_lease=True, command_lease=False)] * count, (
                'repository context bypassed actual guardian descriptor custody', records,
            )
    assert not _busy(lease_path)


@pytest.mark.parametrize('consumer', ['value', 'files', 'state', 'matrix', 'candidate'])
def test_repository_context_queries_never_execute_configured_fsmonitor(tmp_path, monkeypatch, consumer):
    repo = tmp_path / 'project'
    commit = _committed_repository(repo)
    marker = tmp_path / 'candidate-program-executed'
    monitor = tmp_path / 'candidate-fsmonitor'
    monitor.write_text('#!/bin/sh\ntouch "' + str(marker) + '"\nprintf "token\\0"\n')
    monitor.chmod(0o700)
    subprocess.run(['git', '-C', str(repo), 'config', 'core.fsmonitor', str(monitor)], check=True)
    _repository_query(repo, consumer, commit, monkeypatch)
    assert not marker.exists(), 'repository preflight executed candidate Git configuration'
    assert subprocess.check_output(
        ['git', '-C', str(repo), 'config', '--get', 'core.fsmonitor'], text=True,
    ).strip() == str(monitor)

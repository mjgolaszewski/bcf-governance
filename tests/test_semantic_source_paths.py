from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from bcf_governance.tooling import semantic_source_paths as source


def git(root, *args):
    return subprocess.run(['git', *args], cwd=root, check=True, capture_output=True).stdout.decode().strip()


@pytest.fixture
def repo(tmp_path):
    git(tmp_path, 'init', '-q')
    git(tmp_path, 'config', 'user.name', 'Source Test')
    git(tmp_path, 'config', 'user.email', 'source@example.invalid')
    (tmp_path / 'nested').mkdir()
    (tmp_path / 'nested/root.py').write_text('raise RuntimeError("must never execute")\n')
    (tmp_path / 'non_python.txt').write_text('other')
    git(tmp_path, 'add', '.')
    git(tmp_path, 'commit', '-qm', 'base')
    return tmp_path


def subject(repo):
    return dict(commit_sha=git(repo, 'rev-parse', 'HEAD'), tree_sha=git(repo, 'rev-parse', 'HEAD^{tree}'))


def test_exact_population_uses_committed_blobs_without_executing_source(repo):
    identity = subject(repo)
    expected_oid = git(repo, 'rev-parse', 'HEAD:nested/root.py')
    (repo / 'nested/root.py').write_text('uncommitted()\n')
    (repo / 'untracked.py').write_text('untracked()\n')
    result = source.committed_python_source_population(repo, **identity)
    assert result['authority'] is False
    assert result['execution_qualified'] is False
    assert result['subject'] == identity
    assert result['python_blobs'] == (('nested/root.py', '100644', expected_oid),)
    assert result['unresolved_entries'] == ()


@pytest.mark.parametrize('value', ['HEAD', '', 'a' * 39, 'A' * 40, True, None])
def test_nonexact_subject_rejects_before_git(repo, monkeypatch, value):
    identity = subject(repo)
    def forbidden(*args, **kwargs):
        raise AssertionError('Git called before validating subject')
    monkeypatch.setattr(source.subprocess, 'run', forbidden)
    with pytest.raises(ValueError, match='exact'):
        source.committed_python_source_population(repo, **dict(identity, commit_sha=value))


def test_wrong_tree_cannot_bind_a_commit(repo):
    identity = subject(repo)
    (repo / 'new.py').write_text('new()\n')
    git(repo, 'add', '.')
    git(repo, 'commit', '-qm', 'new')
    with pytest.raises(ValueError, match='tree'):
        source.committed_python_source_population(repo, **dict(identity, tree_sha=subject(repo)['tree_sha']))


def test_source_delta_retains_removed_and_changed_python_population(repo):
    base = subject(repo)
    (repo / 'nested/root.py').unlink()
    (repo / 'replacement.py').write_text('replacement()\n')
    git(repo, 'add', '-A')
    git(repo, 'commit', '-qm', 'remove and add')
    candidate = subject(repo)
    result = source.committed_python_source_delta(repo, base=base, candidate=candidate)
    assert result['removed'] == ('nested/root.py',)
    assert result['added'] == ('replacement.py',)
    assert result['changed'] == ()
    assert result['base']['python_blobs'][0][0] == 'nested/root.py'
    assert result['candidate']['python_blobs'][0][0] == 'replacement.py'

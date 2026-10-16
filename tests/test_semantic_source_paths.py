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


def test_unusual_paths_and_executable_mode_are_preserved(repo):
    name = 'nested/space\tnewline\nλ.py'
    (repo / name).write_text('pass\n')
    (repo / name).chmod(0o755)
    git(repo, 'add', '.')
    git(repo, 'commit', '-qm', 'unusual path')
    result = source.committed_python_source_population(repo, **subject(repo))
    assert (name, '100755', git(repo, 'rev-parse', f'HEAD:{name}')) in result['python_blobs']


def test_symlinks_and_gitlinks_are_unresolved_even_without_python_suffix(repo):
    base = subject(repo)
    (repo / 'alias.py').symlink_to('../outside.py')
    (repo / 'directory_alias').symlink_to('../outside_directory')
    git(repo, 'add', '.')
    git(repo, 'update-index', '--add', '--cacheinfo', '160000,' + base['commit_sha'] + ',vendor')
    git(repo, 'commit', '-qm', 'unresolved entries')
    result = source.committed_python_source_population(repo, **subject(repo))
    assert {row[:2] for row in result['unresolved_entries']} == {
        ('alias.py', '120000'), ('directory_alias', '120000'), ('vendor', '160000')
    }
    assert [row[0] for row in result['python_blobs']] == ['nested/root.py']
    assert source.committed_python_source_delta(repo, base=base, candidate=subject(repo))['unresolved_changed'] is True


def test_git_replacement_cannot_substitute_the_source_subject(repo):
    original = subject(repo)
    oid = git(repo, 'rev-parse', 'HEAD:nested/root.py')
    (repo / 'nested/root.py').write_text('substituted()\n')
    git(repo, 'add', '.')
    git(repo, 'commit', '-qm', 'replacement')
    replacement = subject(repo)
    git(repo, 'replace', original['commit_sha'], replacement['commit_sha'])
    assert git(repo, 'rev-parse', original['commit_sha'] + '^{tree}') == replacement['tree_sha']
    result = source.committed_python_source_population(repo, **original)
    assert result['python_blobs'] == (('nested/root.py', '100644', oid),)


def test_source_content_and_mode_change_are_retained(repo):
    base = subject(repo)
    (repo / 'nested/root.py').write_text('changed()\n')
    (repo / 'nested/root.py').chmod(0o755)
    git(repo, 'add', '.')
    git(repo, 'commit', '-qm', 'changed')
    result = source.committed_python_source_delta(repo, base=base, candidate=subject(repo))
    assert result['changed'] == ('nested/root.py',)
    assert result['added'] == result['removed'] == ()


@pytest.mark.parametrize('record', [b'\0', b'malformed\0', b'100644 blob ' + b'a' * 40 + b'\t../escape.py\0', b'100644 blob ' + b'a' * 40 + b'\tbad\xff.py\0', b'100644 blob ' + b'a' * 40 + b'\tx.py'])
def test_malformed_tree_population_rejects_instead_of_narrowing(repo, monkeypatch, record):
    identity = subject(repo)
    real = source.subprocess.run
    def forged(args, **kwargs):
        if 'ls-tree' in args:
            return subprocess.CompletedProcess(args, 0, record, b'')
        return real(args, **kwargs)
    monkeypatch.setattr(source.subprocess, 'run', forged)
    with pytest.raises(ValueError, match='tree'):
        source.committed_python_source_population(repo, **identity)


def test_discovery_binds_exact_tree_and_preserves_default_output(repo):
    from bcf_governance.tooling.semantic_ownership_inventory import discover_python_source

    identity = subject(repo)
    default = discover_python_source(repo)
    assert discover_python_source(repo, source_subject=None) == default
    exact = discover_python_source(repo, source_subject=identity)
    assert exact['source_population'] == source.committed_python_source_population(repo, **identity)
    for key, value in default.items():
        assert exact[key] == value
    assert exact['authority'] is False


@pytest.mark.parametrize('defect', ['dirty', 'missing', 'untracked', 'wrong_mode', 'subset', 'symlink'])
def test_discovery_rejects_source_mismatch_before_parsing(repo, monkeypatch, defect):
    from bcf_governance.tooling import semantic_ownership_inventory as inventory

    identity = subject(repo)
    files = None
    if defect == 'dirty':
        (repo / 'nested/root.py').write_text('changed()\n')
    elif defect == 'missing':
        (repo / 'nested/root.py').unlink()
    elif defect == 'untracked':
        (repo / 'untracked.py').write_text('extra()\n')
    elif defect == 'wrong_mode':
        (repo / 'nested/root.py').chmod(0o755)
    elif defect == 'subset':
        files = []
    else:
        (repo / 'alias').symlink_to('../outside')
        git(repo, 'add', '.')
        git(repo, 'commit', '-qm', 'symlink')
        identity = subject(repo)
    def forbidden(*args, **kwargs):
        raise AssertionError('source parsed before exact-subject rejection')
    with monkeypatch.context() as patches:
        patches.setattr(inventory.ast, 'parse', forbidden)
        with pytest.raises(inventory.SemanticInventoryError, match='source'):
            inventory.discover_python_source(repo, files=files, source_subject=identity)


def test_committed_tree_object_cannot_be_used_as_a_commit(repo):
    identity = subject(repo)
    with pytest.raises(ValueError, match='commit'):
        source.committed_python_source_population(repo, **dict(identity, commit_sha=identity['tree_sha']))


def test_wrong_tree_rejects_before_population_enumeration(repo, monkeypatch):
    identity = subject(repo)
    real = source.subprocess.run
    def guarded(args, **kwargs):
        if 'ls-tree' in args:
            raise AssertionError('tree enumerated before subject verification')
        return real(args, **kwargs)
    monkeypatch.setattr(source.subprocess, 'run', guarded)
    with pytest.raises(ValueError, match='tree'):
        source.committed_python_source_population(repo, **dict(identity, tree_sha='0' * 40))


def test_empty_committed_python_population_is_not_execution_authority(repo):
    from bcf_governance.tooling.semantic_ownership_inventory import discover_python_source

    (repo / 'nested/root.py').unlink()
    git(repo, 'add', '-A')
    git(repo, 'commit', '-qm', 'no Python files')
    inventory = discover_python_source(repo, source_subject=subject(repo))
    assert inventory['files'] == []
    assert inventory['source_population']['python_blobs'] == ()
    assert inventory['source_population']['execution_qualified'] is False
    assert inventory['authority'] is False


def test_exact_subject_output_does_not_depend_on_caller_file_order(repo):
    from bcf_governance.tooling.semantic_ownership_inventory import discover_python_source

    extra = repo / 'extra.py'
    extra.write_text('def extra():\n    pass\n')
    git(repo, 'add', '.')
    git(repo, 'commit', '-qm', 'two files')
    paths = [repo / 'nested/root.py', extra]
    identity = subject(repo)
    assert discover_python_source(repo, files=paths, source_subject=identity) == discover_python_source(repo, files=list(reversed(paths)), source_subject=identity)


def test_source_disappearing_after_population_discovery_is_a_typed_blocker(repo, monkeypatch):
    from bcf_governance.tooling.semantic_ownership_inventory import discover_python_source, SemanticInventoryError

    identity = subject(repo)
    real = Path.read_bytes
    def vanished(path):
        if path == repo / 'nested/root.py':
            raise FileNotFoundError('source vanished after discovery')
        return real(path)
    monkeypatch.setattr(Path, 'read_bytes', vanished)
    with pytest.raises(SemanticInventoryError, match='source'):
        discover_python_source(repo, source_subject=identity)



def test_committed_regular_blob_capture_preserves_exact_bytes_and_policy_identity(repo):
    import hashlib
    identity = subject(repo)
    metadata, raw = source.committed_regular_blob_capture(repo, path='non_python.txt', **identity)
    assert raw == b'other'
    assert metadata['sha256'] == hashlib.sha256(raw).hexdigest()
    assert metadata['subject'] == identity
    assert metadata['authority'] is False
    (repo / 'non_python.txt').unlink()
    assert source.committed_regular_blob_capture(repo, path='non_python.txt', **identity) == (metadata, raw)


@pytest.mark.parametrize('path', ['', '/non_python.txt', '../non_python.txt', './non_python.txt', 'nested/../non_python.txt', 'nested//root.py', 'nested\\root.py', 'missing.json'])
def test_committed_regular_blob_capture_rejects_unsafe_or_absent_paths(repo, path):
    with pytest.raises(ValueError):
        source.committed_regular_blob_capture(repo, path=path, **subject(repo))

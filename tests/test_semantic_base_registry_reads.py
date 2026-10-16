from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from bcf_governance.tooling import semantic_authority_migrations as owner


def git(repo, *args):
    return subprocess.run(['git', *args], cwd=repo, capture_output=True, text=True, check=True).stdout.strip()


@pytest.fixture
def repo(tmp_path):
    git(tmp_path, 'init', '-q')
    git(tmp_path, 'config', 'user.name', 'Registry Test')
    git(tmp_path, 'config', 'user.email', 'registry@example.invalid')
    (tmp_path / 'governance').mkdir()
    (tmp_path / 'governance/application-operations.yml').write_text('operations: []\n')
    git(tmp_path, 'add', '.')
    git(tmp_path, 'commit', '-qm', 'base')
    return tmp_path


def test_unavailable_base_is_not_an_absent_registry(repo):
    with pytest.raises(owner.SemanticMigrationError, match='base'):
        owner._git_yaml(repo, 'f' * 40, Path('governance/application-operations.yml'))


def test_read_error_for_present_registry_is_not_absence(repo, monkeypatch):
    base = git(repo, 'rev-parse', 'HEAD')
    real = owner.subprocess.run
    def failed(args, **kwargs):
        if 'show' in args:
            return subprocess.CompletedProcess(args, 128, '', 'unable to read object')
        return real(args, **kwargs)
    monkeypatch.setattr(owner.subprocess, 'run', failed)
    with pytest.raises(owner.SemanticMigrationError, match='base'):
        owner._git_yaml(repo, base, Path('governance/application-operations.yml'))


def test_true_registry_absence_and_valid_mapping_remain_supported(repo):
    base = git(repo, 'rev-parse', 'HEAD')
    assert owner._git_yaml(repo, base, Path('governance/absent.yml')) is None
    assert owner._git_yaml(repo, base, Path('governance/application-operations.yml')) == {'operations': []}


@pytest.mark.parametrize('payload', ['null\n', '[]\n', 'plain scalar\n', 'operations: []\noperations: []\n'])
def test_present_nonmapping_or_ambiguous_base_is_not_absence(repo, payload):
    (repo / 'governance/application-operations.yml').write_text(payload)
    git(repo, 'add', '.')
    git(repo, 'commit', '-qm', 'ambiguous base')
    with pytest.raises(owner.SemanticMigrationError, match='base'):
        owner._git_yaml(repo, git(repo, 'rev-parse', 'HEAD'), Path('governance/application-operations.yml'))


def test_git_replacement_cannot_erase_base_operation_population(repo):
    path = repo / 'governance/application-operations.yml'
    path.write_text('operations: [{id: original.operation}]\n')
    git(repo, 'add', '.')
    git(repo, 'commit', '-qm', 'original population')
    base = git(repo, 'rev-parse', 'HEAD')
    path.write_text('operations: []\n')
    git(repo, 'add', '.')
    git(repo, 'commit', '-qm', 'replacement population')
    replacement = git(repo, 'rev-parse', 'HEAD')
    git(repo, 'replace', base, replacement)
    assert git(repo, 'show', base + ':governance/application-operations.yml') == 'operations: []'
    assert owner._git_yaml(repo, base, Path('governance/application-operations.yml')) == {'operations': [{'id': 'original.operation'}]}


def test_unavailable_base_cannot_disable_full_migration_validation(repo, monkeypatch):
    from types import SimpleNamespace

    monkeypatch.setenv('BCF_PR_BASE_SHA', 'f' * 40)
    with pytest.raises(owner.SemanticMigrationError, match='base'):
        owner.validate_exact_base_migrations(repo, {'families': [], 'migrations': []}, {'operations': [], 'migrations': []}, SimpleNamespace(raw={}))


def test_unreadable_base_cannot_hide_operation_retirement(repo, monkeypatch):
    from types import SimpleNamespace

    path = repo / 'governance/application-operations.yml'
    path.write_text('operations: [{id: original.operation}]\n')
    git(repo, 'add', '.')
    git(repo, 'commit', '-qm', 'old operation')
    base = git(repo, 'rev-parse', 'HEAD')
    monkeypatch.setenv('BCF_PR_BASE_SHA', base)
    real = owner.subprocess.run
    def failed(args, **kwargs):
        if 'show' in args and args[-1].endswith(':governance/application-operations.yml'):
            return subprocess.CompletedProcess(args, 128, '', 'object unavailable')
        return real(args, **kwargs)
    monkeypatch.setattr(owner.subprocess, 'run', failed)
    with pytest.raises(owner.SemanticMigrationError, match='base registry'):
        owner.validate_exact_base_migrations(repo, {'families': [], 'migrations': []}, {'operations': [], 'migrations': []}, SimpleNamespace(raw={}))


def test_file_and_text_semantic_yaml_decoders_share_duplicate_rejection(tmp_path):
    from bcf_governance.tooling.semantic_yaml import load_unique_mapping, load_unique_mapping_text, SemanticYAMLError

    path = tmp_path / 'source.yml'
    path.write_text('key: [value]\n')
    assert load_unique_mapping(path) == load_unique_mapping_text(path.read_text())
    path.write_text('key: first\nkey: second\n')
    with pytest.raises(SemanticYAMLError, match='duplicate'):
        load_unique_mapping_text(path.read_text())
    with pytest.raises(SemanticYAMLError, match='duplicate'):
        load_unique_mapping(path)


def test_malformed_present_registry_is_a_typed_base_failure(repo):
    path = repo / 'governance/application-operations.yml'
    path.write_text('operations: [\n')
    git(repo, 'add', '.')
    git(repo, 'commit', '-qm', 'malformed base')
    with pytest.raises(owner.SemanticMigrationError, match='base registry'):
        owner._git_yaml(repo, git(repo, 'rev-parse', 'HEAD'), Path('governance/application-operations.yml'))


@pytest.mark.parametrize('payload', [
    'defaults: &base\n  operations: []\n<<: *base\n',
    'defaults: &base {flag: old}\n<<: *base\nflag: new\n',
    'defaults: &base {a: 1}\nfirst: &first {<<: *base, b: 2}\nsecond: {<<: *first, a: 3}\n',
    'a: &a {flag: first}\nb: &b {flag: second}\n<<: [*a, *b]\n',
])
def test_valid_legacy_yaml_merges_keep_safe_loader_semantics(repo, payload):
    import yaml
    from bcf_governance.tooling.semantic_yaml import load_unique_mapping_text

    expected = yaml.safe_load(payload)
    path = repo / 'governance/application-operations.yml'
    path.write_text(payload)
    git(repo, 'add', '.')
    git(repo, 'commit', '-qm', 'legacy merge')
    assert load_unique_mapping_text(payload) == expected
    assert owner._git_yaml(repo, git(repo, 'rev-parse', 'HEAD'), Path('governance/application-operations.yml')) == expected


@pytest.mark.parametrize('payload', [
    'defaults: &base {operations: []}\n<<: *base\noperations: []\noperations: []\n',
    'defaults: &base {operations: [], operations: []}\n<<: *base\n',
    'defaults: &base {operations: []}\n<<: *base\n<<: *base\n',
])
def test_merge_expansion_cannot_hide_repeated_authored_keys(payload):
    from bcf_governance.tooling.semantic_yaml import load_unique_mapping_text, SemanticYAMLError

    with pytest.raises(SemanticYAMLError, match='duplicate'):
        load_unique_mapping_text(payload)


@pytest.mark.parametrize('kind', ['tree', 'unrelated_commit'])
def test_full_migration_validation_requires_a_real_ancestor_commit_before_reads(repo, monkeypatch, kind):
    from types import SimpleNamespace

    tree = git(repo, 'rev-parse', 'HEAD^{tree}')
    base = tree if kind == 'tree' else git(repo, 'commit-tree', tree, '-m', 'unrelated')
    monkeypatch.setenv('BCF_PR_BASE_SHA', base)
    monkeypatch.setattr(owner, '_git_yaml', lambda *a, **kw: pytest.fail('registry read before exact base validation'))
    with pytest.raises(owner.SemanticMigrationError, match='base'):
        owner.validate_exact_base_migrations(repo, {'families': [], 'migrations': []}, {'operations': [], 'migrations': []}, SimpleNamespace(raw={}))

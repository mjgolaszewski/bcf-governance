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

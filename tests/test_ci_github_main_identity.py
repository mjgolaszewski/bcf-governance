"""Repository facts must bind both canonical provider source reconstruction paths."""
from __future__ import annotations

import pytest

from bcf_governance.tooling.ci_github_identity import (
    GitHubControllerError, resolve_main, resolve_run_subject,
)


class Provider:
    def __init__(self, full_name='owner/repo'):
        self.metadata = {'id': 42, 'default_branch': 'main', 'full_name': full_name}
        self.reads = []

    def repository(self, repository):
        self.reads.append(('repository', repository))
        return dict(self.metadata)

    def reference(self, repository, ref):
        self.reads.append(('reference', repository, ref))
        return {'object': {'type': 'commit', 'sha': 'a' * 40}}

    def commit(self, repository, sha):
        self.reads.append(('commit', repository, sha))
        return {'sha': sha, 'tree': {'sha': 'b' * 40}}

    def run(self, repository, run_id):
        self.reads.append(('run', repository, run_id))
        return {'id': 10, 'run_attempt': 1, 'head_branch': 'main', 'head_sha': 'a' * 40,
                'repository': {'id': 42}, 'head_repository': {'id': 42}}


def _resolve(provider, kind):
    if kind == 'default':
        return resolve_main(provider, 'owner/repo')
    return resolve_run_subject(provider, 'owner/repo', run_id=10, run_attempt=1)


@pytest.mark.parametrize('kind', ['default', 'run'])
@pytest.mark.parametrize('full_name', ['owner/repo', 'Owner/Repo'])
def test_source_identity_retains_case_insensitive_repository_binding(kind, full_name):
    provider = Provider(full_name)
    identity = _resolve(provider, kind)
    assert identity.repository_id == '42' and identity.default_branch == 'main'
    assert identity.checkout_sha == 'a' * 40 and identity.tree_sha == 'b' * 40


@pytest.mark.parametrize('kind', ['default', 'run'])
@pytest.mark.parametrize('cause', ['wrong-owner', 'wrong-name', 'blank', 'missing', 'null', 'number', 'object'])
def test_source_identity_rejects_unbound_repository_before_later_reads(kind, cause):
    values = {'wrong-owner': 'other/repo', 'wrong-name': 'owner/other', 'blank': '',
              'missing': None, 'null': None, 'number': 42, 'object': {'full_name': 'owner/repo'}}
    provider = Provider(values[cause])
    if cause == 'missing':
        del provider.metadata['full_name']
    with pytest.raises(GitHubControllerError, match='repository'):
        _resolve(provider, kind)
    assert provider.reads == [('repository', 'owner/repo')]

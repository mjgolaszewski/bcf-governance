from __future__ import annotations

import hashlib
import json
import copy
from pathlib import Path

import pytest

from bcf_governance.tooling import release_adopter_sources as sources
from bcf_governance.tooling.ci_github_api import GitHubAPI
from bcf_governance.tooling.ci_github_errors import GitHubAPIError

from bcf_governance.tooling.release_adopter_sources import (
    AdopterSourceError,
    AdopterSourceIdentity,
    require_adopter_profile,
    source_inventory_sha256,
)


def _source(*, profile: str = "standard") -> AdopterSourceIdentity:
    return AdopterSourceIdentity(
        id="sample-standard-v3",
        repository="owner/sample",
        repository_id="123",
        profile=profile,
        default_branch="pinned-local",
        commit_sha="a" * 40,
        tree_sha="b" * 40,
    )


def test_source_inventory_digest_binds_order_and_every_identity_field() -> None:
    first = _source()
    second = AdopterSourceIdentity(
        **({**first.as_dict(), "id": "other", "commit_sha": "c" * 40})
    )
    expected = hashlib.sha256(
        json.dumps(
            [first.as_dict(), second.as_dict()],
            separators=(",", ":"),
            sort_keys=True,
        ).encode()
    ).hexdigest()
    assert source_inventory_sha256((first, second)) == expected
    assert source_inventory_sha256((second, first)) != expected


def test_pinned_source_profile_must_match_before_compatibility_execution(
    tmp_path: Path,
) -> None:
    (tmp_path / "governance-profile.yml").write_text(
        "profile:\n  selected: standard\n", encoding="utf-8"
    )
    require_adopter_profile(tmp_path, _source())
    with pytest.raises(AdopterSourceError, match="differs from contract"):
        require_adopter_profile(tmp_path, _source(profile="lite"))


def test_missing_profile_fails_closed(tmp_path: Path) -> None:
    with pytest.raises(AdopterSourceError, match="profile is unreadable"):
        require_adopter_profile(tmp_path, _source())


def _provider_contract() -> dict:
    return {
        'schema_version': '1.4',
        'qualification': {
            'source': 'provider_default_branch_transaction',
            'caller_checkout_role': 'materialization_resource_only',
            'source_freshness': 'provider_exact_at_capture_and_collection',
        },
        'required_adopters': [
            {'id': 'second', 'repository': 'owner/second', 'profile': 'standard'},
            {'id': 'first', 'repository': 'owner/first', 'profile': 'lite'},
        ],
    }


def _provider(monkeypatch):
    state = {'id': 123, 'branch': 'default', 'commit': 'a' * 40, 'tree': 'b' * 40}
    calls = []

    def request(_self, method, path, **_kwargs):
        assert method == 'GET', 'source selection must not mutate provider state'
        calls.append(path)
        if '/git/ref/' in path:
            return {'ref': 'refs/heads/' + state['branch'],
                    'object': {'type': 'commit', 'sha': state['commit']}}
        if '/git/commits/' in path:
            return {'sha': state['commit'], 'tree': {'sha': state['tree']}}
        return {'id': state['id'], 'default_branch': state['branch']}

    monkeypatch.setattr(GitHubAPI, '_request', request)
    return GitHubAPI(token='test-only'), state, calls


def test_provider_source_population_is_complete_ordered_and_authentic(monkeypatch):
    api, _state, calls = _provider(monkeypatch)
    selected = sources.resolve_adopter_sources(api, _provider_contract())
    assert [item.repository for item in selected] == ['owner/second', 'owner/first']
    assert [item.profile for item in selected] == ['standard', 'lite']
    assert all(item.repository_id == '123' and item.default_branch == 'default'
               and item.commit_sha == 'a' * 40 and item.tree_sha == 'b' * 40
               for item in selected)
    assert len(calls) == 6
    sources.authenticate_adopter_sources(api, selected)
    assert len(calls) == 12


@pytest.mark.parametrize('field,value', [
    ('id', 456), ('branch', 'other'), ('commit', 'c' * 40), ('tree', 'd' * 40),
])
def test_provider_source_movement_rejects_frozen_inventory(monkeypatch, field, value):
    api, state, _calls = _provider(monkeypatch)
    selected = sources.resolve_adopter_sources(api, _provider_contract())
    frozen = tuple(item.as_dict() for item in selected)
    state[field] = value
    with pytest.raises(AdopterSourceError, match='stale'):
        sources.authenticate_adopter_sources(api, selected)
    assert tuple(item.as_dict() for item in selected) == frozen


@pytest.mark.parametrize('corruption', ['empty', 'duplicate_repository', 'duplicate_id', 'missing_profile'])
def test_provider_source_inventory_rejects_before_reads(monkeypatch, corruption):
    api, _state, calls = _provider(monkeypatch)
    contract = _provider_contract()
    if corruption == 'empty':
        contract['required_adopters'] = []
    elif corruption == 'missing_profile':
        del contract['required_adopters'][0]['profile']
    else:
        field = 'repository' if corruption == 'duplicate_repository' else 'id'
        contract['required_adopters'][1][field] = contract['required_adopters'][0][field]
    with pytest.raises(AdopterSourceError, match='inventory'):
        sources.resolve_adopter_sources(api, contract)
    assert calls == []


@pytest.mark.parametrize('corruption', ['unavailable', 'wrong_ref', 'wrong_commit', 'bad_id', 'bad_tree'])
def test_provider_source_failure_cannot_become_pinned_or_partial_success(monkeypatch, corruption):
    api, state, calls = _provider(monkeypatch)
    original = GitHubAPI._request

    def request(self, method, path, **kwargs):
        if 'owner/first' in path and corruption == 'unavailable':
            raise GitHubAPIError('provider unavailable')
        reply = original(self, method, path, **kwargs)
        if '/git/ref/' in path and corruption == 'wrong_ref':
            reply['ref'] = 'refs/heads/unrelated'
        if '/git/commits/' in path and corruption == 'wrong_commit':
            reply['sha'] = 'f' * 40
        return reply

    monkeypatch.setattr(GitHubAPI, '_request', request)
    if corruption == 'bad_id':
        state['id'] = False
    elif corruption == 'bad_tree':
        state['tree'] = 'unavailable'
    with pytest.raises(AdopterSourceError, match='provider inventory'):
        sources.resolve_adopter_sources(api, _provider_contract())
    assert calls


@pytest.mark.parametrize('corruption', ['legacy', 'missing', 'caller_role', 'freshness'])
def test_source_policy_migration_block_precedes_provider_reads(monkeypatch, corruption):
    api, _state, calls = _provider(monkeypatch)
    contract = copy.deepcopy(_provider_contract())
    if corruption == 'legacy':
        contract['schema_version'] = '1.3'
    elif corruption == 'missing':
        del contract['qualification']
    elif corruption == 'caller_role':
        contract['qualification']['caller_checkout_role'] = 'exact_source_identity'
    else:
        contract['qualification']['source_freshness'] = 'exact_at_observation'
    with pytest.raises(AdopterSourceError, match='source policy'):
        sources.resolve_adopter_sources(api, contract)
    assert calls == []

"""Admitted policy source and current default frontier are independent identities."""

from dataclasses import replace
import hashlib

import pytest
import yaml

from bcf_governance.tooling import trusted_inputs
from bcf_governance.tooling.ci_github_api import GitHubContent
from bcf_governance.tooling.ci_github_identity import GitHubControllerError, MainIdentity
from tests.test_phase_closure_population import protected_population, phase_input, SHA_A, SHA_B, TREE  # noqa: F401


@pytest.fixture
def admitted_policy(protected_population, monkeypatch):
    api, policy, calls = protected_population
    original = api.content
    history_calls = []
    historical = {
        "plans/build-plan.yml": {"phase_sequence": [{"phase_id": "P01", "hard_dependencies": []}]},
        "plans/phase-ledger.yml": {"active_phase": {"id": "P01"}},
        "plans/phase-history.yml": {"entries": []},
    }
    def content(repository, path, *, ref):
        if ref == SHA_A and path in historical:
            history_calls.append((path, ref))
            raw = yaml.safe_dump(historical[path]).encode()
            return GitHubContent(path, hashlib.sha1(raw).hexdigest(), raw)
        return original(repository, path, ref=ref)
    monkeypatch.setattr(api, "content", content)
    return api, MainIdentity("42", "main", SHA_A, TREE), history_calls


def test_historical_admitted_policy_is_not_replaced_by_current_plan(admitted_policy):
    api, subject, calls = admitted_policy
    selected, inputs = trusted_inputs.verify_required_phase_closure_inputs(
        api, repository="owner/repo", phase_id="P01", policy_subject=subject,
    )
    assert selected == subject
    assert inputs == {}
    assert len(calls) == 3 and {ref for _, ref in calls} == {SHA_A}
    assert api.main == SHA_B and api.reads == 0


@pytest.mark.parametrize("fields", [
    {"repository_id": "99"}, {"default_branch": "other"},
    {"checkout_sha": "bad"}, {"tree_sha": "bad"}, {"tree_sha": SHA_B},
])
def test_untrusted_policy_coordinates_reject_before_policy_reads(admitted_policy, fields):
    api, subject, calls = admitted_policy
    with pytest.raises(GitHubControllerError):
        trusted_inputs.verify_required_phase_closure_inputs(
            api, repository="owner/repo", phase_id="P01", policy_subject=replace(subject, **fields),
        )
    assert calls == [] and api.reads == 0


def test_non_default_lineage_policy_subject_rejects_before_policy_reads(admitted_policy):
    api, subject, calls = admitted_policy
    api.outside_default_lineage = True
    with pytest.raises(GitHubControllerError, match="lineage"):
        trusted_inputs.verify_required_phase_closure_inputs(
            api, repository="owner/repo", phase_id="P01", policy_subject=subject,
        )
    assert calls == [] and api.reads == 0


def test_admitted_policy_does_not_hide_moving_current_frontier(admitted_policy, monkeypatch):
    api, subject, _ = admitted_policy
    original = api.content
    def moved(repository, path, *, ref):
        value = original(repository, path, ref=ref)
        if path == "plans/phase-history.yml":
            api.main = SHA_A
        return value
    monkeypatch.setattr(api, "content", moved)
    with pytest.raises(GitHubControllerError, match="frontier moved"):
        trusted_inputs.verify_required_phase_closure_inputs(
            api, repository="owner/repo", phase_id="P01", policy_subject=subject,
        )
    assert api.reads == 0

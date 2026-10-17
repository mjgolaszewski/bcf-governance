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


@pytest.fixture
def advanced_admitted_population(protected_population, monkeypatch):
    api, _, calls = protected_population
    api.main = "c" * 40
    original_commit = api.commit
    def commit(repository, sha):
        if sha == SHA_B:
            assert repository == "owner/repo"
            return {"sha": SHA_B, "tree": {"sha": TREE}}
        return original_commit(repository, sha)
    monkeypatch.setattr(api, "commit", commit)
    original = api.compare_commits
    def compare(repository, *, base, head):
        if base == SHA_B:
            return {"status": "ahead", "base_commit": {"sha": base}, "merge_base_commit": {"sha": base}}
        return original(repository, base=base, head=head)
    monkeypatch.setattr(api, "compare_commits", compare)
    return api, MainIdentity("42", "main", SHA_B, TREE), calls


def test_historical_policy_consumes_real_predecessor_bundle_after_default_advances(advanced_admitted_population):
    api, subject, calls = advanced_admitted_population
    selected, inputs = trusted_inputs.verify_required_phase_closure_inputs(
        api, repository="owner/repo", phase_id="P02", policy_subject=subject,
    )
    assert selected == subject and api.main == "c" * 40
    assert {ref for _, ref in calls} == {SHA_B}
    assert list(inputs) == ["P01"]
    assert inputs["P01"][1].computed_state == "certified"
    assert inputs["P01"][2] == api.archive and api.reads == 1


def test_rewritten_admitted_subject_rejects_before_policy_reads(admitted_policy):
    api, subject, calls = admitted_policy
    api.rewritten = True
    with pytest.raises(GitHubControllerError, match="source is not exact"):
        trusted_inputs.verify_required_phase_closure_inputs(
            api, repository="owner/repo", phase_id="P01", policy_subject=subject,
        )
    assert calls == [] and api.reads == 0


@pytest.mark.parametrize("subject", [True, {"provider_authenticated": True}])
def test_asserted_authority_is_not_a_policy_subject(admitted_policy, subject):
    api, _, calls = admitted_policy
    with pytest.raises(GitHubControllerError, match="subject is invalid"):
        trusted_inputs.verify_required_phase_closure_inputs(
            api, repository="owner/repo", phase_id="P01", policy_subject=subject,
        )
    assert calls == [] and api.reads == 0


def test_active_predecessor_uses_admitted_subject_not_new_default(admitted_policy, monkeypatch):
    api, subject, _ = admitted_policy
    original = api.content
    def content(repository, path, *, ref):
        if ref == SHA_A and path == "plans/build-plan.yml":
            raw = yaml.safe_dump({"phase_sequence": [
                {"phase_id": "P01", "hard_dependencies": []},
                {"phase_id": "P02", "hard_dependencies": ["P01"]},
            ]}).encode()
            return GitHubContent(path, hashlib.sha1(raw).hexdigest(), raw)
        return original(repository, path, ref=ref)
    monkeypatch.setattr(api, "content", content)
    selected, inputs = trusted_inputs.verify_required_phase_closure_inputs(
        api, repository="owner/repo", phase_id="P02", policy_subject=subject,
    )
    assert selected == subject and api.main == SHA_B
    assert list(inputs) == ["P01"]
    assert inputs["P01"][1].computed_state == "certified"
    assert inputs["P01"][2] == api.archive and api.reads == 1


def test_admitted_source_can_derive_its_own_active_phase(admitted_policy):
    api, subject, calls = admitted_policy
    selected, inputs = trusted_inputs.verify_required_phase_closure_inputs(
        api, repository="owner/repo", phase_id=None, policy_subject=subject,
    )
    assert selected == subject and inputs == {}
    assert len(calls) == 3 and {ref for _, ref in calls} == {SHA_A}


def test_active_phase_derivation_requires_explicit_admitted_subject(protected_population):
    api, _, calls = protected_population
    with pytest.raises(GitHubControllerError, match="target"):
        trusted_inputs.verify_required_phase_closure_inputs(api, repository="owner/repo", phase_id=None)
    assert calls == [] and api.reads == 0

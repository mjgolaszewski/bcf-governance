"""Required predecessor phases come from authenticated protected lifecycle policy."""

from copy import deepcopy
import hashlib

import pytest
import yaml

from bcf_governance.tooling import trusted_inputs
from bcf_governance.tooling.ci_github_api import GitHubContent
from bcf_governance.tooling.ci_github_identity import GitHubControllerError
from tests.test_phase_closure_input import SHA_A, SHA_B, TREE, phase_input  # noqa: F401


@pytest.fixture
def protected_population(phase_input, monkeypatch):
    api, _ = phase_input
    api.main = SHA_B
    policy = {
        "plans/build-plan.yml": {"phase_sequence": [
            {"phase_id": "P02", "hard_dependencies": ["P01"]},
        ]},
        "plans/phase-ledger.yml": {"active_phase": {"id": "P02"}},
        "plans/phase-history.yml": {"entries": [{
            "phase_id": "P01", "retention_ref": SHA_A,
            "status": "planned", "derived_state_at_capture": "unverified",
            "verification_snapshot": {"commit_sha": SHA_A, "tree_sha": TREE},
        }]},
    }
    original = api.content
    calls = []
    def content(repository, path, *, ref):
        if path not in policy:
            return original(repository, path, ref=ref)
        assert repository == "owner/repo" and ref == SHA_B
        calls.append((path, ref))
        raw = yaml.safe_dump(policy[path]).encode()
        return GitHubContent(path=path, blob_oid=hashlib.sha1(raw).hexdigest(), content=raw)
    monkeypatch.setattr(api, "content", content)
    return api, policy, calls


def _verify(api, phase_id="P02"):
    return trusted_inputs.verify_required_phase_closure_inputs(
        api, repository="owner/repo", phase_id=phase_id,
    )


@pytest.mark.parametrize("path", ["plans/build-plan.yml", "plans/phase-ledger.yml", "plans/phase-history.yml"])
def test_duplicate_protected_policy_blocks_before_any_phase_artifact(protected_population, monkeypatch, path):
    api, _, _ = protected_population
    assert _verify(api)[1]["P01"][1].computed_state == "certified"
    api.reads = 0
    original = api.content

    def content(repository, observed_path, *, ref):
        result = original(repository, observed_path, ref=ref)
        if observed_path != path:
            return result
        mapping = yaml.safe_load(result.content)
        key = next(iter(mapping))
        raw = result.content + b"\n" + yaml.safe_dump({key: mapping[key]}).encode()
        oid = hashlib.sha1(b"blob " + str(len(raw)).encode() + b"\0" + raw).hexdigest()
        return GitHubContent(path=path, blob_oid=oid, content=raw)

    monkeypatch.setattr(api, "content", content)
    with pytest.raises(GitHubControllerError):
        _verify(api)
    assert api.reads == 0


def test_protected_dependencies_and_provider_certificates_define_population(protected_population):
    api, _, calls = protected_population
    subject, inputs = _verify(api)
    assert subject.checkout_sha == SHA_B
    assert list(inputs) == ["P01"]
    assert inputs["P01"][1].computed_state == "certified"
    assert inputs["P01"][2] == api.archive
    assert {ref for _, ref in calls} == {SHA_B}
    # Authored historical labels deliberately disagree with independent proof.
    assert api.reads == 1


@pytest.mark.parametrize("mutation", [
    "no_dependencies", "duplicate_dependency", "self_dependency", "malformed_dependency",
    "missing_phase", "duplicate_phase", "missing_history", "duplicate_history",
    "bad_commit", "bad_tree", "contradictory_retention", "second_missing_predecessor",
])
def test_population_defects_block_before_any_artifact_download(protected_population, mutation):
    api, policy, _ = protected_population
    phase = policy["plans/build-plan.yml"]["phase_sequence"][0]
    history = policy["plans/phase-history.yml"]["entries"]
    if mutation == "no_dependencies":
        del phase["hard_dependencies"]
    elif mutation == "duplicate_dependency":
        phase["hard_dependencies"] *= 2
    elif mutation == "self_dependency":
        phase["hard_dependencies"] = ["P02"]
    elif mutation == "malformed_dependency":
        phase["hard_dependencies"] = [" P01"]
    elif mutation == "missing_phase":
        policy["plans/build-plan.yml"]["phase_sequence"] = []
    elif mutation == "duplicate_phase":
        policy["plans/build-plan.yml"]["phase_sequence"].append(deepcopy(phase))
    elif mutation == "missing_history":
        history.clear()
    elif mutation == "duplicate_history":
        history.append(deepcopy(history[0]))
    elif mutation == "bad_commit":
        history[0]["verification_snapshot"]["commit_sha"] = "main"
    elif mutation == "bad_tree":
        history[0]["verification_snapshot"]["tree_sha"] = "unknown"
    elif mutation == "contradictory_retention":
        history[0]["retention_ref"] = SHA_B
    else:
        phase["hard_dependencies"].append("P99")
    with pytest.raises(GitHubControllerError):
        _verify(api)
    assert api.reads == 0


def test_active_predecessor_uses_current_main_without_archived_history(protected_population, monkeypatch):
    api, policy, _ = protected_population
    policy["plans/phase-ledger.yml"]["active_phase"]["id"] = "P01"
    policy["plans/phase-history.yml"]["entries"] = []
    seen = []
    def verify(_api, **kw):
        seen.append(kw)
        raise GitHubControllerError("current predecessor not closed")
    monkeypatch.setattr(trusted_inputs, "verify_phase_closure_input", verify)
    with pytest.raises(GitHubControllerError, match="current predecessor not closed"):
        _verify(api)
    assert seen == [{
        "repository": "owner/repo", "phase_id": "P01",
        "source_commit": SHA_B, "source_tree": TREE,
    }]


def test_local_candidate_policy_cannot_shrink_protected_population(protected_population, tmp_path, monkeypatch):
    api, _, _ = protected_population
    plans = tmp_path / "plans"
    plans.mkdir()
    (plans / "build-plan.yml").write_text("phase_sequence: []\n")
    (plans / "phase-history.yml").write_text("entries: []\n")
    monkeypatch.chdir(tmp_path)
    _, inputs = _verify(api)
    assert set(inputs) == {"P01"} and api.reads == 1


def test_history_completed_labels_cannot_replace_independent_proof(protected_population):
    api, policy, _ = protected_population
    history = policy["plans/phase-history.yml"]["entries"][0]
    history.update(status="completed", derived_state_at_capture="closed")
    api.missing = True
    with pytest.raises(GitHubControllerError):
        _verify(api)


def test_outer_population_reauthenticates_after_inner_verification(protected_population, monkeypatch):
    api, _, _ = protected_population
    original = trusted_inputs.verify_phase_closure_input
    def moved(*args, **kw):
        result = original(*args, **kw)
        api.main = SHA_A
        return result
    monkeypatch.setattr(trusted_inputs, "verify_phase_closure_input", moved)
    with pytest.raises(GitHubControllerError, match="frontier moved"):
        _verify(api)


def test_already_moved_policy_rejects_before_proof_download(protected_population, monkeypatch):
    api, _, _ = protected_population
    original = api.content
    def moved(repository, path, *, ref):
        value = original(repository, path, ref=ref)
        if path == "plans/phase-history.yml":
            api.main = SHA_A
        return value
    monkeypatch.setattr(api, "content", moved)
    with pytest.raises(GitHubControllerError, match="frontier moved"):
        _verify(api)
    assert api.reads == 0

"""Lifecycle eligibility consumes authenticated phase facts, never authored labels."""

import pytest
import yaml

from bcf_governance.tooling import governance_truth
from bcf_governance.tooling.evidence_workitem_lifecycle import (
    WorkitemContractError, validate_bounded_target_authored_ready,
    validate_phase_closure_authored_ready,
    workitem_observation, workitem_predecessors,
)
from tests.test_phase_closure_population import protected_population, phase_input  # noqa: F401
from tests.test_governance_truth import _make_repo, _commit, _write_complete_bundle


def _repo(root, *, predicate="requires-phase-closure:P01", future_predicate=None):
    plans = root / "plans"
    plans.mkdir()
    (plans / "phase-ledger.yml").write_text(yaml.safe_dump({
        "active_phase": {"id": "P02", "workitems": "plans/items.yml"},
    }))
    entries = [
        {"id": "P02-W01", "status": "DONE", "acceptance": [predicate] if predicate else [],
         "acceptance_evidence": ["test"]},
        {"id": "P02-W02", "status": "TODO", "acceptance": [
            "requires-workitem-closure:P02-W01",
            *([future_predicate] if future_predicate else []),
        ], "acceptance_evidence": ["test"]},
    ]
    (plans / "items.yml").write_text(yaml.safe_dump({"workitems": entries}))
    return entries


def _observe(root, api=None, repository=None):
    receipts = {"test": [{
        "result": "verified", "gate_id": "test", "evidence_id": "exact-test",
        "receipt": {"subject": {"binding": "exact_tree"}},
    }]}
    return workitem_observation(
        root, receipts, {"claims": {}}, set(), {},
        provider_api=api, repository=repository,
    )


def test_authenticated_phase_evidence_closes_only_the_bounded_workitem(tmp_path, protected_population):
    api, _, _ = protected_population
    _repo(tmp_path)
    report = _observe(tmp_path, api, "owner/repo")
    assert report["closed_ids"] == ["P02-W01"]
    assert report["items"][1]["eligible"] is True
    assert report["items"][0]["phase_predecessors"] == ["P01"]
    assert report["phase_prerequisites"]["verified_phases"] == ["P01"]
    refs = report["phase_prerequisites"]["evidence_refs"]
    assert refs[0]["artifact"]["artifact_id"] == "800"
    assert report["satisfied"] is False  # Future work remains open.


@pytest.mark.parametrize(("api", "repository"), [
    (None, None), (None, "owner/repo"), (True, "owner/repo"),
    ({"provider_authenticated": True, "phase_closed": True}, "owner/repo"),
])
def test_missing_or_caller_asserted_authority_cannot_grant_eligibility(tmp_path, api, repository):
    _repo(tmp_path)
    report = _observe(tmp_path, api, repository)
    assert report["closed_ids"] == []
    assert all(item["eligible"] is False for item in report["items"])
    assert report["phase_prerequisites"]["issues"]


def test_provider_api_without_expected_repository_cannot_grant_eligibility(tmp_path, protected_population):
    api, _, _ = protected_population
    _repo(tmp_path)
    report = _observe(tmp_path, api)
    assert report["closed_ids"] == [] and api.reads == 0


@pytest.mark.parametrize("mutation", ["missing", "later_failed", "digest_substituted"])
def test_invalid_provider_phase_evidence_remains_unverified(tmp_path, protected_population, mutation):
    api, _, _ = protected_population
    _repo(tmp_path)
    setattr(api, mutation, True)
    report = _observe(tmp_path, api, "owner/repo")
    assert report["closed_ids"] == []
    assert report["items"][0]["verification_state"] == "unverified"
    assert report["phase_prerequisites"]["issues"]


def test_candidate_cannot_remove_protected_phase_requirement(tmp_path, protected_population):
    api, _, _ = protected_population
    _repo(tmp_path, predicate=None)
    (tmp_path / "plans/build-plan.yml").write_text("phase_sequence: []\n")
    api.missing = True
    report = _observe(tmp_path, api, "owner/repo")
    assert report["closed_ids"] == []
    assert report["items"][0]["eligible"] is False


def test_another_authentic_phase_cannot_satisfy_the_declared_phase(tmp_path, protected_population):
    api, _, _ = protected_population
    _repo(tmp_path, predicate="requires-phase-closure:P99")
    report = _observe(tmp_path, api, "owner/repo")
    assert report["closed_ids"] == []
    assert report["items"][0]["missing_phase_closure"] == ["P99"]


def test_unrelated_future_phase_requirement_does_not_block_current_target(tmp_path, protected_population):
    api, _, _ = protected_population
    _repo(tmp_path, future_predicate="requires-phase-closure:P99")
    validate_bounded_target_authored_ready(
        tmp_path, "P02-W01", provider_api=api, repository="owner/repo",
    )
    report = _observe(tmp_path, api, "owner/repo")
    assert report["closed_ids"] == ["P02-W01"]
    assert report["items"][1]["eligible"] is False


def test_readiness_requires_phase_proof_from_target_predecessor_closure(tmp_path):
    entries = _repo(tmp_path)
    entries[1]["status"] = "DONE"
    (tmp_path / "plans/items.yml").write_text(yaml.safe_dump({"workitems": entries}))
    with pytest.raises(WorkitemContractError, match="phase"):
        validate_bounded_target_authored_ready(tmp_path, "P02-W02")


def test_readiness_does_not_authorize_later_computed_truth(tmp_path, protected_population):
    api, _, _ = protected_population
    _repo(tmp_path)
    validate_bounded_target_authored_ready(
        tmp_path, "P02-W01", provider_api=api, repository="owner/repo",
    )
    api.later_failed = True
    report = _observe(tmp_path, api, "owner/repo")
    assert report["closed_ids"] == []


def test_genuinely_unbound_workitem_without_phase_predicate_preserves_behavior(tmp_path):
    _repo(tmp_path, predicate=None)
    validate_bounded_target_authored_ready(tmp_path, "P02-W01")
    report = _observe(tmp_path)
    assert report["closed_ids"] == ["P02-W01"]
    assert report["items"][1]["eligible"] is True


def _phase_log(root):
    path = root / "plans/phase-ledger.yml"
    ledger = yaml.safe_load(path.read_text())
    ledger["active_phase"]["log"] = "phases/phase-02-log.yml"
    path.write_text(yaml.safe_dump(ledger))
    phases = root / "phases"
    phases.mkdir()
    (phases / "phase-02-log.yml").write_text(yaml.safe_dump({
        "document": {"status": "completed"}, "phase": {"id": "P02"},
    }))


def test_full_phase_unfinished_authored_work_blocks_before_provider_work(tmp_path, protected_population):
    api, _, _ = protected_population
    _repo(tmp_path)
    _phase_log(tmp_path)
    with pytest.raises(WorkitemContractError, match="workitems.*not authored DONE"):
        validate_phase_closure_authored_ready(tmp_path, provider_api=api, repository="owner/repo")
    assert api.reads == 0


def test_full_phase_authored_done_still_requires_authenticated_parent(tmp_path, protected_population):
    api, _, _ = protected_population
    entries = _repo(tmp_path)
    entries[1]["status"] = "DONE"
    (tmp_path / "plans/items.yml").write_text(yaml.safe_dump({"workitems": entries}))
    _phase_log(tmp_path)
    validate_phase_closure_authored_ready(tmp_path, provider_api=api, repository="owner/repo")
    with pytest.raises(WorkitemContractError, match="phase"):
        validate_phase_closure_authored_ready(tmp_path)


@pytest.mark.parametrize("predicate", [
    "requires-phase-closure:", "requires-phase-closure:p01", "requires-phase-closure: P01",
    "requires-phase-closure:P01 ", " requires-phase-closure:P01", "Requires-phase-closure:P01",
    "requires-phase-closure:P01:extra",
])
def test_phase_grammar_remains_exact_and_fail_closed(predicate):
    with pytest.raises(WorkitemContractError):
        workitem_predecessors({"acceptance": [predicate]})


def test_exact_phase_grammar_is_not_confused_with_workitem_dependency():
    assert workitem_predecessors({"acceptance": ["requires-phase-closure:P01"]}) == []


def _truth_repo(tmp_path):
    repo = _make_repo(tmp_path)
    for path in [repo / "plans/phase-ledger.yml", repo / "phases/phase-01-log.yml"]:
        value = yaml.safe_load(path.read_text())
        if "active_phase" in value:
            value["active_phase"]["id"] = "P02"
        else:
            value["phase"]["id"] = "P02"
        path.write_text(yaml.safe_dump(value))
    path = repo / "plans/phase-01-workitems.yml"
    value = yaml.safe_load(path.read_text())
    value["workitems"][0].update(id="P02-W01", acceptance=["requires-phase-closure:P01"])
    path.write_text(yaml.safe_dump(value))
    _commit(repo, "declare exact phase prerequisite")
    return repo, _write_complete_bundle(repo)


def test_existing_truth_owner_consumes_authenticated_phase_inputs(tmp_path, protected_population):
    api, _, _ = protected_population
    repo, evidence = _truth_repo(tmp_path)
    report = governance_truth.derive_truth(
        repo, evidence, evaluation_mode="workitem", evaluation_target="P02-W01",
        provider_api=api, repository="owner/repo",
    )
    assert report["status"] == "pass", report["issues"]
    assert report["certified_proposition"]["predicate"] == "workitem_closed"
    assert report["certified_proposition"]["target"] == {"kind": "workitem", "id": "P02-W01"}


def test_existing_truth_owner_without_phase_authority_cannot_close_target(tmp_path):
    repo, evidence = _truth_repo(tmp_path)
    report = governance_truth.derive_truth(
        repo, evidence, evaluation_mode="workitem", evaluation_target="P02-W01",
    )
    assert report["status"] == "fail"
    assert "bounded_workitem_target_not_closed" in report["issues"]

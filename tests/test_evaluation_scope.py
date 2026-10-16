"""Typed proposition boundaries retain exact scope without conferring authority."""
from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator, ValidationError

from bcf_governance.tooling.evaluation_scope import (
    EvaluationIntent, EvaluationScope, EvaluationScopeError, certified_proposition,
    evaluation_scope, is_terminal_phase_certification, validate_certified_proposition,
)

ROOT = Path(__file__).resolve().parents[1]
SUBJECT = {"commit_sha": "a" * 40, "tree_sha": "b" * 40}
TARGET_KINDS = tuple(json.loads((ROOT / "schemas/ci-certification.schema.json").read_text())["$defs"]["evaluationTarget"]["properties"]["kind"]["enum"])


def _report(intent="closure", status="pass", closed=True):
    scope = evaluation_scope(intent, target="P01-W01" if intent == "workitem" else None,
                             phase_id="P01", subject_commit=SUBJECT["commit_sha"])
    items = {"items": [
        {"id": "P01-W01", "effective_state": "closed" if closed else "active"},
        {"id": "P01-W02", "eligible": True, "predecessors": ["P01-W01"]},
    ]}
    proposition = certified_proposition(scope, subject=SUBJECT, status=status, workitems=items)
    return {"status": status, "evaluation_scope": scope.as_dict(), "certified_proposition": proposition}


@pytest.mark.parametrize("status", ["pass", "fail"])
@pytest.mark.parametrize("closed", [True, False])
def test_bounded_proposition_never_authorizes_failed_evaluation(status, closed):
    report = _report("workitem", status, closed)
    value = report["certified_proposition"]
    success = status == "pass" and closed
    assert value["conclusion"] == ("success" if success else "failure")
    assert value["authorizes"] == (["declared_successor_workitem_eligibility"] if success else [])
    assert value["eligible_successors"] == (["P01-W02"] if success else [])
    # A producer result must satisfy its own decoder when the final status agrees.
    report["status"] = "pass" if success else "fail"
    assert validate_certified_proposition(report, subject=SUBJECT) == value


@pytest.mark.parametrize("intent", list(EvaluationIntent))
@pytest.mark.parametrize("kind", TARGET_KINDS)
def test_proposition_decoder_binds_intent_to_canonical_target_kind(intent, kind):
    report = _report(intent.value)
    canonical = report["evaluation_scope"]["target"]["kind"]
    report["evaluation_scope"]["target"]["kind"] = kind
    report["certified_proposition"]["target"]["kind"] = kind
    if kind == canonical:
        validate_certified_proposition(report, subject=SUBJECT)
    else:
        with pytest.raises(EvaluationScopeError, match="target"):
            validate_certified_proposition(report, subject=SUBJECT)


@pytest.mark.parametrize("intent", list(EvaluationIntent))
def test_proposition_producer_rejects_scope_with_wrong_target_kind(intent):
    with pytest.raises(EvaluationScopeError, match="target"):
        certified_proposition(EvaluationScope(intent, "unknown-kind", "P01-W01"),
                              subject=SUBJECT, status="pass", workitems={})


@pytest.mark.parametrize("defect", ["empty", "missing-kind", "extra", "bad-workitem", "wrong-pr-subject"])
def test_proposition_decoder_rejects_unbound_target_identity(defect):
    report = _report("pr" if defect == "wrong-pr-subject" else "workitem")
    target = report["evaluation_scope"]["target"]
    if defect == "empty": target["id"] = ""
    elif defect == "missing-kind": target.pop("kind")
    elif defect == "extra": target["agent_choice"] = True
    elif defect == "bad-workitem": target["id"] = "P01"
    else: target["id"] = "c" * 40
    report["certified_proposition"]["target"] = copy.deepcopy(target)
    with pytest.raises(EvaluationScopeError, match="target"):
        validate_certified_proposition(report, subject=SUBJECT)


@pytest.mark.parametrize("defect", ["phase-as-workitem", "different-target", "bounded-authority", "successors", "failed-status", "missing-target", "bad-scope", "bad-proposition"])
def test_terminal_predicate_rejects_scope_or_authority_confusion(defect):
    report = _report()
    if defect == "phase-as-workitem":
        report["evaluation_scope"]["target"]["kind"] = "workitem"
        report["certified_proposition"]["target"]["kind"] = "workitem"
    elif defect == "different-target": report["certified_proposition"]["target"] = {"kind": "phase", "id": "P02"}
    elif defect == "bounded-authority": report["certified_proposition"]["authorizes"] = ["declared_successor_workitem_eligibility"]
    elif defect == "successors": report["certified_proposition"]["eligible_successors"] = ["P02-W01"]
    elif defect == "failed-status": report["status"] = "fail"
    elif defect == "missing-target": report["evaluation_scope"].pop("target")
    elif defect == "bad-scope": report["evaluation_scope"] = None
    else: report["certified_proposition"] = None
    assert is_terminal_phase_certification(report) is False


def test_terminal_predicate_preserves_valid_certification_without_truth_status():
    report = _report()
    assert is_terminal_phase_certification(report) is True
    report.pop("status")
    assert is_terminal_phase_certification(report) is True
    assert is_terminal_phase_certification(_report("workitem")) is False
    assert is_terminal_phase_certification(_report("pr")) is False


@pytest.mark.parametrize("intent", list(EvaluationIntent))
@pytest.mark.parametrize("kind", TARGET_KINDS)
def test_certification_scope_schema_matches_canonical_intent_owner(intent, kind):
    schema = json.loads((ROOT / "schemas/ci-certification.schema.json").read_text())
    scope = _report(intent.value)["evaluation_scope"]
    canonical = scope["target"]["kind"]
    scope["target"]["kind"] = kind
    validator = Draft202012Validator({"$defs": schema["$defs"], "$ref": "#/$defs/evaluationScope"})
    if kind == canonical:
        validator.validate(scope)
    else:
        with pytest.raises(ValidationError):
            validator.validate(scope)


@pytest.mark.parametrize("intent", list(EvaluationIntent))
def test_every_canonical_intent_has_schema_valid_target(intent):
    schema = json.loads((ROOT / "schemas/ci-certification.schema.json").read_text())
    validator = Draft202012Validator({"$defs": schema["$defs"], "$ref": "#/$defs/evaluationScope"})
    validator.validate(_report(intent.value)["evaluation_scope"])


@pytest.mark.parametrize("intent,target", [('workitem', 'P01'), ('pr', 'unbound'), ('workitem', 'P01-W01\n'), ('pr', 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n')])
def test_certification_schema_rejects_noncanonical_target_identity(intent, target):
    schema = json.loads((ROOT / "schemas/ci-certification.schema.json").read_text())
    scope = _report(intent)["evaluation_scope"]
    scope["target"]["id"] = target
    validator = Draft202012Validator({"$defs": schema["$defs"], "$ref": "#/$defs/evaluationScope"})
    with pytest.raises(ValidationError):
        validator.validate(scope)

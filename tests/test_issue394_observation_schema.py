"""Retained neutral observations have a strict contract and cannot confer truth."""
import json
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator

from bcf_governance.tooling.ci_graph_yaml import load_yaml_path

ROOT = Path(__file__).resolve().parents[1]


def _contract():
    plan = load_yaml_path(ROOT / "audits/issue-394/workplan.yml")
    schema = json.loads((ROOT / "audits/issue-394/workplan.schema.json").read_text())
    return plan, Draft202012Validator(schema)


def test_retained_observation_records_are_admitted_without_truth_credit():
    plan, validator = _contract()
    errors = list(validator.iter_errors(plan))
    assert not errors, [error.message for error in errors]
    assert plan["named_source_population_observation"]["authority"] is False
    assert plan["named_source_population_observation"]["execution_qualified"] is False
    assert all(row["evidence_status"] == "not_executed" for row in plan["requirements"].values())


@pytest.mark.parametrize("field,key,value", [
    ("named_source_population_observation", "authority", True),
    ("named_source_population_observation", "execution_qualified", True),
    ("named_source_population_observation", "whole_requirement_advancement", True),
    ("named_source_population_observation", "sha256", "z" * 64),
    ("named_source_population_observation", "report", "../escape.json"),
    ("named_source_population_observation", "release_certified", True),
    ("maintenance_release_lessons", "whole_requirement_advancement", True),
    ("maintenance_release_lessons", "sha256", "not-a-digest"),
    ("maintenance_release_lessons", "source_subject_before", "a" * 8),
    ("maintenance_release_lessons", "report", "../escape.yml"),
])
def test_retained_observations_reject_forged_truth_and_unbound_references(field, key, value):
    plan, validator = _contract()
    errors = list(validator.iter_errors(plan))
    assert not errors, [error.message for error in errors]
    plan[field][key] = value
    errors = list(validator.iter_errors(plan))
    assert any(tuple(error.absolute_path)[:1] == (field,) for error in errors)


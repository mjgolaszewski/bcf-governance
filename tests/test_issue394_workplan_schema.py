"""Authored followup metadata cannot confer computed authority."""
from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest
import yaml
from jsonschema import Draft202012Validator


ROOT = Path(__file__).resolve().parents[1]
FOLLOWUP = 'release_train_terminal_authority_followup'


@pytest.fixture
def inputs():
    plan = yaml.safe_load((ROOT / 'audits/issue-394/workplan.yml').read_text())
    schema = json.loads((ROOT / 'audits/issue-394/workplan.schema.json').read_text())
    return plan, Draft202012Validator(schema)


def test_retained_terminal_followup_has_a_closed_schema(inputs):
    plan, validator = inputs
    before = copy.deepcopy(plan)
    errors = list(validator.iter_errors(plan))
    assert not errors, [error.message for error in errors]
    assert plan == before
    assert plan[FOLLOWUP]['authority'] is False
    assert plan[FOLLOWUP]['acceptance_advance'] is False


@pytest.mark.parametrize('field,value,rule', [
    ('authority', True, 'const'),
    ('acceptance_advance', True, 'const'),
    ('status', 'verified', 'enum'),
    ('status', 'closed', 'enum'),
    ('contract_commit', 'HEAD', 'pattern'),
    ('query_cases_authored', True, 'type'),
])
def test_terminal_followup_rejects_invalid_authority_at_its_own_field(inputs, field, value, rule):
    plan, validator = inputs
    plan[FOLLOWUP][field] = value
    errors = list(validator.iter_errors(plan))
    assert any(tuple(error.absolute_path) == (FOLLOWUP, field) and error.validator == rule
               for error in errors), [error.message for error in errors]


@pytest.mark.parametrize('field', ['authority', 'acceptance_advance', 'runtime_readiness_audit'])
def test_terminal_followup_requires_its_existing_guards(inputs, field):
    plan, validator = inputs
    del plan[FOLLOWUP][field]
    errors = list(validator.iter_errors(plan))
    assert any(tuple(error.absolute_path) == (FOLLOWUP,) and error.validator == 'required'
               and field in error.message for error in errors), [error.message for error in errors]


def test_terminal_followup_cannot_add_an_undeclared_override(inputs):
    plan, validator = inputs
    plan[FOLLOWUP]['operator_override'] = True
    errors = list(validator.iter_errors(plan))
    assert any(tuple(error.absolute_path) == (FOLLOWUP,) and error.validator == 'additionalProperties'
               for error in errors), [error.message for error in errors]


def test_authored_done_does_not_change_followup_authority(inputs):
    plan, validator = inputs
    plan[FOLLOWUP]['status'] = 'DONE'
    errors = list(validator.iter_errors(plan))
    assert not errors, [error.message for error in errors]
    assert plan[FOLLOWUP]['authority'] is False
    assert plan[FOLLOWUP]['acceptance_advance'] is False

"""New source membership owners retain narrow typed capability checks."""
from pathlib import Path

import pytest

from bcf_governance.tooling.governance_validation.environment_boundaries import inspect_environment_source


@pytest.mark.parametrize("module", ["architecture_native_gate", "architecture_release_context", "release_adopter_qualification"])
def test_exact_membership_consumers_have_declared_typed_environment_owners(module):
    root = Path(__file__).resolve().parents[1] / "bcf_governance/tooling"
    assert inspect_environment_source((root / (module + ".py")).read_text(), module) == []


def test_unregistered_membership_setting_remains_rejected():
    source = "from .bootstrap.environment import comparison_settings\ndef compile_gate_ownership(root):\n return comparison_settings().unregistered_membership_inputs()\n"
    assert inspect_environment_source(source, "architecture_native_gate")


def test_foreign_consumer_cannot_borrow_registered_membership_capability():
    source = "from .bootstrap.environment import comparison_settings\ndef foreign(root):\n return comparison_settings().candidate_membership_inputs()\n"
    assert inspect_environment_source(source, "foreign_owner")

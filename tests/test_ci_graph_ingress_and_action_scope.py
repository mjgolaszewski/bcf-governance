"""Compiler owns placeholder validation; adopter pins do not claim framework use."""
from ci_graph_render_fixture_support import compiled_fixture as SimpleNamespace

import pytest

from bcf_governance.tooling.ci_github_actions import ACTION_PINS, ADOPTER_ACTION_PINS, action_pin
from bcf_governance.tooling.ci_graph_compatibility import validate_compatibility_declarations
from bcf_governance.tooling.ci_graph_errors import CIGraphError
from bcf_governance.tooling.ci_graph_render import _command_step


def graph(value):
    return {"commands": {"sample": {"argv": ["echo", value], "cwd": ".", "environment": {}, "required_environment": []}}, "workflows": [], "step_components": {}, "conditions": {}, "artifacts": {}}


@pytest.mark.parametrize("value", ["{env:}", "{env:lower}", "{env:BAD-NAME}", "{env:BAD;echo nope}"])
def test_invalid_placeholder_refused_at_compiler_ingress(value):
    with pytest.raises(CIGraphError, match="environment placeholder"):
        validate_compatibility_declarations(graph(value))


def test_validated_placeholder_projection_preserves_exact_name():
    value = graph("{env:BCF_EXACT_1}")
    validate_compatibility_declarations(value)
    compiled = SimpleNamespace(commands=value["commands"], trusted_controller="bcf")
    assert _command_step(compiled, "sample", name="sample")["run"] == 'set -euo pipefail\necho "$BCF_EXACT_1"'


def test_adopter_setup_uv_identity_remains_supported_and_closed():
    exact = "astral-sh/setup-uv@37802adc94f370d6bfd71619e3f0bf239e1f3b78"
    assert "setup-uv" not in ACTION_PINS
    assert ADOPTER_ACTION_PINS["setup-uv"] == exact
    assert action_pin("setup-uv") == action_pin("setup-uv", exact) == exact
    with pytest.raises(ValueError):
        action_pin("setup-uv", "astral-sh/setup-uv@main")

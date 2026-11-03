"""Opt-in authored CI compatibility, with existing renderer defaults retained."""
from types import SimpleNamespace

import pytest

from bcf_governance.tooling.ci_github_actions import action_pin
from bcf_governance.tooling.ci_graph_contracts import CIGraphError, _validate_step_components
from bcf_governance.tooling.ci_graph_render import _command_step, _component_steps, _events
from bcf_governance.tooling.ci_graph_shell_projection import hoist_run_expressions


def graph(command=None, component=None, event=None):
    return {
        "artifacts": {}, "conditions": {},
        "commands": {"cleanup": command} if command else {},
        "step_components": {"cleanup": component} if component else {},
        "workflows": [{"events": [event]}] if event else [],
    }


def command(body="bash scripts/tools/ci_cleanup.sh end"):
    return {"argv": ["bash", "-c", body], "cwd": ".", "environment": {},
            "required_environment": [], "render_mode": "shell-body"}


def component():
    return {"kind": "command", "name": "Clean CI disk after job", "id": None,
            "command": "cleanup", "condition": "always", "condition_style": "bare",
            "environment": {}, "produces": [], "consumes": []}


def test_original_cleanup_bytes_and_builtin_condition_survive_projection():
    value = graph(command(), component())
    _validate_step_components(value)
    compiled = SimpleNamespace(graph=value, commands=value["commands"])
    steps = _component_steps(compiled, ["cleanup"])
    hoist_run_expressions(steps)
    assert steps[0]["run"] == "bash scripts/tools/ci_cleanup.sh end"
    assert steps[0]["name"] == "Clean CI disk after job"
    assert steps[0]["if"] == "always()"


def test_default_argv_and_condition_projection_remain_unchanged():
    cmd = command()
    cmd.pop("render_mode")
    part = component()
    part.pop("condition_style")
    value = graph(cmd, part)
    compiled = SimpleNamespace(graph=value, commands=value["commands"])
    step = _component_steps(compiled, ["cleanup"])[0]
    assert step["run"] == "set -euo pipefail\nbash -c 'bash scripts/tools/ci_cleanup.sh end'"
    assert step["if"] == "${{ always() }}"


@pytest.mark.parametrize("argv", [["echo", "hello"], ["sh", "-c", "true"],
                                  ["bash", "-c", "true", "extra"],
                                  ["bash", "-c", "bad\x00body"]])
def test_shell_body_refuses_ambiguous_invocation(argv):
    cmd = command()
    cmd["argv"] = argv
    with pytest.raises(CIGraphError):
        _validate_step_components(graph(cmd))


@pytest.mark.parametrize("condition", [None, "success", "custom"])
def test_bare_conditions_cannot_render_arbitrary_expressions(condition):
    part = component()
    part["condition"] = condition
    with pytest.raises(CIGraphError):
        _validate_step_components(graph(command(), part))


def test_explicit_null_workflow_call_preserves_original_preflight_event():
    event = {"type": "workflow_call", "empty_configuration": "null"}
    _validate_step_components(graph(event=event))
    assert _events([event]) == {"workflow_call": None}
    assert _events([{"type": "workflow_call"}]) == {"workflow_call": {}}


@pytest.mark.parametrize("event", [
    {"type": "push", "empty_configuration": "null"},
    {"type": "workflow_call", "empty_configuration": "null", "inputs": {}},
])
def test_null_event_refuses_discarded_configuration(event):
    with pytest.raises(CIGraphError):
        _validate_step_components(graph(event=event))


def test_original_immutable_action_sources_are_explicit_and_closed():
    original = "actions/checkout@93cb6efe18208431cddfb8368fd83d5badbf9bfd"
    assert action_pin("checkout", original) == original
    assert action_pin("checkout") == "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1"
    assert action_pin("upload-artifact", "actions/upload-artifact@b7c566a772e6b6bfb58ed0dc250532a479d7789f")
    assert action_pin("setup-uv") == "astral-sh/setup-uv@37802adc94f370d6bfd71619e3f0bf239e1f3b78"
    for source in ["actions/checkout@main", "evil/checkout@" + "a" * 40,
                   "actions/upload-artifact@b7c566a772e6b6bfb58ed0dc250532a479d7789f"]:
        with pytest.raises(ValueError):
            action_pin("checkout", source)


def test_shell_body_still_hoists_provider_data_and_refuses_interpreter_sink():
    compiled = SimpleNamespace(commands={"cleanup": command('echo "${{ github.event.pull_request.title }}"')})
    steps = [_command_step(compiled, "cleanup", name="Observe")]
    hoist_run_expressions(steps)
    assert "${{ github.event.pull_request.title }}" not in steps[0]["run"]
    assert steps[0]["env"]["BCF_RUN_EXPRESSION_0"] == "${{ github.event.pull_request.title }}"
    compiled.commands["cleanup"] = command('bash -c "${{ github.event.pull_request.title }}"')
    with pytest.raises(AssertionError, match="interpreter source sink"):
        hoist_run_expressions([_command_step(compiled, "cleanup", name="Refuse")])

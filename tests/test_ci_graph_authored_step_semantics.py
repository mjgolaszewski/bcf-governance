"""Preserve native scan outcomes and successful verifier environment bindings."""
from __future__ import annotations

import copy
import json
from pathlib import Path
from types import SimpleNamespace

import pytest
from jsonschema import Draft202012Validator

from bcf_governance.tooling.ci_graph_compatibility import validate_compatibility_declarations
from bcf_governance.tooling.ci_graph_conditions import validate_authored_conditions
from bcf_governance.tooling.ci_graph_environment_bindings import validate_environment_output_bindings
from bcf_governance.tooling.ci_graph_errors import CIGraphError
from bcf_governance.tooling.ci_graph_render import _command_step, _component_steps, _job
from bcf_governance.tooling.ci_graph_step_outcomes import validate_deferred_step_failures


def command(body):
    return {"argv": ["bash", "-c", body], "render_mode": "shell-body",
            "cwd": ".", "environment": {}, "required_environment": []}


def component(name, command_id, step_id=None, condition=None):
    return {"kind": "command", "name": name, "command": command_id,
            "id": step_id, "condition": condition, "environment": {},
            "produces": [], "consumes": []}


def job(job_id, sequence):
    return {"id": job_id, "display_name": job_id, "semantic_role": job_id,
            "trust": "candidate", "permissions": {"contents": "read"},
            "condition": "success", "needs": [], "outputs": {},
            "produces": [], "consumes": [], "checkout": False,
            "components": [], "resource_class": "candidate", "timeout_minutes": 5,
            "environment": {}, "controller_requirement": None,
            "executor": {"kind": "component_sequence", "components": sequence}}


def scan_graph():
    scan = component("Run scan", "scan", "scan")
    scan.update(continue_on_error=True, failure_guard="fail-scan")
    guard = component("Fail scan", "exit-one", condition="scan-failed")
    guard["condition_style"] = "named"
    return {"commands": {"scan": command("make security-scan"), "exit-one": command("exit 1")},
            "conditions": {"scan-failed": "steps.scan.outcome != 'success'"},
            "step_components": {"scan": scan, "fail-scan": guard}, "artifacts": {},
            "workflows": [{"events": [], "jobs": [job("security-scan", ["scan", "fail-scan"])]}]}


def test_deferred_scan_renders_native_flag_and_exact_later_outcome_guard():
    graph = scan_graph()
    validate_compatibility_declarations(graph)
    compiled = SimpleNamespace(graph=graph, commands=graph["commands"])
    steps = _component_steps(compiled, ["scan", "fail-scan"])
    assert steps[0]["continue-on-error"] is True
    assert steps[0]["id"] == "scan"
    assert steps[1]["if"] == "steps.scan.outcome != 'success'"
    assert steps[1]["run"] == "exit 1"
    assert "continue-on-error" not in steps[1]


@pytest.mark.parametrize("mutation", [
    lambda g: g["step_components"]["scan"].update(continue_on_error="true"),
    lambda g: g["step_components"]["scan"].pop("failure_guard"),
    lambda g: g["step_components"]["scan"].update(id=None),
    lambda g: g["step_components"]["fail-scan"].update(continue_on_error=True),
    lambda g: g["commands"]["exit-one"].update(argv=["bash", "-c", "true"]),
    lambda g: g["commands"].pop("exit-one"),
    lambda g: g["conditions"].update({"scan-failed": "always()"}),
    lambda g: g["conditions"].update({"scan-failed": "steps.other.outcome != 'success'"}),
    lambda g: g["workflows"][0]["jobs"][0]["executor"].update(components=["fail-scan", "scan"]),
    lambda g: g["workflows"][0]["jobs"][0].update(semantic_role="cheap-preflight"),
    lambda g: g["workflows"][0]["jobs"][0].update(trust="trusted"),
    lambda g: g["workflows"][0]["jobs"][0]["executor"].update(kind="terminal_truth"),
])
def test_deferred_failure_cannot_lose_guard_or_become_governance_authority(mutation):
    graph = scan_graph()
    mutation(graph)
    with pytest.raises(CIGraphError):
        validate_compatibility_declarations(graph)


def test_receipt_and_control_artifact_owners_cannot_defer_failure():
    for kind in ["session", "terminal", "control", "durable-reference"]:
        graph = scan_graph()
        graph["artifacts"]["proof"] = {"kind": kind}
        graph["workflows"][0]["jobs"][0]["produces"] = ["proof"]
        with pytest.raises(CIGraphError, match="evidence"):
            validate_deferred_step_failures(graph)


@pytest.mark.parametrize("period", ["nightly", "weekly"])
def test_original_missing_summary_failure_guard_is_preserved(period):
    graph = scan_graph()
    graph["step_components"]["scan"]["id"] = period + "-mutation"
    expression = "steps." + period + "-mutation.outcome != 'success' && hashFiles('.artifacts/mutation/" + period + "/summary.json') == ''"
    graph["conditions"]["scan-failed"] = expression
    validate_compatibility_declarations(graph)
    steps = _component_steps(SimpleNamespace(graph=graph, commands=graph["commands"]), ["scan", "fail-scan"])
    assert steps[1]["if"] == expression


@pytest.mark.parametrize("expression", [
    "always() && hashFiles('.artifacts/security/*.sarif') != ''",
    "steps.grype-scan.outcome != 'success'",
])
def test_closed_condition_grammar_supports_original_artifact_and_outcome_guards(expression):
    graph = {"conditions": {"authored": expression}, "workflows": []}
    validate_authored_conditions(graph)


@pytest.mark.parametrize("expression", [
    "hashFiles('../outside') != ''", "hashFiles('/absolute') != ''",
    "hashFiles(github.event.title) != ''", "evilFunction('x')",
    "always() && ${{ github.event.title }}", "hashFiles('x', 'y') != ''",
])
def test_conditions_refuse_traversal_dynamic_calls_and_inline_passthrough(expression):
    with pytest.raises(CIGraphError):
        validate_authored_conditions({"conditions": {"unsafe": expression}, "workflows": []})


def test_shell_body_preserves_exact_authored_environment_and_argv_default():
    cmd = command("scan-image")
    cmd["environment"] = {"TMPDIR": "${{ github.workspace }}/.artifacts/tmp"}
    compiled = SimpleNamespace(commands={"scan": cmd})
    assert _command_step(compiled, "scan", name="Scan")["env"] == cmd["environment"]
    cmd.pop("render_mode")
    assert "BCF_PYTHON" in _command_step(compiled, "scan", name="Scan")["env"]


def environment_graph():
    verifier = job("verify-identity-environment", ["verify"])
    verifier["outputs"] = {"environment": "${{ steps.verify.outputs.environment }}"}
    consumer = job("enterprise-contract-tests", ["contract"])
    consumer["needs"] = ["pre-clean-runner", verifier["id"]]
    consumer["protected_environment_from"] = {"job": verifier["id"], "output": "environment"}
    return {"conditions": {}, "artifacts": {}, "commands": {"verify": command("verify-existing-environment"), "contract": command("run-contract-tests")},
            "step_components": {"verify": component("Verify existing environment", "verify", "verify"),
                                "contract": component("Run contracts", "contract")},
            "workflows": [{"events": [], "jobs": [verifier, consumer]}]}


def test_verified_environment_binding_renders_original_mapping(monkeypatch):
    graph = environment_graph()
    validate_environment_output_bindings(graph)
    from bcf_governance.tooling import ci_graph_render
    monkeypatch.setattr(ci_graph_render, "controller_requirement_condition", lambda *args: None)
    compiled = SimpleNamespace(
        graph=graph, commands=graph["commands"], trusted_controller_lifecycle=None,
    )
    consumer = graph["workflows"][0]["jobs"][1]
    graph["resource_classes"] = {"candidate": {"runner": ["self-hosted"]}}
    rendered = _job(compiled, graph["workflows"][0], consumer)
    assert rendered["environment"] == {"name": "${{ needs.verify-identity-environment.outputs.environment }}"}


@pytest.mark.parametrize("mutation", [
    lambda g: g["workflows"][0]["jobs"][1].update(needs=[]),
    lambda g: g["workflows"][0]["jobs"][1].update(condition="always"),
    lambda g: g["workflows"][0]["jobs"][0].update(condition="always"),
    lambda g: g["workflows"][0]["jobs"][0].update(outputs={}),
    lambda g: g["workflows"][0]["jobs"][1].update(protected_environment="unverified"),
    lambda g: g["workflows"][0]["jobs"][1].update(executor={"kind": "reusable_workflow"}),
    lambda g: g["step_components"]["verify"].update(condition="failure"),
    lambda g: g["workflows"][0]["jobs"][0]["executor"].update(components=["undeclared"]),
    lambda g: g["step_components"]["verify"].update(continue_on_error=True),
    lambda g: g["workflows"][0]["jobs"][0]["permissions"].update(actions="write"),
])
def test_environment_binding_refuses_failed_skipped_undeclared_or_privileged_verifier(mutation):
    graph = environment_graph()
    mutation(graph)
    with pytest.raises(CIGraphError):
        validate_environment_output_bindings(graph)


def test_schema_requires_literal_boolean_and_closed_environment_binding():
    schema = json.loads((Path(__file__).resolve().parents[1] / "schemas/ci-graph.schema.json").read_text())
    validator = Draft202012Validator({"$defs": schema["$defs"], "$ref": "#/$defs/stepComponent"})
    scan = copy.deepcopy(scan_graph()["step_components"]["scan"])
    assert not list(validator.iter_errors(scan))
    scan["continue_on_error"] = "true"
    assert list(validator.iter_errors(scan))
    assert schema["$defs"]["job"]["properties"]["protected_environment_from"]["additionalProperties"] is False


@pytest.mark.parametrize("suffix", [
    " && false", " && github.event.enabled", " || true",
    " && hashFiles('.artifacts/mutation/nightly/summary.json') == ''",
])
def test_deferred_failure_refuses_masking_conjuncts(suffix):
    graph = scan_graph()
    graph["conditions"]["scan-failed"] += suffix
    with pytest.raises(CIGraphError):
        validate_compatibility_declarations(graph)


@pytest.mark.parametrize("style", ["bare", "unrecognized"])
def test_deferred_guard_refuses_renderer_style_mismatch(style):
    graph = scan_graph()
    graph["step_components"]["fail-scan"]["condition_style"] = style
    with pytest.raises(CIGraphError):
        validate_deferred_step_failures(graph)


@pytest.mark.parametrize("condition", ["success", "always", "failure", "cancelled"])
@pytest.mark.parametrize("style", ["named", "expression"])
def test_deferred_guard_refuses_reserved_condition_shadowing(condition, style):
    graph = scan_graph()
    graph["conditions"][condition] = graph["conditions"]["scan-failed"]
    graph["step_components"]["fail-scan"].update(condition=condition, condition_style=style)
    with pytest.raises(CIGraphError):
        validate_compatibility_declarations(graph)


def test_deferred_outcome_guard_allows_always_prefix():
    graph = scan_graph()
    graph["conditions"]["scan-failed"] = "always() && " + graph["conditions"]["scan-failed"]
    validate_compatibility_declarations(graph)
    steps = _component_steps(SimpleNamespace(graph=graph, commands=graph["commands"]), ["scan", "fail-scan"])
    assert steps[1]["if"] == graph["conditions"]["scan-failed"]


def test_original_missing_summary_guard_refuses_different_summary_path():
    graph = scan_graph()
    graph["step_components"]["scan"]["id"] = "nightly-mutation"
    graph["conditions"]["scan-failed"] = "steps.nightly-mutation.outcome != 'success' && hashFiles('.artifacts/mutation/weekly/summary.json') == ''"
    with pytest.raises(CIGraphError):
        validate_deferred_step_failures(graph)

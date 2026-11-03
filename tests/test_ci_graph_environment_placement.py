"""Keep required credentials checked after safe preparation and before work."""
from copy import deepcopy
from types import SimpleNamespace

import pytest

from bcf_governance.tooling.ci_graph_compatibility import validate_compatibility_declarations
from bcf_governance.tooling.ci_graph_environment_placement import validate_environment_placement
from bcf_governance.tooling.ci_graph_errors import CIGraphError
from bcf_governance.tooling.ci_graph_render import _job


def fixture_graph():
    def command(body, environment=None, required=None):
        return {"argv": ["bash", "-c", body], "render_mode": "shell-body", "cwd": ".",
                "environment": environment or {}, "required_environment": required or []}
    def component(name, command_id):
        return {"kind": "command", "name": name, "command": command_id, "id": None,
                "condition": None, "environment": {}, "produces": [], "consumes": []}
    components = {"checkout": {"kind": "action", "name": "Checkout repository", "action": "checkout",
                   "with": {"persist-credentials": False}, "id": None, "condition": None,
                   "environment": {}, "produces": [], "consumes": []},
                  "cleanup": component("Clean CI disk before job", "cleanup"),
                  "temp": component("Prepare CI temp directories", "temp"),
                  "work": component("Run credential-bound work", "work")}
    job = {"id": "architecture", "display_name": "Architecture", "condition": "success", "needs": [],
           "permissions": {"contents": "read"}, "outputs": {}, "resource_class": "candidate",
           "timeout_minutes": 30, "environment": {}, "controller_requirement": None,
           "checkout": False, "components": [], "produces": [], "consumes": [], "trust": "candidate",
           "required_environment_position": "after-repo-preparation",
           "executor": {"kind": "component_sequence", "components": ["checkout", "cleanup", "temp", "work"]}}
    return {"step_components": components, "commands": {
        "cleanup": command("bash scripts/tools/ci_cleanup.sh start"), "temp": command("mkdir -p .artifacts/tmp"),
        "work": command("perform-work", {"GITHUB_TOKEN": "${{ github.token }}"}, ["GITHUB_TOKEN"])},
        "conditions": {}, "artifacts": {}, "resource_classes": {"candidate": {"runner": ["self-hosted"]}},
        "workflows": [{"events": [], "jobs": [job]}]}


def render(graph, monkeypatch, *, whole=False):
    from bcf_governance.tooling import ci_graph_render
    monkeypatch.setattr(ci_graph_render, "controller_requirement_condition", lambda *args: None)
    compiled = SimpleNamespace(graph=graph, commands=graph["commands"], trusted_controller_lifecycle=None)
    workflow = graph["workflows"][0]
    result = _job(compiled, workflow, workflow["jobs"][0])
    return result if whole else result["steps"]


def test_required_token_check_follows_exact_safe_prefix_before_work(monkeypatch):
    graph = fixture_graph()
    validate_environment_placement(graph)
    steps = render(graph, monkeypatch)
    assert [step["name"] for step in steps[:3]] == ["Checkout repository", "Clean CI disk before job", "Prepare CI temp directories"]
    assert steps[3]["name"] == "Validate all required environment inputs before work"
    assert steps[3]["env"] == {"GITHUB_TOKEN": "${{ github.token }}"}
    assert 'test -n "$GITHUB_TOKEN"' in steps[3]["run"]
    assert steps[4]["name"] == "Run credential-bound work"
    assert graph["commands"]["work"]["required_environment"] == ["GITHUB_TOKEN"]


def test_existing_environment_first_default_is_preserved(monkeypatch):
    graph = fixture_graph()
    del graph["workflows"][0]["jobs"][0]["required_environment_position"]
    validate_environment_placement(graph)
    assert render(graph, monkeypatch)[0]["name"] == "Validate all required environment inputs before work"


@pytest.mark.parametrize("mutation", [
    lambda g: g["workflows"][0]["jobs"][0].update(checkout=True),
    lambda g: g["workflows"][0]["jobs"][0].update(consumes=["session"]),
    lambda g: g["workflows"][0]["jobs"][0]["executor"].update(components=["checkout", "work", "temp", "cleanup"]),
    lambda g: g["step_components"]["cleanup"].update(condition="always"),
    lambda g: g["step_components"]["cleanup"].update(continue_on_error=True),
    lambda g: g["step_components"]["cleanup"].update(environment={"GITHUB_TOKEN": "secret"}),
    lambda g: g["step_components"]["checkout"]["with"].update({"persist-credentials": True}),
    lambda g: g["step_components"]["checkout"]["with"].update(path="other"),
    lambda g: g["step_components"]["checkout"]["with"].update(repository="other/repo"),
    lambda g: g["step_components"]["checkout"]["with"].update(token="${{ secrets.OTHER_TOKEN }}"),
    lambda g: g["step_components"]["checkout"]["with"].update({"ssh-key": "private-fixture"}),
    lambda g: g["step_components"]["checkout"]["with"].update(submodules=True),
    lambda g: g["step_components"]["checkout"]["with"].update(ref="other-branch"),
    lambda g: g["step_components"]["checkout"]["with"].update({"fetch-depth": 1}),
    lambda g: g["step_components"]["checkout"]["with"].update({"fetch-depth": False}),
    lambda g: g["commands"]["cleanup"].update(argv=["bash", "-c", "run-arbitrary-work"]),
    lambda g: g["commands"]["temp"].update(required_environment=["GITHUB_TOKEN"]),
    lambda g: g["workflows"][0]["jobs"][0].update(required_environment_position="after-work"),
])
def test_unsafe_or_skipped_prefix_is_refused(mutation):
    graph = deepcopy(fixture_graph())
    mutation(graph)
    with pytest.raises(CIGraphError):
        validate_environment_placement(graph)


def test_exact_candidate_checkout_ref_and_full_history_are_supported():
    graph = fixture_graph()
    graph["step_components"]["checkout"]["with"].update({"ref": "${{ github.sha }}", "fetch-depth": 0})
    validate_environment_placement(graph)


def test_opt_in_singleton_needs_preserves_original_scalar(monkeypatch):
    graph = fixture_graph()
    job = graph["workflows"][0]["jobs"][0]
    job.update(needs=["pre-clean-runner"], needs_style="singleton-scalar")
    validate_compatibility_declarations(graph)
    assert render(graph, monkeypatch, whole=True)["needs"] == "pre-clean-runner"
    assert job["needs"] == ["pre-clean-runner"]


@pytest.mark.parametrize("needs", [[], ["pre-clean-runner", "verify-identity-environment"]])
def test_singleton_needs_refuses_zero_or_multiple_dependencies(needs):
    graph = fixture_graph()
    graph["workflows"][0]["jobs"][0].update(needs=needs, needs_style="singleton-scalar")
    with pytest.raises(CIGraphError, match="exactly one"):
        validate_compatibility_declarations(graph)


@pytest.mark.parametrize("needs", [["pre-clean-runner"], ["pre-clean-runner", "verify-identity-environment"]])
def test_default_needs_array_is_preserved(monkeypatch, needs):
    graph = fixture_graph()
    graph["workflows"][0]["jobs"][0]["needs"] = needs
    validate_compatibility_declarations(graph)
    assert render(graph, monkeypatch, whole=True)["needs"] == needs

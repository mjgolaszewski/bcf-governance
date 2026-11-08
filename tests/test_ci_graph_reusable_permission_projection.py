"""Omit redundant reusable permissions only when exact inheritance is safe."""
from ci_graph_render_fixture_support import compiled_fixture as SimpleNamespace

import pytest

from bcf_governance.tooling.ci_graph_compatibility import validate_compatibility_declarations
from bcf_governance.tooling.ci_graph_errors import CIGraphError
from bcf_governance.tooling.ci_graph_render import _job
from bcf_governance.tooling.ci_graph_reusable_artifacts import project_reusable_workflow_permissions


def graph_fixture():
    caller = {"id": "pre-clean-runner", "display_name": "Preclean", "omit_name": True,
              "needs": [], "condition": "success", "permissions": {}, "outputs": {},
              "controller_requirement": None, "permissions_style": "inherit-workflow",
              "executor": {"kind": "reusable_workflow", "path": ".github/workflows/ci-preflight.yml", "inputs": {}}}
    leaf = {"id": "pre-clean-runner", "permissions": {}, "executor": {"kind": "component_sequence", "components": []}}
    return {"commands": {}, "step_components": {}, "conditions": {}, "artifacts": {},
            "workflows": [{"path": ".github/workflows/quality.yml", "events": [],
                           "permissions": {"contents": "read"}, "jobs": [caller]},
                          {"path": ".github/workflows/ci-preflight.yml", "events": [],
                           "permissions": {"contents": "read"}, "jobs": [leaf]}]}


def rendered(graph, monkeypatch):
    from bcf_governance.tooling import ci_graph_render
    monkeypatch.setattr(ci_graph_render, "controller_requirement_condition", lambda *args: None)
    workflow = graph["workflows"][0]
    return _job(SimpleNamespace(graph=graph, trusted_controller_lifecycle=None), workflow, workflow["jobs"][0])


def test_uses_only_projection_retains_derived_security_bound(monkeypatch):
    graph = graph_fixture()
    project_reusable_workflow_permissions(graph)
    validate_compatibility_declarations(graph)
    assert graph["workflows"][0]["jobs"][0]["permissions"] == {"contents": "read"}
    assert rendered(graph, monkeypatch) == {"uses": "./.github/workflows/ci-preflight.yml"}
    assert graph["workflows"][0]["jobs"][0]["permissions"] == {"contents": "read"}


def test_existing_explicit_permission_projection_is_unchanged(monkeypatch):
    graph = graph_fixture()
    del graph["workflows"][0]["jobs"][0]["permissions_style"]
    project_reusable_workflow_permissions(graph)
    validate_compatibility_declarations(graph)
    assert rendered(graph, monkeypatch) == {"permissions": {"contents": "read"}, "uses": "./.github/workflows/ci-preflight.yml"}


@pytest.mark.parametrize("bound", [{}, {"contents": "write"}, {"contents": "read", "actions": "read"}])
def test_different_workflow_permission_bound_is_refused(bound):
    graph = graph_fixture()
    project_reusable_workflow_permissions(graph)
    graph["workflows"][0]["permissions"] = bound
    with pytest.raises(CIGraphError, match="exact workflow permission bound"):
        validate_compatibility_declarations(graph)


def test_changed_child_authority_cannot_be_hidden_by_inheritance():
    graph = graph_fixture()
    graph["workflows"][1]["jobs"][0]["permissions"] = {"contents": "write"}
    project_reusable_workflow_permissions(graph)
    assert graph["workflows"][0]["jobs"][0]["permissions"] == {"contents": "write"}
    with pytest.raises(CIGraphError):
        validate_compatibility_declarations(graph)


def test_nonreusable_job_cannot_omit_permissions():
    graph = graph_fixture()
    caller = graph["workflows"][0]["jobs"][0]
    caller["permissions"] = {"contents": "read"}
    caller["executor"] = {"kind": "component_sequence", "components": []}
    with pytest.raises(CIGraphError):
        validate_compatibility_declarations(graph)


@pytest.mark.parametrize("filename", ["gitleaks-secret-scan.yml", "sbom-vuln-scan.yml"])
def test_original_readonly_caller_superset_keeps_explicit_callee_bound(monkeypatch, filename):
    graph = graph_fixture()
    graph["workflows"][0]["path"] = ".github/workflows/" + filename
    graph["workflows"][0]["permissions"] = {"contents": "read", "actions": "read"}
    graph["workflows"][0]["jobs"][0]["permissions_style"] = "inherit-callee-bound"
    project_reusable_workflow_permissions(graph)
    validate_compatibility_declarations(graph)
    assert rendered(graph, monkeypatch) == {"uses": "./.github/workflows/ci-preflight.yml"}
    assert graph["workflows"][0]["jobs"][0]["permissions"] == {"contents": "read"}
    assert graph["workflows"][0]["permissions"] == {"contents": "read", "actions": "read"}
    assert graph["workflows"][1]["permissions"] == {"contents": "read"}


@pytest.mark.parametrize("mutation", [
    lambda g: g["workflows"][0]["permissions"].update(actions="write"),
    lambda g: g["workflows"][0]["permissions"].update(contents="none"),
    lambda g: g["workflows"][1].update(permissions={}),
    lambda g: g["workflows"][1]["jobs"][0].update(permissions={"contents": "write"}),
    lambda g: g["workflows"][1]["jobs"][0].update(permissions={"contents": "read", "actions": "read"}),
    lambda g: g["workflows"][1]["jobs"][0].update(executor={"kind": "reusable_workflow", "path": ".github/workflows/ci-preflight.yml"}),
    lambda g: g["workflows"][1].update(jobs=[]),
    lambda g: g["workflows"][0]["jobs"][0].update(permissions={}),
])
def test_callee_bound_cannot_hide_writes_missing_limits_or_nested_dispatch(mutation):
    graph = graph_fixture()
    graph["workflows"][0]["permissions"] = {"contents": "read", "actions": "read"}
    graph["workflows"][0]["jobs"][0]["permissions_style"] = "inherit-callee-bound"
    project_reusable_workflow_permissions(graph)
    mutation(graph)
    with pytest.raises(CIGraphError):
        validate_compatibility_declarations(graph)


def test_absent_opt_in_does_not_require_unrelated_workflow_path():
    from bcf_governance.tooling.ci_graph_permission_projection import validate_permission_projection
    validate_permission_projection({"workflows": [{"jobs": []}]})

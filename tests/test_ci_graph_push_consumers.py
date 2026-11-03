"""Ordinary split push CI cannot acquire exact-main authority."""
import copy
from types import SimpleNamespace

import pytest

from bcf_governance.tooling.ci_graph_errors import CIGraphError
from bcf_governance.tooling.ci_graph_push_authority import validate_push_authority
from bcf_governance.tooling.ci_graph_render import _job


def fixture():
    authority = {"id": "exact-main", "role": "exact-main", "path": ".github/workflows/exact.yml",
                 "events": [{"type": "push"}], "permissions": {}, "jobs": []}
    job = {"trust": "candidate", "permissions": {"contents": "read"},
           "semantic_role": "quality", "executor": {"kind": "command", "command": "quality"},
           "produces": []}
    consumers = [{"id": "quality-" + str(i), "role": "push-consumer",
                  "path": ".github/workflows/quality-" + str(i) + ".yml",
                  "events": [{"type": "push"}, {"type": "workflow_dispatch"}],
                  "permissions": {"contents": "read"}, "jobs": [copy.deepcopy(job)]}
                 for i in range(4)]
    return {"workflows": [authority, *consumers], "artifacts": {}, "step_components": {}}


def test_five_push_workflows_keep_exactly_one_authority():
    graph = fixture()
    validate_push_authority(graph)
    assert sum(any(event["type"] == "push" for event in w["events"])
               for w in graph["workflows"]) == 5


@pytest.mark.parametrize("mutation", [
    lambda g: g["workflows"][0].update(role="custom"),
    lambda g: g["workflows"][1].update(role="exact-main"),
    lambda g: g["workflows"][1].update(role="custom"),
    lambda g: g["workflows"][1]["permissions"].update(contents="write"),
    lambda g: g["workflows"][1]["jobs"][0].update(trust="trusted"),
    lambda g: g["workflows"][1]["jobs"][0]["permissions"].update(checks="write"),
    lambda g: g["workflows"][1]["jobs"][0].update(semantic_role="exact-main-admission"),
    lambda g: g["workflows"][1]["jobs"][0].update(executor={"kind": "authority"}),
    lambda g: g["workflows"][1]["jobs"][0].update(executor={"kind": "terminal_truth"}),
    lambda g: g["workflows"][1]["jobs"][0].update(executor={"kind": "reusable_workflow", "path": ".github/workflows/exact.yml"}),
    lambda g: g["workflows"][1]["events"].append({"type": "pull_request_target"}),
])
def test_consumer_refuses_authority_escalation(mutation):
    graph = fixture()
    mutation(graph)
    with pytest.raises(CIGraphError, match="push authority"):
        validate_push_authority(graph)


def test_reusable_callee_is_checked_for_transitive_privilege():
    graph = fixture()
    workflow = graph["workflows"][1]
    callee = copy.deepcopy(workflow)
    callee.update(id="preflight", path=".github/workflows/preflight.yml", role="custom",
                  events=[{"type": "workflow_call"}])
    graph["workflows"].append(callee)
    workflow["jobs"][0]["executor"] = {"kind": "reusable_workflow", "path": callee["path"]}
    validate_push_authority(graph)
    callee["jobs"][0]["executor"] = {"kind": "authority"}
    with pytest.raises(CIGraphError, match="push authority"):
        validate_push_authority(graph)


def test_original_uses_only_preflight_is_an_explicit_projection(monkeypatch):
    from bcf_governance.tooling import ci_graph_render
    monkeypatch.setattr(ci_graph_render, "controller_requirement_condition", lambda *args: None)
    job = {"display_name": "unique-preflight-name", "omit_name": True, "needs": [],
           "condition": "success", "controller_requirement": None, "permissions": {},
           "outputs": {}, "executor": {"kind": "reusable_workflow",
                                        "path": ".github/workflows/ci-preflight.yml", "inputs": {}}}
    compiled = SimpleNamespace(trusted_controller_lifecycle=None)
    assert _job(compiled, {}, job) == {"uses": "./.github/workflows/ci-preflight.yml"}
    job.pop("omit_name")
    assert _job(compiled, {}, job)["name"] == "unique-preflight-name"

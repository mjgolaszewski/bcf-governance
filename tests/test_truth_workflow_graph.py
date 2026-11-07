"""Causal workflow-ownership checks against preserved real serial capture commands."""
import copy
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from bcf_governance.tooling import truth_workflow_graph as owner

FIXTURE = Path(__file__).parent / "fixtures" / "serial_gate_capture_commands.json"
WORKFLOW = ".github/workflows/governance.yml"


def _graph(monkeypatch):
    capture = json.loads(FIXTURE.read_text())
    commands = copy.deepcopy(capture["commands"])
    components = {
        key: {"kind": "command", "command": key, "condition": "always"}
        for key in commands
    }
    workflow = {
        "path": WORKFLOW,
        "events": [{"type": "pull_request"}],
        "jobs": [{"executor": {"kind": "component_sequence", "components": list(commands)}}],
    }
    compiled = SimpleNamespace(
        graph={"commands": commands, "step_components": components}, workflows=[workflow]
    )
    monkeypatch.setattr(owner, "validate_ci_graph", lambda root: compiled)
    monkeypatch.setattr(owner, "check_ci_graph", lambda root: SimpleNamespace(status="clean"))
    return compiled, set(capture["gates"])


def _issues(tmp_path, gates, paths=None, events=None):
    return owner.graph_workflow_gate_issues(
        tmp_path,
        paths=paths or [WORKFLOW],
        required_events=events or ["pull_request"],
        gate_ids=gates,
    )


def test_actual_twenty_serial_captures_have_workflow_ownership(monkeypatch, tmp_path):
    _, gates = _graph(monkeypatch)
    assert len(gates) == 20
    assert _issues(tmp_path, gates) == []


@pytest.mark.parametrize("change", [
    "print_only", "dead_code", "dynamic_gate", "wrong_gate", "wrong_output",
    "wrong_session", "wrong_python", "extra_command", "wrong_cwd",
    "conditional", "unreferenced", "command_name_only",
])
def test_non_capture_or_unbound_commands_cannot_claim_a_gate(monkeypatch, tmp_path, change):
    compiled, _ = _graph(monkeypatch)
    gate = "security-sbom"
    key = "sdk-capture-" + gate
    command = compiled.graph["commands"][key]
    script = command["argv"][2]
    if change == "print_only":
        command["argv"] = ["printf", "%s", script]
    elif change == "dead_code":
        command["argv"][2] = "exit 0\n" + script
    elif change == "dynamic_gate":
        command["argv"][2] = script.replace("--gate security-sbom", '--gate "$GATE"')
    elif change == "wrong_gate":
        command["argv"][2] = script.replace("--gate security-sbom", "--gate test")
    elif change == "wrong_output":
        command["argv"][2] = script.replace("$session_dir/security-sbom", "$session_dir/test")
    elif change == "wrong_session":
        command["argv"][2] = script.replace('--session-manifest "$session"', '--session-manifest "other.json"')
    elif change == "wrong_python":
        command["argv"][2] = script.replace(".venv/bin/python", "other/bin/python")
    elif change == "extra_command":
        command["argv"][2] = script + "\ntrue"
    elif change == "wrong_cwd":
        command["cwd"] = "elsewhere"
    elif change == "conditional":
        compiled.graph["step_components"][key]["condition"] = "never"
    elif change == "unreferenced":
        compiled.workflows[0]["jobs"][0]["executor"]["components"].remove(key)
    elif change == "command_name_only":
        command["argv"] = ["true"]
    assert _issues(tmp_path, {gate}) == ["workflow_gate_security-sbom_unresolved"]


def test_repeated_serial_capture_is_not_a_second_owner(monkeypatch, tmp_path):
    compiled, _ = _graph(monkeypatch)
    key = "sdk-capture-security-sbom"
    compiled.graph["step_components"]["duplicate"] = copy.deepcopy(
        compiled.graph["step_components"][key]
    )
    compiled.workflows[0]["jobs"][0]["executor"]["components"].append("duplicate")
    assert _issues(tmp_path, {"security-sbom"}) == [
        "workflow_gate_security-sbom_multiple_owners"
    ]


@pytest.mark.parametrize("kind", ["gate_group", "gate_shard"])
def test_existing_declared_gate_owners_are_preserved(monkeypatch, tmp_path, kind):
    compiled, gates = _graph(monkeypatch)
    compiled.workflows[0]["jobs"][0]["executor"] = {"kind": kind, "gates": sorted(gates)}
    assert _issues(tmp_path, gates) == []


def test_reusable_workflow_resolves_its_actual_serial_components(monkeypatch, tmp_path):
    compiled, gates = _graph(monkeypatch)
    child = copy.deepcopy(compiled.workflows[0])
    child["path"] = ".github/workflows/capture.yml"
    compiled.workflows[0]["jobs"][0]["executor"] = {
        "kind": "reusable_workflow", "path": child["path"]
    }
    compiled.workflows.append(child)
    assert _issues(tmp_path, gates) == []


def test_graph_validation_still_blocks_before_ownership(monkeypatch, tmp_path):
    _, gates = _graph(monkeypatch)
    def invalid(root):
        raise owner.CIGraphError("invalid fixture")
    monkeypatch.setattr(owner, "validate_ci_graph", invalid)
    assert _issues(tmp_path, gates) == ["ci_graph_invalid"]


def test_rendered_drift_still_blocks_before_ownership(monkeypatch, tmp_path):
    _, gates = _graph(monkeypatch)
    monkeypatch.setattr(
        owner, "check_ci_graph",
        lambda root: SimpleNamespace(status="drift", changed_paths=[WORKFLOW]),
    )
    assert _issues(tmp_path, gates) == ["ci_graph_workflow_drift_" + WORKFLOW]


def test_required_events_are_not_supplied_by_capture_commands(monkeypatch, tmp_path):
    _, gates = _graph(monkeypatch)
    assert _issues(tmp_path, gates, events=["workflow_dispatch"]) == [
        "workflow_event_workflow_dispatch_missing"
    ]

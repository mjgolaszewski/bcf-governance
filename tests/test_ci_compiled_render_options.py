"""Authored schema shape stays hostile; compiler defaults preserve workflow bytes."""
from copy import deepcopy
from pathlib import Path
import pytest
import yaml
from bcf_governance.tooling.ci_graph_contracts import CIGraphError, validate_ci_graph
from bcf_governance.tooling.ci_graph_render import _workflow

ROOT = Path(__file__).resolve().parents[1]


def compile_authored(tmp_path, graph, name):
    path = tmp_path / name
    path.write_text(yaml.safe_dump(graph, sort_keys=False))
    return validate_ci_graph(ROOT, graph_path=path)


def test_explicit_default_declarations_preserve_exact_workflow_bytes_and_raw_shape(tmp_path):
    graph = yaml.safe_load((ROOT / "governance/ci-graph.yml").read_text())
    raw = deepcopy(graph)
    implicit = compile_authored(tmp_path, graph, "implicit.yml")
    explicit = deepcopy(graph)
    changed = 0
    for command in explicit["commands"].values():
        if "render_mode" not in command:
            command["render_mode"] = "argv"
            changed += 1
    for component in explicit["step_components"].values():
        if component["kind"] in {"action", "command"} and "condition_style" not in component:
            component["condition_style"] = "expression"
            changed += 1
    assert changed > 0
    authored = compile_authored(tmp_path, explicit, "explicit.yml")
    assert graph == raw
    assert yaml.safe_load((tmp_path / "implicit.yml").read_text()) == raw
    left = {w["path"]: _workflow(implicit, w) for w in implicit.workflows}
    right = {w["path"]: _workflow(authored, w) for w in authored.workflows}
    assert left.keys() == right.keys()
    assert implicit.graph_sha256 != authored.graph_sha256
    for path, actual in left.items():
        expected = right[path]
        assert type(actual) is type(expected) is bytes
        actual_lines = actual.splitlines(keepends=True)
        expected_lines = expected.splitlines(keepends=True)
        assert actual_lines[1] == f"# graph-sha256: {implicit.graph_sha256}\n".encode()
        assert expected_lines[1] == f"# graph-sha256: {authored.graph_sha256}\n".encode()
        # Only the independently checked authored-source provenance differs;
        # generated header, extension/input provenance and ordered YAML remain exact.
        assert actual_lines[:1] + actual_lines[2:] == expected_lines[:1] + expected_lines[2:]
    for command_id, command in implicit.commands.items():
        if "render_mode" not in command:
            assert implicit.command_render_modes[command_id] == "argv"
    for workflow in implicit.workflows:
        for job in workflow["jobs"]:
            options = implicit.job_render_options[(workflow["id"], job["id"])]
            if "omit_name" not in job:
                assert options.omit_name is False
            if "needs_style" not in job:
                assert options.singleton_needs is False
            if "required_environment_position" not in job:
                assert options.deferred_environment is False


@pytest.mark.parametrize("field,value", [("omit_name", False), ("needs_style", "list"),
                                         ("required_environment_position", "before-work")])
def test_invalid_authored_default_spellings_still_fail_schema(tmp_path, field, value):
    graph = yaml.safe_load((ROOT / "governance/ci-graph.yml").read_text())
    graph["workflows"][0]["jobs"][0][field] = value
    with pytest.raises(CIGraphError, match="schema violation"):
        compile_authored(tmp_path, graph, "invalid.yml")

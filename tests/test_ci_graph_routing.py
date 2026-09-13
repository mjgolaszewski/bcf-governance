"""Candidate allocation contracts, with an independent native-event truth table."""

from __future__ import annotations

import copy
from itertools import product
import json
from pathlib import Path
import re

import pytest
import yaml

from bcf_governance.tooling.ci_authority_pins import _compiled_workflow_jobs
from bcf_governance.tooling.ci_graph_audit import _effective_graph
from bcf_governance.tooling.ci_graph_contracts import CIGraphError, validate_ci_graph
from bcf_governance.tooling.ci_graph_defaults import build_reference_ci_graph
from bcf_governance.tooling.ci_graph_diagnostics import diagnose_ci_graph
from bcf_governance.tooling import ci_graph_render
from bcf_governance.tooling.ci_graph_routing import (
    render_runner,
    routing_audit,
    validate_candidate_routing,
)


ROOT = Path(__file__).resolve().parents[1]
CASES = ["same_repository_pull_request", "protected_push", "protected_schedule", "protected_dispatch"]
LOCAL = ["self-hosted", "Linux", "X64", "fixture-local-candidate"]


def _policy() -> dict:
    return {"kind": "private_local_candidate", "repository_id": "12345", "local_runner": LOCAL.copy(),
            "local_cases": CASES.copy(), "allowed_refs": ["refs/heads/main"]}


def _graph() -> dict:
    return build_reference_ci_graph(
        project_id="routing-fixture", profile="standard", profile_contract_version="2.0", gates=["test"],
        candidate_labels=["ubuntu-24.04"], trusted_labels=["self-hosted", "fixture-controller"],
        candidate_hosted=True, trusted_hosted=False,
    )


def _write(root: Path, graph: dict) -> None:
    (root / "governance/ci-extensions").mkdir(parents=True, exist_ok=True)
    (root / "schemas").mkdir(exist_ok=True)
    for name in ("ci-graph.schema.json", "ci-graph-extension.schema.json"):
        (root / "schemas" / name).write_bytes((ROOT / "schemas" / name).read_bytes())
    (root / "governance/ci-graph.yml").write_text(yaml.safe_dump(graph, sort_keys=False))


def _routed() -> tuple[dict, dict]:
    graph = _graph()
    resource = graph["resource_classes"]["candidate-python"]
    resource["routing"] = _policy()
    return graph, resource


def _selector(expression: str):
    """Parse the emitted closed GitHub syntax without evaluating Python or JS."""
    outer = re.fullmatch(r"\$\{\{ fromJSON\(\((.*)\) && '([^']+)' \|\| '([^']+)'\) \}\}", expression)
    assert outer is not None
    source, local, hosted = outer.groups()
    token_pattern = re.compile(r"\s*(\&\&|\|\||==|[()]|'[^']*'|[0-9]+|true|github\.[A-Za-z0-9_.]+)")
    tokens, offset = [], 0
    while offset < len(source):
        token = token_pattern.match(source, offset)
        assert token is not None, source[offset:]
        tokens.append(token[1]); offset = token.end()
    cursor = 0
    def atom():
        nonlocal cursor
        token = tokens[cursor]; cursor += 1
        if token == "(":
            value = disjunction()
            assert tokens[cursor] == ")"; cursor += 1
            return value
        if token.startswith("github."):
            return ("field", token.split(".")[1:])
        return ("value", True if token == "true" else token[1:-1] if token.startswith("'") else int(token))
    def comparison():
        nonlocal cursor
        left = atom()
        if cursor < len(tokens) and tokens[cursor] == "==":
            cursor += 1
            return ("==", left, atom())
        return left
    def conjunction():
        nonlocal cursor
        left = comparison()
        while cursor < len(tokens) and tokens[cursor] == "&&":
            cursor += 1; left = ("&&", left, comparison())
        return left
    def disjunction():
        nonlocal cursor
        left = conjunction()
        while cursor < len(tokens) and tokens[cursor] == "||":
            cursor += 1; left = ("||", left, conjunction())
        return left
    tree = disjunction()
    assert cursor == len(tokens)
    def evaluate(node, context):
        if node[0] == "value":
            return node[1]
        if node[0] == "field":
            value = context
            for key in node[1]:
                value = value.get(key) if isinstance(value, dict) else None
            return value
        left, right = evaluate(node[1], context), evaluate(node[2], context)
        if node[0] == "==":
            return left == right
        return bool(left and right) if node[0] == "&&" else bool(left or right)
    return lambda context: json.loads(local if evaluate(tree, context) else hosted)


@pytest.mark.parametrize("event", ["pull_request", "push", "schedule", "workflow_dispatch", "workflow_run",
                                   "repository_dispatch", "pull_request_target", "workflow_call", "unknown"])
def test_native_event_visibility_identity_and_protected_ref_matrix(event: str) -> None:
    _, resource = _routed()
    select = _selector(render_runner(resource))
    heads = list(product((12345, 67890, None), repeat=2)) if event == "pull_request" else [(None, None)]
    refs = list(product(("branch", "tag", None), (True, False, None),
                        ("refs/heads/main", "refs/heads/unreviewed", None))) if event in {
        "push", "schedule", "workflow_dispatch"} else [(None, None, None)]
    for private, ambient_id, event_id in product((True, False, None), ("12345", "67890", None), (12345, 67890, None)):
        for (head_id, base_id), (kind, protected, ref) in product(heads, refs):
            context = {"repository_id": ambient_id, "event_name": event, "ref_type": kind,
                       "ref_protected": protected, "ref": ref,
                       "event": {"repository": {"private": private, "id": event_id},
                                 "pull_request": {"head": {"repo": {"id": head_id}}, "base": {"repo": {"id": base_id}}}},
                       "inputs": {"trusted": True, "runner": LOCAL}}
            qualified = private is True and ambient_id == "12345" and event_id == 12345
            accepted_event = ((event == "pull_request" and head_id == base_id == 12345) or
                              (event in {"push", "schedule", "workflow_dispatch"} and kind == "branch"
                               and protected is True and ref == "refs/heads/main"))
            assert select(context) == (LOCAL if qualified and accepted_event else ["ubuntu-24.04"])
    assert select({}) == ["ubuntu-24.04"]


def test_same_repository_pr_requires_explicit_opt_in_and_does_not_accept_caller_flags() -> None:
    _, resource = _routed()
    resource["routing"]["local_cases"].remove("same_repository_pull_request")
    select = _selector(render_runner(resource))
    context = {"repository_id": "12345", "event_name": "pull_request", "inputs": {"trusted": True},
               "event": {"repository": {"private": True, "id": 12345},
                         "pull_request": {"head": {"repo": {"id": 12345}}, "base": {"repo": {"id": 12345}}}}}
    assert select(context) == ["ubuntu-24.04"]
    assert all("routing" not in resource for resource in _graph()["resource_classes"].values())


def test_pr_only_policy_needs_no_protected_ref_declaration(tmp_path: Path) -> None:
    graph, resource = _routed()
    resource["routing"].update(local_cases=["same_repository_pull_request"], allowed_refs=[])
    _write(tmp_path, graph)
    validate_ci_graph(tmp_path)
    assert "github.ref" not in render_runner(resource)


@pytest.mark.parametrize("field", ["kind", "repository_id", "local_runner", "local_cases", "allowed_refs"])
def test_routing_policy_rejects_missing_contract_fields(tmp_path: Path, field: str) -> None:
    graph, resource = _routed(); del resource["routing"][field]; _write(tmp_path, graph)
    with pytest.raises(CIGraphError, match="schema violation"):
        validate_ci_graph(tmp_path)


@pytest.mark.parametrize("field,value", [
    ("kind", "arbitrary_expression"), ("repository_id", True), ("repository_id", "0"),
    ("repository_id", "${{ inputs.repository_id }}"), ("local_runner", ["self-hosted", "${{ inputs.runner }}"]),
    ("local_cases", ["pull_request_target"]), ("local_cases", []), ("allowed_refs", ["refs/heads/*"]),
    ("allowed_refs", ["refs/heads/main' || true"]), ("trusted", True),
])
def test_routing_policy_rejects_unknown_and_executable_declarations(tmp_path: Path, field: str, value) -> None:
    graph, resource = _routed(); resource["routing"][field] = value; _write(tmp_path, graph)
    with pytest.raises(CIGraphError, match="schema violation"):
        validate_ci_graph(tmp_path)


@pytest.mark.parametrize("case,diagnostic", [
    ("trusted", "remain candidate"), ("unhosted", "potentially hosted"),
    ("unsupported-hosted", "hosted fallback"), ("array-hosted", "hosted fallback"),
    ("general-local", "dedicated local"), ("controller-local", "dedicated local"),
    ("missing-self-hosted", "dedicated local"), ("duplicate-case", "case-insensitive"),
    ("hosted-local", "mixes hosted"), ("missing-refs", "protected branch refs"),
    ("bad-ref", "invalid literal branch"), ("different-repository", "one repository identity"),
])
def test_routed_resources_cannot_weaken_resource_custody(tmp_path: Path, case: str, diagnostic: str) -> None:
    graph, resource = _routed(); policy = resource["routing"]
    if case == "trusted": resource["trust"] = "trusted"
    elif case == "unhosted": resource["hosted"] = False
    elif case == "unsupported-hosted": resource["runner"] = "self-hosted"
    elif case == "array-hosted": resource["runner"] = ["ubuntu-24.04"]
    elif case == "general-local": policy["local_runner"] = ["self-hosted", "Linux", "X64"]
    elif case == "controller-local": policy["local_runner"] = ["self-hosted", "FIXTURE-CONTROLLER"]
    elif case == "missing-self-hosted": policy["local_runner"] = ["Linux", "fixture-local-candidate"]
    elif case == "duplicate-case": policy["local_runner"].append("SELF-HOSTED")
    elif case == "hosted-local": policy["local_runner"].append("ubuntu-24.04")
    elif case == "missing-refs": policy["allowed_refs"] = []
    elif case == "bad-ref": policy["allowed_refs"] = ["refs/heads/a..b"]
    elif case == "different-repository":
        graph["resource_classes"]["other-candidate"] = copy.deepcopy(resource)
        graph["resource_classes"]["other-candidate"]["routing"]["repository_id"] = "54321"
    _write(tmp_path, graph)
    with pytest.raises(CIGraphError, match=diagnostic): validate_ci_graph(tmp_path)


@pytest.mark.parametrize("values", [["fixture-local-candidate"], ["${{ inputs.instance }}"], [], "scalar"])
def test_local_candidate_discriminator_cannot_be_a_trusted_matrix_label(values) -> None:
    graph, _ = _routed()
    graph["resource_classes"]["trusted-control"]["runner"] = ["self-hosted", "${{ matrix.instance }}"]
    for workflow in graph["workflows"]:
        for job in workflow["jobs"]:
            if job["resource_class"] == "trusted-control": job["matrix"] = {"instance": values}
    with pytest.raises(CIGraphError, match="dedicated local|trusted.*matrix"):
        validate_candidate_routing(graph)


def test_declared_distinct_trusted_matrix_instances_preserve_candidate_separation() -> None:
    graph, _ = _routed()
    graph["resource_classes"]["trusted-control"]["runner"] = ["self-hosted", "${{ matrix.instance }}"]
    for workflow in graph["workflows"]:
        for job in workflow["jobs"]:
            if job["resource_class"] == "trusted-control": job["matrix"] = {"instance": ["controller-one", "controller-two"]}
    validate_candidate_routing(graph)


@pytest.mark.parametrize("matrix", [
    {"instance": ["controller-one"], "include": [{"instance": "fixture-local-candidate"}]},
    {"instance": ["controller-one"], "include": "not-a-matrix"},
])
def test_trusted_matrix_include_cannot_hide_candidate_overlap(matrix) -> None:
    graph, _ = _routed()
    graph["resource_classes"]["trusted-control"]["runner"] = ["self-hosted", "${{ matrix.instance }}"]
    for workflow in graph["workflows"]:
        for job in workflow["jobs"]:
            if job["resource_class"] == "trusted-control": job["strategy"] = {"matrix": matrix}
    with pytest.raises(CIGraphError, match="dedicated local|trusted selector matrix"):
        validate_candidate_routing(graph)


def test_routing_changes_only_allocation_and_exposes_eligibility(tmp_path: Path) -> None:
    graph = _graph(); _write(tmp_path, graph)
    previous = ci_graph_render.render_ci_graph(tmp_path)
    graph["resource_classes"]["candidate-python"]["routing"] = _policy(); _write(tmp_path, graph)
    compiled = validate_ci_graph(tmp_path); rendered = ci_graph_render.render_ci_graph(tmp_path)
    assert rendered == ci_graph_render.render_ci_graph(tmp_path)
    for path, raw in rendered.items():
        old, new = yaml.safe_load(previous[path]), yaml.safe_load(raw)
        assert _compiled_workflow_jobs(previous[path], roles=None) == _compiled_workflow_jobs(raw, roles=None)
        assert list(new["jobs"]) == list(old["jobs"])
        for job_id, job in new["jobs"].items():
            if isinstance(job.get("runs-on"), str) and job["runs-on"].startswith("${{ fromJSON"):
                assert "strategy" not in job
                job["runs-on"] = old["jobs"][job_id]["runs-on"]
        assert new == old
    facts = [job for workflow in _effective_graph(compiled) for job in workflow["jobs"] if "runner_routing" in job]
    assert facts and all(job["runner_routing"]["hosted_restrictions_apply"] for job in facts)
    assert facts[0]["runner_routing"]["local_runner"] == LOCAL
    diagnostics = diagnose_ci_graph(tmp_path)["diagnostics"]
    assert any("all other contexts use hosted" in row["remediation"] for row in diagnostics)


def test_hosted_waiter_guard_still_applies_to_routed_candidate(tmp_path: Path) -> None:
    graph, _ = _routed(); graph["commands"]["preflight"]["argv"] = ["sleep", "60"]; _write(tmp_path, graph)
    with pytest.raises(CIGraphError, match="hosted waiter"):
        validate_ci_graph(tmp_path)


def test_legacy_runner_projection_and_workflow_bytes_are_unchanged(tmp_path: Path, monkeypatch) -> None:
    graph = _graph(); _write(tmp_path, graph)
    actual = ci_graph_render.render_ci_graph(tmp_path)
    monkeypatch.setattr(ci_graph_render, "render_runner", lambda resource: copy.deepcopy(resource["runner"]))
    assert ci_graph_render.render_ci_graph(tmp_path) == actual
    for runner in ("ubuntu-24.04", ["self-hosted", "${{ matrix.instance }}"]):
        resource = {"runner": runner}
        assert render_runner(resource) == runner and routing_audit(resource) == {}


def test_routed_durable_source_preserves_non_matrix_custody(tmp_path: Path) -> None:
    from tests.test_evidence_storage import _durable_graph_repo
    root = _durable_graph_repo(tmp_path)
    path = root / "governance/ci-graph.yml"; graph = yaml.safe_load(path.read_text())
    storage = yaml.safe_load((root / "governance/evidence-storage.yml").read_text())
    policy = _policy(); policy["repository_id"] = str(storage["provider"]["repository_id"])
    graph["resource_classes"]["candidate-python"]["routing"] = policy
    path.write_text(yaml.safe_dump(graph, sort_keys=False)); compiled = validate_ci_graph(root)
    sources = [job for workflow in compiled.workflows for job in workflow["jobs"]
               if any(compiled.graph["artifacts"][a]["kind"] == "durable-source" for a in job["produces"])]
    assert len(sources) == 1 and "matrix" not in sources[0] and "strategy" not in sources[0]
    policy["repository_id"] = "99999"; path.write_text(yaml.safe_dump(graph, sort_keys=False))
    with pytest.raises(CIGraphError, match="identity differs from evidence storage"):
        validate_ci_graph(root)

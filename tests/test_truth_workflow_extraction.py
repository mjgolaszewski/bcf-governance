"""Preserve the existing workflow truth query while moving its responsibility."""

import ast
import inspect

import pytest
import yaml

from bcf_governance.tooling import governance_truth as truth


ROOT = ".github/workflows/front.yml"


def _workflow(root, path, jobs, events=None):
    target = root / path
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(yaml.safe_dump({"on": events or ["pull_request"], "jobs": jobs}))


def _policy(**kw):
    return {"workflow_contract": {
        "paths": [ROOT], "required_events": ["pull_request"], **kw,
    }}


@pytest.mark.parametrize(("policy", "expected"), [
    ({}, ["workflow_contract_missing"]),
    ({"workflow_contract": {"paths": []}}, ["workflow_paths_missing"]),
])
def test_workflow_contract_diagnostics_preserved(tmp_path, policy, expected):
    assert truth._workflow_gate_issues(tmp_path, policy, {"test"}) == expected


def test_workflow_missing_root_preserves_all_diagnostics(tmp_path):
    assert truth._workflow_gate_issues(tmp_path, _policy(), {"test"}) == [
        "workflow_event_pull_request_missing", "workflow_gate_test_unresolved",
        "workflow_path_.github/workflows/front.yml_missing",
    ]


def test_workflow_evidence_wrapper_and_root_events_preserved(tmp_path):
    _workflow(tmp_path, ROOT, {"test": {"steps": [
        {"run": "python scripts/governance_evidence.py run --gate test"},
    ]}})
    assert truth._workflow_gate_issues(tmp_path, _policy(), {"test"}) == []


def test_workflow_matrix_without_evidence_wrapper_still_blocks(tmp_path):
    _workflow(tmp_path, ROOT, {"test": {
        "strategy": {"matrix": {"gate": ["test"]}}, "steps": [{"run": "pytest"}],
    }})
    assert truth._workflow_gate_issues(tmp_path, _policy(), {"test"}) == [
        "workflow_gate_test_unresolved", "workflow_job_test_evidence_wrapper_missing",
    ]


def test_local_reusable_workflow_and_cycle_preserve_resolution(tmp_path):
    child = ".github/workflows/child.yml"
    _workflow(tmp_path, ROOT, {"child": {"uses": "./" + child}})
    _workflow(tmp_path, child, {
        "parent": {"uses": "./" + ROOT},
        "proof": {"steps": [{"run": "bcf evidence run --gate test"}]},
    }, events=["workflow_call"])
    assert truth._workflow_gate_issues(tmp_path, _policy(), {"test"}) == []


def test_external_reusable_workflow_remains_unresolved(tmp_path):
    _workflow(tmp_path, ROOT, {"external": {"uses": "other/repo/workflow@main"}})
    assert truth._workflow_gate_issues(tmp_path, _policy(), {"test"}) == [
        "workflow_gate_test_unresolved", "workflow_job_external_external_reusable_unresolved",
    ]


def test_canonical_shard_resolver_preserves_safe_source_requirements(tmp_path):
    resolver = {
        "id": "proof", "kind": "canonical_contract_shards", "workflow_path": ROOT,
        "job_id": "proof", "matrix_key": "shard", "script_path": "scripts/shard.py",
        "gate_contract_path": "governance/gate-contracts.yml", "profile_path": "governance-profile.yml",
    }
    for name in ("script_path", "gate_contract_path", "profile_path"):
        path = tmp_path / resolver[name]
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("retained source\n")
    _workflow(tmp_path, ROOT, {"proof": {
        "strategy": {"matrix": {"shard": [0, 1]}},
        "steps": [{"run": "python scripts/shard.py --shard-index ${{ matrix.shard }} --shard-count 2"}],
    }})
    policy = _policy(gate_resolvers=[resolver])
    assert truth._workflow_gate_issues(tmp_path, policy, {"test"}) == []
    script = tmp_path / resolver["script_path"]
    script.unlink()
    script.symlink_to(tmp_path / resolver["profile_path"])
    assert truth._workflow_gate_issues(tmp_path, policy, {"test"}) == [
        "workflow_gate_resolver_proof_invalid", "workflow_gate_test_unresolved",
    ]


def test_workflow_loader_error_identity_preserved(tmp_path):
    path = tmp_path / ROOT
    path.parent.mkdir(parents=True)
    path.write_text("- not-a-mapping\n")
    with pytest.raises(truth.TruthfulnessError, match="must deserialize to a mapping"):
        truth._workflow_gate_issues(tmp_path, _policy(), {"test"})


def test_workflow_truth_algorithm_has_one_existing_owner_and_thin_delegate():
    from bcf_governance.tooling import truth_workflow_graph as owner
    wrapper = ast.parse(inspect.getsource(truth._workflow_gate_issues)).body[0]
    assert len(wrapper.body) == 1 and isinstance(wrapper.body[0], ast.Return)
    call = wrapper.body[0].value
    assert isinstance(call, ast.Call) and isinstance(call.func, ast.Name)
    assert call.func.id == "workflow_gate_issues"
    assert truth.workflow_gate_issues is owner.workflow_gate_issues
    assert not hasattr(truth, "_safe_contract_file")
    assert callable(owner._safe_contract_file)

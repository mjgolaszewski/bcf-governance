"""Protected policy and candidate source have separate authenticated roots."""
import copy
import hashlib
import os
from pathlib import Path
import shutil
import subprocess

import pytest
import yaml

from bcf_governance.tooling import ci_graph_composition_operations as owner
from bcf_governance.tooling.ci_graph_errors import CIGraphError
from bcf_governance.tooling.semantic_ownership_inventory import discover_python_source
from tests.test_independent_call_coverage import SOURCE, payload
from tests.test_lifecycle_public_entrypoint_bindings import (
    _capture_subject, binding_inputs as binding_inputs, composition as composition,
    operation_call_binding_inputs as operation_call_binding_inputs,
    public_facade_inputs as public_facade_inputs,
    public_reconstructed_binding_inputs as public_reconstructed_binding_inputs,
    reconstructed_binding_inputs as reconstructed_binding_inputs,
)

PAIR = ("release", "build", "verify")


def git(root, *args):
    env = {key: value for key, value in os.environ.items() if not key.startswith("GIT_")}
    return subprocess.check_output(["git", "--no-replace-objects", "-c", "core.hooksPath=/dev/null",
        "-c", "core.fsmonitor=false", "-c", "gc.auto=0", "-c", "user.name=Fixture",
        "-c", "user.email=fixture@example.invalid", *args], cwd=root, env=env, text=True).strip()


def subject(root):
    return dict(commit_sha=git(root, "rev-parse", "HEAD"), tree_sha=git(root, "rev-parse", "HEAD^{tree}"))


@pytest.fixture
def roots(tmp_path):
    protected = tmp_path / "protected"
    protected.mkdir()
    (protected / "runtime.py").write_text(SOURCE)
    (protected / "schemas").mkdir()
    shutil.copy2(Path(__file__).parents[1] / "schemas/application-operations.schema.json",
                 protected / "schemas/application-operations.schema.json")
    (protected / "governance").mkdir()
    (protected / "governance/application-operations.yml").write_text(yaml.safe_dump(payload()))
    git(protected, "init", "-b", "main")
    git(protected, "add", ".")
    git(protected, "commit", "-qm", "protected policy")
    candidate = tmp_path / "candidate"
    git(tmp_path, "clone", "-q", "--no-local", str(protected), str(candidate))
    return protected, candidate


def arguments(root, policy_subject=None):
    current = subject(root)
    return dict(repo_root=root, policy_subject=policy_subject or current,
        runtime_subject=current, required_relationships={"coverage.work.v1": frozenset({PAIR})},
        relationship_roots={PAIR: frozenset({"runtime.py::work"})})


def inventory(root, bound=True):
    return discover_python_source(root, call_contracts_version="1.0",
        **({"source_subject": subject(root)} if bound else {"files": [root / "runtime.py"]}))


def test_same_root_capture_remains_compatible(roots):
    _, root = roots
    captured = owner.capture_public_operation_bindings(**arguments(root))
    result = owner.validate_public_operation_capture(root, inventory(root), captured)
    assert result["authority"] is False and result["execution_qualified"] is False
    assert result["operations_checked"] == 1


@pytest.mark.parametrize("defect", ["policy_bytes", "metadata", "registry", "roots", "runtime_metadata", "later_inventory", "unbound_inventory", "unowned_capture"])
def test_consuming_capture_reauthenticates_actual_source(roots, defect):
    _, root = roots
    captured = owner.capture_public_operation_bindings(**arguments(root))
    facts = inventory(root)
    if defect == "policy_bytes":
        path = root / "governance/application-operations.yml"
        path.write_text(path.read_text() + "# moved protected policy\n")
    elif defect == "metadata":
        captured[1]["registry_sha256"] = "0" * 64
    elif defect == "registry":
        captured[0].raw["operations"][0]["bounded_context"] = "forged"
    elif defect == "roots":
        captured[2][PAIR] |= {"runtime.py::helper"}
    elif defect == "runtime_metadata":
        captured[1]["runtime_subject"] = dict(commit_sha="1" * 40, tree_sha="2" * 40)
    elif defect == "later_inventory":
        (root / "runtime.py").write_text(SOURCE.replace("return 1", "return 2"))
        git(root, "add", ".")
        git(root, "commit", "-qm", "later pure source")
        facts = inventory(root)
    elif defect == "unbound_inventory":
        facts = inventory(root, bound=False)
    else:
        captured = tuple(captured[:3])
    with pytest.raises(CIGraphError, match="public operation.*(capture|policy|runtime|source|roots)"):
        owner.validate_public_operation_capture(root, facts, captured)


@pytest.mark.parametrize("candidate_policy", ["unchanged", "invalid_candidate_schema", "changed_candidate_policy"])
def test_separate_policy_source_governs_candidate_without_candidate_authority(roots, candidate_policy):
    protected, candidate = roots
    expected = subject(protected)
    if candidate_policy == "invalid_candidate_schema":
        (candidate / "schemas/application-operations.schema.json").write_text("false")
    elif candidate_policy == "changed_candidate_policy":
        (candidate / "governance/application-operations.yml").write_text("candidate: cannot_supply_authority\n")
    (candidate / "runtime.py").write_text(SOURCE.replace("return 1", "return 2"))
    git(candidate, "add", ".")
    git(candidate, "commit", "-qm", "candidate source and policy data")
    captured = owner.capture_public_operation_bindings(**arguments(candidate, expected), policy_repo_root=protected)
    result = owner.validate_public_operation_capture(candidate, inventory(candidate), captured)
    assert result["policy_subject"] == expected
    assert result["runtime_subject"] == subject(candidate) != expected
    assert result["policy_changed"] is (candidate_policy == "changed_candidate_policy")
    assert result["runtime_policy_sha256"] == hashlib.sha256((candidate / "governance/application-operations.yml").read_bytes()).hexdigest()
    assert result["registry_sha256"] == hashlib.sha256((protected / "governance/application-operations.yml").read_bytes()).hexdigest()
    assert result["authority"] is False and result["execution_qualified"] is False
    assert str(protected) not in repr(result) and str(candidate) not in repr(result)


@pytest.mark.parametrize("cause", ["missing", "foreign", "dirty", "not_path"])
def test_separate_policy_source_rejects_before_catalog_discovery(roots, tmp_path, monkeypatch, cause):
    protected, candidate = roots
    expected = subject(protected)
    selected = protected
    if cause == "missing":
        selected = tmp_path / "missing"
    elif cause == "foreign":
        selected = tmp_path / "foreign"
        selected.mkdir()
        git(selected, "init", "-b", "main")
    elif cause == "dirty":
        (protected / "governance/application-operations.yml").write_text("changed: true\n")
    else:
        selected = str(protected)
    monkeypatch.setattr(owner, "_discover_population", lambda *a, **kw: pytest.fail("catalog before protected policy authentication"))
    with pytest.raises(CIGraphError, match="public operation.*policy"):
        owner.capture_public_operation_bindings(**arguments(candidate, expected), policy_repo_root=selected)


def test_separate_policy_movement_rejects_after_local_factory_capture(roots):
    protected, candidate = roots
    captured = owner.capture_public_operation_bindings(**arguments(candidate), policy_repo_root=protected)
    path = protected / "governance/application-operations.yml"
    path.write_text(path.read_text() + "# moved after capture\n")
    with pytest.raises(CIGraphError, match="public operation.*policy"):
        owner.validate_public_operation_capture(candidate, inventory(candidate), captured)


def test_candidate_cannot_erase_unclassified_operations_with_its_own_policy(roots):
    protected, candidate = roots
    (candidate / "runtime.py").write_text(SOURCE.replace("{'work': work}", "{'work': work, 'extra': helper}"))
    (candidate / "governance/application-operations.yml").write_text("operations: []\n")
    git(candidate, "add", ".")
    git(candidate, "commit", "-qm", "candidate removes its obligations")
    with pytest.raises(CIGraphError, match="unclassified public application operations"):
        owner.capture_public_operation_bindings(**arguments(candidate, subject(protected)), policy_repo_root=protected)


def test_real_reconstruction_propagates_separate_policy_root(public_facade_inputs, composition, tmp_path):
    from bcf_governance.tooling.ci_graph_composition import validate_reconstructed_lifecycle_bindings
    inputs, policy, _ = public_facade_inputs
    root = inputs["repo_root"]
    protected_subject = copy.deepcopy(inputs["operation_policy_subject"])
    protected = tmp_path.parent / (tmp_path.name + "-protected-worktree")
    git(root, "worktree", "add", "--detach", str(protected), protected_subject["commit_sha"])
    policy.write_text("candidate: cannot_supply_authority\n")
    _capture_subject(inputs, composition)
    inputs["operation_policy_subject"] = protected_subject
    result = validate_reconstructed_lifecycle_bindings(**inputs, operation_policy_repo_root=protected)
    observation = result["public_operation_bindings"]
    assert observation["policy_subject"] == protected_subject
    assert observation["runtime_subject"] == result["source_reconstruction"]["subject"]
    assert observation["policy_changed"] is True
    assert result["authority"] is False and result["execution_qualified"] is False

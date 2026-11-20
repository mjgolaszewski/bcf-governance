"""Invalid retirement cannot allocate evidence or become a successful proof."""
import json

import pytest

from bcf_governance.tooling.test_splinter_proofs import (
    load_test_splinter_proof, select_applicable_proof, write_successful_proof,
)
from test_test_splinter_proofs import _plan, _source


def write(root, *, removed=True, state=None):
    junit = root / "source.xml"
    junit.write_text('<testsuite><testcase classname="tests.one" name="test_a"/></testsuite>')
    plan = _plan()
    return write_successful_proof(root / "proofs", plan=plan, splinter=plan["splinters"][0],
        toolchain_sha256="d" * 64, junit=junit, observed_nodes=["tests.one::test_a"],
        execution_state=state, worktree_removed=removed, source=_source())


@pytest.mark.parametrize("removed", [1, "true", [True], {"removed":True}])
def test_truthy_nonboolean_removal_cannot_allocate_or_publish_proof(tmp_path, removed):
    with pytest.raises(ValueError, match="proof"):
        write(tmp_path, removed=removed)
    assert not (tmp_path / "proofs").exists(), "invalid retirement allocated proof outputs"


@pytest.mark.parametrize("state", [
    {}, {"retired":True}, {"retired":False,"removal_verified":True},
    {"retired":1,"removal_verified":True}, {"retired":True,"removal_verified":1},
    {"retired":True,"removal_verified":False}, [True], "retired",
    {"retired":True,"removal_verified":True,"unsupported":object()},
])
def test_invalid_complete_retirement_is_rejected_before_any_output(tmp_path, state):
    with pytest.raises(ValueError, match="proof"):
        write(tmp_path, state=state)
    assert not (tmp_path / "proofs").exists(), "invalid retirement allocated proof outputs"


@pytest.mark.parametrize("state", [None, {"retired":True,"removal_verified":True},
    {"retired":True,"removal_verified":True,"details":{"retired_children":["one"]}}])
def test_valid_retirement_preserves_exact_proof_readback_and_reuse(tmp_path, state):
    manifest, junit = write(tmp_path, state=state)
    decoded = load_test_splinter_proof(manifest)
    assert decoded["result"]["execution_state"] == state
    assert decoded["result"]["worktree_removed"] is True
    selected, restored, reason = select_applicable_proof([manifest.parent], plan=_plan(),
        splinter=_plan()["splinters"][0], toolchain_sha256="d" * 64, current=_source("2"))
    assert selected == decoded and restored == junit and reason == "exact_prior_proof"
    assert json.loads(manifest.read_bytes()) == decoded


def test_actual_false_removal_still_blocks_before_output(tmp_path):
    with pytest.raises(ValueError, match="proof"):
        write(tmp_path, removed=False)
    assert not (tmp_path / "proofs").exists()

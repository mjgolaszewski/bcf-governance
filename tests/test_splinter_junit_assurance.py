"""Self-consistent forged splinter artifacts cannot establish successful execution."""
import copy
import hashlib
import json

import pytest

from bcf_governance.tooling import test_splinter_proofs as owner
from bcf_governance.tooling.evidence_test_adapters import _capture_splinter_proofs
from test_test_splinter_proofs import _plan, _source

GOOD = '<testsuite><testcase classname="tests.one" name="test_a"/></testsuite>'
BAD = [
    '<testsuite><testcase classname="tests.one" name="test_a"><failure/></testcase></testsuite>',
    '<testsuite><testcase classname="tests.one" name="test_a"><error/></testcase></testsuite>',
    '<testsuite><testcase classname="tests.one" name="test_a"><skipped/></testcase></testsuite>',
    '<testsuite/>',
    '<testsuite><testcase classname="tests.other" name="test_b"/></testsuite>',
    '<testsuite><testcase classname="tests.one" name="test_a"/><testcase classname="tests.one" name="test_a"/></testsuite>',
    '<broken',
]


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def write(root, raw=GOOD):
    plan = _plan()
    source = root / "source.xml"
    source.write_text(raw)
    manifest, junit = owner.write_successful_proof(
        root / "proofs", plan=plan, splinter=plan["splinters"][0],
        toolchain_sha256="d" * 64, junit=source, observed_nodes=["tests.one::test_a"],
        execution_state=None, worktree_removed=True, source=_source())
    return plan, manifest, junit


def forge(manifest, junit, raw):
    junit.write_text(raw)
    proof = json.loads(manifest.read_text())
    proof["result"]["junit_sha256"] = hashlib.sha256(junit.read_bytes()).hexdigest()
    proof["proof_sha256"] = digest({k:v for k,v in proof.items() if k != "proof_sha256"})
    manifest.write_text(json.dumps(proof))
    return proof


def report(plan, manifest, junit):
    proof = json.loads(manifest.read_text())
    return dict(copy.deepcopy(plan), results=[{"id":"splinter-0", "returncode":0, "proof_status":"fresh"}],
                proofs=[{"id":"splinter-0", "status":"fresh", "proof_sha256":proof["proof_sha256"],
                         "manifest":manifest.relative_to(manifest.parent.parent).as_posix(),
                         "junit":junit.relative_to(manifest.parent.parent).as_posix()}])


@pytest.mark.parametrize("raw", BAD)
def test_producer_rejects_bad_junit_before_allocation(tmp_path, raw):
    with pytest.raises(ValueError, match="JUnit"):
        write(tmp_path, raw)
    assert not (tmp_path / "proofs").exists(), "invalid JUnit allocated proof outputs"


@pytest.mark.parametrize("raw", BAD)
def test_reuse_reparses_self_consistent_forged_junit(tmp_path, raw):
    plan, manifest, junit = write(tmp_path)
    forge(manifest, junit, raw)
    proof, restored, _ = owner.select_applicable_proof(
        [manifest.parent], plan=plan, splinter=plan["splinters"][0],
        toolchain_sha256="d" * 64, current=_source("2"))
    assert proof is None and restored is None, "forged splinter success reused"


@pytest.mark.parametrize("raw", BAD)
def test_collector_reparses_self_consistent_forged_junit(tmp_path, raw):
    plan, manifest, junit = write(tmp_path)
    forge(manifest, junit, raw)
    destination = tmp_path / "captured"
    destination.mkdir()
    accepted, artifacts = _capture_splinter_proofs(tmp_path, destination, report(plan, manifest, junit))
    assert accepted is False and artifacts == [], "forged splinter success captured"
    assert not list(destination.iterdir()), "rejected splinter allocated captured evidence"


@pytest.mark.parametrize("field", ["subject_commit", "subject_tree", "policy_sha256"])
def test_collector_binds_proof_to_exact_partition(tmp_path, field):
    plan, manifest, junit = write(tmp_path)
    plan["identity"][field] = "f" * (64 if field == "policy_sha256" else 40)
    plan["partition_sha256"] = digest({k:v for k,v in plan.items() if k != "partition_sha256"})
    destination = tmp_path / "captured"
    destination.mkdir()
    assert _capture_splinter_proofs(tmp_path, destination, report(plan, manifest, junit))[0] is False, "wrong partition proof captured"


def test_duplicate_result_identity_cannot_hide_in_dictionary_projection(tmp_path):
    plan, manifest, junit = write(tmp_path)
    value = report(plan, manifest, junit)
    value["results"].append(dict(value["results"][0]))
    destination = tmp_path / "captured"
    destination.mkdir()
    assert _capture_splinter_proofs(tmp_path, destination, value)[0] is False, "duplicate splinter result hidden"


def test_boolean_exit_cannot_claim_exact_integer_success(tmp_path):
    plan, manifest, junit = write(tmp_path)
    proof = json.loads(manifest.read_text())
    proof["result"]["returncode"] = False
    proof["proof_sha256"] = digest({k:v for k,v in proof.items() if k != "proof_sha256"})
    manifest.write_text(json.dumps(proof))
    selected, _, _ = owner.select_applicable_proof(
        [manifest.parent], plan=plan, splinter=plan["splinters"][0],
        toolchain_sha256="d"*64, current=_source("2"))
    assert selected is None, "boolean splinter exit accepted"


def test_genuine_success_retains_reuse_and_capture(tmp_path):
    plan, manifest, junit = write(tmp_path)
    proof, _, reason = owner.select_applicable_proof(
        [manifest.parent], plan=plan, splinter=plan["splinters"][0],
        toolchain_sha256="d"*64, current=_source("2"))
    assert proof is not None and reason == "exact_prior_proof"
    destination = tmp_path / "captured"
    destination.mkdir()
    accepted, artifacts = _capture_splinter_proofs(tmp_path, destination, report(plan, manifest, junit))
    assert accepted and len(artifacts) == 2
